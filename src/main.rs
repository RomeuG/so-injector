use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
enum Error {
    #[error("number of arguments is incorrect")]
    NotEnoughArgs,

    #[error("impossible to parse as integer")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("impossible to parse")]
    Parse(#[from] std::convert::Infallible),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("Ptrace has not been instantiated")]
    PtraceNotInstantiated,

    #[error("Error attaching to process")]
    PtraceAttach(u32),

    #[error("Error continuing process")]
    PtraceCont(u32),

    #[error("Error getting registers")]
    PtraceGetregs(u32),

    #[error("Error setting registers")]
    PtraceSetregs(u32),

    #[error("Error using waitpid")]
    Waitpid(u32),
}

fn errno() -> u32 {
    unsafe { *libc::__errno_location() as u32 }
}

struct Ptrace {
    pid: libc::pid_t,
    stopped: bool,
}

impl Ptrace {
    fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            stopped: false,
        }
    }

    fn attach(&mut self) -> Result<bool> {
        let result = unsafe { libc::ptrace(libc::PTRACE_ATTACH, self.pid, 0, 0) };

        if result == -1 {
            return Err(Error::PtraceAttach(errno()));
        }

        let waitsig = self.waitsig(libc::SIGSTOP)?;

        Ok(waitsig)
    }

    fn stop(&mut self) -> Result<bool> {
        if self.stopped {
            return Ok(true);
        }

        unsafe {
            libc::kill(self.pid, libc::SIGSTOP);
        }

        let waitsig = self.waitsig(libc::SIGSTOP)?;

        Ok(waitsig)
    }

    fn cont(&mut self) -> Result<()> {
        let result = unsafe { libc::ptrace(libc::PTRACE_CONT, self.pid, 0, 0) };

        if result == -1 {
            return Err(Error::PtraceCont(errno()));
        }

        self.stopped = false;

        Ok(())
    }

    fn get_registers(&mut self) -> Result<libc::user_regs_struct> {
        let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };

        let result = unsafe { libc::ptrace(libc::PTRACE_GETREGS, self.pid, 0, &mut registers) };

        if result == -1 {
            return Err(Error::PtraceGetregs(errno()));
        }

        Ok(registers)
    }

    fn set_registers(&mut self, registers: &libc::user_regs_struct) -> Result<()> {
        let result = unsafe { libc::ptrace(libc::PTRACE_SETREGS, self.pid, 0, registers) };

        if result == -1 {
            return Err(Error::PtraceSetregs(errno()));
        }

        Ok(())
    }

    fn waitsig(&mut self, signal: i32) -> Result<bool> {
        let mut waitpid_status: i32 = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::waitpid(self.pid, &mut waitpid_status, 0) };

        if result == -1 {
            return Err(Error::Waitpid(errno()));
        }

        self.stopped = true;

        Ok(libc::WIFSTOPPED(waitpid_status) && libc::WSTOPSIG(waitpid_status) == signal)
    }
}

struct Process {
    pid: libc::pid_t,
    _ptrace: Option<Ptrace>,
    was_stopped: bool,
    mem_file: File,
}

impl Process {
    fn new(pid: libc::pid_t) -> Self {
        let mem_file_name = format!("/proc/{pid}/mem");
        let mem_file = File::options()
            .read(true)
            .write(true)
            .open(mem_file_name)
            .unwrap();

        Self {
            pid,
            _ptrace: None,
            was_stopped: false,
            mem_file,
        }
    }

    fn ptrace(&mut self) -> Result<&mut Ptrace> {
        self.was_stopped = false;
        if self._ptrace.is_none() {
            self._ptrace = Some(Ptrace::new(self.pid));
            if let Some(p) = self._ptrace.as_mut() {
                p.attach()?;
            }
        } else {
            self.was_stopped = self._ptrace.as_mut().unwrap().stopped;
            self._ptrace.as_mut().unwrap().stop()?;
        }

        return Ok(self._ptrace.as_mut().unwrap());
    }

    fn waitsig(&mut self, signal: i32) -> Result<bool> {
        if let Some(p) = self._ptrace.as_mut() {
            let result = p.waitsig(signal)?;
            return Ok(result);
        }

        Err(Error::PtraceNotInstantiated)
    }

    fn getregs(&mut self) -> Result<libc::user_regs_struct> {
        if let Some(p) = self._ptrace.as_mut() {
            let result = p.get_registers()?;
            return Ok(result);
        }

        Err(Error::PtraceNotInstantiated)
    }

    fn setregs(&mut self, registers: &libc::user_regs_struct) -> Result<()> {
        if let Some(p) = self._ptrace.as_mut() {
            p.set_registers(registers)?;
            return Ok(());
        }

        Err(Error::PtraceNotInstantiated)
    }

    fn cont(&mut self) -> Result<()> {
        if let Some(p) = self._ptrace.as_mut() {
            if !self.was_stopped {
                p.cont()?;
            }
        }

        Ok(())
    }
}

fn get_mappings(pid: i32) -> Result<Vec<String>> {
    let file_name = format!("/proc/{pid}/maps");
    let file = File::open(file_name)?;
    let buffer = BufReader::new(file);

    let lines = buffer
        .lines()
        .map(|l| l.expect("Couldn't parse line!"))
        .map(|l| l.trim().to_owned())
        .collect::<_>();

    Ok(lines)
}

fn base_address_of(pid: i32, substr: &str) -> Option<u64> {
    if let Ok(lines) = get_mappings(pid) {
        for line in lines {
            let splitted = line.split(' ').collect::<Vec<&str>>();
            if splitted.last()?.contains(substr) {
                let address_space = splitted
                    .first()
                    .to_owned()?
                    .split('-')
                    .collect::<Vec<&str>>();

                if let Ok(as_u64) = u64::from_str_radix(address_space.first()?, 16) {
                    return Some(as_u64);
                } else {
                    return None;
                }
            }
        }
    } else {
        return None;
    };

    None
}

fn get_first_executable_address(pid: i32) -> Option<u64> {
    if let Ok(lines) = get_mappings(pid) {
        for line in lines {
            let splitted = line.split(' ').collect::<Vec<&str>>();
            if splitted.get(1)?.contains('x') {
                let address_space = splitted
                    .first()
                    .to_owned()?
                    .split('-')
                    .collect::<Vec<&str>>();

                if let Ok(as_u64) = u64::from_str_radix(address_space.first()?, 16) {
                    return Some(as_u64);
                } else {
                    return None;
                }
            }
        }
    } else {
        return None;
    };

    None
}

fn file_read(file: &mut File, address: u64, n: usize) -> Vec<u8> {
    let mut bytes_vec = vec![0; n];

    file.seek(SeekFrom::Start(address)).unwrap();
    let b = file.read(&mut bytes_vec).unwrap();

    println!("Read {b} bytes");

    bytes_vec
}

fn file_write(file: &mut File, address: u64, bytes: &[u8]) {
    file.seek(SeekFrom::Start(address)).unwrap();
    let b = file.write(bytes).unwrap();

    println!("Wrote {b} bytes");
}

unsafe fn get_func_address(dlname: &str, function_name: &str) -> u64 {
    let libc_path: CString = CString::new(dlname).unwrap();
    let func_name: CString = CString::new(function_name).unwrap();

    let res = libc::dlopen(libc_path.as_ptr(), libc::RTLD_LAZY);
    let address = libc::dlsym(res, func_name.as_ptr());

    address as u64
}

fn _exec(process: &mut Process, address: u64, args: &[u64]) -> Result<u64> {
    let _ = process.ptrace()?;

    let mut regs = process.getregs()?;
    let mut regs_old: libc::user_regs_struct = unsafe { std::mem::zeroed() };

    unsafe {
        libc::memcpy(
            std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs_old),
            std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs),
            std::mem::size_of::<libc::user_regs_struct>(),
        );
    }

    regs.rax = address;
    regs.rdi = *args.first().unwrap_or(&0);
    regs.rsi = *args.get(1).unwrap_or(&0);
    regs.rdx = *args.get(2).unwrap_or(&0);
    regs.rcx = *args.get(3).unwrap_or(&0);
    regs.r8 = *args.get(4).unwrap_or(&0);
    regs.r9 = *args.get(5).unwrap_or(&0);

    process.setregs(&regs)?;

    let backup_bytes = file_read(&mut process.mem_file, regs.rip, 4);
    println!("Backup bytes: {backup_bytes:x?}");
    file_write(&mut process.mem_file, regs.rip, &[0xff, 0xd0, 0xcc, 0x00]);

    process.cont()?;

    let waitsig_res = process.waitsig(5)?;
    println!("Waitsig result: {waitsig_res}");

    regs = process.getregs()?;

    process.setregs(&regs_old)?;

    println!("New RIP: 0x{:x}", regs.rip);
    println!("Writing old RIP: 0x{:x}", regs_old.rip);
    file_write(&mut process.mem_file, regs_old.rip, &backup_bytes);

    process.cont()?;

    Ok(regs.rax)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        return Err(Error::NotEnoughArgs);
    }

    let pid: libc::pid_t = args[1].parse()?;
    let lib_path: String = args[2].parse()?;

    unsafe {
        let dlopen_address = get_func_address("libc.so.6", "dlopen");
        let malloc_address = get_func_address("libc.so.6", "malloc");
        let free_address = get_func_address("libc.so.6", "free");
        let memset_address = get_func_address("libc.so.6", "memset");

        let libc_base_addr = base_address_of(std::process::id() as i32, "libc").unwrap();

        let dlopen_offset = dlopen_address - libc_base_addr;
        let malloc_offset = malloc_address - libc_base_addr;
        let free_offset = free_address - libc_base_addr;
        let memset_offset = memset_address - libc_base_addr;

        let libc_base_addr = base_address_of(pid, "libc.so").unwrap();
        let dlopen_address = libc_base_addr + dlopen_offset;
        let malloc_address = libc_base_addr + malloc_offset;
        let free_address = libc_base_addr + free_offset;
        let memset_address = libc_base_addr + memset_offset;

        println!("dlopen addr: 0x{dlopen_address:x} | offset: 0x{dlopen_offset:x}");
        println!("malloc addr: 0x{malloc_address:x} | offset: 0x{malloc_offset:x}");
        println!("free   addr: 0x{free_address:x} | offset: 0x{free_offset:x}");

        let mut process = Process::new(pid);

        let size_to_allocate = lib_path.len() + 1;
        let allocated_address = _exec(&mut process, malloc_address, &[size_to_allocate as u64])?;
        println!("Malloc allocated address: 0x{allocated_address:x}");

        // write the filename into the address
        let path = format!("{lib_path}\0");
        let path_as_bytes = path.as_bytes();
        process
            .mem_file
            .seek(SeekFrom::Start(allocated_address))
            .unwrap();
        let written = process.mem_file.write(path_as_bytes).unwrap();
        println!("WRITTEN {written} BYTES!!");

        let result = _exec(&mut process, dlopen_address, &[allocated_address, 0x1])?;
        println!("dlopen result: 0x{result:x}");

        _exec(&mut process, free_address, &[allocated_address])?;
    }

    println!("\nArrived here!");

    Ok(())
}
