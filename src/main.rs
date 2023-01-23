use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

use libc::c_void;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum Error {
    NotEnoughArgs,

    PtraceAttachError(i32),

    FileOpen(std::io::Error),

    OutOfBounds(i32),
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

    fn attach(&mut self) -> bool {
        println!("[PTRACE] - attach");
        unsafe {
            libc::ptrace(libc::PTRACE_ATTACH, self.pid, 0, 0);
        };
        self.waitsig(libc::SIGSTOP)
    }

    fn stop(&mut self) -> bool {
        println!("[PTRACE] - stop");

        if self.stopped {
            return true;
        }

        unsafe {
            libc::kill(self.pid, libc::SIGSTOP);
        }

        self.waitsig(libc::SIGSTOP)
    }

    fn cont(&mut self) {
        println!("[PTRACE] - cont");

        unsafe {
            libc::ptrace(libc::PTRACE_CONT, self.pid, 0, 0);
        };
        self.stopped = false;
    }

    fn get_registers(&mut self) -> libc::user_regs_struct {
        let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        unsafe {
            libc::ptrace(libc::PTRACE_GETREGS, self.pid, 0, &mut registers);
        };

        registers
    }

    fn set_registers(&mut self, registers: &mut libc::user_regs_struct) {
        unsafe {
            libc::ptrace(libc::PTRACE_SETREGS, self.pid, 0, registers);
        };
    }

    fn waitsig(&mut self, signal: i32) -> bool {
        println!("[PTRACE] - waitsig");

        let mut waitpid_status = unsafe { std::mem::zeroed() };
        unsafe {
            libc::waitpid(self.pid, &mut waitpid_status, 0);
        };

        self.stopped = true;

        libc::WIFSTOPPED(waitpid_status) && libc::WSTOPSIG(waitpid_status) == signal
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
        let mem_file_name = format!("/proc/{}/mem", pid);
        let mut mem_file = File::options()
            .read(true)
            .write(true)
            .open(&mem_file_name)
            .unwrap();

        Self {
            pid,
            _ptrace: None,
            was_stopped: false,
            mem_file,
        }
    }

    fn ptrace(&mut self) -> &mut Ptrace {
        self.was_stopped = false;
        if self._ptrace.is_none() {
            self._ptrace = Some(Ptrace::new(self.pid));
            if let Some(p) = self._ptrace.as_mut() {
                p.attach();
            }
        } else {
            self.was_stopped = self._ptrace.as_mut().unwrap().stopped;
            self._ptrace.as_mut().unwrap().stop();
        }

        return self._ptrace.as_mut().unwrap();
    }

    fn cont(&mut self) {
        if let Some(p) = self._ptrace.as_mut() {
            if !self.was_stopped {
                p.cont();
            }
        }
    }
}

fn get_mappings(pid: i32) -> Result<Vec<String>> {
    let file_name = format!("/proc/{}/maps", pid);
    let file = File::open(file_name).map_err(Error::FileOpen)?;
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

unsafe fn file_read(file: &mut File, address: u64, n: usize) -> Vec<u8> {
    let mut bytes_vec = vec![0; n];

    file.seek(SeekFrom::Start(address)).unwrap();
    let b = file.read(&mut bytes_vec).unwrap();

    println!("Read {} bytes", b);

    bytes_vec
}

unsafe fn file_write(file: &mut File, address: u64, bytes: &[u8]) {
    file.seek(SeekFrom::Start(address)).unwrap();
    let b = file.write(bytes).unwrap();

    println!("Wrote {} bytes", b);
}

unsafe fn get_func_address(dlname: &str, function_name: &str) -> u64 {
    let libc_path: CString = CString::new(dlname).unwrap();
    let func_name: CString = CString::new(function_name).unwrap();

    let res = libc::dlopen(libc_path.as_ptr(), libc::RTLD_LAZY);
    let address = libc::dlsym(res, func_name.as_ptr());

    address as u64
}

unsafe fn waitsig(pid: libc::pid_t, signal: i32) -> bool {
    let mut status: i32 = std::mem::zeroed();
    if libc::waitpid(pid, &mut status, 0) == -1 {
        println!("Couldn't execute waitpid ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == signal
}

#[inline(always)]
unsafe fn _malloc(process: &mut Process, malloc_address: u64, size: u64) -> u64 {
    let _ = process.ptrace();

    let mut regs: libc::user_regs_struct = std::mem::zeroed();
    let mut regs_old: libc::user_regs_struct = std::mem::zeroed();

    if libc::ptrace(libc::PTRACE_GETREGS, process.pid, 0, &mut regs) == -1 {
        println!(
            "Error while getting registers ({})",
            *libc::__errno_location()
        );
        std::process::exit(1);
    }

    libc::memcpy(
        std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs_old),
        std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs),
        std::mem::size_of::<libc::user_regs_struct>(),
    );

    regs.rax = malloc_address;
    regs.rdi = size;
    regs.rsi = 0;
    regs.rdx = 0;
    regs.rcx = 0;
    regs.r8 = 0;
    regs.r9 = 0;

    if libc::ptrace(libc::PTRACE_SETREGS, process.pid, 0, &mut regs) == -1 {
        println!("Error setting registers ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    let backup_bytes = file_read(&mut process.mem_file, regs.rip, 4);
    println!("Backup bytes: {:x?}", backup_bytes);
    file_write(&mut process.mem_file, regs.rip, &[0xff, 0xd0, 0xcc, 0x00]);

    if libc::ptrace(libc::PTRACE_CONT, process.pid, 0, 0) == -1 {
        println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    let waitsig_res = waitsig(process.pid, 5);
    println!("Waitsig result: {}", waitsig_res);

    if libc::ptrace(libc::PTRACE_GETREGS, process.pid, 0, &mut regs) == -1 {
        println!(
            "Error while getting registers ({})",
            *libc::__errno_location()
        );
        std::process::exit(1);
    }

    if libc::ptrace(libc::PTRACE_SETREGS, process.pid, 0, &mut regs_old) == -1 {
        println!("Error setting registers ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    println!("New RIP: 0x{:x}", regs.rip);
    println!("Writing old RIP: 0x{:x}", regs_old.rip);
    file_write(&mut process.mem_file, regs_old.rip, &backup_bytes);

    if libc::ptrace(libc::PTRACE_CONT, process.pid, 0, 0) == -1 {
        println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    process.cont();

    regs.rax
}

#[inline(always)]
unsafe fn _dlopen(
    process: &mut Process,
    dlopen_address: u64,
    string_address: u64,
    flags: u32,
) -> u64 {
    let _ = process.ptrace();

    let mut regs: libc::user_regs_struct = std::mem::zeroed();
    let mut regs_old: libc::user_regs_struct = std::mem::zeroed();

    if libc::ptrace(libc::PTRACE_GETREGS, process.pid, 0, &mut regs) == -1 {
        println!(
            "Error while getting registers ({})",
            *libc::__errno_location()
        );
        std::process::exit(1);
    }

    libc::memcpy(
        std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs_old),
        std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs),
        std::mem::size_of::<libc::user_regs_struct>(),
    );

    regs.rax = dlopen_address;
    regs.rdi = string_address;
    regs.rsi = flags as u64;
    regs.rdx = 0;
    regs.rcx = 0;
    regs.r8 = 0;
    regs.r9 = 0;

    if libc::ptrace(libc::PTRACE_SETREGS, process.pid, 0, &mut regs) == -1 {
        println!("Error setting registers ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    let backup_bytes = file_read(&mut process.mem_file, regs.rip, 4);
    println!("Backup bytes: {:x?}", backup_bytes);
    file_write(&mut process.mem_file, regs.rip, &[0xff, 0xd0, 0xcc, 0x00]);

    if libc::ptrace(libc::PTRACE_CONT, process.pid, 0, 0) == -1 {
        println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    let waitsig_res = waitsig(process.pid, 5);
    println!("Waitsig result: {}", waitsig_res);

    if libc::ptrace(libc::PTRACE_GETREGS, process.pid, 0, &mut regs) == -1 {
        println!(
            "Error while getting registers ({})",
            *libc::__errno_location()
        );
        std::process::exit(1);
    }

    if libc::ptrace(libc::PTRACE_SETREGS, process.pid, 0, &mut regs_old) == -1 {
        println!("Error setting registers ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    println!("New RIP: 0x{:x}", regs.rip);
    println!("Writing old RIP: 0x{:x}", regs_old.rip);
    file_write(&mut process.mem_file, regs_old.rip, &backup_bytes);

    if libc::ptrace(libc::PTRACE_CONT, process.pid, 0, 0) == -1 {
        println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    process.cont();

    regs.rax
}

#[inline(always)]
unsafe fn _free(process: &mut Process, free_address: u64, address: u64) -> u64 {
    let _ = process.ptrace();

    let mut regs: libc::user_regs_struct = std::mem::zeroed();
    let mut regs_old: libc::user_regs_struct = std::mem::zeroed();

    if libc::ptrace(libc::PTRACE_GETREGS, process.pid, 0, &mut regs) == -1 {
        println!(
            "Error while getting registers ({})",
            *libc::__errno_location()
        );
        std::process::exit(1);
    }

    libc::memcpy(
        std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs_old),
        std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs),
        std::mem::size_of::<libc::user_regs_struct>(),
    );

    regs.rax = free_address;
    regs.rdi = address;
    regs.rsi = 0;
    regs.rdx = 0;
    regs.rcx = 0;
    regs.r8 = 0;
    regs.r9 = 0;

    if libc::ptrace(libc::PTRACE_SETREGS, process.pid, 0, &mut regs) == -1 {
        println!("Error setting registers ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    let backup_bytes = file_read(&mut process.mem_file, regs.rip, 4);
    println!("Backup bytes: {:x?}", backup_bytes);
    file_write(&mut process.mem_file, regs.rip, &[0xff, 0xd0, 0xcc, 0x00]);

    if libc::ptrace(libc::PTRACE_CONT, process.pid, 0, 0) == -1 {
        println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    let waitsig_res = waitsig(process.pid, 5);
    println!("Waitsig result: {}", waitsig_res);

    if libc::ptrace(libc::PTRACE_GETREGS, process.pid, 0, &mut regs) == -1 {
        println!(
            "Error while getting registers ({})",
            *libc::__errno_location()
        );
        std::process::exit(1);
    }

    if libc::ptrace(libc::PTRACE_SETREGS, process.pid, 0, &mut regs_old) == -1 {
        println!("Error setting registers ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    println!("New RIP: 0x{:x}", regs.rip);
    println!("Writing old RIP: 0x{:x}", regs_old.rip);
    file_write(&mut process.mem_file, regs_old.rip, &backup_bytes);

    if libc::ptrace(libc::PTRACE_CONT, process.pid, 0, 0) == -1 {
        println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        std::process::exit(1);
    }

    process.cont();

    regs.rax
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        return Err(Error::NotEnoughArgs);
    }

    let pid: libc::pid_t = args[1].parse().expect("Couldn't parse argument.");
    let lib_path: String = args[2].parse().expect("Couldn't parse argument.");

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

        println!(
            "dlopen addr: 0x{:x} | offset: 0x{:x}",
            dlopen_address, dlopen_offset
        );
        println!(
            "malloc addr: 0x{:x} | offset: 0x{:x}",
            malloc_address, malloc_offset
        );
        println!(
            "free   addr: 0x{:x} | offset: 0x{:x}",
            free_address, free_offset
        );

        let mut process = Process::new(pid);

        let size_to_allocate = lib_path.len() + 1;
        let allocated_address = _malloc(&mut process, malloc_address, size_to_allocate as u64);
        println!("Malloc allocated address: 0x{:x}", allocated_address);

        // write the filename into the address
        let path = format!("{lib_path}\0");
        let path_as_bytes = path.as_bytes();
        process
            .mem_file
            .seek(SeekFrom::Start(allocated_address))
            .unwrap();
        let written = process.mem_file.write(path_as_bytes).unwrap();
        println!("WRITTEN {written} BYTES!!");

        let result = _dlopen(&mut process, dlopen_address, allocated_address, 0x1);
        println!("dlopen result: 0x{:x}", result);

        _free(&mut process, free_address, allocated_address);

        // --*****----********--------**********-------***********---------_**********_-----------_***********_------

        // let mut ptrace = process.ptrace();

        // let mut regs: libc::user_regs_struct = std::mem::zeroed();
        // let mut regs_old: libc::user_regs_struct = std::mem::zeroed();

        // if libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) == -1 {
        //     println!(
        //         "Error while getting registers ({})",
        //         *libc::__errno_location()
        //     );
        //     std::process::exit(1);
        // }

        // libc::memcpy(
        //     std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs_old),
        //     std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs),
        //     std::mem::size_of::<libc::user_regs_struct>(),
        // );

        // regs.rax = memset_address;
        // regs.rdi = allocated_address;
        // regs.rsi = 0;
        // regs.rdx = 1024;
        // regs.rcx = 0;
        // regs.r8 = 0;
        // regs.r9 = 0;

        // if libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &mut regs) == -1 {
        //     println!("Error setting registers ({})", *libc::__errno_location());
        //     std::process::exit(1);
        // }

        // let backup_bytes = file_read(&mut process.mem_file, regs.rip, 4);
        // println!("Backup bytes: {:x?}", backup_bytes);
        // file_write(&mut process.mem_file, regs.rip, &[0xff, 0xd0, 0xcc, 0x00]);

        // if libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) == -1 {
        //     println!("Error PTRACE_CONT ({})", *libc::__errno_location());
        //     std::process::exit(1);
        // }

        // let waitsig_res = waitsig(pid, 5);
        // println!("Waitsig result: {}", waitsig_res);

        // if libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) == -1 {
        //     println!(
        //         "Error while getting registers ({})",
        //         *libc::__errno_location()
        //     );
        //     std::process::exit(1);
        // }

        // if libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &mut regs_old) == -1 {
        //     println!("Error setting registers ({})", *libc::__errno_location());
        //     std::process::exit(1);
        // }

        // println!("New RIP: 0x{:x}", regs.rip);
        // println!("Writing old RIP: 0x{:x}", regs_old.rip);
        // file_write(&mut process.mem_file, regs_old.rip, &backup_bytes);

        // process.cont();

        // println!("Malloc return address: 0x{:x}", regs.rax);
        // let allocated_address = regs.rax;

        // let malloc_address = get_func_address("libc.so.6", "malloc");
        // let free_address = get_func_address("libc.so.6", "free");
        // let dlopen_address = get_func_address("libc.so.6", "dlopen");

        // println!("Malloc address: 0x{:x}", malloc_address);
        // println!("Free address: 0x{:x}", free_address);
        // println!("Dlopen address: 0x{:x}", dlopen_address);

        // let libc_base_addr = base_address_of(std::process::id() as i32, "libc").unwrap();
        // println!("Libc base address: 0x{:x}", libc_base_addr);

        // println!("Malloc offset: 0x{:x}", (malloc_address - libc_base_addr));
        // println!("Free offset: 0x{:x}", (free_address - libc_base_addr));
        // println!("Dlopen offset: 0x{:x}", (dlopen_address - libc_base_addr));

        // let libc_base_addr_remote = base_address_of(pid, "libc").unwrap();
        // println!("Remote libc base address: 0x{:x}", libc_base_addr_remote);
        // println!(
        //     "Remote Malloc location: 0x{:x}",
        //     (libc_base_addr_remote + (malloc_address - libc_base_addr))
        // );
        // println!(
        //     "Remote Free location: 0x{:x}",
        //     (libc_base_addr_remote + (free_address - libc_base_addr))
        // );
        // println!(
        //     "Remote Dlopen location: 0x{:x}",
        //     (libc_base_addr_remote + (dlopen_address - libc_base_addr))
        // );

        // println!("");

        // // ptrace_attach
        // if libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) == -1 {
        //     println!("Error PTRACE_ATTACH: {}", *libc::__errno_location());
        //     std::process::exit(1);
        // }
        // println!("PTRACE_ATTACH successful");

        // // waitpid
        // libc::waitpid(pid, 0 as *mut i32, libc::WUNTRACED);
        // println!("WAITPID successful");

        // let mut regs: libc::user_regs_struct = std::mem::zeroed();
        // let mut regs_old: libc::user_regs_struct = std::mem::zeroed();

        // if libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) == -1 {
        //     println!("Error PTRACE_GETREGS: {}", *libc::__errno_location());
        //     std::process::exit(1);
        // }

        // libc::memcpy(
        //     std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs_old),
        //     std::mem::transmute::<*mut libc::user_regs_struct, *mut libc::c_void>(&mut regs),
        //     std::mem::size_of::<libc::user_regs_struct>(),
        // );

        // let x_addr = get_first_executable_address(pid).unwrap();
        // println!("Found address: 0x{:x}", x_addr);

        // regs.rip = x_addr + 2;
        // println!("New RIP: 0x{:x}", regs.rip);
    }

    // unsafe {
    //     let mut buffer = vec![u8::default(); 16];

    //     let local_iov = libc::iovec {
    //         iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
    //         iov_len: buffer.len() * std::mem::size_of::<u8>(),
    //     };

    //     let remote_iov = libc::iovec {
    //         iov_base: 0x668250 as *mut libc::c_void,
    //         iov_len: buffer.len() * std::mem::size_of::<u8>(),
    //     };

    //     libc::process_vm_readv(
    //         pid,
    //         &local_iov as *const _,
    //         1,
    //         &remote_iov as *const _,
    //         1,
    //         0,
    //     );

    //     println!("Buffer: {:02X?}", buffer);
    // }

    // unsafe {
    //     let mut buffer = vec![0x90, 0x90];

    //     let local_iov = libc::iovec {
    //         iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
    //         iov_len: buffer.len() * std::mem::size_of::<u8>(),
    //     };

    //     let remote_iov = libc::iovec {
    //         iov_base: (0x668250 + 23) as *mut libc::c_void,
    //         iov_len: buffer.len() * std::mem::size_of::<u8>(),
    //     };

    //     let result = libc::process_vm_writev(
    //         pid,
    //         &local_iov as *const _,
    //         1,
    //         &remote_iov as *const _,
    //         1,
    //         0,
    //     );

    //     println!("Result: {} ({})", result, *libc::__errno_location());
    // }

    println!("\nArrived here!");

    Ok(())
}
