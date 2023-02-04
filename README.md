# Shared Object Injector

This is a small Rust program that injects a shared object in a running x64 process.


The code is based on a Python implementation of a similar program by [danielfvm](https://github.com/danielfvm/memmod).

# Brief Explanation

How does this actually inject a shared object in a running process?

1. Ptrace attach to process;
2. The process will stop and we get its current state by getting the registers values;
3. We create a new registers object that will hold the to-execute function's values like address and arguments;
4. We save the next 4 bytes in RIP;
5. At the same time, we change the code in the current RIP to `\xff\xd0\xcc\x00`, which, in x64 Assembly translates to:

```asm
call rax
int3
```

6. We instruct ptrace to continue and the function call above will execute and then the process will stop again;
7. After the process stops, we get the registers once again, to get the return value (from `rax`);
8. We then set the registers to the old ones and the 4 bytes we replaced will also be reinstated;
9. Instruct ptrace to continue the process;
