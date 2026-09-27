

 TEB  —  FS on x86 / GS on x64
    field                               x86     x64
    ExceptionList (SEH)       0x00    0x00
    StackBase                      0x04    0x08
    StackLimit                     0x08    0x10
    Self (TEB address)         0x18    0x30
    PID                                0x20    0x40
    TID                                0x24    0x48
    TLS pointer                   0x2C    0x58
    PEB pointer   ───────►0x30    0x60
    LastError                       0x34    0x68

  PEB  —  reached through the "PEB pointer" above
    field                             x86     x64     anti-debug meaning
    BeingDebugged          0x02    0x02    IsDebuggerPresent
    ImageBaseAddress      0x08    0x10    module base
    Ldr (module list)          0x0C    0x18    walking loaded modules
    ProcessParameters      0x10    0x20    cmdline etc.
    ProcessHeap                0x18    0x30    heap-flags anti-debug
    NtGlobalFlag                0x68    0xBC    = 0x70 under a debugger

 
