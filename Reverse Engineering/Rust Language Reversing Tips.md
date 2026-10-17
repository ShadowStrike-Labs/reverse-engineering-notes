 - Entry = __scrt_common_main_seh (MSVC CRT)
 - main is a 1–2-line shim that calls std::rt::lang_start_internal
 - lang_start_internal ALWAYS has AddVectoredExceptionHandler + SetThreadStackGuarantee(20480) — this is Rust's
   stack-overflow panic plumbing
 -  There's typically ONE TLS callback for thread-local destructors
 - __eh34_* SEH intrinsics everywhere = MSVC-style EH used by Rust's unwinding
 -  Panic calls to core::panicking::* scattered throughout = THE Rust fingerprint


- At Rust Language the program has 2 main functions. 1 for the author's main function and the other lang_start main function that is created by the rust language itself. The author's main function gets stored at the RCX register of the lang_start function as lang_start(main_func,......(other parameters here)). 
- Also in the rust-written binaries rust compiler adds one TLS callback for running the destructors of thread_local! variables.
  