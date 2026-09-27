- push 33h followed shortly by a far return (retf) or far jump. 0x33 = 64-bit code selector, 0x23 = 32-bit.
  - The call $+5 → add [esp], 5 → retf idiom (builds a return address inline, then far-returns).
  - A 32-bit disassembler ending the function early with sp-analysis failed.
  - Long runs of dec eax (byte 0x48) inside real logic — in 64-bit mode 0x48 is a prefix, not an instruction.
  - A matching far transition back to selector 0x23 to return to 32-bit mode.

