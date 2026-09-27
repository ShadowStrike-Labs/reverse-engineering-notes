# Reverse Engineering Notes

Personal notes I keep while doing reverse engineering. Made public on the chance someone else finds them useful.

The repo is a moving target: new material gets added whenever something is worth writing down, and old entries get corrected when I realize I got them wrong. It won't ever be "complete" — mastering everything in RE isn't a realistic goal, so treating this as finished would be dishonest.

## Scope

Short, reference-style notes — recognition patterns, register maps, structure offsets, API parameter tables, tool cheat sheets, and the occasional idiom I keep forgetting. Focus is Windows x86 / x64 user-mode, with some general assembly and language-specific material (Go, C++) mixed in.

Not a tutorial. The entries assume you already know what a disassembler, PE header, and calling convention are.

## Index

Everything currently lives under [`Reverse Engineering/`](./Reverse%20Engineering).

| File | Content |
|---|---|
| [`Fundamental Notes.md`](./Reverse%20Engineering/Fundamental%20Notes.md) | Flag semantics for `TEST` / `XOR` / `AND` / `OR`, `idiv` quotient-remainder mapping, shift-as-divide, unsigned-range comparison idioms, `_bittest64` bitmask decoding, `std::to_string` leftover string. |
| [`Lengths of Different Instructions in bytes.md`](./Reverse%20Engineering/Lengths%20of%20Different%20Instructions%20in%20bytes.md) | Byte-size table for the different `call` encodings (`E8 rel32`, `FF 15 disp32`, `FF D0`, …). |
| [`Go_Language_Reversing_Tips.md`](./Reverse%20Engineering/Go_Language_Reversing_Tips.md) | Go runtime entry chain, x64 calling convention, `string` and `[]byte` layouts, common runtime helpers (`concatstring2`, `stringtoslicebyte`, `FscanLn`, …). |
| [`HASH - CRYPTO - MAGIC CONSTANT RECOGNITION PATTERNS.md`](./Reverse%20Engineering/HASH%20-%20CRYPTO%20-%20MAGIC%20CONSTANT%20RECOGNITION%20PATTERNS.md) | IVs, primes, S-box entries and quick fingerprints for MD5, SHA-1 / 256 / 512, CRC family, FNV, xxHash, MurmurHash, SipHash, RC5 / RC6, AES, ChaCha / Salsa20, plus notes on ECB vs CBC, IV, PKCS7. |
| [`Heavens Gate Recognition Patterns.md`](./Reverse%20Engineering/Heavens%20Gate%20Recognition%20Patterns.md) | Byte-level tells of 32 ↔ 64 far transitions: `push 33h` / `retf`, `call $+5` idiom, long `dec eax` runs in 64-bit mode, selector `0x23` return. |
| [`Virtualization Based Obfuscation Notes.md`](./Reverse%20Engineering/Virtualization%20Based%20Obfuscation%20Notes.md) | PC / Opcode / ByteCode terminology and the switch-driven VM shape. |
| [`x86 FS and x64 GS Tables + PEB Offsets.md`](./Reverse%20Engineering/x86%20FS%20and%20x64%20GS%20Tables%20+%20PEB%20Offsets.md) | TEB and PEB field offsets side-by-side for x86 and x64, with the anti-debug relevance of each field called out. |
| [`Ready-to-use Specific Struct Definitions For IDA-Pro.md`](./Reverse%20Engineering/Ready-to-use%20Specific%20Struct%20Definitions%20For%20IDA-Pro.md) | Copy-paste struct definitions (MSVC `std::string`, `SYSTEMTIME`, …) for IDA's Local Types. |
| [`PE-Sieve Tool Usage.md`](./Reverse%20Engineering/PE-Sieve%20Tool%20Usage.md) | Practical `pe-sieve64` invocations for unpacking, malware triage and anti-analysis processes, with every switch explained (`/dmode`, `/imp`, `/data`, `/shellc`, `/iat`, `/obfusc`, `/refl`). Also ScyllaHide injection and UPX unpack. |
| [`Specific API-Parameters And Their Meanings.md`](./Reverse%20Engineering/Specific%20API-Parameters%20And%20Their%20Meanings.md) | Register maps and constant tables for `VirtualAlloc`, `VirtualProtect`, `CreateFileA`, `fwrite`, `DllMain`, `TlsCallback`, plus the `NtGlobalFlag & 0x70` anti-debug check. |

## Companion repositories

Crackme write-ups, malware analysis and IDA Pro scripts live in separate repositories on the same account: <https://github.com/ShadowStrike-Labs>.

## A word on accuracy

These are working notes, not a textbook. Offsets, constants and behaviours are correct on the versions I checked, but Windows internals drift and compilers change their output. Verify anything critical against the actual binary and the official documentation before you rely on it. Corrections via issues are welcome.
