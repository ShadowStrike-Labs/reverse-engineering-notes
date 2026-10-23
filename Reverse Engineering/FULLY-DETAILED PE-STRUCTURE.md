================================================================================
                PE / COFF FORMAT - COMPLETE BYTE-LEVEL REFERENCE
                   for reverse engineering (IDA / GHidra / x64dbg)
================================================================================

HOW TO USE THIS FILE
  You see  *(TYPE *)(ptr + NUMBER)  in IDA and want to know what NUMBER is:
    - if ptr is the module base / MZ base  -> section 2 (DOS) and section 30
    - if ptr is the NT header (base+e_lfanew) -> SECTION 9 REVERSE LOOKUP TABLE
    - if ptr is a struct inside a directory  -> sections 12..28
  Every offset is given in hex AND decimal. Sizes are in bytes.
  "RVA" = offset from the module base once mapped. "VA" = absolute address.
  "raw"/"file offset" = offset inside the file on disk. These are NOT the same.

NOTATION
  NT+X     = (module base + e_lfanew) + X          <- the most useful anchor
  OH+X     = optional header + X = NT+0x18+X
  DD[n]    = DataDirectory entry n
  x86/PE32 = 32-bit image, Magic 0x10B
  x64/PE32+= 64-bit image, Magic 0x20B
  [!]      = classic trap / where tools and the real loader disagree
  [PACK]   = frequently abused by packers/protectors

================================================================================
TABLE OF CONTENTS
================================================================================
  PART I - HEADERS
   1. File layout map (disk vs memory)
   2. IMAGE_DOS_HEADER                        base+0x00, 0x40 bytes
   3. DOS stub                                base+0x40
   4. Rich header (MSVC provenance)           between stub and PE sig
   5. IMAGE_NT_HEADERS / Signature            base+e_lfanew
   6. IMAGE_FILE_HEADER (COFF)                NT+0x04, 20 bytes
   7. IMAGE_OPTIONAL_HEADER32                 NT+0x18, 0xE0 bytes
   8. IMAGE_OPTIONAL_HEADER64                 NT+0x18, 0xF0 bytes
   9. REVERSE LOOKUP: every NT+X offset, both bitnesses   <<<<<< START HERE
  10. Data directory master table (all 16)
  11. IMAGE_SECTION_HEADER + all characteristics

  PART II - DIRECTORIES
  12. DD[0]  Export
  13. DD[1]  Import  (+ INT/IAT/thunks/ordinals)
  14. DD[2]  Resource
  15. DD[3]  Exception (.pdata/.xdata, x64 UNWIND_INFO, ARM64, x86 SEH)
  16. DD[4]  Security / Authenticode           [!] file offset, not RVA
  17. DD[5]  Base relocations
  18. DD[6]  Debug (all 22 types + payloads)
  19. DD[7]  Architecture
  20. DD[8]  Global pointer
  21. DD[9]  TLS
  22. DD[10] Load config (CFG/SafeSEH, full field map, size versioning)
  23. DD[11] Bound imports
  24. DD[12] IAT
  25. DD[13] Delay import                      <- the one you were chasing
  26. DD[14] CLR / .NET
  27. DD[15] Reserved
  28. Dynamic value relocs / ARM64X / CHPE

  PART III - MECHANICS
  29. RVA <-> file offset, alignment, low-alignment images, overlay
  30. What the Windows loader actually does, in order
  31. Loader validation: what is rejected, what is tolerated
  32. OptionalHeader.CheckSum algorithm
  33. COFF symbol table, string table, COFF relocations, line numbers
  34. Packer / anti-analysis header anomaly cheat sheet
  35. Magic values and signatures index

  PART IV - APPENDICES (in-memory structures, kept from the old notes)
  A1. TEB / PEB / loader lists
  A2. EXCEPTION_RECORD / CONTEXT
  A3. Calling conventions
  A4. IDA tips, offset arithmetic, IAT range recovery


================================================================================
1. FILE LAYOUT MAP
================================================================================
ON DISK (file offsets)                       IN MEMORY (RVA, after mapping)
  0x00  IMAGE_DOS_HEADER (0x40)                0x00  same headers, one page+,
  0x40  DOS stub (16-bit code + message)             read-only, size =
  ~0x80 Rich header (MSVC only)                      SizeOfHeaders rounded up
  e_lfanew:                                          to SectionAlignment
        "PE\0\0"                               |
        IMAGE_FILE_HEADER (20)                 |  each section mapped at
        IMAGE_OPTIONAL_HEADER (0xE0/0xF0)      |  its VirtualAddress,
          incl. DataDirectory[16] (128)        |  zero-filled up to
        IMAGE_SECTION_HEADER * N (40 each)     |  VirtualSize
  pad to FileAlignment                         |
  SizeOfHeaders:                               |  gaps between sections are
        section 1 raw data                     |  zero pages
        pad to FileAlignment                   |
        section 2 raw data ...                 |  total span = SizeOfImage
  (optional) COFF symbols, .dbg, cert table,
             overlay / appended payload        (none of this is mapped)

KEY CONSEQUENCE: the headers are mapped at RVA 0. So in a running process
  moduleBase + e_lfanew  ->  NT headers, always readable.
  On disk you must convert every RVA (section 29) - EXCEPT in low-alignment
  images where RVA == file offset (section 29.4). [PACK]


================================================================================
2. IMAGE_DOS_HEADER                     base + 0x00, exactly 0x40 = 64 bytes
================================================================================
HEX   DEC  SIZE  FIELD          MEANING (MZ / DOS semantics)
0x00  0    2     e_magic        0x5A4D = "MZ". Required by the loader.
0x02  2    2     e_cblp         bytes used on last 512-byte page (MSVC 0x90)
0x04  4    2     e_cp           number of 512-byte pages in the DOS image (3)
0x06  6    2     e_crlc         DOS relocation entry count (0)
0x08  8    2     e_cparhdr      DOS header size in 16-byte paragraphs (4 = 0x40)
0x0A  10   2     e_minalloc     min extra paragraphs needed (0)
0x0C  12   2     e_maxalloc     max extra paragraphs needed (0xFFFF)
0x0E  14   2     e_ss           initial SS, relative (0)
0x10  16   2     e_sp           initial SP (0xB8)
0x12  18   2     e_csum         DOS checksum, always 0 in practice
0x14  20   2     e_ip           initial IP (0)
0x16  22   2     e_cs           initial CS, relative (0)
0x18  24   2     e_lfarlc       file offset of DOS reloc table (0x40)
0x1A  26   2     e_ovno         overlay number (0)
0x1C  28   8     e_res[4]       reserved, 4 words, zero
0x24  36   2     e_oemid        OEM identifier
0x26  38   2     e_oeminfo      OEM info
0x28  40   20    e_res2[10]     reserved, 10 words, zero
0x3C  60   4     e_lfanew       LONG. FILE OFFSET of "PE\0\0".  <<< THE FIELD

Only TWO fields matter to the NT loader: e_magic (0x00) and e_lfanew (0x3C).
Everything else is DOS-era decoration and is ignored - which is why it is
free real estate for packers, watermarks and stego. [PACK]

Standard MSVC bytes (verbatim, e.g. C:\Windows\System32\notepad.exe):
  0000: 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
  0010: B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
  0020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0030: 00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00   e_lfanew = 0xF8

TYPICAL e_lfanew VALUES (measured over 600 System32 DLLs):
  0x100 (176x)  0x108 (133x)  0x0F8 (102x)  0x110 (83x)  0x0F0 (49x)
  0x0E8 (14x)   0x0B0 (13x)   0x0D8 (10x)   0x0B8/0x118 (5x)  0x080 (3x)
  All observed values are multiples of 8. 0x80 means "no Rich header".
  0xB0-0xE0 = older MSVC (VC6/VC7). 0xE8-0x118 = VS2015..VS2022.
  ANOMALY: 0x04, 0x40, values > 0x1000, or anything not 4-aligned. [PACK]

  0x3C is famously written in shellcode as 0xF * sizeof(DWORD).


================================================================================
3. DOS STUB                                     base + 0x40 .. e_lfanew
================================================================================
Real 16-bit MS-DOS code that prints a message and exits. Never executed by
Windows. Standard MSVC stub is exactly 0x40 bytes (0x40..0x7F):

  0040: 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
  0050: 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
  0060: 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20
  0070: 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00

Disassembly of the 14 code bytes:
  0E              push cs
  1F              pop  ds
  BA 0E 00        mov  dx, 0x0E        ; DS:DX -> message (stub-relative 0x0E)
  B4 09           mov  ah, 9           ; DOS: write string
  CD 21           int  0x21
  B8 01 4C        mov  ax, 0x4C01      ; DOS: exit(1)
  CD 21           int  0x21
Message at stub+0x0E, 43 = 0x2B bytes (file offsets 0x4E..0x78 inclusive):
  "This program cannot be run in DOS mode." 0D 0D 0A 24
  Note the doubled CR (0D 0D 0A), then '$' = DOS string terminator.

FINGERPRINTING VALUE
  MinGW/GCC, Delphi, Borland, Go, Rust-with-lld, nasm and every packer use a
  different stub or none. A non-MSVC stub combined with an MSVC-looking Rich
  header is a contradiction worth chasing. Some samples put a real dual-mode
  MZ program, a decryptor, or a config blob here. [PACK]


================================================================================
4. RICH HEADER                        after the DOS stub, before "PE\0\0"
================================================================================
Undocumented MSVC linker artifact. No header field points to it - you scan
for it. Canonically starts at 0x80. Everything except the 'Rich' marker and
the key dword is XORed with one 32-bit key.

OFF  SIZE  CONTENT
+00  4     0x536E6144 ('DanS')  XOR key      <- encrypted signature
+04  4     0x00000000 XOR key   == key       }
+08  4     0x00000000 XOR key   == key       } 3 padding dwords, each == key
+0C  4     0x00000000 XOR key   == key       }
+10  8*N   entries:  DWORD CompID XOR key
                     DWORD Count  XOR key
...  4     0x68636952 ('Rich')  PLAINTEXT    <- scan for this
...  4     key                  PLAINTEXT
...  0..15 zero padding up to e_lfanew

  CompID = (ProdID << 16) | BuildID
    ProdID  = which MS tool produced the input (compiler / linker / masm /
              cvtres / import-lib stub)
    BuildID = that tool's build number, e.g. 0x8179 = 33145
    Count   = how many object files/records came from that exact tool build.
              For ProdID 0x0001 ("Import0") Count = number of imported symbols.

HOW TO FIND IT
  1. search 0x68636952 between 0x40 and e_lfanew
  2. key = the dword immediately after it
  3. walk backwards in 4-byte steps until (raw ^ key) == 0x536E6144
  Alternative tell: three identical raw dwords equal to the key.

REAL DECODE - notepad.exe, key = 0xA4531774, DanS@0x80, Rich@0xE8, 11 entries
  (0x80 + 0x10 + 11*8 = 0xE8, checks out)
  raw@0x80: 30 76 3D F7 | 74 17 53 A4 | 74 17 53 A4 | 74 17 53 A4
            0xF73D7630 ^ 0xA4531774 = 0x536E6144 = 'DanS'
  +10 CompID 0x00937809 Count 0x5E   ProdID 0x0093 build 30729, 94 objects
  +18 CompID 0x00000000 Count 0x01
  +20 CompID 0x01048179 Count 0x0B   ProdID 0x0104 build 33145
  +28 CompID 0x01038179 Count 0x05
  +30 CompID 0x01058179 Count 0x1F
  +38 CompID 0x01018179 Count 0x07
  +40 CompID 0x00010000 Count 0x564  Import0 -> 1380 records pulled from
                                     import libraries. NOTE: this is far more
                                     than notepad's actual import count, so
                                     read it as "import-library records", not
                                     "APIs imported" - the exact meaning is
                                     community interpretation, like the
                                     ProdID names below.
  +48 CompID 0x01088179 Count 0x1C
  +50 CompID 0x00FD8179 Count 0x01
  +58 CompID 0x00FF8179 Count 0x01
  +60 CompID 0x01028179 Count 0x01

KEY == CHECKSUM OF THE DOS HEADER + STUB + ENTRIES
Verified to reproduce the stored key on notepad.exe (0xA4531774),
cmd.exe (0xD7965A3A), kernel32.dll (0x54F34DDD), ntdll.dll (0x03CAD0BC):

  rol32(v,n) = 32-bit rotate left by (n mod 32)

  key = dansOffset                       # seed = file offset of DanS (0x80)
  for i in 0 .. dansOffset-1:            # DOS header + DOS stub bytes
      if 0x3C <= i <= 0x3F: continue     # e_lfanew is EXCLUDED on purpose
      key = (key + rol32(file[i], i mod 32)) & 0xFFFFFFFF
  for each decoded (CompID, Count):
      key = (key + rol32(CompID, Count mod 32)) & 0xFFFFFFFF
  # the 3 padding dwords and the 'Rich'/key dwords are NOT summed

WHY YOU CARE
  * The key authenticates the DOS header, the DOS stub, and every entry. Any
    tool that patches the stub, moves the PE header or edits an entry without
    recomputing it leaves a mismatch = hard tamper evidence. [PACK]
  * e_lfanew is excluded so the linker can patch it afterwards.
  * link /EMITTOOLVERSIONINFO:NO (VS2019+) omits the Rich header entirely, so
    absence alone is not suspicious for non-MS toolchains.
  * It sits outside every section, so it survives most packers -> excellent
    family-clustering / provenance artifact.
  * Common ProdIDs: 0x0000 Unknown, 0x0001 Import0, 0x0002 Linker510,
    0x0004 Linker600, 0x0006 Cvtres500, 0x000A Utc12_C, 0x000B Utc12_CPP,
    0x000D VisualBasic60, 0x000E Masm613, 0x000F Masm710, 0x0010 Linker511,
    0x0019 Implib700, 0x001C Utc13_C, 0x001D Utc13_CPP, 0x001E Linker610.
    0x0093 / 0x00FD / 0x00FF / 0x0101-0x0108 = VS2015..VS2022 era; exact
    names come from community tables (pefile prodids), not from Microsoft.


================================================================================
5. IMAGE_NT_HEADERS                             base + e_lfanew
================================================================================
HEX   DEC  SIZE  FIELD
0x00  0    4     Signature       0x00004550 = "PE\0\0"
0x04  4    20    FileHeader      IMAGE_FILE_HEADER, section 6
0x18  24   var   OptionalHeader  size = FileHeader.SizeOfOptionalHeader

  sizeof(IMAGE_NT_HEADERS32) = 0xF8 = 248     (4 + 20 + 0xE0)
  sizeof(IMAGE_NT_HEADERS64) = 0x108 = 264    (4 + 20 + 0xF0)

Section table starts at   NT + 0x18 + SizeOfOptionalHeader
  standard: PE32 -> NT+0xF8,  PE32+ -> NT+0x108
  [!] The loader honors ANY SizeOfOptionalHeader. Setting it to a non-standard
  value desynchronizes naive parsers from the real section table. [PACK]

From here on, all offsets are written NT+X.


================================================================================
6. IMAGE_FILE_HEADER (COFF header)              NT+0x04, 20 = 0x14 bytes
================================================================================
SELF  NT       DEC  SIZE  FIELD
0x00  NT+0x04  4    2     Machine
0x02  NT+0x06  6    2     NumberOfSections
0x04  NT+0x08  8    4     TimeDateStamp
0x08  NT+0x0C  12   4     PointerToSymbolTable    [!] FILE OFFSET, not RVA
0x0C  NT+0x10  16   4     NumberOfSymbols
0x10  NT+0x14  20   2     SizeOfOptionalHeader
0x12  NT+0x16  22   2     Characteristics

--- 6.1 Machine (IMAGE_FILE_MACHINE_*) - complete ---
0x0000 UNKNOWN        any machine / bigobj marker
0x0001 TARGET_HOST    "interacts with the host, not emulated" (header only)
0x014C I386           Intel 386+
0x014D I860           legacy
0x0160 R3000BE        MIPS big-endian  (docs only, not in winnt.h)
0x0162 R3000          MIPS little-endian
0x0166 R4000          MIPS little-endian
0x0168 R10000         MIPS little-endian
0x0169 WCEMIPSV2      MIPS little-endian WCE v2
0x0184 ALPHA          Alpha AXP
0x01A2 SH3            Hitachi SH3
0x01A3 SH3DSP         Hitachi SH3 DSP
0x01A4 SH3E           (header only)
0x01A6 SH4            Hitachi SH4
0x01A8 SH5            Hitachi SH5
0x01C0 ARM            ARM little-endian
0x01C2 THUMB / ARMV7  Thumb / ARMv7 Thumb-2
0x01C4 ARMNT          ARM Thumb-2 little-endian (Windows RT / WinPhone)
0x01D3 AM33           Matsushita AM33
0x01F0 POWERPC        PowerPC little-endian
0x01F1 POWERPCFP      PowerPC with FP
0x0200 IA64           Intel Itanium
0x0266 MIPS16
0x0284 ALPHA64/AXP64  Alpha 64-bit
0x0366 MIPSFPU
0x0466 MIPSFPU16
0x0520 TRICORE        Infineon (header only)
0x0CEF CEF            (header only)
0x0EBC EBC            EFI byte code
0x3A64 CHPE_X86       x86-on-ARM64 compiled-hybrid (km\ntimage.h)
0x5032 RISCV32        (docs only)
0x5064 RISCV64        (docs only)
0x5128 RISCV128       (docs only)
0x6232 LOONGARCH32    (docs only)
0x6264 LOONGARCH64    (docs only)
0x8664 AMD64          x64
0x9041 M32R           Mitsubishi M32R little-endian
0xA641 ARM64EC        ARM64 emulation-compatible (km\ntimage.h)
0xA64E ARM64X         ARM64 + ARM64EC in one image (km\ntimage.h)
0xAA64 ARM64          ARM64 little-endian
0xC0EE CEE            (header only)
  Note: winnt.h and learn.microsoft.com do NOT agree. RISCV*/LOONGARCH* are
  documented but absent from the SDK headers; TARGET_HOST/SH3E/TRICORE/CEF/CEE
  are in the headers but absent from the docs.

--- 6.2 Characteristics (IMAGE_FILE_*) - all 16 bits ---
0x0001 RELOCS_STRIPPED         no base relocs -> must load at ImageBase
0x0002 EXECUTABLE_IMAGE        valid executable (clear = object/not runnable)
0x0004 LINE_NUMS_STRIPPED      deprecated, should be 0
0x0008 LOCAL_SYMS_STRIPPED     deprecated, should be 0
0x0010 AGGRESIVE_WS_TRIM       obsolete (winnt.h really spells it with one S)
0x0020 LARGE_ADDRESS_AWARE     >2GB user VA (mandatory-ish on x64)
0x0040 (reserved, no name)
0x0080 BYTES_REVERSED_LO       obsolete big-endian marker
0x0100 32BIT_MACHINE           32-bit word machine
0x0200 DEBUG_STRIPPED          debug info moved to a .DBG file
0x0400 REMOVABLE_RUN_FROM_SWAP copy to swap if launched from removable media
0x0800 NET_RUN_FROM_SWAP       copy to swap if launched from the network
0x1000 SYSTEM                  system file (driver), not a user program
0x2000 DLL                     this is a DLL
0x4000 UP_SYSTEM_ONLY          uniprocessor only
0x8000 BYTES_REVERSED_HI       obsolete big-endian marker
  Typical: EXE x64 0x0022, DLL x64 0x2022, EXE x86 0x0102/0x0103,
           driver 0x0102|0x1000.

--- 6.3 TimeDateStamp ---
  32-bit time_t, seconds since 1970-01-01 UTC, LOW byte first.
  [!] With link /Brepro this field is NOT a date - it is a hash of the build
  inputs. Measured: 299 of 600 System32 DLLs have "future" timestamps
  (mssrch.dll 0x9E47342D -> 2054, RuntimeDeviceInstall.dll 0xD20B622C -> 2081).
  The reliable marker for a reproducible build is a DEBUG directory entry of
  Type 16 (IMAGE_DEBUG_TYPE_REPRO), section 18.
  RULE: future stamp + REPRO entry = benign. Future stamp, no REPRO = look.
  0 = deliberately stripped or produced by a packer.

--- 6.4 PointerToSymbolTable / NumberOfSymbols ---
  Both should be 0 in an image. Non-zero in an image means a COFF symbol
  table survived (link /DEBUGTYPE:COFF) or a packer stashed data. The pointer
  is a RAW FILE OFFSET and often lands outside every section - tools that
  treat it as an RVA go off the rails. See section 33. [PACK]


================================================================================
7. IMAGE_OPTIONAL_HEADER32                      NT+0x18, 0xE0 = 224 bytes
================================================================================
Discriminate on the first WORD:  0x10B PE32 | 0x20B PE32+ | 0x107 ROM

OH    NT       DEC  SIZE  FIELD
0x00  NT+0x18  24   2     Magic = 0x010B
0x02  NT+0x1A  26   1     MajorLinkerVersion
0x03  NT+0x1B  27   1     MinorLinkerVersion
0x04  NT+0x1C  28   4     SizeOfCode
0x08  NT+0x20  32   4     SizeOfInitializedData
0x0C  NT+0x24  36   4     SizeOfUninitializedData
0x10  NT+0x28  40   4     AddressOfEntryPoint      RVA (0 allowed for DLLs)
0x14  NT+0x2C  44   4     BaseOfCode               RVA of the code section
0x18  NT+0x30  48   4     BaseOfData               <- PE32 ONLY
0x1C  NT+0x34  52   4     ImageBase                4 bytes here
0x20  NT+0x38  56   4     SectionAlignment
0x24  NT+0x3C  60   4     FileAlignment
0x28  NT+0x40  64   2     MajorOperatingSystemVersion
0x2A  NT+0x42  66   2     MinorOperatingSystemVersion
0x2C  NT+0x44  68   2     MajorImageVersion
0x2E  NT+0x46  70   2     MinorImageVersion
0x30  NT+0x48  72   2     MajorSubsystemVersion
0x32  NT+0x4A  74   2     MinorSubsystemVersion
0x34  NT+0x4C  76   4     Win32VersionValue        must be 0
0x38  NT+0x50  80   4     SizeOfImage
0x3C  NT+0x54  84   4     SizeOfHeaders
0x40  NT+0x58  88   4     CheckSum
0x44  NT+0x5C  92   2     Subsystem
0x46  NT+0x5E  94   2     DllCharacteristics
0x48  NT+0x60  96   4     SizeOfStackReserve
0x4C  NT+0x64  100  4     SizeOfStackCommit
0x50  NT+0x68  104  4     SizeOfHeapReserve
0x54  NT+0x6C  108  4     SizeOfHeapCommit
0x58  NT+0x70  112  4     LoaderFlags              must be 0
0x5C  NT+0x74  116  4     NumberOfRvaAndSizes      normally 16
0x60  NT+0x78  120  128   DataDirectory[16]        <<< PE32 directory table


================================================================================
8. IMAGE_OPTIONAL_HEADER64                      NT+0x18, 0xF0 = 240 bytes
================================================================================
OH    NT       DEC  SIZE  FIELD
0x00  NT+0x18  24   2     Magic = 0x020B
0x02  NT+0x1A  26   1     MajorLinkerVersion
0x03  NT+0x1B  27   1     MinorLinkerVersion
0x04  NT+0x1C  28   4     SizeOfCode
0x08  NT+0x20  32   4     SizeOfInitializedData
0x0C  NT+0x24  36   4     SizeOfUninitializedData
0x10  NT+0x28  40   4     AddressOfEntryPoint
0x14  NT+0x2C  44   4     BaseOfCode
0x18  NT+0x30  48   8     ImageBase                <- 8 bytes, NO BaseOfData
0x20  NT+0x38  56   4     SectionAlignment
0x24  NT+0x3C  60   4     FileAlignment
0x28  NT+0x40  64   2     MajorOperatingSystemVersion
0x2A  NT+0x42  66   2     MinorOperatingSystemVersion
0x2C  NT+0x44  68   2     MajorImageVersion
0x2E  NT+0x46  70   2     MinorImageVersion
0x30  NT+0x48  72   2     MajorSubsystemVersion
0x32  NT+0x4A  74   2     MinorSubsystemVersion
0x34  NT+0x4C  76   4     Win32VersionValue
0x38  NT+0x50  80   4     SizeOfImage
0x3C  NT+0x54  84   4     SizeOfHeaders
0x40  NT+0x58  88   4     CheckSum
0x44  NT+0x5C  92   2     Subsystem
0x46  NT+0x5E  94   2     DllCharacteristics
0x48  NT+0x60  96   8     SizeOfStackReserve       <- 8 bytes from here on
0x50  NT+0x68  104  8     SizeOfStackCommit
0x58  NT+0x70  112  8     SizeOfHeapReserve
0x60  NT+0x78  120  8     SizeOfHeapCommit
0x68  NT+0x80  128  4     LoaderFlags
0x6C  NT+0x84  132  4     NumberOfRvaAndSizes
0x70  NT+0x88  136  128   DataDirectory[16]        <<< PE32+ directory table

--- 8.1 THE ONLY DIFFERENCES BETWEEN PE32 AND PE32+ ---
  NT+0x18 .. NT+0x2F   IDENTICAL
  NT+0x30              PE32: BaseOfData(4) + ImageBase(4)
                       PE32+: ImageBase(8)
  NT+0x38 .. NT+0x5F   IDENTICAL  (this is why CheckSum is always NT+0x58
                                   and Subsystem always NT+0x5C)
  NT+0x60 onward       stack/heap fields are 4 vs 8 bytes -> everything after
                       shifts by exactly 0x10, so DataDirectory moves from
                       NT+0x78 to NT+0x88.

--- 8.2 ROM image (Magic 0x0107) ---
IMAGE_ROM_OPTIONAL_HEADER, 56 = 0x38 bytes, not loadable by Windows:
  0x00 2 Magic=0x107 | 0x02 1 MajorLinkerVersion | 0x03 1 MinorLinkerVersion
  0x04 4 SizeOfCode | 0x08 4 SizeOfInitializedData
  0x0C 4 SizeOfUninitializedData | 0x10 4 AddressOfEntryPoint
  0x14 4 BaseOfCode | 0x18 4 BaseOfData | 0x1C 4 BaseOfBss
  0x20 4 GprMask | 0x24 16 CprMask[4] | 0x34 4 GpValue

--- 8.3 Field semantics you actually need ---
MajorLinkerVersion.MinorLinkerVersion
  MSVC: 14.x = VS2015..VS2022 (0x0E). 6.0 = VC6. 2.25/2.50 = older MinGW ld.
  Packers historically wrote their own values. Compare against the Rich header.
SizeOfCode / SizeOfInitializedData / SizeOfUninitializedData
  Sums of section sizes by class. Informational; the loader does not use them.
  SizeOfCode == 0 in something that clearly runs code is an anomaly. [PACK]
AddressOfEntryPoint
  RVA, not VA. Real address = ImageBase + AddressOfEntryPoint (or the actual
  load base after relocation). For a DLL, 0 is legal and means "no DllMain"
  (normal for resource-only DLLs). For an EXE, 0 means "execute the MZ bytes";
  4D 5A decodes as dec ebp / pop edx on x86. XP-era loaders ran it, modern
  Windows rejects it. TLS callbacks run BEFORE this - section 21.
BaseOfCode / BaseOfData
  RVA of the first code / first data section. Informational.
ImageBase
  Preferred load address, must be a multiple of 0x10000 (64 KB).
  Defaults: EXE x86 0x00400000, EXE x64 0x140000000, DLL x86 0x10000000,
  DLL x64 0x180000000, drivers 0x10000. With ASLR the real base differs; the
  in-memory difference (actualBase - ImageBase) is the relocation delta.
SectionAlignment / FileAlignment
  See section 29. FileAlignment: power of 2, 0x200..0x10000.
  SectionAlignment >= FileAlignment, normally 0x1000 (one page).
  If SectionAlignment < 0x1000 then FileAlignment MUST EQUAL it -> the image
  is mapped flat and RVA == file offset. [PACK]
Major/MinorOperatingSystemVersion, Major/MinorImageVersion
  Cosmetic. The loader ignores them.
Major/MinorSubsystemVersion
  ENFORCED. This is the real "minimum Windows version". 4.00 = NT4/95,
  5.00 = 2000, 5.01 = XP, 5.02 = Server 2003, 6.00 = Vista, 6.01 = Win7,
  6.02 = Win8, 6.03 = Win8.1, 10.00 = Win10/11. Too high -> refuses to run.
Win32VersionValue
  Must be 0. If non-zero it overrides the values PEB reports for
  OSMajorVersion/OSMinorVersion/OSBuildNumber -> a cheap way to fool
  version checks inside the process. Non-zero = anomaly. [PACK]
SizeOfImage
  Total bytes the image occupies in memory, rounded up to SectionAlignment.
  Must cover the headers and every section. This is how much VA the loader
  reserves. Compare with the aligned end of the last section; a mismatch is
  a packer/dumper tell.
SizeOfHeaders
  DOS header + stub + NT headers + section table, rounded UP to FileAlignment.
  Equals the file offset where the first section's raw data begins.
  Measured System32: 0x1000 (513 files), 0x400 (84), 0x200 (3).
CheckSum
  Section 32. Enforced for kernel drivers, boot-time images and DLLs loaded
  into critical system processes; NOT enforced for ordinary user EXEs/DLLs.
  Measured: 0 of 600 System32 DLLs have CheckSum == 0, so a zero/stale
  checksum on a file that claims to be a Microsoft binary means it was
  patched or rebuilt after signing. [PACK]
SizeOfStackReserve / Commit, SizeOfHeapReserve / Commit
  Main-thread stack and default-heap reserve/commit. Defaults 0x100000 /
  0x1000. Only meaningful for an EXE.
LoaderFlags
  Must be 0. Historically a "break on load / debug on load" hint.
NumberOfRvaAndSizes
  Number of valid DataDirectory entries. Normally 16 (measured 16/16 on
  600/600 System32 DLLs).
  [!] RtlImageDirectoryEntryToData returns NULL when index >= this value, so a
  small value HIDES directories from the loader as well as from your tools:
  set it to 0 and imports/relocs/TLS are ignored; set it to 2 and only
  EXPORT+IMPORT are visible. Values > 16 are tolerated and the extra entries
  physically overlap the section table, but the loader clamps its own use to
  16 and the section table does NOT move (only SizeOfOptionalHeader moves
  it). [PACK]

--- 8.4 Subsystem (NT+0x5C, IMAGE_SUBSYSTEM_*) - complete ---
0  UNKNOWN
1  NATIVE                    no subsystem - kernel drivers, native apps
2  WINDOWS_GUI               GUI app, no console allocated
3  WINDOWS_CUI               console app
5  OS2_CUI
7  POSIX_CUI
8  NATIVE_WINDOWS            Win9x native driver
9  WINDOWS_CE_GUI
10 EFI_APPLICATION
11 EFI_BOOT_SERVICE_DRIVER
12 EFI_RUNTIME_DRIVER
13 EFI_ROM
14 XBOX
16 WINDOWS_BOOT_APPLICATION  bootmgr/winload
17 XBOX_CODE_CATALOG         (winnt.h only)
   values 4, 6, 15 are undefined.

--- 8.5 DllCharacteristics (NT+0x5E, IMAGE_DLLCHARACTERISTICS_*) ---
0x0001 (reserved)  0x0002 (reserved)  0x0004 (reserved)  0x0008 (reserved)
0x0010 (reserved, no name)
0x0020 HIGH_ENTROPY_VA       64-bit ASLR entropy (needs DYNAMIC_BASE too)
0x0040 DYNAMIC_BASE          ASLR: image may be relocated
0x0080 FORCE_INTEGRITY       code integrity checks enforced
0x0100 NX_COMPAT             DEP compatible
0x0200 NO_ISOLATION          do not use side-by-side isolation/manifest
0x0400 NO_SEH                image uses NO structured exception handling;
                             no handler inside it may be called
0x0800 NO_BIND               do not bind this image (section 23)
0x1000 APPCONTAINER          must run inside an AppContainer (UWP)
0x2000 WDM_DRIVER
0x4000 GUARD_CF              Control Flow Guard instrumented (section 22)
0x8000 TERMINAL_SERVER_AWARE
  Typical modern MS binary: 0x4160 = HIGH_ENTROPY_VA|DYNAMIC_BASE|NX_COMPAT|
  GUARD_CF; add 0x8000 for TS-aware -> 0xC160.
  ANOMALY: DYNAMIC_BASE set but no .reloc / empty DD[5], or DYNAMIC_BASE
  together with FileHeader RELOCS_STRIPPED (0x0001) - the image cannot
  actually move. Missing NX_COMPAT/GUARD_CF on a file claiming to be a
  modern MS binary is also a tell. [PACK]
  See also the EXTENDED DLL characteristics (CET/hotpatch) in debug
  directory type 20, section 18.



================================================================================
9. REVERSE LOOKUP - EVERY NT+X OFFSET, BOTH BITNESSES
================================================================================
You saw  *(_DWORD *)(base + e_lfanew + X)  in IDA. Find X in the left column.
Anchor: NT = base + *(_DWORD *)(base + 0x3C).

FIRST: DECIDE THE BITNESS. Read the WORD at NT+0x18.
  0x010B -> use the PE32 column      0x020B -> use the PE32+ column
Guessing wrong shifts everything from NT+0x60 onward by 0x10 and gives you
the wrong directory. This is the single most common mistake in PE parsing.

NT+X  DEC  PE32 (Magic 0x10B)                PE32+ (Magic 0x20B)
----  ---  ------------------------------     ------------------------------
0x00  0    Signature "PE\0\0"                 Signature "PE\0\0"
0x04  4    Machine (2)                        Machine (2)
0x06  6    NumberOfSections (2)               NumberOfSections (2)
0x08  8    TimeDateStamp                      TimeDateStamp
0x0C  12   PointerToSymbolTable               PointerToSymbolTable
0x10  16   NumberOfSymbols                    NumberOfSymbols
0x14  20   SizeOfOptionalHeader (2)           SizeOfOptionalHeader (2)
0x16  22   Characteristics (2)                Characteristics (2)
0x18  24   Magic (2) = 0x010B                 Magic (2) = 0x020B
0x1A  26   MajorLinkerVersion (1)             MajorLinkerVersion (1)
0x1B  27   MinorLinkerVersion (1)             MinorLinkerVersion (1)
0x1C  28   SizeOfCode                         SizeOfCode
0x20  32   SizeOfInitializedData              SizeOfInitializedData
0x24  36   SizeOfUninitializedData            SizeOfUninitializedData
0x28  40   AddressOfEntryPoint                AddressOfEntryPoint
0x2C  44   BaseOfCode                         BaseOfCode
0x30  48   BaseOfData                         ImageBase (8) low half
0x34  52   ImageBase (4)                      ImageBase high half
0x38  56   SectionAlignment                   SectionAlignment
0x3C  60   FileAlignment                      FileAlignment
0x40  64   MajorOperatingSystemVersion (2)    MajorOperatingSystemVersion (2)
0x42  66   MinorOperatingSystemVersion (2)    MinorOperatingSystemVersion (2)
0x44  68   MajorImageVersion (2)              MajorImageVersion (2)
0x46  70   MinorImageVersion (2)              MinorImageVersion (2)
0x48  72   MajorSubsystemVersion (2)          MajorSubsystemVersion (2)
0x4A  74   MinorSubsystemVersion (2)          MinorSubsystemVersion (2)
0x4C  76   Win32VersionValue                  Win32VersionValue
0x50  80   SizeOfImage                        SizeOfImage
0x54  84   SizeOfHeaders                      SizeOfHeaders
0x58  88   CheckSum                           CheckSum
0x5C  92   Subsystem (2)                      Subsystem (2)
0x5E  94   DllCharacteristics (2)             DllCharacteristics (2)
---------- FROM HERE THE TWO LAYOUTS DIVERGE BY 0x10 ------------------------
0x60  96   SizeOfStackReserve (4)             SizeOfStackReserve (8) low
0x64  100  SizeOfStackCommit (4)              SizeOfStackReserve high
0x68  104  SizeOfHeapReserve (4)              SizeOfStackCommit (8) low
0x6C  108  SizeOfHeapCommit (4)               SizeOfStackCommit high
0x70  112  LoaderFlags                        SizeOfHeapReserve (8) low
0x74  116  NumberOfRvaAndSizes                SizeOfHeapReserve high
0x78  120  DD[0].VirtualAddress  EXPORT       SizeOfHeapCommit (8) low
0x7C  124  DD[0].Size            EXPORT       SizeOfHeapCommit high
0x80  128  DD[1].VirtualAddress  IMPORT       LoaderFlags
0x84  132  DD[1].Size            IMPORT       NumberOfRvaAndSizes
0x88  136  DD[2].VirtualAddress  RESOURCE     DD[0].VirtualAddress  EXPORT
0x8C  140  DD[2].Size            RESOURCE     DD[0].Size            EXPORT
0x90  144  DD[3].VirtualAddress  EXCEPTION    DD[1].VirtualAddress  IMPORT
0x94  148  DD[3].Size            EXCEPTION    DD[1].Size            IMPORT
0x98  152  DD[4].VirtualAddress  SECURITY     DD[2].VirtualAddress  RESOURCE
0x9C  156  DD[4].Size            SECURITY     DD[2].Size            RESOURCE
0xA0  160  DD[5].VirtualAddress  BASERELOC    DD[3].VirtualAddress  EXCEPTION
0xA4  164  DD[5].Size            BASERELOC    DD[3].Size            EXCEPTION
0xA8  168  DD[6].VirtualAddress  DEBUG        DD[4].VirtualAddress  SECURITY
0xAC  172  DD[6].Size            DEBUG        DD[4].Size            SECURITY
0xB0  176  DD[7].VirtualAddress  ARCHITECT    DD[5].VirtualAddress  BASERELOC
0xB4  180  DD[7].Size            ARCHITECT    DD[5].Size            BASERELOC
0xB8  184  DD[8].VirtualAddress  GLOBALPTR    DD[6].VirtualAddress  DEBUG
0xBC  188  DD[8].Size            GLOBALPTR    DD[6].Size            DEBUG
0xC0  192  DD[9].VirtualAddress  TLS          DD[7].VirtualAddress  ARCHITECT
0xC4  196  DD[9].Size            TLS          DD[7].Size            ARCHITECT
0xC8  200  DD[10].VirtualAddress LOAD_CONFIG  DD[8].VirtualAddress  GLOBALPTR
0xCC  204  DD[10].Size           LOAD_CONFIG  DD[8].Size            GLOBALPTR
0xD0  208  DD[11].VirtualAddress BOUND_IMPORT DD[9].VirtualAddress  TLS
0xD4  212  DD[11].Size           BOUND_IMPORT DD[9].Size            TLS
0xD8  216  DD[12].VirtualAddress IAT          DD[10].VirtualAddress LOAD_CONFIG
0xDC  220  DD[12].Size           IAT          DD[10].Size           LOAD_CONFIG
0xE0  224  DD[13].VirtualAddress DELAY_IMPORT DD[11].VirtualAddress BOUND_IMPORT
0xE4  228  DD[13].Size           DELAY_IMPORT DD[11].Size           BOUND_IMPORT
0xE8  232  DD[14].VirtualAddress CLR/COM      DD[12].VirtualAddress IAT
0xEC  236  DD[14].Size           CLR/COM      DD[12].Size           IAT
0xF0  240  DD[15].VirtualAddress RESERVED     DD[13].VirtualAddress DELAY_IMPORT
0xF4  244  DD[15].Size           RESERVED     DD[13].Size           DELAY_IMPORT
0xF8  248  >>> SECTION TABLE [0].Name+0       DD[14].VirtualAddress CLR/COM
0xFC  252      section[0].Name+4              DD[14].Size           CLR/COM
0x100 256      section[0].VirtualSize         DD[15].VirtualAddress RESERVED
0x104 260      section[0].VirtualAddress      DD[15].Size           RESERVED
0x108 264      section[0].SizeOfRawData        >>> SECTION TABLE [0].Name+0
0x10C 268      section[0].PointerToRawData     section[0].Name+4
0x110 272      section[0].PointerToRelocations section[0].VirtualSize
0x114 276      section[0].PointerToLinenumbers section[0].VirtualAddress
0x118 280      sect[0].NumberOfRelocations(2)  section[0].SizeOfRawData
0x11A 282      sect[0].NumberOfLinenumbers(2)  (inside SizeOfRawData)
0x11C 284      section[0].Characteristics      section[0].PointerToRawData
0x120 288      section[1].Name+0               section[0].PointerToRelocations
  (the two columns above assume the standard SizeOfOptionalHeader 0xE0 / 0xF0)

--- 9.1 THE ARITHMETIC, so you never need the table ---
  DD[n].VirtualAddress = NT + 0x78 + 8*n     (PE32)
  DD[n].Size           = NT + 0x7C + 8*n     (PE32)
  DD[n].VirtualAddress = NT + 0x88 + 8*n     (PE32+)
  DD[n].Size           = NT + 0x8C + 8*n     (PE32+)

  Going the other way, given X:
    PE32 : d = X - 0x78 ;  PE32+ : d = X - 0x88
    n = d / 8 ; if (d % 8) == 0 -> VirtualAddress field
                if (d % 8) == 4 -> Size field
    if d < 0 you are still inside the fixed optional header fields.

--- 9.2 WORKED EXAMPLE: NT+0xD4 ---
  PE32+ : d = 0xD4 - 0x88 = 0x4C = 76 ;  76 = 8*9 + 4
          -> DD[9].Size  =  TLS DIRECTORY SIZE
  PE32  : d = 0xD4 - 0x78 = 0x5C = 92 ;  92 = 8*11 + 4
          -> DD[11].Size =  BOUND IMPORT SIZE
  It is NOT the delay import descriptor in either case.
  Delay import (DD[13]) lives at:
          PE32  : NT+0xE0 (RVA) / NT+0xE4 (Size)
          PE32+ : NT+0xF0 (RVA) / NT+0xF4 (Size)
  A 64-bit binary reading NT+0xD0 / NT+0xD4 is almost always asking
  "does this image have a TLS directory?" - a standard packer / anti-debug
  probe, because TLS callbacks run before the entry point.
  MEASURED ON THIS MACHINE (confirms the arithmetic):
    System32\shell32.dll  PE32+, e_lfanew 0x100:
      NT+0xD0 = 0x624C38, NT+0xD4 = 0x28  and DD[9] TLS is rva 0x624C38
      size 0x28 = 40 = sizeof(IMAGE_TLS_DIRECTORY64)   -> identical
    System32\ole32.dll    PE32+:  NT+0xD4 = 0x28 = TLS size
    System32\notepad.exe  PE32+:  NT+0xD4 = 0x00, no TLS directory
    SysWOW64\shell32.dll  PE32 :  DD[9] TLS at NT+0xC0/0xC4, size 0x18
                                  = 24 = sizeof(IMAGE_TLS_DIRECTORY32)
    Delay imports on the same files sit at NT+0xF0 (PE32+) / NT+0xE0 (PE32),
    e.g. notepad.exe NT+0xF0 = 0x303E0, NT+0xF4 = 0xE0. 0xE0/0x20 = 7 slots
    = 6 descriptors + an all-zero terminator, all with Attributes = 1:
    ADVAPI32.dll, COMDLG32.dll, PROPSYS.dll, SHELL32.dll, WINSPOOL.DRV,
    urlmon.dll.

--- 9.3 OFFSETS WORTH MEMORISING ---
  base+0x00  "MZ"                       base+0x3C  e_lfanew
  NT+0x00    "PE\0\0"                   NT+0x04    Machine
  NT+0x06    NumberOfSections           NT+0x14    SizeOfOptionalHeader
  NT+0x18    Magic (bitness!)           NT+0x28    AddressOfEntryPoint
  NT+0x30    ImageBase (both, x64 = 8B) NT+0x34    ImageBase (PE32)
  NT+0x38    SectionAlignment           NT+0x3C    FileAlignment
  NT+0x50    SizeOfImage                NT+0x54    SizeOfHeaders
  NT+0x58    CheckSum (both)            NT+0x5C    Subsystem (both)
  NT+0x5E    DllCharacteristics (both)
  export    NT+0x78 / NT+0x88     import    NT+0x80 / NT+0x90
  resource  NT+0x88 / NT+0x98     reloc     NT+0xA0 / NT+0xB0
  TLS       NT+0xC0 / NT+0xD0     loadcfg   NT+0xC8 / NT+0xD8
  IAT       NT+0xD8 / NT+0xE8     delay     NT+0xE0 / NT+0xF0
  Shellcode that walks exports uses NT+0x78 (x86) or NT+0x88 (x64). Seeing
  both in one blob means it is bitness-agnostic loader code.


================================================================================
10. DATA DIRECTORY MASTER TABLE
================================================================================
IMAGE_DATA_DIRECTORY, 8 bytes each, 16 entries, 128 bytes total:
  +0x00 4 VirtualAddress    RVA  (EXCEPT index 4 - see below)
  +0x04 4 Size              bytes

IDX NAME (IMAGE_DIRECTORY_ENTRY_*)  VA POINTS TO            SIZE IS
--- ------------------------------  ---------------------   -----------------
0   EXPORT          .edata          IMAGE_EXPORT_DIRECTORY  whole blob
1   IMPORT          .idata          IMAGE_IMPORT_DESCRIPTOR[] IGNORED [!]
2   RESOURCE        .rsrc           IMAGE_RESOURCE_DIRECTORY whole tree
3   EXCEPTION       .pdata          RUNTIME_FUNCTION[]      DRIVES count
4   SECURITY        (not mapped)    WIN_CERTIFICATE[]       DRIVES count
                    [!] VirtualAddress here is a FILE OFFSET, not an RVA
5   BASERELOC       .reloc          IMAGE_BASE_RELOCATION[] DRIVES iteration
6   DEBUG           .rdata/.debug   IMAGE_DEBUG_DIRECTORY[] /28 = entry count
7   ARCHITECTURE    -               unused, must be 0/0
8   GLOBALPTR       -               VA = the GP value, Size MUST be 0
9   TLS             .tls            IMAGE_TLS_DIRECTORY     sizeof(struct)
10  LOAD_CONFIG     .rdata          IMAGE_LOAD_CONFIG_DIR   see 22 [!]
11  BOUND_IMPORT    header gap      IMAGE_BOUND_IMPORT_DESC[] DRIVES iteration
12  IAT             .idata          first IAT thunk         total IAT bytes
13  DELAY_IMPORT    .didat/.text    IMAGE_DELAYLOAD_DESC[]  IGNORED [!]
14  COM_DESCRIPTOR  .text/.rdata    IMAGE_COR20_HEADER      72 (0x48)
15  RESERVED        -               must be 0/0

--- 10.1 SIZE-DRIVEN vs TERMINATOR-DRIVEN (matters a lot) ---
  SIZE-DRIVEN (loader trusts Size; wrong Size = data silently dropped):
    3 EXCEPTION, 4 SECURITY, 5 BASERELOC, 6 DEBUG, 10 LOAD_CONFIG
    (also has its own internal Size dword), 11 BOUND_IMPORT,
    12 IAT (Size is what tells the loader which pages to unprotect while
    snapping and re-protect afterwards), 14 COM_DESCRIPTOR
  TERMINATOR-DRIVEN (Size is ignored, an all-zero record ends the array):
    1 IMPORT, 13 DELAY_IMPORT
  NEITHER: 9 TLS is a single fixed-size struct - the loader knows its length
    from the bitness, so Size is informational.
  => Setting DD[1].Size = 0 still imports perfectly at runtime while many
  tools display "no imports". Truncating DD[5].Size silently drops
  relocations. Both are standard tricks. [PACK]

--- 10.2 Historical notes ---
  Index 7 was IMAGE_DIRECTORY_ENTRY_COPYRIGHT on x86 (an ASCII string).
  Index 8 GLOBALPTR is only meaningful on IA64/MIPS/RISC targets.
  Index 15 must be zero; a non-zero value is an anomaly.



================================================================================
11. IMAGE_SECTION_HEADER               NT+0x18+SizeOfOptionalHeader, 40 = 0x28
================================================================================
Array of NumberOfSections entries, no padding between them, immediately after
the optional header. Entry n is at   sectionTable + 40*n.

HEX   DEC  SIZE  FIELD                  MEANING
0x00  0    8     Name[8]                ASCII, NOT necessarily NUL-terminated
0x08  8    4     VirtualSize            size in MEMORY, before alignment
0x0C  12   4     VirtualAddress         RVA where this section is mapped
0x10  16   4     SizeOfRawData          size on DISK, multiple of FileAlignment
0x14  20   4     PointerToRawData       FILE OFFSET of the raw data
0x18  24   4     PointerToRelocations   objects only; 0 in images
0x1C  28   4     PointerToLinenumbers   objects only, deprecated; 0 in images
0x20  32   2     NumberOfRelocations    objects only; 0 in images
0x22  34   2     NumberOfLinenumbers    objects only, deprecated; 0 in images
0x24  36   4     Characteristics        flags, see 11.2

--- 11.1 FIELD SEMANTICS AND TRAPS ---
Name[8]
  Exactly 8 bytes. A name of exactly 8 characters has NO terminator, so
  printf("%s") runs into VirtualSize. Long names are only possible in OBJECT
  files, encoded as "/nnnn" (slash + ASCII decimal offset into the COFF string
  table, section 33); the image linker truncates to 8. Case sensitive.
  Names are purely cosmetic to the loader - it never matches on them.
VirtualSize
  Actual bytes used in memory. The loader maps
  round_up(VirtualSize, SectionAlignment) bytes and ZERO-FILLS whatever the
  raw data does not cover. This is how .bss works with SizeOfRawData == 0.
  In OBJECT files this field is 0 and SizeOfRawData holds the real size.
VirtualAddress
  RVA, must be a multiple of SectionAlignment. Sections are expected in
  ascending VirtualAddress order and contiguous after alignment.
SizeOfRawData
  Bytes present in the file, rounded up to FileAlignment. May be LARGER than
  VirtualSize (the trailing alignment padding is not mapped - a cave that
  dumpers drop) or SMALLER (the remainder is zero-filled in memory).
  0 means "nothing in the file", i.e. pure zero-init memory.
PointerToRawData
  FILE OFFSET, multiple of FileAlignment. 0 when SizeOfRawData is 0.
  The number of bytes actually copied is
    min( round(SizeOfRawData, FileAlignment), round(VirtualSize, SectionAlignment) )
[!] THE TWO SIZES ARE THE #1 SOURCE OF DUMPING BUGS
  On disk you index with SizeOfRawData; in memory with VirtualSize. A
  correct RVA-contains test uses the LARGER of the two (section 29).

--- 11.2 Characteristics (IMAGE_SCN_*) - complete ---
0x00000000  (reserved)
0x00000001  TYPE_DSECT / (reserved)
0x00000002  TYPE_NOLOAD / (reserved)
0x00000004  TYPE_GROUP / (reserved)
0x00000008  TYPE_NO_PAD      do not pad to the next boundary (obsolete,
                             replaced by ALIGN_1BYTES); objects only
0x00000010  TYPE_COPY / (reserved)
0x00000020  CNT_CODE                 contains executable code
0x00000040  CNT_INITIALIZED_DATA     contains initialized data
0x00000080  CNT_UNINITIALIZED_DATA   contains uninitialized data (.bss)
0x00000100  LNK_OTHER                reserved
0x00000200  LNK_INFO                 comments/.drectve/.sxdata; objects only
0x00000400  (reserved)
0x00000800  LNK_REMOVE               do not put this section in the image
0x00001000  LNK_COMDAT               COMDAT section; objects only
0x00004000  NO_DEFER_SPEC_EXC        reset speculative exceptions (winnt.h only)
0x00008000  GPREL / MEM_FARDATA      data referenced through the global pointer
0x00020000  MEM_PURGEABLE / MEM_16BIT   reserved / 16-bit code (ARM THUMB)
0x00040000  MEM_LOCKED               reserved
0x00080000  MEM_PRELOAD              reserved
0x00100000  ALIGN_1BYTES         }
0x00200000  ALIGN_2BYTES         }
0x00300000  ALIGN_4BYTES         }  alignment lives in bits 20-23 as a nibble
0x00400000  ALIGN_8BYTES         }  value n<<20, alignment = 1 << (n-1)
0x00500000  ALIGN_16BYTES        }  nibble 0 = default (16 bytes)
0x00600000  ALIGN_32BYTES        }  nibble 0xF unused
0x00700000  ALIGN_64BYTES        }  MASK = 0x00F00000
0x00800000  ALIGN_128BYTES       }  objects only - the linker consumes these
0x00900000  ALIGN_256BYTES       }
0x00A00000  ALIGN_512BYTES       }
0x00B00000  ALIGN_1024BYTES      }
0x00C00000  ALIGN_2048BYTES      }
0x00D00000  ALIGN_4096BYTES      }
0x00E00000  ALIGN_8192BYTES      }
0x01000000  LNK_NRELOC_OVFL      relocation count overflowed 16 bits; the real
                                 count is in the first relocation record's
                                 VirtualAddress and NumberOfRelocations = 0xFFFF
0x02000000  MEM_DISCARDABLE      can be discarded after use (typical .reloc)
0x04000000  MEM_NOT_CACHED       must not be cached
0x08000000  MEM_NOT_PAGED        must not be paged out (drivers)
0x10000000  MEM_SHARED           shared across all processes mapping the image
0x20000000  MEM_EXECUTE          executable
0x40000000  MEM_READ             readable
0x80000000  MEM_WRITE            writable

  COMMON COMBINATIONS
    0x60000020  .text    CODE | EXECUTE | READ
    0x40000040  .rdata   INITIALIZED_DATA | READ
    0xC0000040  .data    INITIALIZED_DATA | READ | WRITE
    0xC0000080  .bss     UNINITIALIZED_DATA | READ | WRITE
    0x42000040  .reloc   INITIALIZED_DATA | DISCARDABLE | READ
    0x40000040  .rsrc / .pdata / .xdata
    0xE0000020  RWX code - legitimate almost never; JIT and packers only [PACK]
    0xE0000080  UPX0-style container: UNINIT | R | W | X
  Note: the MEM_* bits are the ONLY thing that decides page protection. The
  CNT_* bits are documentation. A ".text" without CNT_CODE still executes if
  MEM_EXECUTE is set.
  The same 0x00F00000 alignment nibble is reused inside
  IMAGE_TLS_DIRECTORY.Characteristics, where 0x00000001 means
  IMAGE_SCN_SCALE_INDEX (TLS-only flag).

--- 11.3 WELL-KNOWN SECTION NAMES ---
NAME          PRODUCED BY / CONTENTS
.text         all compiled code (MSVC). Subsections .text$mn, .text$x,
              .text$di, .text$yd get merged in name order by the linker.
.textbss      /INCREMENTAL thunk section, VirtualSize>0 SizeOfRawData=0
CODE / DATA   Borland / Delphi naming
.data         initialized read-write data
.rdata        read-only data: string literals, vtables, RTTI, import
              descriptors on modern MSVC, debug directory, load config,
              .xdata. Subsections .rdata$r (RTTI), .rdata$zzzdbg,
              .rdata$voltmd, .rdata$brc.
.bss          uninitialized data (SizeOfRawData 0)
.idata        import directory + INT + IAT (older linkers; modern MSVC folds
              this into .rdata). Subsections $2 descriptors, $3 terminator,
              $4 INT, $5 IAT, $6 DLL name strings.
.didat        delay-load IAT when it needs its own writable section
              (see IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION)
.edata        export directory (usually folded into .rdata)
.rsrc         resources; subsections .rsrc$01 (directory) and .rsrc$02 (data)
.reloc        base relocations
.pdata        RUNTIME_FUNCTION table (x64/ARM); .xdata = unwind info
.tls          TLS template data; the TLS directory itself is in .rdata
.CRT          C runtime initializer/terminator pointer arrays:
              .CRT$XCA..XCZ (C++ ctors), .CRT$XIA..XIZ (C initializers),
              .CRT$XLA..XLZ (TLS callbacks - XLB is where yours lands),
              .CRT$XPA..XPZ (pre-terminators), .CRT$XTA..XTZ (terminators)
.gfids        Control Flow Guard function-ID table (GuardCFFunctionTable)
.giats       CFG address-taken IAT entry table
.gehcont      CFG EH continuation table
.00cfg        CFG load-config marker section
.voltbl       volatile-access metadata (/volatileMetadata)
.msvcjmc      /JMC (just-my-code) support data
.sxdata       SafeSEH handler symbol indices; x86 OBJECT files only
.drectve      linker directives as ASCII text; objects only, LNK_INFO
              (the PE spec table misspells this as ".drective")
.debug$S      CodeView symbols; .debug$T types; .debug$P precomp;
              .debug$F FPO data - objects only
.debug        merged .DBG-style debug section (rare)
.arch         alpha-era architecture data
.sdata/.sbss  GP-relative short data (IA64/MIPS/RISC-V)
.tls$         TLS subsections
.didat$2..$7  delay-load subsections
.fogrp        PGO instrumentation grouping
PACKER / PROTECTOR NAMES (strong indicators, not proof) [PACK]
  UPX0 UPX1 UPX2 / UPX!         UPX          (UPX0: VSize huge, raw 0)
  .aspack .adata                ASPack
  .themida .winlice             Themida/WinLicense
  .vmp0 .vmp1 .vmp2             VMProtect
  .MPRESS1 .MPRESS2             MPRESS
  .nsp0 .nsp1 .nsp2             NsPack
  .petite                       Petite
  pec1 pec2                     PECompact
  .enigma1 .enigma2             Enigma Protector
  .RLPack                       RLPack
  .y0da .yP                     yoda's crypter
  .taz .boom .ccg .charmve      various old crypters
  .mackt                        ImpREC-rebuilt import table
  (blank) / random 8 bytes      tElock, FSG, Upack, custom - these use empty,
                                random or overlapping names instead



================================================================================
                              PART II - DIRECTORIES
================================================================================

================================================================================
12. DD[0] EXPORT DIRECTORY              IMAGE_EXPORT_DIRECTORY, 40 = 0x28 bytes
================================================================================
At RVA DD[0].VirtualAddress. Only DLLs normally have one (EXEs can too).

HEX   DEC  SIZE  FIELD                  MEANING
0x00  0    4     Characteristics        always 0
0x04  4    4     TimeDateStamp          build time of the export table
0x08  8    2     MajorVersion           usually 0
0x0A  10   2     MinorVersion           usually 0
0x0C  12   4     Name                   RVA of the internal DLL name (ASCII)
0x10  16   4     Base                   ordinal of the FIRST entry (usually 1)
0x14  20   4     NumberOfFunctions      entries in AddressOfFunctions (EAT)
0x18  24   4     NumberOfNames          entries in AddressOfNames  (ENT)
0x1C  28   4     AddressOfFunctions     RVA -> DWORD[NumberOfFunctions]  (EAT)
0x20  32   4     AddressOfNames         RVA -> DWORD[NumberOfNames]      (ENT)
0x24  36   4     AddressOfNameOrdinals  RVA -> WORD[NumberOfNames]       (EOT)

THREE PARALLEL ARRAYS
  EAT: AddressOfFunctions[i]    = RVA of the exported thing, indexed by
                                  (ordinal - Base). A 0 entry means that
                                  ordinal slot is empty.
  ENT: AddressOfNames[j]        = RVA of a NUL-terminated ASCII name.
                                  SORTED case-sensitively ascending, so you
                                  can binary search it.
  EOT: AddressOfNameOrdinals[j] = the UNBIASED index into EAT for name j.
                                  It is a WORD. It equals (ordinal - Base),
                                  so the real ordinal is
                                  AddressOfNameOrdinals[j] + Base.
  NumberOfFunctions >= NumberOfNames. The difference is exports by ordinal
  only (NONAME in the .def file) - they have an EAT slot and no name.

--- 12.1 GetProcAddress, by name (this is the whole algorithm) ---
  find j such that strcmp(AddressOfNames[j], wanted) == 0   (binary search)
  k   = AddressOfNameOrdinals[j]            // WORD array -> stride 2
  rva = AddressOfFunctions[k]               // DWORD array -> stride 4
  address = moduleBase + rva
--- 12.2 GetProcAddress, by ordinal ---
  k = ordinal - Base
  if (k >= NumberOfFunctions) fail
  rva = AddressOfFunctions[k];  if (rva == 0) fail
  address = moduleBase + rva
  (An ordinal is passed as a bare integer with the high 16 bits clear.)

--- 12.3 FORWARDED EXPORTS ---
  If AddressOfFunctions[k] points INSIDE the export directory itself, i.e.
    DD[0].VirtualAddress <= rva < DD[0].VirtualAddress + DD[0].Size
  then it is NOT code. It is a NUL-terminated ASCII string of the form
    "OTHERDLL.FunctionName"     e.g. "NTDLL.RtlAllocateHeap"
    "OTHERDLL.#123"             forward to an ordinal
    "api-ms-win-core-x-l1-1-0.SomeFunc"   API set forward
  GetProcAddress resolves it recursively (LoadLibrary + GetProcAddress on the
  target). kernel32 is mostly forwarders to kernelbase/ntdll now.
  RE consequence: an IAT slot may end up pointing into a completely different
  module than the one named in the import descriptor.

--- 12.4 RE notes ---
  * The DLL's internal Name (0x0C) is the name the linker recorded, which can
    differ from the file name on disk. Bound imports and forwarders use it.
  * Base is usually 1 but not always; ignoring it shifts every ordinal.
  * The export table is what shellcode walks after finding kernel32 via the
    PEB loader list (appendix A1). Standard hash-based API resolution never
    touches the strings twice - it hashes AddressOfNames[j] and compares.
  * A DLL can export with NumberOfNames == 0 (ordinals only) - common in
    malware and in some Microsoft internal DLLs.
  * .NET assemblies normally export nothing.


================================================================================
13. DD[1] IMPORT DIRECTORY
================================================================================
An ARRAY of IMAGE_IMPORT_DESCRIPTOR, one per imported DLL, terminated by an
all-zero (20 bytes of 0) entry. DD[1].Size is IGNORED by the loader. [PACK]

IMAGE_IMPORT_DESCRIPTOR - 20 = 0x14 bytes
HEX   DEC  SIZE  FIELD                     MEANING
0x00  0    4     OriginalFirstThunk         RVA of the INT (a.k.a. hint/name
                 (union: Characteristics)   table). 0 for some linkers/packers.
0x04  4    4     TimeDateStamp              0 = not bound
                                            0xFFFFFFFF = bound, new-style
                                              (real stamps in DD[11])
                                            other = bound, old-style
0x08  8    4     ForwarderChain             index of the first forwarder ref,
                                            -1 = none. Legacy binding only.
0x0C  12   4     Name                       RVA of the DLL name, ASCII, NUL-term
0x10  16   4     FirstThunk                 RVA of the IAT for this DLL.
                                            The loader OVERWRITES this array
                                            with real addresses.

TWO PARALLEL THUNK ARRAYS
  INT (Import Name Table)    at OriginalFirstThunk - stays intact on disk and
                             in memory. This is your ground truth for names.
  IAT (Import Address Table) at FirstThunk - identical content on disk, but
                             after loading each slot holds a real function
                             address.
  Both are arrays of IMAGE_THUNK_DATA terminated by an all-zero element.
    PE32  : DWORD  (4 bytes per slot)
    PE32+ : QWORD  (8 bytes per slot)     <- stride 8, not 4

THUNK VALUE DECODING
  if (value & IMAGE_ORDINAL_FLAG) -> import BY ORDINAL
       IMAGE_ORDINAL_FLAG32 = 0x80000000
       IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
       ordinal = value & 0xFFFF
  else -> value is an RVA to IMAGE_IMPORT_BY_NAME:
       0x00  2      Hint     suggested ENT index; the loader tries this index
                             first and falls back to a binary search. A wrong
                             hint costs nothing but time.
       0x02  var    Name     NUL-terminated ASCII
       (the struct is then padded to an even boundary)

--- 13.1 WHAT THE LOADER DOES ---
  for each descriptor until the zero entry:
    hMod = LoadLibrary(Name)                       // recursive, with its own
                                                   // dependency graph
    for i = 0.. until INT[i] == 0:
        IAT[i] = resolve(hMod, INT[i])             // name or ordinal
  If OriginalFirstThunk is 0, the loader reads the names from the IAT itself
  (which is why that still works) - but then you lose the on-disk name copy
  once the slots are overwritten. Packers do this deliberately: dump the
  process and you have addresses with no names left. [PACK]

--- 13.2 CALL SHAPES IN DISASSEMBLY ---
  x86 indirect:  FF 15 xx xx xx xx      call dword ptr [__imp__Func]
  x86 thunk:     E8 rel32 -> FF 25 ...  call thunk; thunk jmps through IAT
  x64 indirect:  FF 15 disp32           call qword ptr [rip+disp]  -> IAT slot
  x64 tail jmp:  FF 25 disp32           jmp  qword ptr [rip+disp]
  IDA names IAT slots __imp_Func / __imp_?mangled. A "call register" after
  loading from a data address that is NOT in the IAT range = manual
  resolution (GetProcAddress or hash walking).

--- 13.3 API SETS ---
  Names like api-ms-win-core-synch-l1-2-0.dll, ext-ms-win-... are virtual.
  They are resolved by the API set schema in the PEB
  (PEB->ApiSetMap) to a real host DLL (kernelbase.dll etc). The file does not
  exist on disk. Do not go looking for it.

--- 13.4 IMPORT ANOMALIES [PACK] ---
  * Only LoadLibraryA/GetProcAddress imported, or no imports at all (PEB
    walking / syscall stubs).
  * OriginalFirstThunk == 0 (see above), or INT and IAT pointing at the SAME
    array (self-referential, legal, breaks some rebuilders).
  * IAT placed in a writable section far from .idata, or split across
    several ranges.
  * Descriptor Name RVA pointing into a section that is decrypted at runtime.
  * Import descriptors present but DD[1].Size == 0 (tools show nothing).
  * A single descriptor with hundreds of ordinal-only imports - typical of
    ordinal-obfuscated builds.
  * .NET files usually import exactly one function: mscoree.dll!_CorExeMain
    (EXE) or _CorDllMain (DLL). Anything more means mixed-mode/native code.
  See section 25 for delay imports, which are a SEPARATE table that many
  tools do not show at all.


================================================================================
14. DD[2] RESOURCE DIRECTORY
================================================================================
A three-level tree: TYPE -> NAME/ID -> LANGUAGE -> data.
[!] ALL "OffsetToData"/"NameOffset" values inside the tree are offsets from
the START of the resource directory (i.e. from DD[2].VirtualAddress), NOT
RVAs and NOT file offsets. Only IMAGE_RESOURCE_DATA_ENTRY.OffsetToData is a
real RVA.

IMAGE_RESOURCE_DIRECTORY - 16 = 0x10 bytes (one node)
HEX   DEC  SIZE  FIELD
0x00  0    4     Characteristics        0
0x04  4    4     TimeDateStamp
0x08  8    2     MajorVersion
0x0A  10   2     MinorVersion
0x0C  12   2     NumberOfNamedEntries   entries keyed by string
0x0E  14   2     NumberOfIdEntries      entries keyed by integer
  Immediately followed by (NumberOfNamedEntries + NumberOfIdEntries) entries.
  Named entries come FIRST and are sorted by string; ID entries follow and
  are sorted by value.

IMAGE_RESOURCE_DIRECTORY_ENTRY - 8 bytes
HEX  SIZE  FIELD
0x00 4     Name / Id      if bit 31 set: (value & 0x7FFFFFFF) = offset to an
                          IMAGE_RESOURCE_DIRECTORY_STRING
                          if bit 31 clear: the low 16 bits are the integer ID
0x04 4     OffsetToData   if bit 31 set: (value & 0x7FFFFFFF) = offset to a
                          child IMAGE_RESOURCE_DIRECTORY (go deeper)
                          if bit 31 clear: offset to IMAGE_RESOURCE_DATA_ENTRY
                          (leaf)

IMAGE_RESOURCE_DIRECTORY_STRING (ANSI form) / _STRING_U (Unicode, the real one)
  0x00 2    Length         in CHARACTERS, not bytes, and no NUL terminator
  0x02 2*L  NameString     UTF-16LE

IMAGE_RESOURCE_DATA_ENTRY - 16 = 0x10 bytes (the leaf)
  0x00 4    OffsetToData   <- a real RVA to the resource bytes
  0x04 4    Size           bytes
  0x08 4    CodePage
  0x0C 4    Reserved       0

WALKING IT
  root = base + DD[2].VirtualAddress
  level 1 entries: Name/Id = resource TYPE (RT_*)
  level 2 entries: Name/Id = resource NAME or ID
  level 3 entries: Name/Id = LANGUAGE id (LANGID: 0x0409 = en-US, 0 = neutral)
  level 3 OffsetToData -> IMAGE_RESOURCE_DATA_ENTRY -> the bytes
  Three levels is the convention; the format allows fewer or more, and
  malformed trees with self-referencing child offsets are a known parser DoS.

--- 14.1 Resource type IDs (RT_*) ---
1  RT_CURSOR         2  RT_BITMAP        3  RT_ICON         4  RT_MENU
5  RT_DIALOG         6  RT_STRING        7  RT_FONTDIR      8  RT_FONT
9  RT_ACCELERATOR    10 RT_RCDATA        11 RT_MESSAGETABLE
12 RT_GROUP_CURSOR (= RT_CURSOR + 11)    14 RT_GROUP_ICON (= RT_ICON + 11)
16 RT_VERSION        17 RT_DLGINCLUDE    19 RT_PLUGPLAY     20 RT_VXD
21 RT_ANICURSOR      22 RT_ANIICON       23 RT_HTML         24 RT_MANIFEST
  13 and 18 are unassigned. 15 is the legacy RT_NAMETABLE. RT_DLGINIT 240
  and RT_TOOLBAR 241 are undocumented MFC/dialog-editor types.

--- 14.2 The resources you actually care about ---
  RT_VERSION (16), name 1: VS_VERSIONINFO. Nested structure of
    { WORD wLength; WORD wValueLength; WORD wType; WCHAR szKey[]; padding to
      4 bytes; BYTE Value[wValueLength]; children... }
    Key "VS_VERSION_INFO" -> VS_FIXEDFILEINFO (Signature 0xFEEF04BD,
    dwFileVersionMS/LS, dwProductVersionMS/LS, flags), then "StringFileInfo"
    -> lang-codepage block -> CompanyName / FileDescription / FileVersion /
    InternalName / OriginalFilename / ProductName. OriginalFilename vs the
    real file name is a cheap masquerading check.
  RT_MANIFEST (24), name 1: XML. requestedExecutionLevel (asInvoker /
    highestAvailable / requireAdministrator), dpiAware, supportedOS GUIDs,
    dependent assemblies (Common-Controls v6 pulls in comctl32 v6).
  RT_ICON / RT_GROUP_ICON: GRPICONDIR indexes RT_ICON entries by ID.
    Icon reuse across samples is a good clustering signal.
  RT_RCDATA (10): arbitrary blobs. THE standard hiding place for a packed
    second stage, a config, or an embedded PE. Check for MZ at offset 0.
  RT_STRING (6): stored in bundles of 16; resource ID = (stringId >> 4) + 1,
    each entry is a WORD length + UTF-16 chars, no terminators.

--- 14.3 RE notes ---
  * The whole tree is normally in .rsrc and read-only, but nothing stops a
    file from putting it in a writable section and rewriting it at runtime.
  * Resource sizes lying about the real payload size, or a data entry whose
    OffsetToData points outside .rsrc, are both common. [PACK]
  * FindResource/LoadResource/LockResource/SizeofResource in the imports plus
    a large .rsrc = self-extracting stage. Follow the resource ID passed to
    FindResource.



================================================================================
15. DD[3] EXCEPTION DIRECTORY   (.pdata + .xdata)
================================================================================
Size-driven. On x86 32-bit this directory is normally 0/0 - x86 has no static
unwind tables (see 15.5).

--- 15.1 x64: RUNTIME_FUNCTION - 12 = 0xC bytes, DWORD aligned ---
HEX  SIZE  FIELD
0x00 4     BeginAddress       RVA of the first byte of the function
0x04 4     EndAddress         RVA of one byte PAST the last byte
0x08 4     UnwindInfoAddress  RVA of the UNWIND_INFO  (winnt.h: UnwindData)

  entryCount = DD[3].Size / 12
  The array is SORTED ascending by BeginAddress -> binary search.
  Match test: BeginAddress <= rva < EndAddress.

  THIS IS THE MOST RELIABLE FUNCTION-BOUNDARY ORACLE ON x64. IDA uses it.
  If .pdata is intact you get exact starts and ends for every non-leaf
  function, even in a stripped binary. Leaf functions that touch no stack and
  call nothing may legitimately have no entry.
  Rebuilding a stripped .pdata is what makes dumped x64 samples analysable.
  JIT/dynamic code registers entries at runtime with RtlAddFunctionTable or
  RtlInstallFunctionTableCallback - so an in-memory function table can have
  entries that do not exist in the file.

--- 15.2 x64: UNWIND_INFO - variable size, DWORD aligned, min 8 bytes ---
HEX  SIZE  FIELD
0x00 1     Version : bits 0-2       1 normally (2 exists in modern MSVC)
           Flags   : bits 3-7       UNW_FLAG_*
0x01 1     SizeOfProlog             prolog length in bytes
0x02 1     CountOfCodes             number of 2-byte slots USED
0x03 1     FrameRegister : bits 0-3  0 = none, else register number
           FrameOffset   : bits 4-7  frame ptr = RSP + 16*FrameOffset (0..240)
0x04 2*n   UnwindCode[ (CountOfCodes + 1) & ~1 ]
             ALWAYS padded to an EVEN slot count; the last slot is unused when
             CountOfCodes is odd. Sorted DESCENDING by CodeOffset.
then at   0x04 + 2*((CountOfCodes + 1) & ~1) :
  if Flags has EHANDLER or UHANDLER (and not CHAININFO):
     4     ExceptionHandler         RVA of the language-specific handler
     var   ExceptionData            format defined by that handler
  if Flags has CHAININFO:
     12    a full RUNTIME_FUNCTION of the PRIMARY (parent) function

  Flags:
    0x00 UNW_FLAG_NHANDLER   none
    0x01 UNW_FLAG_EHANDLER   has an exception handler (__try/__except; runs in
                             the SEARCH pass)
    0x02 UNW_FLAG_UHANDLER   has a termination handler (__finally, C++ dtors;
                             runs in the UNWIND pass)
    0x04 UNW_FLAG_CHAININFO  this is a secondary record; EHANDLER/UHANDLER
                             must be clear and FrameRegister/FrameOffset must
                             match the primary. Chains may nest - follow until
                             a record WITHOUT this flag; that one names the
                             real function entry.

--- 15.3 x64: UNWIND_CODE - exactly 2 bytes ---
0x00 1     CodeOffset    offset in the prolog of the END of the instruction
                         (= the start of the next instruction)
0x01 1     UnwindOp : bits 0-3
           OpInfo   : bits 4-7

  REGISTER NUMBERS (used by OpInfo and FrameRegister):
    0 RAX  1 RCX  2 RDX  3 RBX  4 RSP  5 RBP  6 RSI  7 RDI  8..15 R8..R15
  XMM opcodes use OpInfo as the XMM register number 0-15.

  OP  NAME                 SLOTS  MEANING
  0   UWOP_PUSH_NONVOL     1      push of an integer reg; OpInfo = reg.
                                  RSP -= 8. First in prolog / last in array.
  1   UWOP_ALLOC_LARGE     2 or 3 OpInfo=0: next 1 slot = size/8
                                    (136 .. 512K-8)
                                  OpInfo=1: next 2 slots = raw size, LE ULONG
                                    (512K .. 4G-8)
  2   UWOP_ALLOC_SMALL     1      size = OpInfo*8 + 8   (8..128)
  3   UWOP_SET_FPREG       1      OpInfo must be 0. Establishes the frame
                                  pointer: FrameRegister = RSP +
                                  16*FrameOffset (from the header).
  4   UWOP_SAVE_NONVOL     2      OpInfo = reg; next slot = offset/8 (USHORT).
                                  MOV-based save, reach < 512K.
  5   UWOP_SAVE_NONVOL_FAR 3      OpInfo = reg; next 2 slots = raw offset.
  6   (UWOP_EPILOG)        2      MS docs say "unused". Real Windows/LLVM use
                                  it to encode epilog location/size when
                                  Version == 2; the unwinder ignores it while
                                  replaying prolog effects.
  7   (UWOP_SPARE_CODE)    3      MS docs say "unused". Historically
                                  SAVE_XMM_FAR.
  8   UWOP_SAVE_XMM128     2      OpInfo = XMM reg; next slot = offset/16.
                                  Saves all 128 bits. Reach < 1M.
  9   UWOP_SAVE_XMM128_FAR 3      OpInfo = XMM reg; next 2 slots = raw offset.
  10  UWOP_PUSH_MACHFRAME  1      OpInfo=0: hardware pushed SS,oldRSP,EFLAGS,
                                  CS,RIP -> RSP -= 40 (0x28)
                                  OpInfo=1: plus an error code -> RSP -= 48
                                  (0x30). Only in interrupt-routine prologs.
  OFFSET SCALING: everything except the XMM128 pair scales by 8; XMM128
  scales by 16; the _FAR variants store the raw byte offset across two slots,
  little-endian. Offsets are measured from the lowest address of the fixed
  stack allocation (from RSP when FrameRegister == 0, otherwise from
  FrameRegister - 16*FrameOffset).

  C accessor from the docs:
    handlerOrChain = &UnwindCode[(CountOfCodes + 1) & ~1];
    ExceptionData  = (BYTE*)handlerOrChain + 4;

--- 15.4 x64: SCOPE_TABLE (the ExceptionData of __C_specific_handler) ---
This is what DISPATCHER_CONTEXT.HandlerData points at. 4-byte aligned.
  0x00 4    Count
  then Count * 16 bytes:
    0x00 4  BeginAddress     RVA, start of the guarded region
    0x04 4  EndAddress       RVA, one past the end
    0x08 4  HandlerAddress   filter funclet RVA, or the literal 1, or the
                             __finally funclet RVA
    0x0C 4  JumpTarget       RVA of the __except body, or 0
  total size = 4 + 16*Count

  SEMANTICS
    JumpTarget == 0  -> a __finally. HandlerAddress is the termination
                        funclet; called as handler(TRUE, EstablisherFrame)
                        during the UNWIND pass only.
    JumpTarget != 0  -> a __try/__except. SEARCH pass only.
                        HandlerAddress != 1 -> filter funclet, called with
                          (EXCEPTION_POINTERS*, frame), returns
                          -1 CONTINUE_EXECUTION / 0 CONTINUE_SEARCH /
                           1 EXECUTE_HANDLER
                        HandlerAddress == 1 -> the constant filter
                          EXCEPTION_EXECUTE_HANDLER (source `__except(1)`),
                          no call is made.
    On EXECUTE_HANDLER the handler calls
    RtlUnwindEx(frame, ImageBase + JumpTarget, ...).
    Iteration starts at DISPATCHER_CONTEXT.ScopeIndex (resume point for
    collided/nested dispatch) and matches on ControlPc in [Begin, End).
    Nesting is expressed by record ORDER and overlap, not by a parent field.
  THIS TABLE IS A MAP OF EVERY try/except/finally REGION IN THE FUNCTION.
  Read it and you know the exception-driven control flow without executing.

  Other x64 language data you will meet:
    __CxxFrameHandler3 / __CxxFrameHandler4 -> a FuncInfo structure
                                               (C++ EH state machine)
    __GSHandlerCheck        -> /GS cookie data only
    __GSHandlerCheck_SEH    -> GS data followed by the SCOPE_TABLE above
    __GSHandlerCheck_EH     -> GS data followed by C++ FuncInfo

  HANDLER ABI
    EXCEPTION_DISPOSITION handler(PEXCEPTION_RECORD, ULONG64 EstablisherFrame,
                                  PCONTEXT, PDISPATCHER_CONTEXT)
    EstablisherFrame = base of the fixed stack allocation.
    DISPATCHER_CONTEXT = ControlPc, ImageBase, FunctionEntry,
      EstablisherFrame, TargetIp, ContextRecord, LanguageHandler, HandlerData
      (8 pointer-sized fields, in that order).

--- 15.5 ARM64 (0xAA64), ARM64EC (0xA641), ARM64X (0xA64E) ---
.pdata entry = 8 bytes:
  0x00 4    Function Start RVA
  0x04 4    if bits 0-1 == 0 -> RVA of the .xdata record (low 2 bits are 0)
            if bits 0-1 != 0 -> PACKED unwind data (no .xdata at all)

PACKED UNWIND DATA bit layout (bit 0 = LSB of the second dword):
  0-1    Flag         00 not packed / 01 packed, one prolog + one epilog /
                      10 packed, no prolog and no epilog (separated fragment) /
                      11 reserved
  2-12   FunctionLength   bytes / 4  -> max 8188 bytes
  13-15  RegF         0 = no FP regs; else RegF+1 regs saved, d8..d(8+RegF)
  16-19  RegI         count of x19..x28 saved (0-10)
  20     H            1 = homes x0-x7 in the home-parameter area
  21-22  CR           00 unchained, <x29,lr> not saved
                      01 unchained, lr saved in the int save area
                      10 chained, return address signed with pacibsp
                      11 chained, <x29,lr> stored/loaded as a pair
  23-31  FrameSize    total stack / 16 -> max 8176 bytes
  Derived: intsz = RegI*8 (+8 if CR==01); fpsz = RegF*8 (+8 if RegF);
           savsz = align16(intsz + fpsz + 64*H); locsz = FrameSize*16 - savsz.

UNPACKED .xdata, 4-byte aligned. Word 0:
  0-17   Function Length   bytes / 4 (max 1 MB)
  18-19  Vers             only 0 defined
  20     X                1 = exception handler present
  21     E                1 = the single epilog is packed into this header
  22-26  Epilog Count     E==0: number of epilog scope words that follow
                          E==1: byte index of that epilog's first unwind code
  27-31  Code Words       number of 32-bit words of unwind codes
Word 1 exists ONLY if Epilog Count == 0 AND Code Words == 0:
  0-15   Extended Epilog Count      16-23  Extended Code Words   24-31 reserved
Then, if E==0, one word per epilog scope:
  0-17   Epilog Start Offset  bytes / 4, relative to this fragment
  18-21  reserved (0)
  22-31  Epilog Start Index   byte index into the unwind code array
Then Code Words*4 bytes of unwind codes (big-endian within a multi-byte code,
padded with 0xE3 = nop). Then, if X==1, 4 bytes of Exception Handler RVA
followed by handler data (a SCOPE_TABLE, same layout as 15.4).
  Common unwind codes (first byte):
    000xxxxx alloc_s          001zzzzz save_r19r20_x
    01zzzzzz save_fplr        10zzzzzz save_fplr_x
    11000xxx alloc_m          110010xx save_regp     110011xx save_regp_x
    110100xx save_reg         1101010x save_reg_x    1101011x save_lrpair
    1101100x save_fregp       1101101x save_fregp_x  1101110x save_freg
    11011110 save_freg_x      11100000 alloc_l (+3 bytes)
    11100001 set_fp           11100010 add_fp        11100011 nop
    11100100 end              11100101 end_c         11100110 save_next
    11111100 pac_sign_lr
  Partial unwind rule: n instructions into an epilog skips n codes forward;
  n instructions into the prolog starts n codes from the end of the sequence.
ARM 32-bit (ARMNT 0x1C4) uses the same shape with different bit widths, and
sets bit 0 of the function start RVA to mark Thumb code.

--- 15.6 x86 32-bit: there is no .pdata ---
Dispatch is runtime, through a linked list on the stack whose head is
TEB.NtTib.ExceptionList at fs:[0]. Consequences: no static per-function
unwind metadata, stack walking depends on EBP chains, FPO_DATA (debug type 3)
or the PDB.

EXCEPTION_REGISTRATION_RECORD, 8 bytes, on the stack:
  0x00 4  Next     next outer record; 0xFFFFFFFF terminates the chain
  0x04 4  Handler  _except_handler3 / _except_handler4 / __CxxFrameHandler...
Registration idiom:  push handler ; push fs:[0] ; mov fs:[0], esp

MSVC _EH3 frame (_except_handler3):
  [ebp+04] return address    [ebp+00] saved ebp
  [ebp-04] TryLevel          [ebp-08] ScopeTable (plain pointer)
  [ebp-0C] Handler = &_except_handler3
  [ebp-10] Next   = old fs:[0]        <- fs:[0] points here
  ScopeTable = array of { LONG EnclosingLevel; PVOID FilterFunc;
                          PVOID HandlerFunc; }  (12 bytes each), indexed by
  TryLevel. FilterFunc == NULL marks a __finally.

MSVC _EH4 frame (_except_handler4, VS2005+ /GS) - increasing addresses:
  [ebp-18] SavedESP
  [ebp-14] ExceptionPointers
  [ebp-10] Next        }  fs:[0] points at ebp-0x10
  [ebp-0C] Handler     }
  [ebp-08] EncodedScopeTable   = scopeTablePtr XOR __security_cookie
  [ebp-04] TryLevel            initialised to -2 (0xFFFFFFFE) = no active try
  Canonical prologue: push ebp / mov ebp,esp / push -2 / push offset
  scopetable / push offset __except_handler4 / push fs:[0] / sub esp,8 /
  push ebx,esi,edi / xor [ebp-8], __security_cookie / mov eax,
  __security_cookie ; xor eax,ebp ; push eax / lea eax,[ebp-10h] ;
  mov fs:[0],eax / mov [ebp-18h],esp
  EH4_SCOPETABLE (in .rdata):
    int GSCookieOffset      (-2 = no GS cookie for this function)
    int GSCookieXOROffset
    int EHCookieOffset
    int EHCookieXOROffset
    { int EnclosingLevel; void* FilterFunc; void* HandlerFunc; } records[]
  Cookie offsets are relative to the END of the registration record, which
  equals EBP in the canonical frame, so the cookie is at [ebp + Offset] with
  Offset negative.
  Identification symbols: __except_handler4_common, _EH4_LocalUnwind,
  _EH4_GlobalUnwind2, _EH4_CallFilterFunc, _EH4_TransferToHandler,
  __security_check_cookie.
  Because the scope-table pointer is cookie-encoded and the table is
  read-only, manually mapped x86 images need the real __security_cookie of
  the mapped image for these frames to work - a known failure mode in
  reflective loaders. [PACK]
SafeSEH (/SAFESEH): the list of legal handlers lives in the load config as
SEHandlerTable / SEHandlerCount - see section 22.



================================================================================
16. DD[4] SECURITY / ATTRIBUTE CERTIFICATE TABLE       (Authenticode)
================================================================================
[!] DD[4].VirtualAddress IS A RAW FILE OFFSET, NOT AN RVA.
The certificates are never mapped into memory. The PE spec says it outright:
"the first field of this entry, which is normally an RVA, is a file pointer
instead". Treating it as an RVA is the single most common bug in home-made
PE parsers.
Read at PE32+ NT+0xA8 / PE32 NT+0x98 (VirtualAddress) and NT+0xAC / NT+0x9C
(Size).

WIN_CERTIFICATE (wintrust.h) - 8-byte header + payload
HEX  SIZE            FIELD
0x00 4               dwLength            TOTAL length INCLUDING this header
                                         AND the trailing quadword padding
0x04 2               wRevision
0x06 2               wCertificateType
0x08 dwLength-8      bCertificate        the blob (DER PKCS#7 for Authenticode)

  wRevision:
    0x0100 WIN_CERT_REVISION_1_0   legacy, verify-only
    0x0200 WIN_CERT_REVISION_2_0   current, what signtool emits
  wCertificateType:
    0x0001 WIN_CERT_TYPE_X509                 NOT SUPPORTED
    0x0002 WIN_CERT_TYPE_PKCS_SIGNED_DATA     the only one Authenticode uses
    0x0003 WIN_CERT_TYPE_RESERVED_1
    0x0004 WIN_CERT_TYPE_TS_STACK_SIGNED      NOT SUPPORTED
    (UEFI reuses the header with 0x0EF0 EFI_PKCS115 and 0x0EF1 EFI_GUID)

REAL EXAMPLE (a signed PE32+, e_lfanew = 0xF8):
  8 bytes at NT+0xA8  = F0 DD 8C 00 | 98 2E 00 00
                      -> VirtualAddress 0x008CDDF0, Size 0x2E98
  raw FILE offset 0x8CDDF0 =
      98 2E 00 00 | 00 02 | 02 00 | 30 82 2E 8C 06 09 2A 86 ...
      dwLength         0x00002E98   (== the directory Size: one cert exactly)
      wRevision        0x0200
      wCertificateType 0x0002
      bCertificate     30 82 2E 8C = DER SEQUENCE len 0x2E8C, then
                       06 09 2A 86 48 86 F7 0D 01 07 02 = OID
                       1.2.840.113549.1.7.2 = PKCS#7 signedData

INDEPENDENT PROOF THAT IT IS A FILE OFFSET (measured on this machine):
  System32\kernel32.dll  file length 0x000CC270
                         DD[4] = off 0x000C8000, size 0x00004270
                         0xC8000 + 0x4270 = 0xCC270 = EXACTLY the file length
  System32\ole32.dll     file length 0x0019CF70
                         DD[4] = off 0x00197000, size 0x00005F70
                         0x197000 + 0x5F70 = 0x19CF70 = EXACTLY the file length
  The certificate table ends precisely at EOF, which only works if the value
  is a raw file offset. Interpreted as an RVA it would land in the middle of a
  section. (notepad.exe has DD[4] = 0/0 - it is catalog-signed, not
  embedded-signed, which is the "signed with no cert table" case noted below.)

ENUMERATION (entries are contiguous and QUADWORD aligned)
  off = DD[4].VirtualAddress            // file offset
  end = off + DD[4].Size
  while (off < end) {
      cert = (WIN_CERTIFICATE*)(file + off);
      off += (cert->dwLength + 7) & ~7;   // round up to 8
  }
  Zero padding is inserted before the table to quadword-align it, and after
  each bCertificate to the next quadword boundary; dwLength and the directory
  Size both INCLUDE that padding. If the rounded lengths do not sum exactly
  to Size, the table or the Size field is corrupt.

WHAT IS EXCLUDED FROM THE AUTHENTICODE PE HASH (this is why you can patch
some bytes without breaking a signature, and not others):
  1. OptionalHeader.CheckSum - 4 bytes at NT+0x58 (same for PE32/PE32+).
     (It must be excluded because the checksum covers the certificate too.)
  2. The DD[4] entry itself - 8 bytes, BOTH VirtualAddress and Size:
       PE32  at NT+0x98        PE32+ at NT+0xA8
  3. The attribute certificate table itself: DD[4].Size bytes at file offset
     DD[4].VirtualAddress, plus the alignment padding in front of it.
  THAT IS THE COMPLETE LIST - only those three regions (4 + 8 + the cert
  table). EVERYTHING ELSE IN THE FILE IS HASHED, INCLUDING TRAILING DATA
  PAST THE LAST SECTION (the overlay).
  Hashing order:
    a. hash [0, NT+0x58)
    b. skip 4                                   (CheckSum)
    c. hash [NT+0x5C, secDirOff)                (secDirOff = NT+0x98 / NT+0xA8)
    d. skip 8                                   (the DD[4] entry)
    e. hash [secDirOff+8, SizeOfHeaders)        (rest of the headers)
    f. sort sections by PointerToRawData ascending; hash SizeOfRawData bytes
       of each in that order
    g. hash the trailing bytes: everything from the end of the last hashed
       section up to the start of the certificate table, i.e.
       fileLength - bytesHashedSoFar - certTableSize bytes
  VERIFIED ON THIS MACHINE with Get-AuthenticodeSignature on private copies
  of System32\kernel32.dll:
    pristine (len 0xCC270)                                    -> Valid
    8 bytes 0x41 appended (len 0xCC278), nothing else changed  -> NotSigned
    same 8 bytes ABSORBED into the cert table by raising both
      DD[4].Size and WIN_CERTIFICATE.dwLength 0x4270 -> 0x4278 -> Valid
  So step (g) is real: you cannot simply append to a signed file. What DOES
  work is EXPANDING the certificate region so the new bytes fall inside the
  one excluded range - that is the actual "Authenticode blob stuffing"
  technique, and it is why an oversized DD[4].Size is a red flag. [PACK]

RE CONSEQUENCES
  * You can zero the CheckSum and edit the DD[4] entry without touching the
    signed hash. You cannot edit section content.
  * A file can be validly signed with NO WIN_CERTIFICATE at all - the hash
    may live in an external security catalog (.cat). "No cert table" does not
    mean "unsigned".
  * Appended data AFTER the certificate table BREAKS the Authenticode hash
    (step g above) as well as OptionalHeader.CheckSum - verified above. The
    working variant is to grow the certificate table so the payload lands
    inside the only excluded region; that keeps the signature Valid and is a
    known abuse. Detection: DD[4].Size larger than the real PKCS#7 DER
    length. [PACK]
  * A cert table whose Size is much larger than the real PKCS#7 length =
    something is hiding in the padding.


================================================================================
17. DD[5] BASE RELOCATION TABLE   (.reloc)
================================================================================
A sequence of variable-length BLOCKS, each covering one 4 KB page. Iterate
until you have consumed DD[5].Size bytes (size-driven).

IMAGE_BASE_RELOCATION - 8-byte header + entries
HEX  SIZE   FIELD
0x00 4      VirtualAddress   RVA of the page this block patches
0x04 4      SizeOfBlock      TOTAL size of this block INCLUDING these 8 bytes
0x08 2*n    TypeOffset[]     WORD each:  bits 12-15 = Type
                                         bits 0-11  = offset within the page
  entryCount = (SizeOfBlock - 8) / 2
  next block = (BYTE*)thisBlock + SizeOfBlock
  Blocks are 4-byte aligned, so a padding entry of type 0 is added when the
  entry count is odd.

RELOCATION TYPES (IMAGE_REL_BASED_*)
0   ABSOLUTE        no-op, used as padding. SKIP IT.
1   HIGH            add the HIGH 16 bits of the delta to the 16-bit field
2   LOW             add the LOW 16 bits of the delta to the 16-bit field
3   HIGHLOW         add the full 32-bit delta to a 32-bit field  <- x86 normal
4   HIGHADJ         [!] CONSUMES TWO ENTRIES: this word, then a second word
                    that is the adjustment. The 16-bit field gets the high 16
                    bits of (field<<16 + adjustment + delta). If you do not
                    special-case this, every subsequent entry in the block is
                    misparsed.
5   MACHINE_SPECIFIC_5 = MIPS_JMPADDR / ARM_MOV32 / RISCV_HIGH20
6   RESERVED
7   MACHINE_SPECIFIC_7 = THUMB_MOV32 / RISCV_LOW12I
8   MACHINE_SPECIFIC_8 = RISCV_LOW12S / LOONGARCH32_MARK_LA /
                         LOONGARCH64_MARK_LA
9   MACHINE_SPECIFIC_9 = MIPS_JMPADDR16 / IA64_IMM64
10  DIR64           add the full 64-bit delta to a 64-bit field  <- x64 normal
  No type above 10 is defined. The Type field is 4 bits, so values 11-15 are
  representable but unassigned (16 is not representable at all); winnt.h
  stops at 10. An entry with Type 11-15 is malformed or a deliberate
  parser trap.

APPLYING THEM
  delta = actualLoadBase - OptionalHeader.ImageBase
  for each block, for each entry with Type != 0:
      target = base + block.VirtualAddress + (entry & 0x0FFF)
      patch target according to Type

RE NOTES
  * .reloc is usually MEM_DISCARDABLE and is thrown away after load, so a
    dumped image may have a valid directory pointing at zeroed pages.
  * A relocation list is a free map of every absolute address in the image -
    i.e. every pointer-sized constant the compiler emitted. Useful for
    finding vtables, string tables and function pointer arrays in stripped
    binaries.
  * DYNAMIC_BASE (0x0040) set with an empty or missing .reloc, or set at the
    same time as FileHeader RELOCS_STRIPPED (0x0001), means the image cannot
    actually move. Very common in hand-built and packed files. [PACK]
  * Packers often keep only the relocations for their own stub and rebuild the
    payload's at runtime.
  * See section 28 for the DYNAMIC VALUE RELOC TABLE, a second, different
    relocation mechanism used by CFG/ARM64X.


================================================================================
18. DD[6] DEBUG DIRECTORY
================================================================================
An ARRAY of IMAGE_DEBUG_DIRECTORY. entryCount = DD[6].Size / 28.

IMAGE_DEBUG_DIRECTORY - 28 = 0x1C bytes
HEX  DEC SIZE FIELD              NOTES
0x00 0   4    Characteristics    reserved, 0
0x04 4   4    TimeDateStamp      NOT a real date when a REPRO entry exists
0x08 8   2    MajorVersion       version of the DATA FORMAT, not of the tool
0x0A 10  2    MinorVersion       portable-PDB CodeView uses 0x504D here
0x0C 12  4    Type               IMAGE_DEBUG_TYPE_*
0x10 16  4    SizeOfData         payload size, excludes this record
0x14 20  4    AddressOfRawData   RVA of the payload when mapped; 0 if unmapped
0x18 24  4    PointerToRawData   FILE OFFSET of the payload
  Both pointers are given because the payload may live outside any section.
  Use PointerToRawData on disk, AddressOfRawData in memory.

--- 18.1 COMPLETE TYPE LIST (0..21) ---
0   UNKNOWN
1   COFF                  IMAGE_COFF_SYMBOLS_HEADER, 32 bytes = 8 DWORDs:
                          NumberOfSymbols, LvaToFirstSymbol,
                          NumberOfLinenumbers, LvaToFirstLinenumber,
                          RvaToFirstByteOfCode, RvaToLastByteOfCode,
                          RvaToFirstByteOfData, RvaToLastByteOfData
2   CODEVIEW              PDB reference or embedded CodeView - see 18.2
3   FPO                   FPO_DATA array - see 18.3
4   MISC                  IMAGE_DEBUG_MISC - see 18.4
5   EXCEPTION             verbatim copy of .pdata
6   FIXUP                 reserved
7   OMAP_TO_SRC           { DWORD rva; DWORD rvaTo; } array, 8 bytes/entry
8   OMAP_FROM_SRC         same layout, reverse direction (BBT/PGO reordering)
9   BORLAND               reserved for Borland
10  RESERVED10 / BBT      (same value, two names)
11  CLSID                 reserved
12  VC_FEATURE            20 bytes of counters - see 18.5
13  POGO                  PGO/LTCG COFF group map - see 18.6
14  ILTCG                 marker only, SizeOfData == 0
15  MPX                   Intel MPX, dead
16  REPRO                 deterministic build - see 18.7
17  (EmbeddedPortablePdb) no winnt.h name. 'MPDB' magic + uncompressed size +
                          deflate-compressed portable PDB. Entry Minor 0x0100,
                          stamp 0.
18  SPGO                  in winnt.h, absent from the MS docs table; payload
                          undocumented
19  (PdbChecksum)         no winnt.h name - see 18.8
20  EX_DLLCHARACTERISTICS 4-byte extended characteristics - see 18.9
21  (R2R PerfMap)         'R2RM' + 16-byte signature + version + UTF-8 path
  Neither Microsoft source is complete on its own: winnt.h has no name for
  17, 19 or 21, and the learn.microsoft.com table omits 12, 13, 14, 15, 18.

--- 18.2 CODEVIEW payloads ---
PDB 7.0, signature "RSDS" (file bytes 52 53 44 53), header 24 bytes:
  0x00 4    CvSignature = 0x53445352
  0x04 16   Guid       Data1 LE u32, Data2 LE u16, Data3 LE u16, Data4[8] raw
  0x14 4    Age        u32, first build = 1
  0x18 var  PdbFileName  UTF-8, NUL-terminated, length = SizeOfData - 24
  Real example (SizeOfData 0x75):
    52 53 44 53 | BA 66 20 E8 EF 35 73 48 BB DA 33 71 FD 93 2C 53
    | 01 00 00 00 | "D:\a\_w\..."
    -> GUID {E82066BA-35EF-4873-BBDA-3371FD932C53}, Age 1
  GUID + Age is the symbol-server key: symbol path =
  <name>.pdb/<GUID as 32 hex, no braces><Age in hex>/<name>.pdb
  THE EMBEDDED PDB PATH IS FREE INTELLIGENCE: build machine layout, user
  name, project name, CI paths. Always read it.
  Portable PDB variant: identical bytes but the entry's MinorVersion is
  0x504D, Age must be 1, and the match key is GUID(16) || TimeDateStamp(4).
PDB 2.0, signature "NB10" (4E 42 31 30), header 16 bytes:
  0x00 4 CvSignature = 0x3031424E | 0x04 4 Offset (0 in images)
  0x08 4 Signature (u32 timestamp) | 0x0C 4 Age | 0x10 var PdbFileName
Embedded CodeView, no PDB: 'NB09' (0x3930424E, CV 4.10) or 'NB11'
  (0x3131424E, CV 5.0): 4-byte signature + 4-byte offset to the OMF
  subsection directory, relative to the start of the blob. Legacy 'NB05',
  'NB02' also exist.

--- 18.3 FPO_DATA - 16 bytes per entry (x86 only, obsolete) ---
  0x00 4  ulOffStart   RVA of the first byte of the function
  0x04 4  cbProcSize   function size in bytes
  0x08 4  cdwLocals    bytes of locals / 4
  0x0C 2  cdwParams    bytes of params / 4
  0x0E 2  packed bitfield (LSB first):
            bits 0-7   cbProlog   prolog byte count
            bits 8-10  cbRegs     registers saved (0-7)
            bit  11    fHasSEH
            bit  12    fUseBP     EBP used as a general register
            bit  13    reserved
            bits 14-15 cbFrame    0 FRAME_FPO, 1 FRAME_TRAP, 2 FRAME_TSS,
                                  3 FRAME_NONFPO
  This is the only static stack-layout data x86 ever had. Priceless in old
  binaries that omit frame pointers.

--- 18.4 IMAGE_DEBUG_MISC ---
  0x00 4  DataType    only IMAGE_DEBUG_MISC_EXENAME = 1 is defined
  0x04 4  Length      TOTAL record length, rounded up to a multiple of 4
  0x08 1  Unicode     TRUE -> Data is UTF-16
  0x09 3  Reserved[3]
  0x0C var Data       the .DBG/exe name, NUL-terminated, zero-padded
  Records may be chained; walk with Length.

--- 18.5 VC_FEATURE - exactly 20 bytes (0x14), five LE DWORDs ---
  0x00 4  count of pre-VC++ 11.00 objects
  0x04 4  count of C/C++ objects
  0x08 4  count of objects compiled with /GS
  0x0C 4  count of objects compiled with /sdl
  0x10 4  guardN count
  Example: 00000000 44000000 44000000 00000000 14000000
    -> dumpbin: "Pre-VC++ 11.00=0, C/C++=68, /GS=68, /sdl=0, guardN=20"
  Undocumented; layout established empirically. Useful for build
  fingerprinting: "C/C++ count" is roughly the object-file count.

--- 18.6 POGO - COFF group map ---
  0x00 4    Signature (LE DWORD). Observed 0x5350474F - on disk the bytes are
            4F 47 50 53, i.e. ASCII "OGPS"; the community name "SPGO" is the
            byte-reversed reading of the same dword, so search for the DWORD
            0x5350474F, not for the text "SPGO". Also seen: 0x4C544347 (bytes
            47 43 54 4C = "GCTL" on disk, commonly called "LTCG"), and
            0x00000001 for older PGI/PGU builds.
  then entries until SizeOfData is consumed:
    +0 4    Rva      RVA of this COFF group / section contribution
    +4 4    Size     byte length
    +8 var  Name     ASCII NUL-terminated, then zero-padded so the ENTRY
                     total length is a multiple of 4
  Example from kernel32.dll: rva 0x1000 size 0x1B0 ".text\0" (+2 pad, entry
  16 bytes), then rva 0x11B0 size 0x49A20 ".text$lp00SPGO\0" (+1 pad, entry
  24 bytes) - note the RVAs are contiguous.
  THIS IS A FREE SECTION-CONTRIBUTION MAP. Names seen: .text, .text$mn,
  .text$mn$00, .text$x, .text$lp00SPGO, .idata$5, .00cfg, .gehcont, .gfids,
  .giats, .rdata, .rdata$voltmd, .rdata$zETW0..9, .rdata$zzzdbg, .xdata,
  .didat$2..7, .edata, .data, .bss, .pdata, .rsrc$01, .rsrc$02, .fogrp.
  It tells you exactly which byte ranges are hot code, CFG metadata, ETW
  strings, etc., inside a merged section.

--- 18.7 REPRO - two legal forms ---
  Form 1 (Roslyn/CLI): SizeOfData == 0 and every field except Type is 0.
    Presence alone means "deterministic build".
  Form 2 (MSVC link.exe): SizeOfData == 0x24 = 36 bytes
    0x00 4    length of the hash that follows (observed 0x20)
    0x04 32   hash bytes
    Cross-check from kernel32.dll: hash[0..15] equals the CodeView GUID and
    hash[28..31] equals the TimeDateStamp stamped on every debug entry.
    So with REPRO present, all the "dates" in the file are hash bits.

--- 18.8 PdbChecksum (type 19) ---
  0x00        AlgNameLength   algorithm name, NUL-terminated UTF-8,
                              case sensitive ("SHA256"/"SHA384"/"SHA512")
  AlgNameLen  ChecksumSize    the raw checksum (32/48/64 bytes)
  No length prefix, no padding - the algorithm name implies the size.
  SizeOfData = AlgNameLength + ChecksumSize. Multiple type-19 entries are
  legal (private + public PDB).

--- 18.9 EX_DLLCHARACTERISTICS (type 20) - 4 bytes ---
  A single LE DWORD bitmask (IMAGE_DLLCHARACTERISTICS_EX_*):
    0x01 CET_COMPAT                          shadow stacks / Intel CET
    0x02 CET_COMPAT_STRICT_MODE
    0x04 CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE
    0x08 CET_DYNAMIC_APIS_ALLOW_IN_PROC
    0x10 CET_RESERVED_1                      policy downgrade only
    0x20 CET_RESERVED_2                      policy downgrade only
    0x40 FORWARD_CFI_COMPAT                  unused by Windows
    0x80 HOTPATCH_COMPATIBLE
  Observed 0x81 = CET_COMPAT | HOTPATCH_COMPATIBLE. These are the modern
  mitigation bits that do NOT fit in the 16-bit DllCharacteristics field.

--- 18.10 RE VALUE OF THE DEBUG DIRECTORY ---
  * PDB path, GUID and Age -> symbol server lookup, build provenance.
  * Multiple entry types tell you the toolchain precisely (VC_FEATURE +
    POGO + ILTCG + REPRO = a modern optimised MSVC build).
  * Packers usually strip or zero the whole directory; a surviving debug
    directory that points at a PDB path unrelated to the file's claimed
    identity is a strong lead.
  * The payloads live outside any section in many files. They are still
    covered by the Authenticode hash (section 16 step g hashes the trailing
    bytes), so this is not a free hiding place - but they ARE outside every
    section, so tools that only walk sections miss them.


================================================================================
19. DD[7] ARCHITECTURE
================================================================================
Unused on every current architecture. Must be 0 / 0. Historically
IMAGE_DIRECTORY_ENTRY_COPYRIGHT on x86 - an ASCII copyright string - and
architecture-specific fixup data on Alpha. A non-zero value today is either
a deliberate stash or a broken generator. [PACK]



================================================================================
20. DD[8] GLOBAL POINTER
================================================================================
VirtualAddress holds the RVA to be used as the GP register value.
Size MUST be 0 (there is no structure - the "address" IS the data).
Only meaningful on IA64 / MIPS / RISC-V style targets. 0/0 on x86 and x64.


================================================================================
21. DD[9] TLS DIRECTORY
================================================================================
[!] Every "Address" field here is an ABSOLUTE VA, not an RVA. That is why a
file with a TLS directory always needs base relocations for these fields.
Size is the struct size; the loader knows the layout from the bitness.

--- IMAGE_TLS_DIRECTORY32 - 24 = 0x18 bytes ---
HEX  DEC SIZE FIELD
0x00 0   4    StartAddressOfRawData   VA of the TLS template start
0x04 4   4    EndAddressOfRawData     VA of the template end
0x08 8   4    AddressOfIndex          VA of a DWORD that the loader fills with
                                      this module's TLS slot index
0x0C 12  4    AddressOfCallBacks      VA of a NULL-terminated array of
                                      PIMAGE_TLS_CALLBACK
0x10 16  4    SizeOfZeroFill          bytes of zero after the template
0x14 20  4    Characteristics         alignment nibble 0x00F00000, plus
                                      IMAGE_SCN_SCALE_INDEX 0x00000001

--- IMAGE_TLS_DIRECTORY64 - 40 = 0x28 bytes ---
HEX  DEC SIZE FIELD
0x00 0   8    StartAddressOfRawData   VA (8 bytes)
0x08 8   8    EndAddressOfRawData     VA
0x10 16  8    AddressOfIndex          VA
0x18 24  8    AddressOfCallBacks      VA   <<< the interesting one
0x20 32  4    SizeOfZeroFill
0x24 36  4    Characteristics

HOW TLS WORKS
  The template [Start,End) plus SizeOfZeroFill zero bytes is copied for every
  new thread into a per-thread block. TEB->ThreadLocalStoragePointer points
  at an array of pointers to those blocks, indexed by the value the loader
  wrote at AddressOfIndex. So `__declspec(thread) int x` compiles to
    mov eax, fs:[2Ch]        ; x86: TEB->ThreadLocalStoragePointer
    mov ecx, [eax + _tls_index*4]
    mov eax, [ecx + offsetof_x]

TLS CALLBACKS - WHY THIS DIRECTORY MATTERS FOR RE
  AddressOfCallBacks -> array of pointers, NULL terminated. Each has the
  DllMain prototype:
    void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved);
  Reason values: 0 DLL_PROCESS_DETACH, 1 DLL_PROCESS_ATTACH,
                 2 DLL_THREAD_ATTACH, 3 DLL_THREAD_DETACH
  For the main EXE these run with DLL_PROCESS_ATTACH **BEFORE**
  AddressOfEntryPoint (after static-import DLL initialisation). They also run
  on every thread create/destroy.
  => "Break at entry point" MISSES THEM ENTIRELY. Turn on your debugger's
     "break on TLS callback" option (x64dbg: Options > Events > TLS
     Callbacks; IDA: they appear as TlsCallback_0, TlsCallback_1 ...).
  => Anti-debug, unpacking stubs, integrity checks and IsDebuggerPresent
     probes live here constantly. [PACK]
  In MSVC source a callback is placed via
    #pragma section(".CRT$XLB",read) / __declspec(allocate(".CRT$XLB"))
  so .CRT$XLB in the section contribution map (18.6) is a giveaway.

ANOMALIES [PACK]
  * A TLS directory in a file with no thread-local variables at all.
  * DD[9].Size smaller than the real struct size.
  * AddressOfCallBacks pointing into a section that is written at runtime, or
    into the header region.
  * A callback array that is empty on disk and populated by the stub.
  * Reading NT+0xD0 / NT+0xD4 (PE32+) or NT+0xC0 / NT+0xC4 (PE32) is a code
    pattern that means "does this image have TLS?".


================================================================================
22. DD[10] LOAD CONFIG DIRECTORY
================================================================================
[!] TWO SIZES EXIST AND THEY DISAGREE IN THE WILD: DD[10].Size from the data
directory, and the Size DWORD at offset 0 of the structure itself. Trust the
one at offset 0 for field presence; the loader does. Any field beyond that
Size does not exist - do not read it.
[!] The pointer-typed fields in here are ABSOLUTE VAs, not RVAs (except the
few explicitly named ...Offset / ...Section).

sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32) = 0xC4 = 196
sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) = 0x148 = 328

--- 22.1 32-BIT LAYOUT ---
HEX  SIZE FIELD
0x00 4    Size                        <- version discriminator
0x04 4    TimeDateStamp
0x08 2    MajorVersion
0x0A 2    MinorVersion
0x0C 4    GlobalFlagsClear            bits to CLEAR in PEB->NtGlobalFlag
0x10 4    GlobalFlagsSet              bits to SET   in PEB->NtGlobalFlag
0x14 4    CriticalSectionDefaultTimeout
0x18 4    DeCommitFreeBlockThreshold
0x1C 4    DeCommitTotalFreeThreshold
0x20 4    LockPrefixTable             VA; x86 uniprocessor lock patching
0x24 4    MaximumAllocationSize
0x28 4    VirtualMemoryThreshold
0x2C 4    ProcessHeapFlags            <- note the order vs 64-bit
0x30 4    ProcessAffinityMask
0x34 2    CSDVersion
0x36 2    DependentLoadFlags          LoadLibrary flags for dependencies
0x38 4    EditList                    VA, reserved
0x3C 4    SecurityCookie              VA of __security_cookie (/GS)
0x40 4    SEHandlerTable              VA of the SafeSEH RVA table
0x44 4    SEHandlerCount              number of entries
0x48 4    GuardCFCheckFunctionPointer     VA of __guard_check_icall_fptr
0x4C 4    GuardCFDispatchFunctionPointer  VA of __guard_dispatch_icall_fptr
0x50 4    GuardCFFunctionTable            VA of the GFIDS table
0x54 4    GuardCFFunctionCount            entry count (NOT bytes)
0x58 4    GuardFlags                      IMAGE_GUARD_*
0x5C 12   CodeIntegrity  { WORD Flags; WORD Catalog; DWORD CatalogOffset;
                           DWORD Reserved; }
0x68 4    GuardAddressTakenIatEntryTable  VA
0x6C 4    GuardAddressTakenIatEntryCount
0x70 4    GuardLongJumpTargetTable        VA
0x74 4    GuardLongJumpTargetCount
0x78 4    DynamicValueRelocTable          VA
0x7C 4    CHPEMetadataPointer             VA (x86-on-ARM64 hybrid metadata)
0x80 4    GuardRFFailureRoutine           VA
0x84 4    GuardRFFailureRoutineFunctionPointer VA
0x88 4    DynamicValueRelocTableOffset    offset within the section below
0x8C 2    DynamicValueRelocTableSection   1-based section index
0x8E 2    Reserved2
0x90 4    GuardRFVerifyStackPointerFunctionPointer VA
0x94 4    HotPatchTableOffset
0x98 4    Reserved3
0x9C 4    EnclaveConfigurationPointer     VA
0xA0 4    VolatileMetadataPointer         VA
0xA4 4    GuardEHContinuationTable        VA
0xA8 4    GuardEHContinuationCount
0xAC 4    GuardXFGCheckFunctionPointer    VA
0xB0 4    GuardXFGDispatchFunctionPointer VA
0xB4 4    GuardXFGTableDispatchFunctionPointer VA
0xB8 4    CastGuardOsDeterminedFailureMode VA
0xBC 4    GuardMemcpyFunctionPointer      VA
0xC0 4    UmaFunctionPointers             VA   (last field, SDK 26100)

--- 22.2 64-BIT LAYOUT ---
HEX   SIZE FIELD
0x00  4    Size
0x04  4    TimeDateStamp
0x08  2    MajorVersion
0x0A  2    MinorVersion
0x0C  4    GlobalFlagsClear
0x10  4    GlobalFlagsSet
0x14  4    CriticalSectionDefaultTimeout
0x18  8    DeCommitFreeBlockThreshold
0x20  8    DeCommitTotalFreeThreshold
0x28  8    LockPrefixTable
0x30  8    MaximumAllocationSize
0x38  8    VirtualMemoryThreshold
0x40  8    ProcessAffinityMask         <- SWAPPED relative to the 32-bit form
0x48  4    ProcessHeapFlags            <-
0x4C  2    CSDVersion
0x4E  2    DependentLoadFlags
0x50  8    EditList
0x58  8    SecurityCookie
0x60  8    SEHandlerTable              (x86-only concept, present anyway)
0x68  8    SEHandlerCount
0x70  8    GuardCFCheckFunctionPointer
0x78  8    GuardCFDispatchFunctionPointer
0x80  8    GuardCFFunctionTable
0x88  8    GuardCFFunctionCount
0x90  4    GuardFlags
0x94  12   CodeIntegrity
0xA0  8    GuardAddressTakenIatEntryTable
0xA8  8    GuardAddressTakenIatEntryCount
0xB0  8    GuardLongJumpTargetTable
0xB8  8    GuardLongJumpTargetCount
0xC0  8    DynamicValueRelocTable
0xC8  8    CHPEMetadataPointer
0xD0  8    GuardRFFailureRoutine
0xD8  8    GuardRFFailureRoutineFunctionPointer
0xE0  4    DynamicValueRelocTableOffset
0xE4  2    DynamicValueRelocTableSection
0xE6  2    Reserved2
0xE8  8    GuardRFVerifyStackPointerFunctionPointer
0xF0  4    HotPatchTableOffset
0xF4  4    Reserved3
0xF8  8    EnclaveConfigurationPointer
0x100 8    VolatileMetadataPointer
0x108 8    GuardEHContinuationTable
0x110 8    GuardEHContinuationCount
0x118 8    GuardXFGCheckFunctionPointer
0x120 8    GuardXFGDispatchFunctionPointer
0x128 8    GuardXFGTableDispatchFunctionPointer
0x130 8    CastGuardOsDeterminedFailureMode
0x138 8    GuardMemcpyFunctionPointer
0x140 8    UmaFunctionPointers          (last field, SDK 26100)

--- 22.3 VERSION BY Size VALUE (every legal truncation point) ---
  32-bit: 0x40 0x48 0x5C 0x68 0x70 0x78 0x80 0x88 0x90 0x94 0x9C 0xA0 0xA4
          0xAC 0xB8 0xBC 0xC0 0xC4
  64-bit: 0x60 0x70 0x94 0xA0 0xB0 0xC0 0xC8 0xD0 0xD8 0xE0 0xE8 0xF0 0xF4
          0xF8 0x100 0x108 0x110 0x118 0x120 0x130 0x138 0x140 0x148
  Useful landmarks:
    32-bit 0x40 = the XP-era minimum (everything up to SecurityCookie)
    32-bit 0x48 = the first size that actually contains SafeSEH data
    64-bit 0x70 = up to SEHandlerCount, pre-CFG
    64-bit 0x94/0xA0 = CFG era (Win8.1/Win10 1507)
    Measured on a current Windows 11 install (26100-class winnt.h):
    SysWOW64\ntdll.dll = 0xC4, System32\ntdll.dll = 0x148 (i.e. the full
    current structures).
  A Size that is not one of these values, or that disagrees wildly with
  DD[10].Size, is worth a second look. [PACK]

--- 22.4 GuardFlags (IMAGE_GUARD_*) ---
0x00000100 CF_INSTRUMENTED                    module performs CFG checks
0x00000200 CFW_INSTRUMENTED                   + write-integrity checks
0x00000400 CF_FUNCTION_TABLE_PRESENT          GFIDS table is valid
0x00000800 SECURITY_COOKIE_UNUSED             module does not use /GS
0x00001000 PROTECT_DELAYLOAD_IAT              delay-load IAT is made
                                              read-only after patching
0x00002000 DELAYLOAD_IAT_IN_ITS_OWN_SECTION   so it can be re-protected
                                              (this is why .didat exists)
0x00004000 CF_EXPORT_SUPPRESSION_INFO_PRESENT
0x00008000 CF_ENABLE_EXPORT_SUPPRESSION
0x00010000 CF_LONGJUMP_TABLE_PRESENT
0x00020000 RF_INSTRUMENTED                    Return Flow Guard
0x00040000 RF_ENABLE
0x00080000 RF_STRICT
0x00100000 RETPOLINE_PRESENT
0x00200000 (burned - do not use)
0x00400000 EH_CONTINUATION_TABLE_PRESENT
0x00800000 XFG_ENABLED                        eXtended Flow Guard (marked
                                              deprecated in the header)
0x01000000 CASTGUARD_PRESENT
0x02000000 MEMCPY_PRESENT
0xF0000000 CF_FUNCTION_TABLE_SIZE_MASK        shift right by 28

--- 22.5 The GFIDS table (GuardCFFunctionTable) ---
  Entry = DWORD Rva, followed by N extra metadata bytes where
    N = (GuardFlags & 0xF0000000) >> 28      (N == 1 in practice)
  so the stride is 4 + N. The table is SORTED ascending by RVA.
  GuardCFFunctionCount is an ENTRY count, not a byte count.
  Metadata byte 0 bits:
    0x01 FID_SUPPRESSED           0x02 EXPORT_SUPPRESSED
    0x04 FID_LANGEXCPTHANDLER     0x08 FID_XFG
  WHY YOU CARE: this table is a LIST OF EVERY VALID INDIRECT CALL TARGET in
  the module - effectively a compiler-provided function-start list. On a
  stripped CFG-enabled binary it is the second-best function oracle after
  .pdata. IDA will use it if you let it.
  __guard_check_icall_fptr / __guard_dispatch_icall_fptr are what every
  indirect call goes through; seeing "call cs:__guard_dispatch_icall_fptr"
  everywhere is normal, not obfuscation.

--- 22.6 SafeSEH (x86 only) ---
  SEHandlerTable (VA) -> a table of RVAs, one per legal SE handler, sorted
  ascending. SEHandlerCount = entry count. RtlIsValidHandler binary searches
  it. If an image is SEH-aware and a handler inside it is not in the table,
  the process is terminated. DllCharacteristics NO_SEH (0x0400) means "no
  handler in this image may ever be called"; SEHandlerCount == 0 with the
  SafeSEH marking has the same effect.
  Object-file side: .sxdata (LNK_INFO, x86 objects) holds COFF symbol indices
  of registered handlers, and the absolute symbol @feat.00 with bit 0 set
  marks the object as SafeSEH-aware.

--- 22.7 Other sub-structures reachable from here ---
  EnclaveConfigurationPointer -> IMAGE_ENCLAVE_CONFIG32/64 (0x4C / 0x50
    bytes; the only difference is EnclaveSize being 4 vs 8 bytes at 0x40).
    Minimum config size 0x48 / 0x4C. Followed by IMAGE_ENCLAVE_IMPORT
    records (0x50 bytes each, ImportName at 0x48, MatchType 0-4). VBS
    enclaves only.
  VolatileMetadataPointer -> IMAGE_VOLATILE_METADATA, 24 bytes, in NO SDK
    header but present in real binaries:
      0x00 4 Size = 0x18       0x04 2 MinVersion    0x06 2 MaxVersion
      0x08 4 VolatileAccessTable RVA
      0x0C 4 VolatileAccessTableSize
      0x10 4 VolatileInfoRangeTable RVA
      0x14 4 VolatileInfoRangeTableSize
    The access table is a DWORD RVA array; the info-range table is an array
    of { DWORD Rva; DWORD Size; }.
  DynamicValueRelocTable -> see section 28.
  CHPEMetadataPointer -> x86-on-ARM64 hybrid metadata (see 28).
  GuardEHContinuationTable -> sorted RVA list of legal EH continuation
    targets (the EHCONT mitigation).


================================================================================
23. DD[11] BOUND IMPORT DIRECTORY
================================================================================
Pre-computed import addresses baked in at link time (link /BIND, editbin
/bind, or the old bind.exe). Obsolete since ASLR made it pointless - measured
0 of 250 System32 DLLs still have one - but you WILL meet stale ones.

IMAGE_BOUND_IMPORT_DESCRIPTOR - 8 bytes
HEX  SIZE FIELD
0x00 4    TimeDateStamp                  the target DLL's TimeDateStamp at
                                         bind time
0x04 2    OffsetModuleName               [!] byte offset from the START OF THE
                                         FIRST DESCRIPTOR, not an RVA
0x06 2    NumberOfModuleForwarderRefs    how many IMAGE_BOUND_FORWARDER_REF
                                         records follow THIS descriptor

IMAGE_BOUND_FORWARDER_REF - 8 bytes (same shape, third field reserved)
0x00 4    TimeDateStamp
0x04 2    OffsetModuleName
0x06 2    Reserved

  The array is a flat sequence: descriptor, its forwarder refs, next
  descriptor, ... terminated by an all-zero descriptor. Size-driven.
  The blob normally sits in the header gap, where RVA == file offset anyway.

VALIDATION
  The loader accepts the pre-bound IAT only if, for the descriptor AND every
  forwarder ref, TimeDateStamp equals the target module's
  FileHeader.TimeDateStamp, and the image loaded at its preferred base. Any
  mismatch -> throw away the pre-bound values and re-snap everything by name.
  Related: IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp is 0 (unbound),
  0xFFFFFFFF (bound, new style - real stamps live here in DD[11]), or a real
  stamp (bound, old style). DllCharacteristics NO_BIND (0x0800) forbids
  binding this image.

WHY IT IS USEFUL TO YOU
  Stale bound descriptors are (a) a tamper indicator, and (b) a RECOVERY
  SOURCE: the bound table still lists the original DLL names even when the
  import directory has been wiped or encrypted by a packer. [PACK]


================================================================================
24. DD[12] IAT
================================================================================
VirtualAddress = RVA of the FIRST import address table thunk,
Size = total bytes covering ALL the IAT thunk arrays of all descriptors
(they are laid out contiguously by the linker).

The loader uses this only to know which pages to make writable during
snapping and then optionally read-only again. Everything functional comes
from DD[1]. Contents are the same IMAGE_THUNK_DATA slots described in 13.

WHY IT MATTERS: it is the authoritative IAT bounds for rebuilding imports on
a dumped sample. If it is zeroed (common), reconstruct the range yourself:
  1. Go to the import resolver / the first thunk your code calls.
  2. Read the slot RVA it dereferences -> that is inside the IAT.
  3. Walk BACKWARDS in pointer-size steps while the values still look like
     addresses inside loaded modules (or are 0) -> IAT_START.
  4. Walk FORWARDS the same way -> last valid slot; IAT_END = that slot +
     pointer size.
     e.g. x64 with base 0x140000000: if the resolver's slot RVA is 0xABCD,
     IAT_START = 0x140000000 + 0xABCD; if the last slot RVA is 0xDEF0,
     IAT_END = 0x140000000 + 0xDEF0 + 8.
  5. Feed START/SIZE to Scylla / ImpREC and let it rebuild names.
Sanity checks: the IAT is pointer-aligned, is usually one contiguous run per
DLL separated by a single 0 slot, and lives in a section that is writable at
load time.


================================================================================
25. DD[13] DELAY IMPORT DESCRIPTOR
================================================================================
  PE32  : RVA at NT+0xE0, Size at NT+0xE4
  PE32+ : RVA at NT+0xF0, Size at NT+0xF4
Terminator-driven: an ARRAY of 32-byte descriptors ending with an all-zero
one. DD[13].Size is ignored by the runtime. Many tools do not display this
table at all, which is exactly why a "missing" import can be hiding here.

IMAGE_DELAYLOAD_DESCRIPTOR / ImgDelayDescr - 32 = 0x20 bytes, 8 DWORDs
HEX  DEC SIZE FIELD                        MEANING
0x00 0   4    Attributes (grAttrs)         bit 0 = dlattrRva (see below)
0x04 4   4    DllNameRVA                   RVA of the DLL name, ASCII
0x08 8   4    ModuleHandleRVA              RVA of a pointer-sized slot that
                                           caches the HMODULE
0x0C 12  4    ImportAddressTableRVA        RVA of the delay IAT (patched)
0x10 16  4    ImportNameTableRVA           RVA of the delay INT (names/ords)
0x14 20  4    BoundImportAddressTableRVA   RVA of the pre-bound IAT, or 0
0x18 24  4    UnloadInformationTableRVA    RVA of a copy of the ORIGINAL IAT
                                           (the thunk addresses), or 0
0x1C 28  4    TimeDateStamp                the bind timestamp, or 0

  Attributes:
    0x00000001  dlattrRva  "delay load version 2" (VC7.0+): the seven fields
                above are RVAs. THIS IS ALWAYS SET IN MODERN BINARIES.
    0x00000000  the legacy VC6 form, where the same dwords hold ABSOLUTE VAs.
                __delayLoadHelper2 rejects it with
                RaiseException(0xC06D0057).
  Note the fields are the same width (4 bytes) in PE32 and PE32+ - only the
  THUNK SLOTS in the tables they point to are 8 bytes wide on x64.

--- 25.1 HOW A DELAY-LOADED CALL ACTUALLY WORKS ---
  1. The compiler emits `call [__imp_Func]` exactly as for a normal import,
     but the slot initially contains the address of a per-function LOAD THUNK
     instead of the real function.
  2. The load thunk stuffs its own delay-IAT slot address into a register and
     jumps to a per-DLL TAIL MERGE stub.
  3. The tail merge stub loads the address of this DLL's
     IMAGE_DELAYLOAD_DESCRIPTOR and calls __delayLoadHelper2(descriptor,
     &iatSlot).
  4. The helper:
       slotIndex = &iatSlot - ImportAddressTableRVA_base
       looks up ImportNameTableRVA[slotIndex] for the name or ordinal
       calls the optional user hook (dliStartProcessing / dliNotePreLoadLibrary
        / dliNotePreGetProcAddress / dliFailLoadLib / dliFailGetProc /
        dliNoteEndProcessing = codes 0..5)
       hmod = *ModuleHandleRVA, else LoadLibraryEx(DllNameRVA), cached with
        InterlockedExchangePointer (a duplicate load is FreeLibrary'd)
       pfn = GetProcAddress(hmod, name-or-ordinal)
       fast path: if BoundImportAddressTableRVA != 0 && TimeDateStamp != 0 &&
        the target has a valid NT signature && its FileHeader.TimeDateStamp
        matches && it loaded at its OptionalHeader.ImageBase -> take the
        pre-bound address instead of calling GetProcAddress
       writes *iatSlot = pfn, using VirtualProtect around the write when
        IMAGE_GUARD_PROTECT_DELAYLOAD_IAT (0x1000) is set
       returns pfn; the stub jumps to it
     Failures raise SEH exceptions: 0xC06D007E VcppException(ERROR_SEVERITY_
     ERROR, ERROR_MOD_NOT_FOUND) and 0xC06D007F (ERROR_PROC_NOT_FOUND).
  5. Every later call goes straight through the now-patched slot. Zero
     overhead after the first hit.
  UNLOAD: __FUnloadDelayLoadedDLL2 uses UnloadInformationTableRVA to restore
  the ORIGINAL thunk addresses into the IAT, calls FreeLibrary, and zeroes
  *ModuleHandleRVA - so the next call re-triggers the whole dance.

--- 25.2 WHAT IT LOOKS LIKE IN THE DISASSEMBLY ---
  x86 load thunk:      B8 <imm32>            mov eax, offset __imp_Func
                       E9 <rel32>            jmp __tailMerge_DLLNAME
  x86 tail merge:      51 52 50 68 <imm32> E8 <rel32> 5A 59 FF E0
                       push ecx / push edx / push eax /
                       push offset descriptor / call __delayLoadHelper2 /
                       pop edx / pop ecx / jmp eax
  x64 load thunk:      48 8D 05 <disp32>     lea rax, __imp_Func
                       E9 <rel32>            jmp __tailMerge_DLLNAME
  x64 tail merge:      homes rcx/rdx/r8/r9 into the shadow space,
                       sub rsp,68h, saves xmm0-xmm3, mov rdx,rax,
                       lea rcx,<descriptor>, call __delayLoadHelper2,
                       restores everything, jmp rax
  LINKER SYMBOL PREFIXES you will see in symbols or can name yourself:
    __imp_load_<Func>            the load thunk
    __tailMerge_<DLLNAME>        the per-DLL stub
    __DELAY_IMPORT_DESCRIPTOR_<DLLNAME>
    __NULL_DELAY_IMPORT_DESCRIPTOR
    __hmod__<DLLNAME>            the module handle slot
    __sz<...>                    the name strings
  IDA labels these __imp_load_* when symbols allow; without symbols you get a
  cluster of tiny mov/jmp thunks all funnelling into one stub that calls one
  function - that stub IS __delayLoadHelper2.

--- 25.3 DelayLoadInfo (passed to hooks; useful when reversing a hook) ---
  cb, pidd (descriptor ptr), ppfn (IAT slot ptr), szDll, dlp (DelayLoadProc:
  fImportByName + name-or-ordinal union), hmodCur, pfnCur, dwLastError.
  Total size: x86 36 bytes, x64 72 bytes.

--- 25.4 RE NOTES ---
  * Delay imports are REAL imports. A sample whose static import table looks
    innocent can pull in wininet/ws2_32/advapi32 entirely through DD[13].
    Always check both tables.
  * Measured: 107 of 250 System32 DLLs sampled have a delay import directory,
    so its presence is completely normal in legitimate binaries. (Different
    sample size from the 600-DLL figures quoted elsewhere in this file.)
  * The delay IAT is writable and is patched at runtime -> a natural hooking
    target, and the reason for the .didat section plus the two guard flags
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT (0x1000) and
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION (0x2000).
  * On a memory dump, delay IAT slots that were never called still contain
    thunk addresses, not API addresses - do not mistake them for resolved
    imports.
  * A hand-crafted DD[13] with Attributes == 0 is a legacy/forged table; the
    real runtime would refuse it.


================================================================================
26. DD[14] CLR RUNTIME HEADER  (.NET / COM+ 2.0)
================================================================================
IMAGE_COR20_HEADER - 72 = 0x48 bytes. Non-zero => this is a managed assembly.

HEX  DEC SIZE FIELD
0x00 0   4    cb                       = 72 (0x48)
0x04 4   2    MajorRuntimeVersion      2
0x06 6   2    MinorRuntimeVersion      5
0x08 8   8    MetaData                 IMAGE_DATA_DIRECTORY -> the metadata
                                       root (RVA at 0x08, Size at 0x0C)
0x10 16  4    Flags                    COMIMAGE_FLAGS_*
0x14 20  4    EntryPointToken /        a metadata token (usually a MethodDef,
              EntryPointRVA            table 0x06) - OR an RVA if
                                       COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set
0x18 24  8    Resources                IMAGE_DATA_DIRECTORY
0x20 32  8    StrongNameSignature      IMAGE_DATA_DIRECTORY
0x28 40  8    CodeManagerTable         reserved, 0
0x30 48  8    VTableFixups             IMAGE_DATA_DIRECTORY
0x38 56  8    ExportAddressTableJumps  IMAGE_DATA_DIRECTORY
0x40 64  8    ManagedNativeHeader      IMAGE_DATA_DIRECTORY (NGEN / ReadyToRun)

  Flags (COMIMAGE_FLAGS_*):
    0x00000001 ILONLY               pure IL, no native code
    0x00000002 32BITREQUIRED        must run as 32-bit
    0x00000004 IL_LIBRARY
    0x00000008 STRONGNAMESIGNED
    0x00000010 NATIVE_ENTRYPOINT    EntryPointToken field is an RVA instead
    0x00010000 TRACKDEBUGDATA
    0x00020000 32BITPREFERRED       AnyCPU-prefer-32-bit
  The 32BITREQUIRED/32BITPREFERRED pair encodes the platform:
    00 = AnyCPU (64-bit on x64), 10 = x86, 01 = invalid, 11 = AnyCPU 32-bit
    preferred.

--- 26.1 The metadata root (at the MetaData RVA) ---
  0x00 4    Signature = 0x424A5342  ("BSJB")
  0x04 2    MajorVersion   1
  0x06 2    MinorVersion   1
  0x08 4    Reserved       0
  0x0C 4    Length         byte length of the version string, rounded up to a
                           multiple of 4 (12 for "v4.0.30319")
  0x10 L    Version        UTF-8, NUL-terminated, zero-padded
  then 2    Flags          0
  then 2    Streams        number of stream headers
  then      stream headers, each: DWORD Offset (from the metadata root),
            DWORD Size, then the name as ASCII NUL-terminated and padded to a
            4-byte boundary
  Stream names:
    #~        compressed metadata tables (the normal case)
    #-        UNcompressed/editable tables (ENC, obfuscators, some packers)
    #Strings  identifier heap        #US   user string heap (UTF-16 literals)
    #GUID     GUID heap              #Blob signature/constant heap
    #Pdb      embedded portable PDB   #JTD  minimal-delta marker
  The #~ header starts: Reserved(4)=0, Major(1)=2, Minor(1)=0, HeapSizes(1),
  Reserved(1)=1, Valid(8) bitmask of present tables, Sorted(8), then the row
  counts for each present table.

--- 26.2 The native stub in a managed EXE ---
  Older/32-bit managed images keep a tiny native entry point:
    FF 25 <abs32>     jmp dword ptr [__imp__CorExeMain]   (EXE)
                      jmp dword ptr [__imp__CorDllMain]   (DLL)
  with a single import of mscoree.dll. Verified: InstallUtil.exe has
  FF 25 00 20 40 00 -> jmp [0x00402000]. A .NET 9 AnyCPU DLL still carries
  FF 25 00 20 00 10.
  Modern x64 managed images typically have AddressOfEntryPoint == 0 and no
  import/IAT directories at all - the OS loader recognises the CLR header.
  ReadyToRun/NGEN images put "RTR\0" at ManagedNativeHeader.
  RE consequence: for a managed binary, stop reversing the native code and
  switch to dnSpy/ILSpy/dotPeek. Native code in a file with a CLR header
  means mixed mode (C++/CLI) or a native payload bolted on.


================================================================================
27. DD[15] RESERVED
================================================================================
Must be 0 / 0. Non-zero is an anomaly. [PACK]


================================================================================
28. DYNAMIC VALUE RELOC TABLE / ARM64X / CHPE
================================================================================
Reached through LoadConfig.DynamicValueRelocTable (a VA) or through
DynamicValueRelocTableOffset + DynamicValueRelocTableSection (an offset into
a numbered section). A SECOND relocation mechanism, unrelated to DD[5], used
for retpoline/import-optimisation patching and for ARM64X.

  IMAGE_DYNAMIC_RELOCATION_TABLE:  DWORD Version; DWORD Size;
  then per-entry: Symbol (pointer-sized) + BaseRelocSize (DWORD), followed by
  ordinary IMAGE_BASE_RELOCATION blocks scoped to that Symbol.

  Symbol values (IMAGE_DYNAMIC_RELOCATION_*):
    1  GUARD_RF_PROLOGUE                    5  GUARD_SWITCHTABLE_BRANCH
    2  GUARD_RF_EPILOGUE                    6  ARM64X
    3  GUARD_IMPORT_CONTROL_TRANSFER        7  FUNCTION_OVERRIDE
    4  GUARD_INDIR_CONTROL_TRANSFER         8  ARM64_KERNEL_IMPORT_CALL_TRANSFER
  Symbols 3/4/5 are how retpoline and import-call optimisation get patched in
  at load time: the file ships a generic indirect call and the loader
  rewrites it in place. So the bytes you disassemble statically are NOT
  necessarily the bytes that execute. [PACK-adjacent, but this is Microsoft
  doing it]

  ARM64X fixups (Symbol == 6). Each record is a 16-bit word:
    bits 0-11   Offset    within the 4 KB page of the enclosing
                          IMAGE_BASE_RELOCATION block
    bits 12-13  Type      0 ZEROFILL, 1 VALUE, 2 DELTA
    bits 14-15  Size      for ZEROFILL/VALUE: 0 -> 2 bytes, 1 -> 4, 2 -> 8
  For Type 1 (VALUE) the record is followed by that many bytes of replacement
  data. For Type 2 (DELTA) the record is followed by a USHORT and the applied
  delta is  value * (Scale ? 8 : 4) * (Sign ? -1 : +1), where bit 14 is Sign
  and bit 15 is Scale.
  [This record layout is community-derived from the loader and from ARM64X
  binaries; it is not declared in winnt.h. The Type/Size semantics are solid,
  the DELTA sign/scale bit assignment is the part to double-check against a
  real sample.]
  Net effect: the loader turns ONE file into either an ARM64 or an ARM64EC
  view of the same image. That is why an ARM64X binary appears to contain two
  different byte sequences at the same RVA depending on which process loads
  it - if your disassembly of an ARM64X file looks like nonsense, you are
  probably looking at the un-transformed view.
  CHPEMetadataPointer serves the analogous role for x86-on-ARM64 hybrid
  images (Machine 0x3A64), describing the mapping between x86 code addresses
  and their ARM64 counterparts. HotPatchTableOffset points at an
  IMAGE_HOT_PATCH_INFO block used by hotpatching; neither is laid out here -
  read them with the SDK types if you meet one.



================================================================================
                              PART III - MECHANICS
================================================================================

================================================================================
29. RVA <-> FILE OFFSET, ALIGNMENT, OVERLAY
================================================================================
--- 29.1 The conversion ---
Find the section that contains the RVA:
  VirtualAddress <= RVA < VirtualAddress + max(VirtualSize, SizeOfRawData)
then
  fileOffset = PointerToRawData + (RVA - VirtualAddress)
  RVA        = VirtualAddress   + (fileOffset - PointerToRawData)
In a loaded module no conversion is needed at all:
  realAddress = moduleBase + RVA

--- 29.2 The edge cases that break naive converters ---
  a) RVA < SizeOfHeaders and below the first section's VirtualAddress:
     it is inside the HEADERS, which are mapped at RVA 0. fileOffset == RVA.
  b) SizeOfRawData == 0 (pure .bss): the RVA has NO file representation. Any
     answer you compute is wrong; the correct result is "zero bytes".
  c) VirtualSize > SizeOfRawData: RVAs past PointerToRawData + SizeOfRawData
     are zero-filled memory with no file bytes behind them. Using
     max(VirtualSize, SizeOfRawData) in the containment test keeps you from
     silently landing in the next section, but you must then clamp the read.
  d) SizeOfRawData > VirtualSize: the extra file bytes are NOT mapped. Data
     there is invisible at runtime - a classic cave. [PACK]
  e) Two sections claiming overlapping virtual ranges: the loader maps them
     in table order, so the LAST one wins for the overlapping pages, while
     most tools report the first. [PACK]
  f) The gap between the end of the headers and the first PointerToRawData,
     and the FileAlignment padding after each section, exist on disk and are
     not mapped. Bound imports legitimately live in the first gap.

--- 29.3 Alignment rules ---
  FileAlignment    : power of two, 0x200 (512) .. 0x10000 (65536). Default
                     0x200. PointerToRawData and SizeOfRawData are multiples
                     of it. SizeOfHeaders is rounded up to it.
  SectionAlignment : must be >= FileAlignment. Default 0x1000 (one page).
                     VirtualAddress is a multiple of it, and SizeOfImage is
                     the aligned end of the last section.
  Measured on 600 System32 DLLs (what "normal" looks like):
    SectionAlignment/FileAlignment = 0x1000/0x1000 (512 files),
    0x1000/0x200 (85), 0x2000/0x200 (2), 0x2000/0x1000 (1).

--- 29.4 LOW-ALIGNMENT ("unaligned") IMAGES [PACK] ---
  If SectionAlignment < 0x1000 then FileAlignment MUST EQUAL SectionAlignment.
  Such an image is mapped FLAT: the file is copied contiguously to the load
  address, so
      RVA == FILE OFFSET everywhere
  Per-section protection cannot be applied at sub-page granularity, so the
  whole image ends up effectively RWX. This is how sub-1 KB PEs, tiny
  droppers and the famous "smallest PE" files work, and it is why dumpers
  that assume RVA != offset produce garbage on them. Recognise it instantly:
  SectionAlignment == FileAlignment && SectionAlignment < 0x1000.

--- 29.5 OVERLAY (appended data) ---
  overlayStart = max over all sections of (PointerToRawData + SizeOfRawData)
  overlaySize  = fileSize - overlayStart
  The overlay is not mapped and is not part of any section. It holds:
    - installer payloads (NSIS, InnoSetup, 7z SFX, WinRAR SFX)
    - the Authenticode certificate table (compare against DD[4]; if the
      overlay starts exactly at DD[4].VirtualAddress it is just the signature)
    - COFF symbols / .DBG data pointed to by PointerToSymbolTable or the
      debug directory
    - a second-stage payload, appended config, or a decoy
  A large overlay that is NOT the certificate table is always worth dumping.
  Note: the overlay is covered by OptionalHeader.CheckSum AND by the
  Authenticode hash (section 16 step g). Only the certificate table region
  itself is excluded, so appending to a signed file invalidates it.


================================================================================
30. WHAT THE WINDOWS LOADER ACTUALLY DOES, IN ORDER
================================================================================
 31. Open the file, create a section object. Validate MZ, e_lfanew, "PE\0\0",
    Machine, alignment, SizeOfImage (section 31).
 32. Reserve SizeOfImage bytes of VA. Preferred base = ImageBase; with ASLR
    (DYNAMIC_BASE and no RELOCS_STRIPPED) a random base is chosen instead.
 33. Map the headers at RVA 0 (SizeOfHeaders bytes, read-only), then each
    section at its VirtualAddress with the protection implied by its MEM_*
    characteristics, copying
      min(round(SizeOfRawData,FileAlignment), round(VirtualSize,SectionAlignment))
    bytes and zero-filling the remainder.
 34. If the actual base != ImageBase, apply DD[5] base relocations with
    delta = actualBase - ImageBase. If relocations are needed but stripped,
    the load fails.
 35. Apply DD[10] load config effects: GlobalFlagsSet/Clear into
    PEB->NtGlobalFlag, CriticalSectionDefaultTimeout, ProcessHeapFlags,
    register the SafeSEH / CFG / EHCONT tables, initialise the security
    cookie.
 36. Resolve DD[1] imports: for each descriptor LoadLibrary the DLL
    (recursively, depth-first, with its own imports resolved first), then
    snap every thunk. Bound imports (DD[11]) short-circuit this when their
    timestamps match. API set names are redirected through PEB->ApiSetMap.
    Delay imports (DD[13]) are NOT touched here - they resolve on first call.
 37. Set final page protections; make the IAT read-only again if the guard
    flags ask for it.
 38. Allocate the TLS slot, copy the TLS template, fill *AddressOfIndex.
 39. Call each dependency DLL's entry point with DLL_PROCESS_ATTACH, in
    dependency order.
40. Run the EXE's TLS callbacks (DD[9]) with DLL_PROCESS_ATTACH.
    ***THIS HAPPENS BEFORE THE ENTRY POINT.***
41. Jump to AddressOfEntryPoint.
For a later LoadLibrary: steps 1-9 again for that DLL, then its TLS
callbacks, then DllMain(DLL_PROCESS_ATTACH).
Order that matters for RE: static imports resolve before ANY of your code
runs, TLS callbacks run before the entry point, and delay imports resolve
lazily much later.


================================================================================
31. LOADER VALIDATION - WHAT IS REJECTED, WHAT IS TOLERATED
================================================================================
Statuses you will see: STATUS_INVALID_IMAGE_FORMAT 0xC000007B
(-> ERROR_BAD_EXE_FORMAT 193), STATUS_INVALID_IMAGE_NOT_MZ 0xC000012F,
STATUS_INVALID_IMAGE_PROTECT 0xC0000130, STATUS_INVALID_IMAGE_WIN_32
0xC0000359, STATUS_INVALID_IMAGE_WIN_64 0xC000035A.

REJECTED
  * file smaller than 0x40, or e_magic != 0x5A4D
  * e_lfanew <= 0, or huge (the ReactOS/Wine implementation caps it at
    0x10000000 = 256 MB), or e_lfanew + sizeof(NT headers) past EOF
  * Signature != 0x00004550
  * Magic not 0x10B / 0x20B, or disagreeing with Machine's bitness
    (0x107 ROM images are not loadable)
  * Machine not supported by the host (or by WOW64 / ARM64EC emulation)
  * FileAlignment not a power of two in 0x200..0x10000
  * SectionAlignment < FileAlignment
  * SectionAlignment < 0x1000 while FileAlignment != SectionAlignment
  * NumberOfSections > 96 (0x60)
  * SizeOfImage that does not cover the headers and all sections
  * relocations required (base taken) but RELOCS_STRIPPED set
  * a kernel driver with AddressOfEntryPoint == 0
  * an EXE with AddressOfEntryPoint == 0 on modern Windows (older loaders
    happily executed the 'MZ' bytes; treat this as version-dependent)
  * PointerToRawData/SizeOfRawData extending past EOF (fails at map time or
    faults on touch)

TOLERATED BUT ANOMALOUS - this is where the tricks live [PACK]
  * SizeOfOptionalHeader != 0xE0 / 0xF0. Honored, and it MOVES the section
    table. Tools that hardcode 0xF8/0x108 then read garbage sections.
  * NumberOfRvaAndSizes != 16. Below 16 it HIDES directories from the loader
    itself (RtlImageDirectoryEntryToData returns NULL for index >= it).
    Above 16 the extra entries overlap the section table but the loader
    clamps to 16 and the section table does not move.
  * e_lfanew not 4-byte aligned, or pointing into the DOS stub so that the
    PE header overlaps the DOS header.
  * Non-zero Win32VersionValue (overrides the version the PEB reports) or
    LoaderFlags.
  * SizeOfImage not a multiple of SectionAlignment (rounded up in practice).
  * A DLL with AddressOfEntryPoint == 0 (perfectly legal: no DllMain).
  * Entry point inside the header region: the mapper accepts it, but that
    page is read-only unless a section covers RVA 0 or the image is
    low-alignment.
  * PointerToSymbolTable / NumberOfSymbols non-zero in an image.
  * CheckSum == 0 or stale (not enforced for user-mode EXEs/DLLs; IS enforced
    for kernel drivers, boot images and DLLs loaded into critical system
    processes).


================================================================================
32. OptionalHeader.CheckSum ALGORITHM
================================================================================
Field location: NT+0x58, both PE32 and PE32+.
This is what CheckSumMappedFile / editbin /release computes. It is NOT a
one's-complement IP checksum: the 16-bit fold happens on EVERY word, there is
no final negation, and the FILE LENGTH is added at the end.

  uint32 PeCheckSum(bytes f):
      ckOff  = e_lfanew + 0x58            # offset of the 4-byte CheckSum
      sum    = 0
      nwords = (len(f) + 1) / 2           # rounds UP; a trailing odd byte is
                                          # the low half of a word whose high
                                          # half is 0
      for w in 0 .. nwords-1:
          off = 2*w
          if ckOff <= off < ckOff+4: continue      # skip the field itself
          word = f[off] | (f[off+1] << 8)          # little-endian, 0 past EOF
          sum  = sum + word
          sum  = (sum >> 16) + (sum & 0xFFFF)      # fold carry every word
      sum = ((sum >> 16) + sum) & 0xFFFF           # final fold
      return (sum + len(f)) & 0xFFFFFFFF           # add the total file length

The real imagehlp implementation is equivalent but sums the whole file
including the stored checksum and then subtracts it with 16-bit borrow:
  WORD ChkSum(DWORD partial, USHORT *src, DWORD lenInWords) {
      while (lenInWords--) { partial += *src++;
                             partial = (partial>>16) + (partial & 0xFFFF); }
      return (WORD)(((partial>>16) + partial) & 0xFFFF);
  }
  calc = ChkSum(0, base, (FileLength+1)/2);
  calc -= storedCheckSum;            // with borrow
  result = calc + FileLength;
Because (FileLength+1)/2 can read one byte past EOF, the API relies on the
mapped view being zero-padded to the page; a raw-file implementation must
substitute 0.

Verified on this machine (both formulations above reproduce the stored value
byte-exactly):
  notepad.exe  len 0x58000  ckOff 0x150  stored = computed = 0x000656AE
  kernel32.dll len 0xCC270  ckOff 0x150  stored = computed = 0x000CE053
  ole32.dll    len 0x19CF70 ckOff 0x158  stored = computed = 0x0019EEBB

RE FACTS
  * Coverage is the ENTIRE FILE, including the overlay and the Authenticode
    blob. Append one byte and the checksum is stale.
  * Not enforced for ordinary user-mode images - which is why so many packed
    files ship CheckSum = 0.
  * Measured: 0 of 600 System32 DLLs have CheckSum == 0. A zero or
    mismatching checksum on a file claiming to be a Microsoft binary means it
    was patched or rebuilt after signing. [PACK]


================================================================================
33. COFF SYMBOL TABLE, STRING TABLE, RELOCATIONS, LINE NUMBERS
================================================================================
Located by FileHeader.PointerToSymbolTable (a RAW FILE OFFSET, never an RVA)
and NumberOfSymbols. Records are 18 bytes, packed, no alignment padding.

IMAGE_SYMBOL - 18 = 0x12 bytes
HEX  SIZE FIELD
0x00 8    Name (union)
            BYTE ShortName[8]                 <=8 chars; NOT NUL-terminated
                                              when exactly 8
            struct { DWORD Short; DWORD Long; }  Short == 0 => Long is an
                                              offset into the string table
0x08 4    Value
0x0C 2    SectionNumber   SHORT, SIGNED, 1-based index into the section table
0x0E 2    Type            base type in the low nibble, derived type above
0x10 1    StorageClass
0x11 1    NumberOfAuxSymbols

  Value depends on SectionNumber/StorageClass:
    SectionNumber > 0            -> offset from the start of that section
    SectionNumber == 0, Value!=0 -> COMMON symbol; Value is the requested size
    SectionNumber == 0, Value==0 -> external/undefined reference
    SectionNumber == -1 ABSOLUTE -> Value is a constant (@comp.id, @feat.00)
    SectionNumber == -2 DEBUG    -> not an address (.file records)
  Special section numbers: UNDEFINED 0, ABSOLUTE -1 (stored 0xFFFF),
  DEBUG -2 (stored 0xFFFE), SECTION_MAX 0xFEFF.

  Type masks (winnt.h is authoritative; the spec's prose is misleading):
    N_BTMASK 0x000F base type, N_TMASK 0x0030 first derived level,
    N_BTSHFT 4, N_TSHIFT 2.  ISFCN(x) is (x & 0x30) == (2 << 4), i.e.
    Type == 0x20 means FUNCTION. Microsoft tools only ever emit 0x0000 and
    0x0020.
    Base types: 0 NULL, 1 VOID, 2 CHAR, 3 SHORT, 4 INT, 5 LONG, 6 FLOAT,
    7 DOUBLE, 8 STRUCT, 9 UNION, 10 ENUM, 11 MOE, 12 BYTE, 13 WORD,
    14 UINT, 15 DWORD.  Derived: 0 NULL, 1 POINTER, 2 FUNCTION, 3 ARRAY.

  StorageClass (IMAGE_SYM_CLASS_*):
    0xFF END_OF_FUNCTION (-1)  0x00 NULL              0x01 AUTOMATIC
    0x02 EXTERNAL              0x03 STATIC            0x04 REGISTER
    0x05 EXTERNAL_DEF          0x06 LABEL             0x07 UNDEFINED_LABEL
    0x08 MEMBER_OF_STRUCT      0x09 ARGUMENT          0x0A STRUCT_TAG
    0x0B MEMBER_OF_UNION       0x0C UNION_TAG         0x0D TYPE_DEFINITION
    0x0E UNDEFINED_STATIC      0x0F ENUM_TAG          0x10 MEMBER_OF_ENUM
    0x11 REGISTER_PARAM        0x12 BIT_FIELD         0x44 FAR_EXTERNAL
    0x64 BLOCK (100)           0x65 FUNCTION (101)    0x66 END_OF_STRUCT
    0x67 FILE (103)            0x68 SECTION (104)     0x69 WEAK_EXTERNAL (105)
    0x6B CLR_TOKEN (107)
    In real MSVC objects you mostly see EXTERNAL(2), STATIC(3), FILE(103),
    FUNCTION(101) for .bf/.ef, and WEAK_EXTERNAL(105).

  AUX RECORDS: NumberOfAuxSymbols records of 18 bytes each follow and CONSUME
  SYMBOL INDICES. Iterate with i += 1 + NumberOfAuxSymbols; TagIndex values
  count aux records too.
   (a) Function definition (EXTERNAL, Type 0x20, SectionNumber > 0):
       0x00 4 TagIndex (the .bf record) | 0x04 4 TotalSize
       0x08 4 PointerToLinenumber       | 0x0C 4 PointerToNextFunction
       0x10 2 Unused
   (b) .bf / .ef (class FUNCTION 101):
       0x00 4 Unused | 0x04 2 Linenumber | 0x06 6 Unused
       0x0C 4 PointerToNextFunction (.bf only) | 0x10 2 Unused
   (c) Weak external (class WEAK_EXTERNAL 105, SectionNumber UNDEFINED):
       0x00 4 TagIndex (the default symbol) | 0x04 4 Characteristics:
       1 SEARCH_NOLIBRARY, 2 SEARCH_LIBRARY, 3 SEARCH_ALIAS,
       4 ANTI_DEPENDENCY | 0x08 10 Unused
   (d) File (class FILE 103, name ".file"): the aux records hold the ANSI
       source path, 18 bytes per record, NUL-padded, spanning as many records
       as needed.
   (e) Section definition (class STATIC 3, name == a section name):
       0x00 4 Length | 0x04 2 NumberOfRelocations
       0x06 2 NumberOfLinenumbers | 0x08 4 CheckSum (COMDAT CRC)
       0x0C 2 Number (associated section index) | 0x0E 1 Selection
       (COMDAT: 1 NODUPLICATES, 2 ANY, 3 SAME_SIZE, 4 EXACT_MATCH,
        5 ASSOCIATIVE, 6 LARGEST) | 0x0F 3 Unused
   (f) CLR token (class CLR_TOKEN 107):
       0x00 1 bAuxType (=1) | 0x01 1 bReserved | 0x02 4 SymbolTableIndex
       0x06 12 rgbReserved

STRING TABLE - immediately after the symbol table, at
PointerToSymbolTable + NumberOfSymbols*18
  0x00 4    TotalSize   in bytes, INCLUDING these 4 bytes. Minimum legal 4.
                        Some tools write 0 when empty.
  0x04 ...  NUL-terminated strings, back to back.
  Offsets in symbol records are measured from the START of the table, so the
  smallest valid string offset is 4. In OBJECT files, section names longer
  than 8 chars use the same table via the "/1234" form (slash + ASCII decimal
  offset); a "//" + base64 form exists for very large offsets.

--- 33.1 IMAGE_RELOCATION - 10 bytes (OBJECT FILES ONLY) ---
Pointed to by IMAGE_SECTION_HEADER.PointerToRelocations, count in
NumberOfRelocations. These are COMPILE-TIME fixups consumed by the linker -
completely different from the DD[5] base relocations (section 17), which are
LOAD-TIME fixups.
HEX  SIZE FIELD
0x00 4    VirtualAddress     offset of the item to fix up, from the start of
                             the section
0x04 4    SymbolTableIndex   0-based index into the COFF symbol table
0x08 2    Type               architecture-specific, see below
  IMAGE_SIZEOF_RELOCATION = 10. Note the struct is NOT padded to 12, so
  entry n is at PointerToRelocations + 10*n. Using 12 is a classic bug.
  If IMAGE_SCN_LNK_NRELOC_OVFL (0x01000000) is set, NumberOfRelocations is
  0xFFFF and the REAL count is in the FIRST relocation record's
  VirtualAddress field; the actual relocations then start at record 1.

x86 (IMAGE_REL_I386_*):
  0x0000 ABSOLUTE  no-op   0x0001 DIR16     0x0002 REL16
  0x0006 DIR32     32-bit VA           0x0007 DIR32NB  32-bit RVA
  0x0009 SEG12     0x000A SECTION   0x000B SECREL   0x000C TOKEN
  0x000D SECREL7   0x0014 REL32     32-bit relative displacement
x64 (IMAGE_REL_AMD64_*):
  0x0000 ABSOLUTE  0x0001 ADDR64    0x0002 ADDR32    0x0003 ADDR32NB (RVA)
  0x0004 REL32     0x0005 REL32_1   0x0006 REL32_2   0x0007 REL32_3
  0x0008 REL32_4   0x0009 REL32_5   0x000A SECTION   0x000B SECREL
  0x000C SECREL7   0x000D TOKEN     0x000E SREL32    0x000F PAIR
  0x0010 SSPAN32
  (REL32_1..REL32_5 mean "relative to the byte n past the end of the field" -
   they exist because x86-64 instructions can have trailing immediates.)
ARM64 (IMAGE_REL_ARM64_*):
  0x0000 ABSOLUTE  0x0001 ADDR32    0x0002 ADDR32NB  0x0003 BRANCH26
  0x0004 PAGEBASE_REL21             0x0005 REL21
  0x0006 PAGEOFFSET_12A             0x0007 PAGEOFFSET_12L
  0x0008 SECREL    0x0009 SECREL_LOW12A  0x000A SECREL_HIGH12A
  0x000B SECREL_LOW12L  0x000C TOKEN  0x000D SECTION  0x000E ADDR64
  0x000F BRANCH19  0x0010 BRANCH14  0x0011 REL32
  ARMNT has its own IMAGE_REL_ARM_* set with the same shape.

--- 33.2 IMAGE_LINENUMBER - 6 bytes (OBJECT FILES ONLY, deprecated) ---
Pointed to by PointerToLinenumbers / NumberOfLinenumbers.
HEX  SIZE FIELD
0x00 4    Type (union)   if Linenumber == 0 -> SymbolTableIndex of a function
                         if Linenumber != 0 -> VirtualAddress of the code
0x04 2    Linenumber     0 marks a function-start record; otherwise the
                         source line number
  IMAGE_SIZEOF_LINENUMBER = 6, again unpadded. Superseded by the PDB;
  LINE_NUMS_STRIPPED (0x0004) is set in essentially every modern image.

--- 33.3 OBJECT FILES vs IMAGES ---
  * An object file has NO MZ/PE at all: it starts directly with the
    IMAGE_FILE_HEADER (e.g. 64 86 for AMD64), SizeOfOptionalHeader == 0, and
    non-zero PointerToSymbolTable/NumberOfSymbols. /bigobj objects use
    ANON_OBJECT_HEADER_BIGOBJ (Machine 0x0000 + a class GUID) and 20-byte
    IMAGE_SYMBOL_EX records with a 4-byte SectionNumber.
  * In an IMAGE both fields are normally 0; symbols live in the PDB. Relevant
    flags: LOCAL_SYMS_STRIPPED 0x0008, DEBUG_STRIPPED 0x0200,
    LINE_NUMS_STRIPPED 0x0004.
  * A non-zero PointerToSymbolTable in an image is a FILE OFFSET that often
    lands outside every section. Tools that treat it as an RVA go off the
    rails - packers exploit exactly that. [PACK]



================================================================================
34. PACKER / ANTI-ANALYSIS HEADER ANOMALY CHEAT SHEET
================================================================================
None of these is proof on its own. Two or three together is a strong signal.

--- 34.1 DOS / header region ---
  * e_lfanew < 0x40, i.e. the PE header OVERLAPS the DOS header. Only bytes
    0-1 and 0x3C-0x3F are used, so this is legal. The extreme form is
    e_lfanew = 4, which puts "PE\0\0" at offset 4 and requires the dword at
    0x3C (now inside the optional header / section table) to read back as 4.
    This is the core of the classic 97-byte and 268-byte minimal PEs.
    Detection: e_lfanew < 0x40, or the ranges [0,0x40) and
    [e_lfanew, e_lfanew+0x18+SizeOfOptionalHeader) overlapping.
  * e_lfanew huge (near the 256 MB cap) so the real headers sit far into the
    file, past where naive parsers look.
  * A section with VirtualAddress 0 or PointerToRawData < SizeOfHeaders, so
    the PE header itself becomes part of a writable/executable section -
    self-modifying headers, header-resident stubs, entry point in the header.
  * DOS stub replaced by custom text, real 16-bit code (dual-mode binaries),
    or reused as data / a decryptor.
  * Rich header present but its key does not match the recomputed checksum
    (section 4) -> the DOS header/stub or the entry list was patched.
    Also: Rich header at an unusual offset, duplicated 'Rich' markers, or
    tool versions that contradict MajorLinkerVersion / TimeDateStamp / the
    debug directory.

--- 34.2 Optional header ---
  * SizeOfOptionalHeader != 0xE0 / 0xF0 (moves the section table).
  * NumberOfRvaAndSizes != 16 (hides directories from the loader itself).
  * Non-zero Win32VersionValue (fakes the OS version inside the process) or
    LoaderFlags.
  * SizeOfCode == 0 or BaseOfCode == 0 in something that clearly runs code.
  * SizeOfImage not equal to the aligned end of the last section.
  * SectionAlignment == FileAlignment < 0x1000 -> low-alignment flat image,
    RVA == file offset (section 29.4).
  * DYNAMIC_BASE without relocations, or DYNAMIC_BASE together with
    RELOCS_STRIPPED. Missing NX_COMPAT / GUARD_CF on a file claiming to be a
    modern Microsoft binary.
  * CheckSum == 0 or stale on a signed-looking file.
  * TimeDateStamp == 0, or contradicting the Rich header and debug directory.
    A FUTURE timestamp is NOT automatically suspicious: link /Brepro replaces
    the field with a build-input hash (measured: 299 of 600 System32 DLLs
    have "future" stamps). Rule: future stamp + a debug entry of type 16
    (REPRO) = reproducible build, benign. Future stamp with no REPRO entry =
    worth a look.
  * MajorLinkerVersion set to packer-specific values.

--- 34.3 Section table ---
  * VirtualSize huge with SizeOfRawData == 0 - the decompression container.
    UPX0 is the archetype: VirtualSize ~ the original image size, raw size 0,
    characteristics 0xE0000080.
  * SizeOfRawData > VirtualSize (unmapped cave) or extending past EOF.
  * Overlapping raw ranges, two sections at the same VirtualAddress,
    unsorted VirtualAddresses.
  * RWX on the code section, all sections RWX, a ".text" without CNT_CODE,
    MEM_DISCARDABLE on real code.
  * Names: non-standard (see the packer list in 11.3), empty, not starting
    with '.', non-ASCII, high-entropy, duplicated, or exactly 8 chars with no
    NUL (legal, breaks naive C parsers).
  * Entry point in the last section, in .rsrc, in .reloc, or outside every
    section.
  * Very high entropy (> 7.2 bits/byte) in a section marked as code.

--- 34.4 Directories ---
  * DD[1].Size == 0 while imports work fine (terminator-driven), or the
    reverse: a plausible Size pointing at a zeroed table.
  * OriginalFirstThunk == 0, or INT and IAT aliased to the same array.
  * Imports reduced to LoadLibraryA/GetProcAddress, or none at all (PEB
    walking, direct syscalls).
  * Real functionality hidden in DD[13] delay imports while DD[1] looks
    innocent (section 25).
  * Stale DD[11] bound imports - both a tamper indicator and a way to recover
    the original DLL names.
  * A TLS directory in a file with no thread-local data; callbacks pointing
    into a section that is rewritten at runtime (section 21).
  * DD[4] Size much larger than the real PKCS#7 length (data hidden in the
    signature padding), or data appended after the certificate table.
  * DD[7] or DD[15] non-zero.
  * LoadConfig internal Size disagreeing with DD[10].Size, or a Size that is
    not one of the legal truncation points (22.3).
  * A debug directory whose PDB path is unrelated to the file's claimed
    identity - or a stripped debug directory in a file that has POGO /
    VC_FEATURE artifacts elsewhere.

--- 34.5 Behavioural corollaries worth checking early ---
  * TLS callbacks exist -> set the debugger to break on them BEFORE the EP.
  * Delay imports exist -> the interesting API set may only appear at
    runtime.
  * .pdata missing on an x64 binary that clearly has non-leaf functions ->
    stripped or manually built; expect poor IDA function recovery, and
    consider rebuilding it.
  * CFG tables present (22.5) -> free function-start list even without
    .pdata.


================================================================================
35. MAGIC VALUES AND SIGNATURES INDEX
================================================================================
--- Structure signatures ---
0x5A4D              "MZ"      IMAGE_DOS_HEADER.e_magic
0x00004550          "PE\0\0"  IMAGE_NT_HEADERS.Signature
0x454E              "NE"      16-bit Windows / OS2 new executable
0x454C              "LE"      linear executable (VXD)
0x584C              "LX"      OS/2 2.x
0x010B              PE32      optional header magic
0x020B              PE32+     optional header magic
0x0107              ROM image optional header magic
0x536E6144          "DanS"    Rich header signature (XORed on disk)
0x68636952          "Rich"    Rich header end marker (plaintext)
0x53445352          "RSDS"    CodeView PDB 7.0 reference
0x3031424E          "NB10"    CodeView PDB 2.0 reference
0x3930424E / 0x3131424E  "NB09"/"NB11"  embedded CodeView
0x424A5342          "BSJB"    .NET metadata root
0x5350474F          POGO debug payload (on-disk bytes 4F 47 50 53 = "OGPS";
                              usually called "SPGO", which is the reversed
                              reading - search the DWORD, not the text)
0x4C544347          POGO variant (bytes 47 43 54 4C = "GCTL"; called "LTCG")
0x4244504D          "MPDB"    embedded portable PDB (bytes 4D 50 44 42)
0x4D523252          "R2RM"    ReadyToRun perfmap
"RTR\0"                       ReadyToRun managed native header
0xFEEF04BD                    VS_FIXEDFILEINFO signature (VERSIONINFO)
0x00905A4D                    the first 4 bytes of a standard MZ file
0xE011CFD0                    OLE compound file (not PE, but you will hit it)

--- Ordinal flags ---
0x80000000                    IMAGE_ORDINAL_FLAG32
0x8000000000000000            IMAGE_ORDINAL_FLAG64

--- Default image bases ---
0x00400000    EXE x86         0x0000000140000000  EXE x64
0x10000000    DLL x86         0x0000000180000000  DLL x64
0x00010000    driver / kernel-mode

--- Sizes to recognise instantly ---
0x40 = 64    IMAGE_DOS_HEADER
0x14 = 20    IMAGE_FILE_HEADER
0xE0 = 224   IMAGE_OPTIONAL_HEADER32     0xF0 = 240  IMAGE_OPTIONAL_HEADER64
0xF8 = 248   IMAGE_NT_HEADERS32          0x108 = 264 IMAGE_NT_HEADERS64
0x80 = 128   DataDirectory[16]           8           IMAGE_DATA_DIRECTORY
0x28 = 40    IMAGE_SECTION_HEADER        0x28 = 40   IMAGE_EXPORT_DIRECTORY
0x14 = 20    IMAGE_IMPORT_DESCRIPTOR     0x20 = 32   IMAGE_DELAYLOAD_DESCRIPTOR
0x10 = 16    IMAGE_RESOURCE_DIRECTORY / _DATA_ENTRY
8            IMAGE_RESOURCE_DIRECTORY_ENTRY / BOUND_IMPORT_DESCRIPTOR
0xC = 12     RUNTIME_FUNCTION (x64)      8           .pdata entry (ARM64)
0x1C = 28    IMAGE_DEBUG_DIRECTORY       0x12 = 18   IMAGE_SYMBOL
0x18 = 24    IMAGE_TLS_DIRECTORY32       0x28 = 40   IMAGE_TLS_DIRECTORY64
0xC4 = 196   LOAD_CONFIG_DIRECTORY32     0x148 = 328 LOAD_CONFIG_DIRECTORY64
0x48 = 72    IMAGE_COR20_HEADER          16          FPO_DATA
0x14 = 20    VC_FEATURE debug payload

--- Instruction bytes worth recognising in stubs ---
FF 25 <disp32>       jmp  [mem]      IAT / import thunk
FF 15 <disp32>       call [mem]      indirect API call
E9 <rel32>           jmp  rel        tail jump
B8 <imm32> E9 ...    x86 delay-load thunk (mov eax, slot; jmp tailMerge)
48 8D 05 <disp32> E9 x64 delay-load thunk (lea rax, slot; jmp tailMerge)
64 A1 30 00 00 00    x86  mov eax, fs:[30h]   -> PEB
65 48 8B 04 25 60 00 00 00   x64 mov rax, gs:[60h] -> PEB
CC                   int3            breakpoint / padding
0F 05 / 0F 34        syscall/sysenter direct syscall stub
4D 5A                "MZ" - as x86 code this is dec ebp / pop edx


================================================================================
                    PART IV - APPENDICES (in-memory structures)
================================================================================
These are not part of the PE file format, but you need them to FIND PE headers
in a live process and to reason about loader state.

================================================================================
A1. TEB / PEB / LOADER LISTS
================================================================================
GETTING THE TEB/PEB
  x86:  mov eax, fs:[0x18]    ; TEB self
        mov eax, fs:[0x30]    ; PEB
  x64:  mov rax, gs:[0x30]    ; TEB self
        mov rax, gs:[0x60]    ; PEB directly
Any fs:/gs: prefix in x86/x64 user code means TEB/PEB access.

--- TEB ---
x86    x64    FIELD
0x00   0x00   NtTib.ExceptionList        SEH chain head (x86); 0 on x64
0x04   0x08   NtTib.StackBase
0x08   0x10   NtTib.StackLimit
0x0C   0x18   NtTib.SubSystemTib
0x10   0x20   NtTib.FiberData
0x14   0x28   NtTib.ArbitraryUserPointer
0x18   0x30   NtTib.Self                 the TEB's own linear address
0x1C   0x38   EnvironmentPointer
0x20   0x40   ClientId.UniqueProcess     PID
0x24   0x48   ClientId.UniqueThread      TID
0x28   0x50   ActiveRpcHandle
0x2C   0x58   ThreadLocalStoragePointer  <- TLS slot array (section 21)
0x30   0x60   ProcessEnvironmentBlock    <- PEB
0x34   0x68   LastErrorValue             what GetLastError reads
0x38   0x6C   CountOfOwnedCriticalSections
0x1A4  0x2C0  ExceptionCode
0xE0C  0x1478 DeallocationStack
0xE10  0x1480 TlsSlots[64]

--- PEB ---
x86    x64    SIZE FIELD
0x00   0x00   1    InheritedAddressSpace
0x01   0x01   1    ReadImageFileExecOptions
0x02   0x02   1    BeingDebugged            <- ANTI-DEBUG: 1 under a debugger
0x03   0x03   1    BitField
0x04   0x08   ptr  Mutant
0x08   0x10   ptr  ImageBaseAddress         <- this module's base
0x0C   0x18   ptr  Ldr                      <- module list
0x10   0x20   ptr  ProcessParameters        cmdline, cwd, env
0x14   0x28   ptr  SubSystemData
0x18   0x30   ptr  ProcessHeap
0x1C   0x38   ptr  FastPebLock
0x68   0xBC   4    NtGlobalFlag             <- ANTI-DEBUG: 0x70 under a debugger
  NtGlobalFlag == 0x70 is the sum of the three heap-debug bits the debug heap
  sets: 0x10 FLG_HEAP_ENABLE_TAIL_CHECK, 0x20 FLG_HEAP_ENABLE_FREE_CHECK,
  0x40 FLG_HEAP_VALIDATE_PARAMETERS.  So (NtGlobalFlag & 0x70) != 0 means
  "being debugged". Note LoadConfig.GlobalFlagsSet/Clear (section 22) let an
  image legitimately preset these bits - which is also a way to defeat the
  check, or to make a clean process look debugged.

--- PEB_LDR_DATA (PEB->Ldr) ---
x86    x64    FIELD
0x00   0x00   Length
0x04   0x04   Initialized
0x08   0x08   SsHandle
0x0C   0x10   InLoadOrderModuleList            <- start here
0x14   0x20   InMemoryOrderModuleList
0x1C   0x30   InInitializationOrderModuleList
All three are circular doubly linked lists over the SAME modules in different
orders.

--- LDR_DATA_TABLE_ENTRY (a node) ---
x86    x64    FIELD
0x00   0x00   InLoadOrderLinks
0x08   0x10   InMemoryOrderLinks
0x10   0x20   InInitializationOrderLinks
0x18   0x30   DllBase                  <- the module base = your PE header
0x1C   0x38   EntryPoint
0x20   0x40   SizeOfImage
0x24   0x48   FullDllName.Length
0x26   0x4A   FullDllName.MaximumLength
0x28   0x50   FullDllName.Buffer
0x2C   0x58   BaseDllName.Length       BYTES, not characters (/2 = chars)
0x2E   0x5A   BaseDllName.MaximumLength
0x30   0x60   BaseDllName.Buffer       WCHAR*
[!] TRAP: a pointer obtained by walking InMemoryOrderModuleList points at
offset 0x10 (x64) / 0x08 (x86) of the node, not at its start. From that
pointer DllBase is at +0x20 (x64) / +0x10 (x86). Always check WHICH list you
are walking before applying an offset.
GetModuleHandle logic: walk the list, lowercase-compare BaseDllName.Buffer,
return DllBase. That base + e_lfanew gives you the NT headers, and from there
the export directory (section 12) - the whole shellcode API-resolution chain.

--- UNICODE_STRING / LIST_ENTRY ---
UNICODE_STRING: 0x00 2 Length (BYTES), 0x02 2 MaximumLength,
                x86 0x04 / x64 0x08 ptr Buffer.  Total x86 8, x64 16.
LIST_ENTRY:     0x00 Flink, x86 0x04 / x64 0x08 Blink. Total x86 8, x64 16.
If IDA guesses a struct is _LIST_ENTRY it prints X[N].Flink; convert with
  X[N].Flink = byte offset N*16 + 0   (x64)
  X[N].Blink = byte offset N*16 + 8   (x64)


================================================================================
A2. EXCEPTION_RECORD / CONTEXT (x64)
================================================================================
EXCEPTION_POINTERS:  0x00 ptr ExceptionRecord | 0x08 ptr ContextRecord
EXCEPTION_RECORD (x64):
  0x00 4   ExceptionCode        0x04 4   ExceptionFlags
  0x08 ptr ExceptionRecord (chain)       0x10 ptr ExceptionAddress
  0x18 4   NumberParameters     0x20 -   ExceptionInformation[15]
CONTEXT (x64) - the offsets that matter:
  0x30 ContextFlags
  0x48 Dr0   0x50 Dr1   0x58 Dr2   0x60 Dr3   0x68 Dr6   0x70 Dr7
       <- ANTI-DEBUG: Dr7 != 0 or any Dr0-Dr3 != 0 means a hardware
          breakpoint is set. GetThreadContext / an exception handler reading
          these is checking for you.
  0x78 Rax  0x80 Rcx  0x88 Rdx  0x90 Rbx  0x98 Rsp  0xA0 Rbp
  0xA8 Rsi  0xB0 Rdi  0xB8 R8   0xC0 R9   0xC8 R10  0xD0 R11
  0xD8 R12  0xE0 R13  0xE8 R14  0xF0 R15
  0xF8 Rip   <- writing this inside a VEH/SEH handler redirects execution;
                the standard "exception-driven control flow" obfuscation
Common exception codes:
  0xC0000005 ACCESS_VIOLATION        0x80000003 BREAKPOINT (INT3)
  0x80000004 SINGLE_STEP             0xC000001D ILLEGAL_INSTRUCTION
  0xC0000094 INTEGER_DIVIDE_BY_ZERO  0xC0000096 PRIVILEGED_INSTRUCTION
  0xC0000025 NONCONTINUABLE_EXCEPTION 0xC0000008 INVALID_HANDLE
  0xC06D007E delay-load MOD_NOT_FOUND 0xC06D007F delay-load PROC_NOT_FOUND
  0xC06D0057 delay-load bad descriptor version
  0xE06D7363 C++ EH ("msc")           0x406D1388 SetThreadName (debugger)


================================================================================
A3. CALLING CONVENTIONS
================================================================================
--- Windows x64 (Microsoft ABI) ---
  arg1 RCX (XMM0 if float)   arg2 RDX (XMM1)
  arg3 R8  (XMM2)            arg4 R9  (XMM3)     arg5+ on the stack
  At the FIRST instruction of the callee:
    [RSP+0x00] return address
    [RSP+0x08] arg1 shadow slot (may be uninitialised)
    [RSP+0x10] arg2 shadow    [RSP+0x18] arg3 shadow
    [RSP+0x20] arg4 shadow    [RSP+0x28] arg5   [RSP+0x30] arg6 ...
  Return: RAX (XMM0 for float). Results > 8 bytes are returned via a hidden
  pointer passed in RCX, shifting every other argument right by one.
  Volatile (may be clobbered):   RAX RCX RDX R8 R9 R10 R11, XMM0-XMM5
  Non-volatile (must be saved):  RBX RBP RDI RSI RSP R12-R15, XMM6-XMM15
  Stack must be 16-byte aligned at the call; the shadow space is mandatory
  even for functions with no arguments.
--- Windows x86 ---
  __cdecl     args on the stack right-to-left; CALLER cleans up
  __stdcall   args on the stack; CALLEE cleans up (ret N) - all Win32 APIs
  __fastcall  arg1 ECX, arg2 EDX, rest on the stack, callee cleans
  __thiscall  this in ECX, rest on the stack, callee cleans
  Return: EAX, or EDX:EAX for 64-bit values, ST0 for float
  Volatile: EAX ECX EDX.  Non-volatile: EBX ESI EDI EBP ESP
--- Linux/SysV x64 (for comparison) ---
  RDI RSI RDX RCX R8 R9, then the stack. NO shadow space. Return RAX/RDX.


================================================================================
A4. IDA TIPS AND OFFSET ARITHMETIC
================================================================================
READING DEREFERENCES
  *(_BYTE  *)(p + N)   -> 1 byte at p+N
  *(_WORD  *)(p + N)   -> 2 bytes
  *(_DWORD *)(p + N)   -> 4 bytes
  *(_QWORD *)(p + N)   -> 8 bytes
INDEXED ACCESS - multiply by the element size to get the byte offset
  ((_DWORD *)p)[47]  -> 47*4 = 188 = 0xBC
  ((_QWORD *)p)[6]   ->  6*8 =  48 = 0x30
  ((_WORD  *)p)[5]   ->  5*2 =  10 = 0x0A
  A stride of 2 means a WORD array (e.g. AddressOfNameOrdinals), 4 a DWORD
  array (AddressOfNames/Functions, PE32 thunks), 8 a pointer array (PE32+
  thunks, TLS callbacks).
USEFUL KEYS
  Y          set the variable's type (the highest-leverage action in Hex-Rays)
  N          rename            T  convert a number to a struct offset
  R          number -> character (77 -> 'M')      H  hex/decimal toggle
  Shift+F1   Local Types (define your own structs)
  Shift+F11  Type Libraries - load mssdk64 / ntapi64 to get the real PE and
             PEB/TEB structures, then T on the constants
  Alt+Q      apply a struct to the current variable
DO NOT give a local variable the same name as an existing function - Hex-Rays
will infer its type from that function and turn the variable into a function
pointer.
FAST PE TRIAGE INSIDE IDA
  1. Jump to the start of the file/module, apply IMAGE_DOS_HEADER.
  2. Read e_lfanew, apply IMAGE_NT_HEADERS32/64 there (check Magic first).
  3. Apply IMAGE_SECTION_HEADER to the section table as an array of
     NumberOfSections.
  4. For each non-zero data directory, apply the matching struct from this
     file.
  Everything then reads as named fields instead of raw arithmetic.
================================================================================
END
================================================================================
