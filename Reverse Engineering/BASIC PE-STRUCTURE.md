================================================================================
                     BASIC PE STRUCTURE REFERENCE
                 Portable Executable format - working notes
================================================================================

A PE file consists of three main parts:

    1. DOS header + stub      first 0x40 bytes + MS-DOS leftover
    2. NT headers             the real PE header, located via e_lfanew
    3. Sections               .text .rdata .data .reloc .rsrc etc.


File layout:

    +---------------------+  offset 0
    | DOS header (0x40)   |  starts with "MZ", ends with e_lfanew
    +---------------------+
    | DOS stub            |  "This program cannot be run in DOS mode"
    +---------------------+
    | NT headers          |  at offset e_lfanew, starts with "PE\0\0"
    |   File Header       |
    |   Optional Header   |  contains DataDirectory[16]
    +---------------------+
    | Section headers     |  array of 40-byte records
    +---------------------+
    | .text (code)        |
    | .rdata (consts)     |  strings, imports, debug info
    | .data (globals)     |
    | .rsrc (resources)   |
    | .reloc              |
    +---------------------+


================================================================================
1. DOS HEADER                   base + 0x00, 64 bytes
================================================================================

Only two fields are used by the Windows loader:

    0x00  2    e_magic         "MZ" = 0x5A4D
    0x3C  4    e_lfanew        file offset of "PE\0\0"

Everything else is DOS-era padding, frequently abused by packers for stego
and watermarks.

NT headers location:
    NT = base + *(DWORD*)(base + 0x3C)


================================================================================
2. NT HEADERS                   base + e_lfanew
================================================================================

    0x00  4    Signature       "PE\0\0" = 0x00004550
    0x04  20   FileHeader      COFF header
    0x18  var  OptionalHeader  size given by FileHeader.SizeOfOptionalHeader

All offsets below are written NT+X.


================================================================================
3. FILE HEADER                  NT+0x04, 20 bytes
================================================================================

    NT+0x04  2  Machine                 0x8664 = x64, 0x014C = x86
    NT+0x06  2  NumberOfSections        typically 4-7
    NT+0x08  4  TimeDateStamp           build time, or hash if /Brepro
    NT+0x0C  4  PointerToSymbolTable    should be 0 in images
    NT+0x10  4  NumberOfSymbols         should be 0
    NT+0x14  2  SizeOfOptionalHeader    0xF0 for x64, 0xE0 for x86
    NT+0x16  2  Characteristics         flags

Characteristics flags:
    0x0002  EXECUTABLE_IMAGE   runnable
    0x0020  LARGE_ADDRESS      >2GB VA (default on x64)
    0x2000  DLL                image is a DLL


================================================================================
4. OPTIONAL HEADER              NT+0x18, 240 bytes (x64) or 224 (x86)
================================================================================

Bitness determined by the WORD at NT+0x18:
    0x010B = PE32  (x86)
    0x020B = PE32+ (x64)

Fields of practical interest:

                               PE32+ (x64)     PE32 (x86)
    Magic                      NT+0x18         NT+0x18
    AddressOfEntryPoint        NT+0x28         NT+0x28       RVA of entry
    BaseOfCode                 NT+0x2C         NT+0x2C
    ImageBase                  NT+0x30 (8B)    NT+0x34 (4B)  preferred load addr
    SectionAlignment           NT+0x38         NT+0x38       usually 0x1000
    FileAlignment              NT+0x3C         NT+0x3C       usually 0x200
    SizeOfImage                NT+0x50         NT+0x50       total RAM size
    SizeOfHeaders              NT+0x54         NT+0x54       where sections start
    CheckSum                   NT+0x58         NT+0x58
    Subsystem                  NT+0x5C         NT+0x5C       2=GUI, 3=console
    DllCharacteristics         NT+0x5E         NT+0x5E       ASLR / DEP / CFG
    NumberOfRvaAndSizes        NT+0x84         NT+0x74       usually 16
    DataDirectory[16]          NT+0x88         NT+0x78       128 bytes

Default ImageBase values:
    EXE x64:  0x140000000     EXE x86:  0x400000
    DLL x64:  0x180000000     DLL x86:  0x10000000

DllCharacteristics flags:
    0x0020  HIGH_ENTROPY_VA    64-bit ASLR
    0x0040  DYNAMIC_BASE       ASLR enabled
    0x0100  NX_COMPAT          DEP compatible
    0x4000  GUARD_CF           Control Flow Guard


================================================================================
5. DATA DIRECTORY                 16 entries, 8 bytes each
================================================================================

Each entry:  { DWORD VirtualAddress (RVA);  DWORD Size; }

PE32+ layout (x64):
    NT+0x88  DD[0]  EXPORT          IMAGE_EXPORT_DIRECTORY
    NT+0x90  DD[1]  IMPORT          IMAGE_IMPORT_DESCRIPTOR array
    NT+0x98  DD[2]  RESOURCE        .rsrc tree
    NT+0xA0  DD[3]  EXCEPTION       .pdata (x64 unwind info)
    NT+0xA8  DD[4]  SECURITY        Authenticode cert (file offset, not RVA)
    NT+0xB0  DD[5]  BASERELOC       .reloc
    NT+0xB8  DD[6]  DEBUG           debug info + PDB path
    NT+0xC0  DD[7]  ARCHITECTURE    unused, must be 0
    NT+0xC8  DD[8]  GLOBALPTR       unused on x86/x64
    NT+0xD0  DD[9]  TLS             IMAGE_TLS_DIRECTORY
    NT+0xD8  DD[10] LOAD_CONFIG     security cookie, CFG, SafeSEH
    NT+0xE0  DD[11] BOUND_IMPORT    legacy
    NT+0xE8  DD[12] IAT             IAT (loader uses for permissions)
    NT+0xF0  DD[13] DELAY_IMPORT    delay-loaded imports
    NT+0xF8  DD[14] COM_DESCRIPTOR  .NET header
    NT+0x100 DD[15] RESERVED        must be 0

For PE32 (x86) subtract 0x10 from each offset above.

Formula:
    PE32+ : DD[n].RVA  at NT + 0x88 + 8*n ;   DD[n].Size at NT + 0x8C + 8*n
    PE32  : DD[n].RVA  at NT + 0x78 + 8*n ;   DD[n].Size at NT + 0x7C + 8*n


================================================================================
6. SECTION HEADER                 40 bytes per entry
================================================================================

Section table starts at:  NT + 0x18 + SizeOfOptionalHeader
    Standard x64:   NT+0x108
    Standard x86:   NT+0xF8

Section header layout:

    0x00  8   Name                   8 ASCII bytes, e.g. ".text\0\0\0"
    0x08  4   VirtualSize            bytes in memory
    0x0C  4   VirtualAddress         RVA where section is mapped
    0x10  4   SizeOfRawData          bytes on disk
    0x14  4   PointerToRawData       file offset of raw data
    0x18  4   PointerToRelocations   0 in images
    0x1C  4   PointerToLinenumbers   0 in images
    0x20  2   NumberOfRelocations    0 in images
    0x22  2   NumberOfLinenumbers    0 in images
    0x24  4   Characteristics        R/W/X flags

Characteristics flags:
    0x00000020  CODE                 contains executable code
    0x00000040  INITIALIZED_DATA     has initialized data
    0x00000080  UNINITIALIZED_DATA   .bss
    0x02000000  DISCARDABLE          thrown away after load (.reloc)
    0x20000000  EXECUTE              executable
    0x40000000  READ                 readable
    0x80000000  WRITE                writable

Common combinations:
    0x60000020  .text    CODE | EXECUTE | READ
    0x40000040  .rdata   DATA | READ
    0xC0000040  .data    DATA | READ | WRITE
    0x42000040  .reloc   DATA | DISCARDABLE | READ
    0xE0000020  RWX      code + writable (rare in legitimate binaries)

Standard section names:
    .text    executable code
    .rdata   read-only data: strings, imports, const
    .data    read-write globals
    .bss     uninitialized data (SizeOfRawData = 0)
    .idata   import table (older linkers)
    .rsrc    resources (icons, version info, manifest)
    .reloc   base relocations
    .pdata   exception unwind data (x64)
    .tls     TLS template data

Packer-associated section names:
    UPX0 UPX1 UPX2           UPX
    .aspack .adata           ASPack
    .vmp0 .vmp1 .vmp2        VMProtect
    .themida                 Themida
    .enigma1 .enigma2        Enigma
    Random 8-byte names      custom packer


================================================================================
7. RVA vs FILE OFFSET
================================================================================

RVA        = offset from the module BASE in memory after loading
File offset = offset in the file on DISK

Conversion from RVA to file offset:

    Find the section where:
        VirtualAddress <= RVA < VirtualAddress + max(VirtualSize, SizeOfRawData)
    Then:
        fileOffset = PointerToRawData + (RVA - VirtualAddress)

In a running process no conversion is needed:
    realAddress = moduleBase + RVA


================================================================================
8. IMPORT DIRECTORY (DD[1])
================================================================================

Array of IMAGE_IMPORT_DESCRIPTOR, terminated by an all-zero entry.
One entry per imported DLL.

IMAGE_IMPORT_DESCRIPTOR (20 bytes):
    0x00  4  OriginalFirstThunk    RVA of INT (names table, read-only)
    0x04  4  TimeDateStamp         0 = not bound
    0x08  4  ForwarderChain        legacy, usually -1
    0x0C  4  Name                  RVA of DLL name ("kernel32.dll\0")
    0x10  4  FirstThunk            RVA of IAT (patched with real addrs)

Two parallel arrays per descriptor:
    INT (Import Name Table) at OriginalFirstThunk - stays as names/ordinals
    IAT (Import Address Table) at FirstThunk - becomes real function pointers
                                               after loading

Each thunk entry (DWORD on x86, QWORD on x64):
    If high bit set (0x80000000 or 0x8000000000000000):
        Import by ORDINAL
        ordinal = value & 0xFFFF
    Else:
        Value is RVA to IMAGE_IMPORT_BY_NAME:
            0x00  2    Hint (ignored by GetProcAddress fallback)
            0x02  var  Name (ASCII, null-terminated)

Disassembly patterns for import calls:
    x64:  call qword ptr [rip + disp]    IAT slot
    x86:  call dword ptr [addr]           IAT slot
    FF 25 ...  =  jmp [IAT slot]  (tail-jump thunk)
    FF 15 ...  =  call [IAT slot]


================================================================================
9. EXPORT DIRECTORY (DD[0])
================================================================================

Normally only DLLs have an export directory.

IMAGE_EXPORT_DIRECTORY (40 bytes):
    0x00  4  Characteristics        always 0
    0x04  4  TimeDateStamp
    0x08  2  MajorVersion
    0x0A  2  MinorVersion
    0x0C  4  Name                   RVA of DLL's internal name
    0x10  4  Base                   ordinal of first entry (usually 1)
    0x14  4  NumberOfFunctions      entries in EAT
    0x18  4  NumberOfNames          entries in ENT (<= NumberOfFunctions)
    0x1C  4  AddressOfFunctions     RVA to DWORD[]  (EAT - real addrs)
    0x20  4  AddressOfNames         RVA to DWORD[]  (ENT - name RVAs)
    0x24  4  AddressOfNameOrdinals  RVA to WORD[]   (EOT - indices into EAT)

GetProcAddress algorithm (by name):
    1. Find j such that strcmp(AddressOfNames[j], wanted) == 0
    2. k   = AddressOfNameOrdinals[j]
    3. rva = AddressOfFunctions[k]
    4. Return base + rva

Shellcode API resolution uses this table, typically with a hashed name
comparison instead of strcmp.


================================================================================
10. TLS DIRECTORY (DD[9])
================================================================================

TLS callbacks execute BEFORE AddressOfEntryPoint. Breakpoints set only at EP
will miss them.

IMAGE_TLS_DIRECTORY64 (40 bytes):
    0x00  8  StartAddressOfRawData    VA of TLS template start
    0x08  8  EndAddressOfRawData      VA of TLS template end
    0x10  8  AddressOfIndex           VA of DWORD slot the loader fills
    0x18  8  AddressOfCallBacks       VA of null-terminated callback array
    0x20  4  SizeOfZeroFill
    0x24  4  Characteristics

IMAGE_TLS_DIRECTORY32 (24 bytes): same shape, all pointers 4 bytes.

AddressOfCallBacks points to:  PIMAGE_TLS_CALLBACK[]  (null-terminated)

Each callback has DllMain signature:
    void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved);
    Reason: 0 = DLL_PROCESS_DETACH
            1 = DLL_PROCESS_ATTACH  (fires first, main thread)
            2 = DLL_THREAD_ATTACH
            3 = DLL_THREAD_DETACH

TLS callbacks are a common hiding place for anti-debug checks and unpacking
stubs because they execute before any user-set entry-point breakpoint.


================================================================================
11. BASE RELOCATION (DD[5])
================================================================================

Used when the loader cannot load the image at ImageBase (ASLR, address
collision).

Series of blocks, each covering a 4KB page:

    IMAGE_BASE_RELOCATION header (8 bytes):
        0x00  4  VirtualAddress     RVA of the page this block patches
        0x04  4  SizeOfBlock        total block size including header
    Followed by:
        2 bytes per entry: bits 12-15 = type, bits 0-11 = offset in page

Relocation types in use:
    0  ABSOLUTE   padding, no fixup
    3  HIGHLOW    add 32-bit delta (x86)
    10 DIR64      add 64-bit delta (x64)

Loader applies them with:
    delta = actualBase - ImageBase
    for each entry: *(target) += delta

DYNAMIC_BASE set with no .reloc section means the image cannot actually
relocate.


================================================================================
12. KEY OFFSETS REFERENCE
================================================================================

From module base:
    base+0x00    "MZ"
    base+0x3C    e_lfanew (DWORD)
    base+e_lfanew = NT headers

From NT headers:
    NT+0x00     "PE\0\0"
    NT+0x04     Machine
    NT+0x06     NumberOfSections
    NT+0x14     SizeOfOptionalHeader
    NT+0x18     Magic (0x10B x86, 0x20B x64)
    NT+0x28     AddressOfEntryPoint
    NT+0x30     ImageBase (x64, 8 bytes)   /  NT+0x34 (x86, 4 bytes)
    NT+0x38     SectionAlignment
    NT+0x3C     FileAlignment
    NT+0x50     SizeOfImage
    NT+0x54     SizeOfHeaders
    NT+0x5C     Subsystem
    NT+0x5E     DllCharacteristics

Data Directory offsets (x64):
    EXPORT     NT+0x88 / NT+0x8C
    IMPORT     NT+0x90 / NT+0x94
    RESOURCE   NT+0x98 / NT+0x9C
    EXCEPTION  NT+0xA0 / NT+0xA4
    SECURITY   NT+0xA8 / NT+0xAC   (file offset, not RVA)
    BASERELOC  NT+0xB0 / NT+0xB4
    DEBUG      NT+0xB8 / NT+0xBC
    TLS        NT+0xD0 / NT+0xD4
    LOADCFG    NT+0xD8 / NT+0xDC
    IAT        NT+0xE8 / NT+0xEC
    DELAY_IMP  NT+0xF0 / NT+0xF4


================================================================================
13. COMMON DISASSEMBLY PATTERNS
================================================================================

PEB access (characteristic of shellcode and API resolvers):
    x86:  mov eax, fs:[30h]      -> PEB
          mov eax, fs:[18h]      -> TEB
    x64:  mov rax, gs:[60h]      -> PEB
          mov rax, gs:[30h]      -> TEB

Reading PE header fields from code:
    mov eax, [rax + 0x3C]        reading e_lfanew
    mov eax, [rax + NT + 0x28]   reading AddressOfEntryPoint
    mov eax, [rax + NT + 0x78]   reading export directory RVA (x86)
    mov eax, [rax + NT + 0x88]   reading export directory RVA (x64)

Import call shapes:
    x64:  call qword ptr [rip + disp]   indirect through IAT
    x86:  call dword ptr [addr]          indirect through IAT
    FF 25 ...  =  jmp [IAT slot]  (tail-jump thunk)
    FF 15 ...  =  call [IAT slot]

File format signatures:
    4D 5A           "MZ"
    50 45 00 00     "PE\0\0"
    52 53 44 53     "RSDS" (CodeView PDB reference)
    4E 42 31 30     "NB10" (older PDB reference)
    42 53 4A 42     "BSJB" (.NET metadata)


================================================================================
14. STANDARD STRUCTURE SIZES
================================================================================

    IMAGE_DOS_HEADER              0x40  (64)
    IMAGE_FILE_HEADER             0x14  (20)
    IMAGE_OPTIONAL_HEADER32       0xE0  (224)
    IMAGE_OPTIONAL_HEADER64       0xF0  (240)
    IMAGE_NT_HEADERS32            0xF8  (248)
    IMAGE_NT_HEADERS64            0x108 (264)
    DataDirectory[16]             0x80  (128)
    IMAGE_DATA_DIRECTORY          8
    IMAGE_SECTION_HEADER          0x28  (40)
    IMAGE_EXPORT_DIRECTORY        0x28  (40)
    IMAGE_IMPORT_DESCRIPTOR       0x14  (20)
    IMAGE_DELAYLOAD_DESCRIPTOR    0x20  (32)
    IMAGE_RESOURCE_DIRECTORY      0x10  (16)
    IMAGE_TLS_DIRECTORY32         0x18  (24)
    IMAGE_TLS_DIRECTORY64         0x28  (40)
    IMAGE_BASE_RELOCATION         8  (header only)


================================================================================
15. PEB / TEB RELEVANT FIELDS
================================================================================

PEB access:
    x64:  mov rax, gs:[60h]
    x86:  mov eax, fs:[30h]

PEB fields:
    PEB + 0x02       BeingDebugged         1 if debugger attached
    PEB + 0xBC (x64) NtGlobalFlag          0x70 under debugger
    PEB + 0x68 (x86) NtGlobalFlag          0x70 under debugger
    PEB + 0x18       ProcessHeap           heap debug flags accessible here

TEB access:
    x64:  mov rax, gs:[30h]
    x86:  mov eax, fs:[18h]

TEB fields:
    TEB + 0x00       NtTib.ExceptionList   SEH chain head (x86 only)

NtGlobalFlag value 0x70 is the sum of three heap-debug bits set by the
debug heap:
    0x10  FLG_HEAP_ENABLE_TAIL_CHECK
    0x20  FLG_HEAP_ENABLE_FREE_CHECK
    0x40  FLG_HEAP_VALIDATE_PARAMETERS


================================================================================
16. TRIAGE SEQUENCE
================================================================================

17. Confirm PE format:
   - base+0 should be "MZ"
   - base+e_lfanew should be "PE\0\0"

2. Determine bitness:
   - WORD at NT+0x18:  0x10B = x86, 0x20B = x64

3. Determine image type:
   - WORD at NT+0x16 (Characteristics): bit 0x2000 set = DLL

4. Locate entry point:
   - DWORD at NT+0x28 = AddressOfEntryPoint RVA
   - Real EP = ImageBase + AddressOfEntryPoint

5. Check for TLS callbacks:
   - QWORD at NT+0xD0 (x64) or DWORD at NT+0xC0 (x86)
   - If non-zero, follow to AddressOfCallBacks field

6. Enumerate imports:
   - Follow DD[1] at NT+0x90 (x64) or NT+0x80 (x86)
   - Walk descriptors, read DLL names and function names
   - Also check DD[13] delay imports at NT+0xF0 (x64) or NT+0xE0 (x86)

7. Enumerate sections:
   - WORD at NT+0x06 = count
   - Table starts at NT+0x18+SizeOfOptionalHeader
   - Each entry 40 bytes

8. Packer indicators:
   - Non-standard section names (UPX0, .vmp0, etc.)
   - RWX section characteristics (0xE0000020)
   - Minimal imports (only LoadLibrary + GetProcAddress) or none
   - High entropy in code sections
   - DYNAMIC_BASE set with no .reloc entries


================================================================================
END
================================================================================
