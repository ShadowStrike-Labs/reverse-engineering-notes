================================================================================
                PE FORMAT - BYTE-LEVEL OFFSET REFERENCE
================================================================================

HIERARCHY

    base + 0x00                                   IMAGE_DOS_HEADER
    base + e_lfanew                               IMAGE_NT_HEADERS
    NT + 0x00                                     Signature
    NT + 0x04                                     IMAGE_FILE_HEADER
    NT + 0x18                                     IMAGE_OPTIONAL_HEADER
    NT + 0x18 + SizeOfOptionalHeader              Section header array

    e_lfanew  = *(DWORD *)(base + 0x3C)
    NT        = base + e_lfanew


================================================================================
IMAGE_DOS_HEADER                base + 0x00, size 0x40 (64)
================================================================================

HEX   DEC   SIZE  FIELD
0x00  0     2     e_magic              "MZ" = 0x5A4D
0x02  2     2     e_cblp
0x04  4     2     e_cp
0x06  6     2     e_crlc
0x08  8     2     e_cparhdr
0x0A  10    2     e_minalloc
0x0C  12    2     e_maxalloc
0x0E  14    2     e_ss
0x10  16    2     e_sp
0x12  18    2     e_csum
0x14  20    2     e_ip
0x16  22    2     e_cs
0x18  24    2     e_lfarlc
0x1A  26    2     e_ovno
0x1C  28    8     e_res[4]
0x24  36    2     e_oemid
0x26  38    2     e_oeminfo
0x28  40    20    e_res2[10]
0x3C  60    4     e_lfanew             file offset of "PE\0\0"


================================================================================
IMAGE_NT_HEADERS                base + e_lfanew
================================================================================

NT+   DEC   SIZE  FIELD
0x00  0     4     Signature            "PE\0\0" = 0x00004550
0x04  4     20    FileHeader           IMAGE_FILE_HEADER
0x18  24    var   OptionalHeader       IMAGE_OPTIONAL_HEADER (0xE0 or 0xF0)

    IMAGE_NT_HEADERS32  total size  0xF8  (248)
    IMAGE_NT_HEADERS64  total size  0x108 (264)


================================================================================
IMAGE_FILE_HEADER               NT + 0x04, size 0x14 (20)
================================================================================

NT+   DEC   SIZE  FIELD
0x04  4     2     Machine              0x8664 = x64, 0x014C = x86
0x06  6     2     NumberOfSections
0x08  8     4     TimeDateStamp
0x0C  12    4     PointerToSymbolTable
0x10  16    4     NumberOfSymbols
0x14  20    2     SizeOfOptionalHeader 0xF0 for x64, 0xE0 for x86
0x16  22    2     Characteristics

Characteristics bits:
    0x0001  RELOCS_STRIPPED
    0x0002  EXECUTABLE_IMAGE
    0x0004  LINE_NUMS_STRIPPED
    0x0008  LOCAL_SYMS_STRIPPED
    0x0020  LARGE_ADDRESS_AWARE
    0x0100  32BIT_MACHINE
    0x0200  DEBUG_STRIPPED
    0x1000  SYSTEM
    0x2000  DLL


================================================================================
IMAGE_OPTIONAL_HEADER32         NT + 0x18, size 0xE0 (224)
================================================================================

NT+   DEC   SIZE  FIELD
0x18  24    2     Magic                0x010B
0x1A  26    1     MajorLinkerVersion
0x1B  27    1     MinorLinkerVersion
0x1C  28    4     SizeOfCode
0x20  32    4     SizeOfInitializedData
0x24  36    4     SizeOfUninitializedData
0x28  40    4     AddressOfEntryPoint
0x2C  44    4     BaseOfCode
0x30  48    4     BaseOfData
0x34  52    4     ImageBase
0x38  56    4     SectionAlignment
0x3C  60    4     FileAlignment
0x40  64    2     MajorOperatingSystemVersion
0x42  66    2     MinorOperatingSystemVersion
0x44  68    2     MajorImageVersion
0x46  70    2     MinorImageVersion
0x48  72    2     MajorSubsystemVersion
0x4A  74    2     MinorSubsystemVersion
0x4C  76    4     Win32VersionValue
0x50  80    4     SizeOfImage
0x54  84    4     SizeOfHeaders
0x58  88    4     CheckSum
0x5C  92    2     Subsystem
0x5E  94    2     DllCharacteristics
0x60  96    4     SizeOfStackReserve
0x64  100   4     SizeOfStackCommit
0x68  104   4     SizeOfHeapReserve
0x6C  108   4     SizeOfHeapCommit
0x70  112   4     LoaderFlags
0x74  116   4     NumberOfRvaAndSizes
0x78  120   128   DataDirectory[16]


================================================================================
IMAGE_OPTIONAL_HEADER64         NT + 0x18, size 0xF0 (240)
================================================================================

NT+   DEC   SIZE  FIELD
0x18  24    2     Magic                0x020B
0x1A  26    1     MajorLinkerVersion
0x1B  27    1     MinorLinkerVersion
0x1C  28    4     SizeOfCode
0x20  32    4     SizeOfInitializedData
0x24  36    4     SizeOfUninitializedData
0x28  40    4     AddressOfEntryPoint
0x2C  44    4     BaseOfCode
0x30  48    8     ImageBase            (no BaseOfData on x64)
0x38  56    4     SectionAlignment
0x3C  60    4     FileAlignment
0x40  64    2     MajorOperatingSystemVersion
0x42  66    2     MinorOperatingSystemVersion
0x44  68    2     MajorImageVersion
0x46  70    2     MinorImageVersion
0x48  72    2     MajorSubsystemVersion
0x4A  74    2     MinorSubsystemVersion
0x4C  76    4     Win32VersionValue
0x50  80    4     SizeOfImage
0x54  84    4     SizeOfHeaders
0x58  88    4     CheckSum
0x5C  92    2     Subsystem
0x5E  94    2     DllCharacteristics
0x60  96    8     SizeOfStackReserve
0x68  104   8     SizeOfStackCommit
0x70  112   8     SizeOfHeapReserve
0x78  120   8     SizeOfHeapCommit
0x80  128   4     LoaderFlags
0x84  132   4     NumberOfRvaAndSizes
0x88  136   128   DataDirectory[16]

DllCharacteristics bits:
    0x0020  HIGH_ENTROPY_VA
    0x0040  DYNAMIC_BASE
    0x0080  FORCE_INTEGRITY
    0x0100  NX_COMPAT
    0x0200  NO_ISOLATION
    0x0400  NO_SEH
    0x0800  NO_BIND
    0x1000  APPCONTAINER
    0x2000  WDM_DRIVER
    0x4000  GUARD_CF
    0x8000  TERMINAL_SERVER_AWARE


================================================================================
DATA DIRECTORY                  16 entries, 8 bytes each
================================================================================

Each entry:
    0x00  4   VirtualAddress  (RVA)
    0x04  4   Size

Formula:
    PE32+ : DD[n].RVA  = NT + 0x88 + 8*n ; DD[n].Size = NT + 0x8C + 8*n
    PE32  : DD[n].RVA  = NT + 0x78 + 8*n ; DD[n].Size = NT + 0x7C + 8*n


PE32+ (x64):
NT+   DEC   DD INDEX  NAME
0x88  136   DD[0]     EXPORT              IMAGE_EXPORT_DIRECTORY
0x90  144   DD[1]     IMPORT              IMAGE_IMPORT_DESCRIPTOR array
0x98  152   DD[2]     RESOURCE            IMAGE_RESOURCE_DIRECTORY
0xA0  160   DD[3]     EXCEPTION           RUNTIME_FUNCTION array
0xA8  168   DD[4]     SECURITY            Authenticode cert
0xB0  176   DD[5]     BASERELOC           IMAGE_BASE_RELOCATION blocks
0xB8  184   DD[6]     DEBUG               IMAGE_DEBUG_DIRECTORY array
0xC0  192   DD[7]     ARCHITECTURE        unused
0xC8  200   DD[8]     GLOBALPTR           unused
0xD0  208   DD[9]     TLS                 IMAGE_TLS_DIRECTORY
0xD8  216   DD[10]    LOAD_CONFIG         IMAGE_LOAD_CONFIG_DIRECTORY
0xE0  224   DD[11]    BOUND_IMPORT
0xE8  232   DD[12]    IAT
0xF0  240   DD[13]    DELAY_IMPORT        IMAGE_DELAYLOAD_DESCRIPTOR array
0xF8  248   DD[14]    COM_DESCRIPTOR      IMAGE_COR20_HEADER
0x100 256   DD[15]    RESERVED


PE32 (x86):
NT+   DEC   DD INDEX  NAME
0x78  120   DD[0]     EXPORT
0x80  128   DD[1]     IMPORT
0x88  136   DD[2]     RESOURCE
0x90  144   DD[3]     EXCEPTION
0x98  152   DD[4]     SECURITY
0xA0  160   DD[5]     BASERELOC
0xA8  168   DD[6]     DEBUG
0xB0  176   DD[7]     ARCHITECTURE
0xB8  184   DD[8]     GLOBALPTR
0xC0  192   DD[9]     TLS
0xC8  200   DD[10]    LOAD_CONFIG
0xD0  208   DD[11]    BOUND_IMPORT
0xD8  216   DD[12]    IAT
0xE0  224   DD[13]    DELAY_IMPORT
0xE8  232   DD[14]    COM_DESCRIPTOR
0xF0  240   DD[15]    RESERVED


================================================================================
IMAGE_SECTION_HEADER            size 0x28 (40)
================================================================================

Table location: NT + 0x18 + SizeOfOptionalHeader
    PE32+ default:  NT + 0x108
    PE32  default:  NT + 0xF8

Entry n location: section_table + 40*n

HEX   DEC   SIZE  FIELD
0x00  0     8     Name
0x08  8     4     VirtualSize
0x0C  12    4     VirtualAddress
0x10  16    4     SizeOfRawData
0x14  20    4     PointerToRawData
0x18  24    4     PointerToRelocations
0x1C  28    4     PointerToLinenumbers
0x20  32    2     NumberOfRelocations
0x22  34    2     NumberOfLinenumbers
0x24  36    4     Characteristics

Characteristics bits:
    0x00000020  CNT_CODE
    0x00000040  CNT_INITIALIZED_DATA
    0x00000080  CNT_UNINITIALIZED_DATA
    0x02000000  MEM_DISCARDABLE
    0x04000000  MEM_NOT_CACHED
    0x08000000  MEM_NOT_PAGED
    0x10000000  MEM_SHARED
    0x20000000  MEM_EXECUTE
    0x40000000  MEM_READ
    0x80000000  MEM_WRITE


================================================================================
IMAGE_IMPORT_DESCRIPTOR         size 0x14 (20)
================================================================================

Array located at DD[1].VirtualAddress, terminated by all-zero descriptor.

HEX   DEC   SIZE  FIELD
0x00  0     4     OriginalFirstThunk       RVA of INT
0x04  4     4     TimeDateStamp
0x08  8     4     ForwarderChain
0x0C  12    4     Name                     RVA of DLL name string
0x10  16    4     FirstThunk               RVA of IAT


================================================================================
IMAGE_THUNK_DATA                size 4 (PE32) or 8 (PE32+)
================================================================================

Terminated by all-zero entry.

If high bit set:
    PE32  :  (value & 0x80000000)         -> import by ordinal
    PE32+ :  (value & 0x8000000000000000) -> import by ordinal
    ordinal = value & 0xFFFF

Else:
    value is RVA to IMAGE_IMPORT_BY_NAME


================================================================================
IMAGE_IMPORT_BY_NAME            variable size
================================================================================

HEX   DEC   SIZE  FIELD
0x00  0     2     Hint
0x02  2     var   Name                     ASCII, NUL-terminated


================================================================================
IMAGE_DELAYLOAD_DESCRIPTOR      size 0x20 (32)
================================================================================

Array located at DD[13].VirtualAddress, terminated by all-zero descriptor.

HEX   DEC   SIZE  FIELD
0x00  0     4     Attributes
0x04  4     4     DllNameRVA
0x08  8     4     ModuleHandleRVA
0x0C  12    4     ImportAddressTableRVA
0x10  16    4     ImportNameTableRVA
0x14  20    4     BoundImportAddressTableRVA
0x18  24    4     UnloadInformationTableRVA
0x1C  28    4     TimeDateStamp


================================================================================
IMAGE_EXPORT_DIRECTORY          size 0x28 (40)
================================================================================

Located at DD[0].VirtualAddress.

HEX   DEC   SIZE  FIELD
0x00  0     4     Characteristics
0x04  4     4     TimeDateStamp
0x08  8     2     MajorVersion
0x0A  10    2     MinorVersion
0x0C  12    4     Name                     RVA of DLL internal name
0x10  16    4     Base                     ordinal of first entry
0x14  20    4     NumberOfFunctions
0x18  24    4     NumberOfNames
0x1C  28    4     AddressOfFunctions       RVA to DWORD[] (EAT)
0x20  32    4     AddressOfNames           RVA to DWORD[] (ENT)
0x24  36    4     AddressOfNameOrdinals    RVA to WORD[]  (EOT)


================================================================================
IMAGE_TLS_DIRECTORY32           size 0x18 (24)
================================================================================

Located at DD[9].VirtualAddress.

HEX   DEC   SIZE  FIELD
0x00  0     4     StartAddressOfRawData    VA
0x04  4     4     EndAddressOfRawData      VA
0x08  8     4     AddressOfIndex           VA
0x0C  12    4     AddressOfCallBacks       VA
0x10  16    4     SizeOfZeroFill
0x14  20    4     Characteristics


================================================================================
IMAGE_TLS_DIRECTORY64           size 0x28 (40)
================================================================================

HEX   DEC   SIZE  FIELD
0x00  0     8     StartAddressOfRawData    VA
0x08  8     8     EndAddressOfRawData      VA
0x10  16    8     AddressOfIndex           VA
0x18  24    8     AddressOfCallBacks       VA
0x20  32    4     SizeOfZeroFill
0x24  36    4     Characteristics


================================================================================
IMAGE_BASE_RELOCATION           header size 8, variable total
================================================================================

Array of blocks located at DD[5].VirtualAddress.
Iterate until DD[5].Size bytes consumed.

Block header:
HEX   DEC   SIZE  FIELD
0x00  0     4     VirtualAddress           RVA of 4KB page
0x04  4     4     SizeOfBlock              total block size including header

Followed by (SizeOfBlock - 8) / 2 entries, 2 bytes each:
    bits 15..12  Type
    bits 11..0   Offset within page

Relocation types:
    0   ABSOLUTE   padding
    3   HIGHLOW    32-bit delta (x86)
    10  DIR64      64-bit delta (x64)

Next block: current_block + SizeOfBlock


================================================================================
IMAGE_RESOURCE_DIRECTORY        size 0x10 (16)
================================================================================

Located at DD[2].VirtualAddress.

HEX   DEC   SIZE  FIELD
0x00  0     4     Characteristics
0x04  4     4     TimeDateStamp
0x08  8     2     MajorVersion
0x0A  10    2     MinorVersion
0x0C  12    2     NumberOfNamedEntries
0x0E  14    2     NumberOfIdEntries


================================================================================
IMAGE_RESOURCE_DIRECTORY_ENTRY  size 8
================================================================================

HEX   DEC   SIZE  FIELD
0x00  0     4     Name / Id                high bit set = name offset
0x04  4     4     OffsetToData             high bit set = subdirectory


================================================================================
IMAGE_RESOURCE_DATA_ENTRY       size 0x10 (16)
================================================================================

HEX   DEC   SIZE  FIELD
0x00  0     4     OffsetToData             RVA to resource bytes
0x04  4     4     Size
0x08  8     4     CodePage
0x0C  12    4     Reserved


================================================================================
IMAGE_DEBUG_DIRECTORY           size 0x1C (28)
================================================================================

Array located at DD[6].VirtualAddress.
Count = DD[6].Size / 28.

HEX   DEC   SIZE  FIELD
0x00  0     4     Characteristics
0x04  4     4     TimeDateStamp
0x08  8     2     MajorVersion
0x0A  10    2     MinorVersion
0x0C  12    4     Type
0x10  16    4     SizeOfData
0x14  20    4     AddressOfRawData         RVA
0x18  24    4     PointerToRawData         file offset


================================================================================
STRUCTURE SIZE REFERENCE
================================================================================

HEX     DEC    STRUCTURE
0x40    64     IMAGE_DOS_HEADER
0x14    20     IMAGE_FILE_HEADER
0xE0    224    IMAGE_OPTIONAL_HEADER32
0xF0    240    IMAGE_OPTIONAL_HEADER64
0xF8    248    IMAGE_NT_HEADERS32
0x108   264    IMAGE_NT_HEADERS64
0x80    128    DataDirectory[16]
0x08    8      IMAGE_DATA_DIRECTORY
0x28    40     IMAGE_SECTION_HEADER
0x28    40     IMAGE_EXPORT_DIRECTORY
0x14    20     IMAGE_IMPORT_DESCRIPTOR
0x20    32     IMAGE_DELAYLOAD_DESCRIPTOR
0x10    16     IMAGE_RESOURCE_DIRECTORY
0x08    8      IMAGE_RESOURCE_DIRECTORY_ENTRY
0x10    16     IMAGE_RESOURCE_DATA_ENTRY
0x1C    28     IMAGE_DEBUG_DIRECTORY
0x18    24     IMAGE_TLS_DIRECTORY32
0x28    40     IMAGE_TLS_DIRECTORY64
0x08    8      IMAGE_BASE_RELOCATION header


================================================================================
NT+X REVERSE LOOKUP
================================================================================

NT+   DEC   PE32 FIELD                      PE32+ FIELD
0x00  0     Signature                       Signature
0x04  4     Machine                         Machine
0x06  6     NumberOfSections                NumberOfSections
0x08  8     TimeDateStamp                   TimeDateStamp
0x0C  12    PointerToSymbolTable            PointerToSymbolTable
0x10  16    NumberOfSymbols                 NumberOfSymbols
0x14  20    SizeOfOptionalHeader            SizeOfOptionalHeader
0x16  22    Characteristics                 Characteristics
0x18  24    Magic (0x10B)                   Magic (0x20B)
0x1A  26    MajorLinkerVersion              MajorLinkerVersion
0x1B  27    MinorLinkerVersion              MinorLinkerVersion
0x1C  28    SizeOfCode                      SizeOfCode
0x20  32    SizeOfInitializedData           SizeOfInitializedData
0x24  36    SizeOfUninitializedData         SizeOfUninitializedData
0x28  40    AddressOfEntryPoint             AddressOfEntryPoint
0x2C  44    BaseOfCode                      BaseOfCode
0x30  48    BaseOfData                      ImageBase (8 bytes)
0x34  52    ImageBase
0x38  56    SectionAlignment                SectionAlignment
0x3C  60    FileAlignment                   FileAlignment
0x40  64    MajorOperatingSystemVersion     MajorOperatingSystemVersion
0x42  66    MinorOperatingSystemVersion     MinorOperatingSystemVersion
0x44  68    MajorImageVersion               MajorImageVersion
0x46  70    MinorImageVersion               MinorImageVersion
0x48  72    MajorSubsystemVersion           MajorSubsystemVersion
0x4A  74    MinorSubsystemVersion           MinorSubsystemVersion
0x4C  76    Win32VersionValue               Win32VersionValue
0x50  80    SizeOfImage                     SizeOfImage
0x54  84    SizeOfHeaders                   SizeOfHeaders
0x58  88    CheckSum                        CheckSum
0x5C  92    Subsystem                       Subsystem
0x5E  94    DllCharacteristics              DllCharacteristics
0x60  96    SizeOfStackReserve              SizeOfStackReserve (8 bytes)
0x64  100   SizeOfStackCommit
0x68  104   SizeOfHeapReserve               SizeOfStackCommit (8 bytes)
0x6C  108   SizeOfHeapCommit
0x70  112   LoaderFlags                     SizeOfHeapReserve (8 bytes)
0x74  116   NumberOfRvaAndSizes
0x78  120   DD[0].VirtualAddress  EXPORT    SizeOfHeapCommit (8 bytes)
0x7C  124   DD[0].Size            EXPORT
0x80  128   DD[1].VirtualAddress  IMPORT    LoaderFlags
0x84  132   DD[1].Size            IMPORT    NumberOfRvaAndSizes
0x88  136   DD[2].VirtualAddress  RESOURCE  DD[0].VirtualAddress  EXPORT
0x8C  140   DD[2].Size            RESOURCE  DD[0].Size            EXPORT
0x90  144   DD[3].VirtualAddress  EXCEPTION DD[1].VirtualAddress  IMPORT
0x94  148   DD[3].Size            EXCEPTION DD[1].Size            IMPORT
0x98  152   DD[4].VirtualAddress  SECURITY  DD[2].VirtualAddress  RESOURCE
0x9C  156   DD[4].Size            SECURITY  DD[2].Size            RESOURCE
0xA0  160   DD[5].VirtualAddress  BASERELOC DD[3].VirtualAddress  EXCEPTION
0xA4  164   DD[5].Size            BASERELOC DD[3].Size            EXCEPTION
0xA8  168   DD[6].VirtualAddress  DEBUG     DD[4].VirtualAddress  SECURITY
0xAC  172   DD[6].Size            DEBUG     DD[4].Size            SECURITY
0xB0  176   DD[7].VirtualAddress            DD[5].VirtualAddress  BASERELOC
0xB4  180   DD[7].Size                      DD[5].Size            BASERELOC
0xB8  184   DD[8].VirtualAddress  GLOBALPTR DD[6].VirtualAddress  DEBUG
0xBC  188   DD[8].Size            GLOBALPTR DD[6].Size            DEBUG
0xC0  192   DD[9].VirtualAddress  TLS       DD[7].VirtualAddress
0xC4  196   DD[9].Size            TLS       DD[7].Size
0xC8  200   DD[10].VirtualAddress LOADCFG   DD[8].VirtualAddress  GLOBALPTR
0xCC  204   DD[10].Size           LOADCFG   DD[8].Size            GLOBALPTR
0xD0  208   DD[11].VirtualAddress           DD[9].VirtualAddress  TLS
0xD4  212   DD[11].Size                     DD[9].Size            TLS
0xD8  216   DD[12].VirtualAddress IAT       DD[10].VirtualAddress LOADCFG
0xDC  220   DD[12].Size           IAT       DD[10].Size           LOADCFG
0xE0  224   DD[13].VirtualAddress DELAY     DD[11].VirtualAddress
0xE4  228   DD[13].Size           DELAY     DD[11].Size
0xE8  232   DD[14].VirtualAddress COM       DD[12].VirtualAddress IAT
0xEC  236   DD[14].Size           COM       DD[12].Size           IAT
0xF0  240   DD[15].VirtualAddress           DD[13].VirtualAddress DELAY
0xF4  244   DD[15].Size                     DD[13].Size           DELAY
0xF8  248   section_table[0] starts         DD[14].VirtualAddress COM
0xFC  252                                   DD[14].Size           COM
0x100 256                                   DD[15].VirtualAddress
0x104 260                                   DD[15].Size
0x108 264                                   section_table[0] starts

================================================================================
END
================================================================================
