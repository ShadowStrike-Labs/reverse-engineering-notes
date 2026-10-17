
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)

void NTAPI TlsCallback(
    PVOID DllHandle,    // a - DLL module handle
    DWORD Reason,       // b - Calling Reason
    PVOID Reserved      // c - Reserved
);

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // a - DLL module handle
    DWORD     fdwReason, // b - Calling Reason
    LPVOID    lpvReserved // c - Reserved parameter
);

#define DLL_PROCESS_DETACH 0  // Process finishes or DLL gets unloaded
#define DLL_PROCESS_ATTACH 1  // Process starts or DLL gets loaded
#define DLL_THREAD_ATTACH  2  // New thread is created
#define DLL_THREAD_DETACH  3  // Thread is detaching.

NtGlobalFlag & 0x70  -> False while not debugging true while debugging.

size_t fwrite(
    const void *ptr,   // a: Memory address of the data that will get written
    size_t size,       // b: Size of each element
    size_t count,      // c: How many elements?
    FILE *stream       // d: Where will be written? (FILE* pointer)
);


 VirtualProtect — register map (x64 fastcall)

  RCX = lpAddress        -> base address of the region to reprotect
  RDX = dwSize           -> region size in bytes
  R8  = flNewProtect     -> NEW protection constant                 <-- KEY
  R9  = lpflOldProtect   -> [OUT] pointer that receives the old protection
  RAX = (return) BOOL    -> nonzero on success

 VirtualProtect - R8 :

 0x01 -> PAGE_NOACCESS -> no access to anything
0x02 -> PAGE_READONLY -> R--(only read)
0x04 ->PAGE_READWRITE ->RW-
0x10 -> PAGE_EXECUTE -> --X
0x20 -> PAGE_EXECUTE_READ->R-X
0x40 -> PAGE_EXECUTE_READWRITE -> RWX
0x80 -> PAGE_EXECUTE_WRITECOPY -> RWX(copy on write)


  VirtualAlloc — register map (x64 fastcall)

  RCX = lpAddress          -> desired base address (0/NULL = let the system choose)
  RDX = dwSize             -> number of bytes to allocate
  R8  = flAllocationType   -> allocation type (MEM_*)               <-- list below
  R9  = flProtect          -> memory protection (SAME constants as VirtualProtect)
  RAX = (return)           -> base address of the allocated region  <-- note this for unpacking

  VirtualAlloc — flAllocationType (R8)

  0x1000     MEM_COMMIT          -> commit pages (ready to use)
  0x2000     MEM_RESERVE         -> reserve address space (not committed yet)
  0x3000     MEM_COMMIT|RESERVE  -> both at once (most common in packers)
  0x100000   MEM_TOP_DOWN        -> allocate from the highest address downward
  0x40000    MEM_WRITE_WATCH     -> track writes to the region
  0x20000000 MEM_LARGE_PAGES     -> large-page allocation

 



HANDLE CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

Explanations on CreateFileA :

 1. lpFileName            - LPCSTR : name/path of file (or device, pipe, \\.\ etc.) to create/open

  2. dwDesiredAccess       - DWORD :
     0x80000000  GENERIC_READ
     0x40000000  GENERIC_WRITE
     0xC0000000  GENERIC_READ | GENERIC_WRITE
     0           query attributes only (no data access)

  3. dwShareMode           - DWORD :
     0  no sharing (exclusive)
     1  FILE_SHARE_READ    -> others may read
     2  FILE_SHARE_WRITE   -> others may write
     4  FILE_SHARE_DELETE  -> others may delete/rename
     7  full sharing (R|W|D)

  4. lpSecurityAttributes  - LPSECURITY_ATTRIBUTES :
     NULL      default security, handle not inherited
     non-NULL  custom DACL / inheritable handle

  5. dwCreationDisposition - DWORD :
     1  CREATE_NEW        create; FAIL if it already exists
     2  CREATE_ALWAYS     create; OVERWRITE if it exists
     3  OPEN_EXISTING     open; FAIL if it does not exist
     4  OPEN_ALWAYS       open; create it if it does not exist
     5  TRUNCATE_EXISTING open and truncate to 0; FAIL if it does not exist

  6. dwFlagsAndAttributes  - DWORD : (attributes | flags, OR-combined)
     attributes:
       0x1    FILE_ATTRIBUTE_READONLY
       0x2    FILE_ATTRIBUTE_HIDDEN
       0x4    FILE_ATTRIBUTE_SYSTEM
       0x20   FILE_ATTRIBUTE_ARCHIVE
       0x80   FILE_ATTRIBUTE_NORMAL      (only valid if used alone)
       0x100  FILE_ATTRIBUTE_TEMPORARY
     flags (RE-relevant):
       0x02000000 FILE_FLAG_BACKUP_SEMANTICS  (required to open a directory handle)
       0x04000000 FILE_FLAG_DELETE_ON_CLOSE   (file removed when last handle closes)
       0x10000000 FILE_FLAG_RANDOM_ACCESS
       0x08000000 FILE_FLAG_SEQUENTIAL_SCAN
       0x20000000 FILE_FLAG_NO_BUFFERING
       0x40000000 FILE_FLAG_OVERLAPPED        (async I/O)
       0x80000000 FILE_FLAG_WRITE_THROUGH

  7. hTemplateFile         - HANDLE : template supplying attributes for a NEW file;
                             usually NULL (0). Ignored when opening an existing file.

  RETURN                   - HANDLE :
     success  -> valid file handle
     failure  -> INVALID_HANDLE_VALUE (0xFFFFFFFF / -1)   [check GetLastError]


* If you see those parameters --> They are prolly related with that function

	((int (__fastcall *)(__int64, __int64 *, _QWORD, __int64 *, int, int))(func_addr))(X,&Y,0,&Z,12288(Or 0x3000),4)  --> NtAllocateVirtualMemory(Because 0x3000 directly means MEM_COMMIT | MEM_RESERVE at windows. While allocating a new memory at RAM this value is necessary. 0x04(4) also means PAGE_READWRITE. In memory there is only one Native Windows API that allocates memory with 0x3000 mode and PAGE_READWRITE and its NtAllocateVirtualMemory)
	((int (__fastcall *)(__int64, __int64 *, _QWORD, __int64 *, int, int))(func_addr))(X,&Y,&Z,64(0x40),&E) --> NtProtectVirtualMemory(Especially if this calling convention comes just right after the NtAllocateVirtualMemory its a high chance that its NtProtectVirtualMemory because it tooks a long list and also 0x40 here means PAGE_EXECUTE_READWRITE(RWX) To run code in the memory that memory region should be in the need of X(execution) Permission)
	((int (__fastcall *)(__int64 *, __int64, _QWORD, __int64, __int64, __int64, _DWORD, _QWORD, _QWORD, _QWORD, _QWORD))(...))(&X,0x1FFFFF,0,Y,Z,E,0,0,0,0,0) --> NtCreateThreadEx(Here again its obvious that 0x1FFFFF means THREAD_ALL_ACCESS at windows and also classic createthread and createremotethread functions are in user-mode and gets less parameters while this one here gets 11 parameters.)

