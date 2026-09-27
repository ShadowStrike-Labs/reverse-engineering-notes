

// Standard C++ std::string memory layout (x64 - MSVC / Clang)
 struct std_string    // 0x20
  {
      char   buf[16];   // 0x00  SSO buffer; first 8 bytes are the char* when heap-allocated
      size_t size;      // 0x10
      size_t capacity;  // 0x18
  };

typedef struct _SYSTEMTIME {
    WORD wYear;         // +0  (2 bytes)
    WORD wMonth;        // +2  (2 bytes)
    WORD wDayOfWeek;    // +4  (2 bytes)
    WORD wDay;          // +6  (2 bytes)
    WORD wHour;         // +8  (2 bytes)
    WORD wMinute;       // +10 (2 bytes)
    WORD wSecond;       // +12 (2 bytes)
    WORD wMilliseconds; // +14 (2 bytes)
} SYSTEMTIME;

