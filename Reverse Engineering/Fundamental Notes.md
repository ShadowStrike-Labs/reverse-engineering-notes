
** TEST-XOR-OR-AND Quick Notes : 

TEST RAX, RCX -> If RAX and RCX have at least one shared bit where both are 1, the result is non-zero, so ZF = 0
TEST RAX, RCX -> If RAX and RCX have no shared bits where both are 1, the result is zero, so ZF = 1

XOR RAX, RCX -> If RAX = RCX, the result is zero, so ZF = 1
XOR RAX, RCX -> If RAX != RCX, the result is non-zero, so ZF = 0

AND RAX, RCX -> Performs a bitwise AND. Result is written to RAX. RCX stays unchanged.
AND RAX, RCX -> If RAX and RCX have no shared bits where both are 1, the result is zero, so ZF = 1
AND RAX, RCX -> If RAX and RCX have at least one shared bit where both are 1, the result is non-zero, so ZF = 0

OR RAX, RCX -> Performs a bitwise OR. Result is written to RAX. RCX stays unchanged.
OR RAX, RCX -> If RAX and RCX are both zero, the result is zero, so ZF = 1
OR RAX, RCX -> If RAX or RCX has at least one bit set to 1, the result is non-zero, so ZF = 0

**  '>> n ' operator equals dividing with 2^n

**  idiv esi command makes those :

EAX = (EDX:EAX) / ESI     
EDX = (EDX:EAX) % ESI     

**  cvar -0x37 pattern -> Hex character to a numerical value e.g. 'A' --> 0x41

** Ranges:

(unsigned)(X - A) > B --> range : [A, A+B] e.g. (x-4)>28 → [4,32]

(unsigned)(X - A) > 0 --> range : X == A e.g. (x-16)>0 → x=16

(unsigned)X > B --> range : [0, B] e.g. x>256 → [0,256]

(unsigned)(X - 1) > B --> range : [1, B+1] (x-1)>254 → [1,255]

(unsigned)(X - A) > B --> range : X >= A


** If you see _bittest64 with a large hexadecimal value (e.g., 0x100002400), convert the hex to binary and check which bits are set to 1:

Bits 9, 13, 32 → Trimming whitespace characters (TAB, CR/LF, SPACE)

Bits 48 - 57 → Validating/expecting only digits (0-9)

Bits 65 - 90 → Validating/expecting only uppercase letters (A-Z)

Bits 97 - 122 → Validating/expecting only lowercase letters (a-z)

** EndPtr = "000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515"
               "25354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899bad cast"; --> std::to_string pattern in code.




