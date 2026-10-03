
* TEST-XOR-OR-AND Quick Notes : 

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

* '>> n ' operator equals dividing with 2^n

* idiv esi command makes those :

	  EAX = (EDX:EAX) / ESI     
	  EDX = (EDX:EAX) % ESI     

* cvar -0x37 pattern -> Hex character to a numerical value e.g. 'A' --> 0x41

*  Ranges:

	 (unsigned)(X - A) > B --> range : [A, A+B] e.g. (x-4)>28 → [4,32]
	(unsigned)(X - A) > 0 --> range : X == A e.g. (x-16)>0 → x=16
	(unsigned)X > B --> range : [0, B] e.g. x>256 → [0,256]
	(unsigned)(X - 1) > B --> range : [1, B+1] (x-1)>254 → [1,255]
	(unsigned)(X - A) > B --> range : X >= A


* If you see _bittest64 with a large hexadecimal value (e.g., 0x100002400), convert the hex to binary and check which bits are set to 1:

	Bits 9, 13, 32 → Trimming whitespace characters (TAB, CR/LF, SPACE)
	Bits 48 - 57 → Validating/expecting only digits (0-9)
	Bits 65 - 90 → Validating/expecting only uppercase letters (A-Z)
	Bits 97 - 122 → Validating/expecting only lowercase letters (a-z)


* Separating the Process Injection and Reflective DLL Injection from each other:

	First of all in Raw Process Injection binary does not validates the patterns like "MZ" or (if ( *(unsigned __int16 *)(a2 + v10 + 4) != 0x8664 )) Goin thru IMAGE_FILE_HEADER structure and looking for IMAGE_FILE_MACHINE_AMD64 . Those checks are part of Reflective DLL Injections not Raw Process Injections.
	Also In Reflective DLL Injection You should see some pattern such as this :
	v75[0] = LoadLibraryA;
	v75[1] = GetProcAddress; 
	v75[2] = RtlAddFunctionTable; 
	v75[3] = v82; //Base address of the new allocated memory 
	A dll that gets manually copied into memory cant solve its own dependencies(such as IAT(Import Address Table)) because its not registered from windows yet.
	For example if that dll has a MessageBoxA call inside itself , that dll is in the need of finding that Function's address itself by calculating its offset.









