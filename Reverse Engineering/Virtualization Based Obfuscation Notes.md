
PC(Program Counter): Shows the next command's address.[Current Position]
It ussually gets incremented as the opcodes process such as v_X++;

Opcode: The type of command like Sum - sub - write - stop etc.
It ussualy used as switch(Opcode) { ...

ByteCode: Runs the VM. for example its showed as random bytes at disc such as : 

[0x01] [0x05] [0x03] [0x00]
  ^
  PC = 0
