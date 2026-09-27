

Byte lengths for each 'call' command type :

call sub_XXXX --> E8+rel32 -> size : 5 byte
call cs:sub_XXXXX --> FF 15 + disp32 -> size : 6 byte
call [rip+0xADDR] --> FF 15 + disp32 -> size : 6 byte
call rax --> FF D0 -> size : 2 byte
