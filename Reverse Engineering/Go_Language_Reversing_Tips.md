

Main func chain:
_rt_0_amd64_windows->runtime.rt0_go->runtime.newosproc / runtime.mstart -> runtime.main -> main.init -> main.main

Go Calling Convention(x64):
RAX-RBX-RCX-RDX-RSI-R8-R9-R10-R11

Some Function Patterns:

stringtoslicebyte(result,string_data,string_len); -> Converts Go string to bytes.

encoding_base64__ptr_Encoding_EncodeToString(byte_array); -> Encodes byte_array with Base64.

strings.Replace(source(can be 2 params) , old_string,New,N) -> N=-1 -> change every one of them , New: 0,0 -> means " " empty string 

concatstring2(buf,v_X,v_Y,v_Z,v_T) --> Here V_X and V_Y is the first string( data + len sequentially) and the v_Z and v_T is the second string(data + len sequentially again) 
concatstring2 merges two strings e.g. concatstring2("user\\crackme.exe", "QzpcVXNlcnNcdXNlclxjcmFja21lLmV4ZQ=") gives us  "user\\crackme.exeQzpcVXNlcnNcdXNlclxjcmFja21lLmV4ZQ="

func FscanLn(r io.Reader, a ...interface{}) (n int, err error) --> Reads from io.Reader line by line and writes into a.

String in Go :
type string struct {
    str *byte    // _r0 (string data ptr)
    len int      // _r1 (length of string)
}

[]byte in Go :
type slice struct {
    data *byte    // _r0 (byte ptr to the first byte)
    len  int      // _r1 (length of array)
    cap  int      // _r2 (Capacity)
}
