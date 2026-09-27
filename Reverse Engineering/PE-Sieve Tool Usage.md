basic unpacking dump : .\pe-sieve64.exe /pid 5204 /dmode 3 /imp 5 /refl

comprehensive dump(data + shellcode) : \.pe-sieve64.exe /pid <PID> /dmode 3 /imp 5 /data 3 /shellc 3 

Malware triage(Json output,full) :  pe-sieve64.exe /pid <PID> /dmode 3 /imp 5 /data 3 /shellc 3 /threads /json /dir dumps

Anti-analysis packer(reflection) :  pe-sieve64.exe /pid <PID> /refl /dmode 3 /imp 5

/dmp 0-4 --> Dump mode :

0 -> mod:virtual -> copies the memory rawly -> Used very rarely
1-> mod:unmapped -> reverts sections to the disc format back -> classic dump for classic packers
2-> realigned -> Section realigment -> For corrupted section structures
3-> force realign -> Realigns everything forcedly + fix -> MOST COMMON option for unpacking
4-> auto -> tries every one and chooses the best one -> Use this when you are not sure.

/imp 0-5 -> import table recovery

0-> mod:none -> Dont touch to IAT
1-> mod:auto(default) -> basic scanning - only catches basic IAT
2-> mod:unerase -> Rewrite deleted IAT entries again(if exists of course).
3-> mod:rebuild -> Build IAT from scratch - heuristic scanning
4-> mod:rebuild + unerase -> Do either -> Rebuild IAT From scratch and also recover the deleted entries.
5-> mod : rebuild + unerase + adjust -> Do every of the work above + address alignments , fixes -> BEST RESULT , MOST AGGRESSIVE  Option but at the same time Slowest option

/data 0-3 --> Data section-scan

Scans/dumps non-executable pages -> This data section-scan feature scans the embedded PE sections and suspicious data.
0 -> mod:none -> Look only to the executable section
1-> mod : if suspicious -> If it looks suspicious then scan it
2-> mod : always(non-.NET) -> Scans all data sections (.NET is not included)
3-> mod : all with headers -> Scan all data and PE Headers. MOST COMPREHENSIVE OPTION
 
 /shellc <0-3> — Shellcode detection

0-> mode:patterns
2-> mode :stats
3-> mode : both

use this as /shellc 3 at malware analysis every time.

/iat 0-2 IAT-Hook Detection

0-> mode:none
1->mode:standart
2->mode:full

/obfusc 0-3 -> obfuscated content detection(entropy-based)
0-> mod:none
1->mode:strong
2-> mode:weak
3-> mode: full

/refl -> Process reflection -> Use this one on the anti-analysis processes. Get the clone of the process and scan that one not the original one for stealthy.

Injecting Anti-Debugger Hider with scyllahide:

.\InjectorCLIx64.exe C:\path\to\crackme  C:\path\to\HookLibrary_of_scyllahide\HookLibraryx64.dll

Unpacking with upx(Ultimate packer for executables) : upx -d file_name.exe
