
SHA-256 ROR4 Constants --> 17,19,7,18 If those are combined with XORed __ROR4__'s that algorithm is probably SHA-256

 # FNV
  fnv-1/1a 32 prime         --> 0x01000193
  fnv-1/1a 32 offset        --> 0x811C9DC5
  fnv-1/1a 64 prime         --> 0x00000100000001B3
  fnv-1/1a 64 offset        --> 0xCBF29CE484222325

  # CRC
  crc32 poly                --> 0x04C11DB7
  crc32 poly (reversed)     --> 0xEDB88320
  crc32c poly (reversed)    --> 0x82F63B78
  crc16-ccitt poly          --> 0x1021
  crc16-ibm poly (reversed) --> 0xA001
  crc64-ecma poly           --> 0x42F0E1EBA9EA3693
  crc64-iso poly            --> 0x000000000000001B

  # MD5
  md5 init A/B/C/D          --> 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476
  md5 first T const         --> 0xD76AA478

  # SHA-1
  sha1 init                 --> 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0

  # SHA-256
  sha256 init               --> 0x6A09E667 0xBB67AE85 0x3C6EF372 0xA54FF53A 0x510E527F 0x9B05688C 0x1F83D9AB 0x5BE0CD19
  sha256 K[0]               --> 0x428A2F98

  # SHA-512
  sha512 init[0]            --> 0x6A09E667F3BCC908
  sha512 K[0]               --> 0x428A2F98D728AE22

  # Golden ratio / mixers
  golden ratio 32           --> 0x9E3779B9
  golden ratio 64           --> 0x9E3779B97F4A7C15
  golden ratio neg 32       --> 0x61C88647
  golden ratio neg 64       --> 0x61C8864680B583EB
  tea/xtea delta            --> 0x9E3779B9
  splitmix64 mix            --> 0xBF58476D1CE4E5B9 0x94D049BB133111EB
  murmur3 fmix64            --> 0xFF51AFD7ED558CCD 0xC4CEB9FE1A85EC53

  # MurmurHash
  murmur2 m                 --> 0x5BD1E995
  murmur3 x86_32 c1/c2      --> 0xCC9E2D51 0x1B873593
  murmur3 x64_128 c1/c2     --> 0x87C37B91114253D5 0x4CF5AD432745937F

  # xxHash
  xxh32 primes              --> 0x9E3779B1 0x85EBCA77 0xC2B2AE3D 0x27D4EB2F 0x165667B1
  xxh64 primes              --> 0x9E3779B185EBCA87 0xC2B2AE3D27D4EB4F 0x165667B19E3779F9 0x85EBCA77C2B2AE63
  0x27D4EB2F165667C5

  # Simple string hashes
  djb2 init / mult          --> 5381 / 33
  sdbm mult                 --> 65599
  adler32 mod               --> 65521 , 0xFFF1 , 0x15B0

  # PRNG
  glibc rand LCG mult/inc   --> 0x41C64E6D / 12345
  msvc rand LCG mult/inc    --> 0x00343FD / 0x269EC3
  mt19937 matrix a          --> 0x9908B0DF
  mt19937 init mult         --> 0x6C078965
  mt19937 temper masks      --> 0x9D2C5680 0xEFC60000
  pcg mult                  --> 0x5851F42D4C957F2D

  # Ciphers
  aes sbox[0]               --> 0x63
  aes gf poly               --> 0x11B
  chacha/salsa20 sigma      --> 0x61707865 0x3320646E 0x79622D32 0x6B206574
  base64 alphabet           --> ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

 # SipHash (keyed PRF / MAC) — IV spells ASCII "somepseudorandomlygeneratedbytes"
  siphash v0 const  --> 0x736F6D6570736575   ("somepseu")
  siphash v1 const  --> 0x646F72616E646F6D   ("dorandom")
  siphash v2 const  --> 0x6C7967656E657261   ("lygenera")
  siphash v3 const  --> 0x7465646279746573   ("tedbytes")

 # RC5 / RC6 key schedule (w=32)
  rc5/rc6 P32 --> 0xB7E15163   (Odd((e-2)*2^32))
  rc5/rc6 Q32 --> 0x9E3779B9   (golden ratio; = TEA delta too -> disambiguate by P)


MD5 recognition pattern

  Every MD5 (and SHA) implementation follows the same three-call skeleton: Init → Update → Final. Your three functions
  map exactly onto it:

  MD5 = Init -> Update -> Final  (call it as a black box; don't trace the internals)

  1. Init  (md5_hash_initializator):
       ctx state = A=0x67452301  B=0xEFCDAB89  C=0x98BADCFE  D=0x10325476
       -> seeing these 4 constants = "this is MD5"
  2. Update (md5_hash_updater_func):  Update(data, len)
       buffers input, processes 64-byte blocks; 64 sine T-constants (0xD76AA478...),
       4 rounds (F/G/H/I), rotations.  Intentionally a mess - RECOGNIZE, don't read.
  3. Final (sub_100018A0):
       pad (append 0x80, zero-fill, append 64-bit bit-length), process last block,
       write the 16-byte digest.
  Digest = 16 bytes (128-bit).

  Same skeleton, different sizes:
    SHA-1   : 5 IVs (…+0xC3D2E1F0), 20-byte digest
    SHA-256 : 8 IVs (0x6A09E667…),  32-byte digest

Distinguishing RC5 and RC6 hashes between each other :

 - RC6 has a mul/imul — the quadratic t = B·(2B+1), which shows up in asm as something like lea eax, [ebx+ebx+1]
   (that's 2B+1) followed by a multiply, plus a fixed rotate by 5 (rol ..., 5).
  - RC5 has NO multiply — only data-dependent rotates (rol/ror by a variable count in cl), XOR, and add.

Hash Pattern --> Init -> Update -> Final Processes

CIPHER Pattern --> KeySchedule -> RoundFunction -> BlockLoop


- Symmetric (AES): one key encrypts and decrypts. Fast — a modern CPU does gigabytes/sec. Problem: how do you share
  that one key without someone stealing it in transit?
  - Asymmetric / public-key (RSA): two keys, mathematically linked. What one encrypts, only the other decrypts. You
  publish the public key freely; you hoard the private key. Solves the sharing problem. Cost: ~1000× slower than AES and
  only useful on small data (a few hundred bytes at a time).

AES -> A block cipher : encrypts in fixed 16-byte chunks. Key size = 128/192/256 bits. And its also deterministic.
Same plaintext + same key -> same ciphertext.

It has 2 modes :

ECB: encrypts each 16-byte block independently. Leaks pattern. Never used.If its ever used its a vulnerability.

CBC:each block gets xored with the previous ciphertext before encryption so that kills the pattern leaking problem. But this needs an some kind of salt we call this Initialization Vector(IV).

IV(Initialization Vector): 16 random bytes that seed CBC. IV is not secret. It can be published publicly. Its not leaking something by just only itself.


 PKCS7 padding — AES only works on multiples of 16 bytes. If your file is 1000 bytes, you need 24 more to reach 1008.PKCS7 says: fill those N missing bytes with the byte value N. So 5 missing bytes → append 05 05 05 05 05. On decrypt you read the last byte, strip that many, done. A file already a multiple of 16 gets a full 16-byte pad (10 10 …) so there's always something to strip. It's just the "how do we know where the real data ends?" convention — a formatting rule, not crypto.
