
This libbrary implements the following algorithms:

MD4
---
- files: md4.c, md4.h
- Implements: MD4Init, MD4Update, MD4Final

MD5
---
- files: md5.c, md5.h
- Implements: MD5Init, MD5Update, MD5Final

RC4
---
- files: rc4.c, rc4.h
- Implements: rc4_init, rc4_crypt

SHA1
----
- files: sha1.c, sha1.h
- Implements: A_SHAInit, A_SHAUpdate, A_SHAFinal

SHA-256
-------
- files: sha256.c, sha256.h
- Written from FIPS 180-4; the constants computed from their definition
- Implements: Sha256Init, Sha256Update, Sha256Final

ChaCha20
--------
- files: chacha20.c, chacha20.h
- Written from RFC 8439 (block function and keystream; no Poly1305)
- Implements: ChaCha20Block, ChaCha20KeyStream

AES
---
- files: mvAesAlg.c, mvAesAlg.h, mvOs.h, mvAesBoxes.dat
- Taken from: http://enduser.subsignal.org/~trondah/tree/target/linux/generic/files/crypto/ocf/kirkwood/cesa/AES/
- Original reference implementation: https://github.com/briandfoy/crypt-rijndael/tree/master/rijndael-vals/reference%20implementation
- Implements: rijndaelEncrypt128, rijndaelDecrypt128
