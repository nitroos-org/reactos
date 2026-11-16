/*
 * PROJECT:     ReactOS Crypto Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     SHA-256 (FIPS 180-4)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Written from FIPS 180-4: functions Ch, Maj, Sigma0/1, sigma0/1 (section 4.1.2), the constants K (4.2.2) and
 * the initial hash value (5.3.3), padding (5.1.1) and the computation (6.2.2). The constants were computed from
 * their definition (fractional parts of the cube and square roots of the first primes), not copied. Checked
 * against the FIPS 180-2 appendix B examples by advapi32_apitest RngKnownAnswer and at the start of ksecdd.sys.
 */

#include "sha256.h"
#include <string.h>

#define ROTR32(v, n) (((v) >> (n)) | ((v) << (32 - (n))))

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)     (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x)     (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x)     (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SSIG1(x)     (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const ULONG Sha256K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static VOID
Wipe(VOID *p, SIZE_T Length)
{
    volatile UCHAR *v = p;

    while (Length--)
        *v++ = 0;
}

static VOID
Sha256Transform(ULONG State[8], const UCHAR *Block)
{
    ULONG W[64];
    ULONG a, b, c, d, e, f, g, h, T1, T2;
    ULONG t;

    for (t = 0; t < 16; t++)
    {
        W[t] = ((ULONG)Block[4 * t] << 24) | ((ULONG)Block[4 * t + 1] << 16) |
               ((ULONG)Block[4 * t + 2] << 8) | (ULONG)Block[4 * t + 3];
    }
    for (t = 16; t < 64; t++)
        W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];

    a = State[0]; b = State[1]; c = State[2]; d = State[3];
    e = State[4]; f = State[5]; g = State[6]; h = State[7];

    for (t = 0; t < 64; t++)
    {
        T1 = h + BSIG1(e) + CH(e, f, g) + Sha256K[t] + W[t];
        T2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    State[0] += a; State[1] += b; State[2] += c; State[3] += d;
    State[4] += e; State[5] += f; State[6] += g; State[7] += h;

    Wipe(W, sizeof(W));
}

VOID NTAPI
Sha256Init(PCRYPTLIB_SHA256_CTX Context)
{
    Context->State[0] = 0x6a09e667;
    Context->State[1] = 0xbb67ae85;
    Context->State[2] = 0x3c6ef372;
    Context->State[3] = 0xa54ff53a;
    Context->State[4] = 0x510e527f;
    Context->State[5] = 0x9b05688c;
    Context->State[6] = 0x1f83d9ab;
    Context->State[7] = 0x5be0cd19;
    Context->Length = 0;
    Context->Used = 0;
}

VOID NTAPI
Sha256Update(PCRYPTLIB_SHA256_CTX Context, const VOID *Data, SIZE_T Length)
{
    const UCHAR *p = Data;
    ULONG n;

    Context->Length += Length;

    if (Context->Used)
    {
        n = SHA256_BLOCK_SIZE - Context->Used;
        if (n > Length)
            n = (ULONG)Length;
        memcpy(Context->Buffer + Context->Used, p, n);
        Context->Used += n;
        p += n;
        Length -= n;
        if (Context->Used < SHA256_BLOCK_SIZE)
            return;
        Sha256Transform(Context->State, Context->Buffer);
        Context->Used = 0;
    }

    while (Length >= SHA256_BLOCK_SIZE)
    {
        Sha256Transform(Context->State, p);
        p += SHA256_BLOCK_SIZE;
        Length -= SHA256_BLOCK_SIZE;
    }

    if (Length)
    {
        memcpy(Context->Buffer, p, Length);
        Context->Used = (ULONG)Length;
    }
}

VOID NTAPI
Sha256Final(PCRYPTLIB_SHA256_CTX Context, UCHAR *Digest)
{
    ULONGLONG Bits = Context->Length * 8;
    ULONG i;

    /* 1 bit, zeros up to 56 bytes modulo 64, then the length in bits, big-endian */
    Context->Buffer[Context->Used++] = 0x80;
    if (Context->Used > SHA256_BLOCK_SIZE - 8)
    {
        memset(Context->Buffer + Context->Used, 0, SHA256_BLOCK_SIZE - Context->Used);
        Sha256Transform(Context->State, Context->Buffer);
        Context->Used = 0;
    }
    memset(Context->Buffer + Context->Used, 0, SHA256_BLOCK_SIZE - 8 - Context->Used);
    for (i = 0; i < 8; i++)
        Context->Buffer[SHA256_BLOCK_SIZE - 1 - i] = (UCHAR)(Bits >> (8 * i));
    Sha256Transform(Context->State, Context->Buffer);

    for (i = 0; i < 8; i++)
    {
        Digest[4 * i] = (UCHAR)(Context->State[i] >> 24);
        Digest[4 * i + 1] = (UCHAR)(Context->State[i] >> 16);
        Digest[4 * i + 2] = (UCHAR)(Context->State[i] >> 8);
        Digest[4 * i + 3] = (UCHAR)Context->State[i];
    }

    Wipe(Context, sizeof(*Context));
}
