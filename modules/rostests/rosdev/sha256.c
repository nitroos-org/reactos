/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     sha256
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * PROJECT:     ReactOS test infrastructure
 * PURPOSE:     rosdev: SHA-256 (FIPS 180-4), HMAC-SHA-256 and hex helpers
 */
#include "rosdev.h"

static const UINT32 K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void Block(SHA256_STATE *s, const BYTE *p)
{
    UINT32 w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((UINT32)p[4*i] << 24) | ((UINT32)p[4*i+1] << 16) | ((UINT32)p[4*i+2] << 8) | p[4*i+3];
    for (i = 16; i < 64; i++)
    {
        UINT32 s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        UINT32 s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++)
    {
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void Sha256Init(SHA256_STATE *s)
{
    static const UINT32 iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(s->h, iv, sizeof(iv));
    s->bits = 0;
    s->used = 0;
}

void Sha256Update(SHA256_STATE *s, const void *data, SIZE_T n)
{
    const BYTE *p = data;

    s->bits += (UINT64)n * 8;
    while (n)
    {
        SIZE_T take = 64 - s->used;
        if (take > n) take = n;
        memcpy(s->buf + s->used, p, take);
        s->used += (UINT)take; p += take; n -= take;
        if (s->used == 64) { Block(s, s->buf); s->used = 0; }
    }
}

void Sha256Final(SHA256_STATE *s, BYTE out[32])
{
    UINT64 bits = s->bits;
    BYTE pad[72] = { 0x80 };
    BYTE len[8];
    int i, padlen = (s->used < 56) ? (56 - s->used) : (120 - s->used);

    for (i = 0; i < 8; i++) len[i] = (BYTE)(bits >> (56 - 8 * i));
    Sha256Update(s, pad, padlen);
    Sha256Update(s, len, 8);
    for (i = 0; i < 8; i++)
    {
        out[4*i] = (BYTE)(s->h[i] >> 24); out[4*i+1] = (BYTE)(s->h[i] >> 16);
        out[4*i+2] = (BYTE)(s->h[i] >> 8); out[4*i+3] = (BYTE)s->h[i];
    }
}

void HmacSha256(const BYTE *key, SIZE_T klen, const BYTE *msg, SIZE_T mlen, BYTE out[32])
{
    BYTE k[64] = { 0 }, ipad[64], opad[64], inner[32];
    SHA256_STATE s;
    int i;

    if (klen > 64) { Sha256Init(&s); Sha256Update(&s, key, klen); Sha256Final(&s, k); }
    else memcpy(k, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    Sha256Init(&s); Sha256Update(&s, ipad, 64); Sha256Update(&s, msg, mlen); Sha256Final(&s, inner);
    Sha256Init(&s); Sha256Update(&s, opad, 64); Sha256Update(&s, inner, 32); Sha256Final(&s, out);
}

void HexEncode(const BYTE *p, SIZE_T n, char *out)
{
    static const char d[] = "0123456789abcdef";
    SIZE_T i;
    for (i = 0; i < n; i++) { out[2*i] = d[p[i] >> 4]; out[2*i+1] = d[p[i] & 15]; }
    out[2*n] = 0;
}

static int Nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int HexDecode(const char *in, BYTE *out, SIZE_T max)
{
    SIZE_T n = 0;
    while (in[0] && in[1])
    {
        int hi = Nib(in[0]), lo = Nib(in[1]);
        if (hi < 0 || lo < 0 || n >= max) return -1;
        out[n++] = (BYTE)(hi << 4 | lo);
        in += 2;
    }
    return in[0] ? -1 : (int)n;
}
