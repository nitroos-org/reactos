/*
 * PROJECT:     ReactOS Crypto Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     ChaCha20 block function and keystream (RFC 8439)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Written from the description in RFC 8439 sections 2.1-2.4 (state layout, quarter round, 20 rounds as ten
 * column/diagonal double rounds, the final addition, little-endian serialization). The test vectors of the RFC
 * (sections 2.3.2, 2.4.2 and appendix A.1) are checked by advapi32_apitest RngKnownAnswer and at the start of
 * ksecdd.sys.
 */

#include "chacha20.h"

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    do { \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 8); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 7); \
    } while (0)

static __inline ULONG
LoadLe32(const UCHAR *p)
{
    return (ULONG)p[0] | ((ULONG)p[1] << 8) | ((ULONG)p[2] << 16) | ((ULONG)p[3] << 24);
}

static __inline VOID
StoreLe32(UCHAR *p, ULONG v)
{
    p[0] = (UCHAR)v;
    p[1] = (UCHAR)(v >> 8);
    p[2] = (UCHAR)(v >> 16);
    p[3] = (UCHAR)(v >> 24);
}

static VOID
WipeWords(ULONG *p, ULONG Count)
{
    volatile ULONG *v = p;

    while (Count--)
        *v++ = 0;
}

static VOID
ChaCha20Setup(ULONG State[16], const UCHAR *Key, ULONG Counter, const UCHAR *Nonce)
{
    ULONG i;

    /* "expand 32-byte k" */
    State[0] = 0x61707865;
    State[1] = 0x3320646e;
    State[2] = 0x79622d32;
    State[3] = 0x6b206574;
    for (i = 0; i < 8; i++)
        State[4 + i] = LoadLe32(Key + 4 * i);
    State[12] = Counter;
    State[13] = LoadLe32(Nonce);
    State[14] = LoadLe32(Nonce + 4);
    State[15] = LoadLe32(Nonce + 8);
}

static VOID
ChaCha20Core(const ULONG State[16], UCHAR *Output)
{
    ULONG x[16];
    ULONG i;

    for (i = 0; i < 16; i++)
        x[i] = State[i];

    for (i = 0; i < 10; i++)
    {
        /* column round */
        QUARTERROUND(0, 4, 8, 12);
        QUARTERROUND(1, 5, 9, 13);
        QUARTERROUND(2, 6, 10, 14);
        QUARTERROUND(3, 7, 11, 15);
        /* diagonal round */
        QUARTERROUND(0, 5, 10, 15);
        QUARTERROUND(1, 6, 11, 12);
        QUARTERROUND(2, 7, 8, 13);
        QUARTERROUND(3, 4, 9, 14);
    }

    for (i = 0; i < 16; i++)
        StoreLe32(Output + 4 * i, x[i] + State[i]);

    WipeWords(x, 16);
}

VOID NTAPI
ChaCha20Block(
    const UCHAR *Key,
    ULONG Counter,
    const UCHAR *Nonce,
    UCHAR *Output)
{
    ULONG State[16];

    ChaCha20Setup(State, Key, Counter, Nonce);
    ChaCha20Core(State, Output);
    WipeWords(State, 16);
}

VOID NTAPI
ChaCha20KeyStream(
    const UCHAR *Key,
    ULONG Counter,
    const UCHAR *Nonce,
    UCHAR *Output,
    SIZE_T Length)
{
    ULONG State[16];
    ULONG BlockWords[CHACHA20_BLOCK_SIZE / sizeof(ULONG)];
    UCHAR *Block = (UCHAR *)BlockWords;
    SIZE_T i;

    ChaCha20Setup(State, Key, Counter, Nonce);

    while (Length >= CHACHA20_BLOCK_SIZE)
    {
        ChaCha20Core(State, Output);
        State[12]++;
        Output += CHACHA20_BLOCK_SIZE;
        Length -= CHACHA20_BLOCK_SIZE;
    }

    if (Length)
    {
        ChaCha20Core(State, Block);
        for (i = 0; i < Length; i++)
            Output[i] = Block[i];
        WipeWords(BlockWords, CHACHA20_BLOCK_SIZE / sizeof(ULONG));
    }

    WipeWords(State, 16);
}
