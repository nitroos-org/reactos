/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Known-answer tests of the primitives of the system random number generator (cryptlib ChaCha20 and
 *              SHA-256, the same sources ksecdd.sys and advapi32.dll are built from)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Vectors: RFC 8439 sections 2.3.2, 2.4.2 and appendix A.1 (ChaCha20); FIPS 180-2 appendix B.1/B.2/B.3 and the
 * empty message (SHA-256).
 */

#include "precomp.h"

#include <chacha20.h>
#include <sha256.h>

static BOOL
HexToBytes(const char *Hex, UCHAR *Out, SIZE_T Length)
{
    SIZE_T i;
    unsigned int v;

    for (i = 0; i < Length; i++)
    {
        if (sscanf(Hex + 2 * i, "%2x", &v) != 1)
            return FALSE;
        Out[i] = (UCHAR)v;
    }
    return Hex[2 * Length] == 0;
}

static void
CheckBytes(const UCHAR *Actual, const char *ExpectedHex, SIZE_T Length, const char *What)
{
    UCHAR Expected[256];

    ok(Length <= sizeof(Expected) && HexToBytes(ExpectedHex, Expected, Length), "%s: bad vector\n", What);
    ok(!memcmp(Actual, Expected, Length), "%s: output differs from the published value\n", What);
}

typedef struct
{
    const char *Name;
    const char *Key;
    ULONG Counter;
    const char *Nonce;
    const char *Block;
} CHACHA_VECTOR;

static const CHACHA_VECTOR BlockVectors[] =
{
    { "RFC 8439 2.3.2",
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1, "000000090000004a00000000",
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
      "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e" },
    { "RFC 8439 A.1 #1",
      "0000000000000000000000000000000000000000000000000000000000000000", 0, "000000000000000000000000",
      "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
      "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586" },
    { "RFC 8439 A.1 #2",
      "0000000000000000000000000000000000000000000000000000000000000000", 1, "000000000000000000000000",
      "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
      "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f" },
    { "RFC 8439 A.1 #3",
      "0000000000000000000000000000000000000000000000000000000000000001", 1, "000000000000000000000000",
      "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
      "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0" },
    { "RFC 8439 A.1 #4",
      "00ff000000000000000000000000000000000000000000000000000000000000", 2, "000000000000000000000000",
      "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
      "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096" },
    { "RFC 8439 A.1 #5",
      "0000000000000000000000000000000000000000000000000000000000000000", 0, "000000000000000000000002",
      "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
      "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d" },
};

static void
TestChaCha20(void)
{
    static const char Plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would "
        "be it.";
    static const char Ciphertext[] =
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d";
    UCHAR Key[CHACHA20_KEY_SIZE], Nonce[CHACHA20_NONCE_SIZE], Out[256], Ref[256];
    SIZE_T i, n;

    for (i = 0; i < ARRAYSIZE(BlockVectors); i++)
    {
        HexToBytes(BlockVectors[i].Key, Key, sizeof(Key));
        HexToBytes(BlockVectors[i].Nonce, Nonce, sizeof(Nonce));
        ChaCha20Block(Key, BlockVectors[i].Counter, Nonce, Out);
        CheckBytes(Out, BlockVectors[i].Block, CHACHA20_BLOCK_SIZE, BlockVectors[i].Name);
        /* the keystream function gives the same block */
        memset(Out, 0xcc, sizeof(Out));
        ChaCha20KeyStream(Key, BlockVectors[i].Counter, Nonce, Out, CHACHA20_BLOCK_SIZE);
        CheckBytes(Out, BlockVectors[i].Block, CHACHA20_BLOCK_SIZE, BlockVectors[i].Name);
        ok(Out[CHACHA20_BLOCK_SIZE] == 0xcc, "%s: keystream wrote past its length\n", BlockVectors[i].Name);
    }

    /* RFC 8439 2.4.2: the keystream from counter 1, XORed with the plaintext */
    HexToBytes(BlockVectors[0].Key, Key, sizeof(Key));
    HexToBytes("000000000000004a00000000", Nonce, sizeof(Nonce));
    n = strlen(Plaintext);
    ok(n == 114, "plaintext length %Iu\n", n);
    ChaCha20KeyStream(Key, 1, Nonce, Out, n);
    for (i = 0; i < n; i++)
        Out[i] ^= (UCHAR)Plaintext[i];
    CheckBytes(Out, Ciphertext, n, "RFC 8439 2.4.2");

    /* every length up to four blocks: a prefix of the long keystream, nothing written behind it */
    ChaCha20KeyStream(Key, 7, Nonce, Ref, sizeof(Ref));
    for (n = 0; n <= sizeof(Ref) - 1; n++)
    {
        memset(Out, 0x5a, sizeof(Out));
        ChaCha20KeyStream(Key, 7, Nonce, Out, n);
        if (memcmp(Out, Ref, n) || Out[n] != 0x5a)
        {
            ok(0, "keystream of %Iu bytes is not the prefix of the long one\n", n);
            break;
        }
    }
}

static void
CheckSha256(const void *Data, SIZE_T Length, SIZE_T Piece, const char *Expected, const char *What)
{
    CRYPTLIB_SHA256_CTX Context;
    UCHAR Digest[SHA256_DIGEST_SIZE];
    const UCHAR *p = Data;
    SIZE_T Done, Step;

    Sha256Init(&Context);
    for (Done = 0; Done < Length; Done += Step)
    {
        Step = min(Piece, Length - Done);
        Sha256Update(&Context, p + Done, Step);
    }
    Sha256Final(&Context, Digest);
    CheckBytes(Digest, Expected, sizeof(Digest), What);
}

static void
TestSha256(void)
{
    static const char Two[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const SIZE_T Pieces[] = { 1, 3, 55, 56, 63, 64, 65, 1000000 };
    PUCHAR Million;
    SIZE_T i;

    CheckSha256("", 0, 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty");
    CheckSha256("abc", 3, 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 B.1");
    for (i = 0; i < ARRAYSIZE(Pieces); i++)
    {
        CheckSha256(Two, strlen(Two), Pieces[i],
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256 B.2");
    }

    Million = HeapAlloc(GetProcessHeap(), 0, 1000000);
    ok(Million != NULL, "no memory\n");
    if (!Million)
        return;
    memset(Million, 'a', 1000000);
    for (i = 0; i < ARRAYSIZE(Pieces); i++)
    {
        CheckSha256(Million, 1000000, Pieces[i],
                    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 B.3");
    }
    HeapFree(GetProcessHeap(), 0, Million);
}

START_TEST(RngKnownAnswer)
{
    TestChaCha20();
    TestSha256();
}
