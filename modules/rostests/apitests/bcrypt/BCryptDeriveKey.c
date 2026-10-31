/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for BCryptDeriveKey over an ECDH secret: every KDF, its parameters and its status codes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (x64 and x86, identical). Each case is called twice,
 * once with a NULL output buffer (the size query) and once with an output buffer prefilled with 0xAA.
 */

#if defined(WINREF_PROBE) || defined(WINREF_CHECK)
/* Standalone build for the reference system (WINREF_PROBE prints the table of expected values instead of checking it) */
#define WIN32_NO_STATUS
#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
static int g_Failures;
#define ok(cond, ...) do { if (!(cond)) { g_Failures++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); } } while (0)
#define skip(...) printf(__VA_ARGS__)
#define START_TEST(x) void func_##x(void)
#else
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <bcrypt.h>
#endif

#ifndef KDF_SALT
#define KDF_SALT 0x0f
#endif
#ifndef KDF_PARTYVINFO
#define KDF_PARTYVINFO 0x0a
#define KDF_SUPPPRIVINFO 0x0c
#endif
#define KDF_USE_SECRET_AS_HMAC_KEY 0x1
#define BUFFERS_LOCKED 0x40

#define NO_DESC 0xFFFFFFFF

typedef struct
{
    ULONG Type;
    const void *Data;
    ULONG Size;
} BUF;

typedef struct
{
    const char *Name;
    int Secret;             /* 0: ECDH P-256, 1: ECDH P-384, 2: ECDH P-521 */
    const WCHAR *Kdf;
    ULONG Flags;
    ULONG Count;            /* NO_DESC: pass a NULL descriptor */
    BUF Buf[8];
    ULONG OutLen;
    ULONG Ver;              /* descriptor version: 0 is BCRYPTBUFFER_VERSION, VER0 is 0 */
} CASE;
#define VER0 0x100

typedef struct
{
    ULONG Status1;          /* size query */
    ULONG Len1;
    ULONG Status2;          /* real call */
    ULONG Len2;
    ULONG Touched;          /* bytes of the output the call changed, when it failed */
    const char *Hex;        /* output on success */
} EXPECTED;

#define WS(s) s, sizeof(s)
static const WCHAR wSHA1[] = L"SHA1", wSHA256[] = L"SHA256", wSHA384[] = L"SHA384", wSHA512[] = L"SHA512";
static const WCHAR wMD2[] = L"MD2", wMD4[] = L"MD4", wMD5[] = L"MD5", wFOO[] = L"FOO", wEMPTY[] = L"";
static const UCHAR Pre1[] = { 0xA1, 0xA2, 0xA3 }, Pre2[] = { 0xA4, 0xA5 };
static const UCHAR App1[] = { 0xB1, 0xB2 }, App2[] = { 0xB3, 0xB4, 0xB5 };
static const UCHAR HKey[] = { 'k', 'e', 'y', '-', '0', '1', '2', '3', '4', '5' };
static UCHAR BigKey[200], Seed2[128];
static const UCHAR Label[] = "master secret";
static const UCHAR Seed[64] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static const ULONG Tls10 = 0x0301, Tls11 = 0x0302, Tls12 = 0x0303, TlsBad0 = 0x0300, TlsBad4 = 0x0304, TlsZero = 0, TlsFFFF = 0xFFFF;
static const UCHAR AlgId[] = "algid", PartyU[] = "partyU", PartyV[] = "partyV", PubInfo[] = "pub", PrivInfo[] = "priv";

#define HASH(w)   { KDF_HASH_ALGORITHM, w, sizeof(w) }
#define PRE1      { KDF_SECRET_PREPEND, Pre1, sizeof(Pre1) }
#define PRE2      { KDF_SECRET_PREPEND, Pre2, sizeof(Pre2) }
#define APP1      { KDF_SECRET_APPEND, App1, sizeof(App1) }
#define APP2      { KDF_SECRET_APPEND, App2, sizeof(App2) }
#define HMKEY     { KDF_HMAC_KEY, HKey, sizeof(HKey) }
#define LABEL     { KDF_TLS_PRF_LABEL, Label, sizeof(Label) - 1 }
#define SEED      { KDF_TLS_PRF_SEED, Seed, sizeof(Seed) }
#define CAL { KDF_ALGORITHMID, AlgId, 5 }
#define CPU { KDF_PARTYUINFO, PartyU, 6 }
#define CPV { KDF_PARTYVINFO, PartyV, 6 }
#define CPB { KDF_SUPPPUBINFO, PubInfo, 3 }
#define CPR { KDF_SUPPPRIVINFO, PrivInfo, 4 }
#define PROTO(p)  { KDF_TLS_PRF_PROTOCOL, &p, sizeof(ULONG) }

#define H BCRYPT_KDF_HASH
#define M BCRYPT_KDF_HMAC
#define T BCRYPT_KDF_TLS_PRF
#define C BCRYPT_KDF_SP80056A_CONCAT
#define R BCRYPT_KDF_RAW_SECRET

static const CASE Cases[] =
{
    /* KDF_HASH */
    { "hash nodesc",            0, H, 0, NO_DESC, {{0}}, 64 },
    { "hash emptydesc",         0, H, 0, 0, {{0}}, 64 },
    { "hash sha1",              0, H, 0, 1, { HASH(wSHA1) }, 64 },
    { "hash sha256",            0, H, 0, 1, { HASH(wSHA256) }, 64 },
    { "hash sha384",            0, H, 0, 1, { HASH(wSHA384) }, 64 },
    { "hash sha512",            0, H, 0, 1, { HASH(wSHA512) }, 64 },
    { "hash md5",               0, H, 0, 1, { HASH(wMD5) }, 64 },
    { "hash md4",               0, H, 0, 1, { HASH(wMD4) }, 64 },
    { "hash md2",               0, H, 0, 1, { HASH(wMD2) }, 64 },
    { "hash foo",               0, H, 0, 1, { HASH(wFOO) }, 64 },
    { "hash emptyname",         0, H, 0, 1, { HASH(wEMPTY) }, 64 },
    { "hash sha256 nonul",      0, H, 0, 1, { { KDF_HASH_ALGORITHM, wSHA256, sizeof(wSHA256) - 2 } }, 64 },
    { "hash sha256 pre",        0, H, 0, 2, { HASH(wSHA256), PRE1 }, 64 },
    { "hash sha256 app",        0, H, 0, 2, { HASH(wSHA256), APP1 }, 64 },
    { "hash sha256 pre+app",    0, H, 0, 3, { HASH(wSHA256), PRE1, APP1 }, 64 },
    { "hash sha256 app+pre",    0, H, 0, 3, { HASH(wSHA256), APP1, PRE1 }, 64 },
    { "hash sha256 pre pre",    0, H, 0, 3, { HASH(wSHA256), PRE1, PRE2 }, 64 },
    { "hash sha256 app app",    0, H, 0, 3, { HASH(wSHA256), APP1, APP2 }, 64 },
    { "hash sha256 pre0",       0, H, 0, 2, { HASH(wSHA256), { KDF_SECRET_PREPEND, Pre1, 0 } }, 64 },
    { "hash sha1 pre only",     0, H, 0, 1, { PRE1 }, 64 },
    { "hash sha256 hmackey",    0, H, 0, 2, { HASH(wSHA256), HMKEY }, 64 },
    { "hash hmackey only",      0, H, 0, 1, { HMKEY }, 64 },
    { "hash sha256 out16",      0, H, 0, 1, { HASH(wSHA256) }, 16 },
    { "hash sha256 out0",       0, H, 0, 1, { HASH(wSHA256) }, 0 },
    { "hash sha256 out31",      0, H, 0, 1, { HASH(wSHA256) }, 31 },
    { "hash sha256 out32",      0, H, 0, 1, { HASH(wSHA256) }, 32 },
    { "hash sha256 out33",      0, H, 0, 1, { HASH(wSHA256) }, 33 },
    { "hash sha256 flag1",      0, H, KDF_USE_SECRET_AS_HMAC_KEY, 1, { HASH(wSHA256) }, 64 },
    { "hash sha256 flag40",     0, H, BUFFERS_LOCKED, 1, { HASH(wSHA256) }, 64 },
    { "hash sha256 flag2",      0, H, 2, 1, { HASH(wSHA256) }, 64 },
    { "hash sha256 flag80",     0, H, 0x80000000, 1, { HASH(wSHA256) }, 64 },
    { "hash sha256 salt",       0, H, 0, 2, { HASH(wSHA256), { KDF_SALT, Seed, 8 } }, 64 },
    { "hash sha256 label",      0, H, 0, 2, { HASH(wSHA256), LABEL }, 64 },
    { "hash sha256 type7777",   0, H, 0, 2, { HASH(wSHA256), { 0x7777, Seed, 8 } }, 64 },
    { "hash sha256 twohash",    0, H, 0, 2, { HASH(wSHA256), HASH(wSHA384) }, 64 },
    { "hash p384 sha256 pre",   1, H, 0, 2, { HASH(wSHA256), PRE1 }, 64 },
    { "hash p384 sha384",       1, H, 0, 1, { HASH(wSHA384) }, 64 },
    { "hash p384 nodesc",       1, H, 0, NO_DESC, {{0}}, 64 },

    { "hash sha256 twohash rev",0, H, 0, 2, { HASH(wSHA384), HASH(wSHA256) }, 64 },
    { "hash sha256 ver0",       0, H, 0, 1, { HASH(wSHA256) }, 64, VER0 },
    { "hash sha256 ver2",       0, H, 0, 1, { HASH(wSHA256) }, 64, 2 },
    { "hash sha256 pre null0",  0, H, 0, 2, { HASH(wSHA256), { KDF_SECRET_PREPEND, NULL, 0 } }, 64 },
    { "hash md5 pre app",       0, H, 0, 3, { HASH(wMD5), PRE1, APP1 }, 64 },
    { "hash sha512 pre pre app",0, H, 0, 4, { HASH(wSHA512), PRE1, PRE2, APP1 }, 64 },
    { "hash p384 sha1",         1, H, 0, 1, { HASH(wSHA1) }, 64 },

    /* KDF_HMAC */
    { "hmac nodesc",            0, M, 0, NO_DESC, {{0}}, 64 },
    { "hmac sha1 key",          0, M, 0, 2, { HASH(wSHA1), HMKEY }, 64 },
    { "hmac sha256 key",        0, M, 0, 2, { HASH(wSHA256), HMKEY }, 64 },
    { "hmac sha384 key",        0, M, 0, 2, { HASH(wSHA384), HMKEY }, 64 },
    { "hmac sha512 key",        0, M, 0, 2, { HASH(wSHA512), HMKEY }, 64 },
    { "hmac md5 key",           0, M, 0, 2, { HASH(wMD5), HMKEY }, 64 },
    { "hmac md4 key",           0, M, 0, 2, { HASH(wMD4), HMKEY }, 64 },
    { "hmac md2 key",           0, M, 0, 2, { HASH(wMD2), HMKEY }, 64 },
    { "hmac foo key",           0, M, 0, 2, { HASH(wFOO), HMKEY }, 64 },
    { "hmac key only",          0, M, 0, 1, { HMKEY }, 64 },
    { "hmac sha256 nokey",      0, M, 0, 1, { HASH(wSHA256) }, 64 },
    { "hmac sha256 key0",       0, M, 0, 2, { HASH(wSHA256), { KDF_HMAC_KEY, HKey, 0 } }, 64 },
    { "hmac sha256 key pre app",0, M, 0, 4, { HASH(wSHA256), HMKEY, PRE1, APP1 }, 64 },
    { "hmac sha256 key pre",    0, M, 0, 3, { HASH(wSHA256), HMKEY, PRE1 }, 64 },
    { "hmac sha256 key app",    0, M, 0, 3, { HASH(wSHA256), HMKEY, APP1 }, 64 },
    { "hmac sha256 flag1",      0, M, KDF_USE_SECRET_AS_HMAC_KEY, 1, { HASH(wSHA256) }, 64 },
    { "hmac sha256 flag1 key",  0, M, KDF_USE_SECRET_AS_HMAC_KEY, 2, { HASH(wSHA256), HMKEY }, 64 },
    { "hmac sha256 flag1 pre",  0, M, KDF_USE_SECRET_AS_HMAC_KEY, 2, { HASH(wSHA256), PRE1 }, 64 },
    { "hmac sha256 flag1 app",  0, M, KDF_USE_SECRET_AS_HMAC_KEY, 2, { HASH(wSHA256), APP1 }, 64 },
    { "hmac sha1 flag1",        0, M, KDF_USE_SECRET_AS_HMAC_KEY, 1, { HASH(wSHA1) }, 64 },
    { "hmac nohash flag1",      0, M, KDF_USE_SECRET_AS_HMAC_KEY, NO_DESC, {{0}}, 64 },
    { "hmac sha256 key out16",  0, M, 0, 2, { HASH(wSHA256), HMKEY }, 16 },
    { "hmac sha256 key out0",   0, M, 0, 2, { HASH(wSHA256), HMKEY }, 0 },
    { "hmac sha256 key out33",  0, M, 0, 2, { HASH(wSHA256), HMKEY }, 33 },
    { "hmac sha256 key flag40", 0, M, BUFFERS_LOCKED, 2, { HASH(wSHA256), HMKEY }, 64 },
    { "hmac sha256 key flag2",  0, M, 2, 2, { HASH(wSHA256), HMKEY }, 64 },
    { "hmac p384 sha384 key",   1, M, 0, 2, { HASH(wSHA384), HMKEY }, 64 },
    { "hmac p384 sha256 flag1", 1, M, KDF_USE_SECRET_AS_HMAC_KEY, 1, { HASH(wSHA256) }, 64 },
    { "hmac two keys",          0, M, 0, 3, { HASH(wSHA256), HMKEY, { KDF_HMAC_KEY, Label, 6 } }, 64 },
    { "hmac key200",            0, M, 0, 2, { HASH(wSHA256), { KDF_HMAC_KEY, BigKey, sizeof(BigKey) } }, 64 },
    { "hmac sha512 key200",     0, M, 0, 2, { HASH(wSHA512), { KDF_HMAC_KEY, BigKey, sizeof(BigKey) } }, 64 },
    { "hmac sha256 ver0",       0, M, 0, 2, { HASH(wSHA256), HMKEY }, 64, VER0 },
    { "hmac sha256 pre app flag1 sha1", 0, M, KDF_USE_SECRET_AS_HMAC_KEY, 3, { HASH(wSHA1), PRE1, APP1 }, 64 },

    /* KDF_TLS_PRF */
    { "tls nodesc",             0, T, 0, NO_DESC, {{0}}, 48 },
    { "tls 1.0",                0, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 48 },
    { "tls 1.1",                0, T, 0, 3, { LABEL, SEED, PROTO(Tls11) }, 48 },
    { "tls 1.2 sha256",         0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 48 },
    { "tls 1.2 sha384",         0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA384) }, 48 },
    { "tls 1.2 sha1",           0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA1) }, 48 },
    { "tls 1.2 sha512",         0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA512) }, 48 },
    { "tls 1.2 md5",            0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wMD5) }, 48 },
    { "tls 1.2 md4",            0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wMD4) }, 48 },
    { "tls 1.2 md2",            0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wMD2) }, 48 },
    { "tls 1.2 nohash",         0, T, 0, 3, { LABEL, SEED, PROTO(Tls12) }, 48 },
    { "tls 1.0 sha256",         0, T, 0, 4, { LABEL, SEED, PROTO(Tls10), HASH(wSHA256) }, 48 },
    { "tls 1.1 sha256",         0, T, 0, 4, { LABEL, SEED, PROTO(Tls11), HASH(wSHA256) }, 48 },
    { "tls noproto sha256",     0, T, 0, 3, { LABEL, SEED, HASH(wSHA256) }, 48 },
    { "tls noproto nohash",     0, T, 0, 2, { LABEL, SEED }, 48 },
    { "tls nolabel 1.0",        0, T, 0, 2, { SEED, PROTO(Tls10) }, 48 },
    { "tls label0 1.0",         0, T, 0, 3, { { KDF_TLS_PRF_LABEL, Label, 0 }, SEED, PROTO(Tls10) }, 48 },
    { "tls noseed 1.0",         0, T, 0, 2, { LABEL, PROTO(Tls10) }, 48 },
    { "tls seed0 1.0",          0, T, 0, 3, { LABEL, { KDF_TLS_PRF_SEED, Seed, 0 }, PROTO(Tls10) }, 48 },
    { "tls seed13 1.0",         0, T, 0, 3, { LABEL, { KDF_TLS_PRF_SEED, Seed, 13 }, PROTO(Tls10) }, 48 },
    { "tls seed64 1.0",         0, T, 0, 3, { LABEL, { KDF_TLS_PRF_SEED, Seed, 64 }, PROTO(Tls10) }, 48 },
    { "tls proto 0300",         0, T, 0, 4, { LABEL, SEED, PROTO(TlsBad0), HASH(wSHA256) }, 48 },
    { "tls proto 0304",         0, T, 0, 4, { LABEL, SEED, PROTO(TlsBad4), HASH(wSHA256) }, 48 },
    { "tls proto 0",            0, T, 0, 4, { LABEL, SEED, PROTO(TlsZero), HASH(wSHA256) }, 48 },
    { "tls proto size2",        0, T, 0, 3, { LABEL, SEED, { KDF_TLS_PRF_PROTOCOL, &Tls10, 2 } }, 48 },
    { "tls 1.0 out16",          0, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 16 },
    { "tls 1.0 out47",          0, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 47 },
    { "tls 1.0 out49",          0, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 49 },
    { "tls 1.0 out64",          0, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 64 },
    { "tls 1.0 out0",           0, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 0 },
    { "tls 1.2 sha256 out16",   0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 16 },
    { "tls 1.2 sha256 out64",   0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 64 },
    { "tls 1.2 sha256 flag1",   0, T, KDF_USE_SECRET_AS_HMAC_KEY, 4,
                                { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 48 },
    { "tls 1.2 sha256 flag40",  0, T, BUFFERS_LOCKED, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 48 },
    { "tls 1.2 sha256 pre app", 0, T, 0, 6, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256), PRE1, APP1 }, 48 },
    { "tls 1.2 sha256 hmkey",   0, T, 0, 5, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256), HMKEY }, 48 },
    { "tls p384 1.2 sha384",    1, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA384) }, 48 },
    { "tls p384 1.0",           1, T, 0, 3, { LABEL, SEED, PROTO(Tls10) }, 48 },
    { "tls 1.2 foo",            0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wFOO) }, 48 },
    { "tls 1.0 foo",            0, T, 0, 4, { LABEL, SEED, PROTO(Tls10), HASH(wFOO) }, 48 },
    { "tls seed63 1.0",         0, T, 0, 3, { LABEL, { KDF_TLS_PRF_SEED, Seed, 63 }, PROTO(Tls10) }, 48 },
    { "tls seed65 1.0",         0, T, 0, 3, { LABEL, { KDF_TLS_PRF_SEED, Seed2, 65 }, PROTO(Tls10) }, 48 },
    { "tls seed128 1.2",        0, T, 0, 4, { LABEL, { KDF_TLS_PRF_SEED, Seed2, 128 }, PROTO(Tls12), HASH(wSHA256) }, 48 },
    { "tls seed32 1.2",         0, T, 0, 4, { LABEL, { KDF_TLS_PRF_SEED, Seed, 32 }, PROTO(Tls12), HASH(wSHA256) }, 48 },
    { "tls label100 1.0",       0, T, 0, 3, { { KDF_TLS_PRF_LABEL, Seed2, 100 }, SEED, PROTO(Tls10) }, 48 },
    { "tls 1.1 sha384",         0, T, 0, 4, { LABEL, SEED, PROTO(Tls11), HASH(wSHA384) }, 48 },
    { "tls proto ffff",         0, T, 0, 3, { LABEL, SEED, PROTO(TlsFFFF) }, 48 },
    { "tls 1.2 out0",           0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 0 },
    { "tls 1.2 ver0",           0, T, 0, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA256) }, 48, VER0 },
    { "tls 1.2 two labels",     0, T, 0, 5, { LABEL, { KDF_TLS_PRF_LABEL, Seed2, 5 }, SEED, PROTO(Tls12), HASH(wSHA256) }, 48 },
    { "tls 1.2 flag1 sha384",   0, T, KDF_USE_SECRET_AS_HMAC_KEY, 4, { LABEL, SEED, PROTO(Tls12), HASH(wSHA384) }, 48 },

    /* KDF_SP80056A_CONCAT */
    { "concat nodesc",          0, C, 0, NO_DESC, {{0}}, 64 },
    { "concat emptydesc",       0, C, 0, 0, {{0}}, 64 },
    { "concat all nohash",      0, C, 0, 5, { CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all sha1",        0, C, 0, 6, { HASH(wSHA1), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all sha256",      0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all sha384",      0, C, 0, 6, { HASH(wSHA384), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all sha512",      0, C, 0, 6, { HASH(wSHA512), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all md5",         0, C, 0, 6, { HASH(wMD5), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all foo",         0, C, 0, 6, { HASH(wFOO), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat noalg",           0, C, 0, 5, { HASH(wSHA256), CPU, CPV, CPB, CPR }, 64 },
    { "concat nopartyu",        0, C, 0, 5, { HASH(wSHA256), CAL, CPV, CPB, CPR }, 64 },
    { "concat nopartyv",        0, C, 0, 5, { HASH(wSHA256), CAL, CPU, CPB, CPR }, 64 },
    { "concat nopub",           0, C, 0, 5, { HASH(wSHA256), CAL, CPU, CPV, CPR }, 64 },
    { "concat nopriv",          0, C, 0, 5, { HASH(wSHA256), CAL, CPU, CPV, CPB }, 64 },
    { "concat only alg",        0, C, 0, 2, { HASH(wSHA256), CAL }, 64 },
    { "concat only u",          0, C, 0, 2, { HASH(wSHA256), CPU }, 64 },
    { "concat only v",          0, C, 0, 2, { HASH(wSHA256), CPV }, 64 },
    { "concat only pub",        0, C, 0, 2, { HASH(wSHA256), CPB }, 64 },
    { "concat only priv",       0, C, 0, 2, { HASH(wSHA256), CPR }, 64 },
    { "concat only hash",       0, C, 0, 1, { HASH(wSHA256) }, 64 },
    { "concat alg u v",         0, C, 0, 4, { HASH(wSHA256), CAL, CPU, CPV }, 64 },
    { "concat all pre",         0, C, 0, 7, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR, PRE1 }, 64 },
    { "concat all app",         0, C, 0, 7, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR, APP1 }, 64 },
    { "concat all hmkey",       0, C, 0, 7, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR, HMKEY }, 64 },
    { "concat all label",       0, C, 0, 7, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR, LABEL }, 64 },
    { "concat all salt",        0, C, 0, 7, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR, { KDF_SALT, Seed, 8 } }, 64 },
    { "concat all alg0",        0, C, 0, 6, { HASH(wSHA256), { KDF_ALGORITHMID, AlgId, 0 }, CPU, CPV, CPB, CPR }, 64 },
    { "concat all priv0",       0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, { KDF_SUPPPRIVINFO, PrivInfo, 0 } }, 64 },
    { "concat all out0",        0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 0 },
    { "concat all out16",       0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 16 },
    { "concat all out32",       0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 32 },
    { "concat all out33",       0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 33 },
    { "concat all out100",      0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 100 },
    { "concat all out200",      0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 200 },
    { "concat all flag1",       0, C, KDF_USE_SECRET_AS_HMAC_KEY, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat all flag40",      0, C, BUFFERS_LOCKED, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat p384 all sha384", 1, C, 0, 6, { HASH(wSHA384), CAL, CPU, CPV, CPB, CPR }, 100 },
    { "concat p384 all sha256", 1, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 64 },
    { "concat p521 all sha256", 2, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 150 },
    { "hash p521 sha512 pre",   2, H, 0, 2, { HASH(wSHA512), PRE1 }, 64 },
    { "raw p521",               2, R, 0, NO_DESC, {{0}}, 80 },
    { "concat all ver0",        0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 64, VER0 },
    { "concat two algid",       0, C, 0, 7, { HASH(wSHA256), CAL, { KDF_ALGORITHMID, PartyU, 6 }, CPU, CPV, CPB, CPR }, 64 },
    { "concat uv alg order",    0, C, 0, 6, { HASH(wSHA256), CPR, CPB, CPV, CPU, CAL }, 64 },
    { "concat all out1",        0, C, 0, 6, { HASH(wSHA256), CAL, CPU, CPV, CPB, CPR }, 1 },

    /* KDF_RAW_SECRET */
    { "raw nodesc",             0, R, 0, NO_DESC, {{0}}, 64 },
    { "raw out16",              0, R, 0, NO_DESC, {{0}}, 16 },
    { "raw out31",              0, R, 0, NO_DESC, {{0}}, 31 },
    { "raw out32",              0, R, 0, NO_DESC, {{0}}, 32 },
    { "raw out33",              0, R, 0, NO_DESC, {{0}}, 33 },
    { "raw out0",               0, R, 0, NO_DESC, {{0}}, 0 },
    { "raw sha256 desc",        0, R, 0, 1, { HASH(wSHA256) }, 64 },
    { "raw foo desc",           0, R, 0, 1, { HASH(wFOO) }, 64 },
    { "raw flag1",              0, R, KDF_USE_SECRET_AS_HMAC_KEY, NO_DESC, {{0}}, 64 },
    { "raw flag40",             0, R, BUFFERS_LOCKED, NO_DESC, {{0}}, 64 },
    { "raw p384",               1, R, 0, NO_DESC, {{0}}, 64 },
    { "raw p384 out47",         1, R, 0, NO_DESC, {{0}}, 47 },

    { "raw ver0",               0, R, 0, 1, { HASH(wSHA256) }, 64, VER0 },

    /* unknown names */
    { "kdf FOO",                0, L"FOO", 0, NO_DESC, {{0}}, 64 },
    { "kdf empty",              0, L"", 0, NO_DESC, {{0}}, 64 },
    { "kdf hash lower",         0, L"hash", 0, 1, { HASH(wSHA256) }, 64 },
    { "kdf SHA256",             0, L"SHA256", 0, NO_DESC, {{0}}, 64 },
    { "kdf CAPI_KDF",           0, L"CAPI_KDF", 0, NO_DESC, {{0}}, 64 },
    { "kdf HKDF",               0, L"HKDF", 0, NO_DESC, {{0}}, 64 },
    { "kdf PBKDF2",             0, BCRYPT_PBKDF2_ALGORITHM, 0, NO_DESC, {{0}}, 64 },
    { "kdf TLS1_1_KDF",         0, L"TLS1_1_KDF", 0, NO_DESC, {{0}}, 64 },
    { "kdf SP800_108",          0, L"SP800_108_CTR_HMAC", 0, NO_DESC, {{0}}, 64 },
};

#ifndef WINREF_PROBE
/* Windows 10 22H2, x64 and x86 */
static const EXPECTED Expected[] =
{
    /* hash nodesc */ { 0x00000000, 20, 0x00000000, 20, 0, "f18d89be1f0206d14f29f942842be1c516670180" },
    /* hash emptydesc */ { 0x00000000, 20, 0x00000000, 20, 0, "f18d89be1f0206d14f29f942842be1c516670180" },
    /* hash sha1 */ { 0x00000000, 20, 0x00000000, 20, 0, "f18d89be1f0206d14f29f942842be1c516670180" },
    /* hash sha256 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha384 */ { 0x00000000, 48, 0x00000000, 48, 0, "98d53c742b154f8bc0fd614c02fe6c19bceaba48cfb75b26af7eb816b8b626d2f1fd28567ab93589a43132c0ee7e9a39" },
    /* hash sha512 */ { 0x00000000, 64, 0x00000000, 64, 0, "36880a34d23ea90f76913c2c8af9197fa4b5f12b42805d0769e5284496dc53f5aa80543feeb6bf7b02bc00f2f4edb86ff99e8afeee5eaaeb94c8bc7b57c3a92e" },
    /* hash md5 */ { 0x00000000, 16, 0x00000000, 16, 0, "d1fd7b1f3fa8273cecd6805f36c7fcbb" },
    /* hash md4 */ { 0x00000000, 16, 0x00000000, 16, 0, "cc4b595b69892716d99876f251856b7e" },
    /* hash md2 */ { 0x00000000, 16, 0x00000000, 16, 0, "b17523587a3a15c9a98c3f1ab0647741" },
    /* hash foo */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* hash emptyname */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* hash sha256 nonul */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* hash sha256 pre */ { 0x00000000, 32, 0x00000000, 32, 0, "0c832a0b4d21d6e3aa496b06d1bdfa9c370517b7261297f09503586b06c2fe16" },
    /* hash sha256 app */ { 0x00000000, 32, 0x00000000, 32, 0, "a4eecc845f1d2214c33c9eb7b1f94d2e7c8ae1dbfe3ecdc8d12d6242500de5ed" },
    /* hash sha256 pre+app */ { 0x00000000, 32, 0x00000000, 32, 0, "7c6f7847e839262945831e24a4108e510e0412fc51c6f77130da92613a5fc192" },
    /* hash sha256 app+pre */ { 0x00000000, 32, 0x00000000, 32, 0, "7c6f7847e839262945831e24a4108e510e0412fc51c6f77130da92613a5fc192" },
    /* hash sha256 pre pre */ { 0x00000000, 32, 0x00000000, 32, 0, "f244d3ef6c7570655144165f9be47a1e255dc220ec1f0a969b16e172a581aa37" },
    /* hash sha256 app app */ { 0x00000000, 32, 0x00000000, 32, 0, "3ce182e25c176683809603609a828c5053b90308723d6e6637c8a01cd81d76d6" },
    /* hash sha256 pre0 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha1 pre only */ { 0x00000000, 20, 0x00000000, 20, 0, "484c60864340c8e155d4d6146329cfbaf3803d4c" },
    /* hash sha256 hmackey */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash hmackey only */ { 0x00000000, 20, 0x00000000, 20, 0, "f18d89be1f0206d14f29f942842be1c516670180" },
    /* hash sha256 out16 */ { 0x00000000, 32, 0x00000000, 16, 0, "0519dc09b36efad1d00aef1d5b53b100" },
    /* hash sha256 out0 */ { 0x00000000, 32, 0x00000000, 32, 0, "" },
    /* hash sha256 out31 */ { 0x00000000, 32, 0x00000000, 31, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a36" },
    /* hash sha256 out32 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 out33 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 flag1 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 flag40 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* hash sha256 flag2 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* hash sha256 flag80 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* hash sha256 salt */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 label */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 type7777 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 twohash */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash p384 sha256 pre */ { 0x00000000, 32, 0x00000000, 32, 0, "7e2f584e835822ec78e684ad3b6f2b10bc836056d30ddd750e07e62c385f488d" },
    /* hash p384 sha384 */ { 0x00000000, 48, 0x00000000, 48, 0, "14c68084a6851317f6ee1d0f205477e256adbb69b23f7222fd09e275fedbcbbbea175d8acae6fef8d8bd8ef3f5068a0b" },
    /* hash p384 nodesc */ { 0x00000000, 20, 0x00000000, 20, 0, "103ca10332d43bf74f78d75d2050f443879c48d8" },
    /* hash sha256 twohash rev */ { 0x00000000, 48, 0x00000000, 48, 0, "98d53c742b154f8bc0fd614c02fe6c19bceaba48cfb75b26af7eb816b8b626d2f1fd28567ab93589a43132c0ee7e9a39" },
    /* hash sha256 ver0 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 ver2 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash sha256 pre null0 */ { 0x00000000, 32, 0x00000000, 32, 0, "0519dc09b36efad1d00aef1d5b53b100202eb910b5de0dede75f190a357a367d" },
    /* hash md5 pre app */ { 0x00000000, 16, 0x00000000, 16, 0, "d9f82a067f0a1f506ef71e05e31103a9" },
    /* hash sha512 pre pre app */ { 0x00000000, 64, 0x00000000, 64, 0, "af31b77a2fd6d4509572c552d1ef2c31b84e8b1b0e32bf13730e58e87a45fe4cc90ee3cc9bb1d46045822bfa99335ef9d3d6e7517d5e1c1c604683e2e2e10b3b" },
    /* hash p384 sha1 */ { 0x00000000, 20, 0x00000000, 20, 0, "103ca10332d43bf74f78d75d2050f443879c48d8" },
    /* hmac nodesc */ { 0x00000000, 20, 0xC000000D, 3452816845, 0, "" },
    /* hmac sha1 key */ { 0x00000000, 20, 0x00000000, 20, 0, "6f1192c522dd282621cd2de06fa750ce5d3987fd" },
    /* hmac sha256 key */ { 0x00000000, 32, 0x00000000, 32, 0, "d1b61e16d3fe38543922c18f6261abb29b377726f99e4696ead7c393e8ce694c" },
    /* hmac sha384 key */ { 0x00000000, 48, 0x00000000, 48, 0, "5b6367f010135c93e2fd91b652eeb16b00e328b7a749eedb32348948e588cf91abe360cbcde509214b72ea0a91c3f24d" },
    /* hmac sha512 key */ { 0x00000000, 64, 0x00000000, 64, 0, "ca5dc76c0d91a551079bc9c2762c7e443a6b41344c68707084d1a9075a11e021c3e6dffe886ab5181343dec44445e85a546a02afe9b8398043cf22f941e134bb" },
    /* hmac md5 key */ { 0x00000000, 16, 0x00000000, 16, 0, "101b352797d8fc4bbb18cc73afe40a1e" },
    /* hmac md4 key */ { 0x00000000, 16, 0x00000000, 16, 0, "eb4c072cb8c2e539ef3732c2f4d7f890" },
    /* hmac md2 key */ { 0x00000000, 16, 0x00000000, 16, 0, "1a23a00bd76abe34712c8c8ec07cdc23" },
    /* hmac foo key */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* hmac key only */ { 0x00000000, 20, 0x00000000, 20, 0, "6f1192c522dd282621cd2de06fa750ce5d3987fd" },
    /* hmac sha256 nokey */ { 0x00000000, 32, 0xC000000D, 3452816845, 0, "" },
    /* hmac sha256 key0 */ { 0x00000000, 32, 0x00000000, 32, 0, "753dfd302396f63af1f7d64663696b403453bf4591a20d3f791ace884cb3eaca" },
    /* hmac sha256 key pre app */ { 0x00000000, 32, 0x00000000, 32, 0, "e5fb03a6635d6bf1f9cbb2b4291498098db7e6c1e8ec007a6e891fcc5be45f75" },
    /* hmac sha256 key pre */ { 0x00000000, 32, 0x00000000, 32, 0, "864950c73c74d344f0ba13f7198baf5ff3d8ca69b896fcda402fca478c65f2be" },
    /* hmac sha256 key app */ { 0x00000000, 32, 0x00000000, 32, 0, "961172f593b03abe66258bc598bb966c1ac61919a99f9ffe5c9ed3062fc9eebe" },
    /* hmac sha256 flag1 */ { 0x00000000, 32, 0x00000000, 32, 0, "b9c2111a0f8acbea3b0f785758a464774cb250c7095d3ce60a745f8fd616d659" },
    /* hmac sha256 flag1 key */ { 0x00000000, 32, 0xC000000D, 3452816845, 0, "" },
    /* hmac sha256 flag1 pre */ { 0x00000000, 32, 0x00000000, 32, 0, "04aac51a8918b09ce757f21bf09d9ab4cdb7e096812744c4713b72249386611b" },
    /* hmac sha256 flag1 app */ { 0x00000000, 32, 0x00000000, 32, 0, "3fe1a663dad2577b742949c7d1875fe02c1e1832d9d764c963e7977375d41761" },
    /* hmac sha1 flag1 */ { 0x00000000, 20, 0x00000000, 20, 0, "94524c9b5ab6048f9d9a72e0163ef88a6076cf32" },
    /* hmac nohash flag1 */ { 0x00000000, 20, 0x00000000, 20, 0, "94524c9b5ab6048f9d9a72e0163ef88a6076cf32" },
    /* hmac sha256 key out16 */ { 0x00000000, 32, 0x00000000, 16, 0, "d1b61e16d3fe38543922c18f6261abb2" },
    /* hmac sha256 key out0 */ { 0x00000000, 32, 0x00000000, 32, 0, "" },
    /* hmac sha256 key out33 */ { 0x00000000, 32, 0x00000000, 32, 0, "d1b61e16d3fe38543922c18f6261abb29b377726f99e4696ead7c393e8ce694c" },
    /* hmac sha256 key flag40 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* hmac sha256 key flag2 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* hmac p384 sha384 key */ { 0x00000000, 48, 0x00000000, 48, 0, "2b8b32f5cef54d074a4c345766938ca5602bb6a19c8cfb85ea10c4e5dada5437aa91601ee03603569a88a58b7633a077" },
    /* hmac p384 sha256 flag1 */ { 0x00000000, 32, 0x00000000, 32, 0, "edd05572d2931058820718b6f80be65f384421f00884ff6ecda7815fd19335e4" },
    /* hmac two keys */ { 0x00000000, 32, 0x00000000, 32, 0, "d1b61e16d3fe38543922c18f6261abb29b377726f99e4696ead7c393e8ce694c" },
    /* hmac key200 */ { 0x00000000, 32, 0x00000000, 32, 0, "a8ba71760770417985d1f7244c902fdb459ce015d0edeaefaa849b609b50beb1" },
    /* hmac sha512 key200 */ { 0x00000000, 64, 0x00000000, 64, 0, "590f62e2648bdf0800a7a497ac95b45e86fd035e6098ea325f9b126dc00888864fc2d4ee7f2d2b07e7c24069d24e4b395b6cea4ac2ae0d94b73d53aef8760355" },
    /* hmac sha256 ver0 */ { 0x00000000, 32, 0x00000000, 32, 0, "d1b61e16d3fe38543922c18f6261abb29b377726f99e4696ead7c393e8ce694c" },
    /* hmac sha256 pre app flag1 sha1 */ { 0x00000000, 20, 0x00000000, 20, 0, "b7b37891bac12086d97761968de9c75af6d7a585" },
    /* tls nodesc */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.0 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls 1.1 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls 1.2 sha256 */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.2 sha384 */ { 0x00000000, 48, 0x00000000, 48, 0, "fff5d468a115bc94d676b562737d94de48744809c51a687ba1b11f37e8a2dd6a1e3984ae5c0a72d11eaa51386bf43660" },
    /* tls 1.2 sha1 */ { 0x00000000, 48, 0x00000000, 48, 0, "ebb6883b157f5f998f1c5f985d6d0c71168d83e79bd8195b71cdf4758635b5eb6d1999eb3383609bbd70b80743edead0" },
    /* tls 1.2 sha512 */ { 0x00000000, 48, 0x00000000, 48, 0, "612dd4ae50bf160204c11d536d78150d87ba26ba74bd6990059ce8ebd646140c0c34215023ee3217b87a483421816cf8" },
    /* tls 1.2 md5 */ { 0x00000000, 48, 0x00000000, 48, 0, "74552943e0836f5e7124b71c144d5d4ef929d76358016e966445dd4aa24aea08cb0fcb42531cd1ae18bb920e38a37e3f" },
    /* tls 1.2 md4 */ { 0x00000000, 48, 0x00000000, 48, 0, "ab9c03a55a535cac2fbef6e0cc178cf1185412f37afa21842c2b5d6b3022686e29b4b1639cd25f238896f286b49a6836" },
    /* tls 1.2 md2 */ { 0x00000000, 48, 0x00000000, 48, 0, "1dbab6bb853a49021178d42209102bf0a324d70f517a1a3ecc92fac1c3798db3496c6ebe3070d8040e3b51108b39fb5b" },
    /* tls 1.2 nohash */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.0 sha256 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls 1.1 sha256 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls noproto sha256 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls noproto nohash */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls nolabel 1.0 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls label0 1.0 */ { 0x00000000, 48, 0x00000000, 48, 0, "d1038b1c77f451c14752eb7b79f99ee580dbdefd28cc281776e226372388663865a1ff8b4c58396c9d5ed52707a584a5" },
    /* tls noseed 1.0 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls seed0 1.0 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls seed13 1.0 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls seed64 1.0 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls proto 0300 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls proto 0304 */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls proto 0 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls proto size2 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.0 out16 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.0 out47 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.0 out49 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.0 out64 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.0 out0 */ { 0x00000000, 48, 0x00000000, 48, 0, "" },
    /* tls 1.2 sha256 out16 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.2 sha256 out64 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.2 sha256 flag1 */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.2 sha256 flag40 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* tls 1.2 sha256 pre app */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.2 sha256 hmkey */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls p384 1.2 sha384 */ { 0x00000000, 48, 0x00000000, 48, 0, "fe65810791801cbba9045161ac99677b2ae743e76600e98996847a01893602bac9697b4f49c3b1dfea65b6161aee7341" },
    /* tls p384 1.0 */ { 0x00000000, 48, 0x00000000, 48, 0, "4a483d8452fd36b7615251d273788eff3454b446220a5f369a84f300ff5ff69b4e000c3a429653519eb6f589c565d3a7" },
    /* tls 1.2 foo */ { 0x00000000, 48, 0xC00000BB, 3452816845, 0, "" },
    /* tls 1.0 foo */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls seed63 1.0 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls seed65 1.0 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls seed128 1.2 */ { 0x00000000, 48, 0xC000000D, 3452816845, 0, "" },
    /* tls seed32 1.2 */ { 0x00000000, 48, 0x00000000, 48, 0, "5249e0f631c4bc4ff3072ada4b937e69e7648a26573f53a7e94fb3491a94550f38b58bfc50835fe78e81eb19051bd4a0" },
    /* tls label100 1.0 */ { 0x00000000, 48, 0x00000000, 48, 0, "42e27b60d47de156fd90c6feed265363970afa439ada2b7c85be8a6b227f0c31b88fd0341c76549aa098777d9fbd3dfc" },
    /* tls 1.1 sha384 */ { 0x00000000, 48, 0x00000000, 48, 0, "d42b75e298f9df4184ab3da52f665fcb8b962208c28c2a2c3208e2cef75bb73bde508b8d0272753b4abe3cc3f2d7ed92" },
    /* tls proto ffff */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.2 out0 */ { 0x00000000, 48, 0x00000000, 48, 0, "" },
    /* tls 1.2 ver0 */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.2 two labels */ { 0x00000000, 48, 0x00000000, 48, 0, "fcec41958d926bb98b391e7cf40ae8d81f8b443441f7eaaefdd31ac869bf03ce516a5b618cd3eb6d6f91152b4f2f22e6" },
    /* tls 1.2 flag1 sha384 */ { 0x00000000, 48, 0x00000000, 48, 0, "fff5d468a115bc94d676b562737d94de48744809c51a687ba1b11f37e8a2dd6a1e3984ae5c0a72d11eaa51386bf43660" },
    /* concat nodesc */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat emptydesc */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat all nohash */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all sha1 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all sha256 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all sha384 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all sha512 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all md5 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all foo */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat noalg */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat nopartyu */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat nopartyv */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat nopub */ { 0x00000000, 32, 0x00000000, 64, 0, "5ee08637fab7caae47e6dd378d08d1a4fc5d85975183f3fab0e1257385be182470a936a249a02a7232e4032f93ef1c15a2bebe511dfd9ad1b0b4b7391477ef81" },
    /* concat nopriv */ { 0x00000000, 32, 0x00000000, 64, 0, "5884964b6c1025307db336821dca4acdf0c245d2e9f32a29423a49e3f1a9c81fc7bdc14eb1c5e3f54b077aaedeab73b08b5d724608566a751df258babe0dd373" },
    /* concat only alg */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat only u */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat only v */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat only pub */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat only priv */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat only hash */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat alg u v */ { 0x00000000, 32, 0x00000000, 64, 0, "d3d4b5b8fab66be917e99faa5123664a364dba7bc6a2033456814b17872166f1b75a4c33f251ec2a08c3889adf3c0e9234c33af845aedd9da80c92ee567c724b" },
    /* concat all pre */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all app */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all hmkey */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all label */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all salt */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all alg0 */ { 0x00000000, 32, 0x00000000, 64, 0, "62ed274835e8807a4f61fe8358ff61ff4e5aa582e8c572fae778098e500b33aae7acd87ccb5de9ecd08d832ba11c9fd058c7e1bd70a242cb436633ec5609d330" },
    /* concat all priv0 */ { 0x00000000, 32, 0x00000000, 64, 0, "5884964b6c1025307db336821dca4acdf0c245d2e9f32a29423a49e3f1a9c81fc7bdc14eb1c5e3f54b077aaedeab73b08b5d724608566a751df258babe0dd373" },
    /* concat all out0 */ { 0x00000000, 32, 0x00000000, 32, 0, "" },
    /* concat all out16 */ { 0x00000000, 32, 0x00000000, 16, 0, "9c4af8debe8044387622a2e9f615f577" },
    /* concat all out32 */ { 0x00000000, 32, 0x00000000, 32, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a326" },
    /* concat all out33 */ { 0x00000000, 32, 0x00000000, 33, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260a" },
    /* concat all out100 */ { 0x00000000, 32, 0x00000000, 100, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc394a76c8b9695257c0d2715edd308cdc5e5cd2fb41cd2494acaa18baae6a367c588325b54" },
    /* concat all out200 */ { 0x00000000, 32, 0x00000000, 200, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc394a76c8b9695257c0d2715edd308cdc5e5cd2fb41cd2494acaa18baae6a367c588325b5424dffa6165917bca86a5bc2b060f35abbc649f30d148af0df3d6a76481708f0cca0f450c88e25606599d7fa382e00d6f34beea0d2342087fef091606b21339325afe082e456ad436d264aabe77184cb9d1b6ced58e0d05141e119611bb2c6cc4d6aed465" },
    /* concat all flag1 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all flag40 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* concat p384 all sha384 */ { 0x00000000, 48, 0x00000000, 100, 0, "bf7c67511076ddff65c0ef796cc3606517d36152b446be9ee81910620543d064506f8ae0e05194728e6c217d0083f053359ffe65549370486542e0b8eefdcc3b5a33719c5f4087d9c290b150ec292fdfca2e66c066f391d034d4575fd0f195a078bac7a9" },
    /* concat p384 all sha256 */ { 0x00000000, 48, 0x00000000, 64, 0, "bf7c67511076ddff65c0ef796cc3606517d36152b446be9ee81910620543d064506f8ae0e05194728e6c217d0083f053359ffe65549370486542e0b8eefdcc3b" },
    /* concat p521 all sha256 */ { 0x00000000, 64, 0x00000000, 150, 0, "679106dc02f1ea0d8a9d8d3910bb6a6f26d7fac0017328881cd978b42d36ab6b5c632e74187a8e0706d6022734bc5feb8f21a976f77c00339f00b048a708d4ca3b4253a90504878df0072d7711f64008c16baf6da322bbe0a29f8d1281b69b4deb124c759010429028c85e77d442e1b0af1b232c736c2f51ef7f6fab97c0b3c869ec66a5a8a38e9f7603d7ae3c04f6edac1897bd9dde" },
    /* hash p521 sha512 pre */ { 0x00000000, 64, 0x00000000, 64, 0, "9be51b121d4b595fe90455729c93c669f0ebe6bb67681b0eb0e797a2681539f090b1bac349cc4b444cdb41668e323a6c2c3fcd858c7a02532088dc20497d6847" },
    /* raw p521 */ { 0x00000000, 66, 0x00000000, 66, 0, "e8d68a269d00ef8069feb6169541fb37d156afabf888f58daff6863a918bab73bbec359ae4fd21d230664e6172cf8f054f648e580cc643bcdef00cabd648f8b79300" },
    /* concat all ver0 */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat two algid */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat uv alg order */ { 0x00000000, 32, 0x00000000, 64, 0, "9c4af8debe8044387622a2e9f615f577978f69e54c507a93a562d33cec99a3260adae7ea7e88de38474c8c9c8895b6252bcff8c1e8c65348b499eaf17a0b2bc3" },
    /* concat all out1 */ { 0x00000000, 32, 0x00000000, 1, 0, "9c" },
    /* raw nodesc */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw out16 */ { 0x00000000, 32, 0x00000000, 16, 0, "206525e1e01631d1afedf6426b0f84d6" },
    /* raw out31 */ { 0x00000000, 32, 0x00000000, 31, 0, "42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw out32 */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw out33 */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw out0 */ { 0x00000000, 32, 0x00000000, 32, 0, "" },
    /* raw sha256 desc */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw foo desc */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw flag1 */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* raw flag40 */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* raw p384 */ { 0x00000000, 48, 0x00000000, 48, 0, "88f43591b95490cac32ec647ce645168591fc090633b4cc4270b56dc3e15b90baaaf9013704f3c99b77049821121c5ea" },
    /* raw p384 out47 */ { 0x00000000, 48, 0x00000000, 47, 0, "f43591b95490cac32ec647ce645168591fc090633b4cc4270b56dc3e15b90baaaf9013704f3c99b77049821121c5ea" },
    /* raw ver0 */ { 0x00000000, 32, 0x00000000, 32, 0, "de42944bd064248103ce7dce9e8eef2f206525e1e01631d1afedf6426b0f84d6" },
    /* kdf FOO */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf empty */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf hash lower */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf SHA256 */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf CAPI_KDF */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf HKDF */ { 0xC000000D, 3452816845, 0xC000000D, 3452816845, 0, "" },
    /* kdf PBKDF2 */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf TLS1_1_KDF */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
    /* kdf SP800_108 */ { 0xC00000BB, 3452816845, 0xC00000BB, 3452816845, 0, "" },
};
#endif

typedef struct
{
    BCRYPT_ALG_HANDLE Alg;
    BCRYPT_KEY_HANDLE Priv, Pub;
    BCRYPT_SECRET_HANDLE Secret;
} PAIR;

static PAIR Pairs[3];

static void FillScalar(UCHAR *Scalar, ULONG Size, UCHAR First, int Step)
{
    ULONG i;
    for (i = 0; i < Size; i++)
        Scalar[i] = (UCHAR)(First + Step * (int)i);
}

static BOOL MakePair(PAIR *Pair, PCWSTR AlgName, ULONG Magic, ULONG Size, const UCHAR *ScalarA, const UCHAR *ScalarB)
{
    UCHAR Blob[16 + 3 * 66], PubBlob[16 + 2 * 66];
    BCRYPT_ECCKEY_BLOB *Header = (BCRYPT_ECCKEY_BLOB *)Blob;
    BCRYPT_KEY_HANDLE KeyB;
    ULONG Length;
    NTSTATUS Status;

    Status = BCryptOpenAlgorithmProvider(&Pair->Alg, AlgName, NULL, 0);
    ok(Status == 0, "BCryptOpenAlgorithmProvider(%ls) returned %08lx\n", AlgName, (ULONG)Status);
    if (Status) return FALSE;

    /* Private blob with a zeroed public point: the point is derived from the scalar */
    memset(Blob, 0, sizeof(Blob));
    Header->dwMagic = Magic;
    Header->cbKey = Size;
    memcpy(Blob + sizeof(*Header) + 2 * Size, ScalarA, Size);
    Status = BCryptImportKeyPair(Pair->Alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &Pair->Priv, Blob,
                                 sizeof(*Header) + 3 * Size, 0);
    ok(Status == 0, "import private A returned %08lx\n", (ULONG)Status);
    if (Status) return FALSE;

    memcpy(Blob + sizeof(*Header) + 2 * Size, ScalarB, Size);
    Status = BCryptImportKeyPair(Pair->Alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &KeyB, Blob,
                                 sizeof(*Header) + 3 * Size, 0);
    ok(Status == 0, "import private B returned %08lx\n", (ULONG)Status);
    if (Status) return FALSE;

    Length = 0;
    Status = BCryptExportKey(KeyB, NULL, BCRYPT_ECCPUBLIC_BLOB, PubBlob, sizeof(PubBlob), &Length, 0);
    ok(Status == 0, "export public B returned %08lx\n", (ULONG)Status);
    if (Status) return FALSE;
    Status = BCryptImportKeyPair(Pair->Alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &Pair->Pub, PubBlob, Length, 0);
    ok(Status == 0, "import public B returned %08lx\n", (ULONG)Status);
    if (Status) return FALSE;
    BCryptDestroyKey(KeyB);

    Status = BCryptSecretAgreement(Pair->Priv, Pair->Pub, &Pair->Secret, 0);
    ok(Status == 0, "BCryptSecretAgreement returned %08lx\n", (ULONG)Status);
    return Status == 0;
}

static void HexOf(char *Out, const UCHAR *Data, ULONG Size)
{
    ULONG i;
    for (i = 0; i < Size; i++)
        sprintf(Out + 2 * i, "%02x", Data[i]);
    Out[2 * Size] = 0;
}

static void RunCase(const CASE *Case, EXPECTED *Got)
{
    BCryptBufferDesc Desc;
    BCryptBuffer Buffers[8];
    BCryptBufferDesc *pDesc = NULL;
    UCHAR Out[256];
    ULONG i, Len;
    static char Hex[2 * sizeof(Out) + 1];
    BCRYPT_SECRET_HANDLE Secret;
    NTSTATUS Status;

    if (Case->Count != NO_DESC)
    {
        for (i = 0; i < Case->Count; i++)
        {
            Buffers[i].BufferType = Case->Buf[i].Type;
            Buffers[i].pvBuffer = (PVOID)Case->Buf[i].Data;
            Buffers[i].cbBuffer = Case->Buf[i].Size;
        }
        Desc.ulVersion = Case->Ver == 0 ? BCRYPTBUFFER_VERSION : (Case->Ver == VER0 ? 0 : Case->Ver);
        Desc.cBuffers = Case->Count;
        Desc.pBuffers = Buffers;
        pDesc = &Desc;
    }

    /* a fresh secret per case: the SP800-56A KDF leaves the secret unusable on Windows */
    Status = BCryptSecretAgreement(Pairs[Case->Secret].Priv, Pairs[Case->Secret].Pub, &Secret, 0);
    ok(Status == 0, "%s: BCryptSecretAgreement returned %08lx\n", Case->Name, (ULONG)Status);

    Len = 0xCDCDCDCD;
    Got->Status1 = (ULONG)BCryptDeriveKey(Secret, Case->Kdf, pDesc, NULL, 0, &Len, Case->Flags);
    Got->Len1 = Len;

    memset(Out, 0xAA, sizeof(Out));
    Len = 0xCDCDCDCD;
    Got->Status2 = (ULONG)BCryptDeriveKey(Secret, Case->Kdf, pDesc, Out, Case->OutLen, &Len,
                                          Case->Flags);
    Got->Len2 = Len;
    Got->Touched = 0;
    Got->Hex = "";
    if (Got->Status2 == 0)
    {
        HexOf(Hex, Out, Len < Case->OutLen ? Len : Case->OutLen);
        Got->Hex = Hex;
    }
    else
    {
        for (i = 0; i < sizeof(Out); i++)
            if (Out[i] != 0xAA) Got->Touched++;
    }
    BCryptDestroySecret(Secret);
    /* nothing may be written past the buffer the caller gave */
    for (i = Case->OutLen; i < sizeof(Out); i++)
        ok(Out[i] == 0xAA, "%s: wrote past the end of the buffer\n", Case->Name);
}

#ifdef WINREF_PROBE
static void PrintHexLine(const char *Prefix, const UCHAR *Data, ULONG Size)
{
    char Hex[300];
    HexOf(Hex, Data, Size);
    printf("%s %s\n", Prefix, Hex);
}
#endif

static void TestSpecial(void)
{
    BCRYPT_SECRET_HANDLE Secret = Pairs[0].Secret;
    UCHAR Out[64];
    ULONG Len;
    NTSTATUS Status;
    ULONG Got[10], n = 0;
    BCryptBuffer Cb[6];
    BCryptBufferDesc Cd;
    BCRYPT_SECRET_HANDLE Fresh;

    Len = 0xCDCDCDCD;
    Got[n++] = (ULONG)BCryptDeriveKey(NULL, BCRYPT_KDF_RAW_SECRET, NULL, Out, sizeof(Out), &Len, 0);
    Got[n++] = Len;
    Len = 0xCDCDCDCD;
    Got[n++] = (ULONG)BCryptDeriveKey(Secret, NULL, NULL, Out, sizeof(Out), &Len, 0);
    Got[n++] = Len;

    /* what a successful SP800-56A derivation does to the secret handle: query only, then a real call */
    Cb[0].BufferType = KDF_HASH_ALGORITHM; Cb[0].pvBuffer = (PVOID)wSHA256; Cb[0].cbBuffer = sizeof(wSHA256);
    Cb[1].BufferType = KDF_ALGORITHMID; Cb[1].pvBuffer = (PVOID)AlgId; Cb[1].cbBuffer = 5;
    Cb[2].BufferType = KDF_PARTYUINFO; Cb[2].pvBuffer = (PVOID)PartyU; Cb[2].cbBuffer = 6;
    Cb[3].BufferType = KDF_PARTYVINFO; Cb[3].pvBuffer = (PVOID)PartyV; Cb[3].cbBuffer = 6;
    Cb[4].BufferType = KDF_SUPPPUBINFO; Cb[4].pvBuffer = (PVOID)PubInfo; Cb[4].cbBuffer = 3;
    Cb[5].BufferType = KDF_SUPPPRIVINFO; Cb[5].pvBuffer = (PVOID)PrivInfo; Cb[5].cbBuffer = 4;
    Cd.ulVersion = BCRYPTBUFFER_VERSION; Cd.cBuffers = 6; Cd.pBuffers = Cb;
    BCryptSecretAgreement(Pairs[0].Priv, Pairs[0].Pub, &Fresh, 0);
    Got[n++] = (ULONG)BCryptDeriveKey(Fresh, BCRYPT_KDF_SP80056A_CONCAT, &Cd, NULL, 0, &Len, 0);
    Got[n++] = (ULONG)BCryptDeriveKey(Fresh, BCRYPT_KDF_RAW_SECRET, NULL, Out, 32, &Len, 0);
    BCryptDestroySecret(Fresh);
    BCryptSecretAgreement(Pairs[0].Priv, Pairs[0].Pub, &Fresh, 0);
    Got[n++] = (ULONG)BCryptDeriveKey(Fresh, BCRYPT_KDF_SP80056A_CONCAT, &Cd, Out, 40, &Len, 0);
    Got[n++] = (ULONG)BCryptDeriveKey(Fresh, BCRYPT_KDF_RAW_SECRET, NULL, Out, 32, &Len, 0);
    Got[n++] = (ULONG)BCryptDeriveKey(Fresh, BCRYPT_KDF_SP80056A_CONCAT, &Cd, Out, 40, &Len, 0);
    Got[n++] = (ULONG)BCryptDestroySecret(Fresh);

#ifdef WINREF_PROBE
    printf("SPECIAL2 concat_query=%08lx raw_after_query=%08lx concat_real=%08lx raw_after_real=%08lx concat_again=%08lx destroy=%08lx\n",
           Got[4], Got[5], Got[6], Got[7], Got[8], Got[9]);
    printf("SPECIAL nullsecret=%08lx/%08lx nullkdf=%08lx/%08lx\n",
           Got[0], Got[1], Got[2], Got[3]);
#else
    {
        static const ULONG Want[10] = { 0xC0000008, 0xCDCDCDCD, 0xC000000D, 0xCDCDCDCD, 0x00000000, 0x00000000, 0x00000000, 0xC000000D, 0xC000000D, 0x00000000 };
        for (n = 0; n < 10; n++)
            ok(Got[n] == Want[n], "special %lu: got %08lx, expected %08lx\n", n, Got[n], Want[n]);
    }
#endif
    (void)Status;
}


/*
 * The accepted lengths of the TLS seed and label, and how each hash name is treated by the three KDFs that take
 * one, summarised as strings so that the table does not need a row per value.
 */
static void TestScan(void)
{
    static const WCHAR *Names[] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"sha256",
                                    L"SHA-256", L"AES", L"RNG", L"", L"SHA1 " };
    static UCHAR Big[400];
    static char Seeds[2000], Labels[2000], Hashes[2000];
    BCryptBufferDesc Desc;
    BCryptBuffer Buffers[4];
    BCRYPT_SECRET_HANDLE Secret;
    UCHAR Out[64];
    ULONG Len, i, k, Proto = 0x0303;
    NTSTATUS Status;
    char *p;

    for (i = 0; i < sizeof(Big); i++) Big[i] = (UCHAR)i;
    BCryptSecretAgreement(Pairs[0].Priv, Pairs[0].Pub, &Secret, 0);
    Desc.ulVersion = BCRYPTBUFFER_VERSION;
    Desc.pBuffers = Buffers;
    Buffers[1].BufferType = KDF_TLS_PRF_SEED;
    Buffers[1].pvBuffer = Big;
    Buffers[2].BufferType = KDF_TLS_PRF_PROTOCOL;
    Buffers[2].pvBuffer = &Proto;
    Buffers[2].cbBuffer = sizeof(Proto);
    Buffers[0].BufferType = KDF_TLS_PRF_LABEL;
    Buffers[0].pvBuffer = Big;
    Desc.cBuffers = 3;

    p = Seeds;
    *p = 0;
    Buffers[0].cbBuffer = 13;
    for (i = 0; i <= 140; i++)
    {
        Buffers[1].cbBuffer = i;
        Len = 0;
        Status = BCryptDeriveKey(Secret, BCRYPT_KDF_TLS_PRF, &Desc, Out, 48, &Len, 0);
        if (Status == 0) p += sprintf(p, "%lu,", i);
        else if (Status != (NTSTATUS)0xC000000D) p += sprintf(p, "[%lu:%08lx]", i, (ULONG)Status);
    }
    p = Labels;
    *p = 0;
    Buffers[1].cbBuffer = 64;
    for (i = 0; i <= 300; i++)
    {
        Buffers[0].cbBuffer = i;
        Len = 0;
        Status = BCryptDeriveKey(Secret, BCRYPT_KDF_TLS_PRF, &Desc, Out, 48, &Len, 0);
        if (Status != 0) p += sprintf(p, "%lu:%08lx,", i, (ULONG)Status);
    }
    if (!*Labels) strcpy(Labels, "all ok");

    p = Hashes;
    *p = 0;
    for (k = 0; k < ARRAYSIZE(Names); k++)
    {
        static const PCWSTR Kdfs[] = { BCRYPT_KDF_HASH, BCRYPT_KDF_HMAC, BCRYPT_KDF_TLS_PRF };
        ULONG j;

        p += sprintf(p, "%lu", k);
        for (j = 0; j < 3; j++)
        {
            Buffers[0].BufferType = KDF_HASH_ALGORITHM;
            Buffers[0].pvBuffer = (PVOID)Names[k];
            Buffers[0].cbBuffer = (ULONG)((wcslen(Names[k]) + 1) * sizeof(WCHAR));
            Buffers[1].BufferType = KDF_HMAC_KEY;
            Buffers[1].pvBuffer = Big;
            Buffers[1].cbBuffer = 10;
            Buffers[2].BufferType = KDF_TLS_PRF_LABEL;
            Buffers[2].pvBuffer = Big;
            Buffers[2].cbBuffer = 13;
            Buffers[3].BufferType = KDF_TLS_PRF_SEED;
            Buffers[3].pvBuffer = Big;
            Buffers[3].cbBuffer = 64;
            Desc.cBuffers = 4;
            Len = 0;
            Status = BCryptDeriveKey(Secret, Kdfs[j], &Desc, NULL, 0, &Len, 0);
            p += sprintf(p, " %08lx/%lu", (ULONG)Status, Status ? 0 : Len);
        }
        p += sprintf(p, ";");
    }
    BCryptDestroySecret(Secret);

#ifdef WINREF_PROBE
    printf("SCAN seeds=%s\nSCAN labels=%s\nSCAN hashes=%s\n", Seeds, Labels, Hashes);
#else
    ok(!strcmp(Seeds, "32,36,48,64,"), "TLS seed lengths accepted: %s\n", Seeds);
    ok(!strcmp(Labels, "all ok"), "TLS label lengths refused: %s\n", Labels);
    ok(!strcmp(Hashes, "0 00000000/16 00000000/16 00000000/48;1 00000000/16 00000000/16 00000000/48;2 00000000/16 00000000/16 00000000/48;3 00000000/20 00000000/20 00000000/48;4 00000000/32 00000000/32 00000000/48;5 00000000/48 00000000/48 00000000/48;6 00000000/64 00000000/64 00000000/48;7 c00000bb/0 c00000bb/0 00000000/48;8 c00000bb/0 c00000bb/0 00000000/48;9 c00000bb/0 c00000bb/0 00000000/48;10 c00000bb/0 c00000bb/0 00000000/48;11 c00000bb/0 c00000bb/0 00000000/48;12 c00000bb/0 c00000bb/0 00000000/48;"), "hash names: %s\n", Hashes);
#endif
}

START_TEST(BCryptDeriveKey)
{
    UCHAR ScalarA[66], ScalarB[66];
    ULONG i;
    EXPECTED Got;

    for (i = 0; i < sizeof(BigKey); i++) BigKey[i] = (UCHAR)(i * 7 + 3);
    for (i = 0; i < sizeof(Seed2); i++) Seed2[i] = (UCHAR)(0x80 + i);

    /* RFC 5903 section 8.1 (P-256) */
    static const UCHAR RfcA[32] =
    {
        0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2, 0x92, 0xDA, 0xA2, 0x31, 0x6D, 0xE5,
        0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49, 0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D, 0x14, 0x33
    };
    static const UCHAR RfcB[32] =
    {
        0xC6, 0xEF, 0x9C, 0x5D, 0x78, 0xAE, 0x01, 0x2A, 0x01, 0x11, 0x64, 0xAC, 0xB3, 0x97, 0xCE, 0x20,
        0x88, 0x68, 0x5D, 0x8F, 0x06, 0xBF, 0x9B, 0xE0, 0xB2, 0x83, 0xAB, 0x46, 0x47, 0x6B, 0xEE, 0x53
    };

    if (!MakePair(&Pairs[0], BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_PRIVATE_P256_MAGIC, 32, RfcA, RfcB))
    {
        skip("Cannot make the P-256 pair\n");
        return;
    }
    FillScalar(ScalarA, 48, 0x01, 1);
    FillScalar(ScalarB, 48, 0x30, -1);
    if (!MakePair(&Pairs[1], BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDH_PRIVATE_P384_MAGIC, 48, ScalarA, ScalarB))
    {
        skip("Cannot make the P-384 pair\n");
        return;
    }

    FillScalar(ScalarA, 66, 0x00, 1);
    FillScalar(ScalarB, 66, 0x01, 1);
    ScalarB[0] = 0;
    if (!MakePair(&Pairs[2], BCRYPT_ECDH_P521_ALGORITHM, BCRYPT_ECDH_PRIVATE_P521_MAGIC, 66, ScalarA, ScalarB))
    {
        skip("Cannot make the P-521 pair\n");
        return;
    }

#ifdef WINREF_PROBE
    {
        UCHAR Raw[64];
        ULONG Len = 0;
        NTSTATUS Status = BCryptDeriveKey(Pairs[0].Secret, BCRYPT_KDF_RAW_SECRET, NULL, Raw, sizeof(Raw), &Len, 0);
        printf("RAW256 status=%08lx\n", (ULONG)Status);
        PrintHexLine("RAW256", Raw, Len);
        Status = BCryptDeriveKey(Pairs[1].Secret, BCRYPT_KDF_RAW_SECRET, NULL, Raw, sizeof(Raw), &Len, 0);
        PrintHexLine("RAW384", Raw, Len);
    }
    printf("static const EXPECTED Expected[] =\n{\n");
#endif

    for (i = 0; i < ARRAYSIZE(Cases); i++)
    {
        RunCase(&Cases[i], &Got);
#ifdef WINREF_PROBE
        printf("    /* %s */ { 0x%08lX, %lu, 0x%08lX, %lu, %lu, \"%s\" },\n", Cases[i].Name, Got.Status1, Got.Len1,
               Got.Status2, Got.Len2, Got.Touched, Got.Hex);
#else
        if (i >= ARRAYSIZE(Expected)) continue;
        ok(Got.Status1 == Expected[i].Status1, "%s: size query status %08lx, expected %08lx\n", Cases[i].Name,
           Got.Status1, Expected[i].Status1);
        ok(Got.Len1 == Expected[i].Len1, "%s: size query length %lu, expected %lu\n", Cases[i].Name,
           Got.Len1, Expected[i].Len1);
        ok(Got.Status2 == Expected[i].Status2, "%s: status %08lx, expected %08lx\n", Cases[i].Name,
           Got.Status2, Expected[i].Status2);
        ok(Got.Len2 == Expected[i].Len2, "%s: length %lu, expected %lu\n", Cases[i].Name,
           Got.Len2, Expected[i].Len2);
        ok(Got.Touched == Expected[i].Touched, "%s: failed call changed %lu bytes, expected %lu\n", Cases[i].Name,
           Got.Touched, Expected[i].Touched);
        ok(!strcmp(Got.Hex, Expected[i].Hex), "%s: output %s, expected %s\n", Cases[i].Name, Got.Hex,
           Expected[i].Hex);
#endif
    }
#ifdef WINREF_PROBE
    printf("};\n");
#else
    ok(ARRAYSIZE(Expected) == ARRAYSIZE(Cases), "expected table has %lu rows for %lu cases\n",
       (ULONG)ARRAYSIZE(Expected), (ULONG)ARRAYSIZE(Cases));
#endif

    TestSpecial();
    TestScan();

    for (i = 0; i < 3; i++)
    {
        BCryptDestroySecret(Pairs[i].Secret);
        BCryptDestroyKey(Pairs[i].Priv);
        BCryptDestroyKey(Pairs[i].Pub);
        BCryptCloseAlgorithmProvider(Pairs[i].Alg, 0);
    }
}

#if defined(WINREF_PROBE) || defined(WINREF_CHECK)
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    func_BCryptDeriveKey();
    printf("failures %d\n", g_Failures);
    return g_Failures != 0;
}
#endif
