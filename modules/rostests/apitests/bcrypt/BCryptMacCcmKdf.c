/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for AES-CMAC, AES-GMAC, AES-CCM, AES-GCM call chaining and the SP800-108 counter KDF of bcrypt
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Known answers (the value of every row is public, none comes from this implementation):
 *  - AES-CMAC: NIST SP 800-38B appendix D.1 to D.3 (AES-128, -192, -256; messages of 0, 16, 40 and 64 bytes);
 *    the AES-128 ones are also RFC 4493 section 4.
 *  - AES-CCM: NIST SP 800-38C appendix C, examples 1 to 3.
 *  - AES-GCM / GMAC: McGrew and Viega, "The Galois/Counter Mode of Operation", test case 4 (the GMAC row is the
 *    same key, nonce and associated data with no plaintext).
 *  - SP800-108 counter mode with HMAC-SHA256: the key derivation examples of the Microsoft Open Specifications
 *    blog "SMB 2 and SMB 3 security in Windows 10: the anatomy of signing and cryptographic keys" (SMB 3.0 and
 *    SMB 3.1.1 sections), which follow [MS-SMB2] 3.1.4.2. The same blog states the labels and contexts.
 *  - Rows computed with an independent implementation (Python "cryptography" 46, AESCCM and HMAC) are marked.
 * Rows that depend on what Windows answers (lengths, properties, error codes for invalid parameters, the chained calls of
 * AES-GCM) hold what Windows Server 2022 (20348, x64 and x86) answered when the same code was built with -DWINREF_PROBE and run
 * there: that build prints every such row with the expected value and counts a difference as a failure, it only calls bcrypt.
 * AES-GCM call chaining follows the contract measured there (see ChainGcm below), not the one the structure's documentation
 * suggests: the counter block and the GHASH state are kept by the caller (pbIV, pbMacContext), cbAAD and cbData count what was
 * processed BEFORE the call, the last call has IN_PROGRESS alone. AES-CCM calls cannot be chained on Windows.
 */

#if defined(WINREF_PROBE)
#define WIN32_NO_STATUS
#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
static int g_Failures;
#define ok(cond, ...) do { if (!(cond)) { g_Failures++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); } } while (0)
#define START_TEST(x) void func_##x(void)
#define STAGE(name) printf("-- %s\n", name)
#define NT_ORACLE(what, got, expected) do { printf("ROW %-44s status=0x%08lx (expected 0x%08lx)%s\n", what, (unsigned long)(got), (unsigned long)(expected), (got) == (expected) ? "" : " DIFFERS"); if ((got) != (expected)) g_Failures++; } while (0)
#else
#include <apitest.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <bcrypt.h>
#define STAGE(name) trace("-- %s\n", name)
#define NT_ORACLE(what, got, expected) ok((got) == (expected), "%s: got 0x%08lx, expected 0x%08lx\n", what, (unsigned long)(got), (unsigned long)(expected))
#endif

#ifndef BCRYPT_AES_CMAC_ALGORITHM
#define BCRYPT_AES_CMAC_ALGORITHM L"AES-CMAC"
#endif
#ifndef BCRYPT_SP800108_CTR_HMAC_ALGORITHM
#define BCRYPT_SP800108_CTR_HMAC_ALGORITHM L"SP800_108_CTR_HMAC"
#endif
#ifndef KDF_LABEL
#define KDF_LABEL 0x0d
#define KDF_CONTEXT 0x0e
#endif
#ifndef BCRYPT_AES_CMAC_ALG_HANDLE
#define BCRYPT_AES_CMAC_ALG_HANDLE ((BCRYPT_ALG_HANDLE)0x00000101)
#endif

#define S_OK_ ((NTSTATUS)0)
#define S_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define S_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002)
#define S_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define S_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206)
#define S_INVALID_HANDLE ((NTSTATUS)0xC0000008)
#define S_OUT_OF_SEQUENCE ((NTSTATUS)0xC000042A)
#define S_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

static ULONG unhex(const char *s, UCHAR *out)
{
    ULONG n = 0;
    for (; s[0] && s[1]; s += 2) out[n++] = (UCHAR)(hexval(s[0]) * 16 + hexval(s[1]));
    return n;
}

static void expect_hex(const char *what, const UCHAR *got, ULONG len, const char *want)
{
    UCHAR w[512];
    ULONG n = unhex(want, w);
    ok(n == len && !memcmp(got, w, len), "%s: wrong result\n", what);
}

/* ---------------------------------------------------------------- AES-CMAC */

static const char *cmac_msg =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

static const struct
{
    const char *key;
    ULONG len;
    const char *tag;
} cmac_kat[] =
{
    /* SP 800-38B D.1 (and RFC 4493) */
    { "2b7e151628aed2a6abf7158809cf4f3c",   0, "bb1d6929e95937287fa37d129b756746" },
    { "2b7e151628aed2a6abf7158809cf4f3c",  16, "070a16b46b4d4144f79bdd9dd04a287c" },
    { "2b7e151628aed2a6abf7158809cf4f3c",  40, "dfa66747de9ae63030ca32611497c827" },
    { "2b7e151628aed2a6abf7158809cf4f3c",  64, "51f0bebf7e3b9d92fc49741779363cfe" },
    /* D.2 (AES-192) */
    { "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",   0, "d17ddf46adaacde531cac483de7a9367" },
    { "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",  16, "9e99a7bf31e710900662f65e617c5184" },
    { "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",  40, "8a1de5be2eb31aad089a82e6ee908b0e" },
    { "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",  64, "a1d5df0eed790f794d77589659f39a11" },
    /* D.3 (AES-256) */
    { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",   0, "028962f61b7bf89efc6b551f4667d983" },
    { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",  16, "28a7023f452e8f82bd4bf28d8c37c35c" },
    { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",  40, "aaf3d8f1de5640c232f5b169b9c911e6" },
    { "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",  64, "e1992190549f6ed5696a2c056c315410" },
};

static void test_cmac(void)
{
    UCHAR msg[64], key[32], tag[16];
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE hash, copy;
    NTSTATUS status;
    ULONG i, klen, len, size;

    unhex(cmac_msg, msg);

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_CMAC_ALGORITHM, NULL, 0);
    ok(status == S_OK_, "AES-CMAC provider: 0x%08lx\n", (unsigned long)status);
    if (status) return;

    len = 0;
    status = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (UCHAR *)&len, sizeof(len), &size, 0);
    ok(status == S_OK_ && len == 16, "hash length: 0x%08lx %lu\n", (unsigned long)status, len);

    for (i = 0; i < sizeof(cmac_kat) / sizeof(cmac_kat[0]); i++)
    {
        klen = unhex(cmac_kat[i].key, key);

        /* all at once */
        status = BCryptCreateHash(alg, &hash, NULL, 0, key, klen, 0);
        ok(status == S_OK_, "row %lu: create 0x%08lx\n", i, (unsigned long)status);
        if (status) continue;
        memset(tag, 0xAA, sizeof(tag));
        status = BCryptHashData(hash, msg, cmac_kat[i].len, 0);
        ok(status == S_OK_, "row %lu: hash 0x%08lx\n", i, (unsigned long)status);
        status = BCryptFinishHash(hash, tag, 16, 0);
        ok(status == S_OK_, "row %lu: finish 0x%08lx\n", i, (unsigned long)status);
        expect_hex("CMAC", tag, 16, cmac_kat[i].tag);
        BCryptDestroyHash(hash);

        /* in pieces of 7 bytes, with a duplicate taken half way */
        status = BCryptCreateHash(alg, &hash, NULL, 0, key, klen, 0);
        if (!status)
        {
            ULONG pos = 0, n;
            BOOL duplicated = FALSE;

            copy = NULL;
            while (pos < cmac_kat[i].len)
            {
                n = min(7, cmac_kat[i].len - pos);
                BCryptHashData(hash, msg + pos, n, 0);
                pos += n;
                if (!duplicated && pos >= 14)
                {
                    duplicated = TRUE;
                    status = BCryptDuplicateHash(hash, &copy, NULL, 0, 0);
                    ok(status == S_OK_, "row %lu: duplicate 0x%08lx\n", i, (unsigned long)status);
                    if (status) copy = NULL;
                }
            }
            memset(tag, 0xAA, sizeof(tag));
            status = BCryptFinishHash(hash, tag, 16, 0);
            ok(status == S_OK_, "row %lu: finish (pieces) 0x%08lx\n", i, (unsigned long)status);
            expect_hex("CMAC in pieces", tag, 16, cmac_kat[i].tag);
            BCryptDestroyHash(hash);

            if (copy)
            {
                /* the duplicate continues from the same state: feed it the rest of the message */
                pos = (cmac_kat[i].len >= 14) ? 14 : 0;
                BCryptHashData(copy, msg + pos, cmac_kat[i].len - pos, 0);
                memset(tag, 0xAA, sizeof(tag));
                status = BCryptFinishHash(copy, tag, 16, 0);
                ok(status == S_OK_, "row %lu: finish (duplicate) 0x%08lx\n", i, (unsigned long)status);
                expect_hex("CMAC duplicate", tag, 16, cmac_kat[i].tag);
                BCryptDestroyHash(copy);
            }
        }

        /* in one call, with the pseudo handle */
        memset(tag, 0xAA, sizeof(tag));
        status = BCryptHash(BCRYPT_AES_CMAC_ALG_HANDLE, key, klen, msg, cmac_kat[i].len, tag, 16);
        ok(status == S_OK_, "row %lu: BCryptHash 0x%08lx\n", i, (unsigned long)status);
        expect_hex("CMAC BCryptHash", tag, 16, cmac_kat[i].tag);
    }

    /* a reusable hash: the second message starts afresh */
    klen = unhex(cmac_kat[0].key, key);
    status = BCryptCreateHash(alg, &hash, NULL, 0, key, klen, BCRYPT_HASH_REUSABLE_FLAG);
    ok(status == S_OK_, "reusable create 0x%08lx\n", (unsigned long)status);
    if (!status)
    {
        BCryptHashData(hash, msg, 16, 0);
        BCryptFinishHash(hash, tag, 16, 0);
        expect_hex("reusable first", tag, 16, "070a16b46b4d4144f79bdd9dd04a287c");
        BCryptHashData(hash, msg, 40, 0);
        BCryptFinishHash(hash, tag, 16, 0);
        expect_hex("reusable second", tag, 16, "dfa66747de9ae63030ca32611497c827");
        BCryptDestroyHash(hash);
    }

    /* VERIFY ON ORACLE: what Windows answers for a bad key or output size */
    status = BCryptCreateHash(alg, &hash, NULL, 0, key, 15, 0);
    NT_ORACLE("CMAC create, 15 byte key", status, S_INVALID_PARAMETER);
    if (!status) BCryptDestroyHash(hash);
    status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    NT_ORACLE("CMAC create, no key", status, S_INVALID_PARAMETER);
    if (!status) BCryptDestroyHash(hash);
    status = BCryptCreateHash(alg, &hash, NULL, 0, key, 16, 0);
    if (!status)
    {
        BCryptHashData(hash, msg, 16, 0);
        status = BCryptFinishHash(hash, tag, 15, 0);
        NT_ORACLE("CMAC finish, 15 byte output", status, S_INVALID_PARAMETER);
        status = BCryptFinishHash(hash, tag, 16, 0);
        ok(status == S_OK_, "finish after a refusal: 0x%08lx\n", (unsigned long)status);
        BCryptDestroyHash(hash);
    }

    BCryptCloseAlgorithmProvider(alg, 0);
}

/* ---------------------------------------------------------------- AES-GMAC and AES-GCM chaining */

static const char *gcm_key = "feffe9928665731c6d6a8f9467308308";
static const char *gcm_nonce = "cafebabefacedbaddecaf888";
static const char *gcm_aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
static const char *gcm_pt =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
static const char *gcm_ct =
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
static const char *gcm_tag = "5bc94fbc3221a5db94fae95ae7121a47";
/* the same key, nonce and associated data, no plaintext (independent implementation) */
static const char *gmac_tag = "346434fd51d5cd0c5887ec63e39b907a";

static void init_auth(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *info, UCHAR *nonce, ULONG nonce_len, UCHAR *aad,
                      ULONG aad_len, UCHAR *tag, ULONG tag_len)
{
    memset(info, 0, sizeof(*info));
    info->cbSize = sizeof(*info);
    info->dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info->pbNonce = nonce;
    info->cbNonce = nonce_len;
    info->pbAuthData = aad;
    info->cbAuthData = aad_len;
    info->pbTag = tag;
    info->cbTag = tag_len;
}

static BCRYPT_KEY_HANDLE make_aes_key(const WCHAR *mode, const UCHAR *key, ULONG klen, BCRYPT_ALG_HANDLE *palg)
{
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(palg, BCRYPT_AES_ALGORITHM, NULL, 0);
    ok(status == S_OK_, "AES provider 0x%08lx\n", (unsigned long)status);
    if (status) return NULL;
    status = BCryptSetProperty(*palg, BCRYPT_CHAINING_MODE, (UCHAR *)mode, (ULONG)((lstrlenW(mode) + 1) * sizeof(WCHAR)), 0);
    ok(status == S_OK_, "chaining mode %ls: 0x%08lx\n", mode, (unsigned long)status);
    if (status) return NULL;
    status = BCryptGenerateSymmetricKey(*palg, &k, NULL, 0, (UCHAR *)key, klen, 0);
    ok(status == S_OK_, "generate key 0x%08lx\n", (unsigned long)status);
    return status ? NULL : k;
}

/* ---------------------------------------------------------------- AES-GCM call chaining (as measured on Windows Server 2022) */

typedef struct
{
    UCHAR iv[16];           /* pbIV: the running counter block */
    UCHAR mac[64];          /* pbMacContext: the running GHASH state (16 bytes used) */
    ULONG aad_done;         /* cbAAD: bytes of associated data processed before the next call */
    ULONG data_done;        /* cbData: bytes of data processed before the next call */
} GCM_CHAIN;

static NTSTATUS chain_call(BCRYPT_KEY_HANDLE k, BOOL decrypt, GCM_CHAIN *c, const UCHAR *nonce, const UCHAR *aad, ULONG aad_len,
                           const UCHAR *in, ULONG len, UCHAR *out, ULONG flags, UCHAR *tag, ULONG cb_tag)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG size;
    NTSTATUS status;

    init_auth(&info, (UCHAR *)nonce, 12, (UCHAR *)aad, aad_len, tag, cb_tag);
    info.pbMacContext = c->mac;
    info.cbMacContext = sizeof(c->mac);
    info.cbAAD = c->aad_done;
    info.cbData = c->data_done;
    info.dwFlags = flags;
    if (decrypt) status = BCryptDecrypt(k, (UCHAR *)in, len, &info, c->iv, sizeof(c->iv), out, len, &size, 0);
    else status = BCryptEncrypt(k, (UCHAR *)in, len, &info, c->iv, sizeof(c->iv), out, len, &size, 0);
    if (!status) { c->aad_done += aad_len; c->data_done += len; }
    return status;
}

#define CHAIN_FIRST BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG
#define CHAIN_MIDDLE (BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG | BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG)
#define CHAIN_LAST BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG

/* the message in parts (the last one may have any length, the others a multiple of 16), the associated data in the first data call or in
 * a call of their own in front of the data; returns the status of the first call that failed */
static NTSTATUS run_chain(BCRYPT_KEY_HANDLE k, BOOL decrypt, BOOL lead, const ULONG *parts, ULONG count, const UCHAR *nonce,
                          const UCHAR *aad, const UCHAR *in, UCHAR *out, UCHAR *tag, ULONG cb_tag)
{
    GCM_CHAIN c;
    NTSTATUS status;
    ULONG i, off = 0, calls = count + (lead ? 1 : 0), n = 0;

    memset(&c, 0, sizeof(c));
    memset(c.iv, 0x77, sizeof(c.iv));  /* the first call sets it */
    if (lead)
    {
        status = chain_call(k, decrypt, &c, nonce, aad, 20, NULL, 0, NULL, CHAIN_FIRST, NULL, 16);
        if (status) return status;
        n++;
    }
    for (i = 0; i < count; i++, n++)
    {
        BOOL last = (n == calls - 1);
        ULONG fl = last ? CHAIN_LAST : (n == 0) ? CHAIN_FIRST : CHAIN_MIDDLE;

        status = chain_call(k, decrypt, &c, nonce, (!lead && i == 0) ? aad : NULL, (!lead && i == 0) ? 20 : 0, in + off, parts[i], out + off,
                            fl, last ? tag : NULL, cb_tag);
        if (status) return status;
        off += parts[i];
    }
    return S_OK_;
}

static void ChainGcm(BCRYPT_KEY_HANDLE k, const UCHAR *key, const UCHAR *nonce, const UCHAR *aad, const UCHAR *pt, const UCHAR *ct)
{
    static const struct { ULONG parts[4]; ULONG count; } splits[] =
    {
        { { 16, 32, 12 }, 3 }, { { 16, 16, 16, 12 }, 4 }, { { 16, 44 }, 2 }, { { 32, 28 }, 2 }, { { 48, 12 }, 2 }, { { 16, 16, 28 }, 3 },
    };
    UCHAR out[64], tag[16], tag_vec[16], want[16];
    GCM_CHAIN c;
    NTSTATUS status;
    ULONG i, lead, size;

    unhex(gcm_tag, tag_vec);
    for (lead = 0; lead < 2; lead++) for (i = 0; i < sizeof(splits) / sizeof(splits[0]); i++)
    {
        memset(out, 0xAA, sizeof(out));
        memset(tag, 0xAA, sizeof(tag));
        status = run_chain(k, FALSE, lead, splits[i].parts, splits[i].count, nonce, aad, pt, out, tag, 16);
        ok(status == S_OK_, "chained encrypt, split %lu, lead %lu: 0x%08lx\n", i, lead, (unsigned long)status);
        expect_hex("chained GCM ciphertext", out, 60, gcm_ct);
        expect_hex("chained GCM tag", tag, 16, gcm_tag);

        memset(out, 0xAA, sizeof(out));
        memcpy(tag, tag_vec, 16);
        status = run_chain(k, TRUE, lead, splits[i].parts, splits[i].count, nonce, aad, ct, out, tag, 16);
        ok(status == S_OK_, "chained decrypt, split %lu, lead %lu: 0x%08lx\n", i, lead, (unsigned long)status);
        expect_hex("chained GCM plaintext", out, 60, gcm_pt);

        tag[5] ^= 0x10;
        status = run_chain(k, TRUE, lead, splits[i].parts, splits[i].count, nonce, aad, ct, out, tag, 16);
        ok(status == S_AUTH_TAG_MISMATCH, "chained decrypt, tampered tag, split %lu: 0x%08lx\n", i, (unsigned long)status);
    }

    /* a 12 byte tag is the first 12 bytes of the 16 byte one */
    memset(tag, 0xAA, sizeof(tag));
    status = run_chain(k, FALSE, FALSE, splits[0].parts, 3, nonce, aad, pt, out, tag, 12);
    ok(status == S_OK_ && !memcmp(tag, tag_vec, 12) && tag[12] == 0xAA, "chained 12 byte tag 0x%08lx\n", (unsigned long)status);
    status = run_chain(k, FALSE, FALSE, splits[0].parts, 3, nonce, aad, pt, out, tag, 11);
    NT_ORACLE("GCM chain, 11 byte tag", status, S_INVALID_PARAMETER);
    status = run_chain(k, FALSE, FALSE, splits[0].parts, 3, nonce, aad, pt, out, tag, 17);
    NT_ORACLE("GCM chain, 17 byte tag", status, S_INVALID_PARAMETER);

    /* the state the caller keeps: the counter block after 16, then 48 bytes, and what the last call wipes */
    memset(&c, 0, sizeof(c));
    status = chain_call(k, FALSE, &c, nonce, aad, 20, pt, 16, out, CHAIN_FIRST, NULL, 16);
    ok(status == S_OK_, "first call 0x%08lx\n", (unsigned long)status);
    memcpy(want, nonce, 12); want[12] = 0; want[13] = 0; want[14] = 0; want[15] = 3;
    ok(!memcmp(c.iv, want, 16), "counter block after 16 bytes\n");
    status = chain_call(k, FALSE, &c, nonce, NULL, 0, pt + 16, 32, out + 16, CHAIN_MIDDLE, NULL, 16);
    ok(status == S_OK_, "second call 0x%08lx\n", (unsigned long)status);
    want[15] = 5;
    ok(!memcmp(c.iv, want, 16), "counter block after 48 bytes\n");
    status = chain_call(k, FALSE, &c, nonce, NULL, 0, pt + 48, 12, out + 48, CHAIN_LAST, tag, 16);
    ok(status == S_OK_, "last call 0x%08lx\n", (unsigned long)status);
    memset(want, 0, 16);
    ok(!memcmp(c.iv, want, 16) && !memcmp(c.mac, want, 16), "the last call wipes the counter block and the GHASH state\n");

    /* what the caller keeps matters: a flipped bit of the GHASH state, of the nonce in the counter block */
    for (i = 0; i < 2; i++)
    {
        memset(&c, 0, sizeof(c));
        status = chain_call(k, TRUE, &c, nonce, aad, 20, ct, 16, out, CHAIN_FIRST, NULL, 16);
        if (i == 0) c.mac[0] ^= 1; else c.iv[0] ^= 1;
        status = chain_call(k, TRUE, &c, nonce, NULL, 0, ct + 16, 32, out + 16, CHAIN_MIDDLE, NULL, 16);
        status = chain_call(k, TRUE, &c, nonce, NULL, 0, ct + 48, 12, out + 48, CHAIN_LAST, tag_vec, 16);
        ok(status == S_AUTH_TAG_MISMATCH, "damaged %s: 0x%08lx\n", i ? "counter block" : "GHASH state", (unsigned long)status);
    }

    /* what Windows refuses */
    memset(&c, 0, sizeof(c));
    status = chain_call(k, FALSE, &c, nonce, aad, 20, pt, 20, out, CHAIN_FIRST, NULL, 16);
    NT_ORACLE("GCM chain, first part not a multiple of 16", status, S_INVALID_BUFFER_SIZE);
    memset(&c, 0, sizeof(c));
    status = chain_call(k, FALSE, &c, nonce, aad, 20, pt, 16, out, CHAIN_FIRST, NULL, 16);
    status = chain_call(k, FALSE, &c, nonce, NULL, 0, pt + 16, 30, out + 16, CHAIN_MIDDLE, NULL, 16);
    NT_ORACLE("GCM chain, middle part of 30 bytes", status, S_INVALID_BUFFER_SIZE);
    memset(&c, 0, sizeof(c));
    status = chain_call(k, FALSE, &c, nonce, aad, 20, pt, 16, out, CHAIN_FIRST, NULL, 16);
    status = chain_call(k, FALSE, &c, nonce, NULL, 0, pt + 16, 32, out + 16, CHAIN_MIDDLE, NULL, 16);
    status = chain_call(k, FALSE, &c, nonce, NULL, 0, pt + 48, 12, out + 48, CHAIN_MIDDLE, NULL, 16);
    NT_ORACLE("GCM chain, 12 bytes with CHAIN_CALLS", status, S_INVALID_BUFFER_SIZE);
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        UCHAR iv[16], mac[64];

        memset(&c, 0, sizeof(c));
        status = chain_call(k, FALSE, &c, nonce, aad, 20, pt, 16, out, CHAIN_FIRST, NULL, 16);
        /* a later call without the nonce, without pbIV, without pbMacContext, with a short pbMacContext, with cbTag 11 */
        init_auth(&info, NULL, 0, NULL, 0, NULL, 16);
        info.pbMacContext = c.mac; info.cbMacContext = 64; info.cbData = 16; info.dwFlags = CHAIN_MIDDLE;
        status = BCryptEncrypt(k, (UCHAR *)pt + 16, 16, &info, c.iv, 16, out + 16, 16, &size, 0);
        NT_ORACLE("GCM chain, later call without nonce", status, S_INVALID_PARAMETER);
        init_auth(&info, (UCHAR *)nonce, 12, NULL, 0, NULL, 16);
        info.pbMacContext = c.mac; info.cbMacContext = 64; info.cbData = 16; info.dwFlags = CHAIN_MIDDLE;
        status = BCryptEncrypt(k, (UCHAR *)pt + 16, 16, &info, NULL, 0, out + 16, 16, &size, 0);
        NT_ORACLE("GCM chain, later call without pbIV", status, S_INVALID_PARAMETER);
        info.pbMacContext = NULL; info.cbMacContext = 0;
        status = BCryptEncrypt(k, (UCHAR *)pt + 16, 16, &info, c.iv, 16, out + 16, 16, &size, 0);
        NT_ORACLE("GCM chain, later call without pbMacContext", status, S_INVALID_PARAMETER);
        info.pbMacContext = c.mac; info.cbMacContext = 15;
        status = BCryptEncrypt(k, (UCHAR *)pt + 16, 16, &info, c.iv, 16, out + 16, 16, &size, 0);
        NT_ORACLE("GCM chain, cbMacContext 15", status, S_INVALID_PARAMETER);
        info.cbMacContext = 16;
        info.cbTag = 11;
        status = BCryptEncrypt(k, (UCHAR *)pt + 16, 16, &info, c.iv, 16, out + 16, 16, &size, 0);
        NT_ORACLE("GCM chain, non-final cbTag 11", status, S_INVALID_PARAMETER);
        info.cbTag = 17;
        status = BCryptEncrypt(k, (UCHAR *)pt + 16, 16, &info, c.iv, 16, out + 16, 16, &size, 0);
        NT_ORACLE("GCM chain, non-final cbTag 17", status, S_INVALID_PARAMETER);
        /* no chain yet: the caller's buffers are not read before the first call */
        memset(iv, 0, sizeof(iv)); memset(mac, 0, sizeof(mac));
        init_auth(&info, (UCHAR *)nonce, 12, NULL, 0, NULL, 16);
        info.pbMacContext = mac; info.cbMacContext = 15; info.dwFlags = CHAIN_FIRST;
        status = BCryptEncrypt(k, (UCHAR *)pt, 16, &info, iv, 16, out, 16, &size, 0);
        NT_ORACLE("GCM chain, first call, cbMacContext 15", status, S_INVALID_PARAMETER);
    }

    /* BCRYPT_BLOCK_PADDING: the padded size, too small a buffer, nothing else works */
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        UCHAR big[64];

        init_auth(&info, (UCHAR *)nonce, 12, NULL, 0, tag, 16);
        size = 0xdead;
        status = BCryptEncrypt(k, (UCHAR *)pt, 16, &info, NULL, 0, NULL, 0, &size, BCRYPT_BLOCK_PADDING);
        NT_ORACLE("GCM, block padding, size query", status, S_OK_);
        ok(size == 32, "padded size %lu\n", size);
        status = BCryptEncrypt(k, (UCHAR *)pt, 16, &info, NULL, 0, big, 16, &size, BCRYPT_BLOCK_PADDING);
        NT_ORACLE("GCM, block padding, 16 byte output", status, S_BUFFER_TOO_SMALL);
        status = BCryptEncrypt(k, (UCHAR *)pt, 16, &info, NULL, 0, big, 64, &size, BCRYPT_BLOCK_PADDING);
        NT_ORACLE("GCM, block padding, 64 byte output", status, S_INVALID_PARAMETER);
        status = BCryptDecrypt(k, (UCHAR *)ct, 32, &info, NULL, 0, big, 64, &size, BCRYPT_BLOCK_PADDING);
        NT_ORACLE("GCM decrypt, block padding", status, S_INVALID_PARAMETER);
    }
    (void)key;
}

static void test_gcm_gmac(void)
{
    UCHAR key[16], nonce[12], aad[20], pt[64], ct[64], out[64], tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE k;
    NTSTATUS status;
    ULONG size, n;

    unhex(gcm_key, key);
    unhex(gcm_nonce, nonce);
    unhex(gcm_aad, aad);
    n = unhex(gcm_pt, pt);
    unhex(gcm_ct, ct);
    ok(n == 60, "vector\n");

    k = make_aes_key(BCRYPT_CHAIN_MODE_GCM, key, 16, &alg);
    if (!k) return;

    /* single call */
    init_auth(&info, nonce, 12, aad, 20, tag, 16);
    memset(out, 0xAA, sizeof(out));
    status = BCryptEncrypt(k, pt, 60, &info, NULL, 0, out, 60, &size, 0);
    ok(status == S_OK_ && size == 60, "gcm encrypt 0x%08lx %lu\n", (unsigned long)status, size);
    expect_hex("GCM ciphertext", out, 60, gcm_ct);
    expect_hex("GCM tag", tag, 16, gcm_tag);

    init_auth(&info, nonce, 12, aad, 20, tag, 16);
    status = BCryptDecrypt(k, ct, 60, &info, NULL, 0, out, 60, &size, 0);
    ok(status == S_OK_, "gcm decrypt 0x%08lx\n", (unsigned long)status);
    unhex(gcm_tag, tag);
    expect_hex("GCM plaintext", out, 60, gcm_pt);
    tag[3] ^= 0x40;
    init_auth(&info, nonce, 12, aad, 20, tag, 16);
    status = BCryptDecrypt(k, ct, 60, &info, NULL, 0, out, 60, &size, 0);
    ok(status == S_AUTH_TAG_MISMATCH, "gcm tampered tag 0x%08lx\n", (unsigned long)status);

    /* chained calls: see ChainGcm */
    ChainGcm(k, key, nonce, aad, pt, ct);

    /* GMAC through AES-GCM: associated data only */
    init_auth(&info, nonce, 12, aad, 20, tag, 16);
    memset(tag, 0xAA, sizeof(tag));
    status = BCryptEncrypt(k, NULL, 0, &info, NULL, 0, NULL, 0, &size, 0);
    ok(status == S_OK_ && size == 0, "gmac via gcm 0x%08lx\n", (unsigned long)status);
    expect_hex("GMAC via GCM", tag, 16, gmac_tag);

    /* VERIFY ON ORACLE: nonces and tags the mode refuses */
    init_auth(&info, nonce, 0, aad, 20, tag, 16);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("GCM, empty nonce", status, S_INVALID_PARAMETER);
    init_auth(&info, nonce, 12, aad, 20, tag, 11);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("GCM, 11 byte tag", status, S_INVALID_PARAMETER);
    /* a chain that was never started */
    init_auth(&info, nonce, 12, NULL, 0, tag, 16);
    info.dwFlags = BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG;
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("GCM, IN_PROGRESS with no chain", status, S_INVALID_PARAMETER);

    BCryptDestroyKey(k);
    BCryptCloseAlgorithmProvider(alg, 0);

    /* AES-GMAC as a hash: the key is the secret, the nonce the initialization vector (VERIFY ON ORACLE) */
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_GMAC_ALGORITHM, NULL, 0);
    ok(status == S_OK_, "AES-GMAC provider 0x%08lx\n", (unsigned long)status);
    if (!status)
    {
        BCRYPT_HASH_HANDLE hash;

        status = BCryptCreateHash(alg, &hash, NULL, 0, key, 16, 0);
        NT_ORACLE("GMAC create", status, S_OK_);
        if (!status)
        {
            status = BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, nonce, 12, 0);
            NT_ORACLE("GMAC set nonce", status, S_OK_);
            BCryptHashData(hash, aad, 7, 0);
            BCryptHashData(hash, aad + 7, 13, 0);
            memset(tag, 0xAA, sizeof(tag));
            status = BCryptFinishHash(hash, tag, 16, 0);
            NT_ORACLE("GMAC finish", status, S_OK_);
            if (!status) expect_hex("GMAC hash", tag, 16, gmac_tag);
            status = BCryptFinishHash(hash, tag, 16, 0);
            NT_ORACLE("GMAC second finish", status, S_INVALID_HANDLE);
            BCryptDestroyHash(hash);
        }

        /* the statuses of the nonce and of the key, Windows Server 2022 */
        {
            ULONG len;

            status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
            NT_ORACLE("GMAC create without key", status, S_INVALID_BUFFER_SIZE);
            status = BCryptCreateHash(alg, &hash, NULL, 0, key, 15, 0);
            NT_ORACLE("GMAC create, key of 15 bytes", status, S_INVALID_BUFFER_SIZE);
            for (len = 24; len <= 32; len += 8)
            {
                UCHAR long_key[32];

                memset(long_key, 0x42, sizeof(long_key));
                status = BCryptCreateHash(alg, &hash, NULL, 0, long_key, len, 0);
                NT_ORACLE(len == 24 ? "GMAC create, key of 24 bytes" : "GMAC create, key of 32 bytes", status, S_OK_);
                if (!status) BCryptDestroyHash(hash);
            }
            status = BCryptCreateHash(alg, &hash, NULL, 0, key, 16, 0);
            if (!status)
            {
                UCHAR buf[16];

                status = BCryptFinishHash(hash, buf, 16, 0);
                NT_ORACLE("GMAC finish without nonce", status, S_OUT_OF_SEQUENCE);
                for (len = 0; len <= 16; len++)
                {
                    char what[48];

                    status = BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, nonce, len, 0);
                    sprintf(what, "GMAC nonce of %lu bytes", len);
                    NT_ORACLE(what, status, len == 12 ? S_OK_ : S_INVALID_BUFFER_SIZE);
                }
                BCryptHashData(hash, aad, 20, 0);
                status = BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, nonce, 12, 0);
                NT_ORACLE("GMAC second nonce after hashing began", status, S_OUT_OF_SEQUENCE);
                status = BCryptFinishHash(hash, buf, 15, 0);
                NT_ORACLE("GMAC finish, 15 byte buffer", status, S_INVALID_PARAMETER);
                status = BCryptFinishHash(hash, buf, 16, 0);
                NT_ORACLE("GMAC finish after a refusal", status, S_OK_);
                BCryptDestroyHash(hash);
            }
            /* the first nonce may come after the data */
            status = BCryptCreateHash(alg, &hash, NULL, 0, key, 16, 0);
            if (!status)
            {
                UCHAR buf[16];

                BCryptHashData(hash, aad, 20, 0);
                status = BCryptSetProperty(hash, BCRYPT_INITIALIZATION_VECTOR, nonce, 12, 0);
                NT_ORACLE("GMAC first nonce after hashing began", status, S_OK_);
                status = BCryptFinishHash(hash, buf, 16, 0);
                NT_ORACLE("GMAC finish, nonce set after the data", status, S_OK_);
                /* the data hashed before the nonce are dropped: the tag is the one of an empty message, E(nonce || 1)
                 * (AES-128 under the key of test case 4: independent value from Python cryptography ECB; Windows gives the same) */
                expect_hex("GMAC, nonce after the data", buf, 16, "3247184b3c4f69a44dbcd22887bbb418");
                BCryptDestroyHash(hash);
            }
            status = BCryptSetProperty(alg, BCRYPT_INITIALIZATION_VECTOR, nonce, 12, 0);
            NT_ORACLE("GMAC nonce on the algorithm handle", status, S_INVALID_HANDLE);
            len = 0;
            status = BCryptGetProperty(alg, BCRYPT_INITIALIZATION_VECTOR, (UCHAR *)tag, 16, &len, 0);
            NT_ORACLE("GMAC get nonce of the algorithm handle", status, S_NOT_SUPPORTED);
            status = BCryptHash(alg, key, 16, (UCHAR *)aad, 20, tag, 16);
            NT_ORACLE("GMAC BCryptHash without nonce", status, S_OUT_OF_SEQUENCE);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
}

/* ---------------------------------------------------------------- AES-CCM */

static const struct
{
    const char *nonce, *aad, *pt, *ct, *tag;
    ULONG tag_len;
    const char *source;
} ccm_kat[] =
{
    /* SP 800-38C appendix C, examples 1, 2 and 3 (key 404142434445464748494a4b4c4d4e4f) */
    { "10111213141516", "0001020304050607", "20212223", "7162015b", "4dac255d", 4, "SP800-38C C.1" },
    { "1011121314151617", "000102030405060708090a0b0c0d0e0f", "202122232425262728292a2b2c2d2e2f",
      "d2a1f0e051ea5f62081a7792073d593d", "1fc64fbfaccd", 6, "SP800-38C C.2" },
    { "101112131415161718191a1b", "000102030405060708090a0b0c0d0e0f10111213",
      "202122232425262728292a2b2c2d2e2f3031323334353637",
      "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5", "484392fbc1b09951", 8, "SP800-38C C.3" },
};

static void test_ccm(void)
{
    static const WCHAR ccm_name[] = L"ChainingModeCCM";
    UCHAR key[16], nonce[16], aad[32], pt[64], ct[64], tag[16], out[64];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE k;
    NTSTATUS status;
    ULONG i, size, nl, al, pl;
    UCHAR mode[64];

    for (i = 0; i < 16; i++) key[i] = 0x40 + i;
    k = make_aes_key(ccm_name, key, 16, &alg);
    if (!k) return;

    status = BCryptGetProperty(alg, BCRYPT_CHAINING_MODE, mode, sizeof(mode), &size, 0);
    ok(status == S_OK_ && !lstrcmpW((WCHAR *)mode, BCRYPT_CHAIN_MODE_CCM), "chaining mode: 0x%08lx\n", (unsigned long)status);

    for (i = 0; i < sizeof(ccm_kat) / sizeof(ccm_kat[0]); i++)
    {
        nl = unhex(ccm_kat[i].nonce, nonce);
        al = unhex(ccm_kat[i].aad, aad);
        pl = unhex(ccm_kat[i].pt, pt);
        unhex(ccm_kat[i].ct, ct);

        init_auth(&info, nonce, nl, aad, al, tag, ccm_kat[i].tag_len);
        memset(out, 0xAA, sizeof(out));
        memset(tag, 0xAA, sizeof(tag));
        status = BCryptEncrypt(k, pt, pl, &info, NULL, 0, out, pl, &size, 0);
        ok(status == S_OK_ && size == pl, "%s encrypt 0x%08lx %lu\n", ccm_kat[i].source, (unsigned long)status, size);
        expect_hex(ccm_kat[i].source, out, pl, ccm_kat[i].ct);
        expect_hex(ccm_kat[i].source, tag, ccm_kat[i].tag_len, ccm_kat[i].tag);

        /* decrypt in place */
        memcpy(out, ct, pl);
        unhex(ccm_kat[i].tag, tag);
        init_auth(&info, nonce, nl, aad, al, tag, ccm_kat[i].tag_len);
        status = BCryptDecrypt(k, out, pl, &info, NULL, 0, out, pl, &size, 0);
        ok(status == S_OK_, "%s decrypt 0x%08lx\n", ccm_kat[i].source, (unsigned long)status);
        expect_hex(ccm_kat[i].source, out, pl, ccm_kat[i].pt);

        /* a changed tag, ciphertext or associated data is refused */
        unhex(ccm_kat[i].tag, tag);
        tag[0] ^= 1;
        init_auth(&info, nonce, nl, aad, al, tag, ccm_kat[i].tag_len);
        status = BCryptDecrypt(k, ct, pl, &info, NULL, 0, out, pl, &size, 0);
        ok(status == S_AUTH_TAG_MISMATCH, "%s tampered tag 0x%08lx\n", ccm_kat[i].source, (unsigned long)status);
        unhex(ccm_kat[i].tag, tag);
        aad[0] ^= 1;
        init_auth(&info, nonce, nl, aad, al, tag, ccm_kat[i].tag_len);
        status = BCryptDecrypt(k, ct, pl, &info, NULL, 0, out, pl, &size, 0);
        ok(status == S_AUTH_TAG_MISMATCH, "%s tampered aad 0x%08lx\n", ccm_kat[i].source, (unsigned long)status);
    }

    /* SMB 3 style: 11 byte nonce, 16 byte tag, 32 bytes of associated data (independent implementation) */
    for (i = 0; i < 11; i++) nonce[i] = i;
    for (i = 0; i < 32; i++) aad[i] = 0x80 + i;
    for (i = 0; i < 40; i++) pt[i] = i;
    for (i = 0; i < 16; i++) key[i] = i + 1;
    BCryptDestroyKey(k);
    status = BCryptGenerateSymmetricKey(alg, &k, NULL, 0, key, 16, 0);
    ok(status == S_OK_, "key 0x%08lx\n", (unsigned long)status);
    init_auth(&info, nonce, 11, aad, 32, tag, 16);
    status = BCryptEncrypt(k, pt, 40, &info, NULL, 0, out, 40, &size, 0);
    ok(status == S_OK_, "smb style encrypt 0x%08lx\n", (unsigned long)status);
    expect_hex("CCM 11/16", out, 40, "94b44c6edbaa66d9854bc38be3bad4af80446819af79d0a4a182301a6ade678c5fe7c52bf0ccc363");
    expect_hex("CCM 11/16 tag", tag, 16, "890c6d27a062ea33b9720ce216a93412");

    /* the key can change its mode and back: CBC reads and writes what it did before */
    {
        static const WCHAR cbc[] = L"ChainingModeCBC";
        UCHAR iv[16] = {0}, block[16] = {0}, enc1[16], enc2[16];

        status = BCryptSetProperty(k, BCRYPT_CHAINING_MODE, (UCHAR *)cbc, sizeof(cbc), 0);
        ok(status == S_OK_, "to CBC 0x%08lx\n", (unsigned long)status);
        status = BCryptEncrypt(k, block, 16, NULL, iv, 16, enc1, 16, &size, 0);
        ok(status == S_OK_, "CBC encrypt 0x%08lx\n", (unsigned long)status);
        status = BCryptSetProperty(k, BCRYPT_CHAINING_MODE, (UCHAR *)ccm_name, sizeof(ccm_name), 0);
        ok(status == S_OK_, "to CCM 0x%08lx\n", (unsigned long)status);
        init_auth(&info, nonce, 11, aad, 32, tag, 16);
        status = BCryptEncrypt(k, pt, 40, &info, NULL, 0, out, 40, &size, 0);
        ok(status == S_OK_, "CCM again 0x%08lx\n", (unsigned long)status);
        expect_hex("CCM after a mode change", out, 40, "94b44c6edbaa66d9854bc38be3bad4af80446819af79d0a4a182301a6ade678c5fe7c52bf0ccc363");
        memset(iv, 0, 16);
        status = BCryptSetProperty(k, BCRYPT_CHAINING_MODE, (UCHAR *)cbc, sizeof(cbc), 0);
        BCryptEncrypt(k, block, 16, NULL, iv, 16, enc2, 16, &size, 0);
        ok(!memcmp(enc1, enc2, 16), "CBC changed with the mode switches\n");
    }
    BCryptSetProperty(k, BCRYPT_CHAINING_MODE, (UCHAR *)ccm_name, sizeof(ccm_name), 0);

    /* VERIFY ON ORACLE: properties, bad parameters, chained calls */
    {
        BCRYPT_AUTH_TAG_LENGTHS_STRUCT tl;

        memset(&tl, 0, sizeof(tl));
        status = BCryptGetProperty(alg, BCRYPT_AUTH_TAG_LENGTH, (UCHAR *)&tl, sizeof(tl), &size, 0);
        NT_ORACLE("CCM tag length property", status, S_OK_);
        ok(tl.dwMinLength == 4 && tl.dwMaxLength == 16 && tl.dwIncrement == 2, "CCM tag lengths %lu %lu %lu\n",
           tl.dwMinLength, tl.dwMaxLength, tl.dwIncrement);
    }
    init_auth(&info, nonce, 6, aad, 32, tag, 16);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("CCM, 6 byte nonce", status, S_INVALID_PARAMETER);
    init_auth(&info, nonce, 14, aad, 32, tag, 16);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("CCM, 14 byte nonce", status, S_INVALID_PARAMETER);
    init_auth(&info, nonce, 11, aad, 32, tag, 5);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("CCM, 5 byte tag", status, S_INVALID_PARAMETER);
    init_auth(&info, nonce, 11, aad, 32, tag, 18);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("CCM, 18 byte tag", status, S_INVALID_PARAMETER);
    init_auth(&info, nonce, 11, aad, 32, tag, 16);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 15, &size, 0);
    NT_ORACLE("CCM, output too small", status, S_BUFFER_TOO_SMALL);
    status = BCryptEncrypt(k, pt, 16, NULL, NULL, 0, out, 16, &size, 0);
    NT_ORACLE("CCM, no mode info", status, S_INVALID_PARAMETER);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 16, &size, BCRYPT_BLOCK_PADDING);
    NT_ORACLE("CCM, block padding", status, S_BUFFER_TOO_SMALL);
    ok(size == 32, "CCM padded size %lu\n", size);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, NULL, 0, &size, BCRYPT_BLOCK_PADDING);
    NT_ORACLE("CCM, block padding, size query", status, S_OK_);
    status = BCryptEncrypt(k, pt, 16, &info, NULL, 0, out, 64, &size, BCRYPT_BLOCK_PADDING);
    NT_ORACLE("CCM, block padding, 64 byte output", status, S_INVALID_PARAMETER);
    status = BCryptDecrypt(k, pt, 32, &info, NULL, 0, out, 64, &size, BCRYPT_BLOCK_PADDING);
    NT_ORACLE("CCM decrypt, block padding", status, S_INVALID_PARAMETER);

    /* CCM cannot be chained: about 62000 combinations of the members of a first call were tried on Windows Server 2022 and none
     * was accepted with an output buffer. The input length is checked against the block size first when a pbMacContext is given. */
    {
        UCHAR mac[64], iv[16];
        ULONG fl[3] = { BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG, BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG,
                        BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG | BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG };
        ULONG f, m;

        memset(mac, 0, sizeof(mac));
        memset(iv, 0, sizeof(iv));
        for (f = 0; f < 3; f++) for (m = 0; m < 2; m++)
        {
            char what[80];

            init_auth(&info, nonce, 11, aad, 32, tag, 16);
            info.dwFlags = fl[f];
            if (m) { info.pbMacContext = mac; info.cbMacContext = sizeof(mac); }
            status = BCryptEncrypt(k, pt, 16, &info, iv, 16, out, 16, &size, 0);
            sprintf(what, "CCM chain flags %lu, 16 bytes, macctx %lu", fl[f], m);
            NT_ORACLE(what, status, S_INVALID_PARAMETER);
            status = BCryptEncrypt(k, pt, 12, &info, iv, 16, out, 16, &size, 0);
            sprintf(what, "CCM chain flags %lu, 12 bytes, macctx %lu", fl[f], m);
            NT_ORACLE(what, status, (m && (fl[f] & BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG)) ? S_INVALID_BUFFER_SIZE : S_INVALID_PARAMETER);
            status = BCryptEncrypt(k, pt, 16, &info, iv, 16, NULL, 0, &size, 0);
            sprintf(what, "CCM chain flags %lu, size query, macctx %lu", fl[f], m);
            NT_ORACLE(what, status, S_OK_);
        }
    }

    BCryptDestroyKey(k);
    BCryptCloseAlgorithmProvider(alg, 0);
}

/* ---------------------------------------------------------------- SP800-108 counter KDF */

typedef struct
{
    const char *Key;
    const char *Label;      /* hex: it includes the terminating zero the specification shows */
    const char *Context;    /* hex */
    const char *Out;
    const char *Source;
} KDF_KAT;

#define PREAUTH_1 "0dd13628cc3ed218ef9df9772d436d0887ab9814bfae63a80aa845f36909db7928622dddad522d9751640a459762c5a9d6bb084cbb3ce6bdadef5d5bce3c6c01"
#define PREAUTH_2 "ea3bf912b11cbfec5b1889e8209614218687f82fa5294521ad3063425e49e88a10bd022124ce25123bc9111f52d9566ba88bf46344e6063dc5e3ff0389026f6c"

/* "SMB2AESCMAC\0" = 534d42324145534341 4d414300, "SmbSign\0" = 536d625369676e00, "SMB2AESCCM\0", "ServerIn \0", "ServerOut\0",
 * "SMB2APP\0", "SmbRpc\0" */
#define L_SIGN30 "534d4232414553434d414300"
#define C_SIGN30 "536d625369676e00"
#define L_CCM30  "534d423241455343434d00"
#define C_SRVIN  "536572766572496e2000"
#define C_SRVOUT "5365727665724f757400"

static const KDF_KAT kdf_ms[] =
{
    { "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, "0b7e9c5cac36c0f6ea9ab275298cedce", "MS blog, SMB 3.0 SigningKey" },
    { "7cd451825d0450d235424e44ba6e78cc", L_CCM30, C_SRVIN,  "fad27796665b313ebb578f388632b4f7", "MS blog, SMB 3.0 EncryptionKey (client)" },
    { "7cd451825d0450d235424e44ba6e78cc", L_CCM30, C_SRVOUT, "b0f0427f7ceb416d1d9dcc0cd4f99447", "MS blog, SMB 3.0 DecryptionKey (client)" },
    { "4e01a2b313bcf660cc250bef021aede6", L_SIGN30, C_SIGN30, "ba1a17dbbfec349bca105563d598952f", "MS blog, SMB 3.0 channel SigningKey" },
};

static void derive(BCRYPT_ALG_HANDLE alg, const char *keyhex, const char *label, const char *ctx, const WCHAR *hash,
                   ULONG out_len, UCHAR *out, NTSTATUS *pstatus)
{
    UCHAR key[64], lab[64], con[128];
    BCryptBuffer bufs[3];
    BCryptBufferDesc desc;
    BCRYPT_KEY_HANDLE k;
    ULONG klen = unhex(keyhex, key), ll = label ? unhex(label, lab) : 0, cl = ctx ? unhex(ctx, con) : 0, n = 0, got = 0;
    NTSTATUS status;

    status = BCryptGenerateSymmetricKey(alg, &k, NULL, 0, key, klen, 0);
    if (status) { *pstatus = status; return; }
    if (hash)
    {
        bufs[n].BufferType = KDF_HASH_ALGORITHM; bufs[n].pvBuffer = (PVOID)hash;
        bufs[n].cbBuffer = (ULONG)((lstrlenW(hash) + 1) * sizeof(WCHAR)); n++;
    }
    if (label) { bufs[n].BufferType = KDF_LABEL; bufs[n].pvBuffer = lab; bufs[n].cbBuffer = ll; n++; }
    if (ctx) { bufs[n].BufferType = KDF_CONTEXT; bufs[n].pvBuffer = con; bufs[n].cbBuffer = cl; n++; }
    desc.ulVersion = BCRYPTBUFFER_VERSION;
    desc.cBuffers = n;
    desc.pBuffers = bufs;
    status = BCryptKeyDerivation(k, &desc, out, out_len, &got, 0);
    if (!status) ok(got == out_len, "derived %lu bytes, asked %lu\n", got, out_len);
    BCryptDestroyKey(k);
    *pstatus = status;
}

static void test_kdf(void)
{
    BCRYPT_ALG_HANDLE alg;
    UCHAR out[128], again[128];
    NTSTATUS status;
    ULONG i;
    char label[64], ctx[160];

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SP800108_CTR_HMAC_ALGORITHM, NULL, 0);
    ok(status == S_OK_, "SP800_108_CTR_HMAC provider 0x%08lx\n", (unsigned long)status);
    if (status) return;

    for (i = 0; i < sizeof(kdf_ms) / sizeof(kdf_ms[0]); i++)
    {
        memset(out, 0xAA, sizeof(out));
        derive(alg, kdf_ms[i].Key, kdf_ms[i].Label, kdf_ms[i].Context, BCRYPT_SHA256_ALGORITHM, 16, out, &status);
        ok(status == S_OK_, "%s: 0x%08lx\n", kdf_ms[i].Source, (unsigned long)status);
        expect_hex(kdf_ms[i].Source, out, 16, kdf_ms[i].Out);
    }

    /* SMB 3.1.1: the pre-authentication hash is the context. Labels as text, with the zero (see the blog) */
    {
        static const struct { const char *key, *pre, *text, *out, *what; } k311[] =
        {
            { "270e1ba896585eeb7af3472d3b4c75a7", PREAUTH_1, "SMBSigningKey", "73fe7a9a77bef0bde49c650d8ccb5f76", "SigningKey" },
            { "270e1ba896585eeb7af3472d3b4c75a7", PREAUTH_1, "SMBC2SCipherKey", "629bcbc54422a0f572b97f45989b6073", "EncryptionKey" },
            { "270e1ba896585eeb7af3472d3b4c75a7", PREAUTH_1, "SMBS2CCipherKey", "e2af0dcefac68da71a0dfbd0d1350d74", "DecryptionKey" },
            { "270e1ba896585eeb7af3472d3b4c75a7", PREAUTH_1, "SMBAppKey", "6d7ad7954e9ec61e907b4d473dc178ff", "ApplicationKey" },
            { "84b9dbb730116a8fa6e9889555c265f9", PREAUTH_2, "SMBSigningKey", "c962bca1a9dd1697b030644199705431", "channel SigningKey" },
        };
        for (i = 0; i < sizeof(k311) / sizeof(k311[0]); i++)
        {
            ULONG j, n = (ULONG)lstrlenA(k311[i].text);

            for (j = 0; j < n; j++) sprintf(label + 2 * j, "%02x", (UCHAR)k311[i].text[j]);
            lstrcpyA(label + 2 * n, "00");
            lstrcpyA(ctx, k311[i].pre);
            memset(out, 0xAA, sizeof(out));
            derive(alg, k311[i].key, label, ctx, BCRYPT_SHA256_ALGORITHM, 16, out, &status);
            ok(status == S_OK_, "SMB 3.1.1 %s: 0x%08lx\n", k311[i].what, (unsigned long)status);
            expect_hex(k311[i].what, out, 16, k311[i].out);
        }
    }

    /* the application key of SMB 3.0 (the blog's session key above): label "SMB2APP\0", context "SmbRpc\0" */
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", "534d423241505000", "536d62527063" "00", BCRYPT_SHA256_ALGORITHM, 16, out, &status);
    ok(status == S_OK_, "application key 0x%08lx\n", (unsigned long)status);
    expect_hex("MS blog, SMB 3.0 ApplicationKey", out, 16, "bb23a4575aa26c721af525af15a87b4f");

    /* Longer outputs and other hashes, from the HMAC counter construction of SP 800-108 section 5.1 with an
     * independent implementation (Python hmac/hashlib): key 000102..0f, label "label\0"-less "KDFtest", context "ctx" */
    {
        static const struct { const WCHAR *hash; ULONG len; const char *out; } hv[] =
        {
            { BCRYPT_SHA256_ALGORITHM, 48, "806560dfec43c887b95677b6f704b6e0672ced982cdbb6ab0bec22783589cd77ad3ae3d077f3b08e162bc6cf84bb72c5" },
            { BCRYPT_SHA384_ALGORITHM, 40, "bf624fc904176c690a1aa426c0a50bc1ec01b23c3a64e07429318e1ee4c1952ee7eb34335c8a2c11" },
            { BCRYPT_SHA512_ALGORITHM, 100, "1d88ae2092553331353f14019a70b5b6c4b1339440df386b97df010f38dc7f4d30dac22e320b88a3443ab88e851285ec02efe5a251ed4b1b1b732d1cec3cabee6ca40943dc54cabb253ca570145c56336ba38043910c2312de7fd9634933904f3850e100" },
            { BCRYPT_SHA1_ALGORITHM, 30, "079339046c9aa5d4bf55fa50011540a4eae7bb2c37b4e9a2dd0b96c2655b" },
            /* HMAC-MD5 and AES-CMAC as the PRF (Windows takes both; the values are from the same Python construction and equal
             * what Windows Server 2022 derives) */
            { BCRYPT_MD5_ALGORITHM, 40, "8fe39bc04cdf18e20f064557b1c9b45a69c73cae8f46e9431e206d635ca84ffb169c40fcce77e749" },
            { BCRYPT_AES_CMAC_ALGORITHM, 40, "00d65c11fccefbee73bf1a57d7fbf5ee9d1cfa274498d92ac6716826934e01cf75a8233884667d30" },
        };
        for (i = 0; i < sizeof(hv) / sizeof(hv[0]); i++)
        {
            memset(out, 0xAA, sizeof(out));
            derive(alg, "000102030405060708090a0b0c0d0e0f", "4b44467465737400", "63747800", hv[i].hash, hv[i].len, out, &status);
            ok(status == S_OK_, "%ls %lu bytes 0x%08lx\n", hv[i].hash, hv[i].len, (unsigned long)status);
            expect_hex("KDF (independent implementation)", out, hv[i].len, hv[i].out);
        }
        derive(alg, "000102030405060708090a0b0c0d0e0f", "4b44467465737400", "63747800", BCRYPT_SHA256_ALGORITHM, 48, again, &status);
        derive(alg, "000102030405060708090a0b0c0d0e0f", "4b44467465737400", "63747800", BCRYPT_SHA256_ALGORITHM, 48, out, &status);
        ok(!memcmp(out, again, 48), "not deterministic\n");
    }

    /* VERIFY ON ORACLE */
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, NULL, 16, out, &status);
    NT_ORACLE("KDF, no hash buffer", status, S_OK_);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, L"MD5", 16, out, &status);
    NT_ORACLE("KDF, hash MD5", status, S_OK_);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, L"NOSUCHHASH", 16, out, &status);
    NT_ORACLE("KDF, unknown hash", status, S_NOT_SUPPORTED);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, L"", 16, out, &status);
    NT_ORACLE("KDF, empty hash name", status, S_NOT_SUPPORTED);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, L"sha256", 16, out, &status);
    NT_ORACLE("KDF, lower case hash name", status, S_NOT_SUPPORTED);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, L"RSA", 16, out, &status);
    NT_ORACLE("KDF, hash name of another kind", status, S_NOT_SUPPORTED);
    derive(alg, "000102030405060708090a0b0c0d0e", L_SIGN30, C_SIGN30, BCRYPT_AES_CMAC_ALGORITHM, 16, out, &status);
    NT_ORACLE("KDF, AES-CMAC with a key of 15 bytes", status, S_INVALID_PARAMETER);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", L_SIGN30, C_SIGN30, BCRYPT_SHA256_ALGORITHM, 0, out, &status);
    NT_ORACLE("KDF, zero output length", status, S_INVALID_PARAMETER);
    derive(alg, "7cd451825d0450d235424e44ba6e78cc", NULL, NULL, BCRYPT_SHA256_ALGORITHM, 16, out, &status);
    NT_ORACLE("KDF, no label and no context", status, S_OK_);

    {
        BCRYPT_KEY_LENGTHS_STRUCT kl;
        ULONG size, len = 0;

        memset(&kl, 0, sizeof(kl));
        status = BCryptGetProperty(alg, BCRYPT_KEY_LENGTHS, (UCHAR *)&kl, sizeof(kl), &size, 0);
        NT_ORACLE("KDF key lengths property", status, S_OK_);
        status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (UCHAR *)&len, sizeof(len), &size, 0);
        NT_ORACLE("KDF object length property", status, S_OK_);
    }

    BCryptCloseAlgorithmProvider(alg, 0);
}

START_TEST(BCryptMacCcmKdf)
{
    STAGE("AES-CMAC");
    test_cmac();
    STAGE("AES-GCM, AES-GMAC");
    test_gcm_gmac();
    STAGE("AES-CCM");
    test_ccm();
    STAGE("SP800-108");
    test_kdf();
}

#ifdef WINREF_PROBE
int main(void)
{
    func_BCryptMacCcmKdf();
    printf("done, %d check failures\n", g_Failures);
    return 0;
}
#endif
