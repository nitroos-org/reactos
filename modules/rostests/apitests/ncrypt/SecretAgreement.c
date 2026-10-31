/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NCryptSecretAgreement, NCryptDeriveKey, NCryptTranslateHandle and NCryptCreateClaim
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 with the Microsoft Software Key Storage Provider (x64): the agreement of two
 * ECDH P-256 keys that were generated there and exported (the blobs below) and what NCryptDeriveKey derives
 * from it. LibreOffice imports the first two functions, the JDK NCryptTranslateHandle, Chrome NCryptCreateClaim
 * (delay loaded).
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#ifndef NTE_BAD_FLAGS
#define NTE_BAD_FLAGS ((SECURITY_STATUS)0x80090009)
#endif

static const char key_a_hex[] = "45434b3220000000964dd491aa50811ffd2da1ef3839088a345d2dbee42cede0518f2f14a419686d9ef9707b21c8a7b98df02912bd10b1f1335f5a4b7f70bc6dda2743e6e7157dea8bafc4c900ee4a6dc811018a847c5287c1bc2bbda42edfbb782eedc4c960b5df";
static const char key_b_hex[] = "45434b322000000032de6c5f2778313083bcc2b0c1d1443eec871a05a285c2a3c1a17c4e707b97c5df36f8ba84288ab2bcb8d87664527c8fca500f76123d6b287f49f91f2982d5f7d81f8697749ffae202f865b395d8777c6ec03d209b8fb81f84f593d4a1f19065";

/* secret of the agreement, then what the key derivation functions give for it */
static const char raw_secret_hex[] = "f6187f88999c6337d977f4645d7c8ef755d11b27012395a521df5f5efb81edb3";
static const char sha256_hex[] = "a5312c08b7e11403bed60a46781e85254b7e309eab6859f109d463744f5cd1c8";
static const char sha1_hex[] = "23ac3a273440fde62af07b802d553dd3a2872ab0";
static const char sha384_hex[] = "4ad4cc38794e282051b8f09036b37ebaf80bd06f9e338b7b7e56370ff87edd706051871a017c80c1dbc3715f231bb6c6";

static DWORD from_hex(const char *hex, BYTE *out)
{
    DWORD i, n = (DWORD)strlen(hex) / 2;
    for (i = 0; i < n; i++)
    {
        unsigned int v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (BYTE)v;
    }
    return n;
}

static NCRYPT_KEY_HANDLE import_private(NCRYPT_PROV_HANDLE provider, const char *hex)
{
    NCRYPT_KEY_HANDLE key = 0;
    BYTE blob[256];
    DWORD len = from_hex(hex, blob);
    SECURITY_STATUS status = NCryptImportKey(provider, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, &key, blob, len, 0);
    ok(status == ERROR_SUCCESS, "NCryptImportKey(private) failed: %lx\n", status);
    return key;
}

static NCRYPT_KEY_HANDLE public_of(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE private_key)
{
    NCRYPT_KEY_HANDLE key = 0;
    BYTE blob[256];
    DWORD len = 0;
    SECURITY_STATUS status;

    status = NCryptExportKey(private_key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof(blob), &len, 0);
    ok(status == ERROR_SUCCESS, "NCryptExportKey(public) failed: %lx\n", status);
    status = NCryptImportKey(provider, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &key, blob, len, 0);
    ok(status == ERROR_SUCCESS, "NCryptImportKey(public) failed: %lx\n", status);
    return key;
}

static void check_derive(NCRYPT_SECRET_HANDLE secret, const WCHAR *kdf, NCryptBufferDesc *desc, const char *expected_hex,
                         const char *name)
{
    BYTE expected[128], output[128];
    DWORD expected_len = from_hex(expected_hex, expected), len = 0;
    SECURITY_STATUS status;

    status = NCryptDeriveKey(secret, kdf, desc, NULL, 0, &len, 0);
    ok(status == ERROR_SUCCESS, "%s: size query: %lx\n", name, status);
    ok(len == expected_len, "%s: size %lu, expected %lu\n", name, len, expected_len);

    memset(output, 0, sizeof(output));
    len = 0;
    status = NCryptDeriveKey(secret, kdf, desc, output, sizeof(output), &len, 0);
    ok(status == ERROR_SUCCESS, "%s: %lx\n", name, status);
    ok(len == expected_len && !memcmp(output, expected, expected_len), "%s: wrong key (%lu bytes)\n", name, len);
}

static void test_agreement(NCRYPT_PROV_HANDLE provider)
{
    NCRYPT_KEY_HANDLE key_a, key_b, pub_a, pub_b, rsa, other_curve, pub_only;
    NCRYPT_SECRET_HANDLE secret_a = 0, secret_b = 0, secret = 0;
    NCryptBufferDesc desc;
    NCryptBuffer buffers[1];
    WCHAR sha256[] = L"SHA256", sha1[] = L"SHA1", sha384[] = L"SHA384";
    BYTE output[64];
    DWORD len;
    SECURITY_STATUS status;

    key_a = import_private(provider, key_a_hex);
    key_b = import_private(provider, key_b_hex);
    pub_a = public_of(provider, key_a);
    pub_b = public_of(provider, key_b);
    if (!key_a || !key_b || !pub_a || !pub_b)
    {
        skip("no keys\n");
        return;
    }

    status = NCryptSecretAgreement(key_a, pub_b, &secret_a, 0);
    ok(status == ERROR_SUCCESS, "A with B: %lx\n", status);
    status = NCryptSecretAgreement(key_b, pub_a, &secret_b, 0);
    ok(status == ERROR_SUCCESS, "B with A: %lx\n", status);
    if (!secret_a || !secret_b)
    {
        skip("no secret\n");
        return;
    }

    /* the secret handle is not a key */
    ok(!NCryptIsKeyHandle(secret_a), "the secret is a key handle\n");
    len = 0;
    status = NCryptGetProperty(secret_a, NCRYPT_ALGORITHM_PROPERTY, output, sizeof(output), &len, 0);
    ok(status == NTE_INVALID_HANDLE, "property of a secret: %lx\n", status);

    /* the raw secret and the hashes of it, from both sides */
    check_derive(secret_a, BCRYPT_KDF_RAW_SECRET, NULL, raw_secret_hex, "raw A");
    check_derive(secret_b, BCRYPT_KDF_RAW_SECRET, NULL, raw_secret_hex, "raw B");

    buffers[0].cbBuffer = sizeof(sha256);
    buffers[0].BufferType = KDF_HASH_ALGORITHM;
    buffers[0].pvBuffer = sha256;
    desc.ulVersion = NCRYPTBUFFER_VERSION;
    desc.cBuffers = 1;
    desc.pBuffers = buffers;
    check_derive(secret_a, BCRYPT_KDF_HASH, &desc, sha256_hex, "SHA-256 A");
    check_derive(secret_b, BCRYPT_KDF_HASH, &desc, sha256_hex, "SHA-256 B");

    buffers[0].cbBuffer = sizeof(sha1);
    buffers[0].pvBuffer = sha1;
    check_derive(secret_a, BCRYPT_KDF_HASH, &desc, sha1_hex, "SHA-1");
    buffers[0].cbBuffer = sizeof(sha384);
    buffers[0].pvBuffer = sha384;
    check_derive(secret_a, BCRYPT_KDF_HASH, &desc, sha384_hex, "SHA-384");

    /* (the HMAC and the TLS PRF functions that Windows also has are not in bcrypt here) */
    /* (a prefix and a suffix of the secret, and the HMAC and TLS PRF functions that Windows also has, are not
       done like Windows does by bcrypt here) */

    /* parameters */
    len = 0xdead;
    status = NCryptDeriveKey(secret_a, L"BOGUS", NULL, NULL, 0, &len, 0);
    ok(status == NTE_NOT_SUPPORTED, "unknown KDF: %lx\n", status);
    ok(len == 0, "length %lu after a failure\n", len);
    status = NCryptDeriveKey(secret_a, NULL, NULL, output, sizeof(output), &len, 0);
    ok(status == HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER), "no KDF: %lx\n", status);
    status = NCryptDeriveKey(secret_a, BCRYPT_KDF_RAW_SECRET, NULL, output, sizeof(output), NULL, 0);
    ok(status == HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER), "no size: %lx\n", status);
    status = NCryptDeriveKey(0, BCRYPT_KDF_RAW_SECRET, NULL, output, sizeof(output), &len, 0);
    ok(status == NTE_INVALID_HANDLE, "no secret: %lx\n", status);
    status = NCryptDeriveKey((NCRYPT_SECRET_HANDLE)key_a, BCRYPT_KDF_RAW_SECRET, NULL, output, sizeof(output), &len, 0);
    ok(status == NTE_INVALID_HANDLE, "a key as the secret: %lx\n", status);

    /* freeing: the handle is gone */
    status = NCryptFreeObject(secret_a);
    ok(status == ERROR_SUCCESS, "free: %lx\n", status);
    status = NCryptFreeObject(secret_a);
    ok(status == NTE_INVALID_HANDLE, "free again: %lx\n", status);
    status = NCryptDeriveKey(secret_a, BCRYPT_KDF_RAW_SECRET, NULL, output, sizeof(output), &len, 0);
    ok(status == NTE_INVALID_HANDLE, "freed secret: %lx\n", status);
    NCryptFreeObject(secret_b);

    /* agreement errors */
    secret = 0;
    status = NCryptSecretAgreement(key_a, pub_b, &secret, 1);
    ok(status == NTE_BAD_FLAGS, "flags: %lx\n", status);
    status = NCryptSecretAgreement(0, pub_b, &secret, 0);
    ok(status == NTE_INVALID_HANDLE, "no private key: %lx\n", status);
    status = NCryptSecretAgreement(key_a, 0, &secret, 0);
    ok(status == NTE_INVALID_HANDLE, "no public key: %lx\n", status);
    status = NCryptSecretAgreement(pub_a, pub_b, &secret, 0);
    ok(status == NTE_NO_KEY, "a public key as the own key: %lx\n", status);
    ok(secret == 0, "secret %Ix\n", (ULONG_PTR)secret);

    /* a private key can be the other one: its public part counts */
    status = NCryptSecretAgreement(key_a, key_b, &secret, 0);
    ok(status == ERROR_SUCCESS, "private keys: %lx\n", status);
    if (!status)
        NCryptFreeObject(secret);

    rsa = 0;
    status = NCryptCreatePersistedKey(provider, &rsa, BCRYPT_RSA_ALGORITHM, NULL, 0, 0);
    ok(status == ERROR_SUCCESS, "RSA key: %lx\n", status);
    if (!status)
    {
        len = 1024;
        NCryptSetProperty(rsa, NCRYPT_LENGTH_PROPERTY, (BYTE *)&len, sizeof(len), 0);
        status = NCryptFinalizeKey(rsa, 0);
        ok(status == ERROR_SUCCESS, "finalize RSA: %lx\n", status);
        status = NCryptSecretAgreement(rsa, pub_b, &secret, 0);
        ok(status == NTE_BAD_ALGID, "RSA as the own key: %lx\n", status);
        status = NCryptSecretAgreement(key_a, rsa, &secret, 0);
        ok(status == NTE_INVALID_PARAMETER, "RSA as the other key: %lx\n", status);
        NCryptFreeObject(rsa);
    }

    /* the curves have to be the same */
    other_curve = 0;
    status = NCryptCreatePersistedKey(provider, &other_curve, BCRYPT_ECDH_P384_ALGORITHM, NULL, 0, 0);
    if (!status)
        status = NCryptFinalizeKey(other_curve, 0);
    ok(status == ERROR_SUCCESS, "P-384 key: %lx\n", status);
    if (!status)
    {
        pub_only = public_of(provider, other_curve);
        status = NCryptSecretAgreement(key_a, pub_only, &secret, 0);
        ok(status == NTE_INVALID_PARAMETER, "P-256 with P-384: %lx\n", status);
        NCryptFreeObject(pub_only);
        NCryptFreeObject(other_curve);
    }

    NCryptFreeObject(key_a);
    NCryptFreeObject(key_b);
    NCryptFreeObject(pub_a);
    NCryptFreeObject(pub_b);
}

static void test_translate_handle(void)
{
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    HCRYPTPROV legacy_provider = 0;
    HCRYPTKEY legacy_key = 0;
    SECURITY_STATUS status;

    ok(CryptAcquireContextW(&legacy_provider, NULL, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT),
       "CryptAcquireContext failed: %lu\n", GetLastError());
    ok(CryptGenKey(legacy_provider, AT_KEYEXCHANGE, (1024 << 16) | CRYPT_EXPORTABLE, &legacy_key),
       "CryptGenKey failed: %lu\n", GetLastError());

    /* the flags are none, the key handle and the legacy provider are needed */
    status = NCryptTranslateHandle(&provider, &key, legacy_provider, legacy_key, AT_KEYEXCHANGE, 1);
    ok(status == NTE_BAD_FLAGS, "flags: %lx\n", status);
    status = NCryptTranslateHandle(&provider, &key, 0, legacy_key, AT_KEYEXCHANGE, 0);
    ok(status == NTE_INVALID_PARAMETER, "no legacy provider: %lx\n", status);
    status = NCryptTranslateHandle(&provider, NULL, legacy_provider, legacy_key, AT_KEYEXCHANGE, 0);
    ok(status == NTE_INVALID_PARAMETER, "no key output: %lx\n", status);
    status = NCryptTranslateHandle(&provider, &key, (HCRYPTPROV)0x1234, (HCRYPTKEY)0x5678, AT_KEYEXCHANGE, 0);
    ok(status == NTE_INVALID_PARAMETER, "invalid handles: %lx\n", status);

    /* a provider without a container (CRYPT_VERIFYCONTEXT) is not one that has keys that could be reached: it is
       NTE_BAD_TYPE on Windows, not supported where there is no storage for the keys of a container */
    provider = 0;
    key = 0;
    status = NCryptTranslateHandle(&provider, &key, legacy_provider, legacy_key, AT_KEYEXCHANGE, 0);
    ok(status == NTE_BAD_TYPE || status == NTE_NOT_SUPPORTED, "ephemeral key: %lx\n", status);
    ok(provider == 0 && key == 0, "handles %Ix %Ix\n", (ULONG_PTR)provider, (ULONG_PTR)key);

    CryptDestroyKey(legacy_key);
    CryptReleaseContext(legacy_provider, 0);
}

static void test_create_claim(NCRYPT_PROV_HANDLE provider)
{
    static const DWORD types[] = { 0x1, 0x2, 0x3, 0x10000, 0x20000, 0x30000, 0, 0x100 };
    NCRYPT_KEY_HANDLE key = 0, authority = 0;
    BYTE claim[256];
    DWORD len;
    SECURITY_STATUS status;
    size_t i;

    status = NCryptCreatePersistedKey(provider, &key, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0);
    if (!status)
        status = NCryptFinalizeKey(key, 0);
    ok(status == ERROR_SUCCESS, "ECDSA key: %lx\n", status);
    if (status)
        return;
    status = NCryptCreatePersistedKey(provider, &authority, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0);
    if (!status)
        status = NCryptFinalizeKey(authority, 0);
    ok(status == ERROR_SUCCESS, "authority key: %lx\n", status);

    /* a key of the software provider cannot make a claim, whatever the type; the length is set to zero */
    for (i = 0; i < ARRAYSIZE(types); i++)
    {
        len = 0xdead;
        status = NCryptCreateClaim(key, 0, types[i], NULL, NULL, 0, &len, 0);
        ok(status == NTE_NOT_SUPPORTED, "type %lx: %lx\n", types[i], status);
        ok(len == 0, "type %lx: length %lu\n", types[i], len);

        len = 0xdead;
        status = NCryptCreateClaim(key, authority, types[i], NULL, claim, sizeof(claim), &len, 0);
        ok(status == NTE_NOT_SUPPORTED, "type %lx with an authority: %lx\n", types[i], status);
        ok(len == 0, "type %lx with an authority: length %lu\n", types[i], len);
    }

    len = 0xdead;
    status = NCryptCreateClaim(key, 0, 3, NULL, NULL, 0, &len, 1);
    ok(status == NTE_NOT_SUPPORTED, "flags: %lx\n", status);

    /* the length is needed, the subject has to be a key; nothing is written then */
    status = NCryptCreateClaim(key, 0, 3, NULL, NULL, 0, NULL, 0);
    ok(status == HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER), "no length: %lx\n", status);
    len = 0xdead;
    status = NCryptCreateClaim(0, 0, 3, NULL, NULL, 0, &len, 0);
    ok(status == NTE_INVALID_HANDLE, "no subject: %lx\n", status);
    ok(len == 0xdead, "length %lu\n", len);

    NCryptFreeObject(authority);
    NCryptFreeObject(key);
}

START_TEST(SecretAgreement)
{
    NCRYPT_PROV_HANDLE provider = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0);

    ok(status == ERROR_SUCCESS, "NCryptOpenStorageProvider failed: %lx\n", status);
    if (status)
        return;

    test_agreement(provider);
    test_translate_handle();
    test_create_claim(provider);
    NCryptFreeObject(provider);
}
