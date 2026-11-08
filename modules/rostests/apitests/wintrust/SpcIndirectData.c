/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the SPC_INDIRECT_DATA_CONTENT decoder (OID 1.3.6.1.4.1.311.2.1.4)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The Authenticode content of a signed PE file or catalog is a SpcIndirectDataContent. crypt32 has no builtin
 * decoder for it: wintrust registers one (CryptDllDecodeObject, WVTAsn1SpcIndirectDataContentDecode, under
 * EncodingType 1) and CryptDecodeObjectEx falls back to it. Measured on Windows 10 22H2 (2026-11-08, x64 and x86):
 * the registration is the same, and the blob below decodes, for the OID string, for SPC_INDIRECT_DATA_CONTENT_STRUCT
 * and for the encoding type X509_ASN_ENCODING | PKCS_7_ASN_ENCODING that Office's click-to-run client passes. This
 * test checks that and a few malformed encodings (their error codes were not measured: only failure is checked).
 */

#include <apitest.h>
#include <winuser.h>
#include <wincrypt.h>
#include <wintrust.h>

/* SEQUENCE { SEQUENCE { OID SPC_PE_IMAGE_DATA, SEQUENCE {} }, SEQUENCE { SEQUENCE { OID sha1, NULL }, OCTET STRING (20) } } */
static const BYTE Blob[] =
{
    0x30, 0x33,
        0x30, 0x0E, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F, 0x30, 0x00,
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
};

static void CheckDecoded(const SPC_INDIRECT_DATA_CONTENT *c, const char *what)
{
    ok(c->Data.pszObjId && strcmp(c->Data.pszObjId, "1.3.6.1.4.1.311.2.1.15") == 0, "%s: Data.pszObjId %s\n", what,
       c->Data.pszObjId ? c->Data.pszObjId : "(null)");
    ok(c->Data.Value.cbData == 2, "%s: Data.Value.cbData %lu\n", what, c->Data.Value.cbData);
    ok(c->DigestAlgorithm.pszObjId && strcmp(c->DigestAlgorithm.pszObjId, "1.3.14.3.2.26") == 0, "%s: algorithm %s\n", what,
       c->DigestAlgorithm.pszObjId ? c->DigestAlgorithm.pszObjId : "(null)");
    ok(c->DigestAlgorithm.Parameters.cbData == 2, "%s: Parameters.cbData %lu\n", what, c->DigestAlgorithm.Parameters.cbData);
    ok(c->Digest.cbData == 20, "%s: Digest.cbData %lu\n", what, c->Digest.cbData);
    if (c->Digest.cbData == 20)
        ok(c->Digest.pbData[0] == 1 && c->Digest.pbData[19] == 20, "%s: digest bytes %u..%u\n", what, c->Digest.pbData[0],
           c->Digest.pbData[19]);
}

static void DecodeWith(DWORD enc, LPCSTR type, const char *what)
{
    SPC_INDIRECT_DATA_CONTENT *content = NULL;
    DWORD size = 0;
    BYTE *plain;
    BOOL ret;

    SetLastError(0xdeadbeef);
    ret = CryptDecodeObjectEx(enc, type, Blob, sizeof(Blob), CRYPT_DECODE_ALLOC_FLAG, NULL, &content, &size);
    ok(ret, "%s: CryptDecodeObjectEx failed, error 0x%08lx\n", what, GetLastError());
    if (ret)
    {
        ok(size >= sizeof(SPC_INDIRECT_DATA_CONTENT) + 20, "%s: size %lu\n", what, size);
        CheckDecoded(content, what);
        LocalFree(content);
    }

    /* the non-Ex entry point, with the size query first */
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptDecodeObject(enc, type, Blob, sizeof(Blob), 0, NULL, &size);
    ok(ret, "%s: CryptDecodeObject (size) failed, error 0x%08lx\n", what, GetLastError());
    if (ret && size)
    {
        plain = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        ret = CryptDecodeObject(enc, type, Blob, sizeof(Blob), 0, plain, &size);
        ok(ret, "%s: CryptDecodeObject failed, error 0x%08lx\n", what, GetLastError());
        if (ret)
            CheckDecoded((SPC_INDIRECT_DATA_CONTENT *)plain, what);
        HeapFree(GetProcessHeap(), 0, plain);
    }
}

START_TEST(SpcIndirectData)
{
    SPC_INDIRECT_DATA_CONTENT *content = NULL;
    DWORD size = 0;
    BOOL ret;
    BYTE bad[sizeof(Blob)];

    DecodeWith(X509_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, "X509, OID");
    DecodeWith(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, "X509|PKCS7, OID");
    DecodeWith(X509_ASN_ENCODING, SPC_INDIRECT_DATA_CONTENT_STRUCT, "X509, STRUCT");
    DecodeWith(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, SPC_INDIRECT_DATA_CONTENT_STRUCT, "X509|PKCS7, STRUCT");

    /* a truncated and an overlong-length encoding must not decode */
    ret = CryptDecodeObjectEx(X509_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, Blob, sizeof(Blob) - 7, CRYPT_DECODE_ALLOC_FLAG,
                              NULL, &content, &size);
    ok(!ret, "a truncated encoding decoded\n");
    if (ret)
        LocalFree(content);
    memcpy(bad, Blob, sizeof(bad));
    bad[1] = 0x7f;
    content = NULL;
    ret = CryptDecodeObjectEx(X509_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, bad, sizeof(bad), CRYPT_DECODE_ALLOC_FLAG,
                              NULL, &content, &size);
    ok(!ret, "an encoding with a wrong length decoded\n");
    if (ret)
        LocalFree(content);
    ret = CryptDecodeObjectEx(X509_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, Blob, 0, CRYPT_DECODE_ALLOC_FLAG, NULL, &content, &size);
    ok(!ret, "an empty encoding decoded\n");

    /* encode and decode again: the DER is reproduced byte for byte */
    {
        SPC_INDIRECT_DATA_CONTENT decoded;
        DWORD len = 0;
        BYTE *der = NULL;

        ret = CryptDecodeObjectEx(X509_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, Blob, sizeof(Blob), CRYPT_DECODE_ALLOC_FLAG,
                                  NULL, &content, &size);
        ok(ret, "decode failed\n");
        if (ret)
        {
            decoded = *content;
            ret = CryptEncodeObjectEx(X509_ASN_ENCODING, SPC_INDIRECT_DATA_OBJID, &decoded, CRYPT_ENCODE_ALLOC_FLAG, NULL, &der, &len);
            ok(ret, "CryptEncodeObjectEx failed, error 0x%08lx\n", GetLastError());
            if (ret)
            {
                ok(len == sizeof(Blob) && memcmp(der, Blob, sizeof(Blob)) == 0, "the re-encoded DER differs (length %lu)\n", len);
                LocalFree(der);
            }
            LocalFree(content);
        }
    }
}
