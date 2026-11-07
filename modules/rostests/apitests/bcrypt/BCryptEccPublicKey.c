/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for ECC public key blobs: a point that is not on the curve is not a key
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A public key of a peer arrives as a blob (BCRYPT_ECCPUBLIC_BLOB) and goes straight into
 * BCryptSecretAgreement or a signature check. Importing a point that is not on the curve (or the point
 * at zero) must fail, as it does on Windows; a key of this machine, exported and imported again, works.
 * "PROBE" lines give what each call returned.
 */

#include <apitest.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <bcrypt.h>

#define STATUS_INVALID_PARAMETER_VALUE ((NTSTATUS)0xC000000D)

static const struct
{
    PCWSTR Alg;
    PCWSTR Name;
    ULONG Bits;
    BOOL Ecdh;
} Curves[] =
{
    { BCRYPT_ECDH_P256_ALGORITHM,  L"ECDH P-256",  256, TRUE },
    { BCRYPT_ECDH_P384_ALGORITHM,  L"ECDH P-384",  384, TRUE },
    { BCRYPT_ECDH_P521_ALGORITHM,  L"ECDH P-521",  521, TRUE },
    { BCRYPT_ECDSA_P256_ALGORITHM, L"ECDSA P-256", 256, FALSE },
    { BCRYPT_ECDSA_P384_ALGORITHM, L"ECDSA P-384", 384, FALSE },
    { BCRYPT_ECDSA_P521_ALGORITHM, L"ECDSA P-521", 521, FALSE },
};

static NTSTATUS Import(BCRYPT_ALG_HANDLE Alg, const BYTE *Blob, ULONG Size, BCRYPT_KEY_HANDLE *Key)
{
    return BCryptImportKeyPair(Alg, NULL, BCRYPT_ECCPUBLIC_BLOB, Key, (PUCHAR)Blob, Size, 0);
}

static void TestCurve(ULONG Index)
{
    BCRYPT_ALG_HANDLE Alg;
    BCRYPT_KEY_HANDLE Own = NULL, Peer = NULL, Imported = NULL;
    BCRYPT_SECRET_HANDLE Secret = NULL;
    BCRYPT_ECCKEY_BLOB *Header;
    BYTE Blob[256], Bad[256];
    ULONG Size = 0, KeySize;
    NTSTATUS Status;
    PCWSTR Name = Curves[Index].Name;

    Status = BCryptOpenAlgorithmProvider(&Alg, Curves[Index].Alg, NULL, 0);
    ok(Status == 0, "%ls: BCryptOpenAlgorithmProvider returned %08lx\n", Name, (ULONG)Status);
    if (Status)
        return;

    Status = BCryptGenerateKeyPair(Alg, &Own, Curves[Index].Bits, 0);
    if (Status == 0)
        Status = BCryptFinalizeKeyPair(Own, 0);
    ok(Status == 0, "%ls: generating a key returned %08lx\n", Name, (ULONG)Status);
    if (Status)
        goto Done;
    Status = BCryptExportKey(Own, NULL, BCRYPT_ECCPUBLIC_BLOB, Blob, sizeof(Blob), &Size, 0);
    ok(Status == 0, "%ls: exporting the public key returned %08lx\n", Name, (ULONG)Status);
    if (Status)
        goto Done;
    Header = (BCRYPT_ECCKEY_BLOB *)Blob;
    KeySize = Header->cbKey;
    ok(Size == sizeof(*Header) + 2 * KeySize, "%ls: the blob is %lu bytes, key size %lu\n", Name, Size, KeySize);

    /* the public key of this machine's key, imported again, is a key */
    Status = Import(Alg, Blob, Size, &Imported);
    ok(Status == 0, "%ls: importing a valid public key returned %08lx\n", Name, (ULONG)Status);
    if (Imported)
        BCryptDestroyKey(Imported);
    Imported = NULL;

    /* a point that is not on the curve: the last bit of Y changed (the point is on the curve for no more
     * than one of the two values of that bit) */
    memcpy(Bad, Blob, Size);
    Bad[Size - 1] ^= 1;
    Status = Import(Alg, Bad, Size, &Imported);
    printf("PROBE %ls off-curve import status=%08lx\n", Name, (ULONG)Status);
    ok(Status == STATUS_INVALID_PARAMETER_VALUE, "%ls: importing a point that is not on the curve returned %08lx\n",
       Name, (ULONG)Status);
    if (Imported)
    {
        /* a key that was accepted must not be usable for an agreement */
        if (Curves[Index].Ecdh)
        {
            Status = BCryptSecretAgreement(Own, Imported, &Secret, 0);
            printf("PROBE %ls off-curve agreement status=%08lx\n", Name, (ULONG)Status);
            ok(Status != 0, "%ls: the agreement with a point that is not on the curve worked\n", Name);
            if (Secret)
                BCryptDestroySecret(Secret);
            Secret = NULL;
        }
        BCryptDestroyKey(Imported);
        Imported = NULL;
    }

    /* and the point at zero */
    memset(Bad + sizeof(*Header), 0, 2 * KeySize);
    Status = Import(Alg, Bad, Size, &Imported);
    printf("PROBE %ls zero point import status=%08lx\n", Name, (ULONG)Status);
    ok(Status == STATUS_INVALID_PARAMETER_VALUE, "%ls: importing the point at zero returned %08lx\n", Name, (ULONG)Status);
    if (Imported)
        BCryptDestroyKey(Imported);
    Imported = NULL;

    /* a valid peer key still agrees, both ways, on the same secret */
    if (Curves[Index].Ecdh)
    {
        BYTE One[80], Two[80];
        ULONG OneSize = 0, TwoSize = 0;
        BCRYPT_SECRET_HANDLE Other = NULL;
        BCRYPT_KEY_HANDLE PeerPublic = NULL;

        Status = BCryptGenerateKeyPair(Alg, &Peer, Curves[Index].Bits, 0);
        if (Status == 0)
            Status = BCryptFinalizeKeyPair(Peer, 0);
        ok(Status == 0, "%ls: generating the peer key returned %08lx\n", Name, (ULONG)Status);
        if (Status)
            goto Done;
        Status = BCryptSecretAgreement(Own, Peer, &Secret, 0);
        ok(Status == 0, "%ls: the agreement returned %08lx\n", Name, (ULONG)Status);
        /* the peer's public key crosses as a blob, as it does when it comes from another machine */
        Size = 0;
        Status = BCryptExportKey(Peer, NULL, BCRYPT_ECCPUBLIC_BLOB, Blob, sizeof(Blob), &Size, 0);
        ok(Status == 0, "%ls: exporting the peer key returned %08lx\n", Name, (ULONG)Status);
        Status = Import(Alg, Blob, Size, &PeerPublic);
        ok(Status == 0, "%ls: importing the peer key returned %08lx\n", Name, (ULONG)Status);
        if (PeerPublic)
        {
            Status = BCryptSecretAgreement(Own, PeerPublic, &Other, 0);
            ok(Status == 0, "%ls: the agreement with the imported peer key returned %08lx\n", Name, (ULONG)Status);
            if (Secret && Other)
            {
                Status = BCryptDeriveKey(Secret, BCRYPT_KDF_RAW_SECRET, NULL, One, sizeof(One), &OneSize, 0);
                ok(Status == 0, "%ls: deriving returned %08lx\n", Name, (ULONG)Status);
                Status = BCryptDeriveKey(Other, BCRYPT_KDF_RAW_SECRET, NULL, Two, sizeof(Two), &TwoSize, 0);
                ok(Status == 0, "%ls: deriving returned %08lx\n", Name, (ULONG)Status);
                ok(OneSize == TwoSize && OneSize != 0 && !memcmp(One, Two, OneSize),
                   "%ls: the two secrets differ (%lu, %lu bytes)\n", Name, OneSize, TwoSize);
            }
            BCryptDestroyKey(PeerPublic);
        }
        if (Other)
            BCryptDestroySecret(Other);
    }
    else
    {
        /* a signature of the key verifies with its public key imported from the blob */
        BYTE Hash[64] = { 1, 2, 3 }, Signature[160];
        ULONG SignatureSize = 0, HashSize = Curves[Index].Bits <= 256 ? 32 : 48;

        Status = BCryptSignHash(Own, NULL, Hash, HashSize, Signature, sizeof(Signature), &SignatureSize, 0);
        ok(Status == 0, "%ls: signing returned %08lx\n", Name, (ULONG)Status);
        Size = 0;
        Status = BCryptExportKey(Own, NULL, BCRYPT_ECCPUBLIC_BLOB, Blob, sizeof(Blob), &Size, 0);
        Status = Import(Alg, Blob, Size, &Imported);
        ok(Status == 0, "%ls: importing for the verification returned %08lx\n", Name, (ULONG)Status);
        if (Imported)
        {
            Status = BCryptVerifySignature(Imported, NULL, Hash, HashSize, Signature, SignatureSize, 0);
            ok(Status == 0, "%ls: verifying returned %08lx\n", Name, (ULONG)Status);
            Hash[0] ^= 1;
            Status = BCryptVerifySignature(Imported, NULL, Hash, HashSize, Signature, SignatureSize, 0);
            ok(Status != 0, "%ls: a signature verified for another hash\n", Name);
            BCryptDestroyKey(Imported);
            Imported = NULL;
        }
    }

Done:
    if (Secret)
        BCryptDestroySecret(Secret);
    if (Own)
        BCryptDestroyKey(Own);
    if (Peer)
        BCryptDestroyKey(Peer);
    BCryptCloseAlgorithmProvider(Alg, 0);
}

START_TEST(BCryptEccPublicKey)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(Curves); i++)
        TestCurve(i);
}
