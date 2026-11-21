/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The enhanced key usage extension of the CA certificates (and the root) of a chain counts for the requested usage:
 *              a certificate that does not allow it makes itself and everything below it not valid for the usage
 *              (rows measured on Windows Server 2022). The certificates are made in memory; the chain engine has a root store of its own.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <stdio.h>

enum { E_NONE, E_EMPTY, E_SA, E_CS, E_SACS, E_ANY };

static HCRYPTPROV Prov[3];
static const char *Names[3] = { "kbRoot", "kbCA", "kbLeaf" };
static char Sa[] = szOID_PKIX_KP_SERVER_AUTH;
static char Cs[] = szOID_PKIX_KP_CODE_SIGNING;
static char Any[] = "2.5.29.37.0";

static PCCERT_CONTEXT MakeCert(int Who, int Issuer, BOOL IsCA, int Eku)
{
    CERT_INFO Ci;
    CERT_EXTENSION Ext[2];
    CRYPT_ALGORITHM_IDENTIFIER Alg;
    CERT_BASIC_CONSTRAINTS2_INFO Bc2;
    CERT_ENHKEY_USAGE Eu;
    LPSTR Oids[2];
    BYTE Serial[2], *NameBlob, *IssBlob, *PubInfo, *Bc = NULL, *Ek = NULL, *Enc;
    DWORD NameLen = 0, IssLen = 0, PubLen = 0, BcLen = 0, EkLen = 0, EncLen = 0;
    SYSTEMTIME St;
    char Subj[64];
    PCCERT_CONTEXT Ctx = NULL;
    int Ne = 0;

    Serial[0] = (BYTE)(Who + 1);
    Serial[1] = 7;
    sprintf(Subj, "CN=%s", Names[Who]);
    CertStrToNameA(X509_ASN_ENCODING, Subj, CERT_X500_NAME_STR, NULL, NULL, &NameLen, NULL);
    NameBlob = malloc(NameLen);
    CertStrToNameA(X509_ASN_ENCODING, Subj, CERT_X500_NAME_STR, NULL, NameBlob, &NameLen, NULL);
    sprintf(Subj, "CN=%s", Names[Issuer]);
    CertStrToNameA(X509_ASN_ENCODING, Subj, CERT_X500_NAME_STR, NULL, NULL, &IssLen, NULL);
    IssBlob = malloc(IssLen);
    CertStrToNameA(X509_ASN_ENCODING, Subj, CERT_X500_NAME_STR, NULL, IssBlob, &IssLen, NULL);
    CryptExportPublicKeyInfo(Prov[Who], AT_SIGNATURE, X509_ASN_ENCODING, NULL, &PubLen);
    PubInfo = malloc(PubLen);
    CryptExportPublicKeyInfo(Prov[Who], AT_SIGNATURE, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)PubInfo, &PubLen);

    memset(&Ci, 0, sizeof(Ci));
    memset(&Alg, 0, sizeof(Alg));
    Alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    Ci.dwVersion = CERT_V3;
    Ci.SerialNumber.cbData = 2;
    Ci.SerialNumber.pbData = Serial;
    Ci.SignatureAlgorithm = Alg;
    Ci.Issuer.cbData = IssLen;
    Ci.Issuer.pbData = IssBlob;
    Ci.Subject.cbData = NameLen;
    Ci.Subject.pbData = NameBlob;
    GetSystemTime(&St);
    St.wYear -= 1;
    SystemTimeToFileTime(&St, &Ci.NotBefore);
    St.wYear += 3;
    SystemTimeToFileTime(&St, &Ci.NotAfter);
    Ci.SubjectPublicKeyInfo = *(PCERT_PUBLIC_KEY_INFO)PubInfo;

    Bc2.fCA = IsCA;
    Bc2.fPathLenConstraint = FALSE;
    Bc2.dwPathLenConstraint = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, &Bc2, CRYPT_ENCODE_ALLOC_FLAG, NULL, &Bc, &BcLen);
    Ext[Ne].pszObjId = (LPSTR)szOID_BASIC_CONSTRAINTS2;
    Ext[Ne].fCritical = TRUE;
    Ext[Ne].Value.cbData = BcLen;
    Ext[Ne].Value.pbData = Bc;
    Ne++;
    if (Eku != E_NONE)
    {
        Eu.cUsageIdentifier = 0;
        Eu.rgpszUsageIdentifier = Oids;
        switch (Eku)
        {
            case E_SA: Oids[0] = Sa; Eu.cUsageIdentifier = 1; break;
            case E_CS: Oids[0] = Cs; Eu.cUsageIdentifier = 1; break;
            case E_ANY: Oids[0] = Any; Eu.cUsageIdentifier = 1; break;
            case E_SACS: Oids[0] = Sa; Oids[1] = Cs; Eu.cUsageIdentifier = 2; break;
        }
        CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &Eu, CRYPT_ENCODE_ALLOC_FLAG, NULL, &Ek, &EkLen);
        Ext[Ne].pszObjId = (LPSTR)szOID_ENHANCED_KEY_USAGE;
        Ext[Ne].fCritical = FALSE;
        Ext[Ne].Value.cbData = EkLen;
        Ext[Ne].Value.pbData = Ek;
        Ne++;
    }
    Ci.cExtension = Ne;
    Ci.rgExtension = Ext;
    CryptSignAndEncodeCertificate(Prov[Issuer], AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &Ci, &Alg, NULL, NULL, &EncLen);
    Enc = malloc(EncLen);
    if (CryptSignAndEncodeCertificate(Prov[Issuer], AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &Ci, &Alg, NULL, Enc, &EncLen))
        Ctx = CertCreateCertificateContext(X509_ASN_ENCODING, Enc, EncLen);
    free(Enc);
    free(NameBlob);
    free(IssBlob);
    free(PubInfo);
    LocalFree(Bc);
    LocalFree(Ek);
    return Ctx;
}

static const struct
{
    PCSTR Name;
    int Root, Ca, Leaf;
    char *Use;
    DWORD Chain, E0, E1, E2, Base;
} Rows[] =
{
    { "no EKU anywhere", E_NONE, E_NONE, E_SA, Sa, 0, 0, 0, 0, 0 },
    { "CA server auth", E_NONE, E_SA, E_SA, Sa, 0, 0, 0, 0, 0 },
    { "CA code signing only", E_NONE, E_CS, E_SA, Sa, 0x10, 0x10, 0x10, 0, 0x800b0110 },
    { "CA server auth + code signing", E_NONE, E_SACS, E_SA, Sa, 0, 0, 0, 0, 0 },
    { "CA anyExtendedKeyUsage", E_NONE, E_ANY, E_SA, Sa, 0, 0, 0, 0, 0 },
    { "CA empty EKU", E_NONE, E_EMPTY, E_SA, Sa, 0x10, 0x10, 0x10, 0, 0x800b0110 },
    { "root code signing only", E_CS, E_NONE, E_SA, Sa, 0x10, 0x10, 0x10, 0x10, 0x800b0110 },
    { "root server auth, CA code signing", E_SA, E_CS, E_SA, Sa, 0x10, 0x10, 0x10, 0, 0x800b0110 },
    { "end certificate code signing only", E_NONE, E_SA, E_CS, Sa, 0x10, 0x10, 0, 0, 0x800b0110 },
    { "CA and end code signing, code signing", E_NONE, E_CS, E_CS, Cs, 0, 0, 0, 0, 0 },
    { "CA server auth, end no EKU", E_NONE, E_SA, E_NONE, Sa, 0, 0, 0, 0, 0 },
    { "CA code signing only, end no EKU", E_NONE, E_CS, E_NONE, Sa, 0x10, 0x10, 0x10, 0, 0x800b0110 },
};

START_TEST(ChainCaEku)
{
    char Container[3][32];
    ULONG i;
    HCRYPTKEY Key;

    for (i = 0; i < 3; i++)
    {
        sprintf(Container[i], "ChainCaEku%lu", i);
        CryptAcquireContextA(&Prov[i], Container[i], MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        if (!CryptAcquireContextA(&Prov[i], Container[i], MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_NEWKEYSET) ||
            !CryptGenKey(Prov[i], AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &Key))
        {
            skip("Cannot make a key (%lu)\n", GetLastError());
            return;
        }
        CryptDestroyKey(Key);
    }

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        PCCERT_CONTEXT Root = MakeCert(0, 0, TRUE, Rows[i].Root), Ca = MakeCert(1, 0, TRUE, Rows[i].Ca), Leaf = MakeCert(2, 1, FALSE, Rows[i].Leaf);
        HCERTSTORE Roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL), Inter = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        CERT_CHAIN_ENGINE_CONFIG Cfg;
        HCERTCHAINENGINE Engine = NULL;
        CERT_CHAIN_PARA Para;
        PCCERT_CHAIN_CONTEXT Chain = NULL;
        CERT_CHAIN_POLICY_PARA PolicyPara;
        CERT_CHAIN_POLICY_STATUS Policy;
        LPSTR Use[1];
        DWORD Err[3] = { 0, 0, 0 }, j;

        ok(Root && Ca && Leaf, "%s: making the certificates failed\n", Rows[i].Name);
        if (!Root || !Ca || !Leaf)
            continue;
        CertAddCertificateContextToStore(Roots, Root, CERT_STORE_ADD_ALWAYS, NULL);
        CertAddCertificateContextToStore(Inter, Ca, CERT_STORE_ADD_ALWAYS, NULL);
        memset(&Cfg, 0, sizeof(Cfg));
        Cfg.cbSize = sizeof(Cfg);
        Cfg.hExclusiveRoot = Roots;
        if (!CertCreateCertificateChainEngine(&Cfg, &Engine))
        {
            ok(0, "%s: engine failed %lu\n", Rows[i].Name, GetLastError());
            continue;
        }
        memset(&Para, 0, sizeof(Para));
        Para.cbSize = sizeof(Para);
        Use[0] = Rows[i].Use;
        Para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        Para.RequestedUsage.Usage.cUsageIdentifier = 1;
        Para.RequestedUsage.Usage.rgpszUsageIdentifier = Use;
        if (!CertGetCertificateChain(Engine, Leaf, NULL, Inter, &Para, 0, NULL, &Chain))
        {
            ok(0, "%s: chain failed %lu\n", Rows[i].Name, GetLastError());
            continue;
        }
        ok(Chain->rgpChain[0]->cElement == 3, "%s: %lu elements\n", Rows[i].Name, Chain->rgpChain[0]->cElement);
        ok(Chain->TrustStatus.dwErrorStatus == Rows[i].Chain, "%s: chain status %#lx, expected %#lx\n", Rows[i].Name,
           Chain->TrustStatus.dwErrorStatus, Rows[i].Chain);
        for (j = 0; j < 3 && j < Chain->rgpChain[0]->cElement; j++)
            Err[j] = Chain->rgpChain[0]->rgpElement[j]->TrustStatus.dwErrorStatus;
        ok(Err[0] == Rows[i].E0 && Err[1] == Rows[i].E1 && Err[2] == Rows[i].E2, "%s: element status %#lx %#lx %#lx, expected %#lx %#lx %#lx\n",
           Rows[i].Name, Err[0], Err[1], Err[2], Rows[i].E0, Rows[i].E1, Rows[i].E2);
        memset(&PolicyPara, 0, sizeof(PolicyPara));
        PolicyPara.cbSize = sizeof(PolicyPara);
        memset(&Policy, 0, sizeof(Policy));
        Policy.cbSize = sizeof(Policy);
        CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, Chain, &PolicyPara, &Policy);
        ok(Policy.dwError == Rows[i].Base, "%s: base policy %#lx, expected %#lx\n", Rows[i].Name, Policy.dwError, Rows[i].Base);
        CertFreeCertificateChain(Chain);
        CertFreeCertificateChainEngine(Engine);
        CertCloseStore(Roots, 0);
        CertCloseStore(Inter, 0);
        CertFreeCertificateContext(Root);
        CertFreeCertificateContext(Ca);
        CertFreeCertificateContext(Leaf);
    }
    for (i = 0; i < 3; i++)
    {
        CryptReleaseContext(Prov[i], 0);
        CryptAcquireContextA(&Prov[i], Container[i], MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_DELETEKEYSET);
    }
}
