/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for SignerSign/SignerSignEx/SignerSignEx2, the PE SIP and catalog creation: sign, verify, tamper
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The test generates its own key and self-signed certificate (never a real key), signs a copy of this very program
 * with SHA-1 and SHA-256, verifies it with WinVerifyTrust (the certificate is not trusted: the digest and the
 * signature must be good, the chain ends in an untrusted root), flips a byte of the code and expects a bad digest, and
 * removes the signature. If CODESIGN_TEST_OUT names a directory, the signed copies and the certificate are left there
 * so that they can be checked by other tools (openssl) on the host. The values of a Windows run still have to be
 * recorded: the expectations below are from the documentation of the functions.
 */

#include <apitest.h>
#include <winuser.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <mssip.h>
#include <wine/mssign.h>
#include <imagehlp.h>

#define SIGNER_SUBJECT_FILE_VALUE 1

#ifndef CERT_E_UNTRUSTEDROOT
#define CERT_E_UNTRUSTEDROOT ((HRESULT)0x800B0109L)
#endif
#ifndef CERT_E_CHAINING
#define CERT_E_CHAINING ((HRESULT)0x800B010AL)
#endif
#ifndef TRUST_E_BAD_DIGEST
#define TRUST_E_BAD_DIGEST ((HRESULT)0x80096010L)
#endif
#ifndef TRUST_E_NOSIGNATURE
#define TRUST_E_NOSIGNATURE ((HRESULT)0x800B0100L)
#endif

typedef HRESULT (WINAPI *PFN_SignerSign)(SIGNER_SUBJECT_INFO *, SIGNER_CERT *, SIGNER_SIGNATURE_INFO *,
                                         SIGNER_PROVIDER_INFO *, LPCWSTR, PCRYPT_ATTRIBUTES, void *);
typedef HRESULT (WINAPI *PFN_SignerSignEx)(DWORD, SIGNER_SUBJECT_INFO *, SIGNER_CERT *, SIGNER_SIGNATURE_INFO *,
                                           SIGNER_PROVIDER_INFO *, LPCWSTR, PCRYPT_ATTRIBUTES, void *,
                                           SIGNER_CONTEXT **);
typedef HRESULT (WINAPI *PFN_SignerSignEx2)(DWORD, SIGNER_SUBJECT_INFO *, SIGNER_CERT *, SIGNER_SIGNATURE_INFO *,
                                            SIGNER_PROVIDER_INFO *, DWORD, PCSTR, LPCWSTR, PCRYPT_ATTRIBUTES, void *,
                                            SIGNER_CONTEXT **, void *, void *);
typedef HRESULT (WINAPI *PFN_SignerFree)(SIGNER_CONTEXT *);

static PFN_SignerSign pSignerSign;
static PFN_SignerSignEx pSignerSignEx;
static PFN_SignerSignEx2 pSignerSignEx2;
static PFN_SignerFree pSignerFreeSignerContext;

static WCHAR Container[64];
static HCRYPTPROV TestProv;
static const CERT_CONTEXT *TestCert;
static HCERTSTORE TestStore;
static WCHAR SelfPath[MAX_PATH];
static BOOL KeepOutputs;
static GUID PeSubject = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };

static BOOL MakeCertificate(void)
{
    CRYPT_KEY_PROV_INFO KeyProv = { Container, (LPWSTR)MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0, 0, NULL, AT_SIGNATURE };
    CRYPT_ALGORITHM_IDENTIFIER SigAlg = { (LPSTR)szOID_RSA_SHA256RSA, { 0, NULL } };
    CERT_NAME_BLOB Name = { 0 };
    SYSTEMTIME Start, End;
    HCRYPTKEY Key = 0;
    BOOL Ret;

    wsprintfW(Container, L"CodesignApitest%08lx", GetTickCount());
    Ret = CryptAcquireContextW(&TestProv, Container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET);
    ok(Ret, "CryptAcquireContext failed, error 0x%08lx\n", GetLastError());
    if (!Ret)
        return FALSE;
    Ret = CryptGenKey(TestProv, AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &Key);
    ok(Ret, "CryptGenKey failed, error 0x%08lx\n", GetLastError());
    if (!Ret)
        return FALSE;
    CryptDestroyKey(Key);

    Ret = CertStrToNameW(X509_ASN_ENCODING, L"CN=Codesign apitest signer", CERT_X500_NAME_STR, NULL, NULL, &Name.cbData, NULL) &&
          (Name.pbData = HeapAlloc(GetProcessHeap(), 0, Name.cbData)) &&
          CertStrToNameW(X509_ASN_ENCODING, L"CN=Codesign apitest signer", CERT_X500_NAME_STR, NULL, Name.pbData, &Name.cbData, NULL);
    ok(Ret, "CertStrToName failed, error 0x%08lx\n", GetLastError());
    if (!Ret)
        return FALSE;

    GetSystemTime(&Start);
    End = Start;
    End.wYear += 2;
    TestCert = CertCreateSelfSignCertificate(TestProv, &Name, 0, &KeyProv, &SigAlg, &Start, &End, NULL);
    ok(TestCert != NULL, "CertCreateSelfSignCertificate failed, error 0x%08lx\n", GetLastError());
    HeapFree(GetProcessHeap(), 0, Name.pbData);
    if (!TestCert)
        return FALSE;
    /* the key container is written when the context that made the key goes away: the signer opens it afresh */
    CryptReleaseContext(TestProv, 0);
    TestProv = 0;
    TestStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CertAddCertificateContextToStore(TestStore, TestCert, CERT_STORE_ADD_ALWAYS, NULL);
    return TRUE;
}

static void FreeCertificate(void)
{
    HCRYPTPROV Prov;

    if (TestCert)
        CertFreeCertificateContext(TestCert);
    if (TestStore)
        CertCloseStore(TestStore, 0);
    if (TestProv)
        CryptReleaseContext(TestProv, 0);
    CryptAcquireContextW(&Prov, Container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
}

static BOOL CopyTestFile(const WCHAR *Dest)
{
    SetFileAttributesW(Dest, FILE_ATTRIBUTE_NORMAL);
    return CopyFileW(SelfPath, Dest, FALSE);
}

static HRESULT SignFile(const WCHAR *Path, ALG_ID Alg, DWORD Flags, int Api, SIGNER_CONTEXT **Context)
{
    SIGNER_FILE_INFO FileInfo = { sizeof(FileInfo), Path, NULL };
    DWORD Index = 0xdeadbeef;
    SIGNER_SUBJECT_INFO Subject = { sizeof(Subject), &Index, SIGNER_SUBJECT_FILE_VALUE, { &FileInfo } };
    SIGNER_CERT_STORE_INFO StoreInfo = { sizeof(StoreInfo), TestCert, SIGNER_CERT_POLICY_CHAIN, TestStore };
    SIGNER_CERT Cert = { sizeof(Cert), SIGNER_CERT_STORE, { (const WCHAR *)&StoreInfo }, NULL };
    SIGNER_ATTR_AUTHCODE AuthCode = { sizeof(AuthCode), FALSE, FALSE, L"Codesign apitest", L"http://example.invalid/" };
    SIGNER_SIGNATURE_INFO Sig = { sizeof(Sig), Alg, SIGNER_AUTHCODE_ATTR, { &AuthCode }, NULL, NULL };
    HRESULT hr;

    Cert.pCertStoreInfo = &StoreInfo;
    if (Api == 0)
        hr = pSignerSign(&Subject, &Cert, &Sig, NULL, NULL, NULL, NULL);
    else if (Api == 1)
        hr = pSignerSignEx(Flags, &Subject, &Cert, &Sig, NULL, NULL, NULL, NULL, Context);
    else
        hr = pSignerSignEx2(Flags, &Subject, &Cert, &Sig, NULL, 0, NULL, NULL, NULL, NULL, Context, NULL, NULL);
    if (hr == S_OK)
        ok(Index != 0xdeadbeef, "the index of the signature was not returned\n");
    return hr;
}

static LONG Verify(const WCHAR *Path)
{
    GUID Action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO FileInfo = { sizeof(FileInfo), Path };
    WINTRUST_DATA Data = { sizeof(Data) };
    LONG Ret;

    Data.dwUIChoice = WTD_UI_NONE;
    Data.fdwRevocationChecks = WTD_REVOKE_NONE;
    Data.dwUnionChoice = WTD_CHOICE_FILE;
    Data.pFile = &FileInfo;
    Data.dwStateAction = WTD_STATEACTION_VERIFY;
    Data.dwProvFlags = WTD_SAFER_FLAG;
    Ret = WinVerifyTrust(INVALID_HANDLE_VALUE, &Action, &Data);
    Data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(INVALID_HANDLE_VALUE, &Action, &Data);
    return Ret;
}

/* The signature itself is fine when the only complaint is the root the test certificate cannot have */
static BOOL IsGoodButUntrusted(LONG Res)
{
    return Res == 0 || Res == (LONG)CERT_E_UNTRUSTEDROOT || Res == (LONG)CERT_E_CHAINING;
}

static void FlipCodeByte(const WCHAR *Path)
{
    HANDLE File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS32 Nt;
    IMAGE_SECTION_HEADER Section;
    DWORD Read, Offset = 0;
    BYTE Value;
    WORD i;

    if (File == INVALID_HANDLE_VALUE)
    {
        skip("cannot open %ls to tamper with it\n", Path);
        return;
    }
    ReadFile(File, &Dos, sizeof(Dos), &Read, NULL);
    SetFilePointer(File, Dos.e_lfanew, NULL, FILE_BEGIN);
    ReadFile(File, &Nt, sizeof(Nt), &Read, NULL);
    for (i = 0; i < Nt.FileHeader.NumberOfSections; i++)
    {
        SetFilePointer(File, Dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) +
                       Nt.FileHeader.SizeOfOptionalHeader + i * sizeof(Section), NULL, FILE_BEGIN);
        ReadFile(File, &Section, sizeof(Section), &Read, NULL);
        if (Section.SizeOfRawData >= 64)
        {
            Offset = Section.PointerToRawData + 16;
            break;
        }
    }
    ok(Offset != 0, "no section to tamper with\n");
    if (Offset)
    {
        SetFilePointer(File, Offset, NULL, FILE_BEGIN);
        ReadFile(File, &Value, 1, &Read, NULL);
        Value ^= 0x5a;
        SetFilePointer(File, Offset, NULL, FILE_BEGIN);
        WriteFile(File, &Value, 1, &Read, NULL);
    }
    CloseHandle(File);
}

/* The embedded signature as the PKCS #7 message, or NULL */
static HCRYPTMSG GetEmbeddedMessage(const WCHAR *Path)
{
    HCRYPTMSG Msg = NULL;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, Path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, NULL, &Msg, NULL))
        return NULL;
    return Msg;
}

static void CheckMessage(const WCHAR *Path, ALG_ID Alg, BOOL PageHashes, const WCHAR *Keep)
{
    HCRYPTMSG Msg = GetEmbeddedMessage(Path);
    DWORD Size = 0, Type, TypeSize = sizeof(Type);
    BYTE *Content, *Blob;
    SPC_INDIRECT_DATA_CONTENT *Indirect = NULL;
    DWORD IndirectSize = 0, Count = 0, CountSize = sizeof(Count);
    CERT_INFO *Signer;
    PCCERT_CONTEXT Found;
    HCERTSTORE MsgStore;

    ok(Msg != NULL, "no embedded PKCS #7 message in %ls\n", Path);
    if (!Msg)
        return;

    ok(CryptMsgGetParam(Msg, CMSG_TYPE_PARAM, 0, &Type, &TypeSize) && Type == CMSG_SIGNED, "type %lu\n", Type);
    ok(CryptMsgGetParam(Msg, CMSG_SIGNER_COUNT_PARAM, 0, &Count, &CountSize) && Count == 1, "signers %lu\n", Count);
    ok(CryptMsgGetParam(Msg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, NULL, &Size) && Size > 0, "no inner content type\n");
    if (Size)
    {
        char *Oid = HeapAlloc(GetProcessHeap(), 0, Size);
        CryptMsgGetParam(Msg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, Oid, &Size);
        ok(!strcmp(Oid, SPC_INDIRECT_DATA_OBJID), "inner content type %s\n", Oid);
        HeapFree(GetProcessHeap(), 0, Oid);
    }

    /* the signature verifies against the signer certificate carried in the message */
    Size = 0;
    CryptMsgGetParam(Msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &Size);
    Signer = HeapAlloc(GetProcessHeap(), 0, Size);
    if (CryptMsgGetParam(Msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, Signer, &Size))
    {
        MsgStore = CertOpenStore(CERT_STORE_PROV_MSG, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, Msg);
        Found = CertGetSubjectCertificateFromStore(MsgStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, Signer);
        ok(Found != NULL, "the signer certificate is not in the message, error 0x%08lx\n", GetLastError());
        if (Found)
        {
            ok(CryptMsgControl(Msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, Found->pCertInfo),
               "the signature does not verify, error 0x%08lx\n", GetLastError());
            ok(Found->cbCertEncoded == TestCert->cbCertEncoded &&
               !memcmp(Found->pbCertEncoded, TestCert->pbCertEncoded, Found->cbCertEncoded),
               "another certificate than the signer's\n");
            CertFreeCertificateContext(Found);
        }
        CertCloseStore(MsgStore, 0);
    }
    HeapFree(GetProcessHeap(), 0, Signer);

    Size = 0;
    ok(CryptMsgGetParam(Msg, CMSG_CONTENT_PARAM, 0, NULL, &Size), "no content, error 0x%08lx\n", GetLastError());
    Content = HeapAlloc(GetProcessHeap(), 0, Size);
    ok(CryptMsgGetParam(Msg, CMSG_CONTENT_PARAM, 0, Content, &Size), "content failed\n");
    ok(CryptDecodeObjectEx(X509_ASN_ENCODING, SPC_INDIRECT_DATA_CONTENT_STRUCT, Content, Size, CRYPT_DECODE_ALLOC_FLAG,
                           NULL, &Indirect, &IndirectSize), "SpcIndirectDataContent does not decode, error 0x%08lx\n", GetLastError());
    if (Indirect)
    {
        const char *AlgOid = Alg == CALG_SHA1 ? szOID_OIWSEC_sha1 : szOID_NIST_sha256;
        SPC_PE_IMAGE_DATA *Image = NULL;
        DWORD ImageSize = 0;

        ok(!strcmp(Indirect->Data.pszObjId, SPC_PE_IMAGE_DATA_OBJID), "data type %s\n", Indirect->Data.pszObjId);
        ok(!strcmp(Indirect->DigestAlgorithm.pszObjId, AlgOid), "digest algorithm %s\n", Indirect->DigestAlgorithm.pszObjId);
        ok(Indirect->Digest.cbData == (Alg == CALG_SHA1 ? 20 : 32), "digest size %lu\n", Indirect->Digest.cbData);
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, SPC_PE_IMAGE_DATA_STRUCT, Indirect->Data.Value.pbData,
                                Indirect->Data.Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &Image, &ImageSize))
        {
            ok(Image->pFile != NULL, "no link in the image data\n");
            if (Image->pFile)
            {
                if (PageHashes)
                {
                    ok(Image->pFile->dwLinkChoice == SPC_MONIKER_LINK_CHOICE, "link choice %lu\n", Image->pFile->dwLinkChoice);
                    ok(Image->pFile->Moniker.SerializedData.cbData > 16 + 4,
                       "the page hash table is missing (%lu bytes)\n", Image->pFile->Moniker.SerializedData.cbData);
                }
                else
                    ok(Image->pFile->dwLinkChoice == SPC_FILE_LINK_CHOICE, "link choice %lu\n", Image->pFile->dwLinkChoice);
            }
            LocalFree(Image);
        }
        else
            ok(0, "SpcPeImageData does not decode, error 0x%08lx\n", GetLastError());
        LocalFree(Indirect);
    }
    HeapFree(GetProcessHeap(), 0, Content);

    if (Keep)
    {
        HANDLE File;

        Size = 0;
        CryptMsgGetParam(Msg, CMSG_ENCODED_MESSAGE, 0, NULL, &Size);
        Blob = HeapAlloc(GetProcessHeap(), 0, Size);
        if (CryptMsgGetParam(Msg, CMSG_ENCODED_MESSAGE, 0, Blob, &Size))
        {
            File = CreateFileW(Keep, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (File != INVALID_HANDLE_VALUE)
            {
                WriteFile(File, Blob, Size, &Count, NULL);
                CloseHandle(File);
            }
        }
        HeapFree(GetProcessHeap(), 0, Blob);
    }
    CryptMsgClose(Msg);
}

static void SaveCertificate(const WCHAR *Dir)
{
    WCHAR Path[MAX_PATH];
    DWORD Written;
    HANDLE File;

    wsprintfW(Path, L"%ls\\signer.cer", Dir);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        WriteFile(File, TestCert->pbCertEncoded, TestCert->cbCertEncoded, &Written, NULL);
        CloseHandle(File);
    }
}

static void TestSignRoundTrip(const WCHAR *Dir, ALG_ID Alg, DWORD Flags, int Api, const WCHAR *Name)
{
    WCHAR Path[MAX_PATH], P7[MAX_PATH];
    SIGNER_CONTEXT *Context = NULL;
    SIP_SUBJECTINFO Info = { sizeof(Info) };
    HANDLE File;
    GUID Subject;
    HRESULT hr;
    LONG Res;

    wsprintfW(Path, L"%ls\\%ls", Dir, Name);
    wsprintfW(P7, L"%ls\\%ls.p7", Dir, Name);
    ok(CopyTestFile(Path), "copy failed, error 0x%08lx\n", GetLastError());

    Res = Verify(Path);
    ok(Res == TRUST_E_NOSIGNATURE, "%ls: unsigned file: 0x%08lx\n", Name, Res);

    hr = SignFile(Path, Alg, Flags, Api, &Context);
    ok(hr == S_OK, "%ls: signing failed, 0x%08lx\n", Name, hr);
    if (hr != S_OK)
        return;
    if (Api != 0)
    {
        ok(Context != NULL && Context->cbBlob > 0 && Context->pbBlob, "%ls: no signer context\n", Name);
        if (Context)
            pSignerFreeSignerContext(Context);
    }

    CheckMessage(Path, Alg, !!(Flags & SPC_INC_PE_PAGE_HASHES_FLAG), KeepOutputs ? P7 : NULL);
    Res = Verify(Path);
    ok(IsGoodButUntrusted(Res), "%ls: signed file: 0x%08lx\n", Name, Res);

    /* the SIP of the file recomputes the digest and finds it in the indirect data */
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "open failed\n");
    if (File != INVALID_HANDLE_VALUE)
    {
        BYTE Buffer[256];
        SIP_INDIRECT_DATA *Indirect = (SIP_INDIRECT_DATA *)Buffer;
        DWORD Size = 0;

        ok(CryptSIPRetrieveSubjectGuid(Path, File, &Subject), "no subject GUID, error 0x%08lx\n", GetLastError());
        Info.pgSubjectType = &Subject;
        Info.hFile = File;
        Info.pwsFileName = Path;
        Info.DigestAlgorithm.pszObjId = (LPSTR)(Alg == CALG_SHA1 ? szOID_OIWSEC_sha1 : szOID_NIST_sha256);
        Info.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        ok(CryptSIPCreateIndirectData(&Info, &Size, NULL), "size query failed, error 0x%08lx\n", GetLastError());
        ok(Size > sizeof(SIP_INDIRECT_DATA) && Size <= sizeof(Buffer), "size %lu\n", Size);
        if (Size > sizeof(SIP_INDIRECT_DATA) && Size <= sizeof(Buffer))
        {
            ok(CryptSIPCreateIndirectData(&Info, &Size, Indirect), "create failed, error 0x%08lx\n", GetLastError());
            SetLastError(0xdeadbeef);
            ok(CryptSIPVerifyIndirectData(&Info, Indirect), "verify failed, error 0x%08lx\n", GetLastError());
            Indirect->Digest.pbData[0] ^= 1;
            SetLastError(0xdeadbeef);
            ok(!CryptSIPVerifyIndirectData(&Info, Indirect), "a wrong digest verified\n");
        }
        CloseHandle(File);
    }

    if (KeepOutputs)
    {
        WCHAR Keep[MAX_PATH];

        wsprintfW(Keep, L"%ls.signed", Path);
        CopyFileW(Path, Keep, FALSE);
    }

    /* tamper with the code: the digest no longer matches */
    FlipCodeByte(Path);
    Res = Verify(Path);
    ok(Res == (LONG)TRUST_E_BAD_DIGEST, "%ls: tampered file: 0x%08lx\n", Name, Res);
    DeleteFileW(Path);
}

/* The certificate from an SPC (PKCS #7) file and the key from a named key container */
static void TestSpcFile(const WCHAR *Dir)
{
    WCHAR Path[MAX_PATH], Spc[MAX_PATH];
    SIGNER_FILE_INFO FileInfo = { sizeof(FileInfo), Path, NULL };
    SIGNER_SUBJECT_INFO Subject = { sizeof(Subject), NULL, SIGNER_SUBJECT_FILE_VALUE, { &FileInfo } };
    SIGNER_CERT Cert = { sizeof(Cert), SIGNER_CERT_SPC_FILE, { Spc }, NULL };
    SIGNER_SIGNATURE_INFO Sig = { sizeof(Sig), CALG_SHA_256, SIGNER_NO_ATTR, { NULL }, NULL, NULL };
    SIGNER_PROVIDER_INFO Provider = { sizeof(Provider), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, AT_SIGNATURE, 2, { Container } };
    HRESULT hr;
    LONG Res;

    wsprintfW(Path, L"%ls\\spc.exe", Dir);
    wsprintfW(Spc, L"%ls\\signer.spc", Dir);
    ok(CopyTestFile(Path), "copy failed\n");
    ok(CertSaveStore(TestStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7,
                     CERT_STORE_SAVE_TO_FILENAME_W, Spc, 0), "CertSaveStore failed, error 0x%08lx\n", GetLastError());
    hr = pSignerSign(&Subject, &Cert, &Sig, &Provider, NULL, NULL, NULL);
    ok(hr == S_OK, "signing with an SPC file and a key container: 0x%08lx\n", hr);
    if (hr == S_OK)
    {
        CheckMessage(Path, CALG_SHA_256, FALSE, NULL);
        Res = Verify(Path);
        ok(IsGoodButUntrusted(Res), "signed with an SPC file: 0x%08lx\n", Res);
    }
    /* an SPC file needs a key */
    hr = pSignerSign(&Subject, &Cert, &Sig, NULL, NULL, NULL, NULL);
    ok(hr != S_OK, "an SPC file without a provider was accepted\n");
    DeleteFileW(Path);
    DeleteFileW(Spc);
}

static void TestRemove(const WCHAR *Dir)
{
    WCHAR Path[MAX_PATH];
    SIP_SUBJECTINFO Info = { sizeof(Info) };
    GUID Subject;
    HANDLE File;
    LONG Res;

    wsprintfW(Path, L"%ls\\removed.exe", Dir);
    ok(CopyTestFile(Path), "copy failed\n");
    if (SignFile(Path, CALG_SHA_256, 0, 1, NULL) != S_OK)
    {
        skip("cannot sign\n");
        DeleteFileW(Path);
        return;
    }
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CryptSIPRetrieveSubjectGuid(Path, File, &Subject);
    Info.pgSubjectType = &Subject;
    Info.hFile = File;
    Info.pwsFileName = Path;
    Info.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    ok(CryptSIPRemoveSignedDataMsg(&Info, 0), "remove failed, error 0x%08lx\n", GetLastError());
    CloseHandle(File);
    Res = Verify(Path);
    ok(Res == (LONG)TRUST_E_NOSIGNATURE, "after the removal: 0x%08lx\n", Res);
    DeleteFileW(Path);
}

static void TestSignAgain(const WCHAR *Dir)
{
    WCHAR Path[MAX_PATH];
    HRESULT hr;
    LONG Res;
    DWORD Count = 0;
    HANDLE File;

    wsprintfW(Path, L"%ls\\twice.exe", Dir);
    ok(CopyTestFile(Path), "copy failed\n");
    hr = SignFile(Path, CALG_SHA1, 0, 0, NULL);
    ok(hr == S_OK, "first signature: 0x%08lx\n", hr);
    hr = SignFile(Path, CALG_SHA_256, 0, 0, NULL);
    ok(hr == S_OK, "second signature: 0x%08lx\n", hr);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(ImageEnumerateCertificates(File, CERT_SECTION_TYPE_ANY, &Count, NULL, 0) && Count == 1,
       "a signed file signed again has %lu signatures\n", Count);
    CloseHandle(File);
    Res = Verify(Path);
    ok(IsGoodButUntrusted(Res), "signed twice: 0x%08lx\n", Res);
    DeleteFileW(Path);
}

static void TestBadParameters(const WCHAR *Dir)
{
    SIGNER_FILE_INFO FileInfo = { sizeof(FileInfo), L"C:\\nonexistent\\codesign-test.exe", NULL };
    SIGNER_SUBJECT_INFO Subject = { sizeof(Subject), NULL, SIGNER_SUBJECT_FILE_VALUE, { &FileInfo } };
    SIGNER_CERT_STORE_INFO StoreInfo = { sizeof(StoreInfo), TestCert, SIGNER_CERT_POLICY_CHAIN, TestStore };
    SIGNER_CERT Cert = { sizeof(Cert), SIGNER_CERT_STORE, { NULL }, NULL };
    SIGNER_SIGNATURE_INFO Sig = { sizeof(Sig), CALG_SHA1, SIGNER_NO_ATTR, { NULL }, NULL, NULL };
    HRESULT hr;

    Cert.pCertStoreInfo = &StoreInfo;
    hr = pSignerSign(NULL, &Cert, &Sig, NULL, NULL, NULL, NULL);
    ok(hr != S_OK, "NULL subject accepted\n");
    hr = pSignerSign(&Subject, NULL, &Sig, NULL, NULL, NULL, NULL);
    ok(hr != S_OK, "NULL certificate accepted\n");
    hr = pSignerSign(&Subject, &Cert, &Sig, NULL, NULL, NULL, NULL);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND),
       "missing file: 0x%08lx\n", hr);
}

static void TestKey(void)
{
    HCRYPTPROV Prov = 0;
    DWORD KeySpec = 0, Size = 0;
    BOOL MustFree = FALSE, Ret;
    HCRYPTHASH Hash;
    BYTE Data[] = "data", Sig[512];

    Ret = CryptAcquireCertificatePrivateKey(TestCert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &Prov, &KeySpec, &MustFree);
    ok(Ret, "CryptAcquireCertificatePrivateKey failed, error 0x%08lx\n", GetLastError());
    ok(KeySpec == AT_SIGNATURE, "key spec %lu\n", KeySpec);
    if (!Ret)
        return;
    Ret = CryptCreateHash(Prov, CALG_SHA_256, 0, 0, &Hash);
    ok(Ret, "CryptCreateHash failed, error 0x%08lx\n", GetLastError());
    if (Ret)
    {
        ok(CryptHashData(Hash, Data, 4, 0), "CryptHashData failed, error 0x%08lx\n", GetLastError());
        Size = sizeof(Sig);
        SetLastError(0xdeadbeef);
        Ret = CryptSignHashW(Hash, KeySpec, NULL, 0, Sig, &Size);
        ok(Ret, "CryptSignHash failed, error 0x%08lx\n", GetLastError());
        ok(!Ret || Size == 256, "signature size %lu\n", Size);
        CryptDestroyHash(Hash);
    }
    if (MustFree)
        CryptReleaseContext(Prov, 0);
}

static void TestSip(void)
{
    SIP_DISPATCH_INFO Sip = { sizeof(Sip) };
    SIP_SUBJECTINFO Info = { sizeof(Info) };
    BYTE Buffer[8192];
    SIP_INDIRECT_DATA *Indirect = (SIP_INDIRECT_DATA *)Buffer;
    DWORD Size = 0;
    HANDLE File;
    GUID Subject;
    BOOL Ret;

    File = CreateFileW(SelfPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "open failed\n");
    Ret = CryptSIPRetrieveSubjectGuid(SelfPath, File, &Subject);
    ok(Ret, "CryptSIPRetrieveSubjectGuid failed, error 0x%08lx\n", GetLastError());
    ok(Ret && IsEqualGUID(&Subject, &PeSubject), "subject %s\n", Ret ? "other" : "?");
    Ret = CryptSIPLoad(&Subject, 0, &Sip);
    ok(Ret, "CryptSIPLoad failed, error 0x%08lx\n", GetLastError());
    ok(Ret && Sip.pfCreate && Sip.pfVerify && Sip.pfGet && Sip.pfPut && Sip.pfRemove, "incomplete dispatch table\n");

    Info.pgSubjectType = &Subject;
    Info.hFile = File;
    Info.pwsFileName = SelfPath;
    Info.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    /* the digest algorithm defaults to SHA-1 */
    SetLastError(0xdeadbeef);
    Ret = CryptSIPCreateIndirectData(&Info, &Size, NULL);
    ok(Ret, "size query: error 0x%08lx\n", GetLastError());
    ok(Size > sizeof(SIP_INDIRECT_DATA) && Size < sizeof(Buffer), "size %lu\n", Size);
    SetLastError(0xdeadbeef);
    Size = sizeof(SIP_INDIRECT_DATA);
    Ret = CryptSIPCreateIndirectData(&Info, &Size, Indirect);
    ok(!Ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "short buffer: %d, error 0x%08lx\n", Ret, GetLastError());
    Size = sizeof(Buffer);
    Ret = CryptSIPCreateIndirectData(&Info, &Size, Indirect);
    ok(Ret, "create: error 0x%08lx\n", GetLastError());
    if (Ret)
    {
        ok(!strcmp(Indirect->DigestAlgorithm.pszObjId, szOID_OIWSEC_sha1), "algorithm %s\n", Indirect->DigestAlgorithm.pszObjId);
        ok(Indirect->Digest.cbData == 20, "digest size %lu\n", Indirect->Digest.cbData);
        ok(!strcmp(Indirect->Data.pszObjId, SPC_PE_IMAGE_DATA_OBJID), "data type %s\n", Indirect->Data.pszObjId);
    }

    Info.dwFlags = SPC_INC_PE_PAGE_HASHES_FLAG;
    Info.DigestAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    Size = sizeof(Buffer);
    SetLastError(0xdeadbeef);
    Ret = CryptSIPCreateIndirectData(&Info, &Size, Indirect);
    ok(Ret, "create with page hashes: error 0x%08lx\n", GetLastError());
    Info.dwFlags = 0;

    /* the subject must be a PE file */
    Info.pgSubjectType = &Subject;
    SetLastError(0xdeadbeef);
    Info.DigestAlgorithm.pszObjId = (LPSTR)"1.2.3.4";
    Size = sizeof(Buffer);
    Ret = CryptSIPCreateIndirectData(&Info, &Size, Indirect);
    ok(!Ret, "an unknown digest algorithm was accepted\n");
    CloseHandle(File);
}

static void TestCatalog(const WCHAR *Dir)
{
    WCHAR CatPath[MAX_PATH], FilePath[MAX_PATH], Tag[] = L"CODESIGNMEMBER";
    BYTE Buffer[8192], Hash[32];
    SIP_INDIRECT_DATA *Indirect = (SIP_INDIRECT_DATA *)Buffer;
    SIP_SUBJECTINFO Info = { sizeof(Info) };
    DWORD HashSize = sizeof(Hash), Size = sizeof(Buffer);
    HANDLE Cat, File;
    CRYPTCATMEMBER *Member;
    GUID Action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    CRYPTCATATTRIBUTE *Attr;
    WINTRUST_CATALOG_INFO CatInfo = { sizeof(CatInfo) };
    WINTRUST_DATA Data = { sizeof(Data) };
    LONG Res;

    wsprintfW(CatPath, L"%ls\\codesign.cat", Dir);
    wsprintfW(FilePath, L"%ls\\member.exe", Dir);
    ok(CopyTestFile(FilePath), "copy failed\n");
    File = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(CryptCATAdminCalcHashFromFileHandle(File, &HashSize, Hash, 0), "hash failed, error 0x%08lx\n", GetLastError());

    /* the member data of a catalog is what the file's SIP makes of it */
    Info.pgSubjectType = &PeSubject;
    Info.hFile = File;
    Info.pwsFileName = FilePath;
    Info.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    ok(CryptSIPCreateIndirectData(&Info, &Size, Indirect), "indirect data failed, error 0x%08lx\n", GetLastError());
    CloseHandle(File);
    ok(Indirect->Digest.cbData == HashSize && !memcmp(Indirect->Digest.pbData, Hash, HashSize),
       "the SIP digest is not the file hash the catalog admin computes\n");

    DeleteFileW(CatPath);
    Cat = CryptCATOpen(CatPath, CRYPTCAT_OPEN_CREATENEW, 0, CRYPTCAT_VERSION_1, 0);
    ok(Cat != INVALID_HANDLE_VALUE, "create failed, error 0x%08lx\n", GetLastError());
    if (Cat == INVALID_HANDLE_VALUE)
        return;
    Member = CryptCATPutMemberInfo(Cat, FilePath, Tag, &PeSubject, 0x200, Size, Buffer);
    ok(Member != NULL, "CryptCATPutMemberInfo failed, error 0x%08lx\n", GetLastError());
    ok(CryptCATPutCatAttrInfo(Cat, (LPWSTR)L"CodesignName", CRYPTCAT_ATTR_AUTHENTICATED | CRYPTCAT_ATTR_NAMEASCII |
                              CRYPTCAT_ATTR_DATAASCII, 4, (BYTE *)"abc") != NULL, "put attribute failed, error 0x%08lx\n", GetLastError());
    ok(CryptCATPersistStore(Cat), "persist failed, error 0x%08lx\n", GetLastError());
    CryptCATClose(Cat);

    /* member lookup in what was written */
    Cat = CryptCATOpen(CatPath, CRYPTCAT_OPEN_EXISTING, 0, 0, 0);
    ok(Cat != INVALID_HANDLE_VALUE, "open failed, error 0x%08lx\n", GetLastError());
    if (Cat != INVALID_HANDLE_VALUE)
    {
        Member = CryptCATGetMemberInfo(Cat, Tag);
        ok(Member != NULL, "member not found, error 0x%08lx\n", GetLastError());
        if (Member)
        {
            ok(Member->pIndirectData->Digest.cbData == HashSize &&
               !memcmp(Member->pIndirectData->Digest.pbData, Hash, HashSize), "member digest differs\n");
            ok(Member->dwCertVersion == 0x200, "version 0x%lx\n", Member->dwCertVersion);
        }
        Member = CryptCATEnumerateMember(Cat, NULL);
        ok(Member != NULL, "enumeration found no member\n");
        ok(CryptCATEnumerateMember(Cat, Member) == NULL, "more than one member\n");
        Attr = CryptCATGetCatAttrInfo(Cat, (LPWSTR)L"CodesignName");
        ok(Attr != NULL, "catalog attribute not found\n");
        CryptCATClose(Cat);
    }

    /* the catalog is not signed: a file listed in it does not verify through it */
    CatInfo.pcwszCatalogFilePath = CatPath;
    CatInfo.pcwszMemberTag = Tag;
    CatInfo.pcwszMemberFilePath = FilePath;
    CatInfo.hMemberFile = NULL;
    CatInfo.pbCalculatedFileHash = Hash;
    CatInfo.cbCalculatedFileHash = HashSize;
    Data.dwUIChoice = WTD_UI_NONE;
    Data.fdwRevocationChecks = WTD_REVOKE_NONE;
    Data.dwUnionChoice = WTD_CHOICE_CATALOG;
    Data.pCatalog = &CatInfo;
    Data.dwStateAction = WTD_STATEACTION_VERIFY;
    Res = WinVerifyTrust(INVALID_HANDLE_VALUE, &Action, &Data);
    ok(Res != 0, "an unsigned catalog verified a member\n");
    Data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(INVALID_HANDLE_VALUE, &Action, &Data);
    DeleteFileW(CatPath);
    DeleteFileW(FilePath);
}

START_TEST(SignerSign)
{
    HMODULE Mssign = LoadLibraryW(L"mssign32.dll");
    WCHAR Dir[MAX_PATH], Out[MAX_PATH];
    DWORD Len;

    if (!Mssign)
    {
        skip("mssign32.dll is not available\n");
        return;
    }
    pSignerSign = (PFN_SignerSign)GetProcAddress(Mssign, "SignerSign");
    pSignerSignEx = (PFN_SignerSignEx)GetProcAddress(Mssign, "SignerSignEx");
    pSignerSignEx2 = (PFN_SignerSignEx2)GetProcAddress(Mssign, "SignerSignEx2");
    pSignerFreeSignerContext = (PFN_SignerFree)GetProcAddress(Mssign, "SignerFreeSignerContext");
    ok(pSignerSign && pSignerSignEx && pSignerFreeSignerContext, "mssign32 does not export the SignerSign functions\n");
    if (!pSignerSign || !pSignerSignEx || !pSignerFreeSignerContext)
        return;

    GetModuleFileNameW(NULL, SelfPath, ARRAYSIZE(SelfPath));
    Len = GetEnvironmentVariableW(L"CODESIGN_TEST_OUT", Out, ARRAYSIZE(Out));
    KeepOutputs = Len && Len < ARRAYSIZE(Out);
    if (KeepOutputs)
        wcscpy(Dir, Out);
    else
    {
        GetTempPathW(ARRAYSIZE(Dir), Dir);
        Len = wcslen(Dir);
        if (Len && Dir[Len - 1] == L'\\')
            Dir[Len - 1] = 0;
    }

    if (!MakeCertificate())
    {
        skip("cannot make a test certificate\n");
        FreeCertificate();
        return;
    }
    if (KeepOutputs)
        SaveCertificate(Dir);

    TestKey();
    TestSip();
    TestSignRoundTrip(Dir, CALG_SHA1, 0, 0, L"signed-sha1.exe");
    TestSignRoundTrip(Dir, CALG_SHA_256, 0, 1, L"signed-sha256.exe");
    if (pSignerSignEx2)
        TestSignRoundTrip(Dir, CALG_SHA_256, 0, 2, L"signed-ex2.exe");
    TestSignRoundTrip(Dir, CALG_SHA_256, SPC_INC_PE_PAGE_HASHES_FLAG, 1, L"signed-pagehash.exe");
    TestSignAgain(Dir);
    TestSpcFile(Dir);
    TestRemove(Dir);
    TestBadParameters(Dir);
    TestCatalog(Dir);
    FreeCertificate();
}
