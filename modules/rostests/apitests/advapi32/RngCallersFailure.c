/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Callers of RtlGenRandom (SystemFunction036) when it returns FALSE: they must fail cleanly, with no
 *              uninitialised bytes in the result and no endless loop
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * RtlGenRandom returns FALSE when the system generator (ksecdd.sys) gives no seed, which a test cannot cause
 * from outside. The test makes it happen in this process: the import slots of the DLLs under test that point to
 * advapi32's SystemFunction036 are redirected to a function that fails. Nothing in the DLLs is changed on disk
 * or in other processes. A DLL that does not import the function the usual way (no slot found) is skipped.
 */

#include "precomp.h"

#include <wincrypt.h>
#include <winsock2.h>
#include <winhttp.h>

#define MAX_HOOKED  8

#ifndef RPC_S_OK
#define RPC_S_OK 0L
#endif
#ifndef RPC_S_UUID_LOCAL_ONLY
#define RPC_S_UUID_LOCAL_ONLY 1824L
#endif

static HMODULE g_Modules[MAX_HOOKED];
static ULONG g_ModuleCount;
static PVOID g_Real;
static LONG g_Calls;

static BOOLEAN WINAPI
FailingGenRandom(PVOID Buffer, ULONG Length)
{
    InterlockedIncrement(&g_Calls);
    SetLastError(NTE_FAIL);
    return FALSE;
}

/* Replaces every import slot of Module that holds From with To; returns how many */
static ULONG
PatchImports(HMODULE Module, PVOID From, PVOID To)
{
    PBYTE Base = (PBYTE)Module;
    PIMAGE_NT_HEADERS Nt = RtlImageNtHeader(Module);
    PIMAGE_DATA_DIRECTORY Dir;
    PIMAGE_IMPORT_DESCRIPTOR Import;
    ULONG Count = 0;

    if (!Nt)
        return 0;
    Dir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!Dir->VirtualAddress)
        return 0;

    for (Import = (PIMAGE_IMPORT_DESCRIPTOR)(Base + Dir->VirtualAddress); Import->Name && Import->FirstThunk; Import++)
    {
        PVOID *Slot;

        for (Slot = (PVOID *)(Base + Import->FirstThunk); *Slot; Slot++)
        {
            DWORD Old;

            if (*Slot != From)
                continue;
            if (!VirtualProtect(Slot, sizeof(*Slot), PAGE_READWRITE, &Old))
                continue;
            *Slot = To;
            VirtualProtect(Slot, sizeof(*Slot), Old, &Old);
            Count++;
        }
    }
    return Count;
}

static BOOL
AddModule(PCWSTR Name)
{
    HMODULE Module = LoadLibraryW(Name);

    if (!Module || g_ModuleCount >= MAX_HOOKED)
        return FALSE;
    g_Modules[g_ModuleCount++] = Module;
    return TRUE;
}

static ULONG
SetHook(BOOL On)
{
    ULONG i, Total = 0;

    for (i = 0; i < g_ModuleCount; i++)
        Total += On ? PatchImports(g_Modules[i], g_Real, FailingGenRandom)
                    : PatchImports(g_Modules[i], FailingGenRandom, g_Real);
    return Total;
}

typedef struct _ENCRYPT_JOB
{
    HCRYPTKEY Key;
    DWORD Flags;
    BOOL Result;
    DWORD Error;
} ENCRYPT_JOB;

static DWORD WINAPI
EncryptThread(PVOID Context)
{
    ENCRYPT_JOB *Job = Context;
    BYTE Data[64] = { 'h', 'e', 'l', 'l', 'o' };
    DWORD Length = 5;

    SetLastError(0);
    Job->Result = CryptEncrypt(Job->Key, 0, TRUE, Job->Flags, Data, &Length, sizeof(Data));
    Job->Error = GetLastError();
    return 0;
}

/* CryptEncrypt on its own thread: a padding routine that loops forever must show up as a failure, not a hang */
static BOOL
EncryptWithTimeout(HCRYPTKEY Key, DWORD Flags, BOOL *Result, DWORD *Error)
{
    ENCRYPT_JOB Job = { Key, Flags, TRUE, 0 };
    HANDLE Thread = CreateThread(NULL, 0, EncryptThread, &Job, 0, NULL);

    if (!Thread)
        return FALSE;
    if (WaitForSingleObject(Thread, 10000) != WAIT_OBJECT_0)
    {
        TerminateThread(Thread, 0);
        CloseHandle(Thread);
        return FALSE;
    }
    CloseHandle(Thread);
    *Result = Job.Result;
    *Error = Job.Error;
    return TRUE;
}

static void
TestRpcrt4(void)
{
    LONG (WINAPI *pUuidCreate)(GUID *);
    HMODULE Module = GetModuleHandleW(L"rpcrt4.dll");
    GUID Guid, Zero = { 0 };
    LONG Status;

    pUuidCreate = Module ? (PVOID)GetProcAddress(Module, "UuidCreate") : NULL;
    if (!pUuidCreate)
    {
        skip("no UuidCreate\n");
        return;
    }

    memset(&Guid, 0xCC, sizeof(Guid));
    Status = pUuidCreate(&Guid);
    ok(Status == RPC_S_OK, "UuidCreate returned %ld\n", Status);

    SetHook(TRUE);
    memset(&Guid, 0xCC, sizeof(Guid));
    Status = pUuidCreate(&Guid);
    ok(Status != RPC_S_OK && Status != RPC_S_UUID_LOCAL_ONLY, "UuidCreate succeeded without random data (%ld)\n", Status);
    ok(memcmp(&Guid, &Zero, sizeof(Guid)) == 0, "UuidCreate left bytes in the GUID that are not random\n");
    SetHook(FALSE);

    Status = pUuidCreate(&Guid);
    ok(Status == RPC_S_OK, "UuidCreate after the hook returned %ld\n", Status);
}

static void
TestRsaenh(void)
{
    HCRYPTPROV Prov;
    HCRYPTKEY Key, Rsa;
    BYTE Buffer[16];
    BOOL Result, Ok;
    DWORD Error;
    ALG_ID Algs[] = { CALG_RC4, CALG_RC2 };
    ULONG i;

    if (!CryptAcquireContextW(&Prov, NULL, MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        skip("no RSA provider: %lu\n", GetLastError());
        return;
    }
    if (!CryptGenKey(Prov, AT_KEYEXCHANGE, (512 << 16) | CRYPT_EXPORTABLE, &Rsa))
    {
        skip("no RSA key: %lu\n", GetLastError());
        CryptReleaseContext(Prov, 0);
        return;
    }

    SetHook(TRUE);

    SetLastError(0);
    Result = CryptGenRandom(Prov, sizeof(Buffer), Buffer);
    Error = GetLastError();
    ok(!Result, "CryptGenRandom succeeded without random data\n");
    ok(Error == NTE_FAIL, "CryptGenRandom: error %lx\n", Error);

    for (i = 0; i < ARRAYSIZE(Algs); i++)
    {
        Key = 0xdeadbeef;
        SetLastError(0);
        Result = CryptGenKey(Prov, Algs[i], CRYPT_EXPORTABLE, &Key);
        Error = GetLastError();
        ok(!Result, "CryptGenKey(%lx) succeeded without random data\n", (ULONG)Algs[i]);
        ok(Error == NTE_FAIL, "CryptGenKey(%lx): error %lx\n", (ULONG)Algs[i], Error);
        if (Result)
            CryptDestroyKey(Key);
        else
        {
            /* the key handle that was made must be gone */
            BYTE Dummy[16];
            DWORD Length = sizeof(Dummy);

            SetLastError(0);
            ok(!CryptGetKeyParam(Key, KP_ALGID, Dummy, &Length, 0) || Key == (HCRYPTKEY)(ULONG_PTR)INVALID_HANDLE_VALUE ||
               Key == 0xdeadbeef, "CryptGenKey(%lx) left a usable key\n", (ULONG)Algs[i]);
        }
    }

    /* PKCS#1 padding (random non-zero bytes) and OAEP (random seed) */
    Ok = EncryptWithTimeout(Rsa, 0, &Result, &Error);
    ok(Ok, "CryptEncrypt with PKCS#1 padding did not return (endless loop)\n");
    if (Ok)
    {
        ok(!Result, "CryptEncrypt with PKCS#1 padding succeeded without random data\n");
        ok(Error == NTE_FAIL, "CryptEncrypt with PKCS#1 padding: error %lx\n", Error);
    }
    Ok = EncryptWithTimeout(Rsa, CRYPT_OAEP, &Result, &Error);
    ok(Ok, "CryptEncrypt with OAEP did not return (endless loop)\n");
    if (Ok)
    {
        ok(!Result, "CryptEncrypt with OAEP succeeded without random data\n");
        ok(Error == NTE_FAIL, "CryptEncrypt with OAEP: error %lx\n", Error);
    }

    SetHook(FALSE);

    /* with random data again, the same calls work */
    ok(CryptGenRandom(Prov, sizeof(Buffer), Buffer), "CryptGenRandom failed: %lu\n", GetLastError());
    ok(CryptGenKey(Prov, CALG_RC4, CRYPT_EXPORTABLE, &Key), "CryptGenKey failed: %lu\n", GetLastError());
    if (Key)
        CryptDestroyKey(Key);
    Ok = EncryptWithTimeout(Rsa, 0, &Result, &Error);
    ok(Ok && Result, "CryptEncrypt with PKCS#1 padding failed after the hook: %d %lu\n", Result, Error);
    Ok = EncryptWithTimeout(Rsa, CRYPT_OAEP, &Result, &Error);
    ok(Ok && Result, "CryptEncrypt with OAEP failed after the hook: %d %lu\n", Result, Error);

    CryptDestroyKey(Rsa);
    CryptReleaseContext(Prov, 0);
}

static void
TestBcrypt(void)
{
    LONG (WINAPI *pBCryptGenRandom)(PVOID, PUCHAR, ULONG, ULONG);
    HRESULT (WINAPI *pMFCreateTempFile)(ULONG, ULONG, ULONG, PVOID *);
    HMODULE Module = GetModuleHandleW(L"bcrypt.dll");
    UCHAR Buffer[16];
    LONG Status;
    PVOID Stream = NULL;
    HRESULT hr;

    pBCryptGenRandom = Module ? (PVOID)GetProcAddress(Module, "BCryptGenRandom") : NULL;
    if (!pBCryptGenRandom)
    {
        skip("no BCryptGenRandom\n");
        return;
    }

    SetHook(TRUE);
    Status = pBCryptGenRandom(NULL, Buffer, sizeof(Buffer), 2 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */);
    ok(Status != 0, "BCryptGenRandom succeeded without random data\n");
    SetHook(FALSE);
    Status = pBCryptGenRandom(NULL, Buffer, sizeof(Buffer), 2);
    ok(Status == 0, "BCryptGenRandom after the hook: %lx\n", Status);

    /* MFCreateTempFile names its file from BCryptGenRandom: 3 = read/write, 4 = delete if exists */
    Module = LoadLibraryW(L"mfplat.dll");
    pMFCreateTempFile = Module ? (PVOID)GetProcAddress(Module, "MFCreateTempFile") : NULL;
    if (!pMFCreateTempFile)
    {
        skip("no MFCreateTempFile\n");
        return;
    }
    hr = pMFCreateTempFile(3, 4, 0, &Stream);
    if (FAILED(hr))
    {
        skip("MFCreateTempFile does not work here: %lx\n", hr);
        return;
    }
    ((ULONG (WINAPI *)(PVOID))(*(PVOID **)Stream)[2])(Stream);

    SetHook(TRUE);
    Stream = NULL;
    hr = pMFCreateTempFile(3, 4, 0, &Stream);
    ok(FAILED(hr), "MFCreateTempFile succeeded without random data: %lx\n", hr);
    ok(Stream == NULL, "MFCreateTempFile returned a stream\n");
    if (Stream)
        ((ULONG (WINAPI *)(PVOID))(*(PVOID **)Stream)[2])(Stream);
    SetHook(FALSE);
}

static void
TestCrypt32(void)
{
    HMODULE Crypt32 = LoadLibraryW(L"crypt32.dll");
    PCCERT_CONTEXT (WINAPI *pSelfSign)(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, PCERT_NAME_BLOB, DWORD, PCRYPT_KEY_PROV_INFO,
                                       PCRYPT_ALGORITHM_IDENTIFIER, PSYSTEMTIME, PSYSTEMTIME, PCERT_EXTENSIONS);
    BOOL (WINAPI *pStrToName)(DWORD, LPCSTR, DWORD, void *, BYTE *, DWORD *, LPCSTR *);
    BOOL (WINAPI *pFreeCert)(PCCERT_CONTEXT);
    HCRYPTPROV Prov;
    HCRYPTKEY Key;
    CERT_NAME_BLOB Name = { 0 };
    BYTE NameBuffer[128];
    PCCERT_CONTEXT Context;

    pSelfSign = Crypt32 ? (PVOID)GetProcAddress(Crypt32, "CertCreateSelfSignCertificate") : NULL;
    pStrToName = Crypt32 ? (PVOID)GetProcAddress(Crypt32, "CertStrToNameA") : NULL;
    pFreeCert = Crypt32 ? (PVOID)GetProcAddress(Crypt32, "CertFreeCertificateContext") : NULL;
    if (!pSelfSign || !pStrToName || !pFreeCert)
    {
        skip("no crypt32 functions\n");
        return;
    }

    Name.pbData = NameBuffer;
    Name.cbData = sizeof(NameBuffer);
    if (!pStrToName(X509_ASN_ENCODING, "CN=rngtest", 0, NULL, NameBuffer, &Name.cbData, NULL))
    {
        skip("CertStrToName failed: %lu\n", GetLastError());
        return;
    }
    if (!CryptAcquireContextW(&Prov, NULL, MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
        !CryptGenKey(Prov, AT_SIGNATURE, (512 << 16) | CRYPT_EXPORTABLE, &Key))
    {
        skip("no key: %lu\n", GetLastError());
        return;
    }
    CryptDestroyKey(Key);

    Context = pSelfSign(Prov, &Name, 0, NULL, NULL, NULL, NULL, NULL);
    if (!Context)
    {
        skip("CertCreateSelfSignCertificate does not work here: %lu\n", GetLastError());
        CryptReleaseContext(Prov, 0);
        return;
    }
    pFreeCert(Context);

    SetHook(TRUE);
    Context = pSelfSign(Prov, &Name, 0, NULL, NULL, NULL, NULL, NULL);
    ok(Context == NULL, "CertCreateSelfSignCertificate succeeded (serial number without random data)\n");
    if (Context)
        pFreeCert(Context);
    SetHook(FALSE);
    CryptReleaseContext(Prov, 0);
}

static void
TestWintrust(void)
{
    HMODULE Module = LoadLibraryW(L"wintrust.dll");
    HANDLE (WINAPI *pOpen)(LPCWSTR, DWORD, HCRYPTPROV, DWORD, DWORD);
    BOOL (WINAPI *pPersist)(HANDLE);
    BOOL (WINAPI *pClose)(HANDLE);
    WCHAR Path[MAX_PATH];
    HANDLE Catalog;
    BOOL Result;

    pOpen = Module ? (PVOID)GetProcAddress(Module, "CryptCATOpen") : NULL;
    pPersist = Module ? (PVOID)GetProcAddress(Module, "CryptCATPersistStore") : NULL;
    pClose = Module ? (PVOID)GetProcAddress(Module, "CryptCATClose") : NULL;
    if (!pOpen || !pPersist || !pClose)
    {
        skip("no catalog functions\n");
        return;
    }

    GetTempPathW(ARRAYSIZE(Path), Path);
    wcscat(Path, L"rngcallers.cat");
    DeleteFileW(Path);

    Catalog = pOpen(Path, 1 /* CRYPTCAT_OPEN_CREATENEW */, 0, 0x100 /* CRYPTCAT_VERSION_1 */, 0);
    if (Catalog == INVALID_HANDLE_VALUE)
    {
        skip("CryptCATOpen failed: %lu\n", GetLastError());
        return;
    }
    Result = pPersist(Catalog);
    if (!Result)
    {
        skip("CryptCATPersistStore does not work here: %lu\n", GetLastError());
        pClose(Catalog);
        DeleteFileW(Path);
        return;
    }
    DeleteFileW(Path);

    SetHook(TRUE);
    Result = pPersist(Catalog);
    ok(!Result, "CryptCATPersistStore wrote a catalog with an identifier that is not random\n");
    SetHook(FALSE);
    pClose(Catalog);
    DeleteFileW(Path);
}

/* A server that completes the WebSocket upgrade and then only reads: the client's frames are never looked at */
static SOCKET g_Listen = INVALID_SOCKET;
static HANDLE g_StopEvent;

static DWORD WINAPI
UpgradeServer(PVOID Context)
{
    static const char Guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    SOCKET Client = accept(g_Listen, NULL, NULL);
    char Request[2048], Response[512], Accept[64];
    int Used = 0, Got;
    char *Key, *End;
    HCRYPTPROV Prov;
    HCRYPTHASH Hash;
    BYTE Digest[20];
    DWORD DigestLength = sizeof(Digest);

    if (Client == INVALID_SOCKET)
        return 0;
    while (Used < (int)sizeof(Request) - 1)
    {
        Got = recv(Client, Request + Used, sizeof(Request) - 1 - Used, 0);
        if (Got <= 0)
            break;
        Used += Got;
        Request[Used] = 0;
        if (strstr(Request, "\r\n\r\n"))
            break;
    }
    Request[Used] = 0;
    Key = strstr(Request, "Sec-WebSocket-Key:");
    if (Key && CryptAcquireContextW(&Prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        Key += sizeof("Sec-WebSocket-Key:") - 1;
        while (*Key == ' ')
            Key++;
        End = strstr(Key, "\r\n");
        if (End && CryptCreateHash(Prov, CALG_SHA1, 0, 0, &Hash))
        {
            CryptHashData(Hash, (BYTE *)Key, (DWORD)(End - Key), 0);
            CryptHashData(Hash, (BYTE *)Guid, sizeof(Guid) - 1, 0);
            CryptGetHashParam(Hash, HP_HASHVAL, Digest, &DigestLength, 0);
            CryptDestroyHash(Hash);
            {
                static const char Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                ULONG i, o = 0;

                /* Base64 of the 20 byte digest: six groups of three bytes and a last one of two */
                for (i = 0; i < sizeof(Digest); i += 3)
                {
                    ULONG Left = sizeof(Digest) - i;
                    ULONG Value = (Digest[i] << 16) | (Left > 1 ? Digest[i + 1] << 8 : 0) | (Left > 2 ? Digest[i + 2] : 0);

                    Accept[o++] = Alphabet[(Value >> 18) & 63];
                    Accept[o++] = Alphabet[(Value >> 12) & 63];
                    Accept[o++] = Left > 1 ? Alphabet[(Value >> 6) & 63] : '=';
                    Accept[o++] = Left > 2 ? Alphabet[Value & 63] : '=';
                }
                Accept[o] = 0;
            }
            StringCchPrintfA(Response, sizeof(Response),
                             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: %s\r\n\r\n", Accept);
            send(Client, Response, (int)strlen(Response), 0);
            while (WaitForSingleObject(g_StopEvent, 50) == WAIT_TIMEOUT)
            {
                char Sink[256];
                u_long Pending = 0;

                if (ioctlsocket(Client, FIONREAD, &Pending) == 0 && Pending)
                    recv(Client, Sink, sizeof(Sink), 0);
            }
        }
        CryptReleaseContext(Prov, 0);
    }
    closesocket(Client);
    return 0;
}

static void
TestWinhttp(void)
{
    HMODULE Module = LoadLibraryW(L"winhttp.dll");
    HINTERNET (WINAPI *pOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    HINTERNET (WINAPI *pConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    HINTERNET (WINAPI *pOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
    BOOL (WINAPI *pSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
    BOOL (WINAPI *pSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    BOOL (WINAPI *pReceiveResponse)(HINTERNET, LPVOID);
    HINTERNET (WINAPI *pUpgrade)(HINTERNET, DWORD_PTR);
    DWORD (WINAPI *pSend)(HINTERNET, DWORD, PVOID, DWORD);
    BOOL (WINAPI *pClose)(HINTERNET);
    WSADATA Wsa;
    struct sockaddr_in Address;
    int Length = sizeof(Address);
    HINTERNET Session, Connection, Request, Web;
    HANDLE Thread;
    BYTE Data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    DWORD Error;

    pOpen = Module ? (PVOID)GetProcAddress(Module, "WinHttpOpen") : NULL;
    pConnect = Module ? (PVOID)GetProcAddress(Module, "WinHttpConnect") : NULL;
    pOpenRequest = Module ? (PVOID)GetProcAddress(Module, "WinHttpOpenRequest") : NULL;
    pSetOption = Module ? (PVOID)GetProcAddress(Module, "WinHttpSetOption") : NULL;
    pSendRequest = Module ? (PVOID)GetProcAddress(Module, "WinHttpSendRequest") : NULL;
    pReceiveResponse = Module ? (PVOID)GetProcAddress(Module, "WinHttpReceiveResponse") : NULL;
    pUpgrade = Module ? (PVOID)GetProcAddress(Module, "WinHttpWebSocketCompleteUpgrade") : NULL;
    pSend = Module ? (PVOID)GetProcAddress(Module, "WinHttpWebSocketSend") : NULL;
    pClose = Module ? (PVOID)GetProcAddress(Module, "WinHttpCloseHandle") : NULL;
    if (!pOpen || !pConnect || !pOpenRequest || !pSetOption || !pSendRequest || !pReceiveResponse || !pUpgrade ||
        !pSend || !pClose)
    {
        skip("no WebSocket functions in winhttp\n");
        return;
    }

    if (WSAStartup(MAKEWORD(2, 2), &Wsa))
    {
        skip("no winsock\n");
        return;
    }
    g_Listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&Address, 0, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (g_Listen == INVALID_SOCKET || bind(g_Listen, (struct sockaddr *)&Address, sizeof(Address)) ||
        listen(g_Listen, 1) || getsockname(g_Listen, (struct sockaddr *)&Address, &Length))
    {
        skip("no loopback listener: %d\n", WSAGetLastError());
        goto Cleanup;
    }
    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, UpgradeServer, NULL, 0, NULL);

    Session = pOpen(L"rngcallers", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    Connection = Session ? pConnect(Session, L"127.0.0.1", ntohs(Address.sin_port), 0) : NULL;
    Request = Connection ? pOpenRequest(Connection, L"GET", L"/", NULL, NULL, NULL, 0) : NULL;
    Web = NULL;
    if (Request && pSetOption(Request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0) &&
        pSendRequest(Request, NULL, 0, NULL, 0, 0, 0) && pReceiveResponse(Request, NULL))
        Web = pUpgrade(Request, 0);
    if (!Web)
    {
        skip("WebSocket upgrade over loopback does not work here: %lu\n", GetLastError());
    }
    else
    {
        Error = pSend(Web, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, Data, sizeof(Data));
        ok(Error == ERROR_SUCCESS, "WinHttpWebSocketSend failed: %lu\n", Error);

        SetHook(TRUE);
        Error = pSend(Web, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, Data, sizeof(Data));
        ok(Error != ERROR_SUCCESS, "WinHttpWebSocketSend sent a frame with a mask that is not random\n");
        SetHook(FALSE);
        pClose(Web);
    }
    if (Request)
        pClose(Request);
    if (Connection)
        pClose(Connection);
    if (Session)
        pClose(Session);
    SetEvent(g_StopEvent);
    closesocket(g_Listen);
    g_Listen = INVALID_SOCKET;
    WaitForSingleObject(Thread, 5000);
    CloseHandle(Thread);
    CloseHandle(g_StopEvent);

Cleanup:
    if (g_Listen != INVALID_SOCKET)
        closesocket(g_Listen);
    WSACleanup();
}

START_TEST(RngCallersFailure)
{
    HMODULE Advapi32 = GetModuleHandleW(L"advapi32.dll");
    ULONG Patched;

    g_Real = Advapi32 ? (PVOID)GetProcAddress(Advapi32, "SystemFunction036") : NULL;
    if (!g_Real)
    {
        skip("no SystemFunction036\n");
        return;
    }

    AddModule(L"rpcrt4.dll");
    AddModule(L"rsaenh.dll");
    AddModule(L"bcrypt.dll");
    AddModule(L"winhttp.dll");

    Patched = SetHook(TRUE);
    SetHook(FALSE);
    trace("%lu import slots of SystemFunction036 in %lu modules\n", Patched, g_ModuleCount);
    if (!Patched)
    {
        skip("no import slot to redirect\n");
        return;
    }

    TestRpcrt4();
    TestRsaenh();
    TestBcrypt();
    TestCrypt32();
    TestWintrust();
    TestWinhttp();
}
