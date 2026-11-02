/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schannel client handshakes with SCH_CREDENTIALS: ClientHello contents (offline) and real servers (online)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <apitest.h>
#include <ntsecapi.h>
#include <wincrypt.h>
#include <sspi.h>
#include <schannel.h>

#define SNI_HOST L"schannel-sni.reactos.test"

#define REQ_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | \
                   ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM)
#define RET_FLAGS (ISC_RET_SEQUENCE_DETECT | ISC_RET_REPLAY_DETECT | ISC_RET_CONFIDENTIALITY | \
                   ISC_RET_EXTENDED_ERROR | ISC_RET_ALLOCATED_MEMORY | ISC_RET_STREAM)

static void InitCred(SCH_CREDENTIALS *Cred, TLS_PARAMETERS *Params, DWORD Flags, DWORD Disabled)
{
    ZeroMemory(Cred, sizeof(*Cred));
    ZeroMemory(Params, sizeof(*Params));
    Cred->dwVersion = SCH_CREDENTIALS_VERSION;
    Cred->dwFlags = Flags;
    if (Disabled)
    {
        Params->grbitDisabledProtocols = Disabled;
        Cred->cTlsParameters = 1;
        Cred->pTlsParameters = Params;
    }
}

/* Returns the ClientHello client_version, whether the server_name extension carries Host, and whether there is one */
static USHORT ParseClientHelloEx(const BYTE *Data, ULONG Size, PCSTR Host, BOOL *HasSni, BOOL *AnySni)
{
    ULONG Pos, End, ExtEnd;
    USHORT Version;

    *HasSni = FALSE;
    *AnySni = FALSE;
    if (Size < 5 + 4 + 2 + 32 + 1 || Data[0] != 0x16 || Data[5] != 0x01)
        return 0;
    Version = (Data[9] << 8) | Data[10];
    End = min(Size, 5 + (ULONG)((Data[3] << 8) | Data[4]));
    Pos = 11 + 32;
    Pos += 1 + Data[Pos];                                       /* session id */
    if (Pos + 2 > End) return Version;
    Pos += 2 + ((Data[Pos] << 8) | Data[Pos + 1]);              /* cipher suites */
    if (Pos + 1 > End) return Version;
    Pos += 1 + Data[Pos];                                       /* compression methods */
    if (Pos + 2 > End) return Version;
    ExtEnd = min(End, Pos + 2 + ((Data[Pos] << 8) | Data[Pos + 1]));
    Pos += 2;
    while (Pos + 4 <= ExtEnd)
    {
        USHORT Type = (Data[Pos] << 8) | Data[Pos + 1];
        USHORT Length = (Data[Pos + 2] << 8) | Data[Pos + 3];

        if (Type == 0)
            *AnySni = TRUE;
        if (Type == 0 && Length >= 5 && Pos + 4 + Length <= ExtEnd)
        {
            /* server_name_list length (2), name type 0 (1), host name length (2), host name */
            USHORT NameLength = (Data[Pos + 7] << 8) | Data[Pos + 8];

            if (Data[Pos + 6] == 0 && NameLength == strlen(Host) && 9 + NameLength <= 4 + Length &&
                !memcmp(Data + Pos + 9, Host, NameLength))
                *HasSni = TRUE;
        }
        Pos += 4 + Length;
    }
    return Version;
}

static USHORT ParseClientHello(const BYTE *Data, ULONG Size, PCSTR Host, BOOL *HasSni)
{
    BOOL AnySni;

    return ParseClientHelloEx(Data, Size, Host, HasSni, &AnySni);
}

/* RFC 6066: no server_name for an IP address literal target (Windows sends none) */
static void TestNoSniForAddress(PCWSTR Target)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CredHandle CredHandle;
    CtxtHandle Ctx;
    TimeStamp Expiry;
    SecBuffer Out;
    SecBufferDesc OutDesc;
    ULONG Attr;
    SECURITY_STATUS Status;
    BOOL HasSni, AnySni;

    InitCred(&Cred, &Params, SCH_CRED_MANUAL_CRED_VALIDATION, 0);
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cred, NULL, NULL,
                                       &CredHandle, &Expiry);
    ok(Status == SEC_E_OK, "AcquireCredentialsHandle returned 0x%08lx\n", Status);
    if (Status != SEC_E_OK)
        return;
    Out.BufferType = SECBUFFER_TOKEN;
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;
    Status = InitializeSecurityContextW(&CredHandle, NULL, (SEC_WCHAR *)Target, REQ_FLAGS, 0, 0, NULL, 0, &Ctx,
                                        &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_I_CONTINUE_NEEDED, "%ls: InitializeSecurityContext returned 0x%08lx\n", Target, Status);
    if (Status == SEC_I_CONTINUE_NEEDED)
    {
        ok(ParseClientHelloEx(Out.pvBuffer, Out.cbBuffer, "", &HasSni, &AnySni) == 0x0303, "%ls: no ClientHello\n", Target);
        ok(!AnySni, "%ls: server_name extension sent for an address\n", Target);
        if (Out.pvBuffer)
            FreeContextBuffer(Out.pvBuffer);
        DeleteSecurityContext(&Ctx);
    }
    FreeCredentialsHandle(&CredHandle);
}

static void TestClientHello(PCSTR Name, DWORD Disabled, USHORT ExpectedVersion)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CredHandle CredHandle;
    CtxtHandle Ctx;
    TimeStamp Expiry;
    SecBuffer Out;
    SecBufferDesc OutDesc;
    ULONG Attr = 0;
    SECURITY_STATUS Status;
    USHORT Version;
    BOOL HasSni;

    InitCred(&Cred, &Params, SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO, Disabled);
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cred, NULL, NULL,
                                       &CredHandle, &Expiry);
    ok(Status == SEC_E_OK, "%s: AcquireCredentialsHandle returned 0x%08lx\n", Name, Status);
    if (Status != SEC_E_OK)
        return;

    Out.BufferType = SECBUFFER_TOKEN;
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;
    Status = InitializeSecurityContextW(&CredHandle, NULL, (SEC_WCHAR *)SNI_HOST, REQ_FLAGS, 0, 0, NULL, 0, &Ctx,
                                        &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_I_CONTINUE_NEEDED, "%s: InitializeSecurityContext returned 0x%08lx\n", Name, Status);
    if (Status == SEC_I_CONTINUE_NEEDED)
    {
        ok(Attr == RET_FLAGS, "%s: attributes 0x%08lx, expected 0x%08lx\n", Name, Attr, (ULONG)RET_FLAGS);
        Version = ParseClientHello(Out.pvBuffer, Out.cbBuffer, "schannel-sni.reactos.test", &HasSni);
        ok(Version == ExpectedVersion, "%s: ClientHello version 0x%04x, expected 0x%04x\n", Name, Version, ExpectedVersion);
        ok(HasSni, "%s: no server_name extension for the target\n", Name);
        if (Out.pvBuffer)
            FreeContextBuffer(Out.pvBuffer);
        DeleteSecurityContext(&Ctx);
    }
    FreeCredentialsHandle(&CredHandle);
}

/* Windows always reports replay/sequence detection, confidentiality and stream; a few more when requested */
static void TestReturnedAttributes(void)
{
    static const struct
    {
        ULONG Req;
        ULONG Ret;
    } Cases[] =
    {
        { 0, ISC_RET_REPLAY_DETECT | ISC_RET_SEQUENCE_DETECT | ISC_RET_CONFIDENTIALITY | ISC_RET_STREAM },
        { ISC_REQ_ALLOCATE_MEMORY, 0x811c },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM, 0x811c },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_EXTENDED_ERROR, 0xc11c },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS, 0x819c },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH, 0x811e },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION, 0x8811c },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_INTEGRITY, 0x811c },
        { ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SESSION_KEY, 0x811c },
    };
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CredHandle CredHandle;
    CtxtHandle Ctx;
    TimeStamp Expiry;
    SecBuffer Out;
    SecBufferDesc OutDesc;
    BYTE Own[16384];
    ULONG i, Attr;
    SECURITY_STATUS Status;

    InitCred(&Cred, &Params, SCH_CRED_MANUAL_CRED_VALIDATION, 0);
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cred, NULL, NULL,
                                       &CredHandle, &Expiry);
    ok(Status == SEC_E_OK, "AcquireCredentialsHandle returned 0x%08lx\n", Status);
    if (Status != SEC_E_OK)
        return;

    for (i = 0; i < ARRAYSIZE(Cases); i++)
    {
        BOOL Allocate = (Cases[i].Req & ISC_REQ_ALLOCATE_MEMORY) != 0;

        Out.BufferType = SECBUFFER_TOKEN;
        Out.cbBuffer = Allocate ? 0 : sizeof(Own);
        Out.pvBuffer = Allocate ? NULL : Own;
        OutDesc.ulVersion = SECBUFFER_VERSION;
        OutDesc.cBuffers = 1;
        OutDesc.pBuffers = &Out;
        Attr = 0xdeadbeef;
        Status = InitializeSecurityContextW(&CredHandle, NULL, (SEC_WCHAR *)SNI_HOST, Cases[i].Req, 0, 0, NULL, 0, &Ctx,
                                            &OutDesc, &Attr, &Expiry);
        ok(Status == SEC_I_CONTINUE_NEEDED, "req 0x%lx: InitializeSecurityContext returned 0x%08lx\n", Cases[i].Req, Status);
        if (Status != SEC_I_CONTINUE_NEEDED)
            continue;
        ok(Attr == Cases[i].Ret, "req 0x%lx: attributes 0x%08lx, expected 0x%08lx\n", Cases[i].Req, Attr, Cases[i].Ret);
        if (Allocate && Out.pvBuffer)
            FreeContextBuffer(Out.pvBuffer);
        DeleteSecurityContext(&Ctx);
    }
    FreeCredentialsHandle(&CredHandle);
}

/* First cipher suite of the ClientHello that is valid with TLS 1.0-1.2 and a plain RSA certificate */
static USHORT PickCipherSuite(const BYTE *Data, ULONG Size)
{
    static const USHORT Wanted[] = { 0xc013, 0xc014, 0x002f, 0x0035 };
    ULONG Pos, Count, i, j;

    if (Size < 5 + 4 + 2 + 32 + 1)
        return 0;
    Pos = 11 + 32;
    Pos += 1 + Data[Pos];
    if (Pos + 2 > Size)
        return 0;
    Count = ((Data[Pos] << 8) | Data[Pos + 1]) / 2;
    Pos += 2;
    for (j = 0; j < ARRAYSIZE(Wanted); j++)
    {
        for (i = 0; i < Count && Pos + 2 * i + 1 < Size; i++)
        {
            if (((Data[Pos + 2 * i] << 8) | Data[Pos + 2 * i + 1]) == Wanted[j])
                return Wanted[j];
        }
    }
    return 0;
}

/* The server answers the ClientHello with a ServerHello for Version. A version the credential does not
 * enable must be refused even when it lies between two enabled ones (TLS 1.0 and 1.2 on, TLS 1.1 off);
 * an enabled one lets the handshake go on (more input needed). Offline: the ServerHello is made here. */
static void TestServerHelloVersion(PCSTR Name, DWORD Disabled, USHORT Version, BOOL Refused)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CredHandle CredHandle;
    CtxtHandle Ctx;
    TimeStamp Expiry;
    SecBuffer Out, In[2];
    SecBufferDesc OutDesc, InDesc;
    BYTE Hello[5 + 4 + 38];
    ULONG Attr, i;
    USHORT Suite;
    SECURITY_STATUS Status;

    InitCred(&Cred, &Params, SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, Disabled);
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cred, NULL, NULL,
                                       &CredHandle, &Expiry);
    ok(Status == SEC_E_OK, "%s: AcquireCredentialsHandle returned 0x%08lx\n", Name, Status);
    if (Status != SEC_E_OK)
        return;

    Out.BufferType = SECBUFFER_TOKEN;
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;
    Status = InitializeSecurityContextW(&CredHandle, NULL, (SEC_WCHAR *)SNI_HOST, REQ_FLAGS, 0, 0, NULL, 0, &Ctx,
                                        &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_I_CONTINUE_NEEDED, "%s: InitializeSecurityContext returned 0x%08lx\n", Name, Status);
    if (Status != SEC_I_CONTINUE_NEEDED)
    {
        FreeCredentialsHandle(&CredHandle);
        return;
    }
    Suite = PickCipherSuite(Out.pvBuffer, Out.cbBuffer);
    ok(Suite != 0, "%s: no usable cipher suite in the ClientHello\n", Name);
    if (Out.pvBuffer)
        FreeContextBuffer(Out.pvBuffer);
    if (!Suite)
    {
        DeleteSecurityContext(&Ctx);
        FreeCredentialsHandle(&CredHandle);
        return;
    }

    /* record header, handshake header, version, random, empty session id, suite, null compression */
    Hello[0] = 0x16; Hello[1] = 3; Hello[2] = Version & 0xff; Hello[3] = 0; Hello[4] = 4 + 38;
    Hello[5] = 0x02; Hello[6] = 0; Hello[7] = 0; Hello[8] = 38;
    Hello[9] = Version >> 8; Hello[10] = Version & 0xff;
    for (i = 0; i < 32; i++)
        Hello[11 + i] = (BYTE)(0x40 + i);
    Hello[43] = 0;
    Hello[44] = Suite >> 8; Hello[45] = Suite & 0xff;
    Hello[46] = 0;

    In[0].BufferType = SECBUFFER_TOKEN;
    In[0].cbBuffer = sizeof(Hello);
    In[0].pvBuffer = Hello;
    In[1].BufferType = SECBUFFER_EMPTY;
    In[1].cbBuffer = 0;
    In[1].pvBuffer = NULL;
    InDesc.ulVersion = SECBUFFER_VERSION;
    InDesc.cBuffers = 2;
    InDesc.pBuffers = In;
    Out.BufferType = SECBUFFER_TOKEN;
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    Status = InitializeSecurityContextW(&CredHandle, &Ctx, (SEC_WCHAR *)SNI_HOST, REQ_FLAGS, 0, 0, &InDesc, 0, NULL,
                                        &OutDesc, &Attr, &Expiry);
    trace("%s: ServerHello 0x%04x suite 0x%04x -> 0x%08lx\n", Name, Version, Suite, Status);
    if (Refused)
        ok(Status == SEC_E_ALGORITHM_MISMATCH, "%s: version 0x%04x accepted (0x%08lx)\n", Name, Version, Status);
    else
        ok(Status == SEC_I_CONTINUE_NEEDED || Status == SEC_E_INCOMPLETE_MESSAGE,
           "%s: version 0x%04x refused (0x%08lx)\n", Name, Version, Status);
    if (Out.pvBuffer)
        FreeContextBuffer(Out.pvBuffer);
    DeleteSecurityContext(&Ctx);
    FreeCredentialsHandle(&CredHandle);
}

typedef struct _CONNECTION
{
    SOCKET Socket;
    CredHandle Cred;
    CtxtHandle Ctx;
    BOOL HaveCtx;
    BYTE *In;
    ULONG InSize;
} CONNECTION;

static BOOL SendAll(SOCKET Socket, const void *Data, ULONG Size)
{
    const char *p = Data;

    while (Size)
    {
        int Sent = send(Socket, p, Size, 0);
        if (Sent <= 0)
            return FALSE;
        p += Sent;
        Size -= Sent;
    }
    return TRUE;
}

/* Non-blocking connect with a timeout, so an unreachable host cannot stall the test */
static BOOL ConnectSocket(SOCKET Socket, const struct sockaddr *Address, int AddressLength, DWORD TimeoutMs)
{
    u_long NonBlocking = 1;
    struct timeval Timeout;
    fd_set Write, Error;
    int SoError = 0, Length = sizeof(SoError);

    if (ioctlsocket(Socket, FIONBIO, &NonBlocking))
        return FALSE;
    if (connect(Socket, Address, AddressLength) && WSAGetLastError() != WSAEWOULDBLOCK)
        return FALSE;
    FD_ZERO(&Write);
    FD_SET(Socket, &Write);
    FD_ZERO(&Error);
    FD_SET(Socket, &Error);
    Timeout.tv_sec = TimeoutMs / 1000;
    Timeout.tv_usec = (TimeoutMs % 1000) * 1000;
    if (select(0, NULL, &Write, &Error, &Timeout) != 1 || !FD_ISSET(Socket, &Write))
        return FALSE;
    if (getsockopt(Socket, SOL_SOCKET, SO_ERROR, (char *)&SoError, &Length) || SoError)
        return FALSE;
    NonBlocking = 0;
    return !ioctlsocket(Socket, FIONBIO, &NonBlocking);
}

static BOOL Connect(CONNECTION *Conn, PCSTR Host, PCSTR Port)
{
    struct addrinfo Hints, *Result = NULL;
    DWORD Timeout = 15000;

    ZeroMemory(Conn, sizeof(*Conn));
    Conn->Socket = INVALID_SOCKET;
    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(Host, Port, &Hints, &Result) || !Result)
        return FALSE;
    Conn->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Conn->Socket == INVALID_SOCKET)
    {
        freeaddrinfo(Result);
        return FALSE;
    }
    setsockopt(Conn->Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
    if (!ConnectSocket(Conn->Socket, Result->ai_addr, (int)Result->ai_addrlen, 10000))
    {
        closesocket(Conn->Socket);
        Conn->Socket = INVALID_SOCKET;
        freeaddrinfo(Result);
        return FALSE;
    }
    freeaddrinfo(Result);
    Conn->In = HeapAlloc(GetProcessHeap(), 0, 65536);
    return Conn->In != NULL;
}

static void Disconnect(CONNECTION *Conn)
{
    if (Conn->HaveCtx)
        DeleteSecurityContext(&Conn->Ctx);
    if (Conn->Cred.dwLower || Conn->Cred.dwUpper)
        FreeCredentialsHandle(&Conn->Cred);
    if (Conn->Socket != INVALID_SOCKET)
        closesocket(Conn->Socket);
    HeapFree(GetProcessHeap(), 0, Conn->In);
    ZeroMemory(Conn, sizeof(*Conn));
}

static SECURITY_STATUS Handshake(CONNECTION *Conn, PCWSTR Target, PVOID Auth)
{
    TimeStamp Expiry;
    SECURITY_STATUS Status;
    ULONG Attr;
    int Rounds;

    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, Auth, NULL, NULL,
                                       &Conn->Cred, &Expiry);
    if (Status != SEC_E_OK)
        return Status;

    for (Rounds = 0; Rounds < 20; Rounds++)
    {
        SecBuffer InBuf[2], OutBuf[1];
        SecBufferDesc InDesc, OutDesc;

        InBuf[0].BufferType = SECBUFFER_TOKEN;
        InBuf[0].cbBuffer = Conn->InSize;
        InBuf[0].pvBuffer = Conn->In;
        InBuf[1].BufferType = SECBUFFER_EMPTY;
        InBuf[1].cbBuffer = 0;
        InBuf[1].pvBuffer = NULL;
        InDesc.ulVersion = SECBUFFER_VERSION;
        InDesc.cBuffers = 2;
        InDesc.pBuffers = InBuf;
        OutBuf[0].BufferType = SECBUFFER_TOKEN;
        OutBuf[0].cbBuffer = 0;
        OutBuf[0].pvBuffer = NULL;
        OutDesc.ulVersion = SECBUFFER_VERSION;
        OutDesc.cBuffers = 1;
        OutDesc.pBuffers = OutBuf;

        Status = InitializeSecurityContextW(&Conn->Cred, Conn->HaveCtx ? &Conn->Ctx : NULL, (SEC_WCHAR *)Target, REQ_FLAGS,
                                            0, 0, Conn->HaveCtx ? &InDesc : NULL, 0, &Conn->Ctx, &OutDesc, &Attr, &Expiry);
        if (!Conn->HaveCtx && (Status == SEC_E_OK || Status == SEC_I_CONTINUE_NEEDED))
            Conn->HaveCtx = TRUE;
        if (OutBuf[0].pvBuffer)
        {
            if (OutBuf[0].cbBuffer && !SendAll(Conn->Socket, OutBuf[0].pvBuffer, OutBuf[0].cbBuffer))
                Status = SEC_E_INTERNAL_ERROR;
            FreeContextBuffer(OutBuf[0].pvBuffer);
        }

        if (Status == SEC_I_CONTINUE_NEEDED && InBuf[1].BufferType == SECBUFFER_EXTRA && Rounds)
        {
            memmove(Conn->In, Conn->In + Conn->InSize - InBuf[1].cbBuffer, InBuf[1].cbBuffer);
            Conn->InSize = InBuf[1].cbBuffer;
            continue;
        }
        if (Status == SEC_I_CONTINUE_NEEDED)
            Conn->InSize = 0;
        if (Status == SEC_I_CONTINUE_NEEDED || Status == SEC_E_INCOMPLETE_MESSAGE)
        {
            int Received = recv(Conn->Socket, (char *)Conn->In + Conn->InSize, 65536 - Conn->InSize, 0);
            if (Received <= 0)
                return SEC_E_INTERNAL_ERROR;
            Conn->InSize += Received;
            continue;
        }
        if (Status == SEC_E_OK)
            ok(Attr == RET_FLAGS, "attributes 0x%08lx, expected 0x%08lx\n", Attr, (ULONG)RET_FLAGS);
        return Status;
    }
    return SEC_E_INTERNAL_ERROR;
}

/* GET / over the established context; returns the first bytes of the response */
static BOOL HttpGet(CONNECTION *Conn, PCSTR Host, char *Reply, ULONG ReplySize)
{
    SecPkgContext_StreamSizes Sizes;
    SecBuffer Buf[4];
    SecBufferDesc Desc;
    SECURITY_STATUS Status;
    char Request[256], *Message;
    int Length, i, Tries;

    Reply[0] = 0;
    if (QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_STREAM_SIZES, &Sizes) != SEC_E_OK)
        return FALSE;
    Length = sprintf(Request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ReactOS-apitest\r\nConnection: close\r\n\r\n", Host);
    Message = HeapAlloc(GetProcessHeap(), 0, Sizes.cbHeader + Length + Sizes.cbTrailer);
    if (!Message)
        return FALSE;
    memcpy(Message + Sizes.cbHeader, Request, Length);
    Buf[0].BufferType = SECBUFFER_STREAM_HEADER; Buf[0].pvBuffer = Message; Buf[0].cbBuffer = Sizes.cbHeader;
    Buf[1].BufferType = SECBUFFER_DATA; Buf[1].pvBuffer = Message + Sizes.cbHeader; Buf[1].cbBuffer = Length;
    Buf[2].BufferType = SECBUFFER_STREAM_TRAILER; Buf[2].pvBuffer = Message + Sizes.cbHeader + Length; Buf[2].cbBuffer = Sizes.cbTrailer;
    Buf[3].BufferType = SECBUFFER_EMPTY; Buf[3].pvBuffer = NULL; Buf[3].cbBuffer = 0;
    Desc.ulVersion = SECBUFFER_VERSION;
    Desc.cBuffers = 4;
    Desc.pBuffers = Buf;
    Status = EncryptMessage(&Conn->Ctx, 0, &Desc, 0);
    ok(Status == SEC_E_OK, "EncryptMessage returned 0x%08lx\n", Status);
    if (Status != SEC_E_OK || !SendAll(Conn->Socket, Message, Buf[0].cbBuffer + Buf[1].cbBuffer + Buf[2].cbBuffer))
    {
        HeapFree(GetProcessHeap(), 0, Message);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, Message);

    Conn->InSize = 0;
    for (Tries = 0; Tries < 50; Tries++)
    {
        int Received = recv(Conn->Socket, (char *)Conn->In + Conn->InSize, 65536 - Conn->InSize, 0);
        if (Received <= 0)
            return FALSE;
        Conn->InSize += Received;
        Buf[0].BufferType = SECBUFFER_DATA; Buf[0].pvBuffer = Conn->In; Buf[0].cbBuffer = Conn->InSize;
        Buf[1].BufferType = Buf[2].BufferType = Buf[3].BufferType = SECBUFFER_EMPTY;
        Buf[1].cbBuffer = Buf[2].cbBuffer = Buf[3].cbBuffer = 0;
        Status = DecryptMessage(&Conn->Ctx, &Desc, 0, NULL);
        if (Status == SEC_E_INCOMPLETE_MESSAGE)
            continue;
        ok(Status == SEC_E_OK, "DecryptMessage returned 0x%08lx\n", Status);
        for (i = 0; i < 4; i++)
        {
            if (Buf[i].BufferType == SECBUFFER_DATA)
            {
                ULONG Copy = min(Buf[i].cbBuffer, ReplySize - 1);
                memcpy(Reply, Buf[i].pvBuffer, Copy);
                Reply[Copy] = 0;
                return TRUE;
            }
        }
        return FALSE;
    }
    return FALSE;
}

/*
 * RFC 5929 channel bindings, which .NET Framework asks for on every SslStream connection (TransportContext):
 * the application data is "tls-server-end-point:" plus the hash of the server certificate (the hash of its signature
 * algorithm, SHA-256 for MD5, SHA-1 and others), or "tls-unique:" plus the 12 byte Finished of a TLS 1.2 handshake.
 * Layout and hash selection as measured on Windows 10 22H2 (oracle-bindprobe-win10-19045.txt of the SSPI ticket).
 */
static void CheckBindingsLayout(PCSTR Host, PCSTR Name, const SecPkgContext_Bindings *Bind, PCSTR Prefix, ULONG DataSize,
                                const BYTE *Data)
{
    ULONG PrefixSize = (ULONG)strlen(Prefix);
    const BYTE *App;

    ok(Bind->Bindings != NULL, "%s: %s: no bindings\n", Host, Name);
    if (!Bind->Bindings)
        return;
    ok(Bind->BindingsLength == sizeof(*Bind->Bindings) + PrefixSize + DataSize, "%s: %s: length %lu\n", Host, Name,
       Bind->BindingsLength);
    ok(!Bind->Bindings->dwInitiatorAddrType && !Bind->Bindings->cbInitiatorLength && !Bind->Bindings->dwInitiatorOffset,
       "%s: %s: initiator %lu/%lu/%lu\n", Host, Name, Bind->Bindings->dwInitiatorAddrType, Bind->Bindings->cbInitiatorLength,
       Bind->Bindings->dwInitiatorOffset);
    ok(!Bind->Bindings->dwAcceptorAddrType && !Bind->Bindings->cbAcceptorLength && !Bind->Bindings->dwAcceptorOffset,
       "%s: %s: acceptor %lu/%lu/%lu\n", Host, Name, Bind->Bindings->dwAcceptorAddrType, Bind->Bindings->cbAcceptorLength,
       Bind->Bindings->dwAcceptorOffset);
    ok(Bind->Bindings->cbApplicationDataLength == PrefixSize + DataSize, "%s: %s: application data %lu\n", Host, Name,
       Bind->Bindings->cbApplicationDataLength);
    ok(Bind->Bindings->dwApplicationDataOffset == sizeof(*Bind->Bindings), "%s: %s: application data offset %lu\n", Host,
       Name, Bind->Bindings->dwApplicationDataOffset);
    if (Bind->BindingsLength >= sizeof(*Bind->Bindings) + PrefixSize + DataSize)
    {
        App = (const BYTE *)(Bind->Bindings + 1);
        ok(!memcmp(App, Prefix, PrefixSize), "%s: %s: prefix\n", Host, Name);
        if (Data)
            ok(!memcmp(App + PrefixSize, Data, DataSize), "%s: %s: data differs\n", Host, Name);
    }
}

static void CheckBindings(CONNECTION *Conn, PCSTR Host, PCCERT_CONTEXT Remote, DWORD Protocol)
{
    SecPkgContext_Bindings Bind;
    SECURITY_STATUS Status;
    PCSTR SigOid = Remote->pCertInfo->SignatureAlgorithm.pszObjId;
    ALG_ID Alg = CALG_SHA_256;
    BYTE Hash[64];
    ULONG HashSize = sizeof(Hash);

    if (SigOid && (!strcmp(SigOid, "1.2.840.113549.1.1.12") || !strcmp(SigOid, "1.2.840.10045.4.3.3")))
        Alg = CALG_SHA_384;
    else if (SigOid && (!strcmp(SigOid, "1.2.840.113549.1.1.13") || !strcmp(SigOid, "1.2.840.10045.4.3.4")))
        Alg = CALG_SHA_512;

    memset(&Bind, 0xcc, sizeof(Bind));
    Status = QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_ENDPOINT_BINDINGS, &Bind);
    ok(Status == SEC_E_OK, "%s: ENDPOINT_BINDINGS returned 0x%08lx\n", Host, Status);
    if (Status == SEC_E_OK)
    {
        ok(CryptHashCertificate(0, Alg, 0, Remote->pbCertEncoded, Remote->cbCertEncoded, Hash, &HashSize),
           "%s: cannot hash the certificate\n", Host);
        trace("%s: certificate signature %s, endpoint binding hash %lu bytes\n", Host, SigOid, HashSize);
        CheckBindingsLayout(Host, "ENDPOINT_BINDINGS", &Bind, "tls-server-end-point:", HashSize, Hash);
        FreeContextBuffer(Bind.Bindings);
    }

    if (Protocol != SP_PROT_TLS1_2_CLIENT)
        return;
    memset(&Bind, 0xcc, sizeof(Bind));
    Status = QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_UNIQUE_BINDINGS, &Bind);
    ok(Status == SEC_E_OK, "%s: UNIQUE_BINDINGS returned 0x%08lx\n", Host, Status);
    if (Status == SEC_E_OK)
    {
        CheckBindingsLayout(Host, "UNIQUE_BINDINGS", &Bind, "tls-unique:", 12, NULL);
        FreeContextBuffer(Bind.Bindings);
    }
}

static void CheckEstablished(CONNECTION *Conn, PCSTR Host, PCWSTR Target)
{
    SecPkgContext_ConnectionInfo Info;
    SecPkgContext_StreamSizes Sizes;
    PCCERT_CONTEXT Remote = NULL;
    SECURITY_STATUS Status;
    char Reply[64];

    memset(&Info, 0, sizeof(Info));
    Status = QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_CONNECTION_INFO, &Info);
    ok(Status == SEC_E_OK, "%s: CONNECTION_INFO returned 0x%08lx\n", Host, Status);
    if (Status == SEC_E_OK)
    {
        trace("%s: protocol 0x%lx cipher 0x%x/%lu hash 0x%x/%lu exchange 0x%x/%lu\n", Host, Info.dwProtocol, Info.aiCipher,
              Info.dwCipherStrength, Info.aiHash, Info.dwHashStrength, Info.aiExch, Info.dwExchStrength);
        ok(Info.dwProtocol == SP_PROT_TLS1_2_CLIENT || Info.dwProtocol == SP_PROT_TLS1_3_CLIENT,
           "%s: protocol 0x%lx\n", Host, Info.dwProtocol);
        ok(Info.dwCipherStrength >= 128, "%s: cipher strength %lu\n", Host, Info.dwCipherStrength);
    }

    Status = QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    ok(Status == SEC_E_OK, "%s: STREAM_SIZES returned 0x%08lx\n", Host, Status);
    if (Status == SEC_E_OK)
    {
        ok(Sizes.cbHeader >= 5 && Sizes.cbTrailer > 0, "%s: header %lu trailer %lu\n", Host, Sizes.cbHeader, Sizes.cbTrailer);
        ok(Sizes.cbMaximumMessage == 16384, "%s: maximum message %lu\n", Host, Sizes.cbMaximumMessage);
        ok(Sizes.cbBuffers == 4, "%s: buffers %lu\n", Host, Sizes.cbBuffers);
    }

    /* No ALPN was offered: nothing negotiated (curl requires the query to succeed) */
    {
        SecPkgContext_ApplicationProtocol Protocol;

        memset(&Protocol, 0xcc, sizeof(Protocol));
        Status = QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_APPLICATION_PROTOCOL, &Protocol);
        ok(Status == SEC_E_OK, "%s: APPLICATION_PROTOCOL returned 0x%08lx\n", Host, Status);
        if (Status == SEC_E_OK)
            ok(Protocol.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_None &&
               Protocol.ProtoNegoExt == SecApplicationProtocolNegotiationExt_None,
               "%s: ALPN status %d, extension %d\n", Host, Protocol.ProtoNegoStatus, Protocol.ProtoNegoExt);
    }

    Status = QueryContextAttributesW(&Conn->Ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &Remote);
    ok(Status == SEC_E_OK && Remote, "%s: REMOTE_CERT_CONTEXT returned 0x%08lx\n", Host, Status);
    if (Status == SEC_E_OK && Remote)
    {
        PCCERT_CONTEXT Iter = NULL;
        CERT_CHAIN_PARA ChainPara;
        PCCERT_CHAIN_CONTEXT Chain = NULL;
        ULONG Count = 0;

        while ((Iter = CertEnumCertificatesInStore(Remote->hCertStore, Iter)))
            Count++;
        ok(Count >= 2, "%s: %lu certificates in the remote store, intermediates missing\n", Host, Count);

        /* What .NET does with SCH_CRED_MANUAL_CRED_VALIDATION: chain to the root store, SSL policy for the name */
        ZeroMemory(&ChainPara, sizeof(ChainPara));
        ChainPara.cbSize = sizeof(ChainPara);
        ok(CertGetCertificateChain(NULL, Remote, NULL, Remote->hCertStore, &ChainPara, 0, NULL, &Chain),
           "%s: CertGetCertificateChain failed (%lu)\n", Host, GetLastError());
        if (Chain)
        {
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA SslPara;
            CERT_CHAIN_POLICY_PARA PolicyPara;
            CERT_CHAIN_POLICY_STATUS PolicyStatus;

            ok(Chain->TrustStatus.dwErrorStatus == 0, "%s: chain error status 0x%lx\n", Host, Chain->TrustStatus.dwErrorStatus);
            ZeroMemory(&SslPara, sizeof(SslPara));
            SslPara.cbSize = sizeof(SslPara);
            SslPara.dwAuthType = AUTHTYPE_SERVER;
            SslPara.pwszServerName = (PWSTR)Target;
            ZeroMemory(&PolicyPara, sizeof(PolicyPara));
            PolicyPara.cbSize = sizeof(PolicyPara);
            PolicyPara.pvExtraPolicyPara = &SslPara;
            ZeroMemory(&PolicyStatus, sizeof(PolicyStatus));
            PolicyStatus.cbSize = sizeof(PolicyStatus);
            ok(CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, Chain, &PolicyPara, &PolicyStatus),
               "%s: CertVerifyCertificateChainPolicy failed\n", Host);
            ok(PolicyStatus.dwError == 0, "%s: SSL policy error 0x%lx\n", Host, PolicyStatus.dwError);
            CertFreeCertificateChain(Chain);
        }
        CheckBindings(Conn, Host, Remote, Info.dwProtocol);
        CertFreeCertificateContext(Remote);
    }

    ok(HttpGet(Conn, Host, Reply, sizeof(Reply)), "%s: no HTTP reply\n", Host);
    ok(!strncmp(Reply, "HTTP/1.1 ", 9), "%s: reply \"%.20s\"\n", Host, Reply);
}

static BOOL TestServer(PCSTR Host, PCSTR Port, PCWSTR Target, DWORD Flags, DWORD Disabled,
                       SECURITY_STATUS Expected, DWORD ExpectedProtocol, BOOL Full)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CONNECTION Conn;
    SECURITY_STATUS Status;

    if (!Connect(&Conn, Host, Port))
    {
        skip("cannot connect to %s:%s\n", Host, Port);
        Disconnect(&Conn);
        return FALSE;
    }
    InitCred(&Cred, &Params, Flags, Disabled);
    Status = Handshake(&Conn, Target, &Cred);
    ok(Status == Expected, "%s:%s flags 0x%lx disabled 0x%lx: handshake returned 0x%08lx, expected 0x%08lx\n",
       Host, Port, Flags, Disabled, Status, (ULONG)Expected);
    if (Status == SEC_E_OK && ExpectedProtocol)
    {
        SecPkgContext_ConnectionInfo Info;
        ok(QueryContextAttributesW(&Conn.Ctx, SECPKG_ATTR_CONNECTION_INFO, &Info) == SEC_E_OK &&
           Info.dwProtocol == ExpectedProtocol, "%s: protocol 0x%lx, expected 0x%lx\n", Host, Info.dwProtocol, ExpectedProtocol);
    }
    if (Status == SEC_E_OK && Full)
        CheckEstablished(&Conn, Host, Target);
    Disconnect(&Conn);
    return TRUE;
}

/*
 * ApplyControlToken, then an output buffer that is too small for the alert record: the request is kept
 * (SEC_E_BUFFER_TOO_SMALL), and the retry delivers the rest of the same record, not a second alert.
 * Offline: the alert goes out in the clear right after the ClientHello.
 */
static void TestControlTokenSmallBuffer(void)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CredHandle CredHandle;
    CtxtHandle Ctx;
    TimeStamp Expiry;
    SecBuffer Out, Buf;
    SecBufferDesc OutDesc, Desc;
    SCHANNEL_ALERT_TOKEN Token;
    ULONG Attr = 0, Total = 0;
    SECURITY_STATUS Status;
    BYTE Small[3], Large[64], Record[128] = {0};
    ULONG Length;

    InitCred(&Cred, &Params, SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, 0);
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cred, NULL, NULL,
                                       &CredHandle, &Expiry);
    ok(Status == SEC_E_OK, "AcquireCredentialsHandle returned 0x%08lx\n", Status);
    if (Status != SEC_E_OK)
        return;

    Out.BufferType = SECBUFFER_TOKEN;
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;
    Status = InitializeSecurityContextW(&CredHandle, NULL, (SEC_WCHAR *)SNI_HOST, REQ_FLAGS, 0, 0, NULL, 0, &Ctx,
                                        &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_I_CONTINUE_NEEDED, "InitializeSecurityContext returned 0x%08lx\n", Status);
    if (Status != SEC_I_CONTINUE_NEEDED)
    {
        FreeCredentialsHandle(&CredHandle);
        return;
    }
    if (Out.pvBuffer)
        FreeContextBuffer(Out.pvBuffer);

    Token.dwTokenType = SCHANNEL_ALERT;
    Token.dwAlertType = TLS1_ALERT_FATAL;
    Token.dwAlertNumber = TLS1_ALERT_HANDSHAKE_FAILURE;
    Buf.BufferType = SECBUFFER_TOKEN;
    Buf.cbBuffer = sizeof(Token);
    Buf.pvBuffer = &Token;
    Desc.ulVersion = SECBUFFER_VERSION;
    Desc.cBuffers = 1;
    Desc.pBuffers = &Buf;
    Status = ApplyControlToken(&Ctx, &Desc);
    ok(Status == SEC_E_OK, "ApplyControlToken returned 0x%08lx\n", Status);

    /* A caller buffer of its own, smaller than the 7 byte record */
    Out.cbBuffer = sizeof(Small);
    Out.pvBuffer = Small;
    Status = InitializeSecurityContextW(&CredHandle, &Ctx, (SEC_WCHAR *)SNI_HOST, REQ_FLAGS & ~ISC_REQ_ALLOCATE_MEMORY,
                                        0, 0, NULL, 0, &Ctx, &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_E_BUFFER_TOO_SMALL, "too small buffer: InitializeSecurityContext returned 0x%08lx\n", Status);
    if (Status == SEC_E_BUFFER_TOO_SMALL && !is_reactos())
    {
        /* Windows 10 returns the size it needs, delivers nothing and drops the request */
        Out.cbBuffer = sizeof(Large);
        Out.pvBuffer = Large;
        Status = InitializeSecurityContextW(&CredHandle, &Ctx, (SEC_WCHAR *)SNI_HOST,
                                            REQ_FLAGS & ~ISC_REQ_ALLOCATE_MEMORY, 0, 0, NULL, 0, &Ctx, &OutDesc, &Attr,
                                            &Expiry);
        ok(Status == SEC_E_INCOMPLETE_MESSAGE, "retry: InitializeSecurityContext returned 0x%08lx\n", Status);
    }
    else if (Status == SEC_E_BUFFER_TOO_SMALL)
    {
        /* This provider keeps the request and delivers what fits, the retry continues the same record. The old
         * retry built the alert again, which queued a second record behind the first. */
        ok(Out.cbBuffer <= sizeof(Small), "too small buffer: %lu bytes\n", Out.cbBuffer);
        Total = Out.cbBuffer <= sizeof(Small) ? Out.cbBuffer : 0;
        memcpy(Record, Small, Total);

        Out.cbBuffer = sizeof(Large);
        Out.pvBuffer = Large;
        Status = InitializeSecurityContextW(&CredHandle, &Ctx, (SEC_WCHAR *)SNI_HOST,
                                            REQ_FLAGS & ~ISC_REQ_ALLOCATE_MEMORY, 0, 0, NULL, 0, &Ctx, &OutDesc, &Attr,
                                            &Expiry);
        ok(Status == SEC_E_OK, "retry: InitializeSecurityContext returned 0x%08lx\n", Status);
        ok(Total + Out.cbBuffer <= sizeof(Record), "retry: %lu bytes\n", Out.cbBuffer);
        if (Total + Out.cbBuffer <= sizeof(Record))
        {
            memcpy(Record + Total, Large, Out.cbBuffer);
            Total += Out.cbBuffer;
        }

        /* Exactly one alert record in what the two calls returned: the 7 byte plaintext record */
        Length = Total > 4 ? 5 + ((Record[3] << 8) | Record[4]) : 0;
        ok(Total == 7 && Length == Total && Record[0] == 0x15 && Record[5] == TLS1_ALERT_FATAL &&
           Record[6] == TLS1_ALERT_HANDSHAKE_FAILURE, "%lu bytes in total, record length %lu, %02x %02x %02x %02x %02x\n",
           Total, Length, Record[0], Record[1], Record[2], Record[5], Record[6]);
    }

    /* Nothing pending any more */
    Out.cbBuffer = sizeof(Large);
    Out.pvBuffer = Large;
    Status = InitializeSecurityContextW(&CredHandle, &Ctx, (SEC_WCHAR *)SNI_HOST, REQ_FLAGS & ~ISC_REQ_ALLOCATE_MEMORY,
                                        0, 0, NULL, 0, &Ctx, &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_E_INCOMPLETE_MESSAGE, "after the alert: InitializeSecurityContext returned 0x%08lx\n", Status);

    DeleteSecurityContext(&Ctx);
    FreeCredentialsHandle(&CredHandle);
}

/* ApplyControlToken: the next InitializeSecurityContext returns the (encrypted) alert record */
static void TestControlToken(DWORD Type)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params;
    CONNECTION Conn;
    SCHANNEL_ALERT_TOKEN Token;
    SecBuffer Buf, Out, In[2];
    SecBufferDesc Desc, OutDesc, InDesc;
    TimeStamp Expiry;
    ULONG Attr;
    SECURITY_STATUS Status;
    BYTE *Record;

    if (!Connect(&Conn, "example.com", "443"))
    {
        skip("cannot connect to example.com\n");
        Disconnect(&Conn);
        return;
    }
    InitCred(&Cred, &Params, SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS, 0);
    Status = Handshake(&Conn, L"example.com", &Cred);
    ok(Status == SEC_E_OK, "handshake returned 0x%08lx\n", Status);
    if (Status != SEC_E_OK)
    {
        Disconnect(&Conn);
        return;
    }

    Token.dwTokenType = Type;
    Token.dwAlertType = TLS1_ALERT_FATAL;
    Token.dwAlertNumber = TLS1_ALERT_BAD_CERTIFICATE;
    Buf.BufferType = SECBUFFER_TOKEN;
    Buf.cbBuffer = Type == SCHANNEL_SHUTDOWN ? sizeof(DWORD) : sizeof(Token);
    Buf.pvBuffer = &Token;
    Desc.ulVersion = SECBUFFER_VERSION;
    Desc.cBuffers = 1;
    Desc.pBuffers = &Buf;
    Status = ApplyControlToken(&Conn.Ctx, &Desc);
    ok(Status == SEC_E_OK, "type %lu: ApplyControlToken returned 0x%08lx\n", Type, Status);

    /* .NET passes an empty input token here, others no input at all */
    Out.BufferType = SECBUFFER_TOKEN;
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    OutDesc.ulVersion = SECBUFFER_VERSION;
    OutDesc.cBuffers = 1;
    OutDesc.pBuffers = &Out;
    In[0].BufferType = SECBUFFER_TOKEN;
    In[0].cbBuffer = 0;
    In[0].pvBuffer = Conn.In;
    In[1].BufferType = SECBUFFER_EMPTY;
    In[1].cbBuffer = 0;
    In[1].pvBuffer = NULL;
    InDesc.ulVersion = SECBUFFER_VERSION;
    InDesc.cBuffers = 2;
    InDesc.pBuffers = In;
    Status = InitializeSecurityContextW(&Conn.Cred, &Conn.Ctx, (SEC_WCHAR *)L"example.com", REQ_FLAGS, 0, 0,
                                        Type == SCHANNEL_SHUTDOWN ? NULL : &InDesc, 0, &Conn.Ctx, &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_E_OK, "type %lu: InitializeSecurityContext returned 0x%08lx\n", Type, Status);
    Record = Out.pvBuffer;
    /* An encrypted alert: record type 21, TLS 1.2, more than the two plain bytes */
    ok(Out.cbBuffer > 7 && Record && Record[0] == 0x15 && Record[1] == 3 && Record[2] == 3 &&
       ((Record[3] << 8) | Record[4]) == Out.cbBuffer - 5,
       "type %lu: output %lu bytes, %02x %02x %02x\n", Type, Out.cbBuffer, Record ? Record[0] : 0,
       Record && Out.cbBuffer > 1 ? Record[1] : 0, Record && Out.cbBuffer > 2 ? Record[2] : 0);
    if (Out.pvBuffer)
    {
        SendAll(Conn.Socket, Out.pvBuffer, Out.cbBuffer);
        FreeContextBuffer(Out.pvBuffer);
    }

    /* Nothing pending any more */
    Out.cbBuffer = 0;
    Out.pvBuffer = NULL;
    Status = InitializeSecurityContextW(&Conn.Cred, &Conn.Ctx, (SEC_WCHAR *)L"example.com", REQ_FLAGS, 0, 0, NULL, 0,
                                        &Conn.Ctx, &OutDesc, &Attr, &Expiry);
    ok(Status == SEC_E_INCOMPLETE_MESSAGE, "type %lu: second call returned 0x%08lx\n", Type, Status);
    if (Out.pvBuffer)
        FreeContextBuffer(Out.pvBuffer);

    /* Windows 10 keeps the context usable after close_notify or a fatal alert: ending the connection is up to the caller */
    {
        SecPkgContext_StreamSizes Sizes;
        SecBuffer Msg[4];
        SecBufferDesc MsgDesc;
        BYTE Data[512];

        if (QueryContextAttributesW(&Conn.Ctx, SECPKG_ATTR_STREAM_SIZES, &Sizes) == SEC_E_OK &&
            Sizes.cbHeader + 16 + Sizes.cbTrailer <= sizeof(Data))
        {
            memset(Data, 'x', sizeof(Data));
            Msg[0].BufferType = SECBUFFER_STREAM_HEADER; Msg[0].pvBuffer = Data; Msg[0].cbBuffer = Sizes.cbHeader;
            Msg[1].BufferType = SECBUFFER_DATA; Msg[1].pvBuffer = Data + Sizes.cbHeader; Msg[1].cbBuffer = 16;
            Msg[2].BufferType = SECBUFFER_STREAM_TRAILER; Msg[2].pvBuffer = Data + Sizes.cbHeader + 16;
            Msg[2].cbBuffer = Sizes.cbTrailer;
            Msg[3].BufferType = SECBUFFER_EMPTY; Msg[3].pvBuffer = NULL; Msg[3].cbBuffer = 0;
            MsgDesc.ulVersion = SECBUFFER_VERSION;
            MsgDesc.cBuffers = 4;
            MsgDesc.pBuffers = Msg;
            Status = EncryptMessage(&Conn.Ctx, 0, &MsgDesc, 0);
            ok(Status == SEC_E_OK, "type %lu: EncryptMessage after the alert returned 0x%08lx\n", Type, Status);
        }
    }

    /* and a second shutdown request sends another close_notify */
    if (Type == SCHANNEL_SHUTDOWN)
    {
        Buf.cbBuffer = sizeof(DWORD);
        Status = ApplyControlToken(&Conn.Ctx, &Desc);
        ok(Status == SEC_E_OK, "second ApplyControlToken returned 0x%08lx\n", Status);
        Out.cbBuffer = 0;
        Out.pvBuffer = NULL;
        Status = InitializeSecurityContextW(&Conn.Cred, &Conn.Ctx, (SEC_WCHAR *)L"example.com", REQ_FLAGS, 0, 0, NULL, 0,
                                            &Conn.Ctx, &OutDesc, &Attr, &Expiry);
        trace("second shutdown: 0x%08lx, %lu bytes\n", Status, Out.cbBuffer);
        ok(Status == SEC_E_OK, "second shutdown: InitializeSecurityContext returned 0x%08lx\n", Status);
        ok(Out.cbBuffer > 7 && Out.pvBuffer && ((BYTE *)Out.pvBuffer)[0] == 0x15,
           "second shutdown: %lu bytes, no alert record\n", Out.cbBuffer);
        if (Out.pvBuffer)
            FreeContextBuffer(Out.pvBuffer);
    }
    Disconnect(&Conn);
}

static BOOL EnvEnabled(PCSTR Name)
{
    char Value[8];
    DWORD Length = GetEnvironmentVariableA(Name, Value, sizeof(Value));

    return Length && Length < sizeof(Value) && strcmp(Value, "0");
}

static void TestOnline(void)
{
    const DWORD Manual = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

    /* What .NET 8 sends for SslProtocols.None, and for Tls12 */
    if (!TestServer("github.com", "443", L"github.com", Manual, 0, SEC_E_OK, 0, TRUE))
        return;
    TestServer("github.com", "443", L"github.com", Manual, ~(DWORD)(SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_2_SERVER), SEC_E_OK,
               SP_PROT_TLS1_2_CLIENT, FALSE);
    TestServer("example.com", "443", L"example.com", Manual, 0, SEC_E_OK, 0, TRUE);
    TestControlToken(SCHANNEL_SHUTDOWN);
    TestControlToken(SCHANNEL_ALERT);
    /* A server that refuses every offered version (protocol_version alert) */
    TestServer("github.com", "443", L"github.com", Manual, ~(DWORD)SP_PROT_TLS1_0, SEC_E_UNSUPPORTED_FUNCTION, 0, FALSE);

    /* schannel validates the server itself without the manual flag */
    TestServer("github.com", "443", L"github.com", 0, 0, SEC_E_OK, 0, FALSE);

    /* Third-party test endpoints, which come and go: opt-in */
    if (!EnvEnabled("SCHANNEL_APITEST_BADSSL"))
    {
        skip("badssl.com checks: set SCHANNEL_APITEST_BADSSL=1\n");
        return;
    }
    if (TestServer("self-signed.badssl.com", "443", L"self-signed.badssl.com", 0, 0, SEC_E_UNTRUSTED_ROOT, 0, FALSE))
    {
        TestServer("expired.badssl.com", "443", L"expired.badssl.com", 0, 0, SEC_E_CERT_EXPIRED, 0, FALSE);
        TestServer("wrong.host.badssl.com", "443", L"wrong.host.badssl.com", 0, 0, SEC_E_WRONG_PRINCIPAL, 0, FALSE);
        TestServer("untrusted-root.badssl.com", "443", L"untrusted-root.badssl.com", 0, 0, SEC_E_UNTRUSTED_ROOT, 0, FALSE);
        /* Protocol floor: TLS 1.0 is a Windows 10 client default, and a disabled protocol is never negotiated */
        TestServer("tls-v1-0.badssl.com", "1010", L"tls-v1-0.badssl.com", Manual, 0, SEC_E_OK, SP_PROT_TLS1_0_CLIENT, FALSE);
        TestServer("tls-v1-0.badssl.com", "1010", L"tls-v1-0.badssl.com", Manual, SP_PROT_TLS1_0, SEC_E_ALGORITHM_MISMATCH, 0, FALSE);
        TestServer("tls-v1-1.badssl.com", "1011", L"tls-v1-1.badssl.com", Manual, SP_PROT_TLS1_0 | SP_PROT_TLS1_1,
                   SEC_E_ALGORITHM_MISMATCH, 0, FALSE);
    }
}

START_TEST(SchannelHandshake)
{
    WSADATA WsaData;

    /* Offline: the ClientHello follows the credential */
    TestClientHello("default", 0, 0x0303);
    TestClientHello("TLS 1.2 disabled", SP_PROT_TLS1_2, 0x0302);
    TestClientHello("TLS 1.0 only", ~(DWORD)SP_PROT_TLS1_0, 0x0301);
    TestClientHello("TLS 1.0 and 1.1 disabled", SP_PROT_TLS1_0 | SP_PROT_TLS1_1, 0x0303);
    /* Server bits do not apply to an outbound credential (Windows 10 22H2: the ClientHello is the default one) */
    TestClientHello("TLS 1.2 server bit disabled", SP_PROT_TLS1_2_SERVER, 0x0303);
    TestClientHello("TLS 1.1 server bit disabled", SP_PROT_TLS1_1_SERVER, 0x0303);
    TestClientHello("all server bits disabled", SP_PROT_SSL3_SERVER | SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER |
                    SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER, 0x0303);
    TestControlTokenSmallBuffer();
    TestReturnedAttributes();
    TestNoSniForAddress(L"192.0.2.1");
    TestNoSniForAddress(L"2001:db8::1");
    /* The ServerHello version against the credential's protocols */
    TestServerHelloVersion("TLS 1.1 enabled", 0, 0x0302, FALSE);
    TestServerHelloVersion("TLS 1.1 between enabled 1.0 and 1.2", SP_PROT_TLS1_1, 0x0302, TRUE);
    TestServerHelloVersion("TLS 1.0 below the enabled range", SP_PROT_TLS1_0, 0x0301, TRUE);
    TestServerHelloVersion("TLS 1.2 enabled", SP_PROT_TLS1_1, 0x0303, FALSE);

    /* Online: real servers, opt-in (SCHANNEL_APITEST_ONLINE=1) so that runs without internet stay deterministic */
    if (!EnvEnabled("SCHANNEL_APITEST_ONLINE"))
    {
        skip("online handshakes: set SCHANNEL_APITEST_ONLINE=1\n");
        return;
    }
    if (WSAStartup(MAKEWORD(2, 2), &WsaData))
    {
        skip("WSAStartup failed\n");
        return;
    }
    TestOnline();
    WSACleanup();
}
