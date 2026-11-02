/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the request flows of the HTTP Server API (versions 1.0 and 2.0) against a loopback client
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every expectation was measured on Windows 10 22H2 with http.sys (x64): URL registration results, the match order
 * of the prefixes, the layout of the request buffer, the completion packets of overlapped calls on a request queue
 * that is bound to a completion port, the bytes of the responses.
 */

#include <apitest.h>
#include <winsock2.h>
#include <windows.h>
#include <http.h>
#include <stddef.h>

WINBASEAPI BOOL WINAPI SetFileCompletionNotificationModes(HANDLE, UCHAR);
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 2
ULONG WINAPI HttpShutdownRequestQueue(HANDLE);

#define PORT    18631
#define PORT1   18632
#define KEY     0x5a5a

/* The structures as the Microsoft compilers lay them out: the 64-bit members are 8-byte aligned on x86 too */
typedef ULONGLONG __attribute__((aligned(8))) U64A;

typedef struct
{
    ULONG Flags;
    U64A ConnectionId;
    U64A RequestId;
    U64A UrlContext;
    HTTP_VERSION Version;
    ULONG Verb;
    USHORT UnknownVerbLength;
    USHORT RawUrlLength;
    const char *pUnknownVerb;
    const char *pRawUrl;
    HTTP_COOKED_URL CookedUrl;
    HTTP_TRANSPORT_ADDRESS Address;
    HTTP_REQUEST_HEADERS Headers;
    U64A BytesReceived;
    USHORT EntityChunkCount;
    void *pEntityChunks;
    U64A RawConnectionId;
    void *pSslInfo;
    USHORT RequestInfoCount;
    void *pRequestInfo;
} TREQ;

typedef struct
{
    union
    {
        struct { ULONG Type; ULONG Pad; void *pBuffer; ULONG Length; } m;
        UCHAR Raw[32];
    } u;
} TCHUNK;

#ifdef _WIN64
C_ASSERT(sizeof(TREQ) == 864);
#endif
C_ASSERT(offsetof(TREQ, ConnectionId) == 8);
C_ASSERT(sizeof(TCHUNK) == 32);

typedef ULONG (WINAPI *PFN_Cancel)(HANDLE, HTTP_REQUEST_ID, OVERLAPPED *);
typedef ULONG (WINAPI *PFN_Wait)(HANDLE, HTTP_CONNECTION_ID, OVERLAPPED *);
typedef ULONG (WINAPI *PFN_Body)(HANDLE, HTTP_REQUEST_ID, ULONG, void *, ULONG, ULONG *, OVERLAPPED *);
typedef ULONG (WINAPI *PFN_SendBody)(HANDLE, HTTP_REQUEST_ID, ULONG, ULONG, void *, ULONG *, void *, ULONG, OVERLAPPED *, void *);

static HANDLE g_Queue, g_Port;
static HTTP_SERVER_SESSION_ID g_Session;
static HTTP_URL_GROUP_ID g_Group;
static PFN_SendBody pSendBody;

/* ---------------------------------------------------------------- loopback client */

typedef struct
{
    USHORT Port;
    const char *Part1, *Part2;
    DWORD Delay;
    DWORD IdleMs;
    BOOL CloseAfterDelay;
    char Raw[16384];
    int Len;
    BOOL Eof;
    BOOL Refused;
} CLIENT;

static DWORD WINAPI ClientThread(void *Param)
{
    CLIENT *C = Param;
    SOCKET S = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in A;
    int Idle = 0;

    memset(&A, 0, sizeof(A));
    A.sin_family = AF_INET;
    A.sin_port = htons(C->Port);
    A.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(S, (struct sockaddr *)&A, sizeof(A)))
    {
        C->Refused = TRUE;
        closesocket(S);
        return 0;
    }
    send(S, C->Part1, (int)strlen(C->Part1), 0);
    if (C->Part2)
    {
        Sleep(C->Delay);
        send(S, C->Part2, (int)strlen(C->Part2), 0);
    }
    if (C->CloseAfterDelay)
    {
        struct linger Li = { 1, 0 };

        Sleep(C->Delay);
        /* a FIN does not end a request for http.sys, a reset does */
        setsockopt(S, SOL_SOCKET, SO_LINGER, (char *)&Li, sizeof(Li));
        closesocket(S);
        return 0;
    }
    for (;;)
    {
        fd_set F;
        struct timeval Tv = { 0, 200000 };
        int R;

        FD_ZERO(&F);
        FD_SET(S, &F);
        R = select(0, &F, NULL, NULL, &Tv);
        if (R <= 0)
        {
            if ((DWORD)(++Idle * 200) > C->IdleMs)
                break;
            continue;
        }
        R = recv(S, C->Raw + C->Len, sizeof(C->Raw) - C->Len - 1, 0);
        if (R <= 0)
        {
            C->Eof = TRUE;
            break;
        }
        C->Len += R;
        Idle = 0;
    }
    C->Raw[C->Len] = 0;
    closesocket(S);
    return 0;
}

static HANDLE StartClient(CLIENT *C, USHORT Port, const char *P1, const char *P2, DWORD Delay, DWORD IdleMs, BOOL CloseAfterDelay)
{
    memset(C, 0, sizeof(*C));
    C->Port = Port;
    C->Part1 = P1;
    C->Part2 = P2;
    C->Delay = Delay;
    C->IdleMs = IdleMs;
    C->CloseAfterDelay = CloseAfterDelay;
    return CreateThread(NULL, 0, ClientThread, C, 0, NULL);
}

static void EndClient(HANDLE Th)
{
    ok(WaitForSingleObject(Th, 20000) == WAIT_OBJECT_0, "client thread did not finish\n");
    CloseHandle(Th);
}

/* ---------------------------------------------------------------- overlapped calls through the completion port */

static BOOL Wait(OVERLAPPED *O, ULONG *Err, DWORD *Bytes, DWORD Ms)
{
    DWORD N = 0;
    ULONG_PTR Key = 0;
    LPOVERLAPPED Po = NULL;
    BOOL Ok;

    SetLastError(0);
    Ok = GetQueuedCompletionStatus(g_Port, &N, &Key, &Po, Ms);
    *Err = Ok ? 0 : GetLastError();
    *Bytes = N;
    if (!Po)
        return FALSE;
    ok(Po == O, "packet of another operation\n");
    ok(Key == KEY, "completion key %Ix\n", Key);
    return Po == O;
}

static ULONG RecvIocp(HTTP_REQUEST_ID Id, ULONG Flags, void *Buf, ULONG Size, DWORD *Bytes)
{
    OVERLAPPED O;
    ULONG R, Err = 0xdead;
    ULONG Ret = 0;

    memset(&O, 0, sizeof(O));
    R = HttpReceiveHttpRequest(g_Queue, Id, Flags, Buf, Size, &Ret, &O);
    *Bytes = 0;
    if (R == ERROR_SUCCESS)
    {
        *Bytes = Ret; /* http.sys finishes at once when the request is there and the handle skips the packet */
        return 0;
    }
    if (R != ERROR_IO_PENDING)
    {
        ok(0, "HttpReceiveHttpRequest returned %lu\n", R);
        return R;
    }
    ok(Wait(&O, &Err, Bytes, 10000), "no completion of HttpReceiveHttpRequest\n");
    return Err;
}

static ULONG SendIocp(HTTP_REQUEST_ID Id, ULONG Flags, USHORT Status, const char *Reason, int KnownCount, const int *Ids,
                      HTTP_KNOWN_HEADER *Known, const char *Body, ULONG BodyLen, BOOL Entity)
{
    HTTP_RESPONSE Resp;
    TCHUNK Chunk;
    OVERLAPPED O;
    ULONG R, Err = 0xdead, Ret = 0;
    DWORD Bytes = 0;
    int i;

    memset(&Resp, 0, sizeof(Resp));
    memset(&Chunk, 0, sizeof(Chunk));
    memset(&O, 0, sizeof(O));
    Resp.s.StatusCode = Status;
    Resp.s.pReason = Reason;
    Resp.s.ReasonLength = Reason ? (USHORT)strlen(Reason) : 0;
    for (i = 0; i < KnownCount; i++)
        Resp.s.Headers.KnownHeaders[Ids[i]] = Known[i];
    if (Body)
    {
        Chunk.u.m.Type = HttpDataChunkFromMemory;
        Chunk.u.m.pBuffer = (void *)Body;
        Chunk.u.m.Length = BodyLen;
        Resp.s.EntityChunkCount = 1;
        Resp.s.pEntityChunks = (HTTP_DATA_CHUNK *)&Chunk;
    }
    if (Entity)
        R = pSendBody(g_Queue, Id, Flags, Body ? 1 : 0, Body ? &Chunk : NULL, &Ret, NULL, 0, &O, NULL);
    else
        R = HttpSendHttpResponse(g_Queue, Id, Flags, &Resp, NULL, &Ret, NULL, 0, &O, NULL);
    if (R == ERROR_SUCCESS)
        return 0;
    if (R != ERROR_IO_PENDING)
    {
        ok(R == ERROR_CONNECTION_INVALID, "send returned %lu\n", R);
        return R;
    }
    ok(Wait(&O, &Err, &Bytes, 10000), "no completion of the send\n");
    ok(Err == 0, "send completed with error %lu\n", Err);
    ok(Bytes != 0, "send completed with no bytes\n");
    return Err;
}

static BOOL StartsWith(const char *S, const char *P) { return !strncmp(S, P, strlen(P)); }

static const char *Find(const char *S, int Len, const char *P)
{
    int Pl = (int)strlen(P), i;

    for (i = 0; i + Pl <= Len; i++)
        if (!memcmp(S + i, P, Pl))
            return S + i;
    return NULL;
}

#define SAMPLE "GET /a/b/c%20d?x=1&y=%41 HTTP/1.1\r\nHost: 127.0.0.1:18631\r\nX-Custom-Hdr: V1\r\nx-custom-hdr:   V2  \r\n" \
               "Accept: text/html\r\nAccept: text/plain\r\nUser-Agent:  spaced value   \r\n\r\n"

static char g_Buf[65536];
#define Req ((TREQ *)g_Buf)

static void CheckSample(void)
{
    int i;
    BOOL Found = FALSE;

    ok(Req->Verb == HttpVerbGET, "verb %lu\n", Req->Verb);
    ok(Req->Version.MajorVersion == 1 && Req->Version.MinorVersion == 1, "version %u.%u\n", Req->Version.MajorVersion, Req->Version.MinorVersion);
    ok(Req->ConnectionId != 0 && Req->RequestId != 0, "no ids\n");
    ok(Req->UrlContext == 2, "UrlContext %I64u, the strong wildcard with the longer path should win\n", (ULONGLONG)Req->UrlContext);
    ok(Req->RawUrlLength == 20, "RawUrlLength %u\n", Req->RawUrlLength);
    ok(Req->pRawUrl && !strcmp(Req->pRawUrl, "/a/b/c%20d?x=1&y=%41"), "RawUrl %s\n", Req->pRawUrl);
    ok(Req->CookedUrl.FullUrlLength == 80, "FullUrlLength %u\n", Req->CookedUrl.FullUrlLength);
    ok(!wcscmp(Req->CookedUrl.pFullUrl, L"http://127.0.0.1:18631/a/b/c d?x=1&y=%41"), "FullUrl %ls\n", Req->CookedUrl.pFullUrl);
    ok(Req->CookedUrl.HostLength == 30 && !wcsncmp(Req->CookedUrl.pHost, L"127.0.0.1:18631", 15), "Host\n");
    ok(Req->CookedUrl.pHost == Req->CookedUrl.pFullUrl + 7, "pHost is not inside the full URL\n");
    ok(Req->CookedUrl.AbsPathLength == 16 && !wcsncmp(Req->CookedUrl.pAbsPath, L"/a/b/c d", 8), "AbsPath\n");
    ok(Req->CookedUrl.QueryStringLength == 20 && !wcsncmp(Req->CookedUrl.pQueryString, L"?x=1&y=%41", 10), "Query\n");
    ok(Req->Address.pLocalAddress && ((SOCKADDR_IN *)Req->Address.pLocalAddress)->sin_port == htons(PORT), "local address\n");
    ok(Req->Address.pRemoteAddress && ((SOCKADDR_IN *)Req->Address.pRemoteAddress)->sin_addr.s_addr == htonl(INADDR_LOOPBACK), "remote address\n");
    ok(Req->Headers.KnownHeaders[HttpHeaderHost].RawValueLength == 15 &&
       !memcmp(Req->Headers.KnownHeaders[HttpHeaderHost].pRawValue, "127.0.0.1:18631", 15), "Host header\n");
    ok(Req->Headers.KnownHeaders[HttpHeaderAccept].RawValueLength == 21 &&
       !memcmp(Req->Headers.KnownHeaders[HttpHeaderAccept].pRawValue, "text/html, text/plain", 21), "Accept is not joined\n");
    ok(Req->Headers.KnownHeaders[HttpHeaderUserAgent].RawValueLength == 12 &&
       !memcmp(Req->Headers.KnownHeaders[HttpHeaderUserAgent].pRawValue, "spaced value", 12), "User-Agent is not trimmed\n");
    ok(Req->Headers.UnknownHeaderCount == 1, "UnknownHeaderCount %u\n", Req->Headers.UnknownHeaderCount);
    for (i = 0; i < Req->Headers.UnknownHeaderCount; i++)
        if (Req->Headers.pUnknownHeaders[i].NameLength == 12 && !memcmp(Req->Headers.pUnknownHeaders[i].pName, "X-Custom-Hdr", 12))
        {
            Found = TRUE;
            ok(Req->Headers.pUnknownHeaders[i].RawValueLength == 6 && !memcmp(Req->Headers.pUnknownHeaders[i].pRawValue, "V1, V2", 6),
               "unknown header value\n");
        }
    ok(Found, "unknown header missing\n");
    ok(Req->BytesReceived == strlen(SAMPLE), "BytesReceived %I64u\n", (ULONGLONG)Req->BytesReceived);
    ok(Req->EntityChunkCount == 0 && !(Req->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS), "body flags\n");
}

static void Respond(HTTP_REQUEST_ID Id, const char *Body)
{
    ULONG R = SendIocp(Id, 0, 200, "OK", 0, NULL, NULL, Body, (ULONG)strlen(Body), FALSE);

    ok(R == 0, "send failed %lu\n", R);
}

START_TEST(HttpServerFlow)
{
    HTTPAPI_VERSION V2 = HTTPAPI_VERSION_2, V1 = HTTPAPI_VERSION_1;
    HTTP_BINDING_INFO Bind;
    WSADATA Wsa;
    ULONG R, Err;
    DWORD Bytes;
    CLIENT Cl;
    HANDLE Th;
    HTTP_REQUEST_ID Id;
    OVERLAPPED O;
    PFN_Cancel pCancel;
    PFN_Wait pWait;
    PFN_Body pBody;
    HMODULE Mod = LoadLibraryW(L"httpapi.dll");

    ok(Mod != NULL, "no httpapi.dll\n");
    if (!Mod)
        return;
    pCancel = (PFN_Cancel)GetProcAddress(Mod, "HttpCancelHttpRequest");
    pWait = (PFN_Wait)GetProcAddress(Mod, "HttpWaitForDisconnect");
    pBody = (PFN_Body)GetProcAddress(Mod, "HttpReceiveRequestEntityBody");
    pSendBody = (PFN_SendBody)GetProcAddress(Mod, "HttpSendResponseEntityBody");
    ok(pCancel && pWait && pBody && pSendBody, "exports missing\n");
    if (!pCancel || !pWait || !pBody || !pSendBody)
        return;
    WSAStartup(MAKEWORD(2, 2), &Wsa);

    ok(HttpInitialize(V2, HTTP_INITIALIZE_SERVER, NULL) == 0, "HttpInitialize\n");
    ok(HttpCreateServerSession(V2, &g_Session, 0) == 0, "session\n");
    ok(HttpCreateUrlGroup(g_Session, &g_Group, 0) == 0, "group\n");
    ok(HttpCreateRequestQueue(V2, NULL, NULL, 0, &g_Queue) == 0, "queue\n");
    Bind.Flags.Present = 1;
    Bind.RequestQueueHandle = g_Queue;
    ok(HttpSetUrlGroupProperty(g_Group, HttpServerBindingProperty, &Bind, sizeof(Bind)) == 0, "binding\n");
    g_Port = CreateIoCompletionPort(g_Queue, NULL, KEY, 0);
    ok(g_Port != NULL, "the request queue handle cannot be bound to a completion port: %lu\n", GetLastError());
    if (!g_Port)
        return;
    SetFileCompletionNotificationModes(g_Queue, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);

    /* --- registrations: results as measured with http.sys */
    R = HttpAddUrlToUrlGroup(g_Group, L"http://127.0.0.1:18631", 1, 0);
    ok(R == ERROR_INVALID_PARAMETER, "no slash after the port: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"http://127.0.0.1/", 1, 0);
    ok(R == ERROR_INVALID_PARAMETER, "no port: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"ftp://127.0.0.1:18631/", 1, 0);
    ok(R == ERROR_INVALID_PARAMETER, "scheme: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"http://127.0.0.1:18631/%41/", 1, 0);
    ok(R == ERROR_INVALID_PARAMETER, "escape: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"http://127.0.0.1:18631/", 1, 0);
    ok(R == 0, "add 1: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"http://127.0.0.1:18631/", 7, 0);
    ok(R == ERROR_ALREADY_EXISTS, "duplicate: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"HTTP://127.0.0.1:18631/", 7, 0);
    ok(R == ERROR_ALREADY_EXISTS, "duplicate in other case: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"http://+:18631/a/", 2, 0);
    ok(R == 0, "add strong: %lu\n", R);
    R = HttpAddUrlToUrlGroup(g_Group, L"http://*:18631/a/b/", 3, 0);
    ok(R == 0, "add weak: %lu\n", R);
    R = HttpRemoveUrlFromUrlGroup(g_Group, L"http://nothere:18631/", 0);
    ok(R == ERROR_FILE_NOT_FOUND, "remove unknown: %lu\n", R);

    /* --- a receive waits for the request; the packet arrives on the port */
    Th = StartClient(&Cl, PORT, SAMPLE, NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    Err = RecvIocp(0, HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY, g_Buf, sizeof(g_Buf), &Bytes);
    ok(Err == 0, "receive completed with %lu\n", Err);
    ok(Bytes > sizeof(TREQ) && Bytes < 4096, "bytes %lu\n", Bytes);
    if (Err == 0)
    {
        CheckSample();
        Id = Req->RequestId;
        Respond(Id, "hello");
    }
    EndClient(Th);
    ok(StartsWith(Cl.Raw, "HTTP/1.1 200 OK\r\n"), "response: %s\n", Cl.Raw);
    ok(Find(Cl.Raw, Cl.Len, "\r\nContent-Length: 5\r\n") != NULL, "no Content-Length\n");
    ok(Find(Cl.Raw, Cl.Len, "\r\nServer: Microsoft-HTTPAPI/2.0\r\n") != NULL, "no Server\n");
    ok(Find(Cl.Raw, Cl.Len, "\r\nDate: ") != NULL, "no Date\n");
    ok(Cl.Len > 9 && !memcmp(Cl.Raw + Cl.Len - 9, "\r\n\r\nhello", 9), "body\n");

    /* --- a buffer that is too small: ERROR_MORE_DATA with the size needed, the request keeps its id */
    Th = StartClient(&Cl, PORT, SAMPLE, NULL, 0, 800, FALSE);
    Sleep(300);
    memset(g_Buf, 0, sizeof(g_Buf));
    Err = RecvIocp(0, 0, g_Buf, sizeof(TREQ) + 40, &Bytes);
    ok(Err == ERROR_MORE_DATA, "small buffer: %lu\n", Err);
    ok(Bytes > sizeof(TREQ) + 40 && Bytes < 4096, "size needed %lu\n", Bytes);
    ok(Req->RequestId != 0, "no request id for the retry\n");
    Id = Req->RequestId;
    memset(g_Buf, 0, sizeof(g_Buf));
    Err = RecvIocp(Id, 0, g_Buf, sizeof(g_Buf), &Bytes);
    ok(Err == 0, "retry with the id: %lu\n", Err);
    ok(Req->RequestId == Id, "other request\n");
    Respond(Id, "x");
    EndClient(Th);
    ok(StartsWith(Cl.Raw, "HTTP/1.1 200 OK\r\n"), "response: %s\n", Cl.Raw);

    /* --- entity body: the part that is there comes with the request, the rest is read on a pending call */
    Th = StartClient(&Cl, PORT, "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabcde", "fghij", 500, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    Err = RecvIocp(0, HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY, g_Buf, sizeof(g_Buf), &Bytes);
    ok(Err == 0, "POST receive %lu\n", Err);
    if (Err == 0)
    {
        char Body[64];
        ULONG Ret = 0;
        TCHUNK *Ch = Req->pEntityChunks;

        Id = Req->RequestId;
        ok(Req->Verb == HttpVerbPOST, "verb\n");
        ok(Req->UrlContext == 1, "UrlContext %I64u\n", (ULONGLONG)Req->UrlContext);
        ok(Req->EntityChunkCount == 1 && Ch && Ch->u.m.Length == 5 && !memcmp(Ch->u.m.pBuffer, "abcde", 5), "chunk\n");
        ok(Req->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS, "no more-body flag\n");
        ok(Req->BytesReceived == 54, "BytesReceived %I64u\n", (ULONGLONG)Req->BytesReceived);
        memset(&O, 0, sizeof(O));
        R = pBody(g_Queue, Id, 0, Body, sizeof(Body), &Ret, &O);
        ok(R == ERROR_IO_PENDING, "body read returned %lu\n", R);
        if (R == ERROR_IO_PENDING)
        {
            ok(Wait(&O, &Err, &Bytes, 10000), "no packet for the body read\n");
            ok(Err == 0 && Bytes == 5 && !memcmp(Body, "fghij", 5), "body read: %lu, %lu bytes\n", Err, Bytes);
        }
        memset(&O, 0, sizeof(O));
        R = pBody(g_Queue, Id, 0, Body, sizeof(Body), &Ret, &O);
        ok(R == ERROR_HANDLE_EOF, "body read at the end returned %lu\n", R);
        Respond(Id, "done");
    }
    EndClient(Th);
    ok(Find(Cl.Raw, Cl.Len, "\r\nContent-Length: 4\r\n") != NULL, "response\n");

    /* --- chunked request body, delivered in two pieces */
    Th = StartClient(&Cl, PORT, "POST /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", "2\r\nde\r\n0\r\n\r\n", 400, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    Err = RecvIocp(0, HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY, g_Buf, sizeof(g_Buf), &Bytes);
    ok(Err == 0, "chunked receive %lu\n", Err);
    if (Err == 0)
    {
        char Body[64];
        ULONG Ret = 0, Got = 0;
        TCHUNK *Ch = Req->pEntityChunks;

        Id = Req->RequestId;
        if (Ch)
        {
            memcpy(Body, Ch->u.m.pBuffer, Ch->u.m.Length);
            Got = Ch->u.m.Length;
        }
        while (Got < 5)
        {
            memset(&O, 0, sizeof(O));
            R = pBody(g_Queue, Id, 0, Body + Got, 32, &Ret, &O);
            if (R != ERROR_IO_PENDING || !Wait(&O, &Err, &Bytes, 10000) || Err || !Bytes)
            {
                ok(0, "chunked body read: %lu %lu %lu\n", R, Err, Bytes);
                break;
            }
            Got += Bytes;
        }
        ok(Got == 5 && !memcmp(Body, "abcde", 5), "decoded body (%lu bytes)\n", Got);
        Respond(Id, "c");
    }
    EndClient(Th);

    /* --- response framing */
    Th = StartClient(&Cl, PORT, "HEAD /h HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
    {
        HTTP_KNOWN_HEADER Kh = { 8, "text/css" };
        int Kid = HttpHeaderContentType;

        ok(Req->Verb == HttpVerbHEAD, "HEAD verb\n");
        SendIocp(Req->RequestId, 0, 200, "OK", 1, &Kid, &Kh, "body", 4, FALSE);
    }
    EndClient(Th);
    ok(Find(Cl.Raw, Cl.Len, "Content-Type: text/css\r\n") != NULL && !Find(Cl.Raw, Cl.Len, "body"), "HEAD response: %s\n", Cl.Raw);

    Th = StartClient(&Cl, PORT, "GET /n HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
        SendIocp(Req->RequestId, 0, 204, "No Content", 0, NULL, NULL, NULL, 0, FALSE);
    EndClient(Th);
    ok(StartsWith(Cl.Raw, "HTTP/1.1 204 No Content\r\n") && !Find(Cl.Raw, Cl.Len, "Content-Length"), "204 response: %s\n", Cl.Raw);

    Th = StartClient(&Cl, PORT, "GET /m HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
    {
        HTTP_KNOWN_HEADER Kh = { 2, "10" };
        int Kid = HttpHeaderContentLength;

        Id = Req->RequestId;
        SendIocp(Id, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 200, "OK", 1, &Kid, &Kh, "12345", 5, FALSE);
        SendIocp(Id, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 0, NULL, 0, NULL, NULL, "67", 2, TRUE);
        SendIocp(Id, 0, 0, NULL, 0, NULL, NULL, "890", 3, TRUE);
        R = SendIocp(Id, 0, 0, NULL, 0, NULL, NULL, "x", 1, TRUE);
        ok(R == ERROR_CONNECTION_INVALID, "send after the final part returned %lu\n", R);
    }
    EndClient(Th);
    ok(Find(Cl.Raw, Cl.Len, "\r\nContent-Length: 10\r\n") != NULL && Cl.Len > 10 && !memcmp(Cl.Raw + Cl.Len - 10, "1234567890", 10), "MORE_DATA response: %s\n", Cl.Raw);

    Th = StartClient(&Cl, PORT, "GET /t HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
    {
        HTTP_KNOWN_HEADER Kh = { 7, "chunked" };
        int Kid = HttpHeaderTransferEncoding;

        Id = Req->RequestId;
        SendIocp(Id, HTTP_SEND_RESPONSE_FLAG_MORE_DATA, 200, "OK", 1, &Kid, &Kh, "5\r\nhello\r\n", 10, FALSE);
        SendIocp(Id, 0, 0, NULL, 0, NULL, NULL, "0\r\n\r\n", 5, TRUE);
    }
    EndClient(Th);
    ok(Find(Cl.Raw, Cl.Len, "Transfer-Encoding: chunked\r\n") != NULL && !Find(Cl.Raw, Cl.Len, "Content-Length") &&
       Cl.Len > 15 && !memcmp(Cl.Raw + Cl.Len - 15, "5\r\nhello\r\n0\r\n\r\n", 15), "chunked response: %s\n", Cl.Raw);

    Th = StartClient(&Cl, PORT, "GET /c HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n", NULL, 0, 3000, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
        Respond(Req->RequestId, "bye");
    EndClient(Th);
    ok(Find(Cl.Raw, Cl.Len, "\r\nConnection: close\r\n") != NULL && Cl.Eof, "Connection: close response (eof %d): %s\n", Cl.Eof, Cl.Raw);

    /* --- two requests in a row on one connection */
    Th = StartClient(&Cl, PORT, "GET /k1 HTTP/1.1\r\nHost: h\r\n\r\nGET /k2 HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
    {
        HTTP_CONNECTION_ID Conn = Req->ConnectionId;
        HTTP_REQUEST_ID First = Req->RequestId;

        Respond(First, "A");
        memset(g_Buf, 0, sizeof(g_Buf));
        if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
        {
            ok(Req->ConnectionId == Conn, "second request on another connection\n");
            ok(Req->RequestId != First, "same request id\n");
            Respond(Req->RequestId, "B");
        }
    }
    EndClient(Th);
    ok(Cl.Len > 3 && Cl.Raw[Cl.Len - 1] == 'B' && Find(Cl.Raw, Cl.Len, "\r\n\r\nAHTTP/1.1 200 OK") != NULL, "pipelined responses: %s\n", Cl.Raw);

    /* --- the client resets the connection: HttpWaitForDisconnect completes, the request is gone */
    Th = StartClient(&Cl, PORT, "GET /w HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 700, 300, TRUE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
    {
        memset(&O, 0, sizeof(O));
        R = pWait(g_Queue, Req->ConnectionId, &O);
        ok(R == ERROR_IO_PENDING, "HttpWaitForDisconnect returned %lu\n", R);
        if (R == ERROR_IO_PENDING)
        {
            ok(Wait(&O, &Err, &Bytes, 10000), "no completion of the disconnect wait\n");
            ok(Err == 0, "disconnect wait %lu\n", Err);
        }
        R = SendIocp(Req->RequestId, 0, 200, "OK", 0, NULL, NULL, NULL, 0, FALSE);
        ok(R == ERROR_CONNECTION_INVALID, "send after the reset returned %lu\n", R);
    }
    EndClient(Th);

    /* --- HttpCancelHttpRequest drops the connection without an answer */
    Th = StartClient(&Cl, PORT, "GET /x HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 800, FALSE);
    memset(g_Buf, 0, sizeof(g_Buf));
    if (RecvIocp(0, 1, g_Buf, sizeof(g_Buf), &Bytes) == 0)
    {
        R = pCancel(g_Queue, Req->RequestId, NULL);
        ok(R == 0, "HttpCancelHttpRequest returned %lu\n", R);
        R = SendIocp(Req->RequestId, 0, 200, "OK", 0, NULL, NULL, NULL, 0, FALSE);
        ok(R == ERROR_CONNECTION_INVALID, "send after the cancel returned %lu\n", R);
    }
    EndClient(Th);
    ok(Cl.Len == 0 && Cl.Eof, "the cancelled request got an answer: %s\n", Cl.Raw);

    /* --- no registration matches: nothing of this server answers */
    ok(HttpRemoveUrlFromUrlGroup(g_Group, L"http://127.0.0.1:18631/", 0) == 0, "remove 1\n");
    ok(HttpRemoveUrlFromUrlGroup(g_Group, L"http://+:18631/a/", 0) == 0, "remove strong\n");
    ok(HttpRemoveUrlFromUrlGroup(g_Group, L"http://*:18631/a/b/", 0) == 0, "remove weak\n");
    Th = StartClient(&Cl, PORT, "GET /nomatch HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 500, FALSE);
    EndClient(Th);
    ok(Cl.Refused || (Cl.Len == 0 && Cl.Eof) || StartsWith(Cl.Raw, "HTTP/1.1 404"), "request without a registration: refused=%d %s\n", Cl.Refused, Cl.Raw);

    /* --- a pending receive is cancelled by a shutdown of the queue */
    R = HttpAddUrlToUrlGroup(g_Group, L"http://127.0.0.1:18631/", 1, 0);
    ok(R == 0, "add again: %lu\n", R);
    memset(&O, 0, sizeof(O));
    R = HttpReceiveHttpRequest(g_Queue, 0, 1, (HTTP_REQUEST *)g_Buf, sizeof(g_Buf), &Bytes, &O);
    ok(R == ERROR_IO_PENDING, "pending receive returned %lu\n", R);
    ok(HttpShutdownRequestQueue(g_Queue) == 0, "shutdown\n");
    ok(Wait(&O, &Err, &Bytes, 10000), "no completion after the shutdown\n");
    ok(Err == ERROR_OPERATION_ABORTED, "pending receive after the shutdown: %lu\n", Err);
    R = HttpReceiveHttpRequest(g_Queue, 0, 1, (HTTP_REQUEST *)g_Buf, sizeof(g_Buf), &Bytes, &O);
    ok(R == ERROR_INVALID_HANDLE, "receive after the shutdown returned %lu\n", R);
    ok(HttpCloseRequestQueue(g_Queue) == 0, "close queue\n");
    ok(HttpCloseUrlGroup(g_Group) == 0, "close group\n");
    ok(HttpCloseServerSession(g_Session) == 0, "close session\n");

    /* the port is free again */
    Th = StartClient(&Cl, PORT, "GET /gone HTTP/1.1\r\nHost: h\r\n\r\n", NULL, 0, 500, FALSE);
    EndClient(Th);
    ok(Cl.Refused, "the port still listens after everything was closed\n");

    /* --- version 1: HttpCreateHttpHandle, HttpAddUrl, synchronous calls */
    {
        HANDLE H1 = NULL;
        ULONG Ret = 0;
        HTTP_RESPONSE Resp;
        TCHUNK Chunk;

        ok(HttpInitialize(V1, HTTP_INITIALIZE_SERVER, NULL) == 0, "v1 init\n");
        ok(HttpCreateHttpHandle(&H1, 0) == 0 && H1, "v1 handle\n");
        ok(HttpAddUrl(H1, L"http://127.0.0.1:18632/v1/", NULL) == 0, "v1 add\n");
        ok(HttpAddUrl(H1, L"http://127.0.0.1:18632/v1/", NULL) == ERROR_ALREADY_EXISTS, "v1 duplicate\n");
        Th = StartClient(&Cl, PORT1, "GET /v1/x HTTP/1.1\r\nHost: 127.0.0.1:18632\r\n\r\n", NULL, 0, 800, FALSE);
        memset(g_Buf, 0, sizeof(g_Buf));
        R = HttpReceiveHttpRequest(H1, 0, 1, (HTTP_REQUEST *)g_Buf, sizeof(g_Buf), &Ret, NULL);
        ok(R == 0, "v1 receive %lu\n", R);
        if (R == 0)
        {
            ok(Req->Verb == HttpVerbGET && !strcmp(Req->pRawUrl, "/v1/x") && Req->UrlContext == 0, "v1 request\n");
            memset(&Resp, 0, sizeof(Resp));
            memset(&Chunk, 0, sizeof(Chunk));
            Resp.s.StatusCode = 200;
            Resp.s.pReason = "OK";
            Resp.s.ReasonLength = 2;
            Chunk.u.m.Type = HttpDataChunkFromMemory;
            Chunk.u.m.pBuffer = "v1";
            Chunk.u.m.Length = 2;
            Resp.s.EntityChunkCount = 1;
            Resp.s.pEntityChunks = (HTTP_DATA_CHUNK *)&Chunk;
            R = HttpSendHttpResponse(H1, Req->RequestId, 0, &Resp, NULL, &Ret, NULL, 0, NULL, NULL);
            ok(R == 0 && Ret > 2, "v1 send %lu, %lu bytes\n", R, Ret);
        }
        EndClient(Th);
        ok(Cl.Len > 2 && !memcmp(Cl.Raw + Cl.Len - 2, "v1", 2), "v1 response: %s\n", Cl.Raw);
        ok(HttpRemoveUrl(H1, L"http://127.0.0.1:18632/v1/") == 0, "v1 remove\n");
        ok(HttpRemoveUrl(H1, L"http://127.0.0.1:18632/v1/") == ERROR_FILE_NOT_FOUND, "v1 remove again\n");
        ok(HttpCloseRequestQueue(H1) == 0, "v1 close\n");
    }

    /* --- what is not served says so */
    {
        HTTP_SERVER_SESSION_ID S;
        HTTP_URL_GROUP_ID G;
        ULONG Auth[2] = { 1, 8 /* HTTP_AUTH_ENABLE_NTLM */ };

        ok(HttpCreateServerSession(V2, &S, 0) == 0, "session\n");
        ok(HttpCreateUrlGroup(S, &G, 0) == 0, "group\n");
        R = HttpSetUrlGroupProperty(G, HttpServerAuthenticationProperty, Auth, sizeof(Auth));
        ok(R == ERROR_NOT_SUPPORTED, "NTLM authentication property: %lu\n", R);
        HttpCloseServerSession(S);
    }
    WSACleanup();
}
