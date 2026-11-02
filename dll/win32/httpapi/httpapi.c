/*
 * PROJECT:     ReactOS HTTP Server API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     HTTP Server API entry points (versions 1.0 and 2.0) on top of an in-process HTTP/1.1 server
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * ReactOS has no http.sys. These entry points keep the registrations and the request queues in the process
 * that calls them and serve over Winsock, which is enough for System.Net.HttpListener of .NET Framework and
 * .NET, local web servers and test servers. Differences from http.sys, all reported with an error and never
 * silently ignored where a program could rely on them:
 *   - plain HTTP only: https prefixes (ERROR_NOT_SUPPORTED), TLS settings, client certificates;
 *   - no authentication: server and URL group authentication with any scheme (ERROR_NOT_SUPPORTED);
 *   - no URL ACLs: HttpSetServiceConfiguration(UrlAcl) succeeds and does nothing, any process can register any
 *     prefix; the other configuration classes are refused;
 *   - registrations are private to the process: two processes cannot share a port;
 *   - no kernel response cache, fragment cache, logging, QoS, opaque (WebSocket) mode, named queues shared
 *     between handles, property queries.
 */

#include "httpapip.h"

static BOOL g_WsaUp;

static void Http_Ensure(void)
{
    WSADATA Wsa;
    HMODULE Self;

    EnterCriticalSection(&g_Lock);
    if (!g_WsaUp)
    {
        g_WsaUp = !WSAStartup(MAKEWORD(2, 2), &Wsa);
        /* connection threads outlive the calls that made them: the DLL stays loaded */
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)Http_Ensure, &Self);
    }
    LeaveCriticalSection(&g_Lock);
}

BOOL WINAPI DllMain(HINSTANCE Instance, DWORD Reason, LPVOID Reserved)
{
    UNREFERENCED_PARAMETER(Reserved);

    if (Reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(Instance);
        InitializeCriticalSection(&g_Lock);
        HL_INIT(&g_Queues);
        HL_INIT(&g_Sessions);
        HL_INIT(&g_Urls);
        HL_INIT(&g_Listeners);
        HL_INIT(&g_Conns);
    }
    return TRUE;
}

static BOOL VersionOk(HTTPAPI_VERSION V, BOOL AllowV1)
{
    return (V.HttpApiMajorVersion == 2 && V.HttpApiMinorVersion == 0) || (AllowV1 && V.HttpApiMajorVersion == 1 && V.HttpApiMinorVersion == 0);
}

/* g_Lock held */
static SESSION *Session_Find(HTTP_SERVER_SESSION_ID Id)
{
    HL *E;

    for (E = g_Sessions.Next; E != &g_Sessions; E = E->Next)
        if ((ULONGLONG)(ULONG_PTR)HL_ENTRY(E, SESSION, Link) == Id)
            return HL_ENTRY(E, SESSION, Link);
    return NULL;
}

/* g_Lock held */
static UGROUP *Group_Find(HTTP_URL_GROUP_ID Id)
{
    HL *E, *F;

    for (E = g_Sessions.Next; E != &g_Sessions; E = E->Next)
    {
        SESSION *S = HL_ENTRY(E, SESSION, Link);

        for (F = S->Groups.Next; F != &S->Groups; F = F->Next)
            if ((ULONGLONG)(ULONG_PTR)HL_ENTRY(F, UGROUP, SessionLink) == Id)
                return HL_ENTRY(F, UGROUP, SessionLink);
    }
    return NULL;
}

ULONG WINAPI HttpInitialize(HTTPAPI_VERSION Version, ULONG Flags, void *Reserved)
{
    if (Reserved || !Flags || (Flags & ~(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG)))
        return ERROR_INVALID_PARAMETER;
    if (!VersionOk(Version, TRUE))
        return ERROR_REVISION_MISMATCH;
    Http_Ensure();
    return ERROR_SUCCESS;
}

ULONG WINAPI HttpTerminate(ULONG Flags, void *Reserved)
{
    if (Reserved || !Flags || (Flags & ~(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG)))
        return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- version 2: server sessions, URL groups */

DWORD WINAPI HttpCreateServerSession(HTTPAPI_VERSION Version, HTTP_SERVER_SESSION_ID *SessionId, ULONG Reserved)
{
    SESSION *S;

    if (!SessionId || Reserved)
        return ERROR_INVALID_PARAMETER;
    if (!VersionOk(Version, FALSE))
        return ERROR_REVISION_MISMATCH;
    Http_Ensure();
    S = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*S));
    if (!S)
        return ERROR_NOT_ENOUGH_MEMORY;
    HL_INIT(&S->Groups);
    EnterCriticalSection(&g_Lock);
    HL_ADD(&g_Sessions, &S->Link);
    LeaveCriticalSection(&g_Lock);
    *SessionId = (ULONGLONG)(ULONG_PTR)S;
    return ERROR_SUCCESS;
}

static void Group_Free(UGROUP *G)
{
    Url_RemoveAll(G, NULL);
    HL_DEL(&G->SessionLink);
    HeapFree(GetProcessHeap(), 0, G);
}

DWORD WINAPI HttpCloseServerSession(HTTP_SERVER_SESSION_ID SessionId)
{
    SESSION *S;

    EnterCriticalSection(&g_Lock);
    S = Session_Find(SessionId);
    if (!S)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_PARAMETER;
    }
    while (!HL_EMPTY(&S->Groups))
        Group_Free(HL_ENTRY(S->Groups.Next, UGROUP, SessionLink));
    HL_DEL(&S->Link);
    HeapFree(GetProcessHeap(), 0, S);
    LeaveCriticalSection(&g_Lock);
    return ERROR_SUCCESS;
}

/* The properties that only tune http.sys limits are accepted, anything that would need authentication, TLS,
 * logging or QoS is refused */
static ULONG SetProperty(HTTP_SERVER_PROPERTY Property, void *Value, ULONG Length, BOOL Server)
{
    if (!Value || !Length)
        return ERROR_INVALID_PARAMETER;
    switch (Property)
    {
        case HttpServerAuthenticationProperty:
            /* HTTP_SERVER_AUTHENTICATION_INFO: Flags, AuthSchemes */
            if (Length >= 2 * sizeof(ULONG) && (((ULONG *)Value)[0] & 1) && ((ULONG *)Value)[1])
                return ERROR_NOT_SUPPORTED;
            return Length >= 2 * sizeof(ULONG) ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
        case HttpServerTimeoutsProperty:
        case HttpServerStateProperty:
        case HttpServerQueueLengthProperty:
        case HttpServer503VerbosityProperty:
            return ERROR_SUCCESS;
        case HttpServerLoggingProperty:
        case HttpServerQosProperty:
        case HttpServerExtendedAuthenticationProperty:
        case HttpServerChannelBindProperty:
        case HttpServerProtectionLevelProperty:
        case HttpServerListenEndpointProperty:
            return ERROR_NOT_SUPPORTED;
        default:
            return ERROR_INVALID_PARAMETER;
    }
    (void)Server;
}

DWORD WINAPI HttpSetServerSessionProperty(HTTP_SERVER_SESSION_ID SessionId, HTTP_SERVER_PROPERTY Property, void *Value, ULONG Length)
{
    ULONG Res;

    EnterCriticalSection(&g_Lock);
    Res = Session_Find(SessionId) ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
    LeaveCriticalSection(&g_Lock);
    if (Res)
        return Res;
    if (Property == HttpServerQueueLengthProperty || Property == HttpServer503VerbosityProperty || Property == HttpServerBindingProperty)
        return ERROR_INVALID_PARAMETER;
    return SetProperty(Property, Value, Length, TRUE);
}

DWORD WINAPI HttpQueryServerSessionProperty(HTTP_SERVER_SESSION_ID SessionId, HTTP_SERVER_PROPERTY Property, void *Value,
                                            ULONG Length, ULONG *ReturnLength)
{
    UNREFERENCED_PARAMETER(SessionId);
    UNREFERENCED_PARAMETER(Property);
    UNREFERENCED_PARAMETER(Value);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ReturnLength);
    return ERROR_NOT_SUPPORTED;
}

DWORD WINAPI HttpCreateUrlGroup(HTTP_SERVER_SESSION_ID SessionId, HTTP_URL_GROUP_ID *GroupId, ULONG Reserved)
{
    SESSION *S;
    UGROUP *G;

    if (!GroupId || Reserved)
        return ERROR_INVALID_PARAMETER;
    G = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*G));
    if (!G)
        return ERROR_NOT_ENOUGH_MEMORY;
    HL_INIT(&G->Urls);
    EnterCriticalSection(&g_Lock);
    S = Session_Find(SessionId);
    if (!S)
    {
        LeaveCriticalSection(&g_Lock);
        HeapFree(GetProcessHeap(), 0, G);
        return ERROR_INVALID_PARAMETER;
    }
    G->Session = S;
    HL_ADD(&S->Groups, &G->SessionLink);
    LeaveCriticalSection(&g_Lock);
    *GroupId = (ULONGLONG)(ULONG_PTR)G;
    return ERROR_SUCCESS;
}

DWORD WINAPI HttpCloseUrlGroup(HTTP_URL_GROUP_ID GroupId)
{
    UGROUP *G;

    EnterCriticalSection(&g_Lock);
    G = Group_Find(GroupId);
    if (!G)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_PARAMETER;
    }
    Group_Free(G);
    LeaveCriticalSection(&g_Lock);
    return ERROR_SUCCESS;
}

DWORD WINAPI HttpSetUrlGroupProperty(HTTP_URL_GROUP_ID GroupId, HTTP_SERVER_PROPERTY Property, void *Value, ULONG Length)
{
    UGROUP *G;
    ULONG Res = ERROR_SUCCESS;

    EnterCriticalSection(&g_Lock);
    G = Group_Find(GroupId);
    if (!G)
        Res = ERROR_INVALID_PARAMETER;
    else if (Property == HttpServerBindingProperty)
    {
        HTTP_BINDING_INFO *Info = Value;

        if (!Value || Length != sizeof(HTTP_BINDING_INFO))
            Res = ERROR_INVALID_PARAMETER;
        else if (!Info->Flags.Present)
            G->Queue = NULL;
        else
        {
            RQ *Q = Queue_Find(Info->RequestQueueHandle);

            if (!Q)
                Res = ERROR_INVALID_HANDLE;
            else
                G->Queue = Q;
        }
    }
    else if (Property == HttpServerQueueLengthProperty || Property == HttpServer503VerbosityProperty)
        Res = ERROR_INVALID_PARAMETER;
    else
        Res = SetProperty(Property, Value, Length, FALSE);
    LeaveCriticalSection(&g_Lock);
    return Res;
}

DWORD WINAPI HttpQueryUrlGroupProperty(HTTP_URL_GROUP_ID GroupId, HTTP_SERVER_PROPERTY Property, void *Value, ULONG Length,
                                       ULONG *ReturnLength)
{
    UNREFERENCED_PARAMETER(GroupId);
    UNREFERENCED_PARAMETER(Property);
    UNREFERENCED_PARAMETER(Value);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(ReturnLength);
    return ERROR_NOT_SUPPORTED;
}

ULONG WINAPI HttpAddUrlToUrlGroup(HTTP_URL_GROUP_ID GroupId, const WCHAR *Url, HTTP_URL_CONTEXT Context, ULONG Reserved)
{
    UGROUP *G;
    ULONG Res;

    if (!Url || Reserved)
        return ERROR_INVALID_PARAMETER;
    Http_Ensure();
    EnterCriticalSection(&g_Lock);
    G = Group_Find(GroupId);
    Res = G ? Url_Register(G, NULL, Url, Context) : ERROR_INVALID_PARAMETER;
    LeaveCriticalSection(&g_Lock);
    return Res;
}

ULONG WINAPI HttpRemoveUrlFromUrlGroup(HTTP_URL_GROUP_ID GroupId, const WCHAR *Url, ULONG Flags)
{
    UGROUP *G;
    ULONG Res;

    if (Flags & ~HTTP_URL_FLAG_REMOVE_ALL)
        return ERROR_INVALID_PARAMETER;
    EnterCriticalSection(&g_Lock);
    G = Group_Find(GroupId);
    if (!G)
        Res = ERROR_INVALID_PARAMETER;
    else if (Flags & HTTP_URL_FLAG_REMOVE_ALL)
    {
        Url_RemoveAll(G, NULL);
        Res = ERROR_SUCCESS;
    }
    else if (!Url)
        Res = ERROR_INVALID_PARAMETER;
    else
        Res = Url_Remove(G, NULL, Url);
    LeaveCriticalSection(&g_Lock);
    return Res;
}

/* ---------------------------------------------------------------- request queues */

DWORD WINAPI HttpCreateRequestQueue(HTTPAPI_VERSION Version, const WCHAR *Name, SECURITY_ATTRIBUTES *Sa, ULONG Flags, HANDLE *Handle)
{
    RQ *Q;

    if (!Handle || (Flags & ~(HTTP_CREATE_REQUEST_QUEUE_FLAG_OPEN_EXISTING | HTTP_CREATE_REQUEST_QUEUE_FLAG_CONTROLLER)))
        return ERROR_INVALID_PARAMETER;
    if (!VersionOk(Version, FALSE))
        return ERROR_REVISION_MISMATCH;
    if (Flags)
        return ERROR_NOT_SUPPORTED;
    Http_Ensure();
    /* A name is accepted and not used: queues are not shared between handles or processes */
    UNREFERENCED_PARAMETER(Name);
    if (!Queue_Create(&Q, TRUE, Sa))
        return GetLastError() ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
    *Handle = Q->hA;
    return ERROR_SUCCESS;
}

ULONG WINAPI HttpCreateHttpHandle(HANDLE *Handle, ULONG Reserved)
{
    RQ *Q;

    if (!Handle || Reserved)
        return ERROR_INVALID_PARAMETER;
    Http_Ensure();
    if (!Queue_Create(&Q, FALSE, NULL))
        return GetLastError() ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
    *Handle = Q->hA;
    return ERROR_SUCCESS;
}

DWORD WINAPI HttpCloseRequestQueue(HANDLE Handle)
{
    RQ *Q;

    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Handle);
    if (!Q)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    Queue_Close(Q);
    LeaveCriticalSection(&g_Lock);
    return ERROR_SUCCESS;
}

DWORD WINAPI HttpShutdownRequestQueue(HANDLE Handle)
{
    RQ *Q;

    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Handle);
    if (!Q)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    Q->Shutdown = TRUE;
    Queue_CancelWaiters(Q);
    LeaveCriticalSection(&g_Lock);
    return ERROR_SUCCESS;
}

DWORD WINAPI HttpSetRequestQueueProperty(HANDLE Handle, HTTP_SERVER_PROPERTY Property, void *Value, ULONG Length,
                                         ULONG Reserved, void *Reserved2)
{
    ULONG Res;

    if (Reserved || Reserved2)
        return ERROR_INVALID_PARAMETER;
    EnterCriticalSection(&g_Lock);
    Res = Queue_Find(Handle) ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
    LeaveCriticalSection(&g_Lock);
    if (Res)
        return Res;
    if (Property != HttpServerQueueLengthProperty && Property != HttpServer503VerbosityProperty && Property != HttpServerStateProperty)
        return ERROR_NOT_SUPPORTED;
    return SetProperty(Property, Value, Length, FALSE);
}

DWORD WINAPI HttpQueryRequestQueueProperty(HANDLE Handle, HTTP_SERVER_PROPERTY Property, void *Value, ULONG Length,
                                           ULONG Reserved, ULONG *ReturnLength, void *Reserved2)
{
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(Property);
    UNREFERENCED_PARAMETER(Value);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(ReturnLength);
    UNREFERENCED_PARAMETER(Reserved2);
    return ERROR_NOT_SUPPORTED;
}

/* ---------------------------------------------------------------- version 1 registrations */

ULONG WINAPI HttpAddUrl(HANDLE Queue, PCWSTR Url, PVOID Reserved)
{
    RQ *Q;
    ULONG Res;

    if (!Url || Reserved)
        return ERROR_INVALID_PARAMETER;
    Http_Ensure();
    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    Res = Q ? Url_Register(NULL, Q, Url, 0) : ERROR_INVALID_HANDLE;
    LeaveCriticalSection(&g_Lock);
    return Res;
}

ULONG WINAPI HttpRemoveUrl(HANDLE Queue, const WCHAR *Url)
{
    RQ *Q;
    ULONG Res;

    if (!Url)
        return ERROR_INVALID_PARAMETER;
    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    Res = Q ? Url_Remove(NULL, Q, Url) : ERROR_INVALID_HANDLE;
    LeaveCriticalSection(&g_Lock);
    return Res;
}

/* ---------------------------------------------------------------- requests and responses */

ULONG WINAPI HttpReceiveHttpRequest(HANDLE Queue, HTTP_REQUEST_ID Id, ULONG Flags, HTTP_REQUEST *Request, ULONG Size,
                                    ULONG *Returned, OVERLAPPED *Ovl)
{
    if (Flags & ~(HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY | HTTP_RECEIVE_REQUEST_FLAG_FLUSH_BODY))
        return ERROR_INVALID_PARAMETER;
    return Req_Receive(Queue, Id, Flags, Request, Size, Returned, Ovl);
}

ULONG WINAPI HttpReceiveRequestEntityBody(HANDLE Queue, HTTP_REQUEST_ID Id, ULONG Flags, void *Buffer, ULONG Size,
                                          ULONG *Returned, OVERLAPPED *Ovl)
{
    if (Flags & ~1)
        return ERROR_INVALID_PARAMETER;
    return Req_Body(Queue, Id, Flags, Buffer, Size, Returned, Ovl);
}

ULONG WINAPI HttpSendHttpResponse(HANDLE Queue, HTTP_REQUEST_ID Id, ULONG Flags, HTTP_RESPONSE *Response,
                                  HTTP_CACHE_POLICY *CachePolicy, ULONG *BytesSent, void *Reserved1, ULONG Reserved2,
                                  OVERLAPPED *Ovl, HTTP_LOG_DATA *LogData)
{
    HTTP_RESPONSE_V1 *V1 = (HTTP_RESPONSE_V1 *)Response;

    UNREFERENCED_PARAMETER(CachePolicy);
    UNREFERENCED_PARAMETER(Reserved1);
    UNREFERENCED_PARAMETER(Reserved2);
    UNREFERENCED_PARAMETER(LogData);
    if (!Response)
        return ERROR_INVALID_PARAMETER;
    return Req_Send(Queue, Id, Flags, Response, V1->EntityChunkCount, (HPI_DATA_CHUNK *)V1->pEntityChunks, BytesSent, Ovl, TRUE);
}

ULONG WINAPI HttpSendResponseEntityBody(HANDLE Queue, HTTP_REQUEST_ID Id, ULONG Flags, ULONG ChunkCount, void *Chunks,
                                        ULONG *BytesSent, void *Reserved1, ULONG Reserved2, OVERLAPPED *Ovl, void *LogData)
{
    UNREFERENCED_PARAMETER(Reserved1);
    UNREFERENCED_PARAMETER(Reserved2);
    UNREFERENCED_PARAMETER(LogData);
    ChunkCount &= 0xffff;
    if (ChunkCount && !Chunks)
        return ERROR_INVALID_PARAMETER;
    return Req_Send(Queue, Id, Flags, NULL, ChunkCount, Chunks, BytesSent, Ovl, FALSE);
}

ULONG WINAPI HttpCancelHttpRequest(HANDLE Queue, HTTP_REQUEST_ID Id, OVERLAPPED *Ovl)
{
    return Req_Cancel(Queue, Id, Ovl);
}

ULONG WINAPI HttpWaitForDisconnect(HANDLE Queue, HTTP_CONNECTION_ID ConnectionId, OVERLAPPED *Ovl)
{
    return Req_WaitDisconnect(Queue, ConnectionId, Ovl);
}

ULONG WINAPI HttpWaitForDisconnectEx(HANDLE Queue, HTTP_CONNECTION_ID ConnectionId, ULONG Reserved, OVERLAPPED *Ovl)
{
    if (Reserved)
        return ERROR_INVALID_PARAMETER;
    return Req_WaitDisconnect(Queue, ConnectionId, Ovl);
}

ULONG WINAPI HttpReceiveClientCertificate(HANDLE Queue, HTTP_CONNECTION_ID ConnectionId, ULONG Flags, PVOID CertInfo,
                                          ULONG Size, ULONG *BytesReceived, OVERLAPPED *Ovl)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(ConnectionId);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(CertInfo);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(BytesReceived);
    UNREFERENCED_PARAMETER(Ovl);
    return ERROR_NOT_SUPPORTED; /* no TLS */
}

/* ---------------------------------------------------------------- service configuration */

/* URL ACLs are not kept: setting or deleting one succeeds and changes nothing */
ULONG WINAPI HttpSetServiceConfiguration(HANDLE Service, HTTP_SERVICE_CONFIG_ID Id, PVOID Info, ULONG Length, LPOVERLAPPED Ovl)
{
    UNREFERENCED_PARAMETER(Service);
    UNREFERENCED_PARAMETER(Ovl);
    if (!Info || !Length)
        return ERROR_INVALID_PARAMETER;
    return Id == HttpServiceConfigUrlAclInfo ? ERROR_SUCCESS : ERROR_NOT_SUPPORTED;
}

ULONG WINAPI HttpDeleteServiceConfiguration(HANDLE Service, HTTP_SERVICE_CONFIG_ID Id, PVOID Info, ULONG Length, LPOVERLAPPED Ovl)
{
    return HttpSetServiceConfiguration(Service, Id, Info, Length, Ovl);
}

ULONG WINAPI HttpQueryServiceConfiguration(HANDLE Service, HTTP_SERVICE_CONFIG_ID Id, PVOID Input, ULONG InputLength,
                                           PVOID Output, ULONG OutputLength, PULONG ReturnLength, LPOVERLAPPED Ovl)
{
    UNREFERENCED_PARAMETER(Service);
    UNREFERENCED_PARAMETER(Input);
    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(Output);
    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Ovl);
    if (ReturnLength)
        *ReturnLength = 0;
    return Id == HttpServiceConfigUrlAclInfo ? ERROR_NO_MORE_ITEMS : ERROR_NOT_SUPPORTED;
}
