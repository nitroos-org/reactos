/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     URLDownloadToFile of an HTTP error status fails and leaves no file
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (build 19045, 2026-11-07) against a local HTTP server:
 * 200 -> S_OK and the file, 404 -> INET_E_OBJECT_NOT_FOUND (0x800c0006) and no file,
 * 403 and 500 -> INET_E_DOWNLOAD_FAILURE (0x800c0008) and no file.
 */

#define COBJMACROS
#define CONST_VTABLE
#include <apitest.h>

#include <winsock2.h>
#include <ole2.h>
#include <urlmon.h>
#include <stdio.h>

static SOCKET g_listener;
static unsigned short g_port;

static DWORD WINAPI ServerThread(LPVOID Param)
{
    for (;;)
    {
        SOCKET Client = accept(g_listener, NULL, NULL);
        char Request[2048], Response[512];
        const char *Status, *Body;
        int Length = 0, Received;

        if (Client == INVALID_SOCKET)
            break;
        while (Length < (int)sizeof(Request) - 1)
        {
            Received = recv(Client, Request + Length, sizeof(Request) - 1 - Length, 0);
            if (Received <= 0)
                break;
            Length += Received;
            Request[Length] = 0;
            if (strstr(Request, "\r\n\r\n"))
                break;
        }
        Request[Length] = 0;

        if (strstr(Request, " /404"))
        {
            Status = "404 Not Found";
            Body = "<html><body>not found</body></html>";
        }
        else if (strstr(Request, " /500"))
        {
            Status = "500 Internal Server Error";
            Body = "<html><body>error</body></html>";
        }
        else if (strstr(Request, " /403"))
        {
            Status = "403 Forbidden";
            Body = "<html><body>forbidden</body></html>";
        }
        else
        {
            Status = "200 OK";
            Body = "<html><body>fine</body></html>";
        }
        _snprintf(Response, sizeof(Response),
                  "HTTP/1.1 %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                  Status, (int)strlen(Body), Body);
        send(Client, Response, (int)strlen(Response), 0);
        shutdown(Client, SD_SEND);
        Sleep(50);
        closesocket(Client);
    }
    return 0;
}

static BOOL StartServer(void)
{
    WSADATA Data;
    struct sockaddr_in Addr;
    int Length = sizeof(Addr);

    if (WSAStartup(MAKEWORD(2, 2), &Data) != 0)
        return FALSE;
    g_listener = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listener == INVALID_SOCKET)
        return FALSE;
    memset(&Addr, 0, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_listener, (struct sockaddr *)&Addr, sizeof(Addr)) != 0 ||
        listen(g_listener, 8) != 0 ||
        getsockname(g_listener, (struct sockaddr *)&Addr, &Length) != 0)
        return FALSE;
    g_port = ntohs(Addr.sin_port);
    CloseHandle(CreateThread(NULL, 0, ServerThread, NULL, 0, NULL));
    return TRUE;
}

/* A caller callback that sees the HTTP status through IHttpNegotiate */
typedef struct
{
    IBindStatusCallback IBindStatusCallback_iface;
    IHttpNegotiate IHttpNegotiate_iface;
    DWORD ResponseCode;
    BOOL Stopped;
} Callback;

static Callback *impl_from_BSC(IBindStatusCallback *iface)
{
    return CONTAINING_RECORD(iface, Callback, IBindStatusCallback_iface);
}

static Callback *impl_from_Negotiate(IHttpNegotiate *iface)
{
    return CONTAINING_RECORD(iface, Callback, IHttpNegotiate_iface);
}

static HRESULT WINAPI BSC_QueryInterface(IBindStatusCallback *iface, REFIID riid, void **ppv)
{
    Callback *This = impl_from_BSC(iface);

    if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IBindStatusCallback))
        *ppv = &This->IBindStatusCallback_iface;
    else if (IsEqualGUID(riid, &IID_IHttpNegotiate))
        *ppv = &This->IHttpNegotiate_iface;
    else
    {
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    return S_OK;
}

static ULONG WINAPI BSC_AddRef(IBindStatusCallback *iface) { return 2; }
static ULONG WINAPI BSC_Release(IBindStatusCallback *iface) { return 1; }
static HRESULT WINAPI BSC_OnStartBinding(IBindStatusCallback *iface, DWORD r, IBinding *b) { return S_OK; }
static HRESULT WINAPI BSC_GetPriority(IBindStatusCallback *iface, LONG *p) { return E_NOTIMPL; }
static HRESULT WINAPI BSC_OnLowResource(IBindStatusCallback *iface, DWORD r) { return S_OK; }
static HRESULT WINAPI BSC_OnProgress(IBindStatusCallback *iface, ULONG p, ULONG m, ULONG s, LPCWSTR t) { return S_OK; }

static HRESULT WINAPI BSC_OnStopBinding(IBindStatusCallback *iface, HRESULT hr, LPCWSTR error)
{
    impl_from_BSC(iface)->Stopped = TRUE;
    return S_OK;
}

static HRESULT WINAPI BSC_GetBindInfo(IBindStatusCallback *iface, DWORD *f, BINDINFO *i) { return S_OK; }
static HRESULT WINAPI BSC_OnDataAvailable(IBindStatusCallback *iface, DWORD f, DWORD s, FORMATETC *e, STGMEDIUM *m) { return S_OK; }
static HRESULT WINAPI BSC_OnObjectAvailable(IBindStatusCallback *iface, REFIID r, IUnknown *u) { return S_OK; }

static const IBindStatusCallbackVtbl BSCVtbl =
{
    BSC_QueryInterface, BSC_AddRef, BSC_Release, BSC_OnStartBinding, BSC_GetPriority, BSC_OnLowResource,
    BSC_OnProgress, BSC_OnStopBinding, BSC_GetBindInfo, BSC_OnDataAvailable, BSC_OnObjectAvailable
};

static HRESULT WINAPI Neg_QueryInterface(IHttpNegotiate *iface, REFIID riid, void **ppv)
{
    return BSC_QueryInterface(&impl_from_Negotiate(iface)->IBindStatusCallback_iface, riid, ppv);
}

static ULONG WINAPI Neg_AddRef(IHttpNegotiate *iface) { return 2; }
static ULONG WINAPI Neg_Release(IHttpNegotiate *iface) { return 1; }

static HRESULT WINAPI Neg_BeginningTransaction(IHttpNegotiate *iface, LPCWSTR url, LPCWSTR headers, DWORD r, LPWSTR *add)
{
    *add = NULL;
    return S_OK;
}

static HRESULT WINAPI Neg_OnResponse(IHttpNegotiate *iface, DWORD code, LPCWSTR resp, LPCWSTR req, LPWSTR *add)
{
    impl_from_Negotiate(iface)->ResponseCode = code;
    return S_OK;
}

static const IHttpNegotiateVtbl NegVtbl =
{
    Neg_QueryInterface, Neg_AddRef, Neg_Release, Neg_BeginningTransaction, Neg_OnResponse
};

static void Download(const WCHAR *Dir, const char *Path, HRESULT Expected, BOOL ExpectFile, DWORD ExpectedStatus)
{
    WCHAR Url[128], File[MAX_PATH];
    Callback Cb;
    HRESULT hr;
    DWORD Attr;

    _snwprintf(Url, ARRAYSIZE(Url), L"http://127.0.0.1:%u%S", g_port, Path);
    _snwprintf(File, ARRAYSIZE(File), L"%s\\httperr%S.out", Dir, Path + 1);
    DeleteFileW(File);

    /* without a callback */
    hr = URLDownloadToFileW(NULL, Url, File, 0, NULL);
    Attr = GetFileAttributesW(File);
    ok(hr == Expected, "%s: URLDownloadToFile returned 0x%08lx, expected 0x%08lx\n", Path, hr, Expected);
    ok((Attr != INVALID_FILE_ATTRIBUTES) == ExpectFile, "%s: the file %s\n", Path, Attr != INVALID_FILE_ATTRIBUTES ? "exists" : "is missing");
    DeleteFileW(File);

    /* with a callback that has IHttpNegotiate: it still sees the response */
    memset(&Cb, 0, sizeof(Cb));
    Cb.IBindStatusCallback_iface.lpVtbl = &BSCVtbl;
    Cb.IHttpNegotiate_iface.lpVtbl = &NegVtbl;
    hr = URLDownloadToFileW(NULL, Url, File, 0, &Cb.IBindStatusCallback_iface);
    Attr = GetFileAttributesW(File);
    ok(hr == Expected, "%s (callback): URLDownloadToFile returned 0x%08lx, expected 0x%08lx\n", Path, hr, Expected);
    ok((Attr != INVALID_FILE_ATTRIBUTES) == ExpectFile, "%s (callback): the file %s\n", Path, Attr != INVALID_FILE_ATTRIBUTES ? "exists" : "is missing");
    ok(Cb.ResponseCode == ExpectedStatus, "%s (callback): OnResponse got %lu, expected %lu\n", Path, Cb.ResponseCode, ExpectedStatus);
    ok(Cb.Stopped, "%s (callback): OnStopBinding was not called\n", Path);
    DeleteFileW(File);
}

START_TEST(HttpError)
{
    WCHAR Dir[MAX_PATH];

    CoInitialize(NULL);
    if (!StartServer())
    {
        skip("cannot start the local HTTP server\n");
        CoUninitialize();
        return;
    }
    GetTempPathW(MAX_PATH, Dir);
    Dir[wcslen(Dir) - 1] = 0;

    Download(Dir, "/ok", S_OK, TRUE, 200);
    Download(Dir, "/404", INET_E_OBJECT_NOT_FOUND, FALSE, 404);
    Download(Dir, "/500", INET_E_DOWNLOAD_FAILURE, FALSE, 500);
    Download(Dir, "/403", INET_E_DOWNLOAD_FAILURE, FALSE, 403);

    closesocket(g_listener);
    WSACleanup();
    CoUninitialize();
}
