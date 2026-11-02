/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the HTTP Server API version 2.0 entry points of httpapi.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and WOW64). LibreOffice (mergedlo.dll) imports five of them.
 * ReactOS serves them from an in-process HTTP server (no http.sys), see HttpServerFlow for the request flows.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <http.h>

typedef ULONG (WINAPI *PFN_HttpInitialize)(HTTPAPI_VERSION, ULONG, PVOID);
typedef ULONG (WINAPI *PFN_HttpTerminate)(ULONG, PVOID);
typedef ULONG (WINAPI *PFN_CreateServerSession)(HTTPAPI_VERSION, PHTTP_SERVER_SESSION_ID, ULONG);
typedef ULONG (WINAPI *PFN_CloseServerSession)(HTTP_SERVER_SESSION_ID);
typedef ULONG (WINAPI *PFN_CreateUrlGroup)(HTTP_SERVER_SESSION_ID, PHTTP_URL_GROUP_ID, ULONG);
typedef ULONG (WINAPI *PFN_CloseUrlGroup)(HTTP_URL_GROUP_ID);
typedef ULONG (WINAPI *PFN_CreateRequestQueue)(HTTPAPI_VERSION, PCWSTR, PSECURITY_ATTRIBUTES, ULONG, PHANDLE);
typedef ULONG (WINAPI *PFN_CloseRequestQueue)(HANDLE);
typedef ULONG (WINAPI *PFN_ShutdownRequestQueue)(HANDLE);

static const char *g_Exports[] =
{
    "HttpCreateServerSession", "HttpCloseServerSession", "HttpSetServerSessionProperty",
    "HttpCreateUrlGroup", "HttpCloseUrlGroup", "HttpSetUrlGroupProperty",
    "HttpCreateRequestQueue", "HttpCloseRequestQueue", "HttpSetRequestQueueProperty",
    "HttpShutdownRequestQueue", "HttpQueryServerSessionProperty", "HttpQueryUrlGroupProperty",
    "HttpQueryRequestQueueProperty", "HttpCancelHttpRequest", "HttpControlService",
    "HttpSendResponseEntityBody", "HttpWaitForDemandStart",
};

START_TEST(HttpServerApi)
{
    HMODULE Httpapi = LoadLibraryW(L"httpapi.dll");
    HTTPAPI_VERSION Version = HTTPAPI_VERSION_2;
    HTTP_SERVER_SESSION_ID Session = 0;
    HTTP_URL_GROUP_ID Group = 0;
    HANDLE Queue = NULL;
    ULONG Ret, Expected;
    UINT i;
    PFN_HttpInitialize pInitialize;
    PFN_HttpTerminate pTerminate;
    PFN_CreateServerSession pCreateSession;
    PFN_CloseServerSession pCloseSession;
    PFN_CreateUrlGroup pCreateGroup;
    PFN_CloseUrlGroup pCloseGroup;
    PFN_CreateRequestQueue pCreateQueue;
    PFN_CloseRequestQueue pCloseQueue;
    PFN_ShutdownRequestQueue pShutdownQueue;

    ok(Httpapi != NULL, "httpapi.dll does not load\n");
    if (!Httpapi)
        return;

    for (i = 0; i < _countof(g_Exports); i++)
        ok(GetProcAddress(Httpapi, g_Exports[i]) != NULL, "%s is not exported\n", g_Exports[i]);

    pInitialize = (PFN_HttpInitialize)GetProcAddress(Httpapi, "HttpInitialize");
    pTerminate = (PFN_HttpTerminate)GetProcAddress(Httpapi, "HttpTerminate");
    pCreateSession = (PFN_CreateServerSession)GetProcAddress(Httpapi, "HttpCreateServerSession");
    pCloseSession = (PFN_CloseServerSession)GetProcAddress(Httpapi, "HttpCloseServerSession");
    pCreateGroup = (PFN_CreateUrlGroup)GetProcAddress(Httpapi, "HttpCreateUrlGroup");
    pCloseGroup = (PFN_CloseUrlGroup)GetProcAddress(Httpapi, "HttpCloseUrlGroup");
    pCreateQueue = (PFN_CreateRequestQueue)GetProcAddress(Httpapi, "HttpCreateRequestQueue");
    pCloseQueue = (PFN_CloseRequestQueue)GetProcAddress(Httpapi, "HttpCloseRequestQueue");
    pShutdownQueue = (PFN_ShutdownRequestQueue)GetProcAddress(Httpapi, "HttpShutdownRequestQueue");
    if (!pInitialize || !pTerminate || !pCreateSession || !pCloseSession || !pCreateGroup ||
        !pCloseGroup || !pCreateQueue || !pCloseQueue || !pShutdownQueue)
    {
        skip("Entry points are missing\n");
        return;
    }

    /* The answer pointers are checked on both systems */
    Ret = pCreateSession(Version, NULL, 0);
    ok(Ret == ERROR_INVALID_PARAMETER, "HttpCreateServerSession(NULL) returned %lu\n", Ret);
    Ret = pCreateGroup(0, NULL, 0);
    ok(Ret == ERROR_INVALID_PARAMETER, "HttpCreateUrlGroup(NULL) returned %lu\n", Ret);
    Ret = pCreateQueue(Version, NULL, NULL, 0, NULL);
    ok(Ret == ERROR_INVALID_PARAMETER, "HttpCreateRequestQueue(NULL) returned %lu\n", Ret);

    Expected = ERROR_SUCCESS;
    pInitialize(Version, HTTP_INITIALIZE_SERVER, NULL);

    Ret = pCreateSession(Version, &Session, 0);
    ok(Ret == Expected, "HttpCreateServerSession returned %lu\n", Ret);
    Ret = pCreateGroup(Session, &Group, 0);
    ok(Ret == Expected, "HttpCreateUrlGroup returned %lu\n", Ret);
    Ret = pCreateQueue(Version, NULL, NULL, 0, &Queue);
    ok(Ret == Expected, "HttpCreateRequestQueue returned %lu\n", Ret);
    if (Expected == ERROR_SUCCESS)
    {
        ok(Session != 0, "No session id\n");
        ok(Group != 0, "No URL group id\n");
        ok(Queue != NULL, "No request queue handle\n");
        Ret = pShutdownQueue(Queue);
        ok(Ret == ERROR_SUCCESS, "HttpShutdownRequestQueue returned %lu\n", Ret);
        Ret = pCloseQueue(Queue);
        ok(Ret == ERROR_SUCCESS, "HttpCloseRequestQueue returned %lu\n", Ret);
        Ret = pCloseGroup(Group);
        ok(Ret == ERROR_SUCCESS, "HttpCloseUrlGroup returned %lu\n", Ret);
        Ret = pCloseSession(Session);
        ok(Ret == ERROR_SUCCESS, "HttpCloseServerSession returned %lu\n", Ret);
    }
    pTerminate(HTTP_INITIALIZE_SERVER, NULL);
}
