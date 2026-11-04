/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Tests for the argument checks and failure codes of wevtapi.dll
 *
 * The expected values were measured on Windows Server 2008 R2 and Windows 10, x64 and WOW64.
 * ReactOS has no event log service. Where a call needs one, it fails with the error of an RPC
 * server that cannot be reached, and the tests accept that error where Windows succeeds.
 */

#include <apitest.h>

#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winevt.h>

#include "evtx_sample.h"

typedef EVT_HANDLE (WINAPI *PEvtOpenSession)(EVT_LOGIN_CLASS, PVOID, DWORD, DWORD);
typedef BOOL (WINAPI *PEvtClose)(EVT_HANDLE);
typedef BOOL (WINAPI *PEvtCancel)(EVT_HANDLE);
typedef DWORD (WINAPI *PEvtGetExtendedStatus)(DWORD, LPWSTR, PDWORD);
typedef EVT_HANDLE (WINAPI *PEvtOpenChannelEnum)(EVT_HANDLE, DWORD);
typedef BOOL (WINAPI *PEvtNextChannelPath)(EVT_HANDLE, DWORD, LPWSTR, PDWORD);
typedef EVT_HANDLE (WINAPI *PEvtOpenChannelConfig)(EVT_HANDLE, LPCWSTR, DWORD);
typedef BOOL (WINAPI *PEvtGetChannelConfigProperty)(EVT_HANDLE, EVT_CHANNEL_CONFIG_PROPERTY_ID, DWORD, DWORD, PEVT_VARIANT, PDWORD);
typedef BOOL (WINAPI *PEvtSetChannelConfigProperty)(EVT_HANDLE, EVT_CHANNEL_CONFIG_PROPERTY_ID, DWORD, PEVT_VARIANT);
typedef BOOL (WINAPI *PEvtSaveChannelConfig)(EVT_HANDLE, DWORD);
typedef EVT_HANDLE (WINAPI *PEvtQuery)(EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI *PEvtNext)(EVT_HANDLE, DWORD, PEVT_HANDLE, DWORD, DWORD, PDWORD);
typedef BOOL (WINAPI *PEvtSeek)(EVT_HANDLE, LONGLONG, EVT_HANDLE, DWORD, DWORD);
typedef EVT_HANDLE (WINAPI *PEvtSubscribe)(EVT_HANDLE, HANDLE, LPCWSTR, LPCWSTR, EVT_HANDLE, PVOID, EVT_SUBSCRIBE_CALLBACK, DWORD);
typedef EVT_HANDLE (WINAPI *PEvtOpenLog)(EVT_HANDLE, LPCWSTR, DWORD);
typedef BOOL (WINAPI *PEvtGetLogInfo)(EVT_HANDLE, EVT_LOG_PROPERTY_ID, DWORD, PEVT_VARIANT, PDWORD);
typedef BOOL (WINAPI *PEvtGetQueryInfo)(EVT_HANDLE, EVT_QUERY_PROPERTY_ID, DWORD, PEVT_VARIANT, PDWORD);
typedef BOOL (WINAPI *PEvtExportLog)(EVT_HANDLE, LPCWSTR, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI *PEvtClearLog)(EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);
typedef EVT_HANDLE (WINAPI *PEvtCreateRenderContext)(DWORD, LPCWSTR *, DWORD);
typedef BOOL (WINAPI *PEvtRender)(EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
typedef EVT_HANDLE (WINAPI *PEvtCreateBookmark)(LPCWSTR);
typedef BOOL (WINAPI *PEvtUpdateBookmark)(EVT_HANDLE, EVT_HANDLE);
typedef EVT_HANDLE (WINAPI *PEvtOpenPublisherMetadata)(EVT_HANDLE, LPCWSTR, LPCWSTR, LCID, DWORD);

static HMODULE hWevtapi;
static PEvtOpenSession pEvtOpenSession;
static PEvtClose pEvtClose;
static PEvtCancel pEvtCancel;
static PEvtGetExtendedStatus pEvtGetExtendedStatus;
static PEvtOpenChannelEnum pEvtOpenChannelEnum;
static PEvtNextChannelPath pEvtNextChannelPath;
static PEvtOpenChannelConfig pEvtOpenChannelConfig;
static PEvtGetChannelConfigProperty pEvtGetChannelConfigProperty;
static PEvtSetChannelConfigProperty pEvtSetChannelConfigProperty;
static PEvtSaveChannelConfig pEvtSaveChannelConfig;
static PEvtQuery pEvtQuery;
static PEvtNext pEvtNext;
static PEvtSeek pEvtSeek;
static PEvtSubscribe pEvtSubscribe;
static PEvtOpenLog pEvtOpenLog;
static PEvtGetLogInfo pEvtGetLogInfo;
static PEvtGetQueryInfo pEvtGetQueryInfo;
static PEvtExportLog pEvtExportLog;
static PEvtClearLog pEvtClearLog;
static PEvtCreateRenderContext pEvtCreateRenderContext;
static PEvtRender pEvtRender;
static PEvtCreateBookmark pEvtCreateBookmark;
static PEvtUpdateBookmark pEvtUpdateBookmark;
static PEvtOpenPublisherMetadata pEvtOpenPublisherMetadata;

static const char *ExportNames[] =
{
    "EvtArchiveExportedLog", "EvtCancel", "EvtClearLog", "EvtClose", "EvtCreateBookmark",
    "EvtCreateRenderContext", "EvtExportLog", "EvtFormatMessage", "EvtGetChannelConfigProperty",
    "EvtGetEventInfo", "EvtGetEventMetadataProperty", "EvtGetExtendedStatus", "EvtGetLogInfo",
    "EvtGetObjectArrayProperty", "EvtGetObjectArraySize", "EvtGetPublisherMetadataProperty",
    "EvtGetQueryInfo", "EvtNext", "EvtNextChannelPath", "EvtNextEventMetadata",
    "EvtNextPublisherId", "EvtOpenChannelConfig", "EvtOpenChannelEnum", "EvtOpenEventMetadataEnum",
    "EvtOpenLog", "EvtOpenPublisherEnum", "EvtOpenPublisherMetadata", "EvtOpenSession", "EvtQuery",
    "EvtRender", "EvtSaveChannelConfig", "EvtSeek", "EvtSetChannelConfigProperty",
    "EvtSetObjectArrayProperty", "EvtSubscribe", "EvtUpdateBookmark",
};

#define ERR_NO_SERVICE RPC_S_SERVER_UNAVAILABLE

#define ok_handle_error(handle, error) \
    do { \
        DWORD LastError_ = GetLastError(); \
        ok((handle) == NULL, "got %p\n", (handle)); \
        ok(LastError_ == (error), "got %lu, expected %lu\n", LastError_, (DWORD)(error)); \
        if (handle) pEvtClose(handle); \
    } while (0)

#define ok_false_error(ret, error) \
    do { \
        DWORD LastError_ = GetLastError(); \
        ok((ret) == FALSE, "got %d\n", (ret)); \
        ok(LastError_ == (error), "got %lu, expected %lu\n", LastError_, (DWORD)(error)); \
    } while (0)

/* A call that succeeds on Windows needs the event log service, which ReactOS does not have */
#define ok_handle_or_no_service(handle) \
    do { \
        DWORD LastError_ = GetLastError(); \
        ok((handle) != NULL || LastError_ == ERR_NO_SERVICE, "got %p and %lu\n", (handle), LastError_); \
        if (handle) pEvtClose(handle); \
    } while (0)

static void test_exports(void)
{
    UINT i;

    for (i = 0; i < ARRAYSIZE(ExportNames); i++)
    {
        /* Windows 8 and later no longer have this one */
        if (!strcmp(ExportNames[i], "EvtSetObjectArrayProperty") && GetNTVersion() >= _WIN32_WINNT_WIN8)
            continue;
        ok(GetProcAddress(hWevtapi, ExportNames[i]) != NULL, "%s is not exported\n", ExportNames[i]);
    }
}

static void test_handles(void)
{
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Ret = pEvtClose(NULL);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtClose((EVT_HANDLE)(ULONG_PTR)0x1234);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtClose(INVALID_HANDLE_VALUE);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);

    /* cancelling nothing succeeds, a handle that is nothing is refused */
    SetLastError(0xdeadbeef);
    Ret = pEvtCancel(NULL);
    ok(Ret == TRUE, "got %d\n", Ret);
    SetLastError(0xdeadbeef);
    Ret = pEvtCancel((EVT_HANDLE)(ULONG_PTR)0x1234);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
}

static void test_publisher(void)
{
    EVT_HANDLE Publisher;

    /* a publisher that is not registered has no manifest file */
    SetLastError(0xdeadbeef);
    Publisher = pEvtOpenPublisherMetadata(NULL, L"wevtapi_apitest_no_such_publisher", NULL, 0, 0);
    ok_handle_error(Publisher, ERROR_FILE_NOT_FOUND);
}

static void test_session(void)
{
    EVT_RPC_LOGIN Login;
    EVT_HANDLE Session, Enum, Config, Query, Log;
    BOOL Ret;

    memset(&Login, 0, sizeof(Login));

    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(EvtRpcLogin, NULL, 0, 0);
    ok_handle_error(Session, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(0, &Login, 0, 0);
    ok_handle_error(Session, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(2, &Login, 0, 0);
    ok_handle_error(Session, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(EvtRpcLogin, &Login, 0, 1);
    ok_handle_error(Session, ERROR_INVALID_PARAMETER);

    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(EvtRpcLogin, &Login, 0, 0);
    ok(Session != NULL, "got NULL and %lu\n", GetLastError());
    if (Session)
    {
        Ret = pEvtClose(Session);
        ok(Ret == TRUE, "got %d\n", Ret);
        SetLastError(0xdeadbeef);
        Ret = pEvtClose(Session);
        ok_false_error(Ret, ERROR_INVALID_HANDLE);
    }

    /* closing a session does not close what was opened through it */
    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(EvtRpcLogin, &Login, 0, 0);
    ok(Session != NULL, "got NULL and %lu\n", GetLastError());
    if (Session)
    {
        WCHAR Name[256];
        DWORD Used;

        Enum = pEvtOpenChannelEnum(Session, 0);
        ok(Enum != NULL, "got NULL and %lu\n", GetLastError());
        Ret = pEvtClose(Session);
        ok(Ret == TRUE, "got %d\n", Ret);
        if (Enum)
        {
            Used = 0;
            Ret = pEvtNextChannelPath(Enum, ARRAYSIZE(Name), Name, &Used);
            ok(Ret == TRUE, "got %d and %lu\n", Ret, GetLastError());
            pEvtClose(Enum);
        }
    }

    /* the session of an unreachable server opens, and every use of it fails with the RPC error */
    Login.Server = (LPWSTR)L"wevtapi-apitest.invalid";
    SetLastError(0xdeadbeef);
    Session = pEvtOpenSession(EvtRpcLogin, &Login, 0, 0);
    ok(Session != NULL, "got NULL and %lu\n", GetLastError());
    if (!Session)
    {
        skip("No remote session to work with\n");
        return;
    }
    SetLastError(0xdeadbeef);
    Enum = pEvtOpenChannelEnum(Session, 0);
    ok_handle_error(Enum, RPC_S_SERVER_UNAVAILABLE);
    SetLastError(0xdeadbeef);
    Config = pEvtOpenChannelConfig(Session, L"Application", 0);
    ok_handle_error(Config, RPC_S_SERVER_UNAVAILABLE);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(Session, L"Application", L"*", EvtQueryChannelPath | EvtQueryForwardDirection);
    ok_handle_error(Query, RPC_S_SERVER_UNAVAILABLE);
    SetLastError(0xdeadbeef);
    Log = pEvtOpenLog(Session, L"Application", EvtOpenChannelPath);
    ok_handle_error(Log, RPC_S_SERVER_UNAVAILABLE);
    pEvtClose(Session);

    /* a handle that is not a session */
    SetLastError(0xdeadbeef);
    Enum = pEvtOpenChannelEnum((EVT_HANDLE)(ULONG_PTR)0x1234, 0);
    ok_handle_error(Enum, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Config = pEvtOpenChannelConfig((EVT_HANDLE)(ULONG_PTR)0x1234, L"Application", 0);
    ok_handle_error(Config, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery((EVT_HANDLE)(ULONG_PTR)0x1234, L"Application", L"*", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_INVALID_HANDLE);
}

static void test_channel_enum(void)
{
    WCHAR Path[256];
    EVT_HANDLE Enum;
    DWORD Used, Count = 0;
    BOOL Ret, Application = FALSE, System = FALSE, Security = FALSE;

    SetLastError(0xdeadbeef);
    Enum = pEvtOpenChannelEnum(NULL, 1);
    ok_handle_error(Enum, ERROR_INVALID_PARAMETER);

    Enum = pEvtOpenChannelEnum(NULL, 0);
    ok(Enum != NULL, "got NULL and %lu\n", GetLastError());
    if (!Enum)
    {
        skip("No channel enumeration to work with\n");
        return;
    }

    /* the length of a name is reported without advancing, so the same name comes back */
    Used = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = pEvtNextChannelPath(Enum, 0, NULL, &Used);
    ok_false_error(Ret, ERROR_INSUFFICIENT_BUFFER);
    ok(Used != 0 && Used != 0xdeadbeef, "got %lu\n", Used);

    SetLastError(0xdeadbeef);
    Ret = pEvtNextChannelPath(Enum, ARRAYSIZE(Path), Path, NULL);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);

    for (;;)
    {
        Used = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        Ret = pEvtNextChannelPath(Enum, ARRAYSIZE(Path), Path, &Used);
        if (!Ret)
            break;
        ok(Used == wcslen(Path) + 1, "got %lu for %ls\n", Used, Path);
        if (!_wcsicmp(Path, L"Application")) Application = TRUE;
        if (!_wcsicmp(Path, L"System")) System = TRUE;
        if (!_wcsicmp(Path, L"Security")) Security = TRUE;
        Count++;
    }
    ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got %lu\n", GetLastError());
    ok(Used == 0xdeadbeef, "got %lu\n", Used);
    ok(Count >= 3, "got %lu channels\n", Count);
    ok(Application && System && Security, "got %d, %d, %d\n", Application, System, Security);

    SetLastError(0xdeadbeef);
    Ret = pEvtNextChannelPath(Enum, ARRAYSIZE(Path), Path, &Used);
    ok_false_error(Ret, ERROR_NO_MORE_ITEMS);

    SetLastError(0xdeadbeef);
    Ret = pEvtNextChannelPath(NULL, ARRAYSIZE(Path), Path, &Used);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtNextChannelPath((EVT_HANDLE)(ULONG_PTR)0x1234, ARRAYSIZE(Path), Path, &Used);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);

    Ret = pEvtClose(Enum);
    ok(Ret == TRUE, "got %d\n", Ret);
    SetLastError(0xdeadbeef);
    Ret = pEvtNextChannelPath(Enum, ARRAYSIZE(Path), Path, &Used);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
}

static void test_channel_config(void)
{
    struct
    {
        EVT_VARIANT Variant;
        WCHAR Buffer[MAX_PATH];
    } Data;
    EVT_HANDLE Config;
    DWORD Used, Size;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Config = pEvtOpenChannelConfig(NULL, L"wevtapi_apitest_no_such_channel", 0);
    ok_handle_error(Config, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Config = pEvtOpenChannelConfig(NULL, L"", 0);
    ok_handle_error(Config, ERROR_EVT_INVALID_CHANNEL_PATH);
    SetLastError(0xdeadbeef);
    Config = pEvtOpenChannelConfig(NULL, NULL, 0);
    ok_handle_error(Config, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Config = pEvtOpenChannelConfig(NULL, L"Application", 1);
    ok_handle_error(Config, ERROR_INVALID_PARAMETER);

    Config = pEvtOpenChannelConfig(NULL, L"Application", 0);
    ok(Config != NULL, "got NULL and %lu\n", GetLastError());
    if (!Config)
    {
        skip("No channel configuration to work with\n");
        return;
    }

    /* a classic log is enabled, and says so */
    memset(&Data, 0xcc, sizeof(Data));
    Used = 0xdeadbeef;
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelConfigEnabled, 0, sizeof(Data), &Data.Variant, &Used);
    ok(Ret == TRUE, "got %d and %lu\n", Ret, GetLastError());
    ok(Data.Variant.Type == EvtVarTypeBoolean, "got %lu\n", Data.Variant.Type);
    ok(Data.Variant.BooleanVal == TRUE, "got %d\n", Data.Variant.BooleanVal);
    ok(Data.Variant.Count == 0xcccccccc, "got %lu\n", Data.Variant.Count);
    ok(Used == sizeof(EVT_VARIANT), "got %lu\n", Used);
    memset(&Data, 0xcc, sizeof(Data));
    Used = 0xdeadbeef;
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelConfigClassicEventlog, 0, sizeof(Data), &Data.Variant, &Used);
    ok(Ret == TRUE, "got %d and %lu\n", Ret, GetLastError());
    ok(Data.Variant.Type == EvtVarTypeBoolean, "got %lu\n", Data.Variant.Type);
    ok(Data.Variant.BooleanVal == TRUE, "got %d\n", Data.Variant.BooleanVal);

    /* the path of the log file follows the structure, a string behind the variant */
    Used = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelLoggingConfigLogFilePath, 0, 0, NULL, &Used);
    ok_false_error(Ret, ERROR_INSUFFICIENT_BUFFER);
    ok(Used > sizeof(EVT_VARIANT) && Used < sizeof(Data), "got %lu\n", Used);
    Size = Used;
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelLoggingConfigLogFilePath, 0, Size - 1, &Data.Variant, &Used);
    ok_false_error(Ret, ERROR_INSUFFICIENT_BUFFER);
    ok(Used == Size, "got %lu, expected %lu\n", Used, Size);

    memset(&Data, 0, sizeof(Data));
    Data.Variant.Count = 0xdeadbeef;
    Data.Variant.Type = 0xdeadbeef;
    Used = 0xdeadbeef;
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelLoggingConfigLogFilePath, 0, Size, &Data.Variant, &Used);
    ok(Ret == TRUE, "got %d and %lu\n", Ret, GetLastError());
    ok(Data.Variant.Type == EvtVarTypeString, "got %lu\n", Data.Variant.Type);
    ok(Data.Variant.Count == 0xdeadbeef, "got %lu\n", Data.Variant.Count);
    ok(Data.Variant.StringVal == Data.Buffer, "got %p, expected %p\n", Data.Variant.StringVal, Data.Buffer);
    ok(Used == Size, "got %lu, expected %lu\n", Used, Size);
    ok(Used == sizeof(EVT_VARIANT) + (wcslen(Data.Variant.StringVal) + 1) * sizeof(WCHAR), "got %lu\n", Used);

    /* the arguments */
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelLoggingConfigLogFilePath, 0, sizeof(Data), &Data.Variant, NULL);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelLoggingConfigLogFilePath, 1, sizeof(Data), &Data.Variant, &Used);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, (EVT_CHANNEL_CONFIG_PROPERTY_ID)-1, 0, sizeof(Data), &Data.Variant, &Used);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelConfigPropertyIdEND, 0, sizeof(Data), &Data.Variant, &Used);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(NULL, EvtChannelLoggingConfigLogFilePath, 0, sizeof(Data), &Data.Variant, &Used);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);

    /* nothing was changed, so there is nothing to save */
    SetLastError(0xdeadbeef);
    Ret = pEvtSaveChannelConfig(Config, 0);
    ok(Ret == TRUE, "got %d and %lu\n", Ret, GetLastError());
    SetLastError(0xdeadbeef);
    Ret = pEvtSaveChannelConfig(Config, 1);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtSaveChannelConfig(NULL, 0);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);

    SetLastError(0xdeadbeef);
    Ret = pEvtSetChannelConfigProperty(Config, EvtChannelConfigEnabled, 0, NULL);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtSetChannelConfigProperty(Config, (EVT_CHANNEL_CONFIG_PROPERTY_ID)9999, 0, &Data.Variant);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtSetChannelConfigProperty(NULL, EvtChannelConfigEnabled, 0, &Data.Variant);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);

    Ret = pEvtClose(Config);
    ok(Ret == TRUE, "got %d\n", Ret);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetChannelConfigProperty(Config, EvtChannelConfigEnabled, 0, sizeof(Data), &Data.Variant, &Used);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
}

static void test_query(void)
{
    static const WCHAR QueryList[] =
        L"<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">*</Select></Query></QueryList>";
    static const WCHAR QueryListMissing[] =
        L"<QueryList><Query Id=\"0\" Path=\"wevtapi_apitest_no_such_channel\">"
        L"<Select Path=\"wevtapi_apitest_no_such_channel\">*</Select></Query></QueryList>";
    EVT_HANDLE Query;
    DWORD Count = 0xdeadbeef;
    EVT_HANDLE Event;
    BOOL Ret;

    /* the flags name one kind of path and at most one direction */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"*", 0);
    ok_handle_error(Query, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"*", EvtQueryChannelPath | EvtQueryFilePath);
    ok_handle_error(Query, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"*", EvtQueryChannelPath | EvtQueryForwardDirection | EvtQueryReverseDirection);
    ok_handle_error(Query, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"*", 0x4);
    ok_handle_error(Query, ERROR_INVALID_PARAMETER);

    /* the channel */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"wevtapi_apitest_no_such_channel", L"*", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"", L"*", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_CHANNEL_PATH);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"*", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_CHANNEL_PATH);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, NULL, EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_CHANNEL_PATH);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, QueryList, NULL, EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_CHANNEL_PATH);

    /* a query is not empty */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_QUERY);

    /* a structured query names its channels itself, and the path is not looked at */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, QueryListMissing, EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"wevtapi_apitest_no_such_channel", QueryList, EvtQueryChannelPath);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"", QueryList, EvtQueryChannelPath);
    ok_handle_or_no_service(Query);

    /* the structure of the text, which is XML with white space and comments where XML allows them */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id = \"0\" Path = 'Application'><Select Path = \"Application\">*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\"><Select Path=\"Application\">*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\" Path=\"Application\"><Select>*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><!-- Path=\"wevtapi_apitest_no_such_channel\" --><Query Id=\"0\"><Select Path=\"Application\">*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\"><Select Path=\"Application\">*</Select><Suppress Path=\"wevtapi_apitest_no_such_channel\">*[System[Level=9]]</Suppress></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_CHANNEL_NOT_FOUND);
    /* every selection needs a path of its own or the default of its query: one that has neither is refused, also behind one that has */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\"><Select>*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_QUERY);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\"><Select Path='Application'>*</Select><Select>*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_QUERY);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\" Path=\"Application\"><Select>*</Select></Query><Query Id=\"1\"><Select>*</Select></Query></QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_INVALID_QUERY);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList></QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_MALFORMED_XML_TEXT);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, L"<QueryList><Query Id=\"0\"><Select Path=\"Application\">*</Select></QueryList>", EvtQueryChannelPath);
    ok_handle_error(Query, ERROR_EVT_MALFORMED_XML_TEXT);

    /* a file that is not there */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"C:\\wevtapi_apitest_no_such_dir\\no_such_file.evtx", L"*", EvtQueryFilePath);
    ok_handle_error(Query, ERROR_PATH_NOT_FOUND);

    /* a query that is fine needs the service, which Windows has */
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"*", EvtQueryChannelPath | EvtQueryForwardDirection);
    if (Query)
    {
        /* a result set answers when it has no event to give */
        SetLastError(0xdeadbeef);
        Ret = pEvtNext(Query, 1, &Event, 0, 0, NULL);
        ok_false_error(Ret, ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        Ret = pEvtNext(Query, 1, NULL, 0, 0, &Count);
        ok_false_error(Ret, ERROR_INVALID_PARAMETER);
        pEvtClose(Query);
    }
    else
    {
        ok(GetLastError() == ERR_NO_SERVICE, "got %lu\n", GetLastError());
    }
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", NULL, EvtQueryChannelPath | EvtQueryReverseDirection);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, L"Application", L"*", EvtQueryChannelPath | EvtQueryTolerateQueryErrors);
    ok_handle_or_no_service(Query);
    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, NULL, QueryList, EvtQueryChannelPath);
    ok_handle_or_no_service(Query);

    /* the handles that do not name a result set */
    SetLastError(0xdeadbeef);
    Ret = pEvtNext(NULL, 1, &Event, 0, 0, &Count);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtNext((EVT_HANDLE)(ULONG_PTR)0x1234, 1, &Event, 0, 0, &Count);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtSeek(NULL, 0, NULL, 0, 0);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetQueryInfo(NULL, EvtQueryNames, 0, NULL, &Count);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtGetLogInfo(NULL, EvtLogFileSize, 0, NULL, &Count);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
}

static void test_log_and_subscription(void)
{
    HANDLE Signal = CreateEventW(NULL, TRUE, FALSE, NULL);
    EVT_HANDLE Handle;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Handle = pEvtOpenLog(NULL, L"Application", 0);
    ok_handle_error(Handle, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Handle = pEvtOpenLog(NULL, NULL, EvtOpenChannelPath);
    ok_handle_error(Handle, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Handle = pEvtOpenLog(NULL, L"wevtapi_apitest_no_such_channel", EvtOpenChannelPath);
    ok_handle_error(Handle, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Handle = pEvtOpenLog(NULL, L"C:\\wevtapi_apitest_no_such_dir\\no_such_file.evtx", EvtOpenFilePath);
    ok_handle_error(Handle, ERROR_PATH_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Handle = pEvtOpenLog(NULL, L"Application", EvtOpenChannelPath);
    ok_handle_or_no_service(Handle);

    /* a subscription needs either an event or a callback, and a bookmark when it starts after one */
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, NULL, L"Application", L"*", NULL, NULL, NULL, EvtSubscribeToFutureEvents);
    ok_handle_error(Handle, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, Signal, L"Application", L"*", NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)(ULONG_PTR)0x1234, EvtSubscribeToFutureEvents);
    ok_handle_error(Handle, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, Signal, L"Application", L"*", NULL, NULL, NULL, 0);
    ok_handle_error(Handle, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, Signal, L"Application", L"*", NULL, NULL, NULL, EvtSubscribeStartAfterBookmark);
    ok_handle_error(Handle, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, Signal, L"wevtapi_apitest_no_such_channel", L"*", NULL, NULL, NULL, EvtSubscribeToFutureEvents);
    ok_handle_error(Handle, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, Signal, NULL, L"*", NULL, NULL, NULL, EvtSubscribeToFutureEvents);
    ok_handle_error(Handle, ERROR_EVT_INVALID_CHANNEL_PATH);
    SetLastError(0xdeadbeef);
    Handle = pEvtSubscribe(NULL, Signal, L"Application", L"*", NULL, NULL, NULL, EvtSubscribeToFutureEvents);
    if (Handle)
    {
        SetLastError(0xdeadbeef);
        Ret = pEvtCancel(Handle);
        ok(Ret == TRUE, "got %d and %lu\n", Ret, GetLastError());
        pEvtClose(Handle);
    }
    else
    {
        ok(GetLastError() == ERR_NO_SERVICE, "got %lu\n", GetLastError());
    }
    CloseHandle(Signal);

    /* exporting and clearing */
    SetLastError(0xdeadbeef);
    Ret = pEvtExportLog(NULL, L"wevtapi_apitest_no_such_channel", L"*", L"C:\\wevtapi_apitest.evtx", EvtExportLogChannelPath);
    ok_false_error(Ret, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    Ret = pEvtExportLog(NULL, NULL, L"*", L"C:\\wevtapi_apitest.evtx", EvtExportLogChannelPath);
    ok_false_error(Ret, ERROR_EVT_INVALID_CHANNEL_PATH);
    SetLastError(0xdeadbeef);
    Ret = pEvtExportLog(NULL, L"Application", L"*", NULL, EvtExportLogChannelPath);
    ok_false_error(Ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Ret = pEvtClearLog(NULL, L"wevtapi_apitest_no_such_channel", NULL, 0);
    ok_false_error(Ret, ERROR_EVT_CHANNEL_NOT_FOUND);
}

static void test_render_context(void)
{
    static const WCHAR *Paths[] = { L"Event/System/EventID", L"Event/System/Level" };
    EVT_HANDLE Context;

    /* values need paths, the other contexts take none */
    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(0, NULL, EvtRenderContextValues);
    ok_handle_error(Context, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(2, NULL, EvtRenderContextValues);
    ok_handle_error(Context, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(1, Paths, EvtRenderContextSystem);
    ok_handle_error(Context, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(0, NULL, 3);
    ok_handle_error(Context, ERROR_INVALID_PARAMETER);

    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    ok(Context != NULL, "got NULL and %lu\n", GetLastError());
    if (Context) pEvtClose(Context);
    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(0, NULL, EvtRenderContextUser);
    ok(Context != NULL, "got NULL and %lu\n", GetLastError());
    if (Context) pEvtClose(Context);
    SetLastError(0xdeadbeef);
    Context = pEvtCreateRenderContext(2, Paths, EvtRenderContextValues);
    ok(Context != NULL, "got NULL and %lu\n", GetLastError());
    if (Context) pEvtClose(Context);
}

static void check_bookmark(PCWSTR Xml, PCWSTR Expected)
{
    WCHAR Buffer[512];
    EVT_HANDLE Bookmark;
    DWORD Used = 0xdeadbeef, Count = 0xdeadbeef;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(Xml);
    ok(Bookmark != NULL, "got NULL and %lu for %ls\n", GetLastError(), Xml);
    if (!Bookmark)
        return;

    SetLastError(0xdeadbeef);
    Ret = pEvtRender(NULL, Bookmark, EvtRenderBookmark, 0, NULL, &Used, &Count);
    ok_false_error(Ret, ERROR_INSUFFICIENT_BUFFER);
    ok(Used == (wcslen(Expected) + 1) * sizeof(WCHAR), "got %lu for %ls\n", Used, Xml);

    memset(Buffer, 0xcc, sizeof(Buffer));
    Ret = pEvtRender(NULL, Bookmark, EvtRenderBookmark, sizeof(Buffer), Buffer, &Used, &Count);
    ok(Ret == TRUE, "got %d and %lu for %ls\n", Ret, GetLastError(), Xml);
    ok(!wcscmp(Buffer, Expected), "got %ls for %ls\n", Buffer, Xml);
    pEvtClose(Bookmark);
}

static void test_bookmark(void)
{
    static const WCHAR Empty[] = L"<BookmarkList>\r\n</BookmarkList>";
    EVT_HANDLE Bookmark, Context;
    DWORD Used, Count;
    BOOL Ret;

    /* text that is not XML is malformed, and so is text that stops */
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"");
    ok_handle_error(Bookmark, ERROR_EVT_MALFORMED_XML_TEXT);
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"this is not xml");
    ok_handle_error(Bookmark, ERROR_EVT_MALFORMED_XML_TEXT);

    /* XML that is not a bookmark list in the form that is written is an invalid parameter */
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"<BookmarkList><Bookmark Channel='a' RecordId='3'></Bookmark></BookmarkList>");
    ok_handle_error(Bookmark, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"<BookmarkList><Bookmark Channel='a' IsCurrent='maybe'/></BookmarkList>");
    ok_handle_error(Bookmark, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"<BookmarkList><Foo/></BookmarkList>");
    ok_handle_error(Bookmark, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"<Bookmark Channel='a' RecordId='5'/>");
    ok_handle_error(Bookmark, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"<BookmarkList><Bookmark Channel='a' Channel='b'/></BookmarkList>");
    ok_handle_error(Bookmark, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    Bookmark = pEvtCreateBookmark(L"<BookmarkList><Bookmark Channel=\"O'Brien &amp; Co\" RecordId=\"1\"/></BookmarkList>");
    ok_handle_error(Bookmark, ERROR_INVALID_PARAMETER);

    /* no text gives a list without entries */
    Bookmark = pEvtCreateBookmark(NULL);
    ok(Bookmark != NULL, "got NULL and %lu\n", GetLastError());
    if (Bookmark)
    {
        Used = 0xdeadbeef;
        Count = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        Ret = pEvtRender(NULL, Bookmark, EvtRenderBookmark, 0, NULL, &Used, &Count);
        ok_false_error(Ret, ERROR_INSUFFICIENT_BUFFER);
        /* Windows 10 gives the first list of a process a direction of its own */
        ok(Used == sizeof(Empty) || broken(Used == 106), "got %lu, expected %lu\n", Used, (DWORD)sizeof(Empty));

        /* the number of properties is not needed */
        Used = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        Ret = pEvtRender(NULL, Bookmark, EvtRenderBookmark, 0, NULL, &Used, NULL);
        ok_false_error(Ret, ERROR_INSUFFICIENT_BUFFER);
        ok(Used == sizeof(Empty) || broken(Used == 106), "got %lu, expected %lu\n", Used, (DWORD)sizeof(Empty));

        /* a bookmark is rendered as a bookmark, without a context, and is not an event */
        Context = pEvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
        ok(Context != NULL, "got NULL and %lu\n", GetLastError());
        if (Context)
        {
            SetLastError(0xdeadbeef);
            Ret = pEvtRender(Context, Bookmark, EvtRenderBookmark, 0, NULL, &Used, &Count);
            ok_false_error(Ret, ERROR_INVALID_PARAMETER);
            SetLastError(0xdeadbeef);
            Ret = pEvtRender(Context, NULL, EvtRenderEventValues, 0, NULL, &Used, &Count);
            ok_false_error(Ret, ERROR_INVALID_HANDLE);
            SetLastError(0xdeadbeef);
            Ret = pEvtRender(NULL, Context, EvtRenderBookmark, 0, NULL, &Used, &Count);
            ok_false_error(Ret, ERROR_INVALID_HANDLE);
            pEvtClose(Context);
        }
        SetLastError(0xdeadbeef);
        Ret = pEvtRender(NULL, Bookmark, EvtRenderEventXml, 0, NULL, &Used, &Count);
        ok_false_error(Ret, ERROR_INVALID_HANDLE);
        SetLastError(0xdeadbeef);
        Ret = pEvtRender(NULL, Bookmark, EvtRenderEventValues, 0, NULL, &Used, &Count);
        ok_false_error(Ret, ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        Ret = pEvtUpdateBookmark(Bookmark, (EVT_HANDLE)(ULONG_PTR)0x1234);
        ok_false_error(Ret, ERROR_INVALID_HANDLE);
        SetLastError(0xdeadbeef);
        Ret = pEvtCancel(Bookmark);
        ok_false_error(Ret, ERROR_NOT_SUPPORTED);
        SetLastError(0xdeadbeef);
        Ret = pEvtSeek(Bookmark, 0, NULL, 0, 0);
        ok_false_error(Ret, ERROR_INVALID_PARAMETER);
        pEvtClose(Bookmark);
    }

    /* a list is rendered in a fixed layout, whatever the white space of the text was */
    check_bookmark(L"<BookmarkList><Bookmark Channel='Application' RecordId='1' IsCurrent='true'/></BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='Application' RecordId='1' IsCurrent='true'/>\r\n</BookmarkList>");
    check_bookmark(L"<BookmarkList>  <Bookmark  Channel = \"a\"  RecordId = \"2\" IsCurrent = \"true\" /> </BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='a' RecordId='2' IsCurrent='true'/>\r\n</BookmarkList>");
    check_bookmark(L"<BookmarkList><Bookmark Channel='a' RecordId='1'/><Bookmark Channel='b' RecordId='2'/></BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='a' RecordId='1'/>\r\n  <Bookmark Channel='b' RecordId='2'/>\r\n</BookmarkList>");

    /* a number that is not one is zero, one that is too large is the largest signed one, and a channel may be missing */
    check_bookmark(L"<BookmarkList><Bookmark Channel='a' RecordId='x'/></BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='a' RecordId='0'/>\r\n</BookmarkList>");
    check_bookmark(L"<BookmarkList><Bookmark Channel='a' RecordId='18446744073709551615'/></BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='a' RecordId='9223372036854775807'/>\r\n</BookmarkList>");
    check_bookmark(L"<BookmarkList><Bookmark Channel='a' RecordId='18446744073709551616'/></BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='a' RecordId='9223372036854775807'/>\r\n</BookmarkList>");
    check_bookmark(L"<BookmarkList><Bookmark RecordId='1'/></BookmarkList>",
                   L"<BookmarkList>\r\n  <Bookmark Channel='' RecordId='1'/>\r\n</BookmarkList>");

    /* the direction of the list stays */
    check_bookmark(L"<BookmarkList Direction='backward'><Bookmark Channel='a' RecordId='4'/></BookmarkList>",
                   L"<BookmarkList Direction='backward'>\r\n  <Bookmark Channel='a' RecordId='4'/>\r\n</BookmarkList>");

    /* the channel of an entry is not looked up */
    Bookmark = pEvtCreateBookmark(L"<BookmarkList><Bookmark Channel='wevtapi_apitest_no_such_channel' RecordId='1'/></BookmarkList>");
    ok(Bookmark != NULL, "got NULL and %lu\n", GetLastError());
    if (Bookmark) pEvtClose(Bookmark);

    /* render without a fragment that exists */
    SetLastError(0xdeadbeef);
    Ret = pEvtRender(NULL, NULL, EvtRenderEventXml, 0, NULL, &Used, &Count);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtRender(NULL, (EVT_HANDLE)(ULONG_PTR)0x1234, EvtRenderEventXml, 0, NULL, &Used, &Count);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    Ret = pEvtUpdateBookmark(NULL, NULL);
    ok_false_error(Ret, ERROR_INVALID_HANDLE);
}

static void test_extended_status(void)
{
    DWORD Used = 0xdeadbeef, Ret;

    Ret = pEvtGetExtendedStatus(0, NULL, &Used);
    ok(Ret == ERROR_SUCCESS, "got %lu\n", Ret);
    ok(Used == 0, "got %lu\n", Used);
}

/* the names of the header have the values of the Windows header: ordinary source that uses them compiles and means the same */
static void test_header_names(void)
{
    ok(EvtFormatMessageEvent == 1 && EvtFormatMessageXml == 9, "format message flags\n");
    ok(EvtEventQueryIDs == 0 && EvtEventPath == 1 && EvtEventPropertyIdEND == 2, "event properties\n");
    ok(EvtPublisherMetadataPublisherGuid == 0 && EvtPublisherMetadataChannelReferences == 6 &&
       EvtPublisherMetadataLevels == 12 && EvtPublisherMetadataTasks == 16 && EvtPublisherMetadataOpcodes == 21 &&
       EvtPublisherMetadataKeywords == 25 && EvtPublisherMetadataPropertyIdEND == 29, "publisher metadata properties\n");
    ok(EvtChannelReferenceImported == 1, "channel reference flags\n");
    ok(EventMetadataEventID == 0 && EventMetadataEventTemplate == 8 && EvtEventMetadataPropertyIdEND == 9, "event metadata properties\n");
}


/*
 * Files are untrusted input. Truncated and corrupted copies of a small .evtx file must be refused or read
 * as far as they can be, with an error of the event log for what is wrong, and without a crash, a hang
 * or an event that cannot be rendered. Not for Windows: this is what the library does, and what Windows
 * says to damaged files was not measured.
 */
static ULONG FuzzSeed = 12345;

static DWORD FuzzRand(void)
{
    FuzzSeed = FuzzSeed * 1103515245 + 12345;
    return (FuzzSeed >> 8) & 0xffffff;
}

static DWORD FuzzOpenAndRead(const WCHAR *Path, const BYTE *Data, DWORD Size, const WCHAR *Filter, DWORD Flags, DWORD *Events)
{
    static const WCHAR *Paths[] = { L"Event/System/Provider/@Name", L"Event/System/EventRecordID" };
    HANDLE File;
    EVT_HANDLE Query, Event, Context;
    DWORD Written, Calls = 0, N, Used, Props, Errors = 0;
    BYTE Buffer[4096];
    WCHAR *Xml;

    *Events = 0;
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE) return 0xffffffff;
    WriteFile(File, Data, Size, &Written, NULL);
    CloseHandle(File);

    SetLastError(0xdeadbeef);
    Query = pEvtQuery(NULL, Path, Filter, EvtQueryFilePath | Flags);
    if (!Query)
    {
        DWORD Error = GetLastError();

        ok(Error == ERROR_EVENTLOG_FILE_CORRUPT, "EvtQuery of a damaged file: %lu\n", Error);
        return 1;
    }
    Context = pEvtCreateRenderContext(2, Paths, EvtRenderContextValues);
    while (Calls++ < 100)
    {
        SetLastError(0xdeadbeef);
        if (!pEvtNext(Query, 1, &Event, 1000, 0, &N))
        {
            DWORD Error = GetLastError();

            if (Error == ERROR_NO_MORE_ITEMS) break;
            ok(Error == ERROR_EVENTLOG_FILE_CORRUPT, "EvtNext on a damaged file: %lu\n", Error);
            Errors++;
            continue;
        }
        (*Events)++;
        Used = Props = 0;
        pEvtRender(NULL, Event, EvtRenderEventXml, 0, NULL, &Used, &Props);
        Xml = malloc(Used + 2);
        if (Xml)
        {
            ok(pEvtRender(NULL, Event, EvtRenderEventXml, Used, Xml, &Used, &Props), "EvtRender of the XML: %lu\n", GetLastError());
            free(Xml);
        }
        ok(pEvtRender(Context, Event, EvtRenderEventValues, sizeof(Buffer), Buffer, &Used, &Props), "EvtRender of values: %lu\n", GetLastError());
        pEvtClose(Event);
    }
    ok(Calls <= 100, "The reading does not end\n");
    pEvtClose(Context);
    pEvtClose(Query);
    return Errors;
}

static void test_evtx_robustness(void)
{
    static BYTE Good[EVTX_SAMPLE_SIZE], Bad[EVTX_SAMPLE_SIZE];
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    DWORD Events, Errors, Size, i, j, N, Cuts, Rounds, Kept = 4096 + 5664;
    char Env[16];
    static const DWORD Sizes[] = { 0, 1, 7, 8, 127, 128, 511, 512, 4095, 4096, 4097, 4096 + 127, 4096 + 128, 4096 + 511,
                                   4096 + 512, 4096 + 513, 4096 + 1000, 4096 + 2920, 4096 + 3000, 4096 + 5663, 4096 + 5664,
                                   4096 + 5665, 4096 + 65535 };

    GetTempPathW(MAX_PATH, Dir);
    GetTempFileNameW(Dir, L"wfz", 0, Path);
    build_evtx_sample(Good);

    /* the file as it is: three events and the error of the checksum */
    Errors = FuzzOpenAndRead(Path, Good, sizeof(Good), L"*", EvtQueryForwardDirection, &Events);
    ok(Events == 3 && Errors == 1, "Good file: %lu events, %lu errors\n", Events, Errors);

    /* cut off at the edges of the header, the chunk and the records, and at every 61st byte of what is used */
    Cuts = 0;
    for (i = 0; i < ARRAY_SIZE(Sizes); i++, Cuts++)
        FuzzOpenAndRead(Path, Good, Sizes[i], L"*", EvtQueryReverseDirection, &Events);
    for (Size = 3; Size < Kept; Size += 61, Cuts++)
        FuzzOpenAndRead(Path, Good, Size, L"*[UserData/*/Param2='Windows x64']", EvtQueryForwardDirection, &Events);

    /* bytes that are changed: one to eight places, in the header, the chunk header and the records, to any value or to the extremes */
    Rounds = GetEnvironmentVariableA("WEVTAPI_FUZZ_ROUNDS", Env, sizeof(Env)) ? (DWORD)atoi(Env) : 1500;
    for (i = 0; i < Rounds; i++)
    {
        memcpy(Bad, Good, sizeof(Bad));
        N = 1 + FuzzRand() % 8;
        for (j = 0; j < N; j++)
        {
            DWORD Where = FuzzRand() % 4 ? 4096 + FuzzRand() % 5664 : FuzzRand() % 4200;
            DWORD How = FuzzRand() % 4;

            Bad[Where] = How == 0 ? 0 : How == 1 ? 0xff : (BYTE)FuzzRand();
        }
        FuzzOpenAndRead(Path, Bad, sizeof(Bad), i % 3 ? L"*" : L"*[System[EventID=370]]", i % 2 ? EvtQueryReverseDirection : EvtQueryForwardDirection, &Events);
    }

    /* whole fields set to extremes: sizes, offsets and counts of the chunk, the records and the binary XML */
    for (i = 0; i < 600; i++)
    {
        DWORD Where = 4096 + 40 + (FuzzRand() % 3) * 4;
        DWORD Value = FuzzRand() % 2 ? 0xffffffff : FuzzRand() * 256;

        memcpy(Bad, Good, sizeof(Bad));
        if (i % 3 == 0) memcpy(Bad + Where, &Value, 4);                                       /* the chunk header */
        else if (i % 3 == 1) memcpy(Bad + 4096 + 512 + 4 + (FuzzRand() % 3) * 4, &Value, 4);   /* the first record */
        else memcpy(Bad + 4096 + 512 + 24 + FuzzRand() % 400, &Value, 4);                      /* its binary XML */
        FuzzOpenAndRead(Path, Bad, sizeof(Bad), L"*", EvtQueryForwardDirection, &Events);
    }
    DeleteFileW(Path);
    trace("%lu cut copies and %lu changed copies read\n", Cuts, Rounds + 600);
}

void test_functional(void);

START_TEST(wevtapi)
{
    hWevtapi = LoadLibraryW(L"wevtapi.dll");
    ok(hWevtapi != NULL, "LoadLibrary failed with %lu\n", GetLastError());
    if (!hWevtapi)
    {
        skip("wevtapi.dll is not available\n");
        return;
    }

    test_exports();
    test_header_names();

#define GET(name) p##name = (PVOID)GetProcAddress(hWevtapi, #name)
    GET(EvtOpenSession); GET(EvtClose); GET(EvtCancel); GET(EvtGetExtendedStatus);
    GET(EvtOpenChannelEnum); GET(EvtNextChannelPath); GET(EvtOpenChannelConfig);
    GET(EvtGetChannelConfigProperty); GET(EvtSetChannelConfigProperty); GET(EvtSaveChannelConfig);
    GET(EvtQuery); GET(EvtNext); GET(EvtSeek); GET(EvtSubscribe); GET(EvtOpenLog); GET(EvtGetLogInfo);
    GET(EvtGetQueryInfo); GET(EvtExportLog); GET(EvtClearLog); GET(EvtCreateRenderContext);
    GET(EvtRender); GET(EvtCreateBookmark); GET(EvtUpdateBookmark); GET(EvtOpenPublisherMetadata);
#undef GET
    if (!pEvtOpenSession || !pEvtClose || !pEvtCancel || !pEvtGetExtendedStatus || !pEvtOpenChannelEnum ||
        !pEvtNextChannelPath || !pEvtOpenChannelConfig || !pEvtGetChannelConfigProperty ||
        !pEvtSetChannelConfigProperty || !pEvtSaveChannelConfig || !pEvtQuery || !pEvtNext || !pEvtSeek ||
        !pEvtSubscribe || !pEvtOpenLog || !pEvtGetLogInfo || !pEvtGetQueryInfo || !pEvtExportLog ||
        !pEvtClearLog || !pEvtCreateRenderContext || !pEvtRender || !pEvtCreateBookmark || !pEvtUpdateBookmark ||
        !pEvtOpenPublisherMetadata)
    {
        skip("Not all of the exports are available\n");
        FreeLibrary(hWevtapi);
        return;
    }

    test_handles();
    test_publisher();
    test_session();
    test_channel_enum();
    test_channel_config();
    test_query();
    test_log_and_subscription();
    test_render_context();
    test_bookmark();
    test_extended_status();
    test_evtx_robustness();
    test_functional();

    FreeLibrary(hWevtapi);
}
