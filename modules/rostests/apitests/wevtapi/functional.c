/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Tests for what wevtapi.dll does on the classic event logs: seeking in the results of a
 *              query, subscriptions, clearing a log, and the metadata of a manifest publisher
 *
 * These change the logs of the machine (they write events, and clear the Application log), so they run
 * here and not among the Wine tests, which also run on Windows.
 */

#include <apitest.h>

#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winevt.h>
#include <stdio.h>
#include <wchar.h>

#define MAX_IDS 4096

#define ok_false_error(ret, error) \
    do { \
        DWORD LastError_ = GetLastError(); \
        ok((ret) == FALSE, "got %d\n", (ret)); \
        ok(LastError_ == (error), "got %lu, expected %lu\n", LastError_, (DWORD)(error)); \
    } while (0)

#define ok_handle_error(handle, error) \
    do { \
        DWORD LastError_ = GetLastError(); \
        ok((handle) == NULL, "got %p\n", (handle)); \
        ok(LastError_ == (error), "got %lu, expected %lu\n", LastError_, (DWORD)(error)); \
        if (handle) EvtClose(handle); \
    } while (0)

/* The record number of an event */
static ULONGLONG record_id(EVT_HANDLE event)
{
    static const WCHAR *paths[] = { L"Event/System/EventRecordID" };
    EVT_HANDLE context = EvtCreateRenderContext(1, paths, EvtRenderContextValues);
    EVT_VARIANT value;
    DWORD size, count;
    ULONGLONG id = 0;

    if (context && EvtRender(context, event, EvtRenderEventValues, sizeof(value), &value, &size, &count)) id = value.UInt64Val;
    if (context) EvtClose(context);
    return id;
}

/* The record numbers of up to max events that the query gives next, one at a time */
static DWORD next_ids(EVT_HANDLE query, ULONGLONG *ids, DWORD max, DWORD *last_error)
{
    DWORD count = 0, n;
    EVT_HANDLE event;

    *last_error = ERROR_SUCCESS;
    while (count < max)
    {
        SetLastError(0xdeadbeef);
        if (!EvtNext(query, 1, &event, 1000, 0, &n))
        {
            *last_error = GetLastError();
            break;
        }
        ids[count++] = record_id(event);
        EvtClose(event);
    }
    return count;
}

static void test_seek(void)
{
    static ULONGLONG all[MAX_IDS], got[8];
    EVT_HANDLE query, event, bookmark;
    DWORD total, count, error, n;
    BOOL ret;

    query = EvtQuery(NULL, L"System", L"*", EvtQueryChannelPath | EvtQueryForwardDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    if (!query) return;
    total = next_ids(query, all, MAX_IDS, &error);
    ok(error == ERROR_NO_MORE_ITEMS, "got %lu\n", error);
    if (total < 8)
    {
        skip("The System log has %lu events\n", total);
        EvtClose(query);
        return;
    }

    /* from the first event */
    ret = EvtSeek(query, 2, NULL, 0, EvtSeekRelativeToFirst);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 2, &error);
    ok(count == 2 && got[0] == all[2] && got[1] == all[3], "got %lu: %I64u %I64u, expected %I64u %I64u\n", count, got[0], got[1], all[2], all[3]);

    /* from the current position, which is that of the next event */
    ret = EvtSeek(query, -1, NULL, 0, EvtSeekRelativeToCurrent);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 2, &error);
    ok(count == 2 && got[0] == all[3] && got[1] == all[4], "got %lu: %I64u %I64u, expected %I64u %I64u\n", count, got[0], got[1], all[3], all[4]);
    ret = EvtSeek(query, 0, NULL, 0, EvtSeekRelativeToCurrent);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 1, &error);
    ok(count == 1 && got[0] == all[5], "got %lu: %I64u, expected %I64u\n", count, got[0], all[5]);
    ret = EvtSeek(query, 1, NULL, 0, EvtSeekRelativeToCurrent);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 1, &error);
    ok(count == 1 && got[0] == all[7], "got %lu: %I64u, expected %I64u\n", count, got[0], all[7]);

    /* from the last: the last event is position 0 */
    ret = EvtSeek(query, -1, NULL, 0, EvtSeekRelativeToLast);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 3, &error);
    ok(count == 2 && got[0] == all[total - 2] && got[1] == all[total - 1], "got %lu: %I64u %I64u\n", count, got[0], got[1]);
    ok(error == ERROR_NO_MORE_ITEMS, "got %lu\n", error);
    ret = EvtSeek(query, 0, NULL, 0, EvtSeekRelativeToLast);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 2, &error);
    ok(count == 1 && got[0] == all[total - 1], "got %lu: %I64u\n", count, got[0]);

    /* positions that are before the first event or behind the last one */
    SetLastError(0xdeadbeef);
    ret = EvtSeek(query, -1, NULL, 0, EvtSeekRelativeToFirst);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    ret = EvtSeek(query, 1, NULL, 0, EvtSeekRelativeToLast);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    ret = EvtSeek(query, -(LONGLONG)total - 5, NULL, 0, EvtSeekRelativeToLast);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    ret = EvtSeek(query, 0, NULL, 0, EvtSeekRelativeToBookmark);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);

    /* from a bookmark: its event is position 0 */
    ret = EvtSeek(query, 3, NULL, 0, EvtSeekRelativeToFirst);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    ret = EvtNext(query, 1, &event, 1000, 0, &n);
    ok(ret, "EvtNext error %lu\n", GetLastError());
    bookmark = EvtCreateBookmark(NULL);
    ok(bookmark != NULL, "EvtCreateBookmark error %lu\n", GetLastError());
    ret = EvtUpdateBookmark(bookmark, event);
    ok(ret, "EvtUpdateBookmark error %lu\n", GetLastError());
    EvtClose(event);
    ret = EvtSeek(query, 1, bookmark, 0, EvtSeekRelativeToBookmark);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 2, &error);
    ok(count == 2 && got[0] == all[4] && got[1] == all[5], "got %lu: %I64u %I64u\n", count, got[0], got[1]);
    ret = EvtSeek(query, -1, bookmark, 0, EvtSeekRelativeToBookmark);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 2, &error);
    ok(count == 2 && got[0] == all[2] && got[1] == all[3], "got %lu: %I64u %I64u\n", count, got[0], got[1]);
    SetLastError(0xdeadbeef);
    ret = EvtSeek(query, 0, bookmark, 0, EvtSeekRelativeToFirst);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);
    EvtClose(bookmark);
    EvtClose(query);

    /* a reverse query counts the same way: the first event is the newest */
    query = EvtQuery(NULL, L"System", L"*", EvtQueryChannelPath | EvtQueryReverseDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    ret = EvtSeek(query, 1, NULL, 0, EvtSeekRelativeToFirst);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 1, &error);
    ok(count == 1 && got[0] == all[total - 2], "got %lu: %I64u\n", count, got[0]);
    ret = EvtSeek(query, 0, NULL, 0, EvtSeekRelativeToLast);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = next_ids(query, got, 2, &error);
    ok(count == 1 && got[0] == all[0], "got %lu: %I64u\n", count, got[0]);
    EvtClose(query);
}

static const WCHAR *source_name = L"Application Error";

/* The security identifier of the user of the process, which an event can carry */
static PSID user_sid(void)
{
    HANDLE token;
    DWORD size = 0;
    TOKEN_USER *user;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    user = HeapAlloc(GetProcessHeap(), 0, size ? size : 1);
    if (!user || !GetTokenInformation(token, TokenUser, user, size, &size)) user = NULL;
    CloseHandle(token);
    return user ? user->User.Sid : NULL;
}

static BOOL write_event_as(const WCHAR *marker, PSID sid)
{
    HANDLE source = RegisterEventSourceW(NULL, source_name);
    BOOL ret;

    if (!source) return FALSE;
    ret = ReportEventW(source, EVENTLOG_INFORMATION_TYPE, 0, 1000, sid, 1, 0, &marker, NULL);
    DeregisterEventSource(source);
    return ret;
}

static BOOL write_event(const WCHAR *marker)
{
    return write_event_as(marker, NULL);
}

/* The events that the subscription gives within the time, until one has the marker in its XML; the record number of it, or 0 */
static ULONGLONG find_marker(EVT_HANDLE subscription, const WCHAR *marker, DWORD timeout, DWORD *seen)
{
    DWORD start = GetTickCount(), n;
    EVT_HANDLE event;
    ULONGLONG id = 0;

    *seen = 0;
    while (!id && GetTickCount() - start < timeout)
    {
        if (!EvtNext(subscription, 1, &event, 500, 0, &n))
        {
            ok(GetLastError() == ERROR_TIMEOUT || GetLastError() == ERROR_NO_MORE_ITEMS, "got %lu\n", GetLastError());
            continue;
        }
        {
            WCHAR xml[4096];
            DWORD size, count;

            (*seen)++;
            if (EvtRender(NULL, event, EvtRenderEventXml, sizeof(xml), xml, &size, &count) && wcsstr(xml, marker)) id = record_id(event);
        }
        EvtClose(event);
    }
    return id;
}

static LONG callback_count;
static WCHAR callback_marker[64];

static DWORD WINAPI subscribe_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event)
{
    WCHAR xml[4096];
    DWORD size, count;

    ok(action == EvtSubscribeActionDeliver, "got %d\n", action);
    ok(context == (PVOID)(ULONG_PTR)0x5678, "got %p\n", context);
    if (EvtRender(NULL, event, EvtRenderEventXml, sizeof(xml), xml, &size, &count) && wcsstr(xml, callback_marker))
        InterlockedIncrement(&callback_count);
    return 0;
}

struct cancel_args
{
    EVT_HANDLE subscription;
    DWORD error;
};

static DWORD WINAPI wait_thread(void *param)
{
    struct cancel_args *args = param;
    EVT_HANDLE event;
    DWORD n;

    SetLastError(0xdeadbeef);
    if (EvtNext(args->subscription, 1, &event, INFINITE, 0, &n)) EvtClose(event);
    args->error = GetLastError();
    return 0;
}

static void test_subscription(void)
{
    WCHAR marker[64], marker2[64];
    HANDLE signal = CreateEventW(NULL, FALSE, FALSE, NULL);
    EVT_HANDLE sub, sub2, bookmark, event;
    ULONGLONG id, id2;
    DWORD seen, n, wait;
    EVT_HANDLE junk[16];
    BOOL ret;
    struct cancel_args args;
    HANDLE thread;

    _snwprintf(marker, ARRAYSIZE(marker), L"wevtapi_apitest_%lu_a", GetTickCount());
    _snwprintf(marker2, ARRAYSIZE(marker2), L"wevtapi_apitest_%lu_b", GetTickCount());

    sub = EvtSubscribe(NULL, signal, L"Application", L"*", NULL, NULL, NULL, EvtSubscribeToFutureEvents);
    ok(sub != NULL, "EvtSubscribe error %lu\n", GetLastError());
    if (!sub) { CloseHandle(signal); return; }

    /* what is in the log is not what a subscription to the future has */
    while (EvtNext(sub, 16, junk, 0, 0, &n))
    {
        while (n--) EvtClose(junk[n]);
    }
    SetLastError(0xdeadbeef);
    ret = EvtNext(sub, 1, &event, 0, 0, &n);
    ok_false_error(ret, ERROR_NO_MORE_ITEMS);
    SetLastError(0xdeadbeef);
    ret = EvtNext(sub, 1, &event, 200, 0, &n);
    ok_false_error(ret, ERROR_TIMEOUT);
    SetLastError(0xdeadbeef);
    ret = EvtSeek(sub, 0, NULL, 0, EvtSeekRelativeToFirst);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);

    ok(write_event(marker), "ReportEvent error %lu\n", GetLastError());
    wait = WaitForSingleObject(signal, 10000);
    ok(wait == WAIT_OBJECT_0, "got %lu\n", wait);
    id = find_marker(sub, marker, 10000, &seen);
    ok(id != 0, "The event was not delivered, %lu events seen\n", seen);

    /* a wait that is cancelled ends with an error */
    args.subscription = sub;
    args.error = 0;
    thread = CreateThread(NULL, 0, wait_thread, &args, 0, NULL);
    Sleep(500);
    ret = EvtCancel(sub);
    ok(ret, "EvtCancel error %lu\n", GetLastError());
    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "got %lu\n", wait);
    ok(args.error == ERROR_OPERATION_ABORTED, "got %lu\n", args.error);
    CloseHandle(thread);

    /* from the oldest record, the subscription has the event that is there already */
    sub2 = EvtSubscribe(NULL, signal, L"Application", L"*", NULL, NULL, NULL, EvtSubscribeStartAtOldestRecord);
    ok(sub2 != NULL, "EvtSubscribe error %lu\n", GetLastError());
    if (sub2)
    {
        id2 = find_marker(sub2, marker, 10000, &seen);
        ok(id2 == id, "got %I64u, expected %I64u\n", id2, id);
        EvtClose(sub2);
    }

    /* behind a bookmark: what came later only */
    bookmark = EvtCreateBookmark(NULL);
    {
        EVT_HANDLE query = EvtQuery(NULL, L"Application", L"*", EvtQueryChannelPath | EvtQueryReverseDirection);

        ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
        ret = EvtNext(query, 1, &event, 1000, 0, &n);
        ok(ret, "EvtNext error %lu\n", GetLastError());
        ok(EvtUpdateBookmark(bookmark, event), "EvtUpdateBookmark error %lu\n", GetLastError());
        EvtClose(event);
        EvtClose(query);
    }
    ok(write_event(marker2), "ReportEvent error %lu\n", GetLastError());
    sub2 = EvtSubscribe(NULL, signal, L"Application", L"*", bookmark, NULL, NULL, EvtSubscribeStartAfterBookmark);
    ok(sub2 != NULL, "EvtSubscribe error %lu\n", GetLastError());
    if (sub2)
    {
        ULONGLONG first = 0;
        EVT_HANDLE e;

        id2 = find_marker(sub2, marker2, 10000, &seen);
        ok(id2 != 0, "The event was not delivered\n");
        EvtClose(sub2);
        /* the event of the bookmark is not delivered again */
        sub2 = EvtSubscribe(NULL, signal, L"Application", L"*", bookmark, NULL, NULL, EvtSubscribeStartAfterBookmark);
        if (sub2 && EvtNext(sub2, 1, &e, 5000, 0, &n))
        {
            first = record_id(e);
            EvtClose(e);
        }
        ok(first > 0 && first >= id, "got %I64u\n", first);
        if (sub2) EvtClose(sub2);
    }
    EvtClose(bookmark);

    /* delivery by a callback */
    _snwprintf(callback_marker, ARRAYSIZE(callback_marker), L"wevtapi_apitest_%lu_c", GetTickCount());
    callback_count = 0;
    sub2 = EvtSubscribe(NULL, NULL, L"Application", L"*", NULL, (PVOID)(ULONG_PTR)0x5678, subscribe_callback, EvtSubscribeToFutureEvents);
    ok(sub2 != NULL, "EvtSubscribe error %lu\n", GetLastError());
    if (sub2)
    {
        DWORD start = GetTickCount();

        SetLastError(0xdeadbeef);
        ret = EvtNext(sub2, 1, &event, 0, 0, &n);
        ok_false_error(ret, ERROR_INVALID_OPERATION);
        ok(write_event(callback_marker), "ReportEvent error %lu\n", GetLastError());
        while (!callback_count && GetTickCount() - start < 10000) Sleep(100);
        ok(callback_count == 1, "got %ld\n", callback_count);
        EvtClose(sub2);
        /* nothing comes after the subscription is closed */
        callback_count = 0;
        ok(write_event(callback_marker), "ReportEvent error %lu\n", GetLastError());
        Sleep(1000);
        ok(callback_count == 0, "got %ld\n", callback_count);
    }

    /* a query on a path that is a file, and a channel that is not there */
    SetLastError(0xdeadbeef);
    sub2 = EvtSubscribe(NULL, signal, L"wevtapi_apitest_no_such_channel", L"*", NULL, NULL, NULL, EvtSubscribeToFutureEvents);
    ok_handle_error(sub2, ERROR_EVT_CHANNEL_NOT_FOUND);

    EvtClose(sub);
    CloseHandle(signal);
}

/* The record numbers and the XML of the events that a query gives, up to max of them */
static DWORD read_all(const WCHAR *path, DWORD flags, const WCHAR *query, ULONGLONG *ids, WCHAR **first_xml, WCHAR **last_xml, DWORD max)
{
    EVT_HANDLE q = EvtQuery(NULL, path, query, flags | EvtQueryForwardDirection), event;
    DWORD count = 0, n, size, props;

    *first_xml = *last_xml = NULL;
    if (!q) return 0;
    while (count < max && EvtNext(q, 1, &event, 2000, 0, &n))
    {
        WCHAR *xml = HeapAlloc(GetProcessHeap(), 0, 16384 * sizeof(WCHAR));

        ids[count] = record_id(event);
        if (xml && EvtRender(NULL, event, EvtRenderEventXml, 16384 * sizeof(WCHAR), xml, &size, &props))
        {
            if (!count) *first_xml = xml;
            else
            {
                if (*last_xml) HeapFree(GetProcessHeap(), 0, *last_xml);
                *last_xml = xml;
            }
            if (count == 0) xml = NULL;
        }
        else if (xml) { HeapFree(GetProcessHeap(), 0, xml); }
        count++;
        EvtClose(event);
    }
    EvtClose(q);
    return count;
}

/* The XML without the record number, which the log has as it was and an exported file keeps */
static BOOL same_event(const WCHAR *a, const WCHAR *b)
{
    return a && b && !wcscmp(a, b);
}

static void test_export(void)
{
    static ULONGLONG ids_a[MAX_IDS], ids_b[MAX_IDS];
    WCHAR dir[MAX_PATH], file[MAX_PATH];
    WCHAR *first_a, *last_a, *first_b, *last_b;
    DWORD count_a, count_b, i;
    BOOL ret;

    GetTempPathW(MAX_PATH, dir);
    wcscpy(file, dir);
    wcscat(file, L"wevtapi_apitest_export.evtx");
    DeleteFileW(file);

    /* enough events to fill a few chunks */
    for (i = 0; i < 400; i++)
    {
        WCHAR text[96];

        _snwprintf(text, ARRAYSIZE(text), L"wevtapi_apitest_export_%lu_<&>_\"'", i);
        write_event(text);
    }
    count_a = read_all(L"Application", EvtQueryChannelPath, L"*", ids_a, &first_a, &last_a, MAX_IDS);
    ok(count_a > 100, "got %lu events\n", count_a);

    ret = EvtExportLog(NULL, L"Application", L"*", file, EvtExportLogChannelPath);
    ok(ret, "EvtExportLog error %lu\n", GetLastError());
    count_b = read_all(file, EvtQueryFilePath, L"*", ids_b, &first_b, &last_b, MAX_IDS);
    ok(count_b == count_a, "got %lu events in the file, %lu in the log\n", count_b, count_a);
    for (i = 0; i < count_a && i < count_b; i++)
        if (ids_a[i] != ids_b[i]) break;
    /* the events are those of the log, in its order, with the XML that it has */
    ok(i == count_a, "the record %lu of the file is %I64u, of the log %I64u\n", i, i < count_b ? ids_b[i] : 0, i < count_a ? ids_a[i] : 0);
    ok(same_event(first_a, first_b), "the first event differs:\n%S\n%S\n", first_a ? first_a : L"(null)", first_b ? first_b : L"(null)");
    ok(same_event(last_a, last_b), "the last event differs:\n%S\n%S\n", last_a ? last_a : L"(null)", last_b ? last_b : L"(null)");
    if (first_a) HeapFree(GetProcessHeap(), 0, first_a);
    if (last_a) HeapFree(GetProcessHeap(), 0, last_a);
    if (first_b) HeapFree(GetProcessHeap(), 0, first_b);
    if (last_b) HeapFree(GetProcessHeap(), 0, last_b);

    /* the information that the log of the file gives */
    {
        EVT_HANDLE log = EvtOpenLog(NULL, file, EvtOpenFilePath);
        EVT_VARIANT value;
        DWORD size;

        ok(log != NULL, "EvtOpenLog error %lu\n", GetLastError());
        if (log)
        {
            ret = EvtGetLogInfo(log, EvtLogNumberOfLogRecords, sizeof(value), &value, &size);
            ok(ret && value.Type == EvtVarTypeUInt64 && value.UInt64Val == count_b, "got %d, %lu, %I64u, expected %lu\n", ret, value.Type, value.UInt64Val, count_b);
            ret = EvtGetLogInfo(log, EvtLogFileSize, sizeof(value), &value, &size);
            ok(ret && value.Type == EvtVarTypeUInt64 && value.UInt64Val >= 4096 + 65536, "got %d, %I64u\n", ret, value.UInt64Val);
            ret = EvtGetLogInfo(log, EvtLogLastWriteTime, sizeof(value), &value, &size);
            ok(ret && value.Type == EvtVarTypeFileTime && value.FileTimeVal != 0, "got %d, %lu\n", ret, value.Type);
            EvtClose(log);
        }
    }

    /* a file that is there is not written over unless it is asked for */
    SetLastError(0xdeadbeef);
    ret = EvtExportLog(NULL, L"Application", L"*", file, EvtExportLogChannelPath);
    ok_false_error(ret, ERROR_ALREADY_EXISTS);
    ret = EvtExportLog(NULL, L"Application", L"*[System[EventID=1000]]", file, EvtExportLogChannelPath | EvtExportLogOverwrite);
    ok(ret, "EvtExportLog error %lu\n", GetLastError());
    count_b = read_all(file, EvtQueryFilePath, L"*", ids_b, &first_b, &last_b, MAX_IDS);
    ok(count_b > 100 && count_b <= count_a + 5, "got %lu events in the file\n", count_b);
    if (first_b) HeapFree(GetProcessHeap(), 0, first_b);
    if (last_b) HeapFree(GetProcessHeap(), 0, last_b);

    /* an export of an export, and of a file that is not there */
    wcscpy(dir + wcslen(dir), L"wevtapi_apitest_export2.evtx");
    DeleteFileW(dir);
    ret = EvtExportLog(NULL, file, L"*", dir, EvtExportLogFilePath);
    ok(ret, "EvtExportLog error %lu\n", GetLastError());
    count_a = read_all(dir, EvtQueryFilePath, L"*", ids_a, &first_a, &last_a, MAX_IDS);
    ok(count_a == count_b, "got %lu, %lu\n", count_a, count_b);
    if (first_a) HeapFree(GetProcessHeap(), 0, first_a);
    if (last_a) HeapFree(GetProcessHeap(), 0, last_a);
    DeleteFileW(dir);
    SetLastError(0xdeadbeef);
    ret = EvtExportLog(NULL, L"Application", L"*", L"C:\\wevtapi_apitest_no_such_dir\\x.evtx", EvtExportLogChannelPath);
    ok(!ret && (GetLastError() == ERROR_PATH_NOT_FOUND || GetLastError() == ERROR_FILE_NOT_FOUND), "got %d, %lu\n", ret, GetLastError());
    SetLastError(0xdeadbeef);
    ret = EvtExportLog(NULL, L"Application", L"*", file, EvtExportLogChannelPath | 0x4000);
    ok_false_error(ret, ERROR_INVALID_PARAMETER);
    DeleteFileW(file);
}

static void test_clear_log(void)
{
    static ULONGLONG ids[MAX_IDS];
    WCHAR backup[MAX_PATH];
    WCHAR *first, *last;
    DWORD n, before, after;
    BOOL ret;

    ok(write_event(L"wevtapi_apitest_clear"), "ReportEvent error %lu\n", GetLastError());
    GetTempPathW(MAX_PATH, backup);
    wcscat(backup, L"wevtapi_apitest_backup.evtx");
    DeleteFileW(backup);
    before = read_all(L"Application", EvtQueryChannelPath, L"*", ids, &first, &last, MAX_IDS);
    if (first) HeapFree(GetProcessHeap(), 0, first);
    if (last) HeapFree(GetProcessHeap(), 0, last);
    ok(before > 0, "got %lu\n", before);

    /* the log is copied first; a copy that cannot be made leaves the log as it is */
    SetLastError(0xdeadbeef);
    ret = EvtClearLog(NULL, L"Application", L"C:\\wevtapi_apitest_no_such_dir\\x.evtx", 0);
    ok(!ret && (GetLastError() == ERROR_PATH_NOT_FOUND || GetLastError() == ERROR_FILE_NOT_FOUND), "got %d, %lu\n", ret, GetLastError());
    after = read_all(L"Application", EvtQueryChannelPath, L"*", ids, &first, &last, MAX_IDS);
    if (first) HeapFree(GetProcessHeap(), 0, first);
    if (last) HeapFree(GetProcessHeap(), 0, last);
    ok(after >= before, "got %lu events after a clear that failed, %lu before\n", after, before);

    ret = EvtClearLog(NULL, L"Application", backup, 0);
    ok(ret, "EvtClearLog error %lu\n", GetLastError());
    n = read_all(backup, EvtQueryFilePath, L"*", ids, &first, &last, MAX_IDS);
    ok(n >= before, "got %lu events in the backup, %lu before\n", n, before);
    if (first) HeapFree(GetProcessHeap(), 0, first);
    if (last) HeapFree(GetProcessHeap(), 0, last);
    after = read_all(L"Application", EvtQueryChannelPath, L"*", ids, &first, &last, MAX_IDS);
    if (first) HeapFree(GetProcessHeap(), 0, first);
    if (last) HeapFree(GetProcessHeap(), 0, last);
    /* the log may say that it was cleared */
    ok(after <= 1, "got %lu events in the log that was cleared\n", after);
    DeleteFileW(backup);

    ret = EvtClearLog(NULL, L"Application", NULL, 0);
    ok(ret, "EvtClearLog error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = EvtClearLog(NULL, L"wevtapi_apitest_no_such_channel", NULL, 0);
    ok_false_error(ret, ERROR_EVT_CHANNEL_NOT_FOUND);
    SetLastError(0xdeadbeef);
    ret = EvtArchiveExportedLog(NULL, L"C:\\wevtapi_apitest_no_such_dir\\x.evtx", 0, 0);
    ok(!ret, "got %d\n", ret);
}

/*
 * A manifest that these tests make up (testmanifest.dat, in the DLL wevtapi_testmanifest.dll that stands
 * next to the test program): the publisher wevtapi-apitest-synthetic with two channels, three levels, two
 * tasks, two opcodes, two keywords and five events.
 */
static const WCHAR synth_key[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{c2f0a1e0-7f3b-4b4e-9f2a-5d7e1d2f0a12}";
static const WCHAR synth_name[] = L"wevtapi-apitest-synthetic";

/* The path of the test DLL, and whether it is there */
static BOOL synth_path(WCHAR *path)
{
    WCHAR *p;

    GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!(p = wcsrchr(path, '\\'))) return FALSE;
    wcscpy(p + 1, L"wevtapi_testmanifest.dll");
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

/* Registers the publisher as an installed manifest does; the file is the resource file */
static BOOL synth_register(const WCHAR *file, HKEY *key)
{
    static const WCHAR *channels[] = { L"WevtapiTest/Operational", L"WevtapiTest/Debug" };
    HKEY refs, ref;
    DWORD i, id, count = ARRAYSIZE(channels);
    WCHAR index[8];

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, synth_key, 0, NULL, 0, KEY_WRITE, NULL, key, NULL)) return FALSE;
    RegSetValueExW(*key, NULL, 0, REG_SZ, (const BYTE *)synth_name, sizeof(synth_name));
    RegSetValueExW(*key, L"ResourceFileName", 0, REG_SZ, (const BYTE *)file, (wcslen(file) + 1) * sizeof(WCHAR));
    RegSetValueExW(*key, L"MessageFileName", 0, REG_SZ, (const BYTE *)file, (wcslen(file) + 1) * sizeof(WCHAR));
    if (RegCreateKeyExW(*key, L"ChannelReferences", 0, NULL, 0, KEY_WRITE, NULL, &refs, NULL)) return TRUE;
    RegSetValueExW(refs, L"Count", 0, REG_DWORD, (const BYTE *)&count, sizeof(count));
    for (i = 0; i < count; i++)
    {
        _snwprintf(index, ARRAYSIZE(index), L"%lu", i);
        if (RegCreateKeyExW(refs, index, 0, NULL, 0, KEY_WRITE, NULL, &ref, NULL)) continue;
        RegSetValueExW(ref, NULL, 0, REG_SZ, (const BYTE *)channels[i], (wcslen(channels[i]) + 1) * sizeof(WCHAR));
        id = 16 + i;
        RegSetValueExW(ref, L"Id", 0, REG_DWORD, (const BYTE *)&id, sizeof(id));
        id = 0;
        RegSetValueExW(ref, L"Flags", 0, REG_DWORD, (const BYTE *)&id, sizeof(id));
        RegCloseKey(ref);
    }
    RegCloseKey(refs);
    return TRUE;
}

static void synth_unregister(HKEY key)
{
    WCHAR path[256];

    RegCloseKey(key);
    _snwprintf(path, ARRAYSIZE(path), L"%ls\\ChannelReferences\\0", synth_key);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, path);
    _snwprintf(path, ARRAYSIZE(path), L"%ls\\ChannelReferences\\1", synth_key);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, path);
    _snwprintf(path, ARRAYSIZE(path), L"%ls\\ChannelReferences", synth_key);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, path);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, synth_key);
}

/* What the metadata of the made-up publisher says: its levels, tasks, opcodes and keywords, its channels and its events */
static void test_manifest_arrays(void)
{
    static const WCHAR *template_100 =
        L"<template xmlns=\"http://schemas.microsoft.com/win/2004/08/events\">\r\n"
        L"  <data name=\"Name\" inType=\"win:UnicodeString\" outType=\"xs:string\"/>\r\n"
        L"  <data name=\"Count\" inType=\"win:UInt32\" outType=\"xs:unsignedInt\"/>\r\n"
        L"</template>\r\n";
    static const WCHAR *template_101 = L"<template xmlns=\"http://schemas.microsoft.com/win/2004/08/events\">\r\n</template>\r\n";
    static const struct { DWORD id, count; } arrays[] =
    {
        { EvtPublisherMetadataChannelReferences, 2 }, { EvtPublisherMetadataLevels, 3 }, { EvtPublisherMetadataTasks, 2 },
        { EvtPublisherMetadataOpcodes, 2 }, { EvtPublisherMetadataKeywords, 2 },
    };
    static const GUID guid = {0xc2f0a1e0, 0x7f3b, 0x4b4e, {0x9f, 0x2a, 0x5d, 0x7e, 0x1d, 0x2f, 0x0a, 0x12}};
    struct { EVT_VARIANT var; WCHAR buf[2048]; } data;
    EVT_HANDLE meta, array, events, event;
    WCHAR path[MAX_PATH];
    DWORD size, count, i, n = 0;
    BOOL ret;
    HKEY key;

    if (!synth_path(path))
    {
        skip("wevtapi_testmanifest.dll is not there\n");
        return;
    }
    if (!synth_register(path, &key))
    {
        skip("Cannot register a publisher\n");
        return;
    }
    meta = EvtOpenPublisherMetadata(NULL, synth_name, NULL, 0, 0);
    ok(meta != NULL, "EvtOpenPublisherMetadata error %lu\n", GetLastError());
    if (!meta) goto done;

    memset(&data, 0, sizeof(data));
    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataPublisherGuid, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeGuid && !memcmp(data.var.GuidVal, &guid, sizeof(guid)), "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataResourceFilePath, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeString && !_wcsicmp(data.var.StringVal, path), "got %d, %lu\n", ret, data.var.Type);

    for (i = 0; i < ARRAYSIZE(arrays); i++)
    {
        memset(&data, 0, sizeof(data));
        ret = EvtGetPublisherMetadataProperty(meta, arrays[i].id, 0, sizeof(data), &data.var, &size);
        ok(ret && data.var.Type == EvtVarTypeEvtHandle, "got %d, %lu\n", ret, GetLastError());
        if (!ret) continue;
        array = data.var.EvtHandleVal;
        ret = EvtGetObjectArraySize(array, &count);
        ok(ret && count == arrays[i].count, "property %lu: got %d, %lu\n", arrays[i].id, ret, count);
        SetLastError(0xdeadbeef);
        ret = EvtGetObjectArrayProperty(array, arrays[i].id + 1, count, 0, sizeof(data), &data.var, &size);
        ok_false_error(ret, ERROR_NO_MORE_ITEMS);
        EvtClose(array);
    }

    /* names and values: an opcode is the high word of its value */
    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataOpcodes, 0, sizeof(data), &data.var, &size);
    ok(ret, "EvtGetPublisherMetadataProperty error %lu\n", GetLastError());
    array = data.var.EvtHandleVal;
    ret = EvtGetObjectArrayProperty(array, EvtPublisherMetadataOpcodeName, 1, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeString && !wcscmp(data.var.StringVal, L"Stop"), "got %d\n", ret);
    ret = EvtGetObjectArrayProperty(array, EvtPublisherMetadataOpcodeValue, 1, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeUInt32 && data.var.UInt32Val == (2 << 16), "got %d, %lx\n", ret, data.var.UInt32Val);
    EvtClose(array);

    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataKeywords, 0, sizeof(data), &data.var, &size);
    ok(ret, "EvtGetPublisherMetadataProperty error %lu\n", GetLastError());
    array = data.var.EvtHandleVal;
    ret = EvtGetObjectArrayProperty(array, EvtPublisherMetadataKeywordValue, 1, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeUInt64 && data.var.UInt64Val == 0x200000000ULL, "got %d, %I64x\n", ret, data.var.UInt64Val);
    EvtClose(array);

    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataChannelReferences, 0, sizeof(data), &data.var, &size);
    ok(ret, "EvtGetPublisherMetadataProperty error %lu\n", GetLastError());
    array = data.var.EvtHandleVal;
    ret = EvtGetObjectArrayProperty(array, EvtPublisherMetadataChannelReferencePath, 1, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeString && !wcscmp(data.var.StringVal, L"WevtapiTest/Debug"), "got %d\n", ret);
    ret = EvtGetObjectArrayProperty(array, EvtPublisherMetadataChannelReferenceID, 1, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeUInt32 && data.var.UInt32Val == 17, "got %d, %lu\n", ret, data.var.UInt32Val);
    EvtClose(array);

    /* the events, with the data of their templates */
    events = EvtOpenEventMetadataEnum(meta, 0);
    ok(events != NULL, "EvtOpenEventMetadataEnum error %lu\n", GetLastError());
    while (events && (event = EvtNextEventMetadata(events, 0)))
    {
        DWORD id, version;

        memset(&data, 0, sizeof(data));
        ret = EvtGetEventMetadataProperty(event, EventMetadataEventID, 0, sizeof(data), &data.var, &size);
        ok(ret && data.var.Type == EvtVarTypeUInt32, "got %d, %lu\n", ret, data.var.Type);
        id = data.var.UInt32Val;
        ret = EvtGetEventMetadataProperty(event, EventMetadataEventVersion, 0, sizeof(data), &data.var, &size);
        ok(ret && data.var.Type == EvtVarTypeUInt32, "got %d, %lu\n", ret, data.var.Type);
        version = data.var.UInt32Val;
        ret = EvtGetEventMetadataProperty(event, EventMetadataEventKeyword, 0, sizeof(data), &data.var, &size);
        ok(ret && data.var.Type == EvtVarTypeUInt64, "got %d, %lu\n", ret, data.var.Type);
        ret = EvtGetEventMetadataProperty(event, EventMetadataEventTemplate, 0, sizeof(data), &data.var, &size);
        ok(ret, "EvtGetEventMetadataProperty error %lu\n", GetLastError());
        if (id == 100 && version == 0)
            ok(data.var.Type == EvtVarTypeString && !wcscmp(data.var.StringVal, template_100), "got %lu\n", data.var.Type);
        else if (id == 101)
            ok(data.var.Type == EvtVarTypeString && !wcscmp(data.var.StringVal, template_101), "got %lu\n", data.var.Type);
        else if (id == 102)
            ok(data.var.Type == EvtVarTypeNull, "got %lu\n", data.var.Type);
        if (id == 100 && version == 0)
        {
            ret = EvtGetEventMetadataProperty(event, EventMetadataEventChannel, 0, sizeof(data), &data.var, &size);
            ok(ret && data.var.Type == EvtVarTypeUInt32 && data.var.UInt32Val == 16, "got %d, %lu\n", ret, data.var.UInt32Val);
            ret = EvtGetEventMetadataProperty(event, EventMetadataEventLevel, 0, sizeof(data), &data.var, &size);
            ok(ret && data.var.UInt32Val == 4, "got %d, %lu\n", ret, data.var.UInt32Val);
            ret = EvtGetEventMetadataProperty(event, EventMetadataEventOpcode, 0, sizeof(data), &data.var, &size);
            ok(ret && data.var.UInt32Val == 1, "got %d, %lu\n", ret, data.var.UInt32Val);
            ret = EvtGetEventMetadataProperty(event, EventMetadataEventTask, 0, sizeof(data), &data.var, &size);
            ok(ret && data.var.UInt32Val == 1, "got %d, %lu\n", ret, data.var.UInt32Val);
        }
        SetLastError(0xdeadbeef);
        ret = EvtGetEventMetadataProperty(event, EvtEventMetadataPropertyIdEND, 0, sizeof(data), &data.var, &size);
        ok_false_error(ret, ERROR_INVALID_PARAMETER);
        n++;
        EvtClose(event);
    }
    ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got %lu\n", GetLastError());
    ok(n == 5, "got %lu events\n", n);
    if (events) EvtClose(events);

    SetLastError(0xdeadbeef);
    array = EvtOpenEventMetadataEnum((EVT_HANDLE)(ULONG_PTR)0x1234, 0);
    ok(!array && GetLastError() == ERROR_INVALID_HANDLE, "got %p, %lu\n", array, GetLastError());
    SetLastError(0xdeadbeef);
    array = EvtOpenEventMetadataEnum(meta, 1);
    ok(!array && GetLastError() == ERROR_INVALID_PARAMETER, "got %p, %lu\n", array, GetLastError());
    EvtClose(meta);

done:
    synth_unregister(key);

    /* a classic source has no events */
    meta = EvtOpenPublisherMetadata(NULL, L"Application Error", NULL, 0, 0);
    if (meta)
    {
        array = EvtOpenEventMetadataEnum(meta, 0);
        ok(array != NULL, "EvtOpenEventMetadataEnum error %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        ok(EvtNextEventMetadata(array, 0) == NULL && GetLastError() == ERROR_NO_MORE_ITEMS, "got %lu\n", GetLastError());
        EvtClose(array);
        EvtClose(meta);
    }
}

static void write_file(const WCHAR *path, const BYTE *data, DWORD size)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;

    if (file == INVALID_HANDLE_VALUE) return;
    WriteFile(file, data, size, &written, NULL);
    CloseHandle(file);
}

static ULONG random_seed = 0x1234567;

static ULONG next_random(void)
{
    random_seed = random_seed * 1103515245 + 12345;
    return (random_seed >> 8) & 0xffffff;
}

/* The resource is a program's to install: whatever it holds, reading the metadata must end, with no crash */
static void test_manifest_robustness(void)
{
    static const WCHAR key_path[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{c2f0a1e0-7f3b-4b4e-9f2a-5d7e1d2f0a11}";
    WCHAR source[MAX_PATH], temp[MAX_PATH], copy[MAX_PATH];
    HANDLE file;
    DWORD size, read, round, rounds = 600, i, crim = 0, damaged = 0, opened = 0;
    BYTE *data, *orig;
    HKEY key;

    if (!synth_path(source) || (file = CreateFileW(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
    {
        skip("wevtapi_testmanifest.dll is not there\n");
        return;
    }
    size = GetFileSize(file, NULL);
    orig = HeapAlloc(GetProcessHeap(), 0, size);
    data = HeapAlloc(GetProcessHeap(), 0, size);
    ReadFile(file, orig, size, &read, NULL);
    CloseHandle(file);
    memcpy(data, orig, size);
    for (i = 0; i + 4 < size; i++)
        if (!memcmp(data + i, "CRIM", 4)) { crim = i; break; }
    ok(crim != 0, "no metadata resource in the file\n");
    if (!crim)
    {
        HeapFree(GetProcessHeap(), 0, data);
        HeapFree(GetProcessHeap(), 0, orig);
        return;
    }
    GetTempPathW(MAX_PATH, temp);
    wcscat(temp, L"wevtapi_apitest_manifest.dll");

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key_path, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL))
    {
        skip("Cannot register a publisher\n");
        HeapFree(GetProcessHeap(), 0, orig);
        HeapFree(GetProcessHeap(), 0, data);
        return;
    }
    RegSetValueExW(key, NULL, 0, REG_SZ, (const BYTE *)L"wevtapi_apitest_manifest", sizeof(L"wevtapi_apitest_manifest"));

    {
        WCHAR env[16];

        if (GetEnvironmentVariableW(L"WEVTAPI_FUZZ_ROUNDS", env, ARRAYSIZE(env)) && _wtol(env) > 0) rounds = _wtol(env);
    }
    for (round = 0; round < rounds; round++)
    {
        EVT_HANDLE meta, array, events, event;
        static const DWORD arrays[] = { EvtPublisherMetadataChannelReferences, EvtPublisherMetadataLevels, EvtPublisherMetadataTasks,
                                        EvtPublisherMetadataOpcodes, EvtPublisherMetadataKeywords };
        struct { EVT_VARIANT var; WCHAR buf[2048]; } v;
        DWORD changes = 1 + next_random() % 8, n, j, k;

        wcscpy(copy, temp);
        memcpy(copy + wcslen(copy) - 4, L".dll", 10);
        /* the changes go into the first part of the metadata, where the headers and the tables are, and anywhere in it */
        for (j = 0; j < changes; j++)
        {
            DWORD span = round % 2 ? 2048 : 27000;
            DWORD at = crim + next_random() % (size - crim < span ? size - crim : span);
            static const BYTE values[] = { 0x00, 0xff, 0x7f, 0x80, 0x01 };

            data[at] = (next_random() % 3) ? values[next_random() % ARRAYSIZE(values)] : (BYTE)next_random();
            damaged++;
        }
        write_file(temp, data, size);
        RegSetValueExW(key, L"ResourceFileName", 0, REG_SZ, (const BYTE *)temp, (wcslen(temp) + 1) * sizeof(WCHAR));
        meta = EvtOpenPublisherMetadata(NULL, L"wevtapi_apitest_manifest", NULL, 0, 0);
        if (meta)
        {
            opened++;
            for (k = 0; k < ARRAYSIZE(arrays); k++)
            {
                if (!EvtGetPublisherMetadataProperty(meta, arrays[k], 0, sizeof(v), &v.var, &n)) continue;
                array = v.var.EvtHandleVal;
                if (EvtGetObjectArraySize(array, &n))
                    for (j = 0; j < n && j < 40; j++)
                        EvtGetObjectArrayProperty(array, arrays[k] + 1, j, 0, sizeof(v), &v.var, &read);
                EvtClose(array);
            }
            events = EvtOpenEventMetadataEnum(meta, 0);
            while (events && (event = EvtNextEventMetadata(events, 0)))
            {
                for (k = 0; k < EvtEventMetadataPropertyIdEND; k++)
                    EvtGetEventMetadataProperty(event, k, 0, sizeof(v), &v.var, &n);
                EvtClose(event);
            }
            if (events) EvtClose(events);
            EvtClose(meta);
        }
        /* the file is back as it was, for the next round to change it again */
        memcpy(data, orig, size);
    }
    ok(opened > 0, "no damaged resource could be opened\n");
    RegCloseKey(key);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key_path);
    DeleteFileW(temp);
    HeapFree(GetProcessHeap(), 0, orig);
    HeapFree(GetProcessHeap(), 0, data);
    trace("%lu changes in %lu files, %lu opened\n", damaged, rounds, opened);
}

/* How many records ReadEventLog gives, forwards or backwards */
static DWORD raw_count(BOOL backwards)
{
    HANDLE log = OpenEventLogW(NULL, L"Application");
    BYTE *buffer = HeapAlloc(GetProcessHeap(), 0, 64 * 1024);
    DWORD read, needed, count = 0, pos;

    if (!log) return 0;
    for (;;)
    {
        EVENTLOGRECORD *rec;

        SetLastError(0xdeadbeef);
        if (!ReadEventLogW(log, EVENTLOG_SEQUENTIAL_READ | (backwards ? EVENTLOG_BACKWARDS_READ : EVENTLOG_FORWARDS_READ), 0, buffer, 64 * 1024, &read, &needed))
        {
            break;
        }
        for (pos = 0; pos < read; pos += rec->Length)
        {
            rec = (EVENTLOGRECORD *)(buffer + pos);
            count++;
        }
    }
    CloseEventLog(log);
    HeapFree(GetProcessHeap(), 0, buffer);
    return count;
}

static void test_small_log(void)
{
    static ULONGLONG ids[MAX_IDS];
    WCHAR *first, *last;
    DWORD n, forward, backward;

    /* a log that was cleared holds only the records that come after: the records that it held do not show again */
    for (n = 1; n <= 3; n++)
    {
        WCHAR text[64];

        _snwprintf(text, ARRAYSIZE(text), L"wevtapi_apitest_before_%lu", n);
        ok(write_event(text), "ReportEvent error %lu\n", GetLastError());
    }
    ok(EvtClearLog(NULL, L"Application", NULL, 0), "EvtClearLog error %lu\n", GetLastError());
    ok(raw_count(FALSE) == raw_count(TRUE), "ReadEventLog gives %lu forwards, %lu backwards in a log that was cleared\n", raw_count(FALSE), raw_count(TRUE));
    for (n = 1; n <= 5; n++)
    {
        WCHAR text[64];

        _snwprintf(text, ARRAYSIZE(text), L"wevtapi_apitest_small_%lu", n);
        /* the events that a program writes with its user's identifier are read in both directions as well */
        ok(write_event_as(text, n % 2 ? user_sid() : NULL), "ReportEvent error %lu\n", GetLastError());
        Sleep(300);
        forward = read_all(L"Application", EvtQueryChannelPath, L"*", ids, &first, &last, MAX_IDS);
        if (first) HeapFree(GetProcessHeap(), 0, first);
        if (last) HeapFree(GetProcessHeap(), 0, last);
        backward = raw_count(TRUE);
        ok(forward >= n && forward <= n + 1, "after %lu events a forward query gives %lu\n", n, forward);
        ok(backward >= n && backward <= n + 1, "after %lu events ReadEventLog backwards gives %lu\n", n, backward);
        ok(raw_count(FALSE) == backward, "after %lu events ReadEventLog forwards gives %lu, backwards %lu\n", n, raw_count(FALSE), backward);
    }
}

void test_functional(void)
{
    test_small_log();
    test_seek();
    test_subscription();
    test_manifest_arrays();
    test_manifest_robustness();
    test_export();
    test_clear_log();
    test_small_log();
}
