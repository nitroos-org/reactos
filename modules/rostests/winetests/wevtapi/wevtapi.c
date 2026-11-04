/*
 * Copyright 2021 Dmitry Timoshkov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winevt.h"
#include "wine/test.h"
#include "evtx_sample.h"

static const WCHAR help_prefix[] = L"https://go.microsoft.com/fwlink/events.asp?CoName=";

static void test_EvtGetChannelConfigProperty(void)
{
    HKEY key;
    EVT_HANDLE config;
    DWORD size, ret;
    struct
    {
        EVT_VARIANT var;
        WCHAR buf[MAX_PATH];
    } path;

    ret = RegCreateKeyW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\EventLog\\Winetest", &key);
    if (ret == ERROR_ACCESS_DENIED)
    {
        skip("Not enough privileges to modify HKLM\n");
        return;
    }
    ok(ret == ERROR_SUCCESS, "RegCreateKey error %lu\n", ret);

    config = EvtOpenChannelConfig(NULL, L"Winetest", 0);
    ok(config != NULL, "EvtOpenChannelConfig error %lu\n", GetLastError());

    ret = EvtGetChannelConfigProperty(config, EvtChannelLoggingConfigLogFilePath, 0, 0, NULL, &size);
    ok(!ret, "EvtGetChannelConfigProperty should fail\n");
    ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got %lu\n", GetLastError());
    ok(size < sizeof(path), "got %lu\n", size);

    memset(&path, 0, sizeof(path));
    path.var.Count = 0xdeadbeef;
    path.var.Type = 0xdeadbeef;
    ret = EvtGetChannelConfigProperty(config, EvtChannelLoggingConfigLogFilePath, 0, size, (EVT_VARIANT *)&path, &size);
    ok(ret, "EvtGetChannelConfigProperty error %lu\n", GetLastError());
    ok(path.var.Count == 0xdeadbeef, "got %lu\n", path.var.Count);
    ok(path.var.Type == EvtVarTypeString, "got %lu\n", path.var.Type);
    ok(size == sizeof(EVT_VARIANT) + (wcslen(path.var.StringVal) + 1) * sizeof(WCHAR), "got %lu\n", size);
    ok(path.var.StringVal == path.buf, "path.var.StringVal = %p, path.buf = %p\n", path.var.StringVal, path.buf);

    EvtClose(config);

    RegDeleteKeyW(key, L"");
    RegCloseKey(key);
}

static BOOL render_xml(EVT_HANDLE event, WCHAR **xml)
{
    DWORD size = 0, count, error;
    BOOL ret;

    *xml = NULL;
    SetLastError(0xdeadbeef);
    ret = EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &size, &count);
    error = GetLastError();
    ok(!ret, "EvtRender should fail\n");
    ok(error == ERROR_INSUFFICIENT_BUFFER, "got %lu\n", error);
    if (error != ERROR_INSUFFICIENT_BUFFER) return FALSE;
    ok(size >= sizeof(WCHAR) && !(size % sizeof(WCHAR)), "got %lu\n", size);

    *xml = HeapAlloc(GetProcessHeap(), 0, size);
    ret = EvtRender(NULL, event, EvtRenderEventXml, size, *xml, &size, &count);
    ok(ret, "EvtRender error %lu\n", GetLastError());
    ok(size == (wcslen(*xml) + 1) * sizeof(WCHAR), "got %lu for %lu characters\n", size, (DWORD)wcslen(*xml));
    return ret;
}

static void test_query_and_render(void)
{
    static const WCHAR *provider_path[] = { L"Event/System/Provider/@Name" };
    static const WCHAR *no_such_event = L"*[System[Level=99]]";
    EVT_HANDLE query, forward, event = NULL, event2, context;
    EVT_VARIANT *values;
    DWORD count, size, error, id, level, i;
    ULONGLONG newest, oldest;
    WCHAR *xml, *filter, name[256];
    BOOL ret;
    struct { EVT_VARIANT var; WCHAR buf[256]; } info;

    SetLastError(0xdeadbeef);
    query = EvtQuery(NULL, L"System", L"*[System[bogus", EvtQueryChannelPath);
    error = GetLastError();
    ok(!query, "EvtQuery should fail\n");
    ok(error == ERROR_EVT_INVALID_QUERY, "got %lu\n", error);

    SetLastError(0xdeadbeef);
    query = EvtQuery(NULL, L"wevtapi_winetest_no_such_log", NULL, EvtQueryChannelPath);
    ok(!query, "EvtQuery should fail\n");
    ok(GetLastError() == ERROR_EVT_CHANNEL_NOT_FOUND, "got %lu\n", GetLastError());

    query = EvtQuery(NULL, L"System", L"*", EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query)
    {
        skip("Cannot query the System log, error %lu\n", GetLastError());
        return;
    }

    /* the name of the log */
    memset(&info, 0, sizeof(info));
    ret = EvtGetQueryInfo(query, EvtQueryNames, sizeof(info), &info.var, &size);
    ok(ret, "EvtGetQueryInfo error %lu\n", GetLastError());
    ok(info.var.Type == (EvtVarTypeString | EVT_VARIANT_TYPE_ARRAY), "got %lu\n", info.var.Type);
    ok(info.var.Count == 1, "got %lu\n", info.var.Count);
    ok(info.var.StringArr && !_wcsicmp(info.var.StringArr[0], L"System"), "got %s\n",
       wine_dbgstr_w(info.var.StringArr ? info.var.StringArr[0] : NULL));

    SetLastError(0xdeadbeef);
    ret = EvtNext(query, 1, &event, 1000, 0, &count);
    if (!ret)
    {
        ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got %lu\n", GetLastError());
        skip("The System log has no event\n");
        EvtClose(query);
        return;
    }
    ok(count == 1, "got %lu\n", count);

    ret = render_xml(event, &xml);
    if (ret)
    {
        static const WCHAR prefix[] = L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='";

        ok(!wcsncmp(xml, prefix, ARRAY_SIZE(prefix) - 1), "got %s\n", wine_dbgstr_w(xml));
        ok(wcsstr(xml, L"<Channel>System</Channel>") != NULL, "got %s\n", wine_dbgstr_w(xml));
        ok(wcsstr(xml, L"<TimeCreated SystemTime='") != NULL, "got %s\n", wine_dbgstr_w(xml));
        ok(wcsstr(xml, L"</System>") != NULL, "got %s\n", wine_dbgstr_w(xml));
    }
    HeapFree(GetProcessHeap(), 0, xml);

    /* the system properties */
    context = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    ok(context != NULL, "EvtCreateRenderContext error %lu\n", GetLastError());
    size = 0;
    SetLastError(0xdeadbeef);
    ret = EvtRender(context, event, EvtRenderEventValues, 0, NULL, &size, &count);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got %d, %lu\n", ret, GetLastError());
    ok(count == EvtSystemPropertyIdEND, "got %lu\n", count);
    values = HeapAlloc(GetProcessHeap(), 0, size);
    ret = EvtRender(context, event, EvtRenderEventValues, size, values, &size, &count);
    ok(ret, "EvtRender error %lu\n", GetLastError());
    id = level = 0;
    newest = 0;
    if (ret && count == EvtSystemPropertyIdEND)
    {
        ok(values[EvtSystemProviderName].Type == EvtVarTypeString, "got %lu\n", values[EvtSystemProviderName].Type);
        ok(values[EvtSystemEventID].Type == EvtVarTypeUInt16, "got %lu\n", values[EvtSystemEventID].Type);
        ok(values[EvtSystemLevel].Type == EvtVarTypeByte || values[EvtSystemLevel].Type == EvtVarTypeNull, "got %lu\n",
           values[EvtSystemLevel].Type);
        ok(values[EvtSystemKeywords].Type == EvtVarTypeHexInt64, "got %lu\n", values[EvtSystemKeywords].Type);
        ok(values[EvtSystemTimeCreated].Type == EvtVarTypeFileTime, "got %lu\n", values[EvtSystemTimeCreated].Type);
        ok(values[EvtSystemTimeCreated].FileTimeVal != 0, "no time\n");
        ok(values[EvtSystemEventRecordId].Type == EvtVarTypeUInt64, "got %lu\n", values[EvtSystemEventRecordId].Type);
        ok(values[EvtSystemChannel].Type == EvtVarTypeString && !_wcsicmp(values[EvtSystemChannel].StringVal, L"System"),
           "got %lu\n", values[EvtSystemChannel].Type);
        ok(values[EvtSystemComputer].Type == EvtVarTypeString, "got %lu\n", values[EvtSystemComputer].Type);
        id = values[EvtSystemEventID].UInt16Val;
        level = values[EvtSystemLevel].Type == EvtVarTypeByte ? values[EvtSystemLevel].ByteVal : 0;
        newest = values[EvtSystemEventRecordId].UInt64Val;
    }
    HeapFree(GetProcessHeap(), 0, values);
    EvtClose(context);

    /* the text of the message is for the provider of the event to give */
    if (level >= 1 && level <= 5)
    {
        EVT_HANDLE meta;
        WCHAR provider[256];

        context = EvtCreateRenderContext(1, provider_path, EvtRenderContextValues);
        ok(context != NULL, "EvtCreateRenderContext error %lu\n", GetLastError());
        values = HeapAlloc(GetProcessHeap(), 0, 512);
        ret = EvtRender(context, event, EvtRenderEventValues, 512, values, &size, &count);
        ok(ret && count == 1 && values[0].Type == EvtVarTypeString, "got %d, %lu, %lu\n", ret, count, values[0].Type);
        provider[0] = 0;
        if (ret) lstrcpynW(provider, values[0].StringVal, ARRAY_SIZE(provider));
        HeapFree(GetProcessHeap(), 0, values);
        EvtClose(context);

        meta = EvtOpenPublisherMetadata(NULL, provider, NULL, 0, 0);
        if (meta)
        {
            ret = EvtFormatMessage(meta, event, 0, 0, NULL, EvtFormatMessageLevel, ARRAY_SIZE(name), name, &size);
            ok(ret, "EvtFormatMessage error %lu\n", GetLastError());
            ok(size == wcslen(name) + 1, "got %lu for %s\n", size, wine_dbgstr_w(name));
            ok(!wcscmp(name, level == 2 ? L"Error" : level == 3 ? L"Warning" : level == 4 ? L"Information" : name),
               "level %lu: %s\n", level, wine_dbgstr_w(name));

            SetLastError(0xdeadbeef);
            ret = EvtFormatMessage(meta, event, 0, 0, NULL, EvtFormatMessageLevel, 1, name, &size);
            ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got %d, %lu\n", ret, GetLastError());
            ok(size > 1, "got %lu\n", size);
            EvtClose(meta);
        }
        else skip("No publisher %s, error %lu\n", wine_dbgstr_w(provider), GetLastError());
    }

    /* the oldest event is the first of the other direction, and has the lowest record number */
    forward = EvtQuery(NULL, L"System", L"*", EvtQueryChannelPath | EvtQueryForwardDirection);
    ok(forward != NULL, "EvtQuery error %lu\n", GetLastError());
    if (forward)
    {
        event2 = NULL;
        ret = EvtNext(forward, 1, &event2, 1000, 0, &count);
        ok(ret, "EvtNext error %lu\n", GetLastError());
        if (ret)
        {
            context = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
            values = HeapAlloc(GetProcessHeap(), 0, 4096);
            ret = EvtRender(context, event2, EvtRenderEventValues, 4096, values, &size, &count);
            ok(ret, "EvtRender error %lu\n", GetLastError());
            oldest = ret ? values[EvtSystemEventRecordId].UInt64Val : 0;
            ok(oldest <= newest, "got %I64u, %I64u\n", oldest, newest);
            HeapFree(GetProcessHeap(), 0, values);
            EvtClose(context);
            EvtClose(event2);
        }
        EvtClose(forward);
    }

    /* filters */
    filter = HeapAlloc(GetProcessHeap(), 0, 128 * sizeof(WCHAR));
    _snwprintf(filter, 128, L"*[System[(EventID=%lu)]]", id);
    forward = EvtQuery(NULL, L"System", filter, EvtQueryChannelPath);
    ok(forward != NULL, "EvtQuery error %lu\n", GetLastError());
    if (forward)
    {
        for (i = 0;; i++)
        {
            EVT_HANDLE e = NULL;

            if (!EvtNext(forward, 1, &e, 1000, 0, &count)) break;
            EvtClose(e);
            if (i >= 3) break;
        }
        ok(i >= 1, "the event with the id of %lu is not found\n", id);
        EvtClose(forward);
    }
    HeapFree(GetProcessHeap(), 0, filter);

    forward = EvtQuery(NULL, L"System", no_such_event, EvtQueryChannelPath);
    ok(forward != NULL, "EvtQuery error %lu\n", GetLastError());
    if (forward)
    {
        EVT_HANDLE e = NULL;

        SetLastError(0xdeadbeef);
        ret = EvtNext(forward, 1, &e, 1000, 0, &count);
        ok(!ret && GetLastError() == ERROR_NO_MORE_ITEMS, "got %d, %lu\n", ret, GetLastError());
        EvtClose(forward);
    }

    /* the structured form of the same query */
    forward = EvtQuery(NULL, NULL, L"<QueryList><Query Id='0'><Select Path='System'>*[System[Level=99]]</Select>"
                       L"<Suppress Path='System'>*[System[EventID=1]]</Suppress></Query></QueryList>", EvtQueryChannelPath);
    ok(forward != NULL, "EvtQuery error %lu\n", GetLastError());
    EvtClose(forward);

    /* a bookmark follows the event that it is updated with */
    {
        EVT_HANDLE bookmark = EvtCreateBookmark(NULL);
        WCHAR text[512];

        ok(bookmark != NULL, "EvtCreateBookmark error %lu\n", GetLastError());
        ret = EvtUpdateBookmark(bookmark, event);
        ok(ret, "EvtUpdateBookmark error %lu\n", GetLastError());
        ret = EvtRender(NULL, bookmark, EvtRenderBookmark, sizeof(text), text, &size, &count);
        ok(ret, "EvtRender error %lu\n", GetLastError());
        if (ret)
        {
            ok(wcsstr(text, L"<Bookmark Channel='System' RecordId='") != NULL, "got %s\n", wine_dbgstr_w(text));
            ok(wcsstr(text, L"IsCurrent='true'") != NULL, "got %s\n", wine_dbgstr_w(text));
        }
        EvtClose(bookmark);
    }

    /* room for no event is room for the end of the results */
    SetLastError(0xdeadbeef);
    ret = EvtNext(query, 0, &event2, 1000, 0, &count);
    ok(!ret && GetLastError() == ERROR_NO_MORE_ITEMS, "got %d, %lu\n", ret, GetLastError());

    EvtClose(event);
    EvtClose(query);
}

static void test_log_info(void)
{
    EVT_HANDLE log;
    EVT_VARIANT value;
    DWORD size;
    BOOL ret;

    SetLastError(0xdeadbeef);
    log = EvtOpenLog(NULL, L"wevtapi_winetest_no_such_log", EvtOpenChannelPath);
    ok(!log && GetLastError() == ERROR_EVT_CHANNEL_NOT_FOUND, "got %p, %lu\n", log, GetLastError());

    log = EvtOpenLog(NULL, L"System", EvtOpenChannelPath);
    if (!log)
    {
        skip("Cannot open the System log, error %lu\n", GetLastError());
        return;
    }
    memset(&value, 0, sizeof(value));
    ret = EvtGetLogInfo(log, EvtLogNumberOfLogRecords, sizeof(value), &value, &size);
    ok(ret, "EvtGetLogInfo error %lu\n", GetLastError());
    ok(value.Type == EvtVarTypeUInt64, "got %lu\n", value.Type);
    ok(size == sizeof(value), "got %lu\n", size);
    ok(value.UInt64Val > 0, "the System log has no record\n");

    ret = EvtGetLogInfo(log, EvtLogFull, sizeof(value), &value, &size);
    ok(ret && value.Type == EvtVarTypeBoolean, "got %d, %lu\n", ret, value.Type);

    SetLastError(0xdeadbeef);
    ret = EvtGetLogInfo(log, EvtLogLastWriteTime, 0, NULL, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got %d, %lu\n", ret, GetLastError());
    ok(size == sizeof(value), "got %lu\n", size);

    SetLastError(0xdeadbeef);
    ret = EvtGetLogInfo(log, EvtLogPropertyIdEND, sizeof(value), &value, &size);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "got %d, %lu\n", ret, GetLastError());
    EvtClose(log);
}

static void test_channel_properties(void)
{
    EVT_HANDLE config;
    struct { EVT_VARIANT var; WCHAR buf[1024]; } data;
    DWORD size;
    BOOL ret;

    config = EvtOpenChannelConfig(NULL, L"System", 0);
    if (!config)
    {
        skip("Cannot open the System channel, error %lu\n", GetLastError());
        return;
    }
    memset(&data, 0, sizeof(data));
    ret = EvtGetChannelConfigProperty(config, EvtChannelConfigClassicEventlog, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeBoolean && data.var.BooleanVal, "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetChannelConfigProperty(config, EvtChannelConfigIsolation, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeUInt32 && data.var.UInt32Val == 1, "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetChannelConfigProperty(config, EvtChannelConfigType, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeUInt32 && data.var.UInt32Val == 0, "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetChannelConfigProperty(config, EvtChannelLoggingConfigMaxSize, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeUInt64 && data.var.UInt64Val > 0, "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetChannelConfigProperty(config, EvtChannelLoggingConfigRetention, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeBoolean && !data.var.BooleanVal, "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetChannelConfigProperty(config, EvtChannelConfigAccess, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeString && !wcsncmp(data.var.StringVal, L"O:", 2), "got %d, %lu\n", ret, data.var.Type);
    ret = EvtGetChannelConfigProperty(config, EvtChannelPublishingConfigLevel, 0, sizeof(data), &data.var, &size);
    ok(ret && data.var.Type == EvtVarTypeNull, "got %d, %lu\n", ret, data.var.Type);
    EvtClose(config);
}

static void test_publishers(void)
{
    EVT_HANDLE publishers, meta, array;
    struct { EVT_VARIANT var; WCHAR buf[1024]; } data;
    WCHAR name[256];
    DWORD size, count = 0, array_size;
    BOOL ret, found = FALSE;

    publishers = EvtOpenPublisherEnum(NULL, 0);
    if (!publishers)
    {
        skip("Cannot enumerate the publishers, error %lu\n", GetLastError());
        return;
    }
    while (EvtNextPublisherId(publishers, ARRAY_SIZE(name), name, &size))
    {
        ok(size == wcslen(name) + 1, "got %lu for %s\n", size, wine_dbgstr_w(name));
        if (!_wcsicmp(name, L"Service Control Manager")) found = TRUE;
        count++;
    }
    ok(GetLastError() == ERROR_NO_MORE_ITEMS, "got %lu\n", GetLastError());
    ok(count > 0, "no publisher\n");
    ok(found, "Service Control Manager is not among %lu publishers\n", count);
    EvtClose(publishers);

    SetLastError(0xdeadbeef);
    meta = EvtOpenPublisherMetadata(NULL, L"wevtapi_winetest_no_such_publisher", NULL, 0, 0);
    ok(!meta && GetLastError() == ERROR_FILE_NOT_FOUND, "got %p, %lu\n", meta, GetLastError());

    meta = EvtOpenPublisherMetadata(NULL, L"Service Control Manager", NULL, 0, 0);
    if (!meta)
    {
        skip("Cannot open the Service Control Manager publisher, error %lu\n", GetLastError());
        return;
    }
    memset(&data, 0, sizeof(data));
    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataMessageFilePath, 0, sizeof(data), &data.var, &size);
    ok(ret, "EvtGetPublisherMetadataProperty error %lu\n", GetLastError());
    ok(data.var.Type == EvtVarTypeString && wcslen(data.var.StringVal) > 4, "got %lu\n", data.var.Type);

    /* the link of the help comes from the version resource of the file of messages */
    memset(&data, 0, sizeof(data));
    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataHelpLink, 0, sizeof(data), &data.var, &size);
    ok(ret, "EvtGetPublisherMetadataProperty error %lu\n", GetLastError());
    ok(data.var.Type == EvtVarTypeString && !wcsncmp(data.var.StringVal, help_prefix, ARRAY_SIZE(help_prefix) - 1) &&
       wcsstr(data.var.StringVal, L"&ProdName=") && wcsstr(data.var.StringVal, L"&ProdVer=") && wcsstr(data.var.StringVal, L"&FileName=") &&
       wcsstr(data.var.StringVal, L"&FileVer="), "got %lu %s\n", data.var.Type, data.var.Type == EvtVarTypeString ? wine_dbgstr_w(data.var.StringVal) : "");

    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataChannelReferences, 0, sizeof(data), &data.var, &size);
    ok(ret, "EvtGetPublisherMetadataProperty error %lu\n", GetLastError());
    ok(data.var.Type == EvtVarTypeEvtHandle, "got %lu\n", data.var.Type);
    if (ret && data.var.Type == EvtVarTypeEvtHandle)
    {
        array = data.var.EvtHandleVal;
        ret = EvtGetObjectArraySize(array, &array_size);
        ok(ret && array_size >= 1, "got %d, %lu\n", ret, array_size);
        memset(&data, 0, sizeof(data));
        ret = EvtGetObjectArrayProperty(array, EvtPublisherMetadataChannelReferencePath, 0, 0, sizeof(data), &data.var, &size);
        ok(ret, "EvtGetObjectArrayProperty error %lu\n", GetLastError());
        ok(data.var.Type == EvtVarTypeString && !_wcsicmp(data.var.StringVal, L"System"), "got %lu\n", data.var.Type);
        EvtClose(array);
    }

    /* the properties of one element are not those of the publisher */
    SetLastError(0xdeadbeef);
    ret = EvtGetPublisherMetadataProperty(meta, EvtPublisherMetadataChannelReferencePath, 0, sizeof(data), &data.var, &size);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "got %d, %lu\n", ret, GetLastError());
    EvtClose(meta);
}


static void test_backwards_read(void)
{
    BYTE *buffer = HeapAlloc(GetProcessHeap(), 0, 64 * 1024);
    DWORD read, needed, calls = 0, error = 0, last = 0, records = 0;
    HANDLE log = OpenEventLogW(NULL, L"System");

    if (!log)
    {
        skip("Cannot open the System log, error %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, buffer);
        return;
    }
    /* a read backwards comes to the first record, and then to the end */
    while (calls < 100)
    {
        EVENTLOGRECORD *rec;
        DWORD pos;

        calls++;
        if (!ReadEventLogW(log, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, buffer, 64 * 1024, &read, &needed))
        {
            error = GetLastError();
            break;
        }
        for (pos = 0; pos < read; pos += rec->Length)
        {
            rec = (EVENTLOGRECORD *)(buffer + pos);
            ok(!last || rec->RecordNumber < last, "record %lu follows record %lu\n", rec->RecordNumber, last);
            last = rec->RecordNumber;
            records++;
        }
    }
    ok(error == ERROR_HANDLE_EOF, "got %lu after %lu calls\n", error, calls);
    ok(records > 0, "no record\n");
    CloseEventLog(log);
    HeapFree(GetProcessHeap(), 0, buffer);
}


static WCHAR evtx_path[MAX_PATH];

static BOOL write_evtx_file(void)
{
    static BYTE buf[EVTX_SAMPLE_SIZE];
    WCHAR dir[MAX_PATH];
    HANDLE file;
    DWORD written;
    BOOL ret;

    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"wev", 0, evtx_path);
    file = CreateFileW(evtx_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    build_evtx_sample(buf);
    ret = WriteFile(file, buf, sizeof(buf), &written, NULL) && written == sizeof(buf);
    CloseHandle(file);
    return ret;
}

/* The record numbers that a query gives, in order. A damaged file is reported with an error and read on. */
static DWORD read_records(EVT_HANDLE query, ULONGLONG *ids, DWORD max, DWORD *errors)
{
    static const WCHAR *paths[] = { L"Event/System/EventRecordID" };
    EVT_HANDLE event, context = EvtCreateRenderContext(1, paths, EvtRenderContextValues);
    DWORD count = 0, calls = 0, n, size, props;
    EVT_VARIANT value;

    *errors = 0;
    while (calls++ < 20)
    {
        SetLastError(0xdeadbeef);
        if (!EvtNext(query, 1, &event, 5000, 0, &n))
        {
            DWORD error = GetLastError();

            if (error == ERROR_NO_MORE_ITEMS) break;
            ok(error == ERROR_EVENTLOG_FILE_CORRUPT, "got %lu\n", error);
            (*errors)++;
            continue;
        }
        ok(n == 1, "got %lu\n", n);
        if (EvtRender(context, event, EvtRenderEventValues, sizeof(value), &value, &size, &props) && count < max)
            ids[count++] = value.UInt64Val;
        EvtClose(event);
    }
    EvtClose(context);
    return count;
}

static void test_evtx_file(void)
{
    static const WCHAR *xml_10 =
        L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        L"<Provider Name='Microsoft-Windows-PrintService' Guid='{747ef6fd-e535-4d16-b510-42c90f6873a1}'/>"
        L"<EventID>370</EventID><Version>0</Version><Level>2</Level><Task>38</Task><Opcode>12</Opcode>"
        L"<Keywords>0x8000000000000900</Keywords><TimeCreated SystemTime='2016-09-21T10:22:57.9085752Z'/>"
        L"<EventRecordID>10</EventRecordID><Correlation/><Execution ProcessID='2424' ThreadID='4728'/>"
        L"<Channel>Microsoft-Windows-PrintService/Admin</Channel>"
        L"<Computer>joeuser6.rrrrrrr.cccc.company12.com</Computer><Security UserID='S-1-5-18'/></System>"
        L"<UserData><PackageRegenerationForDriverFailed xmlns='http://manifests.microsoft.com/win/2005/08/windows/printing/spooler/core/events'>"
        L"<Param1>Remote Desktop Easy Print</Param1><Param2>Windows x64</Param2><Param3>87 (0x57)</Param3>"
        L"</PackageRegenerationForDriverFailed></UserData></Event>";
    EVT_HANDLE query, event, context;
    ULONGLONG ids[8];
    DWORD count, errors, size, props, n, i, error;
    WCHAR *query_text, *xml;
    EVT_VARIANT *values;
    BOOL ret;

    if (!write_evtx_file())
    {
        skip("Cannot write the sample file, error %lu\n", GetLastError());
        return;
    }

    /* oldest first: the checksum of the records is wrong, which is reported once, and the first event is lost */
    SetLastError(0xdeadbeef);
    query = EvtQuery(NULL, evtx_path, L"*", EvtQueryFilePath | EvtQueryForwardDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    if (!query) goto done;
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 3, "got %lu\n", count);
    ok(errors == 1, "got %lu\n", errors);
    if (count == 3) ok(ids[0] == 10 && ids[1] == 11 && ids[2] == 12, "got %I64u %I64u %I64u\n", ids[0], ids[1], ids[2]);

    /* a seek back to the start reads the file again with no error and with every event */
    ret = EvtSeek(query, 0, NULL, 0, EvtSeekRelativeToFirst);
    ok(ret, "EvtSeek error %lu\n", GetLastError());
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 4 && errors == 0, "got %lu %lu\n", count, errors);
    if (count == 4) ok(ids[0] == 9 && ids[1] == 10 && ids[2] == 11 && ids[3] == 12, "got %I64u %I64u %I64u %I64u\n", ids[0], ids[1], ids[2], ids[3]);
    EvtClose(query);

    query = EvtQuery(NULL, evtx_path, L"*", EvtQueryFilePath | EvtQueryReverseDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 3, "got %lu\n", count);
    ok(errors == 1, "got %lu\n", errors);
    if (count == 3) ok(ids[0] == 11 && ids[1] == 10 && ids[2] == 9, "got %I64u %I64u %I64u\n", ids[0], ids[1], ids[2]);

    /* the XML, the system values and the values of the data of the event of record 10 */
    ret = EvtNext(query, 1, &event, 1000, 0, &n);
    ok(!ret && GetLastError() == ERROR_NO_MORE_ITEMS, "got %d %lu\n", ret, GetLastError());
    EvtClose(query);

    query = EvtQuery(NULL, evtx_path, L"*[UserData/*/Param2='Windows x64']", EvtQueryFilePath | EvtQueryReverseDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 1 && errors == 1, "got %lu %lu\n", count, errors);
    if (count == 1) ok(ids[0] == 10, "got %I64u\n", ids[0]);
    EvtClose(query);

    query = EvtQuery(NULL, evtx_path, L"*/UserData/*/Param2='Windows x64'", EvtQueryFilePath | EvtQueryReverseDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 1 && (count < 1 || ids[0] == 10), "got %lu\n", count);
    EvtClose(query);

    query = EvtQuery(NULL, evtx_path, L"*[System[EventID=215]]", EvtQueryFilePath | EvtQueryForwardDirection);
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 1 && (count < 1 || ids[0] == 11), "got %lu\n", count);
    EvtClose(query);

    /* a structured query with a file, and a suppression */
    query_text = malloc(2048 * sizeof(WCHAR));
    swprintf(query_text, 2048, L"<QueryList><Query Id='0'><Select Path='file://%ls'>*</Select>"
             L"<Suppress Path='file://%ls'>*[System[EventID=370]]</Suppress></Query></QueryList>", evtx_path, evtx_path);
    query = EvtQuery(NULL, NULL, query_text, EvtQueryFilePath | EvtQueryReverseDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    count = read_records(query, ids, ARRAY_SIZE(ids), &errors);
    ok(count == 2, "got %lu\n", count);
    if (count == 2) ok(ids[0] == 11 && ids[1] == 9, "got %I64u %I64u\n", ids[0], ids[1]);
    EvtClose(query);
    free(query_text);

    /* the events of the file in reverse order, the one with record 10 is the second one after the error */
    query = EvtQuery(NULL, evtx_path, L"*[System[EventRecordID=10]]", EvtQueryFilePath | EvtQueryForwardDirection);
    ok(query != NULL, "EvtQuery error %lu\n", GetLastError());
    event = NULL;
    for (i = 0; i < 4; i++)
    {
        if (EvtNext(query, 1, &event, 1000, 0, &n)) break;
        error = GetLastError();
        ok(error == ERROR_EVENTLOG_FILE_CORRUPT, "got %lu\n", error);
    }
    ok(event != NULL, "no event\n");
    if (event)
    {
        size = 0;
        ret = EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &size, &props);
        ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got %d %lu\n", ret, GetLastError());
        xml = malloc(size);
        ret = EvtRender(NULL, event, EvtRenderEventXml, size, xml, &size, &props);
        ok(ret, "EvtRender error %lu\n", GetLastError());
        if (ret) ok(!wcscmp(xml, xml_10), "got %s\n", wine_dbgstr_w(xml));
        free(xml);

        context = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
        size = 0;
        EvtRender(context, event, EvtRenderEventValues, 0, NULL, &size, &props);
        values = malloc(size);
        ret = EvtRender(context, event, EvtRenderEventValues, size, values, &size, &props);
        ok(ret, "EvtRender error %lu\n", GetLastError());
        ok(props == 18, "got %lu\n", props);
        if (ret && props == 18)
        {
            ok(values[0].Type == EvtVarTypeString && !wcscmp(values[0].StringVal, L"Microsoft-Windows-PrintService"), "got %s\n",
               wine_dbgstr_w(values[0].StringVal));
            ok(values[1].Type == EvtVarTypeGuid && values[1].GuidVal->Data1 == 0x747ef6fd, "got %lu\n", values[1].Type);
            ok(values[2].Type == EvtVarTypeUInt16 && values[2].UInt16Val == 370, "got %lu\n", values[2].Type);
            ok(values[3].Type == EvtVarTypeNull, "got %lu\n", values[3].Type);
            ok(values[4].Type == EvtVarTypeByte && values[4].ByteVal == 2, "got %lu\n", values[4].Type);
            ok(values[5].Type == EvtVarTypeUInt16 && values[5].UInt16Val == 38, "got %lu\n", values[5].Type);
            ok(values[6].Type == EvtVarTypeByte && values[6].ByteVal == 12, "got %lu\n", values[6].Type);
            ok(values[7].Type == EvtVarTypeHexInt64 && values[7].UInt64Val == 0x8000000000000900ull, "got %lu\n", values[7].Type);
            ok(values[8].Type == EvtVarTypeFileTime && values[8].FileTimeVal == 0x1d213f21f8679b8ull, "got %I64x\n", values[8].FileTimeVal);
            ok(values[9].Type == EvtVarTypeUInt64 && values[9].UInt64Val == 10, "got %lu\n", values[9].Type);
            ok(values[10].Type == EvtVarTypeNull && values[11].Type == EvtVarTypeNull, "got %lu %lu\n", values[10].Type, values[11].Type);
            ok(values[12].Type == EvtVarTypeUInt32 && values[12].UInt32Val == 2424, "got %lu\n", values[12].Type);
            ok(values[13].Type == EvtVarTypeUInt32 && values[13].UInt32Val == 4728, "got %lu\n", values[13].Type);
            ok(values[14].Type == EvtVarTypeString && !wcscmp(values[14].StringVal, L"Microsoft-Windows-PrintService/Admin"), "got %lu\n", values[14].Type);
            ok(values[15].Type == EvtVarTypeString && !wcscmp(values[15].StringVal, L"joeuser6.rrrrrrr.cccc.company12.com"), "got %lu\n", values[15].Type);
            ok(values[16].Type == EvtVarTypeSid && IsValidSid(values[16].SidVal), "got %lu\n", values[16].Type);
            ok(values[17].Type == EvtVarTypeByte && values[17].ByteVal == 0, "got %lu\n", values[17].Type);
        }
        free(values);
        EvtClose(context);

        context = EvtCreateRenderContext(0, NULL, EvtRenderContextUser);
        size = 0;
        EvtRender(context, event, EvtRenderEventValues, 0, NULL, &size, &props);
        values = malloc(size);
        ret = EvtRender(context, event, EvtRenderEventValues, size, values, &size, &props);
        ok(ret, "EvtRender error %lu\n", GetLastError());
        ok(props == 3, "got %lu\n", props);
        if (ret && props == 3)
        {
            ok(values[0].Type == EvtVarTypeString && !wcscmp(values[0].StringVal, L"Remote Desktop Easy Print"), "got %lu\n", values[0].Type);
            ok(values[1].Type == EvtVarTypeString && !wcscmp(values[1].StringVal, L"Windows x64"), "got %lu\n", values[1].Type);
            ok(values[2].Type == EvtVarTypeString && !wcscmp(values[2].StringVal, L"87 (0x57)"), "got %lu\n", values[2].Type);
        }
        free(values);
        EvtClose(context);

        /* the path that an event of a file is said to come from is the file */
        {
            struct { EVT_VARIANT var; WCHAR buf[MAX_PATH]; } info;

            ret = EvtGetEventInfo(event, EvtEventPath, sizeof(info), &info.var, &size);
            ok(ret, "EvtGetEventInfo error %lu\n", GetLastError());
            if (ret) ok(info.var.Type == EvtVarTypeString && !_wcsicmp(info.var.StringVal, evtx_path), "got %s\n",
                        wine_dbgstr_w(info.var.StringVal));
        }
        EvtClose(event);
    }
    EvtClose(query);

done:
    DeleteFileW(evtx_path);
}

START_TEST(wevtapi)
{
    test_EvtGetChannelConfigProperty();
    test_log_info();
    test_channel_properties();
    test_publishers();
    test_query_and_render();
    test_backwards_read();
    test_evtx_file();
}
