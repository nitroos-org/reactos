/*
 * Unit tests for IBackgroundCopyJob3::AddFileWithRanges: a download of parts of a remote file
 * with HTTP range requests, from a server of the test itself
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

#include <stdio.h>
#include <winsock2.h>

#define COBJMACROS

#include "wine/test.h"
#include "bits.h"
#include "bits2_0.h"

#define DATA_SIZE 100000

static BYTE data[DATA_SIZE];
static SOCKET listener = INVALID_SOCKET;
static HANDLE server_thread;
static LONG server_stop;
static BOOL server_ranges = TRUE;
static DWORD server_delay_ms;
static CRITICAL_SECTION server_cs;
static char server_log[16][64];
static int server_requests;

static BYTE expected_byte(ULONG64 offset)
{
    return (BYTE)(offset * 7 + offset / 251 + 1);
}

static void serve(SOCKET s)
{
    char request[2048], head[256];
    ULONG64 first = 0, last = DATA_SIZE - 1;
    BOOL ranged = FALSE, is_head;
    int len = 0, n, sent;
    const char *range;

    while (len < sizeof(request) - 1 && !strstr(request, "\r\n\r\n"))
    {
        n = recv(s, request + len, sizeof(request) - 1 - len, 0);
        if (n <= 0) return;
        len += n;
        request[len] = 0;
    }
    is_head = !strncmp(request, "HEAD ", 5);

    if ((range = strstr(request, "Range: bytes=")) || (range = strstr(request, "range: bytes=")))
    {
        char *dash;
        first = _strtoui64(range + 13, &dash, 10);
        if (*dash == '-' && dash[1] >= '0' && dash[1] <= '9') last = _strtoui64(dash + 1, NULL, 10);
        ranged = server_ranges;
        EnterCriticalSection(&server_cs);
        if (server_requests < ARRAY_SIZE(server_log))
        {
            const char *eol = strpbrk(range, "\r\n");
            int count = eol ? eol - range : 0;
            if (count > 63) count = 63;
            memcpy(server_log[server_requests], range, count);
            server_log[server_requests][count] = 0;
        }
        server_requests++;
        LeaveCriticalSection(&server_cs);
    }
    if (last >= DATA_SIZE) last = DATA_SIZE - 1;
    if (!ranged) { first = 0; last = DATA_SIZE - 1; }

    if (ranged)
        n = sprintf(head, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %I64u-%I64u/%d\r\n"
                    "Content-Length: %I64u\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                    first, last, DATA_SIZE, last - first + 1);
    else
        n = sprintf(head, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nAccept-Ranges: %s\r\nConnection: close\r\n\r\n",
                    DATA_SIZE, server_ranges ? "bytes" : "none");
    send(s, head, n, 0);
    if (is_head) return;
    for (sent = 0; first + sent <= last; sent += n)
    {
        n = (int)min(last - first + 1 - sent, 8192);
        if (send(s, (const char *)data + first + sent, n, 0) <= 0) break;
        if (server_delay_ms) Sleep(server_delay_ms);
    }
}

static DWORD WINAPI server_proc(void *arg)
{
    while (!InterlockedCompareExchange(&server_stop, 0, 0))
    {
        SOCKET s = accept(listener, NULL, NULL);
        if (s == INVALID_SOCKET) break;
        serve(s);
        shutdown(s, SD_SEND);
        closesocket(s);
    }
    return 0;
}

static BOOL start_server(WORD *port)
{
    struct sockaddr_in addr = {0};
    int size = sizeof(addr);
    WSADATA wsa;
    DWORD i;

    if (WSAStartup(MAKEWORD(2, 2), &wsa)) return FALSE;
    for (i = 0; i < DATA_SIZE; ++i) data[i] = expected_byte(i);
    InitializeCriticalSection(&server_cs);
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return FALSE;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) || listen(listener, 4) ||
        getsockname(listener, (struct sockaddr *)&addr, &size))
        return FALSE;
    *port = ntohs(addr.sin_port);
    server_thread = CreateThread(NULL, 0, server_proc, NULL, 0, NULL);
    return server_thread != NULL;
}

static void stop_server(void)
{
    InterlockedExchange(&server_stop, 1);
    if (listener != INVALID_SOCKET)
    {
        closesocket(listener);   /* wakes accept() */
        listener = INVALID_SOCKET;
    }
    if (server_thread)
    {
        WaitForSingleObject(server_thread, 5000);
        CloseHandle(server_thread);
    }
    WSACleanup();
}

static BG_JOB_STATE wait_for_job(IBackgroundCopyJob *job, int seconds)
{
    BG_JOB_STATE state = BG_JOB_STATE_QUEUED;
    int i;

    for (i = 0; i < seconds * 10; ++i)
    {
        HRESULT hr = IBackgroundCopyJob_GetState(job, &state);
        ok(hr == S_OK, "GetState: 0x%08lx\n", hr);
        if (state == BG_JOB_STATE_TRANSFERRED || state == BG_JOB_STATE_ERROR ||
            state == BG_JOB_STATE_CANCELLED || state == BG_JOB_STATE_ACKNOWLEDGED)
            break;
        if (state == BG_JOB_STATE_TRANSIENT_ERROR)
        {
            hr = IBackgroundCopyJob_Resume(job);
            ok(hr == S_OK, "Resume: 0x%08lx\n", hr);
        }
        Sleep(100);
    }
    return state;
}

static IBackgroundCopyJob3 *create_job(IBackgroundCopyManager *manager, BG_JOB_TYPE type, IBackgroundCopyJob **base)
{
    IBackgroundCopyJob3 *job3 = NULL;
    GUID id;
    HRESULT hr;

    hr = IBackgroundCopyManager_CreateJob(manager, L"Ranges", type, &id, base);
    ok(hr == S_OK, "CreateJob: 0x%08lx\n", hr);
    if (hr != S_OK) return NULL;
    hr = IBackgroundCopyJob_QueryInterface(*base, &IID_IBackgroundCopyJob3, (void **)&job3);
    if (hr != S_OK)
    {
        win_skip("IBackgroundCopyJob3 is not available: 0x%08lx\n", hr);
        IBackgroundCopyJob_Cancel(*base);
        IBackgroundCopyJob_Release(*base);
        *base = NULL;
    }
    return job3;
}

static void test_arguments(IBackgroundCopyManager *manager)
{
    static const BG_FILE_RANGE good[] = {{0, 10}, {100, 50}, {1000, BG_LENGTH_TO_EOF}};
    static const BG_FILE_RANGE zero[] = {{0, 0}};
    static const BG_FILE_RANGE overlap[] = {{0, 100}, {99, 10}};
    static const BG_FILE_RANGE overlap_reverse[] = {{50, 10}, {0, 100}};
    static const BG_FILE_RANGE eof_first[] = {{0, BG_LENGTH_TO_EOF}, {100, 10}};
    static const BG_FILE_RANGE huge[] = {{~0ull - 5, 100}};
    IBackgroundCopyJob *job, *upload;
    IBackgroundCopyJob3 *job3, *upload3;
    IBackgroundCopyFile2 *file2;
    IEnumBackgroundCopyFiles *files;
    IBackgroundCopyFile *file;
    BG_FILE_RANGE *ranges;
    DWORD count;
    ULONG fetched;
    HRESULT hr;

    job3 = create_job(manager, BG_JOB_TYPE_DOWNLOAD, &job);
    if (!job3) return;

    /* NULL pointers do not get past the RPC stub of a job in another process */
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, NULL, L"C:\\ranges.tmp", 3, (BG_FILE_RANGE *)good);
    ok(FAILED(hr), "NULL url: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", NULL, 3, (BG_FILE_RANGE *)good);
    ok(FAILED(hr), "NULL local name: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 0, (BG_FILE_RANGE *)good);
    ok(FAILED(hr), "no ranges: 0x%08lx\n", hr);
    trace("no ranges: 0x%08lx\n", hr);

    /* The exact codes are not measured on Windows; a job takes no such file */
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 1, (BG_FILE_RANGE *)zero);
    ok(FAILED(hr), "empty range: 0x%08lx\n", hr);
    trace("empty range: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 2, (BG_FILE_RANGE *)overlap);
    ok(FAILED(hr), "overlapping ranges: 0x%08lx\n", hr);
    trace("overlapping ranges: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 2, (BG_FILE_RANGE *)overlap_reverse);
    ok(FAILED(hr), "overlapping ranges, reverse order: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 2, (BG_FILE_RANGE *)eof_first);
    ok(FAILED(hr), "range to the end of the file, then another: 0x%08lx\n", hr);
    trace("range to the end of the file, then another: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 1, (BG_FILE_RANGE *)huge);
    ok(FAILED(hr), "range past 2^63: 0x%08lx\n", hr);

    hr = IBackgroundCopyJob_EnumFiles(job, &files);
    ok(hr == S_OK, "EnumFiles: 0x%08lx\n", hr);
    hr = IEnumBackgroundCopyFiles_GetCount(files, &count);
    ok(hr == S_OK && count == 0, "files after the failed calls: 0x%08lx, %lu\n", hr, count);
    IEnumBackgroundCopyFiles_Release(files);

    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 3, (BG_FILE_RANGE *)good);
    ok(hr == S_OK, "valid ranges: 0x%08lx\n", hr);

    hr = IBackgroundCopyJob_EnumFiles(job, &files);
    ok(hr == S_OK, "EnumFiles: 0x%08lx\n", hr);
    hr = IEnumBackgroundCopyFiles_GetCount(files, &count);
    ok(hr == S_OK && count == 1, "file count: 0x%08lx, %lu\n", hr, count);
    fetched = 0;
    hr = IEnumBackgroundCopyFiles_Next(files, 1, &file, &fetched);
    ok(hr == S_OK && fetched == 1, "Next: 0x%08lx, %lu\n", hr, fetched);
    if (hr == S_OK)
    {
        hr = IBackgroundCopyFile_QueryInterface(file, &IID_IBackgroundCopyFile2, (void **)&file2);
        if (hr == S_OK)
        {
            count = 0;
            ranges = NULL;
            hr = IBackgroundCopyFile2_GetFileRanges(file2, &count, &ranges);
            ok(hr == S_OK, "GetFileRanges: 0x%08lx\n", hr);
            ok(count == 3, "range count %lu\n", count);
            if (hr == S_OK && count == 3)
                ok(!memcmp(ranges, good, sizeof(good)), "ranges differ\n");
            CoTaskMemFree(ranges);
            IBackgroundCopyFile2_Release(file2);
        }
        else win_skip("IBackgroundCopyFile2 is not available: 0x%08lx\n", hr);
        IBackgroundCopyFile_Release(file);
    }
    IEnumBackgroundCopyFiles_Release(files);

    hr = IBackgroundCopyJob_Cancel(job);
    ok(hr == S_OK || hr == BG_S_UNABLE_TO_DELETE_FILES, "Cancel: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, L"http://localhost/x", L"C:\\ranges.tmp", 3, (BG_FILE_RANGE *)good);
    ok(hr == BG_E_INVALID_STATE, "cancelled job: 0x%08lx\n", hr);
    IBackgroundCopyJob3_Release(job3);
    IBackgroundCopyJob_Release(job);

    /* Ranges are for downloads */
    upload3 = create_job(manager, BG_JOB_TYPE_UPLOAD, &upload);
    if (upload3)
    {
        hr = IBackgroundCopyJob3_AddFileWithRanges(upload3, L"http://localhost/x", L"C:\\ranges.tmp", 3, (BG_FILE_RANGE *)good);
        ok(FAILED(hr), "upload job: 0x%08lx\n", hr);
        trace("upload job: 0x%08lx\n", hr);
        IBackgroundCopyJob_Cancel(upload);
        IBackgroundCopyJob3_Release(upload3);
        IBackgroundCopyJob_Release(upload);
    }
}

static BOOL read_local_file(const WCHAR *name, BYTE **buffer, DWORD *size)
{
    HANDLE file = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD read = 0;

    *buffer = NULL;
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    *size = GetFileSize(file, NULL);
    *buffer = calloc(1, *size + 1);
    ReadFile(file, *buffer, *size, &read, NULL);
    CloseHandle(file);
    return read == *size;
}

static void test_transfer(IBackgroundCopyManager *manager, WORD port)
{
    static const BG_FILE_RANGE ranges[] = {{1000, 500}, {50000, 2000}, {90000, BG_LENGTH_TO_EOF}};
    IBackgroundCopyJob *job;
    IBackgroundCopyJob3 *job3;
    IEnumBackgroundCopyFiles *files;
    IBackgroundCopyFile *file;
    BG_FILE_PROGRESS progress;
    BG_JOB_PROGRESS job_progress;
    BG_JOB_STATE state;
    WCHAR url[100], local[MAX_PATH], dir[MAX_PATH];
    ULONG fetched = 0;
    BYTE *content;
    DWORD size, i;
    HRESULT hr;

    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"rng", 0, local);
    DeleteFileW(local);
    swprintf(url, ARRAY_SIZE(url), L"http://127.0.0.1:%u/file.bin", port);

    job3 = create_job(manager, BG_JOB_TYPE_DOWNLOAD, &job);
    if (!job3) return;

    server_requests = 0;
    server_ranges = TRUE;
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, url, local, ARRAY_SIZE(ranges), (BG_FILE_RANGE *)ranges);
    ok(hr == S_OK, "AddFileWithRanges: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob_Resume(job);
    ok(hr == S_OK, "Resume: 0x%08lx\n", hr);

    state = wait_for_job(job, 60);
    ok(state == BG_JOB_STATE_TRANSFERRED, "job state %d\n", state);

    if (state == BG_JOB_STATE_TRANSFERRED)
    {
        hr = IBackgroundCopyJob_GetProgress(job, &job_progress);
        ok(hr == S_OK, "GetProgress: 0x%08lx\n", hr);
        ok(job_progress.FilesTotal == 1 && job_progress.FilesTransferred == 1, "files %lu/%lu\n",
           job_progress.FilesTransferred, job_progress.FilesTotal);
        ok(job_progress.BytesTransferred == 500 + 2000 + 10000, "job bytes %I64u\n", job_progress.BytesTransferred);

        hr = IBackgroundCopyJob_EnumFiles(job, &files);
        ok(hr == S_OK, "EnumFiles: 0x%08lx\n", hr);
        hr = IEnumBackgroundCopyFiles_Next(files, 1, &file, &fetched);
        ok(hr == S_OK && fetched == 1, "Next: 0x%08lx\n", hr);
        if (hr == S_OK)
        {
            hr = IBackgroundCopyFile_GetProgress(file, &progress);
            ok(hr == S_OK, "file GetProgress: 0x%08lx\n", hr);
            ok(progress.Completed, "file not completed\n");
            ok(progress.BytesTransferred == 12500, "file bytes %I64u\n", progress.BytesTransferred);
            trace("file BytesTotal %I64u\n", progress.BytesTotal);
            IBackgroundCopyFile_Release(file);
        }
        IEnumBackgroundCopyFiles_Release(files);

        hr = IBackgroundCopyJob_Complete(job);
        ok(hr == S_OK, "Complete: 0x%08lx\n", hr);

        ok(read_local_file(local, &content, &size), "local file unreadable: %lu\n", GetLastError());
        if (content)
        {
            ok(size == DATA_SIZE, "local file size %lu\n", size);
            for (i = 0; i < ARRAY_SIZE(ranges) && size == DATA_SIZE; ++i)
            {
                ULONG64 end = ranges[i].Length == BG_LENGTH_TO_EOF ? DATA_SIZE : ranges[i].InitialOffset + ranges[i].Length;
                ULONG64 pos;
                for (pos = ranges[i].InitialOffset; pos < end; ++pos)
                    if (content[pos] != expected_byte(pos)) break;
                ok(pos == end, "range %lu: byte %I64u is %02x, expected %02x\n", i, pos, content[pos], expected_byte(pos));
            }
            free(content);
        }
    }
    else
    {
        IBackgroundCopyError *error = NULL;
        if (IBackgroundCopyJob_GetError(job, &error) == S_OK)
        {
            BG_ERROR_CONTEXT context;
            HRESULT code;
            if (IBackgroundCopyError_GetError(error, &context, &code) == S_OK)
                trace("job error: context %d code 0x%08lx\n", context, code);
            IBackgroundCopyError_Release(error);
        }
        IBackgroundCopyJob_Cancel(job);
    }

    /* The server saw one request for each range, with that range */
    EnterCriticalSection(&server_cs);
    trace("range requests: %d\n", server_requests);
    for (i = 0; i < (DWORD)min(server_requests, ARRAY_SIZE(server_log)); ++i) trace("  %s\n", server_log[i]);
    ok(server_requests >= 3, "requests with a range header: %d\n", server_requests);
    for (i = 0; i < 3 && i < (DWORD)server_requests; ++i)
    {
        static const char *expect[] = {"Range: bytes=1000-1499", "Range: bytes=50000-51999", "Range: bytes=90000-"};
        int j, found = 0;
        for (j = 0; j < min(server_requests, ARRAY_SIZE(server_log)); ++j)
            if (!strcmp(server_log[j], expect[i])) found = 1;
        ok(found, "no request for %s\n", expect[i]);
    }
    LeaveCriticalSection(&server_cs);

    DeleteFileW(local);
    IBackgroundCopyJob3_Release(job3);
    IBackgroundCopyJob_Release(job);
}

/* A server that does not do ranges answers 200 and the whole file: the job must not take it for the range */
static void test_no_range_support(IBackgroundCopyManager *manager, WORD port)
{
    static const BG_FILE_RANGE ranges[] = {{1000, 500}};
    IBackgroundCopyJob *job;
    IBackgroundCopyJob3 *job3;
    BG_JOB_STATE state;
    WCHAR url[100], local[MAX_PATH], dir[MAX_PATH];
    HRESULT hr;

    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"rng", 0, local);
    DeleteFileW(local);
    swprintf(url, ARRAY_SIZE(url), L"http://127.0.0.1:%u/file.bin", port);

    job3 = create_job(manager, BG_JOB_TYPE_DOWNLOAD, &job);
    if (!job3) return;

    server_ranges = FALSE;
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, url, local, 1, (BG_FILE_RANGE *)ranges);
    ok(hr == S_OK, "AddFileWithRanges: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob_Resume(job);
    ok(hr == S_OK, "Resume: 0x%08lx\n", hr);

    state = BG_JOB_STATE_QUEUED;
    {
        int i;
        for (i = 0; i < 300; ++i)
        {
            IBackgroundCopyJob_GetState(job, &state);
            if (state == BG_JOB_STATE_TRANSFERRED || state == BG_JOB_STATE_ERROR || state == BG_JOB_STATE_TRANSIENT_ERROR)
                break;
            Sleep(100);
        }
    }
    ok(state == BG_JOB_STATE_ERROR || state == BG_JOB_STATE_TRANSIENT_ERROR, "job state %d\n", state);

    IBackgroundCopyJob_Cancel(job);
    server_ranges = TRUE;
    DeleteFileW(local);
    IBackgroundCopyJob3_Release(job3);
    IBackgroundCopyJob_Release(job);
}


typedef struct
{
    IBackgroundCopyCallback2 IBackgroundCopyCallback2_iface;
    LONG ref;
} Callback;

static HRESULT WINAPI callback_QueryInterface(IBackgroundCopyCallback2 *iface, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IBackgroundCopyCallback) ||
        IsEqualIID(riid, &IID_IBackgroundCopyCallback2))
    {
        *ppv = iface;
        IBackgroundCopyCallback2_AddRef(iface);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI callback_AddRef(IBackgroundCopyCallback2 *iface)
{
    return InterlockedIncrement(&CONTAINING_RECORD(iface, Callback, IBackgroundCopyCallback2_iface)->ref);
}

static ULONG WINAPI callback_Release(IBackgroundCopyCallback2 *iface)
{
    Callback *callback = CONTAINING_RECORD(iface, Callback, IBackgroundCopyCallback2_iface);
    ULONG ref = InterlockedDecrement(&callback->ref);
    if (!ref) free(callback);
    return ref;
}

static LONG callbacks_called;

static HRESULT WINAPI callback_JobTransferred(IBackgroundCopyCallback2 *iface, IBackgroundCopyJob *job)
{
    InterlockedIncrement(&callbacks_called);
    return S_OK;
}

static HRESULT WINAPI callback_JobError(IBackgroundCopyCallback2 *iface, IBackgroundCopyJob *job, IBackgroundCopyError *error)
{
    return S_OK;
}

static HRESULT WINAPI callback_JobModification(IBackgroundCopyCallback2 *iface, IBackgroundCopyJob *job, DWORD reserved)
{
    return S_OK;
}

static HRESULT WINAPI callback_FileTransferred(IBackgroundCopyCallback2 *iface, IBackgroundCopyJob *job, IBackgroundCopyFile *file)
{
    return S_OK;
}

static const IBackgroundCopyCallback2Vtbl callback_vtbl =
{
    callback_QueryInterface, callback_AddRef, callback_Release, callback_JobTransferred,
    callback_JobError, callback_JobModification, callback_FileTransferred
};

/* A client that sets its callback while the job is moving data: the service asks the callback for its
 * interface, and the client is inside a call at that time. Click-to-Run does this. */
static void test_callback_during_transfer(IBackgroundCopyManager *manager, WORD port)
{
    static const BG_FILE_RANGE ranges[] = {{0, 60000}};
    IBackgroundCopyJob *job;
    IBackgroundCopyJob3 *job3;
    Callback *callback;
    BG_JOB_STATE state;
    WCHAR url[100], local[MAX_PATH], dir[MAX_PATH];
    DWORD start, elapsed;
    HRESULT hr;

    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"rng", 0, local);
    DeleteFileW(local);
    swprintf(url, ARRAY_SIZE(url), L"http://127.0.0.1:%u/file.bin", port);

    job3 = create_job(manager, BG_JOB_TYPE_DOWNLOAD, &job);
    if (!job3) return;

    callback = calloc(1, sizeof(*callback));
    callback->IBackgroundCopyCallback2_iface.lpVtbl = &callback_vtbl;
    callback->ref = 1;

    server_delay_ms = 250;
    hr = IBackgroundCopyJob3_AddFileWithRanges(job3, url, local, ARRAY_SIZE(ranges), (BG_FILE_RANGE *)ranges);
    ok(hr == S_OK, "AddFileWithRanges: 0x%08lx\n", hr);
    hr = IBackgroundCopyJob_Resume(job);
    ok(hr == S_OK, "Resume: 0x%08lx\n", hr);
    Sleep(600);
    hr = IBackgroundCopyJob_GetState(job, &state);
    ok(hr == S_OK, "GetState: 0x%08lx\n", hr);
    trace("state while the callback is set: %d\n", state);

    start = GetTickCount();
    hr = IBackgroundCopyJob_SetNotifyInterface(job, (IUnknown *)&callback->IBackgroundCopyCallback2_iface);
    elapsed = GetTickCount() - start;
    ok(hr == S_OK, "SetNotifyInterface: 0x%08lx\n", hr);
    ok(elapsed < 20000, "SetNotifyInterface took %lu ms\n", elapsed);
    trace("SetNotifyInterface took %lu ms\n", elapsed);
    hr = IBackgroundCopyJob_SetNotifyFlags(job, BG_NOTIFY_JOB_TRANSFERRED);
    ok(hr == S_OK, "SetNotifyFlags: 0x%08lx\n", hr);

    state = wait_for_job(job, 60);
    ok(state == BG_JOB_STATE_TRANSFERRED, "job state %d\n", state);
    server_delay_ms = 0;
    IBackgroundCopyJob_Cancel(job);
    IBackgroundCopyJob_SetNotifyInterface(job, NULL);
    IBackgroundCopyCallback2_Release(&callback->IBackgroundCopyCallback2_iface);
    DeleteFileW(local);
    IBackgroundCopyJob3_Release(job3);
    IBackgroundCopyJob_Release(job);
}

START_TEST(ranges)
{
    IBackgroundCopyManager *manager = NULL;
    WORD port = 0;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx: 0x%08lx\n", hr);
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, EOAC_NONE, 0);
    ok(hr == S_OK, "CoInitializeSecurity: 0x%08lx\n", hr);

    hr = CoCreateInstance(&CLSID_BackgroundCopyManager, NULL, CLSCTX_LOCAL_SERVER, &IID_IBackgroundCopyManager,
                          (void **)&manager);
    if (hr != S_OK)
    {
        win_skip("The BITS manager is not available: 0x%08lx\n", hr);
        CoUninitialize();
        return;
    }

    test_arguments(manager);
    if (start_server(&port))
    {
        test_transfer(manager, port);
        test_no_range_support(manager, port);
        test_callback_during_transfer(manager, port);
        stop_server();
    }
    else skip("Cannot start the local HTTP server\n");

    IBackgroundCopyManager_Release(manager);
    CoUninitialize();
}
