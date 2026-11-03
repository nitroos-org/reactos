/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Guest-side reproducers for edge cases of the driver: renames into a subtree,
 *              deletes with open streams, concurrent queries and size changes, cached and
 *              non-cached writers on one file, parallel metadata traffic, record reuse
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * usage: ngedge DIR TEST [ARG]
 *   TEST: rename-subtree | rename-cycle | delete-open-stream | dir-async | size-race | cache-mix | parallel
 *         | stream-reuse | replace | junction-dos | prealloc | commit-race | prealloc-space | read-pattern FILE | all
 *         (prealloc-space measures free space, so it is not part of "all": run it on an otherwise idle volume)
 *   One NGE: line per check, NGE:DONE pass=N fail=M at the end.  A test that hangs leaves the
 *   machine to the harness timeout (the watchdog prints NGE:HANG first when it still can).
 */
#define WIN32_NO_STATUS
#include <windows.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/exfuncs.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int Pass, Fail;
static WCHAR Dir[MAX_PATH];
static volatile LONG Stop;
static volatile LONG Current;
static const char *TestName = "";

static void report(const char *name, int ok, const char *fmt, ...)
{
    char line[600], detail[400] = "";
    va_list ap;
    if (fmt)
    {
        va_start(ap, fmt);
        _vsnprintf(detail, sizeof(detail) - 1, fmt, ap);
        va_end(ap);
    }
    _snprintf(line, sizeof(line) - 1, "NGE:%s %s %s\n", ok ? "PASS" : "FAIL", name, detail);
    line[sizeof(line) - 1] = 0;
    OutputDebugStringA(line);
    fputs(line, stdout);
    fflush(stdout);
    if (ok) Pass++; else Fail++;
}

static DWORD WINAPI watchdog(LPVOID arg)
{
    LONG seen = -1, n = 0;
    (void)arg;
    for (;;)
    {
        Sleep(10000);
        if (Current != seen)
        {
            seen = Current;
            n = 0;
            continue;
        }
        if (++n == 30)
        {
            char line[128];
            _snprintf(line, sizeof(line), "NGE:HANG %s (no progress for 5 minutes)\n", TestName);
            OutputDebugStringA(line);
            fputs(line, stdout);
            fflush(stdout);
        }
    }
    return 0;
}

static void path(WCHAR *out, const WCHAR *rel)
{
    _snwprintf(out, MAX_PATH, L"%s\\%s", Dir, rel);
}

static BOOL putfile(const WCHAR *p, const void *data, DWORD len)
{
    HANDLE h = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD n;
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    ok = WriteFile(h, data, len, &n, NULL) && n == len;
    CloseHandle(h);
    return ok;
}

/* ---------------------------------------------------------------- rename into own subtree */
static void t_rename_subtree(void)
{
    WCHAR a[MAX_PATH], b[MAX_PATH], c[MAX_PATH], x[MAX_PATH];
    BOOL r;
    DWORD e;
    path(a, L"rs-a");
    path(b, L"rs-a\\b");
    path(c, L"rs-a\\b\\c");
    path(x, L"rs-a\\x");
    CreateDirectoryW(a, NULL);
    CreateDirectoryW(b, NULL);
    r = MoveFileW(a, c);
    e = GetLastError();
    report("rename-into-grandchild-refused", !r, "MoveFile ok=%d error %lu", r, e);
    r = MoveFileW(a, x);
    e = GetLastError();
    report("rename-into-child-refused", !r, "MoveFile ok=%d error %lu", r, e);
    r = MoveFileW(b, c);
    e = GetLastError();
    report("rename-into-itself-refused", !r, "MoveFile ok=%d error %lu", r, e);
    report("rename-subtree-intact", GetFileAttributesW(b) != INVALID_FILE_ATTRIBUTES, NULL);
    path(x, L"rs-moved");
    r = MoveFileW(b, x);
    report("rename-out-of-subtree-works", r, "error %lu", GetLastError());
}

/* Two threads move two sibling directories into each other: never both at once (a cycle). */
static WCHAR CycA[MAX_PATH], CycB[MAX_PATH], CycAB[MAX_PATH], CycBA[MAX_PATH];
static volatile LONG CycMoves[2];
static HANDLE CycGo;
static DWORD WINAPI cycle_mover(LPVOID arg)
{
    const WCHAR *from = arg ? CycB : CycA, *to = arg ? CycAB : CycBA;
    int i;
    WaitForSingleObject(CycGo, INFINITE);
    for (i = 0; i < 3000 && !Stop; i++)
    {
        if (MoveFileW(from, to))
        {
            InterlockedIncrement(&CycMoves[arg ? 1 : 0]);
            MoveFileW(to, from);
        }
        if (!(i & 63))
            InterlockedIncrement(&Current);
    }
    return 0;
}

static void t_rename_cycle(void)
{
    HANDLE t[2];
    BOOL a, b, ab, ba;
    path(CycA, L"rc-a");
    path(CycB, L"rc-b");
    path(CycAB, L"rc-a\\rc-b");
    path(CycBA, L"rc-b\\rc-a");
    /* Leftovers of an earlier run in the same directory go first. */
    RemoveDirectoryW(CycAB);
    RemoveDirectoryW(CycBA);
    RemoveDirectoryW(CycA);
    RemoveDirectoryW(CycB);
    if (!CreateDirectoryW(CycA, NULL) || !CreateDirectoryW(CycB, NULL))
    {
        report("rename-cycle-setup", 0, "CreateDirectory error %lu", GetLastError());
        return;
    }
    CycMoves[0] = CycMoves[1] = 0;
    Stop = 0;
    /* Both workers start together, so their moves can overlap. */
    CycGo = CreateEventW(NULL, TRUE, FALSE, NULL);
    t[0] = CreateThread(NULL, 0, cycle_mover, (LPVOID)0, 0, NULL);
    t[1] = CreateThread(NULL, 0, cycle_mover, (LPVOID)1, 0, NULL);
    if (!CycGo || !t[0] || !t[1])
    {
        report("rename-cycle-setup", 0, "CreateThread/CreateEvent error %lu", GetLastError());
        Stop = 1;
        if (CycGo) SetEvent(CycGo);
        if (t[0]) { WaitForSingleObject(t[0], INFINITE); CloseHandle(t[0]); }
        if (t[1]) { WaitForSingleObject(t[1], INFINITE); CloseHandle(t[1]); }
        if (CycGo) CloseHandle(CycGo);
        return;
    }
    SetEvent(CycGo);
    if (WaitForMultipleObjects(2, t, TRUE, INFINITE) != WAIT_OBJECT_0)
        report("rename-cycle-join", 0, "error %lu", GetLastError());
    CloseHandle(t[0]);
    CloseHandle(t[1]);
    CloseHandle(CycGo);
    a = GetFileAttributesW(CycA) != INVALID_FILE_ATTRIBUTES;
    b = GetFileAttributesW(CycB) != INVALID_FILE_ATTRIBUTES;
    ab = GetFileAttributesW(CycAB) != INVALID_FILE_ATTRIBUTES;
    ba = GetFileAttributesW(CycBA) != INVALID_FILE_ATTRIBUTES;
    if (ab) RemoveDirectoryW(CycAB);
    if (ba) RemoveDirectoryW(CycBA);
    RemoveDirectoryW(CycA);
    RemoveDirectoryW(CycB);
    report("rename-cycle-both-reachable", CycMoves[0] && CycMoves[1] && ((a && (b || ab)) || (b && ba)),
           "moves %ld and %ld; rc-a %d rc-b %d rc-a\\rc-b %d rc-b\\rc-a %d", CycMoves[0], CycMoves[1], a, b, ab, ba);
}

/* ---------------------------------------------------------------- delete with an open stream */
static void t_delete_open_stream(void)
{
    WCHAR f[MAX_PATH], s[MAX_PATH];
    HANDLE hs, hb;
    BOOL r;
    DWORD n, e;
    path(f, L"ds.txt");
    path(s, L"ds.txt:st");
    putfile(f, "base", 4);
    hs = CreateFileW(s, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     CREATE_ALWAYS, 0, NULL);
    if (hs == INVALID_HANDLE_VALUE)
    {
        report("delete-open-stream-setup", 0, "stream create error %lu", GetLastError());
        return;
    }
    WriteFile(hs, "stream data", 11, &n, NULL);
    r = DeleteFileW(f);
    e = GetLastError();
    report("delete-with-open-stream-returns", 1, "DeleteFile ok=%d error %lu", r, e);
    /* Either refused now, or the file disappears once the stream is closed: never both and never a hang. */
    hb = CreateFileW(f, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                     FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hb != INVALID_HANDLE_VALUE)
        CloseHandle(hb);
    report("delete-on-close-with-open-stream-returns", 1, NULL);
    /* A delete-on-close handle that wrote: the delete is refused (stream open), and what it wrote stays. */
    hb = CreateFileW(f, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hb != INVALID_HANDLE_VALUE)
    {
        char got[8] = {0};
        HANDLE hr;
        WriteFile(hb, "written", 7, &n, NULL);
        CloseHandle(hb);
        hr = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        r = hr != INVALID_HANDLE_VALUE && ReadFile(hr, got, 7, &n, NULL) && n == 7 && !memcmp(got, "written", 7);
        report("refused-delete-keeps-data", r, "open %d, read %lu bytes", hr != INVALID_HANDLE_VALUE, n);
        if (hr != INVALID_HANDLE_VALUE)
            CloseHandle(hr);
    }
    else
        report("refused-delete-keeps-data", 0, "open error %lu", GetLastError());
    /* The record cannot go while its stream is open: the file and the stream's data stay. */
    report("file-kept-while-stream-open", GetFileAttributesW(f) != INVALID_FILE_ATTRIBUTES ||
           GetLastError() == ERROR_ACCESS_DENIED, "error %lu", GetLastError());
    {
        char got[16] = {0};
        BOOL rd = SetFilePointer(hs, 0, NULL, FILE_BEGIN) == 0 && ReadFile(hs, got, 11, &n, NULL) && n == 11;
        report("stream-data-intact", rd && !memcmp(got, "stream data", 11), "read ok=%d, %lu bytes", rd, n);
    }
    CloseHandle(hs);
    r = DeleteFileW(f);
    report("delete-after-stream-closed", r || GetFileAttributesW(f) == INVALID_FILE_ATTRIBUTES, "ok=%d error %lu", r, GetLastError());
    report("file-gone", GetFileAttributesW(f) == INVALID_FILE_ATTRIBUTES, NULL);
}

/* ---------------------------------------------------------------- two async queries on one handle */
static HANDLE DirH;
static volatile LONG DirBad, DirRounds;
static volatile NTSTATUS DirLast;

/* A FILE_BOTH_DIR_INFORMATION buffer whose entry chain and names stay inside the returned length. */
static int dir_buffer_ok(const UCHAR *b, ULONG len)
{
    ULONG ofs = 0;
    for (;;)
    {
        const FILE_BOTH_DIR_INFORMATION *e = (const FILE_BOTH_DIR_INFORMATION *)(b + ofs);
        if (len - ofs < FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) ||
            e->FileNameLength > len - ofs - FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) || !e->FileNameLength)
            return 0;
        if (!e->NextEntryOffset)
            return 1;
        if (e->NextEntryOffset & 7 || e->NextEntryOffset > len - ofs)
            return 0;
        ofs += e->NextEntryOffset;
    }
}

static DWORD WINAPI dir_querier(LPVOID arg)
{
    static UCHAR bufs[2][65536];
    UCHAR *buf = bufs[(ULONG_PTR)arg];
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    int i;
    for (i = 0; i < 2000 && !Stop; i++)
    {
        IO_STATUS_BLOCK q;
        NTSTATUS st;
        ResetEvent(ev);
        st = NtQueryDirectoryFile(DirH, ev, NULL, NULL, &q, buf, 65536, FileBothDirectoryInformation, FALSE, NULL,
                                  (i + (int)(ULONG_PTR)arg) % 3 == 0);
        if (st == STATUS_PENDING)
        {
            WaitForSingleObject(ev, 30000);
            st = q.Status;
        }
        DirLast = st;
        if (NT_SUCCESS(st) && !dir_buffer_ok(buf, (ULONG)q.Information))
            InterlockedIncrement(&DirBad);
        else if (!NT_SUCCESS(st) && st != STATUS_NO_MORE_FILES)
            InterlockedIncrement(&DirBad);
        InterlockedIncrement(&DirRounds);
        InterlockedIncrement(&Current);
    }
    CloseHandle(ev);
    return 0;
}

static void t_dir_async(void)
{
    WCHAR d[MAX_PATH], f[MAX_PATH];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    HANDLE t[2];
    NTSTATUS st;
    int i;
    path(d, L"da");
    CreateDirectoryW(d, NULL);
    for (i = 0; i < 1500; i++)
    {
        _snwprintf(f, MAX_PATH, L"%s\\file-with-a-longer-name-%04d.txt", d, i);
        putfile(f, "x", 1);
    }
    if (!RtlDosPathNameToNtPathName_U(d, &name, NULL, NULL))
        return;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = NtOpenFile(&DirH, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &io, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_DIRECTORY_FILE);   /* no FILE_SYNCHRONOUS_IO_*: the I/O manager does not serialise */
    RtlFreeUnicodeString(&name);
    if (!NT_SUCCESS(st))
    {
        report("dir-async-open", 0, "status 0x%08lx", st);
        return;
    }
    /* Two threads query the one handle at the same time; each buffer must be whole. */
    DirBad = DirRounds = 0;
    Stop = 0;
    t[0] = CreateThread(NULL, 0, dir_querier, (LPVOID)0, 0, NULL);
    t[1] = CreateThread(NULL, 0, dir_querier, (LPVOID)1, 0, NULL);
    WaitForMultipleObjects(2, t, TRUE, INFINITE);
    report("dir-async-two-threads", DirBad == 0 && DirRounds == 4000, "%ld queries, %ld bad, last status 0x%08lx",
           DirRounds, DirBad, DirLast);
    CloseHandle(t[0]);
    CloseHandle(t[1]);
    NtClose(DirH);
}

/* ---------------------------------------------------------------- size queries racing appends */
#define REC 4096
static WCHAR RaceFile[MAX_PATH];
static DWORD WINAPI size_querier(LPVOID arg)
{
    HANDLE h = CreateFileW(RaceFile, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    LARGE_INTEGER sz;
    BY_HANDLE_FILE_INFORMATION bi;
    FILE_STANDARD_INFORMATION si;
    IO_STATUS_BLOCK io;
    (void)arg;
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    while (!Stop)
    {
        GetFileSizeEx(h, &sz);
        GetFileInformationByHandle(h, &bi);
        NtQueryInformationFile(h, &io, &si, sizeof(si), FileStandardInformation);
    }
    CloseHandle(h);
    return 0;
}

static void t_size_race(void)
{
    static UCHAR rec[REC], chk[REC];
    HANDLE w, q[3], r;
    DWORD n, i, nrec = 0, bad = 0, t0 = GetTickCount(), k;
    LARGE_INTEGER sz;
    BOOL wrote = TRUE;
    path(RaceFile, L"race.bin");
    w = CreateFileW(RaceFile, FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    if (w == INVALID_HANDLE_VALUE)
    {
        report("size-race-setup", 0, "error %lu", GetLastError());
        return;
    }
    Stop = 0;
    for (k = 0; k < 3; k++)
        q[k] = CreateThread(NULL, 0, size_querier, NULL, 0, NULL);
    while (GetTickCount() - t0 < 30000 && wrote)
    {
        memset(rec, (int)(nrec & 0xff), REC);
        *(DWORD *)rec = nrec;
        wrote = WriteFile(w, rec, REC, &n, NULL) && n == REC;
        if (wrote)
            nrec++;
        if ((nrec & 255) == 0)
            InterlockedIncrement(&Current);
    }
    Stop = 1;
    WaitForMultipleObjects(3, q, TRUE, 60000);
    CloseHandle(w);
    r = CreateFileW(RaceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    GetFileSizeEx(r, &sz);
    for (i = 0; i < nrec; i++)
    {
        if (!ReadFile(r, chk, REC, &n, NULL) || n != REC || *(DWORD *)chk != i || chk[REC - 1] != (UCHAR)(i & 0xff))
            bad++;
    }
    CloseHandle(r);
    report("size-race-appends", wrote && bad == 0 && sz.QuadPart == (LONGLONG)nrec * REC,
           "%lu records, size %I64d (want %I64d), %lu bad records", nrec, sz.QuadPart, (LONGLONG)nrec * REC, bad);
}

/* ---------------------------------------------------------------- cached and non-cached writers */
#define MIXPAGES 256
static WCHAR MixFile[MAX_PATH];
static volatile LONG NcVer[MIXPAGES], CVer[MIXPAGES];
static volatile LONG MixWrites[3], MixReads, MixErrors;
static DWORD WINAPI nc_writer(LPVOID arg)
{
    HANDLE h = CreateFileW(MixFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    UCHAR *b = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    ULONG seed = 1;
    (void)arg;
    if (h == INVALID_HANDLE_VALUE || !b)
        return 1;
    while (!Stop)
    {
        LONG p, v;
        OVERLAPPED ov;
        DWORD n;
        seed = seed * 1103515245 + 12345;
        p = (seed >> 8) % MIXPAGES;
        v = NcVer[p] + 1;
        memset(b, (int)(v & 0xff), 2048);
        memset(&ov, 0, sizeof(ov));
        ov.Offset = p * 4096;
        if (WriteFile(h, b, 2048, &n, &ov) && n == 2048)
        {
            NcVer[p] = v;
            InterlockedIncrement(&MixWrites[0]);
        }
        else
            InterlockedIncrement(&MixErrors);
    }
    CloseHandle(h);
    return 0;
}

static DWORD WINAPI c_writer(LPVOID arg)
{
    HANDLE h = CreateFileW(MixFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    UCHAR b[2048];
    ULONG seed = 7;
    (void)arg;
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    while (!Stop)
    {
        LONG p, v;
        OVERLAPPED ov;
        DWORD n;
        seed = seed * 1103515245 + 12345;
        p = ((seed >> 8) % MIXPAGES) & ~1;     /* even pages; the mapped writer has the odd ones */
        v = CVer[p] + 1;
        memset(b, (int)(0x80 | (v & 0x7f)), sizeof(b));
        memset(&ov, 0, sizeof(ov));
        ov.Offset = p * 4096 + 2048;
        if (WriteFile(h, b, sizeof(b), &n, &ov) && n == sizeof(b))
        {
            CVer[p] = v;
            InterlockedIncrement(&MixWrites[1]);
        }
        else
            InterlockedIncrement(&MixErrors);
    }
    CloseHandle(h);
    return 0;
}

static DWORD WINAPI c_reader(LPVOID arg)
{
    HANDLE h = CreateFileW(MixFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    UCHAR b[4096];
    ULONG seed = 99;
    (void)arg;
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    while (!Stop)
    {
        OVERLAPPED ov;
        DWORD n;
        seed = seed * 1103515245 + 12345;
        memset(&ov, 0, sizeof(ov));
        ov.Offset = ((seed >> 8) % MIXPAGES) * 4096;
        if (ReadFile(h, b, sizeof(b), &n, &ov) && n == sizeof(b))
            InterlockedIncrement(&MixReads);
        else
            InterlockedIncrement(&MixErrors);
    }
    CloseHandle(h);
    return 0;
}

/* Writes the second half of odd pages through a mapped view: page faults and partial page updates. */
static DWORD WINAPI m_writer(LPVOID arg)
{
    HANDLE h = CreateFileW(MixFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE m;
    UCHAR *v;
    ULONG seed = 31, k = 0;
    (void)arg;
    if (h == INVALID_HANDLE_VALUE)
        return 1;
    m = CreateFileMappingW(h, NULL, PAGE_READWRITE, 0, MIXPAGES * 4096, NULL);
    v = m ? MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, MIXPAGES * 4096) : NULL;
    if (!v)
    {
        if (m)
            CloseHandle(m);
        CloseHandle(h);
        return 1;
    }
    while (!Stop)
    {
        LONG p, ver;
        seed = seed * 1103515245 + 12345;
        p = ((seed >> 8) % MIXPAGES) | 1;
        ver = CVer[p] + 1;
        memset(v + p * 4096 + 2048, (int)(0x80 | (ver & 0x7f)), 2048);
        CVer[p] = ver;
        InterlockedIncrement(&MixWrites[2]);
        if (!(++k & 63) && !FlushViewOfFile(v, 0))
            InterlockedIncrement(&MixErrors);
        if (!(k & 1023))
        {
            /* Drop the view now and then so the pages have to come back from the file. */
            FlushViewOfFile(v, 0);
            UnmapViewOfFile(v);
            v = MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, MIXPAGES * 4096);
            if (!v)
                break;
        }
    }
    if (v)
    {
        FlushViewOfFile(v, 0);
        UnmapViewOfFile(v);
    }
    CloseHandle(m);
    CloseHandle(h);
    return v ? 0 : 1;
}

static void t_cache_mix(void)
{
    HANDLE t[5], h;
    UCHAR *b;
    DWORD i, n = 0, bad = 0, t0, code, exits = 0;
    path(MixFile, L"mix.bin");
    b = VirtualAlloc(NULL, MIXPAGES * 4096, MEM_COMMIT, PAGE_READWRITE);
    h = CreateFileW(MixFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE || !b)
    {
        report("cache-mix-setup", 0, "error %lu", GetLastError());
        return;
    }
    for (i = 0; i < MIXPAGES; i++)
    {
        memset(b + i * 4096, 0, 2048);
        memset(b + i * 4096 + 2048, 0x80, 2048);
        NcVer[i] = 0;
        CVer[i] = 0;
    }
    WriteFile(h, b, MIXPAGES * 4096, &n, NULL);
    CloseHandle(h);
    Stop = 0;
    MixWrites[0] = MixWrites[1] = MixWrites[2] = MixReads = MixErrors = 0;
    t[0] = CreateThread(NULL, 0, nc_writer, NULL, 0, NULL);
    t[1] = CreateThread(NULL, 0, c_writer, NULL, 0, NULL);
    t[2] = CreateThread(NULL, 0, c_reader, NULL, 0, NULL);
    t[3] = CreateThread(NULL, 0, c_reader, NULL, 0, NULL);
    t[4] = CreateThread(NULL, 0, m_writer, NULL, 0, NULL);
    for (t0 = GetTickCount(); GetTickCount() - t0 < 30000;)
    {
        Sleep(1000);
        InterlockedIncrement(&Current);
    }
    Stop = 1;
    WaitForMultipleObjects(5, t, TRUE, 60000);
    for (i = 0; i < 5; i++)
    {
        if (!GetExitCodeThread(t[i], &code) || code)
            exits++;
        CloseHandle(t[i]);
    }
    report("cache-mix-workers", !exits && !MixErrors && MixWrites[0] && MixWrites[1] && MixWrites[2] && MixReads,
           "%lu workers failed, %ld errors, writes nc=%ld cached=%ld mapped=%ld, %ld reads", exits, MixErrors,
           MixWrites[0], MixWrites[1], MixWrites[2], MixReads);
    /* Every half page holds its own writer's last version, read back without the cache. */
    h = CreateFileW(MixFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    if (h == INVALID_HANDLE_VALUE || !ReadFile(h, b, MIXPAGES * 4096, &n, NULL) || n != MIXPAGES * 4096)
    {
        report("cache-mix-no-stale-data", 0, "read back failed: error %lu, %lu bytes", GetLastError(), n);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        return;
    }
    CloseHandle(h);
    for (i = 0; i < MIXPAGES; i++)
    {
        UCHAR want1 = (UCHAR)(NcVer[i] & 0xff), want2 = (UCHAR)(0x80 | (CVer[i] & 0x7f));
        DWORD k;
        for (k = 0; k < 2048; k++)
            if (b[i * 4096 + k] != want1 || b[i * 4096 + 2048 + k] != want2)
            {
                bad++;
                break;
            }
    }
    report("cache-mix-no-stale-data", bad == 0, "%lu of %d pages wrong", bad, MIXPAGES);
}

/* ---------------------------------------------------------------- parallel metadata traffic */
static DWORD WINAPI meta_worker(LPVOID arg)
{
    ULONG seed = (ULONG)(ULONG_PTR)arg * 7919 + 1;
    WCHAR f[MAX_PATH];
    UCHAR sd[1024], buf[512];
    DWORD need, n;
    while (!Stop)
    {
        HANDLE h;
        WIN32_FIND_DATAW fd;
        seed = seed * 1103515245 + 12345;
        _snwprintf(f, MAX_PATH, L"%s\\pm\\f%03lu.txt", Dir, (seed >> 8) % 200);
        switch ((seed >> 20) % 4)
        {
            case 0:
                GetFileSecurityW(f, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd, sizeof(sd), &need);
                break;
            case 1:
                h = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                if (h != INVALID_HANDLE_VALUE)
                {
                    ReadFile(h, buf, sizeof(buf), &n, NULL);
                    CloseHandle(h);
                }
                break;
            case 2:
                _snwprintf(f, MAX_PATH, L"%s\\pm\\*", Dir);
                h = FindFirstFileW(f, &fd);
                if (h != INVALID_HANDLE_VALUE)
                {
                    while (FindNextFileW(h, &fd))
                        ;
                    FindClose(h);
                }
                break;
            default:
                GetFileAttributesW(f);
                break;
        }
    }
    return 0;
}

static void t_parallel(void)
{
    WCHAR f[MAX_PATH];
    HANDLE t[8];
    DWORD i, t0;
    char data[64];
    path(f, L"pm");
    CreateDirectoryW(f, NULL);
    for (i = 0; i < 200; i++)
    {
        _snwprintf(f, MAX_PATH, L"%s\\pm\\f%03lu.txt", Dir, i);
        _snprintf(data, sizeof(data), "file %lu", i);
        putfile(f, data, (DWORD)strlen(data));
    }
    Stop = 0;
    for (i = 0; i < 8; i++)
        t[i] = CreateThread(NULL, 0, meta_worker, (LPVOID)(ULONG_PTR)i, 0, NULL);
    for (t0 = GetTickCount(); GetTickCount() - t0 < 60000;)
    {
        Sleep(1000);
        InterlockedIncrement(&Current);
    }
    Stop = 1;
    report("parallel-metadata", WaitForMultipleObjects(8, t, TRUE, 120000) == WAIT_OBJECT_0, NULL);
}

/* ---------------------------------------------------------------- record reuse after delete */
static void t_stream_reuse(void)
{
    WCHAR f[MAX_PATH], s[MAX_PATH];
    char buf[64];
    DWORD i, n, stale = 0, round;
    HANDLE h;
    for (round = 0; round < 20; round++)
    {
        /* A file with a cached, dirty named stream; then the file goes and its record is reused. */
        _snwprintf(f, MAX_PATH, L"%s\\sr-%lu.txt", Dir, round);
        _snwprintf(s, MAX_PATH, L"%s:st", f);
        putfile(f, "base", 4);
        putfile(s, "OLD-STREAM", 10);
        DeleteFileW(f);
        for (i = 0; i < 20; i++)
        {
            _snwprintf(f, MAX_PATH, L"%s\\sr-new-%lu-%lu.txt", Dir, round, i);
            _snwprintf(s, MAX_PATH, L"%s:st", f);
            putfile(f, "new", 3);
            h = CreateFileW(s, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                memset(buf, 0, sizeof(buf));
                ReadFile(h, buf, sizeof(buf) - 1, &n, NULL);
                CloseHandle(h);
                stale++;   /* a new file has no stream: any content is a stale FCB */
            }
        }
        InterlockedIncrement(&Current);
    }
    report("stream-reuse-no-stale-stream", stale == 0, "%lu new files showed a stream", stale);
}

/* ---------------------------------------------------------------- replace a cached target */
static void t_replace(void)
{
    WCHAR a[MAX_PATH], b[MAX_PATH];
    char buf[16];
    DWORD i, n, ok = 0;
    HANDLE h;
    for (i = 0; i < 50; i++)
    {
        _snwprintf(a, MAX_PATH, L"%s\\rp-target-%lu.txt", Dir, i);
        _snwprintf(b, MAX_PATH, L"%s\\rp-source-%lu.txt", Dir, i);
        putfile(a, "old target", 10);
        h = CreateFileW(a, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ReadFile(h, buf, sizeof(buf), &n, NULL);    /* leaves a cached FCB behind */
        CloseHandle(h);
        putfile(b, "new", 3);
        if (MoveFileExW(b, a, MOVEFILE_REPLACE_EXISTING))
            ok++;
    }
    report("replace-cached-target", ok == 50, "%lu of 50 replaced (the offline check counts orphan records)", ok);
}

/* ---------------------------------------------------------------- junction on a DOS-named directory */
typedef struct
{
    ULONG Tag;
    USHORT DataLength, Reserved;
    USHORT SubOffset, SubLength, PrintOffset, PrintLength;
    WCHAR Path[256];
} NG_MP_REPARSE;

static void t_junction_dos(void)
{
    WCHAR d[MAX_PATH], target[MAX_PATH];
    NG_MP_REPARSE r;
    HANDLE h;
    DWORD n, i, ok = 0, set = 0;
    for (i = 0; i < 10; i++)
    {
        USHORT len;
        _snwprintf(d, MAX_PATH, L"%s\\Junction Directory Long Name %lu", Dir, i);
        CreateDirectoryW(d, NULL);
        h = CreateFileW(d, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        _snwprintf(target, MAX_PATH, L"\\??\\%s", Dir);
        len = (USHORT)(wcslen(target) * sizeof(WCHAR));
        memset(&r, 0, sizeof(r));
        r.Tag = IO_REPARSE_TAG_MOUNT_POINT;
        r.SubOffset = 0;
        r.SubLength = len;
        r.PrintOffset = len + sizeof(WCHAR);
        r.PrintLength = 0;
        memcpy(r.Path, target, len);
        r.DataLength = (USHORT)(8 + len + 2 * sizeof(WCHAR));
        if (DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &r, 8 + r.DataLength, NULL, 0, &n, NULL) &&
            (GetFileAttributesW(d) & FILE_ATTRIBUTE_REPARSE_POINT))
            set++;
        CloseHandle(h);
        if (RemoveDirectoryW(d))
            ok++;
    }
    report("junction-dos-set", set == 10, "%lu of 10 junctions set", set);
    report("junction-dos-removed", ok == 10, "%lu of 10 removed (the offline check looks for leftover records)", ok);
}

/* ---------------------------------------------------------------- nonpaged pool while listing */
static ULONG nonpaged_pages(void)
{
    SYSTEM_PERFORMANCE_INFORMATION spi;
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemPerformanceInformation, &spi, sizeof(spi), NULL)))
        return 0;
    return spi.NonPagedPoolPages;
}

static void t_pool(void)
{
    WCHAR d[MAX_PATH], f[MAX_PATH];
    WIN32_FIND_DATAW fd;
    MEMORYSTATUS ms;
    ULONG before, peak = 0, after, i, k, n;
    HANDLE h;
    path(d, L"pool");
    CreateDirectoryW(d, NULL);
    for (i = 0; i < 20000; i++)
    {
        _snwprintf(f, MAX_PATH, L"%s\\pool-file-with-a-long-name-%05lu.dat", d, i);
        putfile(f, "p", 1);
        if ((i & 511) == 0)
            InterlockedIncrement(&Current);
    }
    before = nonpaged_pages();
    for (k = 0; k < 10; k++)
    {
        _snwprintf(f, MAX_PATH, L"%s\\*", d);
        h = FindFirstFileW(f, &fd);
        n = 0;
        if (h != INVALID_HANDLE_VALUE)
        {
            while (FindNextFileW(h, &fd))
                n++;
            FindClose(h);
        }
        for (i = 0; i < 20000; i += 7)
        {
            _snwprintf(f, MAX_PATH, L"%s\\pool-file-with-a-long-name-%05lu.dat", d, i);
            GetFileAttributesW(f);
        }
        after = nonpaged_pages();
        if (after > peak)
            peak = after;
        InterlockedIncrement(&Current);
    }
    GlobalMemoryStatus(&ms);
    report("pool-listing", peak && peak - before < ms.dwTotalPhys / 4096 / 8,
           "nonpaged pool %lu -> peak %lu pages (%lu MB physical)", before, peak, (ULONG)(ms.dwTotalPhys >> 20));
}


/* ---------------------------------------------------------------- allocation ahead of the file size */
#define PA_PAT(o) ((UCHAR)((((o) * 7) + 3) & 0xff))

static DWORD cluster_size(void)
{
    WCHAR root[4] = { Dir[0], L':', L'\\', 0 };
    DWORD spc = 0, bps = 0, fc, tc;
    if (!GetDiskFreeSpaceW(root, &spc, &bps, &fc, &tc) || !spc || !bps)
        return 4096;
    return spc * bps;
}

static BOOL std_info(HANDLE h, LONGLONG *alloc, LONGLONG *eof)
{
    FILE_STANDARD_INFORMATION si;
    IO_STATUS_BLOCK io;
    if (NtQueryInformationFile(h, &io, &si, sizeof(si), FileStandardInformation) < 0)
        return FALSE;
    *alloc = si.AllocationSize.QuadPart;
    *eof = si.EndOfFile.QuadPart;
    return TRUE;
}

/* The allocation size a listing reports for @name in Dir. */
static BOOL list_alloc(const WCHAR *name, LONGLONG *alloc)
{
    UCHAR buf[1024];
    IO_STATUS_BLOCK io;
    UNICODE_STRING mask;
    HANDLE d = CreateFileW(Dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    NTSTATUS st;
    if (d == INVALID_HANDLE_VALUE)
        return FALSE;
    RtlInitUnicodeString(&mask, name);
    st = NtQueryDirectoryFile(d, NULL, NULL, NULL, &io, buf, sizeof(buf), FileDirectoryInformation, TRUE, &mask, TRUE);
    CloseHandle(d);
    if (st < 0)
        return FALSE;
    *alloc = ((PFILE_DIRECTORY_INFORMATION)buf)->AllocationSize.QuadPart;
    return TRUE;
}

static BOOL append_pattern(HANDLE h, LONGLONG from, LONGLONG to, LONGLONG cl, int *bad_alloc, LONGLONG *first_bad)
{
    static UCHAR b[65536];
    LONGLONG o, a, e;
    DWORD n, i;
    for (o = from; o < to; o += sizeof(b))
    {
        for (i = 0; i < sizeof(b); i++)
            b[i] = PA_PAT(o + i);
        if (!WriteFile(h, b, sizeof(b), &n, NULL) || n != sizeof(b))
            return FALSE;
        if (!std_info(h, &a, &e) || e != o + (LONGLONG)sizeof(b) || a != ((e + cl - 1) / cl) * cl)
        {
            if (!(*bad_alloc)++)
                *first_bad = e;
        }
    }
    return TRUE;
}

static void t_prealloc(void)
{
    WCHAR p[MAX_PATH], bait[MAX_PATH];
    static UCHAR b[65536];
    HANDLE h;
    DWORD n, i;
    LONGLONG cl = cluster_size(), a, e, o, bad_alloc_at = 0, la = 0;
    LARGE_INTEGER pos;
    int bad_alloc = 0, bad_zero = 0, bad_pat = 0, ok;

    /* Clusters with other data in them, free again before the file grows: stale bytes must stay hidden. */
    path(bait, L"pa-bait.bin");
    path(p, L"pa-grow.bin");
    h = CreateFileW(bait, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        memset(b, 0xEE, sizeof(b));
        for (i = 0; i < 16 * 16; i++)
            WriteFile(h, b, sizeof(b), &n, NULL);
        CloseHandle(h);
        DeleteFileW(bait);
    }
    h = CreateFileW(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        report("prealloc-setup", 0, "error %lu", GetLastError());
        return;
    }
    /* Growth in 64 KB steps: past 1 MB the driver allocates ahead, the allocation size NT sees follows the size. */
    ok = append_pattern(h, 0, 6 << 20, cl, &bad_alloc, &bad_alloc_at);
    report("prealloc-append", ok && !bad_alloc, "6 MB in 64 KB appends, %d steps with an allocation size other than the size rounded up (first at EOF %I64d)", bad_alloc, bad_alloc_at);
    ok = list_alloc(L"pa-grow.bin", &la) && std_info(h, &a, &e);
    report("prealloc-listing", ok && la == a, "listing says %I64d, the handle %I64d (size %I64d)", la, a, e);

    /* SetEndOfFile past the end, inside what was allocated ahead: the new bytes read as zeros. */
    pos.QuadPart = (6 << 20) + (512 << 10);
    ok = SetFilePointerEx(h, pos, NULL, FILE_BEGIN) && SetEndOfFile(h);
    pos.QuadPart = 6 << 20;
    SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    for (o = 6 << 20; ok && o < (6 << 20) + (512 << 10); o += sizeof(b))
    {
        if (!ReadFile(h, b, sizeof(b), &n, NULL) || n != sizeof(b))
        {
            ok = FALSE;
            break;
        }
        for (i = 0; i < n; i++)
            if (b[i])
                bad_zero++;
    }
    report("prealloc-extend-zero", ok && !bad_zero, "%d non-zero bytes in the 512 KB past the old end", bad_zero);
    ok = std_info(h, &a, &e) && e == (6 << 20) + (512 << 10) && a == ((e + cl - 1) / cl) * cl;
    report("prealloc-extend-alloc", ok, "alloc %I64d size %I64d", a, e);

    /* Shrink below the allocation, then grow again by appends. */
    pos.QuadPart = (3 << 20) + 100;
    ok = SetFilePointerEx(h, pos, NULL, FILE_BEGIN) && SetEndOfFile(h) && std_info(h, &a, &e) && a == ((e + cl - 1) / cl) * cl;
    report("prealloc-shrink", ok, "alloc %I64d size %I64d", a, e);
    pos.QuadPart = 3 << 20;
    SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    bad_alloc = 0;
    /* The 100 bytes past 3 MB stay; rewrite from the 3 MB mark in whole 64 KB blocks. */
    ok = append_pattern(h, 3 << 20, 5 << 20, cl, &bad_alloc, &bad_alloc_at);
    report("prealloc-regrow", ok && !bad_alloc, "%d steps with a wrong allocation size", bad_alloc);
    CloseHandle(h);

    /* Everything written reads back: after the close (which gives the allocation ahead back) and a reopen. */
    h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok = h != INVALID_HANDLE_VALUE && std_info(h, &a, &e);
    report("prealloc-close-alloc", ok && e == (5 << 20) && a == ((e + cl - 1) / cl) * cl, "alloc %I64d size %I64d", a, e);
    for (o = 0; ok && o < e; o += sizeof(b))
    {
        if (!ReadFile(h, b, sizeof(b), &n, NULL) || !n)
            break;
        for (i = 0; i < n; i++)
            if (b[i] != PA_PAT(o + i))
                bad_pat++;
    }
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
    report("prealloc-readback", ok && !bad_pat, "%d wrong bytes", bad_pat);
    DeleteFileW(p);
}

/* Free space after the close is the file's size plus a little metadata, not the allocation ahead of it (idle volume only). */
static void t_prealloc_space(void)
{
    WCHAR p[MAX_PATH];
    static UCHAR b[65536];
    HANDLE h;
    DWORD n;
    ULARGE_INTEGER f0, f1, f2, tot, tf;
    LONGLONG size = (5 << 20) + (256 << 10), o, used, back;
    WCHAR root[4] = { Dir[0], L':', L'\\', 0 };
    path(p, L"pa-space.bin");
    memset(b, 0x5a, sizeof(b));
    GetDiskFreeSpaceExW(root, &f0, &tot, &tf);
    h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        report("prealloc-space-setup", 0, "error %lu", GetLastError());
        return;
    }
    for (o = 0; o < size; o += sizeof(b))
        WriteFile(h, b, (DWORD)min((LONGLONG)sizeof(b), size - o), &n, NULL);
    GetDiskFreeSpaceExW(root, &f1, &tot, &tf);
    CloseHandle(h);
    GetDiskFreeSpaceExW(root, &f2, &tot, &tf);
    used = (LONGLONG)(f0.QuadPart - f2.QuadPart);
    report("prealloc-space-closed", used >= size && used < size + (1 << 20), "after close %I64d bytes used for %I64d of data (while open %I64d)",
           used, size, (LONGLONG)(f0.QuadPart - f1.QuadPart));
    DeleteFileW(p);
    GetDiskFreeSpaceExW(root, &f2, &tot, &tf);
    back = (LONGLONG)(f2.QuadPart - f0.QuadPart);
    report("prealloc-space-delete", back > -(1 << 20) && back < (1 << 20), "free space after the delete differs from the start by %I64d", back);
}


/* ---------------------------------------------------------------- concurrent commits (the journal I/O runs without the volume lock) */
/*
 * Threads that grow files in 64 KB steps (an allocation after the frees of the threads that delete), flush them
 * (FlushFileBuffers = a commit that must be complete when it returns), rename and delete, and check the content
 * after each close.  Several commits want to run at once and allocations follow frees: the paths of a second
 * committer waiting for the first, a growth waiting for the commit that covers a free, readers of metadata that is
 * being committed.  A file read back wrong, or an error that is not out of space, fails.
 */
#define CR_THREADS 6
static volatile LONG CrBad, CrErr, CrFiles, CrFlush;
#define CR_PAT(seed, o) ((UCHAR)((((o) * 13) + (seed) * 31 + 7) & 0xff))

static DWORD WINAPI commit_worker(LPVOID arg)
{
    DWORD id = (DWORD)(ULONG_PTR)arg, rnd = id * 2654435761u + 12345, n, i, step;
    static const DWORD sizes[] = { 3000, 70000, 300000, 1500000, 2500000 };
    UCHAR *buf = HeapAlloc(GetProcessHeap(), 0, 65536);
    WCHAR f[MAX_PATH], g[MAX_PATH];
    if (!buf)
        return 1;
    while (!Stop)
    {
        DWORD total, seed, o;
        HANDLE h;
        BOOL ok = TRUE;
        rnd = rnd * 1103515245u + 12345;
        total = sizes[(rnd >> 16) % 5];
        seed = (rnd >> 8) & 0xff;
        _snwprintf(f, MAX_PATH, L"%s\\cr%lu-%lu.bin", Dir, id, (DWORD)CrFiles % 7);
        h = CreateFileW(f, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            InterlockedIncrement(&CrErr);
            Sleep(10);
            continue;
        }
        for (o = 0, step = 0; o < total && ok && !Stop; o += n, step++)
        {
            n = min(65536, total - o);
            for (i = 0; i < n; i++)
                buf[i] = CR_PAT(seed, o + i);
            ok = WriteFile(h, buf, n, &n, NULL);
            if (ok && (step % 5) == (id % 5) && FlushFileBuffers(h))
                InterlockedIncrement(&CrFlush);
            else if (!ok)
                InterlockedIncrement(&CrErr);
        }
        if (ok && !Stop)
        {
            /* The content, through the same handle and after the close through a new one. */
            LARGE_INTEGER z = { 0 };
            SetFilePointerEx(h, z, NULL, FILE_BEGIN);
            for (o = 0; o < total; o += n)
            {
                if (!ReadFile(h, buf, 65536, &n, NULL) || !n)
                    break;
                for (i = 0; i < n; i++)
                    if (buf[i] != CR_PAT(seed, o + i))
                        InterlockedIncrement(&CrBad);
            }
            if (o != total)
                InterlockedIncrement(&CrBad);
        }
        CloseHandle(h);
        if (ok && !Stop)
        {
            h = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE)
                InterlockedIncrement(&CrBad);
            else
            {
                for (o = 0; o < total; o += n)
                {
                    if (!ReadFile(h, buf, 65536, &n, NULL) || !n)
                        break;
                    for (i = 0; i < n; i++)
                        if (buf[i] != CR_PAT(seed, o + i))
                            InterlockedIncrement(&CrBad);
                }
                if (o != total)
                    InterlockedIncrement(&CrBad);
                CloseHandle(h);
            }
        }
        InterlockedIncrement(&CrFiles);
        /* Delete (frees clusters the other threads' growth takes next), or rename over a spare name. */
        if (rnd & 0x400000)
        {
            _snwprintf(g, MAX_PATH, L"%s\\cr%lu-r.bin", Dir, id);
            MoveFileExW(f, g, MOVEFILE_REPLACE_EXISTING);
        }
        else
            DeleteFileW(f);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

static void t_commit_race(void)
{
    HANDLE t[CR_THREADS];
    DWORD i, t0;
    WCHAR f[MAX_PATH];
    Stop = 0;
    CrBad = CrErr = CrFiles = CrFlush = 0;
    for (i = 0; i < CR_THREADS; i++)
        t[i] = CreateThread(NULL, 0, commit_worker, (LPVOID)(ULONG_PTR)i, 0, NULL);
    for (t0 = GetTickCount(); GetTickCount() - t0 < 40000;)
    {
        Sleep(1000);
        InterlockedIncrement(&Current);
    }
    Stop = 1;
    i = WaitForMultipleObjects(CR_THREADS, t, TRUE, 180000);
    report("commit-race", i == WAIT_OBJECT_0 && !CrBad && !CrErr, "%ld files, %ld flushes, %ld wrong files or bytes, %ld errors",
           (long)CrFiles, (long)CrFlush, (long)CrBad, (long)CrErr);
    for (i = 0; i < CR_THREADS; i++)
    {
        _snwprintf(f, MAX_PATH, L"%s\\cr%lu-r.bin", Dir, i);
        DeleteFileW(f);
    }
}

/* ---------------------------------------------------------------- read a file with a known pattern */
static void t_read_pattern(const char *file)
{
    WCHAR w[MAX_PATH];
    static UCHAR b[65536];
    HANDLE h;
    DWORD n, i, bad = 0, err;
    LONGLONG total = 0;
    MultiByteToWideChar(CP_ACP, 0, file, -1, w, MAX_PATH);
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        report("read-pattern", 0, "open error %lu", GetLastError());
        return;
    }
    LARGE_INTEGER size = {0};
    BOOL rd;
    GetFileSizeEx(h, &size);
    while ((rd = ReadFile(h, b, sizeof(b), &n, NULL)) && n)
    {
        for (i = 0; i < n; i++)
            if (b[i] != (UCHAR)(((total + i) * 7 + 3) & 0xff))
                bad++;
        total += n;
    }
    err = rd ? 0 : GetLastError();
    CloseHandle(h);
    report("read-pattern", total > 0 && total == size.QuadPart && bad == 0 && !err,
           "%I64d of %I64d bytes, %lu wrong, read error %lu", total, size.QuadPart, bad, err);
}

int main(int argc, char **argv)
{
    char line[64];
    int all;
    if (argc < 3)
    {
        printf("usage: ngedge DIR TEST [ARG]\n");
        return 2;
    }
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, Dir, MAX_PATH);
    CreateDirectoryW(Dir, NULL);
    CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    all = !strcmp(argv[2], "all");
#define RUN(n, f) if (all || !strcmp(argv[2], n)) { TestName = n; InterlockedIncrement(&Current); f; }
    RUN("rename-subtree", t_rename_subtree());
    RUN("rename-cycle", t_rename_cycle());
    RUN("delete-open-stream", t_delete_open_stream());
    RUN("dir-async", t_dir_async());
    RUN("size-race", t_size_race());
    RUN("cache-mix", t_cache_mix());
    RUN("parallel", t_parallel());
    RUN("stream-reuse", t_stream_reuse());
    RUN("replace", t_replace());
    RUN("junction-dos", t_junction_dos());
    RUN("pool", t_pool());
    RUN("prealloc", t_prealloc());
    RUN("commit-race", t_commit_race());
    if (!strcmp(argv[2], "prealloc-space"))
    {
        TestName = "prealloc-space";
        t_prealloc_space();
    }
    if (!strcmp(argv[2], "read-pattern") && argc > 3)
        t_read_pattern(argv[3]);
    _snprintf(line, sizeof(line), "NGE:DONE pass=%d fail=%d\n", Pass, Fail);
    OutputDebugStringA(line);
    fputs(line, stdout);
    return Fail ? 1 : 0;
}
