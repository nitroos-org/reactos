/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Once every view of a file is unmapped and the mapping handle is closed, truncating the file
 *              (CREATE_ALWAYS, SetEndOfFile) must succeed at once, never with ERROR_USER_MAPPED_FILE.
 *              Runs on any file system: the directory comes from UMAPPED_DIR (default C:\\umapped), the
 *              rounds per thread from UMAPPED_ITER (default 300).  Run with 1 and with 8 threads.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdio.h>

#define MAXTHREADS 8
#define MAXSIZE (384 * 4096)

typedef struct
{
    ULONG Id;
    ULONG Iter;
    WCHAR Path[MAX_PATH];
    volatile LONG Fails;
    volatile LONG Refused;
    PUCHAR Data;
    BOOL MapOnly;
} CTX;

static BOOL MapAndTouch(HANDLE File, ULONG Size, ULONG Round)
{
    HANDLE Map;
    PUCHAR View;

    Map = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, Size, NULL);
    if (!Map)
        return FALSE;
    View = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, Size);
    if (!View)
    {
        CloseHandle(Map);
        return FALSE;
    }
    memset(View, (UCHAR)Round, Size);
    if (Round & 1)
        FlushViewOfFile(View, 0);
    UnmapViewOfFile(View);
    CloseHandle(Map);
    return TRUE;
}

static DWORD WINAPI Worker(PVOID Arg)
{
    CTX *c = Arg;
    ULONG i;

    c->Data = VirtualAlloc(NULL, MAXSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!c->Data)
    {
        InterlockedIncrement(&c->Fails);
        return 0;
    }
    memset(c->Data, 0xA5, MAXSIZE);
    for (i = 0; i < c->Iter; i++)
    {
        ULONG Size = 4096 * (1 + (i * 37) % 384);   /* 4 KB .. 1.5 MB */
        DWORD Written;
        HANDLE H = CreateFileW(c->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, CREATE_ALWAYS, 0, NULL);
        if (H == INVALID_HANDLE_VALUE)
        {
            DWORD Err = GetLastError();
            if (Err == ERROR_USER_MAPPED_FILE)
                InterlockedIncrement(&c->Refused);
            InterlockedIncrement(&c->Fails);
            if (c->Fails <= 3)
                trace("[t%lu] round %lu: CREATE_ALWAYS failed %lu\n", c->Id, i, Err);
            continue;
        }
        /* Dirty cached data first (the cache map of the file is torn down when the handle closes), then a view */
        if (c->MapOnly)
        {
            /* No cached I/O at all: the file is only ever reached through the view */
            LARGE_INTEGER Eof;
            Eof.QuadPart = Size;
            Written = Size;
            if (!SetFilePointerEx(H, Eof, NULL, FILE_BEGIN) || !SetEndOfFile(H))
                Written = 0;
        }
        else if (!WriteFile(H, c->Data, Size, &Written, NULL))
            Written = 0;
        if (Written != Size || !MapAndTouch(H, Size, i))
        {
            InterlockedIncrement(&c->Fails);
            trace("[t%lu] round %lu: setup failed %lu\n", c->Id, i, GetLastError());
            CloseHandle(H);
            continue;
        }
        /* Shrink through the still-open handle: the view and the mapping are both gone. */
        {
            LARGE_INTEGER Li;
            Li.QuadPart = 100;
            if (!SetFilePointerEx(H, Li, NULL, FILE_BEGIN) || !SetEndOfFile(H))
            {
                DWORD Err = GetLastError();
                if (Err == ERROR_USER_MAPPED_FILE)
                    InterlockedIncrement(&c->Refused);
                InterlockedIncrement(&c->Fails);
                if (c->Fails <= 3)
                    trace("[t%lu] round %lu: SetEndOfFile failed %lu\n", c->Id, i, Err);
            }
        }
        CloseHandle(H);
        /* Pace the rounds so that the lazy writer meets files whose last handle was just closed */
        Sleep(i % 4);
    }
    VirtualFree(c->Data, 0, MEM_RELEASE);
    return 0;
}

static volatile LONG StopChurn;
static WCHAR ChurnPath[MAX_PATH];

/* Keeps the lazy writer and the flush paths busy: big dirty cached writes to another file */
static DWORD WINAPI ChurnThread(PVOID Arg)
{
    PUCHAR Buf = VirtualAlloc(NULL, 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!Buf)
        return 0;
    memset(Buf, 0x5A, 1 << 20);
    while (!StopChurn)
    {
        HANDLE H = CreateFileW(ChurnPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ULONG i;
        DWORD Written;

        if (H == INVALID_HANDLE_VALUE)
            break;
        for (i = 0; i < 128 && !StopChurn; i++)
            WriteFile(H, Buf, 1 << 20, &Written, NULL);
        CloseHandle(H);
    }
    DeleteFileW(ChurnPath);
    VirtualFree(Buf, 0, MEM_RELEASE);
    return 0;
}

/* Memory pressure: empties the working set and touches memory, so cached and mapped pages are stolen */
static DWORD WINAPI PressureThread(PVOID Arg)
{
    BOOL (WINAPI *Empty)(HANDLE) = NULL;
    HMODULE Psapi = LoadLibraryW(L"psapi.dll");
    ULONG n = 0;

    if (Psapi)
        Empty = (PVOID)GetProcAddress(Psapi, "EmptyWorkingSet");
    while (!StopChurn)
    {
        PUCHAR Mem;

        if (Empty)
            Empty(GetCurrentProcess());
        if ((n++ % 4) == 0 && (Mem = VirtualAlloc(NULL, 64 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        {
            ULONG i;
            for (i = 0; i < (64u << 20); i += 4096)
                Mem[i] = 1;
            VirtualFree(Mem, 0, MEM_RELEASE);
        }
        Sleep(20);
    }
    return 0;
}

/*
 * A mix of the operations an application does to one file in a row: rewrite it (CREATE_ALWAYS), change its
 * size, write through a view.  Every mapping is closed (view and handle) before the next operation, so the
 * rewrite and the size change must never be refused.
 */
static DWORD WINAPI MixWorker(PVOID Arg)
{
    CTX *c = Arg;
    ULONG i, Rng = 0x9e3779b9 * (c->Id + 1) + GetTickCount();
    BOOL Exists = FALSE;

    c->Data = VirtualAlloc(NULL, MAXSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!c->Data)
    {
        InterlockedIncrement(&c->Fails);
        return 0;
    }
    memset(c->Data, 0xA5, MAXSIZE);
    for (i = 0; i < c->Iter; i++)
    {
        ULONG Op, Size;
        HANDLE H;
        DWORD Written, Err;

        Rng = Rng * 1103515245 + 12345;
        Op = (Rng >> 16) % 100;
        Rng = Rng * 1103515245 + 12345;
        Size = 4096 * (1 + ((Rng >> 16) % 384));
        if (!Exists || Op < 35)
        {
            H = CreateFileW(c->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            CREATE_ALWAYS, 0, NULL);
            if (H == INVALID_HANDLE_VALUE)
            {
                Err = GetLastError();
                if (Err == ERROR_USER_MAPPED_FILE)
                    InterlockedIncrement(&c->Refused);
                InterlockedIncrement(&c->Fails);
                if (c->Fails <= 3)
                    trace("[t%lu] round %lu: CREATE_ALWAYS failed %lu\n", c->Id, i, Err);
                continue;
            }
            Exists = TRUE;
            WriteFile(H, c->Data, Size, &Written, NULL);
            CloseHandle(H);
        }
        else if (Op < 75)
        {
            H = CreateFileW(c->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, 0, NULL);
            if (H != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER Len;
                if (GetFileSizeEx(H, &Len) && Len.QuadPart > 0 && Len.QuadPart <= MAXSIZE)
                    MapAndTouch(H, (ULONG)Len.QuadPart, i);
                CloseHandle(H);
            }
        }
        else
        {
            H = CreateFileW(c->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, 0, NULL);
            if (H != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER Pos;
                Pos.QuadPart = Size;
                if (!SetFilePointerEx(H, Pos, NULL, FILE_BEGIN) || !SetEndOfFile(H))
                {
                    Err = GetLastError();
                    if (Err == ERROR_USER_MAPPED_FILE)
                        InterlockedIncrement(&c->Refused);
                    InterlockedIncrement(&c->Fails);
                    if (c->Fails <= 3)
                        trace("[t%lu] round %lu: SetEndOfFile failed %lu\n", c->Id, i, Err);
                }
                CloseHandle(H);
            }
        }
    }
    VirtualFree(c->Data, 0, MEM_RELEASE);
    return 0;
}

static void RunThreads(PCWSTR Dir, ULONG Count, ULONG Iter, BOOL Churn, BOOL MapOnly, BOOL Mix)
{
    HANDLE ChurnThr = NULL, PressThr = NULL;

    static CTX Ctx[MAXTHREADS];
    HANDLE Thr[MAXTHREADS];
    ULONG i;
    LONG Fails = 0, Refused = 0;

    if (Churn)
    {
        StopChurn = 0;
        _snwprintf(ChurnPath, MAX_PATH, L"%ls\\churn.bin", Dir);
        ChurnThr = CreateThread(NULL, 0, ChurnThread, NULL, 0, NULL);
        PressThr = CreateThread(NULL, 0, PressureThread, NULL, 0, NULL);
    }
    for (i = 0; i < Count; i++)
    {
        Ctx[i].Id = i;
        Ctx[i].MapOnly = MapOnly;
        Ctx[i].Iter = Iter;
        Ctx[i].Fails = Ctx[i].Refused = 0;
        _snwprintf(Ctx[i].Path, MAX_PATH, L"%ls\\f%lu.bin", Dir, i);
        Thr[i] = CreateThread(NULL, 0, Mix ? MixWorker : Worker, &Ctx[i], 0, NULL);
        ok(Thr[i] != NULL, "CreateThread failed %lu\n", GetLastError());
        if (!Thr[i])
            return;
    }
    WaitForMultipleObjects(Count, Thr, TRUE, INFINITE);
    if (ChurnThr)
    {
        StopChurn = 1;
        WaitForSingleObject(ChurnThr, INFINITE);
        CloseHandle(ChurnThr);
        if (PressThr)
        {
            WaitForSingleObject(PressThr, INFINITE);
            CloseHandle(PressThr);
        }
    }
    for (i = 0; i < Count; i++)
    {
        CloseHandle(Thr[i]);
        Fails += Ctx[i].Fails;
        Refused += Ctx[i].Refused;
        DeleteFileW(Ctx[i].Path);
    }
    ok(Refused == 0, "%lu threads: %ld operations refused with ERROR_USER_MAPPED_FILE\n", Count, Refused);
    ok(Fails == 0, "%lu threads: %ld failures\n", Count, Fails);
}

START_TEST(UMapped)
{
    WCHAR Dir[MAX_PATH];
    WCHAR Env[MAX_PATH];
    ULONG Iter = 300;

    if (!GetEnvironmentVariableW(L"UMAPPED_DIR", Dir, MAX_PATH))
        wcscpy(Dir, L"C:\\umapped");
    if (GetEnvironmentVariableW(L"UMAPPED_ITER", Env, MAX_PATH))
        Iter = wcstoul(Env, NULL, 10);
    CreateDirectoryW(Dir, NULL);

    RunThreads(Dir, 1, Iter, FALSE, FALSE, FALSE);
    RunThreads(Dir, 8, Iter, FALSE, FALSE, FALSE);
    RunThreads(Dir, 8, Iter, TRUE, FALSE, FALSE);
    RunThreads(Dir, 1, Iter, FALSE, TRUE, FALSE);
    RunThreads(Dir, 8, Iter, FALSE, TRUE, FALSE);
    RunThreads(Dir, 8, Iter, TRUE, TRUE, FALSE);
    RunThreads(Dir, 1, Iter, FALSE, FALSE, TRUE);
    RunThreads(Dir, 8, Iter, FALSE, FALSE, TRUE);
    RunThreads(Dir, 8, Iter, TRUE, FALSE, TRUE);
    RemoveDirectoryW(Dir);
}
