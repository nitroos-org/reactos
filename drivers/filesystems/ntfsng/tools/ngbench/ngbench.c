/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     File system benchmark: small-file create/delete, sequential and random I/O,
 *              directory listing and parallel readers; ops/s and MB/s per workload, plus the
 *              ntfsng CoreLock statistics of each workload when the volume is ntfsng
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NG_LOCK_CATEGORIES (0x1b + 4)
#define FSCTL_NG_LOCK_STATS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0xA41, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct
{
    ULONG Acquired, Contended;
    ULONGLONG WaitUs, HeldUs;
} LOCK_STAT;

typedef struct
{
    ULONG Version, Categories;
    LOCK_STAT Stat[NG_LOCK_CATEGORIES];
} LOCKS;
#define NG_PROFILE_STAGES 64
#define FSCTL_NG_PROFILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0xA42, METHOD_BUFFERED, FILE_WRITE_ACCESS)
typedef struct
{
    ULONGLONG Count, Ticks, Bytes;
} PROF_STAT;
typedef struct
{
    ULONG Version, Stages;
    ULONGLONG TicksPerSecond;
    PROF_STAT Stage[NG_PROFILE_STAGES];
} PROFILE;
typedef struct
{
    LOCKS L;
    PROFILE P;
    BOOL HaveP;
} LOCK_STATS;
static const char *StageName[NG_PROFILE_STAGES] = {
    "dev-read", "dev-write", "dev-flush", "commit", "writeback", "jnl-commit", "commit-full", "commit-alloc",
    "sync", "lookup", "create", "unlink", "rename", "readdir", "iget", "put", "stat", "read", "write", "set-size",
    "set-info", "short-name", "add-short-name", "security", "dir-empty", "link", "dirwalk", "skip-taken", "skip-checked",
    "skip-wrong", "skip-raced", "resv-retry" };

static const char *CatName[NG_LOCK_CATEGORIES] = {
    "create", "pipe", "close", "read", "write", "queryinfo", "setinfo", "queryea", "setea", "flush",
    "queryvol", "setvol", "dirctl", "fsctl", "devctl", "intdevctl", "shutdown", "lock", "cleanup",
    "mailslot", "querysec", "setsec", "power", "syscontrol", "devchange", "queryquota", "setquota", "pnp",
    "pagingread", "pagingwrite", "noirp" };

static char Root[MAX_PATH];
static HANDLE Volume = INVALID_HANDLE_VALUE;
static LARGE_INTEGER Freq;
static BYTE *Big;                       /* 1 MB, sector aligned */
#define CHUNK (1024 * 1024)

static double Now(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)Freq.QuadPart;
}

static BOOL Snap(LOCK_STATS *s)
{
    DWORD n;
    memset(s, 0, sizeof(*s));
    if (Volume == INVALID_HANDLE_VALUE)
        return FALSE;
    s->HaveP = DeviceIoControl(Volume, FSCTL_NG_PROFILE, NULL, 0, &s->P, sizeof(s->P), &n, NULL) && n == sizeof(s->P);
    return DeviceIoControl(Volume, FSCTL_NG_LOCK_STATS, NULL, 0, &s->L, sizeof(s->L), &n, NULL) && n == sizeof(s->L);
}

static void LockReport(const char *wl, const LOCK_STATS *a, const LOCK_STATS *b)
{
    int i;
    ULONG acq = 0, cont = 0;
    ULONGLONG wait = 0, held = 0;
    char line[512];
    for (i = 0; i < NG_LOCK_CATEGORIES; i++)
    {
        ULONG da = b->L.Stat[i].Acquired - a->L.Stat[i].Acquired;
        ULONG dc = b->L.Stat[i].Contended - a->L.Stat[i].Contended;
        ULONGLONG dw = b->L.Stat[i].WaitUs - a->L.Stat[i].WaitUs, dh = b->L.Stat[i].HeldUs - a->L.Stat[i].HeldUs;
        if (!da)
            continue;
        acq += da; cont += dc; wait += dw; held += dh;
        _snprintf(line, sizeof(line), "NGB-LOCK:%s %s acq=%lu cont=%lu wait_ms=%.1f held_ms=%.1f\n", wl, CatName[i],
                  da, dc, dw / 1000.0, dh / 1000.0);
        OutputDebugStringA(line);
        fputs(line, stdout);
    }
    _snprintf(line, sizeof(line), "NGB-LOCK:%s TOTAL acq=%lu cont=%lu wait_ms=%.1f held_ms=%.1f\n", wl, acq, cont,
              wait / 1000.0, held / 1000.0);
    OutputDebugStringA(line);
    fputs(line, stdout);
    if (!a->HaveP || !b->HaveP || !b->P.TicksPerSecond)
        return;
    for (i = 0; i < NG_PROFILE_STAGES; i++)
    {
        ULONGLONG dc = b->P.Stage[i].Count - a->P.Stage[i].Count;
        double ms = (double)(b->P.Stage[i].Ticks - a->P.Stage[i].Ticks) * 1000.0 / (double)b->P.TicksPerSecond;
        char nm[32];
        if (!dc)
            continue;
        if (i >= 32)
            _snprintf(nm, sizeof(nm), "irp-%s", CatName[i - 32]);
        else
            _snprintf(nm, sizeof(nm), "%s", StageName[i] ? StageName[i] : "?");
        _snprintf(line, sizeof(line), "NGB-PROF:%s %s n=%I64u ms=%.1f us_each=%.1f kb=%I64u\n", wl, nm, dc, ms,
                  ms * 1000.0 / (double)dc, (b->P.Stage[i].Bytes - a->P.Stage[i].Bytes) / 1024);
        OutputDebugStringA(line);
        fputs(line, stdout);
    }
}

static void Report(const char *wl, int threads, double ops, double bytes, double secs, const LOCK_STATS *a,
                   const LOCK_STATS *b, BOOL haveLock)
{
    char line[256];
    _snprintf(line, sizeof(line), "NGB:%s threads=%d secs=%.2f ops=%.0f ops_s=%.1f MB_s=%.2f\n", wl, threads, secs, ops,
              secs > 0 ? ops / secs : 0, secs > 0 ? bytes / secs / 1048576.0 : 0);
    OutputDebugStringA(line);
    fputs(line, stdout);
    if (haveLock)
        LockReport(wl, a, b);
    fflush(stdout);
}

/* ---- small files: create (write 4 KB) and delete, one thread per directory */

typedef struct
{
    int Id, Count, Phase;               /* phase 0 create, 1 delete */
    LONG Fail;
} SMALL;

static DWORD WINAPI SmallThread(LPVOID p)
{
    SMALL *s = p;
    char path[MAX_PATH];
    int i;
    for (i = 0; i < s->Count; i++)
    {
        _snprintf(path, sizeof(path), "%s\\s%d\\file%05d.dat", Root, s->Id, i);
        if (s->Phase == 0)
        {
            HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            DWORD n;
            if (h == INVALID_HANDLE_VALUE || !WriteFile(h, Big, 4096, &n, NULL) || n != 4096)
                s->Fail++;
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
        else if (!DeleteFileA(path))
            s->Fail++;
    }
    return 0;
}

static void SmallFiles(int threads, int perThread)
{
    SMALL s[16];
    HANDLE th[16];
    LOCK_STATS a, b;
    BOOL lk;
    char path[MAX_PATH], name[64];
    int i, phase;
    for (i = 0; i < threads; i++)
    {
        _snprintf(path, sizeof(path), "%s\\s%d", Root, i);
        CreateDirectoryA(path, NULL);
    }
    for (phase = 0; phase < 2; phase++)
    {
        double t0, t1;
        LONG fail = 0;
        lk = Snap(&a);
        t0 = Now();
        for (i = 0; i < threads; i++)
        {
            s[i].Id = i; s[i].Count = perThread; s[i].Phase = phase; s[i].Fail = 0;
            th[i] = CreateThread(NULL, 0, SmallThread, &s[i], 0, NULL);
        }
        WaitForMultipleObjects(threads, th, TRUE, INFINITE);
        t1 = Now();
        lk = lk && Snap(&b);
        for (i = 0; i < threads; i++)
        {
            CloseHandle(th[i]);
            fail += s[i].Fail;
        }
        _snprintf(name, sizeof(name), "small-%s-t%d%s", phase ? "delete" : "create", threads, fail ? "-ERRORS" : "");
        Report(name, threads, (double)threads * perThread, phase ? 0 : (double)threads * perThread * 4096, t1 - t0, &a, &b, lk);
    }
    for (i = 0; i < threads; i++)
    {
        _snprintf(path, sizeof(path), "%s\\s%d", Root, i);
        RemoveDirectoryA(path);
    }
}

/* ---- sequential and random I/O */

static double WriteFileSeq(const char *path, ULONGLONG size, BOOL nocache)
{
    DWORD flags = nocache ? FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH : 0, n;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, flags, NULL);
    ULONGLONG done;
    double t0, t1;
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    t0 = Now();
    for (done = 0; done < size; done += CHUNK)
        if (!WriteFile(h, Big, CHUNK, &n, NULL) || n != CHUNK)
        {
            CloseHandle(h);
            return -1;
        }
    FlushFileBuffers(h);
    t1 = Now();
    CloseHandle(h);
    return t1 - t0;
}

static double ReadFileSeq(const char *path, BOOL nocache)
{
    DWORD flags = nocache ? FILE_FLAG_NO_BUFFERING : FILE_FLAG_SEQUENTIAL_SCAN, n;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, flags, NULL);
    double t0, t1;
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    t0 = Now();
    while (ReadFile(h, Big, CHUNK, &n, NULL) && n)
        ;
    t1 = Now();
    CloseHandle(h);
    return t1 - t0;
}

static double RandomReads(const char *path, ULONGLONG size, int count, BOOL nocache)
{
    DWORD flags = nocache ? FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS : FILE_FLAG_RANDOM_ACCESS, n;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, flags, NULL);
    ULONG blocks = (ULONG)(size / 4096), seed = 12345;
    double t0, t1;
    int i;
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    t0 = Now();
    for (i = 0; i < count; i++)
    {
        LARGE_INTEGER off;
        seed = seed * 1103515245 + 12345;
        off.QuadPart = (LONGLONG)((seed >> 4) % blocks) * 4096;
        SetFilePointerEx(h, off, NULL, FILE_BEGIN);
        if (!ReadFile(h, Big, 4096, &n, NULL) || n != 4096)
        {
            CloseHandle(h);
            return -1;
        }
    }
    t1 = Now();
    CloseHandle(h);
    return t1 - t0;
}

static void Sequential(ULONGLONG size)
{
    char cpath[MAX_PATH], npath[MAX_PATH];
    LOCK_STATS a, b;
    BOOL lk;
    double t;
    _snprintf(cpath, sizeof(cpath), "%s\\seq-cached.dat", Root);
    _snprintf(npath, sizeof(npath), "%s\\seq-nocache.dat", Root);

    lk = Snap(&a); t = WriteFileSeq(cpath, size, FALSE); lk = lk && Snap(&b);
    Report(t < 0 ? "seqwrite-cached-ERROR" : "seqwrite-cached", 1, (double)(size / CHUNK), (double)size, t, &a, &b, lk);
    ReadFileSeq(cpath, FALSE);
    lk = Snap(&a); t = ReadFileSeq(cpath, FALSE); lk = lk && Snap(&b);
    Report(t < 0 ? "seqread-cached-ERROR" : "seqread-cached", 1, (double)(size / CHUNK), (double)size, t, &a, &b, lk);
    lk = Snap(&a); t = RandomReads(cpath, size, 20000, FALSE); lk = lk && Snap(&b);
    Report(t < 0 ? "rand4k-cached-ERROR" : "rand4k-cached", 1, 20000, 20000.0 * 4096, t, &a, &b, lk);

    lk = Snap(&a); t = WriteFileSeq(npath, size, TRUE); lk = lk && Snap(&b);
    Report(t < 0 ? "seqwrite-nocache-ERROR" : "seqwrite-nocache", 1, (double)(size / CHUNK), (double)size, t, &a, &b, lk);
    lk = Snap(&a); t = ReadFileSeq(npath, TRUE); lk = lk && Snap(&b);
    Report(t < 0 ? "seqread-nocache-ERROR" : "seqread-nocache", 1, (double)(size / CHUNK), (double)size, t, &a, &b, lk);
    lk = Snap(&a); t = RandomReads(npath, size, 4000, TRUE); lk = lk && Snap(&b);
    Report(t < 0 ? "rand4k-nocache-ERROR" : "rand4k-nocache", 1, 4000, 4000.0 * 4096, t, &a, &b, lk);
    DeleteFileA(cpath);
    DeleteFileA(npath);
}

/* ---- directory listing */

static void DirList(int entries, int passes)
{
    char dir[MAX_PATH], path[MAX_PATH], pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    LOCK_STATS a, b;
    BOOL lk;
    double t0, t1;
    long seen = 0;
    int i;
    _snprintf(dir, sizeof(dir), "%s\\list", Root);
    CreateDirectoryA(dir, NULL);
    for (i = 0; i < entries; i++)
    {
        HANDLE h;
        _snprintf(path, sizeof(path), "%s\\entry-with-a-longer-name-%05d.txt", dir, i);
        h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    _snprintf(pat, sizeof(pat), "%s\\*", dir);
    lk = Snap(&a);
    t0 = Now();
    for (i = 0; i < passes; i++)
    {
        HANDLE f = FindFirstFileA(pat, &fd);
        if (f == INVALID_HANDLE_VALUE)
            break;
        do
            seen++;
        while (FindNextFileA(f, &fd));
        FindClose(f);
    }
    t1 = Now();
    lk = lk && Snap(&b);
    Report(seen == (long)passes * (entries + 2) ? "dirlist" : "dirlist-COUNT-MISMATCH", 1, (double)seen, 0, t1 - t0, &a, &b, lk);
    for (i = 0; i < entries; i++)
    {
        _snprintf(path, sizeof(path), "%s\\entry-with-a-longer-name-%05d.txt", dir, i);
        DeleteFileA(path);
    }
    RemoveDirectoryA(dir);
}

/* ---- parallel readers, one file each */

typedef struct
{
    char Path[MAX_PATH];
    BOOL NoCache;
    double Secs;
} READER;

static DWORD WINAPI ReaderThread(LPVOID p)
{
    READER *r = p;
    r->Secs = ReadFileSeq(r->Path, r->NoCache);
    return 0;
}

static void ParallelReaders(int threads, ULONGLONG size)
{
    READER r[16];
    HANDLE th[16];
    LOCK_STATS a, b;
    BOOL lk;
    char name[64];
    int i, nc;
    for (i = 0; i < threads; i++)
    {
        _snprintf(r[i].Path, sizeof(r[i].Path), "%s\\par%d.dat", Root, i);
        WriteFileSeq(r[i].Path, size, TRUE);
    }
    for (nc = 1; nc >= 0; nc--)
    {
        double t0, t1;
        BOOL bad = FALSE;
        if (!nc)
            for (i = 0; i < threads; i++)
                ReadFileSeq(r[i].Path, FALSE);      /* warm the cache */
        lk = Snap(&a);
        t0 = Now();
        for (i = 0; i < threads; i++)
        {
            r[i].NoCache = nc;
            th[i] = CreateThread(NULL, 0, ReaderThread, &r[i], 0, NULL);
        }
        WaitForMultipleObjects(threads, th, TRUE, INFINITE);
        t1 = Now();
        lk = lk && Snap(&b);
        for (i = 0; i < threads; i++)
        {
            CloseHandle(th[i]);
            bad |= r[i].Secs < 0;
        }
        _snprintf(name, sizeof(name), "parread-%s-t%d%s", nc ? "nocache" : "cached", threads, bad ? "-ERROR" : "");
        Report(name, threads, (double)threads * (size / CHUNK), (double)threads * size, t1 - t0, &a, &b, lk);
    }
    for (i = 0; i < threads; i++)
        DeleteFileA(r[i].Path);
}

int main(int argc, char **argv)
{
    char vol[8] = "\\\\.\\C:", line[128];
    int threads = 4, i;
    ULONGLONG mb = 64;
    SYSTEM_INFO si;
    LOCK_STATS s;

    if (argc < 2)
    {
        fprintf(stderr, "usage: ngbench DIR [-threads N] [-mb SIZE]\n");
        return 2;
    }
    strncpy(Root, argv[1], sizeof(Root) - 1);
    for (i = 2; i + 1 < argc; i += 2)
    {
        if (!strcmp(argv[i], "-threads")) threads = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "-mb")) mb = (ULONGLONG)atoi(argv[i + 1]);
    }
    if (threads < 1) threads = 1;
    if (threads > 16) threads = 16;
    QueryPerformanceFrequency(&Freq);
    Big = VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Big)
        return 3;
    for (i = 0; i < CHUNK; i++)
        Big[i] = (BYTE)(i * 7);
    CreateDirectoryA(Root, NULL);
    vol[4] = Root[0];
    Volume = CreateFileA(vol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Volume == INVALID_HANDLE_VALUE)
        Volume = CreateFileA(vol, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    GetSystemInfo(&si);
    {
        BOOL ok = Snap(&s);
        _snprintf(line, sizeof(line), "NGB:START root=%s cpus=%lu threads=%d mb=%I64u ntfsng_lock_stats=%s (volume %s, error %lu)\n",
                  Root, si.dwNumberOfProcessors, threads, mb, ok ? "yes" : "no",
                  Volume == INVALID_HANDLE_VALUE ? "not opened" : "open", ok ? 0 : GetLastError());
    }
    OutputDebugStringA(line);
    fputs(line, stdout);

    SmallFiles(1, 1000);
    SmallFiles(threads, 1000);
    Sequential(mb * CHUNK);
    DirList(2000, 20);
    ParallelReaders(1, mb / 2 * CHUNK);
    ParallelReaders(threads, mb / 2 * CHUNK);

    OutputDebugStringA("NGB:DONE\n");
    fputs("NGB:DONE\n", stdout);
    if (Volume != INVALID_HANDLE_VALUE)
        CloseHandle(Volume);
    RemoveDirectoryA(Root);
    return 0;
}
