/*
 * PROJECT:     ReactOS-Nitro rostests
 * PURPOSE:     Pager phase H: memory-pressure soak and data-integrity harness (in-guest part)
 * COPYRIGHT:   Copyright 2026 reactos-nitro contributors
 * LICENSE:     GPL-2.0-or-later (see COPYING in the top level directory)
 *
 * pagersoak.exe sup  [key=value ...]   supervisor: starts the workers, trims, counts, writes the verdict
 * pagersoak.exe wrk  [key=value ...]   private-memory writer/verifier (started by sup)
 * pagersoak.exe sect [key=value ...]   section writer or reader (started by sup)
 * pagersoak.exe fck  [key=value ...]   file integrity writer with an intent/ack log (started by sup)
 * pagersoak.exe stop|help
 * See process/PAGER-DESIGN.md (phase H) and tooling/pager-soak/README.md in the harness repo.
 *
 * Output: lines "PAGERH:..." in <dir>\sup.txt and on COM2; per worker <dir>\w<id>.txt.
 * Everything here uses documented Win32 calls; the only native calls are NtQuerySystemInformation
 * (SystemPerformanceInformation, SystemMemoryListInformation) and NtSetSystemInformation(SystemMemoryListInformation).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef LONG (NTAPI *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *PFN_NTSSI)(ULONG, PVOID, ULONG);

#define PAGE 4096
#define REGION_PAGES 2048            /* 8 MB regions */
#define HB_SLOTS 64
#define MAX_WORKERS 40
#define PH_MAGIC 0x50414745u         /* 'PAGE' */
#define DEAD_GEN 0xFFFFFFFFu         /* page of a chunk that could not be recommitted: skipped */

/* exit codes of worker processes */
#define EXIT_OK        0
#define EXIT_MISMATCH  3
#define EXIT_DENIED    4             /* committed less than asked: commit refused, not a failure */
#define EXIT_INTERNAL  5

/* ---------- small helpers ---------- */
static u64 mix64(u64 x)
{
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

static const char *Arg(int argc, char **argv, const char *key, const char *def)
{
    size_t n = strlen(key);
    int i;
    for (i = 2; i < argc; i++)
        if (!strncmp(argv[i], key, n) && argv[i][n] == '=')
            return argv[i] + n + 1;
    return def;
}
static long ArgL(int argc, char **argv, const char *key, long def)
{
    const char *v = Arg(argc, argv, key, NULL);
    return v ? atol(v) : def;
}

static char gDir[MAX_PATH] = "C:\\pagerh";
static CRITICAL_SECTION gOutCs;
static FILE *gOut;
static HANDLE gCom = INVALID_HANDLE_VALUE;
static int gToCom;

static void Say(const char *fmt, ...)
{
    char b[1024];
    int n;
    va_list ap;
    DWORD w;
    va_start(ap, fmt);
    n = _vsnprintf(b, sizeof(b) - 2, fmt, ap);
    va_end(ap);
    if (n < 0 || n > (int)sizeof(b) - 3) n = sizeof(b) - 3;
    b[n++] = '\n'; b[n] = 0;
    EnterCriticalSection(&gOutCs);
    if (gOut) { fputs(b, gOut); fflush(gOut); }
    if (gToCom && gCom != INVALID_HANDLE_VALUE) WriteFile(gCom, b, n, &w, NULL);
    LeaveCriticalSection(&gOutCs);
}

static void PathIn(char *dst, size_t cap, const char *name)
{
    _snprintf(dst, cap - 1, "%s\\%s", gDir, name);
    dst[cap - 1] = 0;
}

static void EnablePriv(const char *name)
{
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(t, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(t);
}

/* ---------- shared heartbeat section (supervisor <-> workers) ---------- */
typedef struct _HBSLOT
{
    volatile LONG Pid, State, Ops, Mism, Denied, Ready, Ticks[4], Pages, Pad[5];
} HBSLOT;                                /* 64 bytes */
static HBSLOT *gHb;

/* ---------- page pattern ---------- */
typedef struct _PHDR
{
    u32 Magic, Seed, Page, Gen;
    u64 Addr, Ck;
} PHDR;                                  /* 32 bytes */

static u64 BodyCk(const u64 *w, int n)
{
    u64 h = 0xCBF29CE484222325ULL;
    int i;
    for (i = 0; i < n; i++) { h ^= w[i]; h *= 0x100000001B3ULL; h ^= h >> 29; }
    return h;
}
static void FillPage(void *pg, u32 seed, u32 page, u32 gen)
{
    PHDR *h = pg;
    u64 *w = (u64 *)((char *)pg + sizeof(PHDR));
    int n = (PAGE - sizeof(PHDR)) / 8, i;
    u64 key = ((u64)seed << 32) ^ ((u64)page * 0x9E3779B1ULL) ^ ((u64)gen << 8);
    for (i = 0; i < n; i++) w[i] = mix64(key + i);
    h->Magic = PH_MAGIC; h->Seed = seed; h->Page = page; h->Gen = gen;
    h->Addr = (u64)(ULONG_PTR)pg;
    h->Ck = BodyCk(w, n);
}
/* returns 0 ok, else a code: 1 magic, 2 seed, 3 page, 4 gen, 5 addr, 6 checksum */
static int CheckPage(const void *pg, u32 seed, u32 page, u32 gen)
{
    const PHDR *h = pg;
    const u64 *w = (const u64 *)((const char *)pg + sizeof(PHDR));
    if (h->Magic != PH_MAGIC) return 1;
    if (h->Seed != seed) return 2;
    if (h->Page != page) return 3;
    if (h->Gen != gen) return 4;
    if (h->Addr != (u64)(ULONG_PTR)pg) return 5;
    if (h->Ck != BodyCk(w, (PAGE - sizeof(PHDR)) / 8)) return 6;
    return 0;
}

/* ====================================================================== */
/* worker                                                                  */
/* ====================================================================== */
typedef struct _WK
{
    int Id, Inst, Threads, WPct, Mix;
    u32 Seed;
    size_t Pages;
    char *Regions[256];
    u32 *Gens;                           /* expected generation of every page */
    HBSLOT *Slot;
    DWORD EndTick;
    volatile LONG Stop;
    volatile LONG Mism, MismLogged, Ops, Rewrites;
    CRITICAL_SECTION Cs[8];              /* per thread; the main thread takes all to pause the others */
    HANDLE Log;
} WK;
static WK W;

static int StopFile(void)
{
    char sp[MAX_PATH];
    _snprintf(sp, sizeof(sp) - 1, "%s\\stop", gDir); sp[sizeof(sp) - 1] = 0;
    return GetFileAttributesA(sp) != INVALID_FILE_ATTRIBUTES;
}

static char *PagePtr(size_t p) { return W.Regions[p / REGION_PAGES] + (p % REGION_PAGES) * PAGE; }

static void WLog(const char *fmt, ...)
{
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(b, sizeof(b) - 1, fmt, ap);
    va_end(ap);
    b[sizeof(b) - 1] = 0;
    Say("PAGERH:W%d.%d %s", W.Id, W.Inst, b);
}

static void Mismatch(size_t p, int code, const char *why)
{
    LONG n = InterlockedIncrement(&W.Mism);
    InterlockedIncrement(&W.Slot->Mism);
    if (InterlockedIncrement(&W.MismLogged) <= 24)
    {
        const PHDR *h = (const PHDR *)PagePtr(p);
        int again = CheckPage(PagePtr(p), W.Seed, (u32)p, W.Gens[p]);
        WLog("MISMATCH #%ld %s page=%lu code=%d want gen=%lu | hdr magic=%08lx seed=%08lx page=%lu gen=%lu addr=%llx | recheck=%s",
             n, why, (unsigned long)p, code, (unsigned long)W.Gens[p], (unsigned long)h->Magic, (unsigned long)h->Seed,
             (unsigned long)h->Page, (unsigned long)h->Gen, h->Addr, again ? "STILL-BAD" : "now-ok(transient)");
    }
    /* keep going with a fresh generation so one bad page is counted once */
    W.Gens[p]++;
    FillPage(PagePtr(p), W.Seed, (u32)p, W.Gens[p]);
}

static void VerifyPage(size_t p, const char *why)
{
    int c;
    if (W.Gens[p] == DEAD_GEN) return;
    c = CheckPage(PagePtr(p), W.Seed, (u32)p, W.Gens[p]);
    if (c) Mismatch(p, c, why);
}

static DWORD WINAPI WThread(LPVOID a)
{
    int t = (int)(ULONG_PTR)a;
    size_t n = 0, k, step, i;
    u64 r = mix64(W.Seed + t);
    for (i = t; i < W.Pages; i += W.Threads) n++;
    if (!n) return 0;
    /* walk the thread's pages in a permutation: step coprime with n */
    step = (size_t)(n * 0.6180339887) | 1;
    for (;;)
    {
        size_t a1 = step, b1 = n, tt;
        while (b1) { tt = a1 % b1; a1 = b1; b1 = tt; }
        if (a1 == 1) break;
        step += 2;
    }
    k = (size_t)(mix64(r) % n);
    while (!W.Stop)
    {
        int batch;
        EnterCriticalSection(&W.Cs[t]);
        for (batch = 0; batch < 64 && !W.Stop; batch++)
        {
            size_t p = t + k * W.Threads;
            k = (k + step) % n;
            VerifyPage(p, "verify");
            r = mix64(r);
            if (W.Gens[p] != DEAD_GEN && (int)(r % 100) < W.WPct)
            {
                W.Gens[p]++;
                FillPage(PagePtr(p), W.Seed, (u32)p, W.Gens[p]);
                InterlockedIncrement(&W.Rewrites);
            }
            InterlockedIncrement(&W.Ops);
            InterlockedIncrement(&W.Slot->Ops);
        }
        LeaveCriticalSection(&W.Cs[t]);
        W.Slot->Ticks[t & 3] = (LONG)GetTickCount();
        Sleep(0);
    }
    return 0;
}

static void PauseAll(void) { int t; for (t = 0; t < W.Threads; t++) EnterCriticalSection(&W.Cs[t]); }
static void ResumeAll(void) { int t; for (t = W.Threads - 1; t >= 0; t--) LeaveCriticalSection(&W.Cs[t]); }

/* extra operations on one 64-page chunk while the walkers are paused: the paths the pager changes */
static void MixOps(u64 *rr, long *cycle)
{
    size_t chunk_pages = 64, p0, p, i;
    char *base;
    DWORD old;
    MEMORY_BASIC_INFORMATION mbi;
    u64 r = mix64(*rr + (*cycle)++);
    *rr = r;
    p0 = (size_t)(r % (W.Pages / chunk_pages)) * chunk_pages;
    if (p0 / REGION_PAGES != (p0 + chunk_pages - 1) / REGION_PAGES) return;
    base = PagePtr(p0);
    PauseAll();
    switch (r % 4)
    {
    case 0: /* decommit + recommit: demand-zero contract, then refill */
        if (!VirtualFree(base, chunk_pages * PAGE, MEM_DECOMMIT)) { WLog("ERROR decommit %lu", GetLastError()); break; }
        {
            int tries;
            for (tries = 0; tries < 20 && !VirtualAlloc(base, chunk_pages * PAGE, MEM_COMMIT, PAGE_READWRITE); tries++) Sleep(1000);
            if (tries == 20)
            {
                WLog("NOTE recommit denied %lu: chunk at page %lu retired", GetLastError(), (unsigned long)p0);
                InterlockedIncrement(&W.Slot->Denied);
                for (p = p0; p < p0 + chunk_pages; p++) W.Gens[p] = DEAD_GEN;
                break;
            }
        }
        for (p = p0; p < p0 + chunk_pages; p++)
        {
            const u64 *w = (const u64 *)PagePtr(p);
            int nz = 0;
            for (i = 0; i < PAGE / 8; i++) if (w[i]) { nz = 1; break; }
            if (nz) { LONG n = InterlockedIncrement(&W.Mism); InterlockedIncrement(&W.Slot->Mism); WLog("MISMATCH #%ld recommitted page %lu is not zero", n, (unsigned long)p); }
            W.Gens[p]++;
            FillPage(PagePtr(p), W.Seed, (u32)p, W.Gens[p]);
        }
        break;
    case 1: /* read-only, no-access, back to read-write; data must survive */
        if (!VirtualProtect(base, chunk_pages * PAGE, PAGE_READONLY, &old)) { WLog("ERROR protect ro %lu", GetLastError()); break; }
        for (p = p0; p < p0 + chunk_pages; p++) VerifyPage(p, "after-ro");
        if (!VirtualProtect(base, chunk_pages * PAGE, PAGE_NOACCESS, &old)) { WLog("ERROR protect na %lu", GetLastError()); break; }
        if (!VirtualProtect(base, chunk_pages * PAGE, PAGE_READWRITE, &old)) { WLog("ERROR protect rw %lu", GetLastError()); break; }
        if (old != PAGE_NOACCESS) WLog("MISMATCH old protect after NOACCESS = %lx", old);
        for (p = p0; p < p0 + chunk_pages; p++) VerifyPage(p, "after-na");
        break;
    case 2: /* query and lock a few pages */
        if (VirtualQuery(base, &mbi, sizeof(mbi)) && (mbi.State != MEM_COMMIT || mbi.Protect != PAGE_READWRITE))
            WLog("MISMATCH VirtualQuery state=%lx protect=%lx", mbi.State, mbi.Protect);
        if (VirtualLock(base, 4 * PAGE))
        {
            for (p = p0; p < p0 + 4; p++) VerifyPage(p, "locked");
            VirtualUnlock(base, 4 * PAGE);
        }
        break;
    default: /* dirty then verify the whole chunk once more (clean pages paged in and re-dirtied) */
        for (p = p0; p < p0 + chunk_pages; p++)
        {
            VerifyPage(p, "chunk");
            if (p & 1) { W.Gens[p]++; FillPage(PagePtr(p), W.Seed, (u32)p, W.Gens[p]); }
        }
        break;
    }
    ResumeAll();
}

static int WorkerMain(int argc, char **argv)
{
    long mb = ArgL(argc, argv, "mb", 64), secs = ArgL(argc, argv, "secs", 60);
    size_t want, got = 0, p;
    HANDLE th[8], hmap;
    char path[MAX_PATH];
    int t, rc = EXIT_OK;
    u64 rr = 1;
    long cycle = 0;
    DWORD t0 = GetTickCount(), last = 0, mixnext;

    memset(&W, 0, sizeof(W));
    W.Id = (int)ArgL(argc, argv, "id", 0);
    W.Inst = (int)ArgL(argc, argv, "inst", 1);
    W.Threads = (int)ArgL(argc, argv, "threads", 2); if (W.Threads < 1) W.Threads = 1; if (W.Threads > 8) W.Threads = 8;
    W.WPct = (int)ArgL(argc, argv, "wpct", 15);
    W.Mix = (int)ArgL(argc, argv, "mix", 1);
    W.Seed = (u32)mix64((u64)W.Id * 1000003 + W.Inst * 7919 + GetTickCount());
    strncpy(gDir, Arg(argc, argv, "dir", gDir), sizeof(gDir) - 1);
    InitializeCriticalSection(&gOutCs);
    _snprintf(path, sizeof(path) - 1, "%s\\w%d.txt", gDir, W.Id);
    gOut = fopen(path, "a");
    hmap = (HANDLE)(ULONG_PTR)ArgL(argc, argv, "hb", 0);
    gHb = hmap ? MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, sizeof(HBSLOT) * HB_SLOTS) : NULL;
    W.Slot = gHb ? &gHb[W.Id] : (HBSLOT *)calloc(1, sizeof(HBSLOT));
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    for (t = 0; t < 8; t++) InitializeCriticalSection(&W.Cs[t]);

    want = (size_t)mb * 1024 * 1024 / PAGE;
    while (got < want && got / REGION_PAGES < 256)
    {
        size_t n = want - got < REGION_PAGES ? want - got : REGION_PAGES;
        char *r = VirtualAlloc(NULL, n * PAGE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!r) { WLog("NOTE commit refused at %lu of %lu MB (error %lu)", (unsigned long)(got * PAGE >> 20), (unsigned long)mb, GetLastError()); InterlockedIncrement(&W.Slot->Denied); break; }
        if (n < REGION_PAGES) { /* round the last region to a whole region so PagePtr stays valid: keep it, use only n pages */ }
        W.Regions[got / REGION_PAGES] = r;
        got += n;
    }
    /* only whole regions are used so that chunk arithmetic is simple */
    W.Pages = got;
    if (W.Pages < 64) { WLog("ERROR only %lu pages", (unsigned long)W.Pages); W.Slot->State = 2; return EXIT_DENIED; }
    W.Gens = VirtualAlloc(NULL, W.Pages * sizeof(u32), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!W.Gens) { WLog("ERROR gens alloc"); return EXIT_INTERNAL; }
    W.Slot->Pages = (LONG)W.Pages;
    for (p = 0; p < W.Pages; p++) { W.Gens[p] = 1; FillPage(PagePtr(p), W.Seed, (u32)p, 1); }
    W.Slot->Pid = (LONG)GetCurrentProcessId();
    W.Slot->State = 1; W.Slot->Ready = 1;
    WLog("START pages=%lu (%lu MB of %ld) threads=%d wpct=%d seed=%08lx secs=%ld", (unsigned long)W.Pages, (unsigned long)(W.Pages * PAGE >> 20), mb, W.Threads, W.WPct, (unsigned long)W.Seed, secs);
    for (t = 0; t < W.Threads; t++) th[t] = CreateThread(NULL, 0, WThread, (LPVOID)(ULONG_PTR)t, 0, NULL);
    mixnext = GetTickCount() + 5000;
    for (;;)
    {
        DWORD now = GetTickCount();
        if (now - t0 >= (DWORD)secs * 1000) break;
        if (W.Stop) break;
        if (StopFile()) break;
        if (now - last >= 20000)
        {
            last = now;
            WLog("progress t=%lus ops=%ld rewrites=%ld mism=%ld", (unsigned long)((now - t0) / 1000), W.Ops, W.Rewrites, W.Mism);
        }
        if (W.Mix && (LONG)(now - mixnext) >= 0)
        {
            MixOps(&rr, &cycle);
            mixnext = GetTickCount() + 3000 + (DWORD)(rr % 4000);
        }
        Sleep(500);
    }
    W.Stop = W.Stop ? W.Stop : 1;
    for (t = 0; t < W.Threads; t++) WaitForSingleObject(th[t], 120000);
    for (p = 0; p < W.Pages; p++) VerifyPage(p, "final");     /* every page, after everything else stopped */
    WLog("DONE ops=%ld rewrites=%ld mism=%ld pages=%lu", W.Ops, W.Rewrites, W.Mism, (unsigned long)W.Pages);
    W.Slot->State = 2;
    if (W.Mism) rc = EXIT_MISMATCH;
    else if (W.Pages < want) rc = EXIT_DENIED;
    return rc;
}

/* ====================================================================== */
/* section pair: writer and reader share a pagefile-backed section        */
/* ====================================================================== */
static int SectMain(int argc, char **argv)
{
    long mb = ArgL(argc, argv, "mb", 16), secs = ArgL(argc, argv, "secs", 60);
    int writer = !strcmp(Arg(argc, argv, "role", "w"), "w");
    int id = (int)ArgL(argc, argv, "id", 0);
    HANDLE hmap, sec;
    volatile char *v;
    size_t np = (size_t)mb * 1024 * 1024 / PAGE, p;
    u32 *last, *gen;
    long mism = 0, ops = 0, skips = 0;
    DWORD t0 = GetTickCount(), lastsay = 0;
    char path[MAX_PATH];
    u64 r = mix64(id + GetTickCount());
    char *copy;

    InitializeCriticalSection(&gOutCs);
    strncpy(gDir, Arg(argc, argv, "dir", gDir), sizeof(gDir) - 1);
    _snprintf(path, sizeof(path) - 1, "%s\\w%d.txt", gDir, id);
    gOut = fopen(path, "a");
    hmap = (HANDLE)(ULONG_PTR)ArgL(argc, argv, "hb", 0);
    gHb = hmap ? MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, sizeof(HBSLOT) * HB_SLOTS) : NULL;
    if (!gHb) return EXIT_INTERNAL;
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    sec = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)(np * PAGE), "pagersoak_sect");
    if (!sec) { Say("PAGERH:S%d ERROR CreateFileMapping %lu", id, GetLastError()); gHb[id].State = 2; return EXIT_DENIED; }
    v = MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 0);
    if (!v) { Say("PAGERH:S%d ERROR MapViewOfFile %lu", id, GetLastError()); gHb[id].State = 2; return EXIT_DENIED; }
    last = calloc(np, sizeof(u32)); gen = calloc(np, sizeof(u32)); copy = malloc(PAGE);
    gHb[id].Pid = (LONG)GetCurrentProcessId(); gHb[id].State = 1; gHb[id].Ready = 1; gHb[id].Pages = (LONG)np;
    Say("PAGERH:S%d START role=%s pages=%lu secs=%ld", id, writer ? "writer" : "reader", (unsigned long)np, secs);
    while (GetTickCount() - t0 < (DWORD)secs * 1000 && !StopFile())
    {
        int b;
        for (b = 0; b < 64; b++)
        {
            volatile LONG *ha, *hb;
            p = (size_t)(r = mix64(r)) % np;
            ha = (volatile LONG *)(v + p * PAGE); hb = (volatile LONG *)(v + p * PAGE + 4);
            if (writer)
            {
                u32 g = ++gen[p];
                u64 key = ((u64)p << 32) ^ g, *w = (u64 *)(v + p * PAGE + 32), ck;
                int i;
                *ha = (LONG)g; MemoryBarrier();
                for (i = 0; i < (PAGE - 32) / 8; i++) w[i] = mix64(key + i);
                ck = BodyCk((const u64 *)w, (PAGE - 32) / 8);
                *(volatile u64 *)(v + p * PAGE + 8) = ck;
                *(volatile u32 *)(v + p * PAGE + 16) = (u32)p;
                MemoryBarrier(); *hb = (LONG)g;
            }
            else
            {
                u32 sb, sa;
                sb = (u32)*hb; MemoryBarrier();
                memcpy(copy, (const void *)(v + p * PAGE), PAGE);
                MemoryBarrier(); sa = (u32)*ha;
                if (!sb || sa != sb) { skips++; continue; }
                {
                    u64 key = ((u64)p << 32) ^ sb;
                    u64 ck = BodyCk((const u64 *)(copy + 32), (PAGE - 32) / 8);
                    const u64 *w = (const u64 *)(copy + 32);
                    int bad = 0;
                    if (*(u64 *)(copy + 8) != ck) bad = 1;
                    else if (*(u32 *)(copy + 16) != (u32)p) bad = 2;
                    else if (w[0] != mix64(key) || w[100] != mix64(key + 100)) bad = 3;
                    else if (sb < last[p]) bad = 4;
                    if (bad) { mism++; InterlockedIncrement(&gHb[id].Mism); if (mism <= 24) Say("PAGERH:S%d MISMATCH #%ld page=%lu code=%d seq=%lu last=%lu", id, mism, (unsigned long)p, bad, (unsigned long)sb, (unsigned long)last[p]); }
                    else last[p] = sb;
                }
            }
            ops++; InterlockedIncrement(&gHb[id].Ops);
        }
        gHb[id].Ticks[0] = (LONG)GetTickCount();
        if (GetTickCount() - lastsay > 20000) { lastsay = GetTickCount(); Say("PAGERH:S%d progress ops=%ld mism=%ld skips=%ld", id, ops, mism, skips); }
        Sleep(1);
    }
    Say("PAGERH:S%d DONE ops=%ld mism=%ld skips=%ld", id, ops, mism, skips);
    gHb[id].State = 2;
    return mism ? EXIT_MISMATCH : EXIT_OK;
}

/* ====================================================================== */
/* file integrity: preallocated files, in-place block writes, intent/ack  */
/* log; the offline verifier (host/verify_fck.py) checks it after a clean */
/* shutdown or a power cut                                                */
/* ====================================================================== */
#define FCK_FILES 8
#define FCK_BLOCKS 512                   /* 4 KB blocks per file: 2 MB */
#define FCK_LOGREC 16
typedef struct { unsigned char Type, File; unsigned short Block; u32 Gen, Seq, Crc; } FREC;
static u32 RecCrc(const FREC *r) { return (u32)mix64(((u64)r->Type << 56) ^ ((u64)r->File << 48) ^ ((u64)r->Block << 32) ^ r->Gen ^ ((u64)r->Seq << 20)) ^ 0xC0DEF00Du; }

static HANDLE gFh[FCK_FILES];
static CRITICAL_SECTION gFcs[FCK_FILES], gLogCs;
static u32 gFGen[FCK_FILES][FCK_BLOCKS];
static HANDLE gLogH = INVALID_HANDLE_VALUE;
static LONGLONG gLogOff, gLogMax;
static volatile LONG gFStop, gFOps, gFReads, gFMism, gFErr;
static u32 gSeq;

static void FckFill(unsigned char *b, int f, int blk, u32 gen)
{
    PHDR *h = (PHDR *)b;
    u64 *w = (u64 *)(b + sizeof(PHDR));
    int n = (PAGE - sizeof(PHDR)) / 8, i;
    u64 key = ((u64)f << 48) ^ ((u64)blk << 32) ^ gen;
    for (i = 0; i < n; i++) w[i] = mix64(key + i);
    h->Magic = PH_MAGIC; h->Seed = f; h->Page = blk; h->Gen = gen; h->Addr = 0; h->Ck = BodyCk(w, n);
}
static int FckCheck(const unsigned char *b, int f, int blk, u32 gen)
{
    const PHDR *h = (const PHDR *)b;
    if (h->Magic != PH_MAGIC || h->Seed != (u32)f || h->Page != (u32)blk || h->Gen != gen) return 1;
    return h->Ck != BodyCk((const u64 *)(b + sizeof(PHDR)), (PAGE - sizeof(PHDR)) / 8);
}
static int FckRead(int f, int blk, unsigned char *b)
{
    OVERLAPPED ov; DWORD rd = 0;
    memset(&ov, 0, sizeof(ov)); ov.Offset = blk * PAGE;
    return ReadFile(gFh[f], b, PAGE, &rd, &ov) && rd == PAGE;
}
static int FckWrite(int f, int blk, const unsigned char *b)
{
    OVERLAPPED ov; DWORD wr = 0;
    memset(&ov, 0, sizeof(ov)); ov.Offset = blk * PAGE;
    return WriteFile(gFh[f], b, PAGE, &wr, &ov) && wr == PAGE;
}
/*
 * Append one record. Returns 0 when the log is full: that is an error of the run (the
 * offline check could not judge the writes that follow), so the file writers stop, the
 * error is counted and said once, and the fck child fails (the supervisor's verdict
 * is FAIL). Size the log with logmb= for long runs.
 */
static volatile LONG gLogFull;
static int FckLog(int type, int f, int blk, u32 gen)
{
    FREC r; OVERLAPPED ov; DWORD wr;
    int ok = 1;
    EnterCriticalSection(&gLogCs);
    if (gLogH != INVALID_HANDLE_VALUE && gLogOff + FCK_LOGREC <= gLogMax)
    {
        r.Type = (unsigned char)type; r.File = (unsigned char)f; r.Block = (unsigned short)blk; r.Gen = gen; r.Seq = ++gSeq; r.Crc = RecCrc(&r);
        memset(&ov, 0, sizeof(ov)); ov.Offset = (DWORD)gLogOff; ov.OffsetHigh = (DWORD)(gLogOff >> 32);
        if (!WriteFile(gLogH, &r, FCK_LOGREC, &wr, &ov) || wr != FCK_LOGREC) InterlockedIncrement(&gFErr);
        gLogOff += FCK_LOGREC;
    }
    else
    {
        ok = 0;
        if (InterlockedExchange(&gLogFull, 1) == 0)
        {
            InterlockedIncrement(&gFErr);
            gFStop = 1;
            Say("PAGERH:FCK ERROR log full at %lld bytes (logmb too small for this run): file writes stopped, the run FAILS", gLogOff);
        }
    }
    LeaveCriticalSection(&gLogCs);
    return ok;
}

static DWORD WINAPI FckWriter(LPVOID a)
{
    int me = (int)(ULONG_PTR)a;
    u64 r = mix64(GetTickCount() + me);
    unsigned char *buf = VirtualAlloc(NULL, PAGE * 4, MEM_COMMIT, PAGE_READWRITE);
    while (!gFStop)
    {
        int f = (int)((r = mix64(r)) % FCK_FILES), n = 1 + (int)(r >> 40) % 3, i, blk0 = (int)((r >> 8) % (FCK_BLOCKS - 4));
        u32 g[4];
        EnterCriticalSection(&gFcs[f]);
        /* No intent record, no write: data is never newer than the log */
        for (i = 0; i < n; i++)
        {
            if (!FckLog(1, f, blk0 + i, gFGen[f][blk0 + i] + 1)) break;
            g[i] = ++gFGen[f][blk0 + i];
        }
        n = i;
        if (n == 0) { LeaveCriticalSection(&gFcs[f]); break; }
        for (i = 0; i < n; i++)
        {
            FckFill(buf + i * PAGE, f, blk0 + i, g[i]);
            if (!FckWrite(f, blk0 + i, buf + i * PAGE)) { InterlockedIncrement(&gFErr); }
        }
        if (!FlushFileBuffers(gFh[f])) InterlockedIncrement(&gFErr);
        for (i = 0; i < n; i++) FckLog(2, f, blk0 + i, g[i]);
        LeaveCriticalSection(&gFcs[f]);
        InterlockedIncrement(&gFOps);
        Sleep(20 + (DWORD)(r % 40));
    }
    return 0;
}

static DWORD WINAPI FckReader(LPVOID a)
{
    u64 r = mix64(GetTickCount() * 3 + (ULONG_PTR)a);
    unsigned char *buf = VirtualAlloc(NULL, PAGE, MEM_COMMIT, PAGE_READWRITE);
    while (!gFStop)
    {
        int f = (int)((r = mix64(r)) % FCK_FILES), blk = (int)((r >> 16) % FCK_BLOCKS);
        EnterCriticalSection(&gFcs[f]);
        if (!FckRead(f, blk, buf)) InterlockedIncrement(&gFErr);
        else
        {
            InterlockedIncrement(&gFReads);
            if (FckCheck(buf, f, blk, gFGen[f][blk]))
            {
                LONG n = InterlockedIncrement(&gFMism);
                if (n <= 24) Say("PAGERH:FCK MISMATCH #%ld live file=%d block=%d want gen=%lu got gen=%lu", n, f, blk, (unsigned long)gFGen[f][blk], (unsigned long)((PHDR *)buf)->Gen);
            }
        }
        LeaveCriticalSection(&gFcs[f]);
        Sleep(5 + (DWORD)(r % 15));
    }
    return 0;
}

static int FckMain(int argc, char **argv)
{
    long secs = ArgL(argc, argv, "secs", 60), logmb = ArgL(argc, argv, "logmb", 64);
    int id = (int)ArgL(argc, argv, "id", 30), f, blk;
    char fdir[MAX_PATH], p[MAX_PATH];
    unsigned char *buf = VirtualAlloc(NULL, PAGE, MEM_COMMIT, PAGE_READWRITE);
    HANDLE th[5], hmap;
    DWORD t0, lastsay = 0;
    int i;

    InitializeCriticalSection(&gOutCs); InitializeCriticalSection(&gLogCs);
    for (f = 0; f < FCK_FILES; f++) InitializeCriticalSection(&gFcs[f]);
    strncpy(gDir, Arg(argc, argv, "dir", gDir), sizeof(gDir) - 1);
    _snprintf(fdir, sizeof(fdir) - 1, "%s", Arg(argc, argv, "fdir", "C:\\fck"));
    _snprintf(p, sizeof(p) - 1, "%s\\w%d.txt", gDir, id);
    gOut = fopen(p, "a");
    hmap = (HANDLE)(ULONG_PTR)ArgL(argc, argv, "hb", 0);
    gHb = hmap ? MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, sizeof(HBSLOT) * HB_SLOTS) : NULL;
    if (gHb) { gHb[id].Pid = (LONG)GetCurrentProcessId(); gHb[id].State = 0; }
    CreateDirectoryA(fdir, NULL);
    /* setup: create, write every block (generation 0 is never logged), flush, then the log */
    for (f = 0; f < FCK_FILES; f++)
    {
        _snprintf(p, sizeof(p) - 1, "%s\\f%02d.bin", fdir, f);
        gFh[f] = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);
        if (gFh[f] == INVALID_HANDLE_VALUE) { Say("PAGERH:FCK ERROR create %s: %lu", p, GetLastError()); return EXIT_INTERNAL; }
        for (blk = 0; blk < FCK_BLOCKS; blk++) { FckFill(buf, f, blk, 0); if (!FckWrite(f, blk, buf)) { Say("PAGERH:FCK ERROR setup write %d/%d %lu", f, blk, GetLastError()); return EXIT_INTERNAL; } }
        FlushFileBuffers(gFh[f]);
    }
    _snprintf(p, sizeof(p) - 1, "%s\\log.bin", fdir);
    gLogH = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);
    if (gLogH == INVALID_HANDLE_VALUE) { Say("PAGERH:FCK ERROR create log: %lu", GetLastError()); return EXIT_INTERNAL; }
    gLogMax = (LONGLONG)logmb * 1024 * 1024;
    {   /* preallocate with real zero data so that appends never change the file size */
        unsigned char *z = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
        LONGLONG o; OVERLAPPED ov; DWORD wr;
        for (o = 0; o < gLogMax; o += 65536)
        {
            memset(&ov, 0, sizeof(ov)); ov.Offset = (DWORD)o; ov.OffsetHigh = (DWORD)(o >> 32);
            if (!WriteFile(gLogH, z, 65536, &wr, &ov) || wr != 65536) { Say("PAGERH:FCK ERROR log prealloc %lu", GetLastError()); return EXIT_INTERNAL; }
        }
        FlushFileBuffers(gLogH);
    }
    { FREC s; DWORD wr; OVERLAPPED ov; memset(&s, 0, sizeof(s)); s.Type = 3; s.Gen = FCK_FILES; s.Seq = 0; s.Block = FCK_BLOCKS; s.Crc = RecCrc(&s);
      memset(&ov, 0, sizeof(ov)); WriteFile(gLogH, &s, FCK_LOGREC, &wr, &ov); gLogOff = FCK_LOGREC; FlushFileBuffers(gLogH); }
    Say("PAGERH:FCK START files=%d blocks=%d dir=%s logmb=%ld secs=%ld", FCK_FILES, FCK_BLOCKS, fdir, logmb, secs);
    if (gHb) { gHb[id].State = 1; gHb[id].Ready = 1; }
    for (i = 0; i < 3; i++) th[i] = CreateThread(NULL, 0, FckWriter, (LPVOID)(ULONG_PTR)i, 0, NULL);
    for (i = 3; i < 5; i++) th[i] = CreateThread(NULL, 0, FckReader, (LPVOID)(ULONG_PTR)i, 0, NULL);
    t0 = GetTickCount();
    while (GetTickCount() - t0 < (DWORD)secs * 1000)
    {
        Sleep(1000);
        if (gHb) { gHb[id].Ticks[0] = (LONG)GetTickCount(); gHb[id].Ops = gFOps; gHb[id].Mism = gFMism; }
        if (GetTickCount() - lastsay > 20000) { lastsay = GetTickCount(); Say("PAGERH:FCK progress writes=%ld reads=%ld mism=%ld errors=%ld logoff=%lld", gFOps, gFReads, gFMism, gFErr, gLogOff); }
        if (gFStop || StopFile()) break;
    }
    gFStop = 1;
    for (i = 0; i < 5; i++) WaitForSingleObject(th[i], 60000);
    for (f = 0; f < FCK_FILES; f++)
        for (blk = 0; blk < FCK_BLOCKS; blk++)
            if (!FckRead(f, blk, buf)) gFErr++;
            else if (FckCheck(buf, f, blk, gFGen[f][blk])) { LONG n = InterlockedIncrement(&gFMism); if (n <= 24) Say("PAGERH:FCK MISMATCH #%ld final file=%d block=%d", n, f, blk); }
    for (f = 0; f < FCK_FILES; f++) { FlushFileBuffers(gFh[f]); CloseHandle(gFh[f]); }
    FlushFileBuffers(gLogH); CloseHandle(gLogH);
    Say("PAGERH:FCK DONE writes=%ld reads=%ld mism=%ld errors=%ld", gFOps, gFReads, gFMism, gFErr);
    if (gHb) gHb[id].State = 2;
    return gFMism ? EXIT_MISMATCH : (gFErr ? EXIT_INTERNAL : EXIT_OK);
}

/* ====================================================================== */
/* supervisor                                                              */
/* ====================================================================== */
typedef struct _SPI                      /* SystemPerformanceInformation, the leading fields */
{
    LARGE_INTEGER Idle, IoR, IoW, IoO;
    ULONG f[24];
} SPI;
typedef struct _MLI                      /* SystemMemoryListInformation (class 80), query */
{
    SIZE_T Zero, Free, Modified, ModifiedNoWrite, Bad, ByPrio[8], Repurposed[8], ModifiedPageFile;
} MLI;

typedef struct _CHILD
{
    HANDLE H;
    DWORD Pid;
    int Id, Inst, Kind;                  /* 0 wrk steady, 1 wrk churn, 2 sect w, 3 sect r, 4 fck */
    int Life;                            /* seconds, 0 = until the end */
    long Mb;
    DWORD Started, Retry;
    int Alive, Pending;
} CHILD;
static CHILD gCh[MAX_WORKERS];
static int gNCh;
static PFN_NTQSI pQsi;
static PFN_NTSSI pSsi;
static volatile LONG gSupStop;
static int gMlState = 0;                 /* 0 untested, 1 works, -1 unsupported, -2 privilege, -3 other error */
static LONG gMlStatus;
static long gMlCalls[3], gTrimCycles, gTrimFail;
static int gMlCmd[3] = { 2, 3, 4 };      /* empty working sets, flush modified list, purge standby (public headers) */
static long gTrimMs, gMlForce;
static char gExe[MAX_PATH];
static HANDLE gHbMap;
static long gMismAccum;
static void MakeStop(void)
{
    char sp[MAX_PATH]; HANDLE h;
    _snprintf(sp, sizeof(sp) - 1, "%s\\stop", gDir); sp[sizeof(sp) - 1] = 0;
    h = CreateFileA(sp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}
static long gLogMb = 64;
static SECURITY_ATTRIBUTES gInh = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

static int StartChild(CHILD *c, long secs)
{
    char cmd[1024];
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    const char *mode = c->Kind <= 1 ? "wrk" : c->Kind <= 3 ? "sect" : "fck";
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (c->Kind <= 1)
        _snprintf(cmd, sizeof(cmd) - 1, "\"%s\" wrk id=%d inst=%d mb=%ld secs=%ld threads=%ld wpct=%ld mix=%ld hb=%lu dir=%s", gExe, c->Id, c->Inst, c->Mb, secs, 2L, 15L, 1L, (unsigned long)(ULONG_PTR)gHbMap, gDir);
    else if (c->Kind <= 3)
        _snprintf(cmd, sizeof(cmd) - 1, "\"%s\" sect id=%d role=%s mb=%ld secs=%ld hb=%lu dir=%s", gExe, c->Id, c->Kind == 2 ? "w" : "r", c->Mb, secs, (unsigned long)(ULONG_PTR)gHbMap, gDir);
    else
        _snprintf(cmd, sizeof(cmd) - 1, "\"%s\" fck id=%d secs=%ld logmb=%ld hb=%lu dir=%s", gExe, c->Id, secs, gLogMb, (unsigned long)(ULONG_PTR)gHbMap, gDir);
    cmd[sizeof(cmd) - 1] = 0;
    gMismAccum += gHb[c->Id].Mism;
    memset(&gHb[c->Id], 0, sizeof(HBSLOT));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        Say("PAGERH:SUP ERROR CreateProcess %s id=%d: %lu", mode, c->Id, GetLastError());
        return 0;
    }
    CloseHandle(pi.hThread);
    c->H = pi.hProcess; c->Pid = pi.dwProcessId; c->Alive = 1; c->Started = GetTickCount();
    return 1;
}

static LONG MemList(int idx)
{
    ULONG cmd = (ULONG)gMlCmd[idx];
    LONG st;
    if (!pSsi) return (LONG)0xC0000002;
    st = pSsi(80, &cmd, sizeof(cmd));
    gMlCalls[idx]++;
    return st;
}

static void TrimCycle(void)
{
    int i;
    LONG st;
    gTrimCycles++;
    /* per-process trim: SetProcessWorkingSetSize(-1,-1), works at every flag value */
    for (i = 0; i < gNCh; i++)
        if (gCh[i].Alive && gCh[i].Kind <= 1)
        {
            HANDLE h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, FALSE, gCh[i].Pid);
            if (h) { SetProcessWorkingSetSize(h, (SIZE_T)-1, (SIZE_T)-1); CloseHandle(h); }
        }
    if (gMlState < 0 && !gMlForce) return;
    for (i = 0; i < 3; i++)
    {
        st = MemList(i);
        if (gMlState == 0)
        {
            gMlStatus = st;
            if (st >= 0) { gMlState = 1; Say("PAGERH:SUP memlist=supported first-status=%08lx", (unsigned long)st); }
            else if ((ULONG)st == 0xC0000002 || (ULONG)st == 0xC0000003 || (ULONG)st == 0xC0000010 || (ULONG)st == 0xC00000BB)
            { gMlState = -1; Say("PAGERH:SUP memlist=unsupported status=%08lx (skipping memory-list commands; per-process trim only)", (unsigned long)st); return; }
            else if ((ULONG)st == 0xC0000061) { gMlState = -2; Say("PAGERH:SUP memlist=privilege-not-held status=%08lx (harness error: run as admin)", (unsigned long)st); return; }
            else { gMlState = -3; Say("PAGERH:SUP memlist=error status=%08lx (skipping)", (unsigned long)st); return; }
        }
        else if (st < 0) { gTrimFail++; if (gTrimFail <= 8) Say("PAGERH:SUP memlist cmd=%d failed status=%08lx", gMlCmd[i], (unsigned long)st); }
    }
}

static DWORD WINAPI TrimThread(LPVOID a)
{
    (void)a;
    while (!gSupStop)
    {
        Sleep((DWORD)gTrimMs);
        if (gSupStop) break;
        TrimCycle();
    }
    return 0;
}

static void Counters(DWORD t0, int nworkers)
{
    union { SPI s; unsigned char raw[4096]; } su;
    SPI *s = &su.s;
    MLI m; ULONG len = 0; LONG st;
    MEMORYSTATUSEX ms; int i; long ops = 0, mism = 0, denied = 0, stalls = 0, pages = 0, alive = 0;
    DWORD now = GetTickCount();
    char ml[256] = "memlist=n/a";
    memset(&su, 0, sizeof(su)); memset(&m, 0, sizeof(m));
    ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    st = pQsi ? pQsi(2, &su, sizeof(su), &len) : -1;
    if (pQsi && gMlState >= 0)
    {
        st = pQsi(80, &m, sizeof(m), &len);
        if (st >= 0)
        {
            SIZE_T stby = 0; int k;
            for (k = 0; k < 8; k++) stby += m.ByPrio[k];
            { SIZE_T rep = 0; for (k = 0; k < 8; k++) rep += m.Repurposed[k];
              _snprintf(ml, sizeof(ml) - 1, "zero=%lu free=%lu mod=%lu modnw=%lu stby=%lu repurposed=%lu modpf=%lu", (unsigned long)m.Zero, (unsigned long)m.Free, (unsigned long)m.Modified, (unsigned long)m.ModifiedNoWrite, (unsigned long)stby, (unsigned long)rep, (unsigned long)m.ModifiedPageFile); }
        }
        else _snprintf(ml, sizeof(ml) - 1, "memlist-query=%08lx", (unsigned long)st);
    }
    for (i = 0; i < gNCh; i++)
    {
        HBSLOT *h = &gHb[gCh[i].Id];
        if (gCh[i].Alive) alive++;
        ops += h->Ops; mism += h->Mism; denied += h->Denied; pages += h->Pages;
    }
    mism += gMismAccum;
    (void)nworkers; (void)stalls;
    Say("PAGERH:COUNT t=%lu availMB=%lu commitMB=%lu/%lu physMB=%lu/%lu faults=%lu pgread=%lu pgreadio=%lu dirtywr=%lu mappedwr=%lu cow=%lu dz=%lu | %s | trims=%ld ml=%ld/%ld/%ld mlfail=%ld | procs=%ld ops=%ld mism=%ld denied=%ld pagesMB=%ld",
        (now - t0) / 1000, (unsigned long)((u64)s->f[3] * PAGE >> 20), (unsigned long)((u64)s->f[4] * PAGE >> 20), (unsigned long)((u64)s->f[5] * PAGE >> 20),
        (unsigned long)(ms.ullAvailPhys >> 20), (unsigned long)(ms.ullTotalPhys >> 20),
        (unsigned long)s->f[7], (unsigned long)s->f[12], (unsigned long)s->f[13], (unsigned long)s->f[16], (unsigned long)s->f[18], (unsigned long)s->f[8], (unsigned long)s->f[11],
        ml, gTrimCycles, gMlCalls[0], gMlCalls[1], gMlCalls[2], gTrimFail, alive, ops, mism, denied, (pages * (long)PAGE) >> 20);
}

static void RunHook(const char *hook)
{
    char cmd[1024], out[MAX_PATH];
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    if (!hook || !*hook) return;
    PathIn(out, sizeof(out), "hook.txt");
    _snprintf(cmd, sizeof(cmd) - 1, "cmd /c \"%s >> \"%s\" 2>&1\"", hook, out);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}

static int SupMain(int argc, char **argv)
{
    long secs = ArgL(argc, argv, "secs", 600);
    double ratio = atof(Arg(argc, argv, "ratio", "1.6"));
    long nsteady = ArgL(argc, argv, "workers", 5), nchurn = ArgL(argc, argv, "churn", 2), life = ArgL(argc, argv, "life", 60);
    long sect = ArgL(argc, argv, "sect", 0), fck = ArgL(argc, argv, "fck", 1), counters = ArgL(argc, argv, "counters", 60);
    /* fck log: about 12 MB per hour were used in an 8 h soak; 32 MB per started hour, at least 64 MB */
    gLogMb = ArgL(argc, argv, "logmb", 0);
    if (gLogMb <= 0) gLogMb = max(64L, ((ArgL(argc, argv, "secs", 600) + 3599) / 3600) * 32L);
    long stallsecs = ArgL(argc, argv, "stall", 180);
    long mbmax = ArgL(argc, argv, "mbmax", 0);   /* explicit total instead of ratio * RAM */
    const char *clamp = Arg(argc, argv, "commit", "clamp");   /* clamp: stay under the commit limit; none: ask for the ratio and count denials */
    const char *hook = Arg(argc, argv, "hook", "");
    const char *label = Arg(argc, argv, "label", "run");
    const char *flag = Arg(argc, argv, "flag", "?");
    MEMORYSTATUSEX ms; HANDLE trim = NULL;
    long totalmb, permb, i;
    DWORD t0, lastcount = 0, lasthook = 0, endtick;
    int fails = 0, denieds = 0, crashes = 0, stalls = 0, stallnow[MAX_WORKERS];
    char path[MAX_PATH];
    HMODULE nt;
    int nextinst = 1;
    long mismatches = 0;

    strncpy(gDir, Arg(argc, argv, "dir", gDir), sizeof(gDir) - 1);
    CreateDirectoryA(gDir, NULL);
    InitializeCriticalSection(&gOutCs);
    PathIn(path, sizeof(path), "stop"); DeleteFileA(path);
    PathIn(path, sizeof(path), "sup.txt");
    gOut = fopen(path, "a");
    gToCom = ArgL(argc, argv, "com", 1) != 0;
    if (gToCom) gCom = CreateFileA("\\\\.\\COM2", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    GetModuleFileNameA(NULL, gExe, sizeof(gExe));
    gTrimMs = ArgL(argc, argv, "trim", 0); gMlForce = ArgL(argc, argv, "memlist-force", 0);
    gMlCmd[0] = (int)ArgL(argc, argv, "cmdempty", 2); gMlCmd[1] = (int)ArgL(argc, argv, "cmdflush", 3); gMlCmd[2] = (int)ArgL(argc, argv, "cmdpurge", 4);
    if (ArgL(argc, argv, "memlist", 1) == 0) gMlState = -1;
    nt = GetModuleHandleA("ntdll.dll");
    pQsi = (PFN_NTQSI)GetProcAddress(nt, "NtQuerySystemInformation");
    pSsi = (PFN_NTSSI)GetProcAddress(nt, "NtSetSystemInformation");
    EnablePriv("SeProfileSingleProcessPrivilege");
    EnablePriv("SeIncreaseQuotaPrivilege");

    ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    totalmb = mbmax ? mbmax : (long)((double)(ms.ullTotalPhys >> 20) * ratio);
    if (!strcmp(clamp, "clamp"))
    {
        long cap = (long)((ms.ullAvailPageFile >> 20) * 0.85) - 96;
        if (cap < 64) cap = 64;
        if (totalmb > cap) { Say("PAGERH:SUP sizing: asked %ld MB, clamped to %ld MB (85%% of free commit minus 96)", totalmb, cap); totalmb = cap; }
    }
    permb = totalmb / (nsteady + nchurn); if (permb < 8) permb = 8;
    Say("PAGERH:SUP START label=%s flag=%s secs=%ld physMB=%lu commitlimitMB=%lu availcommitMB=%lu ratio=%.2f workloadMB=%ld steady=%ld churn=%ld life=%ld per=%ld sect=%ld fck=%ld trimms=%ld commit=%s memlist-cmds=%d/%d/%d",
        label, flag, secs, (unsigned long)(ms.ullTotalPhys >> 20), (unsigned long)(ms.ullTotalPageFile >> 20), (unsigned long)(ms.ullAvailPageFile >> 20),
        ratio, totalmb, nsteady, nchurn, life, permb, sect, fck, gTrimMs, clamp, gMlCmd[0], gMlCmd[1], gMlCmd[2]);

    gHbMap = CreateFileMappingA(INVALID_HANDLE_VALUE, &gInh, PAGE_READWRITE, 0, sizeof(HBSLOT) * HB_SLOTS, NULL);
    gHb = gHbMap ? MapViewOfFile(gHbMap, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    if (!gHb) { Say("PAGERH:SUP ERROR heartbeat section %lu", GetLastError()); return 2; }
    t0 = GetTickCount();
    endtick = t0 + (DWORD)secs * 1000;

    if (sect > 0)
    {
        for (i = 0; i < 2; i++)
        {
            CHILD *c = &gCh[gNCh];
            c->Id = gNCh; c->Inst = 1; c->Kind = 2 + (int)i; c->Mb = sect;
            if (StartChild(c, secs)) gNCh++;
        }
    }
    Sleep(3000);   /* the section is created first so that the private workers do not take all the commit */
    for (i = 0; i < nsteady + nchurn && gNCh < MAX_WORKERS; i++)
    {
        CHILD *c = &gCh[gNCh];
        c->Id = gNCh; c->Inst = nextinst++; c->Kind = i < nsteady ? 0 : 1; c->Mb = permb; c->Life = c->Kind ? (int)life : 0;
        if (StartChild(c, c->Life ? c->Life : secs)) gNCh++;
    }
    if (fck)
    {
        CHILD *c = &gCh[gNCh];
        c->Id = gNCh; c->Inst = 1; c->Kind = 4;
        if (StartChild(c, secs)) gNCh++;
    }
    /* wait until the children are initialised (allocation of the working sets is slow under pressure) */
    {
        DWORD wt = GetTickCount();
        int allready;
        do { allready = 1; for (i = 0; i < gNCh; i++) if (gCh[i].Alive && !gHb[gCh[i].Id].Ready && gHb[gCh[i].Id].State != 2) allready = 0; if (!allready) Sleep(500); }
        while (!allready && GetTickCount() - wt < 600000);
        Say("PAGERH:SUP READY children=%d after=%lus fck=%d", gNCh, (unsigned long)((GetTickCount() - wt) / 1000), fck ? 1 : 0);
        if (fck) Say("PAGERH:FCK-READY");
    }
    if (gTrimMs > 0) trim = CreateThread(NULL, 0, TrimThread, NULL, 0, NULL);
    memset(stallnow, 0, sizeof(stallnow));

    while ((LONG)(endtick - GetTickCount()) > 0)
    {
        DWORD now = GetTickCount();
        Sleep(1000);
        for (i = 0; i < gNCh; i++)
        {
            CHILD *c = &gCh[i];
            DWORD code;
            if (!c->Alive && c->Kind == 1 && c->Pending && (LONG)(now - c->Retry) >= 0)
            {
                long rem = (long)((endtick - now) / 1000), l = c->Life < rem ? c->Life : rem;
                c->Pending = 0;
                if (rem > c->Life / 2) { c->Inst = nextinst++; StartChild(c, l); }
            }
            if (!c->Alive) continue;
            if (GetExitCodeProcess(c->H, &code) && code != STILL_ACTIVE)
            {
                c->Alive = 0; CloseHandle(c->H);
                if (code == EXIT_OK || code == EXIT_DENIED) { if (code == EXIT_DENIED) denieds++; }
                else if (code == EXIT_MISMATCH) { fails++; Say("PAGERH:SUP FAIL child id=%d kind=%d exited with mismatches", c->Id, c->Kind); }
                else { crashes++; fails++; Say("PAGERH:SUP FAIL child id=%d kind=%d died exit=%08lx", c->Id, c->Kind, (unsigned long)code); }
                if (c->Kind == 1)
                {
                    /* restart (churn); a child that died within 5 s (could not allocate) waits 10 s so it does not spin */
                    c->Pending = 1;
                    c->Retry = now + ((now - c->Started) < 5000 ? 10000 : 0);
                }
            }
            else if (c->Kind == 0 || c->Kind == 4)
            {
                /* stall: a live steady child whose newest thread tick is older than stallsecs */
                int t; LONG newest = 0; int any = 0;
                for (t = 0; t < 4; t++) if (gHb[c->Id].Ticks[t]) { any = 1; if (!newest || (LONG)(gHb[c->Id].Ticks[t] - newest) > 0) newest = gHb[c->Id].Ticks[t]; }
                if (any && (LONG)(now - newest) > stallsecs * 1000)
                {
                    if (!stallnow[i]) { stallnow[i] = 1; stalls++; Say("PAGERH:SUP STALL child id=%d kind=%d no progress for %lus", c->Id, c->Kind, (unsigned long)((now - newest) / 1000)); RunHook(hook); }
                }
                else stallnow[i] = 0;
            }
        }
        if (now - lastcount >= (DWORD)counters * 1000) { lastcount = now; Counters(t0, gNCh); }
        if (hook && *hook && now - lasthook >= 300000) { lasthook = now; RunHook(hook); }
        if (StopFile()) { Say("PAGERH:SUP stop file seen"); break; }
    }
    gSupStop = 1;
    MakeStop();
    if (trim) { WaitForSingleObject(trim, 70000); }
    Say("PAGERH:SUP STOPPING (workers finish with a final full verify)");
    for (i = 0; i < gNCh; i++)
        if (gCh[i].Alive)
        {
            DWORD code;
            if (WaitForSingleObject(gCh[i].H, 1800000) == WAIT_TIMEOUT) { Say("PAGERH:SUP FAIL child id=%d did not finish in 30 min (hang)", gCh[i].Id); fails++; stalls++; TerminateProcess(gCh[i].H, 99); continue; }
            GetExitCodeProcess(gCh[i].H, &code);
            if (code == EXIT_MISMATCH) { fails++; Say("PAGERH:SUP FAIL child id=%d mismatches at the final verify", gCh[i].Id); }
            else if (code == EXIT_DENIED) denieds++;
            else if (code != EXIT_OK) { crashes++; fails++; Say("PAGERH:SUP FAIL child id=%d exit=%08lx", gCh[i].Id, (unsigned long)code); }
        }
    mismatches = gMismAccum;
    for (i = 0; i < gNCh; i++) mismatches += gHb[gCh[i].Id].Mism;
    Counters(t0, gNCh);
    Say("PAGERH:SUP DONE verdict=%s fails=%d crashes=%d stalls=%d denied-children=%d hbmism=%ld memlist=%s trimcycles=%ld",
        fails || stalls ? "FAIL" : "PASS", fails, crashes, stalls, denieds, mismatches,
        gMlState == 1 ? "used" : gMlState == -1 ? "unsupported" : gMlState == 0 ? "untested" : "error", gTrimCycles);
    Say("ROSHARNESS:PAGERH-DONE");
    return fails || stalls ? 1 : 0;
}

static int Usage(void)
{
    puts("pagersoak.exe sup [secs=N ratio=1.6 workers=5 churn=2 life=60 trim=MS sect=MB fck=1 commit=clamp|none counters=60 dir=C:\\pagerh label=X flag=N hook=CMD memlist=1 cmdempty=2 cmdflush=3 cmdpurge=4]\n"
         "pagersoak.exe wrk|sect|fck ... (started by sup)\n"
         "pagersoak.exe stop   create the stop file so that sup ends early");
    return 9;
}

int main(int argc, char **argv)
{
    if (argc < 2) return Usage();
    if (!strcmp(argv[1], "sup")) return SupMain(argc, argv);
    if (!strcmp(argv[1], "wrk")) return WorkerMain(argc, argv);
    if (!strcmp(argv[1], "sect")) return SectMain(argc, argv);
    if (!strcmp(argv[1], "fck")) return FckMain(argc, argv);
    if (!strcmp(argv[1], "stop"))
    {
        strncpy(gDir, Arg(argc, argv, "dir", gDir), sizeof(gDir) - 1);
        MakeStop();
        return 0;
    }
    return Usage();
}
