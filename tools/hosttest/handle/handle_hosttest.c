/*
 * PROJECT:     ReactOS host-native test harness (handle table)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Concurrency / invariant tests for the REAL ntoskrnl/ex/handle.c,
 *              built natively against shim/ntoskrnl.h. One pthread == one CPU.
 *
 * Invariants checked:
 *  - no handle is ever handed to two owners at once (ABA / double-pop detector)
 *  - ExMapHandleToPointer on an owned handle returns our entry/object
 *  - HandleCount returns to 0
 *  - free-list audit at quiescence: every index in [1,NextHandleNeedingPool)
 *    (except each low-level table slot 0) is on exactly one of
 *    FirstFree chain / LastFree chain / a per-CPU cache; no loops, no dups
 */
#include <ntoskrnl.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>

EPROCESS HostProcess;
KTHREAD HostThread = { 1 };
ULONG KeNumberProcessors = 1;
int HostPoolFailAfter = -1;
static __thread ULONG TlsCpu;
static atomic_long PoolLive;

ULONG KeGetCurrentProcessorNumber(void) { return TlsCpu; }

PVOID ExAllocatePoolWithTag(POOL_TYPE t, SIZE_T n, ULONG tag)
{
    void *p;
    (void)t; (void)tag;
    if (HostPoolFailAfter >= 0 && __sync_fetch_and_sub(&HostPoolFailAfter, 1) <= 0) return NULL;
    if (posix_memalign(&p, 64, n)) return NULL;
    atomic_fetch_add(&PoolLive, 1);
    return p;
}
void ExFreePoolWithTag(PVOID p, ULONG tag) { (void)tag; atomic_fetch_sub(&PoolLive, 1); free(p); }

#define MAXIDX (1u << 21)
static atomic_uint Owner[MAXIDX]; /* handle index -> owner thread id + 1 */
static atomic_int Failures;
#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); fputc(10, stderr); atomic_fetch_add(&Failures, 1); } while (0)
#define CHECK(c, ...) do { if (!(c)) FAIL(__VA_ARGS__); } while (0)

static inline unsigned HIdx(HANDLE h) { EXHANDLE e; e.GenericHandleOverlay = h; return (unsigned)e.Index; }

typedef struct { PHANDLE_TABLE T; int Id; ULONG Cpu; int Live; int Seconds; atomic_int *Stop; unsigned long Ops; unsigned Seed; } WORKER;

static unsigned Rnd(unsigned *s) { *s = *s * 1103515245u + 12345u; return (*s >> 8); }

static void *Worker(void *arg)
{
    WORKER *w = arg;
    HANDLE *mine = calloc(w->Live, sizeof(HANDLE));
    int n = 0;
    TlsCpu = w->Cpu;
    while (!atomic_load(w->Stop))
    {
        unsigned r = Rnd(&w->Seed);
        /* bias toward keeping ~Live/2 held so free-list heads churn constantly */
        if (n == 0 || (n < w->Live && (r & 1)))
        {
            HANDLE_TABLE_ENTRY e;
            HANDLE h;
            unsigned idx, exp = 0;
            memset(&e, 0, sizeof(e));
            e.Object = (PVOID)(((ULONG_PTR)(w->Id + 1) << 4) | 0);   /* lock bit clear; Create unlocks */
            e.GrantedAccess = 0x1000 + w->Id;
            h = ExCreateHandle(w->T, &e);
            if (!h) { FAIL("ExCreateHandle returned NULL (t%d)", w->Id); continue; }
            idx = HIdx(h);
            if (idx >= MAXIDX) { FAIL("index %u beyond owner map", idx); continue; }
            if (!atomic_compare_exchange_strong(&Owner[idx], &exp, w->Id + 1))
                FAIL("DOUBLE ALLOCATION: handle idx %u given to t%d while owned by t%u", idx, w->Id, exp - 1);
            mine[n++] = h;
        }
        else
        {
            int k = Rnd(&w->Seed) % n;
            HANDLE h = mine[k];
            unsigned idx = HIdx(h), exp = w->Id + 1;
            PHANDLE_TABLE_ENTRY e = ExMapHandleToPointer(w->T, h);
            if (!e) FAIL("ExMapHandleToPointer(own handle idx %u) failed", idx);
            else
            {
                if ((ULONG_PTR)e->Object >> 4 != (ULONG_PTR)(w->Id + 1) || e->GrantedAccess != 0x1000u + w->Id)
                    FAIL("entry for idx %u carries foreign data (obj %p acc %x), t%d", idx, e->Object, e->GrantedAccess, w->Id);
                ExUnlockHandleTableEntry(w->T, e);
            }
            /* release ownership BEFORE the destroy so a legit reuse cannot false-positive */
            if (!atomic_compare_exchange_strong(&Owner[idx], &exp, 0)) FAIL("ownership of idx %u lost", idx);
            if (!ExDestroyHandle(w->T, h, NULL)) FAIL("ExDestroyHandle failed idx %u", idx);
            mine[k] = mine[--n];
        }
        w->Ops++;
    }
    while (n > 0)
    {
        HANDLE h = mine[--n];
        unsigned idx = HIdx(h), exp = w->Id + 1;
        atomic_compare_exchange_strong(&Owner[idx], &exp, 0);
        if (!ExDestroyHandle(w->T, h, NULL)) FAIL("drain destroy failed idx %u", idx);
    }
    free(mine);
    return NULL;
}

static PHANDLE_TABLE_ENTRY Lookup(PHANDLE_TABLE T, ULONG v) { EXHANDLE h; h.Value = v; return ExpLookupHandleTableEntry(T, h); }

/* Walk a free chain; returns count, marks seen[]. */
static long WalkChain(PHANDLE_TABLE T, ULONG head, unsigned char *seen, const char *name)
{
    long c = 0, limit = (long)(T->NextHandleNeedingPool >> 2) + 8;
    ULONG v = head;
    while (v)
    {
        unsigned idx = (v & ~3u) >> 2;
        PHANDLE_TABLE_ENTRY e;
        if (c++ > limit) { FAIL("%s chain loops / too long", name); return -1; }
        if (v >= T->NextHandleNeedingPool) { FAIL("%s chain value %x out of range", name, v); return -1; }
        if (seen[idx]++) { FAIL("%s: idx %u appears twice in free structures", name, idx); return -1; }
        e = Lookup(T, v & ~3u);
        v = (ULONG)e->NextFreeTableEntry;
    }
    return c;
}

static void Audit(PHANDLE_TABLE T, const char *tag)
{
    unsigned total = T->NextHandleNeedingPool >> 2, i;
    unsigned char *seen = calloc(total + 1, 1);
    long freecount = 0, c, expect = 0;
    CHECK(T->HandleCount == 0, "[%s] HandleCount=%ld at quiescence", tag, (long)T->HandleCount);
    if ((c = WalkChain(T, T->FirstFree, seen, "FirstFree")) > 0) freecount += c;
    if ((c = WalkChain(T, T->LastFree, seen, "LastFree")) > 0) freecount += c;
    if (T->PerCpuFreeCache)
        for (i = 0; i < T->PerCpuFreeCacheCount; i++)
        {
            PEX_HANDLE_CPU_CACHE s = EX_HANDLE_CACHE_SLOT(T, i);
            ULONG j;
            CHECK(s->Count <= EX_HANDLE_CACHE_CAPACITY, "[%s] cpu %u cache count %u overflow", tag, i, s->Count);
            for (j = 0; j < s->Count && j < EX_HANDLE_CACHE_CAPACITY; j++)
            {
                unsigned idx = s->Handles[j] >> 2;
                if (idx >= total) { FAIL("[%s] cpu %u cache holds out-of-range handle %x", tag, i, s->Handles[j]); continue; }
                if (seen[idx]++) FAIL("[%s] cpu %u cache idx %u also in another free structure", tag, i, idx);
                freecount++;
            }
        }
    for (i = 1; i < total; i++) if (i % LOW_LEVEL_ENTRIES) expect++;
    CHECK(freecount == expect, "[%s] free structures hold %ld handles, expected %ld (leak/loss)", tag, freecount, expect);
    for (i = 1; i < total; i++)
        if ((i % LOW_LEVEL_ENTRIES) && !seen[i]) { FAIL("[%s] idx %u is in NO free structure (lost)", tag, i); break; }
    free(seen);
}

static int RunStress(const char *name, int threads, int cpus, int live, int secs, int strict, int cache)
{
    PHANDLE_TABLE T;
    pthread_t th[64];
    WORKER w[64];
    atomic_int stop = 0;
    unsigned long ops = 0;
    int i, before = atomic_load(&Failures);
    struct timespec ts = { secs, 0 };

    KeNumberProcessors = cpus;
    TlsCpu = 0;
    T = ExCreateHandleTable(NULL);
    if (!T) { FAIL("[%s] table create failed", name); return 1; }
    if (!cache)
    {
        /* A table without cache storage (as when its allocation failed): everything goes through the shared free list. */
        ExFreePoolWithTag(T->PerCpuFreeCache, TAG_HANDLE_CPU_CACHE);
        T->PerCpuFreeCache = NULL;
        T->PerCpuFreeCacheCount = 0;
    }
    T->StrictFIFO = strict;
    memset(Owner, 0, sizeof(Owner));
    for (i = 0; i < threads; i++)
    {
        w[i] = (WORKER){ T, i, (ULONG)i, live, secs, &stop, 0, 0x9e3779b9u * (i + 1) };
        pthread_create(&th[i], NULL, Worker, &w[i]);
    }
    nanosleep(&ts, NULL);
    atomic_store(&stop, 1);
    for (i = 0; i < threads; i++) { pthread_join(th[i], NULL); ops += w[i].Ops; }
    TlsCpu = 0;
    Audit(T, name);
    ExDestroyHandleTable(T, NULL);
    printf("%-34s threads=%2d cpus=%2d live=%5d strict=%d cache=%d ops=%9lu  %s\n", name, threads, cpus, live, strict, cache, ops,
           atomic_load(&Failures) == before ? "PASS" : "FAIL");
    return atomic_load(&Failures) != before;
}

/* Single-thread: grow through 2- and 3-level tables, mapping every handle. */
static void TestGrowth(void)
{
    PHANDLE_TABLE T;
    enum { N = 400000 };
    HANDLE *hs = malloc(N * sizeof(HANDLE));
    int i, before = atomic_load(&Failures);
    KeNumberProcessors = 1; TlsCpu = 0;
    T = ExCreateHandleTable(NULL);
    memset(Owner, 0, sizeof(Owner));
    for (i = 0; i < N; i++)
    {
        HANDLE_TABLE_ENTRY e = { 0 };
        e.Object = (PVOID)(ULONG_PTR)(((ULONG_PTR)i + 1) << 4);
        hs[i] = ExCreateHandle(T, &e);
        if (!hs[i]) { FAIL("growth: create %d failed", i); break; }
        if (atomic_exchange(&Owner[HIdx(hs[i])], 1)) { FAIL("growth: dup handle at %d", i); break; }
    }
    CHECK(T->HandleCount == i, "growth: HandleCount %ld != %d", (long)T->HandleCount, i);
    CHECK((T->TableCode & 3) == 2, "growth: expected 3-level table, level=%u", (unsigned)(T->TableCode & 3));
    for (int k = 0; k < i; k++)
    {
        PHANDLE_TABLE_ENTRY e = ExMapHandleToPointer(T, hs[k]);
        if (!e || ((ULONG_PTR)e->Object >> 4) != (ULONG_PTR)k + 1) { FAIL("growth: map %d wrong", k); break; }
        ExUnlockHandleTableEntry(T, e);
    }
    for (int k = 0; k < i; k++) if (!ExDestroyHandle(T, hs[k], NULL)) { FAIL("growth: destroy %d", k); break; }
    Audit(T, "growth");
    ExDestroyHandleTable(T, NULL);
    free(hs);
    printf("%-34s handles=%d                                         %s\n", "growth-3level", i, atomic_load(&Failures) == before ? "PASS" : "FAIL");
}

/* Allocation-failure injection: create must fail cleanly, not leak pool. */
static void TestPoolFailure(void)
{
    int before = atomic_load(&Failures), k;
    long base = atomic_load(&PoolLive);
    KeNumberProcessors = 2; TlsCpu = 0;
    for (k = 0; k < 6; k++)
    {
        PHANDLE_TABLE T;
        HostPoolFailAfter = k;
        T = ExCreateHandleTable(NULL);
        HostPoolFailAfter = -1;
        if (T) ExDestroyHandleTable(T, NULL);
    }
    CHECK(atomic_load(&PoolLive) == base, "poolfail: %ld pool blocks leaked", atomic_load(&PoolLive) - base);
    printf("%-34s                                                  %s\n", "pool-failure-no-leak", atomic_load(&Failures) == before ? "PASS" : "FAIL");
}

int main(int argc, char **argv)
{
    int secs = argc > 1 ? atoi(argv[1]) : 2, bad = 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    HostProcess.UniqueProcessId = (HANDLE)4;
    C_ASSERT(sizeof(HANDLE_TABLE_ENTRY) == 16);
    ExpInitializeHandleTables();
    TestGrowth();
    TestPoolFailure();
    /* shared-list ABA hammer: no cache storage, tiny live-set so list heads recycle constantly */
    bad += RunStress("shared-list ABA hammer", 8, 8, 3, secs, 0, 0);
    bad += RunStress("shared-list, bigger live set", 8, 8, 200, secs, 0, 0);
    bad += RunStress("shared-list strict-FIFO", 8, 8, 50, secs, 1, 0);
    /* per-CPU cache (lever #1) */
    bad += RunStress("per-cpu cache", 8, 8, 50, secs, 0, 1);
    bad += RunStress("per-cpu cache, overflow/flush", 8, 8, 400, secs, 0, 1);
    bad += RunStress("per-cpu cache, tiny live set", 8, 8, 3, secs, 0, 1);
    bad += RunStress("per-cpu cache, cpu>=table cpus", 8, 4, 50, secs, 0, 1);
    bad += RunStress("per-cpu cache, 1 thread", 1, 1, 100, secs, 0, 1);
    bad += RunStress("oversubscribed (64 thr on 48 cores)", 64, 64, 20, secs, 0, 1);
    printf("%s (%d failures)\n", atomic_load(&Failures) ? "OVERALL FAIL" : "OVERALL PASS", atomic_load(&Failures));
    return atomic_load(&Failures) != 0;
}
