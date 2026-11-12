/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Guard region of a new thread stack, and reads that skip pages below it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * On Windows 10 x64 a new stack has three guard pages below its committed part, and
 * a hit on one of them commits that page and re-arms the three pages below it. The
 * AV1 decoder in Firefox (dav1d) probes a 24 KB frame by reading 2 pages and 4 pages
 * below the stack pointer; with one guard page the second read is an access violation.
 * Windows x86 was not measured, so the checks apply to 64-bit builds only.
 */

#include "precomp.h"
#include <pseh/pseh2.h>
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>

#define TEST_PAGE_SIZE 0x1000
#define GUARD_PAGES 3

typedef struct _STACKCFG
{
    SIZE_T Size;
    DWORD Flags;
    /* results */
    ULONG_PTR CommitBase;       /* lowest committed, unguarded page of the top region */
    SIZE_T CommitSize;          /* bytes from there up to the end of the committed run */
    ULONG GuardPages;           /* guard pages directly below it */
    BOOL Queried;
    BOOL ReadFailed[3];
} STACKCFG;

static BOOL
QueryPage(ULONG_PTR Address, PMEMORY_BASIC_INFORMATION Info)
{
    return VirtualQuery((PVOID)Address, Info, sizeof(*Info)) == sizeof(*Info);
}

static BOOL
IsGuardPage(ULONG_PTR Address)
{
    MEMORY_BASIC_INFORMATION Info;

    return QueryPage(Address, &Info) && Info.State == MEM_COMMIT &&
           (Info.Protect & PAGE_GUARD) != 0;
}

static BOOL
IsPlainCommitted(ULONG_PTR Address)
{
    MEMORY_BASIC_INFORMATION Info;

    return QueryPage(Address, &Info) && Info.State == MEM_COMMIT &&
           (Info.Protect & PAGE_GUARD) == 0;
}

static DWORD WINAPI
Worker(PVOID Param)
{
    STACKCFG *Cfg = Param;
    volatile BYTE Local[16];
    ULONG_PTR Base, Top;
    ULONG i;

    Local[0] = 1;

    /* Look at the layout before anything touches the guard region: no tracing in here */
    Base = (ULONG_PTR)Local & ~(ULONG_PTR)(TEST_PAGE_SIZE - 1);
    Top = (ULONG_PTR)NtCurrentTeb()->NtTib.StackBase;
    if (!IsPlainCommitted(Base))
        return 0;
    while (IsPlainCommitted(Base - TEST_PAGE_SIZE))
        Base -= TEST_PAGE_SIZE;
    Cfg->CommitBase = Base;
    Cfg->CommitSize = Top - Base;
    while (Cfg->GuardPages < 16 && IsGuardPage(Base - (Cfg->GuardPages + 1) * TEST_PAGE_SIZE))
        Cfg->GuardPages++;
    Cfg->Queried = TRUE;

    /* Reads 2, 4 and 6 pages below the committed part, in this order, like a probing prologue */
    for (i = 0; i < _countof(Cfg->ReadFailed); i++)
    {
        PBYTE Target = (PBYTE)(Base - (2 * (i + 1)) * TEST_PAGE_SIZE + 0x660);

        _SEH2_TRY
        {
            (void)*(volatile BYTE *)Target;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Cfg->ReadFailed[i] = TRUE;
        }
        _SEH2_END;
    }
    return 0;
}

static void
CheckConfig(SIZE_T Size, DWORD Flags)
{
    STACKCFG Cfg = { Size, Flags };
    HANDLE Thread;

    Thread = CreateThread(NULL, Size, Worker, &Cfg, Flags, NULL);
    ok(Thread != NULL, "CreateThread(%lx, %lx) failed, error %lu\n", (ULONG)Size, Flags, GetLastError());
    if (!Thread)
        return;
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);

    ok(Cfg.Queried, "size %lx flags %lx: the stack is not committed where it was expected\n", (ULONG)Size, Flags);
    if (!Cfg.Queried)
        return;

    trace("size %lx flags %lx: committed from %p (%lx bytes), %lu guard pages, reads failed %d %d %d\n",
          (ULONG)Size, Flags, (PVOID)Cfg.CommitBase, (ULONG)Cfg.CommitSize, Cfg.GuardPages,
          Cfg.ReadFailed[0], Cfg.ReadFailed[1], Cfg.ReadFailed[2]);

    /* An explicit commit size is committed up to the page */
    if (Size != 0 && !(Flags & STACK_SIZE_PARAM_IS_A_RESERVATION))
    {
        ok(Cfg.CommitSize == ((Size + TEST_PAGE_SIZE - 1) & ~(SIZE_T)(TEST_PAGE_SIZE - 1)),
           "size %lx: committed part is %lx bytes\n", (ULONG)Size, (ULONG)Cfg.CommitSize);
    }

#ifdef _WIN64
    ok(Cfg.GuardPages == GUARD_PAGES,
       "size %lx flags %lx: %lu guard pages below the committed part, expected %d\n",
       (ULONG)Size, Flags, Cfg.GuardPages, GUARD_PAGES);
    ok(!Cfg.ReadFailed[0], "size %lx flags %lx: read 2 pages below the stack failed\n", (ULONG)Size, Flags);
    ok(!Cfg.ReadFailed[1], "size %lx flags %lx: read 4 pages below the stack failed\n", (ULONG)Size, Flags);
    ok(!Cfg.ReadFailed[2], "size %lx flags %lx: read 6 pages below the stack failed\n", (ULONG)Size, Flags);
#endif
}


#ifdef _WIN64
/*
 * Touching the middle guard page first, then the top one: as on Windows 10 x64 the top hit
 * moves the limit to the top page and arms the three pages below it again, the middle one
 * included, which is a stack page in use then
 */
typedef struct _ORDERCFG
{
    BOOL Queried;
    BOOL ReadFailed[2];
    BOOL Plain[2];              /* G1 and G2: committed without PAGE_GUARD */
    ULONG GuardBelow;           /* of the 3 pages below G2 */
    ULONG_PTR Limit, G2;
    NTSTATUS SyscallStatus;
} ORDERCFG;

static DWORD WINAPI
OrderWorker(PVOID Param)
{
    ORDERCFG *Cfg = Param;
    volatile BYTE Local[16];
    ULONG_PTR Base, G1, G2;
    THREAD_BASIC_INFORMATION *Tbi;
    ULONG i;

    Local[0] = 1;
    Base = (ULONG_PTR)Local & ~(ULONG_PTR)(TEST_PAGE_SIZE - 1);
    if (!IsPlainCommitted(Base))
        return 0;
    while (IsPlainCommitted(Base - TEST_PAGE_SIZE))
        Base -= TEST_PAGE_SIZE;
    G1 = Base - TEST_PAGE_SIZE;
    G2 = Base - 2 * TEST_PAGE_SIZE;
    Cfg->G2 = G2;
    if (!IsGuardPage(G1) || !IsGuardPage(G2))
        return 0;
    Cfg->Queried = TRUE;

    _SEH2_TRY
    {
        (void)*(volatile BYTE *)(G2 + 0x660);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Cfg->ReadFailed[0] = TRUE;
    }
    _SEH2_END;
    _SEH2_TRY
    {
        /* the function body writes its frame into the top guard page */
        *(volatile BYTE *)(G1 + 0x660) = 1;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Cfg->ReadFailed[1] = TRUE;
    }
    _SEH2_END;

    Cfg->Limit = (ULONG_PTR)NtCurrentTeb()->NtTib.StackLimit;
    Cfg->Plain[0] = IsPlainCommitted(G1);
    Cfg->Plain[1] = IsPlainCommitted(G2);
    for (i = 1; i <= 3; i++)
    {
        if (IsGuardPage(G2 - i * TEST_PAGE_SIZE))
            Cfg->GuardBelow++;
    }

    /* A system service writing into a stack page that is a guard page again */
    Tbi = (THREAD_BASIC_INFORMATION *)(G2 + 0x100);
    Cfg->SyscallStatus = NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation,
                                                  Tbi, sizeof(*Tbi), NULL);
    return 0;
}

static void
CheckOrder(void)
{
    ORDERCFG Cfg = { 0 };
    HANDLE Thread = CreateThread(NULL, 0, OrderWorker, &Cfg, 0, NULL);

    ok(Thread != NULL, "CreateThread failed, error %lu\n", GetLastError());
    if (!Thread)
        return;
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);

    ok(Cfg.Queried, "the stack does not start with two guard pages below the commit\n");
    if (!Cfg.Queried)
        return;
    trace("G2 %p limit %p plain %d %d guard below %lu failed %d %d syscall %lx\n", (PVOID)Cfg.G2,
          (PVOID)Cfg.Limit, Cfg.Plain[0], Cfg.Plain[1], Cfg.GuardBelow, Cfg.ReadFailed[0],
          Cfg.ReadFailed[1], Cfg.SyscallStatus);
    ok(!Cfg.ReadFailed[0] && !Cfg.ReadFailed[1], "touching G2 then G1 faulted\n");
    ok(Cfg.Plain[0], "G1 is not a plain committed page after being touched\n");
    ok(!Cfg.Plain[1], "G2 was not guarded again by the hit on G1\n");
    ok(Cfg.Limit == Cfg.G2 + TEST_PAGE_SIZE, "stack limit %p, expected the hit page %p\n",
       (PVOID)Cfg.Limit, (PVOID)(Cfg.G2 + TEST_PAGE_SIZE));
    ok(Cfg.GuardBelow == 3, "%lu of the 3 pages below G2 are guard pages\n", Cfg.GuardBelow);
    ok(Cfg.SyscallStatus == STATUS_SUCCESS, "NtQueryInformationThread into G2 returned %lx\n", Cfg.SyscallStatus);
}
#endif /* _WIN64 */

START_TEST(ThreadStackCommit)
{
#ifndef _WIN64
    skip("The guard region of a 32-bit stack is not measured on Windows\n");
#endif

    CheckConfig(0, 0);
    CheckConfig(0x10000, 0);
    CheckConfig(0x40000, STACK_SIZE_PARAM_IS_A_RESERVATION);
    CheckConfig(0x100000, STACK_SIZE_PARAM_IS_A_RESERVATION);
#ifdef _WIN64
    CheckOrder();
#endif
}
