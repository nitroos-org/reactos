/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for RtlCreateUserStack and RtlFreeUserStack
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022. The output structure is filled with a pattern first: every field of it
 * must be written (the old stack base and limit with zero).
 */

#include "precomp.h"

/* three pages on x64, two on x86 (measured under WoW64) */
#ifdef _M_AMD64
#define RTLP_TEST_GUARD_PAGES 3
#else
#define RTLP_TEST_GUARD_PAGES 2
#endif

typedef NTSTATUS (NTAPI *PFN_CreateUserStack)(SIZE_T, SIZE_T, ULONG_PTR, SIZE_T, ULONG_PTR, PINITIAL_TEB);
typedef VOID (NTAPI *PFN_FreeUserStack)(PVOID);

static const struct
{
    SIZE_T Commit;
    SIZE_T Max;
    SIZE_T PageSize;
    ULONG_PTR Align;
    SIZE_T Total;
    SIZE_T LimitOffset;
    BOOLEAN Guard;      /* a guard region lies below the committed part */
} s_Rows[] =
{
    { 0x1000,  0x100000, 0x1000,  0x10000, 0x100000, 0xff000,  TRUE  },
    { 0x1800,  0x100000, 0x1000,  0x10000, 0x100000, 0xfe000,  TRUE  },
    { 0x1000,  0x112345, 0x1000,  0x10000, 0x120000, 0x11f000, TRUE  },
    { 0x1000,  0x112345, 0x1000,  0x1000,  0x113000, 0x112000, TRUE  },
    { 0x4000,  0x20000,  0x1000,  0x10000, 0x20000,  0x1c000,  TRUE  },
    { 0x4000,  0x4000,   0x1000,  0x10000, 0x100000, 0xfc000,  TRUE  },
    { 0x10000, 0x4000,   0x1000,  0x10000, 0x100000, 0xf0000,  TRUE  },
    { 0x1000,  0x100000, 0x10000, 0x10000, 0x100000, 0xf0000,  TRUE  },
    { 0x1000,  0x100000, 0x1000,  0x100000, 0x100000, 0xff000, TRUE  },
    { 0x2000,  0x3000,   0x1000,  0x1000,  0x3000,   0x1000,   FALSE },
    { 0x1000,  0x2000,   0x1000,  0x1000,  0x2000,   0x1000,   FALSE },
};

START_TEST(RtlCreateUserStack)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PFN_CreateUserStack pCreate = (PFN_CreateUserStack)GetProcAddress(hNtdll, "RtlCreateUserStack");
    PFN_FreeUserStack pFree = (PFN_FreeUserStack)GetProcAddress(hNtdll, "RtlFreeUserStack");
    INITIAL_TEB Teb;
    NTSTATUS Status;
    ULONG i;

    ok(pCreate != NULL, "RtlCreateUserStack is not exported\n");
    ok(pFree != NULL, "RtlFreeUserStack is not exported\n");
    if (!pCreate || !pFree)
    {
        skip("exports missing\n");
        return;
    }

    /* the page size and the alignment must be given, and the structure is left alone */
    memset(&Teb, 0xcc, sizeof(Teb));
    Status = pCreate(0x1000, 0x100000, 0, 0, 0, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_hex(*(PUCHAR)&Teb, 0xcc);
    ok(Teb.StackBase == (PVOID)(ULONG_PTR)(sizeof(PVOID) == 8 ? 0xcccccccccccccccc : 0xcccccccc), "StackBase %p\n", Teb.StackBase);
    Status = pCreate(0x1000, 0x100000, 0, 0x1000, 0, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pCreate(0x1000, 0x100000, 0, 0, 0x10000, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    /* the page size must not be above the alignment */
    memset(&Teb, 0xcc, sizeof(Teb));
    Status = pCreate(0x1000, 0x100000, 0, 0x2000, 0x1000, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pCreate(0x1000, 0x100000, 0, 0x1000, 3, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pCreate(0x1000, 0x100000, 0, 3, 2, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok(Teb.StackBase == (PVOID)(ULONG_PTR)(sizeof(PVOID) == 8 ? 0xcccccccccccccccc : 0xcccccccc), "StackBase %p\n", Teb.StackBase);

    /* a size that overflows when it is rounded is a bad parameter */
    Status = pCreate((SIZE_T)-1, 0, 0, 0x1000, 0x1000, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pCreate(0x2000, 0x100000, 0, 0x1000, (ULONG_PTR)-1, &Teb);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    /* the rounding is the mask (x + a - 1) & ~(a - 1) also when a is no power of two; the limit is on a page */
    {
        static const struct { SIZE_T PageSize, Align, Total, Committed; } s_Masks[] =
        {
            { 2, 3,      0x100001, 0x3001 },
            { 0x1000, 0x1800, 0x100800, 0x3800 },
            { 1, 1,      0x100001, 0x2001 },
        };

        for (i = 0; i < _countof(s_Masks); i++)
        {
            memset(&Teb, 0xcc, sizeof(Teb));
            Status = pCreate(0x2001, 0x100001, 0, s_Masks[i].PageSize, s_Masks[i].Align, &Teb);
            ok_hex(Status, STATUS_SUCCESS);
            if (!NT_SUCCESS(Status))
                continue;
            ok((SIZE_T)((PCHAR)Teb.StackBase - (PCHAR)Teb.AllocatedStackBase) == s_Masks[i].Total, "mask row %lu: total %Ix\n", i,
               (SIZE_T)((PCHAR)Teb.StackBase - (PCHAR)Teb.AllocatedStackBase));
            ok((SIZE_T)((PCHAR)Teb.StackBase - (PCHAR)Teb.StackLimit) == s_Masks[i].Committed, "mask row %lu: committed %Ix\n", i,
               (SIZE_T)((PCHAR)Teb.StackBase - (PCHAR)Teb.StackLimit));
            ok(((ULONG_PTR)Teb.StackLimit & 0xfff) == 0, "mask row %lu: limit %p is not on a page\n", i, Teb.StackLimit);
            pFree(Teb.AllocatedStackBase);
        }
    }

    /* the guard region is there when that much room is left below the limit: exactly that much is enough */
    {
        const SIZE_T GuardPages = RTLP_TEST_GUARD_PAGES;
        MEMORY_BASIC_INFORMATION Mbi2;

        memset(&Teb, 0xcc, sizeof(Teb));
        Status = pCreate(0x1000, (GuardPages + 1) * 0x1000, 0, 0x1000, 0x1000, &Teb);
        ok_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok(VirtualQuery(Teb.AllocatedStackBase, &Mbi2, sizeof(Mbi2)) == sizeof(Mbi2), "VirtualQuery failed\n");
            ok(Mbi2.State == MEM_COMMIT && Mbi2.Protect == (PAGE_READWRITE | PAGE_GUARD) && Mbi2.RegionSize == GuardPages * 0x1000,
               "exact room: state %lx protect %lx size %Ix\n", Mbi2.State, Mbi2.Protect, Mbi2.RegionSize);
            pFree(Teb.AllocatedStackBase);
        }

        memset(&Teb, 0xcc, sizeof(Teb));
        Status = pCreate(0x1000, GuardPages * 0x1000, 0, 0x1000, 0x1000, &Teb);
        ok_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok(VirtualQuery(Teb.AllocatedStackBase, &Mbi2, sizeof(Mbi2)) == sizeof(Mbi2), "VirtualQuery failed\n");
            ok(Mbi2.State == MEM_RESERVE, "one page short: state %lx\n", Mbi2.State);
            pFree(Teb.AllocatedStackBase);
        }
    }

    for (i = 0; i < _countof(s_Rows); i++)
    {
        MEMORY_BASIC_INFORMATION Mbi;
        PCHAR Base, Limit, Top, p;
        SIZE_T Total, GuardBytes = 0;

        memset(&Teb, 0xcc, sizeof(Teb));
        Status = pCreate(s_Rows[i].Commit, s_Rows[i].Max, 0, s_Rows[i].PageSize, s_Rows[i].Align, &Teb);
        ok_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            continue;

        ok(Teb.PreviousStackBase == NULL, "row %lu: old stack base %p\n", i, Teb.PreviousStackBase);
        ok(Teb.PreviousStackLimit == NULL, "row %lu: old stack limit %p\n", i, Teb.PreviousStackLimit);
        Base = Teb.AllocatedStackBase;
        Top = Teb.StackBase;
        Limit = Teb.StackLimit;
        ok(Base != NULL, "row %lu: no allocation base\n", i);
        Total = Top - Base;
        ok(Total == s_Rows[i].Total, "row %lu: total %Ix, expected %Ix\n", i, Total, s_Rows[i].Total);
        ok(Limit - Base == s_Rows[i].LimitOffset, "row %lu: limit offset %Ix, expected %Ix\n", i, (SIZE_T)(Limit - Base), s_Rows[i].LimitOffset);

        /* the committed part is read/write up to the top */
        for (p = Limit; p < Top; p += Mbi.RegionSize)
        {
            ok(VirtualQuery(p, &Mbi, sizeof(Mbi)) == sizeof(Mbi), "row %lu: VirtualQuery failed\n", i);
            ok(Mbi.State == MEM_COMMIT && Mbi.Protect == PAGE_READWRITE, "row %lu: committed part state %lx protect %lx\n", i, Mbi.State, Mbi.Protect);
            if (Mbi.State != MEM_COMMIT)
                break;
        }

        /* below it: the guard region, then what stays reserved */
        p = Limit;
        while (p > Base)
        {
            VirtualQuery(p - 1, &Mbi, sizeof(Mbi));
            if (Mbi.Protect != (PAGE_READWRITE | PAGE_GUARD) || Mbi.State != MEM_COMMIT)
                break;
            GuardBytes += (PCHAR)p - (PCHAR)Mbi.BaseAddress;
            p = Mbi.BaseAddress;
        }
        if (s_Rows[i].Guard)
        {
            ok(GuardBytes != 0, "row %lu: no guard region\n", i);
            ok(GuardBytes == RTLP_TEST_GUARD_PAGES * s_Rows[i].PageSize, "row %lu: guard region of %Ix bytes\n", i, GuardBytes);
            VirtualQuery(Base, &Mbi, sizeof(Mbi));
            ok(Mbi.State == MEM_RESERVE, "row %lu: the start is %lx, not reserved\n", i, Mbi.State);
        }
        else
        {
            ok_dec(GuardBytes, 0);
            VirtualQuery(Base, &Mbi, sizeof(Mbi));
            ok(Mbi.State == MEM_RESERVE, "row %lu: the start is %lx, not reserved\n", i, Mbi.State);
        }

        pFree(Base);
        VirtualQuery(Base, &Mbi, sizeof(Mbi));
        ok(Mbi.State == MEM_FREE, "row %lu: the stack is not released: %lx\n", i, Mbi.State);
    }

    /* the sizes of the image */
    memset(&Teb, 0xcc, sizeof(Teb));
    Status = pCreate(0, 0, 0, 0x1000, 0x10000, &Teb);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        PIMAGE_NT_HEADERS Headers = RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);
        SIZE_T Reserve = Headers->OptionalHeader.SizeOfStackReserve;
        SIZE_T Commit = Headers->OptionalHeader.SizeOfStackCommit;

        if (Commit >= Reserve)
            Reserve = (Commit + 0xfffff) & ~(SIZE_T)0xfffff;
        Reserve = (Reserve + 0xffff) & ~(SIZE_T)0xffff;
        Commit = (Commit + 0xfff) & ~(SIZE_T)0xfff;
        ok((PCHAR)Teb.StackBase - (PCHAR)Teb.AllocatedStackBase == Reserve, "total %Ix, expected %Ix\n",
           (SIZE_T)((PCHAR)Teb.StackBase - (PCHAR)Teb.AllocatedStackBase), Reserve);
        ok((PCHAR)Teb.StackBase - (PCHAR)Teb.StackLimit == Commit, "commit %Ix, expected %Ix\n",
           (SIZE_T)((PCHAR)Teb.StackBase - (PCHAR)Teb.StackLimit), Commit);
        ok(Teb.PreviousStackBase == NULL && Teb.PreviousStackLimit == NULL, "old stack %p %p\n", Teb.PreviousStackBase, Teb.PreviousStackLimit);
        pFree(Teb.AllocatedStackBase);
    }
}
