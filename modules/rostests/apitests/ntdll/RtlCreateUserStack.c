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
#ifdef _M_AMD64
            ok(GuardBytes == 3 * s_Rows[i].PageSize, "row %lu: guard region of %Ix bytes\n", i, GuardBytes);
#endif
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
