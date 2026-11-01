/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for ZwQuerySystemInformationEx: the same function as NtQuerySystemInformationEx in user mode
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 under WOW64: both names are one address; class 181
 * (SystemSupportedProcessorArchitectures) takes the process handle as its input.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_QUERY_EX)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

#define CLASS_SUPPORTED_ARCHITECTURES 181

static
void
TestEntry(PCSTR Name, PFN_QUERY_EX Query)
{
    HANDLE Process = NtCurrentProcess();
    HANDLE Zero = NULL;
    UCHAR Output[64];
    ULONG Length;
    NTSTATUS Status;

    /* a native 64-bit process, or a 32-bit one on a 64-bit system, or a 32-bit system: always the machine list
     * ending in a zero entry (3 ULONGs at 4 bytes each for two machines) */
    RtlFillMemory(Output, sizeof(Output), 0xAA);
    Length = 0xAAAAAAAA;
    Status = Query(CLASS_SUPPORTED_ARCHITECTURES, &Process, sizeof(Process), Output, sizeof(Output), &Length);
    ok(Status == STATUS_SUCCESS, "%s: status 0x%lx\n", Name, Status);
    ok(Length == 8 || Length == 12, "%s: length %lu\n", Name, Length);
    ok(*(PUSHORT)(Output + Length - 4) == 0 && *(PULONG)(Output + Length - 4) == 0, "%s: no zero entry at the end\n", Name);

    /* each entry is a ULONG: Machine in bits 0-15, then KernelMode, UserMode, Native, Process, WoW64Container.
     * The first one is the machine of the kernel (kernel, user and native), the second, on a 64-bit system, is
     * i386 with user mode only; Windows 10 (19045) does not mark it as a WOW64 container, Windows 11 does */
    if (Length == 12)
    {
        ULONG First = ((PULONG)Output)[0], Second = ((PULONG)Output)[1];

        ok_eq_hex(First & 0xFFFF, IMAGE_FILE_MACHINE_AMD64);
        ok_eq_hex((First >> 16) & 7, 7);
        ok_eq_hex(Second & 0xFFFF, IMAGE_FILE_MACHINE_I386);
        ok_eq_hex((Second >> 16) & 7, 2);
        todo_if(is_reactos())
            ok_eq_hex((Second >> 20) & 1, 0);
    }

    /* no process: nothing is the current one */
    RtlFillMemory(Output, sizeof(Output), 0xAA);
    Status = Query(CLASS_SUPPORTED_ARCHITECTURES, &Zero, sizeof(Zero), Output, sizeof(Output), &Length);
    ok(Status == STATUS_SUCCESS, "%s: NULL process: status 0x%lx\n", Name, Status);
    ok(!(Output[2] & 0x08), "%s: first entry marked as the process: 0x%x\n", Name, Output[2]);

    /* too small an output: the length of what would have been written */
    RtlFillMemory(Output, sizeof(Output), 0xAA);
    Length = 0xAAAAAAAA;
    Status = Query(CLASS_SUPPORTED_ARCHITECTURES, &Process, sizeof(Process), Output, 4, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok(Length == 8 || Length == 12, "%s: length %lu\n", Name, Length);
    ok(Output[0] == 0xAA, "%s: output touched\n", Name);
    Status = Query(CLASS_SUPPORTED_ARCHITECTURES, &Process, sizeof(Process), Output, 0, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);

    /* the input has to be a handle */
    RtlFillMemory(Output, sizeof(Output), 0xAA);
    Length = 0xAAAAAAAA;
    Status = Query(CLASS_SUPPORTED_ARCHITECTURES, NULL, 0, Output, sizeof(Output), &Length);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok_eq_hex(Length, 0xAAAAAAAA);
    ok_eq_hex(Output[0], 0xAA);

    /* a class that does not exist */
    Status = Query(0xFFFF, &Process, sizeof(Process), Output, sizeof(Output), &Length);
    ok_hex(Status, STATUS_INVALID_INFO_CLASS);
    ok_eq_hex(Length, 0xAAAAAAAA);
}

START_TEST(ZwQuerySystemInformationEx)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_QUERY_EX pNt, pZw;

    pNt = (PFN_QUERY_EX)GetProcAddress(Ntdll, "NtQuerySystemInformationEx");
    pZw = (PFN_QUERY_EX)GetProcAddress(Ntdll, "ZwQuerySystemInformationEx");
    if (!pNt)
    {
        skip("NtQuerySystemInformationEx is not available\n");
        return;
    }

    ok(pZw != NULL, "ZwQuerySystemInformationEx is not exported\n");
    ok(pZw == pNt, "ZwQuerySystemInformationEx %p, NtQuerySystemInformationEx %p\n", pZw, pNt);
    TestEntry("Nt", pNt);
    if (pZw)
        TestEntry("Zw", pZw);
}
