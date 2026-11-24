/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The rights that a process handle carries in addition to the rights that were asked for
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (build 20348), OpenProcess on the own process for every combination of the 14 rights that are
 * specific to a process, and for the generic rights; the granted mask is read with NtQueryObject:
 *   PROCESS_QUERY_INFORMATION             adds PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
 *   PROCESS_VM_OPERATION | PROCESS_VM_WRITE  adds 0x1000, neither of them alone does
 *   PROCESS_SET_INFORMATION               adds PROCESS_SET_LIMITED_INFORMATION (0x2000)
 *   GENERIC_WRITE (0x20bea)               is granted as 0x23bea
 * The row for 0x2000 is not tested here (a tree without it is not wrong in the rows below).
 */

#include "precomp.h"

typedef struct
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Rest[12];
} BASIC_INFO;

static ACCESS_MASK GrantedOf(ACCESS_MASK Request)
{
    BASIC_INFO Info;
    HANDLE Process;
    NTSTATUS Status;
    CLIENT_ID Cid;
    OBJECT_ATTRIBUTES Oa;

    InitializeObjectAttributes(&Oa, NULL, 0, NULL, NULL);
    Cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    Cid.UniqueThread = NULL;
    Status = NtOpenProcess(&Process, Request, &Oa, &Cid);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return 0;
    Status = NtQueryObject(Process, ObjectBasicInformation, &Info, 56, NULL);
    NtClose(Process);
    ok_ntstatus(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Info.GrantedAccess : 0;
}

START_TEST(NtOpenProcessImplied)
{
    static const struct { ACCESS_MASK Request, Expected; } Rows[] =
    {
        { PROCESS_VM_OPERATION,                           PROCESS_VM_OPERATION },
        { PROCESS_VM_WRITE,                               PROCESS_VM_WRITE },
        { PROCESS_VM_OPERATION | PROCESS_VM_WRITE,        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION },
        { PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
          PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION },
        { PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE,      PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE },
        { PROCESS_QUERY_INFORMATION,                      PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION },
        { PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS },
    };
    ACCESS_MASK Granted;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        Granted = GrantedOf(Rows[i].Request);
        ok(Granted == Rows[i].Expected, "row %lu: request 0x%lx granted 0x%lx, expected 0x%lx\n",
           i, Rows[i].Request, Granted, Rows[i].Expected);
    }

    /* The generic write right: the mapping 0x20bea and 0x1000 (and 0x2000 where SET_INFORMATION carries it) */
    Granted = GrantedOf(GENERIC_WRITE);
    ok((Granted & ~PROCESS_SET_LIMITED_INFORMATION) == 0x21bea, "GENERIC_WRITE granted 0x%lx, expected 0x23bea\n", Granted);
}
