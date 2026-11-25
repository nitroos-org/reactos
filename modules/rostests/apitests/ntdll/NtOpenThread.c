/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the generic mapping of the thread type and the access a thread handle is granted.
 *              The rows were measured on Windows Server 2022 (build 20348).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

#define TEST_THREAD_RESUME 0x1000
#define TEST_THREAD_SET_LIMITED 0x0400
#define TEST_THREAD_QUERY_LIMITED 0x0800

static
ACCESS_MASK
GetGrantedAccess(
    HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Info.GrantedAccess : 0xdeadbeef;
}

static
void
Test_ThreadType(void)
{
    union
    {
        OBJECT_TYPE_INFORMATION Info;
        UCHAR Buffer[1024];
    } u;
    PGENERIC_MAPPING Mapping = &u.Info.GenericMapping;
    NTSTATUS Status;

    Status = NtQueryObject(NtCurrentThread(), ObjectTypeInformation, &u, sizeof(u), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    ok_hex(Mapping->GenericRead, 0x00020048);
    ok_hex(Mapping->GenericWrite, 0x00020437);
    ok_hex(Mapping->GenericExecute, 0x00121800);
    ok_hex(Mapping->GenericAll, 0x001FFFFF);
    ok_hex(u.Info.ValidAccessMask, 0x001FFFFF);
}

static
void
Test_GrantedAccess(void)
{
    static const struct
    {
        ACCESS_MASK Desired;
        ACCESS_MASK Granted;
    } Tests[] =
    {
        { THREAD_QUERY_LIMITED_INFORMATION, TEST_THREAD_QUERY_LIMITED },
        { THREAD_QUERY_INFORMATION, THREAD_QUERY_INFORMATION | TEST_THREAD_QUERY_LIMITED },
        { THREAD_SET_INFORMATION, THREAD_SET_INFORMATION | TEST_THREAD_SET_LIMITED },
        { THREAD_SUSPEND_RESUME, THREAD_SUSPEND_RESUME | TEST_THREAD_RESUME },
        { TEST_THREAD_RESUME, TEST_THREAD_RESUME },
        { SYNCHRONIZE, SYNCHRONIZE },
        { GENERIC_READ, 0x00020848 },
        { GENERIC_WRITE, 0x00021437 },
        { GENERIC_EXECUTE, 0x00121800 },
        { MAXIMUM_ALLOWED, 0x001FFFFF },
    };
    HANDLE Thread;
    ACCESS_MASK Granted;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Tests); i++)
    {
        Thread = OpenThread(Tests[i].Desired, FALSE, GetCurrentThreadId());
        ok(Thread != NULL, "[%lu] OpenThread(0x%lx) failed, error %lu\n", i, Tests[i].Desired, GetLastError());
        if (!Thread) continue;
        Granted = GetGrantedAccess(Thread);
        ok(Granted == Tests[i].Granted, "[%lu] OpenThread(0x%lx): granted 0x%lx, expected 0x%lx\n",
           i, Tests[i].Desired, Granted, Tests[i].Granted);
        CloseHandle(Thread);
    }
}

START_TEST(NtOpenThread)
{
    Test_ThreadType();
    Test_GrantedAccess();
}
