/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for the stub-hit logger: the first call
 *              of an exported but unimplemented routine is recorded under
 *              HKLM\SYSTEM\CurrentControlSet\Control\NitroOS\StubHits with the
 *              name of the calling module.
 */

#include <kmt_test.h>

typedef NTSTATUS (NTAPI *PIO_WMI_QUERY_SINGLE_INSTANCE)(PVOID, PUNICODE_STRING, PULONG, PVOID);

START_TEST(ExStubHit)
{
    static WCHAR KeyPath[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\NitroOS\\StubHits";
    PIO_WMI_QUERY_SINGLE_INSTANCE pStub;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"IoWMIQuerySingleInstance");
    UNICODE_STRING Key = RTL_CONSTANT_STRING(KeyPath);
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 128 * sizeof(WCHAR)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PVOID)Buffer;
    LARGE_INTEGER Delay;
    HANDLE KeyHandle;
    NTSTATUS Status, Result = STATUS_OBJECT_NAME_NOT_FOUND;
    ULONG Length, i;
    ULONG BufferSize = 0;

    pStub = KmtGetSystemRoutineAddress(L"IoWMIQuerySingleInstance");
    ok(pStub != NULL, "IoWMIQuerySingleInstance is not exported\n");
    if (!pStub)
        return;

    /* the stub still reports STATUS_NOT_IMPLEMENTED */
    Status = pStub(NULL, NULL, &BufferSize, NULL);
    ok_eq_hex(Status, STATUS_NOT_IMPLEMENTED);
    Status = pStub(NULL, NULL, &BufferSize, NULL);
    ok_eq_hex(Status, STATUS_NOT_IMPLEMENTED);

    /* the registry record is written from a work item that runs no earlier
       than a minute after boot: allow for that */
    Delay.QuadPart = -100 * 1000 * 10; /* 100 ms */
    for (i = 0; i < 1500; i++)
    {
        InitializeObjectAttributes(&ObjectAttributes, &Key, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
        if (NT_SUCCESS(Status))
        {
            Result = ZwQueryValueKey(KeyHandle, &Name, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
            ZwClose(KeyHandle);
            if (NT_SUCCESS(Result))
                break;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
    ok_eq_hex(Result, STATUS_SUCCESS);
    if (NT_SUCCESS(Result))
    {
        PCWSTR Module = (PCWSTR)Info->Data;
        ULONG Chars = Info->DataLength / sizeof(WCHAR);

        ok_eq_ulong(Info->Type, REG_SZ);
        ok(Chars > 1, "empty module name\n");
        trace("recorded caller: %ls\n", Module);
        /* the caller is this test driver */
        ok(Chars > 1 && (Module[0] == L'k' || Module[0] == L'K') && (Module[1] == L'm' || Module[1] == L'M'),
           "unexpected caller module %ls\n", Module);
    }
}
