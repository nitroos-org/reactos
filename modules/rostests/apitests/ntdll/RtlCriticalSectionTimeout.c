/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     The critical section timeout a process starts with (PEB CriticalSectionTimeout)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* EnterCriticalSection raises STATUS_POSSIBLE_DEADLOCK when a wait times out; the timeout comes from the
   Session Manager CriticalSectionTimeout value (seconds), through PEB CriticalSectionTimeout (relative,
   100 ns units). Without that value the NT default is 30 days, which ntdll treats as no timeout at all
   (anything over an hour). A short default made programs that legitimately hold a lock for minutes die in
   their waiting threads: the d3d10core and d3d11 conformance tests in a 32-bit process, whose wined3d lock
   is held while a software renderer draws for longer than 2 x 150 seconds. A WoW64 process gets the same
   value in its 32-bit PEB. */

#define NT_DEFAULT_SECONDS (720UL * 60 * 60)

static BOOLEAN
QueryRegistryTimeout(PULONG Seconds)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"CriticalSectionTimeout");
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length;
    HANDLE Key;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;
    Status = NtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
    NtClose(Key);
    if (!NT_SUCCESS(Status) || Info->Type != 4 /* REG_DWORD */ || Info->DataLength != sizeof(ULONG))
        return FALSE;
    *Seconds = *(PULONG)Info->Data;
    return TRUE;
}

static ULONG WINAPI
HoldThread(PVOID Param)
{
    PRTL_CRITICAL_SECTION CriticalSection = Param;
    RtlEnterCriticalSection(CriticalSection);
    Sleep(1500);
    RtlLeaveCriticalSection(CriticalSection);
    return 0;
}

START_TEST(RtlCriticalSectionTimeout)
{
    LARGE_INTEGER Timeout = NtCurrentPeb()->CriticalSectionTimeout;
    LONGLONG Expected;
    ULONG Seconds;
    BOOLEAN FromRegistry;
    RTL_CRITICAL_SECTION CriticalSection;
    HANDLE Thread;
    NTSTATUS Status;

    FromRegistry = QueryRegistryTimeout(&Seconds);
    if (!FromRegistry)
        Seconds = NT_DEFAULT_SECONDS;
    Expected = (LONGLONG)Seconds * -10000000LL;
    trace("CriticalSectionTimeout %s: %lu s, PEB %I64d\n", FromRegistry ? "from the registry" : "default", Seconds, Timeout.QuadPart);

    /* relative (negative), in 100 ns units, the registry value or the NT default */
    ok(Timeout.QuadPart == Expected, "PEB CriticalSectionTimeout %I64d, expected %I64d (%lu s)\n",
       Timeout.QuadPart, Expected, Seconds);
    if (!FromRegistry)
    {
        /* ntdll disables the timeout for anything longer than an hour */
        ok(Timeout.QuadPart <= -36000000000LL, "Default critical section timeout %I64d is an hour or less\n",
           Timeout.QuadPart);
    }

    /* a contended enter still waits for the owner and gets the lock */
    Status = RtlInitializeCriticalSection(&CriticalSection);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Thread = CreateThread(NULL, 0, HoldThread, &CriticalSection, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (Thread)
    {
        Sleep(300);
        RtlEnterCriticalSection(&CriticalSection);
        ok(CriticalSection.OwningThread == NtCurrentTeb()->ClientId.UniqueThread, "Not the owner after a contended enter\n");
        RtlLeaveCriticalSection(&CriticalSection);
        ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "Holder thread did not end\n");
        CloseHandle(Thread);
    }
    RtlDeleteCriticalSection(&CriticalSection);
}
