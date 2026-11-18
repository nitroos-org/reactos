/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for CompareObjectHandles (kernelbase.dll) and NtCompareObjects
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef BOOL (WINAPI *PFN_CompareObjectHandles)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtCompareObjects)(HANDLE, HANDLE);

static PFN_CompareObjectHandles pCompareObjectHandles;
static PFN_NtCompareObjects pNtCompareObjects;

static void Check(PCSTR Name, HANDLE First, HANDLE Second, BOOL Same)
{
    BOOL Ret;
    NTSTATUS Status;

    SetLastError(0xdeadbeef);
    Ret = pCompareObjectHandles(First, Second);
    ok(Ret == Same, "%s: ret %d, expected %d\n", Name, Ret, Same);
    if (Same)
        ok(GetLastError() == 0xdeadbeef, "%s: the last error was set to %lu\n", Name, GetLastError());
    else
        ok(GetLastError() == ERROR_NOT_SAME_OBJECT, "%s: error %lu\n", Name, GetLastError());

    Status = pNtCompareObjects(First, Second);
    ok(Status == (Same ? STATUS_SUCCESS : STATUS_NOT_SAME_OBJECT), "%s: NtCompareObjects returned %lx\n", Name, Status);
}

static void CheckInvalid(PCSTR Name, HANDLE First, HANDLE Second)
{
    BOOL Ret;
    NTSTATUS Status;

    SetLastError(0xdeadbeef);
    Ret = pCompareObjectHandles(First, Second);
    ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "%s: ret %d, error %lu\n", Name, Ret, GetLastError());
    Status = pNtCompareObjects(First, Second);
    ok(Status == STATUS_INVALID_HANDLE, "%s: NtCompareObjects returned %lx\n", Name, Status);
}

START_TEST(CompareObjectHandles)
{
    HMODULE Kernelbase = LoadLibraryW(L"kernelbase.dll");
    HANDLE Event1, Event2, Event3, Dup, DupReduced, DupNoAccess, Mutex, Process, Thread, File1, File2, FileDup;
    WCHAR Name[64];

    pCompareObjectHandles = Kernelbase ? (PFN_CompareObjectHandles)GetProcAddress(Kernelbase, "CompareObjectHandles") : NULL;
    pNtCompareObjects = (PFN_NtCompareObjects)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCompareObjects");
    if (!pCompareObjectHandles || !pNtCompareObjects)
    {
        ok(!is_reactos(), "CompareObjectHandles or NtCompareObjects is not exported\n");
        skip("CompareObjectHandles is not available\n");
        return;
    }

    /* Windows (Server 2022): kernel32 does not export it, and the handle contract is kernelbase */
    ok(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CompareObjectHandles") == NULL, "kernel32.dll exports CompareObjectHandles\n");
    {
        HMODULE Api = LoadLibraryW(L"api-ms-win-core-handle-l1-1-0.dll");

        ok(Api != NULL, "api-ms-win-core-handle-l1-1-0.dll does not load, error %lu\n", GetLastError());
        if (Api)
        {
            ok(Api == Kernelbase, "the handle contract resolves to module %p, not to kernelbase.dll %p\n", Api, Kernelbase);
            ok(GetProcAddress(Api, "CompareObjectHandles") == (FARPROC)pCompareObjectHandles, "the handle contract has another CompareObjectHandles\n");
            ok(GetProcAddress(Api, "CloseHandle") != NULL, "the handle contract has no CloseHandle\n");
        }
    }

    StringCchPrintfW(Name, ARRAYSIZE(Name), L"AppexpCompare%lu", GetCurrentProcessId());
    Event1 = CreateEventW(NULL, TRUE, FALSE, Name);
    Event2 = OpenEventW(EVENT_ALL_ACCESS, FALSE, Name);
    StringCchCatW(Name, ARRAYSIZE(Name), L"b");
    Event3 = CreateEventW(NULL, TRUE, FALSE, Name);
    Mutex = CreateMutexW(NULL, FALSE, NULL);
    ok(Event1 && Event2 && Event3 && Mutex, "creating the objects failed with %lu\n", GetLastError());
    DuplicateHandle(GetCurrentProcess(), Event1, GetCurrentProcess(), &Dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(GetCurrentProcess(), Event1, GetCurrentProcess(), &DupReduced, SYNCHRONIZE, FALSE, 0);
    DuplicateHandle(GetCurrentProcess(), Event1, GetCurrentProcess(), &DupNoAccess, 0, FALSE, 0);

    Check("same handle", Event1, Event1, TRUE);
    Check("second open of the name", Event1, Event2, TRUE);
    Check("duplicate", Event1, Dup, TRUE);
    Check("duplicate with less access", Event1, DupReduced, TRUE);
    Check("duplicate without access", Event1, DupNoAccess, TRUE);
    Check("other event", Event1, Event3, FALSE);
    Check("event and mutex", Event1, Mutex, FALSE);

    /* pseudo handles refer to the current process and thread */
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    Thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    Check("process pseudo handles", GetCurrentProcess(), GetCurrentProcess(), TRUE);
    Check("thread pseudo handles", GetCurrentThread(), GetCurrentThread(), TRUE);
    Check("process and thread pseudo handles", GetCurrentProcess(), GetCurrentThread(), FALSE);
    if (Process)
    {
        Check("pseudo and real process", GetCurrentProcess(), Process, TRUE);
        Check("real and pseudo process", Process, GetCurrentProcess(), TRUE);
        Check("(HANDLE)-1 and real process", (HANDLE)(LONG_PTR)-1, Process, TRUE);
    }
    if (Thread)
        Check("pseudo and real thread", GetCurrentThread(), Thread, TRUE);

    /* every open of a file is its own object, a duplicate is not */
    File1 = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    File2 = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File1 != INVALID_HANDLE_VALUE && File2 != INVALID_HANDLE_VALUE, "opening NUL failed with %lu\n", GetLastError());
    DuplicateHandle(GetCurrentProcess(), File1, GetCurrentProcess(), &FileDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    Check("two opens of a file", File1, File2, FALSE);
    Check("file and its duplicate", File1, FileDup, TRUE);

    /* invalid handles fail whichever argument they are */
    CheckInvalid("both invalid", (HANDLE)(ULONG_PTR)0xdeadbeef, (HANDLE)(ULONG_PTR)0xdeadbeef);
    CheckInvalid("first invalid", (HANDLE)(ULONG_PTR)0xdeadbeef, Event1);
    CheckInvalid("second invalid", Event1, (HANDLE)(ULONG_PTR)0xdeadbeef);
    CheckInvalid("both NULL", NULL, NULL);
    CheckInvalid("first NULL", NULL, Event1);
    CheckInvalid("second NULL", Event1, NULL);
    CloseHandle(Event3);
    CheckInvalid("closed handle", Event3, Event1);

    CloseHandle(Event1);
    CloseHandle(Event2);
    CloseHandle(Dup);
    CloseHandle(DupReduced);
    CloseHandle(DupNoAccess);
    CloseHandle(Mutex);
    if (Process) CloseHandle(Process);
    if (Thread) CloseHandle(Thread);
    CloseHandle(File1);
    CloseHandle(File2);
    CloseHandle(FileDup);
}
