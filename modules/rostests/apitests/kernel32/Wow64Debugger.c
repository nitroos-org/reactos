/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What a debugger of a 32-bit program asks under WoW64: selector entries and the debug classes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022, a 32-bit program (probes on the reference): GetThreadSelectorEntry gives the flat code
 * (0x20-0x23) and data (0x28-0x2b) descriptors, the descriptor of the thread's 32-bit TEB (0x50-0x53, limit 0xfff),
 * an empty one for 0, and fails with ERROR_GEN_FAILURE for any other selector (0x33, 0x27, ...); the same for another
 * thread. NtQueryInformationProcess answers ProcessDebugFlags and ProcessDebugObjectHandle (STATUS_PORT_NOT_SET
 * without a debugger). The 64-bit kernel32 exports Wow64GetThreadSelectorEntry.
 */

#include "precomp.h"
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>

#ifdef _M_IX86
static void CheckSelector(HANDLE Thread, DWORD Selector, BOOL Expect, DWORD Base, DWORD Limit, BYTE Flags1, BYTE Flags2)
{
    LDT_ENTRY Entry;
    DWORD GotBase, GotLimit;
    BOOL Ret;

    memset(&Entry, 0xCC, sizeof(Entry));
    SetLastError(0xdeadbeef);
    Ret = GetThreadSelectorEntry(Thread, Selector, &Entry);
    ok(Ret == Expect, "selector 0x%lx: GetThreadSelectorEntry returned %d (error %lu)\n", Selector, Ret, GetLastError());
    if (!Expect)
    {
        ok(GetLastError() == ERROR_GEN_FAILURE, "selector 0x%lx: error %lu\n", Selector, GetLastError());
        return;
    }
    if (!Ret)
        return;
    GotBase = Entry.BaseLow | (Entry.HighWord.Bytes.BaseMid << 16) | ((DWORD)Entry.HighWord.Bytes.BaseHi << 24);
    GotLimit = Entry.LimitLow | ((Entry.HighWord.Bytes.Flags2 & 0xF) << 16);
    ok(GotBase == Base, "selector 0x%lx: base 0x%08lx, expected 0x%08lx\n", Selector, GotBase, Base);
    ok(GotLimit == Limit, "selector 0x%lx: limit 0x%05lx, expected 0x%05lx\n", Selector, GotLimit, Limit);
    ok(Entry.HighWord.Bytes.Flags1 == Flags1, "selector 0x%lx: flags1 0x%02x, expected 0x%02x\n", Selector, Entry.HighWord.Bytes.Flags1, Flags1);
    ok((Entry.HighWord.Bytes.Flags2 & 0xF0) == Flags2, "selector 0x%lx: flags2 0x%02x\n", Selector, Entry.HighWord.Bytes.Flags2);
}

static DWORD WINAPI Sleeper(PVOID Event)
{
    WaitForSingleObject(Event, 10000);
    return 0;
}
#endif

START_TEST(Wow64Debugger)
{
#ifdef _M_IX86
    BOOL Wow64 = FALSE;
    DWORD Teb = (DWORD)NtCurrentTeb(), Flags = 0xdeadbeef, ObjectHandle = 0xdeadbeef;
    HANDLE Thread, Event;
    NTSTATUS Status;
    ULONG Length;

    if (!IsWow64Process(GetCurrentProcess(), &Wow64) || !Wow64)
    {
        skip("not a 32-bit process under WoW64\n");
        return;
    }
    CheckSelector(GetCurrentThread(), 0x00, TRUE, 0, 0, 0, 0);
    CheckSelector(GetCurrentThread(), 0x20, TRUE, 0, 0xFFFFF, 0xFB, 0xC0);
    CheckSelector(GetCurrentThread(), 0x23, TRUE, 0, 0xFFFFF, 0xFB, 0xC0);
    CheckSelector(GetCurrentThread(), 0x2B, TRUE, 0, 0xFFFFF, 0xF3, 0xC0);
    CheckSelector(GetCurrentThread(), 0x53, TRUE, Teb, 0xFFF, 0xF3, 0x40);
    CheckSelector(GetCurrentThread(), 0x50, TRUE, Teb, 0xFFF, 0xF3, 0x40);
    CheckSelector(GetCurrentThread(), 0x33, FALSE, 0, 0, 0, 0);
    CheckSelector(GetCurrentThread(), 0x27, FALSE, 0, 0, 0, 0);
    CheckSelector(GetCurrentThread(), 0x08, FALSE, 0, 0, 0, 0);
    CheckSelector(GetCurrentThread(), 0x1234, FALSE, 0, 0, 0, 0);

    /* Another thread: the base is its own TEB */
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, Sleeper, Event, 0, NULL);
    ok(Thread != NULL, "CreateThread failed %lu\n", GetLastError());
    if (Thread)
    {
        THREAD_BASIC_INFORMATION Info;

        Status = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), NULL);
        ok(Status == STATUS_SUCCESS, "ThreadBasicInformation 0x%08lx\n", Status);
        if (NT_SUCCESS(Status))
            CheckSelector(Thread, 0x53, TRUE, (DWORD)Info.TebBaseAddress, 0xFFF, 0xF3, 0x40);
        CheckSelector(Thread, 0x23, TRUE, 0, 0xFFFFF, 0xFB, 0xC0);
        SetEvent(Event);
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    CloseHandle(Event);

    Length = 0;
    Status = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &Flags, sizeof(Flags), &Length);
    ok(Status == STATUS_SUCCESS, "ProcessDebugFlags 0x%08lx\n", Status);
    ok(Status != STATUS_SUCCESS || Length == sizeof(Flags), "ProcessDebugFlags length %lu\n", Length);
    Status = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &ObjectHandle, sizeof(ObjectHandle), &Length);
    ok(Status == STATUS_PORT_NOT_SET, "ProcessDebugObjectHandle 0x%08lx\n", Status);
#elif defined(_M_AMD64)
    ok(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Wow64GetThreadSelectorEntry") != NULL,
       "Wow64GetThreadSelectorEntry is not exported\n");
#else
    skip("no WoW64 on this architecture\n");
#endif
}
