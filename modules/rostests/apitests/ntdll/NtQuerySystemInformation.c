/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtQuerySystemInformation
 * COPYRIGHT:   Copyright 2019 Thomas Faber (thomas.faber@reactos.org)
 *              Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

static
void
Test_ThreadStackLimits(void)
{
    NTSTATUS Status;
    ULONG_PTR SystemRangeStart;
    PSYSTEM_PROCESS_INFORMATION Process;
    PSYSTEM_EXTENDED_THREAD_INFORMATION Thread;
    PVOID Buffer = NULL;
    SIZE_T BufferSize = 0x10000;
    ULONG Length, i, Threads = 0, Hidden = 0, Bad = 0;
    BOOL IsWow64 = FALSE;

    if (IsWow64Process(GetCurrentProcess(), &IsWow64) && IsWow64)
    {
        skip("WOW64 reports kernel stack addresses truncated to 32 bits\n");
        return;
    }

    Status = NtQuerySystemInformation(SystemRangeStartInformation,
                                      &SystemRangeStart,
                                      sizeof(SystemRangeStart),
                                      NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    for (;;)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize);
        if (!Buffer)
        {
            skip("Out of memory\n");
            return;
        }
        Status = NtQuerySystemInformation(SystemExtendedProcessInformation,
                                          Buffer,
                                          (ULONG)BufferSize,
                                          &Length);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        BufferSize *= 2;
    }

    if (!NT_SUCCESS(Status))
    {
        skip("SystemExtendedProcessInformation: 0x%lx\n", Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        return;
    }

    /* Every thread has a kernel stack. The two bounds are read separately
     * while a thread may switch to a large stack, so do not compare them. */
    Process = Buffer;
    for (;;)
    {
        Thread = (PSYSTEM_EXTENDED_THREAD_INFORMATION)(Process + 1);
        for (i = 0; i < Process->NumberOfThreads; i++, Thread++, Threads++)
        {
            if (!Thread->StackBase && !Thread->StackLimit)
            {
                Hidden++;
                continue;
            }
            if ((ULONG_PTR)Thread->StackLimit < SystemRangeStart ||
                (ULONG_PTR)Thread->StackBase < SystemRangeStart)
            {
                trace("Process %p thread %p: stack limit %p, base %p\n",
                      Thread->ThreadInfo.ClientId.UniqueProcess,
                      Thread->ThreadInfo.ClientId.UniqueThread,
                      Thread->StackLimit,
                      Thread->StackBase);
                Bad++;
            }
        }
        if (!Process->NextEntryOffset)
            break;
        Process = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Process + Process->NextEntryOffset);
    }

    ok(Threads > 0, "No threads listed\n");
    if (Hidden == Threads)
        skip("Kernel stack addresses are not disclosed\n");
    else
        ok(Bad == 0, "%lu of %lu threads have a stack bound below %p\n", Bad, Threads - Hidden, (PVOID)SystemRangeStart);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
}

static
PSYSTEM_PROCESS_INFORMATION
FindProcessEntry(
    _In_ PVOID Buffer,
    _In_ HANDLE ProcessId)
{
    PSYSTEM_PROCESS_INFORMATION Entry = Buffer;

    for (;;)
    {
        if (Entry->UniqueProcessId == ProcessId)
            return Entry;
        if (!Entry->NextEntryOffset)
            return NULL;
        Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset);
    }
}

static
void
Test_ProcessImageNames(void)
{
    NTSTATUS Status;
    PUCHAR Buffer, End;
    SIZE_T BufferSize = 0x40000;
    ULONG Length, Entries = 0;
    PSYSTEM_PROCESS_INFORMATION Entry, Self;
    WCHAR Path[MAX_PATH];
    PWCHAR Name;

    Buffer = VirtualAlloc(NULL, BufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Buffer)
    {
        skip("VirtualAlloc failed\n");
        return;
    }
    End = Buffer + BufferSize;

    /* Garbage in the output buffer, including where the image name headers
     * will go, must not influence the names the kernel composes. */
    memset(Buffer, 0xA5, BufferSize);
    Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        VirtualFree(Buffer, 0, MEM_RELEASE);
        return;
    }

    Entry = (PSYSTEM_PROCESS_INFORMATION)Buffer;
    for (;;)
    {
        Entries++;
        ok((PUCHAR)Entry >= Buffer && (PUCHAR)(Entry + 1) <= End, "Entry %p out of buffer\n", Entry);
        ok(Entry->ImageName.Length % sizeof(WCHAR) == 0, "Length %u is odd\n", Entry->ImageName.Length);
        ok(Entry->ImageName.Length <= Entry->ImageName.MaximumLength,
           "Length %u > MaximumLength %u\n", Entry->ImageName.Length, Entry->ImageName.MaximumLength);
        if (Entry->ImageName.Buffer)
        {
            ok((PUCHAR)Entry->ImageName.Buffer >= (PUCHAR)(Entry + 1) &&
               (PUCHAR)Entry->ImageName.Buffer + Entry->ImageName.MaximumLength <= End,
               "Name buffer %p (%u) outside the output buffer\n",
               Entry->ImageName.Buffer, Entry->ImageName.MaximumLength);
        }
        else
        {
            ok(Entry->ImageName.Length == 0 && Entry->ImageName.MaximumLength == 0,
               "NULL name with lengths %u/%u\n",
               Entry->ImageName.Length, Entry->ImageName.MaximumLength);
        }
        if (!Entry->NextEntryOffset)
            break;
        Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset);
    }
    ok(Entries > 1, "Only %lu entries\n", Entries);

    /* This process: the name comes from the image section */
    Self = FindProcessEntry(Buffer, (HANDLE)(ULONG_PTR)GetCurrentProcessId());
    ok(Self != NULL, "Own process not found\n");
    if (Self && GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path)))
    {
        Name = wcsrchr(Path, L'\\');
        Name = Name ? Name + 1 : Path;
        ok(Self->ImageName.Length == wcslen(Name) * sizeof(WCHAR) &&
           Self->ImageName.Buffer &&
           !_wcsnicmp(Self->ImageName.Buffer, Name, Self->ImageName.Length / sizeof(WCHAR)),
           "Own name is '%.*ls', expected '%ls'\n",
           Self->ImageName.Length / sizeof(WCHAR), Self->ImageName.Buffer, Name);
    }

    /* The System process has no image section: its name is converted from
     * EPROCESS::ImageFileName in the kernel. */
    Entry = FindProcessEntry(Buffer, (HANDLE)(ULONG_PTR)4);
    if (Entry)
    {
        ok(Entry->ImageName.Length == 6 * sizeof(WCHAR) &&
           Entry->ImageName.Buffer &&
           !_wcsnicmp(Entry->ImageName.Buffer, L"System", 6),
           "System name is '%.*ls' (%u)\n",
           Entry->ImageName.Length / sizeof(WCHAR), Entry->ImageName.Buffer, Entry->ImageName.Length);
    }

    /* A buffer that is too short fails cleanly and never writes past its
     * end: put it right in front of an inaccessible page. */
    {
        ULONG Old;
        PUCHAR Guard = Buffer + BufferSize - 0x1000;

        if (Length > 16 && Length - 8 <= BufferSize - 0x1000 &&
            VirtualProtect(Guard, 0x1000, PAGE_NOACCESS, &Old))
        {
            Status = NtQuerySystemInformation(SystemProcessInformation,
                                              Guard - (Length - 8), Length - 8, &Length);
            ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
            VirtualProtect(Guard, 0x1000, Old, &Old);
        }
    }

    VirtualFree(Buffer, 0, MEM_RELEASE);
}

typedef struct _FLIP_CONTEXT
{
    PVOID Address;
    volatile LONG Stop;
} FLIP_CONTEXT;

static
DWORD
WINAPI
FlipThread(PVOID Param)
{
    FLIP_CONTEXT *Flip = Param;
    DWORD Old;

    while (!Flip->Stop)
    {
        VirtualProtect(Flip->Address, 0x1000, PAGE_NOACCESS, &Old);
        Sleep(1);
        VirtualProtect(Flip->Address, 0x1000, PAGE_READWRITE, &Old);
        Sleep(1);
    }
    return 0;
}

static
DWORD
WINAPI
NopThread(PVOID Param)
{
    return 0;
}

static
void
Test_FaultReleasesProcessLock(void)
{
    NTSTATUS Status;
    PUCHAR Buffer, Tail;
    ULONG Needed, Length, Attempt, Faults = 0, Old;
    HANDLE Flipper, Thread;
    FLIP_CONTEXT Flip;
    DWORD Wait, Deadline;

    Status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &Needed);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
    Needed = (Needed + 0x1000) & ~0xFFF;

    /* The buffer ends in a page the flipper thread keeps making
     * inaccessible and accessible again. The kernel touches the whole
     * buffer when it starts, so most calls fail before any lock is taken;
     * a few are preempted later, with the entry for the newest process,
     * which is normally this one, half written and its lock held. */
    Buffer = VirtualAlloc(NULL, Needed + 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Buffer)
    {
        skip("VirtualAlloc failed\n");
        return;
    }
    Tail = Buffer + Needed - 0x1000;

    Flip.Address = Tail;
    Flip.Stop = 0;
    Flipper = CreateThread(NULL, 0, FlipThread, &Flip, 0, NULL);
    if (!Flipper)
    {
        skip("CreateThread failed\n");
        VirtualFree(Buffer, 0, MEM_RELEASE);
        return;
    }
    SetThreadPriority(Flipper, THREAD_PRIORITY_TIME_CRITICAL);

    Deadline = GetTickCount() + 5000;
    for (Attempt = 0; (LONG)(Deadline - GetTickCount()) > 0; Attempt++)
    {
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Needed, &Length);
        if (Status == STATUS_ACCESS_VIOLATION)
            Faults++;
        else if (Status != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH)
            ok(0, "Unexpected status %08lx\n", Status);
    }

    Flip.Stop = 1;
    WaitForSingleObject(Flipper, INFINITE);
    CloseHandle(Flipper);
    VirtualProtect(Tail, 0x1000, PAGE_READWRITE, &Old);

    trace("%lu faulting calls out of %lu\n", Faults, Attempt);
    if (!Faults)
    {
        skip("Could not make a call fault\n");
    }
    else
    {
        /* The fault is reported, the caller is still usable... */
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Needed, &Length);
        ok(Status == STATUS_SUCCESS || Status == STATUS_INFO_LENGTH_MISMATCH,
           "Status %08lx after the faults\n", Status);

        /* ...and no process lock is left held: creating a thread takes the
         * lock of this process exclusively and would wait forever. */
        Thread = CreateThread(NULL, 0, NopThread, NULL, 0, NULL);
        ok(Thread != NULL, "CreateThread failed after the faults: %lu\n", GetLastError());
        if (Thread)
        {
            Wait = WaitForSingleObject(Thread, 10000);
            ok_dec(Wait, WAIT_OBJECT_0);
            CloseHandle(Thread);
        }
    }

    VirtualFree(Buffer, 0, MEM_RELEASE);
}

static
void
Test_PageFileInformation(void)
{
    PSYSTEM_PAGEFILE_INFORMATION Entry;
    UCHAR Buffer[4096];
    NTSTATUS Status;
    ULONG Length, Offset, Entries = 0;
    BOOL IsWow64 = FALSE;
    WCHAR Path[MAX_PATH];
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    IsWow64Process(GetCurrentProcess(), &IsWow64);

    /* A buffer smaller than one entry fails (the required length is not defined by Windows for WoW64) */
    Length = 0xdeadbeef;
    Status = NtQuerySystemInformation(SystemPageFileInformation, Buffer, 0, &Length);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    RtlFillMemory(Buffer, sizeof(Buffer), 0xcd);
    Length = 0;
    Status = NtQuerySystemInformation(SystemPageFileInformation, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    if (Length == 0)
    {
        skip("No paging file\n");
        return;
    }
    ok(Length >= sizeof(*Entry), "Length = %lu\n", Length);

    /* One entry per paging file, each followed by its NT name */
    for (Offset = 0; ; )
    {
        PWCHAR Name;
        SIZE_T NameChars;

        ok(Offset + sizeof(*Entry) <= Length, "entry at %lu beyond Length %lu\n", Offset, Length);
        if (Offset + sizeof(*Entry) > Length)
            break;
        Entry = (PSYSTEM_PAGEFILE_INFORMATION)(Buffer + Offset);
        Entries++;

        ok(Entry->TotalSize > 0, "TotalSize = %lu\n", Entry->TotalSize);
        ok(Entry->TotalInUse <= Entry->TotalSize, "TotalInUse %lu > TotalSize %lu\n", Entry->TotalInUse, Entry->TotalSize);
        ok(Entry->PeakUsage >= Entry->TotalInUse, "PeakUsage %lu < TotalInUse %lu\n", Entry->PeakUsage, Entry->TotalInUse);
        ok(Entry->PeakUsage <= Entry->TotalSize, "PeakUsage %lu > TotalSize %lu\n", Entry->PeakUsage, Entry->TotalSize);

        ok(Entry->PageFileName.Length != 0, "empty paging file name\n");
        ok_int(Entry->PageFileName.MaximumLength, Entry->PageFileName.Length + sizeof(WCHAR));
        Name = Entry->PageFileName.Buffer;
        ok((PUCHAR)Name >= (PUCHAR)(Entry + 1), "name %p before the end of the entry %p\n", Name, Entry + 1);
        ok((PUCHAR)Name + Entry->PageFileName.MaximumLength <= Buffer + Length,
           "name %p +%u beyond Length %lu\n", Name, Entry->PageFileName.MaximumLength, Length);
        if ((PUCHAR)Name >= (PUCHAR)(Entry + 1) &&
            (PUCHAR)Name + Entry->PageFileName.MaximumLength <= Buffer + Length)
        {
            NameChars = Entry->PageFileName.Length / sizeof(WCHAR);
            ok(Name[NameChars] == UNICODE_NULL, "name is not terminated\n");
            ok(NameChars > 4 && !_wcsnicmp(Name, L"\\??\\", 4), "name %.*ls is not an NT DOS path\n", (int)NameChars, Name);
            ok(NameChars > 8 && !_wcsnicmp(Name + NameChars - 4, L".sys", 4), "name %.*ls does not end in .sys\n", (int)NameChars, Name);
            if (NameChars > 4 && NameChars < MAX_PATH + 4)
            {
                WIN32_FIND_DATAW FindData;
                HANDLE Find;

                /* The file is in use: GetFileAttributes fails with a sharing violation, enumeration works */
                wcsncpy(Path, Name + 4, NameChars - 4);
                Path[NameChars - 4] = UNICODE_NULL;
                Find = FindFirstFileW(Path, &FindData);
                ok(Find != INVALID_HANDLE_VALUE, "%ls does not exist (error %lu)\n", Path, GetLastError());
                if (Find != INVALID_HANDLE_VALUE)
                {
                    ULONGLONG FileSize = ((ULONGLONG)FindData.nFileSizeHigh << 32) | FindData.nFileSizeLow;

                    /* TotalSize is the size of the file in pages (the file may be growing) */
                    ok(FileSize >= (ULONGLONG)Entry->TotalSize * si.dwPageSize,
                       "%ls: file size %I64u, TotalSize %lu pages\n", Path, FileSize, Entry->TotalSize);
                    FindClose(Find);
                }
            }
        }

        if (Entry->NextEntryOffset == 0)
            break;
        ok(Entry->NextEntryOffset >= sizeof(*Entry), "NextEntryOffset %lu\n", Entry->NextEntryOffset);
        if (Entry->NextEntryOffset < sizeof(*Entry))
            break;
        Offset += Entry->NextEntryOffset;
    }
    ok(Entries >= 1, "Entries = %lu\n", Entries);

    /* One byte short of everything fails and reports the full length */
    if (!IsWow64)
    {
        ULONG Full = Length, Reported = 0;

        Status = NtQuerySystemInformation(SystemPageFileInformation, Buffer, Full - 1, &Reported);
        ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);
        ok_dec(Reported, Full);
    }
}

typedef struct _PAGEFILE_RACE
{
    PVOID Buffer;
    ULONG Size;
    volatile LONG Stop;
    volatile LONG Calls;
    volatile LONG Faults;
    volatile LONG Bad;
} PAGEFILE_RACE;

static
DWORD
WINAPI
PageFileQueryThread(
    _In_ PVOID Context)
{
    PAGEFILE_RACE *Race = Context;
    ULONG Length;
    NTSTATUS Status;

    while (!Race->Stop)
    {
        Status = NtQuerySystemInformation(SystemPageFileInformation, Race->Buffer, Race->Size, &Length);
        InterlockedIncrement(&Race->Calls);
        if (Status == STATUS_ACCESS_VIOLATION)
            InterlockedIncrement(&Race->Faults);
        else if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH)
            InterlockedIncrement(&Race->Bad);
    }
    return 0;
}

static
void
Test_PageFileBufferFaults(void)
{
    PAGEFILE_RACE Race;
    HANDLE Thread, Section;
    PVOID View;
    NTSTATUS Status;
    ULONG Length = 0, Iter;
    DWORD Wait;
    UCHAR Small[4096];

    Status = NtQuerySystemInformation(SystemPageFileInformation, Small, sizeof(Small), &Length);
    if (!NT_SUCCESS(Status) || Length == 0)
    {
        skip("No paging file information (0x%lx)\n", Status);
        return;
    }

    /* Another thread decommits the buffer while it is being filled: faults must be reported, not hang or bugcheck */
    RtlZeroMemory(&Race, sizeof(Race));
    Race.Size = 0x10000;
    Race.Buffer = VirtualAlloc(NULL, Race.Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Race.Buffer != NULL, "VirtualAlloc failed\n");
    if (Race.Buffer)
    {
        Thread = CreateThread(NULL, 0, PageFileQueryThread, &Race, 0, NULL);
        ok(Thread != NULL, "CreateThread failed\n");
        if (Thread)
        {
            for (Iter = 0; Iter < 20000; Iter++)
            {
                VirtualFree(Race.Buffer, Race.Size, MEM_DECOMMIT);
                VirtualAlloc(Race.Buffer, Race.Size, MEM_COMMIT, PAGE_READWRITE);
            }
            InterlockedExchange(&Race.Stop, 1);
            Wait = WaitForSingleObject(Thread, 30000);
            ok_dec(Wait, WAIT_OBJECT_0);
            if (Wait != WAIT_OBJECT_0)
                TerminateThread(Thread, 0);
            CloseHandle(Thread);
            ok(Race.Calls > 0, "no query completed\n");
            ok(Race.Bad == 0, "%ld queries failed with an unexpected status\n", Race.Bad);
        }
        VirtualFree(Race.Buffer, 0, MEM_RELEASE);
    }

    /* The system still answers (a leaked lock would hang or bugcheck here) */
    Length = 0;
    Status = NtQuerySystemInformation(SystemPageFileInformation, Small, sizeof(Small), &Length);
    ok_hex(Status, STATUS_SUCCESS);

    /* A view of a paging file backed section: its pages may be swapped in while the buffer is written */
    Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x100000, NULL);
    ok(Section != NULL, "CreateFileMappingW failed %lu\n", GetLastError());
    if (Section)
    {
        View = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
        ok(View != NULL, "MapViewOfFile failed %lu\n", GetLastError());
        if (View)
        {
            RtlFillMemory(View, 0x100000, 0xab);
            SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
            Length = 0;
            Status = NtQuerySystemInformation(SystemPageFileInformation, View, 0x100000, &Length);
            ok_hex(Status, STATUS_SUCCESS);
            if (NT_SUCCESS(Status))
                ok(((PSYSTEM_PAGEFILE_INFORMATION)View)->TotalSize != 0, "TotalSize is 0\n");
            UnmapViewOfFile(View);
        }
        CloseHandle(Section);
    }
}

/* The page-fault counters count in the memory manager: new pages touched are faults and demand-zero faults, a
 * write to a page of a private view of a file is a copy on write (measured on Windows 10 22H2: +1002 faults and
 * +1102 demand-zero faults for 1000 new pages, +200 faults and +200 copies for 200 pages of a private view). */
static
BOOLEAN
QueryPerformance(_Out_ SYSTEM_PERFORMANCE_INFORMATION *Info)
{
    /* Windows 10 returns 344 bytes, more than the structure of the headers */
    ULONG Buffer[128];
    ULONG Length = 0;
    NTSTATUS Status;

    memset(Buffer, 0, sizeof(Buffer));
    Status = NtQuerySystemInformation(SystemPerformanceInformation, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;
    ok(Length >= sizeof(*Info), "Length is %lu\n", Length);
    RtlCopyMemory(Info, Buffer, sizeof(*Info));
    return TRUE;
}

static
void
Test_PageFaultCounters(void)
{
    SYSTEM_PERFORMANCE_INFORMATION First, Second, Third, Fourth;
    enum { NewPages = 256, FilePages = 64 };
    PUCHAR Memory, View;
    WCHAR Path[MAX_PATH];
    HANDLE File, Mapping;
    ULONG i;

    if (!QueryPerformance(&First))
        return;
    ok(First.PageFaultCount > 0, "PageFaultCount is %lu\n", First.PageFaultCount);
    ok(First.DemandZeroCount > 0, "DemandZeroCount is %lu\n", First.DemandZeroCount);
    ok(First.PageReadCount > 0, "PageReadCount is %lu\n", First.PageReadCount);
    ok(First.PageReadIoCount > 0 && First.PageReadIoCount <= First.PageReadCount,
       "PageReadIoCount is %lu, PageReadCount %lu\n", First.PageReadIoCount, First.PageReadCount);

    Memory = VirtualAlloc(NULL, NewPages * PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Memory != NULL, "VirtualAlloc failed with %lu\n", GetLastError());
    if (!Memory)
        return;

    if (!QueryPerformance(&Second))
        return;
    ok(Second.PageFaultCount >= First.PageFaultCount, "PageFaultCount fell: %lu, %lu\n", First.PageFaultCount, Second.PageFaultCount);

    for (i = 0; i < NewPages; i++)
        Memory[i * PAGE_SIZE] = 1;
    if (!QueryPerformance(&Third))
        return;
    ok(Third.PageFaultCount - Second.PageFaultCount >= NewPages,
       "PageFaultCount rose by %lu for %d new pages\n", Third.PageFaultCount - Second.PageFaultCount, NewPages);
    ok(Third.DemandZeroCount - Second.DemandZeroCount >= NewPages,
       "DemandZeroCount rose by %lu for %d new pages\n", Third.DemandZeroCount - Second.DemandZeroCount, NewPages);
    VirtualFree(Memory, 0, MEM_RELEASE);

    /* A private view of a file: a write copies the page */
    GetTempPathW(RTL_NUMBER_OF(Path), Path);
    wcscat(Path, L"pf_cow.tmp");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile failed with %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(File, FilePages * PAGE_SIZE, NULL, FILE_BEGIN);
    SetEndOfFile(File);
    Mapping = CreateFileMappingW(File, NULL, PAGE_WRITECOPY, 0, FilePages * PAGE_SIZE, NULL);
    ok(Mapping != NULL, "CreateFileMapping failed with %lu\n", GetLastError());
    View = Mapping ? MapViewOfFile(Mapping, FILE_MAP_COPY, 0, 0, 0) : NULL;
    ok(View != NULL, "MapViewOfFile failed with %lu\n", GetLastError());
    if (View)
    {
        QueryPerformance(&Third);
        for (i = 0; i < FilePages; i++)
            View[i * PAGE_SIZE] = 1;
        if (QueryPerformance(&Fourth))
        {
            ok(Fourth.PageFaultCount - Third.PageFaultCount >= FilePages,
               "PageFaultCount rose by %lu for %d pages of a private view\n", Fourth.PageFaultCount - Third.PageFaultCount, FilePages);
            ok(Fourth.CopyOnWriteCount - Third.CopyOnWriteCount >= FilePages,
               "CopyOnWriteCount rose by %lu for %d pages of a private view\n", Fourth.CopyOnWriteCount - Third.CopyOnWriteCount, FilePages);
        }
        UnmapViewOfFile(View);
    }
    if (Mapping)
        CloseHandle(Mapping);
    CloseHandle(File);
}

static
DWORD
WINAPI
HandleChurnThread(
    _In_ PVOID Context)
{
    volatile LONG *Stop = Context;
    HANDLE Handles[16] = { NULL };
    ULONG i = 0;

    while (!*Stop)
    {
        i = (i + 5) % RTL_NUMBER_OF(Handles);
        if (Handles[i])
        {
            CloseHandle(Handles[i]);
            Handles[i] = NULL;
        }
        else
        {
            Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(Handles); i++)
    {
        if (Handles[i])
            CloseHandle(Handles[i]);
    }
    return 0;
}

static
void
Test_HandleInformationCount(
    _In_ ULONG InfoClass,
    _In_ ULONG HeaderSize,
    _In_ ULONG EntrySize)
{
    volatile LONG Stop = 0;
    HANDLE Threads[4];
    PVOID Buffer = NULL;
    ULONG Size = 0x40000, Length, Queries = 0, Bad = 0, Failed = 0, i;
    ULONG Start = GetTickCount();
    NTSTATUS Status;

    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
        Threads[i] = CreateThread(NULL, 0, HandleChurnThread, (PVOID)&Stop, 0, NULL);

    while (GetTickCount() - Start < 3000)
    {
        ULONG Tries = 0;

        do
        {
            Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
            if (!Buffer)
                break;
            Length = 0;
            Status = NtQuerySystemInformation(InfoClass, Buffer, Size, &Length);
            if (Status == STATUS_INFO_LENGTH_MISMATCH)
            {
                RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
                Buffer = NULL;
                Size = (Length > Size ? Length : Size) + 0x10000;
            }
        } while (Status == STATUS_INFO_LENGTH_MISMATCH && ++Tries < 20);

        if (!Buffer)
            break;
        Queries++;
        if (!NT_SUCCESS(Status))
        {
            Failed++;
        }
        else if (*(PULONG)Buffer > (Length - HeaderSize) / EntrySize)
        {
            /* NumberOfHandles claims entries past the ones the kernel wrote */
            Bad++;
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Buffer = NULL;
    }

    Stop = 1;
    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
    {
        if (Threads[i])
        {
            WaitForSingleObject(Threads[i], INFINITE);
            CloseHandle(Threads[i]);
        }
    }
    ok(Queries > 0, "class %lu: no query completed\n", InfoClass);
    ok(Failed == 0, "class %lu: %lu of %lu queries failed\n", InfoClass, Failed, Queries);
    ok(Bad == 0, "class %lu: NumberOfHandles exceeded the returned entries in %lu of %lu queries\n", InfoClass, Bad, Queries);
}

START_TEST(NtQuerySystemInformation)
{
    NTSTATUS Status;

    Status = NtQuerySystemInformation(0, NULL, 0, NULL);
    ok_hex(Status, STATUS_INFO_LENGTH_MISMATCH);

    Status = NtQuerySystemInformation(0x80000000, NULL, 0, NULL);
    ok_hex(Status, STATUS_INVALID_INFO_CLASS);

    Test_ThreadStackLimits();
    Test_PageFileInformation();
    Test_PageFileBufferFaults();
    Test_ProcessImageNames();
    Test_FaultReleasesProcessLock();
    Test_PageFaultCounters();
    Test_HandleInformationCount(SystemHandleInformation,
                                FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION, Handles),
                                sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
    Test_HandleInformationCount(SystemExtendedHandleInformation,
                                FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles),
                                sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
}
