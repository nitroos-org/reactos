/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtQueryVirtualMemory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static
VOID
CheckViewPage(
    PVOID BaseAddress,
    PVOID Address,
    ULONG State,
    ULONG Protect,
    SIZE_T RegionSize)
{
    NTSTATUS Status;
    MEMORY_BASIC_INFORMATION Info;
    SIZE_T ReturnLength = 0;

    RtlFillMemory(&Info, sizeof(Info), 0x55);
    Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  Address,
                                  MemoryBasicInformation,
                                  &Info,
                                  sizeof(Info),
                                  &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(ReturnLength, sizeof(Info));
    ok_ptr(Info.BaseAddress, Address);
    ok_ptr(Info.AllocationBase, BaseAddress);
    ok_hex(Info.State, State);
    ok_hex(Info.Protect, Protect);
    ok_hex(Info.Type, MEM_MAPPED);
    ok_size_t(Info.RegionSize, RegionSize);
}

static
VOID
Test_SecReserveAccessedPage(VOID)
{
    NTSTATUS Status;
    HANDLE hSection;
    LARGE_INTEGER MaximumSize;
    PVOID BaseAddress = NULL;
    PVOID CommitAddress;
    SIZE_T ViewSize = 0;
    SIZE_T CommitSize;
    PUCHAR Page1;
    volatile UCHAR Value = 0;

    MaximumSize.QuadPart = 3 * PAGE_SIZE;
    Status = NtCreateSection(&hSection,
                             SECTION_ALL_ACCESS,
                             NULL,
                             &MaximumSize,
                             PAGE_READWRITE,
                             SEC_RESERVE,
                             NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    Status = NtMapViewOfSection(hSection,
                                NtCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        NtClose(hSection);
        return;
    }
    ok_size_t(ViewSize, 3 * PAGE_SIZE);

    /* Pages 1 and 2 of the view are reserved */
    Page1 = (PUCHAR)BaseAddress + PAGE_SIZE;
    CheckViewPage(BaseAddress, Page1, MEM_RESERVE, 0, 2 * PAGE_SIZE);

    /* Touching a reserved page faults and leaves a prototype-format PTE */
    Status = STATUS_SUCCESS;
    _SEH2_TRY
    {
        Value = *Page1;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* The page is still reserved, like the one after it */
    CheckViewPage(BaseAddress, Page1, MEM_RESERVE, 0, 2 * PAGE_SIZE);

    /* Commit the touched page: now it is committed on its own */
    CommitAddress = Page1;
    CommitSize = PAGE_SIZE;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                     &CommitAddress,
                                     0,
                                     &CommitSize,
                                     MEM_COMMIT,
                                     PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        CheckViewPage(BaseAddress, Page1, MEM_COMMIT, PAGE_READWRITE, PAGE_SIZE);

        Status = STATUS_SUCCESS;
        _SEH2_TRY
        {
            *Page1 = 0x5A;
            Value = *Page1;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_hex(Value, 0x5A);
    }

    Status = NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    ok_ntstatus(Status, STATUS_SUCCESS);
    NtClose(hSection);
}

/*
 * MemorySectionName
 *
 * The result is a UNICODE_STRING header followed by its characters. The
 * kernel has to build it from its own state, never from what the caller's
 * buffer happens to hold while the call is running.
 */
static
VOID
Test_SectionNameBasic(VOID)
{
    NTSTATUS Status;
    PMEMORY_SECTION_NAME Name;
    PVOID Buffer;
    SIZE_T Size = 0x1000, ReturnLength = 0;
    PVOID Ntdll = GetModuleHandleW(L"ntdll.dll");
    PUCHAR Canary;

    Buffer = VirtualAlloc(NULL, 2 * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Buffer != NULL, "VirtualAlloc failed\n");
    if (!Buffer)
        return;
    Name = Buffer;
    Canary = (PUCHAR)Buffer + Size;
    RtlFillMemory(Buffer, 2 * PAGE_SIZE, 0x77);

    /* Header fields supplied by the caller are meaningless input: garbage must be ignored, not followed */
    Name->SectionFileName.Buffer = (PWSTR)(ULONG_PTR)(sizeof(PVOID) == 8 ? 0xFFFFF78000000000ULL : 0x80001000);
    Name->SectionFileName.Length = 0xFFFE;
    Name->SectionFileName.MaximumLength = 0xFFFF;

    Status = NtQueryVirtualMemory(NtCurrentProcess(), Ntdll, MemorySectionName, Buffer, Size, &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_ptr(Name->SectionFileName.Buffer, (PWSTR)(Name + 1));
        ok(Name->SectionFileName.Length > 0 && Name->SectionFileName.Length <= Name->SectionFileName.MaximumLength,
           "Length %u Max %u\n", Name->SectionFileName.Length, Name->SectionFileName.MaximumLength);
        ok_int(Name->SectionFileName.MaximumLength, Size - sizeof(*Name));
        ok_size_t(ReturnLength, Name->SectionFileName.Length + sizeof(*Name));
        ok(_wcsnicmp((PWSTR)((PUCHAR)Name->SectionFileName.Buffer + Name->SectionFileName.Length - 9 * sizeof(WCHAR)),
                     L"ntdll.dll", 9) == 0, "Name is %wZ\n", &Name->SectionFileName);
    }
    ok_int(*Canary, 0x77);

    /* A buffer that cannot hold the name must never be overrun */
    RtlFillMemory(Buffer, 2 * PAGE_SIZE, 0x77);
    Size = sizeof(*Name) + 8;
    Canary = (PUCHAR)Buffer + Size;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Ntdll, MemorySectionName, Buffer, Size, &ReturnLength);
    if (NT_SUCCESS(Status))
    {
        ok(Name->SectionFileName.Length <= 8, "Length %u\n", Name->SectionFileName.Length);
        ok(Name->SectionFileName.MaximumLength <= 8, "Max %u\n", Name->SectionFileName.MaximumLength);
    }
    ok_int(Canary[0], 0x77);
    ok_int(Canary[1], 0x77);

    VirtualFree(Buffer, 0, MEM_RELEASE);
}

static volatile LONG SectionNameRaceStop;
static PMEMORY_SECTION_NAME SectionNameRaceHeader;
static PVOID SectionNameRaceVictim;

static
DWORD
WINAPI
SectionNameRaceFlipper(PVOID Context)
{
    volatile UNICODE_STRING *Header = &SectionNameRaceHeader->SectionFileName;

    UNREFERENCED_PARAMETER(Context);
    while (!SectionNameRaceStop)
    {
        Header->Buffer = SectionNameRaceVictim;
        Header->MaximumLength = 0xFFFF;
    }
    return 0;
}

/*
 * Double fetch: a second thread rewrites the header in the caller's buffer
 * while the call is in progress. The target is a harmless user page, not
 * kernel memory. If the kernel ever reads the header back from the buffer, the
 * name lands in that page. The window is a few instructions wide, so this is
 * a stress test: a pass proves little by itself, a failure is a real bug.
 */
static
VOID
Test_SectionNameHeaderRace(VOID)
{
    NTSTATUS Status = STATUS_SUCCESS;
    SYSTEM_INFO SystemInfo;
    PVOID Buffer, Victim;
    HANDLE Thread;
    ULONG i, Iterations = 0, Hits = 0;
    ULONG Start;
    SIZE_T ReturnLength;
    PVOID Ntdll = GetModuleHandleW(L"ntdll.dll");

    GetSystemInfo(&SystemInfo);
    if (SystemInfo.dwNumberOfProcessors < 2)
    {
        skip("Needs more than one processor\n");
        return;
    }

    Buffer = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Victim = VirtualAlloc(NULL, 4 * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(Buffer && Victim, "VirtualAlloc failed\n");
    if (!Buffer || !Victim)
        return;

    SectionNameRaceHeader = Buffer;
    SectionNameRaceVictim = Victim;
    SectionNameRaceStop = 0;
    Thread = CreateThread(NULL, 0, SectionNameRaceFlipper, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    if (Thread)
    {
        Start = GetTickCount();
        while (GetTickCount() - Start < 5000 && Iterations < 200000 && !Hits)
        {
            for (i = 0; i < 1000; i++)
            {
                Status = NtQueryVirtualMemory(NtCurrentProcess(), Ntdll, MemorySectionName,
                                              Buffer, PAGE_SIZE, &ReturnLength);
                if (!NT_SUCCESS(Status))
                {
                    ok_ntstatus(Status, STATUS_SUCCESS);
                    break;
                }
                Iterations++;
                if (*(volatile ULONG *)Victim != 0)
                {
                    Hits++;
                    break;
                }
            }
            if (!NT_SUCCESS(Status))
                break;
        }
        SectionNameRaceStop = 1;
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    ok(Hits == 0, "Kernel followed a header rewritten by another thread (%lu iterations)\n", Iterations);
    trace("SectionName race: %lu iterations, %lu hits\n", Iterations, Hits);

    VirtualFree(Buffer, 0, MEM_RELEASE);
    VirtualFree(Victim, 0, MEM_RELEASE);
}

/* The address is looked up in the process that is being queried, not in the caller */
static
VOID
Test_SectionNameOtherProcess(VOID)
{
    NTSTATUS Status;
    WCHAR Path[MAX_PATH];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    PROCESS_BASIC_INFORMATION Pbi;
    PVOID ImageBase = NULL;
    SIZE_T Read;
    UCHAR Buffer[0x400];
    PMEMORY_SECTION_NAME Name = (PMEMORY_SECTION_NAME)Buffer;
    SIZE_T ReturnLength;

    GetSystemDirectoryW(Path, _countof(Path));
    StringCchCatW(Path, _countof(Path), L"\\cmd.exe");
    if (!CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi))
    {
        skip("Could not start %ls: %lu\n", Path, GetLastError());
        return;
    }

    Status = NtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &Pbi, sizeof(Pbi), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status) &&
        ReadProcessMemory(Pi.hProcess,
                          (PUCHAR)Pbi.PebBaseAddress + FIELD_OFFSET(PEB, ImageBaseAddress),
                          &ImageBase, sizeof(ImageBase), &Read) && ImageBase)
    {
        RtlFillMemory(Buffer, sizeof(Buffer), 0xCC);
        Status = NtQueryVirtualMemory(Pi.hProcess, ImageBase, MemorySectionName,
                                      Buffer, sizeof(Buffer), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok(Name->SectionFileName.Length >= 7 * sizeof(WCHAR) &&
               _wcsnicmp((PWSTR)((PUCHAR)Name->SectionFileName.Buffer + Name->SectionFileName.Length - 7 * sizeof(WCHAR)),
                         L"cmd.exe", 7) == 0,
               "Expected cmd.exe, got %wZ\n", &Name->SectionFileName);
        }

        /* Same address, caller's own space: must not resolve to the child's image */
        Status = NtQueryVirtualMemory(NtCurrentProcess(), ImageBase, MemorySectionName,
                                      Buffer, sizeof(Buffer), &ReturnLength);
        if (NT_SUCCESS(Status))
        {
            ok(_wcsnicmp((PWSTR)((PUCHAR)Name->SectionFileName.Buffer + Name->SectionFileName.Length - 7 * sizeof(WCHAR)),
                         L"cmd.exe", 7) != 0 || Name->SectionFileName.Length < 7 * sizeof(WCHAR),
               "Own space returned %wZ\n", &Name->SectionFileName);
        }
    }
    else
    {
        skip("Could not find the child image base\n");
    }

    TerminateProcess(Pi.hProcess, 0);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
}

#ifdef _WIN64
#define TEST_KERNEL_ADDRESS ((PVOID)(ULONG_PTR)0xFFFF800000000000ull)
#else
#define TEST_KERNEL_ADDRESS ((PVOID)(ULONG_PTR)0xFFFF0000ul)
#endif

/* Windows 10 22H2 (measured): an unknown class fails with STATUS_INVALID_INFO_CLASS before the process
 * handle or the address is looked at, and writes nothing. */
static
VOID
Test_InvalidClasses(VOID)
{
    static const ULONG Classes[] = { 9, 10, 14, 15, 99, 0x100, 0x7FFFFFFF, 0xFFFFFFFF };
    UCHAR Buffer[0x40];
    SIZE_T ReturnLength;
    NTSTATUS Status;
    ULONG i, j;

    for (i = 0; i < ARRAYSIZE(Classes); i++)
    {
        PVOID Addresses[] = { Buffer, (PVOID)(ULONG_PTR)0x1000, TEST_KERNEL_ADDRESS };
        HANDLE Handles[] = { NtCurrentProcess(), (HANDLE)(ULONG_PTR)0x1230, NULL };

        for (j = 0; j < ARRAYSIZE(Addresses); j++)
        {
            RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
            ReturnLength = 0xDEAD;
            Status = NtQueryVirtualMemory(Handles[j], Addresses[j], (MEMORY_INFORMATION_CLASS)Classes[i],
                                          Buffer, sizeof(Buffer), &ReturnLength);
            ok(Status == STATUS_INVALID_INFO_CLASS, "class %lx: status %lx\n", Classes[i], Status);
            ok(ReturnLength == 0xDEAD, "class %lx: ReturnLength %Ix\n", Classes[i], ReturnLength);
            ok(Buffer[0] == 0xAA && Buffer[sizeof(Buffer) - 1] == 0xAA, "class %lx: buffer written\n", Classes[i]);
        }
    }
}

typedef struct _TEST_WS_EX_ENTRY
{
    PVOID VirtualAddress;
    ULONG_PTR VirtualAttributes;
} TEST_WS_EX_ENTRY;

static
NTSTATUS
QueryWsEx(HANDLE Process, PVOID BaseAddress, TEST_WS_EX_ENTRY *Entries, SIZE_T Length, PSIZE_T ReturnLength)
{
    return NtQueryVirtualMemory(Process, BaseAddress, (MEMORY_INFORMATION_CLASS)4, Entries, Length, ReturnLength);
}

/* MemoryWorkingSetExInformation (class 4), measured on Windows 10 22H2 x64 */
static
VOID
Test_WorkingSetEx(VOID)
{
    PUCHAR Private = NULL;
    SIZE_T Size = 0x10000, ReturnLength;
    TEST_WS_EX_ENTRY Entries[6];
    HANDLE Section;
    LARGE_INTEGER MaxSize;
    PVOID View = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;
    PVOID Image = GetModuleHandleW(NULL);

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Private, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    Size = 0x2000;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Private, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Private[0] = 1;     /* touched; the second page is committed and never touched; the third is reserved */

    MaxSize.QuadPart = 0x2000;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &MaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = NtMapViewOfSection(Section, NtCurrentProcess(), &View, 0, 0, NULL, &ViewSize, ViewShare, 0, PAGE_READWRITE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status)) *(volatile UCHAR *)View = 7;
    }

    RtlFillMemory(Entries, sizeof(Entries), 0xAA);
    Entries[0].VirtualAddress = Private;
    Entries[1].VirtualAddress = Private + 0x1000;
    Entries[2].VirtualAddress = Private + 0x2000;
    Entries[3].VirtualAddress = (PVOID)(ULONG_PTR)0x1000;
    Entries[4].VirtualAddress = View ? View : Private;
    Entries[5].VirtualAddress = Image;
    ReturnLength = 0xDEAD;
    Status = QueryWsEx(NtCurrentProcess(), NULL, Entries, sizeof(Entries), &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(ReturnLength, sizeof(Entries));
    ok_ptr(Entries[0].VirtualAddress, Private);
#ifdef _WIN64
    ok_hex(Entries[0].VirtualAttributes & 0x7FFF, 0x41);       /* valid, PAGE_READWRITE, not shared */
    ok_hex((Entries[0].VirtualAttributes >> 24) & 7, 5);       /* default priority */
    ok_hex(Entries[1].VirtualAttributes, 0);                   /* committed, never touched */
    ok_hex(Entries[2].VirtualAttributes, 0);                   /* reserved */
    ok_hex(Entries[3].VirtualAttributes, 0);                   /* free */
    if (View) ok_hex(Entries[4].VirtualAttributes & 0xFFFF, 0x8043);  /* valid, share count 1, PAGE_READWRITE, shared */
    ok_hex(Entries[5].VirtualAttributes & 0x8001, 0x8001);     /* the image: valid and shared */
#endif

    /* Lengths: one entry is the least, a partial entry at the end is ignored, ReturnLength is the length given */
    RtlFillMemory(Entries, sizeof(Entries), 0xAA);
    Entries[0].VirtualAddress = Private;
    ReturnLength = 0xDEAD;
    Status = QueryWsEx(NtCurrentProcess(), NULL, Entries, 0, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = QueryWsEx(NtCurrentProcess(), NULL, Entries, sizeof(Entries[0]) - 1, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(ReturnLength, 0xDEAD);
    Status = QueryWsEx(NtCurrentProcess(), NULL, Entries, sizeof(Entries[0]) + 1, &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(ReturnLength, sizeof(Entries[0]) + 1);
    ok(((PUCHAR)&Entries[1])[0] == 0xAA && ((PUCHAR)&Entries[1])[sizeof(Entries[1]) - 1] == 0xAA, "partial entry written\n");

    /* BaseAddress is only checked against the user range; the process handle must be valid */
    Status = QueryWsEx(NtCurrentProcess(), TEST_KERNEL_ADDRESS, Entries, sizeof(Entries[0]), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = QueryWsEx((HANDLE)(ULONG_PTR)0x1230, NULL, Entries, sizeof(Entries[0]), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = QueryWsEx(NULL, NULL, Entries, sizeof(Entries[0]), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    if (View) NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (Section) NtClose(Section);
    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Private, &Size, MEM_RELEASE);
}

#ifdef _WIN64
/* MemoryImageInformation (class 6): ImageBase, SizeOfImage, flags; 0x18 bytes on x64 */
typedef struct _TEST_IMAGE_INFORMATION
{
    PVOID ImageBase;
    SIZE_T SizeOfImage;
    ULONG ImageFlags;
} TEST_IMAGE_INFORMATION;

static
VOID
Test_ImageInformation(VOID)
{
    TEST_IMAGE_INFORMATION Info;
    PVOID Image = GetModuleHandleW(NULL);
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(Image);
    PUCHAR Private = NULL;
    SIZE_T Size = 0x1000, ReturnLength;
    NTSTATUS Status;

    C_ASSERT(sizeof(Info) == 0x18);

    RtlFillMemory(&Info, sizeof(Info), 0xAA);
    ReturnLength = 0xDEAD;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Image, (MEMORY_INFORMATION_CLASS)6, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(ReturnLength, sizeof(Info));
    ok_ptr(Info.ImageBase, Image);
    ok_size_t(Info.SizeOfImage, NtHeaders->OptionalHeader.SizeOfImage);
    ok_hex(Info.ImageFlags, 0);

    /* Any address of the image gives the same answer */
    RtlFillMemory(&Info, sizeof(Info), 0xAA);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PUCHAR)Image + 0x1234, (MEMORY_INFORMATION_CLASS)6, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_ptr(Info.ImageBase, Image);

    /* Short buffers; longer ones still write 0x18 bytes */
    ReturnLength = 0xDEAD;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Image, (MEMORY_INFORMATION_CLASS)6, &Info, sizeof(Info) - 1, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(ReturnLength, 0xDEAD);
    {
        UCHAR Big[0x40];
        RtlFillMemory(Big, sizeof(Big), 0xAA);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Image, (MEMORY_INFORMATION_CLASS)6, Big, sizeof(Big), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_size_t(ReturnLength, sizeof(Info));
        ok(Big[sizeof(Info)] == 0xAA, "wrote past the structure\n");
    }

    /* Private memory is not an image: success with zeros. Free memory is an invalid address. */
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Private, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    RtlFillMemory(&Info, sizeof(Info), 0xAA);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Private, (MEMORY_INFORMATION_CLASS)6, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(ReturnLength, sizeof(Info));
    ok_ptr(Info.ImageBase, NULL);
    ok_size_t(Info.SizeOfImage, 0);
    ok_hex(Info.ImageFlags, 0);
    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Private, &Size, MEM_RELEASE);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)(ULONG_PTR)0x1000, (MEMORY_INFORMATION_CLASS)6, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
}
#endif

START_TEST(NtQueryVirtualMemory)
{
    Test_InvalidClasses();
    Test_WorkingSetEx();
#ifdef _WIN64
    Test_ImageInformation();
#endif
    Test_SecReserveAccessedPage();
    Test_SectionNameBasic();
    Test_SectionNameHeaderRace();
    Test_SectionNameOtherProcess();
}
