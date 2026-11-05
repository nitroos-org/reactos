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
        ok_int(Name->SectionFileName.MaximumLength, Name->SectionFileName.Length + sizeof(WCHAR));
        ok_size_t(ReturnLength, Name->SectionFileName.Length + sizeof(*Name) + sizeof(WCHAR));
        ok(_wcsnicmp((PWSTR)((PUCHAR)Name->SectionFileName.Buffer + Name->SectionFileName.Length - 9 * sizeof(WCHAR)),
                     L"ntdll.dll", 9) == 0, "Name is %wZ\n", &Name->SectionFileName);
    }
    ok_int(*Canary, 0x77);

    /* A buffer that cannot hold the name must never be overrun */
    RtlFillMemory(Buffer, 2 * PAGE_SIZE, 0x77);
    Size = sizeof(*Name) + 8;
    Canary = (PUCHAR)Buffer + Size;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Ntdll, MemorySectionName, Buffer, Size, &ReturnLength);
    ok_ntstatus(Status, STATUS_BUFFER_OVERFLOW);
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

/*
 * MemoryWorkingSetInformation (class 1), MemorySharedCommitInformation (class 5),
 * MemoryRegionInformationEx (class 7) and MemoryPrivilegedBasicInformation (class 8), measured on
 * Windows 10 22H2 x64: see ntoskrnl/mm/ARM3/virtual.c
 */
static
PVOID
MapPagefileView(ULONG ViewProtect, ULONG SectionProtect, ULONG Pages, PHANDLE Section)
{
    LARGE_INTEGER MaxSize;
    PVOID View = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;

    MaxSize.QuadPart = Pages * PAGE_SIZE;
    *Section = NULL;
    Status = NtCreateSection(Section, SECTION_ALL_ACCESS, NULL, &MaxSize, SectionProtect, SEC_COMMIT, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return NULL;
    Status = NtMapViewOfSection(*Section, NtCurrentProcess(), &View, 0, 0, NULL, &ViewSize, ViewUnmap, 0, ViewProtect);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return NULL;
    return View;
}

static
PVOID
AllocPrivate(SIZE_T Size, ULONG Protect)
{
    PVOID Base = NULL;
    NTSTATUS Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE | MEM_COMMIT, Protect);

    ok_ntstatus(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Base : NULL;
}

static
PVOID
FreeAddress(VOID)
{
    PVOID Base = NULL;
    SIZE_T Size = 0x10000;

    NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
    return Base;
}

#define MEMORY_CLASS_WORKING_SET 1
#define MEMORY_CLASS_SHARED_COMMIT 5
#define MEMORY_CLASS_REGION_EX 7
#define MEMORY_CLASS_PRIVILEGED_BASIC 8
#define PAGE_OF(p) ((ULONG_PTR)(p) & ~(ULONG_PTR)(PAGE_SIZE - 1))
#define FILL_PTR ((ULONG_PTR)(sizeof(ULONG_PTR) == 8 ? 0xAAAAAAAAAAAAAAAAull : 0xAAAAAAAAul))

static
NTSTATUS
QueryClass(HANDLE Process, PVOID Address, ULONG Class, PVOID Buffer, SIZE_T Length, PSIZE_T ReturnLength)
{
    return NtQueryVirtualMemory(Process, Address, (MEMORY_INFORMATION_CLASS)Class, Buffer, Length, ReturnLength);
}

/* The working set list, growing the buffer until it fits; the caller frees it with VirtualFree */
static
PULONG_PTR
GetWorkingSetList(HANDLE Process, PSIZE_T ListLength)
{
    SIZE_T Size = 0x10000;
    ULONG i;

    for (i = 0; i < 32; i++)
    {
        PULONG_PTR List = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        NTSTATUS Status;

        ok(List != NULL, "VirtualAlloc failed\n");
        if (!List) return NULL;
        *ListLength = 0xDEAD;
        Status = QueryClass(Process, NULL, MEMORY_CLASS_WORKING_SET, List, Size, ListLength);
        if (NT_SUCCESS(Status)) return List;
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        if ((Status != STATUS_INFO_LENGTH_MISMATCH) || (List[0] > 0x100000))
        {
            VirtualFree(List, 0, MEM_RELEASE);
            return NULL;
        }
        ok(*ListLength == 0xDEAD, "ReturnLength set for a mismatch\n");
        Size = (List[0] + 256 * (i + 1) + 1) * sizeof(ULONG_PTR);
        VirtualFree(List, 0, MEM_RELEASE);
    }
    return NULL;
}

static
BOOLEAN
FindWorkingSetEntry(PULONG_PTR List, PVOID Address, PULONG_PTR Entry)
{
    ULONG_PTR i;

    for (i = 0; i < List[0]; i++)
    {
        if (PAGE_OF(List[1 + i]) == PAGE_OF(Address))
        {
            *Entry = List[1 + i];
            return TRUE;
        }
    }
    return FALSE;
}

static
VOID
Test_WorkingSetList(VOID)
{
    PUCHAR Private, Reserved = NULL, View, RoView;
    HANDLE Section, RoSection, Limited;
    PULONG_PTR List;
    SIZE_T Size = 0x4000, ReturnLength, ListLength, i;
    ULONG_PTR Entry, Small[2];
    UCHAR Buffer[0x20];
    NTSTATUS Status;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&Reserved, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    Private = Reserved;
    Size = 0x2000;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&Private, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Private[0] = 1;     /* touched; page 1 is committed and never touched; pages 2 and 3 are reserved */
    View = MapPagefileView(PAGE_READWRITE, PAGE_READWRITE, 2, &Section);
    RoView = MapPagefileView(PAGE_READONLY, PAGE_READWRITE, 2, &RoSection);
    if (View) View[0] = 7;
    if (RoView) (VOID)*(volatile UCHAR *)RoView;

    /* A buffer without room for the count fails and is left alone; one with room for it gets the count only */
    RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
    ReturnLength = 0xDEAD;
    Status = QueryClass(NtCurrentProcess(), NULL, MEMORY_CLASS_WORKING_SET, Buffer, 0, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = QueryClass(NtCurrentProcess(), NULL, MEMORY_CLASS_WORKING_SET, Buffer, sizeof(ULONG_PTR) - 1, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(ReturnLength, 0xDEAD);
    ok(Buffer[0] == 0xAA && Buffer[sizeof(ULONG_PTR) - 1] == 0xAA, "The count was stored in a buffer too small for it\n");
    Small[0] = 0xDEAD;
    Small[1] = 0xDEAD;
    Status = QueryClass(NtCurrentProcess(), NULL, MEMORY_CLASS_WORKING_SET, Small, sizeof(ULONG_PTR), &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(ReturnLength, 0xDEAD);
    ok(Small[0] != 0xDEAD && Small[0] > 8, "Count %Iu\n", Small[0]);
    ok_size_t(Small[1], 0xDEAD);

    List = GetWorkingSetList(NtCurrentProcess(), &ListLength);
    ok(List != NULL, "No list\n");
    if (List)
    {
        ok_size_t(ListLength, (1 + List[0]) * sizeof(ULONG_PTR));
        for (i = 1; i < List[0]; i++)
        {
            if (PAGE_OF(List[1 + i]) <= PAGE_OF(List[i]))
            {
                ok(0, "Entry %Iu (%Ix) does not follow entry %Iu (%Ix)\n", i, List[1 + i], i - 1, List[i]);
                break;
            }
        }

        ok(FindWorkingSetEntry(List, Private, &Entry), "The touched private page is not listed\n");
        if (FindWorkingSetEntry(List, Private, &Entry))
        {
            ok_hex(Entry & 0x1F, 4);                    /* Protection: MM_READWRITE */
            ok_hex((Entry >> 5) & 7, 0);                /* ShareCount */
            ok_hex((Entry >> 8) & 1, 0);                /* Shared */
            ok_hex((Entry >> 9) & 7, 0);                /* Node */
        }
        ok(!FindWorkingSetEntry(List, Private + 0x1000, &Entry), "A page that was never touched is listed\n");
        ok(!FindWorkingSetEntry(List, Private + 0x2000, &Entry), "A reserved page is listed\n");
        if (View)
        {
            ok(FindWorkingSetEntry(List, View, &Entry), "The written page of the view is not listed\n");
            if (FindWorkingSetEntry(List, View, &Entry))
            {
                ok_hex(Entry & 0x1F, 4);
                ok_hex((Entry >> 8) & 1, 1);            /* Shared */
                ok((Entry >> 5) & 7, "ShareCount 0 for a shared page\n");
            }
        }
        if (RoView)
        {
            ok(FindWorkingSetEntry(List, RoView, &Entry), "The read page of the read-only view is not listed\n");
            if (FindWorkingSetEntry(List, RoView, &Entry))
            {
                ok_hex(Entry & 0x1F, 1);                /* MM_READONLY */
                ok_hex((Entry >> 8) & 1, 1);
            }
        }
        ok(FindWorkingSetEntry(List, GetModuleHandleW(NULL), &Entry), "The image header is not listed\n");
        if (FindWorkingSetEntry(List, GetModuleHandleW(NULL), &Entry))
        {
            ok_hex(Entry & 0x1F, 1);
            ok_hex((Entry >> 8) & 1, 1);
        }
        VirtualFree(List, 0, MEM_RELEASE);
    }

    /* BaseAddress is ignored; a kernel address, a bad handle and a limited handle */
    Status = QueryClass(NtCurrentProcess(), Private, MEMORY_CLASS_WORKING_SET, Small, sizeof(ULONG_PTR), &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, MEMORY_CLASS_WORKING_SET, Small, sizeof(Small), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = QueryClass((HANDLE)(ULONG_PTR)0x1230, NULL, MEMORY_CLASS_WORKING_SET, Small, sizeof(Small), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = QueryClass(NULL, NULL, MEMORY_CLASS_WORKING_SET, Small, sizeof(Small), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    ok(Limited != NULL, "OpenProcess failed\n");
    if (Limited)
    {
        List = GetWorkingSetList(Limited, &ListLength);
        ok(List != NULL, "No list through a limited handle\n");
        if (List) VirtualFree(List, 0, MEM_RELEASE);
        CloseHandle(Limited);
    }

    if (View) NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (RoView) NtUnmapViewOfSection(NtCurrentProcess(), RoView);
    if (Section) NtClose(Section);
    if (RoSection) NtClose(RoSection);
    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&Reserved, &Size, MEM_RELEASE);
}

static
VOID
Test_SharedCommit(VOID)
{
    PUCHAR Private = AllocPrivate(0x1000, PAGE_READWRITE);
    HANDLE Section;
    PVOID View = MapPagefileView(PAGE_READWRITE, PAGE_READWRITE, 2, &Section);
    PVOID Addresses[5];
    SIZE_T Value[3], ReturnLength;
    HANDLE Limited;
    NTSTATUS Status;
    ULONG i;

    Addresses[0] = Private;
    Addresses[1] = View ? View : (PVOID)Private;
    Addresses[2] = FreeAddress();
    Addresses[3] = GetModuleHandleW(NULL);
    Addresses[4] = NULL;

    /* Whatever the address: one SIZE_T, nothing more */
    for (i = 0; i < ARRAYSIZE(Addresses); i++)
    {
        RtlFillMemory(Value, sizeof(Value), 0xAA);
        ReturnLength = 0xDEAD;
        Status = QueryClass(NtCurrentProcess(), Addresses[i], MEMORY_CLASS_SHARED_COMMIT, Value, sizeof(Value), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_size_t(ReturnLength, sizeof(SIZE_T));
        ok(Value[0] != FILL_PTR && Value[1] == FILL_PTR && Value[2] == FILL_PTR, "Written: %Ix %Ix %Ix\n", Value[0], Value[1], Value[2]);
    }

    ReturnLength = 0xDEAD;
    RtlFillMemory(Value, sizeof(Value), 0xAA);
    Status = QueryClass(NtCurrentProcess(), Private, MEMORY_CLASS_SHARED_COMMIT, Value, sizeof(SIZE_T) - 1, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(ReturnLength, 0xDEAD);
    Status = QueryClass(NtCurrentProcess(), Private, MEMORY_CLASS_SHARED_COMMIT, Value, 0, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(Value[0], FILL_PTR);

    Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, MEMORY_CLASS_SHARED_COMMIT, Value, sizeof(SIZE_T), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = QueryClass((HANDLE)(ULONG_PTR)0x1230, Private, MEMORY_CLASS_SHARED_COMMIT, Value, sizeof(SIZE_T), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = QueryClass(NULL, Private, MEMORY_CLASS_SHARED_COMMIT, Value, sizeof(SIZE_T), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (Limited)
    {
        Status = QueryClass(Limited, Private, MEMORY_CLASS_SHARED_COMMIT, Value, sizeof(SIZE_T), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CloseHandle(Limited);
    }

    if (View) NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (Section) NtClose(Section);
}

static
VOID
CheckRegionEx(PCSTR Name, PVOID Address, ULONG TypeMem, ULONG TypeBits)
{
    MEMORY_REGION_INFORMATION Region, RegionEx;
    NTSTATUS Status3, Status7;
    SIZE_T Length3 = 0xDEAD, Length7 = 0xDEAD;

    RtlFillMemory(&Region, sizeof(Region), 0xAA);
    RtlFillMemory(&RegionEx, sizeof(RegionEx), 0xBB);
    Status3 = QueryClass(NtCurrentProcess(), Address, 3, &Region, sizeof(Region), &Length3);
    Status7 = QueryClass(NtCurrentProcess(), Address, MEMORY_CLASS_REGION_EX, &RegionEx, sizeof(RegionEx), &Length7);
    ok(Status3 == STATUS_SUCCESS, "%s: class 3 status %lx\n", Name, Status3);
    ok(Status7 == STATUS_SUCCESS, "%s: class 7 status %lx\n", Name, Status7);
    if (Status3 != STATUS_SUCCESS || Status7 != STATUS_SUCCESS) return;
    ok(Length7 == Length3 && Length7 == sizeof(RegionEx), "%s: lengths %Iu, %Iu\n", Name, Length3, Length7);
    ok(Region.RegionType == TypeMem, "%s: class 3 type %lx\n", Name, Region.RegionType);
    ok(RegionEx.RegionType == TypeBits, "%s: class 7 type %lx, expected %lx\n", Name, RegionEx.RegionType, TypeBits);
    ok(RegionEx.AllocationBase == Region.AllocationBase, "%s: base %p, %p\n", Name, RegionEx.AllocationBase, Region.AllocationBase);
    ok(RegionEx.AllocationProtect == Region.AllocationProtect, "%s: protect\n", Name);
    ok(RegionEx.RegionSize == Region.RegionSize, "%s: size\n", Name);
    ok(RegionEx.CommitSize == Region.CommitSize, "%s: commit\n", Name);
    ok(RegionEx.PartitionId == Region.PartitionId, "%s: partition\n", Name);
    ok(RegionEx.NodePreference == Region.NodePreference, "%s: node\n", Name);
}

static
VOID
Test_RegionEx(VOID)
{
    PUCHAR Private = AllocPrivate(0x2000, PAGE_READWRITE);
    HANDLE Section, File = INVALID_HANDLE_VALUE, Mapping = NULL;
    PVOID View = MapPagefileView(PAGE_READWRITE, PAGE_READWRITE, 2, &Section);
    PVOID FileView = NULL;
    WCHAR Path[MAX_PATH];
    MEMORY_REGION_INFORMATION RegionEx;
    SIZE_T ReturnLength;
    NTSTATUS Status;
    HANDLE Limited;

    CheckRegionEx("private", Private, MEM_PRIVATE, 1);
    if (View) CheckRegionEx("pagefile view", View, 0x08000000, 8);
    CheckRegionEx("image", GetModuleHandleW(NULL), MEM_IMAGE, 4);
    CheckRegionEx("ntdll", GetModuleHandleW(L"ntdll.dll"), MEM_IMAGE, 4);

    GetSystemDirectoryW(Path, ARRAYSIZE(Path));
    StringCchCatW(Path, ARRAYSIZE(Path), L"\\ntdll.dll");
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (File != INVALID_HANDLE_VALUE)
        Mapping = CreateFileMappingW(File, NULL, PAGE_READONLY, 0, 0, NULL);
    if (Mapping)
        FileView = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, 0);
    if (FileView) CheckRegionEx("data file view", FileView, MEM_MAPPED, 2);

    Status = QueryClass(NtCurrentProcess(), FreeAddress(), MEMORY_CLASS_REGION_EX, &RegionEx, sizeof(RegionEx), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
    Status = QueryClass(NtCurrentProcess(), NULL, MEMORY_CLASS_REGION_EX, &RegionEx, sizeof(RegionEx), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
    Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, MEMORY_CLASS_REGION_EX, &RegionEx, sizeof(RegionEx), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = QueryClass((HANDLE)(ULONG_PTR)0x1230, Private, MEMORY_CLASS_REGION_EX, &RegionEx, sizeof(RegionEx), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (Limited)
    {
        Status = QueryClass(Limited, Private, MEMORY_CLASS_REGION_EX, &RegionEx, sizeof(RegionEx), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CloseHandle(Limited);
    }

#ifdef _WIN64
    /* The length is checked first (even for a kernel address); a short buffer gets the fields that fit */
    {
        static const struct { SIZE_T Length, Written; } Cases[] =
        {
            { 0x1F, 0 }, { 0x20, 0x20 }, { 0x27, 0x20 }, { 0x28, 0x28 }, { 0x2F, 0x28 }, { 0x30, 0x30 }, { 0x38, 0x30 }
        };
        UCHAR Buffer[0x40];
        ULONG i;

        Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, MEMORY_CLASS_REGION_EX, Buffer, 0, &ReturnLength);
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        for (i = 0; i < ARRAYSIZE(Cases); i++)
        {
            RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
            ReturnLength = 0xDEAD;
            Status = QueryClass(NtCurrentProcess(), Private, MEMORY_CLASS_REGION_EX, Buffer, Cases[i].Length, &ReturnLength);
            if (!Cases[i].Written)
            {
                ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
                ok_size_t(ReturnLength, 0xDEAD);
            }
            else
            {
                ok_ntstatus(Status, STATUS_SUCCESS);
                ok_size_t(ReturnLength, Cases[i].Written);
                ok(Buffer[Cases[i].Written] == 0xAA, "length %Ix: wrote past %Ix\n", Cases[i].Length, Cases[i].Written);
            }
        }
    }
#endif

    if (FileView) UnmapViewOfFile(FileView);
    if (Mapping) CloseHandle(Mapping);
    if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
    if (View) NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (Section) NtClose(Section);
}

static
VOID
CheckPrivilegedBasic(PCSTR Name, PVOID Address)
{
    MEMORY_BASIC_INFORMATION Basic, Privileged;
    SIZE_T Length0 = 0xDEAD, Length8 = 0xDEAD;
    NTSTATUS Status0, Status8;

    RtlFillMemory(&Basic, sizeof(Basic), 0xAA);
    RtlFillMemory(&Privileged, sizeof(Privileged), 0xBB);
    Status0 = QueryClass(NtCurrentProcess(), Address, 0, &Basic, sizeof(Basic), &Length0);
    Status8 = QueryClass(NtCurrentProcess(), Address, MEMORY_CLASS_PRIVILEGED_BASIC, &Privileged, sizeof(Privileged), &Length8);
    ok(Status0 == STATUS_SUCCESS, "%s: class 0 status %lx\n", Name, Status0);
    ok(Status8 == STATUS_SUCCESS, "%s: class 8 status %lx\n", Name, Status8);
    ok(Length0 == sizeof(Basic) && Length8 == sizeof(Basic), "%s: lengths %Iu, %Iu\n", Name, Length0, Length8);
    ok(!memcmp(&Basic, &Privileged, sizeof(Basic)), "%s: class 8 differs from class 0\n", Name);
}

static
VOID
Test_PrivilegedBasic(VOID)
{
    PUCHAR Private = AllocPrivate(0x2000, PAGE_READWRITE);
    HANDLE Section;
    PVOID View = MapPagefileView(PAGE_READWRITE, PAGE_READWRITE, 2, &Section);
    MEMORY_BASIC_INFORMATION Info;
    UCHAR Big[0x80];
    SIZE_T ReturnLength;
    NTSTATUS Status;
    HANDLE Handle;

    CheckPrivilegedBasic("private", Private);
    CheckPrivilegedBasic("private, mid page", Private + 0x123);
    CheckPrivilegedBasic("free", FreeAddress());
    CheckPrivilegedBasic("NULL", NULL);
    CheckPrivilegedBasic("0x1000", (PVOID)(ULONG_PTR)0x1000);
    if (View) CheckPrivilegedBasic("pagefile view", View);
    CheckPrivilegedBasic("image", GetModuleHandleW(NULL));
    CheckPrivilegedBasic("ntdll", GetModuleHandleW(L"ntdll.dll"));

    /* The length is checked first, even for a kernel address */
    ReturnLength = 0xDEAD;
    Status = QueryClass(NtCurrentProcess(), Private, MEMORY_CLASS_PRIVILEGED_BASIC, &Info, sizeof(Info) - 1, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_size_t(ReturnLength, 0xDEAD);
    Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, MEMORY_CLASS_PRIVILEGED_BASIC, &Info, 0, &ReturnLength);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, MEMORY_CLASS_PRIVILEGED_BASIC, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = QueryClass((HANDLE)(ULONG_PTR)0x1230, Private, MEMORY_CLASS_PRIVILEGED_BASIC, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = QueryClass(NULL, Private, MEMORY_CLASS_PRIVILEGED_BASIC, &Info, sizeof(Info), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    /* Only the structure is written */
    RtlFillMemory(Big, sizeof(Big), 0xAA);
    Status = QueryClass(NtCurrentProcess(), Private, MEMORY_CLASS_PRIVILEGED_BASIC, Big, sizeof(Big), &ReturnLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_size_t(ReturnLength, sizeof(Info));
    ok(Big[sizeof(Info)] == 0xAA, "wrote past the structure\n");

    Handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (Handle)
    {
        Status = QueryClass(Handle, Private, MEMORY_CLASS_PRIVILEGED_BASIC, &Info, sizeof(Info), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        CloseHandle(Handle);
    }

    if (View) NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (Section) NtClose(Section);
}

static
ULONG
ProtectOf(PVOID Address, PSIZE_T RegionSize)
{
    MEMORY_BASIC_INFORMATION Info;

    if (VirtualQuery(Address, &Info, sizeof(Info)) != sizeof(Info)) return 0xDEAD;
    if (RegionSize) *RegionSize = Info.RegionSize;
    return Info.Protect;
}

/* Windows 10 22H2 (measured): the protection VirtualQuery reports for a resident page of a view does not follow
 * the page table entry (a read or a write fault), it is the protection of the view; only a page of a
 * copy-on-write view that was written changes, to the writable form */
static
VOID
Test_ProtectAfterAccess(VOID)
{
    HANDLE Section;
    PUCHAR View;
    SIZE_T Region;

    View = MapPagefileView(PAGE_READWRITE, PAGE_READWRITE, 4, &Section);
    if (View)
    {
        ok_hex(ProtectOf(View + 0x1000, NULL), PAGE_READWRITE);
        (VOID)*(volatile UCHAR *)(View + 0x1000);
        ok_hex(ProtectOf(View + 0x1000, NULL), PAGE_READWRITE);
        View[0] = 1;
        ok_hex(ProtectOf(View, NULL), PAGE_READWRITE);
        View[0x1000] = 1;
        ok_hex(ProtectOf(View + 0x1000, NULL), PAGE_READWRITE);
        View[0x3000] = 1;
        ok_hex(ProtectOf(View + 0x3000, NULL), PAGE_READWRITE);
        ok_hex(ProtectOf(View + 0x2000, NULL), PAGE_READWRITE);
        ok_hex(ProtectOf(View, &Region), PAGE_READWRITE);
        ok_size_t(Region, 0x4000);
        NtUnmapViewOfSection(NtCurrentProcess(), View);
        NtClose(Section);
    }

    View = MapPagefileView(PAGE_READONLY, PAGE_READWRITE, 2, &Section);
    if (View)
    {
        ok_hex(ProtectOf(View, NULL), PAGE_READONLY);
        (VOID)*(volatile UCHAR *)View;
        ok_hex(ProtectOf(View, NULL), PAGE_READONLY);
        NtUnmapViewOfSection(NtCurrentProcess(), View);
        NtClose(Section);
    }

    View = MapPagefileView(PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE, 2, &Section);
    if (View)
    {
        ok_hex(ProtectOf(View, NULL), PAGE_EXECUTE_READWRITE);
        View[0] = 1;
        ok_hex(ProtectOf(View, NULL), PAGE_EXECUTE_READWRITE);
        (VOID)*(volatile UCHAR *)(View + 0x1000);
        ok_hex(ProtectOf(View + 0x1000, NULL), PAGE_EXECUTE_READWRITE);
        NtUnmapViewOfSection(NtCurrentProcess(), View);
        NtClose(Section);
    }

    View = MapPagefileView(PAGE_WRITECOPY, PAGE_READWRITE, 2, &Section);
    if (View)
    {
        ok_hex(ProtectOf(View, NULL), PAGE_WRITECOPY);
        (VOID)*(volatile UCHAR *)View;
        ok_hex(ProtectOf(View, NULL), PAGE_WRITECOPY);
        View[0] = 1;
        ok_hex(ProtectOf(View, &Region), PAGE_READWRITE);
        ok_size_t(Region, 0x1000);
        ok_hex(ProtectOf(View + 0x1000, NULL), PAGE_WRITECOPY);
        View[0x1000] = 1;
        ok_hex(ProtectOf(View + 0x1000, NULL), PAGE_READWRITE);
        NtUnmapViewOfSection(NtCurrentProcess(), View);
        NtClose(Section);
    }

    /* Private memory is unchanged */
    View = AllocPrivate(0x2000, PAGE_READWRITE);
    if (View)
    {
        (VOID)*(volatile UCHAR *)View;
        ok_hex(ProtectOf(View, NULL), PAGE_READWRITE);
        View[0] = 1;
        ok_hex(ProtectOf(View, &Region), PAGE_READWRITE);
        ok_size_t(Region, 0x2000);
    }
}

/* MemorySectionName of addresses that no file backs, measured on Windows 10 22H2 x64: private, reserved and
 * free memory and NULL fail with STATUS_INVALID_ADDRESS, a pagefile view with STATUS_FILE_INVALID, whatever
 * the length of the buffer; the length and the access to the process come after the address */
static
VOID
Test_SectionNameNoFile(VOID)
{
    PUCHAR Private = AllocPrivate(0x2000, PAGE_READWRITE), Reserved = NULL;
    SIZE_T Size = 0x2000;
    HANDLE Section, Limited;
    PVOID View = MapPagefileView(PAGE_READWRITE, PAGE_READWRITE, 2, &Section);
    struct { PVOID Address; NTSTATUS Expected; PCSTR Name; } Cases[5];
    static const SIZE_T Lengths[] = { 0, 1, sizeof(MEMORY_SECTION_NAME), 0x100, 0x1000 };
    UCHAR Buffer[0x1000];
    SIZE_T ReturnLength;
    NTSTATUS Status;
    ULONG i, j;

    NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&Reserved, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    Cases[0].Address = Private; Cases[0].Expected = STATUS_INVALID_ADDRESS; Cases[0].Name = "private";
    Cases[1].Address = Reserved; Cases[1].Expected = STATUS_INVALID_ADDRESS; Cases[1].Name = "reserved";
    Cases[2].Address = FreeAddress(); Cases[2].Expected = STATUS_INVALID_ADDRESS; Cases[2].Name = "free";
    Cases[3].Address = NULL; Cases[3].Expected = STATUS_INVALID_ADDRESS; Cases[3].Name = "NULL";
    Cases[4].Address = View; Cases[4].Expected = STATUS_FILE_INVALID; Cases[4].Name = "pagefile view";

    for (i = 0; i < ARRAYSIZE(Cases); i++)
    {
        if (!Cases[i].Address && i != 3) continue;
        for (j = 0; j < ARRAYSIZE(Lengths); j++)
        {
            RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
            ReturnLength = 0xDEAD;
            Status = QueryClass(NtCurrentProcess(), Cases[i].Address, 2, Buffer, Lengths[j], &ReturnLength);
            ok(Status == Cases[i].Expected, "%s, length %Iu: status %lx, expected %lx\n", Cases[i].Name, Lengths[j], Status, Cases[i].Expected);
            ok(ReturnLength == 0xDEAD && Buffer[0] == 0xAA, "%s, length %Iu: something was written\n", Cases[i].Name, Lengths[j]);
        }
    }

    /* The kernel address and the handle come first */
    Status = QueryClass(NtCurrentProcess(), TEST_KERNEL_ADDRESS, 2, Buffer, 0, &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = QueryClass((HANDLE)(ULONG_PTR)0x1230, Private, 2, Buffer, 0, &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = QueryClass(NULL, Private, 2, Buffer, sizeof(Buffer), &ReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    /* PROCESS_QUERY_LIMITED_INFORMATION is enough */
    Limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    ok(Limited != NULL, "OpenProcess failed\n");
    if (Limited)
    {
        Status = QueryClass(Limited, GetModuleHandleW(L"ntdll.dll"), 2, Buffer, sizeof(Buffer), &ReturnLength);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Status = QueryClass(Limited, Private, 2, Buffer, sizeof(Buffer), &ReturnLength);
        ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
        CloseHandle(Limited);
    }

    /* A handle that is not a process */
    {
        HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);

        Status = QueryClass(Event, GetModuleHandleW(L"ntdll.dll"), 2, Buffer, sizeof(Buffer), &ReturnLength);
        ok_ntstatus(Status, STATUS_OBJECT_TYPE_MISMATCH);
        CloseHandle(Event);
    }

    /* File-backed: the string is Length + 2 long and ReturnLength is the whole size, also when it does not fit */
    {
        PMEMORY_SECTION_NAME Name = (PMEMORY_SECTION_NAME)Buffer;
        PVOID Ntdll = GetModuleHandleW(L"ntdll.dll");
        SIZE_T Needed = 0xDEAD;
        SIZE_T Short[3] = { 0, 1, sizeof(MEMORY_SECTION_NAME) - 1 };
        SIZE_T Small[3];

        RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
        Status = QueryClass(NtCurrentProcess(), Ntdll, 2, Buffer, sizeof(Buffer), &Needed);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok_size_t(Needed, sizeof(MEMORY_SECTION_NAME) + Name->SectionFileName.Length + sizeof(WCHAR));
            ok_int(Name->SectionFileName.MaximumLength, Name->SectionFileName.Length + sizeof(WCHAR));
            ok_ptr(Name->SectionFileName.Buffer, (PWSTR)(Name + 1));
            ok(Name->SectionFileName.Buffer[Name->SectionFileName.Length / sizeof(WCHAR)] == UNICODE_NULL, "Not terminated\n");
            ok_int(Buffer[Needed], 0xAA);

            for (j = 0; j < 3; j++)
            {
                RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
                ReturnLength = 0xDEAD;
                Status = QueryClass(NtCurrentProcess(), Ntdll, 2, Buffer, Short[j], &ReturnLength);
                ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
                ok_size_t(ReturnLength, Needed);
                ok_int(Buffer[0], 0xAA);
            }
            Small[0] = sizeof(MEMORY_SECTION_NAME);
            Small[1] = sizeof(MEMORY_SECTION_NAME) + 8;
            Small[2] = Needed - 1;
            for (j = 0; j < 3; j++)
            {
                RtlFillMemory(Buffer, sizeof(Buffer), 0xAA);
                ReturnLength = 0xDEAD;
                Status = QueryClass(NtCurrentProcess(), Ntdll, 2, Buffer, Small[j], &ReturnLength);
                ok_ntstatus(Status, STATUS_BUFFER_OVERFLOW);
                ok_size_t(ReturnLength, Needed);
                ok_int(Buffer[0], 0xAA);
                ok_int(Buffer[Small[j] - 1], 0xAA);
            }
        }
    }

    if (View) NtUnmapViewOfSection(NtCurrentProcess(), View);
    if (Section) NtClose(Section);
}

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
    Test_WorkingSetList();
    Test_SharedCommit();
    Test_RegionEx();
    Test_PrivilegedBasic();
    Test_ProtectAfterAccess();
    Test_SectionNameNoFile();
}
