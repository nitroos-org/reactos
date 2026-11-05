/* NtQueryVirtualMemory(MemorySectionName) from a 32-bit process: the name of the file mapped
 * at an address (GetMappedFileName). Expected values measured on Windows Server 2008 R2 and
 * Windows 10 (x64, WoW64). SPDX-License-Identifier: LGPL-2.1-or-later */
#include "precomp.h"

static const UCHAR Fill = 0x5a;

/* The name ends with Suffix, case-insensitively */
static BOOLEAN EndsWith(PCUNICODE_STRING Name, PCWSTR Suffix)
{
    SIZE_T Length = wcslen(Suffix) * sizeof(WCHAR);
    return Name->Length >= Length &&
           !_wcsnicmp((PWCHAR)((PUCHAR)Name->Buffer + Name->Length - Length), Suffix, Length / sizeof(WCHAR));
}

/* A successful query of Address into Buffer + Offset (Offset unaligns the buffer); returns the
 * required length, 0 on failure */
static ULONG QueryName(PVOID Address, PCWSTR Suffix, ULONG Offset)
{
    UCHAR Buffer[2048];
    PUNICODE_STRING Name = (PUNICODE_STRING)(Buffer + Offset);
    SIZE_T Needed = 0xdeadbeef;
    NTSTATUS Status;

    memset(Buffer, Fill, sizeof(Buffer));
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Address, MemorySectionName, Name, sizeof(Buffer) - Offset, &Needed);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return 0;
    ok(Name->Buffer == (PWSTR)(Buffer + Offset + sizeof(UNICODE_STRING)), "Buffer %p, expected %p\n",
       Name->Buffer, Buffer + Offset + sizeof(UNICODE_STRING));
    ok(Name->Length > 0 && !(Name->Length & 1), "Length %u\n", Name->Length);
    ok(Name->MaximumLength == Name->Length + sizeof(WCHAR), "MaximumLength %u, Length %u\n",
       Name->MaximumLength, Name->Length);
    ok(Needed == sizeof(UNICODE_STRING) + Name->Length + sizeof(WCHAR), "Return length %lu, Length %u\n",
       (ULONG)Needed, Name->Length);
    if (Name->Buffer != (PWSTR)(Buffer + Offset + sizeof(UNICODE_STRING)) || Name->Length > 1024) return 0;
    ok(Name->Buffer[Name->Length / sizeof(WCHAR)] == UNICODE_NULL, "Not terminated\n");
    ok(Buffer[Offset + Needed] == Fill, "Wrote past the name\n");
    ok(Name->Length > 8 && !_wcsnicmp(Name->Buffer, L"\\Device\\", 8), "Name %wZ\n", Name);
    ok(EndsWith(Name, Suffix), "Name %wZ does not end with %S\n", Name, Suffix);
    return (ULONG)Needed;
}

static void TestLengths(PVOID Address, ULONG Needed)
{
    UCHAR Buffer[2048];
    SIZE_T Bytes;
    NTSTATUS Status;
    ULONG Lengths[] = {0, 4, sizeof(UNICODE_STRING) - 1, sizeof(UNICODE_STRING), sizeof(UNICODE_STRING) + 2, Needed - 2, Needed - 1};
    ULONG i, j;

    for (i = 0; i < ARRAYSIZE(Lengths); ++i)
    {
        memset(Buffer, Fill, sizeof(Buffer));
        Bytes = 0xdeadbeef;
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Address, MemorySectionName, Buffer, Lengths[i], &Bytes);
        ok(Status == (Lengths[i] < sizeof(UNICODE_STRING) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_BUFFER_OVERFLOW),
           "Length %lu: status 0x%lx\n", Lengths[i], Status);
        ok(Bytes == Needed, "Length %lu: return length %lu, expected %lu\n", Lengths[i], (ULONG)Bytes, Needed);
        for (j = 0; j < sizeof(Buffer) && Buffer[j] == Fill; ++j);
        ok(j == sizeof(Buffer), "Length %lu: buffer written at %lu\n", Lengths[i], j);
    }
    /* Exactly the required length; no return length */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Address, MemorySectionName, Buffer, Needed, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    /* The return length is stored after the name, also when it lies inside the buffer */
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Address, MemorySectionName, Buffer, sizeof(Buffer),
                                  (PSIZE_T)(Buffer + sizeof(UNICODE_STRING)));
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(*(PSIZE_T)(Buffer + sizeof(UNICODE_STRING)) == Needed, "Aliased return length %lu, expected %lu\n",
       (ULONG)*(PSIZE_T)(Buffer + sizeof(UNICODE_STRING)), Needed);
}

/* Another process: the name must be that process's mapping or an error, never the caller's own
 * mapping at that address (DataView exists only in this process) */
static void TestOtherProcess(PVOID Image, PVOID DataView)
{
    WCHAR Path[MAX_PATH], *Exe;
    UCHAR Buffer[1024];
    PUNICODE_STRING Name = (PUNICODE_STRING)Buffer;
    char Application[MAX_PATH], Command[] = "child-never-resumed";
    STARTUPINFOA Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Child;
    HANDLE Self;
    SIZE_T Bytes;
    NTSTATUS Status;

    /* A real handle to this process works like the pseudo handle */
    Self = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    ok(Self != NULL, "OpenProcess failed: %lu\n", GetLastError());
    if (Self)
    {
        Status = NtQueryVirtualMemory(Self, DataView, MemorySectionName, Buffer, sizeof(Buffer), &Bytes);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
            ok(EndsWith(Name, L"\\w64gqvm.tmp"), "Own process by handle: %wZ\n", Name);
        CloseHandle(Self);
    }

    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    Exe = wcsrchr(Path, L'\\');
    if (!Exe) Exe = Path;
    GetModuleFileNameA(NULL, Application, ARRAYSIZE(Application));
    if (!CreateProcessA(Application, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Child))
    {
        ok(0, "CreateProcessA failed: %lu\n", GetLastError());
        return;
    }
    memset(Buffer, 0x5a, sizeof(Buffer));
    Status = NtQueryVirtualMemory(Child.hProcess, DataView, MemorySectionName, Buffer, sizeof(Buffer), &Bytes);
    ok(!NT_SUCCESS(Status), "Other process at this process's data view: 0x%lx\n", Status);
    /* ReactOS does not translate requests on another process (its kernel would answer from
     * the caller's address space) */
    if (is_reactos()) ok_ntstatus(Status, STATUS_NOT_SUPPORTED);
    if (NT_SUCCESS(Status))
        ok(!EndsWith(Name, L"\\w64gqvm.tmp"), "Got this process's mapping %wZ\n", Name);
    /* Its executable image: the right name (Windows) or an error (ReactOS) */
    memset(Buffer, 0x5a, sizeof(Buffer));
    Status = NtQueryVirtualMemory(Child.hProcess, Image, MemorySectionName, Buffer, sizeof(Buffer), &Bytes);
    if (is_reactos())
        ok_ntstatus(Status, STATUS_NOT_SUPPORTED);
    else
    {
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status)) ok(EndsWith(Name, Exe), "Other process image %wZ\n", Name);
    }
    TerminateProcess(Child.hProcess, 0);
    CloseHandle(Child.hThread);
    CloseHandle(Child.hProcess);
}

/* Classes 1, 5, 7 and 8 of a 32-bit caller, measured on Windows 10 22H2 (WoW64): the list has ULONG entries,
 * class 5 does not exist, class 7 is class 3 with the RegionType bits of the SDK header and class 8 is class 0 */
static void TestNewClasses(void)
{
    UCHAR Small[16];
    ULONG Region[7], RegionEx[7], Basic[7], Privileged[8], *List = NULL, Size = 0x10000, i, j, Count = 0;
    PUCHAR Private = VirtualAlloc(NULL, 0x3000, MEM_RESERVE, PAGE_READWRITE);
    PVOID Addresses[3];
    SIZE_T Bytes;
    NTSTATUS Status;
    BOOL Found = FALSE, FoundUntouched = FALSE, FoundReserved = FALSE;

    ok(Private != NULL, "VirtualAlloc failed\n");
    if (!Private) return;
    VirtualAlloc(Private, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    Private[0] = 1;

    /* Class 1: no room for the count, then room for the count only */
    memset(Small, Fill, sizeof(Small));
    Bytes = 0xdeadbeef;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), NULL, 1, Small, 3, &Bytes);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok(Bytes == 0xdeadbeef && Small[0] == Fill, "Written for a buffer too small for the count\n");
    Status = NtQueryVirtualMemory(NtCurrentProcess(), NULL, 1, Small, 4, &Bytes);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok(Bytes == 0xdeadbeef && *(ULONG *)Small > 8 && Small[4] == Fill, "Count %lu\n", *(ULONG *)Small);

    for (i = 0; i < 16 && !List; i++)
    {
        List = HeapAlloc(GetProcessHeap(), 0, Size);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), NULL, 1, List, Size, &Bytes);
        if (NT_SUCCESS(Status)) break;
        ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
        Size = sizeof(ULONG) + (List[0] + 256 * (i + 1)) * sizeof(ULONG);
        HeapFree(GetProcessHeap(), 0, List);
        List = NULL;
        if (Status != STATUS_INFO_LENGTH_MISMATCH) break;
    }
    ok(List != NULL, "No list\n");
    if (List && NT_SUCCESS(Status))
    {
        Count = List[0];
        ok(Bytes == sizeof(ULONG) + Count * sizeof(ULONG), "Return length %lu, %lu entries\n", (ULONG)Bytes, Count);
        for (j = 0; j < Count; j++)
        {
            ULONG Entry = List[1 + j];

            if ((Entry & ~0xFFFul) == (ULONG)Private)
            {
                Found = TRUE;
                ok((Entry & 0x1F) == 4 && !((Entry >> 5) & 7) && !((Entry >> 8) & 1), "Entry %lx\n", Entry);
            }
            if ((Entry & ~0xFFFul) == (ULONG)Private + 0x1000) FoundUntouched = TRUE;
            if ((Entry & ~0xFFFul) == (ULONG)Private + 0x2000) FoundReserved = TRUE;
        }
        ok(Found, "The touched page is not listed\n");
        ok(!FoundUntouched, "A page that was never touched is listed\n");
        ok(!FoundReserved, "A reserved page is listed\n");
        HeapFree(GetProcessHeap(), 0, List);
    }
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)0xC0000000, 1, Small, sizeof(Small), &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = NtQueryVirtualMemory((HANDLE)0x1230, NULL, 1, Small, sizeof(Small), &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    /* Class 5 is not there */
    for (i = 0; i < 3; i++)
    {
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Private, 5, Small, i * 8, &Bytes);
        ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);
    }

    /* Classes 7 and 8 against 3 and 0 */
    Addresses[0] = Private;
    Addresses[1] = GetModuleHandleW(NULL);
    Addresses[2] = GetModuleHandleW(L"ntdll.dll");
    for (i = 0; i < 3; i++)
    {
        MEMORY_BASIC_INFORMATION Info0, Info8;
        ULONG Type3, Type7;

        Status = NtQueryVirtualMemory(NtCurrentProcess(), Addresses[i], 3, Region, sizeof(Region), &Bytes);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Addresses[i], 7, RegionEx, sizeof(RegionEx), &Bytes);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Bytes == 28, "Class 7 return length %lu\n", (ULONG)Bytes);
        Type3 = Region[2];
        Type7 = RegionEx[2];
        Region[2] = RegionEx[2] = 0;
        ok(!memcmp(Region, RegionEx, 28), "Class 7 differs from class 3 beyond the type\n");
        ok(Type7 == (i == 0 ? 1 : 4) && Type3 == (i == 0 ? MEM_PRIVATE : MEM_IMAGE), "Types %lx, %lx\n", Type3, Type7);

        Status = NtQueryVirtualMemory(NtCurrentProcess(), Addresses[i], 0, &Info0, sizeof(Info0), &Bytes);
        ok_ntstatus(Status, STATUS_SUCCESS);
        Status = NtQueryVirtualMemory(NtCurrentProcess(), Addresses[i], 8, &Info8, sizeof(Info8), &Bytes);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_size_t(Bytes, sizeof(Info8));
        ok(!memcmp(&Info0, &Info8, sizeof(Info0)), "Class 8 differs from class 0\n");
    }
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Private, 7, RegionEx, 24, &Bytes);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Private, 8, Basic, 27, &Bytes);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)0xC0000000, 7, RegionEx, sizeof(RegionEx), &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    Status = NtQueryVirtualMemory((HANDLE)0x1230, Private, 7, RegionEx, sizeof(RegionEx), &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = NtQueryVirtualMemory((HANDLE)0x1230, Private, 8, Privileged, 28, &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    VirtualFree(Private, 0, MEM_RELEASE);
}

START_TEST(Wow64QueryVirtualMemory)
{
    SYSTEM_BASIC_INFORMATION Basic;
    WCHAR Path[MAX_PATH], *Exe;
    UCHAR Buffer[1024];
    HANDLE File, Map;
    PVOID View, Heap;
    PUCHAR Image = (PUCHAR)GetModuleHandleW(NULL);
    SIZE_T Bytes;
    ULONG Needed;
    NTSTATUS Status;
    DWORD Written;
    BOOL Wow64 = FALSE;

    /* The length semantics of the WoW64 translation */
    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (!Wow64)
    {
        skip("Not a 32-bit process under WoW64\n");
        return;
    }
    Status = NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /* The executable image, at its base and inside it, also into an unaligned buffer */
    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    Exe = wcsrchr(Path, L'\\');
    ok(Exe != NULL, "No path in %S\n", Path);
    if (!Exe) return;
    Needed = QueryName(Image, Exe, 0);
    ok(QueryName(Image + 0x1000, Exe, 0) == Needed, "Inside the image\n");
    ok(QueryName(Image, Exe, 1) == Needed, "Unaligned buffer\n");
    ok(QueryName(Image, Exe, 2) == Needed, "Unaligned buffer\n");
    if (Needed) TestLengths(Image, Needed);

    /* A system DLL of the process's own architecture */
    QueryName(GetModuleHandleW(L"kernel32.dll"), L"\\SysWOW64\\kernel32.dll", 0);
    QueryName(GetModuleHandleW(L"ntdll.dll"), L"\\SysWOW64\\ntdll.dll", 0);

    /* A data file view */
    GetTempPathW(ARRAYSIZE(Path), Path);
    StringCbCatW(Path, sizeof(Path), L"w64gqvm.tmp");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        memset(Buffer, 1, sizeof(Buffer));
        WriteFile(File, Buffer, sizeof(Buffer), &Written, NULL);
        Map = CreateFileMappingW(File, NULL, PAGE_READONLY, 0, 0, NULL);
        ok(Map != NULL, "CreateFileMappingW failed: %lu\n", GetLastError());
        View = Map ? MapViewOfFile(Map, FILE_MAP_READ, 0, 0, 0) : NULL;
        ok(View != NULL, "MapViewOfFile failed: %lu\n", GetLastError());
        if (View)
        {
            Needed = QueryName(View, L"\\w64gqvm.tmp", 0);
            if (Needed) TestLengths(View, Needed);
            TestOtherProcess(Image, View);
            UnmapViewOfFile(View);
        }
        if (Map) CloseHandle(Map);
        CloseHandle(File);
    }

    /* No mapped file: free memory, private memory, a pagefile-backed view. Windows returns
     * STATUS_INVALID_ADDRESS for private memory and STATUS_FILE_INVALID for the pagefile view. */
    Bytes = 0xdeadbeef;
    Status = NtQueryVirtualMemory(NtCurrentProcess(), NULL, MemorySectionName, Buffer, sizeof(Buffer), &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
    Heap = HeapAlloc(GetProcessHeap(), 0, 64);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), Heap, MemorySectionName, Buffer, sizeof(Buffer), &Bytes);
    ok_ntstatus(Status, STATUS_INVALID_ADDRESS);
    HeapFree(GetProcessHeap(), 0, Heap);
    Map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    View = Map ? MapViewOfFile(Map, FILE_MAP_READ, 0, 0, 0) : NULL;
    ok(View != NULL, "Pagefile view failed: %lu\n", GetLastError());
    Status = NtQueryVirtualMemory(NtCurrentProcess(), View, MemorySectionName, Buffer, sizeof(Buffer), &Bytes);
    ok_ntstatus(Status, STATUS_FILE_INVALID);
    if (View) UnmapViewOfFile(View);
    if (Map) CloseHandle(Map);

    TestNewClasses();

    /* Beyond the process's 2 GiB user range */
    if (Basic.MaximumUserModeAddress < 0x80000000)
    {
        Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)0x80000000, MemorySectionName,
                                      Buffer, sizeof(Buffer), &Bytes);
        ok_ntstatus(Status, STATUS_INVALID_PARAMETER);
    }
}
