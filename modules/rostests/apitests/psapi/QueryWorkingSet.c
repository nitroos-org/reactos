/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for psapi!QueryWorkingSet (NtQueryVirtualMemory, MemoryWorkingSetInformation)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results were measured on Windows 10 22H2 (a 64-bit process, and a 32-bit one under WOW64): a buffer smaller
 * than the list fails with ERROR_BAD_LENGTH and leaves the number of entries in it, the list has one entry per
 * resident page in ascending address order, and a private page has ShareCount 0 and is not shared.
 */

#include <wine/test.h>
#include <windef.h>
#include <winbase.h>
#include <psapi.h>

#define MAX_ENTRIES 0x100000

/* PSAPI_WORKING_SET_INFORMATION and PSAPI_WORKING_SET_BLOCK of the SDK: a count, then one pointer-sized entry
 * per page: Protection 5 bits, ShareCount 3 bits, Shared 1 bit, Reserved 3 bits, VirtualPage above */
typedef struct
{
    ULONG_PTR NumberOfEntries;
    ULONG_PTR WorkingSetInfo[1];
} PSAPI_WORKING_SET_INFORMATION;

#define BLOCK_PROTECTION(b) ((unsigned)((b) & 0x1F))
#define BLOCK_SHARECOUNT(b) ((unsigned)(((b) >> 5) & 7))
#define BLOCK_SHARED(b) ((unsigned)(((b) >> 8) & 1))
#define BLOCK_PAGE(b) ((b) >> 12)

/* Fill Info with the working set list of Process (growing the buffer until it fits); NULL on failure */
static PSAPI_WORKING_SET_INFORMATION *GetList(HANDLE Process)
{
    DWORD Size = 0x10000;
    int i;

    for (i = 0; i < 32; i++)
    {
        PSAPI_WORKING_SET_INFORMATION *Info = HeapAlloc(GetProcessHeap(), 0, Size);
        BOOL Result;
        DWORD Error;

        if (!Info) return NULL;
        Info->NumberOfEntries = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        Result = QueryWorkingSet(Process, Info, Size);
        Error = GetLastError();
        if (Result) return Info;
        ok(Error == ERROR_BAD_LENGTH, "QueryWorkingSet failed with %lu\n", Error);
        if (Error != ERROR_BAD_LENGTH || Info->NumberOfEntries > MAX_ENTRIES)
        {
            HeapFree(GetProcessHeap(), 0, Info);
            return NULL;
        }
        Size = (DWORD)(sizeof(ULONG_PTR) + (Info->NumberOfEntries + 256 * (i + 1)) * sizeof(ULONG_PTR));
        HeapFree(GetProcessHeap(), 0, Info);
    }
    return NULL;
}

static const ULONG_PTR *FindPage(const PSAPI_WORKING_SET_INFORMATION *Info, const void *Address)
{
    ULONG_PTR Page = (ULONG_PTR)Address >> 12, i;

    for (i = 0; i < Info->NumberOfEntries; i++)
        if (BLOCK_PAGE(Info->WorkingSetInfo[i]) == Page) return &Info->WorkingSetInfo[i];
    return NULL;
}

typedef struct
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} TEST_PROCESS_BASIC_INFORMATION;

/* The working set of another process, the way a task manager reads it: the child has just been created, so its image
 * header is resident and the list is the child's own (not ours), through a handle with only the limited right too */
static void TestOtherProcess(void)
{
    typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PFN_NtQueryInformationProcess pNtQueryInformationProcess =
        (PFN_NtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    WCHAR Path[MAX_PATH];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    TEST_PROCESS_BASIC_INFORMATION Pbi;
    PVOID ImageBase = NULL;
    SIZE_T Read;
    PSAPI_WORKING_SET_INFORMATION *Info;
    HANDLE Limited;

    GetSystemDirectoryW(Path, ARRAYSIZE(Path));
    lstrcatW(Path, L"\\cmd.exe");
    if (!CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi))
    {
        skip("Could not start %S: %lu\n", Path, GetLastError());
        return;
    }

    if (pNtQueryInformationProcess && pNtQueryInformationProcess(Pi.hProcess, 0, &Pbi, sizeof(Pbi), NULL) == 0 &&
        ReadProcessMemory(Pi.hProcess, (PUCHAR)Pbi.PebBaseAddress + 2 * sizeof(PVOID), &ImageBase, sizeof(ImageBase), &Read) &&
        ImageBase)
    {
        Info = GetList(Pi.hProcess);
        ok(Info != NULL, "No working set list of the child\n");
        if (Info)
        {
            const ULONG_PTR *Block = FindPage(Info, ImageBase);

            ok(Info->NumberOfEntries > 2, "Only %Iu entries\n", Info->NumberOfEntries);
            ok(Block != NULL, "The image header of the child is not in its list\n");
            if (Block)
            {
                ok(BLOCK_PROTECTION(*Block) == 1, "Protection %u\n", BLOCK_PROTECTION(*Block));
                ok(BLOCK_SHARED(*Block) == 1, "Shared %u\n", BLOCK_SHARED(*Block));
            }
            HeapFree(GetProcessHeap(), 0, Info);
        }

        Limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pi.dwProcessId);
        ok(Limited != NULL, "OpenProcess failed: %lu\n", GetLastError());
        if (Limited)
        {
            Info = GetList(Limited);
            ok(Info != NULL, "No working set list through a limited handle\n");
            if (Info) HeapFree(GetProcessHeap(), 0, Info);
            CloseHandle(Limited);
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

START_TEST(QueryWorkingSet)
{
    PSAPI_WORKING_SET_INFORMATION *Info;
    const ULONG_PTR *Block;
    PUCHAR Private, View;
    HANDLE Section, Process;
    PROCESS_MEMORY_COUNTERS Counters;
    ULONG_PTR i;
    DWORD Error;
    BOOL Result;
    ULONG_PTR Small[2];

    Private = VirtualAlloc(NULL, 0x4000, MEM_RESERVE, PAGE_READWRITE);
    ok(Private != NULL, "VirtualAlloc failed\n");
    if (!Private) return;
    VirtualAlloc(Private, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    Private[0] = 1;             /* touched; the second page is committed and never touched; the others are reserved */

    Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x2000, NULL);
    View = Section ? MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    ok(View != NULL, "MapViewOfFile failed\n");
    if (View) View[0] = 7;

    /* A buffer without room for the whole list: ERROR_BAD_LENGTH, and the count is stored when it fits */
    Small[0] = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Result = QueryWorkingSet(GetCurrentProcess(), Small, sizeof(ULONG_PTR));
    Error = GetLastError();
    ok(!Result, "QueryWorkingSet succeeded for a buffer with no room\n");
    ok(Error == ERROR_BAD_LENGTH, "Error %lu\n", Error);
    ok(Small[0] != 0xdeadbeef && Small[0] > 8, "NumberOfEntries %Iu\n", Small[0]);
    SetLastError(0xdeadbeef);
    Small[0] = 0xdeadbeef;
    Result = QueryWorkingSet(GetCurrentProcess(), Small, sizeof(ULONG_PTR) - 1);
    Error = GetLastError();
    ok(!Result, "QueryWorkingSet succeeded for a buffer smaller than the count\n");
    ok(Error == ERROR_BAD_LENGTH, "Error %lu\n", Error);
    ok(Small[0] == 0xdeadbeef, "The count was stored in a buffer too small for it\n");

    Info = GetList(GetCurrentProcess());
    ok(Info != NULL, "No working set list\n");
    if (Info)
    {
        ok(Info->NumberOfEntries > 8, "Only %Iu entries\n", Info->NumberOfEntries);
        for (i = 1; i < Info->NumberOfEntries; i++)
        {
            if (BLOCK_PAGE(Info->WorkingSetInfo[i]) <= BLOCK_PAGE(Info->WorkingSetInfo[i - 1]))
            {
                ok(0, "Entry %Iu (page %Ix) does not follow entry %Iu (page %Ix)\n", i,
                   BLOCK_PAGE(Info->WorkingSetInfo[i]), i - 1, BLOCK_PAGE(Info->WorkingSetInfo[i - 1]));
                break;
            }
        }

        Block = FindPage(Info, Private);
        ok(Block != NULL, "The touched private page is not in the list\n");
        if (Block)
        {
            ok(BLOCK_PROTECTION(*Block) == 4, "Protection %u\n", BLOCK_PROTECTION(*Block));      /* MM_READWRITE */
            ok(BLOCK_SHARECOUNT(*Block) == 0, "ShareCount %u\n", BLOCK_SHARECOUNT(*Block));
            ok(BLOCK_SHARED(*Block) == 0, "Shared %u\n", BLOCK_SHARED(*Block));
        }
        ok(FindPage(Info, Private + 0x1000) == NULL, "A page that was never touched is in the list\n");
        ok(FindPage(Info, Private + 0x2000) == NULL, "A reserved page is in the list\n");

        if (View)
        {
            Block = FindPage(Info, View);
            ok(Block != NULL, "The written page of the view is not in the list\n");
            if (Block)
            {
                ok(BLOCK_PROTECTION(*Block) == 4, "Protection %u\n", BLOCK_PROTECTION(*Block));
                ok(BLOCK_SHARED(*Block) == 1, "Shared %u\n", BLOCK_SHARED(*Block));
                ok(BLOCK_SHARECOUNT(*Block) >= 1, "ShareCount %u\n", BLOCK_SHARECOUNT(*Block));
            }
        }

        /* The image header is resident and read-only */
        Block = FindPage(Info, GetModuleHandleW(NULL));
        ok(Block != NULL, "The image header is not in the list\n");
        if (Block)
        {
            ok(BLOCK_PROTECTION(*Block) == 1, "Protection %u\n", BLOCK_PROTECTION(*Block));      /* MM_READONLY */
            ok(BLOCK_SHARED(*Block) == 1, "Shared %u\n", BLOCK_SHARED(*Block));
        }

        /* The size of the working set agrees roughly (it changes while the list is built) */
        Counters.cb = sizeof(Counters);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &Counters, sizeof(Counters)))
        {
            SIZE_T Pages = Counters.WorkingSetSize / 0x1000;

            ok(Info->NumberOfEntries * 2 >= Pages && Info->NumberOfEntries <= Pages * 2 + 64,
               "%Iu entries, working set of %Iu pages\n", Info->NumberOfEntries, Pages);
        }
        HeapFree(GetProcessHeap(), 0, Info);
    }

    /* A handle with PROCESS_QUERY_INFORMATION to the same process gives a list too */
    Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    ok(Process != NULL, "OpenProcess failed\n");
    if (Process)
    {
        Info = GetList(Process);
        ok(Info != NULL, "No working set list through a handle\n");
        if (Info)
        {
            ok(FindPage(Info, Private) != NULL, "The touched private page is not in the list\n");
            HeapFree(GetProcessHeap(), 0, Info);
        }
        CloseHandle(Process);
    }

    /* A bad handle */
    SetLastError(0xdeadbeef);
    Result = QueryWorkingSet((HANDLE)(ULONG_PTR)0x1230, Small, sizeof(Small));
    Error = GetLastError();
    ok(!Result, "QueryWorkingSet succeeded for a bad handle\n");
    ok(Error == ERROR_INVALID_HANDLE, "Error %lu\n", Error);

    TestOtherProcess();

    if (View) UnmapViewOfFile(View);
    if (Section) CloseHandle(Section);
    VirtualFree(Private, 0, MEM_RELEASE);
}
