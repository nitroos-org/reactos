/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A 32-bit process cannot name memory above its own highest address (WoW64 memory thunks)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Under WoW64 the 64-bit layer that serves the 32-bit process has its own memory below 4 GiB: for a
 * process that is not large address aware, everything above 2 GiB. An explicit address (or a range that
 * reaches it) above the highest address of the 32-bit process must be refused by every memory service
 * instead of reaching that memory: allocate, free, protect, lock, map and unmap. A range inside the
 * address space works as always. Run the same executable natively on Windows to record what it does
 * ("PROBE" lines: operation, result, error); a native i386 system has no layer, so it is skipped there.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

static BOOL Wow;

/* a refused request: no result, and the error Windows 10 22H2 gives a 32-bit process for it (measured) */
static void Refused(const char *What, BOOL Ret, DWORD Error, DWORD Expected)
{
    printf("PROBE %s ret=%d error=%lu\n", What, Ret, Error);
    ++Checks;
    if (Ret || Error != Expected)
    {
        ++Failures;
        printf("FAIL %s ret=%d error=%lu, expected %lu\n", What, Ret, Error, Expected);
    }
}

int main(void)
{
    SYSTEM_INFO Info;
    ULONG_PTR Highest, Above;
    PVOID Ptr;
    DWORD Old, Error;
    HANDLE Map;
    BOOL Ret;
    MEMORY_BASIC_INFORMATION Mbi;

    GetSystemInfo(&Info);
    Highest = (ULONG_PTR)Info.lpMaximumApplicationAddress;
    IsWow64Process(GetCurrentProcess(), &Wow);
    printf("PROBE wow64=%d highest=%p large=%d\n", Wow, (PVOID)Highest, EXPECT_LARGE_ADDRESS);
    if (!Wow)
    {
        printf("SKIP: not a WoW64 process\n");
        return 0;
    }
    Above = Highest + 1;                     /* the first address the process cannot use */

    /* the 64 KiB above the highest address are the layer's: allocate, protect, free, lock and map them */
    SetLastError(0);
    Ptr = VirtualAlloc((PVOID)Above, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Error = GetLastError();
    Refused("alloc above highest", Ptr != NULL, Error, ERROR_INVALID_ADDRESS);
    if (Ptr) VirtualFree(Ptr, 0, MEM_RELEASE);

    SetLastError(0);
    Ptr = VirtualAlloc((PVOID)(Above - 0x10000), 0x20000, MEM_RESERVE, PAGE_READWRITE);
    Error = GetLastError();
    Refused("alloc across highest", Ptr != NULL, Error, ERROR_INVALID_ADDRESS);
    if (Ptr) VirtualFree(Ptr, 0, MEM_RELEASE);

    SetLastError(0);
    Ret = VirtualProtect((PVOID)Above, 0x1000, PAGE_READWRITE, &Old);
    Error = GetLastError();
    Refused("protect above highest", Ret, Error, ERROR_INVALID_PARAMETER);

    SetLastError(0);
    Ret = VirtualProtect((PVOID)(Above - 0x1000), 0x2000, PAGE_READWRITE, &Old);
    Error = GetLastError();
    Refused("protect across highest", Ret, Error, ERROR_INVALID_ADDRESS);

    SetLastError(0);
    Ret = VirtualFree((PVOID)Above, 0, MEM_RELEASE);
    Error = GetLastError();
    Refused("free above highest", Ret, Error, ERROR_INVALID_PARAMETER);
    /* it is still the layer's: the reservation is there */
    CHECK(VirtualQuery((PVOID)Above, &Mbi, sizeof(Mbi)) == sizeof(Mbi) || GetLastError() == ERROR_INVALID_PARAMETER);

    SetLastError(0);
    Ret = VirtualFree((PVOID)(Above - 0x1000), 0x2000, MEM_DECOMMIT);
    Error = GetLastError();
    Refused("decommit across highest", Ret, Error, ERROR_INVALID_ADDRESS);

    SetLastError(0);
    Ret = VirtualLock((PVOID)Above, 0x1000);
    Error = GetLastError();
    Refused("lock above highest", Ret, Error, ERROR_NOACCESS);

    /* a section: map at an address above, unmap one */
    Map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x20000, NULL);
    CHECK(Map != NULL);
    if (Map)
    {
        SetLastError(0);
        Ptr = MapViewOfFileEx(Map, FILE_MAP_WRITE, 0, 0, 0x10000, (PVOID)Above);
        Error = GetLastError();
        Refused("map above highest", Ptr != NULL, Error, ERROR_INVALID_PARAMETER);
        if (Ptr) UnmapViewOfFile(Ptr);

        SetLastError(0);
        Ptr = MapViewOfFileEx(Map, FILE_MAP_WRITE, 0, 0, 0x20000, (PVOID)(Above - 0x10000));
        Error = GetLastError();
        Refused("map across highest", Ptr != NULL, Error, ERROR_INVALID_ADDRESS);
        if (Ptr) UnmapViewOfFile(Ptr);

        SetLastError(0);
        Ret = UnmapViewOfFile((PVOID)Above);
        Error = GetLastError();
        Refused("unmap above highest", Ret, Error, ERROR_INVALID_ADDRESS);
        CloseHandle(Map);
    }

    /* a process that is not large address aware cannot name the memory between 2 and 4 GiB either */
    if (!EXPECT_LARGE_ADDRESS)
    {
        SetLastError(0);
        Ptr = VirtualAlloc((PVOID)0x90000000, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        Error = GetLastError();
        Refused("alloc at 2.25 GiB", Ptr != NULL, Error, ERROR_INVALID_ADDRESS);
        if (Ptr) VirtualFree(Ptr, 0, MEM_RELEASE);
        SetLastError(0);
        Ret = VirtualFree((PVOID)0xA0000000, 0, MEM_RELEASE);
        Error = GetLastError();
        Refused("free at 2.5 GiB", Ret, Error, ERROR_INVALID_ADDRESS);
        SetLastError(0);
        Ret = VirtualProtect((PVOID)0xB0000000, 0x1000, PAGE_READWRITE, &Old);
        Error = GetLastError();
        Refused("protect at 2.75 GiB", Ret, Error, ERROR_INVALID_PARAMETER);
    }

    /* a range inside the address space is served: allocate, protect, lock, query, free */
    {
        PVOID Wanted[] = { (PVOID)0x30000000, (PVOID)0x38000000, (PVOID)0x3C000000, NULL };
        ULONG i;

        Ptr = NULL;
        for (i = 0; i < ARRAYSIZE(Wanted) && !Ptr; ++i)
            Ptr = VirtualAlloc(Wanted[i], 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        CHECK(Ptr != NULL);
        if (Ptr)
        {
            CHECK((ULONG_PTR)Ptr + 0x10000 <= Above);
            CHECK(VirtualProtect(Ptr, 0x1000, PAGE_READONLY, &Old) && Old == PAGE_READWRITE);
            CHECK(VirtualProtect(Ptr, 0x1000, PAGE_READWRITE, &Old) && Old == PAGE_READONLY);
            CHECK(VirtualLock(Ptr, 0x1000));
            CHECK(VirtualUnlock(Ptr, 0x1000) || GetLastError() == ERROR_NOT_LOCKED);
            CHECK(VirtualQuery(Ptr, &Mbi, sizeof(Mbi)) == sizeof(Mbi) && Mbi.State == MEM_COMMIT);
            CHECK(VirtualFree(Ptr, 0x1000, MEM_DECOMMIT));
            CHECK(VirtualFree(Ptr, 0, MEM_RELEASE));
        }
        Map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL);
        CHECK(Map != NULL);
        if (Map)
        {
            Ptr = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0x10000);
            CHECK(Ptr != NULL);
            if (Ptr)
            {
                CHECK((ULONG_PTR)Ptr + 0x10000 <= Above);
                CHECK(UnmapViewOfFile(Ptr));
            }
            CloseHandle(Map);
        }
    }

    printf("GUEST LIMIT checks=%u failures=%u\n", Checks, Failures);
    return Failures ? 1 : 0;
}
