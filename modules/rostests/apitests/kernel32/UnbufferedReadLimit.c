/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that locking the pages of an unbuffered request is charged and limited
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * An unbuffered read or write locks every page of the caller's buffer for the length of the request
 * (MmProbeAndLockPages). Locked pages cannot be paged, so they are charged against the resident
 * available pages, and a request for more than the system can spare is refused with
 * STATUS_INSUFFICIENT_RESOURCES (ERROR_NO_SYSTEM_RESOURCES) before any page is touched. The pages are given
 * back when the request completes: many requests one after another each lock their pages again.
 * Run on ReactOS only for the refusal: the limit of Windows depends on its own resident available pages.
 */
#define BUFFER_SIZE     (16 * 1024 * 1024)
#define FILE_SIZE       (64 * 1024)
#define ROUNDS          200

START_TEST(UnbufferedReadLimit)
{
    WCHAR Path[MAX_PATH], FileName[MAX_PATH];
    HANDLE File, Direct;
    PVOID Buffer, Huge;
    DWORD Read, Written, Error, Round, Failed = 0;
    MEMORYSTATUSEX Memory;
    SIZE_T HugeSize;
    ULONG Step;
    BOOL Ret;

    GetTempPathW(_countof(Path), Path);
    GetTempFileNameW(Path, L"ubl", 0, FileName);
    File = CreateFileW(FileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile failed with %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    Buffer = VirtualAlloc(NULL, BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Buffer != NULL, "VirtualAlloc failed with %lu\n", GetLastError());
    if (!Buffer)
    {
        CloseHandle(File);
        DeleteFileW(FileName);
        return;
    }
    memset(Buffer, 0x5A, FILE_SIZE);
    ok(WriteFile(File, Buffer, FILE_SIZE, &Written, NULL) && Written == FILE_SIZE, "WriteFile failed with %lu\n", GetLastError());
    CloseHandle(File);

    Direct = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    ok(Direct != INVALID_HANDLE_VALUE, "CreateFile(NO_BUFFERING) failed with %lu\n", GetLastError());
    if (Direct == INVALID_HANDLE_VALUE)
    {
        VirtualFree(Buffer, 0, MEM_RELEASE);
        DeleteFileW(FileName);
        return;
    }

    /* a request the buffer of which is locked works, and again and again: the pages come back */
    for (Round = 0; Round < ROUNDS; Round++)
    {
        memset(Buffer, 0, 4096);
        SetFilePointer(Direct, 0, NULL, FILE_BEGIN);
        Ret = ReadFile(Direct, Buffer, BUFFER_SIZE, &Read, NULL);
        if (!Ret || Read != FILE_SIZE || *(BYTE *)Buffer != 0x5A)
        {
            Failed++;
            if (Failed == 1)
                trace("Round %lu: ReadFile returned %d, error %lu, %lu bytes\n", Round, Ret, GetLastError(), Read);
        }
    }
    ok(Failed == 0, "%lu of %d unbuffered reads of a 16 MB buffer failed\n", Failed, ROUNDS);

    /*
     * A request for more than the system can spare is refused, without using the memory. The largest buffer a
     * process can commit is read: on a machine with little memory that is more than the pages that can be locked
     * (all the physical memory less what the system keeps); on a larger one it fits, and there is nothing to refuse.
     */
    if (!is_reactos())
    {
        skip("The limit of the locked pages is that of the ReactOS memory manager\n");
        goto Done;
    }
    Memory.dwLength = sizeof(Memory);
    GlobalMemoryStatusEx(&Memory);
    Huge = NULL;
    for (Step = 0; Step <= 12 && !Huge; Step++)
    {
        HugeSize = (SIZE_T)((Memory.ullTotalPhys - Step * (Memory.ullTotalPhys / 16)) & ~0xFFFFULL);
        if (HugeSize > 0x70000000)
            continue;
        Huge = VirtualAlloc(NULL, HugeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!Huge)
    {
        skip("A buffer of the size of the physical memory (%I64u bytes) cannot be committed\n", Memory.ullTotalPhys);
        goto Done;
    }
    trace("physical %I64u, buffer %Iu\n", Memory.ullTotalPhys, HugeSize);
    SetFilePointer(Direct, 0, NULL, FILE_BEGIN);
    SetLastError(0);
    Ret = ReadFile(Direct, Huge, (DWORD)HugeSize, &Read, NULL);
    Error = GetLastError();
    if (Ret)
        skip("A buffer of %Iu bytes (of %I64u physical) can be locked on this machine\n", HugeSize, Memory.ullTotalPhys);
    else
        ok(Error == ERROR_NO_SYSTEM_RESOURCES, "ReadFile of %Iu bytes (of %I64u) failed with error %lu\n", HugeSize,
           Memory.ullTotalPhys, Error);
    VirtualFree(Huge, 0, MEM_RELEASE);

    /* the refusal took nothing: reads work as before */
    for (Round = 0; Round < 10; Round++)
    {
        SetFilePointer(Direct, 0, NULL, FILE_BEGIN);
        Ret = ReadFile(Direct, Buffer, BUFFER_SIZE, &Read, NULL);
        ok(Ret && Read == FILE_SIZE, "ReadFile after the refusal returned %d, error %lu, %lu bytes\n", Ret, GetLastError(), Read);
    }

Done:
    CloseHandle(Direct);
    VirtualFree(Buffer, 0, MEM_RELEASE);
    DeleteFileW(FileName);
}
