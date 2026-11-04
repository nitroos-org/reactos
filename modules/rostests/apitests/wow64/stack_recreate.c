/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     stack_recreate
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* ReactOS bootstrap-layout regression: extra child RuntimeData must not
 * occupy the parent stack range. This is not an ASLR placement contract. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static PVOID OriginalStack, ParentStack;
static SIZE_T ParentSize;
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

static SIZE_T StackRegion(PVOID Address, PVOID *Base)
{
    MEMORY_BASIC_INFORMATION Info;
    SIZE_T Size = 0;
    if (!VirtualQuery(Address, &Info, sizeof(Info))) return 0;
    *Base = Info.AllocationBase;
    Address = *Base;
    while (VirtualQuery(Address, &Info, sizeof(Info)) && Info.AllocationBase == *Base)
    {
        Size += Info.RegionSize;
        Address = (BYTE *)Address + Info.RegionSize;
    }
    return Size;
}

static VOID WINAPI Recreate(PVOID Argument)
{
    BYTE *Memory;
    CHECK(VirtualFree(OriginalStack, 0, MEM_RELEASE));
    Memory = VirtualAlloc(ParentStack, ParentSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(Memory == ParentStack);
    if (Memory)
    {
        Memory[0] = 0xa5;
        Memory[ParentSize - 1] = 0x5a;
        CHECK(Memory[0] == 0xa5 && Memory[ParentSize - 1] == 0x5a);
        CHECK(VirtualFree(Memory, 0, MEM_RELEASE));
    }
    printf("STACK RECREATE checks=%u failures=%u\n", Checks, Failures);
    /* The original fiber's stack is gone; never switch back to it. */
    ExitProcess(Failures ? 1 : 0);
}

int main(int argc, char **argv)
{
    STARTUPINFOA Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    BYTE Reserved[4096] = {0};
    char Path[MAX_PATH], Command[512];
    DWORD Code = 99;
    PVOID Fiber;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3)
    {
        ParentStack = (PVOID)(ULONG_PTR)strtoul(argv[1], NULL, 16);
        ParentSize = strtoul(argv[2], NULL, 16);
        GetStartupInfoA(&Startup);
        CHECK(Startup.cbReserved2 == sizeof(Reserved) && Startup.lpReserved2);
        if (Startup.lpReserved2 && Startup.cbReserved2 == sizeof(Reserved))
            CHECK(Startup.lpReserved2[sizeof(Reserved) - 1] == 0x5a);
        CHECK(StackRegion(&Startup, &OriginalStack) != 0);
        printf("STACK RECREATE original=%p parent=%p size=%Ix\n", OriginalStack, ParentStack, ParentSize);
        CHECK(ConvertThreadToFiber(NULL) != NULL);
        Fiber = CreateFiber(0x10000, Recreate, NULL);
        CHECK(Fiber != NULL);
        if (Fiber) SwitchToFiber(Fiber);
        return 2;
    }
    ParentSize = StackRegion(&Startup, &ParentStack);
    CHECK(ParentSize != 0);
    CHECK(GetModuleFileNameA(NULL, Path, sizeof(Path)) != 0);
    _snprintf(Command, sizeof(Command), "\"%s\" %lx %lx", Path,
              (ULONG)(ULONG_PTR)ParentStack, (ULONG)ParentSize);
    Reserved[sizeof(Reserved) - 1] = 0x5a;
    Startup.cbReserved2 = sizeof(Reserved);
    Startup.lpReserved2 = Reserved;
    CHECK(CreateProcessA(Path, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process));
    if (Failures) return 1;
    CHECK(WaitForSingleObject(Process.hProcess, 30000) == WAIT_OBJECT_0);
    CHECK(GetExitCodeProcess(Process.hProcess, &Code));
    CHECK(Code == 0);
    if (Code == STILL_ACTIVE) TerminateProcess(Process.hProcess, 99);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    printf("STACK PARENT checks=%u failures=%u child=%lu\n", Checks, Failures, Code);
    return Failures ? 1 : 0;
}
