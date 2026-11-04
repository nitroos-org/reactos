/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     installer_memory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Installer allocators must not receive a block ending at the 32-bit wrap. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

int main(void)
{
    static const SIZE_T Sizes[] = {0x60000, 0x140000, 0x1000};
    SYSTEM_INFO Info;
    MEMORY_BASIC_INFORMATION Memory;
    BYTE *Blocks[3] = {0};
    BOOL Wow = FALSE;
    ULONG Expected;
    unsigned i, j;
    GetSystemInfo(&Info);
    CHECK(IsWow64Process(GetCurrentProcess(), &Wow));
    Expected = Wow && EXPECT_LARGE_ADDRESS ? 0xfffeffff : 0x7ffeffff;
    CHECK((ULONG_PTR)Info.lpMaximumApplicationAddress == Expected);
    printf("ADDRESS LIMIT wow64=%u large=%u maximum=%p\n", Wow, EXPECT_LARGE_ADDRESS, Info.lpMaximumApplicationAddress);
    for (i = 0; i < 3; ++i)
    {
        Blocks[i] = VirtualAlloc(NULL, Sizes[i], MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
        CHECK(Blocks[i] != NULL);
        if (!Blocks[i]) continue;
        printf("TOP DOWN base=%p size=%Ix\n", Blocks[i], Sizes[i]);
        CHECK((ULONGLONG)(ULONG_PTR)Blocks[i] + Sizes[i] <= (ULONGLONG)Expected + 1);
        CHECK(VirtualQuery(Blocks[i], &Memory, sizeof(Memory)) == sizeof(Memory));
        CHECK(Memory.AllocationBase == Blocks[i] && Memory.State == MEM_COMMIT);
        CHECK(Memory.RegionSize >= Sizes[i]);
        for (j = 0; j < i; ++j)
            CHECK((ULONGLONG)(ULONG_PTR)Blocks[i] + Sizes[i] <= (ULONG_PTR)Blocks[j] ||
                  (ULONGLONG)(ULONG_PTR)Blocks[j] + Sizes[j] <= (ULONG_PTR)Blocks[i]);
        Blocks[i][0] = 0x55;
        Blocks[i][Sizes[i] - 1] = 0xaa;
        CHECK(Blocks[i][0] == 0x55 && Blocks[i][Sizes[i] - 1] == 0xaa);
    }
    for (i = 0; i < 3; ++i)
        if (Blocks[i]) CHECK(VirtualFree(Blocks[i], 0, MEM_RELEASE));
    printf("INSTALLER MEMORY checks=%u failures=%u\n", Checks, Failures);
    return Failures ? 1 : 0;
}
