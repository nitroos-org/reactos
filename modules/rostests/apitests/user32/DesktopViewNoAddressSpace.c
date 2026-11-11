/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a desktop cannot be created or opened in a process with no address space left
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Opening a desktop handle maps the desktop heap into the process. In a process that has used up its address space
 * (a 32-bit process; the console server starts a thread with its own stack for every control event, a thousand
 * of them fill 2 GB) the mapping fails, and the request must fail with it, cleanly: no handle, no leaked count on the
 * desktop, no assertion in the object manager. The process works again when the address space is given back.
 */
#define MAX_BLOCKS      (1 << 16)
#define HEADROOM_BLOCKS 8           /* 64 KB blocks given back so that small allocations still work: 512 KB */

static PVOID Blocks[MAX_BLOCKS];

START_TEST(DesktopViewNoAddressSpace)
{
    ULONG Count = 0, i;
    SIZE_T Size;
    PVOID Block;
    HDESK Desktop, DesktopAgain;
    DWORD Error = 0, ErrorAgain = 0;
    WCHAR Name[64];

    if (sizeof(PVOID) > 4)
    {
        skip("A 64-bit process does not run out of address space\n");
        return;
    }

    wsprintfW(Name, L"DesktopViewNoAddressSpace%lu", GetCurrentProcessId());

    /* Reserve all the address space there is, large blocks first */
    for (Size = 64 * 1024 * 1024; Size >= 64 * 1024 && Count < MAX_BLOCKS; )
    {
        Block = VirtualAlloc(NULL, Size, MEM_RESERVE, PAGE_NOACCESS);
        if (Block)
            Blocks[Count++] = Block;
        else
            Size /= 2;
    }
    /* Keep a little for the allocations of the calls below, not enough for a desktop heap view */
    for (i = 0; i < HEADROOM_BLOCKS && Count > 0; i++)
        VirtualFree(Blocks[--Count], 0, MEM_RELEASE);

    SetLastError(0xDEADBEEF);
    Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    Error = GetLastError();
    if (Desktop)
        CloseDesktop(Desktop);
    SetLastError(0xDEADBEEF);
    DesktopAgain = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    ErrorAgain = GetLastError();
    if (DesktopAgain)
        CloseDesktop(DesktopAgain);

    while (Count > 0)
        VirtualFree(Blocks[--Count], 0, MEM_RELEASE);

    /* Which of the two fails depends on the space left; neither may hang or crash, and a failure carries an error */
    ok(Desktop == NULL ? Error != 0 && Error != 0xDEADBEEF : TRUE,
       "CreateDesktop failed without an error code: %lu\n", Error);
    ok(DesktopAgain == NULL ? ErrorAgain != 0 && ErrorAgain != 0xDEADBEEF : TRUE,
       "second CreateDesktop failed without an error code: %lu\n", ErrorAgain);
    trace("CreateDesktop with no address space: %p (error %lu), again %p (error %lu)\n",
          Desktop, Error, DesktopAgain, ErrorAgain);

    /* With the address space back everything works, and the failed attempts left nothing behind */
    Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    ok(Desktop != NULL, "CreateDesktop failed with %lu after the address space came back\n", GetLastError());
    if (Desktop)
    {
        ok(CloseDesktop(Desktop), "CloseDesktop failed with %lu\n", GetLastError());
    }
}
