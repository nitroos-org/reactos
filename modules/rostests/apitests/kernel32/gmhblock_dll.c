/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Helper DLL for GetModuleHandleLoaderLock: its DLL_PROCESS_ATTACH says it entered and waits (the loader
 *              lock held by the loading thread) until the test lets it go
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

/* Gmh<Entered|Release>.<pid>, without the C runtime */
static HANDLE OpenNamedEvent(PCWSTR Prefix)
{
    WCHAR Name[64], Digits[16];
    DWORD Pid = GetCurrentProcessId(), Length;
    int Count = 0;

    lstrcpyW(Name, Prefix);
    do
    {
        Digits[Count++] = L'0' + (WCHAR)(Pid % 10);
        Pid /= 10;
    } while (Pid);
    Length = lstrlenW(Name);
    while (Count)
        Name[Length++] = Digits[--Count];
    Name[Length] = UNICODE_NULL;
    return OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, Name);
}

VOID WINAPI GmhBlockDummy(VOID)
{
}

BOOL WINAPI DllMain(HINSTANCE Instance, DWORD Reason, LPVOID Reserved)
{
    HANDLE Entered, Release;

    if (Reason != DLL_PROCESS_ATTACH)
        return TRUE;

    Entered = OpenNamedEvent(L"GmhEntered.");
    Release = OpenNamedEvent(L"GmhRelease.");
    if (Entered && Release)
    {
        SetEvent(Entered);
        WaitForSingleObject(Release, 20000);
    }
    if (Entered)
        CloseHandle(Entered);
    if (Release)
        CloseHandle(Release);
    return TRUE;
}
