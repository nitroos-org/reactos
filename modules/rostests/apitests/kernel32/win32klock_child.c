/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A process that has made no Win32k call, asking for the Win32k lockdown (ProcessMitigationPolicy test)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Exit code: the error of the request in the low word (0 if it was accepted), and what the policy reads back
 * afterwards in the high word.
 */
#include <windows.h>

typedef BOOL (WINAPI *FN_Get)(HANDLE, int, PVOID, SIZE_T);
typedef BOOL (WINAPI *FN_Set)(int, PVOID, SIZE_T);

void __cdecl mainCRTStartup(void)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FN_Get pGet = (FN_Get)GetProcAddress(hKernel32, "GetProcessMitigationPolicy");
    FN_Set pSet = (FN_Set)GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    DWORD Flags = 1, Back = 0xff, Error = 0;

    if (!pGet || !pSet)
        ExitProcess(0xfffe);
    if (!pSet(4, &Flags, sizeof(Flags)))
        Error = GetLastError();
    if (!pGet(GetCurrentProcess(), 4, &Back, sizeof(Back)))
        Back = 0xff;
    ExitProcess((Back << 16) | Error);
}
