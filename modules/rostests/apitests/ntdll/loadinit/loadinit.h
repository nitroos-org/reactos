/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helpers of the LdrLoadDllPendingInit test: one ordered log of the DllMain events of all helper
 *              DLLs, kept in an environment variable of the process (no helper imports another just to log)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

#define LOADINIT_LOG_VAR "NTDLL_LOADINIT_LOG"

static void LoadInitLog(const char *Event)
{
    char Buffer[1024];
    DWORD Length = GetEnvironmentVariableA(LOADINIT_LOG_VAR, Buffer, sizeof(Buffer));

    if (Length >= sizeof(Buffer)) Length = 0;
    Buffer[Length] = 0;
    if (Length + lstrlenA(Event) + 2 < sizeof(Buffer))
    {
        if (Length) lstrcatA(Buffer, " ");
        lstrcatA(Buffer, Event);
    }
    SetEnvironmentVariableA(LOADINIT_LOG_VAR, Buffer);
}

static __inline BOOL LoadInitEnvIs(const char *Name, const char *Value)
{
    char Buffer[32];
    DWORD Length = GetEnvironmentVariableA(Name, Buffer, sizeof(Buffer));
    return Length && Length < sizeof(Buffer) && !lstrcmpA(Buffer, Value);
}
