/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A DLL with a LOAD_CONFIG whose security cookie the loader has to make (see cookie.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * One source for several DLLs (loadconfig_cookie1 .. 4); each exports its own function so that a program can import
 * them statically, by delay load, or find them with LoadLibrary. loadconfig_cookie3 has no entry point at all.
 */

#include <windows.h>

#ifdef _WIN64
#define DEFAULT_COOKIE 0x00002B992DDFA232ull
#else
#define DEFAULT_COOKIE 0xBB40E64E
#endif

/* the cookie of this image: the loader replaces the default value before any code of the image runs */
static ULONG_PTR DllCookie = DEFAULT_COOKIE;

/* the loader looks for the cookie through this directory */
const IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used =
{
    sizeof(IMAGE_LOAD_CONFIG_DIRECTORY),
    0,                          /* TimeDateStamp */
    0,                          /* MajorVersion */
    0,                          /* MinorVersion */
    0,                          /* GlobalFlagsClear */
    0,                          /* GlobalFlagsSet */
    0,                          /* CriticalSectionDefaultTimeout */
    0,                          /* DeCommitFreeBlockThreshold */
    0,                          /* DeCommitTotalFreeThreshold */
    0,                          /* LockPrefixTable */
    0,                          /* MaximumAllocationSize */
    0,                          /* VirtualMemoryThreshold */
    0,                          /* ProcessHeapFlags */
    0,                          /* ProcessAffinityMask */
    0,                          /* CSDVersion */
    0,                          /* Reserved1 */
    0,                          /* EditList */
    (ULONG_PTR)&DllCookie,      /* SecurityCookie */
};

ULONG_PTR WINAPI GetCookie1(void) { return DllCookie; }
ULONG_PTR WINAPI GetCookie2(void) { return DllCookie; }
ULONG_PTR WINAPI GetCookie3(void) { return DllCookie; }
ULONG_PTR WINAPI GetCookie4(void) { return DllCookie; }

/* what the entry point saw: the cookie has to be in place before it runs */
static BOOL SawDefaultAtAttach;

BOOL WINAPI GetSaw1(void) { return SawDefaultAtAttach; }
BOOL WINAPI GetSaw2(void) { return SawDefaultAtAttach; }
BOOL WINAPI GetSaw4(void) { return SawDefaultAtAttach; }

BOOL WINAPI DllMain(HINSTANCE Instance, DWORD Reason, LPVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
        SawDefaultAtAttach = (DllCookie == DEFAULT_COOKIE);
    return TRUE;
}
