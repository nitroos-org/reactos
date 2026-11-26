/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Child process of the "cookie" test: writes the security cookies it sees to a file
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * loadconfig_cookie_exe.exe <file> static : own cookie, loadconfig_cookie1.dll (imported statically) and
 *                                           loadconfig_cookie4.dll (delay load)
 * loadconfig_cookie_exe.exe <file> dynamic: 100 times LoadLibrary / FreeLibrary of loadconfig_cookie2.dll, then
 *                                           loadconfig_cookie3.dll (no entry point) and the forwarder
 *                                           loadconfig_cookief.dll (which loads loadconfig_cookie2.dll)
 * One line per value: "<name> <hex>" ("saw1" / "saw2" / "saw4": the entry point saw the default cookie).
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN64
#define DEFAULT_COOKIE 0x00002B992DDFA232ull
#else
#define DEFAULT_COOKIE 0xBB40E64E
#endif

#define LOADS 100

typedef ULONG_PTR (WINAPI *PGET_COOKIE)(void);
typedef BOOL (WINAPI *PGET_SAW)(void);

ULONG_PTR WINAPI GetCookie1(void);
BOOL WINAPI GetSaw1(void);
ULONG_PTR WINAPI GetCookie4(void);
BOOL WINAPI GetSaw4(void);

/* the cookie of this executable */
static ULONG_PTR ExeCookie = DEFAULT_COOKIE;

const IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used =
{
    sizeof(IMAGE_LOAD_CONFIG_DIRECTORY),
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    (ULONG_PTR)&ExeCookie,      /* SecurityCookie */
};

static FILE *Out;

static void Put(const char *Name, ULONGLONG Value)
{
    fprintf(Out, "%s %I64x\n", Name, Value);
}

static void Dynamic(const char *Name, const char *Dll, const char *Function, const char *SawFunction)
{
    HMODULE Module = LoadLibraryA(Dll);
    PGET_COOKIE Get;
    PGET_SAW Saw;

    if (!Module)
    {
        fprintf(Out, "%s error %lu\n", Name, GetLastError());
        return;
    }
    Get = (PGET_COOKIE)GetProcAddress(Module, Function);
    Saw = SawFunction ? (PGET_SAW)GetProcAddress(Module, SawFunction) : NULL;
    if (Get)
        Put(Name, Get());
    else
        fprintf(Out, "%s noexport %lu\n", Name, GetLastError());
    if (Saw)
        Put("saw2", Saw());
    FreeLibrary(Module);
}

int main(int argc, char **argv)
{
    HMODULE Module;
    PGET_COOKIE Get;
    int i;

    if (argc < 3)
        return 2;
    Out = fopen(argv[1], "w");
    if (!Out)
        return 3;

    if (!strcmp(argv[2], "static"))
    {
        Put("exe", ExeCookie);
        Put("dll1", GetCookie1());
        Put("saw1", GetSaw1());
        Put("dll4", GetCookie4());
        Put("saw4", GetSaw4());
    }
    else
    {
        for (i = 0; i < LOADS; i++)
            Dynamic("dll2", "loadconfig_cookie2.dll", "GetCookie2", "GetSaw2");
        Dynamic("dll3", "loadconfig_cookie3.dll", "GetCookie3", NULL);

        /* the forwarder: loadconfig_cookie2.dll is not loaded when it is, and is made by the forward */
        Module = LoadLibraryA("loadconfig_cookief.dll");
        Get = Module ? (PGET_COOKIE)GetProcAddress(Module, "FwdCookie") : NULL;
        if (Get)
            Put("fwd", Get());
        else
            fprintf(Out, "fwd error %lu\n", GetLastError());
    }
    fclose(Out);
    return 0;
}
