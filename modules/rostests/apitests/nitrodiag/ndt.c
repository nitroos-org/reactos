/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test target for the compatibility log tool (nitrodiag): one program, many ways to misbehave
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define COBJMACROS
#include <windows.h>
#include <shlobj.h>

static volatile int g_sink;

static int Recurse(int depth)
{
    volatile char pad[512];
    pad[0] = (char)depth;
    g_sink += pad[0];
    return Recurse(depth + 1) + pad[0];
}

int main(int argc, char **argv)
{
    int i;
    const char *mode = argc > 1 ? argv[1] : "";

    if (!strcmp(mode, "av"))
    {
        volatile int *p = (volatile int *)(ULONG_PTR)8;
        printf("ndt: about to write to an invalid address\n");
        fflush(stdout);
        *p = 1;
    }
    else if (!strcmp(mode, "avread"))
    {
        volatile int *p = (volatile int *)(ULONG_PTR)0x10;
        printf("ndt: about to read from an invalid address\n");
        fflush(stdout);
        g_sink = *p;
    }
    else if (!strcmp(mode, "div0"))
    {
        volatile int z = 0;
        printf("ndt: about to divide by zero\n");
        fflush(stdout);
        g_sink = 10 / z;
    }
    else if (!strcmp(mode, "stackoverflow"))
    {
        printf("ndt: about to overflow the stack\n");
        fflush(stdout);
        return Recurse(0);
    }
    else if (!strcmp(mode, "abort"))
    {
        printf("ndt: about to call abort()\n");
        fflush(stdout);
        abort();
    }
    else if (!strcmp(mode, "child"))
    {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        char cmd[MAX_PATH + 32];
        DWORD code = 0;
        GetModuleFileNameA(NULL, cmd, MAX_PATH);
        strcat(cmd, " av");
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        printf("ndt: starting a child that crashes\n");
        fflush(stdout);
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
            return 90;
        WaitForSingleObject(pi.hProcess, 20000);
        GetExitCodeProcess(pi.hProcess, &code);
        printf("ndt: the child ended with 0x%lx\n", code);
        return 0;
    }
    else if (!strcmp(mode, "hang"))
    {
        printf("ndt: hanging at start\n");
        fflush(stdout);
        Sleep(INFINITE);
    }
    else if (!strcmp(mode, "echo"))
    {
        printf("CMD=[%ls]\n", GetCommandLineW());
        for (i = 2; i < argc; i++)
            printf("ARG%d=[%s]\n", i - 1, argv[i]);
    }
    else if (!strcmp(mode, "dbgcheck"))
    {
        if (IsDebuggerPresent())
        {
            printf("ndt: a debugger is attached; leaving\n");
            return 77;
        }
        printf("ndt: no debugger\n");
        return 0;
    }
    else if (!strcmp(mode, "stub"))
    {
        /* an export that NitroOS lists in a spec file as 'stub': the call raises an exception that names it */
        FARPROC f = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckForReadOnlyResource");
        printf("ndt: calling kernel32!CheckForReadOnlyResource (%p)\n", f);
        fflush(stdout);
        if (f)
            ((void (WINAPI *)(void))f)();
    }
    else if (!strcmp(mode, "stub2"))
    {
        /* a '-stub' export: the stub prints its name and returns 0 */
        FARPROC f = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckElevationEnabled");
        printf("ndt: calling kernel32!CheckElevationEnabled (%p)\n", f);
        fflush(stdout);
        if (f)
        {
            ((int (WINAPI *)(void *))f)(NULL);
            ((int (WINAPI *)(void *))f)(NULL);
        }
        return 0;
    }
    else if (!strcmp(mode, "debugstr"))
    {
        OutputDebugStringA("ndt: hello from OutputDebugString\n");
        return 5;
    }
    else if (!strcmp(mode, "mklnk") && argc > 4)
    {
        /* mklnk FILE.lnk TARGET ARGUMENTS: a shortcut for the tests */
        IShellLinkW *sl = NULL;
        IPersistFile *pf = NULL;
        WCHAR file[MAX_PATH], target[MAX_PATH], args[256];
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, file, MAX_PATH);
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, target, MAX_PATH);
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, args, 256);
        CoInitialize(NULL);
        if (FAILED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl)))
            return 91;
        IShellLinkW_SetPath(sl, target);
        IShellLinkW_SetArguments(sl, args);
        if (FAILED(IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf)) || FAILED(IPersistFile_Save(pf, file, TRUE)))
            return 92;
        printf("ndt: wrote %ls\n", file);
        return 0;
    }
    else if (!strcmp(mode, "exit"))
    {
        return argc > 2 ? atoi(argv[2]) : 0;
    }
    else
    {
        printf("ndt: modes: av avread div0 stackoverflow abort child hang echo dbgcheck stub stub2 debugstr exit N\n");
        return 2;
    }
    return 0;
}
