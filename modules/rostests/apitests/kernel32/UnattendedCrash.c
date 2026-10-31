/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that an unhandled crash ends a process promptly when nobody can answer a dialog
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <wingdi.h>
#include <winuser.h>

/*
 * A child crashes without a handler, on a window station that is not
 * interactive (a service, or a session without a desktop). Windows reports the
 * crash without asking anyone and ends the process with the exception code.
 * The crash reporter must not wait for a dialog that no one can see.
 */

/* The report may take a while on a loaded machine, but never this long */
#define TERMINATION_LIMIT   30000

#define STATUS_FAIL_FAST_EXCEPTION_CODE 0xC0000602
#define CPP_EXCEPTION_CODE              0xE06D7363
/* The child could not load uhexit_dll.dll: no crash, and the wrong exit code */
#define NO_DLL_EXIT_CODE                0x0BADD11
#define RETURNED_EXIT_CODE              0x5EE

typedef VOID (WINAPI *FN_RaiseFailFastException)(PEXCEPTION_RECORD, PCONTEXT, DWORD);

static volatile LONG *NullPointer;

/* Child side ****************************************************************/

static VOID RunChild(PCSTR Mode)
{
    FN_RaiseFailFastException pRaiseFailFastException;

    /* Its DLL_PROCESS_DETACH leaves a marker: a crashed process must not run it */
    if (!LoadLibraryW(L"uhexit_dll.dll"))
        ExitProcess(NO_DLL_EXIT_CODE);
    /* The test framework turns off the fault error box; a program that crashes for real has it on */
    SetErrorMode(0);

    if (!strcmp(Mode, "av"))
    {
        *NullPointer = 1;
    }
    else if (!strcmp(Mode, "failfast"))
    {
        pRaiseFailFastException = (FN_RaiseFailFastException)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                                                            "RaiseFailFastException");
        if (pRaiseFailFastException)
            pRaiseFailFastException(NULL, NULL, 0);
    }
    else if (!strcmp(Mode, "throw"))
    {
        /* What an uncaught C++ exception looks like when it reaches the top-level filter */
        ULONG_PTR Arguments[4] = { 0x19930520, 0, 0, 0 };
        RaiseException(CPP_EXCEPTION_CODE, EXCEPTION_NONCONTINUABLE, _countof(Arguments), Arguments);
    }
    ExitProcess(RETURNED_EXIT_CODE);
}

/* Parent side ***************************************************************/

typedef struct _CONTEXT_INFO
{
    PCSTR Name;
    HWINSTA hWinSta;
    HDESK hDesktop;
    WCHAR DesktopName[80];
} CONTEXT_INFO;

static BOOL IsInteractive(HWINSTA hWinSta)
{
    USEROBJECTFLAGS Flags;

    return hWinSta &&
           GetUserObjectInformationW(hWinSta, UOI_FLAGS, &Flags, sizeof(Flags), NULL) &&
           (Flags.dwFlags & WSF_VISIBLE);
}

/* A window station of its own is not interactive, as on a service; the child's desktop is created there */
static BOOL CreatePrivateContext(CONTEXT_INFO *Context)
{
    WCHAR WinStaName[64];
    HWINSTA hOld = GetProcessWindowStation();

    StringCchPrintfW(WinStaName, _countof(WinStaName), L"k32unatt.%lu", GetCurrentProcessId());
    Context->hWinSta = CreateWindowStationW(WinStaName, 0, WINSTA_ALL_ACCESS, NULL);
    if (!Context->hWinSta)
    {
        skip("CreateWindowStation failed with %lu\n", GetLastError());
        return FALSE;
    }
    if (IsInteractive(Context->hWinSta))
    {
        skip("The new window station is interactive\n");
        CloseWindowStation(Context->hWinSta);
        return FALSE;
    }
    /* A desktop is created on the window station of the calling process */
    if (!SetProcessWindowStation(Context->hWinSta))
    {
        skip("SetProcessWindowStation failed with %lu\n", GetLastError());
        CloseWindowStation(Context->hWinSta);
        return FALSE;
    }
    Context->hDesktop = CreateDesktopW(L"Default", NULL, NULL, 0, GENERIC_ALL, NULL);
    SetProcessWindowStation(hOld);
    if (!Context->hDesktop)
    {
        skip("CreateDesktop failed with %lu\n", GetLastError());
        CloseWindowStation(Context->hWinSta);
        return FALSE;
    }
    StringCchPrintfW(Context->DesktopName, _countof(Context->DesktopName), L"%s\\Default", WinStaName);
    return TRUE;
}

static VOID DestroyPrivateContext(CONTEXT_INFO *Context)
{
    CloseDesktop(Context->hDesktop);
    CloseWindowStation(Context->hWinSta);
}

static BOOL DetachRan(DWORD ProcessId)
{
    WCHAR Path[MAX_PATH], Temp[MAX_PATH];
    BOOL Ran;

    GetTempPathW(_countof(Temp), Temp);
    StringCchPrintfW(Path, _countof(Path), L"%suhexit.%lu.txt", Temp, ProcessId);
    Ran = GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
    DeleteFileW(Path);
    return Ran;
}

static VOID TestCrash_(PCSTR Mode, DWORD ExpectedCode, CONTEXT_INFO *Context, int Line)
{
    CHAR FileName[MAX_PATH], CommandLine[MAX_PATH + 64];
    WCHAR Desktop[80];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DWORD Start, Elapsed, Wait, Code = 0;

    GetModuleFileNameA(NULL, FileName, _countof(FileName));
    StringCbPrintfA(CommandLine, sizeof(CommandLine), "\"%s\" UnattendedCrash %s", FileName, Mode);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    if (Context->hDesktop)
    {
        StringCchCopyW(Desktop, _countof(Desktop), Context->DesktopName);
        StartupInfo.lpDesktop = Desktop;
    }

    /* The A version of CreateProcess has no desktop parameter of its own, but takes the command line as it is */
    {
        WCHAR FileNameW[MAX_PATH], CommandLineW[MAX_PATH + 64];
        MultiByteToWideChar(CP_ACP, 0, FileName, -1, FileNameW, _countof(FileNameW));
        MultiByteToWideChar(CP_ACP, 0, CommandLine, -1, CommandLineW, _countof(CommandLineW));
        if (!CreateProcessW(FileNameW, CommandLineW, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
        {
            skip("CreateProcess failed with %lu\n", GetLastError());
            return;
        }
    }
    CloseHandle(ProcessInfo.hThread);

    Start = GetTickCount();
    Wait = WaitForSingleObject(ProcessInfo.hProcess, TERMINATION_LIMIT);
    Elapsed = GetTickCount() - Start;
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(ProcessInfo.hProcess, 0xDEAD);
    WaitForSingleObject(ProcessInfo.hProcess, 10000);
    GetExitCodeProcess(ProcessInfo.hProcess, &Code);
    trace("%s, %s: ended after %lu ms with code 0x%lx\n", Context->Name, Mode, Elapsed, Code);

    ok_(__FILE__, Line)(Wait == WAIT_OBJECT_0, "%s, %s: still running after %lu ms\n", Context->Name, Mode, Elapsed);
    ok_(__FILE__, Line)(Code == ExpectedCode, "%s, %s: exit code 0x%lx, expected 0x%lx\n",
                        Context->Name, Mode, Code, ExpectedCode);
    ok_(__FILE__, Line)(!DetachRan(ProcessInfo.dwProcessId), "%s, %s: the crashed program ran DLL detach\n",
                        Context->Name, Mode);
    CloseHandle(ProcessInfo.hProcess);
}
#define TestCrash(Mode, Code, Context) TestCrash_(Mode, Code, Context, __LINE__)

static VOID TestContext(CONTEXT_INFO *Context)
{
    TestCrash("av", STATUS_ACCESS_VIOLATION, Context);
    TestCrash("failfast", STATUS_FAIL_FAST_EXCEPTION_CODE, Context);
    TestCrash("throw", CPP_EXCEPTION_CODE, Context);
}

START_TEST(UnattendedCrash)
{
    PCHAR *Argv;
    int Argc;
    CONTEXT_INFO Context;

    Argc = winetest_get_mainargs(&Argv);
    if (Argc >= 3)
    {
        RunChild(Argv[2]);
        return;
    }

    ok(SearchPathW(NULL, L"uhexit_dll.dll", NULL, 0, NULL, NULL) != 0,
       "uhexit_dll.dll not found: %lu\n", GetLastError());

    /* Started from a service or over ssh, the child shares this window station */
    if (!IsInteractive(GetProcessWindowStation()))
    {
        ZeroMemory(&Context, sizeof(Context));
        Context.Name = "inherited";
        TestContext(&Context);
    }

    /* Whatever the session, a child on a window station of its own has no one to answer */
    ZeroMemory(&Context, sizeof(Context));
    Context.Name = "private";
    if (CreatePrivateContext(&Context))
    {
        TestContext(&Context);
        DestroyPrivateContext(&Context);
    }
}
