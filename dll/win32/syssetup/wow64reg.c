/*
 * PROJECT:     ReactOS system setup
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registration of the 32-bit COM servers of SysWOW64, shared by Setup's second stage (wizard.c) and by
 *              "featmgr /enable wow64" (the 32-bit side added after the installation). The list of DLLs is data: the
 *              sections [Wow64RegisterCore] and [Wow64RegisterExtra] of syssetup.inf.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <windows.h>
#include <setupapi.h>
#include <stdlib.h>
#include <wchar.h>
#include "wow64reg.h"

#define WOW64REG_MAX_DLLS   256     /* per section; more lines are not read */
#define WOW64REG_NAME_LEN   96      /* a name relative to SysWOW64 */

static VOID
Say(
    _In_opt_ const WOW64REG_CALLBACKS *Callbacks,
    _In_ PCWSTR Format,
    _In_ PCWSTR Dll,
    _In_ DWORD Error,
    _In_ PCWSTR Suffix)
{
    WCHAR Message[WOW64REG_NAME_LEN + 128];

    if (!Callbacks || !Callbacks->Log) return;
    _snwprintf(Message, ARRAYSIZE(Message), Format, Dll, Error, Suffix);
    Message[ARRAYSIZE(Message) - 1] = UNICODE_NULL;
    Callbacks->Log(Callbacks->Context, Message);
}

static DWORD
RunRegsvr32(
    _In_ PCWSTR Application,
    _In_ PCWSTR Directory,
    _In_ PCWSTR Dll)
{
    WCHAR Command[2 * MAX_PATH + 64];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    DWORD ExitCode, Wait, Error;

    _snwprintf(Command, ARRAYSIZE(Command), L"\"%s\" /s \"%s\\%s\"",
               Application, Directory, Dll);
    Command[ARRAYSIZE(Command) - 1] = UNICODE_NULL;
    if (!CreateProcessW(Application, Command, NULL, NULL, FALSE, 0,
                        NULL, NULL, &Startup, &Process))
        return GetLastError();
    Wait = WaitForSingleObject(Process.hProcess, 60000);
    if (Wait == WAIT_OBJECT_0)
    {
        Error = GetExitCodeProcess(Process.hProcess, &ExitCode) ?
                (ExitCode ? ERROR_DLL_INIT_FAILED : ERROR_SUCCESS) : GetLastError();
    }
    else
    {
        Error = Wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        TerminateProcess(Process.hProcess, Error);
        WaitForSingleObject(Process.hProcess, INFINITE);
    }
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    return Error;
}

/* A name relative to SysWOW64 that stays inside it: no drive or stream colon, no ".." , not rooted. The list is in
 * %SystemRoot%\inf (writable by administrators only); this keeps a damaged line from reaching anything else. */
static BOOL
NameOk(
    _In_ PCWSTR Name)
{
    if (Name[0] == L'\\' || Name[0] == L'/' || wcschr(Name, L':') || wcschr(Name, L'/') || wcsstr(Name, L".."))
        return FALSE;
    return TRUE;
}

/* The names of one section, in file order: *Names is one allocation of *Count entries of WOW64REG_NAME_LEN characters */
static BOOL
ReadSection(
    _In_ HINF Inf,
    _In_ PCWSTR Section,
    _Out_ WCHAR (**Names)[WOW64REG_NAME_LEN],
    _Out_ ULONG *Count)
{
    INFCONTEXT Context;
    LONG Lines;
    ULONG n = 0;
    BOOL More;

    *Names = NULL;
    *Count = 0;
    Lines = SetupGetLineCountW(Inf, Section);
    if (Lines <= 0) return Lines == 0;      /* an empty section is fine, a missing one is not */
    if (Lines > WOW64REG_MAX_DLLS) Lines = WOW64REG_MAX_DLLS;
    *Names = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)Lines * sizeof(**Names));
    if (!*Names) return FALSE;

    for (More = SetupFindFirstLineW(Inf, Section, NULL, &Context); More && n < (ULONG)Lines;
         More = SetupFindNextLine(&Context, &Context))
    {
        if (SetupGetStringFieldW(&Context, 1, (*Names)[n], WOW64REG_NAME_LEN, NULL) && (*Names)[n][0] &&
            NameOk((*Names)[n]))
            n++;
    }
    *Count = n;
    return TRUE;
}

/* Pass 0 registers every DLL; pass 1 repeats those that failed, now that the rest is in place (quartz and devenum need each
 * other). A failure does not stop the remaining DLLs. Returns the first error of the second pass. */
static DWORD
RegisterList(
    _In_ PCWSTR Application,
    _In_ PCWSTR Directory,
    _In_reads_(Count) WCHAR (*Dlls)[WOW64REG_NAME_LEN],
    _In_ ULONG Count,
    _In_ BOOL Fatal,
    _Inout_ ULONG *Done,
    _In_ ULONG Total,
    _In_opt_ const WOW64REG_CALLBACKS *Callbacks)
{
    DWORD Result = ERROR_SUCCESS, Error, *Failed;
    ULONG Pass, i;

    Failed = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)(Count ? Count : 1) * sizeof(DWORD));
    if (!Failed) return ERROR_NOT_ENOUGH_MEMORY;

    for (Pass = 0; Pass < 2; ++Pass)
    {
        for (i = 0; i < Count; ++i)
        {
            if (Pass && !Failed[i]) continue;
            if (!Pass && Callbacks && Callbacks->Progress)
                Callbacks->Progress(Callbacks->Context, Dlls[i], *Done, Total);
            Error = RunRegsvr32(Application, Directory, Dlls[i]);
            Failed[i] = Error;
            if (!Pass) ++*Done;
            if (Error && Pass)
            {
                Say(Callbacks, L"SysWOW64 registration of %s failed: %lu%s", Dlls[i], Error,
                    Fatal ? L"" : L" (not fatal)");
                if (Fatal && Result == ERROR_SUCCESS) Result = Error;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Failed);
    return Result;
}

DWORD
Wow64RegisterDlls(
    _In_ HINF Inf,
    _In_opt_ const WOW64REG_CALLBACKS *Callbacks)
{
    WCHAR Directory[MAX_PATH], Application[MAX_PATH];
    WCHAR (*Core)[WOW64REG_NAME_LEN], (*Extra)[WOW64REG_NAME_LEN];
    ULONG CoreCount, ExtraCount, Done = 0;
    DWORD Count, Result;

    Count = GetWindowsDirectoryW(Directory, ARRAYSIZE(Directory));
    if (!Count) return GetLastError();
    if (Count + ARRAYSIZE(L"\\SysWOW64\\regsvr32.exe") > ARRAYSIZE(Application))
        return ERROR_INSUFFICIENT_BUFFER;
    wcscat(Directory, L"\\SysWOW64");
    wcscpy(Application, Directory);
    wcscat(Application, L"\\regsvr32.exe");

    if (!ReadSection(Inf, L"Wow64RegisterCore", &Core, &CoreCount))
        return GetLastError() ? GetLastError() : ERROR_NOT_FOUND;
    if (!ReadSection(Inf, L"Wow64RegisterExtra", &Extra, &ExtraCount))
    {
        Result = GetLastError() ? GetLastError() : ERROR_NOT_FOUND;
        if (Core) HeapFree(GetProcessHeap(), 0, Core);
        return Result;
    }

    /* The core set failing fails the registration; the extras are best-effort */
    Result = RegisterList(Application, Directory, Core, CoreCount, TRUE, &Done, CoreCount + ExtraCount, Callbacks);
    RegisterList(Application, Directory, Extra, ExtraCount, FALSE, &Done, CoreCount + ExtraCount, Callbacks);
    if (Callbacks && Callbacks->Progress)
        Callbacks->Progress(Callbacks->Context, NULL, Done, CoreCount + ExtraCount);

    if (Core) HeapFree(GetProcessHeap(), 0, Core);
    if (Extra) HeapFree(GetProcessHeap(), 0, Extra);
    return Result;
}
