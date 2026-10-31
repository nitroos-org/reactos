/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for what a shortcut starts: arguments, working directory, show command and
 *              environment variables in the target, the directory and the arguments
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"
#include "shell32_apitest_sub.h"
#include <strsafe.h>
#include <shellutils.h>

#define LNK_DIR_VARIABLE L"SHELL32_LNKTEST_DIR"

static WCHAR s_Root[MAX_PATH];      // temporary directory, holds the links and a copy of the sub program
static WCHAR s_WorkDir[MAX_PATH];   // "<root>\work dir"
static WCHAR s_SubCopy[MAX_PATH];   // "<root>\shell32_apitest_sub.exe"
static WCHAR s_Marker[MAX_PATH];

/* expected show command: not checked */
#define SHOW_ANY (-1)

static void
MakeLink(
    _In_ PCWSTR LinkPath,
    _In_ PCWSTR Target,
    _In_opt_ PCWSTR Arguments,
    _In_opt_ PCWSTR WorkingDirectory,
    _In_ INT ShowCmd)
{
    CComPtr<IShellLinkW> ShellLink;
    CComPtr<IPersistFile> PersistFile;
    HRESULT hr;

    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARG(IShellLinkW, &ShellLink));
    ok_hex(hr, S_OK);
    if (FAILED(hr))
        return;
    ShellLink->SetPath(Target);
    if (Arguments)
        ShellLink->SetArguments(Arguments);
    if (WorkingDirectory)
        ShellLink->SetWorkingDirectory(WorkingDirectory);
    ShellLink->SetShowCmd(ShowCmd);
    hr = ShellLink->QueryInterface(IID_PPV_ARG(IPersistFile, &PersistFile));
    ok_hex(hr, S_OK);
    if (SUCCEEDED(hr))
    {
        hr = PersistFile->Save(LinkPath, TRUE);
        ok_hex(hr, S_OK);
    }
}

/* Wait for the started program to leave its line in the marker file */
static BOOL
ReadMarker(_Out_ PWSTR Line, _In_ UINT cchLine, _In_ UINT TimeoutMs)
{
    Line[0] = UNICODE_NULL;
    for (UINT Waited = 0; Waited <= TimeoutMs; Waited += 100)
    {
        HANDLE hFile = CreateFileW(s_Marker, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD cbRead = 0;
            BOOL bRead = ReadFile(hFile, Line, (cchLine - 1) * sizeof(WCHAR), &cbRead, NULL);
            CloseHandle(hFile);
            Line[bRead ? cbRead / sizeof(WCHAR) : 0] = UNICODE_NULL;
            PWSTR pchEnd = wcschr(Line, L'\n');
            if (pchEnd)
            {
                *pchEnd = UNICODE_NULL;
                return TRUE;
            }
        }
        Sleep(100);
    }
    return FALSE;
}

/* Run the link with ShellExecuteEx, returning what the started program recorded */
static BOOL
RunWithShellExecute(_In_ PCWSTR LinkPath, _In_opt_ PCWSTR Verb, _Out_ PWSTR Line, _In_ UINT cchLine)
{
    SHELLEXECUTEINFOW sei = { sizeof(sei) };

    DeleteFileW(s_Marker);
    sei.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = Verb;
    sei.lpFile = LinkPath;
    sei.nShow = SW_SHOWNORMAL;
    BOOL bResult = ShellExecuteExW(&sei);
    ok(bResult, "ShellExecuteEx(%ls) failed with %lu\n", LinkPath, GetLastError());
    if (!bResult)
    {
        Line[0] = UNICODE_NULL;
        return FALSE;
    }
    ok(sei.hProcess != NULL, "ShellExecuteEx(%ls) returned no process handle\n", LinkPath);
    if (sei.hProcess)
    {
        WaitForSingleObject(sei.hProcess, 20 * 1000);
        CloseHandle(sei.hProcess);
    }
    return ReadMarker(Line, cchLine, 10 * 1000);
}

static void
CheckLine(
    _In_ PCSTR Case,
    _In_ PCWSTR Line,
    _In_ PCWSTR ExpectedDir,
    _In_ INT ExpectedShow,
    _In_ PCWSTR ExpectedArgs)
{
    WCHAR Expected[4 * MAX_PATH];

    StringCchPrintfW(Expected, _countof(Expected), L"%s|%d|%s", ExpectedDir, ExpectedShow, ExpectedArgs);
    /* the directory compares without case, the rest exactly: compare the directory part first */
    PCWSTR pchBar = wcschr(Line, L'|');
    PCWSTR pchExpectedBar = wcschr(Expected, L'|');
    ok(pchBar && pchExpectedBar, "%s: no record (\"%ls\")\n", Case, Line);
    if (!pchBar || !pchExpectedBar)
        return;
    ok((pchBar - Line) == (pchExpectedBar - Expected) &&
       !_wcsnicmp(Line, Expected, pchBar - Line), "%s: directory is \"%.*ls\", expected \"%ls\"\n",
       Case, (int)(pchBar - Line), Line, ExpectedDir);
    if (ExpectedShow == SHOW_ANY)
    {
        /* skip "|<show command>" on both sides */
        pchBar = wcschr(pchBar + 1, L'|');
        pchExpectedBar = wcschr(pchExpectedBar + 1, L'|');
        ok(pchBar != NULL, "%s: no arguments in the record (\"%ls\")\n", Case, Line);
        if (!pchBar)
            return;
    }
    ok(!wcsncmp(pchBar, pchExpectedBar, wcslen(pchExpectedBar)), "%s: got \"%ls\", expected \"%ls...\"\n",
       Case, pchBar, pchExpectedBar);
}

static void
TestPlain(void)
{
    WCHAR LinkPath[MAX_PATH], Line[4 * MAX_PATH];
    static const PCWSTR Verbs[] = { NULL, L"open" };

    StringCchPrintfW(LinkPath, _countof(LinkPath), L"%s\\plain.lnk", s_Root);
    MakeLink(LinkPath, s_SubCopy, L"alpha \"beta gamma\" delta", s_WorkDir, SW_SHOWMINNOACTIVE);

    for (UINT i = 0; i < _countof(Verbs); i++)
    {
        RunWithShellExecute(LinkPath, Verbs[i], Line, _countof(Line));
        CheckLine(Verbs[i] ? "plain, verb open" : "plain, no verb", Line, s_WorkDir, SW_SHOWMINNOACTIVE,
                  L"alpha \"beta gamma\" delta|");
    }
}

static void
TestShowCommands(void)
{
    WCHAR LinkPath[MAX_PATH], Line[4 * MAX_PATH];
    static const INT Shows[] = { SW_SHOWNORMAL, SW_SHOWMAXIMIZED, SW_SHOWMINNOACTIVE };

    StringCchPrintfW(LinkPath, _countof(LinkPath), L"%s\\show.lnk", s_Root);
    for (UINT i = 0; i < _countof(Shows); i++)
    {
        MakeLink(LinkPath, s_SubCopy, L"show", s_WorkDir, Shows[i]);
        RunWithShellExecute(LinkPath, NULL, Line, _countof(Line));
        CheckLine("show command", Line, s_WorkDir, Shows[i], L"show|");
    }
}

static void
TestExpandedPaths(void)
{
    WCHAR LinkPath[MAX_PATH], Line[4 * MAX_PATH];
    WCHAR Target[MAX_PATH], WorkDir[MAX_PATH], Args[MAX_PATH], ExpectedArgs[MAX_PATH];

    SetEnvironmentVariableW(LNK_DIR_VARIABLE, s_Root);

    /* the target, the directory and the arguments all hold the variable */
    StringCchPrintfW(LinkPath, _countof(LinkPath), L"%s\\expand.lnk", s_Root);
    StringCchCopyW(Target, _countof(Target), L"%" LNK_DIR_VARIABLE L"%\\shell32_apitest_sub.exe");
    StringCchCopyW(WorkDir, _countof(WorkDir), L"%" LNK_DIR_VARIABLE L"%\\work dir");
    StringCchCopyW(Args, _countof(Args), L"%" LNK_DIR_VARIABLE L"%\\data one");
    StringCchPrintfW(ExpectedArgs, _countof(ExpectedArgs), L"%s\\data one|", s_Root);
    MakeLink(LinkPath, Target, Args, WorkDir, SW_SHOWNORMAL);

    CComPtr<IShellLinkW> ShellLink;
    CComPtr<IPersistFile> PersistFile;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARG(IShellLinkW, &ShellLink))) &&
        SUCCEEDED(ShellLink->QueryInterface(IID_PPV_ARG(IPersistFile, &PersistFile))) &&
        SUCCEEDED(PersistFile->Load(LinkPath, STGM_READ)))
    {
        WCHAR Buffer[MAX_PATH] = L"";
        ok_hex(ShellLink->GetPath(Buffer, _countof(Buffer), NULL, SLGP_RAWPATH), S_OK);
        ok_wstr(Buffer, Target);
        ok_hex(ShellLink->GetArguments(Buffer, _countof(Buffer)), S_OK);
        ok_wstr(Buffer, Args);
    }

    RunWithShellExecute(LinkPath, NULL, Line, _countof(Line));
    CheckLine("expanded target, directory and arguments", Line, s_WorkDir, SW_SHOWNORMAL, ExpectedArgs);

    /* a plain target: the arguments and the directory are expanded as well */
    MakeLink(LinkPath, s_SubCopy, Args, WorkDir, SW_SHOWNORMAL);
    RunWithShellExecute(LinkPath, L"open", Line, _countof(Line));
    CheckLine("plain target, expanded directory and arguments", Line, s_WorkDir, SW_SHOWNORMAL, ExpectedArgs);

    SetEnvironmentVariableW(LNK_DIR_VARIABLE, NULL);
}

static void
TestInvalidDirectory(void)
{
    WCHAR LinkPath[MAX_PATH], Line[4 * MAX_PATH], OldDir[MAX_PATH], Elsewhere[MAX_PATH];

    /* An invalid working directory in the link: the started program stays in the invoker's directory */
    StringCchPrintfW(LinkPath, _countof(LinkPath), L"%s\\baddir.lnk", s_Root);
    MakeLink(LinkPath, s_SubCopy, L"baddir", L"M:\\Shell32 Lnk Test\\No Such Dir", SW_SHOWNORMAL);
    GetCurrentDirectoryW(_countof(OldDir), OldDir);
    StringCchPrintfW(Elsewhere, _countof(Elsewhere), L"%s\\work dir", s_Root);
    SetCurrentDirectoryW(Elsewhere);
    RunWithShellExecute(LinkPath, NULL, Line, _countof(Line));
    SetCurrentDirectoryW(OldDir);
    CheckLine("invalid link directory", Line, Elsewhere, SW_SHOWNORMAL, L"baddir|");
}

/* The same links started by the programs a user starts them with */
static void
TestOtherLaunchers(void)
{
    WCHAR LinkPath[MAX_PATH], CommandLine[2 * MAX_PATH], Line[4 * MAX_PATH], CmdPath[MAX_PATH];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    StringCchPrintfW(LinkPath, _countof(LinkPath), L"%s\\launch.lnk", s_Root);
    MakeLink(LinkPath, s_SubCopy, L"one \"two three\"", s_WorkDir, SW_SHOWNORMAL);

    /* cmd /c start <link> */
    GetEnvironmentVariableW(L"ComSpec", CmdPath, _countof(CmdPath));
    StringCchPrintfW(CommandLine, _countof(CommandLine), L"\"%s\" /c start \"\" \"%s\"", CmdPath, LinkPath);
    DeleteFileW(s_Marker);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 20 * 1000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    ReadMarker(Line, _countof(Line), 10 * 1000);
    CheckLine("cmd /c start", Line, s_WorkDir, SW_SHOWNORMAL, L"one \"two three\"|");

    /* explorer.exe <link>: it needs the shell of the session to be there to hand the work to */
    if (!GetShellWindow())
    {
        skip("No shell window, not testing explorer.exe\n");
        return;
    }
    /* Windows hands the link to the running shell, which starts it without this process's environment:
       the marker file is named in the link arguments. The explorer.exe the caller started exits with 1
       and the shell starts the target with SW_SHOWDEFAULT (10), whatever the link's own show command is
       (ShellExecuteEx with SW_SHOWNORMAL gives the link's) */
    WCHAR Arguments[2 * MAX_PATH];
    StringCchPrintfW(Arguments, _countof(Arguments), LNK_MARKER_ARGUMENT L"%s\" one \"two three\"", s_Marker);
    WCHAR ExplorerPath[MAX_PATH];
    GetWindowsDirectoryW(ExplorerPath, _countof(ExplorerPath));
    StringCchPrintfW(CommandLine, _countof(CommandLine), L"\"%s\\explorer.exe\" \"%s\"", ExplorerPath, LinkPath);
    static const INT LinkShows[] = { SW_SHOWNORMAL, SW_SHOWMAXIMIZED, SW_SHOWMINNOACTIVE };
    for (UINT i = 0; i < _countof(LinkShows); i++)
    {
        MakeLink(LinkPath, s_SubCopy, Arguments, s_WorkDir, LinkShows[i]);
        DeleteFileW(s_Marker);
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            DWORD dwExitCode = 0xdead;
            ok(WaitForSingleObject(pi.hProcess, 20 * 1000) == WAIT_OBJECT_0, "explorer.exe <link> did not exit\n");
            GetExitCodeProcess(pi.hProcess, &dwExitCode);
            ok_dec(dwExitCode, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        else
        {
            ok(0, "CreateProcess(explorer.exe) failed with %lu\n", GetLastError());
        }
        ReadMarker(Line, _countof(Line), 20 * 1000);
        CheckLine("explorer.exe <link>", Line, s_WorkDir, SW_SHOWDEFAULT, L"one \"two three\"|");
    }
}

START_TEST(ShellExecuteExLnk)
{
    WCHAR SubProgram[MAX_PATH], TempPath[MAX_PATH];
    CCoInit ComInit;

    if (!FindSubProgram(SubProgram, _countof(SubProgram)))
    {
        skip("shell32_apitest_sub.exe not found\n");
        return;
    }
    DWORD cchTemp = GetTempPathW(_countof(TempPath), TempPath);
    if (!cchTemp || cchTemp >= _countof(TempPath))
    {
        skip("Cannot get the temporary path\n");
        return;
    }
    StringCchPrintfW(s_Root, _countof(s_Root), L"%sSjLnkExec%lu", TempPath, GetCurrentProcessId());
    StringCchPrintfW(s_WorkDir, _countof(s_WorkDir), L"%s\\work dir", s_Root);
    StringCchPrintfW(s_SubCopy, _countof(s_SubCopy), L"%s\\shell32_apitest_sub.exe", s_Root);
    StringCchPrintfW(s_Marker, _countof(s_Marker), L"%s\\marker.txt", s_Root);
    CreateDirectoryW(s_Root, NULL);
    CreateDirectoryW(s_WorkDir, NULL);
    if (!CopyFileW(SubProgram, s_SubCopy, FALSE))
    {
        skip("Cannot copy the sub program\n");
        RemoveDirectoryW(s_WorkDir);
        RemoveDirectoryW(s_Root);
        return;
    }
    SetEnvironmentVariableW(LNK_MARKER_VARIABLE, s_Marker);

    TestPlain();
    TestShowCommands();
    TestExpandedPaths();
    TestInvalidDirectory();
    TestOtherLaunchers();

    SetEnvironmentVariableW(LNK_MARKER_VARIABLE, NULL);
    static const PCWSTR Files[] = { L"plain.lnk", L"show.lnk", L"expand.lnk", L"baddir.lnk", L"launch.lnk",
                                    L"marker.txt", L"shell32_apitest_sub.exe" };
    WCHAR Path[MAX_PATH];
    for (UINT i = 0; i < _countof(Files); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%s\\%s", s_Root, Files[i]);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(s_WorkDir);
    RemoveDirectoryW(s_Root);
}
