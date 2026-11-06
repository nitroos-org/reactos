/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for the cmd.exe dir /r command: the streams of a file named with a path
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * dir /r asked for the streams of a file by the bare name found in the listed directory, so it showed them only
 * when the directory was the current one. Windows 10 22H2 lists them for an absolute path, a relative one, a
 * wildcard and a subdirectory listing alike, as "<size> <name>:<stream>:$DATA" lines.
 */

#include "precomp.h"
#include <strsafe.h>

static WCHAR s_ComSpec[MAX_PATH];

/* Runs "cmd.exe /d /c <command>" in pszCwd and returns its output (ANSI), NUL terminated */
static BOOL RunCmd(PCWSTR pszCwd, PCWSTR pszCommand, char *pszOut, DWORD cbOut)
{
    WCHAR szCmd[2048];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    DWORD cbRead, cbTotal = 0;

    pszOut[0] = 0;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return FALSE;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    StringCchPrintfW(szCmd, _countof(szCmd), L"\"%s\" /d /c %s", s_ComSpec, pszCommand);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    if (!CreateProcessW(NULL, szCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, pszCwd, &si, &pi))
    {
        ok(0, "CreateProcess failed, error %lu\n", GetLastError());
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return FALSE;
    }
    CloseHandle(hWrite);
    while (cbTotal < cbOut - 1 && ReadFile(hRead, pszOut + cbTotal, cbOut - 1 - cbTotal, &cbRead, NULL) && cbRead)
        cbTotal += cbRead;
    pszOut[cbTotal] = 0;
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    return TRUE;
}

static BOOL WriteFileData(PCWSTR pszPath, const char *pszData)
{
    HANDLE hFile = CreateFileW(pszPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD cb;

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(hFile, pszData, (DWORD)strlen(pszData), &cb, NULL);
    CloseHandle(hFile);
    return TRUE;
}

typedef struct _DIRS_ROW
{
    INT Line;
    PCWSTR Cwd;         /* relative to the test directory, or NULL for the test directory itself */
    PCWSTR Command;     /* %D = the test directory */
    BOOL Streams;       /* t.txt:s1 must be listed */
    BOOL SubStreams;    /* sub\v.txt:s3 must be listed */
} DIRS_ROW;

static const DIRS_ROW s_Rows[] =
{
    { __LINE__, NULL,       L"dir /r %D\\t.txt",        TRUE,  FALSE },
    { __LINE__, NULL,       L"dir /r %D\\*.txt",        TRUE,  FALSE },
    { __LINE__, NULL,       L"dir /r %D",               TRUE,  FALSE },
    { __LINE__, NULL,       L"dir /r %D\\t.txt %D\\u.dat", TRUE, FALSE },
    { __LINE__, NULL,       L"dir /r /s %D",            TRUE,  TRUE },
    { __LINE__, NULL,       L"dir /r sub\\v.txt",       FALSE, TRUE },
    { __LINE__, NULL,       L"dir /r t.txt",            TRUE,  FALSE },
    { __LINE__, L"sub",     L"dir /r ..\\t.txt",        TRUE,  FALSE },
    { __LINE__, L"sub",     L"dir /r ..\\*.*",          TRUE,  FALSE },
    { __LINE__, L"sub",     L"dir /r v.txt",            FALSE, TRUE },
};

START_TEST(dirstreams)
{
    WCHAR szBase[MAX_PATH], szDir[MAX_PATH], szSub[MAX_PATH], szPath[MAX_PATH], szCwd[MAX_PATH], szCommand[2048];
    static char s_Out[16384];
    PWCHAR pD;
    DWORD cch;
    ULONG i;

    cch = GetEnvironmentVariableW(L"ComSpec", s_ComSpec, _countof(s_ComSpec));
    if (!cch || cch >= _countof(s_ComSpec))
    {
        skip("no ComSpec\n");
        return;
    }
    cch = GetTempPathW(_countof(szBase), szBase);
    if (!cch || cch >= _countof(szBase) - 40)
    {
        skip("no temp directory\n");
        return;
    }
    if (szBase[cch - 1] == L'\\')
        szBase[cch - 1] = 0;
    StringCchPrintfW(szDir, _countof(szDir), L"%s\\cmddirs%lu", szBase, GetCurrentProcessId());
    StringCchPrintfW(szSub, _countof(szSub), L"%s\\sub", szDir);
    ok(CreateDirectoryW(szDir, NULL), "cannot create %ls, error %lu\n", szDir, GetLastError());
    ok(CreateDirectoryW(szSub, NULL), "cannot create %ls, error %lu\n", szSub, GetLastError());

    StringCchPrintfW(szPath, _countof(szPath), L"%s\\t.txt", szDir);
    ok(WriteFileData(szPath, "hello"), "cannot write %ls\n", szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\t.txt:s1", szDir);
    if (!WriteFileData(szPath, "stream1"))
    {
        skip("no alternate data streams on %ls\n", szDir);
        goto Cleanup;
    }
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\u.dat", szDir);
    ok(WriteFileData(szPath, "x"), "cannot write %ls\n", szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\sub\\v.txt", szDir);
    ok(WriteFileData(szPath, "v"), "cannot write %ls\n", szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\sub\\v.txt:s3", szDir);
    ok(WriteFileData(szPath, "3333"), "cannot write %ls\n", szPath);

    for (i = 0; i < _countof(s_Rows); i++)
    {
        const DIRS_ROW *Row = &s_Rows[i];
        PCWSTR pszIn = Row->Command;
        BOOL Has1, Has3;

        /* the command with %D replaced */
        szCommand[0] = 0;
        while ((pD = wcsstr(pszIn, L"%D")) != NULL)
        {
            StringCchCatNW(szCommand, _countof(szCommand), pszIn, pD - pszIn);
            StringCchCatW(szCommand, _countof(szCommand), szDir);
            pszIn = pD + 2;
        }
        StringCchCatW(szCommand, _countof(szCommand), pszIn);
        if (Row->Cwd)
            StringCchPrintfW(szCwd, _countof(szCwd), L"%s\\%s", szDir, Row->Cwd);
        else
            StringCchCopyW(szCwd, _countof(szCwd), szDir);

        if (!RunCmd(szCwd, szCommand, s_Out, sizeof(s_Out)))
            continue;
        Has1 = strstr(s_Out, " t.txt:s1:$DATA") != NULL;
        Has3 = strstr(s_Out, " v.txt:s3:$DATA") != NULL;
        ok(Has1 == Row->Streams, "line %d: %ls: t.txt:s1 listed %d, expected %d\n%s\n", Row->Line, szCommand, Has1, Row->Streams, s_Out);
        ok(Has3 == Row->SubStreams, "line %d: %ls: v.txt:s3 listed %d, expected %d\n%s\n", Row->Line, szCommand, Has3, Row->SubStreams, s_Out);
    }

Cleanup:
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\sub\\v.txt", szDir);
    DeleteFileW(szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\t.txt", szDir);
    DeleteFileW(szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\u.dat", szDir);
    DeleteFileW(szPath);
    RemoveDirectoryW(szSub);
    RemoveDirectoryW(szDir);
}
