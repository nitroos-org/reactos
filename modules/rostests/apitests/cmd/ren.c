/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for the cmd.exe ren command: full and relative source paths, a destination that must be a
 *              bare name, wildcards in the source and in the destination mask
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected results were measured with the ren of Windows 10 22H2 (build 19045). ren cut the source path
 * with an unterminated strncpy, so "ren C:\dir\name new" failed with error 123 whenever the stack held
 * garbage behind the path (i386 Debug).
 */

#include "precomp.h"
#include <strsafe.h>

static WCHAR s_ComSpec[MAX_PATH];
static WCHAR s_Dir[MAX_PATH]; /* the directory of the current case, without a trailing backslash */

/* Runs "cmd.exe /d /c <pszCmd>" hidden in pszCwd and returns its exit code */
static DWORD
RunCmd(PCWSTR pszCmd, PCWSTR pszCwd)
{
    WCHAR szCmd[2048];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD dwExit = (DWORD)-1;

    StringCchPrintfW(szCmd, _countof(szCmd), L"\"%s\" /d /c %s", s_ComSpec, pszCmd);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, pszCwd, &si, &pi))
    {
        ok(0, "CreateProcess failed, error %lu\n", GetLastError());
        return dwExit;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    GetExitCodeProcess(pi.hProcess, &dwExit);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return dwExit;
}

/* Replaces @D@ by the case directory and @N@ by the same without the drive */
static void
Expand(PWSTR pszOut, SIZE_T cchOut, PCWSTR pszIn)
{
    SIZE_T cch = 0;

    while (*pszIn && cch + 1 < cchOut)
    {
        PCWSTR pszRepl = NULL;

        if (pszIn[0] == L'@' && pszIn[1] == L'D' && pszIn[2] == L'@')
            pszRepl = s_Dir;
        else if (pszIn[0] == L'@' && pszIn[1] == L'N' && pszIn[2] == L'@')
            pszRepl = s_Dir + 2;
        if (pszRepl)
        {
            while (*pszRepl && cch + 1 < cchOut)
                pszOut[cch++] = *pszRepl++;
            pszIn += 3;
        }
        else
        {
            pszOut[cch++] = *pszIn++;
        }
    }
    pszOut[cch] = 0;
}

static void
MakeFile(PCWSTR pszRel)
{
    WCHAR szPath[MAX_PATH];
    HANDLE hFile;

    StringCchPrintfW(szPath, _countof(szPath), L"%s\\%s", s_Dir, pszRel);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "cannot create %ls, error %lu\n", szPath, GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
}

static void
MakeDir(PCWSTR pszRel)
{
    WCHAR szPath[MAX_PATH];

    StringCchPrintfW(szPath, _countof(szPath), L"%s\\%s", s_Dir, pszRel);
    ok(CreateDirectoryW(szPath, NULL), "cannot create %ls, error %lu\n", szPath, GetLastError());
}

static BOOL
Exists(PCWSTR pszRel)
{
    WCHAR szPath[MAX_PATH];

    StringCchPrintfW(szPath, _countof(szPath), L"%s\\%s", s_Dir, pszRel);
    return GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES;
}

/* Number of entries below pszDir, recursively; the first name found (not "." and "..") goes to pszFirst */
static UINT
CountTree(PCWSTR pszDir, PWSTR pszFirst)
{
    WCHAR szPattern[MAX_PATH], szSub[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    UINT cEntries = 0;

    StringCchPrintfW(szPattern, _countof(szPattern), L"%s\\*", pszDir);
    hFind = FindFirstFileW(szPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;
    do
    {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
            continue;
        if (pszFirst && !cEntries)
            StringCchCopyW(pszFirst, MAX_PATH, fd.cFileName);
        cEntries++;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            StringCchPrintfW(szSub, _countof(szSub), L"%s\\%s", pszDir, fd.cFileName);
            cEntries += CountTree(szSub, NULL);
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return cEntries;
}

static void
DeleteTree(PCWSTR pszDir)
{
    WCHAR szPattern[MAX_PATH], szSub[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;

    StringCchPrintfW(szPattern, _countof(szPattern), L"%s\\*", pszDir);
    hFind = FindFirstFileW(szPattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
                continue;
            StringCchPrintfW(szSub, _countof(szSub), L"%s\\%s", pszDir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                DeleteTree(szSub);
            else
                DeleteFileW(szSub);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryW(pszDir);
}

/* Number of '|' separated names in psz, and whether each of them exists (bExist) or not */
static UINT
CheckNames(PCWSTR psz, BOOL bExist, UINT iCase, PCWSTR pszCmd)
{
    WCHAR szName[MAX_PATH];
    UINT cNames = 0;

    while (psz && *psz)
    {
        SIZE_T cch = wcscspn(psz, L"|");

        StringCchCopyNW(szName, _countof(szName), psz, cch);
        ok(Exists(szName) == bExist, "case %u (%ls): %ls %s\n",
           iCase, pszCmd, szName, bExist ? "is missing" : "still exists");
        cNames++;
        psz += cch;
        if (*psz == L'|')
            psz++;
    }
    return cNames;
}

typedef struct
{
    PCWSTR pszCmd;  /* with @D@ and @N@, see Expand() */
    PCWSTR pszCwd;  /* working directory relative to the case directory, or NULL for the case directory */
    DWORD dwExit;
    PCWSTR pszGone; /* names that must be gone afterwards */
    PCWSTR pszNew;  /* names that must exist afterwards */
} REN_CASE;

#define ALL_TXT L"a b.txt|a.b.txt|a1.txt|abc.txt|abcdef.txt|b2.txt"
#define ALL_BAK L"a b.bak|a.b.bak|a1.bak|abc.bak|abcdef.bak|b2.bak"

static const REN_CASE s_Cases[] =
{
    /* relative source and bare name: always worked */
    { L"ren a1.txt z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren sub\\a.txt z.txt", NULL, 0, L"sub\\a.txt", L"sub\\z.txt" },
    { L"ren .\\a1.txt z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren ..\\a1.txt z1.txt", L"sub", 0, L"a1.txt", L"z1.txt" },
    { L"ren \"sp dir\\a b.txt\" \"c d.txt\"", NULL, 0, L"sp dir\\a b.txt", L"sp dir\\c d.txt" },
    { L"ren \"a b.txt\" \"c d.txt\"", NULL, 0, L"a b.txt", L"c d.txt" },
    { L"ren d1 d2", NULL, 0, L"d1", L"d2" },
    { L"ren d1\\ d2", NULL, 0, L"d1", L"d2" },
    /* a full source path */
    { L"ren \"@D@\\a1.txt\" z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren \"@D@\\d1\" d2", NULL, 0, L"d1", L"d2" },
    { L"ren \"@D@\\d1\\\" d2", NULL, 0, L"d1", L"d2" },
    { L"ren \"@D@\\sp dir\\a b.txt\" \"c d.txt\"", NULL, 0, L"sp dir\\a b.txt", L"sp dir\\c d.txt" },
    { L"ren \"@N@\\a1.txt\" z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren \"\\\\?\\@D@\\a1.txt\" z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren \"@D@\\\\a1.txt\" z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren \"@D@\\sub\\..\\a1.txt\" z1.txt", NULL, 0, L"a1.txt", L"z1.txt" },
    { L"ren \"@D@\\a1.txt\" z1.txt", L"sub", 0, L"a1.txt", L"z1.txt" },
    /* the destination must be a bare name, even when it is the directory of the source */
    { L"ren \"@D@\\a1.txt\" \"@D@\\z1.txt\"", NULL, 1, NULL, NULL },
    { L"ren a1.txt \"@D@\\z1.txt\"", NULL, 1, NULL, NULL },
    { L"ren \"@D@\\a1.txt\" sub\\z1.txt", NULL, 1, NULL, NULL },
    { L"ren sub\\a.txt sub\\z.txt", NULL, 1, NULL, NULL },
    { L"ren sub\\a.txt ..\\z.txt", NULL, 1, NULL, NULL },
    { L"ren a1.txt \"sp dir\\z.txt\"", NULL, 1, NULL, NULL },
    { L"ren \"@D@\\sp dir\\a b.txt\" \"@D@\\sp dir\\c d.txt\"", NULL, 1, NULL, NULL },
    { L"ren \"@D@\\a1.txt\" C:z.txt", NULL, 1, NULL, NULL },
    { L"ren \"@D@\\*.txt\" \"@D@\\*.bak\"", NULL, 1, NULL, NULL },
    /* errors */
    { L"ren a1.txt", NULL, 1, NULL, NULL },
    { L"ren nonexist.txt z.txt", NULL, 1, NULL, NULL },
    { L"ren \"@D@\\nonexist.txt\" z.txt", NULL, 1, NULL, NULL },
    { L"ren a1.txt b2.txt", NULL, 1, NULL, NULL },
    { L"ren \"@D@\\a1.txt\" b2.txt", NULL, 1, NULL, NULL },
    /* wildcards in the source */
    { L"ren *.txt *.bak", NULL, 0, ALL_TXT, ALL_BAK },
    { L"ren \"@D@\\*.txt\" *.bak", NULL, 0, ALL_TXT, ALL_BAK },
    { L"ren a?c.txt x?y.txt", NULL, 0, L"abc.txt", L"xby.txt" },
    { L"ren \"sp dir\\*.txt\" *.bak", NULL, 0, L"sp dir\\a b.txt|sp dir\\q.txt", L"sp dir\\a b.bak|sp dir\\q.bak" },
    { L"ren \"@D@\\sp dir\\*.txt\" *.bak", NULL, 0, L"sp dir\\a b.txt|sp dir\\q.txt", L"sp dir\\a b.bak|sp dir\\q.bak" },
    { L"ren sub\\*.txt *.bak", NULL, 0, L"sub\\a.txt", L"sub\\a.bak" },
    /* wildcards in the destination */
    { L"ren *.txt x*.bak", NULL, 0, ALL_TXT, L"x b.bak|x.b.bak|x1.bak|x2.bak|xbc.bak|xbcdef.bak" },
    { L"ren \"a b.txt\" *.bak", NULL, 0, L"a b.txt", L"a b.bak" },
    { L"ren a1.txt ????.bak", NULL, 0, L"a1.txt", L"a1.bak" },
    { L"ren abcdef.txt a?.dat", NULL, 0, L"abcdef.txt", L"ab.dat" },
    { L"ren f.dat *.*.old", NULL, 0, L"f.dat", L"f.dat.old" },
    { L"ren abc.txt abcdefghij.bak", NULL, 0, L"abc.txt", L"abcdefghij.bak" },
    { L"ren abc.txt .bak", NULL, 0, L"abc.txt", L".bak" },
};

/* One source name and one destination mask in a directory of their own, the resulting name is compared whole */
typedef struct
{
    PCWSTR pszSrc;
    PCWSTR pszMask;
    PCWSTR pszResult;
    DWORD dwExit;
} MASK_CASE;

static const MASK_CASE s_Masks[] =
{
    { L"abc.txt", L"*.bak", L"abc.bak", 0 },
    { L"abc.txt", L"x*", L"xbc.txt", 0 },
    { L"abc.txt", L"??x.*", L"abx.txt", 0 },
    { L"a.b.txt", L"*.bak", L"a.b.bak", 0 },
    { L"abc.txt", L"?z.*", L"az.txt", 0 },
    { L"a.b.txt", L"?z.*", L"az.b.txt", 0 },
    { L"a1.txt", L"?z.*", L"az.txt", 0 },
    { L"abcdef.txt", L"?z.*", L"az.txt", 0 },
    { L"abc.txt", L"?z", L"az", 0 },
    { L"abc.txt", L"a?", L"ab", 0 },
    { L"abc.txt", L"a?.", L"ab", 0 },
    { L"abc.txt", L"?.?", L"a.t", 0 },
    { L"abc.txt", L"???.bak", L"abc.bak", 0 },
    { L"abc.txt", L"????.bak", L"abc.bak", 0 },
    { L"abc.txt", L"?????.bak", L"abc.bak", 0 },
    { L"a.b.txt", L"?.*", L"a.b.txt", 0 },
    { L"a.b.txt", L"?.?", L"a.b", 0 },
    { L"a.b.txt", L"??.*", L"a.b.txt", 0 },
    { L"a.b.txt", L"???.*", L"a.b.txt", 0 },
    { L"a.b.txt", L"*.*.x", L"a.b.txt.x", 0 },
    { L"a.b.txt", L"*b*", L"a.b.txt", 0 },
    { L"a.b.txt", L"a*b.txt", L"a.b.txt", 0 },
    { L"abc.txt", L"*c", L"abc", 0 },
    { L"abc.txt", L"*c.txt", L"abc.txt", 0 },
    { L"abc.txt", L"*b.txt", L"ab.txt", 0 },
    { L"abc.txt", L"x*.y*", L"xbc.yxt", 0 },
    { L"abc.txt", L"*.t*", L"abc.txt", 0 },
    { L"abc.txt", L"*.t?", L"abc.tx", 0 },
    { L"abc.txt", L"*.?", L"abc.t", 0 },
    { L"abc.txt", L"*.???.z", L"abc.txt.z", 0 },
    { L"abc", L"a?c", L"abc", 0 },
    { L"abc", L"?", L"a", 0 },
    { L"abc.txt", L"?", L"a", 0 },
    { L"abc.txt", L"??", L"ab", 0 },
    { L"abc.txt", L"???", L"abc", 0 },
    { L"abc.txt", L"????", L"abc", 0 },
    { L"abc.txt", L"abc?", L"abc", 0 },
    { L"abc.txt", L"abc*", L"abc.txt", 0 },
    { L"abc.txt", L"abc?.bak", L"abc.bak", 0 },
    { L"abc.txt", L"abc*.bak", L"abc.bak", 0 },
    { L"abc.txt", L"*.txt", L"abc.txt", 0 },
    { L"abc.tar.gz", L"*.zip", L"abc.tar.zip", 0 },
    { L"abc.tar.gz", L"*.*.zip", L"abc.tar.gz.zip", 0 },
    { L"abc.tar.gz", L"x.*", L"x.tar.gz", 0 },
    { L"abc.tar.gz", L"?.*", L"a.tar.gz", 0 },
    { L"abc.tar.gz", L"???.*.*", L"abc.tar.gz", 0 },
    { L"abc", L"?.x", L"a.x", 0 },
    { L"abc", L"??????.x", L"abc.x", 0 },
    { L"abc", L".?", L"abc", 1 },
    { L"abc.txt", L".*", L".txt", 0 },
    { L"abc.txt", L"*.*", L"abc.txt", 0 },
    { L"a.b.c.d", L"*.x", L"a.b.c.x", 0 },
    { L"a.b.c.d", L"*.*.x", L"a.b.c.d.x", 0 },
    { L"a.b.c.d", L"?.*.x", L"a.b.c.x", 0 },
    { L"ab.cd.ef", L"*.*", L"ab.cd.ef", 0 },
    { L"ab.cd.ef", L"x.*.*", L"x.cd.ef", 0 },
    { L"ab.cd.ef", L"??.*.y", L"ab.cd.y", 0 },
    { L".hid", L"*.x", L".x", 0 },
    { L"abc.txt", L"*.t*t", L"abc.txt", 0 },
    { L"abc.txt", L"*.*t", L"abc.txt", 0 },
    { L"abc.txt", L"?b*", L"abc.txt", 0 },
    { L"abc.txt", L"?*", L"abc.txt", 0 },
    { L"abc.txt", L"a*c.bak", L"abc.bak", 0 },
    { L"abc.txt", L"ab*c*", L"abc.txt", 0 },
    { L"abc.txt", L"*.", L"abc", 0 },
    { L"abcdef.txt", L"*f.bak", L"abcdef.bak", 0 },
    { L"abc.txt", L"a.b.c", L"a.b.c", 0 },
};

static void
RunCases(void)
{
    UINT i;

    for (i = 0; i < _countof(s_Cases); i++)
    {
        const REN_CASE *pCase = &s_Cases[i];
        WCHAR szCmd[1024], szCwd[MAX_PATH];
        UINT cGone, cNew;
        DWORD dwExit;

        ok(CreateDirectoryW(s_Dir, NULL), "cannot create %ls, error %lu\n", s_Dir, GetLastError());
        MakeFile(L"a b.txt");
        MakeFile(L"a.b.txt");
        MakeFile(L"a1.txt");
        MakeFile(L"abc.txt");
        MakeFile(L"abcdef.txt");
        MakeFile(L"b2.txt");
        MakeFile(L"f.dat");
        MakeDir(L"d1");
        MakeDir(L"sub");
        MakeFile(L"sub\\a.txt");
        MakeDir(L"sp dir");
        MakeFile(L"sp dir\\a b.txt");
        MakeFile(L"sp dir\\q.txt");

        Expand(szCmd, _countof(szCmd), pCase->pszCmd);
        if (pCase->pszCwd)
            StringCchPrintfW(szCwd, _countof(szCwd), L"%s\\%s", s_Dir, pCase->pszCwd);
        else
            StringCchCopyW(szCwd, _countof(szCwd), s_Dir);

        dwExit = RunCmd(szCmd, szCwd);
        ok(dwExit == pCase->dwExit, "case %u (%ls): exit code %lu, expected %lu\n",
           i, pCase->pszCmd, dwExit, pCase->dwExit);
        cGone = CheckNames(pCase->pszGone, FALSE, i, pCase->pszCmd);
        cNew = CheckNames(pCase->pszNew, TRUE, i, pCase->pszCmd);
        ok(CountTree(s_Dir, NULL) == 13 + cNew - cGone, "case %u (%ls): %u entries, expected %u\n",
           i, pCase->pszCmd, CountTree(s_Dir, NULL), 13 + cNew - cGone);

        DeleteTree(s_Dir);
    }
}

static void
RunMasks(void)
{
    UINT i;

    for (i = 0; i < _countof(s_Masks); i++)
    {
        const MASK_CASE *pCase = &s_Masks[i];
        WCHAR szCmd[1024], szFirst[MAX_PATH] = L"";
        DWORD dwExit;

        ok(CreateDirectoryW(s_Dir, NULL), "cannot create %ls, error %lu\n", s_Dir, GetLastError());
        MakeFile(pCase->pszSrc);

        StringCchPrintfW(szCmd, _countof(szCmd), L"ren \"%s\" %s", pCase->pszSrc, pCase->pszMask);
        dwExit = RunCmd(szCmd, s_Dir);
        ok(dwExit == pCase->dwExit, "mask %u (%ls): exit code %lu, expected %lu\n",
           i, szCmd, dwExit, pCase->dwExit);
        ok(CountTree(s_Dir, szFirst) == 1, "mask %u (%ls): not exactly one file left\n", i, szCmd);
        ok(!wcscmp(szFirst, pCase->pszResult), "mask %u (%ls): got \"%ls\", expected \"%ls\"\n",
           i, szCmd, szFirst, pCase->pszResult);

        DeleteTree(s_Dir);
    }
}

START_TEST(ren)
{
    WCHAR szBase[MAX_PATH];
    DWORD cch;

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
    StringCchPrintfW(s_Dir, _countof(s_Dir), L"%s\\cmdren%lu", szBase, GetCurrentProcessId());
    if (s_Dir[1] != L':')
    {
        skip("temp directory without a drive letter\n");
        return;
    }

    RunCases();
    RunMasks();
}
