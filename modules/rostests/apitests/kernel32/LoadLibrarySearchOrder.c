/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Which directories LoadLibraryEx searches for a library and for its dependency, per flag
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022. ll_search_lib.dll imports ll_search_dep.dll; copies of the dependency lie in
 * the application directory, next to the library that is loaded, in the current directory and in a directory added
 * with AddDllDirectory. The copy that the load used says where the search looked (and in what order). The system
 * directory is not written to: a dependency that exists only there is not part of the test.
 */

#include "precomp.h"

#define LOAD_WITH_ALTERED_SEARCH_PATH_ 0x8
#define SEARCH_DLL_LOAD_DIR     0x100
#define SEARCH_APPLICATION_DIR  0x200
#define SEARCH_USER_DIRS        0x400
#define SEARCH_SYSTEM32         0x800
#define SEARCH_DEFAULT_DIRS     0x1000
#define SAFE_CURRENT_DIRS       0x2000
#define SEARCH_SYSTEM32_NO_FWD  0x4000
#define OS_INTEGRITY_CONTINUITY 0x8000

enum { DEP_NONE, DEP_APP, DEP_DIR, DEP_CWD, DEP_USER };

typedef PVOID (WINAPI *FN_AddDllDirectory)(PCWSTR);

static WCHAR AppDir[MAX_PATH], TestRoot[MAX_PATH], LibDir[MAX_PATH], CwdDir[MAX_PATH], UserDir[MAX_PATH];
static WCHAR LibPath[MAX_PATH];

static BOOL InDir(PCWSTR Path, PCWSTR Dir)
{
    SIZE_T Len = wcslen(Dir);

    return _wcsnicmp(Path, Dir, Len) == 0 && Path[Len] == L'\\' && wcschr(Path + Len + 1, L'\\') == NULL;
}

static BOOL Copy(PCWSTR Name, PCWSTR To, PCWSTR NewName)
{
    WCHAR Src[MAX_PATH], Dst[MAX_PATH];

    _snwprintf(Src, MAX_PATH, L"%ls\\%ls", AppDir, Name);
    _snwprintf(Dst, MAX_PATH, L"%ls\\%ls", To, NewName ? NewName : Name);
    return CopyFileW(Src, Dst, FALSE);
}

static void MakeDir(PCWSTR Parent, PCWSTR Name, PWCHAR Out)
{
    _snwprintf(Out, MAX_PATH, L"%ls\\%ls", Parent, Name);
    CreateDirectoryW(Out, NULL);
}

/* Loads the library by Name with Flags; DEP_* is the copy of the dependency it used, DEP_NONE with *Error on failure */
static int Load(PCWSTR Name, DWORD Flags, DWORD *Error)
{
    HMODULE Lib, Dep;
    WCHAR Path[MAX_PATH];
    int Result = -1;

    SetLastError(0xdeadbeef);
    Lib = LoadLibraryExW(Name, NULL, Flags);
    *Error = GetLastError();
    if (!Lib)
        return DEP_NONE;

    Dep = GetModuleHandleW(L"ll_search_dep.dll");
    if (Dep && GetModuleFileNameW(Dep, Path, _countof(Path)))
    {
        if (InDir(Path, AppDir))
            Result = DEP_APP;
        else if (InDir(Path, LibDir))
            Result = DEP_DIR;
        else if (InDir(Path, CwdDir))
            Result = DEP_CWD;
        else if (InDir(Path, UserDir))
            Result = DEP_USER;
    }
    FreeLibrary(Lib);
    return Result;
}

#define EXPECT_LOAD(Name, Flags, Dep, Err) \
    do { \
        DWORD Error_; \
        int Got_ = Load(Name, Flags, &Error_); \
        ok(Got_ == (Dep), "%ls flags 0x%lx: dependency from %d, expected %d (error %lu)\n", Name, (DWORD)(Flags), Got_, (int)(Dep), Error_); \
        if ((Dep) == DEP_NONE && Got_ == DEP_NONE) \
            ok(Error_ == (Err), "%ls flags 0x%lx: error %lu, expected %lu\n", Name, (DWORD)(Flags), Error_, (DWORD)(Err)); \
    } while (0)

START_TEST(LoadLibrarySearchOrder)
{
    FN_AddDllDirectory pAddDllDirectory =
        (FN_AddDllDirectory)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "AddDllDirectory");
    WCHAR Cwd[MAX_PATH], Temp[MAX_PATH];
    PWCHAR Slash;
    PVOID Cookie;
    BOOL Ready;

    if (!pAddDllDirectory)
    {
        skip("AddDllDirectory is missing\n");
        return;
    }

    GetModuleFileNameW(NULL, AppDir, _countof(AppDir));
    Slash = wcsrchr(AppDir, L'\\');
    *Slash = 0;
    GetTempPathW(_countof(Temp), Temp);
    _snwprintf(TestRoot, MAX_PATH, L"%lsllsearch%lu", Temp, GetCurrentProcessId());
    CreateDirectoryW(TestRoot, NULL);
    MakeDir(TestRoot, L"dir", LibDir);
    MakeDir(TestRoot, L"cwd", CwdDir);
    MakeDir(TestRoot, L"user", UserDir);

    /* the library in its own directory, and a copy of it with another name in the current directory */
    Ready = Copy(L"ll_search_lib.dll", LibDir, NULL) &&
            Copy(L"ll_search_dep.dll", LibDir, NULL) &&
            Copy(L"ll_search_dep.dll", CwdDir, NULL) &&
            Copy(L"ll_search_dep.dll", UserDir, NULL) &&
            Copy(L"ll_search_lib.dll", CwdDir, L"ll_search_cwdlib.dll");
    if (!Ready)
    {
        skip("cannot prepare the directories: %lu\n", GetLastError());
        goto cleanup;
    }
    _snwprintf(LibPath, MAX_PATH, L"%ls\\ll_search_lib.dll", LibDir);

    GetCurrentDirectoryW(_countof(Cwd), Cwd);
    SetCurrentDirectoryW(CwdDir);

    /* a full path: the dependency is looked for by the rules of the flags */
    EXPECT_LOAD(LibPath, 0, DEP_APP, 0);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_, DEP_DIR, 0);
    EXPECT_LOAD(LibPath, SEARCH_DLL_LOAD_DIR, DEP_DIR, 0);
    EXPECT_LOAD(LibPath, SEARCH_APPLICATION_DIR, DEP_APP, 0);
    EXPECT_LOAD(LibPath, SEARCH_DEFAULT_DIRS, DEP_APP, 0);
    EXPECT_LOAD(LibPath, SAFE_CURRENT_DIRS, DEP_APP, 0);
    EXPECT_LOAD(LibPath, OS_INTEGRITY_CONTINUITY, DEP_APP, 0);
    EXPECT_LOAD(LibPath, SEARCH_DLL_LOAD_DIR | SEARCH_APPLICATION_DIR, DEP_DIR, 0);
    EXPECT_LOAD(LibPath, SEARCH_DLL_LOAD_DIR | SEARCH_SYSTEM32, DEP_DIR, 0);
    EXPECT_LOAD(LibPath, SEARCH_DLL_LOAD_DIR | SEARCH_DEFAULT_DIRS, DEP_DIR, 0);
    EXPECT_LOAD(LibPath, SEARCH_APPLICATION_DIR | SEARCH_SYSTEM32, DEP_APP, 0);
    EXPECT_LOAD(LibPath, SEARCH_DEFAULT_DIRS | SEARCH_SYSTEM32, DEP_APP, 0);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SAFE_CURRENT_DIRS, DEP_DIR, 0);

    /* a search that has no directory that holds the dependency: it is not found, the current directory is not tried */
    EXPECT_LOAD(LibPath, SEARCH_USER_DIRS, DEP_NONE, ERROR_MOD_NOT_FOUND);
    EXPECT_LOAD(LibPath, SEARCH_SYSTEM32, DEP_NONE, ERROR_MOD_NOT_FOUND);
    EXPECT_LOAD(LibPath, SEARCH_SYSTEM32_NO_FWD, DEP_NONE, ERROR_MOD_NOT_FOUND);
    EXPECT_LOAD(LibPath, SEARCH_USER_DIRS | SEARCH_SYSTEM32, DEP_NONE, ERROR_MOD_NOT_FOUND);

    /* the altered search path cannot be combined with any search flag, and there are no flags above bit 15 */
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_DLL_LOAD_DIR, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_APPLICATION_DIR, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_USER_DIRS, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_SYSTEM32, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_DEFAULT_DIRS, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_SYSTEM32_NO_FWD, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_DLL_LOAD_DIR | SEARCH_SYSTEM32, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, 0x10000, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, 0x100000, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, 0x80000000, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(LibPath, SEARCH_APPLICATION_DIR | 0x20000, DEP_NONE, ERROR_INVALID_PARAMETER);

    /* a directory added with AddDllDirectory is part of the user directories only */
    Cookie = pAddDllDirectory(UserDir);
    ok(Cookie != NULL, "AddDllDirectory failed: %lu\n", GetLastError());
    if (Cookie)
    {
        EXPECT_LOAD(LibPath, SEARCH_USER_DIRS, DEP_USER, 0);
        EXPECT_LOAD(LibPath, SEARCH_USER_DIRS | SEARCH_SYSTEM32, DEP_USER, 0);
        EXPECT_LOAD(LibPath, SEARCH_APPLICATION_DIR | SEARCH_USER_DIRS, DEP_APP, 0);
        EXPECT_LOAD(LibPath, SEARCH_DLL_LOAD_DIR | SEARCH_USER_DIRS, DEP_DIR, 0);
        EXPECT_LOAD(LibPath, 0, DEP_APP, 0);
        EXPECT_LOAD(LibPath, SAFE_CURRENT_DIRS, DEP_APP, 0);
        EXPECT_LOAD(LibPath, SEARCH_SYSTEM32, DEP_NONE, ERROR_MOD_NOT_FOUND);
        EXPECT_LOAD(LibPath, LOAD_WITH_ALTERED_SEARCH_PATH_ | SEARCH_USER_DIRS, DEP_NONE, ERROR_INVALID_PARAMETER);
        RemoveDllDirectory(Cookie);
    }

    /* a name that is not a path: found in the current directory (after the application and the system directories) */
    EXPECT_LOAD(L"ll_search_cwdlib.dll", 0, DEP_APP, 0);
    EXPECT_LOAD(L"ll_search_cwdlib.dll", LOAD_WITH_ALTERED_SEARCH_PATH_, DEP_APP, 0);
    EXPECT_LOAD(L"ll_search_cwdlib.dll", OS_INTEGRITY_CONTINUITY, DEP_APP, 0);
    /* the library of a name is not in the directories of the search flags */
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SEARCH_APPLICATION_DIR, DEP_NONE, ERROR_MOD_NOT_FOUND);
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SEARCH_DEFAULT_DIRS, DEP_NONE, ERROR_MOD_NOT_FOUND);
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SEARCH_SYSTEM32_NO_FWD, DEP_NONE, ERROR_MOD_NOT_FOUND);
    /* the directory of the library is not known for a name */
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SEARCH_DLL_LOAD_DIR, DEP_NONE, ERROR_INVALID_PARAMETER);
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SEARCH_DLL_LOAD_DIR | SEARCH_DEFAULT_DIRS, DEP_NONE, ERROR_INVALID_PARAMETER);
    /* the current directory is not searched when it must be a safe one: it is not on the safe load list */
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SAFE_CURRENT_DIRS, DEP_NONE, ERROR_MOD_NOT_FOUND);
    EXPECT_LOAD(L"ll_search_cwdlib.dll", SAFE_CURRENT_DIRS | LOAD_WITH_ALTERED_SEARCH_PATH_, DEP_NONE, ERROR_MOD_NOT_FOUND);

    SetCurrentDirectoryW(Cwd);

cleanup:
    {
        WCHAR Name[MAX_PATH];
        PCWSTR Dirs[] = { LibDir, CwdDir, UserDir };
        PCWSTR Files[] = { L"ll_search_lib.dll", L"ll_search_dep.dll", L"ll_search_cwdlib.dll" };
        SIZE_T i, j;

        for (i = 0; i < _countof(Dirs); i++)
        {
            for (j = 0; j < _countof(Files); j++)
            {
                _snwprintf(Name, MAX_PATH, L"%ls\\%ls", Dirs[i], Files[j]);
                DeleteFileW(Name);
            }
            RemoveDirectoryW(Dirs[i]);
        }
        RemoveDirectoryW(TestRoot);
    }
}
