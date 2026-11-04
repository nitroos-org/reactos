/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     MoveFileExW and boot-time renames and deletes of a junction or symbolic link act on the link,
 *              not on what it points to
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * "MoveFileReparse" tests the immediate renames and queues renames and deletes for the next boot
 * (MOVEFILE_DELAY_UNTIL_REBOOT). "MoveFileReparse stage2" is run after that reboot and checks what the
 * session manager did with the queue. Functional tests only: a link is renamed or deleted and the target is
 * checked to be unharmed. A junction needs no privilege; the symbolic link part needs
 * SeCreateSymbolicLinkPrivilege and is skipped without it.
 */

#include "precomp.h"
#include <winuser.h>
#include <winioctl.h>

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003L
#endif
#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef SYMBOLIC_LINK_FLAG_DIRECTORY
#define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif
#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

typedef BOOLEAN (WINAPI *PFN_CSLW)(LPCWSTR, LPCWSTR, DWORD);
static PFN_CSLW pCreateSymbolicLinkW;

/* The stage 1 / stage 2 state lives in a fixed directory */
static WCHAR Base[MAX_PATH];

static void P(WCHAR *Out, PCWSTR Rel)
{
    wsprintfW(Out, L"%s\\%s", Base, Rel);
}

static BOOL Exists(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];

    P(Path, Rel);
    return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL IsLink(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];
    DWORD a;

    P(Path, Rel);
    a = GetFileAttributesW(Path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT);
}

static void MakeFile(PCWSTR Rel, const char *Data)
{
    WCHAR Path[MAX_PATH];
    HANDLE h;
    DWORD n;

    P(Path, Rel);
    h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h != INVALID_HANDLE_VALUE, "creating %ls failed: %lu\n", Path, GetLastError());
    if (h != INVALID_HANDLE_VALUE)
    {
        WriteFile(h, Data, (DWORD)strlen(Data), &n, NULL);
        CloseHandle(h);
    }
}

static BOOL ReadsAs(PCWSTR Rel, const char *Expect)
{
    WCHAR Path[MAX_PATH];
    char Buf[32] = {0};
    DWORD n = 0;
    HANDLE h;

    P(Path, Rel);
    h = CreateFileW(Path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(h, Buf, sizeof(Buf) - 1, &n, NULL);
    CloseHandle(h);
    return n == strlen(Expect) && !memcmp(Buf, Expect, n);
}

typedef struct
{
    DWORD ReparseTag;
    WORD  ReparseDataLength;
    WORD  Reserved;
    WORD  SubstituteNameOffset;
    WORD  SubstituteNameLength;
    WORD  PrintNameOffset;
    WORD  PrintNameLength;
    WCHAR PathBuffer[2 * MAX_PATH];
} JUNC_DATA;

/* A junction to TargetDos (an existing directory) at LinkRel */
static BOOL MakeJunction(PCWSTR LinkRel, PCWSTR TargetDos)
{
    JUNC_DATA Data;
    WCHAR Link[MAX_PATH], Nt[MAX_PATH];
    HANDLE h;
    DWORD Size, Ret, SubLen, PrintLen;
    BOOL Ok;

    P(Link, LinkRel);
    if (!CreateDirectoryW(Link, NULL))
        return FALSE;
    h = CreateFileW(Link, GENERIC_WRITE | DELETE, SHARE_ALL, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        RemoveDirectoryW(Link);
        return FALSE;
    }
    wsprintfW(Nt, L"\\??\\%s", TargetDos);
    SubLen = lstrlenW(Nt) * sizeof(WCHAR);
    PrintLen = lstrlenW(TargetDos) * sizeof(WCHAR);
    Data.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data.Reserved = 0;
    Data.SubstituteNameOffset = 0;
    Data.SubstituteNameLength = (WORD)SubLen;
    Data.PrintNameOffset = (WORD)(SubLen + sizeof(WCHAR));
    Data.PrintNameLength = (WORD)PrintLen;
    memcpy(Data.PathBuffer, Nt, SubLen + sizeof(WCHAR));
    memcpy((BYTE *)Data.PathBuffer + SubLen + sizeof(WCHAR), TargetDos, PrintLen + sizeof(WCHAR));
    Size = FIELD_OFFSET(JUNC_DATA, PathBuffer) + SubLen + PrintLen + 2 * sizeof(WCHAR);
    Data.ReparseDataLength = (WORD)(Size - 8);
    Ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &Data, Size, NULL, 0, &Ret, NULL);
    CloseHandle(h);
    if (!Ok)
        RemoveDirectoryW(Link);
    return Ok;
}

static BOOL HasLinkPrivilege(void)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;
    BOOL Held = FALSE;

    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, L"SeCreateSymbolicLinkPrivilege", &Tp.Privileges[0].Luid))
        return FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
    {
        Held = AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
        CloseHandle(Token);
    }
    return Held;
}

/* The target of a file link or a directory link: the file reads as DATA, the directory still has its file */
static void CheckTargetsIntact(PCWSTR Label)
{
    ok(ReadsAs(L"tfile.txt", "HELLO"), "%ls: the target file is gone or damaged\n", Label);
    ok(Exists(L"tdir\\inner.txt") && ReadsAs(L"tdir\\inner.txt", "INNER"), "%ls: the target directory is gone or damaged\n", Label);
}

static void Test_Now(BOOL Symlinks)
{
    WCHAR From[MAX_PATH], To[MAX_PATH], Dir[MAX_PATH];

    /* A junction is renamed, not its target directory */
    P(Dir, L"tdir");
    ok(MakeJunction(L"junc", Dir), "creating the junction failed: %lu\n", GetLastError());
    P(From, L"junc");
    P(To, L"junc-renamed");
    ok(MoveFileExW(From, To, 0), "MoveFileExW(junction) failed: %lu\n", GetLastError());
    ok(!Exists(L"junc"), "the junction is still at its old name\n");
    ok(IsLink(L"junc-renamed"), "the new name is not the junction (reparse attribute missing)\n");
    ok(Exists(L"tdir") && !IsLink(L"tdir"), "the target directory was renamed or turned into a link\n");
    CheckTargetsIntact(L"junction renamed");
    ok(Exists(L"junc-renamed\\inner.txt"), "the junction does not lead to the target after the rename\n");

    /* Again, with MOVEFILE_REPLACE_EXISTING */
    P(From, L"junc-renamed");
    P(To, L"junc-again");
    ok(MoveFileExW(From, To, MOVEFILE_REPLACE_EXISTING), "second MoveFileExW(junction) failed: %lu\n", GetLastError());
    CheckTargetsIntact(L"junction renamed twice");

    P(From, L"junc-again");
    ok(RemoveDirectoryW(From), "removing the junction failed: %lu\n", GetLastError());
    CheckTargetsIntact(L"junction removed");

    if (!Symlinks)
        return;

    /* The same for a file link and a directory link */
    P(To, L"tfile.txt");
    P(From, L"flink");
    ok(pCreateSymbolicLinkW(From, To, 0), "creating the file link failed: %lu\n", GetLastError());
    P(To, L"flink-renamed");
    ok(MoveFileExW(From, To, 0), "MoveFileExW(file link) failed: %lu\n", GetLastError());
    ok(!Exists(L"flink"), "the file link is still at its old name\n");
    ok(IsLink(L"flink-renamed"), "the new name is not the file link\n");
    ok(Exists(L"tfile.txt") && !IsLink(L"tfile.txt"), "the target file was renamed\n");
    ok(ReadsAs(L"flink-renamed", "HELLO"), "the renamed file link does not lead to the target\n");
    CheckTargetsIntact(L"file link renamed");
    ok(DeleteFileW(To), "deleting the file link failed: %lu\n", GetLastError());
    CheckTargetsIntact(L"file link deleted");

    P(To, L"tdir");
    P(From, L"dlink");
    ok(pCreateSymbolicLinkW(From, To, SYMBOLIC_LINK_FLAG_DIRECTORY), "creating the directory link failed: %lu\n", GetLastError());
    P(To, L"dlink-renamed");
    ok(MoveFileExW(From, To, 0), "MoveFileExW(directory link) failed: %lu\n", GetLastError());
    ok(!Exists(L"dlink"), "the directory link is still at its old name\n");
    ok(IsLink(L"dlink-renamed"), "the new name is not the directory link\n");
    ok(Exists(L"tdir") && !IsLink(L"tdir"), "the target directory was renamed\n");
    ok(Exists(L"dlink-renamed\\inner.txt"), "the renamed directory link does not lead to the target\n");
    CheckTargetsIntact(L"directory link renamed");
    ok(RemoveDirectoryW(To), "removing the directory link failed: %lu\n", GetLastError());
    CheckTargetsIntact(L"directory link removed");

    /* A relative link too */
    P(From, L"rlink");
    ok(pCreateSymbolicLinkW(From, L"tfile.txt", 0), "creating the relative link failed: %lu\n", GetLastError());
    P(To, L"rlink-renamed");
    ok(MoveFileExW(From, To, 0), "MoveFileExW(relative link) failed: %lu\n", GetLastError());
    ok(ReadsAs(L"rlink-renamed", "HELLO"), "the renamed relative link does not lead to the target\n");
    ok(Exists(L"tfile.txt") && !IsLink(L"tfile.txt"), "the target of the relative link was renamed\n");
    DeleteFileW(To);
    CheckTargetsIntact(L"relative link");
}

/* Stage 1: queue a rename and a delete for the next boot */
static void Stage1(BOOL Symlinks)
{
    WCHAR From[MAX_PATH], To[MAX_PATH], Dir[MAX_PATH];

    P(Dir, L"tdir");
    ok(MakeJunction(L"q-junc-del", Dir), "creating a junction failed: %lu\n", GetLastError());
    ok(MakeJunction(L"q-junc-ren", Dir), "creating a junction failed: %lu\n", GetLastError());
    P(From, L"q-junc-del");
    ok(MoveFileExW(From, NULL, MOVEFILE_DELAY_UNTIL_REBOOT), "queueing the delete of a junction failed: %lu\n", GetLastError());
    P(From, L"q-junc-ren");
    P(To, L"q-junc-renamed");
    ok(MoveFileExW(From, To, MOVEFILE_DELAY_UNTIL_REBOOT), "queueing the rename of a junction failed: %lu\n", GetLastError());

    if (Symlinks)
    {
        P(To, L"tfile.txt");
        P(From, L"q-flink-del");
        ok(pCreateSymbolicLinkW(From, To, 0), "creating a file link failed: %lu\n", GetLastError());
        ok(MoveFileExW(From, NULL, MOVEFILE_DELAY_UNTIL_REBOOT), "queueing the delete of a file link failed: %lu\n", GetLastError());
        P(From, L"q-flink-ren");
        ok(pCreateSymbolicLinkW(From, To, 0), "creating a file link failed: %lu\n", GetLastError());
        P(To, L"q-flink-renamed");
        ok(MoveFileExW(From, To, MOVEFILE_DELAY_UNTIL_REBOOT), "queueing the rename of a file link failed: %lu\n", GetLastError());

        P(To, L"tdir");
        P(From, L"q-dlink-del");
        ok(pCreateSymbolicLinkW(From, To, SYMBOLIC_LINK_FLAG_DIRECTORY), "creating a directory link failed: %lu\n", GetLastError());
        ok(MoveFileExW(From, NULL, MOVEFILE_DELAY_UNTIL_REBOOT), "queueing the delete of a directory link failed: %lu\n", GetLastError());
    }
    trace("stage 1 done: reboot, then run 'MoveFileReparse stage2'\n");
}

static void Stage2(BOOL Symlinks)
{
    CheckTargetsIntact(L"after the boot");

    ok(!Exists(L"q-junc-del"), "the junction queued for delete is still there\n");
    ok(!Exists(L"q-junc-ren") && IsLink(L"q-junc-renamed"), "the junction queued for rename was not renamed as a link (old %d, new is link %d)\n",
       Exists(L"q-junc-ren"), IsLink(L"q-junc-renamed"));
    ok(Exists(L"q-junc-renamed\\inner.txt"), "the renamed junction does not lead to the target\n");

    if (Symlinks)
    {
        ok(!Exists(L"q-flink-del") && !IsLink(L"q-flink-del"), "the file link queued for delete is still there\n");
        ok(!Exists(L"q-flink-ren") && IsLink(L"q-flink-renamed"), "the file link queued for rename was not renamed as a link\n");
        ok(ReadsAs(L"q-flink-renamed", "HELLO"), "the renamed file link does not lead to the target\n");
        ok(!Exists(L"q-dlink-del"), "the directory link queued for delete is still there\n");
    }

    /* Clean up what stage 1 made */
    {
        WCHAR Path[MAX_PATH];

        P(Path, L"q-junc-renamed"); RemoveDirectoryW(Path);
        P(Path, L"q-flink-renamed"); DeleteFileW(Path);
        P(Path, L"tdir\\inner.txt"); DeleteFileW(Path);
        P(Path, L"tdir"); RemoveDirectoryW(Path);
        P(Path, L"tfile.txt"); DeleteFileW(Path);
        RemoveDirectoryW(Base);
    }
}

static void Cleanup(void)
{
    static const PCWSTR Dirs[] = { L"junc", L"junc-renamed", L"junc-again", L"dlink", L"dlink-renamed", L"q-junc-del",
                                   L"q-junc-ren", L"q-junc-renamed", L"q-dlink-del" };
    static const PCWSTR Files[] = { L"flink", L"flink-renamed", L"rlink", L"rlink-renamed", L"q-flink-del", L"q-flink-ren",
                                    L"q-flink-renamed", L"tdir\\inner.txt", L"tfile.txt" };
    WCHAR Path[MAX_PATH];
    UINT i;

    for (i = 0; i < ARRAYSIZE(Dirs); i++) { P(Path, Dirs[i]); RemoveDirectoryW(Path); }
    for (i = 0; i < ARRAYSIZE(Files); i++) { P(Path, Files[i]); DeleteFileW(Path); }
    P(Path, L"tdir"); RemoveDirectoryW(Path);
    RemoveDirectoryW(Base);
}

START_TEST(MoveFileReparse)
{
    WCHAR Temp[MAX_PATH];
    BOOL Symlinks, Stage2Run = wcsstr(GetCommandLineW(), L"stage2") != NULL;
    BOOL Stage1Run = wcsstr(GetCommandLineW(), L"stage1") != NULL;

    pCreateSymbolicLinkW = (PFN_CSLW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateSymbolicLinkW");
    Symlinks = pCreateSymbolicLinkW != NULL && HasLinkPrivilege();

    GetTempPathW(MAX_PATH, Temp);
    wsprintfW(Base, L"%sMoveFileReparse", Temp);

    if (Stage2Run)
    {
        Stage2(Symlinks);
        return;
    }

    Cleanup();
    if (!CreateDirectoryW(Base, NULL))
    {
        skip("cannot create the test directory %ls: %lu\n", Base, GetLastError());
        return;
    }
    MakeFile(L"tfile.txt", "HELLO");
    {
        WCHAR Dir[MAX_PATH];
        P(Dir, L"tdir");
        ok(CreateDirectoryW(Dir, NULL), "creating the target directory failed: %lu\n", GetLastError());
        MakeFile(L"tdir\\inner.txt", "INNER");
    }

    if (Stage1Run)
    {
        Stage1(Symlinks);
        return;
    }

    if (!Symlinks)
        skip("SeCreateSymbolicLinkPrivilege is not held: the symbolic link cases are skipped\n");
    Test_Now(Symlinks);
    Cleanup();
}
