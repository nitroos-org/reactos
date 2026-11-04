/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for CreateSymbolicLinkW/A: flags, the reparse data written, following the link, deleting it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected behaviour was taken from Windows 10 22H2 (elevated): SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE (0x2)
 * is accepted, bits that are not defined are ignored, relative targets are stored as written with
 * SYMLINK_FLAG_RELATIVE, absolute ones as \??\ paths. Without developer mode Windows wants
 * SeCreateSymbolicLinkPrivilege (ERROR_PRIVILEGE_NOT_HELD) for every flag combination, also with
 * SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE, and for FSCTL_SET_REPARSE_POINT with a symbolic link tag.
 * The test adapts to the token: a token that has the privilege runs the link tests, one that does not (a
 * standard user) tests that every way of creating a link is refused and leaves nothing behind.
 */

#include "precomp.h"
#include <winuser.h>
#include <winioctl.h>

#ifndef SYMBOLIC_LINK_FLAG_DIRECTORY
#define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#ifndef FSCTL_GET_REPARSE_POINT
#define FSCTL_GET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000CL
#endif

#define TEST_SYMLINK_FLAG_RELATIVE 1

typedef struct
{
    DWORD ReparseTag;
    WORD  ReparseDataLength;
    WORD  Reserved;
    WORD  SubstituteNameOffset;
    WORD  SubstituteNameLength;
    WORD  PrintNameOffset;
    WORD  PrintNameLength;
    DWORD Flags;
    WCHAR PathBuffer[1];
} TEST_SYMLINK_REPARSE;

typedef BOOLEAN (WINAPI *PFN_CSLW)(LPCWSTR, LPCWSTR, DWORD);
typedef BOOLEAN (WINAPI *PFN_CSLA)(LPCSTR, LPCSTR, DWORD);
typedef DWORD (WINAPI *PFN_GFPNBH)(HANDLE, LPWSTR, DWORD, DWORD);

static PFN_CSLW pCreateSymbolicLinkW;
static PFN_CSLA pCreateSymbolicLinkA;
static PFN_GFPNBH pGetFinalPathNameByHandleW;

static WCHAR Base[MAX_PATH];
static BOOL Skipped;

static void Path(WCHAR *Out, const WCHAR *Name)
{
    wsprintfW(Out, L"%s\\%s", Base, Name);
}

static void MakeFile(const WCHAR *Name, const char *Data)
{
    WCHAR P[MAX_PATH];
    HANDLE h;
    DWORD n;

    Path(P, Name);
    h = CreateFileW(P, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h != INVALID_HANDLE_VALUE, "creating %ls failed: %lu\n", P, GetLastError());
    if (h != INVALID_HANDLE_VALUE)
    {
        WriteFile(h, Data, (DWORD)strlen(Data), &n, NULL);
        CloseHandle(h);
    }
}

static void MakeDir(const WCHAR *Name)
{
    WCHAR P[MAX_PATH];

    Path(P, Name);
    ok(CreateDirectoryW(P, NULL), "creating %ls failed: %lu\n", P, GetLastError());
}

/* Does the file at Name contain Expect? */
static BOOL ReadsAs(const WCHAR *FullPath, const char *Expect, DWORD *Error)
{
    char Buf[32] = {0};
    DWORD n = 0;
    HANDLE h = CreateFileW(FullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        *Error = GetLastError();
        return FALSE;
    }
    *Error = 0;
    ReadFile(h, Buf, sizeof(Buf) - 1, &n, NULL);
    CloseHandle(h);
    return n == strlen(Expect) && !memcmp(Buf, Expect, n);
}

static void CheckReparseData(const WCHAR *Link, BOOL Relative, const WCHAR *Written, const WCHAR *NtTarget)
{
    BYTE Buf[2048];
    TEST_SYMLINK_REPARSE *Rp = (TEST_SYMLINK_REPARSE *)Buf;
    DWORD Size = 0;
    WCHAR Sub[MAX_PATH] = {0}, Print[MAX_PATH] = {0};
    HANDLE h;
    BOOL Ret;

    h = CreateFileW(Link, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(h != INVALID_HANDLE_VALUE, "opening the link %ls itself failed: %lu\n", Link, GetLastError());
    if (h == INVALID_HANDLE_VALUE)
        return;

    ok(GetFileAttributesW(Link) & FILE_ATTRIBUTE_REPARSE_POINT, "link without FILE_ATTRIBUTE_REPARSE_POINT\n");
    Ret = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, Buf, sizeof(Buf), &Size, NULL);
    ok(Ret, "FSCTL_GET_REPARSE_POINT failed: %lu\n", GetLastError());
    if (Ret)
    {
        ok(Rp->ReparseTag == IO_REPARSE_TAG_SYMLINK, "tag is %08lx\n", Rp->ReparseTag);
        ok(Rp->Flags == (Relative ? TEST_SYMLINK_FLAG_RELATIVE : 0), "flags are %lu, relative %d\n", Rp->Flags, Relative);
        memcpy(Sub, (PBYTE)Rp->PathBuffer + Rp->SubstituteNameOffset, Rp->SubstituteNameLength);
        memcpy(Print, (PBYTE)Rp->PathBuffer + Rp->PrintNameOffset, Rp->PrintNameLength);
        ok(!lstrcmpW(Sub, NtTarget), "substitute name is %ls, expected %ls\n", Sub, NtTarget);
        ok(!lstrcmpW(Print, Written), "print name is %ls, expected %ls\n", Print, Written);
    }
    CloseHandle(h);
}

/*
 * One round: link Name -> Target (written as is), the target itself being TargetName in the test directory.
 * Flags go to CreateSymbolicLinkW; the target is a directory if IsDir.
 */
static void RoundTrip(const char *Label, const WCHAR *LinkName, const WCHAR *Target, const WCHAR *TargetName,
                      BOOL Relative, BOOL IsDir, DWORD Flags)
{
    WCHAR Link[MAX_PATH], TargetFull[MAX_PATH], Inner[MAX_PATH], Final[MAX_PATH], Expect[MAX_PATH], Nt[MAX_PATH];
    BOOLEAN Ret;
    BOOL Ok;
    DWORD Err, Len;
    HANDLE h;

    Path(Link, LinkName);
    Path(TargetFull, TargetName);
    SetLastError(0xdeadbeef);
    Ret = pCreateSymbolicLinkW(Link, Target, Flags);
    if (!Ret)
    {
        Err = GetLastError();
        if (Err == ERROR_INVALID_FUNCTION || Err == ERROR_NOT_SUPPORTED)
        {
            if (!Skipped) skip("the temp volume has no symbolic links (%lu)\n", Err);
            Skipped = TRUE;
            return;
        }
        ok(0, "%s: CreateSymbolicLinkW(%ls -> %ls, %lu) failed: %lu\n", Label, LinkName, Target, Flags, Err);
        return;
    }

    ok(GetFileAttributesW(Link) != INVALID_FILE_ATTRIBUTES, "%s: link does not exist\n", Label);
    ok(!!(GetFileAttributesW(Link) & FILE_ATTRIBUTE_DIRECTORY) == !!(Flags & SYMBOLIC_LINK_FLAG_DIRECTORY),
       "%s: link attributes %08lx for flags %lu\n", Label, GetFileAttributesW(Link), Flags);

    wsprintfW(Nt, L"%s%s", Relative ? L"" : L"\\??\\", Target);
    CheckReparseData(Link, Relative, Target, Nt);

    /* Read through the link */
    if (!IsDir)
    {
        Ok = ReadsAs(Link, "HELLO", &Err);
        ok(Ok, "%s: reading through the file link failed: %lu\n", Label, Err);
        h = CreateFileW(Link, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE && pGetFinalPathNameByHandleW)
        {
            wsprintfW(Expect, L"\\\\?\\%s", TargetFull);
            Len = pGetFinalPathNameByHandleW(h, Final, MAX_PATH, 0);
            ok(Len != 0 && !lstrcmpiW(Final, Expect), "%s: final path %ls, expected %ls (%lu)\n", Label, Final, Expect, Len);
        }
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    else
    {
        WCHAR Pattern[MAX_PATH];
        WIN32_FIND_DATAW Fd;
        BOOL Found = FALSE;
        HANDLE Find;

        wsprintfW(Pattern, L"%s\\*", Link);
        Find = FindFirstFileW(Pattern, &Fd);
        ok(Find != INVALID_HANDLE_VALUE, "%s: listing through the directory link failed: %lu\n", Label, GetLastError());
        if (Find != INVALID_HANDLE_VALUE)
        {
            do
                Found |= !lstrcmpW(Fd.cFileName, L"inner.txt");
            while (FindNextFileW(Find, &Fd));
            FindClose(Find);
            ok(Found, "%s: inner.txt not seen through the directory link\n", Label);
        }

        wsprintfW(Inner, L"%s\\inner.txt", Link);
        Ok = ReadsAs(Inner, "INNER", &Err);
        ok(Ok, "%s: reading a file below the directory link failed: %lu\n", Label, Err);

        wsprintfW(Inner, L"%s\\deeper\\deep.txt", Link);
        Ok = ReadsAs(Inner, "DEEP", &Err);
        ok(Ok, "%s: reading two levels below the directory link failed: %lu\n", Label, Err);

        h = CreateFileW(Link, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        ok(h != INVALID_HANDLE_VALUE, "%s: opening the directory link failed: %lu\n", Label, GetLastError());
        if (h != INVALID_HANDLE_VALUE && pGetFinalPathNameByHandleW)
        {
            wsprintfW(Expect, L"\\\\?\\%s", TargetFull);
            Len = pGetFinalPathNameByHandleW(h, Final, MAX_PATH, 0);
            ok(Len != 0 && !lstrcmpiW(Final, Expect), "%s: final path %ls, expected %ls (%lu)\n", Label, Final, Expect, Len);
        }
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }

    /* The link itself, opened as a reparse point, has the link's own name */
    h = CreateFileW(Link, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h != INVALID_HANDLE_VALUE && pGetFinalPathNameByHandleW)
    {
        wsprintfW(Expect, L"\\\\?\\%s", Link);
        Len = pGetFinalPathNameByHandleW(h, Final, MAX_PATH, 0);
        ok(Len != 0 && !lstrcmpiW(Final, Expect), "%s: final path of the link itself %ls, expected %ls\n", Label, Final, Expect);
    }
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);

    /* Deleting the link must not touch the target */
    if (IsDir)
        ok(RemoveDirectoryW(Link), "%s: RemoveDirectory(link) failed: %lu\n", Label, GetLastError());
    else
        ok(DeleteFileW(Link), "%s: DeleteFile(link) failed: %lu\n", Label, GetLastError());
    ok(GetFileAttributesW(Link) == INVALID_FILE_ATTRIBUTES, "%s: link still there\n", Label);
    ok(GetFileAttributesW(TargetFull) != INVALID_FILE_ATTRIBUTES, "%s: target is gone\n", Label);
    if (!IsDir)
    {
        Ok = ReadsAs(TargetFull, "HELLO", &Err);
        ok(Ok, "%s: target damaged: %lu\n", Label, Err);
    }
    else
    {
        wsprintfW(Inner, L"%s\\inner.txt", TargetFull);
        Ok = ReadsAs(Inner, "INNER", &Err);
        ok(Ok, "%s: target directory damaged: %lu\n", Label, Err);
    }
}

static void Test_Flags(void)
{
    WCHAR Link[MAX_PATH], Target[MAX_PATH];
    BOOLEAN Ret;
    DWORD Flags[] = { 0, 2, 4, 6, 0x10, 0x80000000 };
    DWORD DirFlags[] = { 1, 3, 5, 7, 0x11, 0x80000001 };
    WCHAR Name[16];
    UINT i;

    Path(Target, L"tfile.txt");
    Path(Link, L"flags-link");

    /* File links: only bit 0 selects a directory link, the other bits do not make the call fail (Windows 10) */
    for (i = 0; i < ARRAYSIZE(Flags) && !Skipped; i++)
    {
        wsprintfW(Name, L"flagf%lu", Flags[i]);
        RoundTrip("file", Name, Target, L"tfile.txt", FALSE, FALSE, Flags[i]);
    }

    Path(Target, L"tdir");
    for (i = 0; i < ARRAYSIZE(DirFlags) && !Skipped; i++)
    {
        wsprintfW(Name, L"flagd%lu", DirFlags[i]);
        RoundTrip("dir", Name, Target, L"tdir", FALSE, TRUE, DirFlags[i]);
    }

    if (Skipped)
        return;

    /* Invalid arguments */
    SetLastError(0xdeadbeef);
    Ret = pCreateSymbolicLinkW(NULL, Target, 0);
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "NULL link: %d, %lu\n", Ret, GetLastError());
    SetLastError(0xdeadbeef);
    Ret = pCreateSymbolicLinkW(Link, NULL, 0);
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "NULL target: %d, %lu\n", Ret, GetLastError());

    /* An existing name */
    Path(Link, L"tfile.txt");
    Path(Target, L"tdir");
    SetLastError(0xdeadbeef);
    Ret = pCreateSymbolicLinkW(Link, Target, 0);
    ok(!Ret && GetLastError() == ERROR_ALREADY_EXISTS, "existing name: %d, %lu\n", Ret, GetLastError());
}

static void Test_Follow(void)
{
    WCHAR LinkName[MAX_PATH], Target[MAX_PATH];

    if (Skipped)
        return;

    /* File and directory, absolute and relative target, plain and with the unprivileged flag */
    Path(Target, L"tfile.txt");
    RoundTrip("file abs", L"lnk-fa", Target, L"tfile.txt", FALSE, FALSE, 0);
    RoundTrip("file rel", L"lnk-fr", L"tfile.txt", L"tfile.txt", TRUE, FALSE, 0);
    RoundTrip("file rel 2", L"lnk-fr2", L"tfile.txt", L"tfile.txt", TRUE, FALSE, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);

    Path(Target, L"tdir");
    RoundTrip("dir abs", L"lnk-da", Target, L"tdir", FALSE, TRUE, SYMBOLIC_LINK_FLAG_DIRECTORY);
    RoundTrip("dir rel", L"lnk-dr", L"tdir", L"tdir", TRUE, TRUE, SYMBOLIC_LINK_FLAG_DIRECTORY);
    RoundTrip("dir rel 2", L"lnk-dr2", L"tdir", L"tdir", TRUE, TRUE,
              SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);

    /* A relative target resolves against the directory that holds the link, ".." included */
    wsprintfW(LinkName, L"sub\\lnk-up-file");
    RoundTrip("file up", LinkName, L"..\\tfile.txt", L"tfile.txt", TRUE, FALSE, 0);
    wsprintfW(LinkName, L"sub\\lnk-up-dir");
    RoundTrip("dir up", LinkName, L"..\\tdir", L"tdir", TRUE, TRUE, SYMBOLIC_LINK_FLAG_DIRECTORY);
    wsprintfW(LinkName, L"sub\\lnk-dot-dir");
    RoundTrip("dir dot", LinkName, L".\\..\\.\\tdir", L"tdir", TRUE, TRUE, SYMBOLIC_LINK_FLAG_DIRECTORY);
}

static void Test_AnsiVariant(void)
{
    char Link[MAX_PATH], Target[MAX_PATH];
    WCHAR LinkW[MAX_PATH], TargetW[MAX_PATH];
    BOOL Ok;
    DWORD Err;

    if (Skipped || !pCreateSymbolicLinkA)
        return;

    Path(LinkW, L"ansi-link");
    Path(TargetW, L"tfile.txt");
    WideCharToMultiByte(CP_ACP, 0, LinkW, -1, Link, sizeof(Link), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, TargetW, -1, Target, sizeof(Target), NULL, NULL);

    ok(pCreateSymbolicLinkA(Link, Target, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE),
       "CreateSymbolicLinkA failed: %lu\n", GetLastError());
    Ok = ReadsAs(LinkW, "HELLO", &Err);
    ok(Ok, "reading through the link failed: %lu\n", Err);
    ok(DeleteFileW(LinkW), "DeleteFile failed: %lu\n", GetLastError());
    Ok = ReadsAs(TargetW, "HELLO", &Err);
    ok(Ok, "target damaged: %lu\n", Err);
}

static BOOL HasLinkPrivilege(void)
{
    HANDLE Token;
    LUID Luid;
    BYTE Buf[2048];
    TOKEN_PRIVILEGES *Priv = (TOKEN_PRIVILEGES *)Buf;
    DWORD Size, i;
    BOOL Found = FALSE;

    if (!LookupPrivilegeValueW(NULL, L"SeCreateSymbolicLinkPrivilege", &Luid))
    {
        ok(0, "LookupPrivilegeValue(SeCreateSymbolicLinkPrivilege) failed: %lu\n", GetLastError());
        return FALSE;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (GetTokenInformation(Token, TokenPrivileges, Buf, sizeof(Buf), &Size))
    {
        for (i = 0; i < Priv->PrivilegeCount; i++)
            Found |= Priv->Privileges[i].Luid.LowPart == Luid.LowPart && Priv->Privileges[i].Luid.HighPart == Luid.HighPart;
    }
    CloseHandle(Token);
    return Found;
}

static BOOL SetLinkPrivilege(BOOL Enable)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;
    BOOL Ret;

    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
    if (!LookupPrivilegeValueW(NULL, L"SeCreateSymbolicLinkPrivilege", &Tp.Privileges[0].Luid))
        return FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Ret = AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ret;
}

/* The data of a symbolic link, built by hand: Sub and Print are placed one after the other */
static DWORD BuildLinkData(BYTE *Buf, DWORD Flags, const WCHAR *Sub, const WCHAR *Print)
{
    TEST_SYMLINK_REPARSE *Rp = (TEST_SYMLINK_REPARSE *)Buf;
    DWORD SubLen = lstrlenW(Sub) * sizeof(WCHAR), PrintLen = lstrlenW(Print) * sizeof(WCHAR);

    Rp->ReparseTag = IO_REPARSE_TAG_SYMLINK;
    Rp->Reserved = 0;
    Rp->SubstituteNameOffset = 0;
    Rp->SubstituteNameLength = (WORD)SubLen;
    Rp->PrintNameOffset = (WORD)SubLen;
    Rp->PrintNameLength = (WORD)PrintLen;
    Rp->Flags = Flags;
    memcpy((BYTE *)Rp->PathBuffer, Sub, SubLen);
    memcpy((BYTE *)Rp->PathBuffer + SubLen, Print, PrintLen);
    Rp->ReparseDataLength = (WORD)(FIELD_OFFSET(TEST_SYMLINK_REPARSE, PathBuffer) - 8 + SubLen + PrintLen);
    return FIELD_OFFSET(TEST_SYMLINK_REPARSE, PathBuffer) + SubLen + PrintLen;
}

#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif

/* Sets Data on a new file or directory (Name), returns the DeviceIoControl result and the error */
static BOOL RawSet(const WCHAR *Name, BOOL IsDir, BYTE *Data, DWORD Size, DWORD *Error)
{
    WCHAR P[MAX_PATH];
    HANDLE h;
    DWORD Ret = 0;
    BOOL Ok;

    Path(P, Name);
    if (IsDir)
    {
        ok(CreateDirectoryW(P, NULL), "creating %ls failed: %lu\n", P, GetLastError());
        h = CreateFileW(P, GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    else
    {
        h = CreateFileW(P, GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    if (h == INVALID_HANDLE_VALUE)
    {
        ok(0, "opening %ls failed: %lu\n", P, GetLastError());
        *Error = GetLastError();
        return TRUE;
    }
    SetLastError(0xdeadbeef);
    Ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, Data, Size, NULL, 0, &Ret, NULL);
    *Error = GetLastError();
    CloseHandle(h);
    return Ok;
}

static void RawRemove(const WCHAR *Name, BOOL IsDir)
{
    WCHAR P[MAX_PATH];

    Path(P, Name);
    if (IsDir) RemoveDirectoryW(P); else DeleteFileW(P);
}

/* A token without the privilege (a standard user): no way of creating a link works, and nothing is left behind */
static void Test_Unprivileged(void)
{
    static const DWORD Flags[] = { 0, SYMBOLIC_LINK_FLAG_DIRECTORY, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
                                   SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE };
    WCHAR Link[MAX_PATH], Target[MAX_PATH], Name[16];
    BYTE Data[512];
    DWORD Size, Err;
    UINT i;
    BOOLEAN Ret;
    BOOL Ok;

    Path(Target, L"tfile.txt");
    for (i = 0; i < ARRAYSIZE(Flags); i++)
    {
        wsprintfW(Name, L"unpriv%lu", Flags[i]);
        Path(Link, Name);
        SetLastError(0xdeadbeef);
        Ret = pCreateSymbolicLinkW(Link, (Flags[i] & SYMBOLIC_LINK_FLAG_DIRECTORY) ? L"tdir" : Target, Flags[i]);
        ok(!Ret && GetLastError() == ERROR_PRIVILEGE_NOT_HELD,
           "flags %lu: CreateSymbolicLinkW returned %d, error %lu (expected ERROR_PRIVILEGE_NOT_HELD)\n",
           Flags[i], Ret, GetLastError());
        ok(GetFileAttributesW(Link) == INVALID_FILE_ATTRIBUTES, "flags %lu: a refused link was left behind\n", Flags[i]);
    }

    /* The ANSI variant is the same call */
    if (pCreateSymbolicLinkA)
    {
        SetLastError(0xdeadbeef);
        Ret = pCreateSymbolicLinkA("unpriv-ansi-link", "tfile.txt", SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
        ok(!Ret && GetLastError() == ERROR_PRIVILEGE_NOT_HELD, "ANSI: %d, %lu\n", Ret, GetLastError());
    }

    /* The control code itself: a file and a directory, relative and absolute */
    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Ok = RawSet(L"unpriv-raw-file", FALSE, Data, Size, &Err);
    ok(!Ok && Err == ERROR_PRIVILEGE_NOT_HELD, "FSCTL_SET_REPARSE_POINT on a file: %d, %lu\n", Ok, Err);
    ok(!(GetFileAttributesW((Path(Link, L"unpriv-raw-file"), Link)) & FILE_ATTRIBUTE_REPARSE_POINT),
       "the refused request made the file a reparse point\n");
    RawRemove(L"unpriv-raw-file", FALSE);

    /* Windows 10 22H2 let this one through for a token without the privilege (one probe, 2026-11-04); the
       file systems here require the privilege for every symbolic link, a deliberate difference: a link anyone
       can create is followed for every process */
    Size = BuildLinkData(Data, 0, L"\\??\\C:\\Windows", L"C:\\Windows");
    Ok = RawSet(L"unpriv-raw-dir", TRUE, Data, Size, &Err);
    ok(!Ok && Err == ERROR_PRIVILEGE_NOT_HELD, "FSCTL_SET_REPARSE_POINT on a directory: %d, %lu\n", Ok, Err);
    ok(!(GetFileAttributesW((Path(Link, L"unpriv-raw-dir"), Link)) & FILE_ATTRIBUTE_REPARSE_POINT),
       "the refused request made the directory a reparse point\n");
    RawRemove(L"unpriv-raw-dir", TRUE);
}

/* A token with the privilege: the control code needs it enabled, and the data has to be sound */
static void Test_RawSet(void)
{
    BYTE Data[512];
    DWORD Size, Err;
    BOOL Ok;
    TEST_SYMLINK_REPARSE *Rp = (TEST_SYMLINK_REPARSE *)Data;
    WCHAR P[MAX_PATH];

    /* Disabled: refused, as on Windows (CreateSymbolicLinkW turns the privilege on by itself) */
    ok(SetLinkPrivilege(FALSE), "disabling the privilege failed: %lu\n", GetLastError());
    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Ok = RawSet(L"raw-disabled", FALSE, Data, Size, &Err);
    ok(!Ok && Err == ERROR_PRIVILEGE_NOT_HELD, "privilege disabled: %d, %lu\n", Ok, Err);
    RawRemove(L"raw-disabled", FALSE);

    ok(SetLinkPrivilege(TRUE), "enabling the privilege failed: %lu\n", GetLastError());

    /* Data that is not sound is refused and leaves no reparse point */
    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Rp->SubstituteNameOffset = 0x2000;
    Ok = RawSet(L"raw-badoff", FALSE, Data, Size, &Err);
    ok(!Ok, "substitute name outside the buffer was accepted\n");
    Path(P, L"raw-badoff");
    ok(!(GetFileAttributesW(P) & FILE_ATTRIBUTE_REPARSE_POINT), "bad offset: file became a reparse point\n");
    RawRemove(L"raw-badoff", FALSE);

    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Rp->PrintNameLength = 0x2000;
    Ok = RawSet(L"raw-badprint", FALSE, Data, Size, &Err);
    ok(!Ok, "print name outside the buffer was accepted\n");
    RawRemove(L"raw-badprint", FALSE);

    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Rp->SubstituteNameOffset = 1;
    Ok = RawSet(L"raw-odd", FALSE, Data, Size, &Err);
    ok(!Ok, "odd substitute name offset was accepted\n");
    RawRemove(L"raw-odd", FALSE);

    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Rp->SubstituteNameLength = 0;
    Ok = RawSet(L"raw-empty", FALSE, Data, Size, &Err);
    ok(!Ok, "empty substitute name was accepted\n");
    RawRemove(L"raw-empty", FALSE);

    /* Flags other than SYMLINK_FLAG_RELATIVE are taken (Windows 10 22H2 accepts 0x81) */
    Size = BuildLinkData(Data, 0x80 | TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Ok = RawSet(L"raw-flags", FALSE, Data, Size, &Err);
    ok(Ok, "flags 0x81 refused: %lu\n", Err);
    RawRemove(L"raw-flags", FALSE);

    /* And sound data works */
    Size = BuildLinkData(Data, TEST_SYMLINK_FLAG_RELATIVE, L"tfile.txt", L"tfile.txt");
    Ok = RawSet(L"raw-good", FALSE, Data, Size, &Err);
    ok(Ok, "sound data refused: %lu\n", Err);
    Path(P, L"raw-good");
    ok(!!(GetFileAttributesW(P) & FILE_ATTRIBUTE_REPARSE_POINT), "no reparse point after a good request\n");
    DeleteFileW(P);
}

static void Cleanup(void)
{
    static const WCHAR *Files[] = { L"deeper\\deep.txt", L"inner.txt", L"tfile.txt" };
    WCHAR P[MAX_PATH];
    WIN32_FIND_DATAW Fd;
    HANDLE Find;
    UINT i;

    /* Leftover links of a failed run */
    wsprintfW(P, L"%s\\*", Base);
    Find = FindFirstFileW(P, &Fd);
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (Fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                Path(P, Fd.cFileName);
                if (Fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(P); else DeleteFileW(P);
            }
        } while (FindNextFileW(Find, &Fd));
        FindClose(Find);
    }
    wsprintfW(P, L"%s\\sub\\*", Base);
    Find = FindFirstFileW(P, &Fd);
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (Fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                wsprintfW(P, L"%s\\sub\\%s", Base, Fd.cFileName);
                if (Fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(P); else DeleteFileW(P);
            }
        } while (FindNextFileW(Find, &Fd));
        FindClose(Find);
    }

    for (i = 0; i < ARRAYSIZE(Files); i++)
    {
        wsprintfW(P, L"%s\\%s%s", Base, (i < 2) ? L"tdir\\" : L"", Files[i]);
        DeleteFileW(P);
    }
    wsprintfW(P, L"%s\\tdir\\deeper", Base);
    RemoveDirectoryW(P);
    Path(P, L"tdir");
    RemoveDirectoryW(P);
    Path(P, L"sub");
    RemoveDirectoryW(P);
    RemoveDirectoryW(Base);
}

START_TEST(CreateSymbolicLink)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    WCHAR Temp[MAX_PATH], P[MAX_PATH];

    pCreateSymbolicLinkW = (PFN_CSLW)GetProcAddress(hKernel32, "CreateSymbolicLinkW");
    pCreateSymbolicLinkA = (PFN_CSLA)GetProcAddress(hKernel32, "CreateSymbolicLinkA");
    pGetFinalPathNameByHandleW = (PFN_GFPNBH)GetProcAddress(hKernel32, "GetFinalPathNameByHandleW");
    if (!pCreateSymbolicLinkW)
    {
        skip("CreateSymbolicLinkW is not available\n");
        return;
    }

    GetTempPathW(MAX_PATH, Temp);
    wsprintfW(Base, L"%sCreateSymbolicLink-%lu", Temp, GetCurrentProcessId());
    Cleanup();
    if (!CreateDirectoryW(Base, NULL))
    {
        skip("cannot create the test directory %ls: %lu\n", Base, GetLastError());
        return;
    }

    MakeFile(L"tfile.txt", "HELLO");
    MakeDir(L"tdir");
    MakeDir(L"sub");
    MakeFile(L"tdir\\inner.txt", "INNER");
    MakeDir(L"tdir\\deeper");
    MakeFile(L"tdir\\deeper\\deep.txt", "DEEP");

    /* Tell a volume without symbolic links before anything else */
    Path(P, L"probe-link");
    if (!pCreateSymbolicLinkW(P, L"tfile.txt", 0))
    {
        DWORD Err = GetLastError();
        if (Err == ERROR_INVALID_FUNCTION || Err == ERROR_NOT_SUPPORTED)
            Skipped = TRUE;
    }
    else
        DeleteFileW(P);

    if (!HasLinkPrivilege())
    {
        Test_Unprivileged();
    }
    else
    {
        Test_Flags();
        Test_Follow();
        Test_AnsiVariant();
        Test_RawSet();
    }

    Cleanup();
}
