/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Traverse checks of restricted tokens: object directories and a file path
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (10.0.20348) as an administrator. A token with SeChangeNotifyPrivilege (bypass traverse
 * checking) is not checked for traversing at all. A token without it is: the directory's descriptor is checked for the traverse
 * right with the token's SIDs and, for a restricted token, with its restricting SIDs as well; an ACE of Everyone that grants the
 * right does not decide it for a restricted token whose restricting SIDs are not Everyone.
 *
 * Object directory \BaseNamedObjects\RosTraverseTest<v>, an event "ev" below it that grants Administrators, Everyone, S-1-5-33 and
 * Restricted (S-1-5-12), and a file C:\RosTraverseTest\<v>\leaf.txt with the same grants. The directory descriptors:
 *   v1  Administrators: all; Everyone: traverse
 *   v2  as v1 and S-1-5-33: traverse
 *   v3  Administrators: all
 *   v4  Administrators: all, deny S-1-5-33 traverse, Everyone: traverse
 *   v5  SYSTEM: all, Everyone: traverse                  (the administrators are not in it)
 *   v6  SYSTEM: all, deny S-1-5-33 traverse, Everyone: traverse
 *   v7  Administrators: all; Everyone: traverse; Restricted: traverse
 * Tokens: copies of the administrator's token with SeChangeNotifyPrivilege deleted (the "-np" ones), and restricted by
 * Everyone (RWD), Administrators (RBA) and Restricted (RRC); N-np is not restricted; W33-np write restricted by S-1-5-33.
 * (The ancestors \ and \BaseNamedObjects grant traverse to Everyone and Restricted but not to Administrators; C:\ grants it
 * to Administrators and Users but not to Everyone or Restricted: the rows of RBA for the directories and of RRC and RWD for the
 * file are decided there and are left out.)
 */

#include "precomp.h"
#include <sddl.h>
#include <ndk/obfuncs.h>
#include <ndk/exfuncs.h>

#ifndef WRITE_RESTRICTED
#define WRITE_RESTRICTED 0x8
#endif

#define VARIANTS 7
#define DIRECTORY_TRAVERSE_RIGHT 0x2
#define LEAF L"D:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;S-1-5-33)(A;;GA;;;RC)"

static const PCWSTR DirSds[VARIANTS] =
{
    L"D:P(A;;GA;;;BA)(A;;0x2;;;WD)",
    L"D:P(A;;GA;;;BA)(A;;0x2;;;WD)(A;;0x2;;;S-1-5-33)",
    L"D:P(A;;GA;;;BA)",
    L"D:P(A;;GA;;;BA)(D;;0x2;;;S-1-5-33)(A;;0x2;;;WD)",
    L"D:P(A;;GA;;;SY)(A;;0x2;;;WD)",
    L"D:P(A;;GA;;;SY)(A;;0x2;;;WD)(D;;0x2;;;S-1-5-33)",
    L"D:P(A;;GA;;;BA)(A;;0x2;;;WD)(A;;0x2;;;RC)",
};
static const PCWSTR FileSds[VARIANTS] =
{
    L"D:P(A;;GA;;;BA)(A;;0x20;;;WD)",
    L"D:P(A;;GA;;;BA)(A;;0x20;;;WD)(A;;0x20;;;S-1-5-33)",
    L"D:P(A;;GA;;;BA)",
    L"D:P(A;;GA;;;BA)(D;;0x20;;;S-1-5-33)(A;;0x20;;;WD)",
    L"D:P(A;;GA;;;SY)(A;;0x20;;;WD)",
    L"D:P(A;;GA;;;SY)(A;;0x20;;;WD)(D;;0x20;;;S-1-5-33)",
    L"D:P(A;;GA;;;BA)(A;;0x20;;;WD)(A;;0x20;;;RC)",
};

enum { T_NP, T_RWD_NP, T_RBA_NP, T_RRC_NP, T_W33_NP, T_RRC, T_COUNT };
static const PCSTR TokenNames[T_COUNT] = { "N-np", "RWD-np", "RBA-np", "RRC-np", "W33-np", "RRC (with bypass traverse)" };
static HANDLE Tokens[T_COUNT];

/* 1: opens, 0: access denied; -1: not compared */
static const struct { signed char Dir[VARIANTS]; signed char File[VARIANTS]; } Expected[T_COUNT] =
{
    /* N-np    */ { { 1, 1, 1, 1, 1, 1, 1 }, { 1, 1, 1, 1, 1, 1, 1 } },
    /* RWD-np  */ { { 1, 1, 0, 1, 1, 1, 1 }, { -1, -1, -1, -1, -1, -1, -1 } },
    /* RBA-np  */ { { -1, -1, -1, -1, -1, -1, -1 }, { 1, 1, 1, 1, 0, 0, 1 } },
    /* RRC-np  */ { { 0, 0, 0, 0, 0, 0, 1 }, { -1, -1, -1, -1, -1, -1, -1 } },
    /* W33-np  */ { { 1, 1, 1, 1, 1, 1, 1 }, { 1, 1, 1, 1, 1, 1, 1 } },
    /* RRC     */ { { 1, 1, 1, 1, 1, 1, 1 }, { 1, 1, 1, 1, 1, 1, 1 } },
};

static BOOL
MakeTokens(VOID)
{
    HANDLE hProcess = NULL, hImp = NULL, hNp = NULL;
    LUID_AND_ATTRIBUTES ChangeNotify;
    BYTE Sid33[SECURITY_MAX_SID_SIZE], SidWd[SECURITY_MAX_SID_SIZE], SidBa[SECURITY_MAX_SID_SIZE], SidRc[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_AND_ATTRIBUTES Restrict;
    DWORD cb;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcess))
        return FALSE;
    Ret = DuplicateTokenEx(hProcess, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hImp);
    CloseHandle(hProcess);
    if (!Ret)
        return FALSE;

    RtlInitializeSid((PSID)Sid33, &NtAuthority, 1);
    *RtlSubAuthoritySid((PSID)Sid33, 0) = 33;
    cb = sizeof(SidWd);
    CreateWellKnownSid(WinWorldSid, NULL, SidWd, &cb);
    cb = sizeof(SidBa);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, SidBa, &cb);
    cb = sizeof(SidRc);
    CreateWellKnownSid(WinRestrictedCodeSid, NULL, SidRc, &cb);
    ChangeNotify.Attributes = 0;
    if (!LookupPrivilegeValueA(NULL, SE_CHANGE_NOTIFY_NAME, &ChangeNotify.Luid))
        return FALSE;
    Restrict.Attributes = 0;

    Ret = CreateRestrictedToken(hImp, 0, 0, NULL, 1, &ChangeNotify, 0, NULL, &Tokens[T_NP]);
    hNp = hImp;
    Restrict.Sid = SidWd;
    Ret = Ret && CreateRestrictedToken(hNp, 0, 0, NULL, 1, &ChangeNotify, 1, &Restrict, &Tokens[T_RWD_NP]);
    Restrict.Sid = SidBa;
    Ret = Ret && CreateRestrictedToken(hNp, 0, 0, NULL, 1, &ChangeNotify, 1, &Restrict, &Tokens[T_RBA_NP]);
    Restrict.Sid = SidRc;
    Ret = Ret && CreateRestrictedToken(hNp, 0, 0, NULL, 1, &ChangeNotify, 1, &Restrict, &Tokens[T_RRC_NP]);
    Ret = Ret && CreateRestrictedToken(hNp, 0, 0, NULL, 0, NULL, 1, &Restrict, &Tokens[T_RRC]);
    Restrict.Sid = Sid33;
    Ret = Ret && CreateRestrictedToken(hNp, WRITE_RESTRICTED, 0, NULL, 1, &ChangeNotify, 1, &Restrict, &Tokens[T_W33_NP]);
    CloseHandle(hImp);
    ok(Ret, "creating the tokens failed with %lu\n", GetLastError());
    return Ret;
}

static VOID
InitName(PUNICODE_STRING Name, OBJECT_ATTRIBUTES *Oa, PWSTR Buffer, PSECURITY_DESCRIPTOR Sd)
{
    RtlInitUnicodeString(Name, Buffer);
    InitializeObjectAttributes(Oa, Name, OBJ_CASE_INSENSITIVE, NULL, Sd);
}

START_TEST(TraverseRestricted)
{
    HANDLE hDirs[VARIANTS] = { 0 }, hEvents[VARIANTS] = { 0 }, hFile;
    PSECURITY_DESCRIPTOR OpenSd = NULL, LeafSd = NULL, Sd = NULL;
    WCHAR Name[100], Path[100];
    UNICODE_STRING Us;
    OBJECT_ATTRIBUTES Oa;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa) };
    NTSTATUS Status;
    INT v, t;
    BOOL Made = TRUE, FileAcls = FALSE;
    DWORD VolumeFlags = 0;

    if (GetVolumeInformationW(L"C:\\", NULL, 0, NULL, NULL, &VolumeFlags, NULL, 0))
        FileAcls = (VolumeFlags & FILE_PERSISTENT_ACLS) != 0;
    if (!MakeTokens())
    {
        skip("no tokens\n");
        return;
    }
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1, &OpenSd, NULL);
    ConvertStringSecurityDescriptorToSecurityDescriptorW(LEAF, SDDL_REVISION_1, &LeafSd, NULL);

    /* the root of the files: everybody may traverse it, so that the rows are decided in the directory below it */
    CreateDirectoryW(L"C:\\RosTraverseTest", NULL);
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;S-1-5-33)(A;;GA;;;RC)", SDDL_REVISION_1, &Sd, NULL);
    SetFileSecurityW(L"C:\\RosTraverseTest", DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, Sd);
    LocalFree(Sd);

    for (v = 0; v < VARIANTS; v++)
    {
        /* made while the directory still lets the administrator in; the variant's descriptor goes on afterwards */
        StringCchPrintfW(Name, ARRAYSIZE(Name), L"\\BaseNamedObjects\\RosTraverseTest%d", v + 1);
        InitName(&Us, &Oa, Name, OpenSd);
        Status = NtCreateDirectoryObject(&hDirs[v], DIRECTORY_ALL_ACCESS, &Oa);
        ok_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
        {
            Made = FALSE;
            break;
        }
        StringCchPrintfW(Name, ARRAYSIZE(Name), L"\\BaseNamedObjects\\RosTraverseTest%d\\ev", v + 1);
        InitName(&Us, &Oa, Name, LeafSd);
        Status = NtCreateEvent(&hEvents[v], EVENT_ALL_ACCESS, &Oa, NotificationEvent, FALSE);
        ok_hex(Status, STATUS_SUCCESS);
        ConvertStringSecurityDescriptorToSecurityDescriptorW(DirSds[v], SDDL_REVISION_1, &Sd, NULL);
        ok(SetKernelObjectSecurity(hDirs[v], DACL_SECURITY_INFORMATION, Sd), "SetKernelObjectSecurity failed with %lu\n", GetLastError());
        LocalFree(Sd);

        StringCchPrintfW(Path, ARRAYSIZE(Path), L"C:\\RosTraverseTest\\%d", v + 1);
        CreateDirectoryW(Path, NULL);
        StringCchCatW(Path, ARRAYSIZE(Path), L"\\leaf.txt");
        Sa.lpSecurityDescriptor = LeafSd;
        hFile = CreateFileW(Path, GENERIC_ALL, 0, &Sa, CREATE_ALWAYS, 0, NULL);
        ok(hFile != INVALID_HANDLE_VALUE, "creating %ls failed with %lu\n", Path, GetLastError());
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"C:\\RosTraverseTest\\%d", v + 1);
        ConvertStringSecurityDescriptorToSecurityDescriptorW(FileSds[v], SDDL_REVISION_1, &Sd, NULL);
        ok(SetFileSecurityW(Path, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, Sd),
           "SetFileSecurity(%ls) failed with %lu\n", Path, GetLastError());
        LocalFree(Sd);
    }

    for (t = 0; Made && t < T_COUNT; t++)
    {
        ok(SetThreadToken(NULL, Tokens[t]), "SetThreadToken failed with %lu\n", GetLastError());
        for (v = 0; v < VARIANTS; v++)
        {
            HANDLE h = NULL;

            if (Expected[t].Dir[v] >= 0)
            {
                StringCchPrintfW(Name, ARRAYSIZE(Name), L"\\BaseNamedObjects\\RosTraverseTest%d\\ev", v + 1);
                InitName(&Us, &Oa, Name, NULL);
                Status = NtOpenEvent(&h, EVENT_QUERY_STATE, &Oa);
                if (Expected[t].Dir[v])
                    ok(Status == STATUS_SUCCESS, "%s: directory v%d: 0x%lx, expected success\n", TokenNames[t], v + 1, Status);
                else
                    ok(Status == STATUS_ACCESS_DENIED, "%s: directory v%d: 0x%lx, expected STATUS_ACCESS_DENIED\n", TokenNames[t], v + 1, Status);
                if (h)
                    NtClose(h);
            }
            if (FileAcls && Expected[t].File[v] >= 0)
            {
                StringCchPrintfW(Path, ARRAYSIZE(Path), L"C:\\RosTraverseTest\\%d\\leaf.txt", v + 1);
                SetLastError(0xdeadbeef);
                hFile = CreateFileW(Path, FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, 0, NULL);
                if (Expected[t].File[v])
                    ok(hFile != INVALID_HANDLE_VALUE, "%s: file v%d: error %lu, expected success\n", TokenNames[t], v + 1, GetLastError());
                else
                {
                    ok(hFile == INVALID_HANDLE_VALUE, "%s: file v%d opened, expected access denied\n", TokenNames[t], v + 1);
                    ok(GetLastError() == ERROR_ACCESS_DENIED, "%s: file v%d: error %lu\n", TokenNames[t], v + 1, GetLastError());
                }
                if (hFile != INVALID_HANDLE_VALUE)
                    CloseHandle(hFile);
            }
        }
        SetThreadToken(NULL, NULL);
    }

    for (v = 0; v < VARIANTS; v++)
    {
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"C:\\RosTraverseTest\\%d\\leaf.txt", v + 1);
        DeleteFileW(Path);
        StringCchPrintfW(Path, ARRAYSIZE(Path), L"C:\\RosTraverseTest\\%d", v + 1);
        RemoveDirectoryW(Path);
        if (hEvents[v])
            NtClose(hEvents[v]);
        if (hDirs[v])
            NtClose(hDirs[v]);
    }
    RemoveDirectoryW(L"C:\\RosTraverseTest");
    LocalFree(OpenSd);
    LocalFree(LeafSd);
    for (t = 0; t < T_COUNT; t++)
        if (Tokens[t])
            CloseHandle(Tokens[t]);
}
