/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The per-user recycle bin folder is open to its owner, SYSTEM and the Administrators only
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"
#include <aclapi.h>
#include <sddl.h>

/* Windows Server 2022 (10.0.20348.587): $Recycle.Bin\<SID> of a user has a protected DACL with exactly three allowed
 * entries, full control (0x1f01ff), inherited by containers and objects (OI|CI), for the user, SYSTEM (S-1-5-18) and
 * the Administrators (S-1-5-32-544). On a volume that stores no ACLs the shared folder is used and has none to check. */

static BOOL VolumeHasAcls(PCWSTR Root)
{
    DWORD Flags = 0;

    return GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, NULL, 0) && (Flags & FILE_PERSISTENT_ACLS);
}

static BOOL UserSidString(PWSTR *StringSid)
{
    HANDLE Token;
    BYTE Buffer[256];
    DWORD Len;
    BOOL Ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Len))
        Ret = ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, StringSid);
    CloseHandle(Token);
    return Ret;
}

START_TEST(RecycleBinAcl)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH + 2], Root[4];
    PWSTR StringSid = NULL;
    SHFILEOPSTRUCTW Op = { 0 };
    HANDLE hFile;
    PACL Dacl = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Revision, Err, i, Seen = 0;
    int Result;

    if (!GetEnvironmentVariableW(L"SystemDrive", Dir, _countof(Dir)))
    {
        skip("no system drive\n");
        return;
    }
    Root[0] = Dir[0]; Root[1] = L':'; Root[2] = L'\\'; Root[3] = 0;
    if (!VolumeHasAcls(Root))
    {
        skip("%ls stores no ACLs: the shared recycle bin folder is used\n", Root);
        return;
    }
    ok(UserSidString(&StringSid), "no SID string, error %lu\n", GetLastError());
    if (!StringSid)
        return;

    /* A file on the system volume, deleted into the bin */
    wsprintfW(Dir, L"%lc:\\RecycleBinAclTest", Root[0]);
    CreateDirectoryW(Dir, NULL);
    wsprintfW(File, L"%ls\\victim.txt", Dir);
    hFile = CreateFileW(File, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "CreateFile failed %lu\n", GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LocalFree(StringSid);
        RemoveDirectoryW(Dir);
        return;
    }
    CloseHandle(hFile);
    File[wcslen(File) + 1] = 0;     /* double-null terminated */
    Op.wFunc = FO_DELETE;
    Op.pFrom = File;
    Op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    Result = SHFileOperationW(&Op);
    ok(Result == 0 && !Op.fAnyOperationsAborted, "SHFileOperation returned %d\n", Result);
    DeleteFileW(File);
    RemoveDirectoryW(Dir);

    wsprintfW(Dir, L"%lc:\\RECYCLER\\%ls", Root[0], StringSid);
    if (GetFileAttributesW(Dir) == INVALID_FILE_ATTRIBUTES)
    {
        skip("%ls does not exist: this system does not use the per-user bin of the volume\n", Dir);
        LocalFree(StringSid);
        return;
    }

    Err = GetNamedSecurityInfoW(Dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    ok(Err == ERROR_SUCCESS, "GetNamedSecurityInfo failed %lu\n", Err);
    if (Err == ERROR_SUCCESS)
    {
        ok(GetSecurityDescriptorControl(Sd, &Control, &Revision), "GetSecurityDescriptorControl failed %lu\n", GetLastError());
        ok(Control & SE_DACL_PROTECTED, "the DACL of the folder is not protected (control 0x%x)\n", Control);
        ok(Dacl != NULL, "no DACL\n");
        if (Dacl)
        {
            ok(Dacl->AceCount == 3, "%u entries in the DACL, expected 3\n", Dacl->AceCount);
            for (i = 0; i < Dacl->AceCount; i++)
            {
                PACCESS_ALLOWED_ACE Ace;
                PWSTR Text = NULL;

                if (!GetAce(Dacl, i, (PVOID *)&Ace))
                    continue;
                ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "entry %lu is of type %u\n", i, Ace->Header.AceType);
                ok((Ace->Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
                   "entry %lu has the flags 0x%x\n", i, Ace->Header.AceFlags);
                ok((Ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "entry %lu has the access 0x%lx\n", i, Ace->Mask);
                if (ConvertSidToStringSidW((PSID)&Ace->SidStart, &Text))
                {
                    if (!wcscmp(Text, StringSid))
                        Seen |= 1;
                    else if (!wcscmp(Text, L"S-1-5-18"))
                        Seen |= 2;
                    else if (!wcscmp(Text, L"S-1-5-32-544"))
                        Seen |= 4;
                    else
                        ok(0, "unexpected entry for %ls\n", Text);
                    LocalFree(Text);
                }
            }
            ok(Seen == 7, "the entries are not the user, SYSTEM and the Administrators (mask %lu)\n", Seen);
        }
        LocalFree(Sd);
    }

    /* The label (measured on the same machine): one mandatory label ACE, Low, NO_WRITE_UP, inherited by containers and
     * objects and inherit-only, i.e. S:AI(ML;OICIIO;NW;;;LW); what is created in the folder inherits it (ML;ID;NW;;;LW) */
    {
        static const PCWSTR Checked[] = { L"", L"\\desktop.ini" };
        UINT n;

        for (n = 0; n < _countof(Checked); n++)
        {
            WCHAR Path[MAX_PATH];
            PACL Sacl = NULL;
            PSECURITY_DESCRIPTOR LabelSd = NULL;
            SYSTEM_MANDATORY_LABEL_ACE *Label = NULL;
            BYTE Flags = n == 0 ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE) : INHERITED_ACE;

            wsprintfW(Path, L"%ls%ls", Dir, Checked[n]);
            if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
                continue;
            Err = GetNamedSecurityInfoW(Path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &Sacl, &LabelSd);
            ok(Err == ERROR_SUCCESS, "%ls: GetNamedSecurityInfo (label) failed %lu\n", Path, Err);
            if (Err != ERROR_SUCCESS)
                continue;
            ok(Sacl != NULL && Sacl->AceCount == 1, "%ls: %u entries in the label ACL, expected 1\n", Path, Sacl ? Sacl->AceCount : 0);
            if (Sacl && Sacl->AceCount == 1 && GetAce(Sacl, 0, (PVOID *)&Label))
            {
                ok(Label->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE, "%ls: label ACE of type %u\n", Path, Label->Header.AceType);
                ok(Label->Header.AceFlags == Flags, "%ls: label ACE flags 0x%x, expected 0x%x\n", Path, Label->Header.AceFlags, Flags);
                ok(Label->Mask == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "%ls: label policy 0x%lx\n", Path, Label->Mask);
                ok(*GetSidSubAuthority((PSID)&Label->SidStart, 0) == SECURITY_MANDATORY_LOW_RID, "%ls: label level 0x%lx\n", Path,
                   *GetSidSubAuthority((PSID)&Label->SidStart, 0));
            }
            LocalFree(LabelSd);
        }
    }
    LocalFree(StringSid);
}
