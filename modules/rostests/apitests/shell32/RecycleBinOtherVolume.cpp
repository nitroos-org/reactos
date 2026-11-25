/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The recycle bin folder that the shell makes on a volume other than the system volume
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"
#include <aclapi.h>
#include <sddl.h>

/* Windows Server 2022 (10.0.20348.587), a second NTFS volume, the first deletion on it made by a standard user and
 * by an administrator (the same rows): the folder $Recycle.Bin is made by the shell in the process of the user, so
 * the creator owns it, and it does not have the descriptor of the volume root:
 *   D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;NP;0x1201ad;;;BU)S:AI(ML;OICIIO;NW;;;LW)
 * The test needs a fixed volume with ACLs that is not the system volume and has no bin yet; without one it skips
 * (a bin is not removed afterwards: it is not the test's to remove). */

static BOOL VolumeHasAcls(PCWSTR Root)
{
    DWORD Flags = 0;

    return GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, NULL, 0) && (Flags & FILE_PERSISTENT_ACLS);
}

static void CheckAce(PACL Dacl, DWORD Index, PSID Expected, BYTE Flags, ACCESS_MASK Mask, PCSTR Name)
{
    PACCESS_ALLOWED_ACE Ace = NULL;

    ok(GetAce(Dacl, Index, (PVOID *)&Ace) && Ace, "%s: no entry %lu\n", Name, Index);
    if (!Ace)
        return;
    ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "%s: entry %lu is of type %u\n", Name, Index, Ace->Header.AceType);
    ok(EqualSid((PSID)&Ace->SidStart, Expected), "%s: entry %lu is for another SID\n", Name, Index);
    ok(Ace->Header.AceFlags == Flags, "%s: entry %lu has the flags 0x%x, expected 0x%x\n", Name, Index, Ace->Header.AceFlags, Flags);
    ok(Ace->Mask == Mask || (Mask == FILE_ALL_ACCESS && (Ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS),
       "%s: entry %lu has the access 0x%lx, expected 0x%lx\n", Name, Index, Ace->Mask, Mask);
}

START_TEST(RecycleBinOtherVolume)
{
    WCHAR SystemDrive[MAX_PATH], Root[4], Dir[MAX_PATH], File[MAX_PATH + 2], Bin[MAX_PATH];
    DWORD Drives = GetLogicalDrives(), Letter, Err, Revision;
    SHFILEOPSTRUCTW Op = { 0 };
    SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    PSID Admins = NULL, System = NULL, Users = NULL, Owner = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL, LabelSd = NULL;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PACL Dacl = NULL, Sacl = NULL;
    HANDLE hFile, Token;
    BYTE Buffer[256];
    DWORD Len;
    WCHAR Chosen = 0;
    int Result;

    if (!GetEnvironmentVariableW(L"SystemDrive", SystemDrive, _countof(SystemDrive)))
        SystemDrive[0] = L'C';

    for (Letter = 0; Letter < 26 && !Chosen; Letter++)
    {
        if (!(Drives & (1 << Letter)) || (WCHAR)(L'A' + Letter) == (WCHAR)towupper(SystemDrive[0]))
            continue;
        Root[0] = (WCHAR)(L'A' + Letter); Root[1] = L':'; Root[2] = L'\\'; Root[3] = 0;
        if (GetDriveTypeW(Root) != DRIVE_FIXED || !VolumeHasAcls(Root))
            continue;
        wsprintfW(Bin, L"%ls%ls", Root, L"RECYCLER");
        if (GetFileAttributesW(Bin) != INVALID_FILE_ATTRIBUTES)
            continue;
        Chosen = Root[0];
    }
    if (!Chosen)
    {
        skip("no fixed volume with ACLs other than the system volume that has no recycle bin yet\n");
        return;
    }
    Root[0] = Chosen;
    wsprintfW(Bin, L"%lc:\\RECYCLER", Chosen);

    wsprintfW(Dir, L"%lc:\\RecycleBinOtherVolumeTest", Chosen);
    CreateDirectoryW(Dir, NULL);
    wsprintfW(File, L"%ls\\victim.txt", Dir);
    hFile = CreateFileW(File, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "CreateFile(%ls) failed %lu\n", File, GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
    {
        RemoveDirectoryW(Dir);
        skip("cannot make a file on %ls\n", Root);
        return;
    }
    CloseHandle(hFile);
    File[wcslen(File) + 1] = 0;
    Op.wFunc = FO_DELETE;
    Op.pFrom = File;
    Op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    Result = SHFileOperationW(&Op);
    ok(Result == 0 && !Op.fAnyOperationsAborted, "SHFileOperation returned %d\n", Result);
    DeleteFileW(File);
    RemoveDirectoryW(Dir);

    if (GetFileAttributesW(Bin) == INVALID_FILE_ATTRIBUTES)
    {
        skip("%ls was not made: this system does not use a bin folder on the volume\n", Bin);
        return;
    }

    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins);
    AllocateAndInitializeSid(&Nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &System);
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &Users);

    /* The creator owns it: the owner of the token of this process */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        if (GetTokenInformation(Token, TokenOwner, Buffer, sizeof(Buffer), &Len))
            Owner = ((PTOKEN_OWNER)Buffer)->Owner;
    }

    {
        PSID OwnerOfBin = NULL;

        Err = GetNamedSecurityInfoW(Bin, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                    &OwnerOfBin, NULL, &Dacl, NULL, &Sd);
        ok(Err == ERROR_SUCCESS, "GetNamedSecurityInfo(%ls) failed %lu\n", Bin, Err);
        if (Err == ERROR_SUCCESS)
        {
            ok(Owner && OwnerOfBin && EqualSid(OwnerOfBin, Owner), "the owner of %ls is not the creator\n", Bin);
            ok(GetSecurityDescriptorControl(Sd, &Control, &Revision) && (Control & SE_DACL_PROTECTED),
               "the DACL is not protected (control 0x%x)\n", Control);
            ok(Dacl != NULL && Dacl->AceCount == 3, "%u entries in the DACL, expected 3\n", Dacl ? Dacl->AceCount : 0);
            if (Dacl && Dacl->AceCount == 3)
            {
                CheckAce(Dacl, 0, Admins, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, "Administrators");
                CheckAce(Dacl, 1, System, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, "SYSTEM");
                CheckAce(Dacl, 2, Users, NO_PROPAGATE_INHERIT_ACE, 0x1201ad, "Users");
            }
        }
    }

    Err = GetNamedSecurityInfoW(Bin, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &Sacl, &LabelSd);
    ok(Err == ERROR_SUCCESS, "GetNamedSecurityInfo(%ls, label) failed %lu\n", Bin, Err);
    if (Err == ERROR_SUCCESS)
    {
        SYSTEM_MANDATORY_LABEL_ACE *Label = NULL;

        ok(Sacl != NULL && Sacl->AceCount == 1, "%u entries in the label ACL, expected 1\n", Sacl ? Sacl->AceCount : 0);
        if (Sacl && Sacl->AceCount == 1 && GetAce(Sacl, 0, (PVOID *)&Label))
        {
            ok(Label->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE, "label ACE of type %u\n", Label->Header.AceType);
            ok(Label->Header.AceFlags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE),
               "label ACE flags 0x%x\n", Label->Header.AceFlags);
            ok(Label->Mask == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "label policy 0x%lx\n", Label->Mask);
            ok(*GetSidSubAuthority((PSID)&Label->SidStart, 0) == SECURITY_MANDATORY_LOW_RID, "label level 0x%lx\n",
               *GetSidSubAuthority((PSID)&Label->SidStart, 0));
        }
    }

    LocalFree(Sd);
    LocalFree(LabelSd);
    FreeSid(Admins);
    FreeSid(System);
    FreeSid(Users);
}
