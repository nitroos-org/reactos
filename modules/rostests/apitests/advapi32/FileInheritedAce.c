/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Descriptors of files and directories created below a directory with an explicit DACL
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022 (NTFS): a DACL given at the create is used as it is and
 * the descriptor is protected; what a file inherits is marked INHERITED_ACE, and the descriptor
 * has SE_DACL_AUTO_INHERITED only when the parent's has it.
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>

static void GetDacl(PSTR Path, PSECURITY_DESCRIPTOR *Sd, PACL *Dacl, SECURITY_DESCRIPTOR_CONTROL *Control)
{
    DWORD Revision, Error;

    *Sd = NULL;
    *Control = 0;
    Error = GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL, Sd);
    ok(Error == ERROR_SUCCESS, "%s: error %lu\n", Path, Error);
    if (*Sd)
        ok(GetSecurityDescriptorControl(*Sd, Control, &Revision), "control\n");
}

static void CheckAces(PACL Dacl, ULONG Count, BOOLEAN Inherited, PCSTR Name)
{
    ACL_SIZE_INFORMATION Info;
    ULONG i;

    ok(Dacl != NULL, "%s: no DACL\n", Name);
    if (!Dacl || !GetAclInformation(Dacl, &Info, sizeof(Info), AclSizeInformation))
        return;
    ok(Info.AceCount == Count, "%s: %lu ACEs, expected %lu\n", Name, Info.AceCount, Count);
    for (i = 0; i < Info.AceCount; i++)
    {
        ACE_HEADER *Ace;
        if (!GetAce(Dacl, i, (PVOID *)&Ace))
            continue;
        ok(!!(Ace->AceFlags & INHERITED_ACE) == Inherited, "%s: ACE %lu flags 0x%x\n", Name, i, Ace->AceFlags);
    }
}

START_TEST(FileInheritedAce)
{
    CHAR Base[MAX_PATH], Dir[MAX_PATH], File[MAX_PATH], Root[4];
    CHAR FsName[MAX_PATH];
    PSECURITY_DESCRIPTOR Sd, Parent;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    SECURITY_DESCRIPTOR_CONTROL Control;
    PACL Dacl;
    HANDLE Handle;

    GetTempPathA(MAX_PATH, Base);
    Root[0] = Base[0];
    strcpy(Root + 1, ":\\");
    if (!GetVolumeInformationA(Root, NULL, 0, NULL, NULL, NULL, FsName, sizeof(FsName)) || strcmp(FsName, "NTFS"))
    {
        skip("The temporary directory is not on NTFS\n");
        return;
    }

    /* A directory with an explicit DACL that is inheritable */
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)", SDDL_REVISION_1,
                                                            &Sa.lpSecurityDescriptor, NULL), "convert\n");
    sprintf(Dir, "%sFileInheritedAce.%lu", Base, GetCurrentProcessId());
    ok(CreateDirectoryA(Dir, &Sa), "CreateDirectory: %lu\n", GetLastError());
    LocalFree(Sa.lpSecurityDescriptor);

    GetDacl(Dir, &Parent, &Dacl, &Control);
    ok((Control & SE_DACL_PROTECTED) != 0, "directory control 0x%x\n", Control);
    ok((Control & SE_DACL_AUTO_INHERITED) == 0, "directory control 0x%x\n", Control);
    CheckAces(Dacl, 2, FALSE, "directory");
    LocalFree(Parent);

    /* A file without a descriptor: the ACEs are inherited and marked, the control bit is not set */
    sprintf(File, "%s\\plain.txt", Dir);
    Handle = CreateFileA(File, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFile: %lu\n", GetLastError());
    CloseHandle(Handle);
    GetDacl(File, &Sd, &Dacl, &Control);
    ok((Control & SE_DACL_PROTECTED) == 0, "file control 0x%x\n", Control);
    ok((Control & SE_DACL_AUTO_INHERITED) == 0, "file control 0x%x\n", Control);
    CheckAces(Dacl, 2, TRUE, "file");
    LocalFree(Sd);
    DeleteFileA(File);

    /* A subdirectory keeps the inheritable flags on the inherited ACEs */
    sprintf(File, "%s\\sub", Dir);
    ok(CreateDirectoryA(File, NULL), "CreateDirectory: %lu\n", GetLastError());
    GetDacl(File, &Sd, &Dacl, &Control);
    ok((Control & SE_DACL_PROTECTED) == 0, "subdirectory control 0x%x\n", Control);
    CheckAces(Dacl, 2, TRUE, "subdirectory");
    LocalFree(Sd);
    RemoveDirectoryA(File);

    /* A file with a DACL of its own: used as it is, protected, nothing inherited */
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;;GA;;;BA)", SDDL_REVISION_1,
                                                            &Sa.lpSecurityDescriptor, NULL), "convert\n");
    sprintf(File, "%s\\own.txt", Dir);
    Handle = CreateFileA(File, GENERIC_WRITE, 0, &Sa, CREATE_NEW, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFile: %lu\n", GetLastError());
    CloseHandle(Handle);
    LocalFree(Sa.lpSecurityDescriptor);
    GetDacl(File, &Sd, &Dacl, &Control);
    ok((Control & SE_DACL_PROTECTED) != 0, "file control 0x%x\n", Control);
    CheckAces(Dacl, 1, FALSE, "own file");
    LocalFree(Sd);
    DeleteFileA(File);

    RemoveDirectoryA(Dir);
}
