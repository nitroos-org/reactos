/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: descriptors of new files and directories inherit from their directory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

/* The owner of Path (a copy in Owner, SECURITY_MAX_SID_SIZE bytes). */
static BOOLEAN GetOwner(PCWSTR Path, PSID Owner)
{
    UCHAR Buffer[512];
    PSID Sid;
    BOOLEAN Defaulted;
    ULONG Len;
    HANDLE H;
    BOOLEAN Ok = FALSE;
    if (!NT_SUCCESS(NtOpen(Path, READ_CONTROL, SHARE_ALL, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, NULL, &H)))
        return FALSE;
    if (NT_SUCCESS(NtQuerySecurityObject(H, OWNER_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Len)) &&
        NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Buffer, &Sid, &Defaulted)) && Sid)
        Ok = CopySid(SECURITY_MAX_SID_SIZE, Owner, Sid);
    NtClose(H);
    return Ok;
}

static VOID TestInherit(PCWSTR Base)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH], Sub[MAX_PATH], SubFile[MAX_PATH], Explicit[MAX_PATH], Prot[MAX_PATH];
    WCHAR NoInh[MAX_PATH], NoInhFile[MAX_PATH], UserFile[MAX_PATH];
    UCHAR Owner[SECURITY_MAX_SID_SIZE], UserOwner[SECURITY_MAX_SID_SIZE];
    CHAR Text[1024];
    NT_ACE Aces[5];
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    LONG i;
    /* With a directory whose stored DACL is not marked SE_DACL_AUTO_INHERITED, a create inherits
     * ACEs unmarked and an explicit DACL replaces them (Windows Server 2008 R2 and Windows 10 22H2).
     * Neither version stores the mark from a caller's descriptor (SE_DACL_AUTO_INHERITED or
     * SE_DACL_AUTO_INHERIT_REQ, at create or by NtSetSecurityObject); TestAutoInherited covers a
     * directory that inherited the mark. */
    const BYTE Inh = 0;
    const BYTE AllFlags = 0x1f;
    WCHAR Name[64];

#define NT_SUB(Var, Rel) (_snwprintf(Name, RTL_NUMBER_OF(Name) - 1, L"%ls\\%ls", Base, Rel), Name[RTL_NUMBER_OF(Name) - 1] = 0, NtPath(Var, Name))
    NT_SUB(Dir, L"");
    Dir[wcslen(Dir) - 1] = 0;
    NT_SUB(File, L"file.txt");
    NT_SUB(Sub, L"sub");
    NT_SUB(SubFile, L"sub\\file.txt");
    NT_SUB(Explicit, L"explicit.txt");
    NT_SUB(Prot, L"protected.txt");
    NT_SUB(UserFile, L"byuser.txt");
    NT_SUB(NoInh, L"noinh");
    NT_SUB(NoInhFile, L"noinh\\file.txt");

    /* inh: administrators full (inherited by all), the user reads files, CREATOR OWNER full,
     * Everyone may execute in subdirectories only (one level), the user may add files here. */
    Aces[0].Sid = SidAdmins; Aces[0].Mask = FILE_ALL_ACCESS; Aces[0].Flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE; Aces[0].Deny = FALSE;
    Aces[1].Sid = SidUser; Aces[1].Mask = FILE_GENERIC_READ; Aces[1].Flags = OBJECT_INHERIT_ACE; Aces[1].Deny = FALSE;
    Aces[2].Sid = SidCreatorOwner; Aces[2].Mask = GENERIC_ALL;
    Aces[2].Flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE; Aces[2].Deny = FALSE;
    Aces[3].Sid = SidEveryone; Aces[3].Mask = FILE_GENERIC_EXECUTE;
    Aces[3].Flags = CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE; Aces[3].Deny = FALSE;
    Aces[4].Sid = SidUser; Aces[4].Mask = FILE_ADD_FILE | FILE_TRAVERSE | FILE_LIST_DIRECTORY | SYNCHRONIZE; Aces[4].Flags = 0; Aces[4].Deny = FALSE;
    ok_hex(NtMakeDirControl(Dir, Aces, 5, SE_DACL_PROTECTED), STATUS_SUCCESS);
    ok_hex(NtMakeFile(File, NULL, 0, FALSE, "file"), STATUS_SUCCESS);
    ok_hex(NtMakeDir(Sub, NULL, 0, FALSE), STATUS_SUCCESS);
    ok_hex(NtMakeFile(SubFile, NULL, 0, FALSE, "subfile"), STATUS_SUCCESS);

    /* A file: the effective ACEs inherited by files, CREATOR OWNER replaced by the owner, generic rights mapped. */
    ok(GetOwner(File, (PSID)Owner), "No owner\n");
    Dacl = NtGetDacl(File, Text, sizeof(Text), &Sd);
    trace("file.txt: %s\n", Text);
    ok(Dacl != NULL, "No DACL\n");
    ok(NtFindAce(Dacl, SidAdmins, FILE_ALL_ACCESS, AllFlags, Inh, FALSE) >= 0, "No inherited administrators ACE\n");
    ok(NtFindAce(Dacl, SidUser, FILE_GENERIC_READ, AllFlags, Inh, FALSE) >= 0, "No inherited user read ACE\n");
    ok(NtFindAce(Dacl, (PSID)Owner, FILE_ALL_ACCESS, AllFlags, Inh, FALSE) >= 0, "No owner ACE from CREATOR OWNER\n");
    ok(NtFindAce(Dacl, SidCreatorOwner, GENERIC_ALL, 0, 0, FALSE) < 0, "CREATOR OWNER ACE on a file\n");
    ok(NtFindAce(Dacl, SidEveryone, FILE_GENERIC_EXECUTE, 0, 0, FALSE) < 0, "Container-only ACE on a file\n");
    ok(NtFindAce(Dacl, SidUser, FILE_ADD_FILE | FILE_TRAVERSE | FILE_LIST_DIRECTORY | SYNCHRONIZE, 0, 0, FALSE) < 0,
       "Non-inheritable ACE inherited\n");
    if (Dacl)
        ok(Dacl->AceCount == 3 || (Dacl->AceCount == 2 && EqualSid((PSID)Owner, SidAdmins)),
           "file.txt has %u ACEs\n", Dacl->AceCount);   /* Windows 10 merges the owner ACE with an equal one */
    if (Sd)
    {
        SECURITY_DESCRIPTOR_CONTROL Control = 0;
        ULONG Rev;
        RtlGetControlSecurityDescriptor(Sd, &Control, &Rev);
        ok((Control & SE_DACL_AUTO_INHERITED) == 0, "SE_DACL_AUTO_INHERITED 0x%04x\n", Control);
        ok((Control & SE_DACL_PROTECTED) == 0, "SE_DACL_PROTECTED set\n");
        LocalFree(Sd);
    }

    /* A subdirectory: container ACEs stay inheritable, NO_PROPAGATE ones become effective only. */
    Dacl = NtGetDacl(Sub, Text, sizeof(Text), &Sd);
    trace("sub: %s\n", Text);
    ok(NtFindAce(Dacl, SidAdmins, FILE_ALL_ACCESS, AllFlags, Inh | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FALSE) >= 0,
       "No inherited inheritable administrators ACE\n");
    ok(NtFindAce(Dacl, SidUser, FILE_GENERIC_READ, AllFlags, Inh | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE, FALSE) >= 0,
       "No inherit-only user ACE for files below\n");
    ok(NtFindAce(Dacl, SidEveryone, FILE_GENERIC_EXECUTE, AllFlags, Inh, FALSE) >= 0, "No one-level Everyone ACE\n");
    ok(NtFindAce(Dacl, (PSID)Owner, FILE_ALL_ACCESS, AllFlags, Inh, FALSE) >= 0, "No effective owner ACE\n");
    ok(NtFindAce(Dacl, SidCreatorOwner, GENERIC_ALL, AllFlags,
                 Inh | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, FALSE) >= 0,
       "No inherit-only CREATOR OWNER ACE\n");
    if (Sd)
        LocalFree(Sd);

    /* Two levels down: the NO_PROPAGATE ACE is gone, the user's file ACE arrives through the inherit-only one. */
    Dacl = NtGetDacl(SubFile, Text, sizeof(Text), &Sd);
    trace("sub\\file.txt: %s\n", Text);
    ok(NtFindAce(Dacl, SidUser, FILE_GENERIC_READ, AllFlags, Inh, FALSE) >= 0, "No user read ACE two levels down\n");
    ok(NtFindAce(Dacl, SidEveryone, FILE_GENERIC_EXECUTE, 0, 0, FALSE) < 0, "NO_PROPAGATE ACE propagated\n");
    if (Sd)
        LocalFree(Sd);

    /* An explicit descriptor at create: its ACEs first, then the inherited ones (unless protected). */
    Aces[0].Sid = SidEveryone; Aces[0].Mask = FILE_GENERIC_READ; Aces[0].Flags = 0; Aces[0].Deny = FALSE;
    Sd = NtMakeSd(Aces, 1, FALSE);
    ok_hex(NtOpen(Explicit, FILE_GENERIC_WRITE, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, Sd, NULL), STATUS_SUCCESS);
    LocalFree(Sd);
    Dacl = NtGetDacl(Explicit, Text, sizeof(Text), &Sd);
    trace("explicit.txt: %s\n", Text);
    i = NtFindAce(Dacl, SidEveryone, FILE_GENERIC_READ, AllFlags, 0, FALSE);
    ok(i == 0, "Explicit ACE at %ld\n", i);
    ok(Dacl && Dacl->AceCount == 1, "explicit.txt has %u ACEs\n", Dacl ? Dacl->AceCount : 0);
    if (Sd)
        LocalFree(Sd);
    Sd = NtMakeSd(Aces, 1, TRUE);
    ok_hex(NtOpen(Prot, FILE_GENERIC_WRITE, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, Sd, NULL), STATUS_SUCCESS);
    LocalFree(Sd);
    Dacl = NtGetDacl(Prot, Text, sizeof(Text), &Sd);
    trace("protected.txt: %s\n", Text);
    ok(Dacl && Dacl->AceCount == 1, "Protected DACL has %u ACEs\n", Dacl ? Dacl->AceCount : 0);
    if (Sd)
        LocalFree(Sd);

    /* What inheritance grants is enforced: the user reads file.txt but may not write it, and the
     * user's own new file is the user's (CREATOR OWNER full access). */
    NtBeginUser();
    ok_hex(NtOpen(File, FILE_GENERIC_READ, SHARE_ALL, FILE_OPEN, 0, NULL, NULL), STATUS_SUCCESS);
    ok_hex(NtOpen(File, FILE_WRITE_DATA, SHARE_ALL, FILE_OPEN, 0, NULL, NULL), STATUS_ACCESS_DENIED);
    ok_hex(NtOpen(UserFile, FILE_GENERIC_WRITE, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, NULL), STATUS_SUCCESS);
    ok_hex(NtOpen(UserFile, FILE_GENERIC_WRITE | DELETE | WRITE_DAC, SHARE_ALL, FILE_OPEN, 0, NULL, NULL), STATUS_SUCCESS);
    NtEndUser();
    ok(GetOwner(UserFile, (PSID)UserOwner), "No owner\n");
    ok(EqualSid((PSID)UserOwner, SidUser), "The user's file is not owned by the user\n");

    /* A directory without inheritable ACEs: the new file gets the creator's default DACL. */
    Aces[0].Sid = SidAdmins; Aces[0].Mask = FILE_ALL_ACCESS; Aces[0].Flags = 0; Aces[0].Deny = FALSE;
    ok_hex(NtMakeDirControl(NoInh, Aces, 1, SE_DACL_PROTECTED), STATUS_SUCCESS);
    ok_hex(NtMakeFile(NoInhFile, NULL, 0, FALSE, "x"), STATUS_SUCCESS);
    Dacl = NtGetDacl(NoInhFile, Text, sizeof(Text), &Sd);
    trace("noinh\\file.txt: %s\n", Text);
    ok(Dacl != NULL && Dacl->AceCount > 0, "No default DACL\n");
    ok(NtFindAce(Dacl, SidEveryone, FILE_ALL_ACCESS, 0, 0, FALSE) < 0, "Everyone full access on a new file\n");
    if (Sd)
        LocalFree(Sd);
#undef NT_SUB
}

/* Self-relative descriptor (LocalFree) with the given parts; a NULL Dacl with DaclPresent is a NULL DACL. */
static PSECURITY_DESCRIPTOR MakeSdParts(PSID Owner, BOOLEAN DaclPresent, PACL Dacl, BOOLEAN DaclDefaulted, PACL Sacl)
{
    SECURITY_DESCRIPTOR Abs;
    DWORD Size = 0;
    PSECURITY_DESCRIPTOR Rel;
    InitializeSecurityDescriptor(&Abs, SECURITY_DESCRIPTOR_REVISION);
    if (Owner)
        SetSecurityDescriptorOwner(&Abs, Owner, FALSE);
    if (DaclPresent)
        SetSecurityDescriptorDacl(&Abs, TRUE, Dacl, DaclDefaulted);
    if (Sacl)
        SetSecurityDescriptorSacl(&Abs, TRUE, Sacl, FALSE);
    MakeSelfRelativeSD(&Abs, NULL, &Size);
    Rel = LocalAlloc(LMEM_FIXED, Size);
    if (Rel && !MakeSelfRelativeSD(&Abs, Rel, &Size))
    {
        LocalFree(Rel);
        Rel = NULL;
    }
    return Rel;
}

/* The control word of Path's descriptor and a copy of its SACL (LocalFree, NULL if none). */
static PACL GetSacl(PCWSTR Path, SECURITY_DESCRIPTOR_CONTROL *Control)
{
    UCHAR Buffer[1024];
    BOOLEAN Present = FALSE, Defaulted;
    PACL Sacl = NULL, Copy = NULL;
    ULONG Len, Rev;
    HANDLE H;

    *Control = 0;
    if (!NT_SUCCESS(NtOpen(Path, ACCESS_SYSTEM_SECURITY, SHARE_ALL, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, NULL, &H)))
        return NULL;
    if (NT_SUCCESS(NtQuerySecurityObject(H, SACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Len)))
    {
        RtlGetControlSecurityDescriptor(Buffer, Control, &Rev);
        if (NT_SUCCESS(RtlGetSaclSecurityDescriptor(Buffer, &Present, &Sacl, &Defaulted)) && Present && Sacl)
        {
            Copy = LocalAlloc(LMEM_FIXED, Sacl->AclSize);
            if (Copy)
                RtlCopyMemory(Copy, Sacl, Sacl->AclSize);
        }
    }
    NtClose(H);
    return Copy;
}

/* Number of ACEs of Acl whose flags have all of Set and none of Clear. */
static ULONG CountAces(PACL Acl, BYTE Set, BYTE Clear)
{
    ULONG i, n = 0;
    for (i = 0; Acl && i < Acl->AceCount; i++)
    {
        PACE_HEADER Ace;
        if (GetAce(Acl, i, (PVOID *)&Ace) && (Ace->AceFlags & Set) == Set && !(Ace->AceFlags & Clear))
            n++;
    }
    return n;
}

/*
 * A directory created without a descriptor below an auto-inherited directory (on Windows, the
 * volume's tree) is auto-inherited itself.  Below it, Windows Server 2008 R2 and Windows 10 22H2:
 * - a create that supplies no DACL (no descriptor, an owner only, a SACL only) gets the inherited
 *   ACEs marked INHERITED_ACE and a DACL marked SE_DACL_AUTO_INHERITED;
 * - a create that supplies a DACL gets exactly that DACL: no inherited ACEs are added, a creator ACE
 *   already marked INHERITED_ACE stays, and the DACL is not marked auto-inherited;
 * - a defaulted DACL gives way to the inherited ACEs, which are then not marked;
 * - a SACL set on the directory is not marked auto-inherited (also with SE_SACL_AUTO_INHERIT_REQ),
 *   so a new file inherits its ACEs unmarked.
 * Where the test directory's tree is not auto-inherited (a volume whose root is not marked), only
 * the cases that do not depend on the mark run.  Control bits are checked where the query returns
 * them (ReactOS' SeQuerySecurityDescriptorInfo drops SE_DACL_AUTO_INHERITED and SE_DACL_PROTECTED).
 */
static VOID TestAutoInherited(VOID)
{
    WCHAR Dir[MAX_PATH], P[MAX_PATH];
    UCHAR DaclBuf[128], SaclBuf[128], SaclInhBuf[128];
    PACL Dacl = (PACL)DaclBuf, Sacl = (PACL)SaclBuf, SaclInh = (PACL)SaclInhBuf, Acl;
    CHAR Text[1024];
    PSECURITY_DESCRIPTOR Sd, Got;
    SECURITY_DESCRIPTOR_CONTROL Control = 0, DirControl;
    BOOLEAN Marked, HaveSacl = FALSE;
    ULONG Rev;
    HANDLE H;
    NT_ACE Ace[2];

#define AUTO_PATH(Name) (_snwprintf(P, MAX_PATH - 1, L"%ls\\%ls", Dir, Name), P[MAX_PATH - 1] = 0, P)
#define CONTROL_OF(SdVar) (SdVar ? (RtlGetControlSecurityDescriptor(SdVar, &Control, &Rev), Control) : 0)
    _snwprintf(Dir, MAX_PATH - 1, L"%ls-auto", NtTestDir());
    Dir[MAX_PATH - 1] = 0;
    NtRemove(Dir);
    ok_hex(NtOpen(Dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, SHARE_ALL, FILE_CREATE,
                  FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL), STATUS_SUCCESS);
    /* Marked: its own ACEs came from a marked parent (ReactOS does not return SE_DACL_AUTO_INHERITED). */
    Acl = NtGetDacl(Dir, Text, sizeof(Text), &Got);
    DirControl = CONTROL_OF(Got);
    Marked = Acl && Acl->AceCount > 0 && CountAces(Acl, INHERITED_ACE, 0) == Acl->AceCount;
    trace("auto directory: %s\n", Text);
    if (DirControl & SE_DACL_AUTO_INHERITED)
        ok(Marked, "Auto-inherited directory with unmarked ACEs\n");
    if (Got)
        LocalFree(Got);

    /* A mask no volume tree passes on, so a kept creator ACE is not mistaken for an inherited one. */
    InitializeAcl(Dacl, sizeof(DaclBuf), ACL_REVISION);
    AddAccessAllowedAceEx(Dacl, ACL_REVISION, 0, FILE_READ_EA | FILE_WRITE_EA, SidEveryone);
    InitializeAcl(Sacl, sizeof(SaclBuf), ACL_REVISION);
    AddAuditAccessAce(Sacl, ACL_REVISION, FILE_READ_DATA, SidEveryone, TRUE, FALSE);
    InitializeAcl(SaclInh, sizeof(SaclInhBuf), ACL_REVISION);
    AddAuditAccessAce(SaclInh, ACL_REVISION, FILE_WRITE_DATA, SidEveryone, TRUE, TRUE);
    ((PACE_HEADER)(SaclInh + 1))->AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

    /* An explicit DACL is kept as given, with its pre-marked ACE. */
    Ace[0].Sid = SidEveryone; Ace[0].Mask = FILE_GENERIC_READ; Ace[0].Flags = 0; Ace[0].Deny = FALSE;
    Ace[1].Sid = SidSystem; Ace[1].Mask = FILE_ALL_ACCESS; Ace[1].Flags = INHERITED_ACE; Ace[1].Deny = FALSE;
    Sd = NtMakeSd(Ace, 2, FALSE);
    ok_hex(NtOpen(AUTO_PATH(L"explicit.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, Sd, NULL), STATUS_SUCCESS);
    LocalFree(Sd);
    Acl = NtGetDacl(P, Text, sizeof(Text), &Got);
    trace("auto\\explicit.txt: %s\n", Text);
    ok(Acl && Acl->AceCount == 2, "explicit.txt has %u ACEs\n", Acl ? Acl->AceCount : 0);
    ok(NtFindAce(Acl, SidEveryone, FILE_GENERIC_READ, 0xff, 0, FALSE) == 0, "No unmarked explicit ACE first\n");
    ok(NtFindAce(Acl, SidSystem, FILE_ALL_ACCESS, 0xff, INHERITED_ACE, FALSE) == 1, "The pre-marked creator ACE is gone\n");
    ok((CONTROL_OF(Got) & SE_DACL_AUTO_INHERITED) == 0, "explicit.txt: SE_DACL_AUTO_INHERITED 0x%04x\n", Control);
    if (Got)
        LocalFree(Got);

    /* A defaulted DACL gives way to inheritance without marks. */
    Sd = MakeSdParts(NULL, TRUE, Dacl, TRUE, NULL);
    ok_hex(NtOpen(AUTO_PATH(L"defaulted.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, Sd, NULL), STATUS_SUCCESS);
    LocalFree(Sd);
    Acl = NtGetDacl(P, Text, sizeof(Text), &Got);
    trace("auto\\defaulted.txt: %s\n", Text);
    ok(Acl && Acl->AceCount > 0, "defaulted.txt has no ACEs\n");
    ok(NtFindAce(Acl, SidEveryone, FILE_READ_EA | FILE_WRITE_EA, 0, 0, FALSE) < 0, "The defaulted DACL was kept\n");
    ok(CountAces(Acl, INHERITED_ACE, 0) == 0, "defaulted.txt has %lu marked ACEs\n", CountAces(Acl, INHERITED_ACE, 0));
    ok((CONTROL_OF(Got) & SE_DACL_AUTO_INHERITED) == 0, "defaulted.txt: SE_DACL_AUTO_INHERITED 0x%04x\n", Control);
    if (Got)
        LocalFree(Got);

    /* A SACL set on the directory, with and without the request bit, is inherited unmarked. */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &H))
    {
        HaveSacl = NtSetPrivilege(H, L"SeSecurityPrivilege", TRUE);
        CloseHandle(H);
    }
    if (!HaveSacl)
    {
        skip("SeSecurityPrivilege not available\n");
    }
    else
    {
        static const SECURITY_DESCRIPTOR_CONTROL Req[] = { 0, SE_SACL_AUTO_INHERIT_REQ };
        static const PCWSTR Names[] = { L"sacl.txt", L"saclreq.txt" };
        ULONG i;
        for (i = 0; i < RTL_NUMBER_OF(Req); i++)
        {
            Sd = MakeSdParts(NULL, FALSE, NULL, FALSE, SaclInh);
            if (Req[i])
                SetSecurityDescriptorControl(Sd, Req[i], Req[i]);
            ok_hex(NtOpen(Dir, ACCESS_SYSTEM_SECURITY, SHARE_ALL, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, NULL, &H), STATUS_SUCCESS);
            ok_hex(NtSetSecurityObject(H, SACL_SECURITY_INFORMATION, Sd), STATUS_SUCCESS);
            NtClose(H);
            LocalFree(Sd);
            Acl = GetSacl(Dir, &Control);
            ok((Control & SE_SACL_AUTO_INHERITED) == 0, "SACL set (0x%x): SE_SACL_AUTO_INHERITED 0x%04x\n", Req[i], Control);
            if (Acl)
                LocalFree(Acl);
            ok_hex(NtMakeFile(AUTO_PATH(Names[i]), NULL, 0, FALSE, "s"), STATUS_SUCCESS);
            Acl = GetSacl(P, &Control);
            ok(Acl && Acl->AceCount == 1, "%ls: %u SACL ACEs\n", Names[i], Acl ? Acl->AceCount : 0);
            ok(Acl && CountAces(Acl, SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG, VALID_INHERIT_FLAGS) == 1,
               "%ls: the inherited audit ACE is marked or missing\n", Names[i]);
            ok((Control & SE_SACL_AUTO_INHERITED) == 0, "%ls: SE_SACL_AUTO_INHERITED 0x%04x\n", Names[i], Control);
            if (Acl)
                LocalFree(Acl);
        }
    }

    if (!Marked)
    {
        skip("%ls is not auto-inherited (control 0x%04x): marking below it is not tested\n", Dir, DirControl);
    }
    else
    {
        /* No DACL supplied: inherited ACEs marked, the DACL marked auto-inherited.  The SACL-only sets
         * above must not have cleared the directory's mark. */
        static const PCWSTR Names[] = { L"none.txt", L"owner.txt", L"saclonly.txt", L"none" };
        ULONG i;
        for (i = 0; i < RTL_NUMBER_OF(Names); i++)
        {
            BOOLEAN IsDir = (i == 3);
            Sd = NULL;
            if (i == 1)
                Sd = MakeSdParts(SidAdmins, FALSE, NULL, FALSE, NULL);
            else if (i == 2)
                Sd = HaveSacl ? MakeSdParts(NULL, FALSE, NULL, FALSE, Sacl) : NULL;
            if (i == 2 && !Sd)
                continue;
            ok_hex(NtOpen(AUTO_PATH(Names[i]), (IsDir ? (FILE_LIST_DIRECTORY | SYNCHRONIZE) : FILE_GENERIC_WRITE) |
                          (i == 2 ? ACCESS_SYSTEM_SECURITY : 0),
                          SHARE_ALL, FILE_CREATE,
                          (IsDir ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) | FILE_SYNCHRONOUS_IO_NONALERT, Sd, NULL),
                   STATUS_SUCCESS);
            if (Sd)
                LocalFree(Sd);
            Acl = NtGetDacl(P, Text, sizeof(Text), &Got);
            trace("auto\\%ls: %s\n", Names[i], Text);
            ok(Acl && Acl->AceCount > 0 && CountAces(Acl, INHERITED_ACE, 0) == Acl->AceCount,
               "%ls: %lu of %u ACEs marked\n", Names[i], CountAces(Acl, INHERITED_ACE, 0), Acl ? Acl->AceCount : 0);
            if (DirControl & SE_DACL_AUTO_INHERITED)
                ok((CONTROL_OF(Got) & SE_DACL_AUTO_INHERITED) != 0, "%ls: SE_DACL_AUTO_INHERITED not set (0x%04x)\n",
                   Names[i], Control);
            if (Got)
                LocalFree(Got);
        }
    }
    if (HaveSacl && OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &H))
    {
        NtSetPrivilege(H, L"SeSecurityPrivilege", FALSE);
        CloseHandle(H);
    }
    NtRemove(Dir);
#undef CONTROL_OF
#undef AUTO_PATH
}

/*
 * The descriptor a create inherits is the directory's CURRENT one: NTFS-NG keeps the descriptors it read lately, and
 * a change of the directory's descriptor (NtSetSecurityObject), or a directory that is deleted and made again, must
 * not leave the old one behind for the next create.
 */
static VOID TestInheritAfterChange(PCWSTR Base)
{
    WCHAR Dir[MAX_PATH], F1[MAX_PATH], F2[MAX_PATH], F3[MAX_PATH], F4[MAX_PATH];
    WCHAR Name[64];
    NT_ACE Aces[2];
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    CHAR Text[1024];
    HANDLE H;
    const BYTE AllFlags = 0x1f;
    ULONG i;

#define CHG_SUB(Var, Rel) (_snwprintf(Name, RTL_NUMBER_OF(Name) - 1, L"%ls-chg\\%ls", Base, Rel), Name[RTL_NUMBER_OF(Name) - 1] = 0, NtPath(Var, Name))
    CHG_SUB(Dir, L"");
    Dir[wcslen(Dir) - 1] = 0;
    CHG_SUB(F1, L"f1.txt");
    CHG_SUB(F2, L"f2.txt");
    CHG_SUB(F3, L"f3.txt");
    CHG_SUB(F4, L"f4.txt");
    Aces[0].Sid = SidAdmins; Aces[0].Mask = FILE_ALL_ACCESS; Aces[0].Flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE; Aces[0].Deny = FALSE;
    Aces[1].Sid = SidUser; Aces[1].Mask = FILE_GENERIC_READ; Aces[1].Flags = OBJECT_INHERIT_ACE; Aces[1].Deny = FALSE;
    ok_hex(NtMakeDirControl(Dir, Aces, 2, SE_DACL_PROTECTED), STATUS_SUCCESS);
    /* several creates: the directory's descriptor is read for each of them */
    for (i = 0; i < 3; i++)
    {
        ok_hex(NtMakeFile(F1, NULL, 0, FALSE, "x"), STATUS_SUCCESS);
        NtRemove(F1);
    }
    ok_hex(NtMakeFile(F1, NULL, 0, FALSE, "x"), STATUS_SUCCESS);
    Dacl = NtGetDacl(F1, Text, sizeof(Text), &Sd);
    ok(NtFindAce(Dacl, SidUser, FILE_GENERIC_READ, AllFlags, 0, FALSE) >= 0, "f1: no user ACE\n");
    if (Sd)
        LocalFree(Sd);

    /* another descriptor on the directory: Everyone instead of the user */
    Aces[1].Sid = SidEveryone;
    Sd = NtMakeSd(Aces, 2, TRUE);
    ok(Sd != NULL, "No descriptor\n");
    ok_hex(NtOpen(Dir, WRITE_DAC, SHARE_ALL, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, NULL, &H), STATUS_SUCCESS);
    ok_hex(NtSetSecurityObject(H, DACL_SECURITY_INFORMATION | 0x80000000 /* PROTECTED_DACL_SECURITY_INFORMATION */, Sd), STATUS_SUCCESS);
    NtClose(H);
    if (Sd)
        LocalFree(Sd);
    ok_hex(NtMakeFile(F2, NULL, 0, FALSE, "x"), STATUS_SUCCESS);
    Dacl = NtGetDacl(F2, Text, sizeof(Text), &Sd);
    trace("f2: %s\n", Text);
    ok(NtFindAce(Dacl, SidEveryone, FILE_GENERIC_READ, AllFlags, 0, FALSE) >= 0, "f2: no Everyone ACE after the change\n");
    ok(NtFindAce(Dacl, SidUser, FILE_GENERIC_READ, AllFlags, 0, FALSE) < 0, "f2: the old user ACE is inherited\n");
    if (Sd)
        LocalFree(Sd);

    /* the directory deleted and made again with the first descriptor */
    NtRemove(F1);
    NtRemove(F2);
    NtRemove(Dir);
    Aces[1].Sid = SidUser;
    ok_hex(NtMakeDirControl(Dir, Aces, 2, SE_DACL_PROTECTED), STATUS_SUCCESS);
    ok_hex(NtMakeFile(F3, NULL, 0, FALSE, "x"), STATUS_SUCCESS);
    Dacl = NtGetDacl(F3, Text, sizeof(Text), &Sd);
    ok(NtFindAce(Dacl, SidUser, FILE_GENERIC_READ, AllFlags, 0, FALSE) >= 0, "f3: no user ACE in the new directory\n");
    ok(NtFindAce(Dacl, SidEveryone, FILE_GENERIC_READ, AllFlags, 0, FALSE) < 0, "f3: Everyone ACE of the old directory\n");
    if (Sd)
        LocalFree(Sd);
    NtRemove(F3);
    NtRemove(F4);
    NtRemove(Dir);
#undef CHG_SUB
}

START_TEST(NtfsInherit)
{
    if (!NtInit("NtfsInherit") || !NtHaveUser())
        return;
    TestInherit(L"legacy");
    TestInheritAfterChange(L"legacy");
    TestAutoInherited();
    NtCleanup();
}
