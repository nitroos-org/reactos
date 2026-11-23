/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The mandatory label in object opens: Low and Untrusted children open objects of their parent
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winsock2.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/exfuncs.h>
#include <ndk/mmfuncs.h>
#include <aclapi.h>
#include <sddl.h>

static BOOL (WINAPI *pAddMandatoryAce)(PACL, DWORD, DWORD, DWORD, PSID);

/*
 * The parent makes objects whose DACL grants Everyone everything, with no label, a Low label, a Medium label and a
 * Medium label with NO_READ_UP: a file, a key, a named event, mutex and section, a named pipe. It starts copies of
 * itself with a duplicate of its token lowered to Low and to Untrusted (SetTokenInformation(TokenIntegrityLevel),
 * CreateProcessAsUser). The child opens every object (and the parent's process, thread and token) for read, write,
 * execute, DELETE, WRITE_DAC and MAXIMUM_ALLOWED. The expected result is the rule measured on Windows Server 2022
 * for the access check services and the object opens (AccessCheckMandatory): the label is the first label ACE that is
 * not inherit-only, none is Medium; a token below it gets at most GenericRead | READ_CONTROL (not with NO_READ_UP) and
 * GenericExecute | SYNCHRONIZE (not with NO_EXECUTE_UP) of the object type's generic mapping, never another right;
 * MAXIMUM_ALLOWED gets what the DACL grants within that. The mappings are the kernel's (ObjectTypeInformation).
 * Process and thread objects carry their creator's level with NO_WRITE_UP | NO_READ_UP, token objects their level
 * with NO_WRITE_UP. What the child creates itself carries its level ("Windows Integrity Mechanism Design", Labeling
 * objects created by low subjects), and it can open it again for write.
 * Keys follow the rule only while key access is enforced (RegAcl mode 2); in the other modes every key open is granted.
 */

#define NVARIANTS 4
static const struct
{
    PCWSTR Name;
    DWORD Level;        /* MAXDWORD: no label */
    DWORD Policy;
} Variants[NVARIANTS] =
{
    {L"none", MAXDWORD, 0},
    {L"low", SECURITY_MANDATORY_LOW_RID, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP},
    {L"med", SECURITY_MANDATORY_MEDIUM_RID, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP},
    {L"mednr", SECURITY_MANDATORY_MEDIUM_RID, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP},
};

#define PIPE_INSTANCES 8

typedef enum { KindFile, KindKey, KindEvent, KindMutex, KindSection, KindPipe, KindCount } OBJ_KIND;
static PCSTR KindNames[KindCount] = {"file", "key", "event", "mutex", "section", "pipe"};

static GENERIC_MAPPING Mappings[KindCount + 3];   /* + process, thread, token */
#define IDX_PROCESS (KindCount)
#define IDX_THREAD (KindCount + 1)
#define IDX_TOKEN (KindCount + 2)

static WCHAR BaseDir[MAX_PATH];
/* Whether the volume of the scratch directory / of the profile keeps security descriptors (NTFS does, FAT does not:
   there no file carries a label or a DACL, and every file row would fail) */
static BOOL FileAcls = TRUE, ProfileAcls = TRUE;

static BOOL VolumeKeepsAcls(PCWSTR Path)
{
    WCHAR Root[4], FsName[MAX_PATH];
    DWORD Flags = 0;

    if (!Path[0] || Path[1] != L':')
        return TRUE;
    Root[0] = Path[0]; Root[1] = L':'; Root[2] = L'\\'; Root[3] = 0;
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, FsName, _countof(FsName)))
        return FALSE;
    /* the NTFS driver of this system does not report FILE_PERSISTENT_ACLS */
    return (Flags & FILE_PERSISTENT_ACLS) || !_wcsicmp(FsName, L"NTFS");
}

static VOID DetectVolumes(VOID)
{
    WCHAR Profile[MAX_PATH];

    FileAcls = VolumeKeepsAcls(BaseDir);
    ProfileAcls = !GetEnvironmentVariableW(L"USERPROFILE", Profile, _countof(Profile)) || VolumeKeepsAcls(Profile);
}
static DWORD ParentPid;

static BOOL GetMapping(HANDLE Handle, PGENERIC_MAPPING Mapping)
{
    ULONG Buffer[1024];
    POBJECT_TYPE_INFORMATION Info = (POBJECT_TYPE_INFORMATION)Buffer;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectTypeInformation, Info, sizeof(Buffer), NULL);
    ok(NT_SUCCESS(Status), "ObjectTypeInformation: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return FALSE;
    *Mapping = Info->GenericMapping;
    return TRUE;
}

static ACCESS_MASK GrantedOf(HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL);
    ok(NT_SUCCESS(Status), "ObjectBasicInformation: 0x%lx\n", Status);
    return NT_SUCCESS(Status) ? Info.GrantedAccess : 0;
}

static DWORD TokenLevel(HANDLE Token)
{
    ULONG Buffer[(sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE) / sizeof(ULONG) + 1];
    DWORD Length;

    if (!GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length))
        return MAXDWORD;
    return *GetSidSubAuthority(((PTOKEN_MANDATORY_LABEL)Buffer)->Label.Sid, 0);
}

/* The label of an object: level and policy of its first label ACE, MAXDWORD without one */
static DWORD LabelOf(HANDLE Handle, SE_OBJECT_TYPE Type, PDWORD Policy, PBYTE Flags)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Sacl = NULL;
    PSYSTEM_MANDATORY_LABEL_ACE Ace;
    DWORD Level = MAXDWORD, Error, i;

    Error = GetSecurityInfo(Handle, Type, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &Sacl, &Sd);
    ok(Error == ERROR_SUCCESS, "GetSecurityInfo(LABEL): %lu\n", Error);
    if (Error != ERROR_SUCCESS)
        return MAXDWORD - 1;
    for (i = 0; Sacl && i < Sacl->AceCount; i++)
    {
        if (!GetAce(Sacl, i, (PVOID *)&Ace) || Ace->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE ||
            (Ace->Header.AceFlags & INHERIT_ONLY_ACE))
            continue;
        Level = *GetSidSubAuthority((PSID)&Ace->SidStart, 0);
        if (Policy) *Policy = Ace->Mask;
        if (Flags) *Flags = Ace->Header.AceFlags;
        break;
    }
    LocalFree(Sd);
    return Level;
}

/* What the label leaves a token of level Token: MAXDWORD when it does not restrict it (the measured rule) */
static ACCESS_MASK LabelAllows(DWORD Token, DWORD Level, DWORD Policy, const GENERIC_MAPPING *Mapping)
{
    ACCESS_MASK Allowed = 0;

    if (Level == MAXDWORD)
    {
        Level = SECURITY_MANDATORY_MEDIUM_RID;
        Policy = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
    }
    if (Token >= Level)
        return MAXDWORD;
    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_READ_UP))
        Allowed |= Mapping->GenericRead | READ_CONTROL;
    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP))
        Allowed |= Mapping->GenericExecute | SYNCHRONIZE;
    return Allowed;
}

static DWORD RegAclMode(void)
{
    DWORD Mode = 1, Size = sizeof(Mode);
    HKEY Key;

    /* The value is published by the kernel's registry ACL code; a system without the RegAcl key enforces keys (Windows) */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl", 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return 2;
    RegCloseKey(Key);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats", L"Mode",
                     RRF_RT_REG_DWORD, NULL, &Mode, &Size) != ERROR_SUCCESS)
        Mode = 1;
    return Mode;
}

/* ---------------------------------------------------------------- child */

/*
 * A named event, mutex or section of the parent, opened by its NT name in the session's BaseNamedObjects: the
 * object's label decides. (kernel32 gives a process below the directory's label no directory at all, V2-open: the
 * Win32 open functions would refuse every request of an Untrusted process before the object is looked at.)
 */
static HANDLE OpenNamedKernelObject(OBJ_KIND Kind, PCWSTR Name, ACCESS_MASK Access, PDWORD Error)
{
    WCHAR Path[MAX_PATH];
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Handle = NULL;
    DWORD Session = 0;
    NTSTATUS Status;

    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    if (Session)
        StringCchPrintfW(Path, _countof(Path), L"\\Sessions\\%lu\\BaseNamedObjects\\%s", Session, Name);
    else
        StringCchPrintfW(Path, _countof(Path), L"\\BaseNamedObjects\\%s", Name);
    RtlInitUnicodeString(&String, Path);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (Kind == KindEvent)
        Status = NtOpenEvent(&Handle, Access, &Attributes);
    else if (Kind == KindMutex)
        Status = NtOpenMutant(&Handle, Access, &Attributes);
    else
        Status = NtOpenSection(&Handle, Access, &Attributes);
    *Error = NT_SUCCESS(Status) ? ERROR_SUCCESS : RtlNtStatusToDosError(Status);
    return NT_SUCCESS(Status) ? Handle : NULL;
}

static HANDLE OpenKind(OBJ_KIND Kind, ULONG Variant, ACCESS_MASK Access, PDWORD Error)
{
    WCHAR Name[MAX_PATH];
    HANDLE Handle = NULL;
    HKEY Key;
    LONG Result;

    switch (Kind)
    {
        case KindFile:
            StringCchPrintfW(Name, _countof(Name), L"%s\\f-%s", BaseDir, Variants[Variant].Name);
            Handle = CreateFileW(Name, Access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                 OPEN_EXISTING, 0, NULL);
            if (Handle == INVALID_HANDLE_VALUE) Handle = NULL;
            break;
        case KindKey:
            StringCchPrintfW(Name, _countof(Name), L"Software\\MloTest%lu\\k-%s", ParentPid, Variants[Variant].Name);
            Result = RegOpenKeyExW(HKEY_CURRENT_USER, Name, 0, Access, &Key);
            SetLastError(Result);
            Handle = (Result == ERROR_SUCCESS) ? (HANDLE)Key : NULL;
            break;
        case KindEvent:
            StringCchPrintfW(Name, _countof(Name), L"mlo%lu-e-%s", ParentPid, Variants[Variant].Name);
            return OpenNamedKernelObject(Kind, Name, Access, Error);
        case KindMutex:
            StringCchPrintfW(Name, _countof(Name), L"mlo%lu-m-%s", ParentPid, Variants[Variant].Name);
            return OpenNamedKernelObject(Kind, Name, Access, Error);
        case KindSection:
            StringCchPrintfW(Name, _countof(Name), L"mlo%lu-s-%s", ParentPid, Variants[Variant].Name);
            return OpenNamedKernelObject(Kind, Name, Access, Error);
        case KindPipe:
            StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-p-%s", ParentPid, Variants[Variant].Name);
            Handle = CreateFileW(Name, Access, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (Handle == INVALID_HANDLE_VALUE) Handle = NULL;
            break;
        default:
            break;
    }
    *Error = Handle ? ERROR_SUCCESS : GetLastError();
    return Handle;
}

static VOID CloseKind(OBJ_KIND Kind, HANDLE Handle)
{
    if (Kind == KindKey)
        RegCloseKey((HKEY)Handle);
    else
        CloseHandle(Handle);
}

static VOID ChildObjectRows(DWORD Level)
{
    if (!FileAcls)
        skip("level %lx: the volume keeps no security descriptors: the file rows are not run\n", Level);

    static const ACCESS_MASK Requests[] = {GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, DELETE, WRITE_DAC, MAXIMUM_ALLOWED};
    static const PCSTR RequestNames[] = {"read", "write", "execute", "delete", "write_dac", "maximum"};
    BOOL KeysEnforced = (RegAclMode() == 2);
    ULONG Kind, Variant, r;

    for (Kind = 0; Kind < KindCount; Kind++)
    {
        for (Variant = 0; Variant < NVARIANTS; Variant++)
        {
            ACCESS_MASK Allowed = LabelAllows(Level, Variants[Variant].Level, Variants[Variant].Policy, &Mappings[Kind]);

            if (Kind == KindKey && !KeysEnforced)
                Allowed = MAXDWORD;

            for (r = 0; r < _countof(Requests); r++)
            {
                ACCESS_MASK Mapped = Requests[r];
                BOOL Expected;
                HANDLE Handle;
                DWORD Error;

                /* A pipe has no MAXIMUM_ALLOWED row and no DELETE / WRITE_DAC rows (the server end decides those) */
                if (Kind == KindPipe && r >= 3)
                    continue;
                if (Kind == KindFile && !FileAcls)
                    continue;

                if (Mapped & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE))
                    MapGenericMask(&Mapped, &Mappings[Kind]);
                Expected = (Mapped == MAXIMUM_ALLOWED) ? (Allowed != 0) : ((Mapped & ~Allowed) == 0);

                Handle = OpenKind(Kind, Variant, Requests[r], &Error);
                ok(!!Handle == Expected, "level %lx %s-%S %s: opened %d (error %lu), expected %d\n",
                   Level, KindNames[Kind], Variants[Variant].Name, RequestNames[r], !!Handle, Error, Expected);
                if (!Handle)
                {
                    ok(Expected || Error == ERROR_ACCESS_DENIED, "level %lx %s-%S %s: error %lu\n",
                       Level, KindNames[Kind], Variants[Variant].Name, RequestNames[r], Error);
                    continue;
                }
                if (Requests[r] == MAXIMUM_ALLOWED && Kind != KindKey && Allowed != MAXDWORD)
                {
                    ACCESS_MASK Granted = GrantedOf(Handle);
                    ok((Granted & ~Allowed) == 0, "level %lx %s-%S maximum: granted 0x%lx beyond the label's 0x%lx\n",
                       Level, KindNames[Kind], Variants[Variant].Name, Granted, Allowed);
                    ok((Granted & Mappings[Kind].GenericAll & Allowed) == (Mappings[Kind].GenericAll & Allowed),
                       "level %lx %s-%S maximum: granted 0x%lx, the DACL and the label give 0x%lx\n",
                       Level, KindNames[Kind], Variants[Variant].Name, Granted, Mappings[Kind].GenericAll & Allowed);
                }
                CloseKind(Kind, Handle);
            }
        }
    }
}

/* The parent's process, thread and token: labelled at the parent's level, NW|NR (process, thread), NW (token) */
static VOID ChildParentRows(DWORD Level, DWORD Tid)
{
    static const struct { ACCESS_MASK Access; PCSTR Name; } ProcessRows[] =
    {
        {PROCESS_QUERY_LIMITED_INFORMATION, "query_limited"}, {SYNCHRONIZE, "synchronize"},
        {PROCESS_QUERY_INFORMATION, "query"}, {PROCESS_VM_READ, "vm_read"}, {PROCESS_VM_WRITE, "vm_write"},
        {PROCESS_VM_OPERATION, "vm_operation"}, {PROCESS_DUP_HANDLE, "dup_handle"}, {PROCESS_CREATE_THREAD, "create_thread"},
        {PROCESS_SET_INFORMATION, "set_information"}, {WRITE_DAC, "write_dac"},
    };
    static const struct { ACCESS_MASK Access; PCSTR Name; } ThreadRows[] =
    {
        {THREAD_QUERY_LIMITED_INFORMATION, "query_limited"}, {SYNCHRONIZE, "synchronize"},
        {THREAD_GET_CONTEXT, "get_context"}, {THREAD_SET_CONTEXT, "set_context"}, {THREAD_SUSPEND_RESUME, "suspend"},
        {THREAD_SET_INFORMATION, "set_information"}, {WRITE_DAC, "write_dac"},
    };
    static const struct { ACCESS_MASK Access; PCSTR Name; } TokenRows[] =
    {
        {TOKEN_QUERY, "query"}, {TOKEN_ADJUST_DEFAULT, "adjust_default"}, {TOKEN_ADJUST_PRIVILEGES, "adjust_privileges"},
        {TOKEN_ADJUST_GROUPS, "adjust_groups"}, {WRITE_DAC, "write_dac"},
    };
    HANDLE Process, Handle, Token;
    DWORD ParentLevel = MAXDWORD;
    ACCESS_MASK Allowed;
    BOOL Expected;
    ULONG i;

    /* The query of the parent's level needs a READ_CONTROL handle: execute rights only, so read it from the token */
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParentPid);
    ok(Process != NULL, "level %lx: OpenProcess(QUERY_LIMITED) of the parent: %lu\n", Level, GetLastError());
    if (!Process)
        return;
    if (OpenProcessToken(Process, TOKEN_QUERY, &Token))
    {
        ParentLevel = TokenLevel(Token);
        CloseHandle(Token);
    }
    ok(ParentLevel != MAXDWORD, "level %lx: the parent's level is unknown\n", Level);
    if (ParentLevel == MAXDWORD)
    {
        CloseHandle(Process);
        return;
    }

    Allowed = LabelAllows(Level, ParentLevel, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                          &Mappings[IDX_PROCESS]);
    for (i = 0; i < _countof(ProcessRows); i++)
    {
        Expected = (ProcessRows[i].Access & ~Allowed) == 0;
        Handle = OpenProcess(ProcessRows[i].Access, FALSE, ParentPid);
        ok(!!Handle == Expected, "level %lx parent process %s: opened %d (error %lu), expected %d\n",
           Level, ProcessRows[i].Name, !!Handle, Handle ? 0 : GetLastError(), Expected);
        if (Handle) CloseHandle(Handle);
    }

    Allowed = LabelAllows(Level, ParentLevel, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                          &Mappings[IDX_THREAD]);
    for (i = 0; i < _countof(ThreadRows); i++)
    {
        Expected = (ThreadRows[i].Access & ~Allowed) == 0;
        Handle = OpenThread(ThreadRows[i].Access, FALSE, Tid);
        ok(!!Handle == Expected, "level %lx parent thread %s: opened %d (error %lu), expected %d\n",
           Level, ThreadRows[i].Name, !!Handle, Handle ? 0 : GetLastError(), Expected);
        if (Handle) CloseHandle(Handle);
    }

    Allowed = LabelAllows(Level, ParentLevel, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, &Mappings[IDX_TOKEN]);
    for (i = 0; i < _countof(TokenRows); i++)
    {
        Expected = (TokenRows[i].Access & ~Allowed) == 0;
        Token = NULL;
        ok(OpenProcessToken(Process, TokenRows[i].Access, &Token) == Expected,
           "level %lx parent token %s: error %lu, expected %d\n", Level, TokenRows[i].Name, GetLastError(), Expected);
        if (Token) CloseHandle(Token);
    }
    CloseHandle(Process);
}

/* What the child creates carries its level, and it can open it again for write */
static VOID ChildCreateRows(DWORD Level)
{
    WCHAR Name[MAX_PATH], LocalLow[MAX_PATH];
    DWORD Length;
    HANDLE Event, Again, File;
    DWORD Policy = 0, Label;
    BYTE Flags = 0xFF;
    HKEY Key, Key2;
    LONG Result;
    DWORD BnoLevel = MAXDWORD, Session = 0;
    UNICODE_STRING BnoName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Bno;
    NTSTATUS Status;

    /* The label of the session's BaseNamedObjects (READ_CONTROL is a read right: left below its label) */
    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    if (Session)
        StringCchPrintfW(Name, _countof(Name), L"\\Sessions\\%lu\\BaseNamedObjects", Session);
    else
        StringCchCopyW(Name, _countof(Name), L"\\BaseNamedObjects");
    RtlInitUnicodeString(&BnoName, Name);
    InitializeObjectAttributes(&Attributes, &BnoName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenDirectoryObject(&Bno, READ_CONTROL, &Attributes);
    ok(NT_SUCCESS(Status), "level %lx: %S for READ_CONTROL: 0x%lx\n", Level, Name, Status);
    if (NT_SUCCESS(Status))
    {
        BnoLevel = LabelOf(Bno, SE_KERNEL_OBJECT, NULL, NULL);
        trace("level %lx: %S labelled %lx\n", Level, Name, BnoLevel);
        CloseHandle(Bno);
    }

    /*
     * A named event in the session's BaseNamedObjects: created if the directory's label leaves the child
     * DIRECTORY_CREATE_OBJECT (no label: Medium, so not below Medium); then it carries the child's level
     */
    StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-c-%lx", ParentPid, Level);
    Event = CreateEventW(NULL, TRUE, FALSE, Name);
    if (BnoLevel == MAXDWORD ? Level >= SECURITY_MANDATORY_MEDIUM_RID : Level >= BnoLevel)
        ok(Event != NULL, "level %lx: CreateEvent: %lu\n", Level, GetLastError());
    else
        ok(Event == NULL && GetLastError() == ERROR_ACCESS_DENIED, "level %lx: CreateEvent in BaseNamedObjects (label %lx): %p, %lu\n",
           Level, BnoLevel, Event, GetLastError());
    if (Event)
    {
        Label = LabelOf(Event, SE_KERNEL_OBJECT, &Policy, &Flags);
        ok(Label == Level, "level %lx: own event labelled %lx\n", Level, Label);
        ok(Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, "level %lx: own event policy %lx\n", Level, Policy);
        ok(Flags == 0, "level %lx: own event label flags %x\n", Level, Flags);
        Again = OpenEventW(EVENT_ALL_ACCESS, FALSE, Name);
        ok(Again != NULL, "level %lx: own event for EVENT_ALL_ACCESS: %lu\n", Level, GetLastError());
        if (Again) CloseHandle(Again);
        CloseHandle(Event);
    }

    /* A named pipe the child creates carries its level, and it opens it for write (Untrusted: V7-pipe) */
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-cp-%lx", ParentPid, Level);
    Event = (Level >= SECURITY_MANDATORY_LOW_RID) ?
            CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, 2, 512, 512, 0, NULL) :
            INVALID_HANDLE_VALUE;
    ok(Event != INVALID_HANDLE_VALUE || Level < SECURITY_MANDATORY_LOW_RID, "level %lx: CreateNamedPipe: %lu\n", Level, GetLastError());
    if (Event != INVALID_HANDLE_VALUE)
    {
        Label = LabelOf(Event, SE_KERNEL_OBJECT, &Policy, &Flags);
        ok(Label == Level, "level %lx: own pipe labelled %lx\n", Level, Label);
        Again = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        ok(Again != INVALID_HANDLE_VALUE, "level %lx: own pipe for write: %lu\n", Level, GetLastError());
        if (Again != INVALID_HANDLE_VALUE) CloseHandle(Again);
        CloseHandle(Event);
    }

    if (!FileAcls)
    {
        skip("level %lx: the volume keeps no security descriptors: no file creation rows\n", Level);
    }
    else
    {
        /* A file in a directory without a label: no FILE_ADD_FILE below Medium */
        StringCchPrintfW(Name, _countof(Name), L"%s\\c-%lx", BaseDir, Level);
        File = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        ok(File == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED,
           "level %lx: file in the unlabelled directory: %p, error %lu\n", Level, File, GetLastError());
        if (File != INVALID_HANDLE_VALUE) { CloseHandle(File); DeleteFileW(Name); }

        /* In a directory labelled Low (OICI): created, inherits the Low label, opened again for write */
        StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir\\c-%lx", BaseDir, Level);
        File = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        if (Level >= SECURITY_MANDATORY_LOW_RID)
        {
            ok(File != INVALID_HANDLE_VALUE, "level %lx: file in the Low directory: %lu\n", Level, GetLastError());
            if (File != INVALID_HANDLE_VALUE)
            {
                Label = LabelOf(File, SE_FILE_OBJECT, NULL, NULL);
                ok(Label == SECURITY_MANDATORY_LOW_RID, "level %lx: file in the Low directory labelled %lx\n", Level, Label);
                CloseHandle(File);
                File = CreateFileW(Name, GENERIC_WRITE | DELETE, 0, NULL, OPEN_EXISTING, 0, NULL);
                ok(File != INVALID_HANDLE_VALUE, "level %lx: own file for write: %lu\n", Level, GetLastError());
                if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
                DeleteFileW(Name);
            }
        }
        else
        {
            /* Untrusted is below the directory's Low label */
            ok(File == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED,
               "level %lx: file in the Low directory: %p, error %lu\n", Level, File, GetLastError());
            if (File != INVALID_HANDLE_VALUE) { CloseHandle(File); DeleteFileW(Name); }
        }

    }

    if (!ProfileAcls)
    {
        skip("level %lx: the volume of the profile keeps no security descriptors: no LocalLow rows\n", Level);
    }
    else
    {
        /* The profile's LocalLow (FOLDERID_LocalAppDataLow) is labelled Low and writable at Low */
        Length = GetEnvironmentVariableW(L"USERPROFILE", LocalLow, _countof(LocalLow));
        if (Length && Length < _countof(LocalLow) &&
            SUCCEEDED(StringCchCatW(LocalLow, _countof(LocalLow), L"\\AppData\\LocalLow")))
        {
            HANDLE Dir = CreateFileW(LocalLow, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                     OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            ok(Dir != INVALID_HANDLE_VALUE, "level %lx: LocalLow: %lu\n", Level, GetLastError());
            if (Dir != INVALID_HANDLE_VALUE)
            {
                Flags = 0;
                Label = LabelOf(Dir, SE_FILE_OBJECT, &Policy, &Flags);
                ok(Label == SECURITY_MANDATORY_LOW_RID, "level %lx: LocalLow labelled %lx\n", Level, Label);
                ok(Flags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE), "level %lx: LocalLow label flags %x\n", Level, Flags);
                CloseHandle(Dir);
            }
            StringCchPrintfW(Name, _countof(Name), L"%s\\mlo%lu-%lx", LocalLow, ParentPid, Level);
            File = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, NULL);
            ok((File != INVALID_HANDLE_VALUE) == (Level >= SECURITY_MANDATORY_LOW_RID),
               "level %lx: file in LocalLow: %p, error %lu\n", Level, File, GetLastError());
            if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
        }
        else
        {
            ok(0, "level %lx: no LocalLow folder\n", Level);
        }

    }

    /* A key created below the Low key carries the creator's level */
    StringCchPrintfW(Name, _countof(Name), L"Software\\MloTest%lu\\k-low", ParentPid);
    Result = RegOpenKeyExW(HKEY_CURRENT_USER, Name, 0, KEY_CREATE_SUB_KEY, &Key);
    if (Level >= SECURITY_MANDATORY_LOW_RID || RegAclMode() != 2)
        ok(Result == ERROR_SUCCESS, "level %lx: k-low for KEY_CREATE_SUB_KEY: %ld\n", Level, Result);
    if (Result == ERROR_SUCCESS)
    {
        StringCchPrintfW(Name, _countof(Name), L"c-%lx", Level);
        Result = RegCreateKeyExW(Key, Name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key2, NULL);
        ok(Result == ERROR_SUCCESS, "level %lx: create below k-low: %ld\n", Level, Result);
        if (Result == ERROR_SUCCESS)
        {
            Label = LabelOf((HANDLE)Key2, SE_REGISTRY_KEY, &Policy, NULL);
            ok(Label == Level, "level %lx: own key labelled %lx\n", Level, Label);
            RegCloseKey(Key2);
            Result = RegOpenKeyExW(Key, Name, 0, KEY_SET_VALUE | DELETE, &Key2);
            ok(Result == ERROR_SUCCESS, "level %lx: own key for write: %ld\n", Level, Result);
            if (Result == ERROR_SUCCESS) RegCloseKey(Key2);
            RegDeleteKeyW(Key, Name);
        }
        RegCloseKey(Key);
    }
}

/*
 * Opens and creates beside the object grid: the null device (labelled Untrusted), an explicit label above the
 * creator's level ("Windows Integrity Mechanism Design": no higher than the creating subject), the parent's token
 * (it may be duplicated, but impersonated at most at identification level: no impersonation of a higher-level
 * token), a handle duplicated with more access (an open of the object) and the interactive window station
 * (labelled Low: the clipboard for Low processes).
 */
static VOID ChildReviewRows(DWORD Level)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_ATTRIBUTES Sa = {sizeof(Sa), NULL, FALSE};
    SECURITY_IMPERSONATION_LEVEL ImpLevel = SecurityAnonymous;
    WCHAR Name[MAX_PATH];
    HANDLE Handle, Process, Token, Dup, Again;
    DWORD Written, Length, WinStaLevel;
    BOOL Ok;

    /* NUL for write, as cmd's "> nul": labelled Low (V15-nul), so Low writes, Untrusted is refused */
    Handle = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Level >= SECURITY_MANDATORY_LOW_RID)
        ok(Handle != INVALID_HANDLE_VALUE, "level %lx: NUL for write: %lu\n", Level, GetLastError());
    else
        ok(Handle == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "level %lx: NUL for write: %p, %lu\n",
           Level, Handle, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
    {
        ok(WriteFile(Handle, "x", 1, &Written, NULL), "level %lx: write to NUL: %lu\n", Level, GetLastError());
        CloseHandle(Handle);
    }

    /* A new pipe with an explicit High label (V13-pipe; an Untrusted creator: see ChildRowsV13V7) */
    if (Level >= SECURITY_MANDATORY_LOW_RID &&
        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;HI)", SDDL_REVISION_1, &Sd, NULL))
    {
        Sa.lpSecurityDescriptor = Sd;
        StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-hi-%lx", ParentPid, Level);
        Handle = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, 0, 1, 64, 64, 0, &Sa);
        ok(Handle == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PRIVILEGE_NOT_HELD,
           "level %lx: pipe labelled High by its creator: %p, %lu\n", Level, Handle, GetLastError());
        if (Handle != INVALID_HANDLE_VALUE)
            CloseHandle(Handle);
        LocalFree(Sd);
    }

    /* The parent's token: duplicated, impersonated at identification level only */
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParentPid);
    Token = NULL;
    if (Process && OpenProcessToken(Process, TOKEN_QUERY | TOKEN_DUPLICATE, &Token))
    {
        Dup = NULL;
        ok(DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Dup),
           "level %lx: DuplicateTokenEx of the parent's token: %lu\n", Level, GetLastError());
        if (Dup && SetThreadToken(NULL, Dup))
        {
            Again = NULL;
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Again))
            {
                GetTokenInformation(Again, TokenImpersonationLevel, &ImpLevel, sizeof(ImpLevel), &Length);
                CloseHandle(Again);
            }
            ok(ImpLevel == SecurityIdentification, "level %lx: the parent's token impersonated at level %d\n",
               Level, ImpLevel);
            RevertToSelf();
        }
        if (Dup)
            CloseHandle(Dup);
        CloseHandle(Token);
    }
    if (Process)
        CloseHandle(Process);

    /* A handle to the parent's unlabelled event duplicated with a write right: refused */
    StringCchPrintfW(Name, _countof(Name), L"mlo%lu-e-none", ParentPid);
    Handle = OpenNamedKernelObject(KindEvent, Name, SYNCHRONIZE, &Written);
    ok(Handle != NULL, "level %lx: event for SYNCHRONIZE: %lu\n", Level, Written);
    if (Handle)
    {
        Dup = NULL;
        Ok = DuplicateHandle(GetCurrentProcess(), Handle, GetCurrentProcess(), &Dup, EVENT_MODIFY_STATE, FALSE, 0);
        ok(!Ok && GetLastError() == ERROR_ACCESS_DENIED, "level %lx: duplicated for EVENT_MODIFY_STATE: %d, %lu\n",
           Level, Ok, GetLastError());
        if (Ok)
            CloseHandle(Dup);
        CloseHandle(Handle);
    }

    /* The interactive window station is labelled Low: a Low process uses the clipboard, an Untrusted one does not */
    WinStaLevel = LabelOf(GetProcessWindowStation(), SE_WINDOW_OBJECT, NULL, NULL);
    ok(WinStaLevel == SECURITY_MANDATORY_LOW_RID, "level %lx: window station labelled %lx\n", Level, WinStaLevel);
    Ok = OpenClipboard(NULL);
    ok(Ok == (Level >= SECURITY_MANDATORY_LOW_RID), "level %lx: OpenClipboard %d (%lu)\n", Level, Ok, GetLastError());
    if (Ok)
        CloseClipboard();
}

/* ------------------------------------------------- rows measured on Windows */

/*
 * The rows of the Windows reference (Windows Server 2022, a High administrator parent and a Medium standard user
 * parent, Low and Untrusted children made with SetTokenInformation(TokenIntegrityLevel) and CreateProcessAsUser:
 * "integrity-rows" V1..V17). Each check names its row. The parent here is the administrator (High); where the
 * Medium parent's column differs, the expectation follows the parent's level.
 */

static DWORD ParentLevelOf(void)
{
    HANDLE Process, Token;
    DWORD Level = MAXDWORD;

    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParentPid);
    if (Process && OpenProcessToken(Process, TOKEN_QUERY, &Token))
    {
        Level = TokenLevel(Token);
        CloseHandle(Token);
    }
    if (Process)
        CloseHandle(Process);
    return Level;
}

/* Attributes of a privilege in a token, MAXDWORD when the token does not hold it */
static DWORD PrivilegeAttributes(HANDLE Token, PCWSTR Name)
{
    ULONG Buffer[1024];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Length, i;
    LUID Luid;

    if (!LookupPrivilegeValueW(NULL, Name, &Luid) ||
        !GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return MAXDWORD;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.LowPart == Luid.LowPart &&
            Privileges->Privileges[i].Luid.HighPart == Luid.HighPart)
            return Privileges->Privileges[i].Attributes;
    }
    return MAXDWORD;
}

static BOOL SetLevel(HANDLE Token, DWORD Level)
{
    SID_IDENTIFIER_AUTHORITY LabelAuth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    TOKEN_MANDATORY_LABEL Label;

    InitializeSid((PSID)Sid, &LabelAuth, 1);
    *GetSidSubAuthority((PSID)Sid, 0) = Level;
    Label.Label.Sid = (PSID)Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    return SetTokenInformation(Token, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid((PSID)Sid));
}

/* The label of a named object directory or a device (NT path), MAXDWORD - 1 when it cannot be read */
static DWORD LabelOfNtPath(PCWSTR Path, BOOL Directory, PDWORD Policy, PBYTE Flags)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;
    DWORD Level;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (Directory)
        Status = NtOpenDirectoryObject(&Handle, READ_CONTROL, &Attributes);
    else
        Status = NtOpenFile(&Handle, READ_CONTROL | SYNCHRONIZE, &Attributes, &Iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
    {
        trace("%S for READ_CONTROL: 0x%lx\n", Path, Status);
        return MAXDWORD - 1;
    }
    Level = LabelOf(Handle, SE_KERNEL_OBJECT, Policy, Flags);
    CloseHandle(Handle);
    return Level;
}

static LRESULT CALLBACK HookProc(int Code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

/* Runs "cmd.exe /c Args" with this process's token; returns the exit code or MAXDWORD */
static DWORD RunCmd(PCWSTR Args)
{
    WCHAR Command[MAX_PATH];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Pi;
    DWORD Code = MAXDWORD;

    StringCchPrintfW(Command, _countof(Command), L"cmd.exe /c %s", Args);
    if (!CreateProcessW(NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &Startup, &Pi))
        return MAXDWORD;
    WaitForSingleObject(Pi.hProcess, 60000);
    GetExitCodeProcess(Pi.hProcess, &Code);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    return Code;
}

/* V2: named objects in BaseNamedObjects (Local\, Global\, bare names) and the parent's default event */
static VOID ChildRowsV2(DWORD Level)
{
    static const PCWSTR Prefixes[] = {L"Local\\", L"Global\\", L""};
    WCHAR Name[MAX_PATH];
    HANDLE Handle;
    DWORD Session = 0, Error, i, k;
    BOOL Expected;

    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    for (i = 0; i < _countof(Prefixes); i++)
    {
        for (k = 0; k < 5; k++)
        {
            StringCchPrintfW(Name, _countof(Name), L"%smlo%lu-v2-%lu-%lx", Prefixes[i], ParentPid, k, Level);
            SetLastError(0xdeadbeef);
            switch (k)
            {
                case 0: Handle = CreateEventW(NULL, FALSE, FALSE, Name); break;
                case 1: Handle = CreateMutexW(NULL, FALSE, Name); break;
                case 2: Handle = CreateSemaphoreW(NULL, 0, 1, Name); break;
                case 3: Handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, Name); break;
                default: Handle = CreateWaitableTimerW(NULL, FALSE, Name); break;
            }
            Error = Handle ? 0 : GetLastError();
            /*
             * V2-event/-mutex/-semaphore/-section/-timer: Low creates (BaseNamedObjects is labelled Low), Untrusted
             * does not (5). A section named Global\ is refused on Windows (5): the measured process ran in session 1
             * and Global\ is session 0's directory (SeCreateGlobalPrivilege, disabled below Medium); in session 0 it
             * is the process's own session.
             */
            Expected = (Level >= SECURITY_MANDATORY_LOW_RID);
            if (k == 3 && i == 1 && Session != 0)
                Expected = FALSE;
            ok(!!Handle == Expected && (Expected || Error == ERROR_ACCESS_DENIED),
               "V2 level %lx: create kind %lu %S: %p, error %lu\n", Level, k, Name, Handle, Error);
            if (Handle && k == 0)
            {
                DWORD Policy = 0;
                BYTE Flags = 0xff;
                /* V2-event-label: S:(ML;;NW;;;LW) */
                ok(LabelOf(Handle, SE_KERNEL_OBJECT, &Policy, &Flags) == Level && Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP && Flags == 0,
                   "V2-event-label level %lx: %S policy %lx flags %x\n", Level, Name, Policy, Flags);
            }
            if (Handle)
                CloseHandle(Handle);
        }

        /* V2-open: the parent's event with a default descriptor: Low for SYNCHRONIZE, not for EVENT_MODIFY_STATE */
        StringCchPrintfW(Name, _countof(Name), L"%smlo%lu-pev", Prefixes[i], ParentPid);
        Handle = OpenEventW(SYNCHRONIZE, FALSE, Name);
        Error = Handle ? 0 : GetLastError();
        if (Level >= SECURITY_MANDATORY_LOW_RID)
            ok(Handle != NULL, "V2-open level %lx: %S for SYNCHRONIZE: %lu\n", Level, Name, Error);
        else
            ok(Handle == NULL && Error == ERROR_ACCESS_DENIED, "V2-open level %lx: %S for SYNCHRONIZE: %p, %lu\n",
               Level, Name, Handle, Error);
        if (Handle) CloseHandle(Handle);
        Handle = OpenEventW(EVENT_MODIFY_STATE, FALSE, Name);
        Error = Handle ? 0 : GetLastError();
        ok(Handle == NULL && Error == ERROR_ACCESS_DENIED, "V2-open level %lx: %S for EVENT_MODIFY_STATE: %p, %lu\n",
           Level, Name, Handle, Error);
        if (Handle) CloseHandle(Handle);
    }
}

/* V12: a process with the higher parent's token; NtSetInformationProcess(ProcessAccessToken) */
static VOID ChildRowsV12(DWORD Level, DWORD ParentLevel)
{
    const ACCESS_MASK DupAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
    WCHAR Command[] = L"cmd.exe /c exit 0";
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Pi;
    HANDLE Process, Token = NULL, Dup = NULL, NewToken;
    PROCESS_ACCESS_TOKEN AccessToken;
    NTSTATUS Status;
    DWORD Error;
    BOOL Ok;

    /* V12-1, V12-2: the parent and its token for TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY */
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParentPid);
    ok(Process != NULL, "V12-1 level %lx: %lu\n", Level, GetLastError());
    if (!Process)
        return;
    Ok = OpenProcessToken(Process, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &Token);
    ok(Ok, "V12-2 level %lx: %lu\n", Level, GetLastError());
    CloseHandle(Process);
    if (!Ok)
        return;

    /* V12-3: a primary duplicate at the parent's level; V12-3c: CreateProcessAsUser with it: 1314 */
    Ok = DuplicateTokenEx(Token, DupAccess, NULL, SecurityImpersonation, TokenPrimary, &Dup);
    ok(Ok && TokenLevel(Dup) == ParentLevel, "V12-3 level %lx: %d, %lu\n", Level, Ok, GetLastError());
    if (Ok)
    {
        Ok = CreateProcessAsUserW(Dup, NULL, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Pi);
        Error = Ok ? 0 : GetLastError();
        ok(!Ok && Error == ERROR_PRIVILEGE_NOT_HELD, "V12-3c level %lx: CreateProcessAsUser with the parent's token: %d, %lu\n",
           Level, Ok, Error);
        if (Ok)
        {
            if (OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &NewToken))
            {
                trace("V12-3c level %lx: the new process runs at %lx\n", Level, TokenLevel(NewToken));
                CloseHandle(NewToken);
            }
            TerminateProcess(Pi.hProcess, 0);
            CloseHandle(Pi.hProcess);
            CloseHandle(Pi.hThread);
        }
        CloseHandle(Dup);
    }

    /*
     * V12-4s: SetTokenInformation(TokenIntegrityLevel = own level) on such a duplicate: refused (5) for the
     * duplicate of the High parent's token, done for the Medium parent's; V12-4c: CreateProcessAsUser with the
     * lowered duplicate starts a process at the child's level (measured with the Medium parent)
     */
    Dup = NULL;
    if (DuplicateTokenEx(Token, DupAccess, NULL, SecurityImpersonation, TokenPrimary, &Dup))
    {
        /* V12-4g: what the duplicate of a High token grants to a Low or Untrusted process (Windows: 0xb for
           QUERY|DUPLICATE|ASSIGN_PRIMARY|ADJUST_DEFAULT, 0x2000b with READ_CONTROL; all of it for a Medium token) */
        {
            OBJECT_BASIC_INFORMATION Basic;
            ACCESS_MASK Limited = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
                                  TOKEN_QUERY_SOURCE | READ_CONTROL;

            Status = NtQueryObject(Dup, ObjectBasicInformation, &Basic, sizeof(Basic), NULL);
            ok(NT_SUCCESS(Status), "V12-4g level %lx: NtQueryObject 0x%lx\n", Level, Status);
            if (NT_SUCCESS(Status))
            {
                if (ParentLevel >= SECURITY_MANDATORY_HIGH_RID)
                    ok(Basic.GrantedAccess == (DupAccess & Limited), "V12-4g level %lx: granted 0x%lx, expected 0x%lx\n",
                       Level, Basic.GrantedAccess, DupAccess & Limited);
                else
                    ok((Basic.GrantedAccess & DupAccess) == DupAccess, "V12-4g level %lx: granted 0x%lx\n", Level, Basic.GrantedAccess);
            }
        }
        Ok = SetLevel(Dup, Level);
        Error = Ok ? 0 : GetLastError();
        if (ParentLevel >= SECURITY_MANDATORY_HIGH_RID)
            ok(!Ok && Error == ERROR_ACCESS_DENIED, "V12-4s level %lx: lowering the High duplicate: %d, %lu\n", Level, Ok, Error);
        else
            ok(Ok, "V12-4s level %lx: lowering the duplicate: %lu\n", Level, Error);
        if (Ok)
        {
            Ok = CreateProcessAsUserW(Dup, NULL, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Pi);
            ok(Ok, "V12-4c level %lx: CreateProcessAsUser with the duplicate lowered to the own level: %lu\n", Level, GetLastError());
            if (Ok)
            {
                if (OpenProcessToken(Pi.hProcess, TOKEN_QUERY, &NewToken))
                {
                    ok(TokenLevel(NewToken) == Level, "V12-4c level %lx: new process at %lx\n", Level, TokenLevel(NewToken));
                    CloseHandle(NewToken);
                }
                TerminateProcess(Pi.hProcess, 0);
                CloseHandle(Pi.hProcess);
                CloseHandle(Pi.hThread);
            }
        }
        CloseHandle(Dup);
    }

    /*
     * V12-5: NtSetInformationProcess(ProcessAccessToken) on a suspended own child with a MAXIMUM_ALLOWED duplicate
     * of the parent's token: STATUS_ACCESS_DENIED for the children of the High parent, STATUS_PRIVILEGE_NOT_HELD
     * for those of the Medium parent
     */
    Dup = NULL;
    if (DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &Dup) &&
        CreateProcessW(NULL, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Pi))
    {
        /* V12-5g: a MAXIMUM_ALLOWED duplicate of the High parent's token is granted nothing (Windows 0) */
        {
            OBJECT_BASIC_INFORMATION Basic;

            Status = NtQueryObject(Dup, ObjectBasicInformation, &Basic, sizeof(Basic), NULL);
            ok(NT_SUCCESS(Status), "V12-5g level %lx: NtQueryObject 0x%lx\n", Level, Status);
            if (NT_SUCCESS(Status))
            {
                if (ParentLevel >= SECURITY_MANDATORY_HIGH_RID)
                    ok(Basic.GrantedAccess == 0, "V12-5g level %lx: granted 0x%lx\n", Level, Basic.GrantedAccess);
                else
                    ok((Basic.GrantedAccess & TOKEN_ASSIGN_PRIMARY) != 0, "V12-5g level %lx: granted 0x%lx\n", Level, Basic.GrantedAccess);
            }
        }
        AccessToken.Token = Dup;
        AccessToken.Thread = Pi.hThread;
        Status = NtSetInformationProcess(Pi.hProcess, ProcessAccessToken, &AccessToken, sizeof(AccessToken));
        ok(!NT_SUCCESS(Status), "V12-5 level %lx: 0x%lx\n", Level, Status);
        if (ParentLevel >= SECURITY_MANDATORY_HIGH_RID)
            ok(Status == STATUS_ACCESS_DENIED, "V12-5 level %lx: 0x%lx, Windows 0xc0000022\n", Level, Status);
        else
            ok(Status == STATUS_PRIVILEGE_NOT_HELD, "V12-5 level %lx: 0x%lx\n", Level, Status);
        TerminateProcess(Pi.hProcess, 0);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
    }
    else
    {
        ok(0, "V12-5 level %lx: setup %lu\n", Level, GetLastError());
    }
    if (Dup) CloseHandle(Dup);
    CloseHandle(Token);
}

/* V13: an explicit label above the creator at creation; V7: the creator's own objects with default descriptors */
static VOID ChildRowsV13V7(DWORD Level)
{
    static const PCWSTR High = L"D:(A;;GA;;;WD)S:(ML;;NW;;;HI)";
    static const PCWSTR HighIo = L"D:(A;OICI;GA;;;WD)S:(ML;OICIIO;NW;;;HI)";
    SECURITY_ATTRIBUTES Sa = {sizeof(Sa), NULL, FALSE};
    BOOL KeysEnforced = (RegAclMode() == 2);
    WCHAR Name[MAX_PATH];
    HANDLE Handle;
    DWORD Error, Policy;
    BYTE Flags;
    HKEY Key, Parent;
    LONG Result;
    BOOL Ok;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(High, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL))
    {
        ok(0, "SDDL: %lu\n", GetLastError());
        return;
    }

    /* V13-event: Low 1314, Untrusted 5 (it creates nothing in BaseNamedObjects) */
    StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-v13-%lx", ParentPid, Level);
    Handle = CreateEventW(&Sa, FALSE, FALSE, Name);
    Error = Handle ? 0 : GetLastError();
    ok(!Handle && Error == (Level >= SECURITY_MANDATORY_LOW_RID ? ERROR_PRIVILEGE_NOT_HELD : ERROR_ACCESS_DENIED),
       "V13-event level %lx: %p, %lu\n", Level, Handle, Error);
    if (Handle) CloseHandle(Handle);

    /* V13-file (in the Low directory): Low 1314, Untrusted 5 */
    if (FileAcls)
    {
        StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir\\v13-%lx.txt", BaseDir, Level);
        Handle = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, &Sa, CREATE_NEW, 0, NULL);
        Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        ok(Handle == INVALID_HANDLE_VALUE && Error == (Level >= SECURITY_MANDATORY_LOW_RID ? ERROR_PRIVILEGE_NOT_HELD : ERROR_ACCESS_DENIED),
           "V13-file level %lx: %lu\n", Level, Error);
        if (Handle != INVALID_HANDLE_VALUE) { CloseHandle(Handle); DeleteFileW(Name); }

    }

    /* V13-pipe: Low 1314, Untrusted 5 (on Windows an Untrusted process creates no named pipe, V7-pipe) */
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-v13-%lx", ParentPid, Level);
    Handle = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, 0, 1, 64, 64, 0, &Sa);
    Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    ok(Handle == INVALID_HANDLE_VALUE, "V13-pipe level %lx: created\n", Level);
    if (Level >= SECURITY_MANDATORY_LOW_RID)
        ok(Error == ERROR_PRIVILEGE_NOT_HELD, "V13-pipe level %lx: %lu\n", Level, Error);
    else
        ok(Error == ERROR_ACCESS_DENIED, "V13-pipe level %lx: %lu (Windows 5)\n", Level, Error);
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);

    /* V13-key (below the Low key): Low 1314, Untrusted 5 (keys: under enforcement) */
    StringCchPrintfW(Name, _countof(Name), L"Software\\MloTest%lu\\k-low", ParentPid);
    Result = RegOpenKeyExW(HKEY_CURRENT_USER, Name, 0, KEY_CREATE_SUB_KEY, &Parent);
    if (Result == ERROR_SUCCESS)
    {
        StringCchPrintfW(Name, _countof(Name), L"v13-%lx", Level);
        Result = RegCreateKeyExW(Parent, Name, 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Key, NULL);
        if (Result == ERROR_SUCCESS) { RegCloseKey(Key); RegDeleteKeyW(Parent, Name); }
        RegCloseKey(Parent);
    }
    if (Level >= SECURITY_MANDATORY_LOW_RID)
        ok(Result == ERROR_PRIVILEGE_NOT_HELD, "V13-key level %lx: %ld\n", Level, Result);
    else
        todo_ros_if(!KeysEnforced) ok(Result == ERROR_ACCESS_DENIED, "V13-key level %lx: %ld (Windows 5)\n", Level, Result);
    LocalFree(Sa.lpSecurityDescriptor);

    if (FileAcls)
    {
        /* V13-dir: an inherit-only High label from Low: ERROR_INVALID_LABEL (1299); Untrusted 5 */
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(HighIo, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL))
        {
            StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir\\v13dir-%lx", BaseDir, Level);
            Ok = CreateDirectoryW(Name, &Sa);
            Error = Ok ? 0 : GetLastError();
            ok(!Ok && Error == (Level >= SECURITY_MANDATORY_LOW_RID ? ERROR_INVALID_LABEL : ERROR_ACCESS_DENIED),
               "V13-dir level %lx: %d, %lu\n", Level, Ok, Error);
            if (Ok) RemoveDirectoryW(Name);
            LocalFree(Sa.lpSecurityDescriptor);
        }

    }

    /* V7-pipe: a named pipe with the default descriptor: Low creates it, Untrusted does not (5) */
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-v7-%lx", ParentPid, Level);
    Handle = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, 0, 1, 64, 64, 0, NULL);
    Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (Level >= SECURITY_MANDATORY_LOW_RID)
    {
        ok(Handle != INVALID_HANDLE_VALUE, "V7-pipe level %lx: %lu\n", Level, Error);
        if (Handle != INVALID_HANDLE_VALUE)
        {
            /* V7-pipe-label: S:(ML;;NW;;;LW) */
            Policy = 0; Flags = 0xff;
            ok(LabelOf(Handle, SE_KERNEL_OBJECT, &Policy, &Flags) == Level && Flags == 0,
               "V7-pipe-label level %lx: flags %x\n", Level, Flags);
        }
    }
    else
    {
        ok(Handle == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "V7-pipe level %lx: %lu (Windows 5)\n", Level, Error);
    }
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);

    /* V7-pipe-anon: an anonymous pipe is made at every level (an Untrusted process creates no named pipe but CreatePipe
       works: the pipe has no name) and carries data */
    {
        HANDLE Read = NULL, Write = NULL;
        BYTE Byte = 0x5a, Back = 0;
        DWORD Done = 0;

        SetLastError(0xdeadbeef);
        Ok = CreatePipe(&Read, &Write, NULL, 0);
        ok(Ok, "V7-pipe-anon level %lx: CreatePipe %lu\n", Level, GetLastError());
        if (Ok)
        {
            ok(WriteFile(Write, &Byte, 1, &Done, NULL) && Done == 1, "V7-pipe-anon level %lx: write %lu\n", Level, GetLastError());
            ok(ReadFile(Read, &Back, 1, &Done, NULL) && Done == 1 && Back == Byte, "V7-pipe-anon level %lx: read %lu\n", Level, GetLastError());
            CloseHandle(Read);
            CloseHandle(Write);
        }
    }
    Handle = INVALID_HANDLE_VALUE;
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);

    /* V7-file-label: a file in the Low (OICI) directory inherits (ML;ID;NW;;;LW) */
    if (FileAcls && Level >= SECURITY_MANDATORY_LOW_RID)
    {
        StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir\\v7-%lx.txt", BaseDir, Level);
        Handle = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        ok(Handle != INVALID_HANDLE_VALUE, "V7-file level %lx: %lu\n", Level, GetLastError());
        if (Handle != INVALID_HANDLE_VALUE)
        {
            DWORD Label;

            Policy = 0; Flags = 0;
            Label = LabelOf(Handle, SE_FILE_OBJECT, &Policy, &Flags);
            ok(Label == SECURITY_MANDATORY_LOW_RID && Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
               "V7-file-label level %lx: %lx policy %lx\n", Level, Label, Policy);
            /* Windows marks an inherited label ACE inherited (ID) also where the DACL's are not */
            ok(Flags == INHERITED_ACE, "V7-file-label level %lx: flags %x\n", Level, Flags);
            CloseHandle(Handle);
            DeleteFileW(Name);
        }
    }

    /* V7-key: a key with the default descriptor below the Low key: Low creates it, Untrusted does not (5) */
    StringCchPrintfW(Name, _countof(Name), L"Software\\MloTest%lu\\k-low\\v7-%lx", ParentPid, Level);
    Result = RegCreateKeyExW(HKEY_CURRENT_USER, Name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    if (Result == ERROR_SUCCESS) { RegCloseKey(Key); RegDeleteKeyW(HKEY_CURRENT_USER, Name); }
    if (Level >= SECURITY_MANDATORY_LOW_RID)
        ok(Result == ERROR_SUCCESS, "V7-key level %lx: %ld\n", Level, Result);
    else
        todo_ros_if(!KeysEnforced) ok(Result == ERROR_ACCESS_DENIED, "V7-key level %lx: %ld (Windows 5)\n", Level, Result);
}

/* V14: the window station and the desktop of a Low process (an Untrusted process cannot load user32 on Windows) */
static VOID ChildRowsV14(DWORD Level)
{
    static const char Text[] = "mlo-test-string";
    HGLOBAL Memory;
    HDESK Desktop;
    HHOOK Hook;
    HWND Window;
    ATOM Atom;
    DWORD Policy = 0, Error;
    BYTE Flags = 0xff;
    BOOL Ok;

    if (Level < SECURITY_MANDATORY_LOW_RID)
    {
        /* V14 (Untrusted): user32.dll does not initialise on Windows (1114); not so here (see the README) */
        trace("V14 level %lx: user32 loaded (Windows: ERROR_DLL_INIT_FAILED)\n", Level);
        return;
    }

    /* V14-clip-open/-empty/-set/-get */
    Ok = OpenClipboard(NULL);
    ok(Ok, "V14-clip-open level %lx: %lu\n", Level, GetLastError());
    if (Ok)
    {
        ok(EmptyClipboard(), "V14-clip-empty level %lx: %lu\n", Level, GetLastError());
        Memory = GlobalAlloc(GMEM_MOVEABLE, sizeof(Text));
        if (Memory)
        {
            memcpy(GlobalLock(Memory), Text, sizeof(Text));
            GlobalUnlock(Memory);
            ok(SetClipboardData(CF_TEXT, Memory) != NULL, "V14-clip-set level %lx: %lu\n", Level, GetLastError());
        }
        ok(GetClipboardData(CF_TEXT) != NULL, "V14-clip-get level %lx: %lu\n", Level, GetLastError());
        CloseClipboard();
    }

    /* V14-atom, V14-window */
    Atom = GlobalAddAtomW(L"mlo_test_atom");
    ok(Atom != 0, "V14-atom level %lx: %lu\n", Level, GetLastError());
    if (Atom) GlobalDeleteAtom(Atom);
    Window = CreateWindowExW(0, L"STATIC", L"mlo", WS_POPUP, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    ok(Window != NULL, "V14-window level %lx: %lu\n", Level, GetLastError());
    if (Window) DestroyWindow(Window);

    /* V14-hook-ll: a low-level keyboard hook; V14-hook-kb: a global WH_KEYBOARD hook without a module: 1428 */
    Hook = SetWindowsHookExW(WH_KEYBOARD_LL, HookProc, GetModuleHandleW(NULL), 0);
    ok(Hook != NULL, "V14-hook-ll level %lx: %lu\n", Level, GetLastError());
    if (Hook) UnhookWindowsHookEx(Hook);
    SetLastError(0xdeadbeef);
    Hook = SetWindowsHookExW(WH_KEYBOARD, HookProc, NULL, 0);
    Error = Hook ? 0 : GetLastError();
    ok(Hook == NULL && Error == ERROR_HOOK_NEEDS_HMOD, "V14-hook-kb level %lx: %p, %lu\n", Level, Hook, Error);
    if (Hook) UnhookWindowsHookEx(Hook);

    /* V14-desk-rights; V14-desk-default: the Default desktop is labelled Low, NO_WRITE_UP, not inheritable */
    Desktop = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL);
    ok(Desktop != NULL, "V14-desk-rights level %lx: %lu\n", Level, GetLastError());
    if (Desktop) CloseDesktop(Desktop);
    ok(LabelOf(GetThreadDesktop(GetCurrentThreadId()), SE_WINDOW_OBJECT, &Policy, &Flags) == SECURITY_MANDATORY_LOW_RID &&
       Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP && Flags == 0,
       "V14-desk-default level %lx: policy %lx flags %x\n", Level, Policy, Flags);
    Policy = 0; Flags = 0xff;
    ok(LabelOf(GetProcessWindowStation(), SE_WINDOW_OBJECT, &Policy, &Flags) == SECURITY_MANDATORY_LOW_RID &&
       Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP && Flags == 0,
       "V14-winsta level %lx: policy %lx flags %x\n", Level, Policy, Flags);
}

/* V15: devices and file system roots for read, write and both */
static VOID ChildRowsV15(DWORD Level, DWORD ParentLevel)
{
    static const struct
    {
        PCWSTR Path;
        PCSTR Row;
        BOOL WriteUntrusted;    /* write allowed to Untrusted */
        BOOL WriteLow;          /* write allowed to Low */
    } Devices[] =
    {
        {L"\\\\.\\NUL", "V15-nul", FALSE, TRUE},
        {L"\\\\.\\GLOBALROOT\\Device\\Null", "V15-null-glob", FALSE, TRUE},
        {L"\\\\.\\GLOBALROOT\\Device\\KsecDD", "V15-ksecdd", FALSE, TRUE},
        {L"\\\\.\\GLOBALROOT\\Device\\Afd", "V15-afd", FALSE, TRUE},
        {L"CONOUT$", "V15-conout", TRUE, TRUE},
        {L"CONIN$", "V15-conin", TRUE, TRUE},
        {L"\\\\.\\pipe\\", "V15-pipefs", TRUE, TRUE},
        {L"\\\\.\\mailslot\\", "V15-mailslotfs", TRUE, TRUE},
        {L"\\\\.\\GLOBALROOT\\Device\\Tcp", "V15-tcp", FALSE, FALSE},
    };
    static const ACCESS_MASK Requests[] = {GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE};
    WSADATA WsaData;
    SOCKET Socket;
    HANDLE Handle;
    DWORD Error, i, r, Code;
    BOOL Expected;

    for (i = 0; i < _countof(Devices); i++)
    {
        for (r = 0; r < _countof(Requests); r++)
        {
            /* Read: every row (Tcp for read: the administrator's children; a standard user's DACL refuses it) */
            if (Requests[r] & GENERIC_WRITE)
                Expected = (Level >= SECURITY_MANDATORY_LOW_RID) ? Devices[i].WriteLow : Devices[i].WriteUntrusted;
            else
                Expected = TRUE;
            Handle = CreateFileW(Devices[i].Path, Requests[r], FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
            /* The label decides only between granted and ERROR_ACCESS_DENIED: a driver may refuse an open of its own */
            if (Expected)
                ok(Error != ERROR_ACCESS_DENIED, "%s level %lx: %S for 0x%lx: access denied\n",
                   Devices[i].Row, Level, Devices[i].Path, Requests[r]);
            else
                ok(Error == ERROR_ACCESS_DENIED, "%s level %lx: %S for 0x%lx: error %lu\n",
                   Devices[i].Row, Level, Devices[i].Path, Requests[r], Error);
            if (Error && Error != ERROR_ACCESS_DENIED)
                trace("%s level %lx: %S for 0x%lx: error %lu\n", Devices[i].Row, Level, Devices[i].Path, Requests[r], Error);
            if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);
        }
    }

    /* V15-physdrive0: attributes of the disk */
    Handle = CreateFileW(L"\\\\.\\PhysicalDrive0", FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "V15-physdrive0 level %lx: %lu\n", Level, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);

    /* V15-afd-socket: a socket for Low and Untrusted */
    if (!WSAStartup(MAKEWORD(2, 2), &WsaData))
    {
        Socket = socket(AF_INET, SOCK_STREAM, 0);
        ok(Socket != INVALID_SOCKET, "V15-afd-socket level %lx: %d\n", Level, WSAGetLastError());
        if (Socket != INVALID_SOCKET) closesocket(Socket);
        WSACleanup();
    }

    /* V15-cmd-nul: cmd /c echo x > nul exits 0 at Low, 1 at Untrusted */
    Code = RunCmd(L"echo x > nul");
    ok(Code == (Level >= SECURITY_MANDATORY_LOW_RID ? 0 : 1), "V15-cmd-nul level %lx: exit code %lu\n", Level, Code);
    (void)ParentLevel;
}

/* V17: the parent's token impersonated (identification only); V3: the parent's process; V8, V9 */
static VOID ChildRowsV17V3V8V9(DWORD Level, DWORD ParentLevel)
{
    static const struct { ACCESS_MASK Access; PCSTR Name; BOOL Allowed; } ProcessRows[] =
    {
        {PROCESS_TERMINATE, "terminate", TRUE}, {PROCESS_QUERY_LIMITED_INFORMATION, "query_limited", TRUE},
        {SYNCHRONIZE, "synchronize", TRUE}, {PROCESS_QUERY_INFORMATION, "query", FALSE},
        {PROCESS_VM_READ, "vm_read", FALSE}, {PROCESS_DUP_HANDLE, "dup_handle", FALSE},
    };
    static const PCWSTR Privileges[] = {L"SeBackupPrivilege", L"SeRestorePrivilege", L"SeDebugPrivilege", L"SeShutdownPrivilege"};
    SECURITY_IMPERSONATION_LEVEL ImpLevel = SecurityAnonymous;
    TOKEN_PRIVILEGES Tp;
    WCHAR Name[MAX_PATH], File[MAX_PATH];
    HANDLE Process, Token, Dup, Again, Handle;
    DWORD Attributes, Error, ThreadLevel = MAXDWORD, EventError = 0, FileError = 0, Length, i;
    BOOL Ok, Impersonating = FALSE;

    /* V17-priv: SeImpersonatePrivilege of this child: present and disabled (the administrator's children) */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        Attributes = PrivilegeAttributes(Token, L"SeImpersonatePrivilege");
        if (ParentLevel >= SECURITY_MANDATORY_HIGH_RID)
            ok(Attributes == 0, "V17-priv level %lx: SeImpersonatePrivilege attributes 0x%lx\n", Level, Attributes);
        else
            ok(Attributes == MAXDWORD || !(Attributes & SE_PRIVILEGE_ENABLED), "V17-priv level %lx: 0x%lx\n", Level, Attributes);
        CloseHandle(Token);
    }

    /* V17-3..-7: the parent's token as an impersonation token: identification only; opens then fail with 1346 */
    StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-high", ParentPid);
    StringCchPrintfW(File, _countof(File), L"%s\\f-med", BaseDir);
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParentPid);
    if (Process && OpenProcessToken(Process, TOKEN_QUERY | TOKEN_DUPLICATE, &Token))
    {
        Dup = NULL;
        Ok = DuplicateTokenEx(Token, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, NULL, SecurityImpersonation, TokenImpersonation, &Dup);
        ok(Ok && TokenLevel(Dup) == ParentLevel, "V17-3 level %lx: %d, %lu\n", Level, Ok, GetLastError());
        if (Ok)
        {
            Impersonating = SetThreadToken(NULL, Dup);
            ok(Impersonating, "V17-4 level %lx: %lu\n", Level, GetLastError());
        }
        if (Impersonating)
        {
            /* Nothing is printed while impersonating: the results are checked after RevertToSelf */
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Again))
            {
                GetTokenInformation(Again, TokenImpersonationLevel, &ImpLevel, sizeof(ImpLevel), &Length);
                ThreadLevel = TokenLevel(Again);
                CloseHandle(Again);
            }
            Handle = OpenEventW(EVENT_MODIFY_STATE, FALSE, Name);
            EventError = Handle ? 0 : GetLastError();
            if (Handle) CloseHandle(Handle);
            Handle = CreateFileW(File, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
            FileError = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
            if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);
            RevertToSelf();

            /* V17-5 */
            ok(ImpLevel == SecurityIdentification && ThreadLevel == ParentLevel, "V17-5 level %lx: impersonation level %d, integrity %lx\n",
               Level, ImpLevel, ThreadLevel);
            /* V17-6: the High-labelled event: Low 1346, Untrusted 5 */
            if (Level >= SECURITY_MANDATORY_LOW_RID)
                ok(EventError == ERROR_BAD_IMPERSONATION_LEVEL, "V17-6 level %lx: %lu\n", Level, EventError);
            else
                ok(EventError == ERROR_ACCESS_DENIED, "V17-6 level %lx: %lu\n", Level, EventError);
            /* V17-7: the Medium-labelled file for write: 1346 */
            if (FileAcls)
                ok(FileError == ERROR_BAD_IMPERSONATION_LEVEL, "V17-7 level %lx: %lu\n", Level, FileError);
        }
        if (Dup) CloseHandle(Dup);
        CloseHandle(Token);
    }
    else
    {
        ok(0, "V17 level %lx: the parent's token: %lu\n", Level, GetLastError());
    }

    /* V17-8: the High-labelled event without impersonation: 5 */
    Handle = OpenEventW(EVENT_MODIFY_STATE, FALSE, Name);
    Error = Handle ? 0 : GetLastError();
    ok(Handle == NULL && Error == ERROR_ACCESS_DENIED, "V17-8 level %lx: %p, %lu\n", Level, Handle, Error);
    if (Handle) CloseHandle(Handle);

    /* V3-proc: the parent's process: terminate, limited query and synchronize, nothing else */
    for (i = 0; i < _countof(ProcessRows); i++)
    {
        Handle = OpenProcess(ProcessRows[i].Access, FALSE, ParentPid);
        Error = Handle ? 0 : GetLastError();
        ok(!!Handle == ProcessRows[i].Allowed && (Handle || Error == ERROR_ACCESS_DENIED),
           "V3-proc level %lx: %s: %p, %lu\n", Level, ProcessRows[i].Name, Handle, Error);
        if (Handle) CloseHandle(Handle);
    }
    if (Process) CloseHandle(Process);

    /* V8-priv: no privilege can be enabled (ERROR_NOT_ALL_ASSIGNED, state stays disabled) */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
    {
        for (i = 0; i < _countof(Privileges); i++)
        {
            Tp.PrivilegeCount = 1;
            Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!LookupPrivilegeValueW(NULL, Privileges[i], &Tp.Privileges[0].Luid))
                continue;
            SetLastError(0xdeadbeef);
            Ok = AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL);
            Error = GetLastError();
            Attributes = PrivilegeAttributes(Token, Privileges[i]);
            ok(Ok && Error == ERROR_NOT_ALL_ASSIGNED, "V8-priv level %lx: %S: %d, %lu\n", Level, Privileges[i], Ok, Error);
            ok(Attributes == MAXDWORD || !(Attributes & SE_PRIVILEGE_ENABLED), "V8-priv level %lx: %S attributes 0x%lx\n",
               Level, Privileges[i], Attributes);
            if (ParentLevel >= SECURITY_MANDATORY_HIGH_RID)
                ok(Attributes != MAXDWORD, "V8-priv level %lx: %S not in the token\n", Level, Privileges[i]);
        }
        CloseHandle(Token);
    }

    if (!FileAcls)
    {
        skip("level %lx: the volume keeps no security descriptors: no V8-backup / V9 rows\n", Level);
        return;
    }

    /* V8-backup: the Medium-labelled file for write with backup semantics: 5 */
    Handle = CreateFileW(File, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, NULL);
    Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    ok(Handle == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "V8-backup level %lx: %lu\n", Level, Error);
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);

    /*
     * V9: a Medium-labelled file in the Low (OICI) directory whose DACL grants Everyone full: a Low process deletes
     * it (FILE_DELETE_CHILD of the directory). Untrusted: not measured (the file was gone); by the rule it is below
     * both labels: 5
     */
    StringCchPrintfW(File, _countof(File), L"%s\\lowdir\\medfile-%lx", BaseDir, Level);
    Ok = DeleteFileW(File);
    Error = Ok ? 0 : GetLastError();
    if (Level >= SECURITY_MANDATORY_LOW_RID)
        ok(Ok, "V9 level %lx: %lu\n", Level, Error);
    else
        ok(!Ok && Error == ERROR_ACCESS_DENIED, "V9 level %lx (not measured): %d, %lu\n", Level, Ok, Error);
}

/* V16: the parent's mailslots: Everyone all without a label (refused below Medium) and with a Low label (Low writes) */
static VOID ChildRowsV16(DWORD Level)
{
    WCHAR Name[MAX_PATH];
    HANDLE Handle;
    DWORD Error, Written = 0;

    /* V16-default: refused to Low and Untrusted (5) */
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\mailslot\\mlo%lu-def", ParentPid);
    Handle = CreateFileW(Name, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    ok(Handle == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "V16-default level %lx: %lu\n", Level, Error);
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);

    /* V16-low, V16-low-write: Low opens and writes 3 bytes, Untrusted is refused (5) */
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\mailslot\\mlo%lu-low", ParentPid);
    Handle = CreateFileW(Name, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    Error = (Handle == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (Level >= SECURITY_MANDATORY_LOW_RID)
    {
        ok(Handle != INVALID_HANDLE_VALUE, "V16-low level %lx: %lu\n", Level, Error);
        if (Handle != INVALID_HANDLE_VALUE)
            ok(WriteFile(Handle, "mlo", 3, &Written, NULL) && Written == 3, "V16-low-write level %lx: %lu, %lu\n",
               Level, GetLastError(), Written);
    }
    else
    {
        ok(Handle == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "V16-low level %lx: %lu\n", Level, Error);
    }
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);
}

/* V10 (last: it lowers this process's own token): the process object's label does not follow its token */
static VOID ChildRowV10(DWORD Level)
{
    DWORD Before, After, Policy = 0;
    HANDLE Token;
    BOOL Ok;

    Before = LabelOf(GetCurrentProcess(), SE_KERNEL_OBJECT, &Policy, NULL);
    ok(Before == Level && Policy == (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP),
       "V10-before level %lx: %lx policy %lx\n", Level, Before, Policy);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &Token))
    {
        ok(0, "V10 level %lx: %lu\n", Level, GetLastError());
        return;
    }
    Ok = SetLevel(Token, SECURITY_MANDATORY_UNTRUSTED_RID);
    ok(Ok && TokenLevel(Token) == SECURITY_MANDATORY_UNTRUSTED_RID, "V10-set level %lx: %d, %lu\n", Level, Ok, GetLastError());
    CloseHandle(Token);
    Policy = 0;
    After = LabelOf(GetCurrentProcess(), SE_KERNEL_OBJECT, &Policy, NULL);
    ok(After == Level && Policy == (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP),
       "V10-after level %lx: %lx policy %lx\n", Level, After, Policy);
}

static VOID ChildWindowsRows(DWORD Level)
{
    DWORD ParentLevel = ParentLevelOf();

    ok(ParentLevel != MAXDWORD, "level %lx: the parent's level is unknown\n", Level);
    ChildRowsV2(Level);
    ChildRowsV12(Level, ParentLevel);
    ChildRowsV13V7(Level);
    ChildRowsV14(Level);
    ChildRowsV15(Level, ParentLevel);
    ChildRowsV17V3V8V9(Level, ParentLevel);
    ChildRowsV16(Level);
    ChildRowV10(Level);
}

static VOID Child(DWORD ExpectedLevel, DWORD Tid)
{
    HANDLE Token, Handle;
    DWORD Level;
    HKEY Key;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken: %lu\n", GetLastError());
    Level = TokenLevel(Token);
    CloseHandle(Token);
    ok(Level == ExpectedLevel, "child level %lx, expected %lx\n", Level, ExpectedLevel);
    if (Level != ExpectedLevel)
        return;

    /* The mappings, from handles of each type the child has full access to */
    GetMapping(GetCurrentProcess(), &Mappings[IDX_PROCESS]);
    GetMapping(GetCurrentThread(), &Mappings[IDX_THREAD]);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token)) { GetMapping(Token, &Mappings[IDX_TOKEN]); CloseHandle(Token); }
    Handle = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (Handle) { GetMapping(Handle, &Mappings[KindEvent]); CloseHandle(Handle); }
    Handle = CreateMutexW(NULL, FALSE, NULL);
    if (Handle) { GetMapping(Handle, &Mappings[KindMutex]); CloseHandle(Handle); }
    Handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    if (Handle) { GetMapping(Handle, &Mappings[KindSection]); CloseHandle(Handle); }
    Handle = CreateFileW(BaseDir, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (Handle != INVALID_HANDLE_VALUE) { GetMapping(Handle, &Mappings[KindFile]); CloseHandle(Handle); }
    Mappings[KindPipe] = Mappings[KindFile];
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
        GetMapping((HANDLE)Key, &Mappings[KindKey]);
        RegCloseKey(Key);
    }

    ChildObjectRows(Level);
    ChildParentRows(Level, Tid);
    ChildCreateRows(Level);
    ChildReviewRows(Level);
    ChildWindowsRows(Level);
}

/* ---------------------------------------------------------------- parent */

/* V3-types: the generic mappings of the object types, measured on Windows Server 2022 */
static VOID ParentRowsV3Types(void)
{
    static const struct
    {
        PCWSTR Name;
        GENERIC_MAPPING Mapping;
        ACCESS_MASK Valid;
    } Types[] =
    {
        {L"Type",          {0x00020000, 0x00020000, 0x00020000, 0x000f0001}, 0x001f0001},
        {L"Directory",     {0x00020003, 0x0002000c, 0x00020003, 0x000f000f}, 0x000f000f},
        {L"SymbolicLink",  {0x00020001, 0x00020000, 0x00020001, 0x000f0001}, 0x000fffff},
        {L"Token",         {0x0002001a, 0x000201e0, 0x00020005, 0x000f01ff}, 0x001f01ff},
        {L"Job",           {0x00020004, 0x0002000b, 0x00120000, 0x001f003f}, 0x001f003f},
        {L"Process",       {0x00020410, 0x00020bea, 0x00121001, 0x001fffff}, 0x001fffff},
        {L"Thread",        {0x00020048, 0x00020437, 0x00121800, 0x001fffff}, 0x001fffff},
        {L"Event",         {0x00020001, 0x00020002, 0x00120000, 0x001f0003}, 0x001f0003},
        {L"Mutant",        {0x00020001, 0x00020000, 0x00120000, 0x001f0001}, 0x001f0001},
        {L"Semaphore",     {0x00020001, 0x00020002, 0x00120000, 0x001f0003}, 0x001f0003},
        {L"Timer",         {0x00020001, 0x00020002, 0x00120000, 0x001f0003}, 0x001f0003},
        {L"WindowStation", {0x00020303, 0x0002001c, 0x00020060, 0x000f037f}, 0x000f037f},
        {L"Desktop",       {0x00020041, 0x000200be, 0x00020100, 0x000f01ff}, 0x000f01ff},
        {L"IoCompletion",  {0x00020001, 0x00020002, 0x00120000, 0x001f0003}, 0x001f0003},
        {L"File",          {0x00120089, 0x00120116, 0x001200a0, 0x001f01ff}, 0x001f01ff},
        {L"Section",       {0x00020005, 0x00020002, 0x00020008, 0x000f001f}, 0x001f001f},
        {L"Key",           {0x00020019, 0x00020006, 0x00020039, 0x000f003f}, 0x001f003f},
    };
    PUCHAR Buffer;
    POBJECT_TYPE_INFORMATION Info;
    ULONG Length = 0x10000, Count, i, t;
    NTSTATUS Status;
    BOOL Found[_countof(Types)] = {0};

    Buffer = HeapAlloc(GetProcessHeap(), 0, Length);
    if (!Buffer)
        return;
    Status = NtQueryObject(NULL, ObjectTypesInformation, Buffer, Length, &Length);
    if (!NT_SUCCESS(Status))
    {
        skip("V3-types: ObjectTypesInformation 0x%lx\n", Status);
        HeapFree(GetProcessHeap(), 0, Buffer);
        return;
    }
    Count = ((POBJECT_TYPES_INFORMATION)Buffer)->NumberOfTypes;
    Info = (POBJECT_TYPE_INFORMATION)(Buffer + ALIGN_UP(sizeof(ULONG), ULONG_PTR));
    for (i = 0; i < Count; i++)
    {
        for (t = 0; t < _countof(Types); t++)
        {
            if (Info->TypeName.Buffer && Info->TypeName.Length == wcslen(Types[t].Name) * sizeof(WCHAR) &&
                !_wcsnicmp(Info->TypeName.Buffer, Types[t].Name, wcslen(Types[t].Name)))
            {
                const GENERIC_MAPPING *M = &Info->GenericMapping;
                /*
                 * Known differences, not label rules (tickets): Thread GenericExecute without THREAD_RESUME,
                 * Job GenericAll/valid without 0x20, SymbolicLink valid mask
                 */
                BOOL KnownMapping = !wcscmp(Types[t].Name, L"Thread") || !wcscmp(Types[t].Name, L"Job");
                BOOL KnownValid = !wcscmp(Types[t].Name, L"Job") || !wcscmp(Types[t].Name, L"SymbolicLink");

                Found[t] = TRUE;
                todo_ros_if(KnownMapping)
                ok(M->GenericRead == Types[t].Mapping.GenericRead && M->GenericWrite == Types[t].Mapping.GenericWrite &&
                   M->GenericExecute == Types[t].Mapping.GenericExecute && M->GenericAll == Types[t].Mapping.GenericAll,
                   "V3-types %S: 0x%08lx 0x%08lx 0x%08lx 0x%08lx, Windows 0x%08lx 0x%08lx 0x%08lx 0x%08lx\n", Types[t].Name,
                   M->GenericRead, M->GenericWrite, M->GenericExecute, M->GenericAll,
                   Types[t].Mapping.GenericRead, Types[t].Mapping.GenericWrite,
                   Types[t].Mapping.GenericExecute, Types[t].Mapping.GenericAll);
                todo_ros_if(KnownValid)
                ok(Info->ValidAccessMask == Types[t].Valid, "V3-types %S: valid 0x%08lx, Windows 0x%08lx\n",
                   Types[t].Name, Info->ValidAccessMask, Types[t].Valid);
            }
        }
        Info = (POBJECT_TYPE_INFORMATION)((PUCHAR)(Info + 1) + ALIGN_UP(Info->TypeName.MaximumLength, ULONG_PTR));
    }
    for (t = 0; t < _countof(Types); t++)
        ok(Found[t], "V3-types %S: not listed\n", Types[t].Name);
    HeapFree(GetProcessHeap(), 0, Buffer);
}

/* V2 labels of the named object directories, V6 labels of the devices (read by the parent) */
static VOID ParentRowsLabels(void)
{
    static const struct
    {
        PCWSTR Path;
        BOOL Directory;
        DWORD Level;    /* MAXDWORD: no label */
        PCSTR Row;
    } Objects[] =
    {
        {L"\\BaseNamedObjects", TRUE, SECURITY_MANDATORY_LOW_RID, "V2-bno"},
        {L"\\BaseNamedObjects\\Restricted", TRUE, SECURITY_MANDATORY_LOW_RID, "V2-bno-restricted"},
        {L"\\RPC Control", TRUE, SECURITY_MANDATORY_LOW_RID, "V2-objects-rpcctl"},
        {L"\\Device\\Null", FALSE, SECURITY_MANDATORY_LOW_RID, "V6-null"},
        {L"\\Device\\KsecDD", FALSE, SECURITY_MANDATORY_LOW_RID, "V6-ksecdd"},
        {L"\\Device\\Afd", FALSE, SECURITY_MANDATORY_LOW_RID, "V6-afd"},
        {L"\\Device\\Tcp", FALSE, MAXDWORD, "V6-tcp"},
    };
    WCHAR Path[MAX_PATH];
    DWORD Session = 0, Level, Policy, i;
    BYTE Flags;

    for (i = 0; i < _countof(Objects); i++)
    {
        Policy = 0; Flags = 0xff;
        Level = LabelOfNtPath(Objects[i].Path, Objects[i].Directory, &Policy, &Flags);
        if (Level == MAXDWORD - 1 && !Objects[i].Directory)
        {
            /* A driver may refuse an open of the device itself (no extended attributes): nothing to read */
            skip("%s: %S cannot be opened\n", Objects[i].Row, Objects[i].Path);
            continue;
        }
        ok(Level == Objects[i].Level, "%s: %S labelled %lx\n", Objects[i].Row, Objects[i].Path, Level);
        if (Level != MAXDWORD && Level == Objects[i].Level)
            ok(Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP && Flags == 0, "%s: %S policy %lx flags %x\n",
               Objects[i].Row, Objects[i].Path, Policy, Flags);
    }

    /* V14-desk-winlogon-parent: the Winlogon desktop is not opened for READ_CONTROL by the parent (5) */
    {
        HDESK Desktop = OpenDesktopW(L"Winlogon", 0, FALSE, READ_CONTROL);
        DWORD Error = Desktop ? 0 : GetLastError();

        ok(Desktop == NULL && Error == ERROR_ACCESS_DENIED, "V14-desk-winlogon-parent: %p, %lu\n", Desktop, Error);
        if (Desktop) CloseDesktop(Desktop);
    }

    /* V2-bno-session: the session's own directory */
    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    StringCchPrintfW(Path, _countof(Path), L"\\Sessions\\%lu\\BaseNamedObjects", Session);
    Policy = 0; Flags = 0xff;
    Level = LabelOfNtPath(Path, TRUE, &Policy, &Flags);
    ok(Level == SECURITY_MANDATORY_LOW_RID && Policy == SYSTEM_MANDATORY_LABEL_NO_WRITE_UP && Flags == 0,
       "V2-bno-session: %S labelled %lx policy %lx flags %x\n", Path, Level, Policy, Flags);
}

/* lower-priv-*: lowering a duplicate of the parent's token disables its privileges, which stay disabled */
static VOID ParentRowsLowerPrivileges(DWORD Level)
{
    TOKEN_PRIVILEGES Tp;
    HANDLE Token, Dup = NULL;
    DWORD Before, After, Error;
    BOOL Ok;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        return;
    Ok = DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Dup);
    CloseHandle(Token);
    if (!Ok)
        return;

    /* lower-priv-before: SeImpersonatePrivilege 0x3 (High parent), absent (Medium parent) */
    Before = PrivilegeAttributes(Dup, L"SeImpersonatePrivilege");
    if (Level >= SECURITY_MANDATORY_HIGH_RID)
        ok(Before == (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT), "lower-priv-before: 0x%lx\n", Before);
    ok(SetLevel(Dup, SECURITY_MANDATORY_LOW_RID), "SetTokenInformation(Low): %lu\n", GetLastError());

    /* lower-priv-after: 0x0 */
    After = PrivilegeAttributes(Dup, L"SeImpersonatePrivilege");
    if (Before != MAXDWORD)
        ok(After == 0, "lower-priv-after: 0x%lx\n", After);

    /* spawn-priv2: enabling it again leaves it disabled; the call returns TRUE with ERROR_NOT_ALL_ASSIGNED (Windows Server 2022,
       a duplicate lowered to Low by the High parent: 1300 for every privilege but SeChangeNotifyPrivilege, also when the
       parent had enabled it first; an earlier probe that printed GetLastError after other calls had read 0) */
    if (Before != MAXDWORD && LookupPrivilegeValueW(NULL, L"SeImpersonatePrivilege", &Tp.Privileges[0].Luid))
    {
        Tp.PrivilegeCount = 1;
        Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(0xdeadbeef);
        Ok = AdjustTokenPrivileges(Dup, FALSE, &Tp, 0, NULL, NULL);
        Error = GetLastError();
        ok(Ok, "spawn-priv2: %lu\n", Error);
        ok(Error == ERROR_NOT_ALL_ASSIGNED, "spawn-priv2: GetLastError %lu, Windows 1300\n", Error);
        After = PrivilegeAttributes(Dup, L"SeImpersonatePrivilege");
        ok(After == 0, "spawn-priv2: attributes 0x%lx\n", After);
    }

    /* Changing SeChangeNotifyPrivilege is not measured; it stays enabled here (traverse checking) */
    trace("lowered token: SeChangeNotifyPrivilege 0x%lx\n", PrivilegeAttributes(Dup, L"SeChangeNotifyPrivilege"));
    CloseHandle(Dup);
}

/* V13 from the parent: labels at its own level are accepted; P-event-high */
static VOID ParentRowsV13(DWORD Level, PHANDLE HighEvent)
{
    SECURITY_ATTRIBUTES Sa = {sizeof(Sa), NULL, FALSE};
    WCHAR Name[MAX_PATH];
    HANDLE Handle;
    BOOL Ok;

    *HighEvent = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)S:(ML;;NW;;;HI)", SDDL_REVISION_1,
                                                             &Sa.lpSecurityDescriptor, NULL))
        return;

    /* P-event-high: the High parent creates the High-labelled event the children open (V17); a Medium one: 1314 */
    StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-high", ParentPid);
    *HighEvent = CreateEventW(&Sa, FALSE, FALSE, Name);
    if (Level >= SECURITY_MANDATORY_HIGH_RID)
        ok(*HighEvent != NULL, "P-event-high: %lu\n", GetLastError());
    else
        ok(*HighEvent == NULL && GetLastError() == ERROR_PRIVILEGE_NOT_HELD, "P-event-high: %lu\n", GetLastError());

    /* V13-file / V13-pipe / V13-dir from the parent (the Medium parent's column: 1314 each) */
    StringCchPrintfW(Name, _countof(Name), L"%s\\v13-parent.txt", BaseDir);
    Handle = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, &Sa, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok((Handle != INVALID_HANDLE_VALUE) == (Level >= SECURITY_MANDATORY_HIGH_RID), "V13-file parent: %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-v13-parent", ParentPid);
    Handle = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX, 0, 1, 64, 64, 0, &Sa);
    ok((Handle != INVALID_HANDLE_VALUE) == (Level >= SECURITY_MANDATORY_HIGH_RID), "V13-pipe parent: %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);
    LocalFree(Sa.lpSecurityDescriptor);

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)S:(ML;OICIIO;NW;;;HI)", SDDL_REVISION_1,
                                                            &Sa.lpSecurityDescriptor, NULL))
    {
        StringCchPrintfW(Name, _countof(Name), L"%s\\v13dir-parent", BaseDir);
        Ok = CreateDirectoryW(Name, &Sa);
        ok(Ok == (Level >= SECURITY_MANDATORY_HIGH_RID), "V13-dir parent: %lu\n", GetLastError());
        if (Ok) RemoveDirectoryW(Name);
        LocalFree(Sa.lpSecurityDescriptor);
    }
}

/* Everyone gets Mask (GENERIC_ALL where the create maps it; a specific mask for a descriptor that is set) */
static PSECURITY_DESCRIPTOR MakeSd(ULONG Variant, BOOL Inherit, ACCESS_MASK Mask, PSECURITY_DESCRIPTOR Sd, PACL Dacl, PACL Sacl)
{
    SID_IDENTIFIER_AUTHORITY World = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY LabelAuth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    BYTE WorldSid[SECURITY_MAX_SID_SIZE], LabelSid[SECURITY_MAX_SID_SIZE];
    BYTE AceFlags = Inherit ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) : 0;

    InitializeSid((PSID)WorldSid, &World, 1);
    *GetSidSubAuthority((PSID)WorldSid, 0) = SECURITY_WORLD_RID;
    InitializeSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    InitializeAcl(Dacl, 256, ACL_REVISION);
    AddAccessAllowedAceEx(Dacl, ACL_REVISION, AceFlags, Mask, (PSID)WorldSid);
    SetSecurityDescriptorDacl(Sd, TRUE, Dacl, FALSE);
    if (Variants[Variant].Level != MAXDWORD)
    {
        InitializeSid((PSID)LabelSid, &LabelAuth, 1);
        *GetSidSubAuthority((PSID)LabelSid, 0) = Variants[Variant].Level;
        InitializeAcl(Sacl, 256, ACL_REVISION);
        ok(pAddMandatoryAce(Sacl, ACL_REVISION, AceFlags, Variants[Variant].Policy, (PSID)LabelSid),
           "AddMandatoryAce: %lu\n", GetLastError());
        SetSecurityDescriptorSacl(Sd, TRUE, Sacl, FALSE);
    }
    return Sd;
}

static BOOL LoweredToken(DWORD Level, PHANDLE Out)
{
    SID_IDENTIFIER_AUTHORITY LabelAuth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    TOKEN_MANDATORY_LABEL Label;
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        return FALSE;
    Ret = DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, Out);
    CloseHandle(Token);
    ok(Ret, "DuplicateTokenEx: %lu\n", GetLastError());
    if (!Ret)
        return FALSE;
    InitializeSid((PSID)Sid, &LabelAuth, 1);
    *GetSidSubAuthority((PSID)Sid, 0) = Level;
    Label.Label.Sid = (PSID)Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Ret = SetTokenInformation(*Out, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid((PSID)Sid));
    ok(Ret, "SetTokenInformation(%lx): %lu\n", Level, GetLastError());
    if (!Ret)
        CloseHandle(*Out);
    return Ret;
}

static VOID RunChild(DWORD Level)
{
    WCHAR Path[MAX_PATH], Command[MAX_PATH * 2];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Pi;
    HANDLE Token;

    if (!LoweredToken(Level, &Token))
        return;
    GetModuleFileNameW(NULL, Path, _countof(Path));
    StringCchPrintfW(Command, _countof(Command), L"\"%s\" MandatoryLabelOpen child %lx %lu %lu \"%s\"",
                     Path, Level, GetCurrentProcessId(), GetCurrentThreadId(), BaseDir);
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    Startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessAsUserW(Token, Path, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Pi))
    {
        ok(0, "CreateProcessAsUser(level %lx): %lu\n", Level, GetLastError());
        CloseHandle(Token);
        return;
    }
    CloseHandle(Token);
    winetest_wait_child_process(&Pi);
}

START_TEST(MandatoryLabelOpen)
{
    PSECURITY_DESCRIPTOR SdBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH / sizeof(PVOID) + 1];
    ULONG DaclBuffer[64], SaclBuffer[64];
    SECURITY_ATTRIBUTES Sa = {sizeof(Sa), SdBuffer, FALSE};
    HANDLE Objects[KindCount][NVARIANTS][PIPE_INSTANCES], Token, PevEvent, HighEvent = NULL, Slots[2] = {NULL, NULL};
    WCHAR Name[MAX_PATH], Windows[MAX_PATH];
    ULONG Kind, Variant, i;
    char **Argv;
    DWORD Level, Policy;
    HKEY Key, Root;
    LONG Result;

    pAddMandatoryAce = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "AddMandatoryAce");
    if (!pAddMandatoryAce)
    {
        skip("AddMandatoryAce is not available\n");
        return;
    }

    if (winetest_get_mainargs(&Argv) >= 7 && !strcmp(Argv[2], "child"))
    {
        ParentPid = strtoul(Argv[4], NULL, 10);
        MultiByteToWideChar(CP_ACP, 0, Argv[6], -1, BaseDir, _countof(BaseDir));
        DetectVolumes();
        Child(strtoul(Argv[3], NULL, 16), strtoul(Argv[5], NULL, 10));
        return;
    }

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken: %lu\n", GetLastError());
    Level = TokenLevel(Token);
    CloseHandle(Token);
    trace("parent level %lx, registry ACL mode %lu\n", Level, RegAclMode());
    if (Level < SECURITY_MANDATORY_MEDIUM_RID)
    {
        skip("the test needs a caller at Medium or above\n");
        return;
    }
    ParentPid = GetCurrentProcessId();

    /* The child expects the parent's process and thread labelled at the parent's level with NW|NR */
    Policy = 0;
    ok(LabelOf(GetCurrentProcess(), SE_KERNEL_OBJECT, &Policy, NULL) == Level, "parent process label\n");
    ok(Policy == (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP), "process policy %lx\n", Policy);
    ok(LabelOf(GetCurrentThread(), SE_KERNEL_OBJECT, &Policy, NULL) == Level, "parent thread label\n");

    /* The parent's process and thread: a DACL that grants Everyone everything, so that the label decides */
    /* (the NT 6 masks: the SDK's PROCESS_ALL_ACCESS / THREAD_ALL_ACCESS of an NT 5 build lack the limited rights) */
    MakeSd(0, FALSE, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);
    ok(SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, SdBuffer), "process DACL: %lu\n", GetLastError());
    MakeSd(0, FALSE, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);
    ok(SetKernelObjectSecurity(GetCurrentThread(), DACL_SECURITY_INFORMATION, SdBuffer), "thread DACL: %lu\n", GetLastError());

    /* Scratch directory on the system volume: Everyone full, no label; lowdir: Low OICI */
    GetWindowsDirectoryW(Windows, _countof(Windows));
    StringCchPrintfW(BaseDir, _countof(BaseDir), L"%.2s\\mlo%lu", Windows, ParentPid);
    DetectVolumes();
    if (!FileAcls || !ProfileAcls)
        skip("the volume keeps no security descriptors (FAT): the file rows of the children are skipped\n");
    MakeSd(0, TRUE, GENERIC_ALL, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);
    ok(CreateDirectoryW(BaseDir, &Sa), "CreateDirectory %S: %lu\n", BaseDir, GetLastError());
    StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir", BaseDir);
    MakeSd(1, TRUE, GENERIC_ALL, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);
    ok(CreateDirectoryW(Name, &Sa), "CreateDirectory %S: %lu\n", Name, GetLastError());

    StringCchPrintfW(Name, _countof(Name), L"Software\\MloTest%lu", ParentPid);
    MakeSd(0, TRUE, GENERIC_ALL, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);
    Result = RegCreateKeyExW(HKEY_CURRENT_USER, Name, 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Root, NULL);
    ok(Result == ERROR_SUCCESS, "RegCreateKeyEx %S: %ld\n", Name, Result);
    if (Result != ERROR_SUCCESS)
        Root = NULL;

    ZeroMemory(Objects, sizeof(Objects));
    for (Variant = 0; Variant < NVARIANTS; Variant++)
    {
        MakeSd(Variant, FALSE, GENERIC_ALL, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);

        StringCchPrintfW(Name, _countof(Name), L"%s\\f-%s", BaseDir, Variants[Variant].Name);
        Objects[KindFile][Variant][0] = CreateFileW(Name, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                    &Sa, CREATE_NEW, 0, NULL);
        ok(Objects[KindFile][Variant][0] != INVALID_HANDLE_VALUE, "file %S: %lu\n", Name, GetLastError());
        if (Objects[KindFile][Variant][0] == INVALID_HANDLE_VALUE) Objects[KindFile][Variant][0] = NULL;

        if (Root)
        {
            StringCchPrintfW(Name, _countof(Name), L"k-%s", Variants[Variant].Name);
            Result = RegCreateKeyExW(Root, Name, 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Key, NULL);
            ok(Result == ERROR_SUCCESS, "key %S: %ld\n", Name, Result);
            if (Result == ERROR_SUCCESS) RegCloseKey(Key);
        }

        StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-e-%s", ParentPid, Variants[Variant].Name);
        Objects[KindEvent][Variant][0] = CreateEventW(&Sa, TRUE, FALSE, Name);
        ok(Objects[KindEvent][Variant][0] != NULL, "event %S: %lu\n", Name, GetLastError());
        StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-m-%s", ParentPid, Variants[Variant].Name);
        Objects[KindMutex][Variant][0] = CreateMutexW(&Sa, FALSE, Name);
        ok(Objects[KindMutex][Variant][0] != NULL, "mutex %S: %lu\n", Name, GetLastError());
        StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-s-%s", ParentPid, Variants[Variant].Name);
        Objects[KindSection][Variant][0] = CreateFileMappingW(INVALID_HANDLE_VALUE, &Sa, PAGE_READWRITE, 0, 4096, Name);
        ok(Objects[KindSection][Variant][0] != NULL, "section %S: %lu\n", Name, GetLastError());

        /* One listening instance per open that may succeed (overlapped: nobody waits for the client) */
        StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-p-%s", ParentPid, Variants[Variant].Name);
        for (i = 0; i < PIPE_INSTANCES; i++)
        {
            Objects[KindPipe][Variant][i] = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                                             PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &Sa);
            ok(Objects[KindPipe][Variant][i] != INVALID_HANDLE_VALUE, "pipe %S: %lu\n", Name, GetLastError());
            if (Objects[KindPipe][Variant][i] == INVALID_HANDLE_VALUE) Objects[KindPipe][Variant][i] = NULL;
        }
    }

    /* The Windows rows: P-event (default descriptor), P-event-high, P-file-v9 (a Medium file per child in lowdir) */
    StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-pev", ParentPid);
    PevEvent = CreateEventW(NULL, FALSE, FALSE, Name);
    ok(PevEvent != NULL, "P-event: %lu\n", GetLastError());

    /* P-mailslot-def (Everyone all, no label), P-mailslot-low (and a Low label) for V16 */
    for (i = 0; i < 2; i++)
    {
        SECURITY_ATTRIBUTES SlotSa = {sizeof(SlotSa), NULL, FALSE};

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(i ? L"D:(A;;GA;;;WD)S:(ML;;NW;;;LW)" : L"D:(A;;GA;;;WD)",
                                                                SDDL_REVISION_1, &SlotSa.lpSecurityDescriptor, NULL))
            continue;
        StringCchPrintfW(Name, _countof(Name), L"\\\\.\\mailslot\\mlo%lu-%s", ParentPid, i ? L"low" : L"def");
        Slots[i] = CreateMailslotW(Name, 0, 0, &SlotSa);
        ok(Slots[i] != INVALID_HANDLE_VALUE, "P-mailslot-%s: %lu\n", i ? "low" : "def", GetLastError());
        if (Slots[i] == INVALID_HANDLE_VALUE) Slots[i] = NULL;
        LocalFree(SlotSa.lpSecurityDescriptor);
    }
    ParentRowsV13(Level, &HighEvent);
    for (i = 0; i < 2; i++)
    {
        MakeSd(2, FALSE, GENERIC_ALL, SdBuffer, (PACL)DaclBuffer, (PACL)SaclBuffer);
        StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir\\medfile-%lx", BaseDir,
                         i ? SECURITY_MANDATORY_UNTRUSTED_RID : SECURITY_MANDATORY_LOW_RID);
        Token = CreateFileW(Name, GENERIC_WRITE, 0, &Sa, CREATE_NEW, 0, NULL);
        ok(Token != INVALID_HANDLE_VALUE, "P-file-v9 %S: %lu\n", Name, GetLastError());
        if (Token != INVALID_HANDLE_VALUE) CloseHandle(Token);
    }
    ParentRowsLabels();
    ParentRowsLowerPrivileges(Level);
    ParentRowsV3Types();

    RunChild(SECURITY_MANDATORY_LOW_RID);
    RunChild(SECURITY_MANDATORY_UNTRUSTED_RID);

    if (PevEvent) CloseHandle(PevEvent);
    if (HighEvent) CloseHandle(HighEvent);
    for (i = 0; i < 2; i++)
        if (Slots[i]) CloseHandle(Slots[i]);
    for (i = 0; i < 2; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir\\medfile-%lx", BaseDir,
                         i ? SECURITY_MANDATORY_UNTRUSTED_RID : SECURITY_MANDATORY_LOW_RID);
        DeleteFileW(Name);
    }

    for (Kind = 0; Kind < KindCount; Kind++)
        for (Variant = 0; Variant < NVARIANTS; Variant++)
            for (i = 0; i < PIPE_INSTANCES; i++)
                if (Objects[Kind][Variant][i]) CloseHandle(Objects[Kind][Variant][i]);
    for (Variant = 0; Variant < NVARIANTS; Variant++)
    {
        StringCchPrintfW(Name, _countof(Name), L"%s\\f-%s", BaseDir, Variants[Variant].Name);
        ok(DeleteFileW(Name), "delete %S: %lu\n", Name, GetLastError());
        if (Root)
        {
            StringCchPrintfW(Name, _countof(Name), L"k-%s", Variants[Variant].Name);
            RegDeleteKeyW(Root, Name);
        }
    }
    if (Root)
    {
        RegCloseKey(Root);
        StringCchPrintfW(Name, _countof(Name), L"Software\\MloTest%lu", ParentPid);
        ok(RegDeleteKeyW(HKEY_CURRENT_USER, Name) == ERROR_SUCCESS, "delete key %S\n", Name);
    }
    StringCchPrintfW(Name, _countof(Name), L"%s\\lowdir", BaseDir);
    ok(RemoveDirectoryW(Name), "remove %S: %lu\n", Name, GetLastError());
    ok(RemoveDirectoryW(BaseDir), "remove %S: %lu\n", BaseDir, GetLastError());
}
