/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The mandatory label in object opens: Low and Untrusted children open objects of their parent
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <aclapi.h>

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

    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats", L"Mode",
                     RRF_RT_REG_DWORD, NULL, &Mode, &Size) != ERROR_SUCCESS)
        Mode = 1;
    return Mode;
}

/* ---------------------------------------------------------------- child */

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
            StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-e-%s", ParentPid, Variants[Variant].Name);
            Handle = OpenEventW(Access, FALSE, Name);
            break;
        case KindMutex:
            StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-m-%s", ParentPid, Variants[Variant].Name);
            Handle = OpenMutexW(Access, FALSE, Name);
            break;
        case KindSection:
            StringCchPrintfW(Name, _countof(Name), L"Local\\mlo%lu-s-%s", ParentPid, Variants[Variant].Name);
            Handle = OpenFileMappingW(Access, FALSE, Name);
            break;
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

    /* A named pipe the child creates carries its level, and it opens it for write */
    StringCchPrintfW(Name, _countof(Name), L"\\\\.\\pipe\\mlo%lu-cp-%lx", ParentPid, Level);
    Event = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, 2, 512, 512, 0, NULL);
    ok(Event != INVALID_HANDLE_VALUE, "level %lx: CreateNamedPipe: %lu\n", Level, GetLastError());
    if (Event != INVALID_HANDLE_VALUE)
    {
        Label = LabelOf(Event, SE_KERNEL_OBJECT, &Policy, &Flags);
        ok(Label == Level, "level %lx: own pipe labelled %lx\n", Level, Label);
        Again = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        ok(Again != INVALID_HANDLE_VALUE, "level %lx: own pipe for write: %lu\n", Level, GetLastError());
        if (Again != INVALID_HANDLE_VALUE) CloseHandle(Again);
        CloseHandle(Event);
    }

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
}

/* ---------------------------------------------------------------- parent */

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
    HANDLE Objects[KindCount][NVARIANTS][PIPE_INSTANCES], Token;
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

    RunChild(SECURITY_MANDATORY_LOW_RID);
    RunChild(SECURITY_MANDATORY_UNTRUSTED_RID);

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
