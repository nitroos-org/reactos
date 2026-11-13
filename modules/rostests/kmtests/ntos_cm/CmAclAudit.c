/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite registry ACL audit mode test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The configuration manager's audit mode runs a shadow access check against
 * the descriptor a key has on Windows and logs what Windows would deny, while
 * the open or create itself goes on exactly as before. This test opens and
 * creates keys through a token that Windows would refuse (the caller's token
 * with its user and Administrators made deny-only) and checks that:
 *  - every open and create still succeeds (no behaviour change, any mode);
 *  - in audit mode a denial is counted (Control\RegAcl\AuditStats) and
 *    written to \SystemRoot\System32\LogFiles\RegAcl\audit.log;
 *  - a granted open, and a kernel-mode open (not access checked), are not;
 *  - in legacy mode nothing is logged;
 *  - the published mode is consistent (ENFORCE runs as AUDIT for now).
 * The mode itself is chosen at boot (/REGACL=...); run the test under each.
 */

#include <kmt_test.h>

#define STATS_KEY   L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\RegAcl\\AuditStats"
#define AUDIT_LOG   L"\\SystemRoot\\System32\\LogFiles\\RegAcl\\audit.log"
#define SOFTWARE    L"\\Registry\\Machine\\SOFTWARE"
#define HARDWARE    L"\\Registry\\Machine\\HARDWARE"

typedef struct _AUDIT_STATS
{
    BOOLEAN Present;
    ULONG Mode;
    ULONG ConfiguredMode;
    ULONG ModeSource;
    ULONG Checks;
    ULONG Denials;
    ULONG Entries;
    ULONG Dropped;
    ULONG StoresDescriptors;
    ULONG SetupExclusion;
    ULONG SwitchesIgnored;
} AUDIT_STATS, *PAUDIT_STATS;

static
ULONG
ReadDword(
    _In_ HANDLE Key,
    _In_ PCWSTR Name)
{
    UNICODE_STRING ValueName;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length;
    NTSTATUS Status;

    RtlInitUnicodeString(&ValueName, Name);
    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
    if (!NT_SUCCESS(Status) || Info->Type != REG_DWORD || Info->DataLength != sizeof(ULONG))
        return MAXULONG;
    return *(PULONG)Info->Data;
}

static
VOID
ReadStats(
    _Out_ PAUDIT_STATS Stats)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(STATS_KEY);
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key;
    NTSTATUS Status;

    RtlZeroMemory(Stats, sizeof(*Stats));
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return;
    Stats->Present = TRUE;
    Stats->Mode = ReadDword(Key, L"Mode");
    Stats->ConfiguredMode = ReadDword(Key, L"ConfiguredMode");
    Stats->ModeSource = ReadDword(Key, L"ModeSource");
    Stats->Checks = ReadDword(Key, L"Checks");
    Stats->Denials = ReadDword(Key, L"Denials");
    Stats->Entries = ReadDword(Key, L"Entries");
    Stats->Dropped = ReadDword(Key, L"Dropped");
    Stats->StoresDescriptors = ReadDword(Key, L"StoresDescriptors");
    Stats->SetupExclusion = ReadDword(Key, L"SetupExclusion");
    Stats->SwitchesIgnored = ReadDword(Key, L"SwitchesIgnored");
    ZwClose(Key);
}

/* Does the audit log contain Needle (an ASCII string)? */
static
BOOLEAN
LogContains(
    _In_ PCSTR Needle)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(AUDIT_LOG);
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE File;
    NTSTATUS Status;
    PCHAR Buffer;
    const ULONG Chunk = 64 * 1024;
    SIZE_T NeedleLength = strlen(Needle);
    ULONG Keep = 0, Have, i;
    LARGE_INTEGER Offset;
    BOOLEAN Found = FALSE;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&File, FILE_READ_DATA | SYNCHRONIZE, &ObjectAttributes, &Iosb, NULL, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Buffer = ExAllocatePoolWithTag(PagedPool, Chunk + NeedleLength, 'aAmK');
    if (!Buffer)
    {
        ZwClose(File);
        return FALSE;
    }

    Offset.QuadPart = 0;
    for (;;)
    {
        Status = ZwReadFile(File, NULL, NULL, NULL, &Iosb, Buffer + Keep, Chunk, &Offset, NULL);
        if (!NT_SUCCESS(Status) || Iosb.Information == 0)
            break;
        Offset.QuadPart += Iosb.Information;
        Have = Keep + (ULONG)Iosb.Information;
        for (i = 0; i + NeedleLength <= Have; i++)
        {
            if (RtlCompareMemory(Buffer + i, Needle, NeedleLength) == NeedleLength)
            {
                Found = TRUE;
                break;
            }
        }
        if (Found)
            break;
        /* Keep the tail so a match across two reads is found */
        Keep = (ULONG)min(Have, NeedleLength);
        RtlMoveMemory(Buffer, Buffer + Have - Keep, Keep);
    }

    ExFreePoolWithTag(Buffer, 'aAmK');
    ZwClose(File);
    return Found;
}

/* Poll the log for up to Seconds (the audit worker writes every ~10 s) */
static
BOOLEAN
WaitForLog(
    _In_ PCSTR Needle,
    _In_ ULONG Seconds)
{
    LARGE_INTEGER Interval;
    ULONG i;

    Interval.QuadPart = -10 * 1000 * 1000;
    for (i = 0; i <= Seconds; i++)
    {
        if (LogContains(Needle))
            return TRUE;
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }
    return FALSE;
}

static
HANDLE
KernelCreateKey(
    _In_ PCWSTR Parent,
    _In_ PCWSTR Child)
{
    WCHAR Path[160];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key = NULL;
    NTSTATUS Status;

    RtlStringCbPrintfW(Path, sizeof(Path), L"%ls\\%ls", Parent, Child);
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateKey(&Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    return NT_SUCCESS(Status) ? Key : NULL;
}

/* Open Parent\Child as the current (impersonated) thread; Force = access checked as a user-mode caller */
static
NTSTATUS
OpenAs(
    _In_ PCWSTR Parent,
    _In_ PCWSTR Child,
    _In_ ACCESS_MASK Access,
    _In_ BOOLEAN Force)
{
    WCHAR Path[160];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key;
    NTSTATUS Status;

    RtlStringCbPrintfW(Path, sizeof(Path), L"%ls\\%ls", Parent, Child);
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | (Force ? OBJ_FORCE_ACCESS_CHECK : 0),
                               NULL, NULL);
    Status = ZwOpenKey(&Key, Access, &ObjectAttributes);
    if (NT_SUCCESS(Status))
        ZwClose(Key);
    return Status;
}

/* Create Parent\Child as the current (impersonated) thread, access checked as a user-mode caller */
static
NTSTATUS
CreateAs(
    _In_ HANDLE Parent,
    _In_ PCWSTR Child,
    _Out_ PULONG Disposition,
    _Out_ PHANDLE Key)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&Name, Child);
    InitializeObjectAttributes(&ObjectAttributes, &Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK,
                               Parent, NULL);
    *Key = NULL;
    return ZwCreateKey(Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, Disposition);
}

static
VOID
DeleteKey(
    _In_opt_ HANDLE Key)
{
    if (!Key)
        return;
    ok_eq_hex(ZwDeleteKey(Key), STATUS_SUCCESS);
    ZwClose(Key);
}

/*
 * The caller's token with its user SID and Administrators deny-only, and
 * restricted to Everyone, Users and Authenticated Users (the shape of a
 * sandboxed browser token): Windows lets it read HKLM\HARDWARE but not write
 * HKLM\SOFTWARE. Restricting SIDs are given explicitly: SeFilterToken marks
 * the token restricted even when RestrictedSids is NULL, and a restricted
 * token with no restricting SID is refused everything.
 */
static
PACCESS_TOKEN
MakeFilteredToken(VOID)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    PACCESS_TOKEN Token, Filtered = NULL;
    PTOKEN_USER User = NULL;
    UCHAR GroupsBuffer[sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)GroupsBuffer;
    UCHAR RestrictedBuffer[sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES)];
    PTOKEN_GROUPS Restricted = (PTOKEN_GROUPS)RestrictedBuffer;
    TOKEN_PRIVILEGES NoPrivileges;
    ULONG AdminsBuffer[4], UsersBuffer[4], WorldBuffer[3], AuthenticatedBuffer[3];
    PSID Admins = (PSID)AdminsBuffer, Users = (PSID)UsersBuffer;
    PSID World = (PSID)WorldBuffer, Authenticated = (PSID)AuthenticatedBuffer;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    NTSTATUS Status;

    RtlInitializeSid(Admins, &NtAuthority, 2);
    *RtlSubAuthoritySid(Admins, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(Admins, 1) = DOMAIN_ALIAS_RID_ADMINS;
    RtlInitializeSid(Users, &NtAuthority, 2);
    *RtlSubAuthoritySid(Users, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(Users, 1) = DOMAIN_ALIAS_RID_USERS;
    RtlInitializeSid(World, &WorldAuthority, 1);
    *RtlSubAuthoritySid(World, 0) = SECURITY_WORLD_RID;
    RtlInitializeSid(Authenticated, &NtAuthority, 1);
    *RtlSubAuthoritySid(Authenticated, 0) = SECURITY_AUTHENTICATED_USER_RID;

    Restricted->GroupCount = 3;
    Restricted->Groups[0].Sid = World;
    Restricted->Groups[0].Attributes = 0;
    Restricted->Groups[1].Sid = Users;
    Restricted->Groups[1].Attributes = 0;
    Restricted->Groups[2].Sid = Authenticated;
    Restricted->Groups[2].Attributes = 0;
    NoPrivileges.PrivilegeCount = 0;

    SeCaptureSubjectContext(&Subject);
    SeLockSubjectContext(&Subject);
    Token = SeQuerySubjectContextToken(&Subject);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID*)&User);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Groups->GroupCount = 2;
        Groups->Groups[0].Sid = User->User.Sid;
        Groups->Groups[0].Attributes = 0;
        Groups->Groups[1].Sid = Admins;
        Groups->Groups[1].Attributes = 0;
        Status = SeFilterToken(Token, 0, Groups, &NoPrivileges, Restricted, &Filtered);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ExFreePool(User);
    }
    SeUnlockSubjectContext(&Subject);
    SeReleaseSubjectContext(&Subject);
    return NT_SUCCESS(Status) ? Filtered : NULL;
}

/* \Registry\User\<caller's SID>, and the needle of a write open of its Software key in the log */
static
BOOLEAN
GetUserHive(
    _Out_writes_(PathChars) PWCHAR Path,
    _In_ ULONG PathChars,
    _Out_writes_(NeedleChars) PCHAR Needle,
    _In_ ULONG NeedleChars)
{
    SECURITY_SUBJECT_CONTEXT Subject;
    PTOKEN_USER User = NULL;
    UNICODE_STRING SidString;
    NTSTATUS Status;
    BOOLEAN Result = FALSE;

    SeCaptureSubjectContext(&Subject);
    SeLockSubjectContext(&Subject);
    Status = SeQueryInformationToken(SeQuerySubjectContextToken(&Subject), TokenUser, (PVOID*)&User);
    SeUnlockSubjectContext(&Subject);
    SeReleaseSubjectContext(&Subject);
    if (!NT_SUCCESS(Status))
        return FALSE;
    if (NT_SUCCESS(RtlConvertSidToUnicodeString(&SidString, User->User.Sid, TRUE)))
    {
        RtlStringCchPrintfW(Path, PathChars, L"\\Registry\\User\\%wZ", &SidString);
        RtlStringCchPrintfA(Needle, NeedleChars, "%wZ\\\\Software\",\"desired\":\"0x00000002\",\"granted\":\"0x00000000\",\"status\":\"0xc0000022\",\"rule\":\"user\"", &SidString);
        RtlFreeUnicodeString(&SidString);
        Result = TRUE;
    }
    ExFreePool(User);
    return Result;
}

/*
 * Find the log line that has Needle and check it is a complete, terminated JSON object line:
 * starts with '{', ends with '}' and a newline, and its quotes balance (an escaped quote does not count)
 */
static
VOID
CheckLogLine(
    _In_ PCSTR Needle)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(AUDIT_LOG);
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Iosb;
    FILE_STANDARD_INFORMATION Standard;
    HANDLE File;
    NTSTATUS Status;
    PCHAR Buffer, Start, End, p, Hit = NULL;
    ULONG Length, Quotes = 0;
    SIZE_T NeedleLength = strlen(Needle);
    LARGE_INTEGER Offset;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateFile(&File, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &Iosb, NULL, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = ZwQueryInformationFile(File, &Iosb, &Standard, sizeof(Standard), FileStandardInformation);
    if (!NT_SUCCESS(Status) || Standard.EndOfFile.QuadPart == 0 || Standard.EndOfFile.QuadPart > 8 * 1024 * 1024)
    {
        ok(0, "log size %I64d, status 0x%lx\n", Standard.EndOfFile.QuadPart, Status);
        ZwClose(File);
        return;
    }
    Length = Standard.EndOfFile.LowPart;
    Buffer = ExAllocatePoolWithTag(PagedPool, Length + 1, 'aAmK');
    if (!Buffer)
    {
        ZwClose(File);
        skip(FALSE, "No memory\n");
        return;
    }
    Offset.QuadPart = 0;
    Status = ZwReadFile(File, NULL, NULL, NULL, &Iosb, Buffer, Length, &Offset, NULL);
    ZwClose(File);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Length = (ULONG)Iosb.Information;
        Buffer[Length] = ANSI_NULL;
        for (p = Buffer; p + NeedleLength <= Buffer + Length; p++)
        {
            if (RtlCompareMemory(p, Needle, NeedleLength) == NeedleLength)
            {
                Hit = p;
                break;
            }
        }
        ok(Hit != NULL, "no line with %s\n", Needle);
        if (Hit)
        {
            for (Start = Hit; Start > Buffer && Start[-1] != '\n'; Start--)
                ;
            for (End = Hit; End < Buffer + Length && *End != '\n'; End++)
                ;
            ok(End < Buffer + Length, "the line with %s has no newline\n", Needle);
            ok(*Start == '{' && End > Start && End[-1] == '}', "the line with %s is not an object\n", Needle);
            for (p = Start; p < End; p++)
            {
                if (*p == '\\')
                    p++;
                else if (*p == '"')
                    Quotes++;
            }
            ok((Quotes % 2) == 0, "the line with %s has unbalanced quotes (%lu)\n", Needle, Quotes);
            ok(End - Start < 2048, "the line with %s is %lu bytes\n", Needle, (ULONG)(End - Start));
            /* The fields after the key are still there: the cut is in the key, not the end of the line */
            ok(strstr(Start, "\"mode\":\"") != NULL && strstr(Start, "\"mode\":\"") < End,
               "the line with %s lost its tail\n", Needle);
        }
    }
    ExFreePoolWithTag(Buffer, 'aAmK');
}

/*
 * A key whose path is far longer than the log keeps (512 characters) and made of characters
 * that take six bytes each in the log: the line must still be a valid, terminated line
 */
#define LONG_LEVELS     3
#define LONG_LEVEL_CHARS 250

static
VOID
TestLongNonAsciiKey(
    _In_ ULONG Tag)
{
    HANDLE Keys[LONG_LEVELS] = {NULL};
    PWCHAR Name, Path;
    ULONG Level, i, PathChars = 0;
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PACCESS_TOKEN Filtered;
    HANDLE Key;
    NTSTATUS Status;
    CHAR Needle[64];
    BOOLEAN Impersonating = FALSE;

    Path = ExAllocatePoolWithTag(PagedPool, 4096 * sizeof(WCHAR), 'aAmK');
    Name = ExAllocatePoolWithTag(PagedPool, 4096 * sizeof(WCHAR), 'aAmK');
    if (skip(Path && Name, "No memory\n"))
        goto Cleanup;

    RtlStringCchPrintfW(Path, 4096, L"%ls\\", SOFTWARE);
    PathChars = (ULONG)wcslen(Path);
    for (Level = 0; Level < LONG_LEVELS; Level++)
    {
        ULONG Chars = 0;

        if (Level == 0)
            {
                RtlStringCchPrintfW(Name, 4096, L"KmtAclL-%lu-", Tag);
                Chars = (ULONG)wcslen(Name);
            }
        while (Chars < LONG_LEVEL_CHARS)
            Name[Chars++] = 0x00E9;
        Name[Chars] = UNICODE_NULL;
        RtlCopyMemory(Path + PathChars, Name, Chars * sizeof(WCHAR));
        PathChars += Chars;
        Path[PathChars] = UNICODE_NULL;

        /* Made as kernel mode: not checked, not logged */
        RtlInitUnicodeString(&String, Path);
        InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = ZwCreateKey(&Keys[Level], KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
        {
            Keys[Level] = NULL;
            goto Cleanup;
        }
        if (Level + 1 < LONG_LEVELS)
            Path[PathChars++] = L'\\';
    }

    Filtered = MakeFilteredToken();
    if (skip(Filtered != NULL, "No filtered token\n"))
        goto Cleanup;
    Status = PsImpersonateClient(PsGetCurrentThread(), Filtered, FALSE, FALSE, SecurityImpersonation);
    ObDereferenceObject(Filtered);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Not impersonating\n"))
        goto Cleanup;
    Impersonating = TRUE;

    RtlInitUnicodeString(&String, Path);
    InitializeObjectAttributes(&ObjectAttributes, &String,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK, NULL, NULL);
    Status = ZwOpenKey(&Key, KEY_SET_VALUE, &ObjectAttributes);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        ZwClose(Key);
    PsRevertToSelf();
    Impersonating = FALSE;

    RtlStringCbPrintfA(Needle, sizeof(Needle), "\"key\":\"\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\KmtAclL-%lu-", Tag);
    ok(WaitForLog(Needle, 40), "long key not in the audit log\n");
    CheckLogLine(Needle);

Cleanup:
    if (Impersonating)
        PsRevertToSelf();
    for (i = LONG_LEVELS; i > 0; i--)
        DeleteKey(Keys[i - 1]);
    if (Path)
        ExFreePoolWithTag(Path, 'aAmK');
    if (Name)
        ExFreePoolWithTag(Name, 'aAmK');
}

/*
 * More distinct denials than the log keeps entries for (2048 a boot): the ones past the cap are
 * Dropped, and so is every later repeat of one of them (its slot is given back, not left claimed
 * without an entry). The counters are published at most once a minute.
 */
#define CAP_KEYS        2068
#define CAP_REPEATS     10

static
BOOLEAN
WaitDropped(
    _In_ ULONG Target,
    _In_ ULONG Seconds,
    _Out_ PAUDIT_STATS Stats)
{
    LARGE_INTEGER Interval;
    ULONG i;

    Interval.QuadPart = -10 * 1000 * 1000;
    for (i = 0; i <= Seconds; i++)
    {
        ReadStats(Stats);
        if (Stats->Dropped != MAXULONG && Stats->Dropped >= Target)
            return TRUE;
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }
    return FALSE;
}

static
VOID
TestEntryCap(
    _In_ ULONG Tag)
{
    WCHAR Path[100], Child[24];
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Parent = NULL, Key;
    PACCESS_TOKEN Filtered;
    AUDIT_STATS Start, Capped, Repeated;
    ULONG i, Failed = 0, Created = 0;
    NTSTATUS Status;
    BOOLEAN Impersonating = FALSE, Seen;

    RtlStringCbPrintfW(Path, sizeof(Path), L"KmtAclS-%lu", Tag);
    Parent = KernelCreateKey(SOFTWARE, Path);
    if (skip(Parent != NULL, "No parent key\n"))
        return;

    for (i = 0; i < CAP_KEYS; i++)
    {
        RtlStringCbPrintfW(Child, sizeof(Child), L"c%lu", i);
        RtlInitUnicodeString(&String, Child);
        InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Parent, NULL);
        Status = ZwCreateKey(&Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
        if (NT_SUCCESS(Status))
        {
            ZwClose(Key);
            Created++;
        }
    }
    ok_eq_ulong(Created, (ULONG)CAP_KEYS);
    if (skip(Created == CAP_KEYS, "Keys missing\n"))
        goto Cleanup;

    Filtered = MakeFilteredToken();
    if (skip(Filtered != NULL, "No filtered token\n"))
        goto Cleanup;
    Status = PsImpersonateClient(PsGetCurrentThread(), Filtered, FALSE, FALSE, SecurityImpersonation);
    ObDereferenceObject(Filtered);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status), "Not impersonating\n"))
        goto Cleanup;
    Impersonating = TRUE;

    ReadStats(&Start);
    for (i = 0; i < CAP_KEYS; i++)
    {
        RtlStringCbPrintfW(Child, sizeof(Child), L"c%lu", i);
        RtlInitUnicodeString(&String, Child);
        InitializeObjectAttributes(&ObjectAttributes, &String,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK, Parent, NULL);
        Status = ZwOpenKey(&Key, KEY_SET_VALUE, &ObjectAttributes);
        if (NT_SUCCESS(Status))
            ZwClose(Key);
        else
            Failed++;
    }
    ok_eq_ulong(Failed, 0UL);

    /* At least the keys past the cap are dropped */
    Seen = WaitDropped(Start.Dropped + (CAP_KEYS - 2048), 90, &Capped);
    ok(Seen, "Dropped %lu -> %lu after %d distinct denials\n", Start.Dropped, Capped.Dropped, CAP_KEYS);
    ok(Capped.Entries <= 2048, "Entries %lu\n", Capped.Entries);

    /* The last key was dropped: every repeat of it is dropped again */
    for (i = 0; i < CAP_REPEATS; i++)
    {
        Status = ZwOpenKey(&Key, KEY_SET_VALUE, &ObjectAttributes);
        if (NT_SUCCESS(Status))
            ZwClose(Key);
        else
            Failed++;
    }
    ok_eq_ulong(Failed, 0UL);
    Seen = WaitDropped(Capped.Dropped + CAP_REPEATS, 130, &Repeated);
    ok(Seen, "Dropped %lu -> %lu after %d repeats of a dropped denial\n", Capped.Dropped, Repeated.Dropped, CAP_REPEATS);

Cleanup:
    if (Impersonating)
        PsRevertToSelf();
    for (i = 0; i < CAP_KEYS; i++)
    {
        RtlStringCbPrintfW(Child, sizeof(Child), L"c%lu", i);
        RtlInitUnicodeString(&String, Child);
        InitializeObjectAttributes(&ObjectAttributes, &String, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, Parent, NULL);
        if (NT_SUCCESS(ZwOpenKey(&Key, DELETE, &ObjectAttributes)))
        {
            ZwDeleteKey(Key);
            ZwClose(Key);
        }
    }
    DeleteKey(Parent);
}

START_TEST(CmAclAudit)
{
    AUDIT_STATS Before, After;
    PACCESS_TOKEN Filtered;
    HANDLE KeyA, KeyB, KeyD, KeyC = NULL;
    WCHAR NameA[40], NameB[40], NameC[40], NameD[40];
    CHAR NeedleA[96], NeedleB[96], NeedleC[96], NeedleD[96], NeedleE[256];
    WCHAR UserHive[128];
    BOOLEAN HaveUserHive;
    ULONG Tag, Disposition = 0;
    NTSTATUS Status;
    BOOLEAN Audit, Impersonating = FALSE;

    ReadStats(&Before);
    ok(Before.Present, "AuditStats key is missing\n");
    if (skip(Before.Present, "No AuditStats\n"))
        return;

    trace("RegAcl mode %lu, configured %lu, source %lu, checks %lu, denials %lu, entries %lu\n",
          Before.Mode, Before.ConfiguredMode, Before.ModeSource, Before.Checks, Before.Denials, Before.Entries);
    ok(Before.ConfiguredMode <= 2, "ConfiguredMode = %lu\n", Before.ConfiguredMode);
    ok(Before.ModeSource <= 2, "ModeSource = %lu\n", Before.ModeSource);
    /* Enforcement does not exist yet: ENFORCE runs as AUDIT */
    ok_eq_ulong(Before.Mode, Before.ConfiguredMode == 2 ? 1UL : Before.ConfiguredMode);
    Audit = (Before.Mode == 1);

    /*
     * The switches that turn storage off for a boot: legacy mode, and setup
     * (text mode, or SystemSetupInProgress from a key only administrators can
     * change). A registry value that would turn storage off from a key that
     * others may change is ignored (bit 1 the mode value, bit 2 the setup
     * value), and then storage stays on. A booted, installed system runs with
     * neither switch.
     */
    trace("stores descriptors %lu, setup exclusion %lu, switches ignored 0x%lx\n",
          Before.StoresDescriptors, Before.SetupExclusion, Before.SwitchesIgnored);
    ok(Before.SwitchesIgnored <= 3, "SwitchesIgnored = 0x%lx\n", Before.SwitchesIgnored);
    ok_eq_ulong(Before.StoresDescriptors, (Audit && !Before.SetupExclusion) ? 1UL : 0UL);
    if (Before.SwitchesIgnored & 1)
        ok(Audit, "the ignored legacy value did not leave the audit on\n");
    if (Before.SwitchesIgnored & 2)
        ok(Before.SetupExclusion == 0, "the ignored setup value still excluded setup\n");
    if (!Audit)
        ok(Before.SetupExclusion == 0, "setup exclusion in legacy mode\n");

    /* Names nobody else uses, so their log lines are this run's */
    Tag = (ULONG)(KeQueryInterruptTime() / 10000);
    RtlStringCbPrintfW(NameA, sizeof(NameA), L"KmtAclA-%lu", Tag);
    RtlStringCbPrintfW(NameB, sizeof(NameB), L"KmtAclB-%lu", Tag);
    RtlStringCbPrintfW(NameC, sizeof(NameC), L"KmtAclC-%lu", Tag);
    RtlStringCbPrintfW(NameD, sizeof(NameD), L"KmtAclD-%lu", Tag);
    /* An open line has the key name followed by "desired"; a create line by "child" */
    RtlStringCbPrintfA(NeedleA, sizeof(NeedleA), "KmtAclA-%lu\",\"desired\"", Tag);
    RtlStringCbPrintfA(NeedleB, sizeof(NeedleB), "KmtAclB-%lu", Tag);
    RtlStringCbPrintfA(NeedleC, sizeof(NeedleC), "\"child\":\"KmtAclC-%lu\"", Tag);
    RtlStringCbPrintfA(NeedleD, sizeof(NeedleD), "KmtAclD-%lu", Tag);
    /* E: the caller's own HKU\<SID>\Software, with its user SID deny-only: the user template refuses a write */
    HaveUserHive = GetUserHive(UserHive, RTL_NUMBER_OF(UserHive), NeedleE, sizeof(NeedleE));

    /* Made as kernel mode: not access checked, not logged */
    KeyA = KernelCreateKey(SOFTWARE, NameA);
    KeyB = KernelCreateKey(HARDWARE, NameB);
    KeyD = KernelCreateKey(SOFTWARE, NameD);
    if (skip(KeyA && KeyB && KeyD, "Test keys missing\n"))
        goto Cleanup;

    Filtered = MakeFilteredToken();
    if (skip(Filtered != NULL, "No filtered token\n"))
        goto Cleanup;
    Status = PsImpersonateClient(PsGetCurrentThread(), Filtered, FALSE, FALSE, SecurityImpersonation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ObDereferenceObject(Filtered);
    if (skip(NT_SUCCESS(Status), "Not impersonating\n"))
        goto Cleanup;
    Impersonating = TRUE;

    /* A: write access to an HKLM\SOFTWARE key. Windows denies it; nitro still opens it */
    ok_eq_hex(OpenAs(SOFTWARE, NameA, KEY_SET_VALUE, TRUE), STATUS_SUCCESS);

    /* B: read access to an HKLM\HARDWARE key, which Everyone may read: granted, not logged */
    ok_eq_hex(OpenAs(HARDWARE, NameB, KEY_READ, TRUE), STATUS_SUCCESS);

    /* C: a subkey under A, which needs KEY_CREATE_SUB_KEY on A. Windows denies it; nitro creates it */
    Status = CreateAs(KeyA, NameC, &Disposition, &KeyC);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(Disposition, (ULONG)REG_CREATED_NEW_KEY);

    /* D: the same write open as A, but from kernel mode without a forced check: not checked, not logged */
    ok_eq_hex(OpenAs(SOFTWARE, NameD, KEY_SET_VALUE, FALSE), STATUS_SUCCESS);

    /* E twice: the second open takes the cached HKU descriptor and lands on the same entry */
    if (HaveUserHive)
    {
        ok_eq_hex(OpenAs(UserHive, L"Software", KEY_SET_VALUE, TRUE), STATUS_SUCCESS);
        ok_eq_hex(OpenAs(UserHive, L"Software", KEY_SET_VALUE, TRUE), STATUS_SUCCESS);
    }

    PsRevertToSelf();
    Impersonating = FALSE;

    if (Audit)
    {
        ok(WaitForLog(NeedleA, 40), "open of %s not in the audit log\n", NeedleA);
        ok(WaitForLog(NeedleC, 15), "create of %s not in the audit log\n", NeedleC);
        ok(!LogContains(NeedleB), "granted open %s is in the audit log\n", NeedleB);
        ok(!LogContains(NeedleD), "kernel-mode open %s is in the audit log\n", NeedleD);
        /* Logged by an earlier run of this test too (same user, same key): only its presence is checked */
        if (HaveUserHive)
            ok(WaitForLog(NeedleE, 15), "write open of the user's Software key with rule user not in the audit log\n");

        TestLongNonAsciiKey(Tag);
        TestEntryCap(Tag);

        ReadStats(&After);
        ok(After.Denials >= Before.Denials + 2, "Denials %lu -> %lu\n", Before.Denials, After.Denials);
        ok(After.Entries >= Before.Entries + 2, "Entries %lu -> %lu\n", Before.Entries, After.Entries);
        ok(After.Checks > Before.Checks, "Checks %lu -> %lu\n", Before.Checks, After.Checks);
    }
    else
    {
        /* Legacy: no shadow check at all */
        LARGE_INTEGER Interval;
        Interval.QuadPart = -15LL * 10 * 1000 * 1000;
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
        ok(!LogContains(NeedleA), "legacy mode logged %s\n", NeedleA);
        ok(!LogContains(NeedleC), "legacy mode logged %s\n", NeedleC);
        ReadStats(&After);
        ok_eq_ulong(After.Denials, Before.Denials);
        ok_eq_ulong(After.Checks, Before.Checks);
    }

Cleanup:
    if (Impersonating)
        PsRevertToSelf();
    DeleteKey(KeyC);
    DeleteKey(KeyA);
    DeleteKey(KeyB);
    DeleteKey(KeyD);
}
