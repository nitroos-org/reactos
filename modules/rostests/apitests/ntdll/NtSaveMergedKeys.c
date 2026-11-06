/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for NtSaveMergedKeys: the result, and the lock order of the two key control blocks
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * CmSaveMergedKeys held the hash locks of both keys shared, in the order of its arguments.  Creating or deleting a
 * subkey takes the locks of the key and the new subkey exclusively in the order of their buckets, so a save whose
 * High key sits in a higher bucket than its Low key closed a cycle with a creator whose subkey fell in the Low key's
 * bucket; a save of one key on both sides asked for the same lock twice behind a queued creator.  The stress saves
 * in every order (and one key twice) while threads create and delete subkeys of both keys by the thousand.
 *
 * The saved hive is also checked for its content: it is the union of both keys, recursively; for a value of the
 * same name (compared without case) the data of the High key is kept, a subkey of the same name is merged in the same
 * way.  These rules are those of the Windows registry views (HKEY_CLASSES_ROOT: the user's key wins) and are NOT
 * measured on Windows 10: its NtSaveMergedKeys returned STATUS_INVALID_PARAMETER for the two keys of the SOFTWARE
 * hive that were tried (HKLM\Software\Microsoft\Windows\CurrentVersion and its WOW6432Node twin), so two keys of
 * one hive may not be accepted there; this test uses such a pair and is for ReactOS.
 */

#include "precomp.h"

#ifndef REG_SZ
#define REG_SZ 1
#endif
#define ROOT_PATH   L"\\Registry\\Machine\\Software\\NitroSaveMerged"
#define WORKERS     4
#define ROUNDS      120

static HANDLE KeyP, KeyQ;
static volatile LONG Stop;
static volatile LONG Progress;
static volatile LONG Creates;

static
NTSTATUS
OpenKeyByPath(PHANDLE Handle, ACCESS_MASK Access, PCWSTR Path, ULONG Options, PULONG Disposition)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateKey(Handle, Access, &Attributes, 0, NULL, Options, Disposition);
}

static
NTSTATUS
SetStringValue(HANDLE Key, PCWSTR Name, PCWSTR Data)
{
    UNICODE_STRING ValueName;

    RtlInitUnicodeString(&ValueName, Name);
    return NtSetValueKey(Key, &ValueName, 0, REG_SZ, (PVOID)Data, (ULONG)(wcslen(Data) + 1) * sizeof(WCHAR));
}

/* "w<id>_<counter>" without the C runtime (the creators run on several threads) */
static
void
MakeName(PWCHAR Name, ULONG Id, ULONG Counter)
{
    WCHAR Digits[12];
    ULONG n = 0;

    *Name++ = L'w';
    *Name++ = (WCHAR)(L'0' + Id % 10);
    *Name++ = L'_';
    do
    {
        Digits[n++] = (WCHAR)(L'0' + Counter % 10);
        Counter /= 10;
    } while (Counter);
    while (n)
        *Name++ = Digits[--n];
    *Name = 0;
}

static
DWORD
WINAPI
CreatorThread(PVOID Context)
{
    ULONG Id = (ULONG)(ULONG_PTR)Context, Counter = 0;
    WCHAR Name[40];
    UNICODE_STRING SubName;
    OBJECT_ATTRIBUTES Attributes;
    NTSTATUS Status;
    HANDLE Sub;

    while (!Stop)
    {
        HANDLE Parent = (Counter & 1) ? KeyQ : KeyP;

        MakeName(Name, Id, Counter++);
        RtlInitUnicodeString(&SubName, Name);
        InitializeObjectAttributes(&Attributes, &SubName, OBJ_CASE_INSENSITIVE, Parent, NULL);
        Status = NtCreateKey(&Sub, KEY_ALL_ACCESS | DELETE, &Attributes, 0, NULL, 0, NULL);
        if (NT_SUCCESS(Status))
        {
            NtDeleteKey(Sub);
            NtClose(Sub);
            InterlockedIncrement(&Creates);
        }
    }
    return 0;
}

static
NTSTATUS
SaveMerged(HANDLE High, HANDLE Low, PCWSTR FileName)
{
    NTSTATUS Status;
    HANDLE File = CreateFileW(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);

    if (File == INVALID_HANDLE_VALUE)
        return STATUS_UNSUCCESSFUL;
    Status = NtSaveMergedKeys(High, Low, File);
    CloseHandle(File);
    return Status;
}

static
DWORD
WINAPI
WatchdogThread(PVOID Context)
{
    LONG Last = -1;

    UNREFERENCED_PARAMETER(Context);
    for (;;)
    {
        Sleep(60000);
        if (Stop)
            return 0;
        if (Progress == Last)
        {
            DbgPrint("NSMK:HANG no progress for 60 s (%ld saves done)\n", Progress);
            printf("NSMK:HANG no progress for 60 s (%ld saves done)\n", Progress);
            fflush(stdout);
            ok(0, "NtSaveMergedKeys hung (%ld saves done)\n", Progress);
            ExitProcess(1);
        }
        Last = Progress;
    }
}

static
BOOLEAN
QueryString(HANDLE Key, PCWSTR Name, PWCHAR Out, ULONG OutChars)
{
    UNICODE_STRING ValueName;
    UCHAR Buffer[256];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length;
    NTSTATUS Status;

    RtlInitUnicodeString(&ValueName, Name);
    Status = NtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Buffer, sizeof(Buffer), &Length);
    if (!NT_SUCCESS(Status))
        return FALSE;
    if (Info->Type != REG_SZ || Info->DataLength / sizeof(WCHAR) > OutChars)
        return FALSE;
    memcpy(Out, Info->Data, Info->DataLength);
    return TRUE;
}

/* The value must exist as a REG_SZ with exactly this data */
#define ok_string_value(Key, Name, Expected) \
    do { \
        WCHAR Got_[32]; \
        BOOLEAN Found_ = QueryString(Key, Name, Got_, RTL_NUMBER_OF(Got_)); \
        ok(Found_, "%ls is missing\n", Name); \
        if (Found_) \
            ok(!wcscmp(Got_, Expected), "%ls is \"%ls\", expected \"%ls\"\n", Name, Got_, Expected); \
    } while (0)

static
void
CountChildren(HANDLE Key, PULONG Values, PULONG SubKeys)
{
    KEY_FULL_INFORMATION Info;
    ULONG Length;
    NTSTATUS Status;

    Status = NtQueryKey(Key, KeyFullInformation, &Info, sizeof(Info), &Length);
    /* the class name does not fit: the fixed part is still there */
    ok(Status == STATUS_SUCCESS || Status == STATUS_BUFFER_OVERFLOW, "NtQueryKey returned 0x%08lx\n", Status);
    *Values = Info.Values;
    *SubKeys = Info.SubKeys;
}

static
HANDLE
OpenSub(HANDLE Parent, PCWSTR Name, BOOLEAN Create)
{
    UNICODE_STRING SubName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Sub = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&SubName, Name);
    InitializeObjectAttributes(&Attributes, &SubName, OBJ_CASE_INSENSITIVE, Parent, NULL);
    if (Create)
        Status = NtCreateKey(&Sub, KEY_ALL_ACCESS | DELETE, &Attributes, 0, NULL, 0, NULL);
    else
        Status = NtOpenKey(&Sub, KEY_READ, &Attributes);
    return NT_SUCCESS(Status) ? Sub : NULL;
}

static
void
DeleteSub(HANDLE Parent, PCWSTR Name)
{
    UNICODE_STRING SubName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Sub;

    RtlInitUnicodeString(&SubName, Name);
    InitializeObjectAttributes(&Attributes, &SubName, OBJ_CASE_INSENSITIVE, Parent, NULL);
    if (NT_SUCCESS(NtOpenKey(&Sub, DELETE, &Attributes)))
    {
        NtDeleteKey(Sub);
        NtClose(Sub);
    }
}

/* The keys of the content check, below P and Q; the stress later runs on the bare keys */
static
void
MakeContent(void)
{
    HANDLE H, L;

    /* A value of the same name that differs in case only: one value in the result, the High data */
    SetStringValue(KeyP, L"Mixed", L"high");
    SetStringValue(KeyQ, L"MIXED", L"low");

    /* A subkey of both: merged recursively */
    H = OpenSub(KeyP, L"shared", TRUE);
    L = OpenSub(KeyQ, L"SHARED", TRUE);
    if (H && L)
    {
        SetStringValue(H, L"both", L"high");
        SetStringValue(L, L"both", L"low");
        SetStringValue(H, L"only_high", L"h");
        SetStringValue(L, L"only_low", L"l");
    }
    if (H)
        NtClose(H);
    if (L)
        NtClose(L);

    /* A subkey of one key only, with a subkey of its own */
    H = OpenSub(KeyP, L"high_only_key", TRUE);
    if (H)
    {
        SetStringValue(H, L"v", L"h");
        NtClose(H);
        H = OpenSub(KeyP, L"high_only_key\\deep", TRUE);
        if (H)
            NtClose(H);
    }
    L = OpenSub(KeyQ, L"low_only_key", TRUE);
    if (L)
    {
        SetStringValue(L, L"v", L"l");
        NtClose(L);
    }
}

static
void
RemoveContent(void)
{
    UNICODE_STRING Name;

    DeleteSub(KeyP, L"high_only_key\\deep");
    DeleteSub(KeyP, L"high_only_key");
    DeleteSub(KeyP, L"shared");
    DeleteSub(KeyQ, L"low_only_key");
    DeleteSub(KeyQ, L"shared");
    RtlInitUnicodeString(&Name, L"Mixed");
    NtDeleteValueKey(KeyP, &Name);
    RtlInitUnicodeString(&Name, L"MIXED");
    NtDeleteValueKey(KeyQ, &Name);
}

static
void
CheckMergedContent(HANDLE Loaded)
{
    HANDLE Sub;
    ULONG Values, SubKeys;

    ok_string_value(Loaded, L"both", L"high");
    ok_string_value(Loaded, L"only_low", L"l");
    ok_string_value(Loaded, L"only_high", L"h");
    ok_string_value(Loaded, L"mixed", L"high");
    CountChildren(Loaded, &Values, &SubKeys);
    /* both, only_low, only_high and mixed (once) */
    ok_dec(Values, 4);
    /* shared, high_only_key and low_only_key */
    ok_dec(SubKeys, 3);

    Sub = OpenSub(Loaded, L"shared", FALSE);
    ok(Sub != NULL, "shared is missing\n");
    if (Sub)
    {
        ok_string_value(Sub, L"both", L"high");
        ok_string_value(Sub, L"only_low", L"l");
        ok_string_value(Sub, L"only_high", L"h");
        CountChildren(Sub, &Values, &SubKeys);
        ok_dec(Values, 3);
        NtClose(Sub);
    }

    Sub = OpenSub(Loaded, L"high_only_key", FALSE);
    ok(Sub != NULL, "high_only_key is missing\n");
    if (Sub)
    {
        HANDLE Deep;

        ok_string_value(Sub, L"v", L"h");
        Deep = OpenSub(Sub, L"deep", FALSE);
        ok(Deep != NULL, "high_only_key\\deep is missing\n");
        if (Deep)
            NtClose(Deep);
        NtClose(Sub);
    }

    Sub = OpenSub(Loaded, L"low_only_key", FALSE);
    ok(Sub != NULL, "low_only_key is missing\n");
    if (Sub)
    {
        ok_string_value(Sub, L"v", L"l");
        NtClose(Sub);
    }
}

static
void
TestResult(void)
{
    static const WCHAR LoadedPath[] = L"\\Registry\\Machine\\NitroSaveMergedLoaded";
    NTSTATUS Status;
    HANDLE Loaded;
    UNICODE_STRING Target, Source;
    OBJECT_ATTRIBUTES TargetAttr, SourceAttr;
    WCHAR NtFile[MAX_PATH + 8], Full[MAX_PATH];
    BOOLEAN Old;

    MakeContent();

    /* The saved file is a hive that loads */
    Status = SaveMerged(KeyP, KeyQ, L"nitro_merged.dat");
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        RemoveContent();
        return;
    }

    GetFullPathNameW(L"nitro_merged.dat", RTL_NUMBER_OF(Full), Full, NULL);
    wcscpy(NtFile, L"\\??\\");
    wcscat(NtFile, Full);
    RtlInitUnicodeString(&Source, NtFile);
    RtlInitUnicodeString(&Target, LoadedPath);
    InitializeObjectAttributes(&TargetAttr, &Target, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&SourceAttr, &Source, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &Old);
    Status = NtLoadKey(&TargetAttr, &SourceAttr);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        RemoveContent();
        return;
    }

    Status = NtOpenKey(&Loaded, KEY_READ, &TargetAttr);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        CheckMergedContent(Loaded);
        NtClose(Loaded);
    }
    Status = NtUnloadKey(&TargetAttr);
    ok_hex(Status, STATUS_SUCCESS);
    DeleteFileW(L"nitro_merged.dat");
    RemoveContent();
}

START_TEST(NtSaveMergedKeys)
{
    NTSTATUS Status;
    HANDLE Root, Workers[WORKERS], Watchdog;
    BOOLEAN Old;
    ULONG i, Round;
    ULONG Failures = 0;
    WCHAR Name[64];
    struct { HANDLE High, Low; } Order[3];

    Status = RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &Old);
    if (!NT_SUCCESS(Status))
    {
        skip("No backup privilege (0x%08lx)\n", Status);
        return;
    }

    Status = OpenKeyByPath(&Root, KEY_ALL_ACCESS | DELETE, ROOT_PATH, 0, NULL);
    if (!NT_SUCCESS(Status))
    {
        skip("Cannot create the test key (0x%08lx)\n", Status);
        return;
    }
    wcscpy(Name, ROOT_PATH L"\\P");
    Status = OpenKeyByPath(&KeyP, KEY_ALL_ACCESS | DELETE, Name, 0, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    wcscpy(Name, ROOT_PATH L"\\Q");
    Status = OpenKeyByPath(&KeyQ, KEY_ALL_ACCESS | DELETE, Name, 0, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    if (!KeyP || !KeyQ)
        return;

    SetStringValue(KeyP, L"both", L"high");
    SetStringValue(KeyQ, L"both", L"low");
    SetStringValue(KeyP, L"only_high", L"h");
    SetStringValue(KeyQ, L"only_low", L"l");

    TestResult();

    Order[0].High = KeyP; Order[0].Low = KeyQ;
    Order[1].High = KeyQ; Order[1].Low = KeyP;
    Order[2].High = KeyP; Order[2].Low = KeyP;

    Watchdog = CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
    for (i = 0; i < WORKERS; i++)
        Workers[i] = CreateThread(NULL, 0, CreatorThread, (PVOID)(ULONG_PTR)i, 0, NULL);

    for (Round = 0; Round < ROUNDS; Round++)
    {
        for (i = 0; i < 3; i++)
        {
            Status = SaveMerged(Order[i].High, Order[i].Low, L"nitro_merged_stress.dat");
            if (!NT_SUCCESS(Status))
                Failures++;
            InterlockedIncrement(&Progress);
        }
    }
    ok(Failures == 0, "%lu of %u saves failed\n", Failures, ROUNDS * 3);

    InterlockedExchange(&Stop, 1);
    WaitForMultipleObjects(WORKERS, Workers, TRUE, INFINITE);
    for (i = 0; i < WORKERS; i++)
        CloseHandle(Workers[i]);
    trace("%u saves while %ld subkeys were created and deleted\n", ROUNDS * 3, Creates);
    ok(Creates > 0, "the creators did no work\n");
    printf("NSMK:DONE saves=%u creates=%ld failures=%lu\n", ROUNDS * 3, Creates, Failures);
    fflush(stdout);
    DeleteFileW(L"nitro_merged_stress.dat");

    /* Clean up the keys */
    NtClose(KeyP);
    NtClose(KeyQ);
    wcscpy(Name, ROOT_PATH L"\\P");
    if (NT_SUCCESS(OpenKeyByPath(&KeyP, DELETE, Name, 0, NULL)))
    {
        NtDeleteKey(KeyP);
        NtClose(KeyP);
    }
    wcscpy(Name, ROOT_PATH L"\\Q");
    if (NT_SUCCESS(OpenKeyByPath(&KeyQ, DELETE, Name, 0, NULL)))
    {
        NtDeleteKey(KeyQ);
        NtClose(KeyQ);
    }
    NtDeleteKey(Root);
    NtClose(Root);
    (void)Watchdog;
}
