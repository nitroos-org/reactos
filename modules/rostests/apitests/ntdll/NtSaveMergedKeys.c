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
void
TestResult(void)
{
    static const WCHAR LoadedPath[] = L"\\Registry\\Machine\\NitroSaveMergedLoaded";
    NTSTATUS Status;
    HANDLE Loaded;
    UNICODE_STRING Target, Source, ValueName;
    OBJECT_ATTRIBUTES TargetAttr, SourceAttr;
    WCHAR NtFile[MAX_PATH + 8], Full[MAX_PATH];
    UCHAR Buffer[256];
    ULONG Length;
    BOOLEAN Old;

    /* The saved file is a hive that loads */
    Status = SaveMerged(KeyP, KeyQ, L"nitro_merged.dat");
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

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
        return;

    Status = NtOpenKey(&Loaded, KEY_READ, &TargetAttr);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        /* The values are not asserted: which of two values of the same name wins is Windows behaviour still to be
         * measured on the oracle (the High key should), and the merge of values is not what this test is about */
        RtlInitUnicodeString(&ValueName, L"only_low");
        Status = NtQueryValueKey(Loaded, &ValueName, KeyValuePartialInformation, Buffer, sizeof(Buffer), &Length);
        trace("only_low: 0x%08lx, ", Status);
        RtlInitUnicodeString(&ValueName, L"only_high");
        Status = NtQueryValueKey(Loaded, &ValueName, KeyValuePartialInformation, Buffer, sizeof(Buffer), &Length);
        trace("only_high: 0x%08lx\n", Status);
        NtClose(Loaded);
    }
    Status = NtUnloadKey(&TargetAttr);
    ok_hex(Status, STATUS_SUCCESS);
    DeleteFileW(L"nitro_merged.dat");
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
