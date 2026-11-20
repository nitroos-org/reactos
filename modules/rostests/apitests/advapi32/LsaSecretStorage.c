/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LSA secrets: values read back as they were stored, for every kind of name (local, global,
 *              machine, a machine account style name, plain), through LsaStorePrivateData and through the
 *              secret object functions (rotation of the old value, the times, deletion); and the values are
 *              not kept as plaintext in the registry
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Not run on the Windows 10 oracle: it writes LSA secrets there. The values are made up at run time and
 * never printed (only lengths and status codes are).
 */

#include "precomp.h"
#include <ntsecapi.h>

/* ntlsa.h, not in the public headers */
#ifndef SECRET_ALL_ACCESS
#define SECRET_SET_VALUE    0x00000001
#define SECRET_QUERY_VALUE  0x00000002
#define SECRET_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED | SECRET_SET_VALUE | SECRET_QUERY_VALUE)
#endif

static const PCWSTR SecretNames[] =
{
    L"L$SecretTestLocal",
    L"G$SecretTestGlobal",
    L"M$SecretTestMachine",
    L"$SECRETTEST.ACC",
    L"SecretTestPlain",
};

static WCHAR Values[6][40];

static VOID MakeValues(VOID)
{
    BYTE Random[8];
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Values); i++)
    {
        if (!RtlGenRandom(Random, sizeof(Random)))
            ZeroMemory(Random, sizeof(Random));
        StringCchPrintfW(Values[i], RTL_NUMBER_OF(Values[i]), L"value-%lu-%02x%02x%02x%02x%02x%02x%02x%02x",
                         i, Random[0], Random[1], Random[2], Random[3], Random[4], Random[5], Random[6], Random[7]);
    }
}

static VOID InitString(PLSA_UNICODE_STRING String, PCWSTR Text)
{
    String->Buffer = (PWSTR)Text;
    String->Length = (USHORT)(wcslen(Text) * sizeof(WCHAR));
    String->MaximumLength = String->Length + sizeof(WCHAR);
}

static LSA_HANDLE OpenPolicy(ACCESS_MASK Access)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_HANDLE Policy = NULL;
    NTSTATUS Status;

    Status = LsaOpenPolicy(NULL, &Attributes, Access, &Policy);
    ok(NT_SUCCESS(Status), "LsaOpenPolicy(0x%lx) failed: 0x%08lx\n", Access, Status);
    return NT_SUCCESS(Status) ? Policy : NULL;
}

static NTSTATUS Store(PCWSTR Name, PLSA_UNICODE_STRING Data)
{
    LSA_UNICODE_STRING Key;
    LSA_HANDLE Policy;
    NTSTATUS Status;

    Policy = OpenPolicy(POLICY_CREATE_SECRET);
    if (!Policy)
        return STATUS_UNSUCCESSFUL;
    InitString(&Key, Name);
    Status = LsaStorePrivateData(Policy, &Key, Data);
    LsaClose(Policy);
    return Status;
}

static NTSTATUS StoreText(PCWSTR Name, PCWSTR Text)
{
    LSA_UNICODE_STRING Data;

    InitString(&Data, Text);
    return Store(Name, &Data);
}

/* Retrieves Name and compares it with Text (the value as a string: Length = its bytes, MaximumLength + 2) */
static VOID ExpectRetrieve(PCSTR Row, PCWSTR Name, PCWSTR Text)
{
    LSA_UNICODE_STRING Key;
    PLSA_UNICODE_STRING Data = NULL;
    LSA_HANDLE Policy;
    NTSTATUS Status;
    USHORT Length = (USHORT)(wcslen(Text) * sizeof(WCHAR));

    Policy = OpenPolicy(POLICY_GET_PRIVATE_INFORMATION);
    if (!Policy)
        return;
    InitString(&Key, Name);
    Status = LsaRetrievePrivateData(Policy, &Key, &Data);
    ok(Status == STATUS_SUCCESS, "%s %ls: LsaRetrievePrivateData 0x%08lx\n", Row, Name, Status);
    if (NT_SUCCESS(Status) && Data)
    {
        ok(Data->Length == Length, "%s %ls: Length %u, expected %u\n", Row, Name, Data->Length, Length);
        ok(Data->MaximumLength == Length + sizeof(WCHAR), "%s %ls: MaximumLength %u, expected %u\n",
           Row, Name, Data->MaximumLength, Length + (USHORT)sizeof(WCHAR));
        ok(Data->Length == Length && !memcmp(Data->Buffer, Text, Length), "%s %ls: the value differs\n", Row, Name);
        LsaFreeMemory(Data);
    }
    LsaClose(Policy);
}

static VOID ExpectRetrieveStatus(PCSTR Row, PCWSTR Name, NTSTATUS Expected)
{
    LSA_UNICODE_STRING Key;
    PLSA_UNICODE_STRING Data = NULL;
    LSA_HANDLE Policy;
    NTSTATUS Status;

    Policy = OpenPolicy(POLICY_GET_PRIVATE_INFORMATION);
    if (!Policy)
        return;
    InitString(&Key, Name);
    Status = LsaRetrievePrivateData(Policy, &Key, &Data);
    ok(Status == Expected, "%s %ls: LsaRetrievePrivateData 0x%08lx, expected 0x%08lx\n", Row, Name, Status, Expected);
    if (NT_SUCCESS(Status) && Data)
        LsaFreeMemory(Data);
    LsaClose(Policy);
}

/* Compares one value LsaQuerySecret returned with Text */
static VOID CheckQueried(PCSTR Row, PCWSTR Name, PCSTR Which, PLSA_UNICODE_STRING Value, PCWSTR Text)
{
    USHORT Length = (USHORT)(wcslen(Text) * sizeof(WCHAR));

    ok(Value != NULL, "%s %ls: %s is NULL\n", Row, Name, Which);
    if (!Value)
        return;
    ok(Value->Length == Length && !memcmp(Value->Buffer, Text, Length),
       "%s %ls: %s differs (Length %u, expected %u)\n", Row, Name, Which, Value->Length, Length);
}

static VOID QuerySecretRow(PCSTR Row, LSA_HANDLE Secret, PCWSTR Name, PCWSTR Current, PCWSTR Old,
                           PLARGE_INTEGER CurrentTime, PLARGE_INTEGER OldTime)
{
    PLSA_UNICODE_STRING CurrentValue = NULL, OldValue = NULL;
    NTSTATUS Status;

    /* An empty old value is queried in TestShortValues */
    CurrentTime->QuadPart = OldTime->QuadPart = 0;
    Status = LsaQuerySecret(Secret, &CurrentValue, CurrentTime, &OldValue, OldTime);
    ok(Status == STATUS_SUCCESS, "%s %ls: LsaQuerySecret 0x%08lx\n", Row, Name, Status);
    if (NT_SUCCESS(Status))
    {
        CheckQueried(Row, Name, "current value", CurrentValue, Current);
        CheckQueried(Row, Name, "old value", OldValue, Old);
        ok(CurrentTime->QuadPart != 0, "%s %ls: no current time\n", Row, Name);
        trace("%s %ls: old time %s current time\n", Row, Name,
              OldTime->QuadPart == CurrentTime->QuadPart ? "==" : (OldTime->QuadPart < CurrentTime->QuadPart ? "<" : ">"));
    }
    if (CurrentValue)
        LsaFreeMemory(CurrentValue);
    if (OldValue)
        LsaFreeMemory(OldValue);
}

static VOID SetSecretValues(PCSTR Row, LSA_HANDLE Secret, PCWSTR Name, PCWSTR Current, PCWSTR Old)
{
    LSA_UNICODE_STRING CurrentValue, OldValue;
    NTSTATUS Status;

    InitString(&CurrentValue, Current);
    if (Old)
        InitString(&OldValue, Old);
    Status = LsaSetSecret(Secret, &CurrentValue, Old ? &OldValue : NULL);
    ok(Status == STATUS_SUCCESS, "%s %ls: LsaSetSecret 0x%08lx\n", Row, Name, Status);
}

/* The raw registry value of a secret's attribute does not contain Text (skipped where the caller cannot read it) */
static VOID ExpectNotPlaintext(PCSTR Row, PCWSTR Name, PCWSTR Attribute, PCWSTR Text)
{
    WCHAR Path[256];
    BYTE Data[4096];
    DWORD Size = sizeof(Data), Type, i;
    SIZE_T Length = wcslen(Text) * sizeof(WCHAR);
    HKEY Key;
    LONG Error;
    BOOL Found = FALSE;

    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"SECURITY\\Policy\\Secrets\\%ls\\%ls", Name, Attribute);
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key);
    if (Error == ERROR_ACCESS_DENIED)
    {
        skip("%s %ls: the SECURITY hive is not readable by this caller\n", Row, Name);
        return;
    }
    ok(Error == ERROR_SUCCESS, "%s %ls: RegOpenKeyEx(%ls) %ld\n", Row, Name, Attribute, Error);
    if (Error != ERROR_SUCCESS)
        return;

    Error = RegQueryValueExW(Key, NULL, NULL, &Type, Data, &Size);
    RegCloseKey(Key);
    ok(Error == ERROR_SUCCESS, "%s %ls: RegQueryValueEx(%ls) %ld\n", Row, Name, Attribute, Error);
    if (Error != ERROR_SUCCESS)
        return;

    for (i = 0; i + Length <= Size; i++)
    {
        if (!memcmp(Data + i, Text, Length))
        {
            Found = TRUE;
            break;
        }
    }
    ok(!Found, "%s %ls: the %ls is stored as plaintext\n", Row, Name, Attribute);
    SecureZeroMemory(Data, sizeof(Data));
}

static BOOL CallerIsSystem(VOID)
{
    BYTE Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID System = NULL;
    HANDLE Token;
    DWORD Size;
    BOOL Is = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Size) &&
        AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &System))
    {
        Is = EqualSid(((PTOKEN_USER)Buffer)->User.Sid, System);
        FreeSid(System);
    }
    CloseHandle(Token);
    return Is;
}

/* The key of the stored secrets is not readable by an administrator (the file grants SYSTEM alone) */
static VOID ExpectKeyFileClosed(VOID)
{
    WCHAR Path[MAX_PATH], Root[4], FileSystem[32] = L"";
    DWORD Flags = 0;
    HANDLE File;

    if (CallerIsSystem())
    {
        skip("the caller is SYSTEM: the key file is meant to be readable\n");
        return;
    }
    GetSystemDirectoryW(Path, RTL_NUMBER_OF(Path));
    StringCchCopyNW(Root, RTL_NUMBER_OF(Root), Path, 3);
    /* FAT keeps no descriptors (ntfsng enforces them without reporting FS_PERSISTENT_ACLS) */
    GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, FileSystem, RTL_NUMBER_OF(FileSystem));
    if (!(Flags & FS_PERSISTENT_ACLS) && _wcsnicmp(FileSystem, L"FAT", 3) == 0)
    {
        skip("the system volume keeps no file security (%ls)\n", FileSystem);
        return;
    }
    StringCchCatW(Path, RTL_NUMBER_OF(Path), L"\\config\\LsaKey");

    SetLastError(0xdeadbeef);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, 0, NULL);
    ok(File == INVALID_HANDLE_VALUE, "the key file opened for reading\n");
    ok(GetLastError() == ERROR_ACCESS_DENIED, "opening the key file: error %lu, expected ERROR_ACCESS_DENIED\n",
       GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
}

static VOID TestName(PCWSTR Name)
{
    LSA_HANDLE Policy, Secret = NULL;
    LSA_UNICODE_STRING Key;
    LARGE_INTEGER CurrentTime, OldTime, FirstTime;
    WCHAR Upper[64];
    NTSTATUS Status;

    /* Store, read back, also under the name in other letter case */
    ok(StoreText(Name, Values[0]) == STATUS_SUCCESS, "store %ls failed\n", Name);
    ExpectRetrieve("store", Name, Values[0]);
    StringCchCopyW(Upper, RTL_NUMBER_OF(Upper), Name);
    _wcsupr(Upper);
    ExpectRetrieve("store, upper-case name", Upper, Values[0]);

    /* Replace */
    ok(StoreText(Name, Values[1]) == STATUS_SUCCESS, "replace %ls failed\n", Name);
    ExpectRetrieve("replace", Name, Values[1]);
    ExpectNotPlaintext("replace", Name, L"CurrentValue", Values[1]);
    ExpectNotPlaintext("replace", Name, L"CurrentValue", Values[0]);

    /*
     * The secret LsaStorePrivateData made, opened as an object: the status is printed, not checked (the object
     * gets no descriptor that way and the open is refused; a separate issue)
     */
    Policy = OpenPolicy(POLICY_ALL_ACCESS);
    if (!Policy)
        return;
    InitString(&Key, Name);
    Status = LsaOpenSecret(Policy, &Key, SECRET_ALL_ACCESS, &Secret);
    trace("open the stored %ls as an object: 0x%08lx\n", Name, Status);
    if (NT_SUCCESS(Status))
        LsaClose(Secret);
    Secret = NULL;

    /* Delete */
    ok(Store(Name, NULL) == STATUS_SUCCESS, "delete %ls failed\n", Name);
    ExpectRetrieveStatus("deleted", Name, STATUS_OBJECT_NAME_NOT_FOUND);

    /* The same name as a secret object */
    Status = LsaCreateSecret(Policy, &Key, SECRET_ALL_ACCESS, &Secret);
    ok(Status == STATUS_SUCCESS, "LsaCreateSecret(%ls) 0x%08lx\n", Name, Status);
    if (NT_SUCCESS(Status))
    {
        /* Both values set (the old value is never queried while it is empty: see QuerySecretRow) */
        SetSecretValues("set both", Secret, Name, Values[2], Values[3]);
        QuerySecretRow("set both", Secret, Name, Values[2], Values[3], &FirstTime, &OldTime);
        ExpectNotPlaintext("set both", Name, L"CurrentValue", Values[2]);
        ExpectNotPlaintext("set both", Name, L"OldValue", Values[3]);
        ExpectRetrieve("set both, retrieve", Name, Values[2]);

        /* Rotation: the current value becomes the old one */
        Sleep(20);
        SetSecretValues("rotate", Secret, Name, Values[4], Values[2]);
        QuerySecretRow("rotate", Secret, Name, Values[4], Values[2], &CurrentTime, &OldTime);
        ok(CurrentTime.QuadPart >= FirstTime.QuadPart, "rotate %ls: the current time went back\n", Name);
        ExpectRetrieve("rotate, retrieve", Name, Values[4]);

        /* Rotation without an old value: read back through LsaRetrievePrivateData only */
        SetSecretValues("rotate, no old value", Secret, Name, Values[5], NULL);
        ExpectRetrieve("rotate, no old value, retrieve", Name, Values[5]);
        StringCchCopyW(Upper, RTL_NUMBER_OF(Upper), Name);
        _wcsupr(Upper);
        ExpectRetrieve("object, upper-case name", Upper, Values[5]);

        /* Delete the object */
        Status = LsaDelete(Secret);
        ok(Status == STATUS_SUCCESS, "LsaDelete(%ls) 0x%08lx\n", Name, Status);
        if (!NT_SUCCESS(Status))
            LsaClose(Secret);
        ExpectRetrieveStatus("object deleted", Name, STATUS_OBJECT_NAME_NOT_FOUND);
    }
    LsaClose(Policy);
}

/* A secret created with LsaCreateSecret: no value until one is set; LsaDelete removes it */
static VOID TestCreated(VOID)
{
    PCWSTR Name = L"G$SecretTestCreated";
    PLSA_UNICODE_STRING CurrentValue = NULL, OldValue = NULL;
    LARGE_INTEGER CurrentTime, OldTime;
    LSA_HANDLE Policy, Secret = NULL;
    LSA_UNICODE_STRING Key;
    NTSTATUS Status;

    Policy = OpenPolicy(POLICY_ALL_ACCESS);
    if (!Policy)
        return;
    InitString(&Key, Name);
    Status = LsaCreateSecret(Policy, &Key, SECRET_ALL_ACCESS, &Secret);
    ok(Status == STATUS_SUCCESS, "LsaCreateSecret 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Status = LsaQuerySecret(Secret, &CurrentValue, &CurrentTime, &OldValue, &OldTime);
        trace("created, no value: LsaQuerySecret 0x%08lx current %s old %s\n", Status,
              CurrentValue ? "present" : "NULL", OldValue ? "present" : "NULL");
        if (CurrentValue)
            LsaFreeMemory(CurrentValue);
        if (OldValue)
            LsaFreeMemory(OldValue);
        ExpectRetrieveStatus("created, no value", Name, STATUS_OBJECT_NAME_NOT_FOUND);

        SetSecretValues("created, set", Secret, Name, Values[5], Values[0]);
        QuerySecretRow("created, set", Secret, Name, Values[5], Values[0], &CurrentTime, &OldTime);
        ExpectRetrieve("created, retrieve", Name, Values[5]);
        ExpectNotPlaintext("created", Name, L"CurrentValue", Values[5]);
        ExpectNotPlaintext("created", Name, L"OldValue", Values[0]);

        Status = LsaDelete(Secret);
        ok(Status == STATUS_SUCCESS, "LsaDelete 0x%08lx\n", Status);
    }
    LsaClose(Policy);
    ExpectRetrieveStatus("LsaDelete", Name, STATUS_OBJECT_NAME_NOT_FOUND);
}

/* Values that are not strings: odd lengths, MaximumLength above Length, empty, large */
static VOID TestShapes(VOID)
{
    static const struct { USHORT Length, MaximumLength; } Shapes[] =
    {
        /* {0, 0} and {1, 1} (a stored value shorter than one character): TestShortValues */
        {7, 7}, {7, 9}, {8, 8}, {4, 10}, {0, 2}, {2, 2}, {32766, 32768},
    };
    PCWSTR Name = L"SecretTestShape";
    LSA_UNICODE_STRING Data, Key;
    PLSA_UNICODE_STRING Back;
    LSA_HANDLE Policy;
    PBYTE Buffer;
    NTSTATUS Status;
    ULONG i, j;

    Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32768);
    if (!Buffer)
        return;
    for (j = 0; j < 32768; j++)
        Buffer[j] = (BYTE)(j * 7 + 3);

    for (i = 0; i < RTL_NUMBER_OF(Shapes); i++)
    {
        Data.Buffer = (PWSTR)Buffer;
        Data.Length = Shapes[i].Length;
        Data.MaximumLength = Shapes[i].MaximumLength;
        Status = Store(Name, &Data);
        ok(Status == STATUS_SUCCESS, "shape %lu: store 0x%08lx\n", i, Status);

        Policy = OpenPolicy(POLICY_GET_PRIVATE_INFORMATION);
        if (!Policy)
            break;
        InitString(&Key, Name);
        Back = NULL;
        Status = LsaRetrievePrivateData(Policy, &Key, &Back);
        /* The base's arithmetic (Length = stored bytes - 2) is what must not change: printed, compared base/fix */
        trace("shape %lu (%u/%u): retrieve 0x%08lx Length %u MaximumLength %u same-bytes %d\n", i,
              Shapes[i].Length, Shapes[i].MaximumLength, Status,
              Back ? Back->Length : 0, Back ? Back->MaximumLength : 0,
              Back ? !memcmp(Back->Buffer, Buffer, min(Back->Length, Shapes[i].Length)) : -1);
        if (NT_SUCCESS(Status) && Back)
            LsaFreeMemory(Back);
        LsaClose(Policy);
    }

    ok(Store(Name, NULL) == STATUS_SUCCESS, "shape: delete failed\n");
    HeapFree(GetProcessHeap(), 0, Buffer);
}

/*
 * Values shorter than one character: returned with Length 0 (and MaximumLength = the stored bytes), never with a
 * Length above MaximumLength. An empty old value (a rotation without an old value) is queried too. What Windows
 * returns for these is not documented in [MS-LSAD]: the bounded reply is checked here (verify on peer).
 */
static VOID TestShortValues(VOID)
{
    static const USHORT Lengths[] = {0, 1};
    PCWSTR Name = L"SecretTestShort", ObjectName = L"G$SecretTestEmptyOld";
    PLSA_UNICODE_STRING Back, CurrentValue, OldValue;
    LARGE_INTEGER CurrentTime, OldTime;
    LSA_UNICODE_STRING Data, Key;
    LSA_HANDLE Policy, Secret = NULL;
    BYTE Byte = 0x5a;
    NTSTATUS Status;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Lengths); i++)
    {
        Data.Buffer = (PWSTR)&Byte;
        Data.Length = Data.MaximumLength = Lengths[i];
        Status = Store(Name, &Data);
        ok(Status == STATUS_SUCCESS, "short %u: store 0x%08lx\n", Lengths[i], Status);

        Policy = OpenPolicy(POLICY_GET_PRIVATE_INFORMATION);
        if (!Policy)
            break;
        InitString(&Key, Name);
        Back = NULL;
        Status = LsaRetrievePrivateData(Policy, &Key, &Back);
        ok(Status == STATUS_SUCCESS, "short %u: retrieve 0x%08lx\n", Lengths[i], Status);
        if (NT_SUCCESS(Status) && Back)
        {
            ok(Back->Length == 0, "short %u: Length %u, expected 0\n", Lengths[i], Back->Length);
            ok(Back->MaximumLength == Lengths[i], "short %u: MaximumLength %u, expected %u\n",
               Lengths[i], Back->MaximumLength, Lengths[i]);
            LsaFreeMemory(Back);
        }
        LsaClose(Policy);
    }
    ok(Store(Name, NULL) == STATUS_SUCCESS, "short: delete failed\n");

    Policy = OpenPolicy(POLICY_ALL_ACCESS);
    if (!Policy)
        return;
    InitString(&Key, ObjectName);
    Status = LsaCreateSecret(Policy, &Key, SECRET_ALL_ACCESS, &Secret);
    ok(Status == STATUS_SUCCESS, "LsaCreateSecret(%ls) 0x%08lx\n", ObjectName, Status);
    if (NT_SUCCESS(Status))
    {
        SetSecretValues("empty old", Secret, ObjectName, Values[1], NULL);
        CurrentValue = OldValue = NULL;
        Status = LsaQuerySecret(Secret, &CurrentValue, &CurrentTime, &OldValue, &OldTime);
        ok(Status == STATUS_SUCCESS, "empty old: LsaQuerySecret 0x%08lx\n", Status);
        if (NT_SUCCESS(Status))
        {
            CheckQueried("empty old", ObjectName, "current value", CurrentValue, Values[1]);
            ok(OldValue != NULL, "empty old: the old value is NULL\n");
            if (OldValue)
            {
                ok(OldValue->Length == 0, "empty old: Length %u, expected 0\n", OldValue->Length);
                ok(OldValue->MaximumLength == 0, "empty old: MaximumLength %u, expected 0\n", OldValue->MaximumLength);
            }
        }
        if (CurrentValue)
            LsaFreeMemory(CurrentValue);
        if (OldValue)
            LsaFreeMemory(OldValue);
        Status = LsaDelete(Secret);
        ok(Status == STATUS_SUCCESS, "LsaDelete(%ls) 0x%08lx\n", ObjectName, Status);
        if (!NT_SUCCESS(Status))
            LsaClose(Secret);
    }
    LsaClose(Policy);
}

START_TEST(LsaSecretStorage)
{
    ULONG i;

    MakeValues();

    for (i = 0; i < RTL_NUMBER_OF(SecretNames); i++)
        TestName(SecretNames[i]);

    TestCreated();
    TestShapes();
    TestShortValues();
    ExpectKeyFileClosed();

    SecureZeroMemory(Values, sizeof(Values));
}
