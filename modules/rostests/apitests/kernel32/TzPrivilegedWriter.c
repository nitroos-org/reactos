/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that the kernel, not the caller, writes the time zone to the registry
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The TimeZoneInformation key belongs to SYSTEM and a standard user may only read it
 * (measured on Windows 10 22H2: O:SYG:SYD:AI(A;CIID;KR;;;BU)(A;CIID;KA;;;BA)(A;CIID;KA;;;SY)...),
 * yet a user who holds SeTimeZonePrivilege can change the zone. On Windows 10, run as a user
 * that holds the privilege but cannot write the key (an administrator token with the Administrators
 * group denied):
 *   NtSetSystemInformation(SystemCurrentTimeZoneInformation)  STATUS_INVALID_INFO_CLASS
 *   NtSetSystemInformation(SystemDynamicTimeZoneInformation)  success, the key is rewritten
 *   NtSetSystemInformation(SystemDynamicTimeZoneInformation), 431 bytes
 *                                                             STATUS_INFO_LENGTH_MISMATCH
 *   RtlSetTimeZoneInformation                                 STATUS_ACCESS_DENIED
 *   SetTimeZoneInformation, SetDynamicTimeZoneInformation     success
 * and, without the privilege, 102 gives STATUS_PRIVILEGE_NOT_HELD (the length is checked first).
 */

#include "precomp.h"

#include <lm.h>
#include <ndk/setypes.h>

#define TEST_PASSWORD L"Tz!Writer-2026x"
#define TEST_KEY_NAME L"Tz Writer Test Time"

#define SystemDynamicTimeZoneInformationClass 102

typedef BOOL (WINAPI *FN_SetDynamicTimeZoneInformation)(const DYNAMIC_TIME_ZONE_INFORMATION *);
typedef DWORD (WINAPI *FN_GetDynamicTimeZoneInformation)(PDYNAMIC_TIME_ZONE_INFORMATION);

static FN_SetDynamicTimeZoneInformation pSetDynamicTimeZoneInformation;
static FN_GetDynamicTimeZoneInformation pGetDynamicTimeZoneInformation;

static const WCHAR TimeZoneKey[] = L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation";

typedef struct _SAVED_VALUE
{
    BOOL Present;
    DWORD Type;
    DWORD Size;
    BYTE Data[512];
} SAVED_VALUE;

#define SAVED_COUNT 10

static const PCWSTR SavedNames[SAVED_COUNT] =
{
    L"Bias", L"StandardName", L"StandardBias", L"StandardStart", L"DaylightName", L"DaylightBias",
    L"DaylightStart", L"TimeZoneKeyName", L"DynamicDaylightTimeDisabled", L"DisableAutoDaylightTimeSet"
};
static SAVED_VALUE Saved[SAVED_COUNT];

static BOOL
ReadValue(PCWSTR Name, SAVED_VALUE *Value)
{
    HKEY hKey;
    LONG Error;

    Value->Present = FALSE;
    Value->Size = sizeof(Value->Data);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TimeZoneKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(hKey, Name, NULL, &Value->Type, Value->Data, &Value->Size);
    RegCloseKey(hKey);
    Value->Present = (Error == ERROR_SUCCESS);
    return Value->Present;
}

static VOID
SaveValues(VOID)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(SavedNames); i++)
        ReadValue(SavedNames[i], &Saved[i]);
}

/* As the administrator, after the test: put every value back exactly */
static VOID
RestoreValues(VOID)
{
    HKEY hKey;
    ULONG i;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TimeZoneKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    for (i = 0; i < ARRAYSIZE(SavedNames); i++)
    {
        if (Saved[i].Present)
            RegSetValueExW(hKey, SavedNames[i], 0, Saved[i].Type, Saved[i].Data, Saved[i].Size);
        else
            RegDeleteValueW(hKey, SavedNames[i]);
    }
    RegCloseKey(hKey);
}

static LONG
RegistryBias(VOID)
{
    SAVED_VALUE Value;

    if (!ReadValue(L"Bias", &Value) || Value.Type != REG_DWORD)
        return 0xDEADBEEF;
    return *(LONG *)Value.Data;
}

static LONG
KernelBias(VOID)
{
    RTL_TIME_ZONE_INFORMATION Tzi;
    ULONG Length;

    if (!NT_SUCCESS(NtQuerySystemInformation(SystemCurrentTimeZoneInformation, &Tzi, sizeof(Tzi), &Length)))
        return 0xDEADBEEF;
    return Tzi.Bias;
}

static BOOL
TokenHasPrivilege(HANDLE hToken, ULONG Privilege)
{
    BYTE Buffer[2048];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(hToken, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.LowPart == Privilege && Privileges->Privileges[i].Luid.HighPart == 0)
            return TRUE;
    }
    return FALSE;
}

static VOID
CheckRegistryKeyName(PCSTR Who, PCWSTR Expected)
{
    SAVED_VALUE Value;

    ok(ReadValue(L"TimeZoneKeyName", &Value), "%s: TimeZoneKeyName cannot be read\n", Who);
    if (!Value.Present)
        return;
    ok(Value.Type == REG_SZ, "%s: TimeZoneKeyName type %lu\n", Who, Value.Type);
    ok(Value.Size == (wcslen(Expected) + 1) * sizeof(WCHAR) && !wcscmp((PCWSTR)Value.Data, Expected),
       "%s: TimeZoneKeyName is '%.*S' (%lu bytes), expected '%S'\n",
       Who, (int)(Value.Size / sizeof(WCHAR)), (PCWSTR)Value.Data, Value.Size, Expected);
}

static DWORD
RegistryDisabled(VOID)
{
    SAVED_VALUE Value;

    if (!ReadValue(L"DynamicDaylightTimeDisabled", &Value) || Value.Type != REG_DWORD)
        return 0xDEADBEEF;
    return *(DWORD *)Value.Data;
}

/* What the caller may do depends on who it is: the writer must be the kernel */
static VOID
TestAsUser(PCSTR Who, const TIME_ZONE_INFORMATION *Orig)
{
    DYNAMIC_TIME_ZONE_INFORMATION Dynamic;
    RTL_DYNAMIC_TIME_ZONE_INFORMATION Rtl;
    RTL_TIME_ZONE_INFORMATION RtlZone;
    ULONG Length;
    NTSTATUS Status;
    BOOL Ret;
    HKEY hKey;
    LONG Error;
    LONG OtherBias = (Orig->Bias == 120) ? 180 : 120;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TimeZoneKey, 0, KEY_SET_VALUE, &hKey);
    if (Error == ERROR_SUCCESS)
        RegCloseKey(hKey);
    trace("%s: opening the TimeZoneInformation key for writing: %ld\n", Who, Error);

    /* The zone is set through the dynamic class; the old class is not available to user mode */
    Status = NtQuerySystemInformation(SystemCurrentTimeZoneInformation, &RtlZone, sizeof(RtlZone), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtSetSystemInformation(SystemCurrentTimeZoneInformation, &RtlZone, sizeof(RtlZone));
    ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);

    /* The length is checked before the privilege and before the buffer is looked at */
    ZeroMemory(&Rtl, sizeof(Rtl));
    Status = NtSetSystemInformation(SystemDynamicTimeZoneInformationClass, &Rtl, sizeof(Rtl) - 1);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);

    /* SetDynamicTimeZoneInformation: a zone with a key name and the flag set */
    ZeroMemory(&Dynamic, sizeof(Dynamic));
    if (pGetDynamicTimeZoneInformation(&Dynamic) == TIME_ZONE_ID_INVALID)
    {
        skip("%s: GetDynamicTimeZoneInformation failed with %lu\n", Who, GetLastError());
        return;
    }
    Dynamic.Bias = OtherBias;
    StringCchCopyW(Dynamic.TimeZoneKeyName, ARRAYSIZE(Dynamic.TimeZoneKeyName), TEST_KEY_NAME);
    Dynamic.DynamicDaylightTimeDisabled = TRUE;
    SetLastError(0xDEADBEEF);
    Ret = pSetDynamicTimeZoneInformation(&Dynamic);
    ok(Ret, "%s: SetDynamicTimeZoneInformation failed with %lu\n", Who, GetLastError());
    ok(KernelBias() == OtherBias, "%s: kernel bias %ld, expected %ld\n", Who, KernelBias(), OtherBias);
    ok(RegistryBias() == OtherBias, "%s: registry bias %ld, expected %ld\n", Who, RegistryBias(), OtherBias);
    CheckRegistryKeyName(Who, TEST_KEY_NAME);
    ok(RegistryDisabled() == 1, "%s: DynamicDaylightTimeDisabled is %lu\n", Who, RegistryDisabled());

    /* The flag is the caller's to clear */
    Dynamic.DynamicDaylightTimeDisabled = FALSE;
    Ret = pSetDynamicTimeZoneInformation(&Dynamic);
    ok(Ret, "%s: SetDynamicTimeZoneInformation failed with %lu\n", Who, GetLastError());
    ok(RegistryDisabled() == 0, "%s: DynamicDaylightTimeDisabled is %lu\n", Who, RegistryDisabled());

    /* SetTimeZoneInformation empties the key name and leaves the flag */
    Dynamic.DynamicDaylightTimeDisabled = TRUE;
    ok(pSetDynamicTimeZoneInformation(&Dynamic), "%s: SetDynamicTimeZoneInformation failed with %lu\n", Who, GetLastError());
    Ret = SetTimeZoneInformation(Orig);
    ok(Ret, "%s: SetTimeZoneInformation failed with %lu\n", Who, GetLastError());
    ok(KernelBias() == Orig->Bias, "%s: kernel bias %ld, expected %ld\n", Who, KernelBias(), Orig->Bias);
    ok(RegistryBias() == Orig->Bias, "%s: registry bias %ld, expected %ld\n", Who, RegistryBias(), Orig->Bias);
    CheckRegistryKeyName(Who, L"");
    ok(RegistryDisabled() == 1, "%s: DynamicDaylightTimeDisabled is %lu\n", Who, RegistryDisabled());
}

/* Names that do not end inside their arrays: never stored unterminated, whatever the outcome */
static VOID
TestUnterminated(VOID)
{
    RTL_DYNAMIC_TIME_ZONE_INFORMATION Rtl;
    SAVED_VALUE Value;
    NTSTATUS Status;
    ULONG i;

    ZeroMemory(&Rtl, sizeof(Rtl));
    RtlFillMemory(Rtl.TimeZoneInformation.StandardName, sizeof(Rtl.TimeZoneInformation.StandardName), 'S');
    RtlFillMemory(Rtl.TimeZoneInformation.DaylightName, sizeof(Rtl.TimeZoneInformation.DaylightName), 'D');
    RtlFillMemory(Rtl.TimeZoneKeyName, sizeof(Rtl.TimeZoneKeyName), 'K');
    Rtl.TimeZoneInformation.Bias = Saved[0].Present ? *(LONG *)Saved[0].Data : 0;

    Status = NtSetSystemInformation(SystemDynamicTimeZoneInformationClass, &Rtl, sizeof(Rtl));
    trace("Unterminated names: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    for (i = 0; i < 3; i++)
    {
        static const PCWSTR Names[] = { L"StandardName", L"DaylightName", L"TimeZoneKeyName" };
        ULONG Limit = (i == 2) ? 128 : 32;
        ULONG Chars;

        ok(ReadValue(Names[i], &Value), "%S cannot be read\n", Names[i]);
        if (!Value.Present)
            continue;
        Chars = Value.Size / sizeof(WCHAR);
        ok(Value.Type == REG_SZ && Chars >= 1 && Chars <= Limit && ((PCWSTR)Value.Data)[Chars - 1] == UNICODE_NULL,
           "%S: type %lu, %lu bytes, not terminated inside %lu characters\n", Names[i], Value.Type, Value.Size, Limit);
    }
}

static VOID
TestLegacyFlagMigration(VOID)
{
    TIME_ZONE_INFORMATION Zone;
    SAVED_VALUE Gone;
    HKEY hKey;
    DWORD One = 1;

    if (GetTimeZoneInformation(&Zone) == TIME_ZONE_ID_INVALID ||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, TimeZoneKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
    {
        skip("Cannot prepare the legacy flag\n");
        return;
    }

    /* The NT 5 flag counts as a disabled daylight flag, and is replaced by it */
    RegDeleteValueW(hKey, L"DynamicDaylightTimeDisabled");
    RegSetValueExW(hKey, L"DisableAutoDaylightTimeSet", 0, REG_DWORD, (const BYTE *)&One, sizeof(One));
    RegCloseKey(hKey);

    ok(SetTimeZoneInformation(&Zone), "SetTimeZoneInformation failed with %lu\n", GetLastError());
    ok(RegistryDisabled() == 1, "DynamicDaylightTimeDisabled is %lu\n", RegistryDisabled());
    ok(!ReadValue(L"DisableAutoDaylightTimeSet", &Gone), "DisableAutoDaylightTimeSet is still there\n");
}

START_TEST(TzPrivilegedWriter)
{
    TIME_ZONE_INFORMATION Orig;
    USER_INFO_1 UserInfo;
    LOCALGROUP_MEMBERS_INFO_3 Member;
    BYTE UsersSid[SECURITY_MAX_SID_SIZE];
    WCHAR UsersName[256], Domain[256], UserName[20];
    DWORD SidSize = sizeof(UsersSid), NameSize = ARRAYSIZE(UsersName), DomainSize = ARRAYSIZE(Domain);
    SID_NAME_USE Use;
    HANDLE hLogon = NULL, hImpersonation = NULL;
    NET_API_STATUS NetStatus;
    DWORD ParmError;
    HKEY hKey;
    BOOL CanWrite;

    pSetDynamicTimeZoneInformation = (FN_SetDynamicTimeZoneInformation)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetDynamicTimeZoneInformation");
    pGetDynamicTimeZoneInformation = (FN_GetDynamicTimeZoneInformation)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetDynamicTimeZoneInformation");
    if (!pSetDynamicTimeZoneInformation || !pGetDynamicTimeZoneInformation)
    {
        skip("The dynamic time zone functions are missing\n");
        return;
    }
    if (GetTimeZoneInformation(&Orig) == TIME_ZONE_ID_INVALID)
    {
        skip("GetTimeZoneInformation failed with %lu\n", GetLastError());
        return;
    }

    CanWrite = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TimeZoneKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS);
    if (CanWrite)
        RegCloseKey(hKey);
    SaveValues();

    /* The administrator, with the privilege enabled */
    {
        HANDLE hToken;
        TOKEN_PRIVILEGES Tp;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            Tp.PrivilegeCount = 1;
            Tp.Privileges[0].Luid.LowPart = SE_TIME_ZONE_PRIVILEGE;
            Tp.Privileges[0].Luid.HighPart = 0;
            Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &Tp, 0, NULL, NULL);
            CloseHandle(hToken);
        }
    }
    {
        HANDLE hOwn;

        /* The caller must hold the privilege (a standard user does only where the system grants it to Users) */
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hOwn) || !TokenHasPrivilege(hOwn, SE_TIME_ZONE_PRIVILEGE))
        {
            skip("The caller does not hold SeTimeZonePrivilege\n");
            if (hOwn)
                CloseHandle(hOwn);
            return;
        }
        CloseHandle(hOwn);
    }
    TestAsUser(CanWrite ? "administrator" : "caller", &Orig);
    TestUnterminated();
    if (CanWrite && is_reactos())
        TestLegacyFlagMigration();
    RestoreValues();
    SetTimeZoneInformation(&Orig);
    RestoreValues();

    if (!CanWrite)
    {
        skip("The caller cannot write the key; no standard user to create\n");
        return;
    }

    /* A standard user, with a name of our own; an existing account is never touched */
    StringCbPrintfW(UserName, sizeof(UserName), L"tzw%08lx", GetTickCount() ^ GetCurrentProcessId());
    ZeroMemory(&UserInfo, sizeof(UserInfo));
    UserInfo.usri1_name = UserName;
    UserInfo.usri1_password = TEST_PASSWORD;
    UserInfo.usri1_priv = USER_PRIV_USER;
    UserInfo.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetStatus = NetUserAdd(NULL, 1, (LPBYTE)&UserInfo, &ParmError);
    if (NetStatus != NERR_Success)
    {
        skip("NetUserAdd failed with %lu\n", NetStatus);
        return;
    }
    if (CreateWellKnownSid(WinBuiltinUsersSid, NULL, UsersSid, &SidSize) &&
        LookupAccountSidW(NULL, UsersSid, UsersName, &NameSize, Domain, &DomainSize, &Use))
    {
        Member.lgrmi3_domainandname = UserName;
        NetLocalGroupAddMembers(NULL, UsersName, 3, (LPBYTE)&Member, 1);
    }

    if (!LogonUserW(UserName, L".", TEST_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hLogon))
    {
        skip("LogonUser failed with %lu\n", GetLastError());
        goto done;
    }
    /* Server 2008 R2 grants it to Administrators and LOCAL SERVICE only; Windows 10 also to Users */
    if (!TokenHasPrivilege(hLogon, SE_TIME_ZONE_PRIVILEGE))
    {
        skip("This system does not grant SeTimeZonePrivilege to Users\n");
        goto done;
    }
    if (!DuplicateTokenEx(hLogon, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hImpersonation) ||
        !SetThreadToken(NULL, hImpersonation))
    {
        skip("Impersonation failed with %lu\n", GetLastError());
        goto done;
    }

    /* A user's privilege may be held disabled; enabling it is the user's right */
    {
        TOKEN_PRIVILEGES Tp;

        Tp.PrivilegeCount = 1;
        Tp.Privileges[0].Luid.LowPart = SE_TIME_ZONE_PRIVILEGE;
        Tp.Privileges[0].Luid.HighPart = 0;
        Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hImpersonation, FALSE, &Tp, 0, NULL, NULL);
    }

    /* Whether the key can be written by this user is the system's decision; where it cannot, the zone still changes */
    TestAsUser("standard user", &Orig);
    RevertToSelf();
    RestoreValues();
    SetTimeZoneInformation(&Orig);
    RestoreValues();

done:
    if (hImpersonation)
        CloseHandle(hImpersonation);
    if (hLogon)
        CloseHandle(hLogon);
    ok(NetUserDel(NULL, UserName) == NERR_Success, "NetUserDel failed\n");
}
