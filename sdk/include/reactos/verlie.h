/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     The switch for "an unmanifested program is told what Windows 10 tells it" (6.2 / 6.3).
 *              Used by ntdll (the raise-only effective version stays out of the way) and kernel32
 *              (GetVersion, GetVersionEx, VerifyVersionInfo).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef VERLIE_H
#define VERLIE_H

/*
 * Registry switch: HKLM\SYSTEM\CurrentControlSet\Control\ReactOS\Settings\Version, DWORD "UnmanifestedVersionLie".
 * 0 or absent (the default): every program is told the real version, as before.
 * 1: GetVersion/GetVersionEx/VerifyVersionInfo tell a program the version Windows 10 tells it, from its own
 *    executable manifest (supportedOS) and, without a manifest, its PE header. RtlGetVersion, RtlVerifyVersionInfo,
 *    RtlGetNtVersionNumbers, the PEB and KUSER_SHARED_DATA stay real.
 * Read once per process (cached in the module that asks).
 */
static inline BOOLEAN
RosVersionLieEnabled(VOID)
{
    static volatile LONG g_State = 0; /* 0 = not read, 1 = off, 2 = on */
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ReactOS\\Settings\\Version");
    UNICODE_STRING ValName = RTL_CONSTANT_STRING(L"UnmanifestedVersionLie");
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&KeyName, OBJ_CASE_INSENSITIVE);
    union
    {
        KEY_VALUE_PARTIAL_INFORMATION Info;
        UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    } Value;
    LONG State = g_State;
    ULONG Length;
    HANDLE hKey;

    if (State)
        return State == 2;

    State = 1;
    if (NT_SUCCESS(NtOpenKey(&hKey, KEY_QUERY_VALUE, &ObjectAttributes)))
    {
        if (NT_SUCCESS(NtQueryValueKey(hKey, &ValName, KeyValuePartialInformation, &Value, sizeof(Value), &Length)) &&
            Value.Info.Type == REG_DWORD && Value.Info.DataLength == sizeof(ULONG) &&
            *(PULONG)Value.Info.Data == 1)
        {
            State = 2;
        }
        NtClose(hKey);
    }
    g_State = State;
    return State == 2;
}

#endif /* VERLIE_H */
