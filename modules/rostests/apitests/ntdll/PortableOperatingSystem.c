/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for RtlCheckPortableOperatingSystem and RtlSetPortableOperatingSystem
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022. The state is the DWORD value PortableOperatingSystem of
 * HKLM\SYSTEM\CurrentControlSet\Control; the test restores what it found.
 */

#include "precomp.h"

#ifndef REG_SZ
#define REG_SZ 1
#define REG_BINARY 3
#define REG_DWORD 4
#endif

typedef NTSTATUS (NTAPI *PFN_Check)(PBOOLEAN);
typedef NTSTATUS (NTAPI *PFN_Set)(BOOLEAN);

static UNICODE_STRING s_ValueName = RTL_CONSTANT_STRING(L"PortableOperatingSystem");

static HANDLE OpenControlKey(void)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control");
    OBJECT_ATTRIBUTES Attributes;
    HANDLE hKey = NULL;

    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenKey(&hKey, KEY_QUERY_VALUE | KEY_SET_VALUE, &Attributes)))
        return NULL;
    return hKey;
}

static void SetRaw(HANDLE hKey, ULONG Type, const void *Data, ULONG Size)
{
    NTSTATUS Status = NtSetValueKey(hKey, &s_ValueName, 0, Type, (PVOID)Data, Size);

    ok_hex(Status, STATUS_SUCCESS);
}

static void SetDword(HANDLE hKey, ULONG Value)
{
    SetRaw(hKey, REG_DWORD, &Value, sizeof(Value));
}

/* returns FALSE when the value is absent */
static BOOLEAN GetDword(HANDLE hKey, PULONG Type, PULONG Value)
{
    ULONG Buffer[8], Length;
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PVOID)Buffer;
    NTSTATUS Status = NtQueryValueKey(hKey, &s_ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);

    if (!NT_SUCCESS(Status))
        return FALSE;
    *Type = Info->Type;
    *Value = (Info->DataLength >= sizeof(ULONG)) ? *(PULONG)Info->Data : 0;
    return TRUE;
}

START_TEST(PortableOperatingSystem)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PFN_Check pCheck = (PFN_Check)GetProcAddress(hNtdll, "RtlCheckPortableOperatingSystem");
    PFN_Set pSet = (PFN_Set)GetProcAddress(hNtdll, "RtlSetPortableOperatingSystem");
    HANDLE hKey;
    ULONG Saved = 0, SavedType = 0, Type = 0, Value, i;
    BOOLEAN Byte, HadValue;
    NTSTATUS Status;
    static const ULONG s_NonZero[] = { 1, 5, 0x100, 0x10000, 0xffffffff };

    ok(pCheck != NULL, "RtlCheckPortableOperatingSystem is not exported\n");
    ok(pSet != NULL, "RtlSetPortableOperatingSystem is not exported\n");
    if (!pCheck || !pSet)
    {
        skip("exports missing\n");
        return;
    }

    hKey = OpenControlKey();
    if (!hKey)
    {
        skip("cannot open the Control key\n");
        return;
    }
    HadValue = GetDword(hKey, &SavedType, &Saved) && SavedType == REG_DWORD;

    /* value absent */
    NtDeleteValueKey(hKey, &s_ValueName);
    Byte = 0xcc;
    Status = pCheck(&Byte);
    ok_hex(Status, STATUS_NOT_FOUND);
    ok_hex(Byte, 0xcc);

    /* DWORD values: any nonzero value is TRUE */
    for (i = 0; i < _countof(s_NonZero); i++)
    {
        SetDword(hKey, s_NonZero[i]);
        Byte = 0xcc;
        Status = pCheck(&Byte);
        ok_hex(Status, STATUS_SUCCESS);
        ok_hex(Byte, 1);
    }
    SetDword(hKey, 0);
    Byte = 0xcc;
    Status = pCheck(&Byte);
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(Byte, 0);

    /* other value types */
    SetRaw(hKey, REG_SZ, L"1", sizeof(L"1"));
    Byte = 0xcc;
    Status = pCheck(&Byte);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(Byte, 0xcc);
    SetRaw(hKey, REG_BINARY, "\x01", 1);
    Status = pCheck(&Byte);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    ok_hex(Byte, 0xcc);

    /* Set writes a DWORD from the BOOLEAN */
    NtDeleteValueKey(hKey, &s_ValueName);
    Status = pSet(TRUE);
    ok_hex(Status, STATUS_SUCCESS);
    ok(GetDword(hKey, &Type, &Value), "the value was not written\n");
    ok_dec(Type, REG_DWORD);
    ok_dec(Value, 1);
    Byte = 0xcc;
    ok_hex(pCheck(&Byte), STATUS_SUCCESS);
    ok_hex(Byte, 1);

    Status = pSet(FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    ok(GetDword(hKey, &Type, &Value), "the value was not written\n");
    ok_dec(Type, REG_DWORD);
    ok_dec(Value, 0);
    Byte = 0xcc;
    ok_hex(pCheck(&Byte), STATUS_SUCCESS);
    ok_hex(Byte, 0);

    Status = pSet((BOOLEAN)2);
    ok_hex(Status, STATUS_SUCCESS);
    ok(GetDword(hKey, &Type, &Value), "the value was not written\n");
    ok_dec(Value, 1);

    /* restore */
    if (HadValue)
        SetDword(hKey, Saved);
    else
        NtDeleteValueKey(hKey, &s_ValueName);
    NtClose(hKey);
}
