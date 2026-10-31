/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for CM_Get_Class_PropertyW and CM_Get_Class_Property_Keys (cfgmgr32.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The return codes and types were measured on Windows 10 22H2 (x64 and x86) for the System, Disk drives and Keyboards
 * classes. The values are compared with what the older calls give for the same class. Windows keeps more properties
 * of a class than ReactOS does, so the list of the keys is checked for the keys that are always there, and for every
 * key of the list having a value.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#define INITGUID
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devpropdef.h>
#include <devpkey.h>

typedef CONFIGRET (WINAPI *FN_PROP)(const GUID *, const DEVPROPKEY *, DEVPROPTYPE *, PBYTE, PULONG, ULONG);
typedef CONFIGRET (WINAPI *FN_KEYS)(const GUID *, DEVPROPKEY *, PULONG, ULONG);

static FN_PROP pProperty;
static FN_KEYS pKeys;

static const GUID ClassSystem = {0x4d36e97d, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
static const GUID ClassDisk = {0x4d36e967, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
static const GUID ClassKeyboard = {0x4d36e96b, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
static const GUID InterfaceDisk = {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};
static const GUID NoSuchClass = {0x12345678, 0x1234, 0x1234, {1, 2, 3, 4, 5, 6, 7, 8}};
static const DEVPROPKEY KeyUnknown = {{0x12345678, 0x1234, 0x1234, {1, 2, 3, 4, 5, 6, 7, 8}}, 7};

#define NOT_SET 0xDEADBEEF

static BOOL InList(const DEVPROPKEY *Keys, ULONG Count, const DEVPROPKEY *Key)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        if (Keys[i].pid == Key->pid && IsEqualGUID(&Keys[i].fmtid, &Key->fmtid))
            return TRUE;
    return FALSE;
}

static void CheckClass(const GUID *Guid, PCSTR Tag, BOOL HasFilters)
{
    DEVPROPKEY Keys[64], Small[64];
    DEVPROPTYPE Type;
    WCHAR Text[256];
    BYTE Buffer[1024], Legacy[1024];
    ULONG Size, Count, Need, i, LegacySize;
    CONFIGRET cr;

    /* The class name and the description, as strings */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_ClassName, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_STRING, "%s: ClassName: %lx, type %lx\n", Tag, cr, Type);
    if (cr == CR_SUCCESS)
    {
        ok(Size == (wcslen((PWSTR)Buffer) + 1) * sizeof(WCHAR), "%s: ClassName: size %lu\n", Tag, Size);
        ok(SetupDiClassNameFromGuidW(Guid, Text, ARRAYSIZE(Text), NULL) && !wcscmp(Text, (PWSTR)Buffer),
           "%s: ClassName %ls, SetupDiClassNameFromGuid says %ls\n", Tag, (PWSTR)Buffer, Text);
    }
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_STRING && ((PWSTR)Buffer)[0], "%s: Name: %lx, type %lx\n", Tag, cr, Type);
    Size = sizeof(Buffer);
    Type = NOT_SET;
    cr = pProperty(Guid, &DEVPKEY_NAME, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_STRING, "%s: DEVPKEY_NAME: %lx, type %lx\n", Tag, cr, Type);

    /* The size: no buffer, none, one byte short */
    Type = NOT_SET;
    Size = 0;
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_ClassName, &Type, NULL, &Size, 0);
    Need = Size;
    ok(cr == CR_BUFFER_SMALL && Type == DEVPROP_TYPE_STRING && Need > 2, "%s: no buffer: %lx, type %lx, size %lu\n", Tag, cr, Type, Need);
    Type = NOT_SET;
    Size = 0;
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_ClassName, &Type, Buffer, &Size, 0);
    ok(cr == CR_BUFFER_SMALL && Type == DEVPROP_TYPE_STRING && Size == Need, "%s: size 0: %lx, type %lx, size %lu\n", Tag, cr, Type, Size);
    Type = NOT_SET;
    Size = 2;
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_ClassName, &Type, Buffer, &Size, 0);
    ok(cr == CR_BUFFER_SMALL && Type == DEVPROP_TYPE_STRING && Size == Need, "%s: size 2: %lx, type %lx, size %lu\n", Tag, cr, Type, Size);

    /* The filters, as lists of strings, the same bytes as the registry value of the class key */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_UpperFilters, &Type, Buffer, &Size, 0);
    {
        WCHAR KeyPath[128];
        HKEY hKey;
        DWORD RegType = 0;
        LONG Found = ERROR_FILE_NOT_FOUND;

        LegacySize = sizeof(Legacy);
        _snwprintf(KeyPath, ARRAYSIZE(KeyPath) - 1,
                   L"SYSTEM\\CurrentControlSet\\Control\\Class\\{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                   Guid->Data1, Guid->Data2, Guid->Data3, Guid->Data4[0], Guid->Data4[1], Guid->Data4[2], Guid->Data4[3],
                   Guid->Data4[4], Guid->Data4[5], Guid->Data4[6], Guid->Data4[7]);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyPath, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
        {
            Found = RegQueryValueExW(hKey, L"UpperFilters", NULL, &RegType, Legacy, &LegacySize);
            RegCloseKey(hKey);
        }
        if (Found == ERROR_SUCCESS && RegType == REG_MULTI_SZ)
        {
            ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_STRING_LIST, "%s: UpperFilters: %lx, type %lx\n", Tag, cr, Type);
            ok(cr != CR_SUCCESS || (Size == LegacySize && !memcmp(Buffer, Legacy, Size)),
               "%s: UpperFilters differ from the registry value (%lu and %lu bytes)\n", Tag, Size, LegacySize);
        }
        else
        {
            ok(cr == CR_NO_SUCH_VALUE && Size == 0, "%s: UpperFilters: %lx, size %lu\n", Tag, cr, Size);
        }
    }
    (void)HasFilters;

    /* A property it does not have */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Guid, &KeyUnknown, &Type, Buffer, &Size, 0);
    ok(cr == CR_NO_SUCH_VALUE && Size == 0 && Type == NOT_SET, "%s: unknown key: %lx, size %lu, type %lx\n", Tag, cr, Size, Type);

    /* The security descriptor, if the class has one: binary, valid; and its string form */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Guid, &DEVPKEY_DeviceClass_Security, &Type, Buffer, &Size, 0);
    if (cr == CR_SUCCESS)
    {
        ok(Type == DEVPROP_TYPE_SECURITY_DESCRIPTOR && IsValidSecurityDescriptor(Buffer), "%s: Security: type %lx\n", Tag, Type);
        Type = NOT_SET;
        Size = sizeof(Buffer);
        cr = pProperty(Guid, &DEVPKEY_DeviceClass_SecuritySDS, &Type, Buffer, &Size, 0);
        ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING && ((PWSTR)Buffer)[0] == L'D',
           "%s: SecuritySDS: %lx, type %lx\n", Tag, cr, Type);
    }
    else
    {
        ok(cr == CR_NO_SUCH_VALUE, "%s: Security: %lx\n", Tag, cr);
    }

    /* The keys: sizes, then the list; every key has a value, the class name is among them */
    Count = 0;
    cr = pKeys(Guid, NULL, &Count, 0);
    Need = Count;
    ok(cr == CR_BUFFER_SMALL && Need >= 2, "%s: key count: %lx, %lu\n", Tag, cr, Need);
    Count = 0;
    cr = pKeys(Guid, Keys, &Count, 0);
    ok(cr == CR_BUFFER_SMALL && Count == Need, "%s: count 0: %lx, %lu\n", Tag, cr, Count);
    if (Need > 1)
    {
        memset(Small, 0xab, sizeof(Small));
        Count = Need - 1;
        cr = pKeys(Guid, Small, &Count, 0);
        ok(cr == CR_BUFFER_SMALL && Count == Need, "%s: one short: %lx, %lu\n", Tag, cr, Count);
        ok(Small[0].pid == 0xabababab, "%s: the short array was written\n", Tag);
    }
    Count = ARRAYSIZE(Keys);
    cr = pKeys(Guid, Keys, &Count, 0);
    ok(cr == CR_SUCCESS && Count == Need, "%s: full: %lx, %lu, expected %lu\n", Tag, cr, Count, Need);
    if (cr == CR_SUCCESS)
    {
        ok(InList(Keys, Count, &DEVPKEY_DeviceClass_Name), "%s: no Name in the list\n", Tag);
        ok(InList(Keys, Count, &DEVPKEY_DeviceClass_ClassName), "%s: no ClassName in the list\n", Tag);
        for (i = 0; i < Count; i++)
        {
            Size = 0;
            cr = pProperty(Guid, &Keys[i], &Type, NULL, &Size, 0);
            ok(cr == CR_BUFFER_SMALL || cr == CR_SUCCESS, "%s: listed key %lu (pid %lu) has no value: %lx\n", Tag, i, Keys[i].pid, cr);
        }
    }
}

START_TEST(CM_Get_Class_Property)
{
    HMODULE hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    DEVPROPKEY Keys[8];
    DEVPROPTYPE Type;
    BYTE Buffer[64];
    ULONG Size, Count, i;
    CONFIGRET cr;

    pProperty = hCfgMgr ? (FN_PROP)GetProcAddress(hCfgMgr, "CM_Get_Class_PropertyW") : NULL;
    pKeys = hCfgMgr ? (FN_KEYS)GetProcAddress(hCfgMgr, "CM_Get_Class_Property_Keys") : NULL;
    if (!pProperty || !pKeys)
    {
        ok(!is_reactos(), "CM_Get_Class_PropertyW is not exported by cfgmgr32.dll\n");
        skip("CM_Get_Class_PropertyW is not available\n");
        return;
    }

    CheckClass(&ClassSystem, "System", FALSE);
    CheckClass(&ClassDisk, "DiskDrive", TRUE);
    CheckClass(&ClassKeyboard, "Keyboard", TRUE);

    /* Parameters of the property call */
    Size = sizeof(Buffer);
    cr = pProperty(NULL, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, 0);
    ok(cr == CR_INVALID_POINTER, "no class: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(&ClassSystem, NULL, &Type, Buffer, &Size, 0);
    ok(cr == CR_FAILURE, "no key: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(&ClassSystem, &DEVPKEY_DeviceClass_Name, NULL, Buffer, &Size, 0);
    ok(cr == CR_INVALID_POINTER, "no type: %lx\n", cr);
    cr = pProperty(&ClassSystem, &DEVPKEY_DeviceClass_Name, &Type, Buffer, NULL, 0);
    ok(cr == CR_INVALID_POINTER, "no size: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(&ClassSystem, &DEVPKEY_DeviceClass_Name, &Type, NULL, &Size, 0);
    ok(cr == CR_INVALID_POINTER, "no buffer with a size: %lx\n", cr);
    for (i = 2; i < 5; i++)
    {
        Size = sizeof(Buffer);
        cr = pProperty(&ClassSystem, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, i);
        ok(cr == CR_INVALID_FLAG, "flags %lu: %lx\n", i, cr);
    }

    /* The flag that picks the class of the interfaces: the installer classes are not there, and the other way round */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(&ClassSystem, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, 1);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && Size == 0 && Type == NOT_SET, "System as an interface class: %lx, size %lu\n", cr, Size);
    Size = sizeof(Buffer);
    cr = pProperty(&InterfaceDisk, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, 0);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && Size == 0, "disk interface as an installer class: %lx, size %lu\n", cr, Size);
    Size = sizeof(Buffer);
    cr = pProperty(&InterfaceDisk, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, 1);
    ok(cr == CR_NO_SUCH_VALUE && Size == 0, "disk interface class: %lx, size %lu\n", cr, Size);

    /* A class that is none */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(&NoSuchClass, &DEVPKEY_DeviceClass_Name, &Type, Buffer, &Size, 0);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && Size == 0 && Type == NOT_SET, "no such class: %lx, size %lu, type %lx\n", cr, Size, Type);

    /* The keys: parameters, and the same classes */
    Count = 5;
    cr = pKeys(&ClassSystem, NULL, &Count, 0);
    ok(cr == CR_INVALID_POINTER && Count == 5, "keys, no array with a count: %lx, %lu\n", cr, Count);
    cr = pKeys(&ClassSystem, Keys, NULL, 0);
    ok(cr == CR_INVALID_POINTER, "keys, no count: %lx\n", cr);
    Count = 5;
    cr = pKeys(NULL, Keys, &Count, 0);
    ok(cr == CR_INVALID_POINTER && Count == 5, "keys, no class: %lx, %lu\n", cr, Count);
    for (i = 2; i < 5; i++)
    {
        Count = 5;
        cr = pKeys(&ClassSystem, Keys, &Count, i);
        ok(cr == CR_INVALID_FLAG && Count == 5, "keys, flags %lu: %lx, %lu\n", i, cr, Count);
    }
    Count = 5;
    cr = pKeys(&ClassSystem, Keys, &Count, 1);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && Count == 0, "keys, System as an interface class: %lx, %lu\n", cr, Count);
    Count = 5;
    cr = pKeys(&InterfaceDisk, Keys, &Count, 0);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && Count == 0, "keys, disk interface as an installer class: %lx, %lu\n", cr, Count);
    Count = 5;
    cr = pKeys(&InterfaceDisk, Keys, &Count, 1);
    ok(cr == CR_SUCCESS && Count == 0, "keys, disk interface class: %lx, %lu\n", cr, Count);
    Count = 5;
    cr = pKeys(&NoSuchClass, Keys, &Count, 0);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && Count == 0, "keys, no such class: %lx, %lu\n", cr, Count);
}
