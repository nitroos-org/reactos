/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for CM_Get_Device_Interface_PropertyW, ..._Property_KeysW, CM_Open_Device_Interface_KeyW and
 *              CM_Delete_Device_Interface_KeyW (cfgmgr32.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The return codes were measured on Windows 10 22H2 (x64 and x86), for the interface of the first disk or keyboard of
 * the system and for names made from it. Windows keeps more properties of an interface than ReactOS does, so the
 * list of the keys is checked for the keys that both have, and for every key of the list having a value. Nothing is
 * created or deleted on Windows; the keys of an interface are created and deleted on ReactOS only.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#define INITGUID
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <cfgmgr32.h>
#include <devpropdef.h>
#include <devpkey.h>

typedef CONFIGRET (WINAPI *FN_PROP)(PCWSTR, const DEVPROPKEY *, DEVPROPTYPE *, PBYTE, PULONG, ULONG);
typedef CONFIGRET (WINAPI *FN_KEYS)(PCWSTR, DEVPROPKEY *, PULONG, ULONG);
typedef CONFIGRET (WINAPI *FN_OPEN)(PCWSTR, REGSAM, ULONG, PHKEY, ULONG);
typedef CONFIGRET (WINAPI *FN_DELETE)(PCWSTR, ULONG);

static FN_PROP pProperty;
static FN_KEYS pKeys;
static FN_OPEN pOpen;
static FN_DELETE pDelete;

static const DEVPROPKEY KeyEnabled = {{0x026e516e, 0xb814, 0x414b, {0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22}}, 3};
static const DEVPROPKEY KeyClassGuid = {{0x026e516e, 0xb814, 0x414b, {0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22}}, 4};
static const DEVPROPKEY KeyUnknown = {{0x12345678, 0x1234, 0x1234, {1, 2, 3, 4, 5, 6, 7, 8}}, 7};

static const GUID Disk = {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};
static const GUID Keyboard = {0x884b96c3, 0x56ef, 0x11d1, {0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd}};
static const GUID Mouse = {0x378de44c, 0x56ef, 0x11d1, {0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd}};
static const GUID Volume = {0x53f5630d, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};

#define NOT_SET 0xDEADBEEF
#define MARKER  ((HKEY)(ULONG_PTR)0x1234)

static BOOL InList(const DEVPROPKEY *Keys, ULONG Count, const DEVPROPKEY *Key)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        if (Keys[i].pid == Key->pid && IsEqualGUID(&Keys[i].fmtid, &Key->fmtid))
            return TRUE;
    return FALSE;
}

/* The five outcomes of a malformed or missing name: the property, the keys, the open and the delete */
static void CheckName(PCSTR Tag, PCWSTR Name, CONFIGRET Prop, CONFIGRET KeysCr, CONFIGRET Open, CONFIGRET Delete)
{
    DEVPROPTYPE Type = NOT_SET;
    DEVPROPKEY Keys[8];
    BYTE Buffer[16];
    ULONG Size = sizeof(Buffer), Count = 5;
    HKEY hKey = MARKER;
    CONFIGRET cr;

    cr = pProperty(Name, &KeyEnabled, &Type, Buffer, &Size, 0);
    ok(cr == Prop, "%s: property: %lx, expected %lx\n", Tag, cr, Prop);
    if (Prop != CR_SUCCESS)
        ok(Size == 0, "%s: property: size %lu after the failure\n", Tag, Size);

    cr = pKeys(Name, Keys, &Count, 0);
    ok(cr == KeysCr, "%s: keys: %lx, expected %lx\n", Tag, cr, KeysCr);
    if (KeysCr != CR_SUCCESS)
        ok(Count == 0, "%s: keys: count %lu after the failure\n", Tag, Count);

    cr = pOpen(Name, KEY_READ, RegDisposition_OpenExisting, &hKey, 0);
    if (Open == CR_SUCCESS)
    {
        ok(cr == CR_SUCCESS || cr == CR_NO_SUCH_REGISTRY_KEY, "%s: open: %lx\n", Tag, cr);
        if (cr == CR_SUCCESS)
            RegCloseKey(hKey);
    }
    else
    {
        ok(cr == Open, "%s: open: %lx, expected %lx\n", Tag, cr, Open);
        ok(hKey == NULL, "%s: open: key %p after the failure\n", Tag, hKey);
    }

    if (Delete != CR_SUCCESS)
    {
        cr = pDelete(Name, 0);
        ok(cr == Delete, "%s: delete: %lx, expected %lx\n", Tag, cr, Delete);
    }
}

static void CheckInterface(PWSTR Link)
{
    DEVPROPKEY Keys[64], Small[64];
    DEVPROPTYPE Type;
    BYTE Buffer[512];
    WCHAR Variant[600];
    ULONG Size, Count, Need, i;
    DEVINST Dev;
    GUID Class;
    PWSTR Brace;
    CONFIGRET cr;

    /* Enabled: a boolean of one byte, true for an interface that is listed */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Link, &KeyEnabled, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_BOOLEAN && Size == 1, "Enabled: %lx, type %lx, size %lu\n", cr, Type, Size);
    ok(Buffer[0] == 0xff, "Enabled: %02x\n", Buffer[0]);

    Type = NOT_SET;
    Size = 0;
    cr = pProperty(Link, &KeyEnabled, &Type, NULL, &Size, 0);
    ok(cr == CR_BUFFER_SMALL && Type == DEVPROP_TYPE_BOOLEAN && Size == 1, "Enabled, no buffer: %lx, type %lx, size %lu\n", cr, Type, Size);
    Type = NOT_SET;
    Size = 0;
    cr = pProperty(Link, &KeyEnabled, &Type, Buffer, &Size, 0);
    ok(cr == CR_BUFFER_SMALL && Type == DEVPROP_TYPE_BOOLEAN && Size == 1, "Enabled, size 0: %lx, type %lx, size %lu\n", cr, Type, Size);
    Size = 1;
    cr = pProperty(Link, &KeyEnabled, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Size == 1, "Enabled, size 1: %lx, size %lu\n", cr, Size);

    /* ClassGuid: the class of the name */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Link, &KeyClassGuid, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_GUID && Size == sizeof(GUID), "ClassGuid: %lx, type %lx, size %lu\n", cr, Type, Size);
    Brace = wcsrchr(Link, L'{');
    if (cr == CR_SUCCESS && Brace)
    {
        WCHAR Text[64];
        GUID *Guid = (GUID *)Buffer;

        _snwprintf(Text, ARRAYSIZE(Text) - 1, L"{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", Guid->Data1, Guid->Data2, Guid->Data3,
                 Guid->Data4[0], Guid->Data4[1], Guid->Data4[2], Guid->Data4[3], Guid->Data4[4], Guid->Data4[5],
                 Guid->Data4[6], Guid->Data4[7]);
        ok(!_wcsnicmp(Brace, Text, 38), "ClassGuid %ls, name ends in %ls\n", Text, Brace);
    }
    (void)Class;

    /* The instance ID of the device, which is a devnode */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Link, &DEVPKEY_Device_InstanceId, &Type, Buffer, &Size, 0);
    ok(cr == CR_SUCCESS && Type == DEVPROP_TYPE_STRING, "InstanceId: %lx, type %lx\n", cr, Type);
    if (cr == CR_SUCCESS)
    {
        ok(Size == (wcslen((PWSTR)Buffer) + 1) * sizeof(WCHAR), "InstanceId: size %lu\n", Size);
        cr = CM_Locate_DevNodeW(&Dev, (PWSTR)Buffer, CM_LOCATE_DEVNODE_NORMAL);
        ok(cr == CR_SUCCESS, "InstanceId %ls is no devnode: %lx\n", (PWSTR)Buffer, cr);
    }

    /* A property it does not have */
    Type = NOT_SET;
    Size = sizeof(Buffer);
    cr = pProperty(Link, &KeyUnknown, &Type, Buffer, &Size, 0);
    ok(cr == CR_NO_SUCH_VALUE && Size == 0 && Type == NOT_SET, "unknown key: %lx, size %lu, type %lx\n", cr, Size, Type);

    /* Parameters */
    Size = sizeof(Buffer);
    cr = pProperty(Link, &KeyEnabled, &Type, Buffer, &Size, 1);
    ok(cr == CR_INVALID_FLAG, "flags 1: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(Link, &KeyEnabled, NULL, Buffer, &Size, 0);
    ok(cr == CR_INVALID_POINTER, "no type: %lx\n", cr);
    cr = pProperty(Link, &KeyEnabled, &Type, Buffer, NULL, 0);
    ok(cr == CR_INVALID_POINTER, "no size: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(Link, &KeyEnabled, &Type, NULL, &Size, 0);
    ok(cr == CR_INVALID_POINTER, "no buffer with a size: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(Link, NULL, &Type, Buffer, &Size, 0);
    ok(cr == CR_FAILURE, "no key: %lx\n", cr);
    Size = sizeof(Buffer);
    cr = pProperty(NULL, &KeyEnabled, &Type, Buffer, &Size, 0);
    ok(cr == CR_INVALID_POINTER, "no name: %lx\n", cr);

    /* The keys: sizes, then the list; every key has a value, and the keys that both systems have are there */
    Count = 0;
    cr = pKeys(Link, NULL, &Count, 0);
    ok(cr == CR_BUFFER_SMALL && Count >= 3, "key count: %lx, %lu\n", cr, Count);
    Need = Count;
    Count = 0;
    cr = pKeys(Link, Keys, &Count, 0);
    ok(cr == CR_BUFFER_SMALL && Count == Need, "count 0: %lx, %lu\n", cr, Count);
    if (Need > 1)
    {
        memset(Small, 0xab, sizeof(Small));
        Count = Need - 1;
        cr = pKeys(Link, Small, &Count, 0);
        ok(cr == CR_BUFFER_SMALL && Count == Need, "one short: %lx, %lu\n", cr, Count);
        ok(Small[0].pid == 0xabababab, "the short array was written\n");
    }
    Count = ARRAYSIZE(Keys);
    cr = pKeys(Link, Keys, &Count, 0);
    ok(cr == CR_SUCCESS && Count == Need, "full: %lx, %lu, expected %lu\n", cr, Count, Need);
    if (cr == CR_SUCCESS)
    {
        ok(InList(Keys, Count, &KeyEnabled), "no Enabled in the list\n");
        ok(InList(Keys, Count, &KeyClassGuid), "no ClassGuid in the list\n");
        ok(InList(Keys, Count, &DEVPKEY_Device_InstanceId), "no InstanceId in the list\n");
        for (i = 0; i < Count; i++)
        {
            Size = 0;
            cr = pProperty(Link, &Keys[i], &Type, NULL, &Size, 0);
            ok(cr == CR_BUFFER_SMALL || cr == CR_SUCCESS, "listed key %lu has no value: %lx\n", i, cr);
        }
    }
    Count = 5;
    cr = pKeys(Link, Keys, NULL, 0);
    ok(cr == CR_INVALID_POINTER, "keys, no count: %lx\n", cr);
    Count = 5;
    cr = pKeys(Link, Keys, &Count, 1);
    ok(cr == CR_INVALID_FLAG && Count == 5, "keys, flags 1: %lx, %lu\n", cr, Count);
    Count = 5;
    cr = pKeys(NULL, Keys, &Count, 0);
    ok(cr == CR_INVALID_POINTER && Count == 5, "keys, no name: %lx, %lu\n", cr, Count);

    /* The name the registry way: other forms of the same name, and names that are not interfaces */
    CheckName("real", Link, CR_SUCCESS, CR_SUCCESS, CR_SUCCESS, CR_SUCCESS);

    _snwprintf(Variant, ARRAYSIZE(Variant) - 1, L"%ls\\ref", Link);
    CheckName("reference string", Variant, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_REGISTRY_KEY,
              CR_NO_SUCH_DEVICE_INTERFACE);
    _snwprintf(Variant, ARRAYSIZE(Variant) - 1, L"%lsx", Link);
    CheckName("text after the GUID", Variant, CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    wcscpy(Variant, Link);
    Variant[1] = L'?';
    {
        DEVPROPTYPE T = NOT_SET;
        BYTE B[16];
        ULONG S = sizeof(B);

        cr = pProperty(Variant, &KeyEnabled, &T, B, &S, 0);
        ok(cr == CR_SUCCESS, "\\??\\ form: %lx\n", cr);
        Count = 8;
        cr = pKeys(Variant, Keys, &Count, 0);
        ok(cr == CR_SUCCESS, "\\??\\ form, keys: %lx\n", cr);
    }
    wcscpy(Variant, Link);
    Variant[0] = L'x';
    CheckName("bad prefix", Variant, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    wcscpy(Variant, Link);
    Brace = wcsrchr(Variant, L'{');
    for (i = 0; Brace[i]; i++)
        Brace[i] = towupper(Brace[i]);
    {
        DEVPROPTYPE T = NOT_SET;
        BYTE B[16];
        ULONG S = sizeof(B);

        cr = pProperty(Variant, &KeyEnabled, &T, B, &S, 0);
        ok(cr == CR_SUCCESS, "upper case GUID: %lx\n", cr);
    }
    wcscpy(Variant, Link);
    Brace = wcsrchr(Variant, L'#');
    *Brace = L'\\';
    CheckName("backslash before the GUID", Variant, CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    wcscpy(Variant, Link);
    *wcsrchr(Variant, L'}') = UNICODE_NULL;
    CheckName("no closing brace", Variant, CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    wcscpy(Variant, Link);
    Brace = wcsrchr(Variant, L'#');
    wcscpy(Brace, L"#{12345678-1234-1234-0102-030405060708}");
    CheckName("another class", Variant, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_REGISTRY_KEY,
              CR_NO_SUCH_DEVICE_INTERFACE);
    wcscpy(Variant, Link);
    Brace = wcschr(Variant + 4, L'#');
    Brace[1] = L'Z';
    CheckName("another device", Variant, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_REGISTRY_KEY,
              CR_NO_SUCH_DEVICE_INTERFACE);

    CheckName("empty", L"", CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    CheckName("garbage", L"garbage", CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    CheckName("prefix only", L"\\\\?\\", CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);
    CheckName("GUID only", L"{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA,
              CR_INVALID_DATA, CR_INVALID_DATA);
    CheckName("prefix and GUID", L"\\\\?\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", CR_NO_SUCH_DEVICE_INTERFACE, CR_INVALID_DATA,
              CR_INVALID_DATA, CR_INVALID_DATA);
    CheckName("one part and GUID", L"\\\\?\\x#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", CR_NO_SUCH_DEVICE_INTERFACE,
              CR_INVALID_DATA, CR_INVALID_DATA, CR_INVALID_DATA);

    /* The key of the parameters: parameters first */
    {
        HKEY hKey = MARKER;

        cr = pOpen(Link, KEY_READ, 2, &hKey, 0);
        ok(cr == CR_INVALID_DATA, "disposition 2: %lx\n", cr);
        cr = pOpen(Link, KEY_READ, RegDisposition_OpenExisting, &hKey, 1);
        ok(cr == CR_INVALID_FLAG, "open, flags 1: %lx\n", cr);
        cr = pOpen(Link, KEY_READ, RegDisposition_OpenExisting, NULL, 0);
        ok(cr == CR_INVALID_POINTER, "open, no key: %lx\n", cr);
        cr = pOpen(NULL, KEY_READ, RegDisposition_OpenExisting, &hKey, 0);
        ok(cr == CR_INVALID_POINTER, "open, no name: %lx\n", cr);
        cr = pDelete(NULL, 0);
        ok(cr == CR_INVALID_POINTER, "delete, no name: %lx\n", cr);
        cr = pDelete(Link, 1);
        ok(cr == CR_INVALID_FLAG, "delete, flags 1: %lx\n", cr);
    }
}

/* ReactOS only: the cycle of creating the parameters, writing into them, and deleting them */
static void CheckParameterCycle(PWSTR Link)
{
    HKEY hKey = MARKER, hCheck;
    DWORD Value = 0x1234, Read = 0, Size = sizeof(Read);
    BOOL HadKey;
    CONFIGRET cr;

    cr = pOpen(Link, KEY_READ, RegDisposition_OpenExisting, &hKey, 0);
    HadKey = (cr == CR_SUCCESS);
    if (HadKey)
    {
        RegCloseKey(hKey);
        skip("the interface has parameters already\n");
        return;
    }
    ok(cr == CR_NO_SUCH_REGISTRY_KEY, "open, none there: %lx\n", cr);

    hKey = MARKER;
    cr = pOpen(Link, KEY_READ | KEY_WRITE, RegDisposition_OpenAlways, &hKey, 0);
    ok(cr == CR_SUCCESS && hKey != NULL && hKey != MARKER, "create: %lx, key %p\n", cr, hKey);
    if (cr != CR_SUCCESS)
        return;
    ok(RegSetValueExW(hKey, L"Test", 0, REG_DWORD, (PBYTE)&Value, sizeof(Value)) == ERROR_SUCCESS, "RegSetValueEx failed\n");
    RegCloseKey(hKey);

    cr = pOpen(Link, KEY_READ, RegDisposition_OpenExisting, &hCheck, 0);
    ok(cr == CR_SUCCESS, "open after the create: %lx\n", cr);
    if (cr == CR_SUCCESS)
    {
        ok(RegQueryValueExW(hCheck, L"Test", NULL, NULL, (PBYTE)&Read, &Size) == ERROR_SUCCESS && Read == Value,
           "the value is %lx\n", Read);
        RegCloseKey(hCheck);
    }

    cr = pDelete(Link, 0);
    ok(cr == CR_SUCCESS, "delete: %lx\n", cr);
    hCheck = MARKER;
    cr = pOpen(Link, KEY_READ, RegDisposition_OpenExisting, &hCheck, 0);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY && hCheck == NULL, "open after the delete: %lx, key %p\n", cr, hCheck);
    cr = pDelete(Link, 0);
    ok(cr == CR_NO_SUCH_REGISTRY_KEY, "delete again: %lx\n", cr);
}

START_TEST(CM_Get_Device_Interface_Property)
{
    HMODULE hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    const GUID *Classes[] = { &Disk, &Keyboard, &Mouse, &Volume };
    WCHAR List[4096];
    ULONG Length, i;
    CONFIGRET cr;

    pProperty = hCfgMgr ? (FN_PROP)GetProcAddress(hCfgMgr, "CM_Get_Device_Interface_PropertyW") : NULL;
    pKeys = hCfgMgr ? (FN_KEYS)GetProcAddress(hCfgMgr, "CM_Get_Device_Interface_Property_KeysW") : NULL;
    pOpen = hCfgMgr ? (FN_OPEN)GetProcAddress(hCfgMgr, "CM_Open_Device_Interface_KeyW") : NULL;
    pDelete = hCfgMgr ? (FN_DELETE)GetProcAddress(hCfgMgr, "CM_Delete_Device_Interface_KeyW") : NULL;
    if (!pProperty || !pKeys || !pOpen || !pDelete)
    {
        ok(!is_reactos(), "the device interface property functions are not exported by cfgmgr32.dll\n");
        skip("CM_Get_Device_Interface_PropertyW is not available\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(Classes); i++)
    {
        Length = 0;
        cr = CM_Get_Device_Interface_List_SizeW(&Length, (LPGUID)Classes[i], NULL, 0);
        if (cr != CR_SUCCESS || Length <= 2 || Length > ARRAYSIZE(List))
            continue;
        cr = CM_Get_Device_Interface_ListW((LPGUID)Classes[i], NULL, List, ARRAYSIZE(List), 0);
        ok(cr == CR_SUCCESS, "CM_Get_Device_Interface_List: %lx\n", cr);
        if (cr == CR_SUCCESS && List[0])
            break;
        List[0] = UNICODE_NULL;
    }
    if (i == ARRAYSIZE(Classes))
    {
        skip("no device interface of the classes tried is present\n");
        return;
    }

    CheckInterface(List);
    if (is_reactos())
        CheckParameterCycle(List);
}
