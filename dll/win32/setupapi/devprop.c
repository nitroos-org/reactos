/*
 * PROJECT:     ReactOS Setup API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Device class and device interface properties (DEVPROPKEY)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Two kinds of property are read here, from the registry, the way SetupDiGetDevicePropertyW reads the properties of a
 * device: those of a device setup class (the class key under Control\Class) and those of a device interface (the
 * instance key under Control\DeviceClasses\{class}\##?#...). Only the properties that something stores in the registry
 * of ReactOS are available; the others are absent (ERROR_NOT_FOUND), as a property that was never set is on Windows.
 * Nothing writes these properties yet, and a property store (the Properties subkey) is not read.
 *
 * The types, the keys of a class and an interface, and the errors for the malformed names were measured on Windows 10
 * 22H2 (build 19045) through cfgmgr32.
 */

#include "setupapi_private.h"

#include <devpropdef.h>

#ifndef DICLASSPROP_INSTALLER
#define DICLASSPROP_INSTALLER   0x00000001
#define DICLASSPROP_INTERFACE   0x00000002
#endif

/* The measured classification of an interface name; the CM_ functions turn it into their codes */
#define PARSE_OK            0
#define PARSE_NO_GUID       1   /* no "#{guid}" at the end of the device part, or something after it that is no reference */
#define PARSE_BAD_PREFIX    2   /* the name does not start with \\?\ or \??\ */
#define PARSE_SHORT_DEVICE  3   /* fewer than two '#'-separated parts before the GUID */

static const GUID FmtidName =
    {0xb725f130, 0x47ef, 0x101a, {0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac}};
static const GUID FmtidClass =
    {0x259abffc, 0x50a7, 0x47ce, {0xaf, 0x08, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66}};
static const GUID FmtidClassFilters =
    {0x4321918b, 0xf69e, 0x470d, {0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b}};
static const GUID FmtidInterface =
    {0x026e516e, 0xb814, 0x414b, {0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22}};
static const GUID FmtidInstanceId =
    {0x78c34fc8, 0x104a, 0x4aca, {0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57}};

static const WCHAR DpDeviceClasses[] = L"System\\CurrentControlSet\\Control\\DeviceClasses";
static const WCHAR DpDeviceParameters[] = L"Device Parameters";

LONG WINAPI RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey);

typedef enum _DP_KIND
{
    DpString,           /* REG_SZ */
    DpList,             /* REG_MULTI_SZ */
    DpBoolean,          /* REG_DWORD, or a REG_SZ with a number */
    DpUint32,           /* REG_DWORD */
    DpSecurity,         /* REG_SZ in SDDL, as a self-relative security descriptor */
    DpSecurityString,   /* REG_SZ in SDDL, as the string */
} DP_KIND;

static const struct
{
    const GUID *Fmtid;
    ULONG Pid;
    PCWSTR Value;       /* the value of the class key; "" is the default value */
    DEVPROPTYPE Type;
    DP_KIND Kind;
    BOOLEAN Listed;     /* in the list of the keys of a class (Windows leaves the string form of the security out) */
} ClassProps[] =
{
    { &FmtidName,         10, L"",                DEVPROP_TYPE_STRING,        DpString,         TRUE },   /* DEVPKEY_NAME */
    { &FmtidClass,         2, L"",                DEVPROP_TYPE_STRING,        DpString,         TRUE },   /* DeviceClass_Name */
    { &FmtidClass,         3, L"Class",           DEVPROP_TYPE_STRING,        DpString,         TRUE },   /* ClassName */
    { &FmtidClass,         4, L"Icon",            DEVPROP_TYPE_STRING,        DpString,         TRUE },
    { &FmtidClass,         5, L"Installer32",     DEVPROP_TYPE_STRING,        DpString,         TRUE },   /* ClassInstaller */
    { &FmtidClass,         6, L"EnumPropPages32", DEVPROP_TYPE_STRING,        DpString,         TRUE },   /* PropPageProvider */
    { &FmtidClass,         7, L"NoInstallClass",  DEVPROP_TYPE_BOOLEAN,       DpBoolean,        TRUE },
    { &FmtidClass,         8, L"NoDisplayClass",  DEVPROP_TYPE_BOOLEAN,       DpBoolean,        TRUE },
    { &FmtidClass,         9, L"SilentInstall",   DEVPROP_TYPE_BOOLEAN,       DpBoolean,        TRUE },
    { &FmtidClass,        10, L"NoUseClass",      DEVPROP_TYPE_BOOLEAN,       DpBoolean,        TRUE },
    { &FmtidClass,        12, L"IconPath",        DEVPROP_TYPE_STRING_LIST,   DpList,           TRUE },
    { &FmtidClassFilters, 19, L"UpperFilters",    DEVPROP_TYPE_STRING_LIST,   DpList,           TRUE },
    { &FmtidClassFilters, 20, L"LowerFilters",    DEVPROP_TYPE_STRING_LIST,   DpList,           TRUE },
    { &FmtidClassFilters, 25, L"Security",        DEVPROP_TYPE_SECURITY_DESCRIPTOR, DpSecurity, TRUE },
    { &FmtidClassFilters, 26, L"Security",        DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING, DpSecurityString, FALSE },
    { &FmtidClassFilters, 27, L"DeviceType",      DEVPROP_TYPE_UINT32,        DpUint32,         TRUE },
    { &FmtidClassFilters, 28, L"Exclusive",       DEVPROP_TYPE_BOOLEAN,       DpBoolean,        TRUE },
    { &FmtidClassFilters, 29, L"DeviceCharacteristics", DEVPROP_TYPE_UINT32,  DpUint32,         TRUE },
};

static DWORD
DpReturn(
    DEVPROPTYPE Type,
    const VOID *Value,
    DWORD ValueSize,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize)
{
    *PropertyType = Type;
    if (RequiredSize)
        *RequiredSize = ValueSize;
    if (PropertyBufferSize < ValueSize)
        return ERROR_INSUFFICIENT_BUFFER;
    memcpy(PropertyBuffer, Value, ValueSize);
    return ERROR_SUCCESS;
}

static BOOL
DpSameKey(const DEVPROPKEY *Key, const GUID *Fmtid, ULONG Pid)
{
    return Key->pid == Pid && IsEqualGUID(&Key->fmtid, Fmtid);
}

/* A registry value in a zeroed heap block three characters larger than the value; the caller frees it */
static DWORD
DpReadValue(HKEY hKey, PCWSTR Name, PDWORD Type, PBYTE *Data, PDWORD Size)
{
    DWORD Capacity = 256, Error, Length;
    PBYTE Buffer;

    for (;;)
    {
        Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Capacity + 3 * sizeof(WCHAR));
        if (!Buffer)
            return ERROR_NOT_ENOUGH_MEMORY;
        Length = Capacity;
        Error = RegQueryValueExW(hKey, Name, NULL, Type, Buffer, &Length);
        if (Error == ERROR_SUCCESS)
        {
            *Data = Buffer;
            *Size = Length;
            return ERROR_SUCCESS;
        }
        HeapFree(GetProcessHeap(), 0, Buffer);
        if (Error != ERROR_MORE_DATA)
            return (Error == ERROR_FILE_NOT_FOUND) ? ERROR_NOT_FOUND : Error;
        Capacity = Length > Capacity ? Length : Capacity * 2;
    }
}

/* One property of an open class key */
static DWORD
DpGetClassValue(
    HKEY hClassKey,
    ULONG Index,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize)
{
    DWORD RegType = REG_NONE, Size = 0, Chars, Length, Number, Error;
    PBYTE Data = NULL;
    PWCHAR Text;
    DEVPROP_BOOLEAN Boolean;
    PSECURITY_DESCRIPTOR Sd;

    Error = DpReadValue(hClassKey, ClassProps[Index].Value, &RegType, &Data, &Size);
    if (Error != ERROR_SUCCESS)
        return Error;

    Text = (PWCHAR)Data;
    Chars = (Size + sizeof(WCHAR) - 1) / sizeof(WCHAR);

    switch (ClassProps[Index].Kind)
    {
        case DpString:
        case DpSecurityString:
            if (RegType != REG_SZ && RegType != REG_EXPAND_SZ)
            {
                Error = ERROR_NOT_FOUND;
                break;
            }
            for (Length = 0; Length < Chars && Text[Length]; Length++)
                ;
            Text[Length] = UNICODE_NULL;
            Error = DpReturn(ClassProps[Index].Type, Text, (Length + 1) * sizeof(WCHAR), PropertyType, PropertyBuffer,
                             PropertyBufferSize, RequiredSize);
            break;

        case DpList:
            if (RegType != REG_MULTI_SZ)
            {
                Error = ERROR_NOT_FOUND;
                break;
            }
            /* The strings up to the first empty one, each ended, then the empty string */
            Length = 0;
            while (Length < Chars && Text[Length])
            {
                while (Length < Chars && Text[Length])
                    Length++;
                Length++;
            }
            Text[Length] = UNICODE_NULL;
            Error = DpReturn(ClassProps[Index].Type, Text, (Length + 1) * sizeof(WCHAR), PropertyType, PropertyBuffer,
                             PropertyBufferSize, RequiredSize);
            break;

        case DpBoolean:
        case DpUint32:
            if (RegType == REG_DWORD && Size == sizeof(DWORD))
            {
                Number = *(PDWORD)Data;
            }
            else if (ClassProps[Index].Kind == DpBoolean && RegType == REG_SZ)
            {
                /* The class keys of Windows keep these flags as the text "1" */
                for (Length = 0; Length < Chars && Text[Length]; Length++)
                    ;
                Text[Length] = UNICODE_NULL;
                Number = (DWORD)wcstol(Text, NULL, 0);
            }
            else
            {
                Error = ERROR_NOT_FOUND;
                break;
            }
            if (ClassProps[Index].Kind == DpBoolean)
            {
                Boolean = Number ? DEVPROP_TRUE : DEVPROP_FALSE;
                Error = DpReturn(DEVPROP_TYPE_BOOLEAN, &Boolean, sizeof(Boolean), PropertyType, PropertyBuffer,
                                 PropertyBufferSize, RequiredSize);
            }
            else
            {
                Error = DpReturn(DEVPROP_TYPE_UINT32, &Number, sizeof(Number), PropertyType, PropertyBuffer,
                                 PropertyBufferSize, RequiredSize);
            }
            break;

        case DpSecurity:
            if (RegType != REG_SZ)
            {
                Error = ERROR_NOT_FOUND;
                break;
            }
            for (Length = 0; Length < Chars && Text[Length]; Length++)
                ;
            Text[Length] = UNICODE_NULL;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Text, SDDL_REVISION_1, &Sd, NULL))
            {
                Error = ERROR_NOT_FOUND;
                break;
            }
            Error = DpReturn(DEVPROP_TYPE_SECURITY_DESCRIPTOR, Sd, GetSecurityDescriptorLength(Sd), PropertyType,
                             PropertyBuffer, PropertyBufferSize, RequiredSize);
            LocalFree(Sd);
            break;

        default:
            Error = ERROR_NOT_FOUND;
            break;
    }

    HeapFree(GetProcessHeap(), 0, Data);
    return Error;
}

/*
 * The property of a class. ClassKind is DIOCR_INSTALLER (the class key) or DIOCR_INTERFACE (the key of an interface
 * class, which has none of these properties). Returns ERROR_INVALID_CLASS when the class has no key.
 */
DWORD
SETUP_GetClassProperty(
    const GUID *ClassGuid,
    DWORD ClassKind,
    PCWSTR MachineName,
    const DEVPROPKEY *PropertyKey,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize)
{
    HKEY hKey;
    DWORD Error = ERROR_NOT_FOUND;
    ULONG i;

    hKey = SetupDiOpenClassRegKeyExW(ClassGuid, KEY_QUERY_VALUE, ClassKind, MachineName, NULL);
    if (hKey == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        return (Error == ERROR_SUCCESS || Error == ERROR_FILE_NOT_FOUND || Error == ERROR_KEY_DOES_NOT_EXIST) ?
               ERROR_INVALID_CLASS : Error;
    }

    if (ClassKind == DIOCR_INSTALLER)
    {
        for (i = 0; i < ARRAYSIZE(ClassProps); i++)
        {
            if (DpSameKey(PropertyKey, ClassProps[i].Fmtid, ClassProps[i].Pid))
            {
                Error = DpGetClassValue(hKey, i, PropertyType, PropertyBuffer, PropertyBufferSize, RequiredSize);
                break;
            }
        }
    }
    RegCloseKey(hKey);
    return Error;
}

/* The keys of a class that have a value; RequiredCount is the number of them */
DWORD
SETUP_GetClassPropertyKeys(
    const GUID *ClassGuid,
    DWORD ClassKind,
    PCWSTR MachineName,
    DEVPROPKEY *KeyArray,
    DWORD KeyCount,
    PDWORD RequiredCount)
{
    HKEY hKey;
    DEVPROPTYPE Type;
    DWORD Found = 0, Error;
    ULONG i;

    hKey = SetupDiOpenClassRegKeyExW(ClassGuid, KEY_QUERY_VALUE, ClassKind, MachineName, NULL);
    if (hKey == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        return (Error == ERROR_SUCCESS || Error == ERROR_FILE_NOT_FOUND || Error == ERROR_KEY_DOES_NOT_EXIST) ?
               ERROR_INVALID_CLASS : Error;
    }

    if (ClassKind == DIOCR_INSTALLER)
    {
        for (i = 0; i < ARRAYSIZE(ClassProps); i++)
        {
            if (!ClassProps[i].Listed)
                continue;
            Error = DpGetClassValue(hKey, i, &Type, NULL, 0, NULL);
            if (Error != ERROR_SUCCESS && Error != ERROR_INSUFFICIENT_BUFFER)
                continue;
            if (Found < KeyCount)
            {
                KeyArray[Found].fmtid = *ClassProps[i].Fmtid;
                KeyArray[Found].pid = ClassProps[i].Pid;
            }
            Found++;
        }
    }
    RegCloseKey(hKey);

    *RequiredCount = Found;
    return Found > KeyCount ? ERROR_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
}

/*
 * Splits the symbolic link of a device interface: the class, and the names of the keys under
 * Control\DeviceClasses\{class} (the device key "##?#...", then the instance key "#" or "#reference").
 */
static DWORD
DpParseInterface(
    PCWSTR Link,
    GUID *ClassGuid,
    PWSTR DeviceKeyName,
    SIZE_T DeviceKeyChars,
    PWSTR InstanceKeyName,
    SIZE_T InstanceKeyChars,
    PBOOL EmptyReference)
{
    SIZE_T Length, i, Pos = 0, Hashes = 0, Part;
    WCHAR GuidText[MAX_GUID_STRING_LEN];
    BOOL Found = FALSE, Prefix;

    if (!Link)
        return PARSE_NO_GUID;
    Length = wcslen(Link);

    for (i = 0; i + 39 <= Length; i++)
    {
        if (Link[i] != L'#' || Link[i + 1] != L'{' || Link[i + 38] != L'}')
            continue;
        if (Link[i + 39] != UNICODE_NULL && Link[i + 39] != L'\\')
            continue;
        memcpy(GuidText, &Link[i + 1], 38 * sizeof(WCHAR));
        GuidText[38] = UNICODE_NULL;
        GuidText[0] = L'{';
        if (pSetupGuidFromString(GuidText, ClassGuid) != NO_ERROR)
            continue;
        Pos = i;
        Found = TRUE;
        break;
    }
    if (!Found)
        return PARSE_NO_GUID;

    Prefix = (Length >= 4 && Link[0] == L'\\' && (Link[1] == L'\\' || Link[1] == L'?') && Link[2] == L'?' &&
              Link[3] == L'\\');
    if (!Prefix)
        return PARSE_BAD_PREFIX;

    /* at least the bus and the device: a separator in the device part (and the one before the GUID) */
    for (i = 4; i < Pos; i++)
    {
        if (Link[i] == L'#')
            Hashes++;
    }
    if (Pos <= 4 || Hashes < 1)
        return PARSE_SHORT_DEVICE;

    /* "##?#" and the rest of the name up to the end of the GUID */
    Part = Pos + 39 - 4;
    if (4 + Part + 1 > DeviceKeyChars)
        return PARSE_SHORT_DEVICE;
    wcscpy(DeviceKeyName, L"##?#");
    memcpy(DeviceKeyName + 4, &Link[4], Part * sizeof(WCHAR));
    DeviceKeyName[4 + Part] = UNICODE_NULL;

    *EmptyReference = (Link[Pos + 39] == L'\\' && Link[Pos + 40] == UNICODE_NULL);
    if (Link[Pos + 39] == L'\\' && Link[Pos + 40] != UNICODE_NULL)
    {
        if (wcslen(&Link[Pos + 40]) + 2 > InstanceKeyChars)
            return PARSE_SHORT_DEVICE;
        wcscpy(InstanceKeyName, L"#");
        wcscat(InstanceKeyName, &Link[Pos + 40]);
    }
    else
    {
        wcscpy(InstanceKeyName, L"#");
    }
    return PARSE_OK;
}

/* Opens Control\DeviceClasses\{class}\<device>\<instance>; Error is ERROR_NO_SUCH_DEVICE_INTERFACE if one is missing */
static DWORD
DpOpenInterfaceKeys(
    PCWSTR Link,
    REGSAM Access,
    PDWORD Parse,
    PBOOL EmptyReference,
    HKEY *DeviceKey,
    HKEY *InstanceKey)
{
    WCHAR DeviceName[MAX_PATH], InstanceName[MAX_PATH], ClassPath[3 * MAX_PATH];
    HKEY hDevice, hInstance;
    GUID Class;
    WCHAR GuidString[MAX_GUID_STRING_LEN];
    LONG Error;

    *Parse = DpParseInterface(Link, &Class, DeviceName, ARRAYSIZE(DeviceName), InstanceName, ARRAYSIZE(InstanceName),
                              EmptyReference);
    if (*Parse != PARSE_OK)
        return ERROR_INVALID_DATA;

    pSetupStringFromGuid(&Class, GuidString, ARRAYSIZE(GuidString));
    wcscpy(ClassPath, DpDeviceClasses);
    wcscat(ClassPath, L"\\");
    wcscat(ClassPath, GuidString);
    wcscat(ClassPath, L"\\");
    wcscat(ClassPath, DeviceName);

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ClassPath, 0, Access, &hDevice);
    if (Error != ERROR_SUCCESS)
        return ERROR_NO_SUCH_DEVICE_INTERFACE;

    Error = RegOpenKeyExW(hDevice, InstanceName, 0, Access, &hInstance);
    if (Error != ERROR_SUCCESS)
    {
        RegCloseKey(hDevice);
        return ERROR_NO_SUCH_DEVICE_INTERFACE;
    }
    *DeviceKey = hDevice;
    *InstanceKey = hInstance;
    return ERROR_SUCCESS;
}

/* The property of an interface: Enabled, ClassGuid, and the instance ID of the device */
static DWORD
DpGetInterfaceValue(
    PCWSTR Link,
    HKEY hDevice,
    HKEY hInstance,
    const DEVPROPKEY *PropertyKey,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize)
{
    DWORD RegType, Size, Linked, Chars, Length, Error;
    DEVPROP_BOOLEAN Enabled = DEVPROP_FALSE;
    WCHAR DeviceName[MAX_PATH], InstanceName[MAX_PATH];
    BOOL Empty;
    GUID Class;
    HKEY hControl;
    PBYTE Data;
    PWCHAR Text;

    if (DpSameKey(PropertyKey, &FmtidInterface, 3))
    {
        if (RegOpenKeyExW(hInstance, L"Control", 0, KEY_QUERY_VALUE, &hControl) == ERROR_SUCCESS)
        {
            Size = sizeof(Linked);
            if (RegQueryValueExW(hControl, L"Linked", NULL, &RegType, (PBYTE)&Linked, &Size) == ERROR_SUCCESS &&
                RegType == REG_DWORD && Linked)
            {
                Enabled = DEVPROP_TRUE;
            }
            RegCloseKey(hControl);
        }
        return DpReturn(DEVPROP_TYPE_BOOLEAN, &Enabled, sizeof(Enabled), PropertyType, PropertyBuffer, PropertyBufferSize,
                        RequiredSize);
    }
    if (DpSameKey(PropertyKey, &FmtidInterface, 4))
    {
        if (DpParseInterface(Link, &Class, DeviceName, ARRAYSIZE(DeviceName), InstanceName, ARRAYSIZE(InstanceName),
                             &Empty) != PARSE_OK)
            return ERROR_NOT_FOUND;
        return DpReturn(DEVPROP_TYPE_GUID, &Class, sizeof(Class), PropertyType, PropertyBuffer, PropertyBufferSize,
                        RequiredSize);
    }
    if (DpSameKey(PropertyKey, &FmtidInstanceId, 256))
    {
        Error = DpReadValue(hDevice, L"DeviceInstance", &RegType, &Data, &Size);
        if (Error != ERROR_SUCCESS)
            return Error;
        if (RegType != REG_SZ)
        {
            HeapFree(GetProcessHeap(), 0, Data);
            return ERROR_NOT_FOUND;
        }
        Text = (PWCHAR)Data;
        Chars = (Size + sizeof(WCHAR) - 1) / sizeof(WCHAR);
        for (Length = 0; Length < Chars && Text[Length]; Length++)
            ;
        Text[Length] = UNICODE_NULL;
        Error = DpReturn(DEVPROP_TYPE_STRING, Text, (Length + 1) * sizeof(WCHAR), PropertyType, PropertyBuffer,
                         PropertyBufferSize, RequiredSize);
        HeapFree(GetProcessHeap(), 0, Data);
        return Error;
    }
    return ERROR_NOT_FOUND;
}

/*
 * The property of the device interface of a symbolic link. A name that is no interface of a device is
 * ERROR_NO_SUCH_DEVICE_INTERFACE; one that cannot be an interface name ERROR_INVALID_DATA.
 */
DWORD
SETUP_GetInterfaceProperty(
    PCWSTR Link,
    const DEVPROPKEY *PropertyKey,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize)
{
    HKEY hDevice = NULL, hInstance = NULL;
    DWORD Error, Parse;
    BOOL Empty;

    Error = DpOpenInterfaceKeys(Link, KEY_QUERY_VALUE, &Parse, &Empty, &hDevice, &hInstance);
    if (Error != ERROR_SUCCESS)
    {
        /* Only a name with a bad prefix is invalid here, every other name that is no interface is not one */
        return Parse == PARSE_BAD_PREFIX ? ERROR_INVALID_DATA : ERROR_NO_SUCH_DEVICE_INTERFACE;
    }
    /* A name that ends in a backslash is no interface of this call */
    if (Empty)
        Error = ERROR_NO_SUCH_DEVICE_INTERFACE;
    else
        Error = DpGetInterfaceValue(Link, hDevice, hInstance, PropertyKey, PropertyType, PropertyBuffer,
                                    PropertyBufferSize, RequiredSize);
    RegCloseKey(hInstance);
    RegCloseKey(hDevice);
    return Error;
}

DWORD
SETUP_GetInterfacePropertyKeys(
    PCWSTR Link,
    DEVPROPKEY *KeyArray,
    DWORD KeyCount,
    PDWORD RequiredCount)
{
    static const struct { const GUID *Fmtid; ULONG Pid; } Candidates[] =
    {
        { &FmtidInterface, 3 },     /* DeviceInterface_Enabled */
        { &FmtidInstanceId, 256 },  /* Device_InstanceId */
        { &FmtidInterface, 4 },     /* DeviceInterface_ClassGuid */
    };
    HKEY hDevice = NULL, hInstance = NULL;
    DEVPROPKEY Key;
    DEVPROPTYPE Type;
    DWORD Error, Parse, Found = 0;
    BOOL Empty;
    ULONG i;

    Error = DpOpenInterfaceKeys(Link, KEY_QUERY_VALUE, &Parse, &Empty, &hDevice, &hInstance);
    if (Error != ERROR_SUCCESS)
        return Error;

    for (i = 0; i < ARRAYSIZE(Candidates); i++)
    {
        Key.fmtid = *Candidates[i].Fmtid;
        Key.pid = Candidates[i].Pid;
        Error = DpGetInterfaceValue(Link, hDevice, hInstance, &Key, &Type, NULL, 0, NULL);
        if (Error != ERROR_SUCCESS && Error != ERROR_INSUFFICIENT_BUFFER)
            continue;
        if (Found < KeyCount)
            KeyArray[Found] = Key;
        Found++;
    }
    RegCloseKey(hInstance);
    RegCloseKey(hDevice);

    *RequiredCount = Found;
    return Found > KeyCount ? ERROR_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
}

/*
 * The "Device Parameters" key of an interface. Disposition 0 creates it if it is missing (the interface must exist),
 * 1 opens an existing one; ERROR_KEY_DOES_NOT_EXIST says it is not there.
 */
DWORD
SETUP_OpenInterfaceParameters(
    PCWSTR Link,
    REGSAM Access,
    BOOL OpenExisting,
    HKEY *Key)
{
    HKEY hDevice = NULL, hInstance = NULL;
    DWORD Error, Parse;
    BOOL Empty;
    LONG Result;

    *Key = NULL;
    Error = DpOpenInterfaceKeys(Link, OpenExisting ? KEY_QUERY_VALUE : (KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY), &Parse, &Empty,
                                &hDevice, &hInstance);
    if (Error != ERROR_SUCCESS)
    {
        /* The classes that have no key at all, as for an interface that exists but has none of these keys */
        return (Parse == PARSE_OK && OpenExisting) ? ERROR_KEY_DOES_NOT_EXIST : Error;
    }
    RegCloseKey(hDevice);

    if (OpenExisting)
        Result = RegOpenKeyExW(hInstance, DpDeviceParameters, 0, Access, Key);
    else
        Result = RegCreateKeyExW(hInstance, DpDeviceParameters, 0, NULL, REG_OPTION_NON_VOLATILE, Access, NULL, Key, NULL);
    RegCloseKey(hInstance);

    if (Result == ERROR_SUCCESS)
        return ERROR_SUCCESS;
    if (Result == ERROR_FILE_NOT_FOUND)
        return ERROR_KEY_DOES_NOT_EXIST;
    return Result;
}

DWORD
SETUP_DeleteInterfaceParameters(PCWSTR Link)
{
    HKEY hDevice = NULL, hInstance = NULL;
    DWORD Error, Parse;
    BOOL Empty;
    LONG Result;

    Error = DpOpenInterfaceKeys(Link, KEY_QUERY_VALUE | KEY_WRITE, &Parse, &Empty, &hDevice, &hInstance);
    if (Error != ERROR_SUCCESS)
    {
        if (Parse == PARSE_OK)
        {
            /* The device key may exist when the instance cannot be opened for writing */
            return ERROR_NO_SUCH_DEVICE_INTERFACE;
        }
        return Error;
    }
    RegCloseKey(hDevice);

    Result = RegDeleteTreeW(hInstance, DpDeviceParameters);
    RegCloseKey(hInstance);
    if (Result == ERROR_SUCCESS)
        return ERROR_SUCCESS;
    if (Result == ERROR_FILE_NOT_FOUND)
        return ERROR_KEY_DOES_NOT_EXIST;
    return Result;
}

/***********************************************************************
 *		SetupDiGetClassPropertyExW (SETUPAPI.@)
 *
 * Flags is DICLASSPROP_INSTALLER (1) or DICLASSPROP_INTERFACE (2).
 */
BOOL WINAPI
SetupDiGetClassPropertyExW(
    CONST GUID *ClassGuid,
    CONST DEVPROPKEY *PropertyKey,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize,
    DWORD Flags,
    PCWSTR MachineName,
    PVOID Reserved)
{
    DWORD Error;

    TRACE("%s(%p %p %p %p %lu %p %lx %s %p)\n", __FUNCTION__, ClassGuid, PropertyKey, PropertyType, PropertyBuffer,
          PropertyBufferSize, RequiredSize, Flags, debugstr_w(MachineName), Reserved);

    if (!ClassGuid || !PropertyKey)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    if (!PropertyType || (!PropertyBuffer && PropertyBufferSize) || Reserved)
    {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return FALSE;
    }
    if (Flags != DICLASSPROP_INSTALLER && Flags != DICLASSPROP_INTERFACE)
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return FALSE;
    }

    *PropertyType = DEVPROP_TYPE_EMPTY;
    Error = SETUP_GetClassProperty(ClassGuid, Flags == DICLASSPROP_INSTALLER ? DIOCR_INSTALLER : DIOCR_INTERFACE,
                                   MachineName, PropertyKey, PropertyType, PropertyBuffer, PropertyBufferSize,
                                   RequiredSize);
    SetLastError(Error);
    return Error == ERROR_SUCCESS;
}

/***********************************************************************
 *		SetupDiGetClassPropertyW (SETUPAPI.@)
 */
BOOL WINAPI
SetupDiGetClassPropertyW(
    CONST GUID *ClassGuid,
    CONST DEVPROPKEY *PropertyKey,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize,
    DWORD Flags)
{
    return SetupDiGetClassPropertyExW(ClassGuid, PropertyKey, PropertyType, PropertyBuffer, PropertyBufferSize,
                                      RequiredSize, Flags, NULL, NULL);
}

/***********************************************************************
 *		SetupDiGetClassPropertyKeysExW (SETUPAPI.@)
 */
BOOL WINAPI
SetupDiGetClassPropertyKeysExW(
    CONST GUID *ClassGuid,
    DEVPROPKEY *PropertyKeyArray,
    DWORD PropertyKeyCount,
    PDWORD RequiredPropertyKeyCount,
    DWORD Flags,
    PCWSTR MachineName,
    PVOID Reserved)
{
    DWORD Required = 0, Error;

    TRACE("%s(%p %p %lu %p %lx %s %p)\n", __FUNCTION__, ClassGuid, PropertyKeyArray, PropertyKeyCount,
          RequiredPropertyKeyCount, Flags, debugstr_w(MachineName), Reserved);

    if (!ClassGuid)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    if ((!PropertyKeyArray && PropertyKeyCount) || Reserved)
    {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return FALSE;
    }
    if (Flags != DICLASSPROP_INSTALLER && Flags != DICLASSPROP_INTERFACE)
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return FALSE;
    }

    Error = SETUP_GetClassPropertyKeys(ClassGuid, Flags == DICLASSPROP_INSTALLER ? DIOCR_INSTALLER : DIOCR_INTERFACE,
                                       MachineName, PropertyKeyArray, PropertyKeyCount, &Required);
    if (RequiredPropertyKeyCount && (Error == ERROR_SUCCESS || Error == ERROR_INSUFFICIENT_BUFFER))
        *RequiredPropertyKeyCount = Required;
    SetLastError(Error);
    return Error == ERROR_SUCCESS;
}

/***********************************************************************
 *		SetupDiGetClassPropertyKeys (SETUPAPI.@)
 */
BOOL WINAPI
SetupDiGetClassPropertyKeys(
    CONST GUID *ClassGuid,
    DEVPROPKEY *PropertyKeyArray,
    DWORD PropertyKeyCount,
    PDWORD RequiredPropertyKeyCount,
    DWORD Flags)
{
    return SetupDiGetClassPropertyKeysExW(ClassGuid, PropertyKeyArray, PropertyKeyCount, RequiredPropertyKeyCount,
                                          Flags, NULL, NULL);
}

static PCWSTR
DpInterfaceLink(HDEVINFO DeviceInfoSet, PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData)
{
    struct DeviceInfoSet *Set = (struct DeviceInfoSet *)DeviceInfoSet;
    struct DeviceInterface *Itf;

    if (!DeviceInfoSet || DeviceInfoSet == INVALID_HANDLE_VALUE || Set->magic != SETUP_DEVICE_INFO_SET_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    if (!DeviceInterfaceData || DeviceInterfaceData->cbSize != sizeof(SP_DEVICE_INTERFACE_DATA) ||
        !DeviceInterfaceData->Reserved)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    Itf = (struct DeviceInterface *)DeviceInterfaceData->Reserved;
    return Itf->SymbolicLink;
}

/***********************************************************************
 *		SetupDiGetDeviceInterfacePropertyW (SETUPAPI.@)
 */
BOOL WINAPI
SetupDiGetDeviceInterfacePropertyW(
    HDEVINFO DeviceInfoSet,
    PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
    CONST DEVPROPKEY *PropertyKey,
    DEVPROPTYPE *PropertyType,
    PBYTE PropertyBuffer,
    DWORD PropertyBufferSize,
    PDWORD RequiredSize,
    DWORD Flags)
{
    PCWSTR Link;
    DWORD Error;

    TRACE("%s(%p %p %p %p %p %lu %p %lx)\n", __FUNCTION__, DeviceInfoSet, DeviceInterfaceData, PropertyKey,
          PropertyType, PropertyBuffer, PropertyBufferSize, RequiredSize, Flags);

    Link = DpInterfaceLink(DeviceInfoSet, DeviceInterfaceData);
    if (!Link)
        return FALSE;
    if (Flags)
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return FALSE;
    }
    if (!PropertyType || (!PropertyBuffer && PropertyBufferSize))
    {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return FALSE;
    }
    if (!PropertyKey)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    *PropertyType = DEVPROP_TYPE_EMPTY;
    Error = SETUP_GetInterfaceProperty(Link, PropertyKey, PropertyType, PropertyBuffer, PropertyBufferSize,
                                       RequiredSize);
    SetLastError(Error);
    return Error == ERROR_SUCCESS;
}

/***********************************************************************
 *		SetupDiGetDeviceInterfacePropertyKeys (SETUPAPI.@)
 */
BOOL WINAPI
SetupDiGetDeviceInterfacePropertyKeys(
    HDEVINFO DeviceInfoSet,
    PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
    DEVPROPKEY *PropertyKeyArray,
    DWORD PropertyKeyCount,
    PDWORD RequiredPropertyKeyCount,
    DWORD Flags)
{
    PCWSTR Link;
    DWORD Required = 0, Error;

    TRACE("%s(%p %p %p %lu %p %lx)\n", __FUNCTION__, DeviceInfoSet, DeviceInterfaceData, PropertyKeyArray,
          PropertyKeyCount, RequiredPropertyKeyCount, Flags);

    Link = DpInterfaceLink(DeviceInfoSet, DeviceInterfaceData);
    if (!Link)
        return FALSE;
    if (Flags)
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return FALSE;
    }
    if (!PropertyKeyArray && PropertyKeyCount)
    {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return FALSE;
    }

    Error = SETUP_GetInterfacePropertyKeys(Link, PropertyKeyArray, PropertyKeyCount, &Required);
    if (RequiredPropertyKeyCount && (Error == ERROR_SUCCESS || Error == ERROR_INSUFFICIENT_BUFFER))
        *RequiredPropertyKeyCount = Required;
    SetLastError(Error);
    return Error == ERROR_SUCCESS;
}
