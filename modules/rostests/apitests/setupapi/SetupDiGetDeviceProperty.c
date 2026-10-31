/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for SetupDiGetDevicePropertyW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The types and the errors were measured on Windows Server 2008 R2 (x86 and x64). Windows 10 differs in them, so the
 * test is skipped there.
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
#include <shlwapi.h>
#include <devpropdef.h>
#include <devpkey.h>

typedef BOOL (WINAPI *FN_SetupDiGetDevicePropertyW)(HDEVINFO, PSP_DEVINFO_DATA, const DEVPROPKEY *, DEVPROPTYPE *,
                                                    PBYTE, DWORD, PDWORD, DWORD);
typedef CONFIGRET (WINAPI *FN_CM_Get_DevNode_Status)(PULONG, PULONG, DEVINST, ULONG);
typedef CONFIGRET (WINAPI *FN_CM_Get_Parent)(PDEVINST, DEVINST, ULONG);
typedef CONFIGRET (WINAPI *FN_CM_Get_Device_IDW)(DEVINST, PWSTR, ULONG, ULONG);
typedef CONFIGRET (WINAPI *FN_CM_Get_DevNode_Registry_PropertyW)(DEVINST, ULONG, PULONG, PVOID, PULONG, ULONG);

static FN_SetupDiGetDevicePropertyW pSetupDiGetDevicePropertyW;
static FN_CM_Get_DevNode_Status pCM_Get_DevNode_Status;
static FN_CM_Get_Parent pCM_Get_Parent;
static FN_CM_Get_Device_IDW pCM_Get_Device_IDW;
static FN_CM_Get_DevNode_Registry_PropertyW pCM_Get_DevNode_Registry_PropertyW;

#define NOT_SET 0xDEADBEEF

/* The configuration flags that decide the installation state of ReactOS */
#define TEST_CONFIGFLAG_REINSTALL       0x00000020
#define TEST_CONFIGFLAG_FAILEDINSTALL   0x00000040
#define TEST_CONFIGFLAG_FINISH_INSTALL  0x00000400

/* The type of each SPDRP_* property as a device property, indexed by SPDRP_*; 0 for the unused slots */
static const USHORT ExpectedTypes[] =
{
    DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING_LIST, DEVPROP_TYPE_STRING_LIST, 0, DEVPROP_TYPE_STRING, 0, 0,
    DEVPROP_TYPE_STRING, DEVPROP_TYPE_GUID, DEVPROP_TYPE_STRING, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_STRING,
    DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_UINT32,
    DEVPROP_TYPE_STRING_LIST, DEVPROP_TYPE_STRING_LIST, DEVPROP_TYPE_GUID, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_UINT32,
    DEVPROP_TYPE_STRING, DEVPROP_TYPE_SECURITY_DESCRIPTOR, DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING,
    DEVPROP_TYPE_UINT32, DEVPROP_TYPE_BOOLEAN, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_STRING,
    DEVPROP_TYPE_BINARY, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_UINT32, DEVPROP_TYPE_UINT32,
};

/* The slots the registry-property call has (SPDRP_MAXIMUM_PROPERTY of the older SDKs) */
#define SPDRP_TESTED ARRAYSIZE(ExpectedTypes)

static DEVPROPKEY SpdrpKey(DWORD Property)
{
    DEVPROPKEY Key = DEVPKEY_Device_DeviceDesc;

    Key.pid = Property + 2;
    return Key;
}

static BOOL ReadDeviceProperty(HDEVINFO Set, SP_DEVINFO_DATA *Device, const DEVPROPKEY *Key, DEVPROPTYPE *Type,
                               BYTE **Data, DWORD *Size, DWORD *Error);

/* ------------------------------------------------------------------------------------------------------------- */

#define CALL(handle, data, key, type, buf, size, req, flags) \
    do { \
        Type = NOT_SET; Required = NOT_SET; SetLastError(0xDEADBEEF); \
        Ret = pSetupDiGetDevicePropertyW(handle, data, key, type, buf, size, req, flags); \
    } while (0)

#define EXPECT_FAIL(label, error) \
    do { \
        ok(!Ret, "%s: succeeded\n", label); \
        ok(GetLastError() == (error), "%s: error 0x%lx, expected 0x%lx\n", label, GetLastError(), (DWORD)(error)); \
    } while (0)

static void TestArguments(HDEVINFO Set, SP_DEVINFO_DATA *Device)
{
    static const DWORD BadIds[] = { 0, 1, 5, 7, 8, 39, 40, 60, 1000 };
    DEVPROPKEY Key = DEVPKEY_Device_DeviceDesc;
    DEVPROPKEY Unknown = { { 0x12345678, 0x1234, 0x1234, { 1, 2, 3, 4, 5, 6, 7, 8 } }, 3 };
    SP_DEVINFO_DATA BadSize = *Device, NoReserved = *Device, Gone;
    HDEVINFO Other;
    DEVPROPTYPE Type;
    BYTE Buffer[4096];
    DWORD Required;
    BOOL Ret;
    unsigned i;

    BadSize.cbSize = 4;
    NoReserved.Reserved = 0;

    CALL(Set, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
    ok(Ret, "The baseline call failed: 0x%lx\n", GetLastError());

    /* The checks run in this order: set, device, flags, type and buffer, key */
    CALL(NULL, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("NULL set", ERROR_INVALID_HANDLE);
    CALL(INVALID_HANDLE_VALUE, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("invalid set", ERROR_INVALID_HANDLE);
    CALL(NULL, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("NULL set, flags", ERROR_INVALID_HANDLE);

    CALL(Set, NULL, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("NULL device", ERROR_INVALID_PARAMETER);
    CALL(Set, &BadSize, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("bad size", ERROR_INVALID_PARAMETER);
    CALL(Set, &NoReserved, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("no reserved", ERROR_INVALID_PARAMETER);
    CALL(Set, &BadSize, &Key, &Type, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("bad size, flags", ERROR_INVALID_PARAMETER);
    CALL(Set, NULL, &Key, &Type, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("NULL device, flags", ERROR_INVALID_PARAMETER);

    CALL(Set, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("flags 1", ERROR_INVALID_FLAGS);
    CALL(Set, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0x80000000);
    EXPECT_FAIL("flags 0x80000000", ERROR_INVALID_FLAGS);
    CALL(Set, Device, NULL, &Type, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("NULL key, flags", ERROR_INVALID_FLAGS);
    CALL(Set, Device, &Key, NULL, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("NULL type, flags", ERROR_INVALID_FLAGS);
    CALL(Set, Device, &Unknown, &Type, Buffer, sizeof(Buffer), &Required, 1);
    EXPECT_FAIL("unknown key, flags", ERROR_INVALID_FLAGS);
    ok(Type == NOT_SET && Required == NOT_SET, "Outputs written: type 0x%lx, size %lu\n", Type, Required);

    CALL(Set, Device, &Key, NULL, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("NULL type", ERROR_INVALID_USER_BUFFER);
    CALL(Set, Device, &Key, &Type, NULL, 5, &Required, 0);
    EXPECT_FAIL("NULL buffer with a size", ERROR_INVALID_USER_BUFFER);
    CALL(Set, Device, NULL, NULL, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("NULL key and type", ERROR_INVALID_USER_BUFFER);
    CALL(Set, Device, &Unknown, NULL, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("unknown key, NULL type", ERROR_INVALID_USER_BUFFER);

    CALL(Set, Device, NULL, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("NULL key", ERROR_INVALID_DATA);

    /* A key nothing knows: not found, the type is "empty" and the size stays */
    CALL(Set, Device, &Unknown, &Type, Buffer, sizeof(Buffer), &Required, 0);
    EXPECT_FAIL("unknown key", ERROR_NOT_FOUND);
    ok(Type == DEVPROP_TYPE_EMPTY, "Unknown key: type 0x%lx\n", Type);
    ok(Required == NOT_SET, "Unknown key: required size %lu\n", Required);

    /* The device family has no property 0, 1, the unused slots, or any beyond the last one */
    for (i = 0; i < ARRAYSIZE(BadIds); i++)
    {
        Key.pid = BadIds[i];
        CALL(Set, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
        EXPECT_FAIL("bad property id", ERROR_INVALID_REG_PROPERTY);
        ok(Type == DEVPROP_TYPE_EMPTY, "Property id %lu: type 0x%lx\n", BadIds[i], Type);
        ok(Required == NOT_SET, "Property id %lu: required size %lu\n", BadIds[i], Required);
    }

    /* A device of another set, and a device that was deleted from its set, are not devices of this set */
    Other = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    ok(Other != INVALID_HANDLE_VALUE, "SetupDiGetClassDevsW failed: 0x%lx\n", GetLastError());
    if (Other != INVALID_HANDLE_VALUE)
    {
        Key = DEVPKEY_Device_InstanceId;
        CALL(Other, Device, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
        EXPECT_FAIL("device of another set", ERROR_INVALID_PARAMETER);

        Gone.cbSize = sizeof(Gone);
        if (SetupDiEnumDeviceInfo(Other, 0, &Gone) && SetupDiDeleteDeviceInfo(Other, &Gone))
        {
            CALL(Other, &Gone, &Key, &Type, Buffer, sizeof(Buffer), &Required, 0);
            EXPECT_FAIL("deleted device", ERROR_INVALID_PARAMETER);
        }
        else
        {
            skip("No device to delete: 0x%lx\n", GetLastError());
        }
        SetupDiDestroyDeviceInfoList(Other);
    }
}

/* ------------------------------------------------------------------------------------------------------------- */

static BOOL ParseGuid(const WCHAR *String, GUID *Guid)
{
    unsigned Part[11];
    int i;

    if (swscanf(String, L"{%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}", &Part[0], &Part[1], &Part[2], &Part[3], &Part[4],
                &Part[5], &Part[6], &Part[7], &Part[8], &Part[9], &Part[10]) != 11)
        return FALSE;
    Guid->Data1 = Part[0];
    Guid->Data2 = (USHORT)Part[1];
    Guid->Data3 = (USHORT)Part[2];
    for (i = 0; i < 8; i++)
        Guid->Data4[i] = (BYTE)Part[3 + i];
    return TRUE;
}

/* A registry property in a heap block that grows until the value fits; FALSE if the device does not have it */
static BOOL ReadRegistryProperty(HDEVINFO Set, SP_DEVINFO_DATA *Device, DWORD Property, DWORD *RegType, BYTE **Data,
                                 DWORD *Size)
{
    DWORD Capacity = 256;
    int Round;

    for (Round = 0; Round < 8; Round++)
    {
        *Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Capacity + sizeof(WCHAR));
        *Size = 0;
        if (SetupDiGetDeviceRegistryPropertyW(Set, Device, Property, RegType, *Data, Capacity, Size))
            return TRUE;
        HeapFree(GetProcessHeap(), 0, *Data);
        *Data = NULL;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        Capacity = max(*Size, Capacity * 2);
    }
    return FALSE;
}

/* A device property in a heap block that grows until the value fits; on failure *Error is the error */
static BOOL ReadDeviceProperty(HDEVINFO Set, SP_DEVINFO_DATA *Device, const DEVPROPKEY *Key, DEVPROPTYPE *Type,
                               BYTE **Data, DWORD *Size, DWORD *Error)
{
    DWORD Capacity = 256;
    int Round;

    for (Round = 0; Round < 8; Round++)
    {
        /* Filled with a pattern, then two zero bytes after it: a value that is not terminated shows */
        *Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Capacity + sizeof(WCHAR));
        memset(*Data, 0xCC, Capacity);
        *Type = NOT_SET;
        *Size = NOT_SET;
        SetLastError(0xDEADBEEF);
        if (pSetupDiGetDevicePropertyW(Set, Device, Key, Type, *Data, Capacity, Size, 0))
        {
            *Error = ERROR_SUCCESS;
            return TRUE;
        }
        *Error = GetLastError();
        HeapFree(GetProcessHeap(), 0, *Data);
        *Data = NULL;
        if (*Error != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        Capacity = max(*Size, Capacity * 2);
    }
    return FALSE;
}

/* The size protocol of a property that exists: a short buffer gives the type and the size, the exact size works */
static void CheckBufferProtocol(HDEVINFO Set, SP_DEVINFO_DATA *Device, const DEVPROPKEY *Key, DEVPROPTYPE ExpectedType,
                                DWORD Size, PCWSTR Label)
{
    DEVPROPTYPE Type;
    BYTE *Buffer;
    DWORD Required, i;
    BOOL Ret;

    /* Windows Server 2008 R2 answers a size query for an empty string with the list type and 4 bytes */
    if (Size <= sizeof(WCHAR) && (ExpectedType == DEVPROP_TYPE_STRING || ExpectedType == DEVPROP_TYPE_STRING_LIST) &&
        !is_reactos())
        return;

    Buffer = HeapAlloc(GetProcessHeap(), 0, Size + 8);
    ok(Buffer != NULL, "No memory\n");
    if (!Buffer)
        return;
    memset(Buffer, 0xCC, Size + 8);

    Type = NOT_SET; Required = NOT_SET; SetLastError(0xDEADBEEF);
    Ret = pSetupDiGetDevicePropertyW(Set, Device, Key, &Type, NULL, 0, &Required, 0);
    ok(!Ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER && Type == ExpectedType && Required == Size,
       "%S, property %lu, size query: %d, error 0x%lx, type 0x%lx, size %lu, expected %lu\n",
       Label, Key->pid, Ret, GetLastError(), Type, Required, Size);

    Type = NOT_SET; SetLastError(0xDEADBEEF);
    Ret = pSetupDiGetDevicePropertyW(Set, Device, Key, &Type, NULL, 0, NULL, 0);
    ok(!Ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER && Type == ExpectedType,
       "%S, property %lu, size query without a size pointer: %d, error 0x%lx, type 0x%lx\n",
       Label, Key->pid, Ret, GetLastError(), Type);

    if (Size > 1)
    {
        Type = NOT_SET; Required = NOT_SET; SetLastError(0xDEADBEEF);
        Ret = pSetupDiGetDevicePropertyW(Set, Device, Key, &Type, Buffer, Size - 1, &Required, 0);
        ok(!Ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER && Type == ExpectedType && Required == Size,
           "%S, property %lu, one byte short: %d, error 0x%lx, type 0x%lx, size %lu\n",
           Label, Key->pid, Ret, GetLastError(), Type, Required);
    }

    Type = NOT_SET; Required = NOT_SET; SetLastError(0xDEADBEEF);
    Ret = pSetupDiGetDevicePropertyW(Set, Device, Key, &Type, Buffer, Size, &Required, 0);
    ok(Ret && Type == ExpectedType && Required == Size, "%S, property %lu, exact size: %d, error 0x%lx, type 0x%lx, size %lu\n",
       Label, Key->pid, Ret, GetLastError(), Type, Required);
    for (i = Size; i < Size + 8; i++)
    {
        if (Buffer[i] != 0xCC)
        {
            ok(0, "%S, property %lu: the byte after the buffer was written (offset %lu)\n", Label, Key->pid, i);
            break;
        }
    }

    Type = NOT_SET; SetLastError(0xDEADBEEF);
    Ret = pSetupDiGetDevicePropertyW(Set, Device, Key, &Type, Buffer, Size, NULL, 0);
    ok(Ret && Type == ExpectedType, "%S, property %lu, exact size without a size pointer: %d, error 0x%lx\n",
       Label, Key->pid, Ret, GetLastError());

    HeapFree(GetProcessHeap(), 0, Buffer);
}

/* What a string or list value of the registry-property call must look like as a device property */
static void CheckValueAgainstRegistry(const WCHAR *Label, DWORD Property, DEVPROPTYPE Type, const BYTE *Value, DWORD Size,
                                      DWORD RegType, const BYTE *Legacy, DWORD LegacySize)
{
    if (Type == DEVPROP_TYPE_GUID)
    {
        GUID Guid;

        ok(Size == sizeof(GUID), "%S, property %lu: GUID size %lu\n", Label, Property, Size);
        if (Property == SPDRP_CLASSGUID)
            ok(ParseGuid((const WCHAR *)Legacy, &Guid) && !memcmp(&Guid, Value, sizeof(GUID)), "%S: class GUID differs\n", Label);
        else
            ok(LegacySize == sizeof(GUID) && !memcmp(Value, Legacy, sizeof(GUID)), "%S, property %lu: GUID differs\n", Label, Property);
    }
    else if (Type == DEVPROP_TYPE_STRING)
    {
        /* One terminator, also when the registry value has more */
        ok(Size == (wcslen((const WCHAR *)Value) + 1) * sizeof(WCHAR), "%S, property %lu: size %lu, string '%S'\n",
           Label, Property, Size, (const WCHAR *)Value);
        ok(Size <= LegacySize || Size == sizeof(WCHAR), "%S, property %lu: size %lu, the registry value has %lu\n", Label, Property, Size, LegacySize);
        ok(!wcscmp((const WCHAR *)Value, (const WCHAR *)Legacy), "%S, property %lu: '%S', expected '%S'\n",
           Label, Property, (const WCHAR *)Value, (const WCHAR *)Legacy);
    }
    else if (Type == DEVPROP_TYPE_STRING_LIST)
    {
        /* The list ends with one empty string, also when the registry value has more terminators */
        const WCHAR *List = (const WCHAR *)Value;
        DWORD Position = 0;

        while (Position < Size / sizeof(WCHAR) && List[Position])
            Position += wcslen(&List[Position]) + 1;
        ok(Size == (Position + 1) * sizeof(WCHAR), "%S, property %lu: size %lu, strings end at %lu\n", Label, Property, Size, Position);
        ok(Size <= LegacySize + 2 * sizeof(WCHAR) && !memcmp(Value, Legacy, min(Size - sizeof(WCHAR), LegacySize)),
           "%S, property %lu: the data differs\n", Label, Property);
    }
    else if (Type == DEVPROP_TYPE_BOOLEAN)
    {
        /* A DWORD in the registry; one byte that is 0xFF for any nonzero value as a device property */
        ok(RegType == REG_DWORD && LegacySize == sizeof(DWORD), "%S, property %lu: registry type %lu, size %lu\n",
           Label, Property, RegType, LegacySize);
        ok(Size == 1 && LegacySize == sizeof(DWORD) && Value[0] == (*(DWORD *)Legacy ? 0xFF : 0x00),
           "%S, property %lu: size %lu, value %u\n", Label, Property, Size, Value[0]);
    }
    else if (Type == DEVPROP_TYPE_UINT32)
    {
        /* A four-byte REG_DWORD; ReactOS has a single byte for the default removal policy: a number with zeros above it */
        if (Property == SPDRP_REMOVAL_POLICY_HW_DEFAULT && is_reactos() && LegacySize == 1)
        {
            ok(Size == sizeof(DWORD) && *(DWORD *)Value == Legacy[0], "%S, property %lu: size %lu, value %lu, the byte is %u\n",
               Label, Property, Size, *(DWORD *)Value, Legacy[0]);
        }
        else
        {
            ok(RegType == REG_DWORD && LegacySize == sizeof(DWORD), "%S, property %lu: the registry value has type %lu, %lu bytes\n",
               Label, Property, RegType, LegacySize);
            ok(Size == sizeof(DWORD) && LegacySize == sizeof(DWORD) && !memcmp(Value, Legacy, sizeof(DWORD)),
               "%S, property %lu: size %lu, the data differs\n", Label, Property, Size);
        }
    }
    else
    {
        ok(Size == LegacySize && !memcmp(Value, Legacy, Size), "%S, property %lu: size %lu, expected %lu, or the data differs\n",
           Label, Property, Size, LegacySize);
    }
}

/* The installation state ReactOS makes of the configuration flags; Windows keeps the state apart */
static DWORD ExpectedInstallState(DWORD Flags)
{
    if (Flags & TEST_CONFIGFLAG_FAILEDINSTALL)
        return CM_INSTALL_STATE_FAILED_INSTALL;
    if (Flags & TEST_CONFIGFLAG_REINSTALL)
        return CM_INSTALL_STATE_NEEDS_REINSTALL;
    if (Flags & TEST_CONFIGFLAG_FINISH_INSTALL)
        return CM_INSTALL_STATE_FINISH_INSTALL;
    return CM_INSTALL_STATE_INSTALLED;
}

typedef struct
{
    DWORD PD_Size;
    DWORD PD_MostRecentPowerState;
} POWER_DATA_HEAD;

/* One SPDRP_* property of a device from the system */
static void TestProperty(HDEVINFO Set, SP_DEVINFO_DATA *Device, unsigned Index, DWORD Property,
                         unsigned *Counts)
{
    DEVPROPKEY Key = SpdrpKey(Property);
    DEVPROPTYPE Type;
    BYTE *Value = NULL, *Legacy = NULL;
    DWORD Size, LegacyType = 0, LegacySize = 0, Error;
    BOOL Ret, HaveLegacy;
    WCHAR Label[300];

    wsprintfW(Label, L"Device %u", Index);

    if (!ExpectedTypes[Property])
    {
        BYTE Buffer[64];

        Type = NOT_SET; Size = NOT_SET; SetLastError(0xDEADBEEF);
        Ret = pSetupDiGetDevicePropertyW(Set, Device, &Key, &Type, Buffer, sizeof(Buffer), &Size, 0);
        ok(!Ret && GetLastError() == ERROR_INVALID_REG_PROPERTY && Type == DEVPROP_TYPE_EMPTY && Size == NOT_SET,
           "%S, property %lu: %d, error 0x%lx, type 0x%lx, size 0x%lx\n", Label, Property, Ret, GetLastError(), Type, Size);
        return;
    }

    Ret = ReadDeviceProperty(Set, Device, &Key, &Type, &Value, &Size, &Error);
    HaveLegacy = ReadRegistryProperty(Set, Device, Property, &LegacyType, &Legacy, &LegacySize);

    /* These three have another source than the registry-property call: found exactly when that has it */
    if (Property == SPDRP_PHYSICAL_DEVICE_OBJECT_NAME)
    {
        WCHAR PdoName[260] = L"";
        ULONG Length = sizeof(PdoName);

        HaveLegacy = pCM_Get_DevNode_Registry_PropertyW &&
                     pCM_Get_DevNode_Registry_PropertyW(Device->DevInst, CM_DRP_PHYSICAL_DEVICE_OBJECT_NAME, NULL, PdoName,
                                                        &Length, 0) == CR_SUCCESS && PdoName[0] != UNICODE_NULL;
        ok(Ret == HaveLegacy, "%S: the PDO name %s, the configuration manager %s it (error 0x%lx)\n", Label,
           Ret ? "exists" : "does not", HaveLegacy ? "has" : "does not have", Error);
        if (Ret)
        {
            ok(Type == DEVPROP_TYPE_STRING, "%S: PDO name type 0x%lx\n", Label, Type);
            ok(!_wcsnicmp((WCHAR *)Value, L"\\Device\\", 8), "%S: PDO name '%S'\n", Label, (WCHAR *)Value);
            ok(!wcscmp((WCHAR *)Value, PdoName), "%S: PDO name '%S', expected '%S'\n", Label, (WCHAR *)Value, PdoName);
            CheckBufferProtocol(Set, Device, &Key, Type, Size, Label);
            Counts[1]++;
        }
        else
        {
            ok(Error == ERROR_NOT_FOUND && Type == DEVPROP_TYPE_EMPTY, "%S: PDO name error 0x%lx, type 0x%lx\n", Label, Error, Type);
        }
    }
    else if (Property == SPDRP_DEVICE_POWER_DATA || Property == SPDRP_INSTALL_STATE)
    {
        if (Property == SPDRP_INSTALL_STATE && HaveLegacy && (LegacyType != REG_DWORD || LegacySize != sizeof(DWORD)))
            HaveLegacy = FALSE;
        ok(Ret == HaveLegacy, "%S, property %lu: the device property %s, the registry-property call %s it (error 0x%lx)\n", Label,
           Property, Ret ? "exists" : "does not", HaveLegacy ? "has" : "does not have", Error);
        if (Ret && HaveLegacy)
        {
            ok(Type == ExpectedTypes[Property], "%S, property %lu: type 0x%lx\n", Label, Property, Type);
            if (Property == SPDRP_DEVICE_POWER_DATA)
            {
                POWER_DATA_HEAD Head, LegacyHead;

                ok(Size == 56 && *(DWORD *)Value == 56, "%S: power data of %lu bytes, PD_Size %lu\n", Label, Size, *(DWORD *)Value);
                /* The most recent power state changes by itself; the rest of the 56 bytes does not */
                if (Size == 56 && LegacySize >= 56)
                {
                    memcpy(&Head, Value, sizeof(Head));
                    memcpy(&LegacyHead, Legacy, sizeof(LegacyHead));
                    Head.PD_MostRecentPowerState = LegacyHead.PD_MostRecentPowerState = 0;
                    memcpy(Value, &Head, sizeof(Head));
                    memcpy(Legacy, &LegacyHead, sizeof(LegacyHead));
                    ok(!memcmp(Value, Legacy, 56), "%S: the power data differs\n", Label);
                }
            }
            else
            {
                DWORD Flags = *(DWORD *)Legacy, State = is_reactos() ? ExpectedInstallState(Flags) : Flags;

                ok(Size == sizeof(DWORD) && *(DWORD *)Value == State, "%S: install state %lu bytes, value %lu, expected %lu\n",
                   Label, Size, *(DWORD *)Value, State);
            }
            CheckBufferProtocol(Set, Device, &Key, Type, Size, Label);
            Counts[1]++;
        }
        else if (!Ret)
        {
            ok(Error == ERROR_NOT_FOUND && Type == DEVPROP_TYPE_EMPTY, "%S, property %lu: error 0x%lx, type 0x%lx\n", Label,
               Property, Error, Type);
        }
    }
    else if (!HaveLegacy)
    {
        ok(!Ret, "%S, property %lu: the registry-property call fails but the device property succeeds\n", Label, Property);
        ok(Error == ERROR_NOT_FOUND && Type == DEVPROP_TYPE_EMPTY, "%S, property %lu: error 0x%lx, type 0x%lx\n", Label,
           Property, Error, Type);
    }
    else
    {
        ok(Ret, "%S, property %lu: failed with 0x%lx\n", Label, Property, Error);
        if (Ret)
        {
            ok(Type == ExpectedTypes[Property], "%S, property %lu: type 0x%lx, expected 0x%x\n", Label, Property, Type,
               ExpectedTypes[Property]);
            CheckValueAgainstRegistry(Label, Property, Type, Value, Size, LegacyType, Legacy, LegacySize);
            CheckBufferProtocol(Set, Device, &Key, Type, Size, Label);
            Counts[1]++;
        }
    }

    if (Value)
        HeapFree(GetProcessHeap(), 0, Value);
    if (Legacy)
        HeapFree(GetProcessHeap(), 0, Legacy);
}

/*
 * The status and the problem code against what the configuration manager says before and after the call. A device
 * can change at any time: a mismatch is tried again, and a failure counts only when every try was decisive (the
 * configuration manager knew the device before and after it) and wrong.
 */
static void TestDevNodeValue(HDEVINFO Set, SP_DEVINFO_DATA *Device, unsigned Index, const DEVPROPKEY *Key, BOOL Problem,
                             unsigned *Counts)
{
    DEVPROPTYPE Type;
    BYTE *Value = NULL;
    DWORD Size, Error = 0, Decisive = 0, Wrong = 0, Attempt;
    ULONG Status, ProblemCode, StatusAfter, ProblemAfter;
    BOOL Matched = FALSE, Present = FALSE, Before, After, Ret;
    PCSTR Name = Problem ? "problem code" : "status";
    WCHAR Label[32];

    wsprintfW(Label, L"Device %u", Index);

    for (Attempt = 0; Attempt < 10 && !Matched; Attempt++)
    {
        Before = pCM_Get_DevNode_Status(&Status, &ProblemCode, Device->DevInst, 0) == CR_SUCCESS;
        Ret = ReadDeviceProperty(Set, Device, Key, &Type, &Value, &Size, &Error);
        After = pCM_Get_DevNode_Status(&StatusAfter, &ProblemAfter, Device->DevInst, 0) == CR_SUCCESS;

        if (Ret)
        {
            ok(Type == DEVPROP_TYPE_UINT32 && Size == sizeof(DWORD), "Device %u: %s type 0x%lx, size %lu\n", Index, Name, Type, Size);
            if (!Present && Type == DEVPROP_TYPE_UINT32 && Size == sizeof(DWORD))
                CheckBufferProtocol(Set, Device, Key, DEVPROP_TYPE_UINT32, Size, Label);
            Present = TRUE;
            /* Compared only when the device was in the same state before and after the read */
            if (Before && After && Size == sizeof(DWORD) && StatusAfter == Status && ProblemAfter == ProblemCode)
            {
                Decisive++;
                if (*(DWORD *)Value == (Problem ? ProblemCode : Status))
                    Matched = TRUE;
                else
                    Wrong++;
            }
        }
        else if (Before && After)
        {
            Decisive++;
            Wrong++;
        }
        if (Value)
            HeapFree(GetProcessHeap(), 0, Value);
        Value = NULL;
    }

    if (!Matched && Wrong && Wrong == Decisive && Attempt == Decisive)
        ok(0, "Device %u: %s differs from the configuration manager in all %lu tries (last error 0x%lx)\n", Index, Name, Attempt, Error);
    else if (!Matched)
        trace("Device %u: %s was not steady, not checked\n", Index, Name);
    if (Present)
        Counts[Problem ? 3 : 2]++;
}

/* One device of the system: every property in turn */
static void TestDevice(HDEVINFO Set, SP_DEVINFO_DATA *Device, unsigned Index, unsigned *Counts)
{
    WCHAR InstanceId[256], Other[256], Label[32];
    DEVPROPTYPE Type;
    BYTE *Value, *Legacy = NULL;
    DWORD Size, LegacyType, LegacySize, Property, Error;
    BOOL Ret;
    DEVINST Parent;

    ok(SetupDiGetDeviceInstanceIdW(Set, Device, InstanceId, ARRAYSIZE(InstanceId), NULL), "No instance ID\n");
    wsprintfW(Label, L"Device %u", Index);

    Ret = ReadDeviceProperty(Set, Device, &DEVPKEY_Device_InstanceId, &Type, &Value, &Size, &Error);
    ok(Ret, "Device %u: instance ID failed: 0x%lx\n", Index, Error);
    if (Ret)
    {
        ok(Type == DEVPROP_TYPE_STRING, "Device %u: instance ID type 0x%lx\n", Index, Type);
        ok(Size == (wcslen(InstanceId) + 1) * sizeof(WCHAR), "Device %u: instance ID size %lu\n", Index, Size);
        ok(!wcscmp((WCHAR *)Value, InstanceId), "Device %u: instance ID '%S', expected '%S'\n", Index, (WCHAR *)Value, InstanceId);
        CheckBufferProtocol(Set, Device, &DEVPKEY_Device_InstanceId, DEVPROP_TYPE_STRING, Size, Label);
        Counts[0]++;
        HeapFree(GetProcessHeap(), 0, Value);
    }

    for (Property = 0; Property < SPDRP_TESTED; Property++)
        TestProperty(Set, Device, Index, Property, Counts);

    /* The name is the friendly name, else the description */
    Ret = ReadDeviceProperty(Set, Device, &DEVPKEY_NAME, &Type, &Value, &Size, &Error);
    if (!ReadRegistryProperty(Set, Device, SPDRP_FRIENDLYNAME, &LegacyType, &Legacy, &LegacySize))
        ReadRegistryProperty(Set, Device, SPDRP_DEVICEDESC, &LegacyType, &Legacy, &LegacySize);
    ok(Ret == (Legacy != NULL), "Device %u: name %d (error 0x%lx), registry %d\n", Index, Ret, Error, Legacy != NULL);
    if (Ret && Legacy)
    {
        ok(Type == DEVPROP_TYPE_STRING, "Device %u: name type 0x%lx\n", Index, Type);
        ok(!wcscmp((WCHAR *)Value, (WCHAR *)Legacy), "Device %u: name '%S', expected '%S'\n", Index, (WCHAR *)Value, (WCHAR *)Legacy);
        CheckBufferProtocol(Set, Device, &DEVPKEY_NAME, DEVPROP_TYPE_STRING, Size, Label);
    }
    if (Legacy)
        HeapFree(GetProcessHeap(), 0, Legacy);
    if (Value)
        HeapFree(GetProcessHeap(), 0, Value);

    TestDevNodeValue(Set, Device, Index, &DEVPKEY_Device_DevNodeStatus, FALSE, Counts);
    TestDevNodeValue(Set, Device, Index, &DEVPKEY_Device_ProblemCode, TRUE, Counts);

    /* The parent; a device node without one has no such property */
    Ret = ReadDeviceProperty(Set, Device, &DEVPKEY_Device_Parent, &Type, &Value, &Size, &Error);
    if (pCM_Get_Parent(&Parent, Device->DevInst, 0) == CR_SUCCESS &&
        pCM_Get_Device_IDW(Parent, Other, ARRAYSIZE(Other), 0) == CR_SUCCESS)
    {
        ok(Ret, "Device %u: parent failed: 0x%lx\n", Index, Error);
        if (Ret)
        {
            ok(Type == DEVPROP_TYPE_STRING, "Device %u: parent type 0x%lx\n", Index, Type);
            ok(!_wcsicmp((WCHAR *)Value, Other), "Device %u: parent '%S', expected '%S'\n", Index, (WCHAR *)Value, Other);
            CheckBufferProtocol(Set, Device, &DEVPKEY_Device_Parent, DEVPROP_TYPE_STRING, Size, Label);
            Counts[4]++;
        }
    }
    else
    {
        ok(!Ret && Error == ERROR_NOT_FOUND, "Device %u: a parent, but the device node has none\n", Index);
    }
    if (Value)
        HeapFree(GetProcessHeap(), 0, Value);
}

/* ------------------------------------------------------------------------------------------------------------- */

#define FIXTURE_ENUMERATOR L"ROSTEST_DEVPROP"

static const GUID NullGuid;

static void SetFixtureValue(HKEY Key, PCWSTR Name, DWORD RegType, const void *Data, DWORD Size)
{
    LONG Error = RegSetValueExW(Key, Name, 0, RegType, Data, Size);
    DWORD Stored = 0, StoredType = 0;

    ok(Error == ERROR_SUCCESS, "Writing %S failed: %ld\n", Name, Error);
    /* what was written is what the registry holds, with no terminator of its own added */
    Error = RegQueryValueExW(Key, Name, NULL, &StoredType, NULL, &Stored);
    ok(Error == ERROR_SUCCESS && StoredType == RegType && Stored == Size, "%S: the registry holds type %lu and %lu bytes, %lu were written (%ld)\n",
       Name, StoredType, Stored, Size, Error);
}

/* Reads a property of the fixture device and compares it with the expected type, size and data */
static void ExpectFixtureValue(HDEVINFO Set, SP_DEVINFO_DATA *Device, DWORD Property, PCSTR Label, DEVPROPTYPE Type,
                               const void *Data, DWORD Size)
{
    DEVPROPKEY Key = SpdrpKey(Property);
    DEVPROPTYPE ActualType;
    BYTE *Value;
    DWORD ActualSize, Error;
    BOOL Ret = ReadDeviceProperty(Set, Device, &Key, &ActualType, &Value, &ActualSize, &Error);

    if (!Size)
    {
        ok(!Ret && Error == ERROR_NOT_FOUND && ActualType == DEVPROP_TYPE_EMPTY, "%s: %d, error 0x%lx, type 0x%lx, expected not found\n",
           Label, Ret, Error, ActualType);
        return;
    }

    ok(Ret, "%s: failed with 0x%lx\n", Label, Error);
    if (!Ret)
        return;
    ok(ActualType == Type && ActualSize == Size && !memcmp(Value, Data, Size), "%s: type 0x%lx, size %lu, expected 0x%lx and %lu, or the data differs\n",
       Label, ActualType, ActualSize, Type, Size);
    CheckBufferProtocol(Set, Device, &Key, Type, Size, L"Fixture");
    HeapFree(GetProcessHeap(), 0, Value);
}

/*
 * The test makes its own device (an entry under a private enumerator that it deletes at the end) and writes the values
 * the properties are read from, so each rule of the conversion has a case that no system device holds.
 */
static void TestFixtureDevice(void)
{
    static const struct { DWORD Flags; DWORD State; } States[] =
    {
        { 0x00, 0 }, { 0x20, 1 }, { 0x40, 2 }, { 0x400, 3 }, { 0x60, 2 }, { 0x420, 1 }, { 0x440, 2 }, { 0x460, 2 },
        { 0x01, 0 }, { 0x04, 0 },
    };
    /* A number is a four-byte REG_DWORD; the same bytes under another type, or fewer of them, are not */
    static const struct { DWORD RegType; DWORD Size; BOOL Number; } Raw[] =
    {
        { REG_BINARY, 4, FALSE }, { REG_BINARY, 1, FALSE }, { REG_DWORD, 2, FALSE }, { REG_BINARY, 3, FALSE },
        { REG_DWORD, 4, TRUE },
    };
    static const BYTE Bytes[4] = { 0x20, 0, 0, 0 };
    static const WCHAR Desc[] = L"A device\0\0";
    static const WCHAR DescOne[] = L"A device";
    /* the value after the last supplied byte is not zero, so that the registry does not terminate it */
    static const WCHAR Unended[] = { 'A', 0, 'B', 0x7777 };
    static const WCHAR UnendedOne[] = { 'A', 0x7777 };
    static const WCHAR Extra[] = { 'A', 0, 'B', 0, 0, 0, 'C', 0, 0 };
    static const WCHAR ListEnd[] = { 'A', 0, 'B', 0, 0 };
    static const WCHAR ListSingle[] = { 'A', 0, 0 };
    static const WCHAR Empty[] = { 0 };
    static const BYTE OddBytes[4] = { 'A', 0, 'B', 0x77 };
    static const WCHAR ListOdd[] = { 'A', 'B', 0, 0 };
    static const WCHAR ClassGuid[] = L"{4d36e97d-e325-11ce-bfc1-08002be10318}";
    static const GUID ClassGuidValue = { 0x4d36e97d, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
    static const WCHAR Friendly[] = L"A friendly name";
    WCHAR InstanceId[64], KeyName[160];
    HDEVINFO Set;
    SP_DEVINFO_DATA Device;
    HKEY Key = NULL;
    BYTE *Long;
    DWORD i;
    LONG Error;
    BOOL Ret, Created = FALSE;

    /* Windows does not let an administrator write the keys of a device node (access is denied) */
    if (!is_reactos())
    {
        skip("The fixture device is for ReactOS: Windows keeps the device keys to itself\n");
        return;
    }

    wsprintfW(InstanceId, L"ROOT\\" FIXTURE_ENUMERATOR L"\\%04lX", GetCurrentProcessId() & 0xFFFF);
    wsprintfW(KeyName, L"SYSTEM\\CurrentControlSet\\Enum\\%s", InstanceId);

    Set = SetupDiCreateDeviceInfoList(NULL, NULL);
    ok(Set != INVALID_HANDLE_VALUE, "SetupDiCreateDeviceInfoList failed: 0x%lx\n", GetLastError());
    if (Set == INVALID_HANDLE_VALUE)
        return;

    Device.cbSize = sizeof(Device);
    Ret = SetupDiCreateDeviceInfoW(Set, InstanceId, &NullGuid, NULL, NULL, 0, &Device);
    if (!Ret)
    {
        skip("The fixture device cannot be created: 0x%lx\n", GetLastError());
        goto done;
    }
    Created = TRUE;
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &Key);
    ok(Error == ERROR_SUCCESS, "The fixture device has no registry key: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        goto done;

    /* Installation state of ReactOS: the configuration flags, absent means no state */
    if (is_reactos())
    {
        ExpectFixtureValue(Set, &Device, SPDRP_INSTALL_STATE, "No configuration flags: install state", DEVPROP_TYPE_UINT32, NULL, 0);
        for (i = 0; i < ARRAYSIZE(States); i++)
        {
            DWORD Flags = States[i].Flags;
            char Label[48];

            SetFixtureValue(Key, L"ConfigFlags", REG_DWORD, &Flags, sizeof(Flags));
            sprintf(Label, "Flags 0x%lx: install state", Flags);
            ExpectFixtureValue(Set, &Device, SPDRP_INSTALL_STATE, Label, DEVPROP_TYPE_UINT32, &States[i].State, sizeof(DWORD));
            sprintf(Label, "Flags 0x%lx: configuration flags", Flags);
            ExpectFixtureValue(Set, &Device, SPDRP_CONFIGFLAGS, Label, DEVPROP_TYPE_UINT32, &Flags, sizeof(DWORD));
        }
    }

    for (i = 0; i < ARRAYSIZE(Raw); i++)
    {
        char Label[64];

        SetFixtureValue(Key, L"ConfigFlags", Raw[i].RegType, Bytes, Raw[i].Size);
        sprintf(Label, "ConfigFlags of registry type %lu, %lu bytes", Raw[i].RegType, Raw[i].Size);
        ExpectFixtureValue(Set, &Device, SPDRP_CONFIGFLAGS, Label, DEVPROP_TYPE_UINT32, Bytes, Raw[i].Number ? sizeof(DWORD) : 0);
        if (is_reactos())
        {
            DWORD State = ExpectedInstallState(0x20);

            sprintf(Label, "ConfigFlags of registry type %lu, %lu bytes: install state", Raw[i].RegType, Raw[i].Size);
            ExpectFixtureValue(Set, &Device, SPDRP_INSTALL_STATE, Label, DEVPROP_TYPE_UINT32, &State, Raw[i].Number ? sizeof(DWORD) : 0);
        }
    }

    /* Strings have one terminator, lists end with an empty string, whatever the registry value has */
    SetFixtureValue(Key, L"DeviceDesc", REG_SZ, Desc, sizeof(Desc));
    ExpectFixtureValue(Set, &Device, SPDRP_DEVICEDESC, "Description with more terminators", DEVPROP_TYPE_STRING, DescOne, sizeof(DescOne));
    SetFixtureValue(Key, L"DeviceDesc", REG_SZ, DescOne, sizeof(DescOne));
    ExpectFixtureValue(Set, &Device, SPDRP_DEVICEDESC, "Description", DEVPROP_TYPE_STRING, DescOne, sizeof(DescOne));

    SetFixtureValue(Key, L"HardwareID", REG_MULTI_SZ, Unended, 3 * sizeof(WCHAR));
    ExpectFixtureValue(Set, &Device, SPDRP_HARDWAREID, "List with an unended last string", DEVPROP_TYPE_STRING_LIST, ListEnd, sizeof(ListEnd));
    SetFixtureValue(Key, L"HardwareID", REG_MULTI_SZ, UnendedOne, sizeof(WCHAR));
    ExpectFixtureValue(Set, &Device, SPDRP_HARDWAREID, "List of one unended string", DEVPROP_TYPE_STRING_LIST, ListSingle, sizeof(ListSingle));
    SetFixtureValue(Key, L"HardwareID", REG_MULTI_SZ, Extra, sizeof(Extra));
    ExpectFixtureValue(Set, &Device, SPDRP_HARDWAREID, "List with strings after the end", DEVPROP_TYPE_STRING_LIST, ListEnd, sizeof(ListEnd));
    SetFixtureValue(Key, L"HardwareID", REG_MULTI_SZ, OddBytes, 3);
    ExpectFixtureValue(Set, &Device, SPDRP_HARDWAREID, "List of an odd number of bytes", DEVPROP_TYPE_STRING_LIST, ListOdd, sizeof(ListOdd));
    SetFixtureValue(Key, L"CompatibleIDs", REG_MULTI_SZ, Empty, sizeof(Empty));
    ExpectFixtureValue(Set, &Device, SPDRP_COMPATIBLEIDS, "Empty list", DEVPROP_TYPE_STRING_LIST, Empty, sizeof(Empty));

    /* Values larger than the first buffer of any reader */
    Long = HeapAlloc(GetProcessHeap(), 0, 20000 * sizeof(WCHAR));
    ok(Long != NULL, "No memory\n");
    if (Long)
    {
        for (i = 0; i < 19999; i++)
            ((WCHAR *)Long)[i] = L'a' + (i % 26);
        ((WCHAR *)Long)[19999] = UNICODE_NULL;
        SetFixtureValue(Key, L"DeviceDesc", REG_SZ, Long, 20000 * sizeof(WCHAR));
        ExpectFixtureValue(Set, &Device, SPDRP_DEVICEDESC, "Long description", DEVPROP_TYPE_STRING, Long, 20000 * sizeof(WCHAR));
        SetFixtureValue(Key, L"DeviceDesc", REG_SZ, DescOne, sizeof(DescOne));
        HeapFree(GetProcessHeap(), 0, Long);
    }

    /* The boolean is one byte, 0xFF for any nonzero DWORD; numbers and the descriptor come from their own values */
    {
        static const DWORD Dwords[] = { 0, 1, 0x100, 0xFFFFFFFF };
        static const BYTE Booleans[] = { 0x00, 0xFF, 0xFF, 0xFF };
        static const DWORD DeviceType = 7, Characteristics = 0x10, Policy = 3;
        static const BYTE Security[20] = { 1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        for (i = 0; i < ARRAYSIZE(Dwords); i++)
        {
            char Label[48];

            SetFixtureValue(Key, L"Exclusive", REG_DWORD, &Dwords[i], sizeof(DWORD));
            sprintf(Label, "Exclusive 0x%lx", Dwords[i]);
            ExpectFixtureValue(Set, &Device, SPDRP_EXCLUSIVE, Label, DEVPROP_TYPE_BOOLEAN, &Booleans[i], 1);
        }
        SetFixtureValue(Key, L"Exclusive", REG_BINARY, Bytes, sizeof(Bytes));
        ExpectFixtureValue(Set, &Device, SPDRP_EXCLUSIVE, "Exclusive of the wrong registry type", DEVPROP_TYPE_BOOLEAN, NULL, 0);

        SetFixtureValue(Key, L"DeviceType", REG_DWORD, &DeviceType, sizeof(DWORD));
        ExpectFixtureValue(Set, &Device, SPDRP_DEVTYPE, "Device type", DEVPROP_TYPE_UINT32, &DeviceType, sizeof(DWORD));
        SetFixtureValue(Key, L"DeviceCharacteristics", REG_DWORD, &Characteristics, sizeof(DWORD));
        ExpectFixtureValue(Set, &Device, SPDRP_CHARACTERISTICS, "Characteristics", DEVPROP_TYPE_UINT32, &Characteristics, sizeof(DWORD));
        SetFixtureValue(Key, L"RemovalPolicy", REG_DWORD, &Policy, sizeof(DWORD));
        ExpectFixtureValue(Set, &Device, SPDRP_REMOVAL_POLICY_OVERRIDE, "Removal policy override", DEVPROP_TYPE_UINT32, &Policy, sizeof(DWORD));
        SetFixtureValue(Key, L"Security", REG_BINARY, Security, sizeof(Security));
        ExpectFixtureValue(Set, &Device, SPDRP_SECURITY, "Security descriptor", DEVPROP_TYPE_SECURITY_DESCRIPTOR, Security, sizeof(Security));
    }

    /* The class GUID is a string in the registry; a broken string is no GUID */
    SetFixtureValue(Key, L"ClassGUID", REG_SZ, ClassGuid, sizeof(ClassGuid));
    ExpectFixtureValue(Set, &Device, SPDRP_CLASSGUID, "Class GUID", DEVPROP_TYPE_GUID, &ClassGuidValue, sizeof(GUID));
    SetFixtureValue(Key, L"ClassGUID", REG_SZ, L"{not a guid}", sizeof(L"{not a guid}"));
    ExpectFixtureValue(Set, &Device, SPDRP_CLASSGUID, "Broken class GUID", DEVPROP_TYPE_GUID, NULL, 0);
    SetFixtureValue(Key, L"ClassGUID", REG_BINARY, ClassGuid, sizeof(ClassGuid));
    ExpectFixtureValue(Set, &Device, SPDRP_CLASSGUID, "Class GUID of the wrong registry type", DEVPROP_TYPE_GUID, NULL, 0);

    /* The name: the friendly name when there is one, else the description */
    {
        DEVPROPTYPE Type;
        BYTE *Value;
        DWORD Size, Err;

        Ret = ReadDeviceProperty(Set, &Device, &DEVPKEY_NAME, &Type, &Value, &Size, &Err);
        ok(Ret && Type == DEVPROP_TYPE_STRING && !wcscmp((WCHAR *)Value, DescOne), "Name without a friendly name: %d, 0x%lx\n", Ret, Err);
        if (Ret)
            HeapFree(GetProcessHeap(), 0, Value);
        SetFixtureValue(Key, L"FriendlyName", REG_SZ, Friendly, sizeof(Friendly));
        Ret = ReadDeviceProperty(Set, &Device, &DEVPKEY_NAME, &Type, &Value, &Size, &Err);
        ok(Ret && Type == DEVPROP_TYPE_STRING && !wcscmp((WCHAR *)Value, Friendly) && Size == sizeof(Friendly),
           "Name with a friendly name: %d, 0x%lx\n", Ret, Err);
        if (Ret)
            HeapFree(GetProcessHeap(), 0, Value);
        RegDeleteValueW(Key, L"FriendlyName");
        RegDeleteValueW(Key, L"DeviceDesc");
        Ret = ReadDeviceProperty(Set, &Device, &DEVPKEY_NAME, &Type, &Value, &Size, &Err);
        ok(!Ret && Err == ERROR_NOT_FOUND && Type == DEVPROP_TYPE_EMPTY, "Name without any: %d, 0x%lx, type 0x%lx\n", Ret, Err, Type);
    }

done:
    if (Key)
        RegCloseKey(Key);
    SetupDiDestroyDeviceInfoList(Set);
    if (Created)
    {
        /* Only the instance of this run; the enumerator key goes if nothing else is in it */
        Error = SHDeleteKeyW(HKEY_LOCAL_MACHINE, KeyName);
        /* Windows deletes a device that was never registered together with its list */
        ok(Error == ERROR_SUCCESS || Error == ERROR_FILE_NOT_FOUND, "The fixture device was not deleted: %ld\n", Error);
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_QUERY_VALUE, &Key);
        ok(Error == ERROR_FILE_NOT_FOUND, "The fixture device is still there: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
            RegCloseKey(Key);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\ROOT\\" FIXTURE_ENUMERATOR);
    }
}

/* ------------------------------------------------------------------------------------------------------------- */

START_TEST(SetupDiGetDeviceProperty)
{
    HDEVINFO Set;
    SP_DEVINFO_DATA Device;
    HMODULE hCfgMgr;
    unsigned Index, Counts[5] = { 0 };

    pSetupDiGetDevicePropertyW = (FN_SetupDiGetDevicePropertyW)GetProcAddress(GetModuleHandleW(L"setupapi.dll"),
                                                                              "SetupDiGetDevicePropertyW");
    if (!pSetupDiGetDevicePropertyW)
    {
        skip("SetupDiGetDevicePropertyW is not available\n");
        return;
    }
    if (!is_reactos() && GetNTVersion() > _WIN32_WINNT_WIN7)
    {
        skip("Newer Windows versions differ in the property types, the error codes and the outputs on failure\n");
        return;
    }

    hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    if (hCfgMgr)
    {
        pCM_Get_DevNode_Status = (FN_CM_Get_DevNode_Status)GetProcAddress(hCfgMgr, "CM_Get_DevNode_Status");
        pCM_Get_Parent = (FN_CM_Get_Parent)GetProcAddress(hCfgMgr, "CM_Get_Parent");
        pCM_Get_Device_IDW = (FN_CM_Get_Device_IDW)GetProcAddress(hCfgMgr, "CM_Get_Device_IDW");
        pCM_Get_DevNode_Registry_PropertyW =
            (FN_CM_Get_DevNode_Registry_PropertyW)GetProcAddress(hCfgMgr, "CM_Get_DevNode_Registry_PropertyW");
    }
    if (!hCfgMgr || !pCM_Get_DevNode_Status || !pCM_Get_Parent || !pCM_Get_Device_IDW || !pCM_Get_DevNode_Registry_PropertyW)
    {
        skip("cfgmgr32 is not available\n");
        goto cleanup;
    }

    Set = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    ok(Set != INVALID_HANDLE_VALUE, "SetupDiGetClassDevsW failed: 0x%lx\n", GetLastError());
    if (Set == INVALID_HANDLE_VALUE)
        goto cleanup;

    Device.cbSize = sizeof(Device);
    if (!SetupDiEnumDeviceInfo(Set, 0, &Device))
    {
        ok(GetLastError() == ERROR_NO_MORE_ITEMS, "The first enumeration failed with 0x%lx\n", GetLastError());
        skip("No devices\n");
        SetupDiDestroyDeviceInfoList(Set);
        goto cleanup;
    }

    TestArguments(Set, &Device);
    TestFixtureDevice();

    for (Index = 0; ; Index++)
    {
        Device.cbSize = sizeof(Device);
        if (!SetupDiEnumDeviceInfo(Set, Index, &Device))
        {
            ok(GetLastError() == ERROR_NO_MORE_ITEMS, "Enumeration stopped at device %u with 0x%lx\n", Index, GetLastError());
            break;
        }
        TestDevice(Set, &Device, Index, Counts);
    }
    trace("%u devices: %u instance IDs, %u registry-backed properties, %u statuses, %u problem codes, %u parents\n",
          Index, Counts[0], Counts[1], Counts[2], Counts[3], Counts[4]);
    ok(Counts[0] == Index, "Not every device has an instance ID\n");
    ok(Counts[1] != 0, "No registry-backed property at all\n");

    SetupDiDestroyDeviceInfoList(Set);

cleanup:
    if (hCfgMgr)
        FreeLibrary(hCfgMgr);
}
