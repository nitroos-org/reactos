/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Install a driver over a started device: the stack is restarted, unless the system runs on it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The device is the fake NDIS miniport (modules/rostests/drivers/fakemp) as a root device the
 * test creates itself. Its halt and initialize counters tell whether the driver stack was really
 * torn down and built again. Run it once per boot, and not together with ndis_apitest or
 * RootDeviceDisable: all install the same driver.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winioctl.h>
#include <winreg.h>
#include <cfgmgr32.h>
#include <winuser.h>
#include <setupapi.h>
#include <regstr.h>
#include <shlwapi.h>

#include "fakemp.h"

#define NET_CLASS_GUID  L"{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define CLASS_KEY       L"SYSTEM\\CurrentControlSet\\Control\\Class\\" NET_CLASS_GUID L"\\0953"
#define ENUM_ROOT_KEY   L"SYSTEM\\CurrentControlSet\\Enum\\Root"
#define ENUM_NAME       L"FAKEMPR"
#define SERVICE_NAME    L"fakemps"
#define SERVICE_KEY     L"SYSTEM\\CurrentControlSet\\Services\\" SERVICE_NAME
#define DEVICE_INSTANCE L"ROOT\\" ENUM_NAME L"\\0000"

static HANDLE Control = INVALID_HANDLE_VALUE;
static WCHAR InfPath[MAX_PATH];

static
void
SetString(HKEY Key, PCWSTR Name, DWORD Type, PCWSTR Value)
{
    RegSetValueExW(Key, Name, 0, Type, (const BYTE *)Value, (lstrlenW(Value) + 1) * sizeof(WCHAR));
}

static
void
SetDword(HKEY Key, PCWSTR Name, DWORD Value)
{
    RegSetValueExW(Key, Name, 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
}

static
void
DriverPath(PWSTR Path, ULONG Length, BOOL Destination)
{
    PWSTR Slash;

    if (Destination)
    {
        GetSystemDirectoryW(Path, Length);
        lstrcatW(Path, L"\\drivers\\");
    }
    else
    {
        GetModuleFileNameW(NULL, Path, Length);
        Slash = wcsrchr(Path, L'\\');
        Slash[1] = UNICODE_NULL;
    }
    lstrcatW(Path, SERVICE_NAME L".sys");
}

static
BOOL
Locate(DEVINST *DevInst)
{
    return CM_Locate_DevNodeW(DevInst, (DEVINSTID_W)DEVICE_INSTANCE, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS;
}

static
BOOL
OpenControl(void)
{
    DWORD Start = GetTickCount();

    do
    {
        Control = CreateFileW(L"\\\\.\\FakeMpS", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (Control != INVALID_HANDLE_VALUE)
            break;
        Sleep(200);
    } while (GetTickCount() - Start < 30000);
    ok(Control != INVALID_HANDLE_VALUE, "No control device: %lu\n", GetLastError());
    return Control != INVALID_HANDLE_VALUE;
}

static
FAKEMP_STATS
Stats(void)
{
    FAKEMP_STATS St;
    DWORD Returned;

    ZeroMemory(&St, sizeof(St));
    ok(DeviceIoControl(Control, FAKEMP_IOCTL_GET_STATS, NULL, 0, &St, sizeof(St), &Returned, NULL),
       "GET_STATS failed: %lu\n", GetLastError());
    return St;
}

/* Waits for the device to be started without a problem */
static
BOOL
WaitRunning(DEVINST DevInst, PCSTR When)
{
    ULONG Status = 0, Problem = 0;
    CONFIGRET Cr = CR_FAILURE;
    DWORD Start = GetTickCount();

    do
    {
        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        if (Cr == CR_SUCCESS && (Status & DN_STARTED) && !(Status & DN_HAS_PROBLEM))
            break;
        Sleep(100);
    } while (GetTickCount() - Start < 15000);

    ok(Cr == CR_SUCCESS && (Status & DN_STARTED) && !(Status & DN_HAS_PROBLEM) && Problem == 0,
       "%s: status 0x%lx, problem %lu, cr 0x%lx: not running\n", When, Status, Problem, Cr);
    return Cr == CR_SUCCESS && (Status & DN_STARTED);
}

/* Creates the device, running with its driver */
static
BOOL
Install(void)
{
    WCHAR Source[MAX_PATH], Destination[MAX_PATH];
    WCHAR HardwareId[64];
    HKEY Key, SubKey;
    DEVINST Root, DevInst;
    CONFIGRET Cr;
    LONG Error;
    DWORD Start;

    DriverPath(Source, MAX_PATH, FALSE);
    DriverPath(Destination, MAX_PATH, TRUE);
    if (!CopyFileW(Source, Destination, FALSE))
    {
        skip("Cannot copy %ls: %lu\n", Source, GetLastError());
        return FALSE;
    }

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    if (Error != ERROR_SUCCESS)
    {
        skip("Cannot create the service key: %ld\n", Error);
        return FALSE;
    }
    SetDword(Key, L"Type", 1);
    SetDword(Key, L"Start", 3);
    SetDword(Key, L"ErrorControl", 0);
    SetString(Key, L"ImagePath", REG_EXPAND_SZ, L"system32\\drivers\\" SERVICE_NAME L".sys");
    SetString(Key, L"Group", REG_SZ, L"NDIS");
    RegCloseKey(Key);

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, CLASS_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "Class key: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    SetString(Key, L"DriverDesc", REG_SZ, L"FakeMpS");
    SetString(Key, L"ProviderName", REG_SZ, L"ReactOS Project");
    if (RegCreateKeyExW(Key, L"Linkage", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &SubKey, NULL) == ERROR_SUCCESS)
    {
        SetString(SubKey, L"Export", REG_SZ, L"\\Device\\{7A1D0F53-6D50-4C2A-9E70-46414B454D53}");
        RegCloseKey(SubKey);
    }
    RegCloseKey(Key);

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, ENUM_ROOT_KEY L"\\" ENUM_NAME L"\\0000", 0, NULL, 0,
                            KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "Enum key: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    ZeroMemory(HardwareId, sizeof(HardwareId));
    lstrcpyW(HardwareId, L"ROOT\\" ENUM_NAME);
    RegSetValueExW(Key, L"HardwareID", 0, REG_MULTI_SZ, (const BYTE *)HardwareId,
                   (lstrlenW(HardwareId) + 2) * sizeof(WCHAR));
    SetString(Key, L"Service", REG_SZ, SERVICE_NAME);
    SetString(Key, L"Class", REG_SZ, L"Net");
    SetString(Key, L"ClassGUID", REG_SZ, NET_CLASS_GUID);
    SetString(Key, L"Driver", REG_SZ, NET_CLASS_GUID L"\\0953");
    SetString(Key, L"DeviceDesc", REG_SZ, L"FakeMpS");
    SetDword(Key, L"ConfigFlags", 0);
    RegCloseKey(Key);

    Cr = CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL);
    ok(Cr == CR_SUCCESS, "CM_Locate_DevNodeW(root): 0x%lx\n", Cr);
    if (Cr != CR_SUCCESS)
        return FALSE;
    Cr = CM_Reenumerate_DevNode(Root, CM_REENUMERATE_SYNCHRONOUS);
    ok(Cr == CR_SUCCESS, "CM_Reenumerate_DevNode: 0x%lx\n", Cr);

    Start = GetTickCount();
    while (!Locate(&DevInst) && GetTickCount() - Start < 15000)
        Sleep(200);
    ok(Locate(&DevInst), "No device node\n");

    return OpenControl();
}

/* The INF the driver is installed from: the same driver, one more value in the device's driver
 * key, which the install writes and a running stack does not see */
static
BOOL
WriteInf(DWORD Stamp, PCSTR Class, PCSTR ClassGuid)
{
    static const char Text[] =
        "[Version]\r\n"
        "Signature = \"$Windows NT$\"\r\n"
        "Class = %s\r\n"
        "ClassGUID = %s\r\n"
        "Provider = %%Mfg%%\r\n"
        "DriverVer = 11/05/2026,1.0.0.0\r\n"
        "[Manufacturer]\r\n"
        "%%Mfg%% = Models\r\n"
        "[Models]\r\n"
        "%%Desc%% = Inst,ROOT\\FAKEMPR\r\n"
        "[Inst.NT]\r\n"
        "AddReg = Inst_Reg\r\n"
        "[Inst_Reg]\r\n"
        "HKR,,RestartStamp,0x00010001,%lu\r\n"
        "[Inst.NT.Services]\r\n"
        "AddService = fakemps, 0x00000002, Svc\r\n"
        "[Svc]\r\n"
        "ServiceType = 1\r\n"
        "StartType = 3\r\n"
        "ErrorControl = 0\r\n"
        "ServiceBinary = %%12%%\\fakemps.sys\r\n"
        "LoadOrderGroup = NDIS\r\n"
        "[Strings]\r\n"
        "Mfg = \"ROSTEST\"\r\n"
        "Desc = \"FakeMpS\"\r\n";
    char Buffer[2048];
    HANDLE File;
    DWORD Written;
    int Length;

    if (!InfPath[0])
    {
        GetTempPathW(MAX_PATH, InfPath);
        lstrcatW(InfPath, L"rtrestart.inf");
    }
    Length = _snprintf(Buffer, sizeof(Buffer), Text, Class, ClassGuid, Stamp);
    File = CreateFileW(InfPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        skip("Cannot write %ls: %lu\n", InfPath, GetLastError());
        return FALSE;
    }
    WriteFile(File, Buffer, Length, &Written, NULL);
    CloseHandle(File);
    return TRUE;
}

/* SetupDiInstallDevice with the driver of the INF above, as an update over a running device.
 * Returns the flags the install leaves in the device's install parameters */
static
DWORD
InstallDriver(BOOL *Result)
{
    SP_DEVINFO_DATA DevInfo;
    SP_DEVINSTALL_PARAMS_W Params;
    SP_DRVINFO_DATA_W Drv;
    HDEVINFO Set;
    DWORD Flags = 0xDEAD;

    *Result = FALSE;
    Set = SetupDiCreateDeviceInfoList(NULL, NULL);
    ok(Set != INVALID_HANDLE_VALUE, "SetupDiCreateDeviceInfoList failed: %lu\n", GetLastError());
    if (Set == INVALID_HANDLE_VALUE)
        return Flags;
    DevInfo.cbSize = sizeof(DevInfo);
    if (!SetupDiOpenDeviceInfoW(Set, DEVICE_INSTANCE, NULL, 0, &DevInfo))
    {
        ok(0, "SetupDiOpenDeviceInfoW failed: %lu\n", GetLastError());
        goto done;
    }

    Params.cbSize = sizeof(Params);
    ok(SetupDiGetDeviceInstallParamsW(Set, &DevInfo, &Params), "Get params failed: %lu\n", GetLastError());
    Params.Flags |= DI_ENUMSINGLEINF;
    lstrcpyW(Params.DriverPath, InfPath);
    ok(SetupDiSetDeviceInstallParamsW(Set, &DevInfo, &Params), "Set params failed: %lu\n", GetLastError());

    ok(SetupDiBuildDriverInfoList(Set, &DevInfo, SPDIT_COMPATDRIVER), "No driver list: %lu\n", GetLastError());
    Drv.cbSize = sizeof(Drv);
    if (!SetupDiEnumDriverInfoW(Set, &DevInfo, SPDIT_COMPATDRIVER, 0, &Drv))
    {
        ok(0, "No driver in the INF: %lu\n", GetLastError());
        goto done;
    }
    ok(SetupDiSetSelectedDriverW(Set, &DevInfo, &Drv), "Select driver failed: %lu\n", GetLastError());

    *Result = SetupDiInstallDevice(Set, &DevInfo);
    ok(*Result, "SetupDiInstallDevice failed: %lu\n", GetLastError());

    Params.cbSize = sizeof(Params);
    if (SetupDiGetDeviceInstallParamsW(Set, &DevInfo, &Params))
        Flags = Params.Flags;

done:
    SetupDiDestroyDeviceInfoList(Set);
    return Flags;
}

static
BOOL
ReadStamp(DWORD *Stamp)
{
    HKEY Key;
    DWORD Size = sizeof(*Stamp), Type;
    BOOL Ret;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CLASS_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return FALSE;
    Ret = RegQueryValueExW(Key, L"RestartStamp", NULL, &Type, (BYTE *)Stamp, &Size) == ERROR_SUCCESS && Type == REG_DWORD;
    RegCloseKey(Key);
    return Ret;
}

static
void
SetServiceStart(DWORD Start)
{
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, KEY_SET_VALUE, &Key) == ERROR_SUCCESS)
    {
        SetDword(Key, L"Start", Start);
        RegCloseKey(Key);
    }
}

static
void
Cleanup(void)
{
    WCHAR Path[MAX_PATH];
    DEVINST DevInst;
    PNP_VETO_TYPE Veto;
    WCHAR VetoName[MAX_PATH];
    HKEY Root;

    if (Control != INVALID_HANDLE_VALUE)
        CloseHandle(Control);
    Control = INVALID_HANDLE_VALUE;

    if (Locate(&DevInst))
        CM_Query_And_Remove_SubTreeW(DevInst, &Veto, VetoName, ARRAYSIZE(VetoName), CM_REMOVE_NO_RESTART);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ENUM_ROOT_KEY, 0, DELETE | KEY_ENUMERATE_SUB_KEYS, &Root) == ERROR_SUCCESS)
    {
        SHDeleteKeyW(Root, ENUM_NAME);
        RegCloseKey(Root);
    }
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, CLASS_KEY);
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, SERVICE_KEY);
    DriverPath(Path, MAX_PATH, TRUE);
    DeleteFileW(Path); /* fails while the driver is loaded */
    if (InfPath[0])
        DeleteFileW(InfPath);
}

START_TEST(RootDeviceInstallRestart)
{
    FAKEMP_STATS St, Before;
    DEVINST DevInst;
    DWORD Flags, Stamp;
    BOOL Result;

    if (!Install())
    {
        Cleanup();
        return;
    }
    ok(Locate(&DevInst), "No device node\n");
    if (!WaitRunning(DevInst, "after the first start") || !WriteInf(1, "Net", "{4D36E972-E325-11CE-BFC1-08002BE10318}"))
    {
        Cleanup();
        return;
    }

    /* A driver installed over the running device: its stack is stopped and started again, so
     * the settings of the install are in effect without a reboot */
    Before = Stats();
    Flags = InstallDriver(&Result);
    ok(Result, "The install failed\n");
    ok(!(Flags & (DI_NEEDRESTART | DI_NEEDREBOOT)), "The install asks for a restart: flags 0x%lx\n", Flags);
    ok(ReadStamp(&Stamp) && Stamp == 1, "The install did not write its value\n");
    WaitRunning(DevInst, "after the install");
    St = Stats();
    ok(St.Halts == Before.Halts + 1, "%lu halts, expected %lu: the stack was not stopped\n", St.Halts, Before.Halts + 1);
    ok(St.Initializes == Before.Initializes + 1, "%lu initializes, expected %lu: the stack was not started again\n",
       St.Initializes, Before.Initializes + 1);
    ok(St.Halted == 0, "The miniport is halted\n");

    /* The system runs on a boot-start driver: it is never stopped. The install asks for a
     * restart and the device keeps running */
    SetServiceStart(0);
    if (WriteInf(2, "Net", "{4D36E972-E325-11CE-BFC1-08002BE10318}"))
    {
        Before = Stats();
        Flags = InstallDriver(&Result);
        ok(Result, "The install over a boot-start driver failed\n");
        ok((Flags & DI_NEEDRESTART), "The install does not ask for a restart: flags 0x%lx\n", Flags);
        ok(ReadStamp(&Stamp) && Stamp == 2, "The install did not write its value\n");
        WaitRunning(DevInst, "after the install over a boot-start driver");
        St = Stats();
        ok(St.Halts == Before.Halts, "%lu halts, expected %lu: a boot-start device was stopped\n", St.Halts, Before.Halts);
        ok(St.Initializes == Before.Initializes, "%lu initializes, expected %lu\n", St.Initializes, Before.Initializes);
        ok(St.Halted == 0, "The miniport is halted\n");
    }

    /* An install into a class the system runs on (the display) is not restarted either, whatever
     * the device was before */
    SetServiceStart(3);
    if (WriteInf(3, "Display", "{4D36E968-E325-11CE-BFC1-08002BE10318}"))
    {
        Before = Stats();
        Flags = InstallDriver(&Result);
        ok(Result, "The install into the display class failed\n");
        ok((Flags & DI_NEEDRESTART), "The install into the display class does not ask for a restart: flags 0x%lx\n", Flags);
        WaitRunning(DevInst, "after the install into the display class");
        St = Stats();
        ok(St.Halts == Before.Halts, "%lu halts, expected %lu: the install into the display class stopped the stack\n",
           St.Halts, Before.Halts);
    }

    Cleanup();
}
