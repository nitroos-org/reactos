/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Disable and re-enable a started root-enumerated device
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The device is the fake NDIS miniport (modules/rostests/drivers/fakemp) as a root device the
 * test creates itself. Its halt and initialize counters tell whether the driver stack was
 * really torn down and built again. Run it once per boot, and not together with ndis_apitest:
 * both install the same driver.
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
#include <lm.h>

#include "fakemp.h"

#define FormatW(Buffer, ...) _snwprintf(Buffer, ARRAYSIZE(Buffer) - 1, __VA_ARGS__)

#define NET_CLASS_GUID  L"{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define CLASS_KEY       L"SYSTEM\\CurrentControlSet\\Control\\Class\\" NET_CLASS_GUID L"\\0952"
#define ENUM_ROOT_KEY   L"SYSTEM\\CurrentControlSet\\Enum\\Root"
#define ENUM_NAME       L"FAKEMPS"
#define SERVICE_NAME    L"fakemps"
#define SERVICE_KEY     L"SYSTEM\\CurrentControlSet\\Services\\" SERVICE_NAME
#define DEVICE_INSTANCE L"ROOT\\" ENUM_NAME L"\\0000"

static HANDLE Control = INVALID_HANDLE_VALUE;

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

/* Creates the device. With a ConfigFlags that disables it, it comes up disabled (the state of
 * a device that was disabled before a reboot): the driver is not loaded */
static
BOOL
Install(DWORD ConfigFlags)
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
    SetString(Key, L"Driver", REG_SZ, NET_CLASS_GUID L"\\0952");
    SetString(Key, L"DeviceDesc", REG_SZ, L"FakeMpS");
    SetDword(Key, L"ConfigFlags", ConfigFlags);
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

    /* The driver loads for the device, and so does its control device */
    if (ConfigFlags & CONFIGFLAG_DISABLED)
        return Locate(&DevInst);
    return OpenControl();
}

static
LONG
ReadConfigFlags(DWORD *Flags)
{
    HKEY Key;
    DWORD Size = sizeof(*Flags), Type;
    LONG Error;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ENUM_ROOT_KEY L"\\" ENUM_NAME L"\\0000", 0, KEY_QUERY_VALUE, &Key);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = RegQueryValueExW(Key, L"ConfigFlags", NULL, &Type, (BYTE *)Flags, &Size);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS && Type != REG_DWORD ? ERROR_INVALID_DATA : Error;
}

/* SetupDiChangeState(DICS_DISABLE/DICS_ENABLE, global): the flag goes to the instance key */
static
BOOL
ChangeState(DWORD StateChange)
{
    static const GUID NetClass = {0x4D36E972, 0xE325, 0x11CE, {0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18}};
    SP_DEVINFO_DATA DevInfo;
    SP_PROPCHANGE_PARAMS Params;
    HDEVINFO Set;
    BOOL Ret = FALSE;

    Set = SetupDiCreateDeviceInfoList(&NetClass, NULL);
    ok(Set != INVALID_HANDLE_VALUE, "SetupDiCreateDeviceInfoList failed: %lu\n", GetLastError());
    if (Set == INVALID_HANDLE_VALUE)
        return FALSE;
    DevInfo.cbSize = sizeof(DevInfo);
    if (!SetupDiOpenDeviceInfoW(Set, DEVICE_INSTANCE, NULL, 0, &DevInfo))
    {
        ok(0, "SetupDiOpenDeviceInfoW failed: %lu\n", GetLastError());
        SetupDiDestroyDeviceInfoList(Set);
        return FALSE;
    }
    ZeroMemory(&Params, sizeof(Params));
    Params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    Params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    Params.StateChange = StateChange;
    Params.Scope = DICS_FLAG_GLOBAL;
    ok(SetupDiSetClassInstallParamsW(Set, &DevInfo, &Params.ClassInstallHeader, sizeof(Params)),
       "SetupDiSetClassInstallParamsW failed: %lu\n", GetLastError());
    Ret = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, Set, &DevInfo);
    ok(Ret, "DIF_PROPERTYCHANGE(%lu) failed: %lu\n", StateChange, GetLastError());
    SetupDiDestroyDeviceInfoList(Set);
    return Ret;
}

static
void
CheckConfigFlags(DWORD Expected, PCSTR When)
{
    DWORD Flags = 0xDEAD;
    LONG Error = ReadConfigFlags(&Flags);

    ok(Error == ERROR_SUCCESS, "%s: ConfigFlags: %ld\n", When, Error);
    ok((Flags & CONFIGFLAG_DISABLED) == Expected, "%s: ConfigFlags 0x%lx, expected the disabled bit 0x%lx\n", When, Flags, Expected);
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

    ok(Cr == CR_SUCCESS, "%s: CM_Get_DevNode_Status failed: 0x%lx\n", When, Cr);
    ok((Status & DN_STARTED) && !(Status & DN_HAS_PROBLEM) && Problem == 0,
       "%s: status 0x%lx, problem %lu: not running\n", When, Status, Problem);
    return Cr == CR_SUCCESS && (Status & DN_STARTED);
}

static
void
CheckDisabled(DEVINST DevInst, ULONG Halts, ULONG Initializes, PCSTR When)
{
    ULONG Status = 0, Problem = 0;
    FAKEMP_STATS St;
    DEVINST Again;
    CONFIGRET Cr;

    /* The device node stays in the tree: it is what the device is enabled through */
    Cr = CM_Locate_DevNodeW(&Again, (DEVINSTID_W)DEVICE_INSTANCE, CM_LOCATE_DEVNODE_NORMAL);
    ok(Cr == CR_SUCCESS, "%s: CM_Locate_DevNodeW failed: 0x%lx\n", When, Cr);

    Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
    ok(Cr == CR_SUCCESS, "%s: CM_Get_DevNode_Status failed: 0x%lx\n", When, Cr);
    if (Cr == CR_SUCCESS)
    {
        ok(!(Status & DN_STARTED), "%s: status 0x%lx: still started\n", When, Status);
        ok(Status & DN_HAS_PROBLEM, "%s: status 0x%lx: no problem\n", When, Status);
        ok(Problem == CM_PROB_DISABLED, "%s: problem %lu, expected %u\n", When, Problem, CM_PROB_DISABLED);
    }

    /* The stack is gone: the miniport was halted, and is not initialized again */
    St = Stats();
    ok(St.Halts == Halts, "%s: %lu halts, expected %lu\n", When, St.Halts, Halts);
    ok(St.Initializes == Initializes, "%s: %lu initializes, expected %lu\n", When, St.Initializes, Initializes);
    ok(St.Halted == 1, "%s: the miniport is not halted\n", When);
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
}

#define BAD_ENUM_NAME   L"ROSTEST_BADSVC"
#define BAD_INSTANCE    L"ROOT\\" BAD_ENUM_NAME L"\\0000"

/* A device whose service does not exist never starts. It can still be disabled, and enabling
 * it again reports that it does not start */
static
void
TestFailedDevice(void)
{
    WCHAR HardwareId[64];
    DEVINST Root, DevInst;
    ULONG Status = 0, Problem = 0, i;
    CONFIGRET Cr;
    HKEY Key, EnumKey;
    DWORD Start;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ENUM_ROOT_KEY, 0, DELETE | KEY_CREATE_SUB_KEY, &EnumKey) != ERROR_SUCCESS)
    {
        skip("No write access to the Root enumerator key\n");
        return;
    }
    if (RegCreateKeyExW(EnumKey, BAD_ENUM_NAME L"\\0000", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL) != ERROR_SUCCESS)
    {
        skip("Cannot create a root device key\n");
        RegCloseKey(EnumKey);
        return;
    }
    ZeroMemory(HardwareId, sizeof(HardwareId));
    lstrcpyW(HardwareId, L"ROOT\\" BAD_ENUM_NAME);
    RegSetValueExW(Key, L"HardwareID", 0, REG_MULTI_SZ, (const BYTE *)HardwareId,
                   (lstrlenW(HardwareId) + 2) * sizeof(WCHAR));
    SetString(Key, L"Service", REG_SZ, L"rostestnosuchservice");
    SetDword(Key, L"ConfigFlags", 0);
    RegCloseKey(Key);

    Cr = CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL);
    ok(Cr == CR_SUCCESS, "CM_Locate_DevNodeW(root): 0x%lx\n", Cr);
    if (Cr == CR_SUCCESS)
        CM_Reenumerate_DevNode(Root, CM_REENUMERATE_SYNCHRONOUS);

    Start = GetTickCount();
    while (CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)BAD_INSTANCE, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS &&
           GetTickCount() - Start < 10000)
        Sleep(200);
    Cr = CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)BAD_INSTANCE, CM_LOCATE_DEVNODE_NORMAL);
    ok(Cr == CR_SUCCESS, "No device node for the device without a service: 0x%lx\n", Cr);
    if (Cr == CR_SUCCESS)
    {
        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        ok(Cr == CR_SUCCESS && !(Status & DN_STARTED), "The device without a service is started: 0x%lx\n", Status);

        if (is_reactos())
        {
            Cr = CM_Disable_DevNode(DevInst, 0);
            ok(Cr == CR_SUCCESS, "CM_Disable_DevNode of a device that does not start failed: 0x%lx\n", Cr);
            Status = Problem = 0;
            Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
            ok(Cr == CR_SUCCESS && Problem == CM_PROB_DISABLED, "status 0x%lx, problem %lu: not disabled\n", Status, Problem);

            for (i = 1; i <= 2; i++)
            {
                Cr = CM_Enable_DevNode(DevInst, 0);
                ok(Cr != CR_SUCCESS, "Attempt %lu: CM_Enable_DevNode of a device that cannot start succeeded\n", i);

                /* The device stays, with a problem, and can be tried again */
                Cr = CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)BAD_INSTANCE, CM_LOCATE_DEVNODE_NORMAL);
                ok(Cr == CR_SUCCESS, "Attempt %lu: the device node is gone after the failed enable: 0x%lx\n", i, Cr);
                Status = Problem = 0;
                Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
                ok(Cr == CR_SUCCESS && !(Status & DN_STARTED) && (Status & DN_HAS_PROBLEM) && Problem != 0,
                   "Attempt %lu: status 0x%lx, problem %lu, cr 0x%lx\n", i, Status, Problem, Cr);
                /* The problem is the failure, not the disable that came before it */
                ok(Problem != CM_PROB_DISABLED, "Attempt %lu: problem %lu: still reported as disabled\n", i, Problem);
            }
        }
    }

    SHDeleteKeyW(EnumKey, BAD_ENUM_NAME);
    RegCloseKey(EnumKey);
}

#define NOADMIN_USER L"rtdisuser"
#define NOADMIN_PASS L"RtDis-Pass#1x"
/* The device state calls take an administrator: the same calls from a user get
 * CR_ACCESS_DENIED. The calls are on the running test device, and are harmless for an
 * administrator (enabling a device that runs, a problem refused for a device that runs): only
 * the disable would do something, so it is only made by the user, who must be refused.
 * A new connection (CM_Connect_Machine) is made under the identity of the caller. */
static
void
CheckStateCalls(PCSTR Who, BOOL ExpectDenied)
{
    HMACHINE Machine;
    DEVINST Dev;
    CONFIGRET Cr;

    Cr = CM_Connect_MachineW(NULL, &Machine);
    ok(Cr == CR_SUCCESS, "%s: CM_Connect_MachineW failed: 0x%lx\n", Who, Cr);
    if (Cr != CR_SUCCESS)
        return;
    Cr = CM_Locate_DevNode_ExW(&Dev, (DEVINSTID_W)DEVICE_INSTANCE, CM_LOCATE_DEVNODE_NORMAL, Machine);
    ok(Cr == CR_SUCCESS, "%s: CM_Locate_DevNode_ExW failed: 0x%lx\n", Who, Cr);
    if (Cr == CR_SUCCESS)
    {
        if (ExpectDenied)
        {
            Cr = CM_Disable_DevNode_Ex(Dev, 0, Machine);
            ok(Cr == CR_ACCESS_DENIED, "%s: CM_Disable_DevNode: 0x%lx\n", Who, Cr);
        }
        Cr = CM_Enable_DevNode_Ex(Dev, 0, Machine);
        ok(ExpectDenied ? Cr == CR_ACCESS_DENIED : Cr == CR_SUCCESS, "%s: CM_Enable_DevNode: 0x%lx\n", Who, Cr);
        Cr = CM_Set_DevNode_Problem_Ex(Dev, CM_PROB_FAILED_INSTALL, CM_SET_DEVNODE_PROBLEM_NORMAL, Machine);
        ok(Cr == (ExpectDenied ? CR_ACCESS_DENIED : CR_INVALID_DATA), "%s: CM_Set_DevNode_Problem: 0x%lx\n", Who, Cr);
    }
    CM_Disconnect_Machine(Machine);
}

static
void
TestNonAdmin(void)
{
    USER_INFO_1 Info;
    DWORD Err = 0;
    NET_API_STATUS Ns;
    HANDLE Token;

    CheckStateCalls("administrator", FALSE);

    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = (LPWSTR)NOADMIN_USER;
    Info.usri1_password = (LPWSTR)NOADMIN_PASS;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetUserDel(NULL, NOADMIN_USER);
    Ns = NetUserAdd(NULL, 1, (LPBYTE)&Info, &Err);
    if (Ns != NERR_Success)
    {
        skip("NetUserAdd failed: %lu\n", Ns);
        return;
    }
    if (!LogonUserW(NOADMIN_USER, L".", NOADMIN_PASS, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token) ||
        !ImpersonateLoggedOnUser(Token))
    {
        skip("Cannot log on and impersonate the test user: %lu\n", GetLastError());
        NetUserDel(NULL, NOADMIN_USER);
        return;
    }
    CheckStateCalls("user", TRUE);
    RevertToSelf();
    CloseHandle(Token);
    NetUserDel(NULL, NOADMIN_USER);
}

/* A device that the system boots from (its driver is a boot-start driver) cannot be disabled:
 * setupapi refuses, and ConfigFlags is not touched, so the next boot has it */
static
void
TestBootDeviceNotDisableable(void)
{
    HDEVINFO Set;
    SP_DEVINFO_DATA DevInfo;
    DWORD Index, Tried = 0;

    Set = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    ok(Set != INVALID_HANDLE_VALUE, "SetupDiGetClassDevsW failed: %lu\n", GetLastError());
    if (Set == INVALID_HANDLE_VALUE)
        return;
    DevInfo.cbSize = sizeof(DevInfo);
    for (Index = 0; SetupDiEnumDeviceInfo(Set, Index, &DevInfo) && Tried < 3; Index++)
    {
        WCHAR Service[MAX_PATH], Path[MAX_PATH + 64], Id[MAX_PATH];
        DWORD Start = 3, Size = sizeof(Start), Flags = 0, FlagsBefore, Type;
        ULONG Status = 0, Problem = 0;
        SP_PROPCHANGE_PARAMS Params;
        HKEY Key;
        BOOL Ret;

        if (!SetupDiGetDeviceRegistryPropertyW(Set, &DevInfo, SPDRP_SERVICE, NULL, (PBYTE)Service, sizeof(Service), NULL))
            continue;
        FormatW(Path, L"SYSTEM\\CurrentControlSet\\Services\\%s", Service);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
            continue;
        if (RegQueryValueExW(Key, L"Start", NULL, &Type, (PBYTE)&Start, &Size) != ERROR_SUCCESS || Start != 0)
        {
            RegCloseKey(Key);
            continue;
        }
        RegCloseKey(Key);
        if (CM_Get_DevNode_Status(&Status, &Problem, DevInfo.DevInst, 0) != CR_SUCCESS || !(Status & DN_STARTED))
            continue;
        if (!SetupDiGetDeviceInstanceIdW(Set, &DevInfo, Id, ARRAYSIZE(Id), NULL))
            continue;

        Tried++;
        FormatW(Path, L"SYSTEM\\CurrentControlSet\\Enum\\%s", Id);
        FlagsBefore = 0;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
        {
            Size = sizeof(FlagsBefore);
            RegQueryValueExW(Key, L"ConfigFlags", NULL, &Type, (PBYTE)&FlagsBefore, &Size);
            RegCloseKey(Key);
        }

        ZeroMemory(&Params, sizeof(Params));
        Params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        Params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        Params.StateChange = DICS_DISABLE;
        Params.Scope = DICS_FLAG_GLOBAL;
        SetupDiSetClassInstallParamsW(Set, &DevInfo, &Params.ClassInstallHeader, sizeof(Params));
        SetLastError(0);
        Ret = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, Set, &DevInfo);
        ok(!Ret && GetLastError() == ERROR_NOT_DISABLEABLE, "%ls (service %ls): disabling the boot device: ret %d, error 0x%lx\n",
           Id, Service, Ret, GetLastError());

        Flags = 0xDEAD;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
        {
            Size = sizeof(Flags);
            if (RegQueryValueExW(Key, L"ConfigFlags", NULL, &Type, (PBYTE)&Flags, &Size) != ERROR_SUCCESS)
                Flags = 0;
            RegCloseKey(Key);
        }
        ok(Flags == FlagsBefore, "%ls: ConfigFlags changed from 0x%lx to 0x%lx\n", Id, FlagsBefore, Flags);
        Status = 0;
        CM_Get_DevNode_Status(&Status, &Problem, DevInfo.DevInst, 0);
        ok((Status & DN_STARTED) && !(Status & DN_HAS_PROBLEM), "%ls: status 0x%lx, problem %lu after the refused disable\n", Id, Status, Problem);
    }
    ok(Tried > 0, "No started device with a boot-start driver found\n");
    SetupDiDestroyDeviceInfoList(Set);
}

/* The notifications of CM_Register_Notification (Windows 8 and later): the device interface arrivals and removals that
 * disabling and enabling the device cause, for any class. Windows 10 calls the callback on a thread of its own. */
typedef CONFIGRET (WINAPI *FN_REGISTER_NOTIFICATION)(PCM_NOTIFY_FILTER, PVOID, PCM_NOTIFY_CALLBACK, PHCMNOTIFICATION);
typedef CONFIGRET (WINAPI *FN_UNREGISTER_NOTIFICATION)(HCMNOTIFICATION);

static volatile LONG Arrivals, Removals, WrongData;
static DWORD MainThread;
static volatile LONG OnMainThread;

static
DWORD
CALLBACK
NotifyCallback(
    HCMNOTIFICATION hNotify,
    PVOID Context,
    CM_NOTIFY_ACTION Action,
    PCM_NOTIFY_EVENT_DATA Data,
    DWORD Size)
{
    if (GetCurrentThreadId() == MainThread)
        InterlockedIncrement(&OnMainThread);
    if (Context != (PVOID)(ULONG_PTR)0x1357 || Data->FilterType != CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE ||
        Size < FIELD_OFFSET(CM_NOTIFY_EVENT_DATA, u.DeviceInterface.SymbolicLink) + sizeof(WCHAR) ||
        wcslen(Data->u.DeviceInterface.SymbolicLink) * sizeof(WCHAR) + FIELD_OFFSET(CM_NOTIFY_EVENT_DATA, u.DeviceInterface.SymbolicLink) + sizeof(WCHAR) != Size)
        InterlockedIncrement(&WrongData);
    if (Action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL)
        InterlockedIncrement(&Arrivals);
    else if (Action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL)
        InterlockedIncrement(&Removals);
    return ERROR_SUCCESS;
}

/* Waits until the count of calls stops growing, at most Seconds */
static
void
SettleCalls(ULONG Seconds)
{
    LONG Last = -1, Now;
    ULONG i;

    for (i = 0; i < Seconds * 2; i++)
    {
        Sleep(500);
        Now = Arrivals + Removals;
        if (Now == Last && i >= 2)
            break;
        Last = Now;
    }
}

START_TEST(RootDeviceDisable)
{
    DEVINST DevInst, RootDevInst;
    CONFIGRET Cr;
    FAKEMP_STATS St;
    PNP_VETO_TYPE Veto = PNP_VetoTypeUnknown;
    WCHAR VetoName[MAX_PATH] = L"";
    ULONG i;
    FN_REGISTER_NOTIFICATION pRegisterNotification;
    FN_UNREGISTER_NOTIFICATION pUnregisterNotification;
    HCMNOTIFICATION hNotify = NULL;
    HMODULE hCfgMgr;

    if (is_reactos())
        TestBootDeviceNotDisableable();

    /* A device whose ConfigFlags say that it is disabled (as it is after a reboot, when it was
     * disabled before) comes up disabled: the driver is not loaded, and a reenumeration does not
     * start it. Enabling it, even only through CM_Enable_DevNode, starts it and takes the flag back */
    if (!Install(CONFIGFLAG_DISABLED))
    {
        Cleanup();
        return;
    }
    if (Locate(&DevInst))
    {
        ULONG Status = 0, Problem = 0;

        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        ok(Cr == CR_SUCCESS, "CM_Get_DevNode_Status failed: 0x%lx\n", Cr);
        ok(!(Status & DN_STARTED) && (Status & DN_HAS_PROBLEM) && Problem == CM_PROB_DISABLED,
           "created disabled: status 0x%lx, problem %lu\n", Status, Problem);
        Control = CreateFileW(L"\\\\.\\FakeMpS", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
        ok(Control == INVALID_HANDLE_VALUE, "The driver of a disabled device is loaded\n");
        if (Control != INVALID_HANDLE_VALUE)
            CloseHandle(Control);
        Control = INVALID_HANDLE_VALUE;
        CheckConfigFlags(CONFIGFLAG_DISABLED, "created disabled");

        Cr = CM_Locate_DevNodeW(&RootDevInst, NULL, CM_LOCATE_DEVNODE_NORMAL);
        if (Cr == CR_SUCCESS)
            CM_Reenumerate_DevNode(RootDevInst, CM_REENUMERATE_SYNCHRONOUS);
        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        ok(Cr == CR_SUCCESS && !(Status & DN_STARTED) && Problem == CM_PROB_DISABLED,
           "after a reenumeration: status 0x%lx, problem %lu, cr 0x%lx\n", Status, Problem, Cr);

        Cr = CM_Enable_DevNode(DevInst, 0);
        ok(Cr == CR_SUCCESS, "CM_Enable_DevNode of a device disabled at boot failed: 0x%lx\n", Cr);
        CheckConfigFlags(0, "after CM_Enable_DevNode");
    }
    if (!Locate(&DevInst) || !OpenControl() || !WaitRunning(DevInst, "after install"))
    {
        Cleanup();
        return;
    }

    if (is_reactos())
    {
        TestNonAdmin();
        ok(Locate(&DevInst) && WaitRunning(DevInst, "after the calls of a user"), "The device is not running after the calls of a user\n");
    }

    St = Stats();
    ok(St.Initializes == 1, "%lu initializes after install\n", St.Initializes);
    ok(St.Halted == 0, "Halted after install\n");

    /* Enabling a device that runs is not an error */
    Cr = CM_Enable_DevNode(DevInst, 0);
    ok(Cr == CR_SUCCESS, "CM_Enable_DevNode of a running device failed: 0x%lx\n", Cr);

    /* Device interface notifications (ReactOS delivers them through the plug and play manager's window messages) */
    hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    pRegisterNotification = hCfgMgr == NULL ? NULL : (FN_REGISTER_NOTIFICATION)GetProcAddress(hCfgMgr, "CM_Register_Notification");
    pUnregisterNotification = hCfgMgr == NULL ? NULL : (FN_UNREGISTER_NOTIFICATION)GetProcAddress(hCfgMgr, "CM_Unregister_Notification");
    MainThread = GetCurrentThreadId();
    if (pRegisterNotification && pUnregisterNotification)
    {
        CM_NOTIFY_FILTER Filter;

        memset(&Filter, 0, sizeof(Filter));
        Filter.cbSize = sizeof(Filter);
        Filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
        Filter.Flags = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;
        Cr = pRegisterNotification(&Filter, (PVOID)(ULONG_PTR)0x1357, NotifyCallback, &hNotify);
        ok(Cr == CR_SUCCESS, "CM_Register_Notification failed: 0x%lx\n", Cr);
        SettleCalls(10);
        Arrivals = 0;
        Removals = 0;
    }

    for (i = 1; i <= 2; i++)
    {
        Cr = CM_Disable_DevNode(DevInst, 0);
        ok(Cr == CR_SUCCESS, "Cycle %lu: CM_Disable_DevNode failed: 0x%lx\n", i, Cr);
        CheckDisabled(DevInst, i, i, "after disable");
        if (hNotify && i == 1)
        {
            SettleCalls(10);
            trace("disabled: %ld arrivals, %ld removals\n", Arrivals, Removals);
            ok(Removals > 0, "no device interface was removed by the disable\n");
            Removals = 0;
            Arrivals = 0;
        }

        /* Disabling again changes nothing (as measured on ReactOS) */
        if (is_reactos())
        {
            Cr = CM_Disable_DevNode(DevInst, 0);
            ok(Cr == CR_SUCCESS, "Cycle %lu: second CM_Disable_DevNode failed: 0x%lx\n", i, Cr);
            CheckDisabled(DevInst, i, i, "after the second disable");
        }

        /* A reenumeration does not bring a disabled device back */
        Cr = CM_Locate_DevNodeW(&RootDevInst, NULL, CM_LOCATE_DEVNODE_NORMAL);
        ok(Cr == CR_SUCCESS, "CM_Locate_DevNodeW(root): 0x%lx\n", Cr);
        if (Cr == CR_SUCCESS)
            CM_Reenumerate_DevNode(RootDevInst, CM_REENUMERATE_SYNCHRONOUS);
        ok(Locate(&DevInst), "Cycle %lu: the disabled device node is gone\n", i);
        CheckDisabled(DevInst, i, i, "after a reenumeration");

        Cr = CM_Enable_DevNode(DevInst, 0);
        ok(Cr == CR_SUCCESS, "Cycle %lu: CM_Enable_DevNode failed: 0x%lx\n", i, Cr);
        if (WaitRunning(DevInst, "after enable"))
        {
            St = Stats();
            ok(St.Initializes == i + 1, "Cycle %lu: %lu initializes, expected %lu\n", i, St.Initializes, i + 1);
            ok(St.Halted == 0, "Cycle %lu: the miniport is halted after the enable\n", i);
        }
        if (hNotify && i == 1)
        {
            SettleCalls(10);
            trace("enabled: %ld arrivals, %ld removals\n", Arrivals, Removals);
            ok(Arrivals > 0, "no device interface arrived with the enable\n");
            ok(WrongData == 0, "%ld calls with data that is not that of a device interface\n", WrongData);
            ok(OnMainThread == 0, "%ld calls on the thread that registered\n", OnMainThread);
        }
    }
    if (hNotify)
    {
        Cr = pUnregisterNotification(hNotify);
        ok(Cr == CR_SUCCESS, "CM_Unregister_Notification failed: 0x%lx\n", Cr);
        hNotify = NULL;
    }

    /* The disable that setupapi records for the next boot goes to the instance key, and is
     * taken back by an enable that does not go through setupapi too */
    if (ChangeState(DICS_DISABLE))
    {
        CheckConfigFlags(CONFIGFLAG_DISABLED, "after DICS_DISABLE");
        CheckDisabled(DevInst, 3, 3, "after DICS_DISABLE");

        Cr = CM_Enable_DevNode(DevInst, 0);
        ok(Cr == CR_SUCCESS, "CM_Enable_DevNode failed: 0x%lx\n", Cr);
        if (WaitRunning(DevInst, "after CM_Enable_DevNode"))
        {
            St = Stats();
            ok(St.Initializes == 4, "%lu initializes after the enable, expected 4\n", St.Initializes);
        }
        CheckConfigFlags(0, "after CM_Enable_DevNode");
    }
    if (ChangeState(DICS_DISABLE))
    {
        CheckConfigFlags(CONFIGFLAG_DISABLED, "after the second DICS_DISABLE");
        if (ChangeState(DICS_ENABLE) && WaitRunning(DevInst, "after DICS_ENABLE"))
        {
            St = Stats();
            ok(St.Initializes == 5, "%lu initializes after DICS_ENABLE, expected 5\n", St.Initializes);
        }
        CheckConfigFlags(0, "after DICS_ENABLE");
    }

    /* A problem cannot be set on a device that runs (Windows: CR_INVALID_DATA, measured), and
     * CM_PROB_DISABLED is not for a caller to set. Clearing a problem that is not there is not
     * an error, and does not touch a node that the PnP manager has parked */
    if (is_reactos())
    {
        ULONG Status = 0, Problem = 0;

        Cr = CM_Set_DevNode_Problem(DevInst, CM_PROB_FAILED_INSTALL, CM_SET_DEVNODE_PROBLEM_NORMAL);
        ok(Cr == CR_INVALID_DATA, "CM_Set_DevNode_Problem of a running device: 0x%lx\n", Cr);
        Cr = CM_Set_DevNode_Problem(DevInst, CM_PROB_DISABLED, CM_SET_DEVNODE_PROBLEM_NORMAL);
        ok(Cr == CR_INVALID_DATA, "CM_Set_DevNode_Problem(CM_PROB_DISABLED): 0x%lx\n", Cr);
        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        ok(Cr == CR_SUCCESS && (Status & DN_STARTED) && !(Status & DN_HAS_PROBLEM) && Problem == 0,
           "after the refused calls: status 0x%lx, problem %lu, cr 0x%lx\n", Status, Problem, Cr);
        Cr = CM_Set_DevNode_Problem(DevInst, 0, CM_SET_DEVNODE_PROBLEM_OVERRIDE);
        ok(Cr == CR_SUCCESS, "Clearing no problem failed: 0x%lx\n", Cr);

        /* A parked node keeps its problem */
        Cr = CM_Disable_DevNode(DevInst, 0);
        ok(Cr == CR_SUCCESS, "CM_Disable_DevNode failed: 0x%lx\n", Cr);
        Cr = CM_Set_DevNode_Problem(DevInst, 0, CM_SET_DEVNODE_PROBLEM_OVERRIDE);
        ok(Cr == CR_SUCCESS, "Clearing the problem of a disabled device failed: 0x%lx\n", Cr);
        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        ok(Cr == CR_SUCCESS && !(Status & DN_STARTED) && Problem == CM_PROB_DISABLED,
           "after clearing the problem of a disabled device: status 0x%lx, problem %lu, cr 0x%lx\n", Status, Problem, Cr);
        Cr = CM_Enable_DevNode(DevInst, 0);
        ok(Cr == CR_SUCCESS, "CM_Enable_DevNode failed: 0x%lx\n", Cr);
        if (WaitRunning(DevInst, "after the parked clear"))
        {
            St = Stats();
            ok(St.Initializes == 6, "%lu initializes, expected 6\n", St.Initializes);
        }
    }

    /* Other ConfigFlags bits stay as they are through a disable and an enable */
    {
        HKEY Key;

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ENUM_ROOT_KEY L"\\" ENUM_NAME L"\\0000", 0, KEY_SET_VALUE, &Key) == ERROR_SUCCESS)
        {
            SetDword(Key, L"ConfigFlags", 0x400);
            RegCloseKey(Key);
        }
        if (ChangeState(DICS_DISABLE))
        {
            DWORD Flags = 0;

            ReadConfigFlags(&Flags);
            ok(Flags == (0x400 | CONFIGFLAG_DISABLED), "ConfigFlags 0x%lx after the disable, expected 0x401\n", Flags);
            if (ChangeState(DICS_ENABLE))
            {
                WaitRunning(DevInst, "after the second DICS_ENABLE");
                ReadConfigFlags(&Flags);
                ok(Flags == 0x400, "ConfigFlags 0x%lx after the enable, expected 0x400\n", Flags);
            }
        }
    }

    /* Removing a disabled device removes its node */
    Cr = CM_Disable_DevNode(DevInst, 0);
    ok(Cr == CR_SUCCESS, "CM_Disable_DevNode failed: 0x%lx\n", Cr);
    Cr = CM_Query_And_Remove_SubTreeW(DevInst, &Veto, VetoName, ARRAYSIZE(VetoName), CM_REMOVE_NO_RESTART);
    ok(Cr == CR_SUCCESS, "CM_Query_And_Remove_SubTreeW of a disabled device failed: 0x%lx (veto %d %ls)\n",
       Cr, Veto, VetoName);
    /* The removed root device stays a leaked device node until the next boot (a known
     * limitation, see ndis_apitest): all that is asked is that it does not run again */
    Cr = CM_Locate_DevNodeW(&DevInst, (DEVINSTID_W)DEVICE_INSTANCE, CM_LOCATE_DEVNODE_NORMAL);
    if (Cr == CR_SUCCESS)
    {
        ULONG Status = 0, Problem = 0;

        Cr = CM_Get_DevNode_Status(&Status, &Problem, DevInst, 0);
        ok(Cr != CR_SUCCESS || !(Status & DN_STARTED), "The removed device is started: 0x%lx\n", Status);
    }
    St = Stats();
    ok(St.Halted == 1 && St.Initializes == 7, "The removed device was initialized again: %lu, halted %lu\n",
       St.Initializes, St.Halted);

    TestFailedDevice();

    Cleanup();
}
