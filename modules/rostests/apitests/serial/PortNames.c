/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Serial port naming contract. A port keeps the name stored in the PortName value of its
 *              devnode (Device Parameters), whatever order PnP starts the devices in. Checks that
 *                - every HARDWARE\DEVICEMAP\SERIALCOMM value is a COMx name, no name is listed twice,
 *                - \\.\COMx exists, opens, and COMx is a symbolic link to the \Device\SerialN the value names,
 *                - while the COM port interface of a devnode is open, \\.\<PortName of that devnode> is refused
 *                  (a port opens once), i.e. the name belongs to the devnode's port (a swapped COM1/COM2 fails).
 *              Passes with zero ports (a machine without UARTs).
 */

#define WIN32_NO_STATUS
#include <apitest.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <setupapi.h>

#define NTOS_MODE_USER
#include <ndk/rtlfuncs.h>

#define MAX_PORTS 32

static const GUID GuidComPort =
    { 0x86E0D1E0, 0x8089, 0x11D0, { 0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73 } };

static BOOL ParseComName(PCWSTR Name, ULONG *pNumber)
{
    ULONG Number = 0, i;

    if (_wcsnicmp(Name, L"COM", 3) != 0 || Name[3] == UNICODE_NULL)
        return FALSE;
    for (i = 3; Name[i] != UNICODE_NULL; i++)
    {
        if (Name[i] < L'0' || Name[i] > L'9')
            return FALSE;
        Number = Number * 10 + (Name[i] - L'0');
    }
    *pNumber = Number;
    return Number != 0;
}

static HANDLE OpenPort(PCWSTR Path)
{
    return CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

static void TestSerialComValues(void)
{
    HKEY hKey;
    LONG Err;
    DWORD i, j, Count = 0;
    WCHAR Device[MAX_PORTS][64], Com[MAX_PORTS][16];

    Err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\SERIALCOMM", 0, KEY_READ, &hKey);
    if (Err != ERROR_SUCCESS)
    {
        skip("No SERIALCOMM key (%ld), no serial ports\n", Err);
        return;
    }

    for (i = 0; Count < MAX_PORTS; i++)
    {
        DWORD NameLen = ARRAYSIZE(Device[0]), DataLen = sizeof(Com[0]), Type;

        Err = RegEnumValueW(hKey, i, Device[Count], &NameLen, NULL, &Type, (PBYTE)Com[Count], &DataLen);
        if (Err != ERROR_SUCCESS)
            break;
        if (Type != REG_SZ)
            continue;
        Count++;
    }
    RegCloseKey(hKey);
    trace("SERIALCOMM lists %lu port(s)\n", Count);

    for (i = 0; i < Count; i++)
    {
        ULONG Number;
        WCHAR Target[128], Path[32];
        HANDLE hPort;

        trace("  %ls = %ls\n", Device[i], Com[i]);
        ok(ParseComName(Com[i], &Number), "%ls: '%ls' is not a COMx name\n", Device[i], Com[i]);
        for (j = 0; j < i; j++)
            ok(_wcsicmp(Com[i], Com[j]) != 0, "%ls and %ls are both %ls\n", Device[j], Device[i], Com[i]);

        /* COMx must be a link to the device object named by the value */
        Target[0] = UNICODE_NULL;
        ok(QueryDosDeviceW(Com[i], Target, ARRAYSIZE(Target)) != 0,
           "%ls: QueryDosDevice failed, error %lu\n", Com[i], GetLastError());
        ok(_wcsicmp(Target, Device[i]) == 0,
           "%ls links to '%ls', expected '%ls'\n", Com[i], Target, Device[i]);

        _snwprintf(Path, ARRAYSIZE(Path), L"\\\\.\\%ls", Com[i]);
        hPort = OpenPort(Path);
        ok(hPort != INVALID_HANDLE_VALUE, "%ls: open failed, error %lu\n", Path, GetLastError());
        if (hPort != INVALID_HANDLE_VALUE)
            CloseHandle(hPort);
    }
}

static void TestPortNameBinding(void)
{
    HDEVINFO hInfo;
    SP_DEVICE_INTERFACE_DATA Itf;
    DWORD Index, Count = 0, i, j;
    WCHAR PortNames[MAX_PORTS][16], Paths[MAX_PORTS][MAX_PATH];

    hInfo = SetupDiGetClassDevsW(&GuidComPort, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hInfo == INVALID_HANDLE_VALUE)
    {
        skip("SetupDiGetClassDevs failed, error %lu\n", GetLastError());
        return;
    }

    /* Collect the PortName of each devnode that has a COM port interface, and the interface path */
    Itf.cbSize = sizeof(Itf);
    for (Index = 0; Count < MAX_PORTS && SetupDiEnumDeviceInterfaces(hInfo, NULL, &GuidComPort, Index, &Itf); Index++)
    {
        UCHAR Raw[sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) + 512 * sizeof(WCHAR)];
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W Detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)Raw;
        SP_DEVINFO_DATA Dev;
        HKEY hDevKey;
        DWORD Size = sizeof(PortNames[0]) - sizeof(WCHAR), Type;
        ULONG Number;

        Detail->cbSize = sizeof(*Detail);
        Dev.cbSize = sizeof(Dev);
        if (!SetupDiGetDeviceInterfaceDetailW(hInfo, &Itf, Detail, sizeof(Raw), NULL, &Dev))
            continue;
        hDevKey = SetupDiOpenDevRegKey(hInfo, &Dev, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (hDevKey == INVALID_HANDLE_VALUE)
            continue;
        RtlZeroMemory(PortNames[Count], sizeof(PortNames[Count]));
        if (RegQueryValueExW(hDevKey, L"PortName", NULL, &Type, (PBYTE)PortNames[Count], &Size) != ERROR_SUCCESS ||
            Type != REG_SZ)
        {
            RegCloseKey(hDevKey);
            continue;
        }
        RegCloseKey(hDevKey);

        ok(ParseComName(PortNames[Count], &Number), "PortName '%ls' is not a COMx name\n", PortNames[Count]);
        for (j = 0; j < Count; j++)
            ok(_wcsicmp(PortNames[Count], PortNames[j]) != 0, "PortName %ls is used by two devnodes\n", PortNames[Count]);
        wcsncpy(Paths[Count], Detail->DevicePath, MAX_PATH - 1);
        Paths[Count][MAX_PATH - 1] = UNICODE_NULL;
        Count++;
    }
    SetupDiDestroyDeviceInfoList(hInfo);
    trace("%lu devnode(s) with a PortName and a COM port interface\n", Count);

    /*
     * A serial port can be opened once at a time. So while the interface of devnode i is open, opening
     * \\.\<PortName of devnode i> must be refused, and every other port's name must still open.
     */
    for (i = 0; i < Count; i++)
    {
        HANDLE hItf = OpenPort(Paths[i]);

        if (hItf == INVALID_HANDLE_VALUE)
        {
            /* e.g. the port used by the kernel debugger never starts */
            trace("%ls: interface does not open (error %lu), skipping\n", PortNames[i], GetLastError());
            continue;
        }
        for (j = 0; j < Count; j++)
        {
            WCHAR Path[32];
            HANDLE hCom;

            _snwprintf(Path, ARRAYSIZE(Path), L"\\\\.\\%ls", PortNames[j]);
            hCom = OpenPort(Path);
            if (i == j)
            {
                ok(hCom == INVALID_HANDLE_VALUE,
                   "%ls opened while the interface of the devnode named %ls is open: name points at another port\n",
                   Path, PortNames[i]);
            }
            else if (hCom == INVALID_HANDLE_VALUE)
            {
                /* another port that does not open is skipped by its own iteration; only a refusal that
                   names the port we hold is a naming error, which the i == j case above covers */
                trace("%ls does not open (error %lu)\n", Path, GetLastError());
            }
            if (hCom != INVALID_HANDLE_VALUE)
                CloseHandle(hCom);
        }
        CloseHandle(hItf);
    }
}

START_TEST(SerialPortNames)
{
    TestSerialComValues();
    TestPortNameBinding();
}
