/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Loading and driving the sample mini-filter for the filter manager tests
 */

#include "precomp.h"
#include <fltuser.h>

#define SERVICES_KEY L"SYSTEM\\CurrentControlSet\\Services\\"

BOOL
StartFilterManager(void)
{
    SC_HANDLE Manager, Service;
    BOOL Ret = FALSE;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
    {
        trace("OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }

    Service = OpenServiceW(Manager, L"fltmgr", SERVICE_START | SERVICE_QUERY_STATUS);
    if (Service)
    {
        Ret = StartServiceW(Service, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
        if (!Ret)
            trace("StartService(fltmgr) failed: %lu\n", GetLastError());
        CloseServiceHandle(Service);
    }
    CloseServiceHandle(Manager);
    return Ret;
}

static
BOOL
SetupInstanceKey(PCWSTR Name, PCWSTR Altitude, ULONG AttachMask)
{
    WCHAR Path[MAX_PATH], Instance[64];
    HKEY Service = NULL, Instances = NULL, Key = NULL;
    DWORD Zero = 0;
    BOOL Ret = FALSE;

    StringCbPrintfW(Path, sizeof(Path), SERVICES_KEY L"%ls", Name);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_ALL_ACCESS, &Service) != ERROR_SUCCESS)
        return FALSE;

    StringCbPrintfW(Instance, sizeof(Instance), L"%ls Instance", Name);
    if (RegSetValueExW(Service, L"AttachMask", 0, REG_DWORD, (PBYTE)&AttachMask, sizeof(AttachMask)) != ERROR_SUCCESS ||
        RegCreateKeyExW(Service, L"Instances", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Instances, NULL) != ERROR_SUCCESS ||
        RegSetValueExW(Instances, L"DefaultInstance", 0, REG_SZ, (PBYTE)Instance, (lstrlenW(Instance) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS ||
        RegCreateKeyExW(Instances, Instance, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL) != ERROR_SUCCESS ||
        RegSetValueExW(Key, L"Altitude", 0, REG_SZ, (PBYTE)Altitude, (lstrlenW(Altitude) + 1) * sizeof(WCHAR)) != ERROR_SUCCESS ||
        RegSetValueExW(Key, L"Flags", 0, REG_DWORD, (PBYTE)&Zero, sizeof(Zero)) != ERROR_SUCCESS)
    {
        goto Quit;
    }
    Ret = TRUE;

Quit:
    if (Key) RegCloseKey(Key);
    if (Instances) RegCloseKey(Instances);
    RegCloseKey(Service);
    return Ret;
}

BOOL
LoadSample(PSAMPLE Sample, PCWSTR Name, PCWSTR Altitude, ULONG AttachMask)
{
    SC_HANDLE Manager, Service;
    WCHAR Source[MAX_PATH];
    HRESULT hr;
    PWCHAR Slash;
    WCHAR Device[64];

    ZeroMemory(Sample, sizeof(*Sample));
    Sample->Control = INVALID_HANDLE_VALUE;
    StringCbCopyW(Sample->Name, sizeof(Sample->Name), Name);

    /* One image per service, the driver takes its device name from the service name */
    GetModuleFileNameW(NULL, Source, RTL_NUMBER_OF(Source));
    Slash = wcsrchr(Source, L'\\');
    if (!Slash)
        return FALSE;
    Slash[1] = UNICODE_NULL;
    StringCbCopyW(Sample->Image, sizeof(Sample->Image), Source);
    StringCbCatW(Sample->Image, sizeof(Sample->Image), Name);
    StringCbCatW(Sample->Image, sizeof(Sample->Image), L".sys");
    StringCbCatW(Source, sizeof(Source), L"fltsample.sys");
    if (!CopyFileW(Source, Sample->Image, FALSE))
    {
        skip("Can't copy %ls: %lu\n", Source, GetLastError());
        return FALSE;
    }

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
        return FALSE;

    Service = CreateServiceW(Manager, Name, Name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, Sample->Image,
                             NULL, NULL, NULL, NULL, NULL);
    if (!Service && GetLastError() == ERROR_SERVICE_EXISTS)
        Service = OpenServiceW(Manager, Name, SERVICE_ALL_ACCESS);
    CloseServiceHandle(Manager);
    if (!Service)
        return FALSE;
    CloseServiceHandle(Service);
    Sample->ServiceCreated = TRUE;

    if (!SetupInstanceKey(Name, Altitude, AttachMask))
        return FALSE;

    hr = FilterLoad(Name);
    if (FAILED(hr))
    {
        trace("FilterLoad(%ls) failed with 0x%lx\n", Name, (ULONG)hr);
        return FALSE;
    }

    StringCbPrintfW(Device, sizeof(Device), L"\\\\.\\%ls", Name);
    Sample->Control = CreateFileW(Device, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return Sample->Control != INVALID_HANDLE_VALUE;
}

BOOL
UnloadSample(PSAMPLE Sample, BOOL ExpectUnload)
{
    SC_HANDLE Manager, Service;
    HRESULT hr;
    BOOL Ret;

    if (Sample->Control != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Sample->Control);
        Sample->Control = INVALID_HANDLE_VALUE;
    }

    hr = FilterUnload(Sample->Name);
    Ret = SUCCEEDED(hr);
    if (ExpectUnload)
        ok(Ret, "FilterUnload(%ls) returned 0x%lx\n", Sample->Name, (ULONG)hr);
    if (!Ret)
        return FALSE;

    /* The driver's own report of how it ended */
    Sample->LastSetups = SampleLastRun(Sample, L"LastRunSetups");
    Sample->LastTeardownStarts = SampleLastRun(Sample, L"LastRunTeardownStarts");
    Sample->LastTeardownCompletes = SampleLastRun(Sample, L"LastRunTeardownCompletes");
    Sample->LastLive = SampleLastRun(Sample, L"LastRunLive");
    Sample->LastFiltering = SampleLastRun(Sample, L"LastRunWorkers");

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (Manager)
    {
        Service = OpenServiceW(Manager, Sample->Name, SERVICE_ALL_ACCESS);
        if (Service)
        {
            DeleteService(Service);
            CloseServiceHandle(Service);
        }
        CloseServiceHandle(Manager);
    }

    DeleteFileW(Sample->Image);
    Sample->ServiceCreated = FALSE;
    return TRUE;
}

BOOL
SampleIoctl(PSAMPLE Sample, ULONG Code, PVOID In, ULONG InSize, PVOID Out, ULONG OutSize)
{
    DWORD Returned;

    return DeviceIoControl(Sample->Control, Code, In, InSize, Out, OutSize, &Returned, NULL);
}

BOOL
SampleStats(PSAMPLE Sample, PFLTSAMPLE_STATS Stats)
{
    ZeroMemory(Stats, sizeof(*Stats));
    return SampleIoctl(Sample, FLTSAMPLE_IOCTL_GET_STATS, NULL, 0, Stats, sizeof(*Stats));
}

/* What the driver wrote into its service key when it was unloaded */
ULONG
SampleLastRun(PSAMPLE Sample, PCWSTR Value)
{
    WCHAR Path[MAX_PATH];
    HKEY Key;
    DWORD Data = 0xDEADBEEF, Size = sizeof(Data), Type;

    StringCbPrintfW(Path, sizeof(Path), SERVICES_KEY L"%ls", Sample->Name);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return 0xDEADBEEF;
    if (RegQueryValueExW(Key, Value, NULL, &Type, (PBYTE)&Data, &Size) != ERROR_SUCCESS)
        Data = 0xDEADBEEF;
    RegCloseKey(Key);
    return Data;
}

void
GetTestDirectory(PWSTR Buffer, ULONG Length)
{
    WCHAR Windows[MAX_PATH];

    GetWindowsDirectoryW(Windows, RTL_NUMBER_OF(Windows));
    StringCchPrintfW(Buffer, Length, L"%c:\\fltmgr_test", Windows[0]);
}

void
EnsureTestDirectory(void)
{
    WCHAR Directory[MAX_PATH];

    GetTestDirectory(Directory, RTL_NUMBER_OF(Directory));
    CreateDirectoryW(Directory, NULL);
}

BOOL
MakeTestFile(PCWSTR Name, PWSTR Path, ULONG Length)
{
    WCHAR Directory[MAX_PATH];

    GetTestDirectory(Directory, RTL_NUMBER_OF(Directory));
    StringCchPrintfW(Path, Length, L"%ls\\%ls", Directory, Name);
    return TRUE;
}

ULONG
CurrentFileSystem(void)
{
    WCHAR Root[4], Name[32];

    GetWindowsDirectoryW(Root, RTL_NUMBER_OF(Root));
    Root[3] = UNICODE_NULL;
    Root[2] = L'\\';
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, Name, RTL_NUMBER_OF(Name)))
        return 0;
    if (!_wcsicmp(Name, L"NTFS"))
        return FLTAPI_FSTYPE_NTFS;
    if (!_wcsnicmp(Name, L"FAT", 3))
        return FLTAPI_FSTYPE_FAT;
    return 0;
}
