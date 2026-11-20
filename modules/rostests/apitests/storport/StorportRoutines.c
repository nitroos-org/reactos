/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Storport routines a miniport calls: busy, pause, resume, registry, synchronization,
 *              performance counter, event log, unit attributes, state change
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The miniport is modules/rostests/drivers/storest, a virtual miniport with a RAM disk that the test
 * installs as a root-enumerated device. Its control commands (vendor CDB 0xC0, sent as SCSI pass
 * through to the disk) make it call the routine under test from inside the miniport.
 */

#include <apitest.h>

#include <stdlib.h>
#include <winreg.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <ntddstor.h>
#include <cfgmgr32.h>
#include <shlwapi.h>

#include "storest.h"

#define DISPATCH_LEVEL 2

#define SCSI_CLASS_GUID     L"{4D36E97B-E325-11CE-BFC1-08002BE10318}"
#define ENUM_ROOT_KEY       L"SYSTEM\\CurrentControlSet\\Enum\\Root"
#define SERVICE_KEY         L"SYSTEM\\CurrentControlSet\\Services\\storest"

#define STOR_STATUS_SUCCESS             0x00000000
#define STOR_STATUS_UNSUCCESSFUL        0xC1000001
#define STOR_STATUS_INVALID_PARAMETER   0xC1000006
#define STOR_STATUS_UNSUPPORTED_VERSION 0xC100000B

typedef struct
{
    SCSI_PASS_THROUGH_DIRECT Spt;
    DWORD Padding;
} SPT;

static HANDLE Disk = INVALID_HANDLE_VALUE;

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
Install(void)
{
    WCHAR Source[MAX_PATH], Destination[MAX_PATH], HardwareId[32];
    PWSTR Slash;
    HKEY Key;
    DEVINST Root;

    GetModuleFileNameW(NULL, Source, MAX_PATH);
    Slash = wcsrchr(Source, L'\\');
    lstrcpyW(Slash + 1, L"storest.sys");
    GetSystemDirectoryW(Destination, MAX_PATH);
    lstrcatW(Destination, L"\\drivers\\storest.sys");
    if (!CopyFileW(Source, Destination, FALSE))
    {
        skip("Cannot copy %ls: %lu\n", Source, GetLastError());
        return FALSE;
    }

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL) != ERROR_SUCCESS)
    {
        skip("Cannot create the service key\n");
        return FALSE;
    }
    SetDword(Key, L"Type", 1);
    SetDword(Key, L"Start", 3);
    SetDword(Key, L"ErrorControl", 0);
    SetString(Key, L"ImagePath", REG_EXPAND_SZ, L"system32\\drivers\\storest.sys");
    RegCloseKey(Key);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, ENUM_ROOT_KEY L"\\STORTEST\\0000", 0, NULL, 0, KEY_ALL_ACCESS,
                        NULL, &Key, NULL) != ERROR_SUCCESS)
    {
        skip("Cannot create the device key\n");
        return FALSE;
    }
    ZeroMemory(HardwareId, sizeof(HardwareId));
    lstrcpyW(HardwareId, L"ROOT\\STORTEST");
    RegSetValueExW(Key, L"HardwareID", 0, REG_MULTI_SZ, (const BYTE *)HardwareId,
                   (lstrlenW(HardwareId) + 2) * sizeof(WCHAR));
    SetString(Key, L"Service", REG_SZ, L"storest");
    SetString(Key, L"Class", REG_SZ, L"SCSIAdapter");
    SetString(Key, L"ClassGUID", REG_SZ, SCSI_CLASS_GUID);
    SetString(Key, L"DeviceDesc", REG_SZ, L"Storport test miniport");
    SetDword(Key, L"ConfigFlags", 0);
    RegCloseKey(Key);

    if (CM_Locate_DevNodeW(&Root, NULL, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
        CM_Reenumerate_DevNode(Root, CM_REENUMERATE_SYNCHRONOUS);
    return TRUE;
}

/* The RAM disk, found by its vendor string, waited for up to 30 s */
static
HANDLE
FindDisk(void)
{
    DWORD Start = GetTickCount();

    do
    {
        WCHAR Name[40];
        ULONG Index;

        for (Index = 0; Index < 32; Index++)
        {
            HANDLE File;
            STORAGE_PROPERTY_QUERY Query = { StorageDeviceProperty, PropertyStandardQuery };
            UCHAR Buffer[512];
            DWORD Returned;

            wsprintfW(Name, L"\\\\.\\PhysicalDrive%lu", Index);
            File = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
            if (File == INVALID_HANDLE_VALUE)
                continue;
            if (DeviceIoControl(File, IOCTL_STORAGE_QUERY_PROPERTY, &Query, sizeof(Query), Buffer, sizeof(Buffer),
                                &Returned, NULL))
            {
                PSTORAGE_DEVICE_DESCRIPTOR Desc = (PSTORAGE_DEVICE_DESCRIPTOR)Buffer;

                if (Desc->VendorIdOffset != 0 && !strncmp((PCSTR)Buffer + Desc->VendorIdOffset, "NITROTST", 8))
                    return File;
            }
            CloseHandle(File);
        }
        Sleep(500);
    } while (GetTickCount() - Start < 30000);

    return INVALID_HANDLE_VALUE;
}

/* Sends control command Sub; Data goes in and out */
static
BOOL
Ctl(UCHAR Sub, ULONG Arg, UCHAR B6, UCHAR B7, STOREST_CONTROL *Data)
{
    SPT Spt;
    DWORD Returned;
    OVERLAPPED Ov = { 0 };
    BOOL Ok;

    ZeroMemory(&Spt, sizeof(Spt));
    Spt.Spt.Length = sizeof(Spt.Spt);
    Spt.Spt.CdbLength = 10;
    Spt.Spt.DataIn = SCSI_IOCTL_DATA_IN;
    Spt.Spt.DataTransferLength = sizeof(*Data);
    Spt.Spt.DataBuffer = Data;
    Spt.Spt.TimeOutValue = 30;
    Spt.Spt.Cdb[0] = 0xC0;
    Spt.Spt.Cdb[1] = Sub;
    Spt.Spt.Cdb[2] = (UCHAR)(Arg >> 24);
    Spt.Spt.Cdb[3] = (UCHAR)(Arg >> 16);
    Spt.Spt.Cdb[4] = (UCHAR)(Arg >> 8);
    Spt.Spt.Cdb[5] = (UCHAR)Arg;
    Spt.Spt.Cdb[6] = B6;
    Spt.Spt.Cdb[7] = B7;

    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Ok = DeviceIoControl(Disk, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Spt, sizeof(Spt), &Spt, sizeof(Spt), &Returned, &Ov);
    if (!Ok && GetLastError() == ERROR_IO_PENDING)
        Ok = GetOverlappedResult(Disk, &Ov, &Returned, TRUE);
    CloseHandle(Ov.hEvent);
    return Ok && Spt.Spt.ScsiStatus == 0;
}

static
HANDLE
StartRead(OVERLAPPED *Ov, PVOID Buffer, ULONG Sector)
{
    ZeroMemory(Ov, sizeof(*Ov));
    Ov->Offset = Sector * 512;
    Ov->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ReadFile(Disk, Buffer, 512, NULL, Ov);
    return Ov->hEvent;
}

static
DWORD
TimedRead(void)
{
    OVERLAPPED Ov;
    PVOID Buffer = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    DWORD Start = GetTickCount(), Returned;
    HANDLE Event = StartRead(&Ov, Buffer, 1);

    WaitForSingleObject(Event, 20000);
    GetOverlappedResult(Disk, &Ov, &Returned, TRUE);
    CloseHandle(Event);
    VirtualFree(Buffer, 0, MEM_RELEASE);
    return GetTickCount() - Start;
}

/* The values the miniport reads while it starts (it needs them before the test disk is there) */
static
void
WriteRegistryValues(void)
{
    HKEY Key;
    ULONG Index;

    RegCreateKeyExW(HKEY_LOCAL_MACHINE, SERVICE_KEY L"\\Parameters\\Device", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    SetDword(Key, L"TestDword", 0x12345678);
    SetString(Key, L"TestString", REG_SZ, L"hello");
    RegCloseKey(Key);
    for (Index = 0; Index < 16; Index++)
    {
        WCHAR Path[100];

        wsprintfW(Path, SERVICE_KEY L"\\Parameters\\Device%lu", Index);
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
        SetDword(Key, L"PerAdapter", 0xA0 + Index);
        RegCloseKey(Key);
    }
}

static
void
Test_Registry(void)
{
    STOREST_CONTROL Data;
    SCSI_ADDRESS Address;
    DWORD Returned;

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_REGISTRY, 0, 0, 0, &Data), "registry control command failed\n");
    ok(Data.Value[15] == 1, "StorPortAllocateRegistryBuffer failed\n");
    ok(Data.Value[14] == 1, "a second registry buffer was granted\n");
    ok(Data.Value[13] == 1, "no registry buffer after the free\n");
    ok(Data.Status[0] == 1 && Data.Value[0] == 4 && Data.Value[8] == 0x12345678,
       "DWORD: result %lu length %lu value 0x%lx\n", Data.Status[0], Data.Value[0], Data.Value[8]);
    ok(Data.Status[1] == 1 && Data.Value[1] == 6 && !strcmp(Data.Text, "hello"),
       "string: result %lu length %lu '%s'\n", Data.Status[1], Data.Value[1], Data.Text);
    ok(Data.Status[2] == 0 && Data.Value[2] == 6, "too small: result %lu length %lu\n", Data.Status[2], Data.Value[2]);
    ok(Data.Status[3] == 0 && Data.Value[3] == 0, "missing: result %lu length %lu\n", Data.Status[3], Data.Value[3]);
    ok(Data.Status[4] == 0, "a DWORD was read as a string\n");

    ZeroMemory(&Address, sizeof(Address));
    ok(DeviceIoControl(Disk, IOCTL_SCSI_GET_ADDRESS, NULL, 0, &Address, sizeof(Address), &Returned, NULL),
       "IOCTL_SCSI_GET_ADDRESS failed\n");
    ok(Data.Status[5] == 1 && Data.Value[9] == 0xA0 + Address.PortNumber,
       "adapter %u: result %lu value 0x%lx\n", Address.PortNumber, Data.Status[5], Data.Value[9]);
}

static
void
Test_Sync(void)
{
    STOREST_CONTROL Data;

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_SYNC, 0, 0, 0, &Data), "sync control command failed\n");
    ok(Data.Status[0] == 1, "StorPortSynchronizeAccess did not return the routine's value\n");
    ok(Data.Value[0] == 0x5A5A, "the routine did not run: 0x%lx\n", Data.Value[0]);
    ok(Data.Value[1] >= DISPATCH_LEVEL, "the routine ran at IRQL %lu\n", Data.Value[1]);
}

static
void
Test_Perf(void)
{
    STOREST_CONTROL Data;

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_PERF, 0, 0, 0, &Data), "perf control command failed\n");
    ok(Data.Status[0] == STOR_STATUS_SUCCESS, "counter: 0x%lx\n", Data.Status[0]);
    ok(Data.Status[1] == STOR_STATUS_SUCCESS, "counter without frequency: 0x%lx\n", Data.Status[1]);
    ok(Data.Status[2] == STOR_STATUS_INVALID_PARAMETER, "counter without a destination: 0x%lx\n", Data.Status[2]);
    ok(Data.Value[0] == 1, "the counter did not advance\n");
    ok(Data.Value[1] == 1, "no frequency\n");
    ok(Data.Status[3] == STOR_STATUS_SUCCESS, "StorPortGetStartIoPerfParams: 0x%lx\n", Data.Status[3]);
    ok(Data.Status[4] == STOR_STATUS_INVALID_PARAMETER, "too small a structure: 0x%lx\n", Data.Status[4]);
    ok(Data.Status[5] == STOR_STATUS_INVALID_PARAMETER, "no SRB: 0x%lx\n", Data.Status[5]);
}

static
void
Test_Misc(void)
{
    STOREST_CONTROL Data;

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_MISC, 0, 0, 0, &Data), "misc control command failed\n");
    ok(Data.Status[0] == STOR_STATUS_SUCCESS, "StorPortLogSystemEvent: 0x%lx\n", Data.Status[0]);
    ok(Data.Status[1] == STOR_STATUS_UNSUPPORTED_VERSION, "log, newer revision: 0x%lx\n", Data.Status[1]);
    ok(Data.Status[2] == STOR_STATUS_INVALID_PARAMETER, "log, no details: 0x%lx\n", Data.Status[2]);
    ok(Data.Status[3] == STOR_STATUS_SUCCESS, "StorPortSetUnitAttributes: 0x%lx\n", Data.Status[3]);
    ok(Data.Status[4] == STOR_STATUS_INVALID_PARAMETER, "attributes, no such unit: 0x%lx\n", Data.Status[4]);
    ok(Data.Status[5] == STOR_STATUS_INVALID_PARAMETER, "attributes, reserved bit: 0x%lx\n", Data.Status[5]);
    ok(Data.Status[6] == STOR_STATUS_INVALID_PARAMETER, "MSI lock without messages: 0x%lx\n", Data.Status[6]);
    ok(Data.Status[7] == STOR_STATUS_INVALID_PARAMETER, "MSI unlock without messages: 0x%lx\n", Data.Status[7]);
}

static
void
Test_State(void)
{
    STOREST_CONTROL Data;
    DWORD Start;

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_STATE, 0, 0, 0, &Data), "state control command failed\n");
    ok(Data.Status[0] == STOR_STATUS_SUCCESS, "StorPortStateChangeDetected: 0x%lx\n", Data.Status[0]);
    ok(Data.Status[1] == STOR_STATUS_UNSUCCESSFUL || Data.Status[1] == STOR_STATUS_SUCCESS,
       "second call: 0x%lx\n", Data.Status[1]);
    ok(Data.Status[2] == STOR_STATUS_INVALID_PARAMETER, "no entity: 0x%lx\n", Data.Status[2]);

    Start = GetTickCount();
    do
    {
        ZeroMemory(&Data, sizeof(Data));
        Ctl(STOREST_STATE_DONE, 0, 0, 0, &Data);
        if (Data.Value[0])
            break;
        Sleep(100);
    } while (GetTickCount() - Start < 10000);
    ok(Data.Value[0] == 1, "the state change callback was not called\n");
}

static
void
Test_Busy(void)
{
    STOREST_CONTROL Data;
    OVERLAPPED Ov[6];
    HANDLE Events[6];
    PUCHAR Buffer = VirtualAlloc(NULL, 6 * 4096, MEM_COMMIT, PAGE_READWRITE);
    ULONG i;
    ULONGLONG Freq, First, Last;

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_SET_DELAY, 400, 0, 0, &Data), "set delay failed\n");
    ok(Ctl(STOREST_ARM_BUSY, 2, 0, 0, &Data), "arm busy failed\n");

    /* The first read calls StorPortBusy and stays outstanding for 400 ms; the five after it, sent
     * while it is, are held until it completes */
    Events[0] = StartRead(&Ov[0], Buffer, 1);
    Sleep(150);
    for (i = 1; i < 6; i++)
        Events[i] = StartRead(&Ov[i], Buffer + i * 4096, 1 + i);
    ok(WaitForMultipleObjects(6, Events, TRUE, 20000) == WAIT_OBJECT_0, "the reads did not all complete\n");
    for (i = 0; i < 6; i++)
        CloseHandle(Events[i]);

    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_GET_LOG, 0, 0, 0, &Data), "get log failed\n");
    ok(Data.Value[0] == 6, "%lu reads started, expected 6\n", Data.Value[0]);
    Freq = Data.Value[15];
    First = ((ULONGLONG)Data.Value[2] << 32) | Data.Value[1];
    Last = ((ULONGLONG)Data.Value[4] << 32) | Data.Value[3];
    ok(Freq != 0, "no frequency\n");
    if (Freq != 0)
        ok(Last - First >= Freq * 250 / 1000, "the last read started %I64u ms after the first, expected 250 or more\n",
           (Last - First) * 1000 / Freq);

    ZeroMemory(&Data, sizeof(Data));
    Ctl(STOREST_SET_DELAY, 0, 0, 0, &Data);
    VirtualFree(Buffer, 0, MEM_RELEASE);
}

static
void
Test_Pause(void)
{
    STOREST_CONTROL Data;
    DWORD Elapsed;

    /* Paused for 5 s, the miniport calls StorPortResume after 1 s */
    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_PAUSE, 5, 10, 0, &Data), "pause control command failed\n");
    ok(Data.Status[0] == 1, "StorPortPause failed\n");
    Elapsed = TimedRead();
    ok(Elapsed >= 700, "the read finished after %lu ms, the adapter was paused\n", Elapsed);
    ok(Elapsed < 3500, "the read finished after %lu ms, StorPortResume did not release it\n", Elapsed);
    trace("paused, resumed after 1 s: read took %lu ms\n", Elapsed);

    /* Paused for 2 s and never resumed: the time-out ends it */
    ZeroMemory(&Data, sizeof(Data));
    ok(Ctl(STOREST_PAUSE, 2, 0, 0, &Data), "pause control command failed\n");
    Elapsed = TimedRead();
    ok(Elapsed >= 1500, "the read finished after %lu ms, the adapter was paused\n", Elapsed);
    ok(Elapsed < 5000, "the read finished after %lu ms, the pause did not time out\n", Elapsed);
    trace("paused for 2 s: read took %lu ms\n", Elapsed);

    Elapsed = TimedRead();
    ok(Elapsed < 500, "a read after the pause took %lu ms\n", Elapsed);
}

START_TEST(StorportRoutines)
{
    /* STORTEST_STAGE=n runs the first n steps only (1 = install the miniport, 2 = find the disk, 3.. = the tests in order) */
    int Stage = 99;
    CHAR Value[16];

    if (GetEnvironmentVariableA("STORTEST_STAGE", Value, sizeof(Value)))
        Stage = atoi(Value);

    WriteRegistryValues();
    if (!Install() || Stage < 2)
        return;

    Disk = FindDisk();
    if (Disk == INVALID_HANDLE_VALUE)
    {
        ok(0, "the test disk did not appear\n");
        return;
    }
    trace("the test disk is there\n");

    if (Stage >= 3) Test_Registry();
    if (Stage >= 4) Test_Sync();
    if (Stage >= 5) Test_Perf();
    if (Stage >= 6) Test_Misc();
    if (Stage >= 7) Test_State();
    if (Stage >= 8) Test_Busy();
    if (Stage >= 9) Test_Pause();

    CloseHandle(Disk);
}
