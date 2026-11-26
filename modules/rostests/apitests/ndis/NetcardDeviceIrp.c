/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Requests that a network adapter's device object does not serve are refused, not asserted
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The device object of an adapter (the device of the miniport's driver, FILE_DEVICE_PHYSICAL_NETCARD) can be opened
 * by the name of its physical device object (\Device\0000001e and the like); the file operations on the handle reach
 * the NDIS library's dispatch routine, which serves only create/close/cleanup, PnP, shutdown, device control and
 * power. Every other request must end with an error status (a checked kernel used to stop in an assertion).
 * The adapters are the present devices of the network class. Windows: not measured (verify on the Windows reference:
 * the same calls on the first adapter's physical device object name).
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <winioctl.h>
#include <winreg.h>
#include <cfgmgr32.h>
#include <winuser.h>
#include <setupapi.h>

static const GUID NetClass = { 0x4D36E972, 0xE325, 0x11CE, { 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18 } };

static
VOID
TestAdapter(PCWSTR Path)
{
    UNICODE_STRING PathString;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;
    union
    {
        FILE_STANDARD_INFORMATION Standard;
        FILE_END_OF_FILE_INFORMATION EndOfFile;
    } Info;
    UCHAR Buffer[16];
    LARGE_INTEGER Offset;

    RtlInitUnicodeString(&PathString, Path);
    InitializeObjectAttributes(&Attributes, &PathString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_READ_DATA | FILE_WRITE_DATA |
                                 SYNCHRONIZE,
                        &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
    {
        skip("%ls: open failed with 0x%08lx\n", Path, Status);
        return;
    }

    trace("%ls: sending requests\n", Path);

    Status = NtQueryInformationFile(Handle, &Iosb, &Info.Standard, sizeof(Info.Standard), FileStandardInformation);
    ok(!NT_SUCCESS(Status), "%ls: NtQueryInformationFile succeeded, 0x%08lx\n", Path, Status);
    ok(Status != STATUS_PENDING, "%ls: NtQueryInformationFile is pending\n", Path);

    Info.EndOfFile.EndOfFile.QuadPart = 0;
    Status = NtSetInformationFile(Handle, &Iosb, &Info.EndOfFile, sizeof(Info.EndOfFile), FileEndOfFileInformation);
    ok(!NT_SUCCESS(Status), "%ls: NtSetInformationFile succeeded, 0x%08lx\n", Path, Status);
    ok(Status != STATUS_PENDING, "%ls: NtSetInformationFile is pending\n", Path);

    Status = NtFlushBuffersFile(Handle, &Iosb);
    ok(!NT_SUCCESS(Status), "%ls: NtFlushBuffersFile succeeded, 0x%08lx\n", Path, Status);
    ok(Status != STATUS_PENDING, "%ls: NtFlushBuffersFile is pending\n", Path);

    Offset.QuadPart = 0;
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtReadFile(Handle, NULL, NULL, NULL, &Iosb, Buffer, sizeof(Buffer), &Offset, NULL);
    ok(!NT_SUCCESS(Status), "%ls: NtReadFile succeeded, 0x%08lx\n", Path, Status);
    ok(Status != STATUS_PENDING, "%ls: NtReadFile is pending\n", Path);

    Status = NtWriteFile(Handle, NULL, NULL, NULL, &Iosb, Buffer, sizeof(Buffer), &Offset, NULL);
    ok(!NT_SUCCESS(Status), "%ls: NtWriteFile succeeded, 0x%08lx\n", Path, Status);
    ok(Status != STATUS_PENDING, "%ls: NtWriteFile is pending\n", Path);

    NtClose(Handle);
}

START_TEST(NetcardDeviceIrp)
{
    HDEVINFO DeviceSet;
    SP_DEVINFO_DATA DeviceData;
    WCHAR Name[MAX_PATH];
    DWORD Index, Tested = 0;

    DeviceSet = SetupDiGetClassDevsW(&NetClass, NULL, NULL, DIGCF_PRESENT);
    ok(DeviceSet != INVALID_HANDLE_VALUE, "SetupDiGetClassDevsW failed with %lu\n", GetLastError());
    if (DeviceSet == INVALID_HANDLE_VALUE)
        return;

    DeviceData.cbSize = sizeof(DeviceData);
    for (Index = 0; SetupDiEnumDeviceInfo(DeviceSet, Index, &DeviceData); Index++)
    {
        ULONG Length = sizeof(Name);

        /* (SetupDiGetDeviceRegistryProperty gives the instance id for this property) */
        if (CM_Get_DevNode_Registry_PropertyW(DeviceData.DevInst, CM_DRP_PHYSICAL_DEVICE_OBJECT_NAME, NULL, Name,
                                              &Length, 0) != CR_SUCCESS)
        {
            skip("device %lu: no physical device object name\n", Index);
            continue;
        }
        TestAdapter(Name);
        Tested++;
    }

    if (Tested == 0)
        skip("no network adapter present\n");
    SetupDiDestroyDeviceInfoList(DeviceSet);
}
