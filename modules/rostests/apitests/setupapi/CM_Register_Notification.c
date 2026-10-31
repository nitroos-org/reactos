/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for CM_Register_Notification and CM_Unregister_Notification
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected results are those of Windows 10 22H2 (build 19045). That Windows calls the callback only when a
 * device changes, never at registration, which is why the callbacks are counted: a registration that
 * delivers nothing cannot be told from one that works by the results alone.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <cfgmgr32.h>

typedef CONFIGRET (WINAPI *FN_Register)(PCM_NOTIFY_FILTER, PVOID, PCM_NOTIFY_CALLBACK, PHCMNOTIFICATION);
typedef CONFIGRET (WINAPI *FN_Unregister)(HCMNOTIFICATION);

static FN_Register pRegister;
static FN_Unregister pUnregister;
static volatile LONG g_Calls;
static const GUID DiskGuid = {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};

static DWORD CALLBACK
Callback(HCMNOTIFICATION hNotify, PVOID Context, CM_NOTIFY_ACTION Action, PCM_NOTIFY_EVENT_DATA Data, DWORD Size)
{
    InterlockedIncrement(&g_Calls);
    return ERROR_SUCCESS;
}

/*
 * The plug and play manager of ReactOS delivers the device interface arrivals and removals one after the other, and
 * after the start of the system it still has a queue of them to deliver; a registration made then gets those. Nothing
 * is delivered on Windows, which delivers each event as it happens: wait until the calls stop.
 */
static VOID
DrainEvents(VOID)
{
    CM_NOTIFY_FILTER Filter;
    HCMNOTIFICATION Handle = NULL;
    LONG Last;
    ULONG Quiet = 0, Total = 0;

    memset(&Filter, 0, sizeof(Filter));
    Filter.cbSize = sizeof(Filter);
    Filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
    Filter.Flags = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;
    if (pRegister(&Filter, NULL, Callback, &Handle) != CR_SUCCESS)
        return;

    g_Calls = 0;
    while (Quiet < 6 && Total < 240)
    {
        Last = g_Calls;
        Sleep(500);
        Total++;
        Quiet = (g_Calls == Last) ? Quiet + 1 : 0;
    }
    pUnregister(Handle);
}

/* Register with a filter, expect a result; a handle comes back only with success, and is given back */
static VOID
Check(PCSTR Name, PCM_NOTIFY_FILTER Filter, CONFIGRET Expected)
{
    HCMNOTIFICATION Handle = (HCMNOTIFICATION)(ULONG_PTR)0x1234;
    CONFIGRET cr;

    cr = pRegister(Filter, NULL, Callback, &Handle);
    ok(cr == Expected, "%s: cr = 0x%lx, expected 0x%lx\n", Name, cr, Expected);
    if (cr == CR_SUCCESS)
    {
        ok(Handle != NULL && Handle != (HCMNOTIFICATION)(ULONG_PTR)0x1234, "%s: handle %p\n", Name, Handle);
        cr = pUnregister(Handle);
        ok(cr == CR_SUCCESS, "%s: unregister cr = 0x%lx\n", Name, cr);
    }
    else
    {
        ok(Handle == (HCMNOTIFICATION)(ULONG_PTR)0x1234 || Handle == NULL, "%s: handle %p on failure\n", Name, Handle);
    }
}

static VOID
InitFilter(PCM_NOTIFY_FILTER Filter, CM_NOTIFY_FILTER_TYPE Type, DWORD Flags)
{
    memset(Filter, 0, sizeof(*Filter));
    Filter->cbSize = sizeof(*Filter);
    Filter->FilterType = Type;
    Filter->Flags = Flags;
}

START_TEST(CM_Register_Notification)
{
    HMODULE hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    CM_NOTIFY_FILTER Filter, F;
    HCMNOTIFICATION Handle = (HCMNOTIFICATION)(ULONG_PTR)0x1234, Handle2;
    CONFIGRET cr;
    HANDLE hFile;
    WCHAR Id[MAX_DEVICE_ID_LEN];
    DEVINST Root;

    pRegister = (FN_Register)GetProcAddress(hCfgMgr, "CM_Register_Notification");
    pUnregister = (FN_Unregister)GetProcAddress(hCfgMgr, "CM_Unregister_Notification");
    if (!pRegister || !pUnregister)
    {
        skip("CM_Register_Notification is not exported\n");
        return;
    }

    DrainEvents();

    ok(sizeof(CM_NOTIFY_FILTER) == 416, "sizeof(CM_NOTIFY_FILTER) = %lu\n", (ULONG)sizeof(CM_NOTIFY_FILTER));
    InitFilter(&Filter, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, 0);
    Filter.u.DeviceInterface.ClassGuid = DiskGuid;

    /* Pointers */
    cr = pRegister(NULL, NULL, Callback, &Handle);
    ok(cr == CR_INVALID_DATA, "NULL filter: cr = 0x%lx\n", cr);
    cr = pRegister(&Filter, NULL, NULL, &Handle);
    ok(cr == CR_INVALID_DATA, "NULL callback: cr = 0x%lx\n", cr);
    cr = pRegister(&Filter, NULL, Callback, NULL);
    ok(cr == CR_FAILURE, "NULL result: cr = 0x%lx\n", cr);

    /* Size, type, flags (the reserved field is not looked at) */
    F = Filter; F.cbSize = 0;                 Check("cbSize 0", &F, CR_INVALID_DATA);
    F = Filter; F.cbSize = sizeof(F) - 1;     Check("cbSize - 1", &F, CR_INVALID_DATA);
    F = Filter; F.cbSize = sizeof(F) + 8;     Check("cbSize + 8", &F, CR_INVALID_DATA);
    F = Filter; F.FilterType = CM_NOTIFY_FILTER_TYPE_MAX;  Check("type max", &F, CR_INVALID_DATA);
    F = Filter; F.FilterType = 99;            Check("type 99", &F, CR_INVALID_DATA);
    F = Filter; F.Flags = 4;                  Check("flags 4", &F, CR_INVALID_DATA);
    F = Filter; F.Flags = 0x80000000;         Check("flags 0x80000000", &F, CR_INVALID_DATA);
    F = Filter; F.Reserved = 1;               Check("reserved 1", &F, CR_SUCCESS);

    /* A device interface class, any class (the flag, with no class given) */
    Check("interface class", &Filter, CR_SUCCESS);
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, 0);
    Check("no class", &F, CR_SUCCESS);
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES);
    Check("all classes", &F, CR_SUCCESS);
    F.u.DeviceInterface.ClassGuid = DiskGuid;
    Check("all classes and a class", &F, CR_INVALID_DATA);
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES);
    Check("interface, all instances", &F, CR_INVALID_DATA);
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, 3);
    Check("interface, both flags", &F, CR_INVALID_DATA);

    /* A device handle: of a file, a directory or a volume */
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE, 0);
    Check("NULL handle", &F, CR_INVALID_DATA);
    F.u.DeviceHandle.hTarget = (HANDLE)(ULONG_PTR)0x4444;
    Check("bad handle", &F, CR_INVALID_DATA);
    F.u.DeviceHandle.hTarget = GetCurrentProcess();
    Check("process handle", &F, CR_INVALID_DATA);
    F.u.DeviceHandle.hTarget = CreateEventW(NULL, FALSE, FALSE, NULL);
    Check("event handle", &F, CR_INVALID_DATA);
    CloseHandle(F.u.DeviceHandle.hTarget);
    hFile = CreateFileW(L"\\\\.\\C:", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "opening the volume failed with %lu\n", GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
    {
        F.u.DeviceHandle.hTarget = hFile;
        Check("volume handle", &F, CR_SUCCESS);
        F.Flags = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;
        Check("volume handle, all classes", &F, CR_INVALID_DATA);
        F.Flags = CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES;
        Check("volume handle, all instances", &F, CR_INVALID_DATA);
        CloseHandle(hFile);
    }
    hFile = CreateFileW(L"C:\\", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE, 0);
        F.u.DeviceHandle.hTarget = hFile;
        Check("directory handle", &F, CR_SUCCESS);
        CloseHandle(hFile);
    }

    /* A device instance: one that exists, or all of them (the flag, with no instance given) */
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0);
    Check("no instance", &F, CR_FAILURE);
    wcscpy(F.u.DeviceInstance.InstanceId, L"ROOT\\NOSUCHDEVICE\\0000");
    Check("instance that does not exist", &F, CR_FAILURE);
    if (CM_Locate_DevNodeW(&Root, NULL, 0) == CR_SUCCESS &&
        CM_Get_Device_IDW(Root, Id, ARRAYSIZE(Id), 0) == CR_SUCCESS)
    {
        wcscpy(F.u.DeviceInstance.InstanceId, Id);
        Check("root instance", &F, CR_SUCCESS);
        F.Flags = CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES;
        Check("all instances and an instance", &F, CR_INVALID_DATA);
    }
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES);
    Check("all instances", &F, CR_SUCCESS);
    F.Flags = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;
    Check("instance, all classes", &F, CR_INVALID_DATA);
    F.Flags = 3;
    Check("instance, both flags", &F, CR_INVALID_DATA);

    /* Handles: each registration has its own, which is given back once */
    g_Calls = 0;
    Handle = (HCMNOTIFICATION)(ULONG_PTR)0x1234;
    cr = pRegister(&Filter, (PVOID)(ULONG_PTR)0x77, Callback, &Handle);
    ok(cr == CR_SUCCESS, "cr = 0x%lx\n", cr);
    Handle2 = (HCMNOTIFICATION)(ULONG_PTR)0x1234;
    InitFilter(&F, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES);
    cr = pRegister(&F, NULL, Callback, &Handle2);
    ok(cr == CR_SUCCESS, "cr = 0x%lx\n", cr);
    ok(Handle != Handle2, "the same handle twice: %p\n", Handle);

    /* Nothing is called at registration */
    Sleep(500);
    ok(g_Calls == 0, "%ld calls of the callback\n", g_Calls);

    cr = pUnregister(Handle);
    ok(cr == CR_SUCCESS, "unregister: cr = 0x%lx\n", cr);
    cr = pUnregister(Handle);
    /* The block of the registration was given back: Windows 10 and ReactOS answer invalid data while that memory is still
     * mapped, and failure (a handle that is not memory) when the heap has taken the page away; either is as measured */
    ok(cr == CR_INVALID_DATA || cr == CR_FAILURE, "unregister again: cr = 0x%lx\n", cr);
    cr = pUnregister(Handle2);
    ok(cr == CR_SUCCESS, "unregister the second: cr = 0x%lx\n", cr);
    cr = pUnregister(NULL);
    ok(cr == CR_INVALID_DATA, "unregister NULL: cr = 0x%lx\n", cr);
    cr = pUnregister((HCMNOTIFICATION)(ULONG_PTR)0x1234);
    ok(cr == CR_FAILURE, "unregister garbage: cr = 0x%lx\n", cr);
}
