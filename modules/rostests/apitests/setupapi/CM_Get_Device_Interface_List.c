/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the length and the empty list of CM_Get_Device_Interface_List(_Size)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>

DEFINE_GUID(GUID_ITF_PARALLEL, 0x97F76EF0, 0xF883, 0x11D0, 0xAF, 0x1F, 0x00, 0x00, 0xF8, 0x00, 0x84, 0x5C);
DEFINE_GUID(GUID_ITF_DISK, 0x53F56307, 0xB6BF, 0x11D0, 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B);

static
void
TestInterfaceListLength(void)
{
    WCHAR *Buffer, *p;
    ULONG Length = 0, Used;
    CONFIGRET cr;

    cr = CM_Get_Device_Interface_List_SizeW(&Length, (LPGUID)&GUID_ITF_DISK, NULL, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    ok_long(cr, CR_SUCCESS);
    if (cr != CR_SUCCESS || Length <= 1)
    {
        skip("No disk interface (cr %lx, length %lu)\n", cr, Length);
        return;
    }

    Buffer = HeapAlloc(GetProcessHeap(), 0, (Length + 1) * sizeof(WCHAR));
    if (!Buffer)
    {
        skip("No memory\n");
        return;
    }

    /* The length is in characters, terminators included: a buffer of exactly that many fits the list */
    cr = CM_Get_Device_Interface_ListW((LPGUID)&GUID_ITF_DISK, NULL, Buffer, Length, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    ok_long(cr, CR_SUCCESS);
    Used = 1;
    for (p = Buffer; *p; p += wcslen(p) + 1)
        Used += wcslen(p) + 1;
    ok(Used == Length, "The list takes %lu characters, the size said %lu\n", Used, Length);

    cr = CM_Get_Device_Interface_ListW((LPGUID)&GUID_ITF_DISK, NULL, Buffer, Length - 1, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    ok_long(cr, CR_BUFFER_SMALL);

    HeapFree(GetProcessHeap(), 0, Buffer);
}

static
void
TestEmptyInterfaceList(void)
{
    WCHAR Buffer[4];
    ULONG Length = 0;
    CONFIGRET cr;

    /* No parallel port in a VM; a class without an interface lists nothing, it does not fail */
    cr = CM_Get_Device_Interface_List_SizeW(&Length, (LPGUID)&GUID_ITF_PARALLEL, NULL, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    ok_long(cr, CR_SUCCESS);
    if (cr != CR_SUCCESS || Length != 1)
    {
        skip("The machine has a parallel port (cr %lx, length %lu)\n", cr, Length);
        return;
    }

    Buffer[0] = 0x7777;
    cr = CM_Get_Device_Interface_ListW((LPGUID)&GUID_ITF_PARALLEL, NULL, Buffer, 1, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    ok_long(cr, CR_SUCCESS);
    ok_int(Buffer[0], 0);
}

START_TEST(CM_Get_Device_Interface_List)
{
    TestInterfaceListLength();
    TestEmptyInterfaceList();
}
