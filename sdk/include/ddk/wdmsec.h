/*
 * PROJECT:     ReactOS DDK
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     wdmsec.h: IoCreateDeviceSecure and the SDDL strings for device
 *              objects, as documented on learn.microsoft.com. The routine is
 *              provided by the wdmsec static library (sdk/lib/drivers/wdmsec),
 *              as it is on Windows; it is not an ntoskrnl export.
 */

#pragma once

#include <wdm.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SDDL strings for IoCreateDeviceSecure's DefaultSDDLString (PCUNICODE_STRING:
   initialize with RtlInitUnicodeString). Access letters: GA all, GR read,
   GW write, GX execute; SY system, BA built-in administrators, WD everyone,
   RC restricted code. */
#define SDDL_DEVOBJ_KERNEL_ONLY                     L"D:P"
#define SDDL_DEVOBJ_SYS_ALL                         L"D:P(A;;GA;;;SY)"
#define SDDL_DEVOBJ_SYS_ALL_ADM_ALL                 L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
#define SDDL_DEVOBJ_SYS_ALL_ADM_RX                  L"D:P(A;;GA;;;SY)(A;;GRGX;;;BA)"
#define SDDL_DEVOBJ_SYS_ALL_ADM_RX_WORLD_RX         L"D:P(A;;GA;;;SY)(A;;GRGX;;;BA)(A;;GRGX;;;WD)"
#define SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R  L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)"
#define SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R_RES_R   L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR;;;WD)(A;;GR;;;RC)"
#define SDDL_DEVOBJ_SYS_ALL_WORLD_RWX_RES_RWX       L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;WD)(A;;GRGWGX;;;RC)"
#define SDDL_DEVOBJ_SYS_ALL_WORLD_RW_RES_R          L"D:P(A;;GA;;;SY)(A;;GRGW;;;WD)(A;;GR;;;RC)"

/*
 * Creates a device object like IoCreateDevice and applies the security
 * descriptor given as an SDDL string (DACL, optionally owner) to it.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NTAPI
IoCreateDeviceSecure(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG DeviceExtensionSize,
    _In_opt_ PUNICODE_STRING DeviceName,
    _In_ DEVICE_TYPE DeviceType,
    _In_ ULONG DeviceCharacteristics,
    _In_ BOOLEAN Exclusive,
    _In_ PCUNICODE_STRING DefaultSDDLString,
    _In_opt_ LPCGUID DeviceClassGuid,
    _Out_ PDEVICE_OBJECT *DeviceObject);

#ifdef __cplusplus
}
#endif
