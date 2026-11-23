/*
 * PROJECT:     ReactOS Kernel Security Support Provider Interface Driver
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Driver entry point for ksecdd
 * COPYRIGHT:   Copyright 2014 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include "ksecdd.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PDEVICE_OBJECT KsecDeviceObject;

NTKERNELAPI
NTSTATUS
NTAPI
ObSetSecurityObjectByPointer(
    _In_ PVOID Object,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor);

/* A SACL that holds one mandatory label: Low, no write up */
typedef struct _KSEC_LABEL_SACL
{
    ACL Acl;
    struct
    {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
        SID Sid;
    } Label;
} KSEC_LABEL_SACL;


/* FUNCTIONS ******************************************************************/

/*
 * Object opens apply the mandatory label of the device (a secure-open device:
 * every open is checked against it); a device without one counts as Medium.
 * Windows Server 2022 labels \Device\KsecDD Low, NO_WRITE_UP (measured, V15):
 * Low processes open it for read and write, Untrusted ones for read.
 */
static
VOID
KsecLabelDevice(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    static const KSEC_LABEL_SACL Sacl =
    {
        { ACL_REVISION, 0, sizeof(KSEC_LABEL_SACL), 1, 0 },
        {
            { SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, sizeof(((KSEC_LABEL_SACL *)0)->Label) },
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            { SID_REVISION, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {SECURITY_MANDATORY_LOW_RID} }
        }
    };
    SECURITY_DESCRIPTOR Sd;
    NTSTATUS Status;

    RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    Status = RtlSetSaclSecurityDescriptor(&Sd, TRUE, (PACL)&Sacl, FALSE);
    if (NT_SUCCESS(Status))
        Status = ObSetSecurityObjectByPointer(DeviceObject, LABEL_SECURITY_INFORMATION, &Sd);
    if (!NT_SUCCESS(Status))
        DPRINT1("KsecDD: the device label could not be set (0x%lx)\n", Status);
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KsecDD");
    NTSTATUS Status;

    /* Create the KsecDD device */
    Status = IoCreateDevice(DriverObject,
                            0,
                            &DeviceName,
                            FILE_DEVICE_KSEC,
                            0x100u,
                            FALSE,
                            &KsecDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to create KsecDD device: 0x%lx\n", Status);
        return Status;
    }

    KsecLabelDevice(KsecDeviceObject);

    /* Set up dispatch table */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_READ] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KsecDdDispatch;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = KsecDdDispatch;

    /* The system random number generator first: the encryption keys come from it */
    KsecInitializeRandom(KsecDeviceObject);

    /* Write the saved random seed at shutdown */
    Status = IoRegisterShutdownNotification(KsecDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to register for shutdown notification: 0x%lx\n", Status);
    }

    /* Initialize */
    KsecInitializeEncryptionSupport();

    return STATUS_SUCCESS;
}
