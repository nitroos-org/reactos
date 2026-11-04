/*
 * PROJECT:     Partition manager driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Partition device code
 * COPYRIGHT:   2020 Victor Perevertkin (victor.perevertkin@reactos.org)
 */

#include "partmgr.h"

static const WCHAR PartitionSymLinkFormat[] = L"\\Device\\Harddisk%lu\\Partition%lu";


CODE_SEG("PAGE")
NTSTATUS
PartitionCreateDevice(
    _In_ PDEVICE_OBJECT FDObject,
    _In_ PPARTITION_INFORMATION_EX PartitionEntry,
    _In_ UINT32 PdoNumber,
    _In_ PARTITION_STYLE PartitionStyle,
    _In_reads_(PARTITION_INSTANCE_ID_CHARS) PCWCH BaseId,
    _Out_ PDEVICE_OBJECT *PDO)
{
    PAGED_CODE();

    static UINT32 HarddiskVolumeNextId = 1; // this is 1-based

    WCHAR nameBuf[64];
    UNICODE_STRING deviceName;
    UINT32 volumeNum;

    volumeNum = HarddiskVolumeNextId++;
    _swprintf(nameBuf, L"\\Device\\HarddiskVolume%lu", volumeNum);
    RtlCreateUnicodeString(&deviceName, nameBuf);

    /*
     * Create the partition/volume device object.
     *
     * Due to the fact we are also a (basic) volume manager, this device is
     * ALSO a volume device. Because of this, we need to assign it a device
     * name, and a specific device type for IoCreateDevice() to create a VPB
     * for this device, so that a filesystem can be mounted on it.
     * Once we get a separate volume manager, this partition DO can become
     * anonymous, have a different device type, and without any associated VPB.
     * (The attached volume, on the contrary, would require a VPB.)
     */
    PDEVICE_OBJECT partitionDevice;
    NTSTATUS status = IoCreateDevice(FDObject->DriverObject,
                                     sizeof(PARTITION_EXTENSION),
                                     &deviceName,
                                     FILE_DEVICE_DISK, // FILE_DEVICE_MASS_STORAGE,
                                     FILE_DEVICE_SECURE_OPEN,
                                     FALSE,
                                     &partitionDevice);
    if (!NT_SUCCESS(status))
    {
        ERR("Unable to create device object %wZ\n", &deviceName);
        return status;
    }

    INFO("Created device object %p %wZ\n", partitionDevice, &deviceName);

    PPARTITION_EXTENSION partExt = partitionDevice->DeviceExtension;
    RtlZeroMemory(partExt, sizeof(*partExt));

    partExt->DeviceObject = partitionDevice;
    partExt->LowerDevice = FDObject;
    PartMgrIoStatsInit(&partExt->IoStats);

    // NOTE: See comment above.
    // PFDO_EXTENSION fdoExtension = FDObject->DeviceExtension;
    // partitionDevice->DeviceType = /*fdoExtension->LowerDevice*/FDObject->DeviceType;

    partitionDevice->StackSize = FDObject->StackSize;
    partitionDevice->Flags |= DO_DIRECT_IO;

    if (PartitionStyle == PARTITION_STYLE_MBR)
    {
        partExt->Mbr.PartitionType = PartitionEntry->Mbr.PartitionType;
        partExt->Mbr.BootIndicator = PartitionEntry->Mbr.BootIndicator;
        partExt->Mbr.HiddenSectors = PartitionEntry->Mbr.HiddenSectors;
    }
    else
    {
        partExt->Gpt.PartitionType = PartitionEntry->Gpt.PartitionType;
        partExt->Gpt.PartitionId = PartitionEntry->Gpt.PartitionId;
        partExt->Gpt.Attributes = PartitionEntry->Gpt.Attributes;

        RtlCopyMemory(partExt->Gpt.Name, PartitionEntry->Gpt.Name, sizeof(partExt->Gpt.Name));
    }

    partExt->DeviceName = deviceName;
    partExt->StartingOffset = PartitionEntry->StartingOffset.QuadPart;
    partExt->PartitionLength = PartitionEntry->PartitionLength.QuadPart;
    partExt->OnDiskNumber = PartitionEntry->PartitionNumber; // the "physical" partition number
    partExt->DetectedNumber = PdoNumber; // counts only partitions with PDO created
    partExt->VolumeNumber = volumeNum;
    partExt->CreatedVpb = partitionDevice->Vpb;
    RtlCopyMemory(partExt->BaseId, BaseId, sizeof(partExt->BaseId));
    partExt->BaseId[PARTITION_INSTANCE_ID_CHARS - 1] = UNICODE_NULL;

    // The device is initialized
    partitionDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    *PDO = partitionDevice;
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
PartitionHandleStartDevice(
    _In_ PPARTITION_EXTENSION PartExt,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    // first, create a symbolic link for our device
    WCHAR nameBuf[64];
    UNICODE_STRING partitionSymlink, interfaceName;
    PFDO_EXTENSION fdoExtension = PartExt->LowerDevice->DeviceExtension;

    // \\Device\\Harddisk%lu\\Partition%lu
    _swprintf(nameBuf, PartitionSymLinkFormat,
        fdoExtension->DiskData.DeviceNumber, PartExt->DetectedNumber);

    if (!RtlCreateUnicodeString(&partitionSymlink, nameBuf))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = IoCreateSymbolicLink(&partitionSymlink, &PartExt->DeviceName);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PartExt->SymlinkCreated = TRUE;

    INFO("Symlink created %wZ -> %wZ\n", &partitionSymlink, &PartExt->DeviceName);

    // Our partition device will have two interfaces:
    // GUID_DEVINTERFACE_PARTITION and GUID_DEVINTERFACE_VOLUME
    // (aka. MOUNTDEV_MOUNTED_DEVICE_GUID).
    // The latter one is used to notify MountMgr about the new volume.

    status = IoRegisterDeviceInterface(PartExt->DeviceObject,
                                       &GUID_DEVINTERFACE_PARTITION,
                                       NULL,
                                       &interfaceName);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    INFO("Partition interface %wZ\n", &interfaceName);
    PartExt->PartitionInterfaceName = interfaceName;
    status = IoSetDeviceInterfaceState(&interfaceName, TRUE);
    if (!NT_SUCCESS(status))
    {
        RtlFreeUnicodeString(&interfaceName);
        RtlInitUnicodeString(&PartExt->PartitionInterfaceName, NULL);
        return status;
    }

    status = IoRegisterDeviceInterface(PartExt->DeviceObject,
                                       &GUID_DEVINTERFACE_VOLUME,
                                       NULL,
                                       &interfaceName);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    INFO("Volume interface %wZ\n", &interfaceName);
    PartExt->VolumeInterfaceName = interfaceName;
    status = IoSetDeviceInterfaceState(&interfaceName, TRUE);
    if (!NT_SUCCESS(status))
    {
        RtlFreeUnicodeString(&interfaceName);
        RtlInitUnicodeString(&PartExt->VolumeInterfaceName, NULL);
        return status;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief
 * Notifies MountMgr to delete all mount points
 * associated with the given volume.
 *
 * @note    This should belong to volmgr.sys and act on a PVOLUME_EXTENSION.
 **/
static
CODE_SEG("PAGE")
NTSTATUS
VolumeDeleteMountPoints(
    _In_ PPARTITION_EXTENSION PartExt)
{
    NTSTATUS Status;
    UNICODE_STRING MountMgr;
    ULONG InputSize, OutputSize;
    LOGICAL Retry;
    PUNICODE_STRING DeviceName;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject = NULL;
    PMOUNTMGR_MOUNT_POINT InputBuffer = NULL;
    PMOUNTMGR_MOUNT_POINTS OutputBuffer = NULL;

    PAGED_CODE();

    /* Get the device pointer to the MountMgr */
    RtlInitUnicodeString(&MountMgr, MOUNTMGR_DEVICE_NAME);
    Status = IoGetDeviceObjectPointer(&MountMgr,
                                      FILE_READ_ATTRIBUTES,
                                      &FileObject,
                                      &DeviceObject);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Setup the volume device name for deleting its mount points */
    DeviceName = &PartExt->DeviceName;

    /* Allocate the input buffer */
    InputSize = sizeof(*InputBuffer) + DeviceName->Length;
    InputBuffer = ExAllocatePoolWithTag(PagedPool, InputSize, TAG_PARTMGR);
    if (!InputBuffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quit;
    }

    /* Fill it in */
    RtlZeroMemory(InputBuffer, sizeof(*InputBuffer));
    InputBuffer->DeviceNameOffset = sizeof(*InputBuffer);
    InputBuffer->DeviceNameLength = DeviceName->Length;
    RtlCopyMemory(&InputBuffer[1], DeviceName->Buffer, DeviceName->Length);

    /*
     * IOCTL_MOUNTMGR_DELETE_POINTS needs a large-enough scratch output buffer
     * to work with. (It uses it to query the mount points, before deleting
     * them.) Start with a guessed size and call the IOCTL. If the buffer is
     * not big enough, use the value retrieved in MOUNTMGR_MOUNT_POINTS::Size
     * to re-allocate a larger buffer and call the IOCTL once more.
     */
    OutputSize = max(PAGE_SIZE, sizeof(*OutputBuffer));
    for (Retry = 0; Retry < 2; ++Retry)
    {
        OutputBuffer = ExAllocatePoolWithTag(PagedPool, OutputSize, TAG_PARTMGR);
        if (!OutputBuffer)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Call the MountMgr to delete the drive letter */
        Status = IssueSyncIoControlRequest(IOCTL_MOUNTMGR_DELETE_POINTS,
                                           DeviceObject,
                                           InputBuffer,
                                           InputSize,
                                           OutputBuffer,
                                           OutputSize,
                                           FALSE);

        /* Adjust the allocation size if it was too small */
        if (Status == STATUS_BUFFER_OVERFLOW)
        {
            OutputSize = OutputBuffer->Size;
            ExFreePoolWithTag(OutputBuffer, TAG_PARTMGR);
            continue;
        }
        /* Success or failure: stop the loop */
        break;
    }

Quit:
    if (OutputBuffer)
        ExFreePoolWithTag(OutputBuffer, TAG_PARTMGR);
    if (InputBuffer)
        ExFreePoolWithTag(InputBuffer, TAG_PARTMGR);
    if (FileObject)
        ObDereferenceObject(FileObject);
    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
PartitionHandleRemove(
    _In_ PPARTITION_EXTENSION PartExt,
    _In_ BOOLEAN FinalRemove)
{
    NTSTATUS status;

    PAGED_CODE();

    // remove the symbolic link
    if (PartExt->SymlinkCreated)
    {
        WCHAR nameBuf[64];
        UNICODE_STRING partitionSymlink;
        PFDO_EXTENSION fdoExtension = PartExt->LowerDevice->DeviceExtension;

        _swprintf(nameBuf, PartitionSymLinkFormat,
            fdoExtension->DiskData.DeviceNumber, PartExt->DetectedNumber);

        RtlInitUnicodeString(&partitionSymlink, nameBuf);

        status = IoDeleteSymbolicLink(&partitionSymlink);

        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PartExt->SymlinkCreated = FALSE;

        INFO("Symlink removed %wZ -> %wZ\n", &partitionSymlink, &PartExt->DeviceName);
    }

    // release device interfaces
    if (PartExt->PartitionInterfaceName.Buffer)
    {
        status = IoSetDeviceInterfaceState(&PartExt->PartitionInterfaceName, FALSE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        RtlFreeUnicodeString(&PartExt->PartitionInterfaceName);
        RtlInitUnicodeString(&PartExt->PartitionInterfaceName, NULL);
    }

    if (PartExt->VolumeInterfaceName.Buffer)
    {
        /* Notify MountMgr to delete all associated mount points.
         * MountMgr does not automatically remove these in order to support
         * drive letter persistence for online/offline volume transitions,
         * or volumes arrival/removal on removable devices. */
        status = VolumeDeleteMountPoints(PartExt);
        if (!NT_SUCCESS(status))
        {
            ERR("VolumeDeleteMountPoints(%wZ) failed with status 0x%08lx\n",
                &PartExt->DeviceName, status);
            /* Failure isn't major, continue proceeding with volume removal */
        }

        /* Notify MountMgr of volume removal */
        status = IoSetDeviceInterfaceState(&PartExt->VolumeInterfaceName, FALSE);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        RtlFreeUnicodeString(&PartExt->VolumeInterfaceName);
        RtlInitUnicodeString(&PartExt->VolumeInterfaceName, NULL);
    }

    if (FinalRemove)
    {
        ASSERT(PartExt->DeviceName.Buffer);
        if (PartExt->DeviceName.Buffer)
        {
            INFO("Removed device %wZ\n", &PartExt->DeviceName);
            RtlFreeUnicodeString(&PartExt->DeviceName);
        }

        IoDeleteDevice(PartExt->DeviceObject);
    }

    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
PartitionHandleDeviceRelations(
    _In_ PPARTITION_EXTENSION PartExt,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    DEVICE_RELATION_TYPE type = ioStack->Parameters.QueryDeviceRelations.Type;

    if (type == TargetDeviceRelation)
    {
        // Device relations have one entry built into their size.
        PDEVICE_RELATIONS deviceRelations =
            ExAllocatePoolZero(PagedPool, sizeof(DEVICE_RELATIONS), TAG_PARTMGR);

        if (deviceRelations != NULL)
        {
            deviceRelations->Count = 1;
            deviceRelations->Objects[0] = PartExt->DeviceObject;
            ObReferenceObject(deviceRelations->Objects[0]);

            Irp->IoStatus.Information = (ULONG_PTR)deviceRelations;
            return STATUS_SUCCESS;
        }
        else
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        Irp->IoStatus.Information = 0;
        return Irp->IoStatus.Status;
    }
}

static
CODE_SEG("PAGE")
NTSTATUS
PartitionHandleQueryId(
    _In_ PPARTITION_EXTENSION PartExt,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    BUS_QUERY_ID_TYPE idType = ioStack->Parameters.QueryId.IdType;
    UNICODE_STRING idString;
    NTSTATUS status;

    PAGED_CODE();

    switch (idType)
    {
        case BusQueryDeviceID:
            status = RtlCreateUnicodeString(&idString, L"STORAGE\\Partition")
                     ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
            break;
        case BusQueryHardwareIDs:
        {
            static WCHAR volumeID[] = L"STORAGE\\Volume\0";

            idString.Buffer = ExAllocatePoolWithTag(PagedPool, sizeof(volumeID), TAG_PARTMGR);
            RtlCopyMemory(idString.Buffer, volumeID, sizeof(volumeID));

            status = STATUS_SUCCESS;
            break;
        }
        case BusQueryInstanceID:
        {
            // the same for the whole life of the device: PnP knows the device by it, also after
            // IOCTL_DISK_GROW_PARTITION changed its length
            status = PartMgrQueryInstanceId(PartExt->LowerDevice->DeviceExtension, PartExt, &idString);
            break;
        }
        default:
            status = STATUS_NOT_SUPPORTED;
            break;
    }

    Irp->IoStatus.Information = NT_SUCCESS(status) ? (ULONG_PTR) idString.Buffer : 0;
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
PartitionHandleQueryCapabilities(
    _In_ PPARTITION_EXTENSION PartExt,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_CAPABILITIES devCaps = ioStack->Parameters.DeviceCapabilities.Capabilities;

    PAGED_CODE();
    ASSERT(devCaps);

    devCaps->SilentInstall = TRUE;
    devCaps->RawDeviceOK = TRUE;
    devCaps->NoDisplayInUI = TRUE;
    devCaps->Address = PartExt->OnDiskNumber;
    devCaps->UniqueID = FALSE;

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
PartitionHandlePnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPARTITION_EXTENSION partExt = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    PAGED_CODE();

    switch (ioStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            status = PartitionHandleStartDevice(partExt, Irp);
            break;
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            status = PartitionHandleDeviceRelations(partExt, Irp);
            break;
        }
        case IRP_MN_QUERY_STOP_DEVICE:
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_STOP_DEVICE:
        {
            status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_SURPRISE_REMOVAL:
        {
            status = PartitionHandleRemove(partExt, FALSE);
            break;
        }
        case IRP_MN_REMOVE_DEVICE:
        {
            PFDO_EXTENSION fdoExtension = partExt->LowerDevice->DeviceExtension;
            BOOLEAN attached;

            // A partition that is still in the layout (and in PartitionList) stays: only its links
            // and interfaces go; it is deleted when it leaves the layout or with the disk.
            PartMgrAcquireLayoutLock(fdoExtension);
            attached = partExt->Attached;
            PartMgrReleaseLayoutLock(fdoExtension);
            if (attached)
            {
                status = PartitionHandleRemove(partExt, FALSE);
                break;
            }
            PartMgrReleaseInstanceId(fdoExtension, partExt, FALSE);
            status = PartitionHandleRemove(partExt, TRUE);
            break;
        }
        case IRP_MN_QUERY_ID:
        {
            status = PartitionHandleQueryId(partExt, Irp);
            break;
        }
        case IRP_MN_QUERY_CAPABILITIES:
        {
            status = PartitionHandleQueryCapabilities(partExt, Irp);
            break;
        }
        default:
        {
            Irp->IoStatus.Information = 0;
            status = STATUS_NOT_SUPPORTED;
        }
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* The cached drive layout must show what IOCTL_DISK_SET_PARTITION_INFO(_EX) wrote:
 * IOCTL_DISK_GET_DRIVE_LAYOUT(_EX) returns it, and a layout set from it would bring the
 * old values back. Requires the layout lock. */
static
CODE_SEG("PAGE")
VOID
PartitionUpdateCachedLayout(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PPARTITION_EXTENSION PartExt)
{
    PDRIVE_LAYOUT_INFORMATION_EX layout = FdoExtension->LayoutCache;

    PAGED_CODE();

    if (!FdoExtension->LayoutValid || !layout)
        return;

    for (UINT32 i = 0; i < layout->PartitionCount; i++)
    {
        PPARTITION_INFORMATION_EX entry = &layout->PartitionEntry[i];

        if ((UINT64)entry->StartingOffset.QuadPart != PartExt->StartingOffset ||
            (UINT64)entry->PartitionLength.QuadPart != PartExt->PartitionLength)
        {
            continue;
        }

        if (layout->PartitionStyle == PARTITION_STYLE_MBR)
        {
            entry->Mbr.PartitionType = PartExt->Mbr.PartitionType;
        }
        else
        {
            entry->Gpt.PartitionType = PartExt->Gpt.PartitionType;
            entry->Gpt.PartitionId = PartExt->Gpt.PartitionId;
            entry->Gpt.Attributes = PartExt->Gpt.Attributes;
            RtlCopyMemory(entry->Gpt.Name, PartExt->Gpt.Name, sizeof(entry->Gpt.Name));
        }
    }
}

NTSTATUS
PartitionHandleDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    PPARTITION_EXTENSION partExt = DeviceObject->DeviceExtension;
    PFDO_EXTENSION fdoExtension = partExt->LowerDevice->DeviceExtension;
    NTSTATUS status;

    ASSERT(!partExt->IsFDO);

    // as reads and writes: a partition that left the layout takes no device control, handled here
    // or passed on, as its storage may belong to another partition now
    if (!partExt->IsEnumerated || !partExt->Attached)
    {
        Irp->IoStatus.Status = STATUS_DEVICE_DOES_NOT_EXIST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    switch (ioStack->Parameters.DeviceIoControl.IoControlCode)
    {
        // disk stuff
        case IOCTL_DISK_GET_PARTITION_INFO:
        {
            if (!VerifyIrpOutBufferSize(Irp, sizeof(PARTITION_INFORMATION)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            // not supported on anything other than MBR
            if (fdoExtension->DiskData.PartitionStyle != PARTITION_STYLE_MBR)
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
                PartMgrReleaseLayoutLock(fdoExtension);
                break;
            }

            PPARTITION_INFORMATION partInfo = Irp->AssociatedIrp.SystemBuffer;

            *partInfo = (PARTITION_INFORMATION){
                .PartitionType = partExt->Mbr.PartitionType,
                .StartingOffset.QuadPart = partExt->StartingOffset,
                .PartitionLength.QuadPart = partExt->PartitionLength,
                .HiddenSectors = partExt->Mbr.HiddenSectors,
                .PartitionNumber = partExt->DetectedNumber,
                .BootIndicator = partExt->Mbr.BootIndicator,
                .RecognizedPartition = partExt->Mbr.RecognizedPartition,
                .RewritePartition = FALSE,
            };

            PartMgrReleaseLayoutLock(fdoExtension);

            Irp->IoStatus.Information = sizeof(*partInfo);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_DISK_GET_PARTITION_INFO_EX:
        {
            if (!VerifyIrpOutBufferSize(Irp, sizeof(PARTITION_INFORMATION_EX)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PPARTITION_INFORMATION_EX partInfoEx = Irp->AssociatedIrp.SystemBuffer;

            PartMgrAcquireLayoutLock(fdoExtension);

            *partInfoEx = (PARTITION_INFORMATION_EX){
                .StartingOffset.QuadPart = partExt->StartingOffset,
                .PartitionLength.QuadPart = partExt->PartitionLength,
                .PartitionNumber = partExt->DetectedNumber,
                .PartitionStyle = fdoExtension->DiskData.PartitionStyle,
                .RewritePartition = FALSE,
            };

            if (fdoExtension->DiskData.PartitionStyle == PARTITION_STYLE_MBR)
            {
                partInfoEx->Mbr = (PARTITION_INFORMATION_MBR){
                    .PartitionType = partExt->Mbr.PartitionType,
                    .HiddenSectors = partExt->Mbr.HiddenSectors,
                    .BootIndicator = partExt->Mbr.BootIndicator,
                    .RecognizedPartition = partExt->Mbr.RecognizedPartition,
                };
            }
            else
            {
                partInfoEx->Gpt = (PARTITION_INFORMATION_GPT){
                    .PartitionType = partExt->Gpt.PartitionType,
                    .PartitionId = partExt->Gpt.PartitionId,
                    .Attributes = partExt->Gpt.Attributes,
                };

                RtlCopyMemory(partInfoEx->Gpt.Name,
                              partExt->Gpt.Name,
                              sizeof(partInfoEx->Gpt.Name));
            }

            PartMgrReleaseLayoutLock(fdoExtension);

            Irp->IoStatus.Information = sizeof(*partInfoEx);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_DISK_SET_PARTITION_INFO:
        {
            PSET_PARTITION_INFORMATION inputBuffer = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpInBufferSize(Irp, sizeof(*inputBuffer)))
            {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            // these functions use on disk numbers, not detected ones
            status = IoSetPartitionInformation(fdoExtension->LowerDevice,
                                               fdoExtension->DiskData.BytesPerSector,
                                               partExt->OnDiskNumber,
                                               inputBuffer->PartitionType);

            if (NT_SUCCESS(status))
            {
                partExt->Mbr.PartitionType = inputBuffer->PartitionType;
                PartitionUpdateCachedLayout(fdoExtension, partExt);
            }

            PartMgrReleaseLayoutLock(fdoExtension);

            Irp->IoStatus.Information = 0;
            break;
        }
        case IOCTL_DISK_SET_PARTITION_INFO_EX:
        {
            PSET_PARTITION_INFORMATION_EX inputBuffer = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpInBufferSize(Irp, sizeof(*inputBuffer)))
            {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            // these functions use on disk numbers, not detected ones
            status = IoSetPartitionInformationEx(fdoExtension->LowerDevice,
                                                 partExt->OnDiskNumber,
                                                 inputBuffer);

            if (NT_SUCCESS(status))
            {
                if (fdoExtension->DiskData.PartitionStyle == PARTITION_STYLE_MBR)
                {
                    partExt->Mbr.PartitionType = inputBuffer->Mbr.PartitionType;
                }
                else
                {
                    partExt->Gpt.PartitionType = inputBuffer->Gpt.PartitionType;
                    partExt->Gpt.PartitionId = inputBuffer->Gpt.PartitionId;
                    partExt->Gpt.Attributes = inputBuffer->Gpt.Attributes;

                    RtlMoveMemory(partExt->Gpt.Name,
                                  inputBuffer->Gpt.Name,
                                  sizeof(partExt->Gpt.Name));
                }
                PartitionUpdateCachedLayout(fdoExtension, partExt);
            }

            PartMgrReleaseLayoutLock(fdoExtension);

            Irp->IoStatus.Information = 0;
            break;
        }
        case IOCTL_DISK_GET_LENGTH_INFO:
        {
            PGET_LENGTH_INFORMATION lengthInfo = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpOutBufferSize(Irp, sizeof(*lengthInfo)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            lengthInfo->Length.QuadPart = partExt->PartitionLength;

            PartMgrReleaseLayoutLock(fdoExtension);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*lengthInfo);
            break;
        }
        case IOCTL_DISK_VERIFY:
        {
            PVERIFY_INFORMATION verifyInfo = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpInBufferSize(Irp, sizeof(*verifyInfo)))
            {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            // Partition device should just adjust the starting offset
            verifyInfo->StartingOffset.QuadPart += partExt->StartingOffset;
            return ForwardIrpAndForget(DeviceObject, Irp);
        }
        case IOCTL_DISK_UPDATE_PROPERTIES:
        {
            fdoExtension->LayoutValid = FALSE;
            IoInvalidateDeviceRelations(fdoExtension->PhysicalDiskDO, BusRelations);

            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_STORAGE_GET_DEVICE_NUMBER:
        {
            PSTORAGE_DEVICE_NUMBER deviceNumber = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpOutBufferSize(Irp, sizeof(*deviceNumber)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            deviceNumber->DeviceType = partExt->DeviceObject->DeviceType;
            deviceNumber->DeviceNumber = fdoExtension->DiskData.DeviceNumber;
            deviceNumber->PartitionNumber = partExt->DetectedNumber;

            PartMgrReleaseLayoutLock(fdoExtension);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*deviceNumber);
            break;
        }
        case IOCTL_STORAGE_MEDIA_REMOVAL:
        {
            return ForwardIrpAndForget(DeviceObject, Irp);
        }
        // volume stuff (most of that should be in volmgr.sys once it is implemented)
        case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
        {
            PVOLUME_DISK_EXTENTS volExts = Irp->AssociatedIrp.SystemBuffer;

            // we fill only one extent entry so sizeof(*volExts) is enough
            if (!VerifyIrpOutBufferSize(Irp, sizeof(*volExts)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            // the only type of volume we support right now is disk partition
            // so this structure is simple

            *volExts = (VOLUME_DISK_EXTENTS) {
                .NumberOfDiskExtents = 1,
                .Extents = {{
                    .DiskNumber = fdoExtension->DiskData.DeviceNumber,
                    .StartingOffset.QuadPart = partExt->StartingOffset,
                    .ExtentLength.QuadPart = partExt->PartitionLength
                }}
            };

            PartMgrReleaseLayoutLock(fdoExtension);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*volExts);
            break;
        }
        case IOCTL_VOLUME_QUERY_VOLUME_NUMBER:
        {
            PVOLUME_NUMBER volNum = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpOutBufferSize(Irp, sizeof(*volNum)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            volNum->VolumeNumber = partExt->VolumeNumber;
            RtlCopyMemory(volNum->VolumeManagerName,
                          L"VOLMGR  ", // Must be 8 space-padded characters
                          sizeof(volNum->VolumeManagerName));

            PartMgrReleaseLayoutLock(fdoExtension);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*volNum);
            break;
        }
        case IOCTL_VOLUME_IS_PARTITION:
        {
            // The only type of volume we support right now is disk partition
            // so we just return success. A more robust algorithm would be
            // to check whether the volume has only one single extent, that
            // covers the whole partition on which it lies upon. If this is
            // not the case, return STATUS_UNSUCCESSFUL instead.
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_VOLUME_ONLINE:
        {
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
        {
            PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION gptAttrs = Irp->AssociatedIrp.SystemBuffer;
            if (!VerifyIrpOutBufferSize(Irp, sizeof(*gptAttrs)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            // not supported on anything other than GPT
            if (fdoExtension->DiskData.PartitionStyle != PARTITION_STYLE_GPT)
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
            }

            gptAttrs->GptAttributes = partExt->Gpt.Attributes;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*gptAttrs);
            break;
        }
        // mountmgr notifications (these should be in volmgr.sys once it is implemented)
        case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
        {
            PMOUNTDEV_NAME name = Irp->AssociatedIrp.SystemBuffer;

            // Windows (volmgr) rejects a buffer smaller than the fixed structure outright
            if (!VerifyIrpOutBufferSize(Irp, sizeof(MOUNTDEV_NAME)))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            name->NameLength = partExt->DeviceName.Length;

            // return NameLength back
            if (!VerifyIrpOutBufferSize(Irp, sizeof(USHORT) + name->NameLength))
            {
                Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
                status = STATUS_BUFFER_OVERFLOW;
                break;
            }

            RtlCopyMemory(name->Name, partExt->DeviceName.Buffer, name->NameLength);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(USHORT) + name->NameLength;
            break;
        }
        case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
        {
            const SIZE_T headerSize = FIELD_OFFSET(MOUNTDEV_UNIQUE_ID, UniqueId);
            PMOUNTDEV_UNIQUE_ID uniqueId = Irp->AssociatedIrp.SystemBuffer;
            PBASIC_VOLUME_UNIQUE_ID basicVolId = (PBASIC_VOLUME_UNIQUE_ID)&uniqueId->UniqueId;
            PUNICODE_STRING InterfaceName;

            // Windows (volmgr) rejects a buffer smaller than the fixed structure outright
            if (!VerifyIrpOutBufferSize(Irp, sizeof(MOUNTDEV_UNIQUE_ID)))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            InterfaceName = &partExt->VolumeInterfaceName;
            if (fdoExtension->IsSuperFloppy)
                InterfaceName = &fdoExtension->DiskInterfaceName;

            // Calculate and return the necessary data size
            if ((fdoExtension->DiskData.PartitionStyle == PARTITION_STYLE_MBR) &&
                !fdoExtension->IsSuperFloppy)
            {
                uniqueId->UniqueIdLength = sizeof(basicVolId->Mbr);
            }
            else if (fdoExtension->DiskData.PartitionStyle == PARTITION_STYLE_GPT)
            {
                uniqueId->UniqueIdLength = sizeof(basicVolId->Gpt);
            }
            else
            {
                if (!InterfaceName->Buffer || !InterfaceName->Length)
                {
                    PartMgrReleaseLayoutLock(fdoExtension);
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                uniqueId->UniqueIdLength = InterfaceName->Length;
            }

            // Return UniqueIdLength back
            if (!VerifyIrpOutBufferSize(Irp, headerSize + uniqueId->UniqueIdLength))
            {
                PartMgrReleaseLayoutLock(fdoExtension);
                Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
                status = STATUS_BUFFER_OVERFLOW;
                break;
            }

            //
            // Write the UniqueId
            //
            // Format:
            // - Basic volume on MBR disk: disk Mbr.Signature + partition StartingOffset (length: 0x0C)
            // - Basic volume on GPT disk: "DMIO:ID:" + Gpt.PartitionGuid (length: 0x18)
            // - Volume on Basic disk (NT <= 4): 8-byte FTDisk identifier (length: 0x08)
            // - Volume on Dynamic disk (NT 5+): "DMIO:ID:" + dmio VolumeGuid (length: 0x18)
            // - Super-floppy (single-partition with StartingOffset == 0),
            //   or Removable media: DiskInterfaceName.
            // - As fallback, we use the VolumeInterfaceName.
            //
            if ((fdoExtension->DiskData.PartitionStyle == PARTITION_STYLE_MBR) &&
                !fdoExtension->IsSuperFloppy)
            {
                basicVolId->Mbr.Signature = fdoExtension->DiskData.Mbr.Signature;
                basicVolId->Mbr.StartingOffset = partExt->StartingOffset;
            }
            else if (fdoExtension->DiskData.PartitionStyle == PARTITION_STYLE_GPT)
            {
                basicVolId->Gpt.Signature = DMIO_ID_SIGNATURE;
                basicVolId->Gpt.PartitionGuid = partExt->Gpt.PartitionId;
            }
            else
            {
                RtlCopyMemory(uniqueId->UniqueId,
                              InterfaceName->Buffer,
                              uniqueId->UniqueIdLength);
            }

            PartMgrReleaseLayoutLock(fdoExtension);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = headerSize + uniqueId->UniqueIdLength;
            break;
        }
        case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
        {
            PMOUNTDEV_STABLE_GUID stableGuid = Irp->AssociatedIrp.SystemBuffer;
            static const GUID nullGuid = { 0 };

            if (!VerifyIrpOutBufferSize(Irp, sizeof(*stableGuid)))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PartMgrAcquireLayoutLock(fdoExtension);

            // A GPT partition's volume GUID name is its partition GUID
            if (fdoExtension->DiskData.PartitionStyle != PARTITION_STYLE_GPT ||
                RtlCompareMemory(&partExt->Gpt.PartitionId, &nullGuid, sizeof(GUID)) == sizeof(GUID))
            {
                PartMgrReleaseLayoutLock(fdoExtension);
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
            }

            stableGuid->StableGuid = partExt->Gpt.PartitionId;

            PartMgrReleaseLayoutLock(fdoExtension);

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*stableGuid);
            break;
        }
        case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
        {
            // Windows: a too small buffer is invalid; there is never a suggestion for a volume
            // that has been given its link already (the query is answered once at most)
            if (!VerifyIrpOutBufferSize(Irp, sizeof(MOUNTDEV_SUGGESTED_LINK_NAME)))
                status = STATUS_INVALID_PARAMETER;
            else
                status = STATUS_NOT_FOUND;
            break;
        }
        case IOCTL_MOUNTDEV_LINK_CREATED:
        case IOCTL_MOUNTDEV_LINK_DELETED:
#if (NTDDI_VERSION >= NTDDI_WS03)
        /* Deprecated Windows 2000/XP versions of IOCTL_MOUNTDEV_LINK_[CREATED|DELETED]
         * without access protection, that were updated in Windows 2003 */
        case CTL_CODE(MOUNTDEVCONTROLTYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS):
        case CTL_CODE(MOUNTDEVCONTROLTYPE, 5, METHOD_BUFFERED, FILE_ANY_ACCESS):
#endif
        case IOCTL_MOUNTDEV_UNIQUE_ID_CHANGE_NOTIFY:
        {
            WARN("Ignored MountMgr notification: 0x%lX\n",
                 ioStack->Parameters.DeviceIoControl.IoControlCode);
            status = STATUS_NOT_IMPLEMENTED;
            break;
        }
        case IOCTL_DISK_PERFORMANCE:
        {
            // the partition's own count, with the volume number as its device number (Windows reports
            // the volume manager's there)
            status = PartMgrIoctlDiskPerformance(&partExt->IoStats, partExt->VolumeNumber, Irp);
            break;
        }
        default:
            return ForwardIrpAndForget(DeviceObject, Irp);
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
