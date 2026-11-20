/*
 * PROJECT:     Partition manager driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main file
 * COPYRIGHT:   2020 Victor Perevertkin (victor.perevertkin@reactos.org)
 */

/* The Partition Manager Driver in ReactOS complements disk.sys/classpnp.sys drivers
 * (which are derived from Windows 10 drivers) so does not do exactly what Windows 2003 partmgr.sys
 * does. Here is acts like both partition and volume manager, because volmgr.sys does not (yet)
 * exist in ReactOS. Thus handles some IOCTL_VOLUME_*, and IOCTL_MOUNTMGR_* IOCTLs.
 */

#include "partmgr.h"


static
CODE_SEG("PAGE")
PDRIVE_LAYOUT_INFORMATION
PartMgrConvertExtendedToLayout(
    _In_ CONST PDRIVE_LAYOUT_INFORMATION_EX LayoutEx)
{
    PDRIVE_LAYOUT_INFORMATION Layout;
    PPARTITION_INFORMATION Partition;
    PPARTITION_INFORMATION_EX PartitionEx;

    PAGED_CODE();

    ASSERT(LayoutEx);

    if (LayoutEx->PartitionStyle != PARTITION_STYLE_MBR)
    {
        ASSERT(FALSE);
        return NULL;
    }

    size_t layoutSize = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION, PartitionEntry[0]) +
                        LayoutEx->PartitionCount * sizeof (PARTITION_INFORMATION);

    Layout = ExAllocatePoolWithTag(PagedPool, layoutSize, TAG_PARTMGR);

    if (Layout == NULL)
    {
        return NULL;
    }

    Layout->Signature = LayoutEx->Mbr.Signature;
    Layout->PartitionCount = LayoutEx->PartitionCount;

    for (UINT32 i = 0; i < LayoutEx->PartitionCount; i++)
    {
        Partition = &Layout->PartitionEntry[i];
        PartitionEx = &LayoutEx->PartitionEntry[i];

        Partition->StartingOffset = PartitionEx->StartingOffset;
        Partition->PartitionLength = PartitionEx->PartitionLength;
        Partition->RewritePartition = PartitionEx->RewritePartition;
        Partition->PartitionNumber = PartitionEx->PartitionNumber;

        Partition->PartitionType = PartitionEx->Mbr.PartitionType;
        Partition->BootIndicator = PartitionEx->Mbr.BootIndicator;
        Partition->RecognizedPartition = PartitionEx->Mbr.RecognizedPartition;
        Partition->HiddenSectors = PartitionEx->Mbr.HiddenSectors;
    }

    return Layout;
}

static
CODE_SEG("PAGE")
PDRIVE_LAYOUT_INFORMATION_EX
PartMgrConvertLayoutToExtended(
    _In_ CONST PDRIVE_LAYOUT_INFORMATION Layout)
{
    PDRIVE_LAYOUT_INFORMATION_EX layoutEx;

    PAGED_CODE();

    ASSERT(Layout != NULL);

    size_t layoutSize = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[0]) +
                        Layout->PartitionCount * sizeof (PARTITION_INFORMATION_EX);

    layoutEx = ExAllocatePoolUninitialized(PagedPool, layoutSize, TAG_PARTMGR);

    if (layoutEx == NULL)
    {
        return NULL;
    }

    layoutEx->PartitionStyle = PARTITION_STYLE_MBR;
    layoutEx->PartitionCount = Layout->PartitionCount;
    layoutEx->Mbr.Signature = Layout->Signature;

    for (UINT32 i = 0; i < Layout->PartitionCount; i++)
    {
        PPARTITION_INFORMATION part = &Layout->PartitionEntry[i];

        layoutEx->PartitionEntry[i] = (PARTITION_INFORMATION_EX) {
            .PartitionStyle = PARTITION_STYLE_MBR,
            .StartingOffset = part->StartingOffset,
            .PartitionLength = part->PartitionLength,
            .RewritePartition = part->RewritePartition,
            .PartitionNumber = part->PartitionNumber,
            .Mbr = {
                .PartitionType = part->PartitionType,
                .BootIndicator = part->BootIndicator,
                .RecognizedPartition = part->RecognizedPartition,
                .HiddenSectors = part->HiddenSectors,
            }
        };
    }

    return layoutEx;
}

/**
 * @brief
 * Detects whether a disk is a "super-floppy", i.e. an unpartitioned
 * disk with only a valid VBR, as reported by IoReadPartitionTable()
 * and IoWritePartitionTable():
 * only one single partition starting at offset zero and spanning the
 * whole disk, without hidden sectors, whose type is FAT16 non-bootable.
 *
 * Accessing \Device\HarddiskN\Partition0 or Partition1 on such disks
 * returns the same data.
 *
 * @note
 * - Requires partitioning lock held.
 * - Uses the cached disk partition layout.
 **/
static
CODE_SEG("PAGE")
BOOLEAN
PartMgrIsDiskSuperFloppy(
    _In_ PFDO_EXTENSION FdoExtension)
{
    PPARTITION_INFORMATION_EX PartitionInfo;

    PAGED_CODE();

    ASSERT(FdoExtension->LayoutValid && FdoExtension->LayoutCache);

    /* We must be MBR and have only one partition */
    ASSERT(FdoExtension->DiskData.PartitionStyle == FdoExtension->LayoutCache->PartitionStyle);
    if (FdoExtension->DiskData.PartitionStyle != PARTITION_STYLE_MBR)
        return FALSE;
    if (FdoExtension->LayoutCache->PartitionCount != 1)
        return FALSE;

    /* Get the single partition entry */
    PartitionInfo = FdoExtension->LayoutCache->PartitionEntry;
    ASSERT(FdoExtension->DiskData.PartitionStyle == PartitionInfo->PartitionStyle);

    /* The single partition must start at the beginning of the disk */
    if (!(PartitionInfo->StartingOffset.QuadPart == 0 &&
          PartitionInfo->Mbr.HiddenSectors == 0))
    {
        return FALSE;
    }

    /* The disk signature is usually set to 1; warn in case it's not */
    ASSERT(FdoExtension->DiskData.Mbr.Signature == FdoExtension->LayoutCache->Mbr.Signature);
    if (FdoExtension->DiskData.Mbr.Signature != 1)
    {
        WARN("Super-Floppy disk %lu signature %08x != 1!\n",
             FdoExtension->DiskData.DeviceNumber, FdoExtension->DiskData.Mbr.Signature);
    }

    /* The partition must be recognized and report as FAT16 non-bootable */
    if ((PartitionInfo->Mbr.RecognizedPartition != TRUE) ||
        (PartitionInfo->Mbr.PartitionType != PARTITION_FAT_16) ||
        (PartitionInfo->Mbr.BootIndicator != FALSE))
    {
        WARN("Super-Floppy disk %lu does not return default settings!\n"
             "    RecognizedPartition = %s, expected TRUE\n"
             "    PartitionType = 0x%02x, expected 0x04 (PARTITION_FAT_16)\n"
             "    BootIndicator = %s, expected FALSE\n",
             FdoExtension->DiskData.DeviceNumber,
             PartitionInfo->Mbr.RecognizedPartition ? "TRUE" : "FALSE",
             PartitionInfo->Mbr.PartitionType,
             PartitionInfo->Mbr.BootIndicator ? "TRUE" : "FALSE");
    }

    /* The partition and disk sizes should agree */
    if (PartitionInfo->PartitionLength.QuadPart != FdoExtension->DiskData.DiskSize)
    {
        WARN("PartitionLength = %I64u is different from DiskSize = %I64u\n",
             PartitionInfo->PartitionLength.QuadPart, FdoExtension->DiskData.DiskSize);
    }

    return TRUE;
}

/**
 * @brief
 * Makes the base of the PnP instance ID of a new partition device: the disk's signature (MBR)
 * or GUID (GPT) and the partition's starting offset, as the new layout has them.  Not the length:
 * a resize keeps the partition (IOCTL_DISK_GROW_PARTITION keeps its device), so after a resize and
 * a reboot it has the same ID and installed device key as before.
 **/
static
CODE_SEG("PAGE")
NTSTATUS
PartMgrMakeBaseId(
    _In_ PDRIVE_LAYOUT_INFORMATION_EX Layout,
    _In_ PPARTITION_INFORMATION_EX PartitionEntry,
    _Out_writes_(PARTITION_INSTANCE_ID_CHARS) PWCH BaseId)
{
    int length;

    PAGED_CODE();

    if (Layout->PartitionStyle == PARTITION_STYLE_MBR)
    {
        length = _snwprintf(BaseId, PARTITION_INSTANCE_ID_CHARS, L"S%08lx_O%I64x",
                            Layout->Mbr.Signature,
                            PartitionEntry->StartingOffset.QuadPart);
    }
    else
    {
        length = _snwprintf(BaseId, PARTITION_INSTANCE_ID_CHARS,
                            L"S%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02xS_O%I64x",
                            Layout->Gpt.DiskId.Data1,
                            Layout->Gpt.DiskId.Data2,
                            Layout->Gpt.DiskId.Data3,
                            Layout->Gpt.DiskId.Data4[0],
                            Layout->Gpt.DiskId.Data4[1],
                            Layout->Gpt.DiskId.Data4[2],
                            Layout->Gpt.DiskId.Data4[3],
                            Layout->Gpt.DiskId.Data4[4],
                            Layout->Gpt.DiskId.Data4[5],
                            Layout->Gpt.DiskId.Data4[6],
                            Layout->Gpt.DiskId.Data4[7],
                            PartitionEntry->StartingOffset.QuadPart);
    }
    return (length < 0 || length >= PARTITION_INSTANCE_ID_CHARS) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

/**
 * @brief
 * The PnP instance ID of a partition device, chosen the first time PnP asks for it and then the
 * same for the life of the device (also when IOCTL_DISK_GROW_PARTITION changes its length). It is
 * the base ID unless another device of this disk holds that ID, or a removed one left it behind
 * and may still be in the PnP tree (PartMgrReleaseInstanceId): then the first free "_V<n>"
 * suffix is added, as PnP stops the system on a duplicate instance (bugcheck 0xCA).
 **/
CODE_SEG("PAGE")
NTSTATUS
PartMgrQueryInstanceId(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PPARTITION_EXTENSION PartExt,
    _Out_ PUNICODE_STRING InstanceId)
{
    WCHAR string[PARTITION_INSTANCE_ID_CHARS];
    PPARTITION_ID_RECORD record;
    NTSTATUS status = STATUS_SUCCESS;
    int length;

    PAGED_CODE();

    PartMgrAcquireLayoutLock(FdoExtension);

    record = PartExt->IdRecord;
    if (!record)
    {
        UINT32 suffix = 0;
        PSINGLE_LIST_ENTRY cur = FdoExtension->InstanceIds.Next;

        // the records are few: start over after each suffix that is taken
        while (cur != NULL)
        {
            PPARTITION_ID_RECORD rec = CONTAINING_RECORD(cur, PARTITION_ID_RECORD, ListEntry);

            if (rec->Suffix == suffix && wcscmp(rec->BaseId, PartExt->BaseId) == 0)
            {
                suffix++;
                cur = FdoExtension->InstanceIds.Next;
                continue;
            }
            cur = cur->Next;
        }

        record = ExAllocatePoolZero(PagedPool, sizeof(*record), TAG_PARTMGR);
        if (!record)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        record->Suffix = suffix;
        RtlCopyMemory(record->BaseId, PartExt->BaseId, sizeof(record->BaseId));
        PushEntryList(&FdoExtension->InstanceIds, &record->ListEntry);
        PartExt->IdRecord = record;
    }

    if (record->Suffix == 0)
        length = _snwprintf(string, RTL_NUMBER_OF(string), L"%ls", record->BaseId);
    else
        length = _snwprintf(string, RTL_NUMBER_OF(string), L"%ls_V%lu", record->BaseId, record->Suffix);
    if (length < 0 || length >= (int)RTL_NUMBER_OF(string))
        status = STATUS_BUFFER_OVERFLOW;
    else if (!RtlCreateUnicodeString(InstanceId, string))
        status = STATUS_INSUFFICIENT_RESOURCES;

Exit:
    PartMgrReleaseLayoutLock(FdoExtension);
    return status;
}

/**
 * @brief
 * A partition device is deleted: its instance ID becomes free again, unless the device may
 * still be in the PnP tree, which keeps a devnode until the last reference to the device is
 * gone: when it is still open, or a file system was mounted on it (its VPB is mounted, or a
 * dismount replaced it; a file system keeps references after its dismount). Such an ID is never
 * handed out again on this disk.
 **/
CODE_SEG("PAGE")
VOID
PartMgrReleaseInstanceId(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PPARTITION_EXTENSION PartExt,
    _In_ BOOLEAN LayoutLockHeld)
{
    PDEVICE_OBJECT device = PartExt->DeviceObject;
    PPARTITION_ID_RECORD record;
    BOOLEAN inUse;

    PAGED_CODE();

    inUse = device->ReferenceCount != 0 || device->Vpb != PartExt->CreatedVpb ||
            (device->Vpb && (device->Vpb->Flags & VPB_MOUNTED || device->Vpb->ReferenceCount != 0));

    if (!LayoutLockHeld)
        PartMgrAcquireLayoutLock(FdoExtension);

    record = PartExt->IdRecord;
    PartExt->IdRecord = NULL;
    if (record && !inUse)
    {
        for (PSINGLE_LIST_ENTRY prev = &FdoExtension->InstanceIds; prev->Next != NULL; prev = prev->Next)
        {
            if (prev->Next == &record->ListEntry)
            {
                prev->Next = record->ListEntry.Next;
                ExFreePoolWithTag(record, TAG_PARTMGR);
                break;
            }
        }
    }

    if (!LayoutLockHeld)
        PartMgrReleaseLayoutLock(FdoExtension);
}

// An entry of the layout that is not a partition: an unused or container MBR entry,
// an unused GPT entry (a slot of the entry array that holds nothing)
static
BOOLEAN
PartMgrIsUnusedLayoutEntry(
    _In_ PDRIVE_LAYOUT_INFORMATION_EX Layout,
    _In_ PPARTITION_INFORMATION_EX Entry)
{
    static const GUID unusedGuid = {0};

    if (Layout->PartitionStyle == PARTITION_STYLE_MBR)
    {
        return (Entry->Mbr.PartitionType == PARTITION_ENTRY_UNUSED ||
                IsContainerPartition(Entry->Mbr.PartitionType));
    }
    if (Layout->PartitionStyle == PARTITION_STYLE_GPT)
    {
        return RtlCompareMemory(&Entry->Gpt.PartitionType, &unusedGuid, sizeof(GUID)) == sizeof(GUID);
    }
    return FALSE;
}

static
CODE_SEG("PAGE")
VOID
PartMgrUpdatePartitionDevices(
    _In_ PFDO_EXTENSION FdoExtension,
    _Inout_ PDRIVE_LAYOUT_INFORMATION_EX NewLayout)
{
    NTSTATUS status;
    PSINGLE_LIST_ENTRY curEntry, prevEntry;
    UINT32 totalPartitions = 0;

    // Clear the partition numbers from the list entries
    for (UINT32 i = 0; i < NewLayout->PartitionCount; i++)
    {
        NewLayout->PartitionEntry[i].PartitionNumber = 0;
    }

    // iterate over old partition list
    prevEntry = &FdoExtension->PartitionList;
    curEntry = FdoExtension->PartitionList.Next;
    while (curEntry != NULL)
    {
        PPARTITION_EXTENSION partExt = CONTAINING_RECORD(curEntry, PARTITION_EXTENSION, ListEntry);
        UINT32 partNumber = 0; // count detected partitions for device symlinks
        BOOLEAN found = FALSE;
        PPARTITION_INFORMATION_EX partEntry;

        // trying to find this partition in returned layout
        for (UINT32 i = 0; i < NewLayout->PartitionCount; i++)
        {
            partEntry = &NewLayout->PartitionEntry[i];

            // skip unused and container partitions
            if (PartMgrIsUnusedLayoutEntry(NewLayout, partEntry))
            {
                continue;
            }

            partNumber++;

            // skip already found partitions
            if (partEntry->PartitionNumber)
            {
                continue;
            }

            // skip if partitions are not equal
            if (partEntry->StartingOffset.QuadPart != partExt->StartingOffset ||
                partEntry->PartitionLength.QuadPart != partExt->PartitionLength)
            {
                continue;
            }

            // found matching partition - processing it
            found = TRUE;
            break;
        }

        if (found)
        {
            // update (possibly changed) partition metadata
            if (NewLayout->PartitionStyle == PARTITION_STYLE_MBR)
            {
                partExt->Mbr.PartitionType = partEntry->Mbr.PartitionType;
                partExt->Mbr.BootIndicator = partEntry->Mbr.BootIndicator;
            }
            else
            {
                partExt->Gpt.PartitionType = partEntry->Gpt.PartitionType;
                partExt->Gpt.PartitionId = partEntry->Gpt.PartitionId;
                partExt->Gpt.Attributes = partEntry->Gpt.Attributes;

                RtlCopyMemory(partExt->Gpt.Name, partEntry->Gpt.Name, sizeof(partExt->Gpt.Name));
            }

            partExt->OnDiskNumber = partNumber;
            partEntry->PartitionNumber = partNumber; // mark it as a found one
            totalPartitions++;
        }
        else
        {
            // detach the device from the list
            prevEntry->Next = curEntry->Next;
            curEntry = prevEntry;
            partExt->Attached = FALSE;

            // enumerated PDOs will receive IRP_MN_REMOVE_DEVICE
            if (!partExt->IsEnumerated)
            {
                PartMgrReleaseInstanceId(FdoExtension, partExt, TRUE);
                PartitionHandleRemove(partExt, TRUE);
            }
        }

        prevEntry = curEntry;
        curEntry = curEntry->Next;
    }

    UINT32 partNumber = 0;
    UINT32 pdoNumber = 1;

    // now looking through remaining "new" partitions
    for (UINT32 i = 0; i < NewLayout->PartitionCount; i++)
    {
        PPARTITION_INFORMATION_EX partEntry = &NewLayout->PartitionEntry[i];

        // again, skip unused and container partitions
        if (PartMgrIsUnusedLayoutEntry(NewLayout, partEntry))
        {
            continue;
        }

        partNumber++;

        // and skip processed partitions
        if (partEntry->PartitionNumber != 0)
        {
            continue;
        }

        // find the first free PDO index
        for (PSINGLE_LIST_ENTRY curEntry = FdoExtension->PartitionList.Next;
             curEntry != NULL;
             curEntry = curEntry->Next)
        {
            PPARTITION_EXTENSION partExt = CONTAINING_RECORD(curEntry,
                                                             PARTITION_EXTENSION,
                                                             ListEntry);

            if (partExt->DetectedNumber == pdoNumber)
            {
                // found a matching pdo number - restart the search
                curEntry = FdoExtension->PartitionList.Next;
                pdoNumber++;
            }
        }

        WCHAR baseId[PARTITION_INSTANCE_ID_CHARS];
        status = PartMgrMakeBaseId(NewLayout, partEntry, baseId);
        if (!NT_SUCCESS(status))
        {
            ERR("No instance ID for the partition at %I64x: 0x%lx\n",
                partEntry->StartingOffset.QuadPart, status);
            continue;
        }

        partEntry->PartitionNumber = partNumber;

        PDEVICE_OBJECT partitionDevice;
        status = PartitionCreateDevice(FdoExtension->DeviceObject,
                                       partEntry,
                                       pdoNumber,
                                       NewLayout->PartitionStyle,
                                       baseId,
                                       &partitionDevice);
        if (!NT_SUCCESS(status))
        {
            partEntry->PartitionNumber = 0;
            continue;
        }

        // mark partition as removable if parent device is removable
        if (FdoExtension->LowerDevice->Characteristics & FILE_REMOVABLE_MEDIA)
            partitionDevice->Characteristics |= FILE_REMOVABLE_MEDIA;

        totalPartitions++;

        // insert the structure to the partition list
        curEntry = FdoExtension->PartitionList.Next;
        prevEntry = NULL;
        while (curEntry != NULL)
        {
            PPARTITION_EXTENSION curPart = CONTAINING_RECORD(curEntry,
                                                             PARTITION_EXTENSION,
                                                             ListEntry);
            if (curPart->OnDiskNumber < partNumber)
            {
                prevEntry = curEntry;
                curEntry = curPart->ListEntry.Next;
            }
            else
            { // we found where to put the partition
                break;
            }
        }

        PPARTITION_EXTENSION partExt = partitionDevice->DeviceExtension;

        if (prevEntry)
        {
            // insert after prevEntry
            partExt->ListEntry.Next = prevEntry->Next;
            prevEntry->Next = &partExt->ListEntry;
        }
        else
        {
            // insert at the beginning
            partExt->ListEntry.Next = FdoExtension->PartitionList.Next;
            FdoExtension->PartitionList.Next = &partExt->ListEntry;
        }

        partExt->Attached = TRUE;
    }

    FdoExtension->EnumeratedPartitionsTotal = totalPartitions;
}

// The partition style and the identifier of the disk that the partition manager keeps are those
// of the layout it holds: a new layout (a new table written, or the table read) changes them.
static
CODE_SEG("PAGE")
VOID
PartMgrUpdateDiskData(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PDRIVE_LAYOUT_INFORMATION_EX Layout)
{
    PAGED_CODE();

    FdoExtension->DiskData.PartitionStyle = Layout->PartitionStyle;
    if (Layout->PartitionStyle == PARTITION_STYLE_MBR)
    {
        FdoExtension->DiskData.Mbr.Signature = Layout->Mbr.Signature;
    }
    else
    {
        FdoExtension->DiskData.Gpt.DiskId = Layout->Gpt.DiskId;
    }
}

/**
 * @brief
 * Retrieves the disk partition layout from the given disk FDO.
 *
 * If the disk layout cache is valid, just return it; otherwise,
 * read the partition table layout from disk and update the cache.
 *
 * @note    Requires partitioning lock held.
 **/
static
CODE_SEG("PAGE")
NTSTATUS
PartMgrGetDriveLayout(
    _In_ PFDO_EXTENSION FdoExtension,
    _Out_ PDRIVE_LAYOUT_INFORMATION_EX *DriveLayout)
{
    PAGED_CODE();

    if (FdoExtension->LayoutValid)
    {
        *DriveLayout = FdoExtension->LayoutCache;
        return STATUS_SUCCESS;
    }

    PDRIVE_LAYOUT_INFORMATION_EX layoutEx = NULL;
    NTSTATUS status = IoReadPartitionTableEx(FdoExtension->LowerDevice, &layoutEx);
    if (!NT_SUCCESS(status))
        return status;

    if (FdoExtension->LayoutCache)
        ExFreePool(FdoExtension->LayoutCache);

    FdoExtension->LayoutCache = layoutEx;
    FdoExtension->LayoutValid = TRUE;

    PartMgrUpdateDiskData(FdoExtension, layoutEx);

    FdoExtension->IsSuperFloppy = PartMgrIsDiskSuperFloppy(FdoExtension);

    *DriveLayout = layoutEx;
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskGetDriveGeometryEx(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    // We're patching the DISK_PARTITION_INFO part of the returned structure
    // as disk.sys doesn't really know about the partition table on a disk

    PDISK_GEOMETRY_EX_INTERNAL geometryEx = Irp->AssociatedIrp.SystemBuffer;
    ULONG outBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status;

    status = IssueSyncIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                       FdoExtension->LowerDevice,
                                       NULL,
                                       0,
                                       geometryEx,
                                       outBufferLength,
                                       FALSE);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // if DISK_PARTITION_INFO fits the output size
    if (outBufferLength >= FIELD_OFFSET(DISK_GEOMETRY_EX_INTERNAL, Detection))
    {
        PartMgrAcquireLayoutLock(FdoExtension);

        geometryEx->Partition.SizeOfPartitionInfo = sizeof(geometryEx->Partition);
        geometryEx->Partition.PartitionStyle = FdoExtension->DiskData.PartitionStyle;

        switch (geometryEx->Partition.PartitionStyle)
        {
            case PARTITION_STYLE_MBR:
                geometryEx->Partition.Mbr.Signature = FdoExtension->DiskData.Mbr.Signature;
                // checksum?
                break;

            case PARTITION_STYLE_GPT:
                geometryEx->Partition.Gpt.DiskId = FdoExtension->DiskData.Gpt.DiskId;
                break;

            default:
                RtlZeroMemory(&geometryEx->Partition, sizeof(geometryEx->Partition));
        }

        PartMgrReleaseLayoutLock(FdoExtension);
    }

    // the logic is copied from disk.sys
    Irp->IoStatus.Information = min(outBufferLength, sizeof(DISK_GEOMETRY_EX_INTERNAL));

    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskGetPartitionInfo(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PPARTITION_INFORMATION partInfo = Irp->AssociatedIrp.SystemBuffer;

    PAGED_CODE();

    if (!VerifyIrpOutBufferSize(Irp, sizeof(*partInfo)))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PartMgrAcquireLayoutLock(FdoExtension);

    *partInfo = (PARTITION_INFORMATION){
        .PartitionType = PARTITION_ENTRY_UNUSED,
        .StartingOffset.QuadPart = 0,
        .PartitionLength.QuadPart = FdoExtension->DiskData.DiskSize,
        .HiddenSectors = 0,
        .PartitionNumber = 0,
        .BootIndicator = FALSE,
        .RewritePartition = FALSE,
        .RecognizedPartition = FALSE,
    };

    PartMgrReleaseLayoutLock(FdoExtension);

    Irp->IoStatus.Information = sizeof(*partInfo);
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskGetPartitionInfoEx(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PPARTITION_INFORMATION_EX partInfoEx = Irp->AssociatedIrp.SystemBuffer;

    PAGED_CODE();

    if (!VerifyIrpOutBufferSize(Irp, sizeof(*partInfoEx)))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PartMgrAcquireLayoutLock(FdoExtension);

    // most of the fields a zeroed for Partition0
    *partInfoEx = (PARTITION_INFORMATION_EX){
        .PartitionLength.QuadPart = FdoExtension->DiskData.DiskSize,
        .PartitionStyle = FdoExtension->DiskData.PartitionStyle,
    };

    PartMgrReleaseLayoutLock(FdoExtension);

    Irp->IoStatus.Information = sizeof(*partInfoEx);
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskGetDriveLayout(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    PartMgrAcquireLayoutLock(FdoExtension);

    PDRIVE_LAYOUT_INFORMATION_EX layoutEx;
    NTSTATUS status = PartMgrGetDriveLayout(FdoExtension, &layoutEx);
    if (!NT_SUCCESS(status))
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        return status;
    }

    // checking this value from layoutEx in case it has been changed
    if (layoutEx->PartitionStyle != PARTITION_STYLE_MBR)
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    size_t size = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION, PartitionEntry[0]);
    size += layoutEx->PartitionCount * sizeof(PARTITION_INFORMATION);

    if (!VerifyIrpOutBufferSize(Irp, size))
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDRIVE_LAYOUT_INFORMATION partitionList = PartMgrConvertExtendedToLayout(layoutEx);

    PartMgrReleaseLayoutLock(FdoExtension);

    if (partitionList == NULL)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlMoveMemory(Irp->AssociatedIrp.SystemBuffer, partitionList, size);
    ExFreePoolWithTag(partitionList, TAG_PARTMGR);

    Irp->IoStatus.Information = size;
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskGetDriveLayoutEx(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    PartMgrAcquireLayoutLock(FdoExtension);

    PDRIVE_LAYOUT_INFORMATION_EX layoutEx;
    NTSTATUS status = PartMgrGetDriveLayout(FdoExtension, &layoutEx);
    if (!NT_SUCCESS(status))
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        return status;
    }

    size_t size = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[0]);
    size += layoutEx->PartitionCount * sizeof(PARTITION_INFORMATION_EX);

    if (!VerifyIrpOutBufferSize(Irp, size))
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, layoutEx, size);

    PartMgrReleaseLayoutLock(FdoExtension);

    Irp->IoStatus.Information = size;
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskSetDriveLayout(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PDRIVE_LAYOUT_INFORMATION layoutInfo = Irp->AssociatedIrp.SystemBuffer;

    PAGED_CODE();

    if (!VerifyIrpInBufferSize(Irp, sizeof(*layoutInfo)))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    size_t layoutSize = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION, PartitionEntry[0]);
    layoutSize += layoutInfo->PartitionCount * sizeof(PARTITION_INFORMATION);

    if (!VerifyIrpInBufferSize(Irp, layoutSize))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    PDRIVE_LAYOUT_INFORMATION_EX layoutEx = PartMgrConvertLayoutToExtended(layoutInfo);

    if (layoutEx == NULL)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PartMgrAcquireLayoutLock(FdoExtension);

    // If the current disk is super-floppy but the user changes
    // the number of partitions to > 1, fail the call.
    if (FdoExtension->IsSuperFloppy && (layoutEx->PartitionCount > 1))
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // this in fact updates the bus relations
    PartMgrUpdatePartitionDevices(FdoExtension, layoutEx);

    // write the partition table to the disk
    NTSTATUS status = IoWritePartitionTableEx(FdoExtension->LowerDevice, layoutEx);
    if (NT_SUCCESS(status))
    {
        // save the layout cache
        if (FdoExtension->LayoutCache)
        {
            ExFreePool(FdoExtension->LayoutCache);
        }
        FdoExtension->LayoutCache = layoutEx;
        FdoExtension->LayoutValid = TRUE;
        PartMgrUpdateDiskData(FdoExtension, layoutEx);

        // set updated partition numbers
        for (UINT32 i = 0; i < layoutInfo->PartitionCount; i++)
        {
            PPARTITION_INFORMATION part = &layoutInfo->PartitionEntry[i];

            part->PartitionNumber = layoutEx->PartitionEntry[i].PartitionNumber;
        }

        FdoExtension->IsSuperFloppy = PartMgrIsDiskSuperFloppy(FdoExtension);
    }
    else
    {
        FdoExtension->LayoutValid = FALSE;
    }

    PartMgrReleaseLayoutLock(FdoExtension);

    IoInvalidateDeviceRelations(FdoExtension->PhysicalDiskDO, BusRelations);

    // notify everyone that the disk layout has changed
    TARGET_DEVICE_CUSTOM_NOTIFICATION notification;

    notification.Event = GUID_IO_DISK_LAYOUT_CHANGE;
    notification.Version = 1;
    notification.Size = FIELD_OFFSET(TARGET_DEVICE_CUSTOM_NOTIFICATION, CustomDataBuffer);
    notification.FileObject = NULL;
    notification.NameBufferOffset = -1;

    IoReportTargetDeviceChangeAsynchronous(FdoExtension->PhysicalDiskDO,
                                           &notification,
                                           NULL,
                                           NULL);

    Irp->IoStatus.Information = layoutSize;
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskSetDriveLayoutEx(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PDRIVE_LAYOUT_INFORMATION_EX layoutEx, layoutUser = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status;
    BOOLEAN isGpt, returnLayout = FALSE;

    PAGED_CODE();

    if (!VerifyIrpInBufferSize(Irp, sizeof(*layoutUser)))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    size_t layoutSize = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[0]);
    layoutSize += layoutUser->PartitionCount * sizeof(PARTITION_INFORMATION_EX);

    if (!VerifyIrpInBufferSize(Irp, layoutSize))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    // we need to copy the structure from the IRP input buffer
    layoutEx = ExAllocatePoolWithTag(PagedPool, layoutSize, TAG_PARTMGR);
    if (!layoutEx)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(layoutEx, layoutUser, layoutSize);
    isGpt = (layoutEx->PartitionStyle == PARTITION_STYLE_GPT);

    PartMgrAcquireLayoutLock(FdoExtension);

    // If the current disk is super-floppy but the user changes either
    // the disk type or the number of partitions to > 1, fail the call.
    if (FdoExtension->IsSuperFloppy &&
        ((layoutEx->PartitionStyle != PARTITION_STYLE_MBR) ||
         (layoutEx->PartitionCount > 1)))
    {
        PartMgrReleaseLayoutLock(FdoExtension);
        ExFreePool(layoutEx);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // if partition count is 0, it's the same as IOCTL_DISK_CREATE_DISK
    if (layoutEx->PartitionCount == 0)
    {
        CREATE_DISK createDisk = {0};
        createDisk.PartitionStyle = layoutEx->PartitionStyle;
        if (createDisk.PartitionStyle == PARTITION_STYLE_MBR)
        {
            createDisk.Mbr.Signature = layoutEx->Mbr.Signature;
        }
        else if (createDisk.PartitionStyle == PARTITION_STYLE_GPT)
        {
            createDisk.Gpt.DiskId = layoutEx->Gpt.DiskId;
        }

        status = IoCreateDisk(FdoExtension->LowerDevice, &createDisk);
    }
    else
    {
        if (layoutEx->PartitionStyle == PARTITION_STYLE_GPT)
        {
            // the writer puts every partition into its slot of the entry array and returns
            // the layout in table order: the partitions are numbered in that order
            status = IoWritePartitionTableEx(FdoExtension->LowerDevice, layoutEx);
            if (NT_SUCCESS(status))
            {
                // this in fact updates the bus relations
                PartMgrUpdatePartitionDevices(FdoExtension, layoutEx);
            }
        }
        else
        {
            // this in fact updates the bus relations
            PartMgrUpdatePartitionDevices(FdoExtension, layoutEx);

            // write the partition table to the disk
            status = IoWritePartitionTableEx(FdoExtension->LowerDevice, layoutEx);
        }


    }

    // update the layout cache
    if (NT_SUCCESS(status))
    {
        if (FdoExtension->LayoutCache)
        {
            ExFreePool(FdoExtension->LayoutCache);
        }
        FdoExtension->LayoutCache = layoutEx;
        FdoExtension->LayoutValid = TRUE;
        PartMgrUpdateDiskData(FdoExtension, layoutEx);

        FdoExtension->IsSuperFloppy = PartMgrIsDiskSuperFloppy(FdoExtension);

        // return the layout with the updated partition numbers, in table order, to a caller that gave
        // room for it. This is done here: once the lock is released the cache (which is now layoutEx)
        // can be replaced and freed by another request.
        if (isGpt && VerifyIrpOutBufferSize(Irp, layoutSize))
        {
            RtlCopyMemory(layoutUser, layoutEx, layoutSize);
            returnLayout = TRUE;
        }
    }
    else
    {
        FdoExtension->LayoutValid = FALSE;
        ExFreePool(layoutEx);
        layoutEx = NULL;
    }

    PartMgrReleaseLayoutLock(FdoExtension);

    IoInvalidateDeviceRelations(FdoExtension->PhysicalDiskDO, BusRelations);

    // notify everyone that the disk layout has changed
    TARGET_DEVICE_CUSTOM_NOTIFICATION notification;

    notification.Event = GUID_IO_DISK_LAYOUT_CHANGE;
    notification.Version = 1;
    notification.Size = FIELD_OFFSET(TARGET_DEVICE_CUSTOM_NOTIFICATION, CustomDataBuffer);
    notification.FileObject = NULL;
    notification.NameBufferOffset = -1;

    IoReportTargetDeviceChangeAsynchronous(FdoExtension->PhysicalDiskDO,
                                           &notification,
                                           NULL,
                                           NULL);

    if (isGpt)
    {
        // a failed write is reported
        Irp->IoStatus.Information = returnLayout ? layoutSize : 0;
        return status;
    }

    Irp->IoStatus.Information = layoutSize;
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskUpdateProperties(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    PartMgrAcquireLayoutLock(FdoExtension);
    FdoExtension->LayoutValid = FALSE;
    PartMgrReleaseLayoutLock(FdoExtension);

    IoInvalidateDeviceRelations(FdoExtension->PhysicalDiskDO, BusRelations);
    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskCreateDisk(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    PCREATE_DISK createDisk = Irp->AssociatedIrp.SystemBuffer;
    if (!VerifyIrpInBufferSize(Irp, sizeof(*createDisk)))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    PartMgrAcquireLayoutLock(FdoExtension);

    NTSTATUS status = IoCreateDisk(FdoExtension->LowerDevice, createDisk);

    FdoExtension->LayoutValid = FALSE;
    PartMgrReleaseLayoutLock(FdoExtension);

    IoInvalidateDeviceRelations(FdoExtension->PhysicalDiskDO, BusRelations);
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskDeleteDriveLayout(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    CREATE_DISK createDisk = { .PartitionStyle = PARTITION_STYLE_RAW };

    PAGED_CODE();

    PartMgrAcquireLayoutLock(FdoExtension);

    NTSTATUS status = IoCreateDisk(FdoExtension->LowerDevice, &createDisk);

    FdoExtension->LayoutValid = FALSE;
    PartMgrReleaseLayoutLock(FdoExtension);

    IoInvalidateDeviceRelations(FdoExtension->PhysicalDiskDO, BusRelations);
    return status;
}

static
CODE_SEG("PAGE")
BOOLEAN
PartMgrIsUsedEntry(
    _In_ PDRIVE_LAYOUT_INFORMATION_EX Layout,
    _In_ PPARTITION_INFORMATION_EX Entry)
{
    PAGED_CODE();

    if (Layout->PartitionStyle == PARTITION_STYLE_MBR)
        return Entry->Mbr.PartitionType != PARTITION_ENTRY_UNUSED && Entry->PartitionLength.QuadPart != 0;
    return Entry->PartitionLength.QuadPart != 0;
}

/**
 * @brief
 * IOCTL_DISK_GROW_PARTITION: changes the length of one partition by
 * BytesToGrow (negative shrinks it), keeping its start, number and device.
 * The new end must stay on the disk (an MBR logical partition's container
 * grows with it), in the GPT usable area, and off every other partition and
 * EBR. Behaviour measured on Windows Server 2008 R2.
 **/
static
CODE_SEG("PAGE")
NTSTATUS
FdoIoctlDiskGrowPartition(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PDISK_GROW_PARTITION grow = Irp->AssociatedIrp.SystemBuffer;
    PDRIVE_LAYOUT_INFORMATION_EX layout, newLayout;
    PPARTITION_INFORMATION_EX entry = NULL;
    PPARTITION_EXTENSION partExt = NULL;
    UINT32 i, index = 0, partNumber = 0, container = MAXULONG;
    INT64 start, oldEnd, newLen, newEnd, limit;
    UINT64 sectorSize;
    BOOLEAN changed = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    if (!VerifyIrpInBufferSize(Irp, sizeof(*grow)))
        return STATUS_INFO_LENGTH_MISMATCH;

    PartMgrAcquireLayoutLock(FdoExtension);

    status = PartMgrGetDriveLayout(FdoExtension, &layout);
    if (!NT_SUCCESS(status))
        goto Exit;

    if (FdoExtension->IsSuperFloppy || layout->PartitionStyle == PARTITION_STYLE_RAW)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    // partition numbers count the used entries that are not MBR containers, in layout order
    for (i = 0; i < layout->PartitionCount; i++)
    {
        PPARTITION_INFORMATION_EX cur = &layout->PartitionEntry[i];

        if (!PartMgrIsUsedEntry(layout, cur) ||
            (layout->PartitionStyle == PARTITION_STYLE_MBR && IsContainerPartition(cur->Mbr.PartitionType)))
        {
            continue;
        }
        if (++partNumber == grow->PartitionNumber)
        {
            entry = cur;
            index = i;
            break;
        }
    }
    if (!entry || grow->PartitionNumber == 0)
    {
        status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    // The layout numbers the partitions in order, while a partition device keeps the number it got
    // when it appeared; after a layout change the two can differ. Only a partition both agree on
    // is grown: the device of the entry (if any) carries the number, and no other device does.
    for (PSINGLE_LIST_ENTRY cur = FdoExtension->PartitionList.Next; cur != NULL; cur = cur->Next)
    {
        PPARTITION_EXTENSION pe = CONTAINING_RECORD(cur, PARTITION_EXTENSION, ListEntry);
        BOOLEAN isEntry = pe->StartingOffset == (UINT64)entry->StartingOffset.QuadPart &&
                          pe->PartitionLength == (UINT64)entry->PartitionLength.QuadPart;

        if (isEntry != (pe->DetectedNumber == grow->PartitionNumber))
        {
            status = STATUS_NO_SUCH_DEVICE;
            goto Exit;
        }
    }

    sectorSize = FdoExtension->DiskData.BytesPerSector ? FdoExtension->DiskData.BytesPerSector : 512;
    start = entry->StartingOffset.QuadPart;
    oldEnd = start + entry->PartitionLength.QuadPart;
    if (grow->BytesToGrow.QuadPart == 0)
    {
        status = STATUS_SUCCESS;
        goto Exit;
    }
    if (grow->BytesToGrow.QuadPart <= -entry->PartitionLength.QuadPart ||
        grow->BytesToGrow.QuadPart > (INT64)FdoExtension->DiskData.DiskSize)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    // bytes become whole sectors as the table stores them: an MBR sector count,
    // a GPT ending LBA (which takes in a partial last sector)
    newEnd = oldEnd + grow->BytesToGrow.QuadPart;
    if (layout->PartitionStyle == PARTITION_STYLE_GPT)
        newEnd = (INT64)(((UINT64)(newEnd - 1) / sectorSize + 1) * sectorSize);
    else
        newEnd = start + (INT64)((UINT64)(newEnd - start) / sectorSize * sectorSize);
    newLen = newEnd - start;
    if (newLen <= 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if (newEnd == oldEnd)
    {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    // the area the partition may occupy
    if (layout->PartitionStyle == PARTITION_STYLE_GPT)
        limit = layout->Gpt.StartingUsableOffset.QuadPart + layout->Gpt.UsableLength.QuadPart;
    else
        limit = (INT64)FdoExtension->DiskData.DiskSize;
    // an MBR entry holds a 32-bit sector count (its 32-bit start does not change)
    if (newEnd > limit ||
        (layout->PartitionStyle == PARTITION_STYLE_MBR && (UINT64)newLen / sectorSize > MAXULONG))
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // a logical partition may take its container along past the container's end
    if (layout->PartitionStyle == PARTITION_STYLE_MBR && index >= 4)
    {
        for (i = 0; i < min(layout->PartitionCount, 4); i++)
        {
            PPARTITION_INFORMATION_EX cur = &layout->PartitionEntry[i];

            if (IsContainerPartition(cur->Mbr.PartitionType) &&
                start >= cur->StartingOffset.QuadPart &&
                start < cur->StartingOffset.QuadPart + cur->PartitionLength.QuadPart)
            {
                container = i;
                break;
            }
        }
    }

    // the grown range may not reach any other partition (logical: nor the next EBR)
    for (i = 0; i < layout->PartitionCount && newEnd > oldEnd; i++)
    {
        PPARTITION_INFORMATION_EX cur = &layout->PartitionEntry[i];
        INT64 curStart = cur->StartingOffset.QuadPart;
        INT64 curEnd = curStart + cur->PartitionLength.QuadPart;

        if (i == index || i == container || !PartMgrIsUsedEntry(layout, cur))
            continue;
        // a link entry starts at the next EBR
        if (layout->PartitionStyle == PARTITION_STYLE_MBR && i >= 4 && IsContainerPartition(cur->Mbr.PartitionType))
            curEnd = curStart + (INT64)sectorSize;
        if (curStart < newEnd && curEnd > oldEnd)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }

    size_t layoutSize = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[0]) +
                        layout->PartitionCount * sizeof(PARTITION_INFORMATION_EX);
    newLayout = ExAllocatePoolWithTag(PagedPool, layoutSize, TAG_PARTMGR);
    if (!newLayout)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlCopyMemory(newLayout, layout, layoutSize);

    for (i = 0; i < newLayout->PartitionCount; i++)
        newLayout->PartitionEntry[i].RewritePartition = FALSE;
    newLayout->PartitionEntry[index].PartitionLength.QuadPart = newLen;
    newLayout->PartitionEntry[index].RewritePartition = TRUE;

    if (container != MAXULONG)
    {
        PPARTITION_INFORMATION_EX ext = &newLayout->PartitionEntry[container];

        if (ext->StartingOffset.QuadPart + ext->PartitionLength.QuadPart < newEnd)
        {
            if ((UINT64)(newEnd - ext->StartingOffset.QuadPart) / sectorSize > MAXULONG)
            {
                ExFreePoolWithTag(newLayout, TAG_PARTMGR);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }
            ext->PartitionLength.QuadPart = newEnd - ext->StartingOffset.QuadPart;
            ext->RewritePartition = TRUE;
        }
    }

    if (newLayout->PartitionStyle == PARTITION_STYLE_MBR && index >= 4)
    {
        // the link entry of the previous EBR spans this partition's EBR and the partition:
        // it follows a shrink when it ended with the partition, and holds a larger one
        for (i = 4; i < newLayout->PartitionCount; i++)
        {
            PPARTITION_INFORMATION_EX link = &newLayout->PartitionEntry[i];
            INT64 linkEnd = link->StartingOffset.QuadPart + link->PartitionLength.QuadPart;

            if (!IsContainerPartition(link->Mbr.PartitionType) ||
                link->StartingOffset.QuadPart > start || linkEnd <= start)
            {
                continue;
            }
            if (linkEnd < newEnd || (linkEnd == oldEnd && newEnd < oldEnd))
            {
                link->PartitionLength.QuadPart = newEnd - link->StartingOffset.QuadPart;
                link->RewritePartition = TRUE;
            }
        }
    }

    status = IoWritePartitionTableEx(FdoExtension->LowerDevice, newLayout);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(newLayout, TAG_PARTMGR);
        FdoExtension->LayoutValid = FALSE;
        goto Exit;
    }

    for (i = 0; i < newLayout->PartitionCount; i++)
        newLayout->PartitionEntry[i].RewritePartition = FALSE;

    // the partition device keeps its identity and gets the new length
    for (PSINGLE_LIST_ENTRY cur = FdoExtension->PartitionList.Next; cur != NULL; cur = cur->Next)
    {
        PPARTITION_EXTENSION pe = CONTAINING_RECORD(cur, PARTITION_EXTENSION, ListEntry);

        if (pe->StartingOffset == (UINT64)start && pe->PartitionLength == (UINT64)(oldEnd - start))
        {
            pe->PartitionLength = newLen;
            // kept for the notification after the layout lock goes, when a removal may run
            if (pe->IsEnumerated)
            {
                partExt = pe;
                ObReferenceObject(pe->DeviceObject);
            }
            break;
        }
    }

    ExFreePool(FdoExtension->LayoutCache);
    FdoExtension->LayoutCache = newLayout;
    FdoExtension->LayoutValid = TRUE;
    changed = TRUE;

Exit:
    PartMgrReleaseLayoutLock(FdoExtension);

    if (changed)
    {
        TARGET_DEVICE_CUSTOM_NOTIFICATION notification;

        notification.Version = 1;
        notification.Size = FIELD_OFFSET(TARGET_DEVICE_CUSTOM_NOTIFICATION, CustomDataBuffer);
        notification.FileObject = NULL;
        notification.NameBufferOffset = -1;

        notification.Event = GUID_IO_DISK_LAYOUT_CHANGE;
        IoReportTargetDeviceChangeAsynchronous(FdoExtension->PhysicalDiskDO, &notification, NULL, NULL);

        if (partExt)
        {
            notification.Event = GUID_IO_VOLUME_CHANGE_SIZE;
            IoReportTargetDeviceChangeAsynchronous(partExt->DeviceObject, &notification, NULL, NULL);
            ObDereferenceObject(partExt->DeviceObject);
        }
    }

    Irp->IoStatus.Information = 0;
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoHandleStartDevice(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    // Obtain the disk device number.
    // It is not expected to change, thus not in PartMgrRefreshDiskData().
    STORAGE_DEVICE_NUMBER deviceNumber;
    NTSTATUS status = IssueSyncIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                                FdoExtension->LowerDevice,
                                                NULL,
                                                0,
                                                &deviceNumber,
                                                sizeof(deviceNumber),
                                                FALSE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FdoExtension->DiskData.DeviceNumber = deviceNumber.DeviceNumber;

    // Register the disk interface.
    // partmgr.sys from Windows 8.1 also registers a mysterious GUID_DEVINTERFACE_HIDDEN_DISK here.
    UNICODE_STRING interfaceName;
    status = IoRegisterDeviceInterface(FdoExtension->PhysicalDiskDO,
                                       &GUID_DEVINTERFACE_DISK,
                                       NULL,
                                       &interfaceName);
    if(!NT_SUCCESS(status))
    {
        ERR("Failed to register GUID_DEVINTERFACE_DISK, status %x\n", status);
        return status;
    }

    INFO("Disk interface %wZ\n", &interfaceName);
    FdoExtension->DiskInterfaceName = interfaceName;
    status = IoSetDeviceInterfaceState(&interfaceName, TRUE);
    if (!NT_SUCCESS(status))
    {
        RtlFreeUnicodeString(&interfaceName);
        RtlInitUnicodeString(&FdoExtension->DiskInterfaceName, NULL);
    }

    return status;
}

/**
 * @brief
 * Refreshes all the cached disk FDO data.
 * The geometry of the disk and its partition layout cache is updated.
 *
 * @note    Requires partitioning lock held.
 **/
static
CODE_SEG("PAGE")
NTSTATUS
PartMgrRefreshDiskData(
    _In_ PFDO_EXTENSION FdoExtension)
{
    NTSTATUS status;

    PAGED_CODE();

    // get the DiskSize and BytesPerSector
    DISK_GEOMETRY_EX geometryEx;
    status = IssueSyncIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                       FdoExtension->LowerDevice,
                                       NULL,
                                       0,
                                       &geometryEx,
                                       sizeof(geometryEx),
                                       FALSE);
    if (!NT_SUCCESS(status))
        return status;

    FdoExtension->DiskData.DiskSize = geometryEx.DiskSize.QuadPart;
    FdoExtension->DiskData.BytesPerSector = geometryEx.Geometry.BytesPerSector;

    // get the partition style-related info
    PDRIVE_LAYOUT_INFORMATION_EX layoutEx = NULL;
    status = PartMgrGetDriveLayout(FdoExtension, &layoutEx);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoHandleDeviceRelations(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    DEVICE_RELATION_TYPE type = ioStack->Parameters.QueryDeviceRelations.Type;

    PAGED_CODE();

    if (type == BusRelations)
    {
        PartMgrAcquireLayoutLock(FdoExtension);

        NTSTATUS status = PartMgrRefreshDiskData(FdoExtension);
        if (!NT_SUCCESS(status))
        {
            PartMgrReleaseLayoutLock(FdoExtension);
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return Irp->IoStatus.Status;
        }

        INFO("Partition style %u\n", FdoExtension->DiskData.PartitionStyle);

        // PartMgrRefreshDiskData() calls PartMgrGetDriveLayout() inside
        // so we're sure here that it returns only the cached layout.
        PDRIVE_LAYOUT_INFORMATION_EX layoutEx;
        PartMgrGetDriveLayout(FdoExtension, &layoutEx);

        PartMgrUpdatePartitionDevices(FdoExtension, layoutEx);

        // now fill the DeviceRelations structure
        TRACE("Reporting %u partitions\n", FdoExtension->EnumeratedPartitionsTotal);

        PDEVICE_RELATIONS deviceRelations =
            ExAllocatePoolWithTag(PagedPool,
                                  FIELD_OFFSET(DEVICE_RELATIONS, Objects)
                                  + sizeof(PDEVICE_OBJECT)
                                  * FdoExtension->EnumeratedPartitionsTotal,
                                  TAG_PARTMGR);

        if (!deviceRelations)
        {
            PartMgrReleaseLayoutLock(FdoExtension);
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return Irp->IoStatus.Status;
        }

        deviceRelations->Count = 0;

        PSINGLE_LIST_ENTRY curEntry = FdoExtension->PartitionList.Next;
        while (curEntry != NULL)
        {
            PPARTITION_EXTENSION partExt = CONTAINING_RECORD(curEntry,
                                                             PARTITION_EXTENSION,
                                                             ListEntry);

            // mark the PDO to know that we don't need to manually delete it
            partExt->IsEnumerated = TRUE;
            deviceRelations->Objects[deviceRelations->Count++] = partExt->DeviceObject;
            ObReferenceObject(partExt->DeviceObject);

            curEntry = partExt->ListEntry.Next;
        }

        ASSERT(deviceRelations->Count == FdoExtension->EnumeratedPartitionsTotal);

        PartMgrReleaseLayoutLock(FdoExtension);

        Irp->IoStatus.Information = (ULONG_PTR)deviceRelations;
        Irp->IoStatus.Status = STATUS_SUCCESS;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(FdoExtension->LowerDevice, Irp);
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoHandleRemoveDevice(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    if (FdoExtension->DiskInterfaceName.Buffer)
    {
        IoSetDeviceInterfaceState(&FdoExtension->DiskInterfaceName, FALSE);
        RtlFreeUnicodeString(&FdoExtension->DiskInterfaceName);
        RtlInitUnicodeString(&FdoExtension->DiskInterfaceName, NULL);
    }

    // Send the IRP down the stack
    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    NTSTATUS status = IoCallDriver(FdoExtension->LowerDevice, Irp);

    // the partitions still listed got their IRP_MN_REMOVE_DEVICE before the disk (those PnP knew)
    // and stayed because they were in the layout: they go with the disk
    PSINGLE_LIST_ENTRY entry;
    while ((entry = PopEntryList(&FdoExtension->PartitionList)) != NULL)
    {
        PPARTITION_EXTENSION partExt = CONTAINING_RECORD(entry, PARTITION_EXTENSION, ListEntry);

        partExt->Attached = FALSE;
        PartitionHandleRemove(partExt, TRUE);
    }

    while ((entry = PopEntryList(&FdoExtension->InstanceIds)) != NULL)
    {
        ExFreePoolWithTag(CONTAINING_RECORD(entry, PARTITION_ID_RECORD, ListEntry), TAG_PARTMGR);
    }

    IoDetachDevice(FdoExtension->LowerDevice);
    IoDeleteDevice(FdoExtension->DeviceObject);
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
FdoHandleSurpriseRemoval(
    _In_ PFDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    // all enumerated child devices receive IRP_MN_REMOVE_DEVICE (and stay listed until the disk's
    // removal, FdoHandleRemoveDevice); only the ones PnP never saw are removed here
    PartMgrAcquireLayoutLock(FdoExtension);
    for (PSINGLE_LIST_ENTRY prevEntry = &FdoExtension->PartitionList; prevEntry->Next != NULL;)
    {
        PPARTITION_EXTENSION partExt = CONTAINING_RECORD(prevEntry->Next,
                                                         PARTITION_EXTENSION,
                                                         ListEntry);

        if (partExt->IsEnumerated)
        {
            prevEntry = prevEntry->Next;
            continue;
        }
        prevEntry->Next = partExt->ListEntry.Next;
        partExt->Attached = FALSE;
        PartitionHandleRemove(partExt, TRUE);
    }
    PartMgrReleaseLayoutLock(FdoExtension);

    // Send the IRP down the stack
    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    return IoCallDriver(FdoExtension->LowerDevice, Irp);
}

static
CODE_SEG("PAGE")
NTSTATUS
NTAPI
PartMgrAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDEVICE_OBJECT deviceObject;

    PAGED_CODE();

    /*
     * Create the disk FDO. Use FILE_DEVICE_MASS_STORAGE type (or any other
     * one that is NOT FILE_DEVICE_[DISK|VIRTUAL_DISK|CD_ROM|TAPE]), so that
     * IoCreateDevice() doesn't automatically create a VPB for this device,
     * even if we will later want this device to inherit the type of the
     * underlying PDO which can have any of the types mentioned above.
     */
    NTSTATUS status = IoCreateDevice(DriverObject,
                                     sizeof(FDO_EXTENSION),
                                     NULL,
                                     FILE_DEVICE_MASS_STORAGE,
                                     FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN,
                                     FALSE,
                                     &deviceObject);
    if (!NT_SUCCESS(status))
    {
        ERR("Failed to create FDO 0x%x\n", status);
        return status;
    }

    PFDO_EXTENSION deviceExtension = deviceObject->DeviceExtension;
    RtlZeroMemory(deviceExtension, sizeof(*deviceExtension));

    deviceExtension->IsFDO = TRUE;
    deviceExtension->DeviceObject = deviceObject;
    deviceExtension->LowerDevice = IoAttachDeviceToDeviceStack(deviceObject, PhysicalDeviceObject);
    if (!deviceExtension->LowerDevice)
    {
        // The attachment failed
        IoDeleteDevice(deviceObject);
        return STATUS_DEVICE_REMOVED;
    }
    deviceExtension->PhysicalDiskDO = PhysicalDeviceObject;
    KeInitializeEvent(&deviceExtension->SyncEvent, SynchronizationEvent, TRUE);
    PartMgrIoStatsInit(&deviceExtension->IoStats);

    // Update now the device type with the actual underlying device type
    deviceObject->DeviceType = deviceExtension->LowerDevice->DeviceType;

    deviceObject->Flags |= DO_DIRECT_IO | DO_POWER_PAGABLE;

    // The device is initialized
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
PartMgrDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    PFDO_EXTENSION fdoExtension = DeviceObject->DeviceExtension;
    NTSTATUS status;

    // Note: IRP_MJ_DEVICE_CONTROL handler in the storage stack must be able to pass IOCTLs
    // at an IRQL higher than PASSIVE_LEVEL

    INFO("IRP_MJ_DEVICE_CONTROL %p Irp %p IOCTL %x isFdo: %u\n",
        DeviceObject, Irp, ioStack->Parameters.DeviceIoControl.IoControlCode, fdoExtension->IsFDO);

    if (!fdoExtension->IsFDO)
    {
        return PartitionHandleDeviceControl(DeviceObject, Irp);
    }

    switch (ioStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
            status = FdoIoctlDiskGetDriveGeometryEx(fdoExtension, Irp);
            break;

        case IOCTL_DISK_GET_PARTITION_INFO:
            status = FdoIoctlDiskGetPartitionInfo(fdoExtension, Irp);
            break;

        case IOCTL_DISK_GET_PARTITION_INFO_EX:
            status = FdoIoctlDiskGetPartitionInfoEx(fdoExtension, Irp);
            break;

        case IOCTL_DISK_GET_DRIVE_LAYOUT:
            status = FdoIoctlDiskGetDriveLayout(fdoExtension, Irp);
            break;

        case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
            status = FdoIoctlDiskGetDriveLayoutEx(fdoExtension, Irp);
            break;

        case IOCTL_DISK_SET_DRIVE_LAYOUT:
            status = FdoIoctlDiskSetDriveLayout(fdoExtension, Irp);
            break;

        case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
            status = FdoIoctlDiskSetDriveLayoutEx(fdoExtension, Irp);
            break;

        case IOCTL_DISK_UPDATE_PROPERTIES:
            status = FdoIoctlDiskUpdateProperties(fdoExtension, Irp);
            break;

        case IOCTL_DISK_CREATE_DISK:
            status = FdoIoctlDiskCreateDisk(fdoExtension, Irp);
            break;

        case IOCTL_DISK_DELETE_DRIVE_LAYOUT:
            status = FdoIoctlDiskDeleteDriveLayout(fdoExtension, Irp);
            break;
        case IOCTL_DISK_GROW_PARTITION:
            status = FdoIoctlDiskGrowPartition(fdoExtension, Irp);
            break;

        case IOCTL_DISK_PERFORMANCE:
            status = PartMgrIoctlDiskPerformance(&fdoExtension->IoStats,
                                                 fdoExtension->DiskData.DeviceNumber,
                                                 Irp);
            break;

        default:
            return ForwardIrpAndForget(DeviceObject, Irp);
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static
CODE_SEG("PAGE")
NTSTATUS
NTAPI
PartMgrPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    PFDO_EXTENSION fdoExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

    INFO("IRP_MJ_PNP %p Irp %p %s isFDO: %u\n",
        DeviceObject, Irp, GetIRPMinorFunctionString(ioStack->MinorFunction), fdoExtension->IsFDO);

    if (!fdoExtension->IsFDO)
    {
        return PartitionHandlePnp(DeviceObject, Irp);
    }

    switch (ioStack->MinorFunction) {

        case IRP_MN_START_DEVICE:
        {
            NTSTATUS status;

            // if this is sent to the FDO so we should forward it down the
            // attachment chain before we can start the FDO

            if (!IoForwardIrpSynchronously(fdoExtension->LowerDevice, Irp))
            {
                status = STATUS_UNSUCCESSFUL;
            }
            else
            {
                status = FdoHandleStartDevice(fdoExtension, Irp);
            }

            Irp->IoStatus.Status = status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return status;
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            return FdoHandleDeviceRelations(fdoExtension, Irp);
        }
        case IRP_MN_SURPRISE_REMOVAL:
        {
            return FdoHandleSurpriseRemoval(fdoExtension, Irp);
        }
        case IRP_MN_REMOVE_DEVICE:
        {
            return FdoHandleRemoveDevice(fdoExtension, Irp);
        }
        case IRP_MN_QUERY_STOP_DEVICE:
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_STOP_DEVICE:
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            // fallthrough
        }
        default:
        {
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(fdoExtension->LowerDevice, Irp);
        }
    }
}

static
NTSTATUS
NTAPI
PartMgrReadWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPARTITION_EXTENSION partExt = DeviceObject->DeviceExtension;
    PPARTMGR_IO_STATS stats;

    if (!partExt->IsFDO)
    {
        // a partition that left the layout reads and writes no more: its sectors may belong to
        // another partition now
        if (!partExt->IsEnumerated || !partExt->Attached)
        {
            Irp->IoStatus.Status = STATUS_DEVICE_DOES_NOT_EXIST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_DEVICE_DOES_NOT_EXIST;
        }
        stats = &partExt->IoStats;
    }
    else
    {
        stats = &((PFDO_EXTENSION)partExt)->IoStats;
    }

    // the next driver gets the request (a partition's moved to its place on the disk); this
    // location keeps the original and the time the request started
    IoCopyCurrentIrpStackLocationToNext(Irp);
    if (!partExt->IsFDO)
        IoGetNextIrpStackLocation(Irp)->Parameters.Read.ByteOffset.QuadPart += partExt->StartingOffset;

    return PartMgrIoStatsCallDriver(stats, partExt->LowerDevice, Irp);
}

DRIVER_DISPATCH PartMgrPower;
NTSTATUS
NTAPI
PartMgrPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPARTITION_EXTENSION partExt = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

    PoStartNextPowerIrp(Irp);

    if (!partExt->IsFDO)
    {
        NTSTATUS status;

        if (!partExt->IsEnumerated)
        {
            status = STATUS_DEVICE_DOES_NOT_EXIST;
        }
        else if (ioStack->MinorFunction == IRP_MN_SET_POWER ||
                 ioStack->MinorFunction == IRP_MN_QUERY_POWER)
        {
            status = STATUS_SUCCESS;
        }
        else
        {
            status = Irp->IoStatus.Status;
        }

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    else
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(partExt->LowerDevice, Irp);
    }
}

DRIVER_DISPATCH PartMgrShutdownFlush;
NTSTATUS
NTAPI
PartMgrShutdownFlush(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPARTITION_EXTENSION partExt = DeviceObject->DeviceExtension;
    PDEVICE_OBJECT lowerDevice;

    // forward to the partition0 device in both cases
    if (!partExt->IsFDO)
    {
        if (!partExt->IsEnumerated)
        {
            Irp->IoStatus.Status = STATUS_DEVICE_DOES_NOT_EXIST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_DEVICE_DOES_NOT_EXIST;
        }
        else
        {
            PFDO_EXTENSION fdoExtension = partExt->LowerDevice->DeviceExtension;
            lowerDevice = fdoExtension->LowerDevice;
        }
    }
    else
    {
        lowerDevice = partExt->LowerDevice;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(lowerDevice, Irp);
}

CODE_SEG("PAGE")
VOID
NTAPI
PartMgrUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{

}

CODE_SEG("INIT")
NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    DriverObject->DriverUnload = PartMgrUnload;
    DriverObject->DriverExtension->AddDevice = PartMgrAddDevice;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = ForwardIrpAndForget;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = ForwardIrpAndForget;
    DriverObject->MajorFunction[IRP_MJ_READ]           = PartMgrReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = PartMgrReadWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PartMgrDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_PNP]            = PartMgrPnp;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]       = PartMgrShutdownFlush;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]  = PartMgrShutdownFlush;
    DriverObject->MajorFunction[IRP_MJ_POWER]          = PartMgrPower;

    return STATUS_SUCCESS;
}
