/*
* PROJECT:         ReactOS Kernel
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            ntoskrnl/io/iomgr/arcname.c
* PURPOSE:         ARC Path Initialization Functions
* PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
*                  Eric Kohl
*                  Pierre Schweitzer (pierre.schweitzer@reactos.org)
*/

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include <ntddscsi.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

UNICODE_STRING IoArcHalDeviceName, IoArcBootDeviceName;
PCHAR IoLoaderArcBootDeviceName;

/* FUNCTIONS *****************************************************************/

CODE_SEG("INIT")
NTSTATUS
NTAPI
IopCreateArcNamesCd(IN PLOADER_PARAMETER_BLOCK LoaderBlock);

CODE_SEG("INIT")
NTSTATUS
NTAPI
IopCreateArcNamesDisk(IN PLOADER_PARAMETER_BLOCK LoaderBlock,
                      IN BOOLEAN SingleDisk,
                      OUT PBOOLEAN FoundBoot);

CODE_SEG("INIT")
NTSTATUS
NTAPI
IopCreateArcNames(IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    SIZE_T Length;
    NTSTATUS Status;
    CHAR Buffer[128];
    BOOLEAN SingleDisk;
    BOOLEAN FoundBoot = FALSE;
    UNICODE_STRING SystemDevice, LoaderPathNameW, BootDeviceName;
    PARC_DISK_INFORMATION ArcDiskInfo = LoaderBlock->ArcDiskInformation;
    ANSI_STRING ArcString, LanmanRedirector, LoaderPathNameA;

    /* Check if we only have one disk on the machine */
    SingleDisk = (ArcDiskInfo->DiskSignatureListHead.Flink->Flink ==
                 &ArcDiskInfo->DiskSignatureListHead);

    /* This runs again while waiting for the boot device, drop the previous names */
    RtlFreeUnicodeString(&IoArcHalDeviceName);
    RtlFreeUnicodeString(&IoArcBootDeviceName);
    if (IoLoaderArcBootDeviceName)
    {
        ExFreePoolWithTag(IoLoaderArcBootDeviceName, TAG_IO);
        IoLoaderArcBootDeviceName = NULL;
    }

    /* Create the firmware system loader / HAL partition global name */
    sprintf(Buffer, "\\ArcName\\%s", LoaderBlock->ArcHalDeviceName);
    RtlInitAnsiString(&ArcString, Buffer);
    Status = RtlAnsiStringToUnicodeString(&IoArcHalDeviceName, &ArcString, TRUE);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Create the OS boot partition global name */
    sprintf(Buffer, "\\ArcName\\%s", LoaderBlock->ArcBootDeviceName);
    RtlInitAnsiString(&ArcString, Buffer);
    Status = RtlAnsiStringToUnicodeString(&IoArcBootDeviceName, &ArcString, TRUE);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Allocate memory for the string */
    Length = strlen(LoaderBlock->ArcBootDeviceName) + sizeof(ANSI_NULL);
    IoLoaderArcBootDeviceName = ExAllocatePoolWithTag(PagedPool,
                                                      Length,
                                                      TAG_IO);
    if (IoLoaderArcBootDeviceName)
    {
        /* Copy the name */
        RtlCopyMemory(IoLoaderArcBootDeviceName,
                      LoaderBlock->ArcBootDeviceName,
                      Length);
    }

    /* Check if we only found a disk, but we're booting from CD-ROM */
    if ((SingleDisk) && strstr(LoaderBlock->ArcBootDeviceName, "cdrom"))
    {
        /* Then disable single-disk mode, since there's a CD drive out there */
        SingleDisk = FALSE;
    }

    /* If we are doing remote booting */
    if (IoRemoteBootClient)
    {
        /* Yes, we have found boot device */
        FoundBoot = TRUE;

        /* Get NT device name */
        RtlInitAnsiString(&LanmanRedirector, "\\Device\\LanmanRedirector");
        Status = RtlAnsiStringToUnicodeString(&SystemDevice, &LanmanRedirector, TRUE);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

        /* Get ARC booting device name (in net(0) something) */
        sprintf(Buffer, "\\ArcName\\%s", LoaderBlock->ArcBootDeviceName);
        RtlInitAnsiString(&ArcString, Buffer);
        Status = RtlAnsiStringToUnicodeString(&BootDeviceName, &ArcString, TRUE);
        if (NT_SUCCESS(Status))
        {
            /* Map ARC to NT name */
            IoAssignArcName(&BootDeviceName, &SystemDevice);
            RtlFreeUnicodeString(&BootDeviceName);

            /* Now, get loader path name */
            RtlInitAnsiString(&LoaderPathNameA, LoaderBlock->NtHalPathName);
            Status = RtlAnsiStringToUnicodeString(&LoaderPathNameW, &LoaderPathNameA, TRUE);
            if (!NT_SUCCESS(Status))
            {
                RtlFreeUnicodeString(&SystemDevice);
                return Status;
            }

            /* And set it has system partition */
            IopStoreSystemPartitionInformation(&SystemDevice, &LoaderPathNameW);
        }

        RtlFreeUnicodeString(&SystemDevice);

        /* Don't quit here, even if everything went fine!
         * We need IopCreateArcNamesDisk to properly map
         * devices with symlinks.
         * It will return success if the mapping process went fine
         * even if it didn't find boot device.
         * It won't reset boot device finding status as well.
         */
    }

    /* Loop every disk and try to find boot disk */
    Status = IopCreateArcNamesDisk(LoaderBlock, SingleDisk, &FoundBoot);
    /* If it succeeded but we didn't find boot device, try to browse Cds */
    if (NT_SUCCESS(Status) && !FoundBoot)
    {
        Status = IopCreateArcNamesCd(LoaderBlock);
    }

    /* Return success */
    return Status;
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
IopCreateArcNamesCd(IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;
    PLIST_ENTRY NextEntry;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    LARGE_INTEGER StartingOffset;
    IO_STATUS_BLOCK IoStatusBlock;
    PULONG PartitionBuffer = NULL;
    CHAR Buffer[128], ArcBuffer[128];
    BOOLEAN NotEnabledPresent = FALSE;
    STORAGE_DEVICE_NUMBER DeviceNumber;
    ANSI_STRING DeviceStringA, ArcNameStringA;
    PWSTR SymbolicLinkList, lSymbolicLinkList;
    PARC_DISK_SIGNATURE ArcDiskSignature = NULL;
    UNICODE_STRING DeviceStringW, ArcNameStringW;
    ULONG DiskNumber, CdRomCount, CheckSum, i, EnabledDisks = 0;
    PARC_DISK_INFORMATION ArcDiskInformation = LoaderBlock->ArcDiskInformation;

    /* Get all the Cds present in the system */
    CdRomCount = IoGetConfigurationInformation()->CdRomCount;

    /* Get enabled Cds and check if result matches
     * For the record, enabled Cds (or even disk) are Cds/disks
     * that have been successfully handled by MountMgr driver
     * and that already own their device name. This is the "new" way
     * to handle them, that came with NT5.
     * Currently, Windows 2003 provides an ARC names creation based
     * on both enabled drives and not enabled drives (lack from
     * the driver).
     * Given the current ReactOS state, that's good for us.
     * To sum up, this is NOT a hack or whatsoever.
     */
    Status = IopFetchConfigurationInformation(&SymbolicLinkList,
                                              GUID_DEVINTERFACE_CDROM,
                                              CdRomCount,
                                              &EnabledDisks);
    if (!NT_SUCCESS(Status))
    {
        NotEnabledPresent = TRUE;
    }
    /* Save symbolic link list address in order to free it after */
    lSymbolicLinkList = SymbolicLinkList;
    /* For the moment, we won't fail */
    Status = STATUS_SUCCESS;

    /* Browse all the ARC devices trying to find the one matching boot device */
    for (NextEntry = ArcDiskInformation->DiskSignatureListHead.Flink;
         NextEntry != &ArcDiskInformation->DiskSignatureListHead;
         NextEntry = NextEntry->Flink)
    {
        ArcDiskSignature = CONTAINING_RECORD(NextEntry,
                                             ARC_DISK_SIGNATURE,
                                             ListEntry);

        if (strcmp(LoaderBlock->ArcBootDeviceName, ArcDiskSignature->ArcName) == 0)
        {
            break;
        }

        ArcDiskSignature = NULL;
    }

    /* Not found... Not booting from a Cd */
    if (!ArcDiskSignature)
    {
        DPRINT("Failed finding a cd that could match current boot device\n");
        goto Cleanup;
    }

    /* Allocate needed space for reading Cd */
    PartitionBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, 2048, TAG_IO);
    if (!PartitionBuffer)
    {
        DPRINT("Failed allocating resources!\n");
        /* Here, we fail, BUT we return success, some Microsoft joke */
        goto Cleanup;
    }

    /* If we have more enabled Cds, take that into account */
    if (EnabledDisks > CdRomCount)
    {
        CdRomCount = EnabledDisks;
    }

    /* If we'll have to browse for none enabled Cds, fix higher count */
    if (NotEnabledPresent && !EnabledDisks)
    {
        CdRomCount += 5;
    }

    /* Finally, if in spite of all that work, we still don't have Cds, leave */
    if (!CdRomCount)
    {
        goto Cleanup;
    }

    /* Start browsing Cds */
    for (DiskNumber = 0, EnabledDisks = 0; DiskNumber < CdRomCount; DiskNumber++)
    {
        /* Check if we have an enabled disk */
        if (lSymbolicLinkList && *lSymbolicLinkList != UNICODE_NULL)
        {
            /* Create its device name using first symbolic link */
            RtlInitUnicodeString(&DeviceStringW, lSymbolicLinkList);
            /* Then, update symbolic links list */
            lSymbolicLinkList += wcslen(lSymbolicLinkList) + (sizeof(UNICODE_NULL) / sizeof(WCHAR));

            /* Get its associated device object and file object */
            Status = IoGetDeviceObjectPointer(&DeviceStringW,
                                              FILE_READ_ATTRIBUTES,
                                              &FileObject,
                                              &DeviceObject);
            /* A Cd that went away since its interface arrived cannot be the boot device: try the next one.
             * It is not a failure of the initialization (IopMarkBootPartition waits for the boot device and
             * stops with INACCESSIBLE_BOOT_DEVICE if it does not appear) */
            if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
                Status == STATUS_OBJECT_PATH_NOT_FOUND ||
                Status == STATUS_NO_SUCH_DEVICE)
            {
                Status = STATUS_SUCCESS;
                continue;
            }

            /* Failure? Good bye! */
            if (!NT_SUCCESS(Status))
            {
                goto Cleanup;
            }

            /* Now, we'll ask the device its device number */
            Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                                DeviceObject,
                                                NULL,
                                                0,
                                                &DeviceNumber,
                                                sizeof(DeviceNumber),
                                                FALSE,
                                                &Event,
                                                &IoStatusBlock);
            /* Failure? Good bye! */
            if (!Irp)
            {
                /* Dereference file object before leaving */
                ObDereferenceObject(FileObject);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }

            /* Call the driver, and wait for it if needed */
            KeInitializeEvent(&Event, NotificationEvent, FALSE);
            Status = IoCallDriver(DeviceObject, Irp);
            if (Status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = IoStatusBlock.Status;
            }
            if (!NT_SUCCESS(Status))
            {
                /* A Cd that cannot say which one it is cannot be matched: try the next one */
                ObDereferenceObject(FileObject);
                Status = STATUS_SUCCESS;
                continue;
            }

            /* Finally, build proper device name */
            sprintf(Buffer, "\\Device\\CdRom%lu", DeviceNumber.DeviceNumber);
            RtlInitAnsiString(&DeviceStringA, Buffer);
            Status = RtlAnsiStringToUnicodeString(&DeviceStringW, &DeviceStringA, TRUE);
            if (!NT_SUCCESS(Status))
            {
                ObDereferenceObject(FileObject);
                goto Cleanup;
            }
        }
        else
        {
            /* Create device name for the cd */
            sprintf(Buffer, "\\Device\\CdRom%lu", EnabledDisks++);
            RtlInitAnsiString(&DeviceStringA, Buffer);
            Status = RtlAnsiStringToUnicodeString(&DeviceStringW, &DeviceStringA, TRUE);
            if (!NT_SUCCESS(Status))
            {
                goto Cleanup;
            }

            /* Get its device object */
            Status = IoGetDeviceObjectPointer(&DeviceStringW,
                                              FILE_READ_ATTRIBUTES,
                                              &FileObject,
                                              &DeviceObject);
            if (!NT_SUCCESS(Status))
            {
                RtlFreeUnicodeString(&DeviceStringW);

                /* A Cd that is not there yet is not a failure of the initialization:
                 * IopMarkBootPartition waits for the boot device (as it does for a disk)
                 * and stops with INACCESSIBLE_BOOT_DEVICE if it does not appear */
                if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
                    Status == STATUS_OBJECT_PATH_NOT_FOUND ||
                    Status == STATUS_NO_SUCH_DEVICE)
                {
                    Status = STATUS_SUCCESS;
                }
                goto Cleanup;
            }
        }

        /* Initiate data for reading cd and compute checksum */
        StartingOffset.QuadPart = 0x8000;
        CheckSum = 0;
        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           DeviceObject,
                                           PartitionBuffer,
                                           2048,
                                           &StartingOffset,
                                           &Event,
                                           &IoStatusBlock);
        if (Irp)
        {
            /* Call the driver, and wait for it if needed */
            KeInitializeEvent(&Event, NotificationEvent, FALSE);
            Status = IoCallDriver(DeviceObject, Irp);
            if (Status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = IoStatusBlock.Status;
            }

            /* If reading succeeded, compute checksum by adding data, 2048 bytes checksum */
            if (NT_SUCCESS(Status))
            {
                for (i = 0; i < 2048 / sizeof(ULONG); i++)
                {
                    CheckSum += PartitionBuffer[i];
                }
            }
        }

        /* Dereference file object */
        ObDereferenceObject(FileObject);

        /* If checksums are matching, we have the proper cd */
        if (CheckSum + ArcDiskSignature->CheckSum == 0)
        {
            /* Create ARC name */
            sprintf(ArcBuffer, "\\ArcName\\%s", LoaderBlock->ArcBootDeviceName);
            RtlInitAnsiString(&ArcNameStringA, ArcBuffer);
            Status = RtlAnsiStringToUnicodeString(&ArcNameStringW, &ArcNameStringA, TRUE);
            if (NT_SUCCESS(Status))
            {
                /* Create symbolic link */
                IoAssignArcName(&ArcNameStringW, &DeviceStringW);
                RtlFreeUnicodeString(&ArcNameStringW);
                DPRINT("Boot device found\n");
            }

            /* And quit, whatever happens */
            RtlFreeUnicodeString(&DeviceStringW);
            goto Cleanup;
        }

        /* Free string before trying another disk */
        RtlFreeUnicodeString(&DeviceStringW);
    }

    /* No Cd matched (the status left is that of the last read): the boot device may still appear */
    Status = STATUS_SUCCESS;

Cleanup:
    if (PartitionBuffer)
    {
        ExFreePoolWithTag(PartitionBuffer, TAG_IO);
    }

    if (SymbolicLinkList)
    {
        ExFreePool(SymbolicLinkList);
    }

    return Status;
}

/*
 * Where a disk is, in the terms of the INT 13h EDD device path of the BIOS: the PCI function of its controller
 * (the nearest ancestor in the device tree that is a PCI device) and the SCSI address the port driver gives it
 * (path = IDE channel or SCSI bus, target = IDE device or SCSI target).
 */
typedef struct _IOP_DISK_LOCATION
{
    BOOLEAN Valid;
    ULONG Bus;
    ULONG Slot;
    ULONG Function;
    ULONG Path;
    ULONG Target;
    ULONG Lun;
    ULONG IoBase;       /* IDE: first I/O port of the channel, 0 = not known */
} IOP_DISK_LOCATION, *PIOP_DISK_LOCATION;

CODE_SEG("INIT")
static VOID
IopGetDiskLocation(
    _In_ PDEVICE_OBJECT DiskDevice,
    _Out_ PIOP_DISK_LOCATION Location)
{
    PDEVICE_OBJECT Pdo;
    PDEVICE_NODE Node;
    SCSI_ADDRESS Address;
    KEVENT Event;
    IO_STATUS_BLOCK Iosb;
    PIRP Irp;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOLEAN HavePci = FALSE;

    RtlZeroMemory(Location, sizeof(*Location));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_GET_ADDRESS, DiskDevice, NULL, 0, &Address, sizeof(Address),
                                        FALSE, &Event, &Iosb);
    if (Irp)
    {
        Status = IoCallDriver(DiskDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = Iosb.Status;
        }
    }
    if (!NT_SUCCESS(Status))
        return;
    Location->Path = Address.PathId;
    Location->Target = Address.TargetId;
    Location->Lun = Address.Lun;

    Pdo = IoGetDeviceAttachmentBaseRef(DiskDevice);
    for (Node = IopGetDeviceNode(Pdo); Node != NULL; Node = Node->Parent)
    {
        ULONG Addr, Bus, Len;

        /* An IDE channel: the first I/O port it was given */
        if (Node->InstancePath.Length >= 8 * sizeof(WCHAR) &&
            _wcsnicmp(Node->InstancePath.Buffer, L"PCIIDE\\", 7) == 0 &&
            Node->ResourceList != NULL && Node->ResourceList->Count > 0)
        {
            PCM_PARTIAL_RESOURCE_LIST Partial = &Node->ResourceList->List[0].PartialResourceList;
            ULONG k;

            for (k = 0; k < Partial->Count; k++)
            {
                if (Partial->PartialDescriptors[k].Type == CmResourceTypePort)
                {
                    Location->IoBase = Partial->PartialDescriptors[k].u.Port.Start.LowPart;
                    break;
                }
            }
        }

        if (Node->InstancePath.Length < 4 * sizeof(WCHAR) ||
            _wcsnicmp(Node->InstancePath.Buffer, L"PCI\\", 4) != 0 ||
            Node->PhysicalDeviceObject == NULL)
        {
            continue;
        }
        if (NT_SUCCESS(IoGetDeviceProperty(Node->PhysicalDeviceObject, DevicePropertyAddress, sizeof(Addr), &Addr, &Len)) &&
            NT_SUCCESS(IoGetDeviceProperty(Node->PhysicalDeviceObject, DevicePropertyBusNumber, sizeof(Bus), &Bus, &Len)))
        {
            Location->Bus = Bus;
            Location->Slot = Addr >> 16;
            Location->Function = Addr & 0xFFFF;
            HavePci = TRUE;
        }
        break;
    }
    ObDereferenceObject(Pdo);

    Location->Valid = HavePci;
}

/* The position record the loader appended to the ArcName of an entry (ARC_DISK_POSITION), if there is one */
CODE_SEG("INIT")
static BOOLEAN
IopGetArcDiskPosition(
    _In_ PARC_DISK_SIGNATURE ArcDisk,
    _Out_ PARC_DISK_POSITION Position)
{
    SIZE_T NameLength = strlen(ArcDisk->ArcName) + 1;

    /* The loader's ArcName buffer is 260 bytes (MAX_PATH) long; a record that would not fit in it is not one */
    if (NameLength + sizeof(*Position) > 260)
        return FALSE;
    RtlCopyMemory(Position, ArcDisk->ArcName + NameLength, sizeof(*Position));
    if (Position->Magic != ARC_DISK_POSITION_MAGIC || Position->Version != 1 ||
        Position->Length > ARC_DISK_POSITION_DATA)
    {
        return FALSE;
    }
    return (Position->Kind == ARC_DISK_POSITION_EDD && Position->Length >= 0x24) ||
           (Position->Kind == ARC_DISK_POSITION_UEFI && Position->Length >= 4);
}

/*
 * The UEFI device path of a disk against its location: one PCI node (a path through a bridge has several and
 * does not match), then, as the firmware's driver gives it, nothing (virtio-blk, one disk per function), an ATA
 * (channel, device), SCSI (target, lun), SATA (port) or NVMe (one namespace per function) node.
 */
CODE_SEG("INIT")
static BOOLEAN
IopUefiPathMatches(
    _In_ PARC_DISK_POSITION Position,
    _In_ PIOP_DISK_LOCATION Location)
{
    ULONG Offset, Length, PciNodes = 0;
    PUCHAR Data = Position->Data;
    BOOLEAN Match = TRUE;

    for (Offset = 0; Offset + 4 <= Position->Length; Offset += Length)
    {
        Length = Data[Offset + 2] | (Data[Offset + 3] << 8);
        if (Length < 4 || Offset + Length > Position->Length)
            return FALSE;
        if (Data[Offset] == 0x7F)
            break;
        if (Data[Offset] == 1 && Data[Offset + 1] == 1 && Length >= 6)
        {
            /* PCI: function, device */
            PciNodes++;
            if (Location->Function != Data[Offset + 4] || Location->Slot != Data[Offset + 5])
                Match = FALSE;
        }
        else if (Data[Offset] == 3 && Data[Offset + 1] == 1 && Length >= 8)
        {
            /* ATA: primary or secondary channel, master or slave */
            if (Location->Path != Data[Offset + 4] || Location->Target != Data[Offset + 5])
                Match = FALSE;
        }
        else if (Data[Offset] == 3 && Data[Offset + 1] == 2 && Length >= 8)
        {
            /* SCSI: target, lun */
            if (Location->Target != (ULONG)(Data[Offset + 4] | (Data[Offset + 5] << 8)) ||
                Location->Lun != (ULONG)(Data[Offset + 6] | (Data[Offset + 7] << 8)))
            {
                Match = FALSE;
            }
        }
        else if (Data[Offset] == 3 && Data[Offset + 1] == 0x12 && Length >= 10)
        {
            /* SATA: HBA port */
            if (Location->Path != (ULONG)(Data[Offset + 4] | (Data[Offset + 5] << 8)))
                Match = FALSE;
        }
    }
    return PciNodes == 1 && Match;
}

/* Two entries of the ARC list that are byte-identical copies of one disk */
CODE_SEG("INIT")
static BOOLEAN
IopArcDisksAreCopies(
    _In_ PARC_DISK_SIGNATURE A,
    _In_ PARC_DISK_SIGNATURE B)
{
    if (A == B || !A->ValidPartitionTable || !B->ValidPartitionTable || A->IsGpt != B->IsGpt)
        return FALSE;
    if (A->CheckSum != B->CheckSum)
        return FALSE;
    if (A->IsGpt)
        return RtlEqualMemory(A->GptSignature, B->GptSignature, sizeof(A->GptSignature));
    return A->Signature != 0 && A->Signature == B->Signature;
}

/*
 * Is the disk at the position the loader recorded for an entry? TRUE also when the record says nothing the kernel
 * can compare (a host bus other than PCI): then the position cannot exclude the disk.
 * The record is the EDD device path of INT 13h AH=48h: host bus "PCI ", interface "ATA" or "SCSI", interface path =
 * PCI bus, slot, function, channel; device path = ATA device (0, 1); or a UEFI device path.
 */
CODE_SEG("INIT")
static BOOLEAN
IopPositionMatches(
    _In_ PARC_DISK_POSITION Position,
    _In_ PIOP_DISK_LOCATION Location)
{
    PUCHAR Path;

    if (Position->Kind == ARC_DISK_POSITION_UEFI)
        return IopUefiPathMatches(Position, Location);

    /* Data: key (2), length, reserved (3), host bus type (4), interface type (8), interface path (8), device path (8) */
    Path = Position->Data;
    if (RtlCompareMemory(&Path[6], "PCI ", 4) != 4)
        return TRUE;
    if (Path[18] != Location->Bus || Path[19] != Location->Slot || Path[20] != Location->Function)
        return FALSE;
    if (RtlCompareMemory(&Path[10], "ATA     ", 8) == 8)
    {
        /* The channel: by the port base the BIOS gave (the channel byte of SeaBIOS is 0 for both channels), else by the byte */
        if (Position->IoBase != 0 && Location->IoBase != 0)
        {
            if (Position->IoBase != Location->IoBase)
                return FALSE;
        }
        else if (Path[21] != Location->Path)
        {
            return FALSE;
        }
        return Path[26] == Location->Target;
    }
    if (Path[21] != Location->Path)
        return FALSE;
    /* SCSI: SeaBIOS reports the controller only (measured): two disks of one controller have the same position */
    return TRUE;
}

/*
 * May this disk take the ARC names of this entry? Yes, unless the entry has a copy in the list (then the disks
 * match each other by signature and checksum and the first one of the enumeration would take every name) and the
 * disk is, by the recorded positions, the disk of ANOTHER copy and not of this entry. Everything else is as it was
 * before this check: no copy, no record on the entry, a disk whose position cannot be found, a position that belongs
 * to no copy, two copies with the same position (the firmware did not tell them apart): the first disk that
 * matches takes the names. The check never leaves an entry without a disk that took its names before.
 */
CODE_SEG("INIT")
static BOOLEAN
IopArcPositionAllows(
    _In_ PARC_DISK_INFORMATION ArcDiskInformation,
    _In_ PARC_DISK_SIGNATURE Entry,
    _In_ PIOP_DISK_LOCATION Location)
{
    PLIST_ENTRY NextEntry;
    ARC_DISK_POSITION Position, Other;
    BOOLEAN HasCopy = FALSE;

    if (!Location->Valid)
        return TRUE;

    for (NextEntry = ArcDiskInformation->DiskSignatureListHead.Flink;
         NextEntry != &ArcDiskInformation->DiskSignatureListHead;
         NextEntry = NextEntry->Flink)
    {
        if (IopArcDisksAreCopies(Entry, CONTAINING_RECORD(NextEntry, ARC_DISK_SIGNATURE, ListEntry)))
        {
            HasCopy = TRUE;
            break;
        }
    }
    DPRINT("ARC %s: copy %d, disk at PCI %lu:%lu.%lu path %lu target %lu iobase %lx\n", Entry->ArcName, HasCopy,
           Location->Bus, Location->Slot, Location->Function, Location->Path, Location->Target, Location->IoBase);
    if (!HasCopy || !IopGetArcDiskPosition(Entry, &Position))
        return TRUE;

    if (IopPositionMatches(&Position, Location))
        return TRUE;

    /* Not this entry's position: refuse the names only if the disk is positively another copy's */
    for (NextEntry = ArcDiskInformation->DiskSignatureListHead.Flink;
         NextEntry != &ArcDiskInformation->DiskSignatureListHead;
         NextEntry = NextEntry->Flink)
    {
        PARC_DISK_SIGNATURE Copy = CONTAINING_RECORD(NextEntry, ARC_DISK_SIGNATURE, ListEntry);

        if (IopArcDisksAreCopies(Entry, Copy) && IopGetArcDiskPosition(Copy, &Other) &&
            IopPositionMatches(&Other, Location))
        {
            DPRINT("ARC %s: the disk belongs to %s\n", Entry->ArcName, Copy->ArcName);
            return FALSE;
        }
    }
    return TRUE;
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
IopCreateArcNamesDisk(IN PLOADER_PARAMETER_BLOCK LoaderBlock,
                      IN BOOLEAN SingleDisk,
                      OUT PBOOLEAN FoundBoot)
{
    PIRP Irp;
    PVOID Data;
    KEVENT Event;
    NTSTATUS Status;
    PLIST_ENTRY NextEntry;
    PFILE_OBJECT FileObject;
    DISK_GEOMETRY DiskGeometry;
    PDEVICE_OBJECT DeviceObject;
    LARGE_INTEGER StartingOffset;
    PULONG PartitionBuffer = NULL;
    IO_STATUS_BLOCK IoStatusBlock;
    CHAR Buffer[128], ArcBuffer[128];
    BOOLEAN NotEnabledPresent = FALSE;
    STORAGE_DEVICE_NUMBER DeviceNumber;
    PARC_DISK_SIGNATURE ArcDiskSignature;
    IOP_DISK_LOCATION DiskLocation;
    PWSTR SymbolicLinkList, lSymbolicLinkList;
    PDRIVE_LAYOUT_INFORMATION_EX DriveLayout = NULL;
    UNICODE_STRING DeviceStringW, ArcNameStringW, HalPathStringW;
    ULONG DiskNumber, DiskCount, CheckSum, i, Signature, EnabledDisks = 0;
    PARC_DISK_INFORMATION ArcDiskInformation = LoaderBlock->ArcDiskInformation;
    ANSI_STRING ArcBootString, ArcSystemString, DeviceStringA, ArcNameStringA, HalPathStringA;

    /* Initialise device number */
    DeviceNumber.DeviceNumber = ULONG_MAX;
    /* Get all the disks present in the system */
    DiskCount = IoGetConfigurationInformation()->DiskCount;

    /* Get enabled disks and check if result matches */
    Status = IopFetchConfigurationInformation(&SymbolicLinkList,
                                              GUID_DEVINTERFACE_DISK,
                                              DiskCount,
                                              &EnabledDisks);
    if (!NT_SUCCESS(Status))
    {
        NotEnabledPresent = TRUE;
    }

    /* Save symbolic link list address in order to free it after */
    lSymbolicLinkList = SymbolicLinkList;

    /* Build the boot strings */
    RtlInitAnsiString(&ArcBootString, LoaderBlock->ArcBootDeviceName);
    RtlInitAnsiString(&ArcSystemString, LoaderBlock->ArcHalDeviceName);

    /* If we have more enabled disks, take that into account */
    if (EnabledDisks > DiskCount)
    {
        DiskCount = EnabledDisks;
    }

    /* If we'll have to browse for none enabled disks, fix higher count */
    if (NotEnabledPresent && !EnabledDisks)
    {
        DiskCount += 20;
    }

    /* Finally, if in spite of all that work, we still don't have disks, leave */
    if (!DiskCount)
    {
        goto Cleanup;
    }

    /* Start browsing disks */
    for (DiskNumber = 0; DiskNumber < DiskCount; DiskNumber++)
    {
        ASSERT(DriveLayout == NULL);

        /* Check if we have an enabled disk */
        if (lSymbolicLinkList && *lSymbolicLinkList != UNICODE_NULL)
        {
            /* Create its device name using first symbolic link */
            RtlInitUnicodeString(&DeviceStringW, lSymbolicLinkList);
            /* Then, update symbolic links list */
            lSymbolicLinkList += wcslen(lSymbolicLinkList) + (sizeof(UNICODE_NULL) / sizeof(WCHAR));

            /* Get its associated device object and file object */
            Status = IoGetDeviceObjectPointer(&DeviceStringW,
                                              FILE_READ_ATTRIBUTES,
                                              &FileObject,
                                              &DeviceObject);
            if (NT_SUCCESS(Status))
            {
                /* Now, we'll ask the device its device number */
                Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                                    DeviceObject,
                                                    NULL,
                                                    0,
                                                    &DeviceNumber,
                                                    sizeof(DeviceNumber),
                                                    FALSE,
                                                    &Event,
                                                    &IoStatusBlock);
                /* Missing resources is a shame... No need to go farther */
                if (!Irp)
                {
                    ObDereferenceObject(FileObject);
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Cleanup;
                }

                /* Call the driver, and wait for it if needed */
                KeInitializeEvent(&Event, NotificationEvent, FALSE);
                Status = IoCallDriver(DeviceObject, Irp);
                if (Status == STATUS_PENDING)
                {
                    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                    Status = IoStatusBlock.Status;
                }

                /* If we didn't get the appropriate data, just skip that disk */
                if (!NT_SUCCESS(Status))
                {
                   ObDereferenceObject(FileObject);
                   continue;
                }
            }

            /* End of enabled disks enumeration */
            if (NotEnabledPresent && *lSymbolicLinkList == UNICODE_NULL)
            {
                /* No enabled disk worked, reset field */
                if (DeviceNumber.DeviceNumber == ULONG_MAX)
                {
                    DeviceNumber.DeviceNumber = 0;
                }

                /* Update disk number to enable the following not enabled disks */
                if (DeviceNumber.DeviceNumber > DiskNumber)
                {
                    DiskNumber = DeviceNumber.DeviceNumber;
                }

                /* Increase a bit more */
                DiskCount = DiskNumber + 20;
            }
        }
        else
        {
            /* Create device name for the disk */
            sprintf(Buffer, "\\Device\\Harddisk%lu\\Partition0", DiskNumber);
            RtlInitAnsiString(&DeviceStringA, Buffer);
            Status = RtlAnsiStringToUnicodeString(&DeviceStringW, &DeviceStringA, TRUE);
            if (!NT_SUCCESS(Status))
            {
                goto Cleanup;
            }

            /* Get its device object */
            Status = IoGetDeviceObjectPointer(&DeviceStringW,
                                              FILE_READ_ATTRIBUTES,
                                              &FileObject,
                                              &DeviceObject);

            RtlFreeUnicodeString(&DeviceStringW);
            /* This is a security measure, to ensure DiskNumber will be used */
            DeviceNumber.DeviceNumber = ULONG_MAX;
        }

        /* Something failed somewhere earlier, just skip the disk */
        if (!NT_SUCCESS(Status))
        {
            continue;
        }

        /* Where the disk is, for the copies of a disk that the loader found in the same ARC list */
        IopGetDiskLocation(DeviceObject, &DiskLocation);

        /* Let's ask the disk for its geometry */
        Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                            DeviceObject,
                                            NULL,
                                            0,
                                            &DiskGeometry,
                                            sizeof(DiskGeometry),
                                            FALSE,
                                            &Event,
                                            &IoStatusBlock);
        /* Missing resources is a shame... No need to go farther */
        if (!Irp)
        {
            ObDereferenceObject(FileObject);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        /* Call the driver, and wait for it if needed */
        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }
        /* Failure, skip disk */
        if (!NT_SUCCESS(Status))
        {
            ObDereferenceObject(FileObject);
            continue;
        }

        /* Read the partition table */
        Status = IoReadPartitionTableEx(DeviceObject,
                                        &DriveLayout);
        if (!NT_SUCCESS(Status))
        {
            ObDereferenceObject(FileObject);
            continue;
        }

        /* Ensure we have at least 512 bytes per sector */
        if (DiskGeometry.BytesPerSector < 512)
        {
            DiskGeometry.BytesPerSector = 512;
        }

        /* Check MBR type against EZ Drive type */
        StartingOffset.QuadPart = 0;
        HalExamineMBR(DeviceObject, DiskGeometry.BytesPerSector, PARTITION_EZDRIVE, &Data);
        if (Data)
        {
            /* If MBR is of the EZ Drive type, we'll read after it */
            StartingOffset.QuadPart = DiskGeometry.BytesPerSector;
            ExFreePool(Data);
        }

        /* Allocate for reading enough data for checksum */
        PartitionBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, DiskGeometry.BytesPerSector, TAG_IO);
        if (!PartitionBuffer)
        {
            ObDereferenceObject(FileObject);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        /* Read the first sector for computing checksum */
        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           DeviceObject,
                                           PartitionBuffer,
                                           DiskGeometry.BytesPerSector,
                                           &StartingOffset,
                                           &Event,
                                           &IoStatusBlock);
        if (!Irp)
        {
            ExFreePoolWithTag(PartitionBuffer, TAG_IO);
            ObDereferenceObject(FileObject);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        /* Call the driver to perform reading */
        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        /* If reading succeeded, calculate checksum by adding data */
        if (NT_SUCCESS(Status))
        {
            for (i = 0, CheckSum = 0; i < 512 / sizeof(ULONG); i++)
            {
                CheckSum += PartitionBuffer[i];
            }
        }

        /* Release now unnecessary resources */
        ExFreePoolWithTag(PartitionBuffer, TAG_IO);
        ObDereferenceObject(FileObject);

        /* If we failed, release drive layout before going to next disk */
        if (!NT_SUCCESS(Status))
        {
            ExFreePool(DriveLayout);
            DriveLayout = NULL;
            continue;
        }

        /* Browse each ARC disk */
        for (NextEntry = ArcDiskInformation->DiskSignatureListHead.Flink;
             NextEntry != &ArcDiskInformation->DiskSignatureListHead;
             NextEntry = NextEntry->Flink)
        {
            ArcDiskSignature = CONTAINING_RECORD(NextEntry,
                                                 ARC_DISK_SIGNATURE,
                                                 ListEntry);

            /*
             * If this is the only MBR disk in the ARC list and detected in
             * the device tree, just go ahead and create the ArcName links.
             * Otherwise, verify whether the signatures and checksums match
             * before proceeding.
             */
            if (((SingleDisk && (DiskCount == 1) &&
                  (DriveLayout->PartitionStyle == PARTITION_STYLE_MBR)) ||
                 (IopVerifyDiskSignature(DriveLayout, ArcDiskSignature, &Signature) &&
                  (ArcDiskSignature->CheckSum + CheckSum == 0))) &&
                IopArcPositionAllows(ArcDiskInformation, ArcDiskSignature, &DiskLocation))
            {
                /* Create device name */
                sprintf(Buffer, "\\Device\\Harddisk%lu\\Partition0",
                        (DeviceNumber.DeviceNumber != ULONG_MAX) ? DeviceNumber.DeviceNumber : DiskNumber);
                RtlInitAnsiString(&DeviceStringA, Buffer);
                Status = RtlAnsiStringToUnicodeString(&DeviceStringW, &DeviceStringA, TRUE);
                if (!NT_SUCCESS(Status))
                {
                    goto Cleanup;
                }

                /* Create ARC name */
                sprintf(ArcBuffer, "\\ArcName\\%s", ArcDiskSignature->ArcName);
                RtlInitAnsiString(&ArcNameStringA, ArcBuffer);
                Status = RtlAnsiStringToUnicodeString(&ArcNameStringW, &ArcNameStringA, TRUE);
                if (!NT_SUCCESS(Status))
                {
                    RtlFreeUnicodeString(&DeviceStringW);
                    goto Cleanup;
                }

                /* Link both */
                IoAssignArcName(&ArcNameStringW, &DeviceStringW);

                /* And release strings */
                RtlFreeUnicodeString(&ArcNameStringW);
                RtlFreeUnicodeString(&DeviceStringW);

                /* Now, browse each partition */
                for (i = 1; i <= DriveLayout->PartitionCount; i++)
                {
                    /* Create device name */
                    sprintf(Buffer, "\\Device\\Harddisk%lu\\Partition%lu",
                            (DeviceNumber.DeviceNumber != ULONG_MAX) ? DeviceNumber.DeviceNumber : DiskNumber, i);
                    RtlInitAnsiString(&DeviceStringA, Buffer);
                    Status = RtlAnsiStringToUnicodeString(&DeviceStringW, &DeviceStringA, TRUE);
                    if (!NT_SUCCESS(Status))
                    {
                        goto Cleanup;
                    }

                    /* Create partial ARC name */
                    sprintf(ArcBuffer, "%spartition(%lu)", ArcDiskSignature->ArcName, i);
                    RtlInitAnsiString(&ArcNameStringA, ArcBuffer);

                    /* Is that boot device? */
                    if (RtlEqualString(&ArcNameStringA, &ArcBootString, TRUE))
                    {
                        DPRINT("Found boot device\n");
                        *FoundBoot = TRUE;
                    }

                    /* Is that system partition? */
                    if (RtlEqualString(&ArcNameStringA, &ArcSystemString, TRUE))
                    {
                        /* Create HAL path name */
                        RtlInitAnsiString(&HalPathStringA, LoaderBlock->NtHalPathName);
                        Status = RtlAnsiStringToUnicodeString(&HalPathStringW, &HalPathStringA, TRUE);
                        if (!NT_SUCCESS(Status))
                        {
                            RtlFreeUnicodeString(&DeviceStringW);
                            goto Cleanup;
                        }

                        /* Then store those information to registry */
                        IopStoreSystemPartitionInformation(&DeviceStringW, &HalPathStringW);
                        RtlFreeUnicodeString(&HalPathStringW);
                    }

                    /* Create complete ARC name */
                    sprintf(ArcBuffer, "\\ArcName\\%spartition(%lu)", ArcDiskSignature->ArcName, i);
                    RtlInitAnsiString(&ArcNameStringA, ArcBuffer);
                    Status = RtlAnsiStringToUnicodeString(&ArcNameStringW, &ArcNameStringA, TRUE);
                    if (!NT_SUCCESS(Status))
                    {
                        RtlFreeUnicodeString(&DeviceStringW);
                        goto Cleanup;
                    }

                    /* Link device name & ARC name */
                    IoAssignArcName(&ArcNameStringW, &DeviceStringW);

                    /* Release strings */
                    RtlFreeUnicodeString(&ArcNameStringW);
                    RtlFreeUnicodeString(&DeviceStringW);
                }
            }
            else
            {
                /* Debugging feedback: Warn in case there's a valid partition,
                 * a matching signature, BUT a non-matching checksum: this can
                 * be the sign of a duplicate signature, or even worse a virus
                 * played with the partition table. */
                if (ArcDiskSignature->ValidPartitionTable &&
                    (ArcDiskSignature->Signature == Signature) &&
                    (ArcDiskSignature->CheckSum + CheckSum != 0))
                {
                    DPRINT("Be careful, you have a duplicate disk signature, or a virus altered your MBR!\n");
                }
            }
        }

        /* Finally, release drive layout */
        ExFreePool(DriveLayout);
        DriveLayout = NULL;
    }

    Status = STATUS_SUCCESS;

Cleanup:
    if (DriveLayout)
    {
        ExFreePool(DriveLayout);
    }

    if (SymbolicLinkList)
    {
        ExFreePool(SymbolicLinkList);
    }

    return Status;
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
IopReassignSystemRoot(IN PLOADER_PARAMETER_BLOCK LoaderBlock,
                      OUT PANSI_STRING NtBootPath)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    CHAR Buffer[256], AnsiBuffer[256];
    WCHAR ArcNameBuffer[64];
    ANSI_STRING TargetString, ArcString, TempString;
    UNICODE_STRING LinkName, TargetName, ArcName;
    HANDLE LinkHandle;

    /* Create the Unicode name for the current ARC boot device */
    sprintf(Buffer, "\\ArcName\\%s", LoaderBlock->ArcBootDeviceName);
    RtlInitAnsiString(&TargetString, Buffer);
    Status = RtlAnsiStringToUnicodeString(&TargetName, &TargetString, TRUE);
    if (!NT_SUCCESS(Status)) return FALSE;

    /* Initialize the attributes and open the link */
    InitializeObjectAttributes(&ObjectAttributes,
                               &TargetName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenSymbolicLinkObject(&LinkHandle,
                                      SYMBOLIC_LINK_ALL_ACCESS,
                                      &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        /* We failed, free the string */
        RtlFreeUnicodeString(&TargetName);
        return FALSE;
    }

    /* Query the current \\SystemRoot */
    ArcName.Buffer = ArcNameBuffer;
    ArcName.Length = 0;
    ArcName.MaximumLength = sizeof(ArcNameBuffer);
    Status = NtQuerySymbolicLinkObject(LinkHandle, &ArcName, NULL);
    if (!NT_SUCCESS(Status))
    {
        /* We failed, free the string */
        RtlFreeUnicodeString(&TargetName);
        return FALSE;
    }

    /* Convert it to Ansi */
    ArcString.Buffer = AnsiBuffer;
    ArcString.Length = 0;
    ArcString.MaximumLength = sizeof(AnsiBuffer);
    Status = RtlUnicodeStringToAnsiString(&ArcString, &ArcName, FALSE);
    AnsiBuffer[ArcString.Length] = ANSI_NULL;

    /* Close the link handle and free the name */
    ObCloseHandle(LinkHandle, KernelMode);
    RtlFreeUnicodeString(&TargetName);

    /* Setup the system root name again */
    RtlInitAnsiString(&TempString, "\\SystemRoot");
    Status = RtlAnsiStringToUnicodeString(&LinkName, &TempString, TRUE);
    if (!NT_SUCCESS(Status)) return FALSE;

    /* Open the symbolic link for it */
    InitializeObjectAttributes(&ObjectAttributes,
                               &LinkName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenSymbolicLinkObject(&LinkHandle,
                                      SYMBOLIC_LINK_ALL_ACCESS,
                                      &ObjectAttributes);
    if (!NT_SUCCESS(Status)) return FALSE;

    /* Destroy it */
    NtMakeTemporaryObject(LinkHandle);
    ObCloseHandle(LinkHandle, KernelMode);

    /* Now create the new name for it */
    sprintf(Buffer, "%s%s", ArcString.Buffer, LoaderBlock->NtBootPathName);

    /* Copy it into the passed parameter and null-terminate it */
    RtlCopyString(NtBootPath, &ArcString);
    Buffer[strlen(Buffer) - 1] = ANSI_NULL;

    /* Setup the Unicode-name for the new symbolic link value */
    RtlInitAnsiString(&TargetString, Buffer);
    InitializeObjectAttributes(&ObjectAttributes,
                               &LinkName,
                               OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                               NULL,
                               NULL);
    Status = RtlAnsiStringToUnicodeString(&ArcName, &TargetString, TRUE);
    if (!NT_SUCCESS(Status)) return FALSE;

    /* Create it */
    Status = NtCreateSymbolicLinkObject(&LinkHandle,
                                        SYMBOLIC_LINK_ALL_ACCESS,
                                        &ObjectAttributes,
                                        &ArcName);

    /* Free all the strings and close the handle and return success */
    RtlFreeUnicodeString(&ArcName);
    RtlFreeUnicodeString(&LinkName);
    ObCloseHandle(LinkHandle, KernelMode);
    return TRUE;
}

BOOLEAN
IopVerifyDiskSignature(
    _In_ PDRIVE_LAYOUT_INFORMATION_EX DriveLayout,
    _In_ PARC_DISK_SIGNATURE ArcDiskSignature,
    _Out_ PULONG Signature)
{
    /* Fail if the partition table is invalid */
    if (!ArcDiskSignature->ValidPartitionTable)
        return FALSE;

    /* If the partition style is MBR */
    if (DriveLayout->PartitionStyle == PARTITION_STYLE_MBR)
    {
        /* Check the MBR signature */
        if (DriveLayout->Mbr.Signature == ArcDiskSignature->Signature)
        {
            /* And return it */
            if (Signature)
                *Signature = DriveLayout->Mbr.Signature;
            return TRUE;
        }
    }
    /* If the partition style is GPT */
    else if (DriveLayout->PartitionStyle == PARTITION_STYLE_GPT)
    {
        /* Verify whether the signature is GPT and compare the GUID */
        if (ArcDiskSignature->IsGpt &&
            IsEqualGUID((PGUID)&ArcDiskSignature->GptSignature, &DriveLayout->Gpt.DiskId))
        {
            /* There is no signature to return, just zero it */
            if (Signature)
                *Signature = 0;
            return TRUE;
        }
    }

    /* If we get there, something went wrong, so fail */
    return FALSE;
}

/* EOF */
