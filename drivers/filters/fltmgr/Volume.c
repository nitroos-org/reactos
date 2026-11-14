/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Context.c
* PURPOSE:         Contains routines for the volume
* PROGRAMMERS:     Ged Murphy (gedmurphy@reactos.org)
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"
#include <ntstrsafe.h>

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/

/* The volumes we have a filter device on, protected by FilterListLock */
LIST_ENTRY FltpVolumeList = { &FltpVolumeList, &FltpVolumeList };



/* EXPORTED FUNCTIONS ******************************************************/

NTSTATUS
FLTAPI
FltGetVolumeProperties(
    _In_ PFLT_VOLUME Volume,
    _Out_writes_bytes_to_opt_(VolumePropertiesLength, *LengthReturned) PFLT_VOLUME_PROPERTIES VolumeProperties,
    _In_ ULONG VolumePropertiesLength,
    _Out_ PULONG LengthReturned
)
{
    ULONG BufferRequired;
    ULONG BytesWritten;
    PCHAR Ptr;
    NTSTATUS Status;

    /* Calculate the required buffer size */
    BufferRequired = sizeof(FLT_VOLUME_PROPERTIES) +
                     Volume->CDODriverName.Length +
                     Volume->DeviceName.Length +
                     Volume->CDODeviceName.Length;

    /* If we don't have enough buffer to fill in the fixed struct, return with the required size */
    if (VolumePropertiesLength < sizeof(FLT_VOLUME_PROPERTIES))
    {
        *LengthReturned = BufferRequired;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Clear out the buffer */
    RtlZeroMemory(VolumeProperties, sizeof(FLT_VOLUME_PROPERTIES));

    /* Fill in the fixed data */
    VolumeProperties->DeviceType = Volume->DeviceObject->DeviceType;
    VolumeProperties->DeviceObjectFlags = Volume->DeviceObject->Flags;
    VolumeProperties->AlignmentRequirement = Volume->DeviceObject->AlignmentRequirement;
    VolumeProperties->SectorSize = Volume->DeviceObject->SectorSize;
    if (Volume->DiskDeviceObject)
    {
        VolumeProperties->DeviceCharacteristics = Volume->DiskDeviceObject->Characteristics;
    }
    else
    {
        VolumeProperties->DeviceCharacteristics = Volume->DeviceObject->Characteristics;
    }

    /* So far we've written the fixed struct data */
    BytesWritten = sizeof(FLT_VOLUME_PROPERTIES);
    Ptr = (PCHAR)(VolumeProperties + 1);

    /* Make sure we have enough room to add the dynamic data */
    if (VolumePropertiesLength >= BufferRequired)
    {
        /* Add the FS device name */
        VolumeProperties->FileSystemDeviceName.Length = 0;
        VolumeProperties->FileSystemDeviceName.MaximumLength = Volume->CDODeviceName.Length;
        VolumeProperties->FileSystemDeviceName.Buffer = (PWCH)Ptr;
        RtlCopyUnicodeString(&VolumeProperties->FileSystemDeviceName, &Volume->CDODeviceName);
        Ptr += VolumeProperties->FileSystemDeviceName.Length;

        /* Add the driver name */
        VolumeProperties->FileSystemDriverName.Length = 0;
        VolumeProperties->FileSystemDriverName.MaximumLength = Volume->CDODriverName.Length;
        VolumeProperties->FileSystemDriverName.Buffer = (PWCH)Ptr;
        RtlCopyUnicodeString(&VolumeProperties->FileSystemDriverName, &Volume->CDODriverName);
        Ptr += VolumeProperties->FileSystemDriverName.Length;

        /* Add the volume name */
        VolumeProperties->RealDeviceName.Length = 0;
        VolumeProperties->RealDeviceName.MaximumLength = Volume->DeviceName.Length;
        VolumeProperties->RealDeviceName.Buffer = (PWCH)Ptr;
        RtlCopyUnicodeString(&VolumeProperties->RealDeviceName, &Volume->DeviceName);

        BytesWritten = BufferRequired;

        Status = STATUS_SUCCESS;
    }
    else
    {
        Status = STATUS_BUFFER_OVERFLOW;
    }

    /* Set the number of bytes we wrote and return */
    *LengthReturned = BytesWritten;
    return Status;
}


NTSTATUS
FLTAPI
FltEnumerateVolumes(
    _In_ PFLT_FILTER Filter,
    _Out_writes_to_opt_(VolumeListSize,*NumberVolumesReturned) PFLT_VOLUME *VolumeList,
    _In_ ULONG VolumeListSize,
    _Out_ PULONG NumberVolumesReturned)
{
    ULONG i;
    PFLT_VOLUME Volume;
    PLIST_ENTRY ListEntry;
    ULONG NumberOfVolumes = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Filter);

    /* Lock the volume list */
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&FilterListLock, TRUE);

    /* Browse every entry */
    for (ListEntry = FltpVolumeList.Flink;
         ListEntry != &FltpVolumeList;
         ListEntry = ListEntry->Flink)
    {
        /* Get the volume */
        Volume = CONTAINING_RECORD(ListEntry, FLT_VOLUME, GlobalLink);

        /* If there's still room in the output buffer */
        if (VolumeList && NumberOfVolumes < VolumeListSize)
        {
            /* Reference the volume and return it */
            if (!NT_SUCCESS(FltObjectReference(Volume)))
                continue;
            VolumeList[NumberOfVolumes] = Volume;
        }

        /* We returned one more volume */
        ++NumberOfVolumes;
    }

    /* Release the list */
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    /* If we want to return more volumes than we can */
    if (NumberOfVolumes > VolumeListSize)
    {
        /* We will clear output */
        for (i = 0; VolumeList && i < VolumeListSize; ++i)
        {
            FltObjectDereference(VolumeList[i]);
            VolumeList[i] = NULL;
        }

        /* And set failure status */
        Status = STATUS_BUFFER_TOO_SMALL;
    }

    /* Always return the max amount of volumes we want to return */
    *NumberVolumesReturned = NumberOfVolumes;

    /* Done */
    return Status;
}

NTSTATUS
FLTAPI
FltGetDiskDeviceObject(
    _In_ PFLT_VOLUME Volume,
    _Outptr_ PDEVICE_OBJECT *DiskDeviceObject)
{
    if (Volume->DiskDeviceObject == NULL)
    {
        *DiskDeviceObject = NULL;
        return STATUS_FLT_NO_DEVICE_OBJECT;
    }

    /* The caller gets a reference of its own */
    ObReferenceObject(Volume->DiskDeviceObject);
    *DiskDeviceObject = Volume->DiskDeviceObject;
    return STATUS_SUCCESS;
}

NTSTATUS
FLTAPI
FltGetDeviceObject(
    _In_ PFLT_VOLUME Volume,
    _Outptr_ PDEVICE_OBJECT *DeviceObject)
{
    /* The file system volume device object our device is attached to */
    if (Volume->AttachedToDeviceObject == NULL)
    {
        *DeviceObject = NULL;
        return STATUS_FLT_NO_DEVICE_OBJECT;
    }

    ObReferenceObject(Volume->AttachedToDeviceObject);
    *DeviceObject = Volume->AttachedToDeviceObject;
    return STATUS_SUCCESS;
}


NTSTATUS
FLTAPI
FltGetVolumeName(
    _In_ PFLT_VOLUME Volume,
    _Inout_opt_ PUNICODE_STRING VolumeName,
    _Out_opt_ PULONG BufferSizeNeeded)
{
    NTSTATUS Status;

    /* Check if caller just probes for size */
    if (VolumeName == NULL)
    {
        /* Totally broken call */
        if (BufferSizeNeeded == NULL)
        {
            return STATUS_INVALID_PARAMETER;
        }

        /* Return the appropriate size and quit */
        *BufferSizeNeeded = Volume->DeviceName.Length;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* We have an output buffer! Assume it's too small */
    Status = STATUS_BUFFER_TOO_SMALL;

    /* If we have output size, fill it */
    if (BufferSizeNeeded != NULL)
    {
        *BufferSizeNeeded = Volume->DeviceName.Length;
    }

    /* Init that we didn't return a thing */
    VolumeName->Length = 0;

    /* If we have enough room, copy and return success */
    if (VolumeName->MaximumLength >= Volume->DeviceName.Length)
    {
        RtlCopyUnicodeString(VolumeName, &Volume->DeviceName);
        Status = STATUS_SUCCESS;
    }

    return Status;
}


/* INTERNAL FUNCTIONS ******************************************************/


/* INTERNAL FUNCTIONS ******************************************************/

static
FLT_FILESYSTEM_TYPE
GetFileSystemType(_In_ PDEVICE_OBJECT VolumeDeviceObject)
{
    PCUNICODE_STRING Name = &VolumeDeviceObject->DriverObject->DriverName;
    static const struct { PCWSTR Substring; FLT_FILESYSTEM_TYPE Type; } Map[] =
    {
        { L"ntfs", FLT_FSTYPE_NTFS },
        { L"fat", FLT_FSTYPE_FAT },
        { L"cdfs", FLT_FSTYPE_CDFS },
        { L"udfs", FLT_FSTYPE_UDFS },
        { L"raw", FLT_FSTYPE_RAW },
        { L"mup", FLT_FSTYPE_MUP },
    };
    ULONG i, j, k, Length = Name->Length / sizeof(WCHAR);

    /* Case insensitive substring search in the name of the driver */
    for (i = 0; i < RTL_NUMBER_OF(Map); i++)
    {
        ULONG Match = (ULONG)wcslen(Map[i].Substring);

        for (j = 0; j + Match <= Length; j++)
        {
            for (k = 0; k < Match; k++)
            {
                if (RtlUpcaseUnicodeChar(Name->Buffer[j + k]) != RtlUpcaseUnicodeChar(Map[i].Substring[k]))
                    break;
            }
            if (k == Match)
                return Map[i].Type;
        }
    }

    return FLT_FSTYPE_UNKNOWN;
}

CODE_SEG("PAGE")
BOOLEAN
FltpIsAttachedToDevice(_In_ PDEVICE_OBJECT DeviceObject,
                       _In_opt_ PDEVICE_OBJECT *AttachedDeviceObject)
{
    PDEVICE_OBJECT CurrentDeviceObject;
    PDEVICE_OBJECT NextDeviceObject;

    PAGED_CODE();

    /* Initialize the return pointer */
    if (AttachedDeviceObject) *AttachedDeviceObject = NULL;

    /* Start by getting the top level device in the chain */
    CurrentDeviceObject = IoGetAttachedDeviceReference(DeviceObject);

    /* Loop while there are attached devices */
    while (CurrentDeviceObject)
    {
        /* Check if this device driver matches ours */
        if (CurrentDeviceObject->DriverObject == DriverData.DriverObject)
        {
            /* We're attached, return the device object if the caller asked for it */
            if (AttachedDeviceObject)
            {
                *AttachedDeviceObject = CurrentDeviceObject;
            }
            else
            {
                /* We aren't returning the reference, so decrement the count */
                ObDereferenceObject(CurrentDeviceObject);
            }

            return TRUE;
        }

        /* Get the next device in the chain */
        NextDeviceObject = IoGetLowerDeviceObject(CurrentDeviceObject);

        /* Decrement the count on the last device before we update the pointer */
        ObDereferenceObject(CurrentDeviceObject);
        CurrentDeviceObject = NextDeviceObject;
    }

    return FALSE;
}

NTSTATUS
FltpSnapshotVolumes(_Outptr_result_buffer_(*Count) PFLT_VOLUME **Volumes,
                    _Out_ PULONG Count)
{
    PFLT_VOLUME *Array;
    PLIST_ENTRY Entry;
    ULONG Number = 0;

    *Volumes = NULL;
    *Count = 0;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&FilterListLock, TRUE);

    for (Entry = FltpVolumeList.Flink; Entry != &FltpVolumeList; Entry = Entry->Flink)
        Number++;

    if (Number == 0)
    {
        ExReleaseResourceLite(&FilterListLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    Array = ExAllocatePoolWithTag(NonPagedPool, Number * sizeof(PFLT_VOLUME), FM_TAG_VOLUME);
    if (Array == NULL)
    {
        ExReleaseResourceLite(&FilterListLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Number = 0;
    for (Entry = FltpVolumeList.Flink; Entry != &FltpVolumeList; Entry = Entry->Flink)
    {
        PFLT_VOLUME Volume = CONTAINING_RECORD(Entry, FLT_VOLUME, GlobalLink);
        if (NT_SUCCESS(FltObjectReference(Volume)))
            Array[Number++] = Volume;
    }

    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    *Volumes = Array;
    *Count = Number;
    return STATUS_SUCCESS;
}

VOID
FltpFreeVolumeSnapshot(_In_ PFLT_VOLUME *Volumes,
                       _In_ ULONG Count)
{
    ULONG i;

    if (Volumes == NULL)
        return;

    for (i = 0; i < Count; i++)
        FltObjectDereference(Volumes[i]);

    ExFreePoolWithTag(Volumes, FM_TAG_VOLUME);
}

NTSTATUS
FltpAttachFilterToVolume(_In_ PFLT_FILTER Filter,
                         _In_ PFLT_VOLUME Volume,
                         _In_ ULONG SetupFlags)
{
    return FltpAttachInstance(Filter, Volume, NULL, NULL, SetupFlags, NULL);
}

/*
 * Creates the filter device and the volume object for a file system volume device
 * object and attaches to it, then offers the volume to every filter which is running
 */
NTSTATUS
FltpAttachToVolumeDevice(_In_ PDEVICE_OBJECT VolumeDeviceObject,
                         _In_ PDEVICE_OBJECT StorageDeviceObject,
                         _In_ BOOLEAN NewlyMounted)
{
    PFLTMGR_DEVICE_EXTENSION Extension;
    PDEVICE_OBJECT NewDeviceObject = NULL;
    PDEVICE_OBJECT DiskDeviceObject = StorageDeviceObject;
    PFLT_VOLUME Volume = NULL;
    PFLT_FILTER *Filters;
    ULONG Count, i;
    NTSTATUS Status;

    PAGED_CODE();

    /*
     * The storage device the file system is mounted on comes with a reference of ours,
     * which stays with the volume (or goes if there is no volume).
     */
    if (VolumeDeviceObject->DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&
        VolumeDeviceObject->DeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM)
    {
        ObDereferenceObject(DiskDeviceObject);
        return STATUS_SUCCESS;
    }

    Volume = ExAllocatePoolWithTag(NonPagedPool, sizeof(FLT_VOLUME), FM_TAG_VOLUME);
    if (Volume == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    RtlZeroMemory(Volume, sizeof(FLT_VOLUME));

    Status = IoCreateDevice(DriverData.DriverObject,
                            sizeof(FLTMGR_DEVICE_EXTENSION),
                            NULL,
                            VolumeDeviceObject->DeviceType,
                            0,
                            FALSE,
                            &NewDeviceObject);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Extension = NewDeviceObject->DeviceExtension;
    RtlZeroMemory(Extension, sizeof(*Extension));
    Extension->StorageStackDeviceObject = DiskDeviceObject;
    Extension->Volume = Volume;
    RtlInitEmptyUnicodeString(&Extension->DeviceName,
                              Extension->DeviceNameBuffer,
                              sizeof(Extension->DeviceNameBuffer));
    FltpGetObjectName(DiskDeviceObject, &Extension->DeviceName);

    /* Set the volume up before anything can reach the new device */
    Volume->Base.Flags = FLT_OBFL_TYPE_VOLUME;
    Volume->Base.PointerCount = 1;
    FltpExInitializeRundownProtection(&Volume->Base.RundownRef);
    Volume->FileSystemType = GetFileSystemType(VolumeDeviceObject);
    Volume->DeviceObject = NewDeviceObject;
    Volume->DiskDeviceObject = DiskDeviceObject;
    ExInitializeResourceLite(&Volume->InstanceList.rLock);
    InitializeListHead(&Volume->InstanceList.rList);
    InitializeListHead(&Volume->ContextList);
    ExInitializeFastMutex(&Volume->StreamListLock);
    InitializeListHead(&Volume->StreamList);
    InitializeListHead(&Volume->GlobalLink);

    /* The names filters can ask for */
    FltpGetObjectName(DiskDeviceObject, &Volume->DeviceName);
    if (NT_SUCCESS(FltpReallocateUnicodeString(&Volume->CDODriverName,
                                               VolumeDeviceObject->DriverObject->DriverName.Length,
                                               FALSE)))
    {
        RtlCopyUnicodeString(&Volume->CDODriverName, &VolumeDeviceObject->DriverObject->DriverName);
    }

    /* Our device takes the properties of the file system's device: buffering and secure open */
    SetFlag(NewDeviceObject->Flags, VolumeDeviceObject->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO));
    SetFlag(NewDeviceObject->Characteristics, VolumeDeviceObject->Characteristics & FILE_DEVICE_SECURE_OPEN);

    /* Grab the attach lock before we attempt to attach */
    ExAcquireFastMutex(&DriverData.FilterAttachLock);

    /* Check again that we aren't already attached. It may have changed since our last check */
    if (FltpIsAttachedToDevice(VolumeDeviceObject, NULL))
    {
        ExReleaseFastMutex(&DriverData.FilterAttachLock);
        Status = STATUS_DEVICE_ALREADY_ATTACHED;
        goto Fail;
    }

    Status = IoAttachDeviceToDeviceStackSafe(NewDeviceObject,
                                             VolumeDeviceObject,
                                             &Extension->AttachedToDeviceObject);
    ExReleaseFastMutex(&DriverData.FilterAttachLock);
    if (!NT_SUCCESS(Status))
        goto Fail;

    Volume->AttachedToDeviceObject = Extension->AttachedToDeviceObject;

    /* Make the volume known, then let other filters attach to our device */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&FilterListLock, TRUE);
    InsertTailList(&FltpVolumeList, &Volume->GlobalLink);
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    ClearFlag(NewDeviceObject->Flags, DO_DEVICE_INITIALIZING);

    /* Now every running filter may attach an instance */
    if (NT_SUCCESS(FltpSnapshotFilters(&Filters, &Count)))
    {
        for (i = 0; i < Count; i++)
        {
            if (Filters[i]->Flags & FLTFL_FILTERING_INITIATED)
            {
                (VOID)FltpAttachFilterToVolume(Filters[i],
                                               Volume,
                                               FLTFL_INSTANCE_SETUP_AUTOMATIC_ATTACHMENT |
                                               (NewlyMounted ? FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME : 0));
            }
        }
        FltpFreeFilterSnapshot(Filters, Count);
    }

    return STATUS_SUCCESS;

Fail:
    if (NewDeviceObject)
        IoDeleteDevice(NewDeviceObject);
    if (Volume)
    {
        if (Volume->InstanceList.rLock.SystemResourcesList.Flink)
            ExDeleteResourceLite(&Volume->InstanceList.rLock);
        FltpFreeUnicodeString(&Volume->DeviceName);
        FltpFreeUnicodeString(&Volume->CDODriverName);
        ExFreePoolWithTag(Volume, FM_TAG_VOLUME);
    }
    if (DiskDeviceObject)
        ObDereferenceObject(DiskDeviceObject);
    return Status;
}

/*
 * The file system has dismounted the volume: the filters lose their instances. Our device
 * stays attached as a pass through, it is the file system which decides when its own
 * device object goes away.
 */
VOID
FltpTeardownVolume(_In_ PFLT_VOLUME Volume,
                   _In_ ULONG Reason)
{
    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Volume->InstanceList.rLock, TRUE);
    Volume->Dismounted = TRUE;
    ExReleaseResourceLite(&Volume->InstanceList.rLock);

    ExAcquireResourceExclusiveLite(&FilterListLock, TRUE);
    if (!IsListEmpty(&Volume->GlobalLink))
    {
        RemoveEntryList(&Volume->GlobalLink);
        InitializeListHead(&Volume->GlobalLink);
    }
    ExReleaseResourceLite(&FilterListLock);
    KeLeaveCriticalRegion();

    FltpTeardownVolumeInstances(Volume, Reason);
    FltpTeardownVolumeContexts(Volume);
}

/*
 * Looks for the mounted volumes and attaches to the ones we haven't got yet. Our kernel gives no way to
 * walk the volume devices of a file system and find the storage device they are mounted on
 * (IoGetDiskDeviceObject needs the VPB of the file system's device, which they don't have). The volume
 * names of the storage devices can be opened though, which gives the storage device, and its VPB names the
 * volume device of the file system.
 */
NTSTATUS
FltpEnumerateFileSystemVolumes(_In_ PDEVICE_OBJECT DeviceObject)
{
    static const struct { PCWSTR Format; ULONG First; ULONG Last; } Names[] =
    {
        { L"\\Device\\HarddiskVolume%lu", 1, 64 },
        { L"\\Device\\CdRom%lu", 0, 7 },
    };
    ULONG Set, Number;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    for (Set = 0; Set < RTL_NUMBER_OF(Names); Set++)
    {
        for (Number = Names[Set].First; Number <= Names[Set].Last; Number++)
        {
            WCHAR Buffer[48];
            UNICODE_STRING Name;
            PFILE_OBJECT FileObject;
            PDEVICE_OBJECT Top, Volume = NULL, Storage = NULL;
            KIRQL OldIrql;
            NTSTATUS Status;

            Status = RtlStringCbPrintfW(Buffer, sizeof(Buffer), Names[Set].Format, Number);
            if (!NT_SUCCESS(Status))
                continue;
            RtlInitUnicodeString(&Name, Buffer);

            Status = IoGetDeviceObjectPointer(&Name, FILE_READ_ATTRIBUTES, &FileObject, &Top);
            if (!NT_SUCCESS(Status))
                continue;
            /* Mounted? Then the VPB of the storage device names the volume device of the file system */
            IoAcquireVpbSpinLock(&OldIrql);
            if (Top->Vpb && Top->Vpb->DeviceObject && Top->Vpb->ReferenceCount && (Top->Vpb->Flags & VPB_MOUNTED))
            {
                Volume = Top->Vpb->DeviceObject;
                Storage = Top;
                ObReferenceObject(Volume);
                ObReferenceObject(Storage);
            }
            IoReleaseVpbSpinLock(OldIrql);
            ObDereferenceObject(FileObject);

            if (Volume == NULL)
                continue;

            if (!FltpIsAttachedToDevice(Volume, NULL))
            {
                /* The storage reference moves to the volume */
                (VOID)FltpAttachToVolumeDevice(Volume, Storage, FALSE);
            }
            else
            {
                ObDereferenceObject(Storage);
            }
            ObDereferenceObject(Volume);
        }
    }

    return STATUS_SUCCESS;
}
