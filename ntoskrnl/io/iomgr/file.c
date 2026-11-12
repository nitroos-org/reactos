/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/iomgr/file.c
 * PURPOSE:         Functions that deal with managing the FILE_OBJECT itself.
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Gunnar Dalsnes
 *                  Eric Kohl
 *                  Filip Navara (navaraf@reactos.org)
 *                  Pierre Schweitzer
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

extern ERESOURCE IopSecurityResource;

/* PRIVATE FUNCTIONS *********************************************************/

VOID
NTAPI
IopCheckBackupRestorePrivilege(IN PACCESS_STATE AccessState,
                               IN OUT PULONG CreateOptions,
                               IN KPROCESSOR_MODE PreviousMode,
                               IN ULONG Disposition)
{
    ACCESS_MASK DesiredAccess, ReadAccess, WriteAccess;
    PRIVILEGE_SET Privileges;
    BOOLEAN AccessGranted, HaveBackupPriv = FALSE, CheckRestore = FALSE;
    PAGED_CODE();

    /* Don't do anything if privileges were checked already */
    if (AccessState->Flags & SE_BACKUP_PRIVILEGES_CHECKED) return;

    /* Check if the file was actually opened for backup purposes */
    if (*CreateOptions & FILE_OPEN_FOR_BACKUP_INTENT)
    {
        /* Set the check flag since were doing it now */
        AccessState->Flags |= SE_BACKUP_PRIVILEGES_CHECKED;

        /* Set the access masks required */
        ReadAccess = READ_CONTROL |
                     ACCESS_SYSTEM_SECURITY |
                     FILE_GENERIC_READ |
                     FILE_TRAVERSE;
        WriteAccess = WRITE_DAC |
                      WRITE_OWNER |
                      ACCESS_SYSTEM_SECURITY |
                      FILE_GENERIC_WRITE |
                      FILE_ADD_FILE |
                      FILE_ADD_SUBDIRECTORY |
                      DELETE;
        DesiredAccess = AccessState->RemainingDesiredAccess;

        /* Check if desired access was the maximum */
        if (DesiredAccess & MAXIMUM_ALLOWED)
        {
            /* Then add all the access masks required */
            DesiredAccess |= (ReadAccess | WriteAccess);
        }

        /* Check if the file already exists */
        if (Disposition & FILE_OPEN)
        {
            /* Check if desired access has the read mask */
            if (ReadAccess & DesiredAccess)
            {
                /* Setup the privilege check lookup */
                Privileges.PrivilegeCount = 1;
                Privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
                Privileges.Privilege[0].Luid = SeBackupPrivilege;
                Privileges.Privilege[0].Attributes = 0;
                AccessGranted = SePrivilegeCheck(&Privileges,
                                                 &AccessState->
                                                 SubjectSecurityContext,
                                                 PreviousMode);
                if (AccessGranted)
                {
                    /* Remember that backup was allowed */
                    HaveBackupPriv = TRUE;

                    /* Append the privileges and update the access state */
                    SeAppendPrivileges(AccessState, &Privileges);
                    AccessState->PreviouslyGrantedAccess |= (DesiredAccess & ReadAccess);
                    AccessState->RemainingDesiredAccess &= ~ReadAccess;
                    DesiredAccess &= ~ReadAccess;

                    /* Set backup privilege for the token */
                    AccessState->Flags |= TOKEN_HAS_BACKUP_PRIVILEGE;
                }
            }
        }
        else
        {
            /* Caller is creating the file, check restore privileges later */
            CheckRestore = TRUE;
        }

        /* Check if caller wants write access or if it's creating a file */
        if ((WriteAccess & DesiredAccess) || (CheckRestore))
        {
            /* Setup the privilege lookup and do it */
            Privileges.PrivilegeCount = 1;
            Privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
            Privileges.Privilege[0].Luid = SeRestorePrivilege;
            Privileges.Privilege[0].Attributes = 0;
            AccessGranted = SePrivilegeCheck(&Privileges,
                                             &AccessState->SubjectSecurityContext,
                                             PreviousMode);
            if (AccessGranted)
            {
                /* Remember that privilege was given */
                HaveBackupPriv = TRUE;

                /* Append the privileges and update the access state */
                SeAppendPrivileges(AccessState, &Privileges);
                AccessState->PreviouslyGrantedAccess |= (DesiredAccess & WriteAccess);
                AccessState->RemainingDesiredAccess &= ~WriteAccess;

                /* Set restore privilege for the token */
                AccessState->Flags |= TOKEN_HAS_RESTORE_PRIVILEGE;
            }
        }

        /* If we don't have the privilege, remove the option */
        if (!HaveBackupPriv) *CreateOptions &= ~FILE_OPEN_FOR_BACKUP_INTENT;
    }
}

NTSTATUS
NTAPI
IopCheckDeviceAndDriver(IN POPEN_PACKET OpenPacket,
                        IN PDEVICE_OBJECT DeviceObject)
{
    /* Make sure the object is valid */
    if ((DeviceObject->Flags & DO_DEVICE_INITIALIZING) ||
        (IoGetDevObjExtension(DeviceObject)->ExtensionFlags &
         (DOE_UNLOAD_PENDING | DOE_DELETE_PENDING |
          DOE_REMOVE_PENDING | DOE_REMOVE_PROCESSED)))
    {
        /* It's initializing or unloading, so fail */
        DPRINT1("\nYou are seeing this because the following ROS driver: %wZ\n"
                "sucks. Please fix its AddDevice routine.\n",
                &DeviceObject->DriverObject->DriverName);
        return STATUS_NO_SUCH_DEVICE;
    }
    else if ((DeviceObject->Flags & DO_EXCLUSIVE) &&
             (DeviceObject->ReferenceCount) &&
             !(OpenPacket->RelatedFileObject) &&
             !(OpenPacket->Options & IO_ATTACH_DEVICE))
    {
        return STATUS_ACCESS_DENIED;
    }
    else
    {
        /* Increase reference count */
        InterlockedIncrement(&DeviceObject->ReferenceCount);
        return STATUS_SUCCESS;
    }
}

VOID
NTAPI
IopDoNameTransmogrify(IN PIRP Irp,
                      IN PFILE_OBJECT FileObject,
                      IN PREPARSE_DATA_BUFFER DataBuffer)
{
    PWSTR Buffer;
    USHORT Length;
    USHORT RequiredLength;
    PWSTR NewBuffer;

    PAGED_CODE();

    ASSERT(Irp->IoStatus.Status == STATUS_REPARSE);
    ASSERT(Irp->IoStatus.Information == IO_REPARSE_TAG_MOUNT_POINT);
    ASSERT(Irp->Tail.Overlay.AuxiliaryBuffer != NULL);
    ASSERT(DataBuffer != NULL);
    ASSERT(DataBuffer->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT);
    ASSERT(DataBuffer->ReparseDataLength < MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    ASSERT(DataBuffer->Reserved < MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

    /* First of all, validate data */
    if (DataBuffer->ReparseDataLength < REPARSE_DATA_BUFFER_HEADER_SIZE ||
        (DataBuffer->SymbolicLinkReparseBuffer.PrintNameLength +
         DataBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength +
         FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer[0])) > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
    {
        Irp->IoStatus.Status = STATUS_IO_REPARSE_DATA_INVALID;
    }
    /* The substitute name has to lie inside the data and has to be an absolute name of the object namespace:
       it replaces the whole name, a relative one would be resolved against whatever directory the caller named */
    else if (DataBuffer->ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE <
             FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) ||
             (ULONG)DataBuffer->MountPointReparseBuffer.SubstituteNameOffset +
             DataBuffer->MountPointReparseBuffer.SubstituteNameLength >
             (ULONG)DataBuffer->ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE -
             FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) ||
             (DataBuffer->MountPointReparseBuffer.SubstituteNameOffset & 1) ||
             DataBuffer->MountPointReparseBuffer.SubstituteNameLength < sizeof(WCHAR) ||
             (DataBuffer->MountPointReparseBuffer.SubstituteNameLength & 1) ||
             *(PWCHAR)((ULONG_PTR)DataBuffer->MountPointReparseBuffer.PathBuffer +
                       DataBuffer->MountPointReparseBuffer.SubstituteNameOffset) != L'\\')
    {
        Irp->IoStatus.Status = STATUS_IO_REPARSE_DATA_INVALID;
    }

    /* Everything went right */
    if (NT_SUCCESS(Irp->IoStatus.Status))
    {
        /* Compute buffer & length */
        Buffer = (PWSTR)((ULONG_PTR)DataBuffer->MountPointReparseBuffer.PathBuffer +
                                    DataBuffer->MountPointReparseBuffer.SubstituteNameOffset);
        Length = DataBuffer->MountPointReparseBuffer.SubstituteNameLength;

        /* Check we don't overflow */
        if (((ULONG)MAXUSHORT - DataBuffer->Reserved) <= (Length + sizeof(UNICODE_NULL)))
        {
            Irp->IoStatus.Status = STATUS_IO_REPARSE_DATA_INVALID;
        }
        else
        {
            /* Compute how much memory we'll need */
            RequiredLength = DataBuffer->Reserved + Length + sizeof(UNICODE_NULL);

            /* Check if FileObject can already hold what we need */
            if (FileObject->FileName.MaximumLength >= RequiredLength)
            {
                NewBuffer = FileObject->FileName.Buffer;
            }
            else
            {
                /* Allocate otherwise */
                NewBuffer = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_IO_NAME);
                if (NewBuffer == NULL)
                {
                    Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }
    }

    /* Everything went right */
    if (NT_SUCCESS(Irp->IoStatus.Status))
    {
        /* Copy the reserved data */
        if (DataBuffer->Reserved)
        {
            RtlMoveMemory((PWSTR)((ULONG_PTR)NewBuffer + Length),
                          (PWSTR)((ULONG_PTR)FileObject->FileName.Buffer + FileObject->FileName.Length - DataBuffer->Reserved),
                          DataBuffer->Reserved);
        }

        /* Then the buffer */
        if (Length)
        {
            RtlCopyMemory(NewBuffer, Buffer, Length);
        }

        /* And finally replace buffer if new one was allocated */
        FileObject->FileName.Length = RequiredLength - sizeof(UNICODE_NULL);
        if (NewBuffer != FileObject->FileName.Buffer)
        {
            if (FileObject->FileName.Buffer)
            {
                /*
                 * Don't use TAG_IO_NAME since the FileObject's FileName
                 * may have been re-allocated using a different tag
                 * by a filesystem.
                 */
                ExFreePoolWithTag(FileObject->FileName.Buffer, 0);
            }

            FileObject->FileName.Buffer = NewBuffer;
            FileObject->FileName.MaximumLength = RequiredLength;
            FileObject->FileName.Buffer[RequiredLength / sizeof(WCHAR) - 1] = UNICODE_NULL;
        }
    }

    /* We don't need them anymore - it was allocated by the driver */
    ExFreePool(DataBuffer);
}

/*
 * Collapse "." and ".." components of Buf[Floor..Len) (a run of \component units) in place and return the new
 * length in characters. ".." never climbs above Floor, and an empty result is the root "\".
 */
static
ULONG
IopRemoveDotsFromPath(IN OUT PWCHAR Buf,
                      IN ULONG Len,
                      IN ULONG Floor)
{
    ULONG r = Floor, w = Floor, s, e, cl;

    while (r < Len)
    {
        s = r + 1;
        e = s;
        while (e < Len && Buf[e] != L'\\') e++;
        cl = e - s;

        if (cl == 1 && Buf[s] == L'.')
        {
            /* Current directory: drop it */
        }
        else if (cl == 2 && Buf[s] == L'.' && Buf[s + 1] == L'.')
        {
            /* Parent directory: drop the last component, if any */
            while (w > Floor && Buf[w - 1] != L'\\') w--;
            if (w > Floor) w--;
        }
        else if (cl != 0 || e == Len)
        {
            /* An empty component survives only as a trailing backslash */
            if (w != r) RtlMoveMemory(&Buf[w], &Buf[r], (e - r) * sizeof(WCHAR));
            w += e - r;
        }
        r = e;
    }

    if (w == Floor) Buf[w++] = L'\\';
    return w;
}

/*
 * A file system returned STATUS_REPARSE for an IO_REPARSE_TAG_SYMLINK reparse point: the data is in the
 * auxiliary buffer and its Reserved field counts the bytes of the file name that follow the link. Absolute
 * links replace the name by their substitute name; relative links (SYMLINK_FLAG_RELATIVE) resolve against the
 * directory that holds the link. Either way FileObject->FileName becomes the complete name in the object
 * namespace and the information becomes IO_REPARSE, so that IopParseDevice hands the new name back to the
 * object manager. Frees DataBuffer.
 */
static
VOID
IopDoSymlinkTransmogrify(IN PIRP Irp,
                         IN PFILE_OBJECT FileObject,
                         IN PREPARSE_DATA_BUFFER DataBuffer,
                         IN PUNICODE_STRING CompleteName,
                         IN PUNICODE_STRING RemainingName,
                         IN PFILE_OBJECT RelatedFileObject)
{
    const ULONG HeaderSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) -
                             REPARSE_DATA_BUFFER_HEADER_SIZE;
    PWCHAR Sub, Tail, NewBuffer = NULL, Prefix = NULL;
    ULONG SubLength, TailLength, PathLength;
    ULONG PrefixChars = 0, HeadChars = 0, Floor = 0, Sep = 0, Total, NewChars;
    POBJECT_NAME_INFORMATION RelatedName = NULL;
    BOOLEAN Relative, Rooted;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    ASSERT(Irp->IoStatus.Status == STATUS_REPARSE);
    ASSERT(DataBuffer->ReparseTag == IO_REPARSE_TAG_SYMLINK);

    /* Validate the data the driver gave us */
    if (DataBuffer->ReparseDataLength < HeaderSize ||
        DataBuffer->ReparseDataLength >= MAXIMUM_REPARSE_DATA_BUFFER_SIZE ||
        DataBuffer->Reserved > FileObject->FileName.Length ||
        (DataBuffer->Reserved & 1))
    {
        Status = STATUS_IO_REPARSE_DATA_INVALID;
        goto Done;
    }
    PathLength = DataBuffer->ReparseDataLength - HeaderSize;
    SubLength = DataBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength;
    if (SubLength == 0 || (SubLength & 1) ||
        (DataBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset & 1) ||
        (ULONG)DataBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset + SubLength > PathLength)
    {
        Status = STATUS_IO_REPARSE_DATA_INVALID;
        goto Done;
    }
    Sub = (PWCHAR)((ULONG_PTR)DataBuffer->SymbolicLinkReparseBuffer.PathBuffer +
                   DataBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset);
    TailLength = DataBuffer->Reserved;
    Tail = (PWCHAR)((ULONG_PTR)FileObject->FileName.Buffer + FileObject->FileName.Length - TailLength);
    Relative = (DataBuffer->SymbolicLinkReparseBuffer.Flags & SYMLINK_FLAG_RELATIVE) != 0;
    Rooted = (Sub[0] == L'\\');

    /* An absolute link replaces the whole name, so its substitute has to be an absolute name too
       (Windows 10 gives ERROR_INVALID_NAME when such a link is opened) */
    if (!Relative && !Rooted)
    {
        Status = STATUS_OBJECT_NAME_INVALID;
        goto Done;
    }

    if (Relative)
    {
        PWCHAR Head = FileObject->FileName.Buffer;

        if (!Rooted)
        {
            /* The directory that holds the link: the name up to the link without its last component */
            HeadChars = (FileObject->FileName.Length - TailLength) / sizeof(WCHAR);
            while (HeadChars && Head[HeadChars - 1] != L'\\') HeadChars--;
        }

        if (!RelatedFileObject)
        {
            /* The device part of the complete name is what precedes the remaining name */
            if (CompleteName->Length < RemainingName->Length ||
                RemainingName->Length != FileObject->FileName.Length ||
                RtlCompareMemory((PUCHAR)CompleteName->Buffer + CompleteName->Length - RemainingName->Length,
                                 FileObject->FileName.Buffer,
                                 RemainingName->Length) != RemainingName->Length)
            {
                Status = STATUS_OBJECT_NAME_NOT_FOUND;
                goto Done;
            }
            Prefix = CompleteName->Buffer;
            PrefixChars = (CompleteName->Length - RemainingName->Length) / sizeof(WCHAR);
            Floor = PrefixChars;
        }
        else
        {
            ULONG Needed, Chars, Seen = 0;

            /* Relative to the related file: its full name is the base (a rooted link cannot be resolved here) */
            if (Rooted)
            {
                Status = STATUS_OBJECT_NAME_NOT_FOUND;
                goto Done;
            }
            RelatedName = ExAllocatePoolWithTag(PagedPool, sizeof(OBJECT_NAME_INFORMATION) + 0x10000, TAG_IO_NAME);
            if (!RelatedName)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Done;
            }
            Status = ObQueryNameString(RelatedFileObject,
                                       RelatedName,
                                       sizeof(OBJECT_NAME_INFORMATION) + 0x10000,
                                       &Needed);
            if (!NT_SUCCESS(Status) || !RelatedName->Name.Length)
            {
                if (NT_SUCCESS(Status)) Status = STATUS_OBJECT_NAME_NOT_FOUND;
                goto Done;
            }
            Prefix = RelatedName->Name.Buffer;
            PrefixChars = RelatedName->Name.Length / sizeof(WCHAR);
            while (PrefixChars > 1 && Prefix[PrefixChars - 1] == L'\\') PrefixChars--;

            /* ".." never climbs above \Device\Name */
            for (Chars = 0; Chars < PrefixChars; Chars++)
            {
                if (Prefix[Chars] == L'\\' && ++Seen == 3) break;
            }
            Floor = Chars;

            /* A related name has no leading backslash */
            if (!(HeadChars && Head[0] == L'\\')) Sep = 1;
        }
    }

    /* Build the new name: [prefix][\][head]substitute[tail] */
    Total = (Relative ? PrefixChars + Sep + HeadChars : 0) + SubLength / sizeof(WCHAR) + TailLength / sizeof(WCHAR);
    if ((Total + 2) * sizeof(WCHAR) >= MAXUSHORT)
    {
        Status = STATUS_NAME_TOO_LONG;
        goto Done;
    }
    NewBuffer = ExAllocatePoolWithTag(PagedPool, (Total + 2) * sizeof(WCHAR), TAG_IO_NAME);
    if (!NewBuffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    NewChars = 0;
    if (Relative)
    {
        if (PrefixChars) RtlCopyMemory(NewBuffer, Prefix, PrefixChars * sizeof(WCHAR));
        NewChars = PrefixChars;
        if (Sep) NewBuffer[NewChars++] = L'\\';
        if (HeadChars)
        {
            RtlCopyMemory(&NewBuffer[NewChars], FileObject->FileName.Buffer, HeadChars * sizeof(WCHAR));
            NewChars += HeadChars;
        }
    }
    RtlCopyMemory(&NewBuffer[NewChars], Sub, SubLength);
    NewChars += SubLength / sizeof(WCHAR);
    if (TailLength)
    {
        RtlCopyMemory(&NewBuffer[NewChars], Tail, TailLength);
        NewChars += TailLength / sizeof(WCHAR);
    }
    if (Relative) NewChars = IopRemoveDotsFromPath(NewBuffer, NewChars, Floor);

    /* Replace the file name; don't use TAG_IO_NAME to free the old one, a file system may have re-allocated it */
    if (FileObject->FileName.Buffer) ExFreePoolWithTag(FileObject->FileName.Buffer, 0);
    NewBuffer[NewChars] = UNICODE_NULL;
    FileObject->FileName.Buffer = NewBuffer;
    FileObject->FileName.Length = (USHORT)(NewChars * sizeof(WCHAR));
    FileObject->FileName.MaximumLength = (USHORT)((NewChars + 1) * sizeof(WCHAR));
    NewBuffer = NULL;

Done:
    if (NewBuffer) ExFreePoolWithTag(NewBuffer, TAG_IO_NAME);
    if (RelatedName) ExFreePoolWithTag(RelatedName, TAG_IO_NAME);
    ExFreePool(DataBuffer);

    if (NT_SUCCESS(Status))
    {
        /* The name is complete: the object manager parses it from the root again */
        Irp->IoStatus.Information = IO_REPARSE;
    }
    else
    {
        Irp->IoStatus.Status = Status;
    }
}

/* OBJ_DONT_REPARSE: fail instead of traversing a reparse point (not in every header set) */
#ifndef OBJ_DONT_REPARSE
#define OBJ_DONT_REPARSE 0x00001000
#endif

/* The device belongs to a network file system or a redirector */
static
BOOLEAN
IopIsRemoteDeviceObject(IN PDEVICE_OBJECT DeviceObject)
{
    if (DeviceObject->Characteristics & FILE_REMOTE_DEVICE) return TRUE;

    switch (DeviceObject->DeviceType)
    {
        case FILE_DEVICE_NETWORK_FILE_SYSTEM:
        case FILE_DEVICE_NETWORK_REDIRECTOR:
        case FILE_DEVICE_MULTI_UNC_PROVIDER:
        case FILE_DEVICE_DFS_FILE_SYSTEM:
        case FILE_DEVICE_DFS:
        case FILE_DEVICE_DFS_VOLUME:
            return TRUE;

        default:
            return FALSE;
    }
}

NTSTATUS
IopCheckTopDeviceHint(IN OUT PDEVICE_OBJECT * DeviceObject,
                      IN POPEN_PACKET OpenPacket,
                      BOOLEAN DirectOpen)
{
    PDEVICE_OBJECT LocalDevice;
    DEVICE_TYPE DeviceType;

    LocalDevice = *DeviceObject;

    /* Direct open is not allowed */
    if (DirectOpen)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate we have a file system device */
    DeviceType = LocalDevice->DeviceType;
    if (DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_TAPE_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_DFS_FILE_SYSTEM)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Verify the hint and if it's OK, return it */
    if (IopVerifyDeviceObjectOnStack(LocalDevice, OpenPacket->TopDeviceObjectHint))
    {
        *DeviceObject = OpenPacket->TopDeviceObjectHint;
        return STATUS_SUCCESS;
    }

    /* Failure case here */
    /* If we thought was had come through a mount point,
     * actually update we didn't and return the error
     */
    if (OpenPacket->TraversedMountPoint)
    {
        OpenPacket->TraversedMountPoint = FALSE;
        return STATUS_MOUNT_POINT_NOT_RESOLVED;
    }

    /* Otherwise, just return the fact the hint is invalid */
    return STATUS_INVALID_DEVICE_OBJECT_PARAMETER;
}

NTSTATUS
NTAPI
IopParseDevice(IN PVOID ParseObject,
               IN PVOID ObjectType,
               IN OUT PACCESS_STATE AccessState,
               IN KPROCESSOR_MODE AccessMode,
               IN ULONG Attributes,
               IN OUT PUNICODE_STRING CompleteName,
               IN OUT PUNICODE_STRING RemainingName,
               IN OUT PVOID Context,
               IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
               OUT PVOID *Object)
{
    POPEN_PACKET OpenPacket = (POPEN_PACKET)Context;
    PDEVICE_OBJECT OriginalDeviceObject = (PDEVICE_OBJECT)ParseObject;
    PDEVICE_OBJECT DeviceObject, OwnerDevice;
    NTSTATUS Status;
    PFILE_OBJECT FileObject;
    PVPB Vpb = NULL;
    PIRP Irp;
    PIO_STACK_LOCATION StackLoc;
    IO_SECURITY_CONTEXT SecurityContext;
    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN DirectOpen = FALSE, OpenCancelled, UseDummyFile;
    OBJECT_ATTRIBUTES ObjectAttributes;
    KIRQL OldIrql;
    PDUMMY_FILE_OBJECT LocalFileObject;
    PFILE_BASIC_INFORMATION FileBasicInfo;
    ULONG ReturnLength;
    KPROCESSOR_MODE CheckMode;
    BOOLEAN VolumeOpen = FALSE;
    ACCESS_MASK DesiredAccess, GrantedAccess;
    BOOLEAN AccessGranted, LockHeld = FALSE;
    PPRIVILEGE_SET Privileges = NULL;
    UNICODE_STRING FileString;
    USHORT Attempt;
    IOTRACE(IO_FILE_DEBUG, "ParseObject: %p. RemainingName: %wZ\n",
            ParseObject, RemainingName);

    for (Attempt = 0; Attempt < IOP_MAX_REPARSE_TRAVERSAL; ++Attempt)
    {
        /* Assume failure */
        *Object = NULL;

        /* Validate the open packet */
        if (!IopValidateOpenPacket(OpenPacket)) return STATUS_OBJECT_TYPE_MISMATCH;

        /* Valide reparse point in case we traversed a mountpoint */
        if (OpenPacket->TraversedMountPoint)
        {
            /* This is a reparse point we understand */
            ASSERT(OpenPacket->Information == IO_REPARSE_TAG_MOUNT_POINT);

            /* Make sure we're dealing with correct DO */
            if (OriginalDeviceObject->DeviceType != FILE_DEVICE_DISK &&
                OriginalDeviceObject->DeviceType != FILE_DEVICE_CD_ROM &&
                OriginalDeviceObject->DeviceType != FILE_DEVICE_VIRTUAL_DISK &&
                OriginalDeviceObject->DeviceType != FILE_DEVICE_TAPE)
            {
                OpenPacket->FinalStatus = STATUS_IO_REPARSE_DATA_INVALID;
                return STATUS_IO_REPARSE_DATA_INVALID;
            }
        }

        /* Check if we have a related file object */
        if (OpenPacket->RelatedFileObject)
        {
            /* Use the related file object's device object */
            OriginalDeviceObject = OpenPacket->RelatedFileObject->DeviceObject;
        }

        /* Validate device status */
        Status = IopCheckDeviceAndDriver(OpenPacket, OriginalDeviceObject);
        if (!NT_SUCCESS(Status))
        {
            /* We failed, return status */
            OpenPacket->FinalStatus = Status;
            return Status;
        }

        /* Map the generic mask and set the new mapping in the access state */
        RtlMapGenericMask(&AccessState->RemainingDesiredAccess,
                          &IoFileObjectType->TypeInfo.GenericMapping);
        RtlMapGenericMask(&AccessState->OriginalDesiredAccess,
                          &IoFileObjectType->TypeInfo.GenericMapping);
        SeSetAccessStateGenericMapping(AccessState,
                                       &IoFileObjectType->TypeInfo.GenericMapping);
        DesiredAccess = AccessState->RemainingDesiredAccess;

        /* Check what kind of access checks to do */
        if ((AccessMode != KernelMode) ||
            (OpenPacket->Options & IO_FORCE_ACCESS_CHECK))
        {
            /* Call is from user-mode or kernel is forcing checks */
            CheckMode = UserMode;
        }
        else
        {
            /* Call is from the kernel */
            CheckMode = KernelMode;
        }

        /* Check privilege for backup or restore operation */
        IopCheckBackupRestorePrivilege(AccessState,
                                       &OpenPacket->CreateOptions,
                                       CheckMode,
                                       OpenPacket->Disposition);

        /* Check if we are re-parsing */
        if (((OpenPacket->Override) && !(RemainingName->Length)) ||
            (AccessState->Flags & SE_BACKUP_PRIVILEGES_CHECKED))
        {
            /* Get granted access from the last call */
            DesiredAccess |= AccessState->PreviouslyGrantedAccess;
        }

        /*
         * NT6+ refuses a user-mode open or create that asks for no access at
         * all (zero access handles); attribute/delete-only probes carry their
         * own access and are not affected.
         */
        if ((NtMajorVersion >= 6) &&
            (AccessMode != KernelMode) &&
            !(OpenPacket->QueryOnly) &&
            !(OpenPacket->DeleteOnly) &&
            (DesiredAccess == 0) &&
            (AccessState->PreviouslyGrantedAccess == 0))
        {
            DPRINT("Zero access file open refused\n");
            IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
            return STATUS_ACCESS_DENIED;
        }

        /* Check if this is a volume open */
        if ((OpenPacket->RelatedFileObject) &&
            (OpenPacket->RelatedFileObject->Flags & FO_VOLUME_OPEN) &&
            !(RemainingName->Length))
        {
            /* It is */
            VolumeOpen = TRUE;
        }

        /* Now check if we need access checks */
        if (((AccessMode != KernelMode) ||
             (OpenPacket->Options & IO_FORCE_ACCESS_CHECK)) &&
            (!(OpenPacket->RelatedFileObject) || (VolumeOpen)) &&
            !(OpenPacket->Override))
        {
            KeEnterCriticalRegion();
            ExAcquireResourceSharedLite(&IopSecurityResource, TRUE);

            /* Check if a device object is being parsed  */
            if (!RemainingName->Length)
            {
                /* Lock the subject context */
                SeLockSubjectContext(&AccessState->SubjectSecurityContext);
                LockHeld = TRUE;

                /* Do access check */
                AccessGranted = SeAccessCheck(OriginalDeviceObject->
                                              SecurityDescriptor,
                                              &AccessState->SubjectSecurityContext,
                                              LockHeld,
                                              DesiredAccess,
                                              0,
                                              &Privileges,
                                              &IoFileObjectType->
                                              TypeInfo.GenericMapping,
                                              UserMode,
                                              &GrantedAccess,
                                              &Status);
                if (Privileges)
                {
                    /* Append and free the privileges */
                    SeAppendPrivileges(AccessState, Privileges);
                    SeFreePrivileges(Privileges);
                }

                /* Check if we got access */
                if (AccessGranted)
                {
                    /* Update access state */
                    AccessState->PreviouslyGrantedAccess |= GrantedAccess;
                    AccessState->RemainingDesiredAccess &= ~(GrantedAccess |
                                                             MAXIMUM_ALLOWED);
                    OpenPacket->Override= TRUE;
                }

                FileString.Length = 8;
                FileString.MaximumLength = 8;
                FileString.Buffer = L"File";

                /* Do Audit/Alarm for open operation */
                SeOpenObjectAuditAlarm(&FileString,
                                       OriginalDeviceObject,
                                       CompleteName,
                                       OriginalDeviceObject->SecurityDescriptor,
                                       AccessState,
                                       FALSE,
                                       AccessGranted,
                                       UserMode,
                                       &AccessState->GenerateOnClose);
            }
            else
            {
                /* Check if we need to do traverse validation */
                if (!(AccessState->Flags & TOKEN_HAS_TRAVERSE_PRIVILEGE) ||
                    ((OriginalDeviceObject->DeviceType == FILE_DEVICE_DISK) ||
                     (OriginalDeviceObject->DeviceType == FILE_DEVICE_CD_ROM)))
                {
                    /* Check if this is a restricted token */
                    if (!(AccessState->Flags & TOKEN_IS_RESTRICTED))
                    {
                        /* Do the FAST traverse check */
                        AccessGranted = SeFastTraverseCheck(OriginalDeviceObject->SecurityDescriptor,
                                                            AccessState,
                                                            FILE_TRAVERSE,
                                                            UserMode);
                    }
                    else
                    {
                        /* Fail */
                        AccessGranted = FALSE;
                    }

                    /* Check if we failed to get access */
                    if (!AccessGranted)
                    {
                        /* Lock the subject context */
                        SeLockSubjectContext(&AccessState->SubjectSecurityContext);
                        LockHeld = TRUE;

                        /* Do access check */
                        AccessGranted = SeAccessCheck(OriginalDeviceObject->
                                                      SecurityDescriptor,
                                                      &AccessState->SubjectSecurityContext,
                                                      LockHeld,
                                                      FILE_TRAVERSE,
                                                      0,
                                                      &Privileges,
                                                      &IoFileObjectType->
                                                      TypeInfo.GenericMapping,
                                                      UserMode,
                                                      &GrantedAccess,
                                                      &Status);
                        if (Privileges)
                        {
                            /* Append and free the privileges */
                            SeAppendPrivileges(AccessState, Privileges);
                            SeFreePrivileges(Privileges);
                        }
                    }

                    /* FIXME: Do Audit/Alarm for traverse check */
                }
                else
                {
                    /* Access automatically granted */
                    AccessGranted = TRUE;
                }
            }

            ExReleaseResourceLite(&IopSecurityResource);
            KeLeaveCriticalRegion();

            /* Check if we hold the lock */
            if (LockHeld)
            {
                /* Release it */
                SeUnlockSubjectContext(&AccessState->SubjectSecurityContext);
            }

            /* Check if access failed */
            if (!AccessGranted)
            {
                /* Dereference the device and fail */
                DPRINT1("Traverse access failed!\n");
                IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
                return STATUS_ACCESS_DENIED;
            }
        }

        /* Check if we can simply use a dummy file */
        UseDummyFile = ((OpenPacket->QueryOnly) || (OpenPacket->DeleteOnly));

        /* Check if this is a direct open */
        if (!(RemainingName->Length) &&
            !(OpenPacket->RelatedFileObject) &&
            ((DesiredAccess & ~(SYNCHRONIZE |
                                FILE_READ_ATTRIBUTES |
                                READ_CONTROL |
                                ACCESS_SYSTEM_SECURITY |
                                WRITE_OWNER |
                                WRITE_DAC)) == 0) &&
            !(UseDummyFile))
        {
            /* Remember this for later */
            DirectOpen = TRUE;
        }

        /* Check if we have a related FO that wasn't a direct open */
        if ((OpenPacket->RelatedFileObject) &&
            !(OpenPacket->RelatedFileObject->Flags & FO_DIRECT_DEVICE_OPEN))
        {
            /* The device object is the one we were given */
            DeviceObject = ParseObject;

            /* Check if the related FO had a VPB */
            if (OpenPacket->RelatedFileObject->Vpb)
            {
                /* Yes, remember it */
                Vpb = OpenPacket->RelatedFileObject->Vpb;

                /* Reference it */
                InterlockedIncrement((PLONG)&Vpb->ReferenceCount);

                /* Check if we were given a specific top level device to use */
                if (OpenPacket->InternalFlags & IOP_USE_TOP_LEVEL_DEVICE_HINT)
                {
                    DeviceObject = Vpb->DeviceObject;
                }
            }
        }
        else
        {
            /* Check if it has a VPB */
            if ((OriginalDeviceObject->Vpb) && !(DirectOpen))
            {
                /* Check if the VPB is mounted, and mount it */
                Vpb = IopCheckVpbMounted(OpenPacket,
                                         OriginalDeviceObject,
                                         RemainingName,
                                         &Status);
                if (!Vpb) return Status;

                /* Get the VPB's device object */
                DeviceObject = Vpb->DeviceObject;
            }
            else
            {
                /* The device object is the one we were given */
                DeviceObject = OriginalDeviceObject;
            }

            /* If we weren't given a specific top level device, look for an attached device */
            if (!(OpenPacket->InternalFlags & IOP_USE_TOP_LEVEL_DEVICE_HINT) &&
                DeviceObject->AttachedDevice)
            {
                /* Get the attached device */
                DeviceObject = IoGetAttachedDevice(DeviceObject);
            }
        }

        /* If we have a top level device hint, verify it */
        if (OpenPacket->InternalFlags & IOP_USE_TOP_LEVEL_DEVICE_HINT)
        {
            Status = IopCheckTopDeviceHint(&DeviceObject, OpenPacket, DirectOpen);
            if (!NT_SUCCESS(Status))
            {
                IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
                if (Vpb) IopDereferenceVpbAndFree(Vpb);
                return Status;
            }
        }

        /* If we traversed a mount point, reset the information */
        if (OpenPacket->TraversedMountPoint)
        {
            OpenPacket->TraversedMountPoint = FALSE;
        }

        /* Check if this is a secure FSD */
        if ((DeviceObject->Characteristics & FILE_DEVICE_SECURE_OPEN) &&
            ((OpenPacket->RelatedFileObject) || (RemainingName->Length)) &&
            (!VolumeOpen))
        {
            Privileges = NULL;
            GrantedAccess = 0;

            KeEnterCriticalRegion();
            ExAcquireResourceSharedLite(&IopSecurityResource, TRUE);

            /* Lock the subject context */
            SeLockSubjectContext(&AccessState->SubjectSecurityContext);

            /* Do access check */
            AccessGranted = SeAccessCheck(OriginalDeviceObject->SecurityDescriptor,
                                          &AccessState->SubjectSecurityContext,
                                          TRUE,
                                          DesiredAccess,
                                          0,
                                          &Privileges,
                                          &IoFileObjectType->TypeInfo.GenericMapping,
                                          UserMode,
                                          &GrantedAccess,
                                          &Status);
            if (Privileges != NULL)
            {
                /* Append and free the privileges */
                SeAppendPrivileges(AccessState, Privileges);
                SeFreePrivileges(Privileges);
            }

            /* Check if we got access */
            if (GrantedAccess)
            {
                AccessState->PreviouslyGrantedAccess |= GrantedAccess;
                AccessState->RemainingDesiredAccess &= ~(GrantedAccess | MAXIMUM_ALLOWED);
            }

            FileString.Length = 8;
            FileString.MaximumLength = 8;
            FileString.Buffer = L"File";

            /* Do Audit/Alarm for open operation
             * NOTA: we audit target device object
             */
            SeOpenObjectAuditAlarm(&FileString,
                                   DeviceObject,
                                   CompleteName,
                                   OriginalDeviceObject->SecurityDescriptor,
                                   AccessState,
                                   FALSE,
                                   AccessGranted,
                                   UserMode,
                                   &AccessState->GenerateOnClose);

            SeUnlockSubjectContext(&AccessState->SubjectSecurityContext);

            ExReleaseResourceLite(&IopSecurityResource);
            KeLeaveCriticalRegion();

            /* Check if access failed */
            if (!AccessGranted)
            {
                /* Dereference the device and fail */
                IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
                if (Vpb) IopDereferenceVpbAndFree(Vpb);
                return STATUS_ACCESS_DENIED;
            }
        }

        /* Allocate the IRP */
        Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
        if (!Irp)
        {
            /* Dereference the device and VPB, then fail */
            IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
            if (Vpb) IopDereferenceVpbAndFree(Vpb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Now set the IRP data */
        Irp->RequestorMode = AccessMode;
        Irp->Flags = IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API | IRP_DEFER_IO_COMPLETION;
        Irp->Tail.Overlay.Thread = PsGetCurrentThread();
        Irp->UserIosb = &IoStatusBlock;
        Irp->MdlAddress = NULL;
        Irp->PendingReturned = FALSE;
        Irp->UserEvent = NULL;
        Irp->Cancel = FALSE;
        Irp->CancelRoutine = NULL;
        Irp->Tail.Overlay.AuxiliaryBuffer = NULL;

        /*
         * Deliver the ECP list of IoCreateFileEx: a create IRP carries it in UserBuffer,
         * where IoGetIrpExtraCreateParameter (FsRtlGetEcpListFromIrp) reads it.
         * The caller owns the list for the duration of the create.
         */
        Irp->UserBuffer = OpenPacket->EcpList;

        /* Setup the security context */
        SecurityContext.SecurityQos = SecurityQos;
        SecurityContext.AccessState = AccessState;
        SecurityContext.DesiredAccess = AccessState->RemainingDesiredAccess;
        SecurityContext.FullCreateOptions = OpenPacket->CreateOptions;

        /* Get the I/O Stack location */
        StackLoc = IoGetNextIrpStackLocation(Irp);
        StackLoc->Control = 0;

        /* Check what kind of file this is */
        switch (OpenPacket->CreateFileType)
        {
            /* Normal file */
            case CreateFileTypeNone:

                /* Set the major function and EA Length */
                StackLoc->MajorFunction = IRP_MJ_CREATE;
                StackLoc->Parameters.Create.EaLength = OpenPacket->EaLength;

                /* Set the flags */
                StackLoc->Flags = (UCHAR)OpenPacket->Options;
                StackLoc->Flags |= !(Attributes & OBJ_CASE_INSENSITIVE) ? SL_CASE_SENSITIVE: 0;
                break;

            /* Named pipe */
            case CreateFileTypeNamedPipe:

                /* Set the named pipe MJ and set the parameters */
                StackLoc->MajorFunction = IRP_MJ_CREATE_NAMED_PIPE;
                StackLoc->Parameters.CreatePipe.Parameters = OpenPacket->ExtraCreateParameters;
                break;

            /* Mailslot */
            case CreateFileTypeMailslot:

                /* Set the mailslot MJ and set the parameters */
                StackLoc->MajorFunction = IRP_MJ_CREATE_MAILSLOT;
                StackLoc->Parameters.CreateMailslot.Parameters = OpenPacket->ExtraCreateParameters;
                break;
        }

        /* Set the common data */
        Irp->Overlay.AllocationSize = OpenPacket->AllocationSize;
        Irp->AssociatedIrp.SystemBuffer = OpenPacket->EaBuffer;
        StackLoc->Parameters.Create.Options = (OpenPacket->Disposition << 24) |
                                              (OpenPacket->CreateOptions &
                                               0xFFFFFF);
        StackLoc->Parameters.Create.FileAttributes = OpenPacket->FileAttributes;
        StackLoc->Parameters.Create.ShareAccess = OpenPacket->ShareAccess;
        StackLoc->Parameters.Create.SecurityContext = &SecurityContext;

        /* Check if we really need to create an object */
        if (!UseDummyFile)
        {
            ULONG ObjectSize = sizeof(FILE_OBJECT);

            /* Tag on space for a file object extension */
            if (OpenPacket->InternalFlags & IOP_CREATE_FILE_OBJECT_EXTENSION)
                ObjectSize += sizeof(FILE_OBJECT_EXTENSION);

            /* Create the actual file object */
            InitializeObjectAttributes(&ObjectAttributes,
                                       NULL,
                                       Attributes,
                                       NULL,
                                       NULL);
            Status = ObCreateObject(KernelMode,
                                    IoFileObjectType,
                                    &ObjectAttributes,
                                    AccessMode,
                                    NULL,
                                    ObjectSize,
                                    0,
                                    0,
                                    (PVOID*)&FileObject);
            if (!NT_SUCCESS(Status))
            {
                /* Create failed, free the IRP */
                IoFreeIrp(Irp);

                /* Dereference the device and VPB */
                IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
                if (Vpb) IopDereferenceVpbAndFree(Vpb);

                /* We failed, return status */
                OpenPacket->FinalStatus = Status;
                return Status;
            }

            /* Clear the file object */
            RtlZeroMemory(FileObject, ObjectSize);

            /* Check if this is Synch I/O */
            if (OpenPacket->CreateOptions &
                (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
            {
                /* Set the synch flag */
                FileObject->Flags |= FO_SYNCHRONOUS_IO;

                /* Check if it's also alertable */
                if (OpenPacket->CreateOptions & FILE_SYNCHRONOUS_IO_ALERT)
                {
                    /* It is, set the alertable flag */
                    FileObject->Flags |= FO_ALERTABLE_IO;
                }
            }

            /* Check if this is synch I/O */
            if (FileObject->Flags & FO_SYNCHRONOUS_IO)
            {
                /* Initialize the event */
                KeInitializeEvent(&FileObject->Lock, SynchronizationEvent, FALSE);
            }

            /* Check if the caller requested no intermediate buffering */
            if (OpenPacket->CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING)
            {
                /* Set the correct flag for the FSD to read */
                FileObject->Flags |= FO_NO_INTERMEDIATE_BUFFERING;
            }

            /* Check if the caller requested write through support */
            if (OpenPacket->CreateOptions & FILE_WRITE_THROUGH)
            {
                /* Set the correct flag for the FSD to read */
                FileObject->Flags |= FO_WRITE_THROUGH;
            }

            /* Check if the caller says the file will be only read sequentially */
            if (OpenPacket->CreateOptions & FILE_SEQUENTIAL_ONLY)
            {
                /* Set the correct flag for the FSD to read */
                FileObject->Flags |= FO_SEQUENTIAL_ONLY;
            }

            /* Check if the caller believes the file will be only read randomly */
            if (OpenPacket->CreateOptions & FILE_RANDOM_ACCESS)
            {
                /* Set the correct flag for the FSD to read */
                FileObject->Flags |= FO_RANDOM_ACCESS;
            }

            /* Check if we were asked to setup a file object extension */
            if (OpenPacket->InternalFlags & IOP_CREATE_FILE_OBJECT_EXTENSION)
            {
                PFILE_OBJECT_EXTENSION FileObjectExtension;

                /* Make sure the file object knows it has an extension */
                FileObject->Flags |= FO_FILE_OBJECT_HAS_EXTENSION;

                /* Initialize file object extension */
                FileObjectExtension = (PFILE_OBJECT_EXTENSION)(FileObject + 1);
                FileObject->FileObjectExtension = FileObjectExtension;

                /* Add the top level device which we'll send the request to */
                if (OpenPacket->InternalFlags & IOP_USE_TOP_LEVEL_DEVICE_HINT)
                {
                    FileObjectExtension->TopDeviceObjectHint = DeviceObject;
                }
            }
        }
        else
        {
            /* Use the dummy object instead */
            LocalFileObject = OpenPacket->LocalFileObject;
            RtlZeroMemory(LocalFileObject, sizeof(DUMMY_FILE_OBJECT));

            /* Set it up */
            FileObject = (PFILE_OBJECT)&LocalFileObject->ObjectHeader.Body;
            LocalFileObject->ObjectHeader.Type = IoFileObjectType;
            LocalFileObject->ObjectHeader.PointerCount = 1;
        }

        /* Setup the file header */
        FileObject->Type = IO_TYPE_FILE;
        FileObject->Size = sizeof(FILE_OBJECT);
        FileObject->RelatedFileObject = OpenPacket->RelatedFileObject;
        FileObject->DeviceObject = OriginalDeviceObject;

        /* Check if this is a direct device open */
        if (DirectOpen) FileObject->Flags |= FO_DIRECT_DEVICE_OPEN;

        /* Check if the caller wants case sensitivity */
        if (!(Attributes & OBJ_CASE_INSENSITIVE))
        {
            /* Tell the driver about it */
            FileObject->Flags |= FO_OPENED_CASE_SENSITIVE;
        }

        /* Now set the file object */
        Irp->Tail.Overlay.OriginalFileObject = FileObject;
        StackLoc->FileObject = FileObject;

        /* Check if the file object has a name */
        if (RemainingName->Length)
        {
            /* Setup the unicode string */
            FileObject->FileName.MaximumLength = RemainingName->Length + sizeof(WCHAR);
            FileObject->FileName.Buffer = ExAllocatePoolWithTag(PagedPool,
                                                                FileObject->FileName.MaximumLength,
                                                                TAG_IO_NAME);
            if (!FileObject->FileName.Buffer)
            {
                /* Failed to allocate the name, free the IRP */
                IoFreeIrp(Irp);

                /* Dereference the device object and VPB */
                IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
                if (Vpb) IopDereferenceVpbAndFree(Vpb);

                /* Clear the FO and dereference it */
                FileObject->DeviceObject = NULL;
                if (!UseDummyFile) ObDereferenceObject(FileObject);

                /* Fail */
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        /* Copy the name */
        RtlCopyUnicodeString(&FileObject->FileName, RemainingName);

        /* Initialize the File Object event and set the FO */
        KeInitializeEvent(&FileObject->Event, NotificationEvent, FALSE);
        OpenPacket->FileObject = FileObject;

        /*
         * A file system that answers FastIoQueryOpen reads the attributes of an existing file straight from the create
         * request, with no file object left behind (so no cleanup and close follow, and the file system need not
         * keep an FCB): NtQueryFullAttributesFile, GetFileAttributes, every stat of a program that scans a tree.  The
         * routine gets the IRP with its current stack location on the create parameters; TRUE with a failure status is
         * a definite answer too (the name is not there).  FALSE (a stream, a reparse
         * point, a file that is being deleted, a failed check) leaves everything as it was
         * and the open goes on the ordinary way.
         */
        if (OpenPacket->QueryOnly && OpenPacket->FullAttributes && UseDummyFile &&
            OpenPacket->CreateFileType == CreateFileTypeNone && DeviceObject->DriverObject &&
            DeviceObject->DriverObject->FastIoDispatch &&
            DeviceObject->DriverObject->FastIoDispatch->SizeOfFastIoDispatch >=
                FIELD_OFFSET(FAST_IO_DISPATCH, FastIoQueryOpen) + sizeof(PFAST_IO_QUERY_OPEN) &&
            DeviceObject->DriverObject->FastIoDispatch->FastIoQueryOpen)
        {
            BOOLEAN FastDone;

            IoSetNextIrpStackLocation(Irp);
            FastDone = DeviceObject->DriverObject->FastIoDispatch->FastIoQueryOpen(Irp,
                                                                                    OpenPacket->NetworkInformation,
                                                                                    DeviceObject);
            /* The location the IRP had: the ordinary open sets it up for the driver, and a freed IRP must be whole */
            Irp->CurrentLocation++;
            Irp->Tail.Overlay.CurrentStackLocation++;
            if (FastDone)
            {
                Status = Irp->IoStatus.Status;

                /* The answer is in the open packet; undo what was set up for the request */
                if (FileObject->FileName.Length)
                {
                    ExFreePoolWithTag(FileObject->FileName.Buffer, 0);
                    FileObject->FileName.Buffer = NULL;
                    FileObject->FileName.Length = 0;
                }
                FileObject->DeviceObject = NULL;
                OpenPacket->FileObject = NULL;
                IoFreeIrp(Irp);
                IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);
                if (Vpb) IopDereferenceVpbAndFree(Vpb);

                OpenPacket->Information = 0;
                OpenPacket->FinalStatus = Status;
                /* As the driver's failure to create does: only a success is the I/O status (see IopQueryAttributesFile) */
                if (NT_SUCCESS(Status)) OpenPacket->ParseCheck = TRUE;
                return Status;
            }
        }

        /* Queue the IRP and call the driver */
        IopQueueIrpToThread(Irp);
        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            /* Wait for the driver to complete the create */
            KeWaitForSingleObject(&FileObject->Event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);

            /* Get the new status */
            Status = IoStatusBlock.Status;
        }
        else
        {
            /* We'll have to complete it ourselves */
            ASSERT(!Irp->PendingReturned);
            ASSERT(!Irp->MdlAddress);

            /* Handle name change if required */
            if (Status == STATUS_REPARSE)
            {
                /*
                 * The caller does not want reparse points traversed, or wants to stop at a symbolic link.
                 * A link a network file system gives us is not followed either: remote to local and
                 * remote to remote evaluation are off by default on Windows (STATUS_SYMLINK_CLASS_DISABLED)
                 */
                if ((Irp->IoStatus.Information == IO_REPARSE_TAG_MOUNT_POINT ||
                     Irp->IoStatus.Information == IO_REPARSE_TAG_SYMLINK) &&
                    ((Attributes & OBJ_DONT_REPARSE) ||
                     (Irp->IoStatus.Information == IO_REPARSE_TAG_SYMLINK &&
                      ((OpenPacket->Options & IO_STOP_ON_SYMLINK) ||
                       IopIsRemoteDeviceObject(OriginalDeviceObject) ||
                       IopIsRemoteDeviceObject(DeviceObject)))))
                {
                    if (Attributes & OBJ_DONT_REPARSE)
                        Irp->IoStatus.Status = STATUS_REPARSE_POINT_ENCOUNTERED;
                    else if (OpenPacket->Options & IO_STOP_ON_SYMLINK)
                        Irp->IoStatus.Status = STATUS_STOPPED_ON_SYMLINK;
                    else
                        Irp->IoStatus.Status = STATUS_SYMLINK_CLASS_DISABLED;

                    if (Irp->Tail.Overlay.AuxiliaryBuffer)
                        ExFreePool(Irp->Tail.Overlay.AuxiliaryBuffer);
                    Irp->Tail.Overlay.AuxiliaryBuffer = NULL;
                }
                /* Check this is a mount point */
                else if (Irp->IoStatus.Information == IO_REPARSE_TAG_MOUNT_POINT)
                {
                    PREPARSE_DATA_BUFFER ReparseData;

                    /* Reparse point attributes were passed by the driver in the auxiliary buffer */
                    ASSERT(Irp->Tail.Overlay.AuxiliaryBuffer != NULL);
                    ReparseData = (PREPARSE_DATA_BUFFER)Irp->Tail.Overlay.AuxiliaryBuffer;

                    ASSERT(ReparseData->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT);
                    ASSERT(ReparseData->ReparseDataLength < MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
                    ASSERT(ReparseData->Reserved < MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

                    IopDoNameTransmogrify(Irp, FileObject, ReparseData);
                }
                else if (Irp->IoStatus.Information == IO_REPARSE_TAG_SYMLINK)
                {
                    PREPARSE_DATA_BUFFER ReparseData;

                    /* Reparse point attributes were passed by the driver in the auxiliary buffer */
                    ASSERT(Irp->Tail.Overlay.AuxiliaryBuffer != NULL);
                    ReparseData = (PREPARSE_DATA_BUFFER)Irp->Tail.Overlay.AuxiliaryBuffer;
                    Irp->Tail.Overlay.AuxiliaryBuffer = NULL;

                    ASSERT(ReparseData->ReparseTag == IO_REPARSE_TAG_SYMLINK);
                    IopDoSymlinkTransmogrify(Irp,
                                             FileObject,
                                             ReparseData,
                                             CompleteName,
                                             RemainingName,
                                             OpenPacket->RelatedFileObject);
                }
            }

            /* Completion happens at APC_LEVEL */
            KeRaiseIrql(APC_LEVEL, &OldIrql);

            /* Get the new I/O Status block ourselves */
            IoStatusBlock = Irp->IoStatus;
            Status = IoStatusBlock.Status;

            /* Manually signal the even, we can't have any waiters */
            FileObject->Event.Header.SignalState = 1;

            /* Now that we've signaled the events, de-associate the IRP */
            IopUnQueueIrpFromThread(Irp);

            /* Check if the IRP had an input buffer */
            if ((Irp->Flags & IRP_BUFFERED_IO) &&
                (Irp->Flags & IRP_DEALLOCATE_BUFFER))
            {
                /* Free it. A driver might've tacked one on */
                ExFreePool(Irp->AssociatedIrp.SystemBuffer);
            }

            /* Free the IRP and bring the IRQL back down */
            IoFreeIrp(Irp);
            KeLowerIrql(OldIrql);
        }

        /* Copy the I/O Status */
        OpenPacket->Information = IoStatusBlock.Information;

        /* The driver failed to create the file */
        if (!NT_SUCCESS(Status))
        {
            /* Check if we have a name and if so, free it */
            if (FileObject->FileName.Length)
            {
                /*
                 * Don't use TAG_IO_NAME since the FileObject's FileName
                 * may have been re-allocated using a different tag
                 * by a filesystem.
                 */
                ExFreePoolWithTag(FileObject->FileName.Buffer, 0);
                FileObject->FileName.Buffer = NULL;
                FileObject->FileName.Length = 0;
            }

            /* Clear its device object */
            FileObject->DeviceObject = NULL;

            /* Save this now because the FO might go away */
            OpenCancelled = FileObject->Flags & FO_FILE_OPEN_CANCELLED ?
                            TRUE : FALSE;

            /* Clear the file object in the open packet */
            OpenPacket->FileObject = NULL;

            /* Dereference the file object */
            if (!UseDummyFile) ObDereferenceObject(FileObject);

            /* Dereference the device object */
            IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);

            /* Unless the driver cancelled the open, dereference the VPB */
            if (!(OpenCancelled) && (Vpb)) IopDereferenceVpbAndFree(Vpb);

            /* Set the status and return */
            OpenPacket->FinalStatus = Status;
            return Status;
        }
        else if (Status == STATUS_REPARSE)
        {
            if (OpenPacket->Information == IO_REPARSE ||
                OpenPacket->Information == IO_REPARSE_TAG_MOUNT_POINT)
            {
                /* Update CompleteName with reparse info which got updated in IopDoNameTransmogrify() */
                if (CompleteName->MaximumLength < FileObject->FileName.Length)
                {
                    PWSTR NewCompleteName;

                    /* Allocate a new buffer for the string */
                    NewCompleteName = ExAllocatePoolWithTag(PagedPool, FileObject->FileName.Length, TAG_IO_NAME);
                    if (NewCompleteName == NULL)
                    {
                        OpenPacket->FinalStatus = STATUS_INSUFFICIENT_RESOURCES;
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    /* Release the old one */
                    if (CompleteName->Buffer != NULL)
                    {
                        /*
                         * Don't use TAG_IO_NAME since the FileObject's FileName
                         * may have been re-allocated using a different tag
                         * by a filesystem.
                         */
                        ExFreePoolWithTag(CompleteName->Buffer, 0);
                    }

                    /* And setup the new one */
                    CompleteName->Buffer = NewCompleteName;
                    CompleteName->MaximumLength = FileObject->FileName.Length;
                }

                /* Copy our new complete name */
                RtlCopyUnicodeString(CompleteName, &FileObject->FileName);

                if (OpenPacket->Information == IO_REPARSE_TAG_MOUNT_POINT)
                {
                    OpenPacket->RelatedFileObject = NULL;
                }
            }

            /* Check if we have a name and if so, free it */
            if (FileObject->FileName.Length)
            {
                /*
                 * Don't use TAG_IO_NAME since the FileObject's FileName
                 * may have been re-allocated using a different tag
                 * by a filesystem.
                 */
                ExFreePoolWithTag(FileObject->FileName.Buffer, 0);
                FileObject->FileName.Buffer = NULL;
                FileObject->FileName.Length = 0;
            }

            /* Clear its device object */
            FileObject->DeviceObject = NULL;

            /* Clear the file object in the open packet */
            OpenPacket->FileObject = NULL;

            /* Dereference the file object */
            if (!UseDummyFile) ObDereferenceObject(FileObject);

            /* Dereference the device object */
            IopDereferenceDeviceObject(OriginalDeviceObject, FALSE);

            /* Unless the driver cancelled the open, dereference the VPB */
            if (Vpb != NULL) IopDereferenceVpbAndFree(Vpb);

            if (OpenPacket->Information != IO_REMOUNT)
            {
                OpenPacket->RelatedFileObject = NULL;

                /* Inform we traversed a mount point for later attempt */
                if (OpenPacket->Information == IO_REPARSE_TAG_MOUNT_POINT)
                {
                    OpenPacket->TraversedMountPoint = 1;
                }

                /* In case we override checks, but got this on volume open, fail hard */
                if (OpenPacket->Override)
                {
                    KeBugCheckEx(DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN,
                                 (ULONG_PTR)OriginalDeviceObject,
                                 (ULONG_PTR)DeviceObject,
                                 (ULONG_PTR)CompleteName,
                                 OpenPacket->Information);
                }

                /* Return to IO/OB so that information can be upgraded */
                return STATUS_REPARSE;
            }

            /* Loop again and reattempt an opening */
            continue;
        }

        break;
    }

    if (Attempt == IOP_MAX_REPARSE_TRAVERSAL)
        return STATUS_UNSUCCESSFUL;

    /* Get the owner of the File Object */
    OwnerDevice = IoGetRelatedDeviceObject(FileObject);

    /*
     * It's possible that the device to whom we sent the IRP to
     * isn't actually the device that ended opening the file object
     * internally.
     */
    if (OwnerDevice != DeviceObject)
    {
        /* We have to de-reference the VPB we had associated */
        if (Vpb) IopDereferenceVpbAndFree(Vpb);

        /* And re-associate with the actual one */
        Vpb = FileObject->Vpb;
        if (Vpb) InterlockedIncrement((PLONG)&Vpb->ReferenceCount);
    }

    /* Make sure we are not using a dummy */
    if (!UseDummyFile)
    {
        /* Check if this was a volume open */
        if ((!(FileObject->RelatedFileObject) ||
              (FileObject->RelatedFileObject->Flags & FO_VOLUME_OPEN)) &&
            !(FileObject->FileName.Length))
        {
            /* All signs point to it, but make sure it was actually an FSD */
            if ((OwnerDevice->DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM) ||
                (OwnerDevice->DeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) ||
                (OwnerDevice->DeviceType == FILE_DEVICE_TAPE_FILE_SYSTEM) ||
                (OwnerDevice->DeviceType == FILE_DEVICE_FILE_SYSTEM))
            {
                /* The owner device is an FSD, so this is a volume open for real */
                FileObject->Flags |= FO_VOLUME_OPEN;
            }
        }

        /* Reference the object and set the parse check */
        ObReferenceObject(FileObject);
        *Object = FileObject;
        OpenPacket->FinalStatus = IoStatusBlock.Status;
        OpenPacket->ParseCheck = TRUE;
        return OpenPacket->FinalStatus;
    }
    else
    {
        /* Check if this was a query */
        if (OpenPacket->QueryOnly)
        {
            /* Check if the caller wants basic info only */
            if (!OpenPacket->FullAttributes)
            {
                /* Allocate the buffer */
                FileBasicInfo = ExAllocatePoolWithTag(NonPagedPool,
                                                      sizeof(*FileBasicInfo),
                                                      TAG_IO);
                if (FileBasicInfo)
                {
                    /* Do the query */
                    Status = IoQueryFileInformation(FileObject,
                                                    FileBasicInformation,
                                                    sizeof(*FileBasicInfo),
                                                    FileBasicInfo,
                                                    &ReturnLength);
                    if (NT_SUCCESS(Status))
                    {
                        /* Copy the data */
                        RtlCopyMemory(OpenPacket->BasicInformation,
                                      FileBasicInfo,
                                      ReturnLength);
                    }

                    /* Free our buffer */
                    ExFreePoolWithTag(FileBasicInfo, TAG_IO);
                }
                else
                {
                    /* Fail */
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            else
            {
                /* This is a full query */
                Status = IoQueryFileInformation(
                    FileObject,
                    FileNetworkOpenInformation,
                    sizeof(FILE_NETWORK_OPEN_INFORMATION),
                    OpenPacket->NetworkInformation,
                    &ReturnLength);

                /*
                 * A file system that does not answer FileNetworkOpenInformation on a handle (npfs
                 * answers STATUS_INVALID_PARAMETER) still reports its attributes by name: build the
                 * answer from the basic and standard information, as Windows does.
                 */
                if (Status == STATUS_INVALID_PARAMETER ||
                    Status == STATUS_INVALID_INFO_CLASS ||
                    Status == STATUS_NOT_IMPLEMENTED ||
                    Status == STATUS_NOT_SUPPORTED ||
                    Status == STATUS_INVALID_DEVICE_REQUEST)
                {
                    FILE_BASIC_INFORMATION LocalBasicInfo;
                    FILE_STANDARD_INFORMATION LocalStandardInfo;

                    Status = IoQueryFileInformation(FileObject,
                                                    FileBasicInformation,
                                                    sizeof(LocalBasicInfo),
                                                    &LocalBasicInfo,
                                                    &ReturnLength);
                    if (NT_SUCCESS(Status))
                    {
                        Status = IoQueryFileInformation(FileObject,
                                                        FileStandardInformation,
                                                        sizeof(LocalStandardInfo),
                                                        &LocalStandardInfo,
                                                        &ReturnLength);
                    }
                    if (NT_SUCCESS(Status))
                    {
                        PFILE_NETWORK_OPEN_INFORMATION NetworkInfo = OpenPacket->NetworkInformation;

                        NetworkInfo->CreationTime = LocalBasicInfo.CreationTime;
                        NetworkInfo->LastAccessTime = LocalBasicInfo.LastAccessTime;
                        NetworkInfo->LastWriteTime = LocalBasicInfo.LastWriteTime;
                        NetworkInfo->ChangeTime = LocalBasicInfo.ChangeTime;
                        NetworkInfo->AllocationSize = LocalStandardInfo.AllocationSize;
                        NetworkInfo->EndOfFile = LocalStandardInfo.EndOfFile;
                        NetworkInfo->FileAttributes = LocalBasicInfo.FileAttributes;
                    }
                }
                if (!NT_SUCCESS(Status)) ASSERT(Status != STATUS_NOT_IMPLEMENTED);
            }
        }

        /* Delete the file object */
        IopDeleteFile(FileObject);

        /* Clear out the file */
        OpenPacket->FileObject = NULL;

        /* Set and return status */
        OpenPacket->FinalStatus = Status;
        OpenPacket->ParseCheck = TRUE;
        return Status;
    }
}

NTSTATUS
NTAPI
IopParseFile(IN PVOID ParseObject,
             IN PVOID ObjectType,
             IN OUT PACCESS_STATE AccessState,
             IN KPROCESSOR_MODE AccessMode,
             IN ULONG Attributes,
             IN OUT PUNICODE_STRING CompleteName,
             IN OUT PUNICODE_STRING RemainingName,
             IN OUT PVOID Context OPTIONAL,
             IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
             OUT PVOID *Object)
{
    PVOID DeviceObject;
    POPEN_PACKET OpenPacket = (POPEN_PACKET)Context;

    /* Validate the open packet */
    if (!IopValidateOpenPacket(OpenPacket)) return STATUS_OBJECT_TYPE_MISMATCH;

    /* Get the device object */
    DeviceObject = IoGetRelatedDeviceObject(ParseObject);
    OpenPacket->RelatedFileObject = ParseObject;

    /* Call the main routine */
    return IopParseDevice(DeviceObject,
                          ObjectType,
                          AccessState,
                          AccessMode,
                          Attributes,
                          CompleteName,
                          RemainingName,
                          OpenPacket,
                          SecurityQos,
                          Object);
}

VOID
NTAPI
IopDeleteFile(IN PVOID ObjectBody)
{
    PFILE_OBJECT FileObject = (PFILE_OBJECT)ObjectBody;
    PIRP Irp;
    PIO_STACK_LOCATION StackPtr;
    NTSTATUS Status;
    KEVENT Event;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN DereferenceDone = FALSE;
    PVPB Vpb;
    KIRQL OldIrql;
    IOTRACE(IO_FILE_DEBUG, "ObjectBody: %p\n", ObjectBody);

    /* Check if the file has a device object */
    if (FileObject->DeviceObject)
    {
        /* Check if this is a direct open or not */
        if (FileObject->Flags & FO_DIRECT_DEVICE_OPEN)
        {
            /* Get the attached device */
            DeviceObject = IoGetAttachedDevice(FileObject->DeviceObject);
        }
        else
        {
            /* Use the file object's device object */
            DeviceObject = IoGetRelatedDeviceObject(FileObject);
        }

        /* Sanity check */
        ASSERT(!(FileObject->Flags & FO_SYNCHRONOUS_IO) ||
               (InterlockedExchange((PLONG)&FileObject->Busy, TRUE) == FALSE));

        /* Check if the handle wasn't created yet */
        if (!(FileObject->Flags & FO_HANDLE_CREATED))
        {
            /* Send the cleanup IRP */
            IopCloseFile(NULL, ObjectBody, 0, 1, 1);
        }

        /* Clear and set up Events */
        KeClearEvent(&FileObject->Event);
        KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

        /* Allocate an IRP */
        Irp = IopAllocateIrpMustSucceed(DeviceObject->StackSize);

        /* Set it up */
        Irp->UserEvent = &Event;
        Irp->UserIosb = &Irp->IoStatus;
        Irp->Tail.Overlay.Thread = PsGetCurrentThread();
        Irp->Tail.Overlay.OriginalFileObject = FileObject;
        Irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;

        /* Set up Stack Pointer Data */
        StackPtr = IoGetNextIrpStackLocation(Irp);
        StackPtr->MajorFunction = IRP_MJ_CLOSE;
        StackPtr->FileObject = FileObject;

        /* Queue the IRP */
        IopQueueIrpToThread(Irp);

        /* Get the VPB and check if this isn't a direct open */
        Vpb = FileObject->Vpb;
        if ((Vpb) && !(FileObject->Flags & FO_DIRECT_DEVICE_OPEN))
        {
            /* Dereference the VPB before the close */
            InterlockedDecrement((PLONG)&Vpb->ReferenceCount);
        }

        /* Check if the FS will never disappear by itself */
        if (FileObject->DeviceObject->Flags & DO_NEVER_LAST_DEVICE)
        {
            /* Dereference it */
            InterlockedDecrement(&FileObject->DeviceObject->ReferenceCount);
            DereferenceDone = TRUE;
        }

        /* Call the FS Driver */
        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            /* Wait for completion */
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        }

        /* De-queue the IRP */
        KeRaiseIrql(APC_LEVEL, &OldIrql);
        IopUnQueueIrpFromThread(Irp);
        KeLowerIrql(OldIrql);

        /* Free the IRP */
        IoFreeIrp(Irp);

        /* Clear the file name */
        if (FileObject->FileName.Buffer)
        {
            /*
             * Don't use TAG_IO_NAME since the FileObject's FileName
             * may have been re-allocated using a different tag
             * by a filesystem.
             */
            ExFreePoolWithTag(FileObject->FileName.Buffer, 0);
            FileObject->FileName.Buffer = NULL;
        }

        /* Check if the FO had a completion port */
        if (FileObject->CompletionContext)
        {
            /* Free it */
            ObDereferenceObject(FileObject->CompletionContext->Port);
            ExFreePool(FileObject->CompletionContext);
        }

        /* Check if the FO had extension */
        if (FileObject->Flags & FO_FILE_OBJECT_HAS_EXTENSION)
        {
            /* Release filter context structure if any */
            FsRtlPTeardownPerFileObjectContexts(FileObject);
        }

        /* Check if dereference has been done yet */
        if (!DereferenceDone)
        {
            /* Dereference device object */
            IopDereferenceDeviceObject(FileObject->DeviceObject, FALSE);
        }
    }
}

PDEVICE_OBJECT
NTAPI
IopGetDeviceAttachmentBase(IN PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_OBJECT PDO = DeviceObject;

    /* Go down the stack to attempt to get the PDO */
    while (IoGetDevObjExtension(PDO)->AttachedTo != NULL)
        PDO = IoGetDevObjExtension(PDO)->AttachedTo;

    return PDO;
}

PDEVICE_OBJECT
NTAPI
IopGetDevicePDO(IN PDEVICE_OBJECT DeviceObject)
{
    KIRQL OldIrql;
    PDEVICE_OBJECT PDO;

    ASSERT(DeviceObject != NULL);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueIoDatabaseLock);
    /* Get the base DO */
    PDO = IopGetDeviceAttachmentBase(DeviceObject);
    /* Check whether that's really a PDO and if so, keep it */
    if ((PDO->Flags & DO_BUS_ENUMERATED_DEVICE) != DO_BUS_ENUMERATED_DEVICE)
    {
        PDO = NULL;
    }
    else
    {
        ObReferenceObject(PDO);
    }
    KeReleaseQueuedSpinLock(LockQueueIoDatabaseLock, OldIrql);

    return PDO;
}

NTSTATUS
NTAPI
IopSetDeviceSecurityDescriptor(IN PDEVICE_OBJECT DeviceObject,
                               IN PSECURITY_INFORMATION SecurityInformation,
                               IN PSECURITY_DESCRIPTOR SecurityDescriptor,
                               IN POOL_TYPE PoolType,
                               IN PGENERIC_MAPPING GenericMapping)
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR OldSecurityDescriptor, CachedSecurityDescriptor, NewSecurityDescriptor;

    PAGED_CODE();

    /* Keep attempting till we find our old SD or fail */
    while (TRUE)
    {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&IopSecurityResource, TRUE);

        /* Get our old SD and reference it */
        OldSecurityDescriptor = DeviceObject->SecurityDescriptor;
        if (OldSecurityDescriptor != NULL)
        {
            ObReferenceSecurityDescriptor(OldSecurityDescriptor, 1);
        }

        ExReleaseResourceLite(&IopSecurityResource);
        KeLeaveCriticalRegion();

        /* Set the SD information */
        NewSecurityDescriptor = OldSecurityDescriptor;
        Status = SeSetSecurityDescriptorInfo(NULL, SecurityInformation,
                                             SecurityDescriptor, &NewSecurityDescriptor,
                                             PoolType, GenericMapping);

        if (!NT_SUCCESS(Status))
        {
            if (OldSecurityDescriptor != NULL)
            {
                ObDereferenceSecurityDescriptor(OldSecurityDescriptor, 1);
            }

            break;
        }

        /* Add the new DS to the internal cache */
        Status = ObLogSecurityDescriptor(NewSecurityDescriptor,
                                         &CachedSecurityDescriptor, 1);
        ExFreePool(NewSecurityDescriptor);
        if (!NT_SUCCESS(Status))
        {
            ObDereferenceSecurityDescriptor(OldSecurityDescriptor, 1);
            break;
        }

        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&IopSecurityResource, TRUE);
        /* Check if someone changed it in our back */
        if (DeviceObject->SecurityDescriptor == OldSecurityDescriptor)
        {
            /* We're clear, do the swap */
            DeviceObject->SecurityDescriptor = CachedSecurityDescriptor;
            ExReleaseResourceLite(&IopSecurityResource);
            KeLeaveCriticalRegion();

            /* And dereference old SD (twice - us + not in use) */
            ObDereferenceSecurityDescriptor(OldSecurityDescriptor, 2);

            break;
        }
        ExReleaseResourceLite(&IopSecurityResource);
        KeLeaveCriticalRegion();

        /* If so, try again */
        ObDereferenceSecurityDescriptor(OldSecurityDescriptor, 1);
        ObDereferenceSecurityDescriptor(CachedSecurityDescriptor, 1);
    }

    return Status;
}

NTSTATUS
NTAPI
IopSetDeviceSecurityDescriptors(IN PDEVICE_OBJECT UpperDeviceObject,
                                IN PDEVICE_OBJECT PhysicalDeviceObject,
                                IN PSECURITY_INFORMATION SecurityInformation,
                                IN PSECURITY_DESCRIPTOR SecurityDescriptor,
                                IN POOL_TYPE PoolType,
                                IN PGENERIC_MAPPING GenericMapping)
{
    PDEVICE_OBJECT CurrentDO = PhysicalDeviceObject, NextDevice;
    NTSTATUS Status = STATUS_SUCCESS, TmpStatus;

    PAGED_CODE();

    ASSERT(PhysicalDeviceObject != NULL);

    /* We always reference the DO we're working on */
    ObReferenceObject(CurrentDO);

    /* Go up from PDO to latest DO */
    do
    {
        /* Attempt to set the new SD on it */
        TmpStatus = IopSetDeviceSecurityDescriptor(CurrentDO, SecurityInformation,
                                                   SecurityDescriptor, PoolType,
                                                   GenericMapping);
        /* Was our last one? Remember that status then */
        if (CurrentDO == UpperDeviceObject)
        {
            Status = TmpStatus;
        }

        /* Try to move to the next DO (and thus, reference it) */
        NextDevice = CurrentDO->AttachedDevice;
        if (NextDevice)
        {
            ObReferenceObject(NextDevice);
        }

        /* Dereference current DO and move to the next one */
        ObDereferenceObject(CurrentDO);
        CurrentDO = NextDevice;
    }
    while (CurrentDO != NULL);

    return Status;
}

NTSTATUS
NTAPI
IopGetSetSecurityObject(IN PVOID ObjectBody,
                        IN SECURITY_OPERATION_CODE OperationCode,
                        IN PSECURITY_INFORMATION SecurityInformation,
                        IN PSECURITY_DESCRIPTOR SecurityDescriptor,
                        IN OUT PULONG BufferLength,
                        IN OUT PSECURITY_DESCRIPTOR *OldSecurityDescriptor,
                        IN POOL_TYPE PoolType,
                        IN OUT PGENERIC_MAPPING GenericMapping,
                        IN KPROCESSOR_MODE AccessMode)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION StackPtr;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    BOOLEAN LocalEvent = FALSE;
    KEVENT Event;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();
    IOTRACE(IO_FILE_DEBUG, "ObjectBody: %p\n", ObjectBody);

    /* Check if this is a device or file */
    if (((PFILE_OBJECT)ObjectBody)->Type == IO_TYPE_DEVICE)
    {
        /* It's a device */
        DeviceObject = (PDEVICE_OBJECT)ObjectBody;
        FileObject = NULL;
    }
    else
    {
        /* It's a file */
        FileObject = (PFILE_OBJECT)ObjectBody;

        /* Check if this is a direct open */
        if (FileObject->Flags & FO_DIRECT_DEVICE_OPEN)
        {
            /* Get the Device Object */
            DeviceObject = IoGetAttachedDevice(FileObject->DeviceObject);
        }
        else
        {
            /* Otherwise, use the direct device*/
            DeviceObject = FileObject->DeviceObject;
        }
    }

    /* Check if the request was for a device object */
    if (!(FileObject) ||
        (!(FileObject->FileName.Length) && !(FileObject->RelatedFileObject)) ||
        (FileObject->Flags & FO_DIRECT_DEVICE_OPEN))
    {
        /* Check what kind of request this was */
        if (OperationCode == QuerySecurityDescriptor)
        {
            return SeQuerySecurityDescriptorInfo(SecurityInformation,
                                                 SecurityDescriptor,
                                                 BufferLength,
                                                 &DeviceObject->SecurityDescriptor);
        }
        else if (OperationCode == DeleteSecurityDescriptor)
        {
            /* Simply return success */
            return STATUS_SUCCESS;
        }
        else if (OperationCode == AssignSecurityDescriptor)
        {
            Status = STATUS_SUCCESS;

            /* Make absolutely sure this is a device object */
            if (!(FileObject) || !(FileObject->Flags & FO_STREAM_FILE))
            {
                PSECURITY_DESCRIPTOR CachedSecurityDescriptor;

                /* Add the security descriptor in cache */
                Status = ObLogSecurityDescriptor(SecurityDescriptor, &CachedSecurityDescriptor, 1);
                if (NT_SUCCESS(Status))
                {
                    KeEnterCriticalRegion();
                    ExAcquireResourceExclusiveLite(&IopSecurityResource, TRUE);

                    /* Assign the Security Descriptor */
                    DeviceObject->SecurityDescriptor = CachedSecurityDescriptor;

                    ExReleaseResourceLite(&IopSecurityResource);
                    KeLeaveCriticalRegion();
                }
            }

            /* Return status */
            return Status;
        }
        else if (OperationCode == SetSecurityDescriptor)
        {
            /* Get the Physical Device Object if any */
            PDEVICE_OBJECT PDO = IopGetDevicePDO(DeviceObject);

            if (PDO != NULL)
            {
                /* Apply the new SD to any DO in the path from PDO to current DO */
                Status = IopSetDeviceSecurityDescriptors(DeviceObject, PDO,
                                                         SecurityInformation,
                                                         SecurityDescriptor,
                                                         PoolType, GenericMapping);
                ObDereferenceObject(PDO);
            }
            else
            {
                /* Otherwise, just set for ourselves */
                Status = IopSetDeviceSecurityDescriptor(DeviceObject,
                                                        SecurityInformation,
                                                        SecurityDescriptor,
                                                        PoolType, GenericMapping);
            }

            return STATUS_SUCCESS;
        }

        /* Shouldn't happen */
        return STATUS_SUCCESS;
    }
    else if (OperationCode == DeleteSecurityDescriptor)
    {
        /* Same as for devices, do nothing */
        return STATUS_SUCCESS;
    }

    /* At this point, we know we're a file. Reference it */
    ObReferenceObject(FileObject);

    /* Check if we should use Sync IO or not */
    if (FileObject->Flags & FO_SYNCHRONOUS_IO)
    {
        /* Lock the file object */
        Status = IopLockFileObject(FileObject, ExGetPreviousMode());
        if (Status != STATUS_SUCCESS)
        {
            ObDereferenceObject(FileObject);
            return Status;
        }
    }
    else
    {
        /* Use local event */
        KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
        LocalEvent = TRUE;
    }

    /* Clear the File Object event */
    KeClearEvent(&FileObject->Event);

    /* Get the device object */
    DeviceObject = IoGetRelatedDeviceObject(FileObject);

    /* Allocate the IRP */
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp) return IopCleanupFailedIrp(FileObject, NULL, NULL);

    /* Set the IRP */
    Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->RequestorMode = ExGetPreviousMode();
    Irp->UserIosb = &IoStatusBlock;
    Irp->UserEvent = (LocalEvent) ? &Event : NULL;
    Irp->Flags = (LocalEvent) ? IRP_SYNCHRONOUS_API : 0;
    Irp->Overlay.AsynchronousParameters.UserApcRoutine = NULL;

    /* Set Stack Parameters */
    StackPtr = IoGetNextIrpStackLocation(Irp);
    StackPtr->FileObject = FileObject;

    /* Check if this is a query or set */
    if (OperationCode == QuerySecurityDescriptor)
    {
        /* Set the major function and parameters */
        StackPtr->MajorFunction = IRP_MJ_QUERY_SECURITY;
        StackPtr->Parameters.QuerySecurity.SecurityInformation =
            *SecurityInformation;
        StackPtr->Parameters.QuerySecurity.Length = *BufferLength;
        Irp->UserBuffer = SecurityDescriptor;
    }
    else
    {
        /* Set the major function and parameters for a set */
        StackPtr->MajorFunction = IRP_MJ_SET_SECURITY;
        StackPtr->Parameters.SetSecurity.SecurityInformation =
            *SecurityInformation;
        StackPtr->Parameters.SetSecurity.SecurityDescriptor =
            SecurityDescriptor;
    }

    /* Queue the IRP */
    IopQueueIrpToThread(Irp);

    /* Update operation counts */
    IopUpdateOperationCount(IopOtherTransfer);

    /* Call the Driver */
    Status = IoCallDriver(DeviceObject, Irp);

    /* Check if this was async I/O */
    if (LocalEvent)
    {
        /* Check if the IRP is pending completion */
        if (Status == STATUS_PENDING)
        {
            /* Wait on the local event */
            KeWaitForSingleObject(&Event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);
            Status = IoStatusBlock.Status;
        }
    }
    else
    {
        /* Check if the IRP is pending completion */
        if (Status == STATUS_PENDING)
        {
            /* Wait on the file object */
            KeWaitForSingleObject(&FileObject->Event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);
            Status = FileObject->FinalStatus;
        }

        /* Release the lock */
        IopUnlockFileObject(FileObject);
    }

    /* This Driver doesn't implement Security, so try to give it a default */
    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        /* Was this a query? */
        if (OperationCode == QuerySecurityDescriptor)
        {
            /* Set a World Security Descriptor */
            Status = SeSetWorldSecurityDescriptor(*SecurityInformation,
                                                  SecurityDescriptor,
                                                  BufferLength);
        }
        else
        {
            /* It wasn't a query, so just fake success */
            Status = STATUS_SUCCESS;
        }
    }
    else if (OperationCode == QuerySecurityDescriptor)
    {
        /* Callers usually expect the normalized form */
        if (Status == STATUS_BUFFER_OVERFLOW) Status = STATUS_BUFFER_TOO_SMALL;

        _SEH2_TRY
        {
            /* Return length */
            *BufferLength = (ULONG)IoStatusBlock.Information;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get the exception code */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    /* Return Status */
    return Status;
}

NTSTATUS
NTAPI
IopQueryName(IN PVOID ObjectBody,
             IN BOOLEAN HasName,
             OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
             IN ULONG Length,
             OUT PULONG ReturnLength,
             IN KPROCESSOR_MODE PreviousMode)
{
    return IopQueryNameInternal(ObjectBody,
                                HasName,
                                FALSE,
                                ObjectNameInfo,
                                Length,
                                ReturnLength,
                                PreviousMode);
}

NTSTATUS
NTAPI
IopQueryNameInternal(IN PVOID ObjectBody,
                     IN BOOLEAN HasName,
                     IN BOOLEAN QueryDosName,
                     OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
                     IN ULONG Length,
                     OUT PULONG ReturnLength,
                     IN KPROCESSOR_MODE PreviousMode)
{
    POBJECT_NAME_INFORMATION LocalInfo;
    PFILE_NAME_INFORMATION LocalFileInfo;
    PFILE_OBJECT FileObject = (PFILE_OBJECT)ObjectBody;
    ULONG LocalReturnLength, FileLength;
    BOOLEAN LengthMismatch = FALSE;
    NTSTATUS Status;
    PWCHAR p;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN NoObCall;

    IOTRACE(IO_FILE_DEBUG, "ObjectBody: %p\n", ObjectBody);

    /* Validate length */
    if (Length < sizeof(OBJECT_NAME_INFORMATION))
    {
        /* NT6+ reports the full size needed for the name even if the caller
         * could not even fit the OBJECT_NAME_INFORMATION header. Run the query
         * against a scratch header (never the caller's buffer, which may be
         * zero sized) just to learn the required length. */
        if (NtMajorVersion >= 6)
        {
            OBJECT_NAME_INFORMATION ScratchInfo;
            ULONG RequiredLength = 0;

            Status = IopQueryNameInternal(ObjectBody,
                                          HasName,
                                          QueryDosName,
                                          &ScratchInfo,
                                          sizeof(ScratchInfo),
                                          &RequiredLength,
                                          PreviousMode);
            if ((Status == STATUS_BUFFER_OVERFLOW) &&
                (RequiredLength > sizeof(OBJECT_NAME_INFORMATION)))
            {
                *ReturnLength = RequiredLength;
                return STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        /* Wrong length, fail */
        *ReturnLength = sizeof(OBJECT_NAME_INFORMATION);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* Allocate Buffer */
    LocalInfo = ExAllocatePoolWithTag(PagedPool, Length, TAG_IO);
    if (!LocalInfo) return STATUS_INSUFFICIENT_RESOURCES;

    /* Query DOS name if the caller asked to */
    NoObCall = FALSE;
    if (QueryDosName)
    {
        DeviceObject = FileObject->DeviceObject;

        /* In case of a network file system, don't call mountmgr */
        if (DeviceObject->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
        {
            /* We'll store separator and terminator */
            LocalReturnLength = sizeof(OBJECT_NAME_INFORMATION) + 2 * sizeof(WCHAR);
            if (Length < LocalReturnLength)
            {
                Status = STATUS_BUFFER_OVERFLOW;
            }
            else
            {
                LocalInfo->Name.Length = sizeof(WCHAR);
                LocalInfo->Name.MaximumLength = sizeof(WCHAR);
                LocalInfo->Name.Buffer = (PVOID)((ULONG_PTR)LocalInfo + sizeof(OBJECT_NAME_INFORMATION));
                LocalInfo->Name.Buffer[0] = OBJ_NAME_PATH_SEPARATOR;
                Status = STATUS_SUCCESS;
            }
        }
        /* Otherwise, call mountmgr to get DOS name */
        else
        {
            Status = IoVolumeDeviceToDosName(DeviceObject, &LocalInfo->Name);
            LocalReturnLength = LocalInfo->Name.Length + sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
        }
    }

    /* Fall back if querying DOS name failed or if caller never wanted it ;-) */
    if (!QueryDosName || !NT_SUCCESS(Status))
    {
        /* Query the name */
        Status = ObQueryNameString(FileObject->DeviceObject,
                                   LocalInfo,
                                   Length,
                                   &LocalReturnLength);
    }
    else
    {
        NoObCall = TRUE;
    }

    if (!NT_SUCCESS(Status) && (Status != STATUS_INFO_LENGTH_MISMATCH))
    {
        /* Free the buffer and fail */
        ExFreePoolWithTag(LocalInfo, TAG_IO);
        return Status;
    }

    /* Get buffer pointer */
    p = (PWCHAR)(ObjectNameInfo + 1);

    _SEH2_TRY
    {
        /* Copy the information */
        if (QueryDosName && NoObCall)
        {
            ASSERT(PreviousMode == KernelMode);

            /* Copy structure first */
            RtlCopyMemory(ObjectNameInfo,
                          LocalInfo,
                          (Length >= LocalReturnLength ? sizeof(OBJECT_NAME_INFORMATION) : Length));
            /* Name then */
            RtlCopyMemory(p, LocalInfo->Name.Buffer,
                          (Length >= LocalReturnLength ? LocalInfo->Name.Length : Length - sizeof(OBJECT_NAME_INFORMATION)));

            if (FileObject->DeviceObject->DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM)
            {
                ExFreePool(LocalInfo->Name.Buffer);
            }
        }
        else
        {
            RtlCopyMemory(ObjectNameInfo,
                          LocalInfo,
                          (LocalReturnLength > Length) ?
                          Length : LocalReturnLength);
        }

        /* Set buffer pointer */
        ObjectNameInfo->Name.Buffer = p;

        /* Advance in buffer */
        p += (LocalInfo->Name.Length / sizeof(WCHAR));

        /* Check if this already filled our buffer */
        if (LocalReturnLength > Length)
        {
            /* Set the length mismatch to true, so that we can return
             * the proper buffer size to the caller later
             */
            LengthMismatch = TRUE;

            /* Save the initial buffer length value */
            *ReturnLength = LocalReturnLength;
        }

        /* Now get the file name buffer and check the length needed */
        LocalFileInfo = (PFILE_NAME_INFORMATION)LocalInfo;
        FileLength = Length -
                     LocalReturnLength +
                     FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);

        /* Query the File name */
        if (PreviousMode == KernelMode &&
            BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO))
        {
            Status = IopGetFileInformation(FileObject,
                                           LengthMismatch ? Length : FileLength,
                                           FileNameInformation,
                                           LocalFileInfo,
                                           &LocalReturnLength);
        }
        else
        {
            Status = IoQueryFileInformation(FileObject,
                                            FileNameInformation,
                                            LengthMismatch ? Length : FileLength,
                                            LocalFileInfo,
                                            &LocalReturnLength);
        }
        if (NT_ERROR(Status))
        {
            /* Allow status that would mean it's not implemented in the storage stack */
            if (Status != STATUS_INVALID_PARAMETER && Status != STATUS_INVALID_DEVICE_REQUEST &&
                Status != STATUS_NOT_IMPLEMENTED && Status != STATUS_INVALID_INFO_CLASS)
            {
                _SEH2_LEAVE;
            }

            /* In such case, zero the output and reset the status */
            LocalReturnLength = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
            LocalFileInfo->FileNameLength = 0;
            LocalFileInfo->FileName[0] = OBJ_NAME_PATH_SEPARATOR;
            Status = STATUS_SUCCESS;
        }
        else
        {
            /* We'll at least return the name length */
            if (LocalReturnLength < FIELD_OFFSET(FILE_NAME_INFORMATION, FileName))
            {
                LocalReturnLength = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
            }
        }

        /* If the provided buffer is too small, return the required size */
        if (LengthMismatch)
        {
            /* Add the required length */
            *ReturnLength += LocalFileInfo->FileNameLength;

            /* Free the allocated buffer and return failure */
            Status = STATUS_BUFFER_OVERFLOW;
            _SEH2_LEAVE;
        }

        /* Now calculate the new lengths left */
        FileLength = LocalReturnLength -
                     FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
        LocalReturnLength = (ULONG)((ULONG_PTR)p -
                                    (ULONG_PTR)ObjectNameInfo +
                                    LocalFileInfo->FileNameLength);

        /* Don't copy the name if it's not valid */
        if (LocalFileInfo->FileName[0] != OBJ_NAME_PATH_SEPARATOR)
        {
            /* Free the allocated buffer and return failure */
            Status = STATUS_OBJECT_PATH_INVALID;
            _SEH2_LEAVE;
        }

        /* Write the Name and null-terminate it */
        RtlCopyMemory(p, LocalFileInfo->FileName, FileLength);
        p += (FileLength / sizeof(WCHAR));
        *p = UNICODE_NULL;
        LocalReturnLength += sizeof(UNICODE_NULL);

        /* Return the length needed */
        *ReturnLength = LocalReturnLength;

        /* Setup the length and maximum length */
        FileLength = (ULONG)((ULONG_PTR)p - (ULONG_PTR)ObjectNameInfo);
        ObjectNameInfo->Name.Length = (USHORT)FileLength -
                                              sizeof(OBJECT_NAME_INFORMATION);
        ObjectNameInfo->Name.MaximumLength = (USHORT)ObjectNameInfo->Name.Length +
                                                     sizeof(UNICODE_NULL);
    }
    _SEH2_FINALLY
    {
        /* Free buffer and return */
        ExFreePoolWithTag(LocalInfo, TAG_IO);
    } _SEH2_END;

    return Status;
}

static
BOOLEAN
IopThreadHasFileIrps(IN PETHREAD Thread,
                     IN PFILE_OBJECT FileObject,
                     IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                     IN BOOLEAN PortOnly);

/* Does a thread of Process have a request in progress on FileObject? */
static
BOOLEAN
IopProcessHasFileIrps(IN PEPROCESS Process,
                      IN PFILE_OBJECT FileObject)
{
    PETHREAD Thread;

    for (Thread = PsGetNextProcessThread(Process, NULL);
         Thread != NULL;
         Thread = PsGetNextProcessThread(Process, Thread))
    {
        if (IopThreadHasFileIrps(Thread, FileObject, NULL, FALSE))
        {
            ObDereferenceObject(Thread);
            return TRUE;
        }
    }

    return FALSE;
}

static IO_COMPLETION_ROUTINE IopUnlockAllCompletion;

static
NTSTATUS
NTAPI
IopUnlockAllCompletion(IN PDEVICE_OBJECT DeviceObject,
                       IN PIRP Irp,
                       IN PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    /* The sender frees the IRP: no I/O completion, the file object is not touched */
    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * Sends IRP_MN_UNLOCK_ALL for the current process without the file object
 * lock. The request does not go through I/O completion, so it neither waits
 * for nor disturbs a synchronous request in progress on the file object (its
 * event and final status belong to the lock holder).
 */
static
VOID
IopUnlockAllWithoutFileObjectLock(IN PDEVICE_OBJECT DeviceObject,
                                  IN PFILE_OBJECT FileObject)
{
    KEVENT Event;
    PIRP Irp;
    PIO_STACK_LOCATION StackPtr;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IopAllocateIrpMustSucceed(DeviceObject->StackSize);
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->RequestorMode = KernelMode;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;

    StackPtr = IoGetNextIrpStackLocation(Irp);
    StackPtr->MajorFunction = IRP_MJ_LOCK_CONTROL;
    StackPtr->MinorFunction = IRP_MN_UNLOCK_ALL;
    StackPtr->FileObject = FileObject;
    IoSetCompletionRoutine(Irp, IopUnlockAllCompletion, &Event, TRUE, TRUE, TRUE);

    /* The completion routine always runs: wait for it whatever the driver returned */
    (VOID)IoCallDriver(DeviceObject, Irp);
    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    IoFreeIrp(Irp);
}

VOID
NTAPI
IopCloseFile(IN PEPROCESS Process OPTIONAL,
             IN PVOID ObjectBody,
             IN ACCESS_MASK GrantedAccess,
             IN ULONG_PTR HandleCount,
             IN ULONG_PTR SystemHandleCount)
{
    PFILE_OBJECT FileObject = (PFILE_OBJECT)ObjectBody;
    KEVENT Event;
    PIRP Irp;
    PIO_STACK_LOCATION StackPtr;
    NTSTATUS Status;
    PDEVICE_OBJECT DeviceObject;
    KIRQL OldIrql;
    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN LockedForSync;
    IOTRACE(IO_FILE_DEBUG, "ObjectBody: %p\n", ObjectBody);

    /* If this isn't the last handle for the current process, quit */
    if (HandleCount != 1) return;

    /* Check if the file is locked and has more then one handle opened */
    if ((FileObject->LockOperation) && (SystemHandleCount != 1))
    {
        /* Check if this is a direct open or not */
        if (BooleanFlagOn(FileObject->Flags, FO_DIRECT_DEVICE_OPEN))
        {
            /* Get the attached device */
            DeviceObject = IoGetAttachedDevice(FileObject->DeviceObject);
        }
        else
        {
            /* Get the FO's device */
            DeviceObject = IoGetRelatedDeviceObject(FileObject);
        }

        /*
         * Take the lock of a synchronous file object for the unlock-all only
         * when this process has a request in progress on it, i.e. when one of
         * its own threads can be the lock holder. Windows behaves the same
         * way (oracle probe 2026-11-06, kernel32 FileCloseLockedDup): a
         * process without requests on the file object closes its last handle
         * at once and releases its own ranges, even while a (suspended)
         * thread of another process holds the lock inside a synchronous
         * request; a process whose own thread waits inside a request on it
         * waits for that request. Edge's crash reporter suspends the browser
         * and closes duplicates of its handles: it hung here forever.
         */
        LockedForSync = BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO) &&
                        ((Process == NULL) || IopProcessHasFileIrps(Process, FileObject));
        if (LockedForSync)
        {
            (VOID)IopLockFileObject(FileObject, KernelMode);
        }

        /* Go the FastIO path if possible, otherwise fall back to IRP */
        if (DeviceObject->DriverObject->FastIoDispatch == NULL ||
            DeviceObject->DriverObject->FastIoDispatch->FastIoUnlockAll == NULL ||
            !DeviceObject->DriverObject->FastIoDispatch->FastIoUnlockAll(FileObject, PsGetCurrentProcess(), &IoStatusBlock, DeviceObject))
        {
            if (BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO) && !LockedForSync)
            {
                /* The file object's event and status belong to the lock holder */
                IopUnlockAllWithoutFileObjectLock(DeviceObject, FileObject);
                goto UnlockAllDone;
            }

            /* Clear and set up Events */
            KeClearEvent(&FileObject->Event);
            KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

            /* Allocate an IRP */
            Irp = IopAllocateIrpMustSucceed(DeviceObject->StackSize);

            /* Set it up */
            Irp->UserEvent = &Event;
            Irp->UserIosb = &Irp->IoStatus;
            Irp->Tail.Overlay.Thread = PsGetCurrentThread();
            Irp->Tail.Overlay.OriginalFileObject = FileObject;
            Irp->RequestorMode = KernelMode;
            Irp->Flags = IRP_SYNCHRONOUS_API;
            Irp->Overlay.AsynchronousParameters.UserApcRoutine = NULL;
            ObReferenceObject(FileObject);

            /* Set up Stack Pointer Data */
            StackPtr = IoGetNextIrpStackLocation(Irp);
            StackPtr->MajorFunction = IRP_MJ_LOCK_CONTROL;
            StackPtr->MinorFunction = IRP_MN_UNLOCK_ALL;
            StackPtr->FileObject = FileObject;

            /* Queue the IRP */
            IopQueueIrpToThread(Irp);

            /* Call the FS Driver */
            Status = IoCallDriver(DeviceObject, Irp);
            if (Status == STATUS_PENDING)
            {
                /* Wait for completion */
                KeWaitForSingleObject(&Event, UserRequest, KernelMode, FALSE, NULL);
            }

            /* IO will unqueue & free for us */
        }
UnlockAllDone:

        /* Release the lock if we were holding it */
        if (LockedForSync)
        {
            IopUnlockFileObject(FileObject);
        }
    }

    /* Make sure this is the last handle */
    if (SystemHandleCount != 1)
    {
        /*
         * This process closed its last handle but other processes still hold
         * the file object, so no cleanup IRP goes down. Like Windows, cancel
         * the requests of this process whose completion only the completion
         * port would report (no event, no APC routine): nothing in this
         * process could pick them up any more. Requests with an event or an
         * APC, and those of other processes, stay in progress. Completion
         * ports exist only on non-synchronous file objects, so the file
         * object lock is not involved.
         */
        if ((Process != NULL) && (FileObject->CompletionContext != NULL))
        {
            BOOLEAN Found;
            (VOID)IopCancelProcessFileIrps(Process, FileObject, NULL, TRUE, &Found);
        }
        return;
    }

    /* Check if this is a direct open or not */
    if (FileObject->Flags & FO_DIRECT_DEVICE_OPEN)
    {
        /* Get the attached device */
        DeviceObject = IoGetAttachedDevice(FileObject->DeviceObject);
    }
    else
    {
        /* Get the FO's device */
        DeviceObject = IoGetRelatedDeviceObject(FileObject);
    }

    /* Set the handle created flag */
    FileObject->Flags |= FO_HANDLE_CREATED;

    /* Check if this is a sync FO and lock it */
    if (Process != NULL &&
        BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO))
    {
        (VOID)IopLockFileObject(FileObject, KernelMode);
    }

    /* Clear and set up Events */
    KeClearEvent(&FileObject->Event);
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Allocate an IRP */
    Irp = IopAllocateIrpMustSucceed(DeviceObject->StackSize);

    /* Set it up */
    Irp->UserEvent = &Event;
    Irp->UserIosb = &Irp->IoStatus;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->Overlay.AsynchronousParameters.UserApcRoutine = NULL;
    Irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;

    /* Set up Stack Pointer Data */
    StackPtr = IoGetNextIrpStackLocation(Irp);
    StackPtr->MajorFunction = IRP_MJ_CLEANUP;
    StackPtr->FileObject = FileObject;

    /* Queue the IRP */
    IopQueueIrpToThread(Irp);

    /* Update operation counts */
    IopUpdateOperationCount(IopOtherTransfer);

    /* Call the FS Driver */
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        /* Wait for completion */
        KeWaitForSingleObject(&Event, UserRequest, KernelMode, FALSE, NULL);
    }

    /* Unqueue the IRP */
    KeRaiseIrql(APC_LEVEL, &OldIrql);
    IopUnQueueIrpFromThread(Irp);
    KeLowerIrql(OldIrql);

    /* Free the IRP */
    IoFreeIrp(Irp);

    /* Release the lock if we were holding it */
    if (Process != NULL &&
        BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO))
    {
        IopUnlockFileObject(FileObject);
    }
}

NTSTATUS
NTAPI
IopQueryAttributesFile(IN POBJECT_ATTRIBUTES ObjectAttributes,
                       IN FILE_INFORMATION_CLASS FileInformationClass,
                       IN ULONG FileInformationSize,
                       OUT PVOID FileInformation)
{
    NTSTATUS Status;
    KPROCESSOR_MODE AccessMode = ExGetPreviousMode();
    DUMMY_FILE_OBJECT LocalFileObject;
    FILE_NETWORK_OPEN_INFORMATION NetworkOpenInfo;
    HANDLE Handle;
    OPEN_PACKET OpenPacket;
    BOOLEAN IsBasic;
    PAGED_CODE();
    IOTRACE(IO_FILE_DEBUG, "Class: %lx\n", FileInformationClass);

    /* Check if the caller was user mode */
    if (AccessMode != KernelMode)
    {
        /* Protect probe in SEH */
        _SEH2_TRY
        {
            /* Probe the buffer */
            ProbeForWrite(FileInformation, FileInformationSize, sizeof(ULONG));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Check if this is a basic or full request */
    IsBasic = (FileInformationSize == sizeof(FILE_BASIC_INFORMATION));

    /* Setup the Open Packet */
    RtlZeroMemory(&OpenPacket, sizeof(OPEN_PACKET));
    OpenPacket.Type = IO_TYPE_OPEN_PACKET;
    OpenPacket.Size = sizeof(OPEN_PACKET);
    OpenPacket.CreateOptions = FILE_OPEN_REPARSE_POINT;
    OpenPacket.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    OpenPacket.Disposition = FILE_OPEN;
    OpenPacket.BasicInformation = IsBasic ? FileInformation : NULL;
    OpenPacket.NetworkInformation = IsBasic ? &NetworkOpenInfo :
                                    (AccessMode != KernelMode) ?
                                    &NetworkOpenInfo : FileInformation;
    OpenPacket.QueryOnly = TRUE;
    OpenPacket.FullAttributes = IsBasic ? FALSE : TRUE;
    OpenPacket.LocalFileObject = &LocalFileObject;

    /* Update the operation count */
    IopUpdateOperationCount(IopOtherTransfer);

    /*
     * Attempt opening the file. This will call the I/O Parse Routine for
     * the File Object (IopParseDevice) which will use the dummy file obejct
     * send the IRP to its device object. Note that we have two statuses
     * to worry about: the Object Manager's status (in Status) and the I/O
     * status, which is in the Open Packet's Final Status, and determined
     * by the Parse Check member.
     */
    Status = ObOpenObjectByName(ObjectAttributes,
                                NULL,
                                AccessMode,
                                NULL,
                                FILE_READ_ATTRIBUTES,
                                &OpenPacket,
                                &Handle);
    if (OpenPacket.ParseCheck == FALSE)
    {
        /* Check if Ob opened an object that is not a file */
        if (NT_SUCCESS(Status))
        {
            /* Close the handle, the object was not parsed as a file */
            ZwClose(Handle);
            Status = STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* Parse failed */
        DPRINT("IopQueryAttributesFile failed for '%wZ' with 0x%lx\n",
               ObjectAttributes->ObjectName, Status);
        return Status;
    }
    else
    {
        /* Use the Io status */
        Status = OpenPacket.FinalStatus;
    }

    /* Check if we were succesful and this was user mode and a full query */
    if ((NT_SUCCESS(Status)) && (AccessMode != KernelMode) && !(IsBasic))
    {
        /* Enter SEH for copy */
        _SEH2_TRY
        {
            /* Copy the buffer back */
            RtlCopyMemory(FileInformation,
                          &NetworkOpenInfo,
                          FileInformationSize);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get exception code */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
IopAcquireFileObjectLock(
    _In_ PFILE_OBJECT FileObject,
    _In_ KPROCESSOR_MODE WaitMode,
    _In_ BOOLEAN Alertable,
    _Out_ PBOOLEAN LockFailed)
{
    NTSTATUS Status;

    PAGED_CODE();

    InterlockedIncrement((PLONG)&FileObject->Waiters);

    Status = STATUS_SUCCESS;
    do
    {
        if (!InterlockedExchange((PLONG)&FileObject->Busy, TRUE))
        {
            break;
        }
        Status = KeWaitForSingleObject(&FileObject->Lock,
                                       Executive,
                                       WaitMode,
                                       Alertable,
                                       NULL);
    } while (Status == STATUS_SUCCESS);

    InterlockedDecrement((PLONG)&FileObject->Waiters);
    if (Status == STATUS_SUCCESS)
    {
        ObReferenceObject(FileObject);
        *LockFailed = FALSE;
    }
    else
    {
        if (!FileObject->Busy && FileObject->Waiters)
        {
            KeSetEvent(&FileObject->Lock, IO_NO_INCREMENT, FALSE);
        }
        *LockFailed = TRUE;
    }

    return Status;
}

PVOID
NTAPI
IoGetFileObjectFilterContext(IN PFILE_OBJECT FileObject)
{
    if (BooleanFlagOn(FileObject->Flags, FO_FILE_OBJECT_HAS_EXTENSION))
    {
        PFILE_OBJECT_EXTENSION FileObjectExtension;

        FileObjectExtension = FileObject->FileObjectExtension;
        return FileObjectExtension->FilterContext;
    }

    return NULL;
}

NTSTATUS
NTAPI
IoChangeFileObjectFilterContext(IN PFILE_OBJECT FileObject,
                                IN PVOID FilterContext,
                                IN BOOLEAN Define)
{
    ULONG_PTR Success;
    PFILE_OBJECT_EXTENSION FileObjectExtension;

    if (!BooleanFlagOn(FileObject->Flags, FO_FILE_OBJECT_HAS_EXTENSION))
    {
        return STATUS_INVALID_PARAMETER;
    }

    FileObjectExtension = FileObject->FileObjectExtension;
    if (Define)
    {
        /* If define, just set the new value if not value is set
         * Success will only contain old value. It is valid if it is NULL
         */
        Success = (ULONG_PTR)InterlockedCompareExchangePointer(&FileObjectExtension->FilterContext, FilterContext, NULL);
    }
    else
    {
        /* If not define, we want to reset filter context.
         * We will remove value (provided by the caller) and set NULL instead.
         * This will only success if caller provides correct previous value.
         * To catch whether it worked, we substract previous value to expect value:
         * If it matches (and thus, we reset), Success will contain 0
         * Otherwise, it will contain a non-zero value.
         */
        Success = (ULONG_PTR)InterlockedCompareExchangePointer(&FileObjectExtension->FilterContext, NULL, FilterContext) - (ULONG_PTR)FilterContext;
    }

    /* If success isn't 0, it means we failed somewhere (set or unset) */
    if (Success != 0)
    {
        return STATUS_ALREADY_COMMITTED;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopCreateFile(OUT PHANDLE FileHandle,
              IN ACCESS_MASK DesiredAccess,
              IN POBJECT_ATTRIBUTES ObjectAttributes,
              OUT PIO_STATUS_BLOCK IoStatusBlock,
              IN PLARGE_INTEGER AllocationSize OPTIONAL,
              IN ULONG FileAttributes,
              IN ULONG ShareAccess,
              IN ULONG Disposition,
              IN ULONG CreateOptions,
              IN PVOID EaBuffer OPTIONAL,
              IN ULONG EaLength,
              IN CREATE_FILE_TYPE CreateFileType,
              IN PVOID ExtraCreateParameters OPTIONAL,
              IN ULONG Options,
              IN ULONG Flags,
              IN PDEVICE_OBJECT DeviceObject OPTIONAL,
              IN PVOID EcpList OPTIONAL)
{
    KPROCESSOR_MODE AccessMode;
    HANDLE LocalHandle = 0;
    LARGE_INTEGER SafeAllocationSize;
    NTSTATUS Status = STATUS_SUCCESS;
    PNAMED_PIPE_CREATE_PARAMETERS NamedPipeCreateParameters;
    POPEN_PACKET OpenPacket;
    ULONG EaErrorOffset;
    PAGED_CODE();

    IOTRACE(IO_FILE_DEBUG, "FileName: %wZ\n", ObjectAttributes->ObjectName);


    /* Check if we have no parameter checking to do */
    if (Options & IO_NO_PARAMETER_CHECKING)
    {
        /* Then force kernel-mode access to avoid checks */
        AccessMode = KernelMode;
    }
    else
    {
        /* Otherwise, use the actual mode */
        AccessMode = ExGetPreviousMode();
    }

    /* Check if we need to do parameter checking */
    if ((AccessMode != KernelMode) || (Options & IO_CHECK_CREATE_PARAMETERS))
    {
        /* Validate parameters */
        if (FileAttributes & ~FILE_ATTRIBUTE_VALID_FLAGS)
        {
            DPRINT1("File Create 'FileAttributes' Parameter contains invalid flags!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if (ShareAccess & ~FILE_SHARE_VALID_FLAGS)
        {
            DPRINT1("File Create 'ShareAccess' Parameter contains invalid flags!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if (Disposition > FILE_MAXIMUM_DISPOSITION)
        {
            DPRINT1("File Create 'Disposition' Parameter is out of range!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if (CreateOptions & ~FILE_VALID_OPTION_FLAGS)
        {
            DPRINT1("File Create 'CreateOptions' parameter contains invalid flags!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) &&
            (!(DesiredAccess & SYNCHRONIZE)))
        {
            DPRINT1("File Create 'CreateOptions' parameter FILE_SYNCHRONOUS_IO_* requested, but 'DesiredAccess' does not have SYNCHRONIZE!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & FILE_DELETE_ON_CLOSE) && (!(DesiredAccess & DELETE)))
        {
            DPRINT1("File Create 'CreateOptions' parameter FILE_DELETE_ON_CLOSE requested, but 'DesiredAccess' does not have DELETE!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) ==
            (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT))
        {
            DPRINT1("File Create 'FileAttributes' parameter both FILE_SYNCHRONOUS_IO_NONALERT and FILE_SYNCHRONOUS_IO_ALERT specified!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & FILE_DIRECTORY_FILE) && !(CreateOptions & FILE_NON_DIRECTORY_FILE) &&
            (CreateOptions & ~(FILE_DIRECTORY_FILE |
                               FILE_SYNCHRONOUS_IO_ALERT |
                               FILE_SYNCHRONOUS_IO_NONALERT |
                               FILE_WRITE_THROUGH |
                               FILE_COMPLETE_IF_OPLOCKED |
                               FILE_OPEN_FOR_BACKUP_INTENT |
                               FILE_DELETE_ON_CLOSE |
                               FILE_OPEN_FOR_FREE_SPACE_QUERY |
                               FILE_OPEN_BY_FILE_ID |
                               FILE_NO_COMPRESSION |
                               FILE_OPEN_REPARSE_POINT)))
        {
            DPRINT1("File Create 'CreateOptions' Parameter has flags incompatible with FILE_DIRECTORY_FILE!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & FILE_DIRECTORY_FILE) && !(CreateOptions & FILE_NON_DIRECTORY_FILE) &&
            (Disposition != FILE_CREATE) && (Disposition != FILE_OPEN) && (Disposition != FILE_OPEN_IF))
        {
            DPRINT1("File Create 'CreateOptions' Parameter FILE_DIRECTORY_FILE requested, but 'Disposition' is not FILE_CREATE/FILE_OPEN/FILE_OPEN_IF!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & FILE_COMPLETE_IF_OPLOCKED) && (CreateOptions & FILE_RESERVE_OPFILTER))
        {
            DPRINT1("File Create 'CreateOptions' Parameter both FILE_COMPLETE_IF_OPLOCKED and FILE_RESERVE_OPFILTER specified!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING) && (DesiredAccess & FILE_APPEND_DATA))
        {
            DPRINT1("File Create 'CreateOptions' parameter FILE_NO_INTERMEDIATE_BUFFERING requested, but 'DesiredAccess' FILE_APPEND_DATA requires it!\n");
            return STATUS_INVALID_PARAMETER;
        }

        /* Now check if this is a named pipe */
        if (CreateFileType == CreateFileTypeNamedPipe)
        {
            /* Make sure we have extra parameters */
            if (!ExtraCreateParameters)
            {
                DPRINT1("Invalid parameter: ExtraCreateParameters == 0!\n");
                return STATUS_INVALID_PARAMETER;
            }

            /* Get the parameters and validate them */
            NamedPipeCreateParameters = ExtraCreateParameters;
            if ((NamedPipeCreateParameters->NamedPipeType > FILE_PIPE_MESSAGE_TYPE) ||
                (NamedPipeCreateParameters->ReadMode > FILE_PIPE_MESSAGE_MODE) ||
                (NamedPipeCreateParameters->CompletionMode > FILE_PIPE_COMPLETE_OPERATION) ||
                (ShareAccess & FILE_SHARE_DELETE) ||
                ((Disposition < FILE_OPEN) || (Disposition > FILE_OPEN_IF)) ||
                (CreateOptions & ~FILE_VALID_PIPE_OPTION_FLAGS))
            {
                /* Invalid named pipe create */
                DPRINT1("Invalid named pipe create\n");
                return STATUS_INVALID_PARAMETER;
            }
        }
        else if (CreateFileType == CreateFileTypeMailslot)
        {
            /* Make sure we have extra parameters */
            if (!ExtraCreateParameters)
            {
                DPRINT1("Invalid parameter: ExtraCreateParameters == 0!\n");
                return STATUS_INVALID_PARAMETER;
            }

            /* Get the parameters and validate them */
            if ((ShareAccess & FILE_SHARE_DELETE) ||
                !(ShareAccess & ~FILE_SHARE_WRITE) ||
                (Disposition != FILE_CREATE) ||
                (CreateOptions & ~FILE_VALID_MAILSLOT_OPTION_FLAGS))
            {
                /* Invalid mailslot create */
                DPRINT1("Invalid mailslot create\n");
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    /* Allocate the open packet */
    OpenPacket = ExAllocatePoolWithTag(NonPagedPool, sizeof(*OpenPacket), 'pOoI');
    if (!OpenPacket) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(OpenPacket, sizeof(*OpenPacket));

    /* Check if the call came from user mode */
    if (AccessMode != KernelMode)
    {
        _SEH2_TRY
        {
            /* Probe the output parameters */
            ProbeForWriteHandle(FileHandle);
            ProbeForWriteIoStatusBlock(IoStatusBlock);

            /* Probe the allocation size if one was passed in */
            if (AllocationSize)
            {
                SafeAllocationSize = ProbeForReadLargeInteger(AllocationSize);
            }
            else
            {
                SafeAllocationSize.QuadPart = 0;
            }

            /* Make sure it's valid */
            if (SafeAllocationSize.QuadPart < 0)
            {
                RtlRaiseStatus(STATUS_INVALID_PARAMETER);
            }

            /* Check if EA was passed in */
            if ((EaBuffer) && (EaLength))
            {
                /* Probe it */
                ProbeForRead(EaBuffer, EaLength, sizeof(ULONG));

                /* And marshall it */
                OpenPacket->EaBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                             EaLength,
                                                             TAG_EA);
                OpenPacket->EaLength = EaLength;
                RtlCopyMemory(OpenPacket->EaBuffer, EaBuffer, EaLength);

                /* Validate the buffer */
                Status = IoCheckEaBufferValidity(OpenPacket->EaBuffer,
                                                 EaLength,
                                                 &EaErrorOffset);
                if (!NT_SUCCESS(Status))
                {
                    /* Undo everything if it's invalid */
                    DPRINT1("Invalid EA buffer\n");
                    IoStatusBlock->Status = Status;
                    IoStatusBlock->Information = EaErrorOffset;
                    RtlRaiseStatus(Status);
                }
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            if (OpenPacket->EaBuffer != NULL) ExFreePool(OpenPacket->EaBuffer);
            ExFreePool(OpenPacket);
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Check if this is a device attach */
        if (CreateOptions & IO_ATTACH_DEVICE_API)
        {
            /* Set the flag properly */
            Options |= IO_ATTACH_DEVICE;
            CreateOptions &= ~IO_ATTACH_DEVICE_API;
        }

        /* Check if we have allocation size */
        if (AllocationSize)
        {
            /* Capture it */
            SafeAllocationSize = *AllocationSize;
        }
        else
        {
            /* Otherwise, no size */
            SafeAllocationSize.QuadPart = 0;
        }

        /* Check if we have an EA packet */
        if ((EaBuffer) && (EaLength))
        {
            /* Allocate the kernel copy */
            OpenPacket->EaBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                         EaLength,
                                                         TAG_EA);
            if (!OpenPacket->EaBuffer)
            {
                ExFreePool(OpenPacket);
                DPRINT1("Failed to allocate open packet EA buffer\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* Copy the data */
            OpenPacket->EaLength = EaLength;
            RtlCopyMemory(OpenPacket->EaBuffer, EaBuffer, EaLength);

            /* Validate the buffer */
            Status = IoCheckEaBufferValidity(OpenPacket->EaBuffer,
                                             EaLength,
                                             &EaErrorOffset);
            if (!NT_SUCCESS(Status))
            {
                /* Undo everything if it's invalid */
                DPRINT1("Invalid EA buffer\n");
                ExFreePool(OpenPacket->EaBuffer);
                IoStatusBlock->Status = Status;
                IoStatusBlock->Information = EaErrorOffset;
                ExFreePool(OpenPacket);
                return Status;
            }
        }
    }

    /* Setup the Open Packet */
    OpenPacket->Type = IO_TYPE_OPEN_PACKET;
    OpenPacket->Size = sizeof(*OpenPacket);
    OpenPacket->AllocationSize = SafeAllocationSize;
    OpenPacket->CreateOptions = CreateOptions;
    OpenPacket->FileAttributes = (USHORT)FileAttributes;
    OpenPacket->ShareAccess = (USHORT)ShareAccess;
    OpenPacket->Options = Options;
    OpenPacket->Disposition = Disposition;
    OpenPacket->CreateFileType = CreateFileType;
    OpenPacket->ExtraCreateParameters = ExtraCreateParameters;
    OpenPacket->InternalFlags = Flags;
    OpenPacket->TopDeviceObjectHint = DeviceObject;
    OpenPacket->EcpList = EcpList;

    /* Update the operation count */
    IopUpdateOperationCount(IopOtherTransfer);

    /*
     * Attempt opening the file. This will call the I/O Parse Routine for
     * the File Object (IopParseDevice) which will create the object and
     * send the IRP to its device object. Note that we have two statuses
     * to worry about: the Object Manager's status (in Status) and the I/O
     * status, which is in the Open Packet's Final Status, and determined
     * by the Parse Check member.
     */
    Status = ObOpenObjectByName(ObjectAttributes,
                                NULL,
                                AccessMode,
                                NULL,
                                DesiredAccess,
                                OpenPacket,
                                &LocalHandle);

    /* Free the EA Buffer */
    if (OpenPacket->EaBuffer) ExFreePool(OpenPacket->EaBuffer);

    /* Now check for Ob or Io failure */
    if (!(NT_SUCCESS(Status)) || (OpenPacket->ParseCheck == FALSE))
    {
        /* Check if Ob thinks well went well */
        if (NT_SUCCESS(Status))
        {
            /*
             * Tell it otherwise. Because we didn't use an ObjectType,
             * it incorrectly returned us a handle to God knows what.
             */
            ZwClose(LocalHandle);
            Status = STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* Now check the Io status */
        if (!NT_SUCCESS(OpenPacket->FinalStatus))
        {
            /* Use this status instead of Ob's */
            Status = OpenPacket->FinalStatus;

            /* Check if it was only a warning */
            if (NT_WARNING(Status))
            {
                /* Protect write with SEH */
                _SEH2_TRY
                {
                    /* In this case, we copy the I/O Status back */
                    IoStatusBlock->Information = OpenPacket->Information;
                    IoStatusBlock->Status = OpenPacket->FinalStatus;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    /* Get exception code */
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
        }
        else if ((OpenPacket->FileObject) && (OpenPacket->ParseCheck == FALSE))
        {
            /*
             * This can happen in the very bizarre case where the parse routine
             * actually executed more then once (due to a reparse) and ended
             * up failing after already having created the File Object.
             */
            if (OpenPacket->FileObject->FileName.Length)
            {
                /* It had a name, free it */
                ExFreePoolWithTag(OpenPacket->FileObject->FileName.Buffer, TAG_IO_NAME);
            }

            /* Clear the device object to invalidate the FO, and dereference */
            OpenPacket->FileObject->DeviceObject = NULL;
            ObDereferenceObject(OpenPacket->FileObject);
        }
    }
    else
    {
        /* We reached success and have a valid file handle */
        OpenPacket->FileObject->Flags |= FO_HANDLE_CREATED;
        ASSERT(OpenPacket->FileObject->Type == IO_TYPE_FILE);

        /* Enter SEH for write back */
        _SEH2_TRY
        {
            /* Write back the handle and I/O Status */
            *FileHandle = LocalHandle;
            IoStatusBlock->Information = OpenPacket->Information;
            IoStatusBlock->Status = OpenPacket->FinalStatus;

            /* Get the Io status */
            Status = OpenPacket->FinalStatus;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get the exception status */
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }

    /* Check if we were 100% successful */
    if ((OpenPacket->ParseCheck != FALSE) && (OpenPacket->FileObject))
    {
        /* Dereference the File Object */
        ObDereferenceObject(OpenPacket->FileObject);
    }

    /* Return status */
    ExFreePool(OpenPacket);
    return Status;
}

/* FUNCTIONS *****************************************************************/

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
IoCheckQuerySetFileInformation(IN FILE_INFORMATION_CLASS FileInformationClass,
                               IN ULONG Length,
                               IN BOOLEAN SetOperation)
{
    NTOS_STUB_HIT();
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
IoCheckQuotaBufferValidity(IN PFILE_QUOTA_INFORMATION QuotaBuffer,
                           IN ULONG QuotaLength,
                           OUT PULONG ErrorOffset)
{
    NTOS_STUB_HIT();
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoCreateFile(OUT PHANDLE FileHandle,
             IN ACCESS_MASK DesiredAccess,
             IN POBJECT_ATTRIBUTES ObjectAttributes,
             OUT PIO_STATUS_BLOCK IoStatusBlock,
             IN PLARGE_INTEGER AllocationSize OPTIONAL,
             IN ULONG FileAttributes,
             IN ULONG ShareAccess,
             IN ULONG Disposition,
             IN ULONG CreateOptions,
             IN PVOID EaBuffer OPTIONAL,
             IN ULONG EaLength,
             IN CREATE_FILE_TYPE CreateFileType,
             IN PVOID ExtraCreateParameters OPTIONAL,
             IN ULONG Options)
{
    PAGED_CODE();

    return IopCreateFile(FileHandle,
                         DesiredAccess,
                         ObjectAttributes,
                         IoStatusBlock,
                         AllocationSize,
                         FileAttributes,
                         ShareAccess,
                         Disposition,
                         CreateOptions,
                         EaBuffer,
                         EaLength,
                         CreateFileType,
                         ExtraCreateParameters,
                         Options,
                         0,
                         NULL,
                         NULL);
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
IoCreateFileSpecifyDeviceObjectHint(OUT PHANDLE FileHandle,
                                    IN ACCESS_MASK DesiredAccess,
                                    IN POBJECT_ATTRIBUTES ObjectAttributes,
                                    OUT PIO_STATUS_BLOCK IoStatusBlock,
                                    IN PLARGE_INTEGER AllocationSize OPTIONAL,
                                    IN ULONG FileAttributes,
                                    IN ULONG ShareAccess,
                                    IN ULONG Disposition,
                                    IN ULONG CreateOptions,
                                    IN PVOID EaBuffer OPTIONAL,
                                    IN ULONG EaLength,
                                    IN CREATE_FILE_TYPE CreateFileType,
                                    IN PVOID ExtraCreateParameters OPTIONAL,
                                    IN ULONG Options,
                                    IN PVOID DeviceObject)
{
    ULONG Flags = 0;

    PAGED_CODE();

    /* Check if we were passed a device to send the create request to*/
    if (DeviceObject)
    {
        /* We'll tag this request into a file object extension */
        Flags = (IOP_CREATE_FILE_OBJECT_EXTENSION | IOP_USE_TOP_LEVEL_DEVICE_HINT);
    }

    return IopCreateFile(FileHandle,
                         DesiredAccess,
                         ObjectAttributes,
                         IoStatusBlock,
                         AllocationSize,
                         FileAttributes,
                         ShareAccess,
                         Disposition,
                         CreateOptions,
                         EaBuffer,
                         EaLength,
                         CreateFileType,
                         ExtraCreateParameters,
                         Options | IO_NO_PARAMETER_CHECKING,
                         Flags,
                         DeviceObject,
                         NULL);
}

/*
 * Honours the device object hint and the extra create parameters (ECP list) of the
 * driver context: the list is delivered to the file system in the create IRP and
 * read there with FsRtlGetEcpListFromIrp.
 *
 * @implemented
 */
NTSTATUS
NTAPI
IoCreateFileEx(OUT PHANDLE FileHandle,
               IN ACCESS_MASK DesiredAccess,
               IN POBJECT_ATTRIBUTES ObjectAttributes,
               OUT PIO_STATUS_BLOCK IoStatusBlock,
               IN PLARGE_INTEGER AllocationSize OPTIONAL,
               IN ULONG FileAttributes,
               IN ULONG ShareAccess,
               IN ULONG Disposition,
               IN ULONG CreateOptions,
               IN PVOID EaBuffer OPTIONAL,
               IN ULONG EaLength,
               IN CREATE_FILE_TYPE CreateFileType,
               IN PVOID ExtraCreateParameters OPTIONAL,
               IN ULONG Options,
               IN PIO_DRIVER_CREATE_CONTEXT DriverContext OPTIONAL)
{
    PDEVICE_OBJECT DeviceObject = NULL;
    PVOID EcpList = NULL;
    ULONG Flags = 0;

    PAGED_CODE();

    if (DriverContext != NULL && DriverContext->Size >= sizeof(*DriverContext))
    {
        DeviceObject = DriverContext->DeviceObjectHint;
        EcpList = DriverContext->ExtraCreateParameter;
    }

    /* A device object hint is tagged into a file object extension, like in
     * IoCreateFileSpecifyDeviceObjectHint, which also forces kernel mode */
    if (DeviceObject != NULL)
    {
        Flags = (IOP_CREATE_FILE_OBJECT_EXTENSION | IOP_USE_TOP_LEVEL_DEVICE_HINT);
        Options |= IO_NO_PARAMETER_CHECKING;
    }

    return IopCreateFile(FileHandle,
                         DesiredAccess,
                         ObjectAttributes,
                         IoStatusBlock,
                         AllocationSize,
                         FileAttributes,
                         ShareAccess,
                         Disposition,
                         CreateOptions,
                         EaBuffer,
                         EaLength,
                         CreateFileType,
                         ExtraCreateParameters,
                         Options,
                         Flags,
                         DeviceObject,
                         EcpList);
}

/*
 * @implemented
 */
PFILE_OBJECT
NTAPI
IoCreateStreamFileObjectEx(IN PFILE_OBJECT FileObject OPTIONAL,
                           IN PDEVICE_OBJECT DeviceObject OPTIONAL,
                           OUT PHANDLE FileObjectHandle OPTIONAL)
{
    PFILE_OBJECT CreatedFileObject;
    NTSTATUS Status;
    HANDLE FileHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PAGED_CODE();
    IOTRACE(IO_FILE_DEBUG, "FileObject: %p\n", FileObject);

    /* Choose Device Object */
    if (FileObject) DeviceObject = FileObject->DeviceObject;

    /* Reference the device object and initialize attributes */
    InterlockedIncrement(&DeviceObject->ReferenceCount);
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    /* Create the File Object */
    Status = ObCreateObject(KernelMode,
                            IoFileObjectType,
                            &ObjectAttributes,
                            KernelMode,
                            NULL,
                            sizeof(FILE_OBJECT),
                            sizeof(FILE_OBJECT),
                            0,
                            (PVOID*)&CreatedFileObject);
    if (!NT_SUCCESS(Status))
    {
        /* Fail */
        IopDereferenceDeviceObject(DeviceObject, FALSE);
        ExRaiseStatus(Status);
    }

    /* Set File Object Data */
    RtlZeroMemory(CreatedFileObject, sizeof(FILE_OBJECT));
    CreatedFileObject->DeviceObject = DeviceObject;
    CreatedFileObject->Type = IO_TYPE_FILE;
    CreatedFileObject->Size = sizeof(FILE_OBJECT);
    CreatedFileObject->Flags = FO_STREAM_FILE;

    /* Initialize the wait event */
    KeInitializeEvent(&CreatedFileObject->Event, SynchronizationEvent, FALSE);

    /* Insert it to create a handle for it */
    Status = ObInsertObject(CreatedFileObject,
                            NULL,
                            FILE_READ_DATA,
                            1,
                            (PVOID*)&CreatedFileObject,
                            &FileHandle);
    if (!NT_SUCCESS(Status)) ExRaiseStatus(Status);

    /* Set the handle created flag */
    CreatedFileObject->Flags |= FO_HANDLE_CREATED;
    ASSERT(CreatedFileObject->Type == IO_TYPE_FILE);

    /* Check if we have a VPB */
    if (DeviceObject->Vpb)
    {
        /* Reference it */
         InterlockedIncrement((PLONG)&DeviceObject->Vpb->ReferenceCount);
    }

    /* Check if the caller wants the handle */
    if (FileObjectHandle)
    {
        /* Return it */
        *FileObjectHandle = FileHandle;
        ObDereferenceObject(CreatedFileObject);
    }
    else
    {
        /* Otherwise, close it */
        ObCloseHandle(FileHandle, KernelMode);
    }

    /* Return the file object */
    return CreatedFileObject;
}

/*
 * @implemented
 */
PFILE_OBJECT
NTAPI
IoCreateStreamFileObject(IN PFILE_OBJECT FileObject,
                         IN PDEVICE_OBJECT DeviceObject)
{
    /* Call the newer function */
    return IoCreateStreamFileObjectEx(FileObject, DeviceObject, NULL);
}

/*
 * @implemented
 */
PFILE_OBJECT
NTAPI
IoCreateStreamFileObjectLite(IN PFILE_OBJECT FileObject OPTIONAL,
                             IN PDEVICE_OBJECT DeviceObject OPTIONAL)
{
    PFILE_OBJECT CreatedFileObject;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PAGED_CODE();
    IOTRACE(IO_FILE_DEBUG, "FileObject: %p\n", FileObject);

    /* Choose Device Object */
    if (FileObject) DeviceObject = FileObject->DeviceObject;

    /* Reference the device object and initialize attributes */
    InterlockedIncrement(&DeviceObject->ReferenceCount);
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    /* Create the File Object */
    Status = ObCreateObject(KernelMode,
                            IoFileObjectType,
                            &ObjectAttributes,
                            KernelMode,
                            NULL,
                            sizeof(FILE_OBJECT),
                            sizeof(FILE_OBJECT),
                            0,
                            (PVOID*)&CreatedFileObject);
    if (!NT_SUCCESS(Status))
    {
        /* Fail */
        IopDereferenceDeviceObject(DeviceObject, FALSE);
        ExRaiseStatus(Status);
    }

    /* Set File Object Data */
    RtlZeroMemory(CreatedFileObject, sizeof(FILE_OBJECT));
    CreatedFileObject->DeviceObject = DeviceObject;
    CreatedFileObject->Type = IO_TYPE_FILE;
    CreatedFileObject->Size = sizeof(FILE_OBJECT);
    CreatedFileObject->Flags = FO_STREAM_FILE;

    /* Initialize the wait event */
    KeInitializeEvent(&CreatedFileObject->Event, SynchronizationEvent, FALSE);

    /* Destroy create information */
    ObFreeObjectCreateInfoBuffer(OBJECT_TO_OBJECT_HEADER(CreatedFileObject)->
                                 ObjectCreateInfo);
    OBJECT_TO_OBJECT_HEADER(CreatedFileObject)->ObjectCreateInfo = NULL;

    /* Set the handle created flag */
    CreatedFileObject->Flags |= FO_HANDLE_CREATED;
    ASSERT(CreatedFileObject->Type == IO_TYPE_FILE);

    /* Check if we have a VPB */
    if (DeviceObject->Vpb)
    {
        /* Reference it */
         InterlockedIncrement((PLONG)&DeviceObject->Vpb->ReferenceCount);
    }

    /* Return the file object */
    return CreatedFileObject;
}

/*
 * @implemented
 */
PGENERIC_MAPPING
NTAPI
IoGetFileObjectGenericMapping(VOID)
{
    /* Return the mapping */
    return &IopFileMapping;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
IoIsFileOriginRemote(IN PFILE_OBJECT FileObject)
{
    /* Return the flag status */
    return FileObject->Flags & FO_REMOTE_ORIGIN ? TRUE : FALSE;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
IoFastQueryNetworkAttributes(IN POBJECT_ATTRIBUTES ObjectAttributes,
                             IN ACCESS_MASK DesiredAccess,
                             IN ULONG OpenOptions,
                             OUT PIO_STATUS_BLOCK IoStatus,
                             OUT PFILE_NETWORK_OPEN_INFORMATION Buffer)
{
    NTSTATUS Status;
    DUMMY_FILE_OBJECT LocalFileObject;
    HANDLE Handle;
    OPEN_PACKET OpenPacket;
    PAGED_CODE();
    IOTRACE(IO_FILE_DEBUG, "FileName: %wZ\n", ObjectAttributes->ObjectName);

    /* Setup the Open Packet */
    RtlZeroMemory(&OpenPacket, sizeof(OPEN_PACKET));
    OpenPacket.Type = IO_TYPE_OPEN_PACKET;
    OpenPacket.Size = sizeof(OPEN_PACKET);
    OpenPacket.CreateOptions = OpenOptions | FILE_OPEN_REPARSE_POINT;
    OpenPacket.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    OpenPacket.Options = IO_FORCE_ACCESS_CHECK;
    OpenPacket.Disposition = FILE_OPEN;
    OpenPacket.NetworkInformation = Buffer;
    OpenPacket.QueryOnly = TRUE;
    OpenPacket.FullAttributes = TRUE;
    OpenPacket.LocalFileObject = &LocalFileObject;

    /*
     * Attempt opening the file. This will call the I/O Parse Routine for
     * the File Object (IopParseDevice) which will use the dummy file obejct
     * send the IRP to its device object. Note that we have two statuses
     * to worry about: the Object Manager's status (in Status) and the I/O
     * status, which is in the Open Packet's Final Status, and determined
     * by the Parse Check member.
     */
    Status = ObOpenObjectByName(ObjectAttributes,
                                NULL,
                                KernelMode,
                                NULL,
                                DesiredAccess,
                                &OpenPacket,
                                &Handle);
    if (OpenPacket.ParseCheck == FALSE)
    {
        /* Check if Ob opened an object that is not a file */
        if (NT_SUCCESS(Status))
        {
            /* Close the handle, the object was not parsed as a file */
            ZwClose(Handle);
            Status = STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* Parse failed */
        IoStatus->Status = Status;
    }
    else
    {
        /* Use the Io status */
        IoStatus->Status = OpenPacket.FinalStatus;
        IoStatus->Information = OpenPacket.Information;
    }

    /* Return success */
    return TRUE;
}

/*
 * @implemented
 */
VOID
NTAPI
IoUpdateShareAccess(IN PFILE_OBJECT FileObject,
                    OUT PSHARE_ACCESS ShareAccess)
{
    PAGED_CODE();

    /* Check if the file has an extension */
    if (FileObject->Flags & FO_FILE_OBJECT_HAS_EXTENSION)
    {
        /* Check if caller specified to ignore access checks */
        //if (FileObject->FoExtFlags & IO_IGNORE_SHARE_ACCESS_CHECK)
        {
            /* Don't update share access */
            return;
        }
    }

    /* Otherwise, check if there's any access present */
    if ((FileObject->ReadAccess) ||
        (FileObject->WriteAccess) ||
        (FileObject->DeleteAccess))
    {
        /* Increase the open count */
        ShareAccess->OpenCount++;

        /* Add new share access */
        ShareAccess->Readers += FileObject->ReadAccess;
        ShareAccess->Writers += FileObject->WriteAccess;
        ShareAccess->Deleters += FileObject->DeleteAccess;
        ShareAccess->SharedRead += FileObject->SharedRead;
        ShareAccess->SharedWrite += FileObject->SharedWrite;
        ShareAccess->SharedDelete += FileObject->SharedDelete;
    }
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoCheckShareAccess(IN ACCESS_MASK DesiredAccess,
                   IN ULONG DesiredShareAccess,
                   IN PFILE_OBJECT FileObject,
                   IN PSHARE_ACCESS ShareAccess,
                   IN BOOLEAN Update)
{
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    PAGED_CODE();

    /* Get access masks */
    ReadAccess = (DesiredAccess & (FILE_READ_DATA | FILE_EXECUTE)) != 0;
    WriteAccess = (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    DeleteAccess = (DesiredAccess & DELETE) != 0;

    /* Set them in the file object */
    FileObject->ReadAccess = ReadAccess;
    FileObject->WriteAccess = WriteAccess;
    FileObject->DeleteAccess = DeleteAccess;

    /* Check if the file has an extension */
    if (FileObject->Flags & FO_FILE_OBJECT_HAS_EXTENSION)
    {
        /* Check if caller specified to ignore access checks */
        //if (FileObject->FoExtFlags & IO_IGNORE_SHARE_ACCESS_CHECK)
        {
            /* Don't check share access */
            return STATUS_SUCCESS;
        }
    }

    /* Check if we have any access */
    if ((ReadAccess) || (WriteAccess) || (DeleteAccess))
    {
        /* Get shared access masks */
        SharedRead = (DesiredShareAccess & FILE_SHARE_READ) != 0;
        SharedWrite = (DesiredShareAccess & FILE_SHARE_WRITE) != 0;
        SharedDelete = (DesiredShareAccess & FILE_SHARE_DELETE) != 0;

        /* Check if the shared access is violated */
        if ((ReadAccess &&
             (ShareAccess->SharedRead < ShareAccess->OpenCount)) ||
            (WriteAccess &&
             (ShareAccess->SharedWrite < ShareAccess->OpenCount)) ||
            (DeleteAccess &&
             (ShareAccess->SharedDelete < ShareAccess->OpenCount)) ||
            ((ShareAccess->Readers != 0) && !SharedRead) ||
            ((ShareAccess->Writers != 0) && !SharedWrite) ||
            ((ShareAccess->Deleters != 0) && !SharedDelete))
        {
            /* Sharing violation, fail */
            return STATUS_SHARING_VIOLATION;
        }

        /* Set them */
        FileObject->SharedRead = SharedRead;
        FileObject->SharedWrite = SharedWrite;
        FileObject->SharedDelete = SharedDelete;

        /* It's not, check if caller wants us to update it */
        if (Update)
        {
            /* Increase open count */
            ShareAccess->OpenCount++;

            /* Update shared access */
            ShareAccess->Readers += ReadAccess;
            ShareAccess->Writers += WriteAccess;
            ShareAccess->Deleters += DeleteAccess;
            ShareAccess->SharedRead += SharedRead;
            ShareAccess->SharedWrite += SharedWrite;
            ShareAccess->SharedDelete += SharedDelete;
        }
    }

    /* Validation successful */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
VOID
NTAPI
IoRemoveShareAccess(IN PFILE_OBJECT FileObject,
                    IN PSHARE_ACCESS ShareAccess)
{
    PAGED_CODE();

    /* Check if the file has an extension */
    if (FileObject->Flags & FO_FILE_OBJECT_HAS_EXTENSION)
    {
        /* Check if caller specified to ignore access checks */
        //if (FileObject->FoExtFlags & IO_IGNORE_SHARE_ACCESS_CHECK)
        {
            /* Don't update share access */
            return;
        }
    }

    /* Otherwise, check if there's any access present */
    if ((FileObject->ReadAccess) ||
        (FileObject->WriteAccess) ||
        (FileObject->DeleteAccess))
    {
        /* Decrement the open count */
        ShareAccess->OpenCount--;

        /* Remove share access */
        ShareAccess->Readers -= FileObject->ReadAccess;
        ShareAccess->Writers -= FileObject->WriteAccess;
        ShareAccess->Deleters -= FileObject->DeleteAccess;
        ShareAccess->SharedRead -= FileObject->SharedRead;
        ShareAccess->SharedWrite -= FileObject->SharedWrite;
        ShareAccess->SharedDelete -= FileObject->SharedDelete;
    }
}

/*
 * @implemented
 */
VOID
NTAPI
IoSetShareAccess(IN ACCESS_MASK DesiredAccess,
                 IN ULONG DesiredShareAccess,
                 IN PFILE_OBJECT FileObject,
                 OUT PSHARE_ACCESS ShareAccess)
{
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    BOOLEAN Update = TRUE;
    PAGED_CODE();

    ReadAccess = (DesiredAccess & (FILE_READ_DATA | FILE_EXECUTE)) != 0;
    WriteAccess = (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    DeleteAccess = (DesiredAccess & DELETE) != 0;

    /* Check if the file has an extension */
    if (FileObject->Flags & FO_FILE_OBJECT_HAS_EXTENSION)
    {
        /* Check if caller specified to ignore access checks */
        //if (FileObject->FoExtFlags & IO_IGNORE_SHARE_ACCESS_CHECK)
        {
            /* Don't update share access */
            Update = FALSE;
        }
    }

    /* Update basic access */
    FileObject->ReadAccess = ReadAccess;
    FileObject->WriteAccess = WriteAccess;
    FileObject->DeleteAccess = DeleteAccess;

    /* Check if we have no access as all */
    if (!(ReadAccess) && !(WriteAccess) && !(DeleteAccess))
    {
        /* Check if we need to update the structure */
        if (!Update) return;

        /* Otherwise, clear data */
        ShareAccess->OpenCount = 0;
        ShareAccess->Readers = 0;
        ShareAccess->Writers = 0;
        ShareAccess->Deleters = 0;
        ShareAccess->SharedRead = 0;
        ShareAccess->SharedWrite = 0;
        ShareAccess->SharedDelete = 0;
    }
    else
    {
        /* Calculate shared access */
        SharedRead = (DesiredShareAccess & FILE_SHARE_READ) != 0;
        SharedWrite = (DesiredShareAccess & FILE_SHARE_WRITE) != 0;
        SharedDelete = (DesiredShareAccess & FILE_SHARE_DELETE) != 0;

        /* Set it in the FO */
        FileObject->SharedRead = SharedRead;
        FileObject->SharedWrite = SharedWrite;
        FileObject->SharedDelete = SharedDelete;

        /* Check if we need to update the structure */
        if (!Update) return;

        /* Otherwise, set data */
        ShareAccess->OpenCount = 1;
        ShareAccess->Readers = ReadAccess;
        ShareAccess->Writers = WriteAccess;
        ShareAccess->Deleters = DeleteAccess;
        ShareAccess->SharedRead = SharedRead;
        ShareAccess->SharedWrite = SharedWrite;
        ShareAccess->SharedDelete = SharedDelete;
    }
}

/*
 * @implemented
 */
VOID
NTAPI
IoCancelFileOpen(IN PDEVICE_OBJECT DeviceObject,
                 IN PFILE_OBJECT FileObject)
{
    PIRP Irp;
    KEVENT Event;
    KIRQL OldIrql;
    NTSTATUS Status;
    PIO_STACK_LOCATION Stack;

    /* Check if handles were already created for the
     * open file. If so, that's over.
     */
    if (FileObject->Flags & FO_HANDLE_CREATED)
        KeBugCheckEx(INVALID_CANCEL_OF_FILE_OPEN,
                     (ULONG_PTR)FileObject,
                     (ULONG_PTR)DeviceObject, 0, 0);

    /* Reset the events */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    KeClearEvent(&FileObject->Event);

    /* Allocate the IRP we'll use */
    Irp = IopAllocateIrpMustSucceed(DeviceObject->StackSize);
    /* Properly set it */
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->UserEvent = &Event;
    Irp->UserIosb = &Irp->IoStatus;
    Irp->Overlay.AsynchronousParameters.UserApcRoutine = NULL;
    Irp->Tail.Overlay.OriginalFileObject = FileObject;
    Irp->RequestorMode = KernelMode;
    Irp->Flags = IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API;

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MajorFunction = IRP_MJ_CLEANUP;
    Stack->FileObject = FileObject;

    /* Put on top of IRPs list of the thread */
    IopQueueIrpToThread(Irp);

    /* Call the driver */
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, UserRequest,
                              KernelMode, FALSE, NULL);
    }

    /* Remove from IRPs list */
    KeRaiseIrql(APC_LEVEL, &OldIrql);
    IopUnQueueIrpFromThread(Irp);
    KeLowerIrql(OldIrql);

    /* Free the IRP */
    IoFreeIrp(Irp);

    /* Clear the event */
    KeClearEvent(&FileObject->Event);
    /* And finally, mark the open operation as canceled */
    FileObject->Flags |= FO_FILE_OPEN_CANCELLED;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoQueryFileDosDeviceName(IN PFILE_OBJECT FileObject,
                         OUT POBJECT_NAME_INFORMATION *ObjectNameInformation)
{
    NTSTATUS Status;
    ULONG Length, ReturnLength;
    POBJECT_NAME_INFORMATION LocalInfo;

    /* Start with a buffer length of 200 */
    ReturnLength = 200;
    /*
     * We'll loop until query works.
     * We will use returned length for next loop
     * iteration, trying to have a big enough buffer.
     */
    for (Length = 200; ; Length = ReturnLength)
    {
        /* Allocate our work buffer */
        LocalInfo = ExAllocatePoolWithTag(PagedPool, Length, 'nDoI');
        if (LocalInfo == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Query the DOS name */
        Status = IopQueryNameInternal(FileObject,
                                      TRUE,
                                      TRUE,
                                      LocalInfo,
                                      Length,
                                      &ReturnLength,
                                      KernelMode);
        /* If it succeed, nothing more to do */
        if (Status == STATUS_SUCCESS)
        {
            break;
        }

        /* Otherwise, prepare for re-allocation */
        ExFreePoolWithTag(LocalInfo, 'nDoI');

        /*
         * If we failed because of something else
         * than memory, simply stop and fail here
         */
        if (Status != STATUS_BUFFER_OVERFLOW)
        {
            return Status;
        }
    }

    /* Success case here: return our buffer */
    *ObjectNameInformation = LocalInfo;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoSetFileOrigin(IN PFILE_OBJECT FileObject,
                IN BOOLEAN Remote)
{
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN FlagSet;

    /* Get the flag status */
    FlagSet = FileObject->Flags & FO_REMOTE_ORIGIN ? TRUE : FALSE;

    /* Don't set the flag if it was set already, and don't remove it if it wasn't set */
    if (Remote && !FlagSet)
    {
        /* Set the flag */
        FileObject->Flags |= FO_REMOTE_ORIGIN;
    }
    else if (!Remote && FlagSet)
    {
        /* Remove the flag */
        FileObject->Flags &= ~FO_REMOTE_ORIGIN;
    }
    else
    {
        /* Fail */
        Status = STATUS_INVALID_PARAMETER_MIX;
    }

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtCreateFile(PHANDLE FileHandle,
             ACCESS_MASK DesiredAccess,
             POBJECT_ATTRIBUTES ObjectAttributes,
             PIO_STATUS_BLOCK IoStatusBlock,
             PLARGE_INTEGER AllocateSize,
             ULONG FileAttributes,
             ULONG ShareAccess,
             ULONG CreateDisposition,
             ULONG CreateOptions,
             PVOID EaBuffer,
             ULONG EaLength)
{
    /* Call the I/O Function */
    return IoCreateFile(FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        AllocateSize,
                        FileAttributes,
                        ShareAccess,
                        CreateDisposition,
                        CreateOptions,
                        EaBuffer,
                        EaLength,
                        CreateFileTypeNone,
                        NULL,
                        0);
}

NTSTATUS
NTAPI
NtCreateMailslotFile(OUT PHANDLE FileHandle,
                     IN ACCESS_MASK DesiredAccess,
                     IN POBJECT_ATTRIBUTES ObjectAttributes,
                     OUT PIO_STATUS_BLOCK IoStatusBlock,
                     IN ULONG CreateOptions,
                     IN ULONG MailslotQuota,
                     IN ULONG MaxMessageSize,
                     IN PLARGE_INTEGER TimeOut)
{
    MAILSLOT_CREATE_PARAMETERS Buffer;
    PAGED_CODE();

    /* Check for Timeout */
    if (TimeOut)
    {
        /* check if the call came from user mode */
        if (KeGetPreviousMode() != KernelMode)
        {
            /* Enter SEH for Probe */
            _SEH2_TRY
            {
                /* Probe the timeout */
                Buffer.ReadTimeout = ProbeForReadLargeInteger(TimeOut);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Return the exception code */
                _SEH2_YIELD(return _SEH2_GetExceptionCode());
            }
            _SEH2_END;
        }
        else
        {
            /* Otherwise, capture directly */
            Buffer.ReadTimeout = *TimeOut;
        }

        /* Set the correct setting */
        Buffer.TimeoutSpecified = TRUE;
    }
    else
    {
        /* Tell the FSD we don't have a timeout */
        Buffer.TimeoutSpecified = FALSE;
    }

    /* Set Settings */
    Buffer.MailslotQuota = MailslotQuota;
    Buffer.MaximumMessageSize = MaxMessageSize;

    /* Call I/O */
    return IoCreateFile(FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        NULL,
                        0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_CREATE,
                        CreateOptions,
                        NULL,
                        0,
                        CreateFileTypeMailslot,
                        (PVOID)&Buffer,
                        0);
}

NTSTATUS
NTAPI
NtCreateNamedPipeFile(OUT PHANDLE FileHandle,
                      IN ACCESS_MASK DesiredAccess,
                      IN POBJECT_ATTRIBUTES ObjectAttributes,
                      OUT PIO_STATUS_BLOCK IoStatusBlock,
                      IN ULONG ShareAccess,
                      IN ULONG CreateDisposition,
                      IN ULONG CreateOptions,
                      IN ULONG NamedPipeType,
                      IN ULONG ReadMode,
                      IN ULONG CompletionMode,
                      IN ULONG MaximumInstances,
                      IN ULONG InboundQuota,
                      IN ULONG OutboundQuota,
                      IN PLARGE_INTEGER DefaultTimeout)
{
    NAMED_PIPE_CREATE_PARAMETERS Buffer;
    PAGED_CODE();

    /* Check for Timeout */
    if (DefaultTimeout)
    {
        /* check if the call came from user mode */
        if (KeGetPreviousMode() != KernelMode)
        {
            /* Enter SEH for Probe */
            _SEH2_TRY
            {
                /* Probe the timeout */
                Buffer.DefaultTimeout =
                    ProbeForReadLargeInteger(DefaultTimeout);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Return the exception code */
                _SEH2_YIELD(return _SEH2_GetExceptionCode());
            }
            _SEH2_END;
        }
        else
        {
            /* Otherwise, capture directly */
            Buffer.DefaultTimeout = *DefaultTimeout;
        }

        /* Set the correct setting */
        Buffer.TimeoutSpecified = TRUE;
    }
    else
    {
        /* Tell the FSD we don't have a timeout */
        Buffer.TimeoutSpecified = FALSE;
    }

    /* Set Settings */
    Buffer.NamedPipeType = NamedPipeType;
    Buffer.ReadMode = ReadMode;
    Buffer.CompletionMode = CompletionMode;
    Buffer.MaximumInstances = MaximumInstances;
    Buffer.InboundQuota = InboundQuota;
    Buffer.OutboundQuota = OutboundQuota;

    /* Call I/O */
    return IoCreateFile(FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        NULL,
                        0,
                        ShareAccess,
                        CreateDisposition,
                        CreateOptions,
                        NULL,
                        0,
                        CreateFileTypeNamedPipe,
                        (PVOID)&Buffer,
                        0);
}

NTSTATUS
NTAPI
NtFlushWriteBuffer(VOID)
{
    PAGED_CODE();

    /* Call the kernel */
    KeFlushWriteBuffer();
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtOpenFile(OUT PHANDLE FileHandle,
           IN ACCESS_MASK DesiredAccess,
           IN POBJECT_ATTRIBUTES ObjectAttributes,
           OUT PIO_STATUS_BLOCK IoStatusBlock,
           IN ULONG ShareAccess,
           IN ULONG OpenOptions)
{
    /* Call the I/O Function */
    return IoCreateFile(FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        NULL,
                        0,
                        ShareAccess,
                        FILE_OPEN,
                        OpenOptions,
                        NULL,
                        0,
                        CreateFileTypeNone,
                        NULL,
                        0);
}

NTSTATUS
NTAPI
NtQueryAttributesFile(IN POBJECT_ATTRIBUTES ObjectAttributes,
                      OUT PFILE_BASIC_INFORMATION FileInformation)
{
    /* Call the internal helper API */
    return IopQueryAttributesFile(ObjectAttributes,
                                  FileBasicInformation,
                                  sizeof(FILE_BASIC_INFORMATION),
                                  FileInformation);
}

NTSTATUS
NTAPI
NtQueryFullAttributesFile(IN POBJECT_ATTRIBUTES ObjectAttributes,
                          OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
    /* Call the internal helper API */
    return IopQueryAttributesFile(ObjectAttributes,
                                  FileNetworkOpenInformation,
                                  sizeof(FILE_NETWORK_OPEN_INFORMATION),
                                  FileInformation);
}

/**
 * @name NtCancelIoFile
 *
 * Cancel all pending I/O operations in the current thread for specified
 * file object.
 *
 * @param FileHandle
 *        Handle to file object to cancel requests for. No specific
 *        access rights are needed.
 * @param IoStatusBlock
 *        Pointer to status block which is filled with final completition
 *        status on successful return.
 *
 * @return Status.
 *
 * @implemented
 */
NTSTATUS
NTAPI
NtCancelIoFile(IN HANDLE FileHandle,
               OUT PIO_STATUS_BLOCK IoStatusBlock)
{
    PFILE_OBJECT FileObject;
    PETHREAD Thread;
    PIRP Irp;
    KIRQL OldIrql;
    BOOLEAN OurIrpsInList = FALSE;
    LARGE_INTEGER Interval;
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    NTSTATUS Status;
    PLIST_ENTRY ListHead, NextEntry;
    PAGED_CODE();
    IOTRACE(IO_API_DEBUG, "FileHandle: %p\n", FileHandle);

    /* Check the previous mode */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH for probing */
        _SEH2_TRY
        {
            /* Probe the I/O Status Block */
            ProbeForWriteIoStatusBlock(IoStatusBlock);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Reference the file object */
    Status = ObReferenceObjectByHandle(FileHandle,
                                       0,
                                       IoFileObjectType,
                                       PreviousMode,
                                       (PVOID*)&FileObject,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* IRP cancellations are synchronized at APC_LEVEL. */
    KeRaiseIrql(APC_LEVEL, &OldIrql);

    /* Get the current thread */
    Thread = PsGetCurrentThread();

    /* Update the operation counts */
    IopUpdateOperationCount(IopOtherTransfer);

    /* Loop the list */
    ListHead = &Thread->IrpList;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        /* Get the IRP and check if the File Object matches */
        Irp = CONTAINING_RECORD(NextEntry, IRP, ThreadListEntry);
        if (Irp->Tail.Overlay.OriginalFileObject == FileObject)
        {
            /* Cancel this IRP and keep looping */
            IoCancelIrp(Irp);
            OurIrpsInList = TRUE;
        }

        /* Go to the next entry */
        NextEntry = NextEntry->Flink;
    }

    /* Lower the IRQL */
    KeLowerIrql(OldIrql);

    /* Check if we had found an IRP */
    if (OurIrpsInList)
    {
        /* Setup a 10ms wait */
        Interval.QuadPart = -100000;

        /* Start looping */
        while (OurIrpsInList)
        {
            /* Do the wait */
            KeDelayExecutionThread(KernelMode, FALSE, &Interval);
            OurIrpsInList = FALSE;

            /* Raise IRQL */
            KeRaiseIrql(APC_LEVEL, &OldIrql);

            /* Now loop the list again */
            NextEntry = ListHead->Flink;
            while (NextEntry != ListHead)
            {
                /* Get the IRP and check if the File Object matches */
                Irp = CONTAINING_RECORD(NextEntry, IRP, ThreadListEntry);
                if (Irp->Tail.Overlay.OriginalFileObject == FileObject)
                {
                    /* Keep looping */
                    OurIrpsInList = TRUE;
                    break;
                }

                /* Go to the next entry */
                NextEntry = NextEntry->Flink;
            }

            /* Lower the IRQL */
            KeLowerIrql(OldIrql);
        }
    }

    /* Enter SEH for writing back the I/O Status */
    _SEH2_TRY
    {
        /* Write success */
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Ignore exception */
    }
    _SEH2_END;

    /* Dereference the file object and return success */
    ObDereferenceObject(FileObject);
    return STATUS_SUCCESS;
}

typedef struct _IOP_CANCEL_APC
{
    KAPC Apc;
    PFILE_OBJECT FileObject;
    PIO_STATUS_BLOCK IoRequestToCancel;
    BOOLEAN PortOnly;
} IOP_CANCEL_APC, *PIOP_CANCEL_APC;

/*
 * A request whose completion is reported only through the file's completion
 * port: asynchronous, pending, no event, no APC routine, and an APC context
 * for the port packet. Nothing else in the issuing process can learn about it.
 */
static
BOOLEAN
IopIsPortOnlyRequest(IN PIRP Irp,
                     IN PFILE_OBJECT FileObject)
{
    return (FileObject->CompletionContext != NULL) &&
           !(Irp->Flags & (IRP_SYNCHRONOUS_API | IRP_PAGING_IO |
                           IRP_CREATE_OPERATION | IRP_CLOSE_OPERATION)) &&
           (Irp->UserEvent == NULL) &&
           (Irp->Overlay.AsynchronousParameters.UserApcRoutine == NULL) &&
           (Irp->Overlay.AsynchronousParameters.UserApcContext != NULL);
}

static
BOOLEAN
IopIsRequestToCancel(IN PIRP Irp,
                     IN PFILE_OBJECT FileObject,
                     IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                     IN BOOLEAN PortOnly)
{
    return (Irp->Tail.Overlay.OriginalFileObject == FileObject) &&
           (!(IoRequestToCancel) || (Irp->UserIosb == IoRequestToCancel)) &&
           (!(PortOnly) || IopIsPortOnlyRequest(Irp, FileObject));
}

/* Only the owning thread walks its IRP list to cancel, at APC_LEVEL */
static
BOOLEAN
IopCancelThreadFileIrps(IN PETHREAD Thread,
                        IN PFILE_OBJECT FileObject,
                        IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                        IN BOOLEAN PortOnly)
{
    PLIST_ENTRY ListHead, NextEntry;
    BOOLEAN Found = FALSE;
    PIRP Irp;

    ASSERT(Thread == PsGetCurrentThread());
    ASSERT(KeGetCurrentIrql() == APC_LEVEL);

    ListHead = &Thread->IrpList;
    for (NextEntry = ListHead->Flink; NextEntry != ListHead; NextEntry = NextEntry->Flink)
    {
        /* Get the IRP and check if it is one of the requests to cancel */
        Irp = CONTAINING_RECORD(NextEntry, IRP, ThreadListEntry);
        if (IopIsRequestToCancel(Irp, FileObject, IoRequestToCancel, PortOnly))
        {
            IoCancelIrp(Irp);
            Found = TRUE;
        }
    }

    return Found;
}

/* Looks for the requests of another thread without cancelling them */
static
BOOLEAN
IopThreadHasFileIrps(IN PETHREAD Thread,
                     IN PFILE_OBJECT FileObject,
                     IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                     IN BOOLEAN PortOnly)
{
    PLIST_ENTRY ListHead, NextEntry;
    BOOLEAN Found = FALSE;
    KIRQL OldIrql;

    KeAcquireSpinLock(IopGetThreadIrpListLock(Thread), &OldIrql);
    ListHead = &Thread->IrpList;
    for (NextEntry = ListHead->Flink; NextEntry != ListHead; NextEntry = NextEntry->Flink)
    {
        if (IopIsRequestToCancel(CONTAINING_RECORD(NextEntry, IRP, ThreadListEntry),
                                 FileObject,
                                 IoRequestToCancel,
                                 PortOnly))
        {
            Found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(IopGetThreadIrpListLock(Thread), OldIrql);

    return Found;
}

static
VOID
NTAPI
IopCancelApcKernelRoutine(IN PKAPC Apc,
                          IN OUT PKNORMAL_ROUTINE *NormalRoutine,
                          IN OUT PVOID *NormalContext,
                          IN OUT PVOID *SystemArgument1,
                          IN OUT PVOID *SystemArgument2)
{
    /* The normal routine does the work */
    UNREFERENCED_PARAMETER(Apc);
}

/*
 * A normal kernel APC is not delivered while the thread is in a critical
 * region, which is where drivers hold the locks their cancel routines take.
 */
static
VOID
NTAPI
IopCancelApcNormalRoutine(IN PVOID NormalContext,
                          IN PVOID SystemArgument1,
                          IN PVOID SystemArgument2)
{
    PIOP_CANCEL_APC CancelApc = NormalContext;
    KIRQL OldIrql;

    /* Completion runs as a special kernel APC, which APC_LEVEL holds off */
    KeRaiseIrql(APC_LEVEL, &OldIrql);
    IopCancelThreadFileIrps(PsGetCurrentThread(),
                            CancelApc->FileObject,
                            CancelApc->IoRequestToCancel,
                            CancelApc->PortOnly);
    KeLowerIrql(OldIrql);

    /* An exiting thread runs this after IoCancelThreadIo, which detached its port-only requests */
    IopCancelDetachedIrps(PsGetCurrentProcess(), CancelApc->FileObject, CancelApc->IoRequestToCancel);

    /* Defer: the last deref must not run IopDeleteFile inside this cancel APC */
    ObDereferenceObjectDeferDelete(CancelApc->FileObject);
    ExFreePoolWithTag(CancelApc, TAG_IO);
}

/*
 * Cancels the matching requests of every thread of Process on FileObject:
 * the current thread's right away, the others' from a kernel APC queued to
 * each of them (only the owning thread walks its IRP list to cancel), and
 * the port-only requests that outlived their thread right away.
 */
NTSTATUS
NTAPI
IopCancelProcessFileIrps(IN PEPROCESS Process,
                         IN PFILE_OBJECT FileObject,
                         IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                         IN BOOLEAN PortOnly,
                         OUT PBOOLEAN Found)
{
    PIOP_CANCEL_APC CancelApc;
    PETHREAD CurrentThread = PsGetCurrentThread();
    PETHREAD Thread;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    *Found = FALSE;

    /* The current thread cancels its own requests right away (it may be attached elsewhere) */
    if (PsGetThreadProcess(CurrentThread) == Process)
    {
        KeRaiseIrql(APC_LEVEL, &OldIrql);
        if (IopCancelThreadFileIrps(CurrentThread, FileObject, IoRequestToCancel, PortOnly))
            *Found = TRUE;
        KeLowerIrql(OldIrql);
    }

    /* Port-only requests whose thread has exited belong to no thread (all are port-only) */
    if (IopCancelDetachedIrps(Process, FileObject, IoRequestToCancel))
        *Found = TRUE;

    /* Other threads with matching requests cancel them from a kernel APC */
    for (Thread = PsGetNextProcessThread(Process, NULL);
         Thread != NULL;
         Thread = PsGetNextProcessThread(Process, Thread))
    {
        if ((Thread == CurrentThread) ||
            !IopThreadHasFileIrps(Thread, FileObject, IoRequestToCancel, PortOnly))
        {
            continue;
        }

        *Found = TRUE;
        CancelApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(*CancelApc), TAG_IO);
        if (!CancelApc)
        {
            /* The requests of this and the remaining threads stay in progress */
            ObDereferenceObject(Thread);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ObReferenceObject(FileObject);
        CancelApc->FileObject = FileObject;
        CancelApc->IoRequestToCancel = IoRequestToCancel;
        CancelApc->PortOnly = PortOnly;
        KeInitializeApc(&CancelApc->Apc,
                        &Thread->Tcb,
                        OriginalApcEnvironment,
                        IopCancelApcKernelRoutine,
                        NULL,
                        IopCancelApcNormalRoutine,
                        KernelMode,
                        CancelApc);

        if (!KeInsertQueueApc(&CancelApc->Apc, NULL, NULL, IO_NO_INCREMENT))
        {
            /* The thread is exiting: IoCancelThreadIo cancels its I/O or detaches it (rescanned below) */
            ObDereferenceObject(FileObject);
            ExFreePoolWithTag(CancelApc, TAG_IO);
        }
    }

    /*
     * A thread that exited meanwhile detached its port-only requests instead of
     * cancelling them. PspExitThread clears ApcQueueable only after
     * IoCancelThreadIo: a thread that refused the APC has detached already (this
     * look finds it), one that took it detaches before it can run the APC, whose
     * routine looks again (IopCancelApcNormalRoutine).
     */
    if (IopCancelDetachedIrps(Process, FileObject, IoRequestToCancel))
        *Found = TRUE;

    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtCancelIoFileEx(IN HANDLE FileHandle,
                 IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                 OUT PIO_STATUS_BLOCK IoStatusBlock)
{
    BOOLEAN Found = FALSE;
    PFILE_OBJECT FileObject;
    PEPROCESS Process = PsGetCurrentProcess();
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();
    IOTRACE(IO_API_DEBUG, "FileHandle: %p\n", FileHandle);

    /* Check the previous mode */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH for probing, IoRequestToCancel is only compared, never dereferenced */
        _SEH2_TRY
        {
            /* Probe the I/O Status Block */
            ProbeForWriteIoStatusBlock(IoStatusBlock);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Reference the file object */
    Status = ObReferenceObjectByHandle(FileHandle,
                                       0,
                                       IoFileObjectType,
                                       PreviousMode,
                                       (PVOID*)&FileObject,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Update the operation counts */
    IopUpdateOperationCount(IopOtherTransfer);

    /* Cancellation does not wait for the requests to complete */
    Status = IopCancelProcessFileIrps(Process, FileObject, IoRequestToCancel, FALSE, &Found);
    if (NT_SUCCESS(Status))
        Status = Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;

    /* Enter SEH for writing back the I/O Status */
    _SEH2_TRY
    {
        IoStatusBlock->Status = Status;
        IoStatusBlock->Information = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Ignore exception */
    }
    _SEH2_END;

    /* Dereference the file object */
    ObDereferenceObject(FileObject);
    return Status;
}

typedef struct _IOP_SYNC_CANCEL_APC
{
    KAPC Apc;
    PIO_STATUS_BLOCK IoRequestToCancel;
    PETHREAD TargetThread;
    LIST_ENTRY PendingEntry;
} IOP_SYNC_CANCEL_APC, *PIOP_SYNC_CANCEL_APC;

/*
 * The cancel requests that are queued and not yet delivered. A thread that waits where its normal
 * kernel APCs cannot run (a critical region of a driver) keeps them queued, and a caller that cancels
 * in a loop (a runtime stopping a reader thread) would queue one nonpaged APC per call, hundreds of
 * megabytes of pool in a few seconds. One pending request per thread and I/O status block does the
 * same work: when it runs it cancels every matching request the thread has.
 */
static LIST_ENTRY IopSyncCancelPending = { &IopSyncCancelPending, &IopSyncCancelPending };
static KSPIN_LOCK IopSyncCancelPendingLock;

static
VOID
IopSyncCancelForget(IN PIOP_SYNC_CANCEL_APC CancelApc)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&IopSyncCancelPendingLock, &OldIrql);
    RemoveEntryList(&CancelApc->PendingEntry);
    KeReleaseSpinLock(&IopSyncCancelPendingLock, OldIrql);
}

/*
 * A request the thread waits for inside its system service: one on a file
 * opened for synchronous I/O (the service locks the file and waits for it)
 * or one with a service-owned event (IRP_SYNCHRONOUS_API). Closing a file and
 * paging I/O are not cancellable this way.
 */
static
BOOLEAN
IopIsSynchronousRequestToCancel(IN PIRP Irp,
                                IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL)
{
    PFILE_OBJECT FileObject = Irp->Tail.Overlay.OriginalFileObject;

    if (Irp->Flags & (IRP_CLOSE_OPERATION | IRP_PAGING_IO))
        return FALSE;

    if (!(Irp->Flags & IRP_SYNCHRONOUS_API) &&
        !(FileObject && (FileObject->Flags & FO_SYNCHRONOUS_IO)))
    {
        return FALSE;
    }

    return !(IoRequestToCancel) || (Irp->UserIosb == IoRequestToCancel);
}

/* Only the owning thread walks its IRP list to cancel, at APC_LEVEL */
static
BOOLEAN
IopCancelThreadSynchronousIrps(IN PETHREAD Thread,
                               IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL)
{
    PLIST_ENTRY ListHead, NextEntry;
    BOOLEAN Found = FALSE;
    PIRP Irp;

    ASSERT(Thread == PsGetCurrentThread());
    ASSERT(KeGetCurrentIrql() == APC_LEVEL);

    ListHead = &Thread->IrpList;
    for (NextEntry = ListHead->Flink; NextEntry != ListHead; NextEntry = NextEntry->Flink)
    {
        Irp = CONTAINING_RECORD(NextEntry, IRP, ThreadListEntry);
        if (IopIsSynchronousRequestToCancel(Irp, IoRequestToCancel))
        {
            IoCancelIrp(Irp);
            Found = TRUE;
        }
    }

    return Found;
}

/* Looks for the synchronous requests of another thread without cancelling them */
static
BOOLEAN
IopThreadHasSynchronousIrps(IN PETHREAD Thread,
                            IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL)
{
    PLIST_ENTRY ListHead, NextEntry;
    BOOLEAN Found = FALSE;
    KIRQL OldIrql;

    KeAcquireSpinLock(IopGetThreadIrpListLock(Thread), &OldIrql);
    ListHead = &Thread->IrpList;
    for (NextEntry = ListHead->Flink; NextEntry != ListHead; NextEntry = NextEntry->Flink)
    {
        if (IopIsSynchronousRequestToCancel(CONTAINING_RECORD(NextEntry, IRP, ThreadListEntry),
                                            IoRequestToCancel))
        {
            Found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(IopGetThreadIrpListLock(Thread), OldIrql);

    return Found;
}

static
VOID
NTAPI
IopSyncCancelApcKernelRoutine(IN PKAPC Apc,
                              IN OUT PKNORMAL_ROUTINE *NormalRoutine,
                              IN OUT PVOID *NormalContext,
                              IN OUT PVOID *SystemArgument1,
                              IN OUT PVOID *SystemArgument2)
{
    /* The normal routine does the work */
    UNREFERENCED_PARAMETER(Apc);
}

static
VOID
NTAPI
IopSyncCancelApcRundownRoutine(IN PKAPC Apc)
{
    PIOP_SYNC_CANCEL_APC CancelApc = CONTAINING_RECORD(Apc, IOP_SYNC_CANCEL_APC, Apc);

    /* The thread exited before the APC ran: it cancelled its own requests then */
    IopSyncCancelForget(CancelApc);
    ExFreePoolWithTag(CancelApc, TAG_IO);
}

/* Normal kernel APC: not delivered while the thread is in a critical region, where drivers hold their cancel locks */
static
VOID
NTAPI
IopSyncCancelApcNormalRoutine(IN PVOID NormalContext,
                              IN PVOID SystemArgument1,
                              IN PVOID SystemArgument2)
{
    PIOP_SYNC_CANCEL_APC CancelApc = NormalContext;
    KIRQL OldIrql;

    /* From here on a new request queues its own APC: this one may already have passed the thread's list */
    IopSyncCancelForget(CancelApc);

    /* Completion runs as a special kernel APC, which APC_LEVEL holds off */
    KeRaiseIrql(APC_LEVEL, &OldIrql);
    IopCancelThreadSynchronousIrps(PsGetCurrentThread(), CancelApc->IoRequestToCancel);
    KeLowerIrql(OldIrql);

    ExFreePoolWithTag(CancelApc, TAG_IO);
}

/*
 * @implemented
 *
 * Cancels the synchronous I/O (the request that makes the thread wait inside
 * its system service) the thread has in progress, whatever file it is on, or
 * the one whose I/O status block is IoRequestToCancel. STATUS_NOT_FOUND when
 * there is none. The thread cancels from a kernel APC: only the owner walks
 * its IRP list. Cancellation does not wait for the request to complete.
 */
NTSTATUS
NTAPI
NtCancelSynchronousIoFile(IN HANDLE ThreadHandle,
                          IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
                          OUT PIO_STATUS_BLOCK IoStatusBlock)
{
    PETHREAD Thread;
    PIOP_SYNC_CANCEL_APC CancelApc;
    BOOLEAN Found;
    KIRQL OldIrql;
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    NTSTATUS Status;
    PAGED_CODE();

    /* Check the previous mode */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH for probing, IoRequestToCancel is only compared, never dereferenced */
        _SEH2_TRY
        {
            ProbeForWriteIoStatusBlock(IoStatusBlock);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    Status = ObReferenceObjectByHandle(ThreadHandle,
                                       THREAD_TERMINATE,
                                       PsThreadType,
                                       PreviousMode,
                                       (PVOID*)&Thread,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Update the operation counts */
    IopUpdateOperationCount(IopOtherTransfer);

    if (Thread == PsGetCurrentThread())
    {
        /* A thread inside this service has no request of its own in progress, but look anyway */
        KeRaiseIrql(APC_LEVEL, &OldIrql);
        Found = IopCancelThreadSynchronousIrps(Thread, IoRequestToCancel);
        KeLowerIrql(OldIrql);
        Status = Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }
    else if (!IopThreadHasSynchronousIrps(Thread, IoRequestToCancel))
    {
        Status = STATUS_NOT_FOUND;
    }
    else
    {
        PLIST_ENTRY Entry;
        BOOLEAN Queued = FALSE;

        /* An earlier request for this thread and status block still waits for delivery: it does this one's work too */
        CancelApc = NULL;
        KeAcquireSpinLock(&IopSyncCancelPendingLock, &OldIrql);
        for (Entry = IopSyncCancelPending.Flink; Entry != &IopSyncCancelPending; Entry = Entry->Flink)
        {
            PIOP_SYNC_CANCEL_APC Pending = CONTAINING_RECORD(Entry, IOP_SYNC_CANCEL_APC, PendingEntry);

            if ((Pending->TargetThread == Thread) && (Pending->IoRequestToCancel == IoRequestToCancel))
            {
                Queued = TRUE;
                break;
            }
        }
        if (!Queued)
        {
            CancelApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(*CancelApc), TAG_IO);
            if (CancelApc)
            {
                CancelApc->IoRequestToCancel = IoRequestToCancel;
                CancelApc->TargetThread = Thread;
                InsertTailList(&IopSyncCancelPending, &CancelApc->PendingEntry);
            }
        }
        KeReleaseSpinLock(&IopSyncCancelPendingLock, OldIrql);

        if (Queued)
        {
            Status = STATUS_SUCCESS;
        }
        else if (!CancelApc)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            KeInitializeApc(&CancelApc->Apc,
                            &Thread->Tcb,
                            OriginalApcEnvironment,
                            IopSyncCancelApcKernelRoutine,
                            IopSyncCancelApcRundownRoutine,
                            IopSyncCancelApcNormalRoutine,
                            KernelMode,
                            CancelApc);

            /* A thread that is exiting cancels its I/O itself (IoCancelThreadIo) */
            if (!KeInsertQueueApc(&CancelApc->Apc, NULL, NULL, IO_NO_INCREMENT))
            {
                IopSyncCancelForget(CancelApc);
                ExFreePoolWithTag(CancelApc, TAG_IO);
            }
            Status = STATUS_SUCCESS;
        }
    }

    /* Enter SEH for writing back the I/O Status */
    _SEH2_TRY
    {
        IoStatusBlock->Status = Status;
        IoStatusBlock->Information = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Ignore exception */
    }
    _SEH2_END;

    ObDereferenceObject(Thread);
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS Status;
    DUMMY_FILE_OBJECT LocalFileObject;
    HANDLE Handle;
    KPROCESSOR_MODE AccessMode = KeGetPreviousMode();
    OPEN_PACKET OpenPacket;
    PAGED_CODE();
    IOTRACE(IO_API_DEBUG, "FileMame: %wZ\n", ObjectAttributes->ObjectName);

    /* Setup the Open Packet */
    RtlZeroMemory(&OpenPacket, sizeof(OPEN_PACKET));
    OpenPacket.Type = IO_TYPE_OPEN_PACKET;
    OpenPacket.Size = sizeof(OPEN_PACKET);
    OpenPacket.CreateOptions = FILE_DELETE_ON_CLOSE;
    OpenPacket.ShareAccess = FILE_SHARE_READ |
                             FILE_SHARE_WRITE |
                             FILE_SHARE_DELETE;
    OpenPacket.Disposition = FILE_OPEN;
    OpenPacket.DeleteOnly = TRUE;
    OpenPacket.LocalFileObject = &LocalFileObject;

    /* Update the operation counts */
    IopUpdateOperationCount(IopOtherTransfer);

    /*
     * Attempt opening the file. This will call the I/O Parse Routine for
     * the File Object (IopParseDevice) which will use the dummy file obejct
     * send the IRP to its device object. Note that we have two statuses
     * to worry about: the Object Manager's status (in Status) and the I/O
     * status, which is in the Open Packet's Final Status, and determined
     * by the Parse Check member.
     */
    Status = ObOpenObjectByName(ObjectAttributes,
                                NULL,
                                AccessMode,
                                NULL,
                                DELETE,
                                &OpenPacket,
                                &Handle);
    if (OpenPacket.ParseCheck == FALSE)
    {
        /* Check if Ob opened an object that is not a file */
        if (NT_SUCCESS(Status))
        {
            /* Close the handle, the object was not parsed as a file */
            ZwClose(Handle);
            Status = STATUS_OBJECT_TYPE_MISMATCH;
        }

        /* Parse failed */
        return Status;
    }

    /* Retrn the Io status */
    return OpenPacket.FinalStatus;
}

/* EOF */
