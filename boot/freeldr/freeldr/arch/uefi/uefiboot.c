/*
 * PROJECT:     FreeLoader UEFI Support
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The firmware boot entry of an installed system, and the hand-off
 *              from the installation medium to an installed system
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Setup puts this loader on the EFI system partition, in \EFI\NITROOS and at
 * the removable-media path \EFI\BOOT\BOOT<arch>.EFI, but it cannot add a boot
 * option to the firmware: text-mode Setup runs after ExitBootServices and the
 * kernel has no access to the variable services. Two things are done here,
 * before ExitBootServices, while the variable services are available:
 *
 * 1. Started from a hard disk partition that holds \EFI\NITROOS\BOOT<arch>.EFI
 *    (an installed system), the loader makes sure that the firmware has a
 *    load option for that file (UEFI 2.10, section 3.1.3 "Load Options"):
 *    a Boot#### variable whose device path is the one the firmware gave the
 *    partition we were started from (ending in its hard drive media node,
 *    which names the partition by its GPT GUID or MBR signature) followed by
 *    the file path. A new option goes first in BootOrder (section 3.1.1).
 *    The full device path, not the short form that starts at the hard drive
 *    node, because OVMF deletes short-form options whenever QEMU passes a
 *    boot order (OvmfPkg QemuBootOrderLib, BootOrderComplete: "drop HD()"),
 *    while a full path that starts with the disk's own path is kept.
 *
 *    A normal boot reads BootOrder and the options it lists and writes
 *    nothing; so does a boot through any option (BootCurrent) that starts our
 *    loader from our partition, whoever made it. An option of ours (our
 *    description) for this partition with another device path (the disk
 *    moved to another port) is rewritten in place; an option of ours
 *    whose partition is gone (the system was copied to another disk) is reused,
 *    not duplicated. Options of other systems are never written. A firmware
 *    that refuses the write is logged and the boot goes on. A firmware that
 *    drops the option again at every boot gets it NV_MAX_WRITES times per
 *    partition and NV_MAX_WRITES_TOTAL times in all, then no more (counted in
 *    our own variable NV_STATE_NAME, written before the option: no count, no
 *    option). Nothing is written to a variable store that would keep less
 *    than NV_MIN_RESERVE bytes free.
 *
 * 2. Started from an optical disc (the installation medium) while a hard
 *    disk holds an installed system, the loader offers the same choice as
 *    the BIOS CD boot sector (isoboot.S): "Press any key to boot from the
 *    medium", and after 5 seconds without a key it starts the installed
 *    system's loader. This finishes a two-stage installation when the
 *    firmware starts the disc again after the first stage (VirtualBox keeps
 *    its CD-ROM option before the disk option it made while the disk was
 *    blank), and the installed loader then adds its boot option (1).
 *
 * 3. When Setup starts from the disc, BootNext names the option that started
 *    the disc (unless it comes first in BootOrder anyway), so that after the
 *    first stage the firmware starts the disc once more instead of another
 *    system that comes first in BootOrder, and (2) hands over.
 */

#include <uefildr.h>
#include <reactos/buildno.h>

#include <debug.h>
DBG_DEFAULT_CHANNEL(WARNING);

/* GLOBALS ********************************************************************/

extern EFI_SYSTEM_TABLE* GlobalSystemTable;
extern EFI_HANDLE GlobalImageHandle;

#if defined(_M_AMD64)
#define NV_OWN_LOADER_PATH L"\\EFI\\NITROOS\\BOOTX64.EFI"
#elif defined(_M_IX86)
#define NV_OWN_LOADER_PATH L"\\EFI\\NITROOS\\BOOTIA32.EFI"
#endif

#define NV_DESCRIPTION      BRAND_PRODUCT_NAME_W
#define NV_ATTRIBUTES       (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)
#define NV_HD_NODE_LENGTH   42 /* UEFI 2.10, 10.3.5.1: the hard drive media device path node is 42 bytes */
#define NV_MAX_PATH         260
#define NV_MAX_DEVICE_PATH  4096 /* longer paths are not looked at (a load option's list is at most 64 KB) */
#define NV_HANDOFF_SECONDS  5
#define NV_NO_LIMIT         ((UINTN)-1) /* a device path read up to its end node */
#define NV_MAX_WRITES       3
#define NV_MAX_WRITES_TOTAL 8   /* over all partitions: two systems booted in turn do not reset each other's count */
#define NV_MIN_RESERVE      5120 /* bytes the variable store keeps free after our writes: some firmware cannot start with a full store */
#define NV_HEADER_BYTES     128 /* what a firmware may add per variable written: header and name */

/*
 * Our own variable (vendor GUID of this loader): how often the boot option was
 * written for which partition, and in all. Data: NV_STATE.
 */
#define NV_STATE_NAME L"NitroOSBootEntry"
#define NV_LOADER_VENDOR_GUID \
    { 0x4ecd2201, 0xc79a, 0x4beb, { 0xa1, 0x07, 0xdd, 0x02, 0xf0, 0x29, 0x1f, 0x83 } }

#include <pshpack1.h>
typedef struct _NV_STATE
{
    UINT32 Version;     /* 2 */
    UINT32 Writes;      /* times the option was written for this partition */
    UCHAR HdNode[NV_HD_NODE_LENGTH];
    UINT32 TotalWrites; /* times it was written for any partition */
} NV_STATE;
#include <poppack.h>

/*
 * Simple File System and File protocols (UEFI 2.10, sections 13.4 and 13.5):
 * only the members used here are named, the others keep their slots.
 */
#define NV_SIMPLE_FILE_SYSTEM_GUID \
    { 0x964e5b22, 0x6459, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
#define NV_FILE_MODE_READ 0x0000000000000001ULL

typedef struct _NV_FILE NV_FILE;
struct _NV_FILE
{
    UINT64 Revision;
    EFI_STATUS (EFIAPI *Open)(NV_FILE *This, NV_FILE **NewHandle, CHAR16 *FileName, UINT64 OpenMode, UINT64 Attributes);
    EFI_STATUS (EFIAPI *Close)(NV_FILE *This);
};

typedef struct _NV_SIMPLE_FILE_SYSTEM NV_SIMPLE_FILE_SYSTEM;
struct _NV_SIMPLE_FILE_SYSTEM
{
    UINT64 Revision;
    EFI_STATUS (EFIAPI *OpenVolume)(NV_SIMPLE_FILE_SYSTEM *This, NV_FILE **Root);
};

/* What a device path says, as far as we need it */
typedef struct _NV_PATH_INFO
{
    BOOLEAN HaveHd;
    BOOLEAN HaveCd;
    HARDDRIVE_DEVICE_PATH Hd;   /* the last hard drive node (copied: nodes are not aligned) */
    UINTN HdOffset;             /* where it starts: the bytes before it are the path of the disk */
    UINTN Length;               /* bytes before the end node */
    WCHAR File[NV_MAX_PATH];    /* the file path after the hard drive node */
} NV_PATH_INFO;

static EFI_GUID NvGlobalVariableGuid = EFI_GLOBAL_VARIABLE;
static EFI_GUID NvLoaderVendorGuid = NV_LOADER_VENDOR_GUID;
static EFI_GUID NvDevicePathGuid = EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID NvLoadedImageGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID NvBlockIoGuid = BLOCK_IO_PROTOCOL;
static EFI_GUID NvSimpleFileSystemGuid = NV_SIMPLE_FILE_SYSTEM_GUID;

/* Variable writes made by this boot (the debug log shows the count) */
static ULONG NvWriteCount = 0;

/* FUNCTIONS ******************************************************************/

#ifdef NV_OWN_LOADER_PATH

static
PVOID
NvAlloc(
    _In_ UINTN Size)
{
    PVOID Buffer = NULL;

    if (EFI_ERROR(GlobalSystemTable->BootServices->AllocatePool(EfiLoaderData, Size, &Buffer)))
        return NULL;
    return Buffer;
}

static
VOID
NvFree(
    _In_opt_ PVOID Buffer)
{
    if (Buffer)
        GlobalSystemTable->BootServices->FreePool(Buffer);
}

static
WCHAR
NvUpcase(
    _In_ WCHAR Char)
{
    return (Char >= L'a' && Char <= L'z') ? (WCHAR)(Char - L'a' + L'A') : Char;
}

static
BOOLEAN
NvEqualNoCase(
    _In_ const WCHAR *A,
    _In_ const WCHAR *B)
{
    while (*A && NvUpcase(*A) == NvUpcase(*B))
    {
        A++;
        B++;
    }
    return (*A == 0 && *B == 0);
}

/*
 * Walks a device path of at most MaxLength bytes (NV_NO_LIMIT: up to its end
 * node; a load option gives its FilePathListLength). The file path of the
 * nodes after the hard drive node is joined with '\' where needed: it may be
 * split over several nodes (UEFI 2.10, 10.3.5.4). FALSE for a malformed path.
 */
static
BOOLEAN
NvParseDevicePath(
    _In_ const VOID *Path,
    _In_ UINTN MaxLength,
    _Out_ NV_PATH_INFO *Info)
{
    const UCHAR *Node = Path;
    UINTN Offset = 0, PathLength = 0;

    RtlZeroMemory(Info, sizeof(*Info));

    for (;;)
    {
        UINT16 NodeLength;
        UCHAR Type, SubType;

        if (MaxLength != NV_NO_LIMIT && Offset + sizeof(EFI_DEVICE_PATH_PROTOCOL) > MaxLength)
            return FALSE;
        if (Offset > NV_MAX_DEVICE_PATH)
            return FALSE;
        Type = Node[Offset];
        SubType = Node[Offset + 1];
        NodeLength = (UINT16)(Node[Offset + 2] | (Node[Offset + 3] << 8));
        if (NodeLength < sizeof(EFI_DEVICE_PATH_PROTOCOL))
            return FALSE;
        if (MaxLength != NV_NO_LIMIT && Offset + NodeLength > MaxLength)
            return FALSE;

        if (Type == END_DEVICE_PATH_TYPE)
        {
            /* The end of the first instance ends what we look at */
            Info->Length = Offset;
            return TRUE;
        }

        if (Type == MEDIA_DEVICE_PATH && SubType == MEDIA_HARDDRIVE_DP && NodeLength >= NV_HD_NODE_LENGTH)
        {
            RtlCopyMemory(&Info->Hd, &Node[Offset], NV_HD_NODE_LENGTH);
            Info->HdOffset = Offset;
            Info->HaveHd = TRUE;
            PathLength = 0;
            Info->File[0] = UNICODE_NULL;
        }
        else if (Type == MEDIA_DEVICE_PATH && SubType == MEDIA_CDROM_DP)
        {
            Info->HaveCd = TRUE;
        }
        else if (Type == MEDIA_DEVICE_PATH && SubType == MEDIA_FILEPATH_DP && Info->HaveHd)
        {
            UINTN Chars = (NodeLength - sizeof(EFI_DEVICE_PATH_PROTOCOL)) / sizeof(WCHAR);
            const UCHAR *Text = &Node[Offset + sizeof(EFI_DEVICE_PATH_PROTOCOL)];
            UINTN i;

            for (i = 0; i < Chars; i++)
            {
                WCHAR Char = (WCHAR)(Text[2 * i] | (Text[2 * i + 1] << 8));
                if (Char == UNICODE_NULL)
                    break;
                if (i == 0 && Char != L'\\' && PathLength > 0 && Info->File[PathLength - 1] != L'\\')
                {
                    if (PathLength + 1 >= NV_MAX_PATH)
                        return FALSE;
                    Info->File[PathLength++] = L'\\';
                }
                if (PathLength + 1 >= NV_MAX_PATH)
                    return FALSE;
                Info->File[PathLength++] = Char;
            }
            Info->File[PathLength] = UNICODE_NULL;
        }

        Offset += NodeLength;
    }
}

/* The same partition: GPT by its unique GUID, MBR by disk signature and start */
static
BOOLEAN
NvSamePartition(
    _In_ const HARDDRIVE_DEVICE_PATH *A,
    _In_ const HARDDRIVE_DEVICE_PATH *B)
{
    if (A->MBRType != B->MBRType || A->SignatureType != B->SignatureType)
        return FALSE;
    if (A->SignatureType == SIGNATURE_TYPE_GUID)
        return RtlEqualMemory(A->Signature, B->Signature, 16);
    if (A->SignatureType == SIGNATURE_TYPE_MBR)
        return RtlEqualMemory(A->Signature, B->Signature, 4) && A->PartitionStart == B->PartitionStart;
    return FALSE;
}

static
BOOLEAN
NvFileExists(
    _In_ EFI_HANDLE Volume,
    _In_ const WCHAR *Path)
{
    NV_SIMPLE_FILE_SYSTEM *Fs = NULL;
    NV_FILE *Root = NULL, *File = NULL;
    WCHAR Name[NV_MAX_PATH];
    BOOLEAN Exists = FALSE;

    RtlStringCbCopyW(Name, sizeof(Name), Path);
    if (EFI_ERROR(GlobalSystemTable->BootServices->HandleProtocol(Volume, &NvSimpleFileSystemGuid, (VOID**)&Fs)) || !Fs)
        return FALSE;
    if (EFI_ERROR(Fs->OpenVolume(Fs, &Root)) || !Root)
        return FALSE;
    if (!EFI_ERROR(Root->Open(Root, &File, Name, NV_FILE_MODE_READ, 0)) && File)
    {
        Exists = TRUE;
        File->Close(File);
    }
    Root->Close(Root);
    return Exists;
}

static
BOOLEAN
NvGetHandlePath(
    _In_ EFI_HANDLE Handle,
    _Out_ EFI_DEVICE_PATH_PROTOCOL **Path)
{
    *Path = NULL;
    return !EFI_ERROR(GlobalSystemTable->BootServices->HandleProtocol(Handle, &NvDevicePathGuid, (VOID**)Path)) &&
           *Path != NULL;
}

/* Reads a variable into pool memory. EFI_NOT_FOUND if it does not exist (or is empty). */
static
EFI_STATUS
NvGetVariable(
    _In_ const WCHAR *Name,
    _In_ EFI_GUID *Vendor,
    _Out_ UCHAR **Data,
    _Out_ UINTN *Size)
{
    WCHAR NameCopy[32];
    EFI_STATUS Status;
    UINTN Length = 0;
    UCHAR *Buffer;

    *Data = NULL;
    *Size = 0;
    RtlStringCbCopyW(NameCopy, sizeof(NameCopy), Name);
    Status = GlobalSystemTable->RuntimeServices->GetVariable(NameCopy, Vendor, NULL, &Length, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL)
        return EFI_ERROR(Status) ? Status : EFI_NOT_FOUND;
    Buffer = NvAlloc(Length);
    if (!Buffer)
        return EFI_OUT_OF_RESOURCES;
    Status = GlobalSystemTable->RuntimeServices->GetVariable(NameCopy, Vendor, NULL, &Length, Buffer);
    if (EFI_ERROR(Status))
    {
        NvFree(Buffer);
        return Status;
    }
    *Data = Buffer;
    *Size = Length;
    return EFI_SUCCESS;
}

static
EFI_STATUS
NvSetVariable(
    _In_ const WCHAR *Name,
    _In_ EFI_GUID *Vendor,
    _In_ PCSTR LogName,
    _In_ PVOID Data,
    _In_ UINTN Size)
{
    WCHAR NameCopy[32];
    EFI_STATUS Status;

    RtlStringCbCopyW(NameCopy, sizeof(NameCopy), Name);
    NvWriteCount++;
    Status = GlobalSystemTable->RuntimeServices->SetVariable(NameCopy, Vendor, NV_ATTRIBUTES, Size, Data);
    ERR("UEFI boot entry: SetVariable(%s, %lu bytes) = 0x%lx\n", LogName, (ULONG)Size, (ULONG)Status);
    return Status;
}

static
VOID
NvOptionName(
    _Out_writes_(9) WCHAR *Name,
    _In_ ULONG Number)
{
    static const WCHAR Hex[] = L"0123456789ABCDEF";
    Name[0] = L'B'; Name[1] = L'o'; Name[2] = L'o'; Name[3] = L't';
    Name[4] = Hex[(Number >> 12) & 0xF];
    Name[5] = Hex[(Number >> 8) & 0xF];
    Name[6] = Hex[(Number >> 4) & 0xF];
    Name[7] = Hex[Number & 0xF];
    Name[8] = UNICODE_NULL;
}

/* "Boot####" with four upper-case hexadecimal digits (UEFI 2.10, 3.1.1) */
static
BOOLEAN
NvParseOptionName(
    _In_ const WCHAR *Name,
    _Out_ ULONG *Number)
{
    ULONG i, Value = 0;

    if (Name[0] != L'B' || Name[1] != L'o' || Name[2] != L'o' || Name[3] != L't')
        return FALSE;
    for (i = 4; i < 8; i++)
    {
        WCHAR c = Name[i];
        if (c >= L'0' && c <= L'9')
            Value = (Value << 4) | (c - L'0');
        else if (c >= L'A' && c <= L'F')
            Value = (Value << 4) | (c - L'A' + 10);
        else
            return FALSE;
    }
    if (Name[8] != UNICODE_NULL)
        return FALSE;
    *Number = Value;
    return TRUE;
}

typedef enum _NV_OPTION_KIND
{
    NvOptionOther,          /* not ours, or not readable */
    NvOptionMatch,          /* starts our loader from our partition: nothing to do */
    NvOptionOursMoved,      /* our description, loader and partition, another device path: rewrite it */
    NvOptionOthersForUs,    /* another description, our loader and partition, another device path: never written */
    NvOptionOursElsewhere   /* our description and loader, another partition */
} NV_OPTION_KIND;

/*
 * Classifies load option Boot<Number> (UEFI 2.10, 3.1.3: UINT32 Attributes,
 * UINT16 FilePathListLength, the description, the device path list) against
 * the device path of our partition (Ours, OursPath).
 */
static
NV_OPTION_KIND
NvClassifyOption(
    _In_ ULONG Number,
    _In_ const NV_PATH_INFO *Ours,
    _In_ const UCHAR *OursPath,
    _Out_opt_ HARDDRIVE_DEVICE_PATH *TheirPartition)
{
    WCHAR Name[9];
    UCHAR *Data;
    UINTN Size, DescEnd;
    UINT16 PathListLength;
    NV_PATH_INFO *Theirs;
    NV_OPTION_KIND Kind = NvOptionOther;
    BOOLEAN DescOurs;

    NvOptionName(Name, Number);
    if (EFI_ERROR(NvGetVariable(Name, &NvGlobalVariableGuid, &Data, &Size)))
        return NvOptionOther;
    Theirs = NvAlloc(sizeof(*Theirs));
    if (!Theirs || Size < 6 + sizeof(WCHAR))
        goto Done;

    PathListLength = (UINT16)(Data[4] | (Data[5] << 8));

    /* The description: a null-terminated UCS-2 string from offset 6 */
    for (DescEnd = 6; DescEnd + 1 < Size; DescEnd += 2)
    {
        if (Data[DescEnd] == 0 && Data[DescEnd + 1] == 0)
            break;
    }
    if (DescEnd + 1 >= Size)
        goto Done;
    if (DescEnd + 2 + PathListLength > Size || PathListLength < sizeof(EFI_DEVICE_PATH_PROTOCOL))
        goto Done;

    if (!NvParseDevicePath(&Data[DescEnd + 2], PathListLength, Theirs) || !Theirs->HaveHd ||
        !NvEqualNoCase(Theirs->File, NV_OWN_LOADER_PATH))
    {
        goto Done;
    }

    /* Ours by name: the description is ours too */
    {
        const UCHAR *Desc = &Data[6];
        const WCHAR *Want = NV_DESCRIPTION;
        UINTN i = 0;

        while (Want[i] && 6 + 2 * i + 1 < DescEnd &&
               (WCHAR)(Desc[2 * i] | (Desc[2 * i + 1] << 8)) == Want[i])
        {
            i++;
        }
        DescOurs = (Want[i] == UNICODE_NULL && 6 + 2 * i == DescEnd);
    }

    if (NvSamePartition(&Theirs->Hd, &Ours->Hd))
    {
        /* The short form (starts at the hard drive node) or the device path of our disk */
        if (Theirs->HdOffset == 0 ||
            (Theirs->HdOffset == Ours->HdOffset && RtlEqualMemory(&Data[DescEnd + 2], OursPath, Ours->HdOffset)))
        {
            Kind = NvOptionMatch;
        }
        else
        {
            /* Made by hand or by another program, or rewritten by the firmware: not ours to change */
            Kind = DescOurs ? NvOptionOursMoved : NvOptionOthersForUs;
        }
    }
    else if (DescOurs)
    {
        Kind = NvOptionOursElsewhere;
        if (TheirPartition)
            *TheirPartition = Theirs->Hd;
    }

Done:
    NvFree(Theirs);
    NvFree(Data);
    return Kind;
}

/* Is there a partition with this signature among the block devices of the firmware? */
static
BOOLEAN
NvPartitionPresent(
    _In_ const HARDDRIVE_DEVICE_PATH *Partition)
{
    EFI_HANDLE *Handles = NULL;
    UINTN Count = 0, i;
    BOOLEAN Present = FALSE;
    NV_PATH_INFO *Info = NvAlloc(sizeof(*Info));

    if (!Info)
        return TRUE; /* cannot tell: treat it as present, so that it is never overwritten */
    if (EFI_ERROR(GlobalSystemTable->BootServices->LocateHandleBuffer(ByProtocol, &NvBlockIoGuid, NULL, &Count, &Handles)))
    {
        NvFree(Info);
        return TRUE;
    }

    for (i = 0; i < Count && !Present; i++)
    {
        EFI_DEVICE_PATH_PROTOCOL *Path;

        if (NvGetHandlePath(Handles[i], &Path) &&
            NvParseDevicePath(Path, NV_NO_LIMIT, Info) && Info->HaveHd &&
            NvSamePartition(&Info->Hd, Partition))
        {
            Present = TRUE;
        }
    }
    NvFree(Handles);
    NvFree(Info);
    return Present;
}

/*
 * Every Boot#### variable, through GetNextVariableName: marks the numbers in
 * use and finds, in this order of preference: an option for our loader on our
 * partition, the same with another device path, our option of a partition
 * that is gone.
 */
static
BOOLEAN
NvScanAllOptions(
    _In_ const NV_PATH_INFO *Ours,
    _In_ const UCHAR *OursPath,
    _Out_writes_bytes_(0x10000 / 8) UCHAR *Used,
    _Out_ LONG *Match,
    _Out_ LONG *Moved,
    _Out_ LONG *Stale)
{
    UINTN NameBytes = 128 * sizeof(WCHAR);
    WCHAR *Name = NvAlloc(NameBytes);
    EFI_GUID Guid;
    EFI_STATUS Status = EFI_SUCCESS;
    ULONG Rounds, Grown = 0;

    *Match = *Moved = *Stale = -1;
    RtlZeroMemory(Used, 0x10000 / 8);
    if (!Name)
        return FALSE;
    Name[0] = UNICODE_NULL;
    RtlZeroMemory(&Guid, sizeof(Guid));

    for (Rounds = 0; Rounds < 4096; Rounds++)
    {
        UINTN Size = NameBytes;
        ULONG Number;
        HARDDRIVE_DEVICE_PATH Theirs;
        NV_OPTION_KIND Kind;

        Status = GlobalSystemTable->RuntimeServices->GetNextVariableName(&Size, Name, &Guid);
        if (Status == EFI_BUFFER_TOO_SMALL && Grown < 4 && Size > NameBytes)
        {
            WCHAR *Bigger = NvAlloc(Size);
            if (!Bigger)
                break;
            Grown++;
            RtlCopyMemory(Bigger, Name, NameBytes);
            NvFree(Name);
            Name = Bigger;
            NameBytes = Size;
            continue;
        }
        if (Status == EFI_NOT_FOUND)
        {
            NvFree(Name);
            return TRUE;
        }
        if (EFI_ERROR(Status))
            break;

        if (!RtlEqualMemory(&Guid, &NvGlobalVariableGuid, sizeof(Guid)) || !NvParseOptionName(Name, &Number))
            continue;

        Used[Number / 8] |= (UCHAR)(1 << (Number % 8));
        if (*Match >= 0)
            continue;
        Kind = NvClassifyOption(Number, Ours, OursPath, &Theirs);
        if (Kind == NvOptionMatch)
            *Match = (LONG)Number;
        else if (Kind == NvOptionOursMoved && *Moved < 0)
            *Moved = (LONG)Number;
        else if (Kind == NvOptionOursElsewhere && *Stale < 0 && !NvPartitionPresent(&Theirs))
            *Stale = (LONG)Number;
    }

    ERR("UEFI boot entry: cannot list the firmware variables (0x%lx)\n", (ULONG)Status);
    NvFree(Name);
    return FALSE;
}

/*
 * Is there room in the variable store for Needed bytes, keeping NV_MIN_RESERVE
 * free (UEFI 2.10, 8.2 QueryVariableInfo)? A firmware older than UEFI 2.0, or
 * one that cannot say, gets nothing written.
 */
static
BOOLEAN
NvStoreHasRoom(
    _In_ UINTN Needed)
{
    EFI_RUNTIME_SERVICES *Rt = GlobalSystemTable->RuntimeServices;
    UINT64 MaxStorage = 0, Remaining = 0, MaxVariable = 0;
    EFI_STATUS Status;

    if (Rt->Hdr.Revision < EFI_2_00_SYSTEM_TABLE_REVISION || !Rt->QueryVariableInfo)
    {
        ERR("UEFI boot entry: no QueryVariableInfo, nothing written\n");
        return FALSE;
    }
    Status = Rt->QueryVariableInfo(NV_ATTRIBUTES, &MaxStorage, &Remaining, &MaxVariable);
    if (EFI_ERROR(Status) || Remaining < Needed + NV_MIN_RESERVE || MaxVariable < Needed)
    {
        ERR("UEFI boot entry: variable store: status 0x%lx, %lu bytes free, %lu needed: nothing written\n",
            (ULONG)Status, (ULONG)Remaining, (ULONG)(Needed + NV_MIN_RESERVE));
        return FALSE;
    }
    return TRUE;
}

/*
 * The write budget: FALSE when the option was written NV_MAX_WRITES times for
 * this partition already (a firmware that drops it at every boot), or
 * NV_MAX_WRITES_TOTAL times in all, or when the store has no room for Needed
 * bytes. Otherwise counts this write first (one more variable write, only
 * when the option is written: never on a normal boot); a count that cannot be
 * written stops everything, so that a firmware that refuses it is not written
 * to at every boot.
 */
static
BOOLEAN
NvTakeWriteBudget(
    _In_ const NV_PATH_INFO *Ours,
    _In_ UINTN Needed)
{
    NV_STATE State;
    UCHAR *Data;
    UINTN Size;

    RtlZeroMemory(&State, sizeof(State));
    if (!EFI_ERROR(NvGetVariable(NV_STATE_NAME, &NvLoaderVendorGuid, &Data, &Size)))
    {
        if (Size == sizeof(State))
            RtlCopyMemory(&State, Data, sizeof(State));
        NvFree(Data);
    }
    if (State.Version != 2)
    {
        RtlZeroMemory(&State, sizeof(State));
        State.Version = 2;
    }
    if (!NvSamePartition((const HARDDRIVE_DEVICE_PATH *)State.HdNode, &Ours->Hd))
    {
        State.Writes = 0;
        RtlCopyMemory(State.HdNode, &Ours->Hd, NV_HD_NODE_LENGTH);
    }
    if (State.Writes >= NV_MAX_WRITES || State.TotalWrites >= NV_MAX_WRITES_TOTAL)
    {
        ERR("UEFI boot entry: written %lu times for this partition (%lu in all) already and gone again: the firmware drops it, not written again\n",
            (ULONG)State.Writes, (ULONG)State.TotalWrites);
        return FALSE;
    }
    if (!NvStoreHasRoom(Needed + NV_HEADER_BYTES + sizeof(State)))
        return FALSE;
    State.Writes++;
    State.TotalWrites++;
    if (EFI_ERROR(NvSetVariable(NV_STATE_NAME, &NvLoaderVendorGuid, "NitroOSBootEntry", &State, sizeof(State))))
    {
        ERR("UEFI boot entry: the write count cannot be kept: nothing written\n");
        return FALSE;
    }
    return TRUE;
}

static
VOID
NvEnsureBootEntry(
    _In_ const NV_PATH_INFO *Ours,
    _In_ const UCHAR *OursPath)
{
    UCHAR *Order = NULL, *NewOrder = NULL, *Option = NULL, *Used = NULL, *Current = NULL;
    UINTN OrderSize = 0, CurrentSize, i, OptionSize, PathListLength, DescBytes, FileBytes, FileNodeLength;
    LONG Match, Moved, Stale;
    ULONG Number;
    BOOLEAN InOrder = FALSE;
    EFI_STATUS Status;
    WCHAR Name[9];
    CHAR LogName[16];

    /* 1. The normal boot: an option in BootOrder starts us. Read only. */
    Status = NvGetVariable(L"BootOrder", &NvGlobalVariableGuid, &Order, &OrderSize);
    if (Status == EFI_NOT_FOUND)
    {
        OrderSize = 0;
    }
    else if (EFI_ERROR(Status))
    {
        ERR("UEFI boot entry: cannot read BootOrder (0x%lx), nothing done\n", (ULONG)Status);
        return;
    }
    OrderSize &= ~(UINTN)1;

    for (i = 0; i < OrderSize / 2; i++)
    {
        UINT16 Entry = (UINT16)(Order[2 * i] | (Order[2 * i + 1] << 8));
        if (NvClassifyOption(Entry, Ours, OursPath, NULL) == NvOptionMatch)
        {
            ERR("UEFI boot entry: Boot%04X starts this system, %lu variable writes\n", Entry, NvWriteCount);
            goto Quit;
        }
    }

    /*
     * The option that started us (BootCurrent, UEFI 2.10 3.3) starts our loader
     * from our partition, though with a device path of its own (made by hand
     * or by another program, or rewritten by the firmware) or from outside
     * BootOrder (the firmware's boot menu): it works, nothing to do.
     */
    if (!EFI_ERROR(NvGetVariable(L"BootCurrent", &NvGlobalVariableGuid, &Current, &CurrentSize)))
    {
        NV_OPTION_KIND Kind = NvOptionOther;
        UINT16 Entry = 0;

        if (CurrentSize == sizeof(UINT16))
        {
            Entry = (UINT16)(Current[0] | (Current[1] << 8));
            Kind = NvClassifyOption(Entry, Ours, OursPath, NULL);
        }
        NvFree(Current);
        if (Kind == NvOptionMatch || Kind == NvOptionOursMoved || Kind == NvOptionOthersForUs)
        {
            ERR("UEFI boot entry: Boot%04X (BootCurrent) starts this system, %lu variable writes\n", Entry, NvWriteCount);
            goto Quit;
        }
    }

    /* 2. Not in BootOrder: look at every option */
    Used = NvAlloc(0x10000 / 8);
    if (!Used || !NvScanAllOptions(Ours, OursPath, Used, &Match, &Moved, &Stale))
        goto Quit;

    DescBytes = (wcslen(NV_DESCRIPTION) + 1) * sizeof(WCHAR);
    FileBytes = (wcslen(NV_OWN_LOADER_PATH) + 1) * sizeof(WCHAR);
    FileNodeLength = sizeof(EFI_DEVICE_PATH_PROTOCOL) + FileBytes;
    /* The device path of our partition up to and including its hard drive node, the file, the end */
    PathListLength = Ours->HdOffset + NV_HD_NODE_LENGTH + FileNodeLength + sizeof(EFI_DEVICE_PATH_PROTOCOL);
    OptionSize = 6 + DescBytes + PathListLength;

    /* The option and BootOrder, each with what the firmware adds */
    if (!NvTakeWriteBudget(Ours, OptionSize + OrderSize + sizeof(UINT16) + 2 * NV_HEADER_BYTES))
        goto Quit;

    if (Match >= 0)
    {
        Number = (ULONG)Match;
        ERR("UEFI boot entry: Boot%04lX starts this system but is not in BootOrder\n", Number);
    }
    else
    {
        /* Rewrite our option of this partition, or reuse ours of a partition that is gone, or the lowest free number */
        if (Moved >= 0)
        {
            Number = (ULONG)Moved;
        }
        else if (Stale >= 0)
        {
            Number = (ULONG)Stale;
        }
        else
        {
            for (Number = 0; Number < 0x10000; Number++)
            {
                if (!(Used[Number / 8] & (1 << (Number % 8))))
                    break;
            }
            if (Number >= 0x10000)
            {
                ERR("UEFI boot entry: no free Boot#### number\n");
                goto Quit;
            }
        }

        Option = NvAlloc(OptionSize);
        if (!Option)
            goto Quit;

        {
            UCHAR *p = Option;

            /* Attributes, FilePathListLength */
            p[0] = (UCHAR)LOAD_OPTION_ACTIVE; p[1] = 0; p[2] = 0; p[3] = 0;
            p[4] = (UCHAR)(PathListLength & 0xFF); p[5] = (UCHAR)(PathListLength >> 8);
            p += 6;
            RtlCopyMemory(p, NV_DESCRIPTION, DescBytes);
            p += DescBytes;
            RtlCopyMemory(p, OursPath, Ours->HdOffset);
            p += Ours->HdOffset;
            RtlCopyMemory(p, &Ours->Hd, NV_HD_NODE_LENGTH);
            p += NV_HD_NODE_LENGTH;
            p[0] = MEDIA_DEVICE_PATH; p[1] = MEDIA_FILEPATH_DP;
            p[2] = (UCHAR)(FileNodeLength & 0xFF); p[3] = (UCHAR)(FileNodeLength >> 8);
            RtlCopyMemory(p + 4, NV_OWN_LOADER_PATH, FileBytes);
            p += FileNodeLength;
            p[0] = END_DEVICE_PATH_TYPE; p[1] = END_ENTIRE_DEVICE_PATH_SUBTYPE; p[2] = 4; p[3] = 0;
        }

        NvOptionName(Name, Number);
        RtlStringCbPrintfA(LogName, sizeof(LogName), "Boot%04lX", Number);
        Status = NvSetVariable(Name, &NvGlobalVariableGuid, LogName, Option, OptionSize);
        if (EFI_ERROR(Status))
        {
            ERR("UEFI boot entry: the firmware refused %s (0x%lx): booting on without a boot entry\n", LogName, (ULONG)Status);
            goto Quit;
        }
    }

    /* 3. BootOrder: a number that is in it keeps its place; otherwise ours goes first */
    for (i = 0; i < OrderSize / 2; i++)
    {
        if ((ULONG)(Order[2 * i] | (Order[2 * i + 1] << 8)) == Number)
            InOrder = TRUE;
    }
    if (InOrder)
    {
        ERR("UEFI boot entry: Boot%04lX rewritten in place, %lu variable writes\n", Number, NvWriteCount);
        goto Quit;
    }

    NewOrder = NvAlloc(OrderSize + 2);
    if (!NewOrder)
        goto Quit;
    NewOrder[0] = (UCHAR)(Number & 0xFF);
    NewOrder[1] = (UCHAR)(Number >> 8);
    if (OrderSize)
        RtlCopyMemory(NewOrder + 2, Order, OrderSize);

    Status = NvSetVariable(L"BootOrder", &NvGlobalVariableGuid, "BootOrder", NewOrder, OrderSize + 2);
    if (EFI_ERROR(Status))
        ERR("UEFI boot entry: the firmware refused BootOrder (0x%lx): booting on\n", (ULONG)Status);
    else
        ERR("UEFI boot entry: Boot%04lX added first in BootOrder, %lu variable writes\n", Number, NvWriteCount);

Quit:
    NvFree(NewOrder);
    NvFree(Option);
    NvFree(Used);
    NvFree(Order);
}

/* The Attributes of load option Boot<Number>, 0 if it cannot be read */
static
UINT32
NvOptionAttributes(
    _In_ ULONG Number)
{
    WCHAR Name[9];
    UCHAR *Data;
    UINTN Size;
    UINT32 Attributes = 0;

    NvOptionName(Name, Number);
    if (!EFI_ERROR(NvGetVariable(Name, &NvGlobalVariableGuid, &Data, &Size)))
    {
        if (Size >= 6)
            Attributes = (UINT32)(Data[0] | (Data[1] << 8) | (Data[2] << 16) | ((UINT32)Data[3] << 24));
        NvFree(Data);
    }
    return Attributes;
}

/*
 * Started from the installation disc: an installed system on a hard disk is
 * started after NV_HANDOFF_SECONDS unless a key is pressed (isoboot.S does
 * the same on BIOS computers). Returns only when the disc is to be booted.
 */
static
VOID
NvHandOffToInstalledSystem(VOID)
{
    EFI_BOOT_SERVICES *BootServices = GlobalSystemTable->BootServices;
    EFI_HANDLE *Handles = NULL;
    UINTN Count = 0, i, Tick;
    EFI_DEVICE_PATH_PROTOCOL *VolumePath = NULL;
    UCHAR *LoaderPath = NULL;
    UINTN VolumePathLength = 0, FileBytes, FileNodeLength;
    EFI_HANDLE Image = NULL;
    EFI_INPUT_KEY Key;
    EFI_STATUS Status;
    NV_PATH_INFO *Info = NvAlloc(sizeof(*Info));

    if (!Info)
        return;
    if (EFI_ERROR(BootServices->LocateHandleBuffer(ByProtocol, &NvSimpleFileSystemGuid, NULL, &Count, &Handles)))
    {
        NvFree(Info);
        return;
    }

    for (i = 0; i < Count; i++)
    {
        EFI_DEVICE_PATH_PROTOCOL *Path;

        if (!NvGetHandlePath(Handles[i], &Path) ||
            !NvParseDevicePath(Path, NV_NO_LIMIT, Info) ||
            !Info->HaveHd || Info->HaveCd)
        {
            continue;
        }
        if (NvFileExists(Handles[i], NV_OWN_LOADER_PATH))
        {
            VolumePath = Path;
            VolumePathLength = Info->Length;
            break;
        }
    }
    NvFree(Handles);
    NvFree(Info);
    if (!VolumePath)
        return;

    /* The device path of the installed loader: the volume's path, a file node, the end */
    FileBytes = (wcslen(NV_OWN_LOADER_PATH) + 1) * sizeof(WCHAR);
    FileNodeLength = sizeof(EFI_DEVICE_PATH_PROTOCOL) + FileBytes;
    LoaderPath = NvAlloc(VolumePathLength + FileNodeLength + sizeof(EFI_DEVICE_PATH_PROTOCOL));
    if (!LoaderPath)
        return;
    RtlCopyMemory(LoaderPath, VolumePath, VolumePathLength);
    {
        UCHAR *p = LoaderPath + VolumePathLength;
        p[0] = MEDIA_DEVICE_PATH; p[1] = MEDIA_FILEPATH_DP;
        p[2] = (UCHAR)(FileNodeLength & 0xFF); p[3] = (UCHAR)(FileNodeLength >> 8);
        RtlCopyMemory(p + 4, NV_OWN_LOADER_PATH, FileBytes);
        p += FileNodeLength;
        p[0] = END_DEVICE_PATH_TYPE; p[1] = END_ENTIRE_DEVICE_PATH_SUBTYPE; p[2] = 4; p[3] = 0;
    }

    /* The same prompt as the BIOS boot sector of the disc */
    GlobalSystemTable->ConIn->Reset(GlobalSystemTable->ConIn, FALSE);
    GlobalSystemTable->ConOut->OutputString(GlobalSystemTable->ConOut,
        L"\r\nPress any key to boot from the " NV_DESCRIPTION L" medium");
    for (Tick = 0; Tick < NV_HANDOFF_SECONDS * 10; Tick++)
    {
        if (GlobalSystemTable->ConIn->ReadKeyStroke(GlobalSystemTable->ConIn, &Key) == EFI_SUCCESS)
        {
            GlobalSystemTable->ConOut->OutputString(GlobalSystemTable->ConOut, L"\r\n\r\n");
            ERR("UEFI hand-off: key pressed, booting from the medium\n");
            NvFree(LoaderPath);
            return;
        }
        BootServices->Stall(100000);
        if (Tick % 10 == 9)
            GlobalSystemTable->ConOut->OutputString(GlobalSystemTable->ConOut, L".");
    }
    GlobalSystemTable->ConOut->OutputString(GlobalSystemTable->ConOut, L"\r\n");

    ERR("UEFI hand-off: starting the installed system's loader\n");
    Status = BootServices->LoadImage(FALSE, GlobalImageHandle, (EFI_DEVICE_PATH_PROTOCOL *)LoaderPath, NULL, 0, &Image);
    if (!EFI_ERROR(Status))
    {
        Status = BootServices->StartImage(Image, NULL, NULL);
        /* It returns only if it failed before taking over */
        BootServices->UnloadImage(Image);
    }
    ERR("UEFI hand-off: the installed system's loader failed (0x%lx), booting from the medium\n", (ULONG)Status);
    GlobalSystemTable->ConOut->OutputString(GlobalSystemTable->ConOut,
        L"The installed system could not be started: booting from the medium.\r\n");
    NvFree(LoaderPath);
}

#endif /* NV_OWN_LOADER_PATH */

/* This loader was started from an optical disc (UefiBootEntryInit) */
static BOOLEAN NvStartedFromDisc = FALSE;

/*
 * Setup is about to start from an optical disc. Its first stage ends with a
 * restart, and the firmware then starts the first option of BootOrder, which
 * need not be this disc: it may be another system's, or the disk's own option
 * that started the removable-media path of another system. BootNext (UEFI
 * 2.10, 3.1.2: one boot from the given option, then deleted by the firmware)
 * names the option that started us, so the disc comes back once and hands
 * over to the installed system, which adds its boot option. Nothing is
 * written when that option is the first the firmware tries anyway.
 */
VOID
UefiBootThisMediumNext(VOID)
{
#ifdef NV_OWN_LOADER_PATH
    UCHAR *Data = NULL;
    UINTN Size, i;
    UINT16 Current, First = 0;
    BOOLEAN HaveFirst = FALSE;
    EFI_STATUS Status;

    if (!NvStartedFromDisc)
        return;

    if (EFI_ERROR(NvGetVariable(L"BootCurrent", &NvGlobalVariableGuid, &Data, &Size)) || Size < 2)
    {
        NvFree(Data);
        ERR("UEFI boot entry: no BootCurrent, BootNext not set\n");
        return;
    }
    Current = (UINT16)(Data[0] | (Data[1] << 8));
    NvFree(Data);

    /* The first option the firmware starts: active, not hidden, of the boot category */
    if (!EFI_ERROR(NvGetVariable(L"BootOrder", &NvGlobalVariableGuid, &Data, &Size)))
    {
        for (i = 0; i + 1 < Size && !HaveFirst; i += 2)
        {
            UINT16 Entry = (UINT16)(Data[i] | (Data[i + 1] << 8));
            UINT32 Attributes = NvOptionAttributes(Entry);

            if ((Attributes & LOAD_OPTION_ACTIVE) && !(Attributes & LOAD_OPTION_HIDDEN) &&
                (Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT)
            {
                First = Entry;
                HaveFirst = TRUE;
            }
        }
        NvFree(Data);
    }
    if (HaveFirst && First == Current)
    {
        ERR("UEFI boot entry: Boot%04X (this disc) comes first in BootOrder, BootNext not needed\n", Current);
        return;
    }

    Status = NvSetVariable(L"BootNext", &NvGlobalVariableGuid, "BootNext", &Current, sizeof(Current));
    if (EFI_ERROR(Status))
        ERR("UEFI boot entry: the firmware refused BootNext (0x%lx)\n", (ULONG)Status);
#endif
}

VOID
UefiBootEntryInit(VOID)
{
#ifdef NV_OWN_LOADER_PATH
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
    EFI_DEVICE_PATH_PROTOCOL *Path;
    EFI_BLOCK_IO *BlockIo = NULL;
    NV_PATH_INFO *Ours = NvAlloc(sizeof(*Ours));

    if (!Ours)
        return;
    if (EFI_ERROR(GlobalSystemTable->BootServices->HandleProtocol(GlobalImageHandle, &NvLoadedImageGuid, (VOID**)&LoadedImage)) ||
        !LoadedImage || !LoadedImage->DeviceHandle ||
        !NvGetHandlePath(LoadedImage->DeviceHandle, &Path) ||
        !NvParseDevicePath(Path, NV_NO_LIMIT, Ours))
    {
        NvFree(Ours);
        return;
    }

    /* An optical disc: CD-ROM media node, or the 2048-byte removable medium of a firmware that has none */
    if (!Ours->HaveCd && !Ours->HaveHd &&
        !EFI_ERROR(GlobalSystemTable->BootServices->HandleProtocol(LoadedImage->DeviceHandle, &NvBlockIoGuid, (VOID**)&BlockIo)) &&
        BlockIo && BlockIo->Media->RemovableMedia && BlockIo->Media->BlockSize == 2048)
    {
        Ours->HaveCd = TRUE;
    }

    if (Ours->HaveCd)
    {
        NvFree(Ours);
        NvStartedFromDisc = TRUE;
        NvHandOffToInstalledSystem();
        return;
    }

    /*
     * A hard disk partition (the hard drive node is the last node of its path)
     * with our loader directory: an installed system.
     */
    if (Ours->HaveHd && Ours->HdOffset + NV_HD_NODE_LENGTH == Ours->Length &&
        (Ours->Hd.SignatureType == SIGNATURE_TYPE_GUID || Ours->Hd.SignatureType == SIGNATURE_TYPE_MBR) &&
        NvFileExists(LoadedImage->DeviceHandle, NV_OWN_LOADER_PATH))
    {
        NvEnsureBootEntry(Ours, (const UCHAR *)Path);
    }
    NvFree(Ours);
#endif
}
