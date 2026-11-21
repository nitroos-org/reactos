/*
 * PROJECT:         ReactOS DiskPart
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            base/system/diskpart/tablecheck.c
 * PURPOSE:         Tells whether the partition table that is on a disk can be relied on
 *                  before a command writes a table (and refuses if not). No repair.
 */

#include "diskpart.h"

#define NDEBUG
#include <debug.h>

/* The rules of the kernel's reader (FstubReadHeaderEFI, FstubDetectPartitionStyle) */
#define GPT_HEADER_SIGNATURE    0x5452415020494645ULL
#define GPT_HEADER_REVISION_1   0x00010000
#define GPT_HEADER_SIZE         92
#define GPT_ENTRY_SIZE          128
#define GPT_MIN_ENTRIES         128
#define GPT_MAX_ENTRIES         4096
#define MBR_TYPE_EFI_PROTECTIVE 0xEE

typedef enum _GPT_COPY_STATE
{
    GptCopyOk,
    GptCopyBad,
    GptCopyUnsupported
} GPT_COPY_STATE;

static
ULONG
Crc32(
    _In_ ULONG Crc,
    _In_ const UCHAR *Buffer,
    _In_ ULONG Length)
{
    ULONG i, k;

    Crc = ~Crc;
    for (i = 0; i < Length; i++)
    {
        Crc ^= Buffer[i];
        for (k = 0; k < 8; k++)
            Crc = (Crc >> 1) ^ (0xEDB88320UL & (0UL - (Crc & 1)));
    }

    return ~Crc;
}

static
NTSTATUS
ReadSectors(
    _In_ HANDLE FileHandle,
    _In_ ULONG BytesPerSector,
    _In_ ULONGLONG Lba,
    _In_ ULONG Count,
    _Out_ PUCHAR Buffer)
{
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Offset;

    Offset.QuadPart = (LONGLONG)(Lba * BytesPerSector);
    return NtReadFile(FileHandle, NULL, NULL, NULL, &Iosb, Buffer, Count * BytesPerSector, &Offset, NULL);
}

/* One copy of the GPT (primary: LBA 1, backup: last sector) by the rules of the kernel's reader */
static
GPT_COPY_STATE
CheckGptCopy(
    _In_ HANDLE FileHandle,
    _In_ ULONG BytesPerSector,
    _In_ ULONGLONG TotalSectors,
    _In_ ULONGLONG Lba)
{
    PUCHAR Sector, Array = NULL;
    UCHAR Header[GPT_HEADER_SIZE];
    GPT_COPY_STATE State = GptCopyBad;
    ULONGLONG MyLba, FirstUsable, LastUsable, EntryLba;
    ULONG Revision, HeaderSize, HeaderCrc, Entries, EntrySize, ArrayCrc, EntrySectors;

    if (TotalSectors < 3 || Lba >= TotalSectors)
        return GptCopyBad;

    Sector = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector);
    if (Sector == NULL)
        return GptCopyBad;

    if (!NT_SUCCESS(ReadSectors(FileHandle, BytesPerSector, Lba, 1, Sector)))
        goto done;

    Revision = *(PULONG)(Sector + 8);
    HeaderSize = *(PULONG)(Sector + 12);
    HeaderCrc = *(PULONG)(Sector + 16);
    MyLba = *(PULONGLONG)(Sector + 24);
    FirstUsable = *(PULONGLONG)(Sector + 40);
    LastUsable = *(PULONGLONG)(Sector + 48);
    EntryLba = *(PULONGLONG)(Sector + 72);
    Entries = *(PULONG)(Sector + 80);
    EntrySize = *(PULONG)(Sector + 84);
    ArrayCrc = *(PULONG)(Sector + 88);

    if (*(PULONGLONG)Sector != GPT_HEADER_SIGNATURE ||
        Revision != GPT_HEADER_REVISION_1 ||
        HeaderSize != GPT_HEADER_SIZE)
    {
        goto done;
    }

    RtlCopyMemory(Header, Sector, GPT_HEADER_SIZE);
    *(PULONG)(Header + 16) = 0;
    if (Crc32(0, Header, GPT_HEADER_SIZE) != HeaderCrc)
        goto done;

    if (MyLba != Lba)
        goto done;

    /* The entry size and count the code (and the partition manager) works with */
    if (EntrySize != GPT_ENTRY_SIZE || Entries < GPT_MIN_ENTRIES || Entries > GPT_MAX_ENTRIES)
    {
        State = GptCopyUnsupported;
        goto done;
    }

    EntrySectors = (Entries * GPT_ENTRY_SIZE + BytesPerSector - 1) / BytesPerSector;
    if (EntryLba < 2 || EntryLba >= TotalSectors ||
        EntrySectors > TotalSectors - EntryLba ||
        FirstUsable < 2 || FirstUsable > LastUsable || LastUsable >= TotalSectors)
    {
        goto done;
    }

    Array = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, EntrySectors * BytesPerSector);
    if (Array == NULL)
        goto done;

    if (!NT_SUCCESS(ReadSectors(FileHandle, BytesPerSector, EntryLba, EntrySectors, Array)))
        goto done;

    if (Crc32(0, Array, Entries * GPT_ENTRY_SIZE) != ArrayCrc)
        goto done;

    State = GptCopyOk;

done:
    if (Array != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Array);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Sector);
    return State;
}

/*
 * Can the partition table that is on the disk be relied on? Not when the disk is RAW (the kernel
 * found no table), when the MBR has a protective (0xEE) entry beside other entries, when a disk
 * with a protective MBR has no GPT header and entry array that pass the kernel's checks in BOTH
 * copies (a good primary beside a damaged backup is refused too), or when the header claims an
 * entry size or count that is not supported. Nothing is repaired. The state is read from the disk
 * each time (a table that was just written by CONVERT is judged by what is on the disk).
 */
BOOLEAN
IsPartitionTableUsable(
    _In_ PDISKENTRY DiskEntry,
    _Out_ PCWSTR *Reason)
{
    WCHAR Path[MAX_PATH];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Iosb;
    GET_LENGTH_INFORMATION Length;
    HANDLE FileHandle = NULL;
    PUCHAR Sector = NULL;
    ULONG BytesPerSector = DiskEntry->BytesPerSector;
    ULONGLONG Total;
    ULONG i, Protective = 0, Others = 0;
    GPT_COPY_STATE Primary, Backup;
    BOOLEAN Usable = FALSE;
    NTSTATUS Status;

    *Reason = L"the disk could not be examined";

    if (DiskEntry->PartitionStyle != PARTITION_STYLE_MBR &&
        DiskEntry->PartitionStyle != PARTITION_STYLE_GPT)
    {
        *Reason = L"the disk is not initialized: the system found no partition table on it";
        return FALSE;
    }

    if (BytesPerSector == 0)
        return FALSE;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"\\Device\\Harddisk%lu\\Partition0", DiskEntry->DiskNumber);
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = NtDeviceIoControlFile(FileHandle, NULL, NULL, NULL, &Iosb, IOCTL_DISK_GET_LENGTH_INFO,
                                   NULL, 0, &Length, sizeof(Length));
    if (!NT_SUCCESS(Status))
        goto done;
    Total = (ULONGLONG)Length.Length.QuadPart / BytesPerSector;

    Sector = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BytesPerSector);
    if (Sector == NULL)
        goto done;

    if (!NT_SUCCESS(ReadSectors(FileHandle, BytesPerSector, 0, 1, Sector)))
    {
        *Reason = L"the first sector of the disk could not be read";
        goto done;
    }

    if (*(PUSHORT)(Sector + 510) != 0xAA55)
    {
        *Reason = L"the disk has no valid master boot record (the system treats it as not initialized)";
        goto done;
    }

    for (i = 0; i < 4; i++)
    {
        UCHAR Type = Sector[446 + 16 * i + 4];

        if (Type == MBR_TYPE_EFI_PROTECTIVE)
            Protective++;
        else if (Type != 0)
            Others++;
    }

    if (DiskEntry->PartitionStyle == PARTITION_STYLE_MBR)
    {
        if (Protective != 0)
        {
            *Reason = L"the master boot record has a protective (0xEE) entry together with other entries (a hybrid or damaged table)";
            goto done;
        }

        Usable = TRUE;
        goto done;
    }

    /* GPT: the protective MBR must be the one entry, and both copies of the GPT must be good */
    if (Protective != 1 || Others != 0 || Sector[446 + 4] != MBR_TYPE_EFI_PROTECTIVE)
    {
        *Reason = L"the protective master boot record of the GPT has other entries or is not the first entry";
        goto done;
    }

    Primary = CheckGptCopy(FileHandle, BytesPerSector, Total, 1);
    Backup = CheckGptCopy(FileHandle, BytesPerSector, Total, Total - 1);

    if (Primary == GptCopyOk && Backup == GptCopyOk)
    {
        Usable = TRUE;
    }
    else if (Primary == GptCopyUnsupported || Backup == GptCopyUnsupported)
    {
        *Reason = L"the GPT header claims an entry size or entry count that is not supported";
    }
    else if (Primary != GptCopyOk && Backup != GptCopyOk)
    {
        *Reason = L"both copies of the GPT (header or entry array) are damaged";
    }
    else if (Primary != GptCopyOk)
    {
        *Reason = L"the primary copy of the GPT (header or entry array) is damaged, only the backup is good";
    }
    else
    {
        *Reason = L"the backup copy of the GPT (header or entry array) is damaged, only the primary is good";
    }

done:
    if (Sector != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Sector);
    if (FileHandle != NULL)
        NtClose(FileHandle);
    return Usable;
}
