/*
 * Copyright (C) 1998-2005 ReactOS Team (and the authors from the programmers section)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *
 * PROJECT:         ReactOS kernel
 * PURPOSE:         Implements section objects
 *
 * PROGRAMMERS:     Rex Jolliff
 *                  David Welch
 *                  Eric Kohl
 *                  Emanuele Aliberti
 *                  Eugene Ingerman
 *                  Casper Hornstrup
 *                  KJK::Hyperion
 *                  Guido de Jong
 *                  Ge van Geldorp
 *                  Royce Mitchell III
 *                  Filip Navara
 *                  Aleksey Bragin
 *                  Jason Filby
 *                  Thomas Weidenmueller
 *                  Gunnar Andre' Dalsnes
 *                  Mike Nordell
 *                  Alex Ionescu
 *                  Gregor Anich
 *                  Steven Edwards
 *                  Herve Poussineau
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#include <cache/newcc.h>
#include <cache/section/newmm.h>
#define NDEBUG
#include <debug.h>
#include <reactos/exeformat.h>

#include "ARM3/miarm.h"

#undef MmSetPageEntrySectionSegment
#define MmSetPageEntrySectionSegment(S,O,E) \
        _MmSetPageEntrySectionSegment((S),(O),(E),__FILE__,__LINE__)

extern MMSESSION MmSession;

static LARGE_INTEGER TinyTime = {{-1L, -1L}};

/* A demand page-in read can hit a transient backing-store failure: a disk that is
   briefly slow, or that the storage stack reset and recovered under load. Windows
   treats STATUS_IN_PAGE_ERROR as rare and retryable; the in-page path rides out a
   retryable failure instead of letting it bugcheck the faulting thread
   (STOP 0x7E / 0xC0000006 on kernel code). We do the same for section and image
   page-ins: a small bounded number of retries with a short growing backoff, which
   lets a transient slow or just-reset disk complete the read. */
#define MI_MAX_INPAGE_RETRIES 3
/* Backoff base in 100ns units; grows per attempt (30ms, 60ms, 90ms). */
#define MI_INPAGE_RETRY_INTERVAL (30 * 10 * 1000)

static
BOOLEAN
MiIsTransientInPageError(NTSTATUS Status)
{
    switch (Status)
    {
        case STATUS_IO_TIMEOUT:           /* SRB_STATUS_TIMEOUT / COMMAND_TIMEOUT */
        case STATUS_IO_DEVICE_ERROR:      /* SRB_STATUS_BUS_RESET and generic device errors */
        case STATUS_DEVICE_NOT_READY:
        case STATUS_DEVICE_NOT_CONNECTED: /* SRB_STATUS_SELECTION_TIMEOUT during a reset */
            return TRUE;
        default:
            return FALSE;
    }
}

/* Serializes NtExtendSection's size decisions with its file growth; taken before any file-system lock */
static ERESOURCE MmpExtendSectionLock;

#ifndef NEWCC
KEVENT MmWaitPageEvent;

VOID
NTAPI
_MmLockSectionSegment(PMM_SECTION_SEGMENT Segment, const char *file, int line)
{
    //DPRINT("MmLockSectionSegment(%p,%s:%d)\n", Segment, file, line);
    ExAcquireFastMutex(&Segment->Lock);
    Segment->Locked = TRUE;
}

VOID
NTAPI
_MmUnlockSectionSegment(PMM_SECTION_SEGMENT Segment, const char *file, int line)
{
    ASSERT(Segment->Locked);
    Segment->Locked = FALSE;
    ExReleaseFastMutex(&Segment->Lock);
    //DPRINT("MmUnlockSectionSegment(%p,%s:%d)\n", Segment, file, line);
}
#endif

static
PMM_SECTION_SEGMENT
MiGrabDataSection(PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
    KIRQL OldIrql = MiAcquirePfnLock();
    PMM_SECTION_SEGMENT Segment = NULL;

    while (TRUE)
    {
        Segment = SectionObjectPointer->DataSectionObject;
        if (!Segment)
            break;

        if (Segment->SegFlags & (MM_SEGMENT_INCREATE | MM_SEGMENT_INDELETE))
        {
            MiReleasePfnLock(OldIrql);
            KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
            OldIrql = MiAcquirePfnLock();
            continue;
        }

        ASSERT(Segment->SegFlags & MM_DATAFILE_SEGMENT);
        InterlockedIncrement64(&Segment->RefCount);
        break;
    }

    MiReleasePfnLock(OldIrql);

    return Segment;
}

/* Somewhat grotesque, but eh... */
PMM_IMAGE_SECTION_OBJECT ImageSectionObjectFromSegment(PMM_SECTION_SEGMENT Segment)
{
    ASSERT((Segment->SegFlags & MM_DATAFILE_SEGMENT) == 0);

    return CONTAINING_RECORD(Segment->ReferenceCount, MM_IMAGE_SECTION_OBJECT, RefCount);
}

NTSTATUS
MiMapViewInSystemSpace(IN PVOID Section,
                       IN PVOID Session,
                       OUT PVOID *MappedBase,
                       IN OUT PSIZE_T ViewSize,
                       IN PLARGE_INTEGER SectionOffset);

NTSTATUS
NTAPI
MmCreateArm3Section(OUT PVOID *SectionObject,
                    IN ACCESS_MASK DesiredAccess,
                    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                    IN PLARGE_INTEGER InputMaximumSize,
                    IN ULONG SectionPageProtection,
                    IN ULONG AllocationAttributes,
                    IN HANDLE FileHandle OPTIONAL,
                    IN PFILE_OBJECT FileObject OPTIONAL);

NTSTATUS
NTAPI
MmMapViewOfArm3Section(
    _In_ PVOID SectionObject,
    _In_ PEPROCESS Process,
    _Outptr_result_bytebuffer_(*ViewSize)
      _When_(*ViewSize != 0, _Pre_opt_valid_)
      _When_(*ViewSize == 0, _Pre_valid_)
        PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_range_(ViewShare, ViewUnmap) SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect,
    _In_ ULONG_PTR LowestAddress,
    _In_ ULONG_PTR HighestBound);

//
// PeFmtCreateSection depends on the following:
//
C_ASSERT(EXEFMT_LOAD_HEADER_SIZE >= sizeof(IMAGE_DOS_HEADER));
C_ASSERT(sizeof(IMAGE_NT_HEADERS32) <= sizeof(IMAGE_NT_HEADERS64));

C_ASSERT(TYPE_ALIGNMENT(IMAGE_NT_HEADERS32) == TYPE_ALIGNMENT(IMAGE_NT_HEADERS64));
C_ASSERT(RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, FileHeader) == RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS64, FileHeader));
C_ASSERT(FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) == FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader));

C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, Magic));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, SectionAlignment));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, FileAlignment));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, Subsystem));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, MinorSubsystemVersion));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, MajorSubsystemVersion));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, SizeOfCode));
C_ASSERT(PEFMT_FIELDS_EQUAL(IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64, SizeOfHeaders));

/* TYPES *********************************************************************/

typedef struct
{
    PMEMORY_AREA MemoryArea;
    PMM_SECTION_SEGMENT Segment;
    LARGE_INTEGER Offset;
    BOOLEAN WasDirty;
    BOOLEAN Private;
    PEPROCESS CallingProcess;
    ULONG_PTR SectionEntry;
}
MM_SECTION_PAGEOUT_CONTEXT;

/* GLOBALS *******************************************************************/

POBJECT_TYPE MmSectionObjectType = NULL;

ULONG_PTR MmSubsectionBase;

static ULONG SectionCharacteristicsToProtect[16] =
{
    PAGE_NOACCESS,          /* 0 = NONE */
    PAGE_NOACCESS,          /* 1 = SHARED */
    PAGE_EXECUTE,           /* 2 = EXECUTABLE */
    PAGE_EXECUTE,           /* 3 = EXECUTABLE, SHARED */
    PAGE_READONLY,          /* 4 = READABLE */
    PAGE_READONLY,          /* 5 = READABLE, SHARED */
    PAGE_EXECUTE_READ,      /* 6 = READABLE, EXECUTABLE */
    PAGE_EXECUTE_READ,      /* 7 = READABLE, EXECUTABLE, SHARED */
    /*
     * FIXME? do we really need the WriteCopy field in segments? can't we use
     * PAGE_WRITECOPY here?
     */
    PAGE_READWRITE,         /* 8 = WRITABLE */
    PAGE_READWRITE,         /* 9 = WRITABLE, SHARED */
    PAGE_EXECUTE_READWRITE, /* 10 = WRITABLE, EXECUTABLE */
    PAGE_EXECUTE_READWRITE, /* 11 = WRITABLE, EXECUTABLE, SHARED */
    PAGE_READWRITE,         /* 12 = WRITABLE, READABLE */
    PAGE_READWRITE,         /* 13 = WRITABLE, READABLE, SHARED */
    PAGE_EXECUTE_READWRITE, /* 14 = WRITABLE, READABLE, EXECUTABLE */
    PAGE_EXECUTE_READWRITE, /* 15 = WRITABLE, READABLE, EXECUTABLE, SHARED */
};

extern ACCESS_MASK MmMakeFileAccess[8];
static GENERIC_MAPPING MmpSectionMapping =
{
    STANDARD_RIGHTS_READ | SECTION_MAP_READ | SECTION_QUERY,
    STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE,
    STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE,
    SECTION_ALL_ACCESS
};


/* FUNCTIONS *****************************************************************/



/* Adjacent dirty pages of a data file that one flush writes with one paging write (64 KB) */
#define MM_FLUSH_CLUSTER_PAGES 16

static
NTSTATUS
MiWritePages(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG SegOffset,
    _In_reads_(Count) PPFN_NUMBER Pages,
    _In_ ULONG Count)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    KEVENT Event;
    PFN_NUMBER MdlBuffer[(sizeof(MDL) + sizeof(PFN_NUMBER) - 1) / sizeof(PFN_NUMBER) + MM_FLUSH_CLUSTER_PAGES];
    PMDL Mdl = (PMDL)MdlBuffer;
    PFILE_OBJECT FileObject = Segment->FileObject;
    LARGE_INTEGER FileOffset;

    ASSERT((Count != 0) && (Count <= MM_FLUSH_CLUSTER_PAGES));

    FileOffset.QuadPart = Segment->Image.FileOffset + SegOffset;

    RtlZeroMemory(MdlBuffer, sizeof(MdlBuffer));
    MmInitializeMdl(Mdl, NULL, Count * PAGE_SIZE);
    MmBuildMdlFromPages(Mdl, Pages);
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Status = IoSynchronousPageWrite(FileObject, Mdl, &FileOffset, &Event, &IoStatus);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }
    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
    {
        MmUnmapLockedPages (Mdl->MappedSystemVa, Mdl);
    }

    if (NT_SUCCESS(Status))
    {
        InterlockedExchangeAdd(&MiReclaimProgress, (LONG)Count);
        MI_PRCB_COUNT_ADD(MmMappedPagesWriteCount, Count);
        MI_PRCB_COUNT_ADD(MmMappedWriteIoCount, 1);
    }

    return Status;
}

NTSTATUS
NTAPI
MiWritePage(PMM_SECTION_SEGMENT Segment,
            LONGLONG SegOffset,
            PFN_NUMBER Page)
/*
 * FUNCTION: write a page for a section backed memory area.
 * PARAMETERS:
 *       MemoryArea - Memory area to write the page for.
 *       Offset - Offset of the page to write.
 *       Page - Page which contains the data to write.
 */
{
    return MiWritePages(Segment, SegOffset, &Page, 1);
}


/* Windows creates image sections only for the machines that go with each
 * header format; an image of another machine fails at creation. Windows 7
 * still takes IA64 for PE32+ (Windows 10 does not) */
static
BOOLEAN
PeFmtIsMachineForMagic(USHORT Magic, USHORT Machine)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    if (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return (Machine == IMAGE_FILE_MACHINE_I386);
    return (Machine == IMAGE_FILE_MACHINE_AMD64) || (Machine == IMAGE_FILE_MACHINE_IA64);
#else
    /* Not measured on other architectures */
    UNREFERENCED_PARAMETER(Magic);
    UNREFERENCED_PARAMETER(Machine);
    return TRUE;
#endif
}

/* The COM descriptor (the .NET runtime header) and its COMIMAGE_FLAGS_* */
#define PEFMT_COR20_HEADER_SIZE             0x48
#define PEFMT_COMIMAGE_FLAGS_ILONLY         0x00000001
#define PEFMT_COMIMAGE_FLAGS_32BITREQUIRED  0x00000002
#define PEFMT_COMIMAGE_FLAGS_32BITPREFERRED 0x00020000

typedef struct _PEFMT_COR20_PREFIX
{
    ULONG cb;
    USHORT MajorRuntimeVersion;
    USHORT MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    ULONG Flags;
} PEFMT_COR20_PREFIX, *PPEFMT_COR20_PREFIX;

/*
 * The .NET image flags of the image information, as measured on Windows 10 22H2: the descriptor must be complete
 * (its size in the directory) and in the file data of the image, and the runtime version at least 2.5 (older images
 * are for .NET 1.x, which has no 64-bit runtime). Then an IL-only image is ComPlusILOnly; a PE32 one is also
 * ComPlusNativeReady unless it requires 32 bits without preferring them (Prefer32Bit sets both bits), and
 * ComPlusPrefer32bit when it prefers them. The 64-bit kernel starts a native-ready PE32 image that does not prefer
 * 32 bits as a 64-bit process. A descriptor that cannot be read only leaves the flags clear.
 */
static
VOID
PeFmtSetComPlusFlags(
    _In_ PVOID File,
    _Inout_ PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
    _In_ USHORT Magic,
    _In_ ULONG ComRva,
    _In_ ULONG ComSize,
    _In_ PEXEFMT_CB_READ_FILE ReadFileCb)
{
    PMM_SECTION_SEGMENT Segments = ImageSectionObject->Segments;
    PSECTION_IMAGE_INFORMATION Info = &ImageSectionObject->ImageInformation;
    LARGE_INTEGER Offset;
    PPEFMT_COR20_PREFIX Cor;
    PVOID Data, Buffer = NULL;
    ULONG ReadSize, Flags, i;
    ULONGLONG Delta = 0;
    NTSTATUS Status;

    if (ComSize < PEFMT_COR20_HEADER_SIZE)
        return;

    /* Find the descriptor in the raw data of a segment (the headers are segment 0) */
    for (i = 0; i < ImageSectionObject->NrSegments; i++)
    {
        if (ComRva < Segments[i].Image.VirtualAddress)
            continue;
        Delta = ComRva - Segments[i].Image.VirtualAddress;
        if ((ULONGLONG)Segments[i].RawLength.QuadPart >= PEFMT_COR20_HEADER_SIZE &&
            Delta <= (ULONGLONG)Segments[i].RawLength.QuadPart - PEFMT_COR20_HEADER_SIZE)
        {
            break;
        }
    }
    if (i == ImageSectionObject->NrSegments)
        return;

    Offset.QuadPart = Segments[i].Image.FileOffset + Delta;
    Status = ReadFileCb(File, &Offset, PEFMT_COR20_HEADER_SIZE, &Data, &Buffer, &ReadSize);
    if (!NT_SUCCESS(Status))
        return;
    if (ReadSize >= sizeof(PEFMT_COR20_PREFIX))
    {
        Cor = Data;
        Flags = Cor->Flags;
        if ((Flags & PEFMT_COMIMAGE_FLAGS_ILONLY) &&
            (Cor->MajorRuntimeVersion > 2 || (Cor->MajorRuntimeVersion == 2 && Cor->MinorRuntimeVersion >= 5)))
        {
            Info->ComPlusILOnly = 1;
            if (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                if (!(Flags & PEFMT_COMIMAGE_FLAGS_32BITREQUIRED) || (Flags & PEFMT_COMIMAGE_FLAGS_32BITPREFERRED))
                    Info->ComPlusNativeReady = 1;
                if (Flags & PEFMT_COMIMAGE_FLAGS_32BITPREFERRED)
                    Info->ComPlusPrefer32bit = 1;
            }
        }
    }
    ExFreePool(Buffer);
}

/*
 References:
  [1] Microsoft Corporation, "Microsoft Portable Executable and Common Object
      File Format Specification", revision 6.0 (February 1999)
*/
NTSTATUS NTAPI PeFmtCreateSection(IN CONST VOID * FileHeader,
                                  IN SIZE_T FileHeaderSize,
                                  IN PVOID File,
                                  OUT PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
                                  OUT PULONG Flags,
                                  IN PEXEFMT_CB_READ_FILE ReadFileCb,
                                  IN PEXEFMT_CB_ALLOCATE_SEGMENTS AllocateSegmentsCb)
{
    NTSTATUS nStatus;
    ULONG cbFileHeaderOffsetSize = 0;
    ULONG cbSectionHeadersOffset = 0;
    ULONG cbSectionHeadersSize;
    ULONG cbSectionHeadersOffsetSize = 0;
    ULONG cbOptHeaderSize;
    ULONG cbHeadersSize = 0;
    ULONG nSectionAlignment;
    ULONG nFileAlignment;
    ULONG_PTR ImageBase = 0;
    const IMAGE_DOS_HEADER * pidhDosHeader;
    const IMAGE_NT_HEADERS32 * pinhNtHeader;
    const IMAGE_OPTIONAL_HEADER32 * piohOptHeader;
    const IMAGE_SECTION_HEADER * pishSectionHeaders;
    PMM_SECTION_SEGMENT pssSegments;
    LARGE_INTEGER lnOffset;
    PVOID pBuffer;
    SIZE_T nPrevVirtualEndOfSegment = 0;
    ULONG nFileSizeOfHeaders = 0;
    ULONG i;
    ULONG AlignedLength;
    ULONG nSizeOfImage = MAXULONG;
    ULONGLONG AlignedSizeOfImage;
    LARGE_INTEGER FileSize;
    USHORT Magic;
    ULONG ComRva = 0, ComSize = 0;

    ASSERT(FileHeader);
    ASSERT(FileHeaderSize > 0);
    ASSERT(File);
    ASSERT(ImageSectionObject);
    ASSERT(ReadFileCb);
    ASSERT(AllocateSegmentsCb);

    ASSERT(Intsafe_CanOffsetPointer(FileHeader, FileHeaderSize));

    ASSERT(((UINT_PTR)FileHeader % TYPE_ALIGNMENT(IMAGE_DOS_HEADER)) == 0);

#define DIE(ARGS_) { DPRINT ARGS_; goto l_Return; }

    pBuffer = NULL;
    pidhDosHeader = FileHeader;

    /* DOS HEADER */
    nStatus = STATUS_ROS_EXEFMT_UNKNOWN_FORMAT;

    /* image too small to be an MZ executable */
    if(FileHeaderSize < sizeof(IMAGE_DOS_HEADER))
        DIE(("Too small to be an MZ executable, size is %lu\n", FileHeaderSize));

    /* no MZ signature */
    if(pidhDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        DIE(("No MZ signature found, e_magic is %hX\n", pidhDosHeader->e_magic));

    /* NT HEADER */
    nStatus = STATUS_INVALID_IMAGE_PROTECT;

    /* not a Windows executable */
    if(pidhDosHeader->e_lfanew <= 0)
        DIE(("Not a Windows executable, e_lfanew is %d\n", pidhDosHeader->e_lfanew));

    if(!Intsafe_AddULong32(&cbFileHeaderOffsetSize, pidhDosHeader->e_lfanew, RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, FileHeader)))
        DIE(("The DOS stub is too large, e_lfanew is %X\n", pidhDosHeader->e_lfanew));

    if(FileHeaderSize < cbFileHeaderOffsetSize)
        pinhNtHeader = NULL;
    else
    {
        /*
         * we already know that Intsafe_CanOffsetPointer(FileHeader, FileHeaderSize),
         * and FileHeaderSize >= cbFileHeaderOffsetSize, so this holds true too
         */
        ASSERT(Intsafe_CanOffsetPointer(FileHeader, pidhDosHeader->e_lfanew));
        pinhNtHeader = (PVOID)((UINT_PTR)FileHeader + pidhDosHeader->e_lfanew);
    }

    /*
     * the buffer doesn't contain the NT file header, or the alignment is wrong: we
     * need to read the header from the file
     */
    if(FileHeaderSize < cbFileHeaderOffsetSize ||
            (UINT_PTR)pinhNtHeader % TYPE_ALIGNMENT(IMAGE_NT_HEADERS32) != 0)
    {
        ULONG cbNtHeaderSize;
        ULONG cbReadSize;
        PVOID pData;

l_ReadHeaderFromFile:
        cbNtHeaderSize = 0;
        lnOffset.QuadPart = pidhDosHeader->e_lfanew;

        /* read the header from the file */
        nStatus = ReadFileCb(File, &lnOffset, sizeof(IMAGE_NT_HEADERS64), &pData, &pBuffer, &cbReadSize);

        if(!NT_SUCCESS(nStatus))
        {
            NTSTATUS ReturnedStatus = nStatus;

            /* If it attempted to read past the end of the file, it means e_lfanew is invalid */
            if (ReturnedStatus == STATUS_END_OF_FILE) nStatus = STATUS_INVALID_IMAGE_PROTECT;

            DIE(("ReadFile failed, status %08X\n", ReturnedStatus));
        }

        ASSERT(pData);
        ASSERT(pBuffer);
        ASSERT(cbReadSize > 0);

        nStatus = STATUS_INVALID_IMAGE_FORMAT;

        /* the buffer doesn't contain the file header */
        if(cbReadSize < RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, FileHeader))
            DIE(("The file doesn't contain the PE file header\n"));

        pinhNtHeader = pData;

        /* object still not aligned: copy it to the beginning of the buffer */
        if((UINT_PTR)pinhNtHeader % TYPE_ALIGNMENT(IMAGE_NT_HEADERS32) != 0)
        {
            ASSERT((UINT_PTR)pBuffer % TYPE_ALIGNMENT(IMAGE_NT_HEADERS32) == 0);
            RtlMoveMemory(pBuffer, pData, cbReadSize);
            pinhNtHeader = pBuffer;
        }

        /* invalid NT header */
        nStatus = STATUS_INVALID_IMAGE_PROTECT;

        if(pinhNtHeader->Signature != IMAGE_NT_SIGNATURE)
            DIE(("The file isn't a PE executable, Signature is %X\n", pinhNtHeader->Signature));

        nStatus = STATUS_INVALID_IMAGE_FORMAT;

        if(!Intsafe_AddULong32(&cbNtHeaderSize, pinhNtHeader->FileHeader.SizeOfOptionalHeader, FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader)))
            DIE(("The full NT header is too large\n"));

        /* the buffer doesn't contain the whole NT header */
        if(cbReadSize < cbNtHeaderSize)
            DIE(("The file doesn't contain the full NT header\n"));
    }
    else
    {
        ULONG cbOptHeaderOffsetSize = 0;

        nStatus = STATUS_INVALID_IMAGE_PROTECT;

        /* don't trust an invalid NT header */
        if(pinhNtHeader->Signature != IMAGE_NT_SIGNATURE)
            DIE(("The file isn't a PE executable, Signature is %X\n", pinhNtHeader->Signature));

        if(!Intsafe_AddULong32(&cbOptHeaderOffsetSize, pidhDosHeader->e_lfanew, FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader)))
            DIE(("The DOS stub is too large, e_lfanew is %X\n", pidhDosHeader->e_lfanew));

        nStatus = STATUS_INVALID_IMAGE_FORMAT;

        if(!Intsafe_AddULong32(&cbOptHeaderOffsetSize, cbOptHeaderOffsetSize, pinhNtHeader->FileHeader.SizeOfOptionalHeader))
            DIE(("The NT header is too large, SizeOfOptionalHeader is %X\n", pinhNtHeader->FileHeader.SizeOfOptionalHeader));

        /* the buffer doesn't contain the whole NT header: read it from the file */
        if(cbOptHeaderOffsetSize > FileHeaderSize)
            goto l_ReadHeaderFromFile;
    }

    /* read information from the NT header */
    piohOptHeader = &pinhNtHeader->OptionalHeader;
    cbOptHeaderSize = pinhNtHeader->FileHeader.SizeOfOptionalHeader;

    nStatus = STATUS_INVALID_IMAGE_FORMAT;

    if(!RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, Magic))
        DIE(("The optional header doesn't contain the Magic field, SizeOfOptionalHeader is %X\n", cbOptHeaderSize));

    /* ASSUME: RtlZeroMemory(ImageSectionObject, sizeof(*ImageSectionObject)); */

    switch(piohOptHeader->Magic)
    {
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
#ifndef _WIN64
            nStatus = STATUS_INVALID_IMAGE_WIN_64;
            DIE(("Win64 optional header, unsupported\n"));
#else
            // Fall through.
#endif
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            break;
        default:
            DIE(("Unrecognized optional header, Magic is %X\n", piohOptHeader->Magic));
    }

    if (!PeFmtIsMachineForMagic(piohOptHeader->Magic, pinhNtHeader->FileHeader.Machine))
        DIE(("Machine %X does not match optional header %X\n", pinhNtHeader->FileHeader.Machine, piohOptHeader->Magic));

    if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, SectionAlignment) &&
            RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, FileAlignment))
    {
        /* See [1], section 3.4.2 */
        if(piohOptHeader->SectionAlignment < PAGE_SIZE)
        {
            if(piohOptHeader->FileAlignment != piohOptHeader->SectionAlignment)
                DIE(("Sections aren't page-aligned and the file alignment isn't the same\n"));
        }
        else
        {
            if(piohOptHeader->SectionAlignment < piohOptHeader->FileAlignment)
                DIE(("The section alignment is smaller than the file alignment\n"));

            /* Windows refuses a file alignment below 512 in a page-aligned image */
            if(piohOptHeader->FileAlignment < 0x200)
                DIE(("The file alignment (%u) is below 512\n", piohOptHeader->FileAlignment));
        }

        nSectionAlignment = piohOptHeader->SectionAlignment;
        nFileAlignment = piohOptHeader->FileAlignment;

        if(!IsPowerOf2(nSectionAlignment) || !IsPowerOf2(nFileAlignment))
            DIE(("The section alignment (%u) and file alignment (%u) aren't both powers of 2\n", nSectionAlignment, nFileAlignment));
    }
    else
    {
        nSectionAlignment = PAGE_SIZE;
        nFileAlignment = PAGE_SIZE;
    }

    ASSERT(IsPowerOf2(nSectionAlignment));
    ASSERT(IsPowerOf2(nFileAlignment));

    switch(piohOptHeader->Magic)
    {
    /* PE32 */
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    {
        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, ImageBase))
            ImageBase = piohOptHeader->ImageBase;

        if(RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, SizeOfImage))
        {
            ImageSectionObject->ImageInformation.ImageFileSize = piohOptHeader->SizeOfImage;
            ImageSectionObject->SizeOfImage = piohOptHeader->SizeOfImage;
            nSizeOfImage = piohOptHeader->SizeOfImage;
        }

        if(RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, SizeOfStackReserve))
            ImageSectionObject->ImageInformation.MaximumStackSize = piohOptHeader->SizeOfStackReserve;

        if(RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, SizeOfStackCommit))
            ImageSectionObject->ImageInformation.CommittedStackSize = piohOptHeader->SizeOfStackCommit;

        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, Subsystem))
        {
            ImageSectionObject->ImageInformation.SubSystemType = piohOptHeader->Subsystem;

            if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, MinorSubsystemVersion) &&
                    RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, MajorSubsystemVersion))
            {
                ImageSectionObject->ImageInformation.SubSystemMinorVersion = piohOptHeader->MinorSubsystemVersion;
                ImageSectionObject->ImageInformation.SubSystemMajorVersion = piohOptHeader->MajorSubsystemVersion;
            }
        }

        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, AddressOfEntryPoint))
        {
            ImageSectionObject->ImageInformation.TransferAddress = (PVOID) (ImageBase +
                    piohOptHeader->AddressOfEntryPoint);
        }

        /* As in Windows: code size or an entry point */
        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, AddressOfEntryPoint))
            ImageSectionObject->ImageInformation.ImageContainsCode = (piohOptHeader->SizeOfCode != 0) ||
                                                                     (piohOptHeader->AddressOfEntryPoint != 0);
        else
            ImageSectionObject->ImageInformation.ImageContainsCode = TRUE;

        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, LoaderFlags))
            ImageSectionObject->ImageInformation.LoaderFlags = piohOptHeader->LoaderFlags;

        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]) &&
            piohOptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            ComRva = piohOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
            ComSize = piohOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
        }

        if (RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, DllCharacteristics))
        {
            ImageSectionObject->ImageInformation.DllCharacteristics = piohOptHeader->DllCharacteristics;

            /*
             * Since we don't really implement SxS yet and LD doesn't supoprt /ALLOWISOLATION:NO, hard-code
             * this flag here, which will prevent the loader and other code from doing any .manifest or SxS
             * magic to any binary.
             *
             * This will break applications that depend on SxS when running with real Windows Kernel32/SxS/etc
             * but honestly that's not tested. It will also break them when running no ReactOS once we implement
             * the SxS support -- at which point, duh, this should be removed.
             *
             * But right now, any app depending on SxS is already broken anyway, so this flag only helps.
             */
            ImageSectionObject->ImageInformation.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;
        }

        break;
    }
#ifdef _WIN64
    /* PE64 */
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    {
        const IMAGE_OPTIONAL_HEADER64 * pioh64OptHeader;

        pioh64OptHeader = (const IMAGE_OPTIONAL_HEADER64 *)piohOptHeader;

        if(RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, ImageBase))
        {
            ImageBase = pioh64OptHeader->ImageBase;
            if(pioh64OptHeader->ImageBase > MAXULONG_PTR)
                DIE(("ImageBase exceeds the address space\n"));
        }

        if(RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, SizeOfImage))
        {
            if(pioh64OptHeader->SizeOfImage > MAXULONG_PTR)
                DIE(("SizeOfImage exceeds the address space\n"));

            ImageSectionObject->ImageInformation.ImageFileSize = pioh64OptHeader->SizeOfImage;
            ImageSectionObject->SizeOfImage = pioh64OptHeader->SizeOfImage;
            nSizeOfImage = pioh64OptHeader->SizeOfImage;
        }

        if(RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, SizeOfStackReserve))
        {
            if(pioh64OptHeader->SizeOfStackReserve > MAXULONG_PTR)
                DIE(("SizeOfStackReserve exceeds the address space\n"));

            ImageSectionObject->ImageInformation.MaximumStackSize = (ULONG_PTR) pioh64OptHeader->SizeOfStackReserve;
        }

        if(RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, SizeOfStackCommit))
        {
            if(pioh64OptHeader->SizeOfStackCommit > MAXULONG_PTR)
                DIE(("SizeOfStackCommit exceeds the address space\n"));

            ImageSectionObject->ImageInformation.CommittedStackSize = (ULONG_PTR) pioh64OptHeader->SizeOfStackCommit;
        }

        if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, Subsystem))
        {
            ImageSectionObject->ImageInformation.SubSystemType = pioh64OptHeader->Subsystem;

            if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, MinorSubsystemVersion) &&
                    RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, MajorSubsystemVersion))
            {
                ImageSectionObject->ImageInformation.SubSystemMinorVersion = pioh64OptHeader->MinorSubsystemVersion;
                ImageSectionObject->ImageInformation.SubSystemMajorVersion = pioh64OptHeader->MajorSubsystemVersion;
            }
        }

        if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, AddressOfEntryPoint))
        {
            ImageSectionObject->ImageInformation.TransferAddress = (PVOID) (ImageBase +
                    pioh64OptHeader->AddressOfEntryPoint);
        }

        /* As in Windows: code size or an entry point */
        if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, AddressOfEntryPoint))
            ImageSectionObject->ImageInformation.ImageContainsCode = (pioh64OptHeader->SizeOfCode != 0) ||
                                                                     (pioh64OptHeader->AddressOfEntryPoint != 0);
        else
            ImageSectionObject->ImageInformation.ImageContainsCode = TRUE;

        if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, LoaderFlags))
            ImageSectionObject->ImageInformation.LoaderFlags = pioh64OptHeader->LoaderFlags;

        if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]) &&
            pioh64OptHeader->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            ComRva = pioh64OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
            ComSize = pioh64OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
        }

        if (RTL_CONTAINS_FIELD(pioh64OptHeader, cbOptHeaderSize, DllCharacteristics))
            ImageSectionObject->ImageInformation.DllCharacteristics = pioh64OptHeader->DllCharacteristics;

        break;
    }
#endif // _WIN64
    }

    /* [1], section 3.4.2 */
    if((ULONG_PTR)ImageBase % 0x10000)
        DIE(("ImageBase is not aligned on a 64KB boundary"));

    /* Windows marks an image with a COM descriptor for the loader, on top of the header's loader flags */
    Magic = piohOptHeader->Magic;
    if (ComRva != 0 && ComSize != 0)
        ImageSectionObject->ImageInformation.LoaderFlags |= IMAGE_LOADER_FLAGS_COMPLUS;

    ImageSectionObject->ImageInformation.ImageCharacteristics = pinhNtHeader->FileHeader.Characteristics;
    ImageSectionObject->ImageInformation.Machine = pinhNtHeader->FileHeader.Machine;
    ImageSectionObject->ImageInformation.GpValue = 0;
    ImageSectionObject->ImageInformation.ZeroBits = 0;
    ImageSectionObject->BasedAddress = (PVOID)ImageBase;

    /* SECTION HEADERS */
    nStatus = STATUS_INVALID_IMAGE_FORMAT;

    /* see [1], section 3.3 */
    if(pinhNtHeader->FileHeader.NumberOfSections > 96)
        DIE(("Too many sections, NumberOfSections is %u\n", pinhNtHeader->FileHeader.NumberOfSections));

    /*
     * the additional segment is for the file's headers. They need to be present for
     * the benefit of the dynamic loader (to locate exports, defaults for thread
     * parameters, resources, etc.)
     */
    ImageSectionObject->NrSegments = pinhNtHeader->FileHeader.NumberOfSections + 1;

    /* file offset for the section headers */
    if(!Intsafe_AddULong32(&cbSectionHeadersOffset, pidhDosHeader->e_lfanew, FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader)))
        DIE(("Offset overflow\n"));

    if(!Intsafe_AddULong32(&cbSectionHeadersOffset, cbSectionHeadersOffset, pinhNtHeader->FileHeader.SizeOfOptionalHeader))
        DIE(("Offset overflow\n"));

    /* size of the section headers */
    ASSERT(Intsafe_CanMulULong32(pinhNtHeader->FileHeader.NumberOfSections, sizeof(IMAGE_SECTION_HEADER)));
    cbSectionHeadersSize = pinhNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

    if(!Intsafe_AddULong32(&cbSectionHeadersOffsetSize, cbSectionHeadersOffset, cbSectionHeadersSize))
        DIE(("Section headers too large\n"));

    /* size of the executable's headers */
    if(RTL_CONTAINS_FIELD(piohOptHeader, cbOptHeaderSize, SizeOfHeaders))
    {
//        if(!IsAligned(piohOptHeader->SizeOfHeaders, nFileAlignment))
//            DIE(("SizeOfHeaders is not aligned\n"));

        if(cbSectionHeadersSize > piohOptHeader->SizeOfHeaders)
            DIE(("The section headers overflow SizeOfHeaders\n"));

        cbHeadersSize = piohOptHeader->SizeOfHeaders;
    }
    else if(!AlignUp(&cbHeadersSize, cbSectionHeadersOffsetSize, nFileAlignment))
        DIE(("Overflow aligning the size of headers\n"));

    if(pBuffer)
    {
        ExFreePool(pBuffer);
        pBuffer = NULL;
    }
    /* WARNING: pinhNtHeader IS NO LONGER USABLE */
    /* WARNING: piohOptHeader IS NO LONGER USABLE */
    /* WARNING: pioh64OptHeader IS NO LONGER USABLE */

    if(FileHeaderSize < cbSectionHeadersOffsetSize)
        pishSectionHeaders = NULL;
    else
    {
        /*
         * we already know that Intsafe_CanOffsetPointer(FileHeader, FileHeaderSize),
         * and FileHeaderSize >= cbSectionHeadersOffsetSize, so this holds true too
         */
        ASSERT(Intsafe_CanOffsetPointer(FileHeader, cbSectionHeadersOffset));
        pishSectionHeaders = (PVOID)((UINT_PTR)FileHeader + cbSectionHeadersOffset);
    }

    /*
     * the buffer doesn't contain the section headers, or the alignment is wrong:
     * read the headers from the file
     */
    if(FileHeaderSize < cbSectionHeadersOffsetSize ||
            (UINT_PTR)pishSectionHeaders % TYPE_ALIGNMENT(IMAGE_SECTION_HEADER) != 0)
    {
        PVOID pData;
        ULONG cbReadSize;

        lnOffset.QuadPart = cbSectionHeadersOffset;

        /* read the header from the file */
        nStatus = ReadFileCb(File, &lnOffset, cbSectionHeadersSize, &pData, &pBuffer, &cbReadSize);

        if(!NT_SUCCESS(nStatus))
            DIE(("ReadFile failed with status %08X\n", nStatus));

        ASSERT(pData);
        ASSERT(pBuffer);
        ASSERT(cbReadSize > 0);

        nStatus = STATUS_INVALID_IMAGE_FORMAT;

        /* the buffer doesn't contain all the section headers */
        if(cbReadSize < cbSectionHeadersSize)
            DIE(("The file doesn't contain all of the section headers\n"));

        pishSectionHeaders = pData;

        /* object still not aligned: copy it to the beginning of the buffer */
        if((UINT_PTR)pishSectionHeaders % TYPE_ALIGNMENT(IMAGE_SECTION_HEADER) != 0)
        {
            ASSERT((UINT_PTR)pBuffer % TYPE_ALIGNMENT(IMAGE_SECTION_HEADER) == 0);
            RtlMoveMemory(pBuffer, pData, cbReadSize);
            pishSectionHeaders = pBuffer;
        }
    }

    /* SEGMENTS */
    /* allocate the segments */
    nStatus = STATUS_INSUFFICIENT_RESOURCES;
    ImageSectionObject->Segments = AllocateSegmentsCb(ImageSectionObject->NrSegments);

    if(ImageSectionObject->Segments == NULL)
        DIE(("AllocateSegments failed\n"));

    /* initialize the headers segment */
    pssSegments = ImageSectionObject->Segments;

//  ASSERT(IsAligned(cbHeadersSize, nFileAlignment));

    if(!AlignUp(&nFileSizeOfHeaders, cbHeadersSize, nFileAlignment))
        DIE(("Cannot align the size of the section headers\n"));

    nPrevVirtualEndOfSegment = ALIGN_UP_BY(cbHeadersSize, nSectionAlignment);
    if (nPrevVirtualEndOfSegment < cbHeadersSize)
        DIE(("Cannot align the size of the section headers\n"));

    pssSegments[0].Image.FileOffset = 0;
    pssSegments[0].Protection = PAGE_READONLY;
    pssSegments[0].Length.QuadPart = nPrevVirtualEndOfSegment;
    pssSegments[0].RawLength.QuadPart = nFileSizeOfHeaders;
    pssSegments[0].Image.VirtualAddress = 0;
    pssSegments[0].Image.Characteristics = 0;
    pssSegments[0].WriteCopy = TRUE;

    /* skip the headers segment */
    ++ pssSegments;

    nStatus = STATUS_INVALID_IMAGE_FORMAT;

    ASSERT(ImageSectionObject->RefCount > 0);

    /* convert the executable sections into segments. See also [1], section 4 */
    for(i = 0; i < ImageSectionObject->NrSegments - 1; ++ i)
    {
        ULONG nCharacteristics;

        /* validate the alignment */
        if(!IsAligned(pishSectionHeaders[i].VirtualAddress, nSectionAlignment))
            DIE(("Image.VirtualAddress[%u] is not aligned\n", i));

        /* sections must be contiguous, ordered by base address and non-overlapping */
        if(pishSectionHeaders[i].VirtualAddress != nPrevVirtualEndOfSegment)
            DIE(("Memory gap between section %u and the previous\n", i));

        /* ignore explicit BSS sections */
        if(pishSectionHeaders[i].PointerToRawData != 0 && pishSectionHeaders[i].SizeOfRawData != 0)
        {
            /* validate the alignment */
#if 0
            /* Yes, this should be a multiple of FileAlignment, but there's
             * stuff out there that isn't. We can cope with that
             */
            if(!IsAligned(pishSectionHeaders[i].SizeOfRawData, nFileAlignment))
                DIE(("SizeOfRawData[%u] is not aligned\n", i));
#endif

//            if(!IsAligned(pishSectionHeaders[i].PointerToRawData, nFileAlignment))
//                DIE(("PointerToRawData[%u] is not aligned\n", i));

            if(!Intsafe_CanAddULong32(pishSectionHeaders[i].PointerToRawData, pishSectionHeaders[i].SizeOfRawData))
                DIE(("SizeOfRawData[%u] too large\n", i));

            /* Windows refuses a file that does not hold the raw data of the
             * last section header; it does not check the other sections */
            if (i == ImageSectionObject->NrSegments - 2)
            {
                nStatus = FsRtlGetFileSize((PFILE_OBJECT)File, &FileSize);
                if (!NT_SUCCESS(nStatus))
                    DIE(("FsRtlGetFileSize failed with status %08X\n", nStatus));

                nStatus = STATUS_INVALID_IMAGE_FORMAT;
                if ((ULONGLONG)pishSectionHeaders[i].PointerToRawData + pishSectionHeaders[i].SizeOfRawData >
                    (ULONGLONG)FileSize.QuadPart)
                {
                    DIE(("Raw data of the last section is beyond the end of the file\n"));
                }
            }

            /* conversion */
            pssSegments[i].Image.FileOffset = pishSectionHeaders[i].PointerToRawData;
            pssSegments[i].RawLength.QuadPart = pishSectionHeaders[i].SizeOfRawData;
        }
        else
        {
            /* FIXME: Should reset PointerToRawData to 0 in the image mapping */
            ASSERT(pssSegments[i].Image.FileOffset == 0);
            ASSERT(pssSegments[i].RawLength.QuadPart == 0);
        }

        ASSERT(Intsafe_CanAddLong64(pssSegments[i].Image.FileOffset, pssSegments[i].RawLength.QuadPart));

        nCharacteristics = pishSectionHeaders[i].Characteristics;

        /* no explicit protection */
        if((nCharacteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) == 0)
        {
            if(nCharacteristics & IMAGE_SCN_CNT_CODE)
                nCharacteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

            if(nCharacteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
                nCharacteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

            if(nCharacteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                nCharacteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        }

        /* see table above */
        pssSegments[i].Protection = SectionCharacteristicsToProtect[nCharacteristics >> 28];
        pssSegments[i].WriteCopy = !(nCharacteristics & IMAGE_SCN_MEM_SHARED);

        if(pishSectionHeaders[i].Misc.VirtualSize == 0)
            pssSegments[i].Length.QuadPart = pishSectionHeaders[i].SizeOfRawData;
        else
            pssSegments[i].Length.QuadPart = pishSectionHeaders[i].Misc.VirtualSize;

        AlignedLength = ALIGN_UP_BY(pssSegments[i].Length.LowPart, nSectionAlignment);
        if(AlignedLength < pssSegments[i].Length.LowPart)
            DIE(("Cannot align the virtual size of section %u\n", i));

        pssSegments[i].Length.LowPart = AlignedLength;

        if(pssSegments[i].Length.QuadPart == 0)
            DIE(("Virtual size of section %u is null\n", i));

        pssSegments[i].Image.VirtualAddress = pishSectionHeaders[i].VirtualAddress;
        pssSegments[i].Image.Characteristics = pishSectionHeaders[i].Characteristics;

        /* ensure the memory image is no larger than 4GB */
        nPrevVirtualEndOfSegment = (ULONG_PTR)(pssSegments[i].Image.VirtualAddress + pssSegments[i].Length.QuadPart);
        if (nPrevVirtualEndOfSegment < pssSegments[i].Image.VirtualAddress)
            DIE(("The image is too large\n"));
    }

    /* Windows refuses a SizeOfImage that does not cover every section, and
     * an image without sections that ends with its headers */
    if (nSizeOfImage == 0)
        DIE(("SizeOfImage is null\n"));
    AlignedSizeOfImage = ((ULONGLONG)nSizeOfImage + nSectionAlignment - 1) & ~((ULONGLONG)nSectionAlignment - 1);
    if (AlignedSizeOfImage < nPrevVirtualEndOfSegment)
        DIE(("SizeOfImage %lx does not cover the sections, which end at %Ix\n", nSizeOfImage, nPrevVirtualEndOfSegment));
    if ((ImageSectionObject->NrSegments == 1) && (AlignedSizeOfImage <= nPrevVirtualEndOfSegment))
        DIE(("The image has no sections and SizeOfImage %lx ends with the headers\n", nSizeOfImage));

    PeFmtSetComPlusFlags(File, ImageSectionObject, Magic, ComRva, ComSize, ReadFileCb);

    if(nSectionAlignment >= PAGE_SIZE)
        *Flags |= EXEFMT_LOAD_ASSUME_SEGMENTS_PAGE_ALIGNED;

    /* Success */
    nStatus = STATUS_SUCCESS;// STATUS_ROS_EXEFMT_LOADED_FORMAT | EXEFMT_LOADED_PE32;

l_Return:
    if(pBuffer)
        ExFreePool(pBuffer);

    return nStatus;
}

/*
 * FUNCTION:  Waits in kernel mode indefinitely for a file object lock.
 * ARGUMENTS: PFILE_OBJECT to wait for.
 * RETURNS:   Status of the wait.
 */
NTSTATUS
MmspWaitForFileLock(PFILE_OBJECT File)
{
    return STATUS_SUCCESS;
    //return KeWaitForSingleObject(&File->Lock, 0, KernelMode, FALSE, NULL);
}



VOID
NTAPI
MmpFreePageFileSegment(PMM_SECTION_SEGMENT Segment)
{
    ULONG Length;
    LARGE_INTEGER Offset;
    ULONG_PTR Entry;
    SWAPENTRY SavedSwapEntry;
    PFN_NUMBER Page;

    Page = 0;

    MmLockSectionSegment(Segment);

    Length = PAGE_ROUND_UP(Segment->Length.QuadPart);
    for (Offset.QuadPart = 0; Offset.QuadPart < Length; Offset.QuadPart += PAGE_SIZE)
    {
        Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
        if (Entry)
        {
            MmSetPageEntrySectionSegment(Segment, &Offset, 0);
            if (IS_SWAP_FROM_SSE(Entry))
            {
                MmFreeSwapPage(SWAPENTRY_FROM_SSE(Entry));
            }
            else
            {
                Page = PFN_FROM_SSE(Entry);
                SavedSwapEntry = MmGetSavedSwapEntryPage(Page);
                if (SavedSwapEntry != 0)
                {
                    MmSetSavedSwapEntryPage(Page, 0);
                    MmFreeSwapPage(SavedSwapEntry);
                }
                MmReleasePageMemoryConsumer(MC_USER, Page);
            }
        }
    }

    MmUnlockSectionSegment(Segment);
}

static
VOID
NTAPI
FreeSegmentPage(PMM_SECTION_SEGMENT Segment, PLARGE_INTEGER Offset)
{
    ULONG_PTR Entry;
    PFN_NUMBER Page;

    MmLockSectionSegment(Segment);

    Entry = MmGetPageEntrySectionSegment(Segment, Offset);

    MmUnlockSectionSegment(Segment);

    /* This must be either a valid entry or nothing */
    ASSERT(!IS_SWAP_FROM_SSE(Entry));

    /* There should be no reference anymore */
    ASSERT(SHARE_COUNT_FROM_SSE(Entry) == 0);

    Page = PFN_FROM_SSE(Entry);
    /* If there is a page, this must be because it's still dirty */
    ASSERT(Page != 0);

    /* Write the page */
    if (IS_DIRTY_SSE(Entry))
        MiWritePage(Segment, Offset->QuadPart, Page);

    MmReleasePageMemoryConsumer(MC_USER, Page);
}

_When_(OldIrql == MM_NOIRQL, _IRQL_requires_max_(DISPATCH_LEVEL))
_When_(OldIrql == MM_NOIRQL, _Requires_lock_not_held_(MmPfnLock))
_When_(OldIrql != MM_NOIRQL, _Requires_lock_held_(MmPfnLock))
_When_(OldIrql != MM_NOIRQL, _Releases_lock_(MmPfnLock))
_When_(OldIrql != MM_NOIRQL, _IRQL_requires_(DISPATCH_LEVEL))
VOID
NTAPI
MmDereferenceSegmentWithLock(
    _Inout_ PMM_SECTION_SEGMENT Segment,
    _In_ _When_(OldIrql != MM_NOIRQL, _IRQL_restores_) KIRQL OldIrql)
{
    /* Lock the PFN lock because we mess around with SectionObjectPointers */
    if (OldIrql == MM_NOIRQL)
    {
        OldIrql = MiAcquirePfnLock();
    }

    if (InterlockedDecrement64(Segment->ReferenceCount) > 0)
    {
        /* Nothing to do yet */
        MiReleasePfnLock(OldIrql);
        return;
    }

    *Segment->Flags |= MM_SEGMENT_INDELETE;

    /* Flush the segment */
    if (*Segment->Flags & MM_DATAFILE_SEGMENT)
    {
        MiReleasePfnLock(OldIrql);
        /* Free the page table. This will flush any remaining dirty data */
        MmFreePageTablesSectionSegment(Segment, FreeSegmentPage);

        OldIrql = MiAcquirePfnLock();
        /* Delete the pointer on the file */
        ASSERT(Segment->FileObject->SectionObjectPointer->DataSectionObject == Segment);
        Segment->FileObject->SectionObjectPointer->DataSectionObject = NULL;
        MiReleasePfnLock(OldIrql);
        ObDereferenceObject(Segment->FileObject);

        ExFreePoolWithTag(Segment, TAG_MM_SECTION_SEGMENT);
    }
    else
    {
        /* Most grotesque thing ever */
        PMM_IMAGE_SECTION_OBJECT ImageSectionObject = CONTAINING_RECORD(Segment->ReferenceCount, MM_IMAGE_SECTION_OBJECT, RefCount);
        PMM_SECTION_SEGMENT SectionSegments;
        ULONG NrSegments;
        ULONG i;

        /* Delete the pointer on the file */
        ASSERT(ImageSectionObject->FileObject->SectionObjectPointer->ImageSectionObject == ImageSectionObject);
        ImageSectionObject->FileObject->SectionObjectPointer->ImageSectionObject = NULL;
        MiReleasePfnLock(OldIrql);

        ObDereferenceObject(ImageSectionObject->FileObject);

        NrSegments = ImageSectionObject->NrSegments;
        SectionSegments = ImageSectionObject->Segments;
        for (i = 0; i < NrSegments; i++)
        {
            if (SectionSegments[i].Image.Characteristics & IMAGE_SCN_MEM_SHARED)
            {
                MmpFreePageFileSegment(&SectionSegments[i]);
            }

            MmFreePageTablesSectionSegment(&SectionSegments[i], NULL);
        }

        ExFreePoolWithTag(ImageSectionObject->Segments, TAG_MM_SECTION_SEGMENT);
        ExFreePoolWithTag(ImageSectionObject, TAG_MM_SECTION_SEGMENT);
    }
}

VOID
NTAPI
MmSharePageEntrySectionSegment(PMM_SECTION_SEGMENT Segment,
                               PLARGE_INTEGER Offset)
{
    ULONG_PTR Entry;

    Entry = MmGetPageEntrySectionSegment(Segment, Offset);
    if (Entry == 0)
    {
        DPRINT1("Entry == 0 for MmSharePageEntrySectionSegment\n");
        KeBugCheck(MEMORY_MANAGEMENT);
    }
    if (SHARE_COUNT_FROM_SSE(Entry) == MAX_SHARE_COUNT)
    {
        DPRINT1("Maximum share count reached\n");
        KeBugCheck(MEMORY_MANAGEMENT);
    }
    if (IS_SWAP_FROM_SSE(Entry))
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }
    MmSetPageEntrySectionSegment(Segment, Offset, BUMPREF_SSE(Entry));
}

BOOLEAN
NTAPI
MmUnsharePageEntrySectionSegment(PMEMORY_AREA MemoryArea,
                                 PMM_SECTION_SEGMENT Segment,
                                 PLARGE_INTEGER Offset,
                                 BOOLEAN Dirty,
                                 BOOLEAN PageOut,
                                 ULONG_PTR *InEntry)
{
    ULONG_PTR Entry = InEntry ? *InEntry : MmGetPageEntrySectionSegment(Segment, Offset);
    PFN_NUMBER Page = PFN_FROM_SSE(Entry);
    BOOLEAN IsDataMap = BooleanFlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT);
    SWAPENTRY SwapEntry;

    if (Entry == 0)
    {
        DPRINT1("Entry == 0 for MmUnsharePageEntrySectionSegment\n");
        KeBugCheck(MEMORY_MANAGEMENT);
    }
    if (SHARE_COUNT_FROM_SSE(Entry) == 0)
    {
        DPRINT1("Zero share count for unshare (Seg %p Offset %x Page %x)\n", Segment, Offset->LowPart, PFN_FROM_SSE(Entry));
        KeBugCheck(MEMORY_MANAGEMENT);
    }
    if (IS_SWAP_FROM_SSE(Entry))
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }
    Entry = DECREF_SSE(Entry);
    if (Dirty) Entry = DIRTY_SSE(Entry);

    /* If we are paging-out, pruning the page for real will be taken care of in MmCheckDirtySegment */
    if ((SHARE_COUNT_FROM_SSE(Entry) > 0) || PageOut)
    {
        /* Update the page mapping in the segment and we're done */
        MmSetPageEntrySectionSegment(Segment, Offset, Entry);
        return FALSE;
    }

    /* We are pruning the last mapping on this page. See if we can keep it a bit more. */
    ASSERT(!PageOut);

    if (IsDataMap)
    {
        /* We can always keep memory in for data maps */
        MmSetPageEntrySectionSegment(Segment, Offset, Entry);
        return FALSE;
    }

    if (!FlagOn(Segment->Image.Characteristics, IMAGE_SCN_MEM_SHARED))
    {
        ASSERT(Segment->WriteCopy);
        ASSERT(!IS_DIRTY_SSE(Entry));
        ASSERT(MmGetSavedSwapEntryPage(Page) == 0);
        /* So this must have been a read-only page. Keep it ! */
        MmSetPageEntrySectionSegment(Segment, Offset, Entry);
        return FALSE;
    }

    /*
     * So this is a page for a shared section of a DLL.
     * We can keep it if it is not dirty.
     */
    SwapEntry = MmGetSavedSwapEntryPage(Page);
    if ((SwapEntry == 0) && !IS_DIRTY_SSE(Entry))
    {
        MmSetPageEntrySectionSegment(Segment, Offset, Entry);
        return FALSE;
    }

    /* No more processes are referencing this shared dirty page. Ditch it. */
    if (SwapEntry)
    {
        MmSetSavedSwapEntryPage(Page, 0);
        MmFreeSwapPage(SwapEntry);
    }
    MmSetPageEntrySectionSegment(Segment, Offset, 0);
    MmReleasePageMemoryConsumer(MC_USER, Page);
    return TRUE;
}

static
NTSTATUS
MiCopyFromUserPage(PFN_NUMBER DestPage, const VOID *SrcAddress)
{
    PEPROCESS Process;
    KIRQL Irql;
    PVOID DestAddress;

    Process = PsGetCurrentProcess();
    DestAddress = MiMapPageInHyperSpace(Process, DestPage, &Irql);
    if (DestAddress == NULL)
    {
        return STATUS_NO_MEMORY;
    }
    ASSERT((ULONG_PTR)DestAddress % PAGE_SIZE == 0);
    ASSERT((ULONG_PTR)SrcAddress % PAGE_SIZE == 0);
    RtlCopyMemory(DestAddress, SrcAddress, PAGE_SIZE);
    MiUnmapPageInHyperSpace(Process, DestAddress, Irql);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
MmMakeSegmentResident(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ValidDataLength,
    _In_ BOOLEAN SetDirty,
    _Out_opt_ PBOOLEAN OutOfPages)
{
    /* Let's use a 64K granularity. */
    LONGLONG RangeStart, RangeEnd;
    NTSTATUS Status;
    PFILE_OBJECT FileObject = Segment->FileObject;

    /* Calculate our range, aligned on 64K if possible. */
    Status = RtlLongLongAdd(Offset, Length, &RangeEnd);
    ASSERT(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status))
        return Status;

    /* If the file is not random access and we are not the page out thread
     * read a 64K Chunk. */
    if (((ULONG_PTR)IoGetTopLevelIrp() != FSRTL_MOD_WRITE_TOP_LEVEL_IRP)
        && !FlagOn(FileObject->Flags, FO_RANDOM_ACCESS))
    {
        RangeStart = Offset - (Offset % _64K);
        if (RangeEnd % _64K)
            RangeEnd += _64K - (RangeEnd % _64K);
    }
    else
    {
        RangeStart = Offset  - (Offset % PAGE_SIZE);
        if (RangeEnd % PAGE_SIZE)
            RangeEnd += PAGE_SIZE - (RangeEnd % PAGE_SIZE);
    }

    /* Clamp if needed */
    if (!FlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT))
    {
        if (RangeEnd > Segment->RawLength.QuadPart)
            RangeEnd = Segment->RawLength.QuadPart;
    }

    /* Let's gooooooooo */
    for ( ; RangeStart < RangeEnd; RangeStart += _64K)
    {
        /* First take a look at where we miss pages */
        ULONG ToReadPageBits = 0;
        LONGLONG ChunkEnd = RangeStart + _64K;

        if (ChunkEnd > RangeEnd)
            ChunkEnd = RangeEnd;

        MmLockSectionSegment(Segment);
        for (LONGLONG ChunkOffset = RangeStart; ChunkOffset < ChunkEnd; ChunkOffset += PAGE_SIZE)
        {
            LARGE_INTEGER CurrentOffset;

            CurrentOffset.QuadPart = ChunkOffset;
            ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &CurrentOffset);

            /* Let any pending read proceed */
            while (MM_IS_WAIT_PTE(Entry))
            {
                MmUnlockSectionSegment(Segment);

                KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);

                MmLockSectionSegment(Segment);
                Entry = MmGetPageEntrySectionSegment(Segment, &CurrentOffset);
            }

            if (Entry != 0)
            {
                /* Dirtify it if it's a resident page and we're asked to */
                if (SetDirty && !IS_SWAP_FROM_SSE(Entry))
                {
                    NT_VERIFY(NT_SUCCESS(MmSetPageEntrySectionSegment(Segment, &CurrentOffset, DIRTY_SSE(Entry))));
                }
                continue;
            }

            ToReadPageBits |= 1UL << ((ChunkOffset - RangeStart) >> PAGE_SHIFT);

            /* Put a wait entry here */
            Status = MmSetPageEntrySectionSegment(Segment, &CurrentOffset, MAKE_SWAP_SSE(MM_WAIT_ENTRY));
            if (!NT_SUCCESS(Status))
            {
                /* Failed, roll back! */
                DPRINT1("Failed to set wait entry for segment %p at offset %I64d\n", Segment, ChunkOffset);
                LARGE_INTEGER RollbackOffset;
                RollbackOffset.QuadPart = ChunkOffset;
                while (RollbackOffset.QuadPart > RangeStart)
                {
                    RollbackOffset.QuadPart -= PAGE_SIZE;
                    if (MM_IS_WAIT_PTE(MmGetPageEntrySectionSegment(Segment, &RollbackOffset)))
                    {
                        NT_VERIFY(NT_SUCCESS(MmSetPageEntrySectionSegment(Segment, &RollbackOffset, 0)));
                    }
                }

                MmUnlockSectionSegment(Segment);
                return Status;
            }
            ASSERT(MM_IS_WAIT_PTE(MmGetPageEntrySectionSegment(Segment, &CurrentOffset)));
        }
        MmUnlockSectionSegment(Segment);

        if (ToReadPageBits == 0)
        {
            /* Nothing to do for this chunk */
            continue;
        }

        /* Now perform the actual read */
        LONGLONG ChunkOffset = RangeStart;
        while (ChunkOffset < ChunkEnd)
        {
            /* Move forward if there is a hole */
            ULONG BitSet;
            if (!_BitScanForward(&BitSet, ToReadPageBits))
            {
                /* Nothing more to read */
                break;
            }
            ToReadPageBits >>= BitSet;
            ChunkOffset += BitSet * PAGE_SIZE;
            ASSERT(ChunkOffset < ChunkEnd);

            /* Get the range we have to read */
            _BitScanForward(&BitSet, ~ToReadPageBits);
            ULONG ReadLength = BitSet * PAGE_SIZE;

            ASSERT(ReadLength <= _64K);

            /* Clamp (This is for image mappings */
            if ((ChunkOffset + ReadLength) > ChunkEnd)
                ReadLength = ChunkEnd - ChunkOffset;

            ASSERT(ReadLength != 0);

            /* Allocate a MDL */
            PMDL Mdl = IoAllocateMdl(NULL, ReadLength, FALSE, FALSE, NULL);
            if (!Mdl)
            {
                /* Damn. Roll-back. */
                MmLockSectionSegment(Segment);
                while (ChunkOffset < ChunkEnd)
                {
                    if (ToReadPageBits & 1)
                    {
                        LARGE_INTEGER CurrentOffset;
                        CurrentOffset.QuadPart = ChunkOffset;
                        ASSERT(MM_IS_WAIT_PTE(MmGetPageEntrySectionSegment(Segment, &CurrentOffset)));
                        MmSetPageEntrySectionSegment(Segment, &CurrentOffset, 0);
                    }
                    ToReadPageBits >>= 1;
                    ChunkOffset += PAGE_SIZE;
                }
                MmUnlockSectionSegment(Segment);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* Get our pages */
            PPFN_NUMBER Pages = MmGetMdlPfnArray(Mdl);
            RtlZeroMemory(Pages, BYTES_TO_PAGES(ReadLength) * sizeof(PFN_NUMBER));
            for (UINT i = 0; i < BYTES_TO_PAGES(ReadLength); i++)
            {
                Status = MmRequestPageMemoryConsumer(MC_USER, FALSE, &Pages[i]);
                if (!NT_SUCCESS(Status))
                {
                    /* Damn. Roll-back. */
                    for (UINT j = 0; j < i; j++)
                        MmReleasePageMemoryConsumer(MC_USER, Pages[j]);
                    if (OutOfPages)
                        *OutOfPages = TRUE;
                    goto Failed;
                }
            }

            Mdl->MdlFlags |= MDL_PAGES_LOCKED | MDL_IO_PAGE_READ;

            LARGE_INTEGER FileOffset;
            FileOffset.QuadPart = Segment->Image.FileOffset + ChunkOffset;

            /* Clamp to VDL: nothing past it is read from the file, the
               pages there stay zero. A range starting exactly at the VDL
               has nothing valid in it; one that ends past it is read up to
               the end of the page holding the VDL, so the read stays whole
               pages (sector aligned) for the file system */
            if (ValidDataLength && ((FileOffset.QuadPart + ReadLength) > ValidDataLength->QuadPart))
            {
                if (FileOffset.QuadPart >= ValidDataLength->QuadPart)
                {
                    /* Great, nothing to read. */
                    goto AssignPagesToSegment;
                }

                Mdl->ByteCount = (ULONG)ROUND_TO_PAGES(ValidDataLength->QuadPart - FileOffset.QuadPart);
                ASSERT(Mdl->ByteCount <= ReadLength);
            }

            KEVENT Event;
            KIRQL OldIrql;
            IO_STATUS_BLOCK Iosb;
            ULONG InPageAttempt = 0;

            for (;;)
            {
                KeInitializeEvent(&Event, NotificationEvent, FALSE);

                /* Disable APCs */
                KeRaiseIrql(APC_LEVEL, &OldIrql);

                Status = IoPageRead(FileObject, Mdl, &FileOffset, &Event, &Iosb);
                if (Status == STATUS_PENDING)
                {
                    KeWaitForSingleObject(&Event, WrPageIn, KernelMode, FALSE, NULL);
                    Status = Iosb.Status;
                }

                if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
                {
                    MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);
                }

                KeLowerIrql(OldIrql);

                if (Status == STATUS_END_OF_FILE)
                {
                    DPRINT1("Got STATUS_END_OF_FILE at offset %I64d for file %wZ.\n", FileOffset.QuadPart, &FileObject->FileName);
                    Status = STATUS_SUCCESS;
                }

                /* Ride out a transient backing-store failure instead of bugchecking. */
                if (!NT_SUCCESS(Status) &&
                    MiIsTransientInPageError(Status) &&
                    (InPageAttempt < MI_MAX_INPAGE_RETRIES))
                {
                    LARGE_INTEGER RetryDelay;
                    InPageAttempt++;
                    RetryDelay.QuadPart = -((LONGLONG)InPageAttempt * MI_INPAGE_RETRY_INTERVAL);
                    DPRINT1("In-page read 0x%08lx, retry %lu for file %wZ.\n", Status, InPageAttempt, &FileObject->FileName);
                    KeDelayExecutionThread(KernelMode, FALSE, &RetryDelay);
                    continue;
                }

                break;
            }

            if (NT_SUCCESS(Status))
                MI_COUNT_PAGE_READ(BYTES_TO_PAGES(ReadLength));

            if (!NT_SUCCESS(Status))
            {
                /* Damn. Roll back. */
                for (UINT i = 0; i < BYTES_TO_PAGES(ReadLength); i++)
                    MmReleasePageMemoryConsumer(MC_USER, Pages[i]);

Failed:
                MmLockSectionSegment(Segment);
                while (ChunkOffset < ChunkEnd)
                {
                    if (ToReadPageBits & 1)
                    {
                        LARGE_INTEGER CurrentOffset;
                        CurrentOffset.QuadPart = ChunkOffset;
                        ASSERT(MM_IS_WAIT_PTE(MmGetPageEntrySectionSegment(Segment, &CurrentOffset)));
                        MmSetPageEntrySectionSegment(Segment, &CurrentOffset, 0);
                    }
                    ToReadPageBits >>= 1;
                    ChunkOffset += PAGE_SIZE;
                }
                MmUnlockSectionSegment(Segment);
                IoFreeMdl(Mdl);;
                return Status;
            }

AssignPagesToSegment:
            MmLockSectionSegment(Segment);

            for (UINT i = 0; i < BYTES_TO_PAGES(ReadLength); i++)
            {
                ULONG_PTR Entry = MAKE_SSE(Pages[i] << PAGE_SHIFT, 0);
                LARGE_INTEGER CurrentOffset;
                CurrentOffset.QuadPart = ChunkOffset + (i * PAGE_SIZE);

                ASSERT(MM_IS_WAIT_PTE(MmGetPageEntrySectionSegment(Segment, &CurrentOffset)));

                if (SetDirty)
                    Entry = DIRTY_SSE(Entry);

                MmSetPageEntrySectionSegment(Segment, &CurrentOffset, Entry);
            }

            MmUnlockSectionSegment(Segment);

            IoFreeMdl(Mdl);
            ToReadPageBits >>= BitSet;
            ChunkOffset += BitSet * PAGE_SIZE;
        }
    }

    return STATUS_SUCCESS;
}

static VOID
MmAlterViewAttributes(PMMSUPPORT AddressSpace,
                      PVOID BaseAddress,
                      SIZE_T RegionSize,
                      ULONG OldType,
                      ULONG OldProtect,
                      ULONG NewType,
                      ULONG NewProtect)
{
    PMEMORY_AREA MemoryArea;
    PMM_SECTION_SEGMENT Segment;
    BOOLEAN DoCOW = FALSE;
    ULONG i;
    PEPROCESS Process = MmGetAddressSpaceOwner(AddressSpace);
    MM_TB_FLUSH_LIST FlushList;

    MmInitializeTbFlushList(&FlushList, FALSE);
    MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace, BaseAddress);
    ASSERT(MemoryArea != NULL);
    Segment = MemoryArea->SectionData.Segment;
    MmLockSectionSegment(Segment);

    if ((Segment->WriteCopy) &&
            (NewProtect == PAGE_READWRITE || NewProtect == PAGE_EXECUTE_READWRITE))
    {
        DoCOW = TRUE;
    }

    if (OldProtect != NewProtect)
    {
        for (i = 0; i < PAGE_ROUND_UP(RegionSize) / PAGE_SIZE; i++)
        {
            SWAPENTRY SwapEntry;
            PVOID Address = (char*)BaseAddress + (i * PAGE_SIZE);
            ULONG Protect = NewProtect;

            /* Wait for a wait entry to disappear */
            do
            {
                MmGetPageFileMapping(Process, Address, &SwapEntry);
                if (SwapEntry != MM_WAIT_ENTRY)
                    break;
                /* A copy-on-write fault may run while the locks are dropped */
                MmFlushTbList(&FlushList);
                MmUnlockSectionSegment(Segment);
                MmUnlockAddressSpace(AddressSpace);
                KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
                MmLockAddressSpace(AddressSpace);
                MmLockSectionSegment(Segment);
            }
            while (TRUE);

            /*
             * If we doing COW for this segment then check if the page is
             * already private.
             */
            if (DoCOW && (MmIsPagePresent(Process, Address) || MmIsDisabledPage(Process, Address)))
            {
                LARGE_INTEGER Offset;
                ULONG_PTR Entry;
                PFN_NUMBER Page;

                Offset.QuadPart = (ULONG_PTR)Address - MA_GetStartingAddress(MemoryArea)
                                  + MemoryArea->SectionData.ViewOffset;
                Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
                /*
                 * An MM_WAIT_ENTRY is ok in this case...  It'll just count as
                 * IS_SWAP_FROM_SSE and we'll do the right thing.
                 */
                Page = MmGetPfnForProcess(Process, Address);

                /* Choose protection based on what was requested */
                if (NewProtect == PAGE_EXECUTE_READWRITE)
                    Protect = PAGE_EXECUTE_READ;
                else
                    Protect = PAGE_READONLY;

                if (IS_SWAP_FROM_SSE(Entry) || PFN_FROM_SSE(Entry) != Page)
                {
                    Protect = NewProtect;
                }
            }

            if (MmIsPagePresent(Process, Address) || MmIsDisabledPage(Process, Address))
            {
                MmSetPageProtectDeferFlush(Process, Address, Protect,
                                           BooleanFlagOn(*Segment->Flags, MM_PHYSICALMEMORY_SEGMENT),
                                           &FlushList);
            }
        }
    }

    MmFlushTbList(&FlushList);
    MmUnlockSectionSegment(Segment);
}

/*
 * A section fault that will map a page into a process takes the page's
 * rmap entry before it locks the segment or maps anything, so that
 * running out of nonpaged pool fails the fault with STATUS_NO_MEMORY,
 * which MmAccessFault waits out and retries, instead of bugchecking in
 * MmInsertRmap after the page is mapped. The segment association that
 * MmSetPageEntrySectionSegment inserts still allocates on its own.
 */
static
NTSTATUS
MiReserveFaultRmap(PEPROCESS Process, PVOID *RmapEntry)
{
    if (Process == NULL || *RmapEntry != NULL)
        return STATUS_SUCCESS;

    *RmapEntry = MmAllocateRmapEntry();
    return (*RmapEntry != NULL) ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}

/* A macro, so that the debug caller of each rmap entry is its fault path */
#define MiInsertFaultRmap(Page, Process, Address, RmapEntry)                 \
    do                                                                        \
    {                                                                         \
        ASSERT(*(RmapEntry) != NULL);                                         \
        MmInsertRmapEntry((Page), (Process), (Address), *(RmapEntry));        \
        *(RmapEntry) = NULL;                                                  \
    } while (0)

/*
 * Synchronization of a page-in from a file with the file system, for the fault path.
 *
 * Windows takes no file system lock in Mm when a fault pages data in: it sends the file system a paging
 * read (IRP_PAGING_IO | IRP_NOCACHE, IoPageRead), and the file system synchronizes that read itself,
 * normally with its paging I/O resource shared, which size changes hold exclusive. The acquire callbacks
 * have other callers: AcquireFileForNtCreateSection (and the FsFilter section synchronization callbacks)
 * is for creating a section, AcquireForCcFlush for flushing, AcquireForModWrite for the mapped page writer.
 *
 * Our Mm clamps the read at the file's valid data length itself (MmMakeSegmentResident), so the VDL must not
 * move while the read runs. That used to be done with the section creation acquire, which made a fault
 * call the file system's and the filters' section callbacks, and wait for the file exclusively: a thread
 * that faulted on a cache view while it held the file waited for itself. Instead, the paging I/O semantics:
 *  - a thread that holds the file's main resource, in either mode, takes nothing more: every size or VDL change
 *    needs the main resource exclusive, so its hold pins the VDL (Cc pages data in under that hold too). It
 *    must not wait for the paging resource either: a file system may take the paging resource before the main
 *    one (btrfs, non-cached write), and our hold of the main one would then deadlock with it;
 *  - otherwise the paging resource, shared, without waiting for exclusive waiters while it is shared-owned, as
 *    paging I/O does. A thread that holds it already, in either mode, gets it recursively;
 *  - a file without a paging resource: the main resource, the same way.
 * No callback is called. A file system-private lock the thread holds is not known here; the only wait is for the
 * paging resource while another thread changes the file's size, which is what the file system's own paging read
 * waits for too.
 */
static
PERESOURCE
MiLockFileForPageIn(
    _In_ PFILE_OBJECT FileObject)
{
    PFSRTL_COMMON_FCB_HEADER FcbHeader = FileObject->FsContext;
    PERESOURCE Resource;

    if (!FcbHeader)
        return NULL;

    if (FcbHeader->Resource && ExIsResourceAcquiredSharedLite(FcbHeader->Resource))
        return NULL;

    Resource = FcbHeader->PagingIoResource ? FcbHeader->PagingIoResource : FcbHeader->Resource;
    if (!Resource)
        return NULL;

    FsRtlEnterFileSystem();
    ExAcquireSharedStarveExclusive(Resource, TRUE);
    return Resource;
}

static
VOID
MiUnlockFileForPageIn(
    _In_opt_ PERESOURCE Resource)
{
    if (!Resource)
        return;

    ExReleaseResourceLite(Resource);
    FsRtlExitFileSystem();
}

static
NTSTATUS
MiNotPresentFaultSectionView(PMMSUPPORT AddressSpace,
                             MEMORY_AREA* MemoryArea,
                             PVOID Address,
                             BOOLEAN Locked,
                             PVOID *RmapEntry)
{
    LARGE_INTEGER Offset;
    PFN_NUMBER Page;
    NTSTATUS Status;
    PMM_SECTION_SEGMENT Segment;
    ULONG_PTR Entry;
    ULONG_PTR Entry1;
    ULONG Attributes;
    PMM_REGION Region;
    BOOLEAN HasSwapEntry;
    PVOID PAddress;
    PEPROCESS Process = MmGetAddressSpaceOwner(AddressSpace);
    SWAPENTRY SwapEntry;

    ASSERT(Locked);

    /*
     * There is a window between taking the page fault and locking the
     * address space when another thread could load the page so we check
     * that.
     */
    if (MmIsPagePresent(Process, Address))
    {
        return STATUS_SUCCESS;
    }

    if (MmIsDisabledPage(Process, Address))
    {
        return STATUS_ACCESS_VIOLATION;
    }

    /*
     * Check for the virtual memory area being deleted.
     */
    if (MemoryArea->DeleteInProgress)
    {
        return STATUS_UNSUCCESSFUL;
    }

    PAddress = MM_ROUND_DOWN(Address, PAGE_SIZE);
    Offset.QuadPart = (ULONG_PTR)PAddress - MA_GetStartingAddress(MemoryArea)
                      + MemoryArea->SectionData.ViewOffset;

    Segment = MemoryArea->SectionData.Segment;
    Region = MmFindRegion((PVOID)MA_GetStartingAddress(MemoryArea),
                          &MemoryArea->SectionData.RegionListHead,
                          Address, NULL);
    ASSERT(Region != NULL);

    /* Check for a NOACCESS mapping */
    if (Region->Protect & PAGE_NOACCESS)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    if (Region->Protect & PAGE_GUARD)
    {
        /* Remove it */
        Status = MmAlterRegion(AddressSpace, (PVOID)MA_GetStartingAddress(MemoryArea),
                &MemoryArea->SectionData.RegionListHead,
                Address, PAGE_SIZE, Region->Type, Region->Protect & ~PAGE_GUARD,
                MmAlterViewAttributes);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Removing PAGE_GUARD protection failed : 0x%08x.\n", Status);
        }

        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Every path below maps a page or waits for one; physical memory has no rmap */
    if (!((*Segment->Flags) & MM_PHYSICALMEMORY_SEGMENT))
    {
        Status = MiReserveFaultRmap(Process, RmapEntry);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    HasSwapEntry = MmIsPageSwapEntry(Process, Address);

    /* See if we should use a private page */
    if (HasSwapEntry)
    {
        SWAPENTRY DummyEntry;

        MmGetPageFileMapping(Process, Address, &SwapEntry);
        if (SwapEntry == MM_WAIT_ENTRY)
        {
            MmUnlockAddressSpace(AddressSpace);
            KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
            MmLockAddressSpace(AddressSpace);
            return STATUS_MM_RESTART_OPERATION;
        }

        MI_SET_USAGE(MI_USAGE_SECTION);
        if (Process) MI_SET_PROCESS2(Process->ImageFileName);
        if (!Process) MI_SET_PROCESS2("Kernel Section");
        Status = MmRequestPageMemoryConsumer(MC_USER, TRUE, &Page);
        if (!NT_SUCCESS(Status))
        {
            return STATUS_NO_MEMORY;
        }

        /*
         * Must be private page we have swapped out.
         */

        /*
        * Sanity check
        */
        MmDeletePageFileMapping(Process, Address, &DummyEntry);
        ASSERT(DummyEntry == SwapEntry);

        /* Tell everyone else we are serving the fault. */
        MmCreatePageFileMapping(Process, Address, MM_WAIT_ENTRY);

        MmUnlockAddressSpace(AddressSpace);

        Status = MmReadFromSwapPage(SwapEntry, Page);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MmReadFromSwapPage failed, status = %x\n", Status);
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        MmLockAddressSpace(AddressSpace);
        MmDeletePageFileMapping(Process, PAddress, &DummyEntry);
        ASSERT(DummyEntry == MM_WAIT_ENTRY);

        Status = MmCreateVirtualMapping(Process,
                                        PAddress,
                                        Region->Protect,
                                        Page);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("MmCreateVirtualMapping failed, not out of memory\n");
            KeBugCheck(MEMORY_MANAGEMENT);
            return Status;
        }

        /*
         * Store the swap entry for later use.
         */
        MmSetSavedSwapEntryPage(Page, SwapEntry);

        /*
         * Add the page to the process's working set
         */
        if (Process) MiInsertFaultRmap(Page, Process, Address, RmapEntry);
        /*
         * Finish the operation
         */
        DPRINT("Address 0x%p\n", Address);
        return STATUS_SUCCESS;
    }

    /*
     * Lock the segment
     */
    MmLockSectionSegment(Segment);

    /*
     * Satisfying a page fault on a map of /Device/PhysicalMemory is easy
     */
    if ((*Segment->Flags) & MM_PHYSICALMEMORY_SEGMENT)
    {
        MmUnlockSectionSegment(Segment);
        /*
         * Just map the desired physical page
         */
        Page = (PFN_NUMBER)(Offset.QuadPart >> PAGE_SHIFT);
        Status = MmCreatePhysicalMapping(Process,
                                         PAddress,
                                         Region->Protect,
                                         Page);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("MmCreateVirtualMappingUnsafe failed, not out of memory\n");
            KeBugCheck(MEMORY_MANAGEMENT);
            return Status;
        }

        /*
         * Cleanup and release locks
         */
        DPRINT("Address 0x%p\n", Address);
        return STATUS_SUCCESS;
    }

    /*
     * Check if this page needs to be mapped COW
     */
    if ((Segment->WriteCopy) &&
        (Region->Protect == PAGE_READWRITE || Region->Protect == PAGE_EXECUTE_READWRITE))
    {
        Attributes = Region->Protect == PAGE_READWRITE ? PAGE_READONLY : PAGE_EXECUTE_READ;
    }
    else
    {
        Attributes = Region->Protect;
    }


    /*
     * Get the entry corresponding to the offset within the section
     */
    Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
    if (Entry == 0)
    {
        /*
         * If the entry is zero, then we need to load the page.
         */
        if ((Offset.QuadPart >= (LONGLONG)PAGE_ROUND_UP(Segment->RawLength.QuadPart)) && (MemoryArea->VadNode.u.VadFlags.VadType == VadImageMap))
        {
            /* We are beyond the data which is on file. Just get a new page. */
            MI_PRCB_COUNT_ADD(MmDemandZeroCount, 1);
            MI_SET_USAGE(MI_USAGE_SECTION);
            if (Process) MI_SET_PROCESS2(Process->ImageFileName);
            if (!Process) MI_SET_PROCESS2("Kernel Section");
            Status = MmRequestPageMemoryConsumer(MC_USER, FALSE, &Page);
            if (!NT_SUCCESS(Status))
            {
                MmUnlockSectionSegment(Segment);
                return STATUS_NO_MEMORY;
            }
            MmSetPageEntrySectionSegment(Segment, &Offset, MAKE_SSE(Page << PAGE_SHIFT, 1));
            MmUnlockSectionSegment(Segment);

            Status = MmCreateVirtualMapping(Process, PAddress, Attributes, Page);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("Unable to create virtual mapping\n");
                KeBugCheck(MEMORY_MANAGEMENT);
            }
            ASSERT(MmIsPagePresent(Process, PAddress));
            if (Process)
                MiInsertFaultRmap(Page, Process, Address, RmapEntry);

            DPRINT("Address 0x%p\n", Address);
            return STATUS_SUCCESS;
        }

        MmUnlockSectionSegment(Segment);
        MmUnlockAddressSpace(AddressSpace);

        PFSRTL_COMMON_FCB_HEADER FcbHeader = Segment->FileObject->FsContext;
        PERESOURCE FileLock;

        /*
         * The data must be paged in, with the VDL held still while the read runs (see MiLockFileForPageIn).
         * A file system copying from the cache under its shared hold of the file (CcCopyRead, FsRtlCopyRead)
         * faults here when Mm took the view's page away after Cc made it resident: it must not wait for the
         * file, nor must a thread that holds only the file's paging resource.
         */
        FileLock = MiLockFileForPageIn(Segment->FileObject);

        Status = MmMakeSegmentResident(Segment, Offset.QuadPart, PAGE_SIZE,
                                       FcbHeader ? &FcbHeader->ValidDataLength : NULL, FALSE, NULL);

        MiUnlockFileForPageIn(FileLock);

        /* Lock address space again */
        MmLockAddressSpace(AddressSpace);
        if (!NT_SUCCESS(Status))
        {
            if (Status == STATUS_NO_MEMORY)
            {
                return Status;
            }
            /* Damn */
            DPRINT1("Failed to page data in!\n");
            return STATUS_IN_PAGE_ERROR;
        }

        /* Everything went fine. Restart the operation */
        return STATUS_MM_RESTART_OPERATION;
    }
    else if (IS_SWAP_FROM_SSE(Entry))
    {
        SWAPENTRY SwapEntry;

        SwapEntry = SWAPENTRY_FROM_SSE(Entry);

        /* See if a page op is running on this segment. */
        if (SwapEntry == MM_WAIT_ENTRY)
        {
            MmUnlockSectionSegment(Segment);
            MmUnlockAddressSpace(AddressSpace);
            KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
            MmLockAddressSpace(AddressSpace);
            return STATUS_MM_RESTART_OPERATION;
        }

        Status = MmRequestPageMemoryConsumer(MC_USER, TRUE, &Page);
        if (!NT_SUCCESS(Status))
        {
            MmUnlockSectionSegment(Segment);
            return STATUS_NO_MEMORY;
        }

        /*
        * Release all our locks and read in the page from disk
        */
        MmSetPageEntrySectionSegment(Segment, &Offset, MAKE_SWAP_SSE(MM_WAIT_ENTRY));
        MmUnlockSectionSegment(Segment);

        MmUnlockAddressSpace(AddressSpace);

        Status = MmReadFromSwapPage(SwapEntry, Page);
        if (!NT_SUCCESS(Status))
        {
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        /*
         * Relock the address space and segment
         */
        MmLockAddressSpace(AddressSpace);
        MmLockSectionSegment(Segment);

        /*
         * Check the entry. No one should change the status of a page
         * that has a pending page-in.
         */
        Entry1 = MmGetPageEntrySectionSegment(Segment, &Offset);
        if (Entry1 != MAKE_SWAP_SSE(MM_WAIT_ENTRY))
        {
            DPRINT1("Someone changed ppte entry while we slept (%x vs %x)\n", Entry, Entry1);
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        /*
         * Save the swap entry.
         */
        MmSetSavedSwapEntryPage(Page, SwapEntry);

        /* Map the page into the process address space */
        Status = MmCreateVirtualMapping(Process,
                                        PAddress,
                                        Attributes,
                                        Page);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Unable to create virtual mapping\n");
            KeBugCheck(MEMORY_MANAGEMENT);
        }
        if (Process)
            MiInsertFaultRmap(Page, Process, Address, RmapEntry);

        /*
         * Mark the offset within the section as having valid, in-memory
         * data
         */
        Entry = MAKE_SSE(Page << PAGE_SHIFT, 1);
        MmSetPageEntrySectionSegment(Segment, &Offset, Entry);
        MmUnlockSectionSegment(Segment);

        DPRINT("Address 0x%p\n", Address);
        return STATUS_SUCCESS;
    }
    else
    {
        /* We already have a page on this section offset. Map it into the process address space. */
        Page = PFN_FROM_SSE(Entry);
        MI_PRCB_COUNT_ADD(MmTransitionCount, 1);

        Status = MmCreateVirtualMapping(Process,
                                        PAddress,
                                        Attributes,
                                        Page);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Unable to create virtual mapping\n");
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        if (Process)
            MiInsertFaultRmap(Page, Process, Address, RmapEntry);

        /* Take a reference on it */
        MmSharePageEntrySectionSegment(Segment, &Offset);
        MmUnlockSectionSegment(Segment);

        DPRINT("Address 0x%p\n", Address);
        return STATUS_SUCCESS;
    }
}

/* MmAlterRegion callback for a region change whose PTEs are already right */
static
VOID
MiKeepViewAttributes(
    PMMSUPPORT AddressSpace,
    PVOID BaseAddress,
    SIZE_T RegionSize,
    ULONG OldType,
    ULONG OldProtect,
    ULONG NewType,
    ULONG NewProtect)
{
    UNREFERENCED_PARAMETER(AddressSpace);
    UNREFERENCED_PARAMETER(BaseAddress);
    UNREFERENCED_PARAMETER(RegionSize);
    UNREFERENCED_PARAMETER(OldType);
    UNREFERENCED_PARAMETER(OldProtect);
    UNREFERENCED_PARAMETER(NewType);
    UNREFERENCED_PARAMETER(NewProtect);
}

static
NTSTATUS
MiAccessFaultSectionView(PMMSUPPORT AddressSpace,
                         MEMORY_AREA* MemoryArea,
                         PVOID Address,
                         BOOLEAN Locked,
                         PVOID *RmapEntry)
{
    PMM_SECTION_SEGMENT Segment;
    PFN_NUMBER OldPage;
    PFN_NUMBER NewPage;
    PFN_NUMBER UnmappedPage;
    PVOID PAddress;
    LARGE_INTEGER Offset;
    PMM_REGION Region;
    ULONG_PTR Entry;
    PEPROCESS Process = MmGetAddressSpaceOwner(AddressSpace);
    BOOLEAN Cow = FALSE;
    ULONG NewProtect;
    BOOLEAN Unmapped;
    NTSTATUS Status;

    DPRINT("MmAccessFaultSectionView(%p, %p, %p)\n", AddressSpace, MemoryArea, Address);

    /* Get the region for this address */
    Region = MmFindRegion((PVOID)MA_GetStartingAddress(MemoryArea),
                        &MemoryArea->SectionData.RegionListHead,
                        Address, NULL);
    ASSERT(Region != NULL);
    if (!(Region->Protect & PAGE_IS_WRITABLE))
        return STATUS_ACCESS_VIOLATION;

    /* Make sure we have a page mapping for this address.  */
    if (!MmIsPagePresent(Process, Address))
    {
        Status = MiNotPresentFaultSectionView(AddressSpace, MemoryArea, Address, Locked, RmapEntry);
        if (!NT_SUCCESS(Status))
        {
            /* This is invalid access ! */
            return Status;
        }
    }

    /*
     * Check if the page has already been set readwrite
     */
    if (MmGetPageProtect(Process, Address) & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
    {
        DPRINT("Address 0x%p\n", Address);
        return STATUS_SUCCESS;
    }

    /* Check if we are doing Copy-On-Write */
    Segment = MemoryArea->SectionData.Segment;
    Cow = Segment->WriteCopy || (Region->Protect & PAGE_IS_WRITECOPY);

    if (!Cow)
    {
        /* Simply update page protection and we're done */
        MmSetPageProtectDeferFlush(Process, Address, Region->Protect,
                                   BooleanFlagOn(*Segment->Flags, MM_PHYSICALMEMORY_SEGMENT), NULL);
        return STATUS_SUCCESS;
    }

    /* The copy below maps a new page: reserve before changing anything */
    Status = MiReserveFaultRmap(Process, RmapEntry);
    if (!NT_SUCCESS(Status))
        return Status;

    /*
     * Calculate the new protection. The region is updated only once the page
     * is private: unless the segment itself is copy-on-write, a region marked
     * writable makes the next fault on the page map it writable, and until
     * then that is still the shared page.
     */
    NewProtect = Region->Protect;
    if (NewProtect & PAGE_IS_WRITECOPY)
    {
        NewProtect &= ~PAGE_IS_WRITECOPY;
        if (Region->Protect & PAGE_IS_EXECUTABLE)
            NewProtect |= PAGE_EXECUTE_READWRITE;
        else
            NewProtect |= PAGE_READWRITE;
    }

    /*
     * Find the offset of the page
     */
    PAddress = MM_ROUND_DOWN(Address, PAGE_SIZE);
    Offset.QuadPart = (ULONG_PTR)PAddress - MA_GetStartingAddress(MemoryArea)
                      + MemoryArea->SectionData.ViewOffset;

    /* Get the page mapping this section offset. */
    MmLockSectionSegment(Segment);
    Entry = MmGetPageEntrySectionSegment(Segment, &Offset);

    /* Get the current page mapping for the process */
    ASSERT(MmIsPagePresent(Process, PAddress));
    OldPage = MmGetPfnForProcess(Process, PAddress);
    ASSERT(OldPage != 0);

    if (IS_SWAP_FROM_SSE(Entry) ||
            PFN_FROM_SSE(Entry) != OldPage)
    {
        MmUnlockSectionSegment(Segment);
        /* This is a private page. We must only change the page protection. */
        MmSetPageProtectDeferFlush(Process, PAddress, NewProtect,
                                   BooleanFlagOn(*Segment->Flags, MM_PHYSICALMEMORY_SEGMENT), NULL);
        goto UpdateRegion;
    }

    /*
     * Allocate a page
     */
    Status = MmRequestPageMemoryConsumer(MC_USER, TRUE, &NewPage);
    if (!NT_SUCCESS(Status))
    {
        MmUnlockSectionSegment(Segment);
        return STATUS_NO_MEMORY;
    }

    /*
     * Copy the old page
     */
    NT_VERIFY(NT_SUCCESS(MiCopyFromUserPage(NewPage, PAddress)));
    MI_PRCB_COUNT_ADD(MmCopyOnWriteCount, 1);

    /*
     * Unshare the old page.
     */
    DPRINT("Swapping page (Old %x New %x)\n", OldPage, NewPage);
    Unmapped = MmDeleteVirtualMapping(Process, PAddress, NULL, &UnmappedPage);
    if (!Unmapped || (UnmappedPage != OldPage))
    {
        /* Uh , we had a page just before, but suddenly it changes. Someone corrupted us. */
        KeBugCheckEx(MEMORY_MANAGEMENT,
                    (ULONG_PTR)Process,
                    (ULONG_PTR)PAddress,
                    (ULONG_PTR)__FILE__,
                    __LINE__);
    }

    if (Process)
        MmDeleteRmap(OldPage, Process, PAddress);
    MmUnsharePageEntrySectionSegment(MemoryArea, Segment, &Offset, FALSE, FALSE, NULL);
    MmUnlockSectionSegment(Segment);

    /*
     * Set the PTE to point to the new page
     */
    if (!NT_SUCCESS(MmCreateVirtualMapping(Process, PAddress, NewProtect, NewPage)))
    {
        DPRINT1("MmCreateVirtualMapping failed, unable to create virtual mapping, not out of memory\n");
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    if (Process)
        MiInsertFaultRmap(NewPage, Process, PAddress, RmapEntry);

UpdateRegion:
    /* The PTE already has the new protection: only record it in the region */
    if (Region->Protect & PAGE_IS_WRITECOPY)
    {
        MmAlterRegion(AddressSpace, (PVOID)MA_GetStartingAddress(MemoryArea),
                &MemoryArea->SectionData.RegionListHead,
                PAddress, PAGE_SIZE, Region->Type, NewProtect,
                MiKeepViewAttributes);
    }

    DPRINT("Address 0x%p\n", Address);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MmNotPresentFaultSectionView(PMMSUPPORT AddressSpace,
                             MEMORY_AREA* MemoryArea,
                             PVOID Address,
                             BOOLEAN Locked)
{
    PVOID RmapEntry = NULL;
    NTSTATUS Status;

    Status = MiNotPresentFaultSectionView(AddressSpace, MemoryArea, Address, Locked, &RmapEntry);
    if (RmapEntry != NULL)
        MmFreeRmapEntry(RmapEntry);
    return Status;
}

NTSTATUS
NTAPI
MmAccessFaultSectionView(PMMSUPPORT AddressSpace,
                         MEMORY_AREA* MemoryArea,
                         PVOID Address,
                         BOOLEAN Locked)
{
    PVOID RmapEntry = NULL;
    NTSTATUS Status;

    Status = MiAccessFaultSectionView(AddressSpace, MemoryArea, Address, Locked, &RmapEntry);
    if (RmapEntry != NULL)
        MmFreeRmapEntry(RmapEntry);
    return Status;
}

/*
 * Returns TRUE if the page protection Protect requests no more access
 * (read / write / execute) than the section's maximum protection MaxProtect
 * allows. This is the same three-axis test MmMapViewOfSection applies at map
 * time, so a view can only ever be reprotected to a protection it could have
 * been mapped with in the first place.
 */
static
BOOLEAN
MiIsProtectWithinMaximum(ULONG Protect, ULONG MaxProtect)
{
    /* Requested write access must be granted by the section */
    if ((Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
        !(MaxProtect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
    {
        return FALSE;
    }

    /* Requested read / copy-on-write access must be granted by the section */
    if ((Protect & (PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY)) &&
        !(MaxProtect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    {
        return FALSE;
    }

    /* Requested execute access must be granted by the section */
    if ((Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
        !(MaxProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    {
        return FALSE;
    }

    return TRUE;
}

/*
 * Per-subsection maximum-protection test for image-section views.
 *
 * Each PE section of an image is mapped as its own segment/view, so the
 * MemoryArea passed here already refers to exactly one section: Segment->
 * Protection is the natural protection derived from that section header's
 * characteristics (see SectionCharacteristicsToProtect) and Segment->WriteCopy
 * is set for every non-shared image segment.
 *
 * A copy-on-write segment can be reprotected to any protection (including
 * execute and write+execute, as on Windows): a write only ever produces a
 * private copy of the page that never reaches the file or any other view, and
 * a process can already obtain private executable memory with VirtualAlloc, so
 * refusing execute on its own private image pages protects nothing. Real
 * programs depend on it: the Inno Setup loader (and many packers and
 * self-protecting executables) VirtualProtect()s every region of their own
 * image to PAGE_EXECUTE_READWRITE, touches each page to force the private copy
 * and restores the old protection; failing that with ERROR_INVALID_PARAMETER
 * made the touch fault inside the loader.
 *
 * What is still rejected is the real escalation: a genuinely shared
 * (non-copy-on-write) image segment may not be given more access than its
 * section header grants, as that would be visible to other mappers / the file.
 */
static
BOOLEAN
MiIsImageProtectWithinMaximum(ULONG Protect, PMM_SECTION_SEGMENT Segment)
{
    ULONG MaxProtect = Segment->Protection;

    if (Segment->WriteCopy)
    {
        /* Copy-on-write segment: every access level only ever yields a private page */
        MaxProtect = PAGE_EXECUTE_READWRITE;
    }

    return MiIsProtectWithinMaximum(Protect, MaxProtect);
}

NTSTATUS
NTAPI
MmProtectSectionView(PMMSUPPORT AddressSpace,
                     PMEMORY_AREA MemoryArea,
                     PVOID BaseAddress,
                     SIZE_T Length,
                     ULONG Protect,
                     PULONG OldProtect)
{
    PMM_REGION Region;
    PMM_SECTION_SEGMENT Segment;
    NTSTATUS Status;
    ULONG_PTR MaxLength;

    ASSERT(MemoryArea->Type == MEMORY_AREA_SECTION_VIEW);

    if (MemoryArea->DeleteInProgress)
    {
        return STATUS_UNSUCCESSFUL;
    }

    MaxLength = MA_GetEndingAddress(MemoryArea) - (ULONG_PTR)BaseAddress;
    if (Length > MaxLength)
        Length = (ULONG)MaxLength;

    Region = MmFindRegion((PVOID)MA_GetStartingAddress(MemoryArea),
                          &MemoryArea->SectionData.RegionListHead,
                          BaseAddress, NULL);
    ASSERT(Region != NULL);

    if ((MemoryArea->Flags & SEC_NO_CHANGE) &&
            Region->Protect != Protect)
    {
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /*
     * Enforce the section's maximum protection: a view must not be reprotected
     * beyond the access the section was created with (a W^X / privilege-escalation
     * hole - e.g. gaining execute or write on a read-only data mapping).
     *
     * Data/file sections use the single segment protection (which for a data-file
     * section is the section's page protection). Image sections carry a per-
     * subsection, copy-on-write protection and are checked with a dedicated
     * ceiling that still permits the loader's IAT / relocation fixups while
     * rejecting an execute escalation on a non-executable subsection.
     */
    Segment = MemoryArea->SectionData.Segment;
    if (MemoryArea->VadNode.u.VadFlags.VadType == VadImageMap)
    {
        if (!MiIsImageProtectWithinMaximum(Protect, Segment))
        {
            return STATUS_SECTION_PROTECTION;
        }
    }
    else if (!MiIsProtectWithinMaximum(Protect, Segment->Protection))
    {
        return STATUS_SECTION_PROTECTION;
    }

    if (OldProtect != NULL)
        *OldProtect = Region->Protect;
    Status = MmAlterRegion(AddressSpace, (PVOID)MA_GetStartingAddress(MemoryArea),
                           &MemoryArea->SectionData.RegionListHead,
                           BaseAddress, Length, Region->Type, Protect,
                           MmAlterViewAttributes);

    return Status;
}

NTSTATUS NTAPI
MmQuerySectionView(PMEMORY_AREA MemoryArea,
                   PVOID Address,
                   PMEMORY_BASIC_INFORMATION Info,
                   PSIZE_T ResultLength)
{
    PMM_REGION Region;
    PVOID RegionBaseAddress;
    PMM_SECTION_SEGMENT Segment;

    Region = MmFindRegion((PVOID)MA_GetStartingAddress(MemoryArea),
                          &MemoryArea->SectionData.RegionListHead,
                          Address, &RegionBaseAddress);
    if (Region == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (MemoryArea->VadNode.u.VadFlags.VadType == VadImageMap)
    {
        Segment = MemoryArea->SectionData.Segment;
        Info->AllocationBase = (PUCHAR)MA_GetStartingAddress(MemoryArea) - Segment->Image.VirtualAddress;
        Info->Type = MEM_IMAGE;
    }
    else
    {
        Info->AllocationBase = (PVOID)MA_GetStartingAddress(MemoryArea);
        Info->Type = MEM_MAPPED;
    }
    Info->BaseAddress = RegionBaseAddress;
    Info->AllocationProtect = MmProtectToValue[MemoryArea->VadNode.u.VadFlags.Protection];
    Info->RegionSize = Region->Length;
    Info->State = MEM_COMMIT;
    Info->Protect = Region->Protect;

    *ResultLength = sizeof(MEMORY_BASIC_INFORMATION);
    return STATUS_SUCCESS;
}

VOID NTAPI
MmpDeleteSection(PVOID ObjectBody)
{
    PSECTION Section = ObjectBody;

    /* Check if it's an ARM3, or ReactOS section */
    if (!MiIsRosSectionObject(Section))
    {
        MiDeleteARM3Section(ObjectBody);
        return;
    }

    DPRINT("MmpDeleteSection(ObjectBody %p)\n", ObjectBody);
    if (Section->u.Flags.Image)
    {
        PMM_IMAGE_SECTION_OBJECT ImageSectionObject = (PMM_IMAGE_SECTION_OBJECT)Section->Segment;

        /*
         * NOTE: Section->ImageSection can be NULL for short time
         * during the section creating. If we fail for some reason
         * until the image section is properly initialized we shouldn't
         * process further here.
         */
        if (Section->Segment == NULL)
            return;

        KIRQL OldIrql = MiAcquirePfnLock();
        ImageSectionObject->SectionCount--;

        /* We just dereference the first segment */
        ASSERT(ImageSectionObject->RefCount > 0);
        /* MmDereferenceSegmentWithLock releases PFN lock */
        MmDereferenceSegmentWithLock(ImageSectionObject->Segments, OldIrql);
    }
    else
    {
        PMM_SECTION_SEGMENT Segment = (PMM_SECTION_SEGMENT)Section->Segment;

        /*
         * NOTE: Section->Segment can be NULL for short time
         * during the section creating.
         */
        if (Segment == NULL)
            return;

        KIRQL OldIrql = MiAcquirePfnLock();
        Segment->SectionCount--;

        /* MmDereferenceSegmentWithLock releases PFN lock */
        MmDereferenceSegmentWithLock(Segment, OldIrql);
    }
}

VOID NTAPI
MmpCloseSection(IN PEPROCESS Process OPTIONAL,
                IN PVOID Object,
                IN ACCESS_MASK GrantedAccess,
                IN ULONG_PTR ProcessHandleCount,
                IN ULONG_PTR SystemHandleCount)
{
    DPRINT("MmpCloseSection(OB %p, HC %lu)\n", Object, ProcessHandleCount);
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
MmCreatePhysicalMemorySection(VOID)
{
    PSECTION PhysSection;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Obj;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
    LARGE_INTEGER SectionSize;
    HANDLE Handle;
    PMM_SECTION_SEGMENT Segment;

    /*
     * Create the section mapping physical memory
     */
    SectionSize.QuadPart = MmHighestPhysicalPage * PAGE_SIZE;
    InitializeObjectAttributes(&Obj,
                               &Name,
                               OBJ_PERMANENT | OBJ_KERNEL_EXCLUSIVE,
                               NULL,
                               NULL);
    /*
     * Create the Object
     */
    Status = ObCreateObject(KernelMode,
                            MmSectionObjectType,
                            &Obj,
                            ExGetPreviousMode(),
                            NULL,
                            sizeof(*PhysSection),
                            0,
                            0,
                            (PVOID*)&PhysSection);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmCreatePhysicalMemorySection: failed to create object (0x%lx)\n", Status);
        return Status;
    }

    /*
     * Initialize it
     */
    RtlZeroMemory(PhysSection, sizeof(*PhysSection));

    /* Mark this as a "ROS Section" */
    PhysSection->u.Flags.filler = 1;
    PhysSection->InitialPageProtection = PAGE_EXECUTE_READWRITE;
    PhysSection->u.Flags.PhysicalMemory = 1;
    PhysSection->SizeOfSection = SectionSize;
    Segment = ExAllocatePoolWithTag(NonPagedPool, sizeof(MM_SECTION_SEGMENT),
                                    TAG_MM_SECTION_SEGMENT);
    if (Segment == NULL)
    {
        ObDereferenceObject(PhysSection);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(Segment, sizeof(MM_SECTION_SEGMENT));
    PhysSection->Segment = (PSEGMENT)Segment;
    Segment->RefCount = 1;

    Segment->ReferenceCount = &Segment->RefCount;
    Segment->Flags = &Segment->SegFlags;

    ExInitializeFastMutex(&Segment->Lock);
    Segment->Image.FileOffset = 0;
    Segment->Protection = PAGE_EXECUTE_READWRITE;
    Segment->RawLength = SectionSize;
    Segment->Length = SectionSize;
    Segment->SegFlags = MM_PHYSICALMEMORY_SEGMENT;
    Segment->WriteCopy = FALSE;
    Segment->Image.VirtualAddress = 0;
    Segment->Image.Characteristics = 0;
    MiInitializeSectionPageTable(Segment);

    Status = ObInsertObject(PhysSection,
                            NULL,
                            SECTION_ALL_ACCESS,
                            0,
                            NULL,
                            &Handle);
    if (!NT_SUCCESS(Status))
    {
        /* Note: ObInsertObject dereferences PhysSection on failure */
        return Status;
    }
    ObCloseHandle(Handle, KernelMode);

    return STATUS_SUCCESS;
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
MmInitSectionImplementation(VOID)
{
    OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
    UNICODE_STRING Name;

    DPRINT("Creating Section Object Type\n");

    /* Initialize the section based root */
    ASSERT(MmSectionBasedRoot.NumberGenericTableElements == 0);
    MmSectionBasedRoot.BalancedRoot.u1.Parent = &MmSectionBasedRoot.BalancedRoot;

    /* Initialize the Section object type  */
    RtlZeroMemory(&ObjectTypeInitializer, sizeof(ObjectTypeInitializer));
    RtlInitUnicodeString(&Name, L"Section");
    ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
    ObjectTypeInitializer.DefaultPagedPoolCharge = sizeof(SECTION);
    ObjectTypeInitializer.PoolType = PagedPool;
    ObjectTypeInitializer.UseDefaultObject = TRUE;
    ObjectTypeInitializer.GenericMapping = MmpSectionMapping;
    ObjectTypeInitializer.DeleteProcedure = MmpDeleteSection;
    ObjectTypeInitializer.CloseProcedure = MmpCloseSection;
    ObjectTypeInitializer.ValidAccessMask = SECTION_ALL_ACCESS;
    ObjectTypeInitializer.InvalidAttributes = OBJ_OPENLINK;
    ObCreateObjectType(&Name, &ObjectTypeInitializer, NULL, &MmSectionObjectType);

    MmCreatePhysicalMemorySection();

    ExInitializeResourceLite(&MmpExtendSectionLock);

    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
MmCreateDataFileSection(PSECTION *SectionObject,
                        ACCESS_MASK DesiredAccess,
                        POBJECT_ATTRIBUTES ObjectAttributes,
                        PLARGE_INTEGER UMaximumSize,
                        ULONG SectionPageProtection,
                        ULONG AllocationAttributes,
                        PFILE_OBJECT FileObject,
                        BOOLEAN GotFileHandle)
/*
 * Create a section backed by a data file
 */
{
    PSECTION Section;
    NTSTATUS Status;
    LARGE_INTEGER MaximumSize;
    PMM_SECTION_SEGMENT Segment;
    KIRQL OldIrql;

    /*
     * Create the section
     */
    Status = ObCreateObject(ExGetPreviousMode(),
                            MmSectionObjectType,
                            ObjectAttributes,
                            ExGetPreviousMode(),
                            NULL,
                            sizeof(*Section),
                            0,
                            0,
                            (PVOID*)&Section);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    /*
     * Initialize it
     */
    RtlZeroMemory(Section, sizeof(*Section));

    /* Mark this as a "ROS" section */
    Section->u.Flags.filler = 1;
    Section->InitialPageProtection = SectionPageProtection;
    Section->u.Flags.File = 1;

    if (AllocationAttributes & SEC_NO_CHANGE)
        Section->u.Flags.NoChange = 1;

    if (!GotFileHandle)
    {
        ASSERT(UMaximumSize != NULL);
        // ASSERT(UMaximumSize->QuadPart != 0);
        MaximumSize = *UMaximumSize;
    }
    else
    {
        LARGE_INTEGER FileSize;
        Status = FsRtlGetFileSize(FileObject, &FileSize);
        if (!NT_SUCCESS(Status))
        {
            ObDereferenceObject(Section);
            return Status;
        }

        /*
         * FIXME: Revise this once a locking order for file size changes is
         * decided
         */
        if ((UMaximumSize != NULL) && (UMaximumSize->QuadPart != 0))
        {
            MaximumSize = *UMaximumSize;
        }
        else
        {
            MaximumSize = FileSize;
            /* Mapping zero-sized files isn't allowed. */
            if (MaximumSize.QuadPart == 0)
            {
                ObDereferenceObject(Section);
                return STATUS_MAPPED_FILE_SIZE_ZERO;
            }
        }

        /* A negative size must never reach the file system as an end of file */
        if (MaximumSize.QuadPart < 0)
        {
            ObDereferenceObject(Section);
            return STATUS_SECTION_TOO_BIG;
        }

        if (MaximumSize.QuadPart > FileSize.QuadPart)
        {
            /* Only a section that can write to the file extends it */
            if (!(SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                ObDereferenceObject(Section);
                return STATUS_SECTION_TOO_BIG;
            }

            Status = IoSetInformation(FileObject,
                                      FileEndOfFileInformation,
                                      sizeof(LARGE_INTEGER),
                                      &MaximumSize);
            if (!NT_SUCCESS(Status))
            {
                ObDereferenceObject(Section);
                return STATUS_SECTION_NOT_EXTENDED;
            }
        }
    }

    if (FileObject->SectionObjectPointer == NULL)
    {
        ObDereferenceObject(Section);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    /*
     * Lock the file
     */
    Status = MmspWaitForFileLock(FileObject);
    if (Status != STATUS_SUCCESS)
    {
        ObDereferenceObject(Section);
        return Status;
    }

    /* Lock the PFN lock while messing with Section Object pointers */
grab_segment:
    OldIrql = MiAcquirePfnLock();
    Segment = FileObject->SectionObjectPointer->DataSectionObject;

    while (Segment && (Segment->SegFlags & (MM_SEGMENT_INDELETE | MM_SEGMENT_INCREATE)))
    {
        MiReleasePfnLock(OldIrql);
        KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
        OldIrql = MiAcquirePfnLock();
        Segment = FileObject->SectionObjectPointer->DataSectionObject;
    }

    /*
     * If this file hasn't been mapped as a data file before then allocate a
     * section segment to describe the data file mapping
     */
    if (Segment == NULL)
    {
        /* Release the lock. ExAllocatePoolWithTag might acquire it */
        MiReleasePfnLock(OldIrql);

        Segment = ExAllocatePoolWithTag(NonPagedPool, sizeof(MM_SECTION_SEGMENT),
                                        TAG_MM_SECTION_SEGMENT);
        if (Segment == NULL)
        {
            //KeSetEvent((PVOID)&FileObject->Lock, IO_NO_INCREMENT, FALSE);
            ObDereferenceObject(Section);
            return STATUS_NO_MEMORY;
        }

        /* We are creating it */
        RtlZeroMemory(Segment, sizeof(*Segment));
        Segment->SegFlags = MM_DATAFILE_SEGMENT | MM_SEGMENT_INCREATE;
        Segment->RefCount = 1;

        /* Acquire lock again */
        OldIrql = MiAcquirePfnLock();

        if (FileObject->SectionObjectPointer->DataSectionObject != NULL)
        {
            /* Well that's bad luck. Restart it all over */
            MiReleasePfnLock(OldIrql);
            ExFreePoolWithTag(Segment, TAG_MM_SECTION_SEGMENT);
            goto grab_segment;
        }

        FileObject->SectionObjectPointer->DataSectionObject = Segment;

        /* We're safe to release the lock now */
        MiReleasePfnLock(OldIrql);

        Section->Segment = (PSEGMENT)Segment;

        /* Self-referencing segment */
        Segment->Flags = &Segment->SegFlags;
        Segment->ReferenceCount = &Segment->RefCount;

        Segment->SectionCount = 1;

        ExInitializeFastMutex(&Segment->Lock);
        Segment->FileObject = FileObject;
        ObReferenceObject(FileObject);

        Segment->Image.FileOffset = 0;
        Segment->Protection = SectionPageProtection;

        Segment->Image.Characteristics = 0;
        Segment->WriteCopy = (SectionPageProtection & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY));
        if (AllocationAttributes & SEC_RESERVE)
        {
            Segment->Length.QuadPart = Segment->RawLength.QuadPart = 0;
        }
        else
        {
            Segment->RawLength.QuadPart = MaximumSize.QuadPart;
            Segment->Length.QuadPart = PAGE_ROUND_UP(Segment->RawLength.QuadPart);
        }
        Segment->Image.VirtualAddress = 0;
        MiInitializeSectionPageTable(Segment);

        /* We're good to use it now */
        OldIrql = MiAcquirePfnLock();
        Segment->SegFlags &= ~MM_SEGMENT_INCREATE;
        MiReleasePfnLock(OldIrql);
    }
    else
    {
        Section->Segment = (PSEGMENT)Segment;
        InterlockedIncrement64(&Segment->RefCount);
        InterlockedIncrementUL(&Segment->SectionCount);

        MiReleasePfnLock(OldIrql);

        MmLockSectionSegment(Segment);

        if (MaximumSize.QuadPart > Segment->RawLength.QuadPart &&
                !(AllocationAttributes & SEC_RESERVE))
        {
            Segment->RawLength.QuadPart = MaximumSize.QuadPart;
            Segment->Length.QuadPart = PAGE_ROUND_UP(Segment->RawLength.QuadPart);
        }

        MmUnlockSectionSegment(Segment);
    }
    Section->SizeOfSection = MaximumSize;

    //KeSetEvent((PVOID)&FileObject->Lock, IO_NO_INCREMENT, FALSE);
    *SectionObject = Section;
    return STATUS_SUCCESS;
}

/*
 TODO: not that great (declaring loaders statically, having to declare all of
 them, having to keep them extern, etc.), will fix in the future
*/
extern NTSTATUS NTAPI PeFmtCreateSection
(
    IN CONST VOID * FileHeader,
    IN SIZE_T FileHeaderSize,
    IN PVOID File,
    OUT PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
    OUT PULONG Flags,
    IN PEXEFMT_CB_READ_FILE ReadFileCb,
    IN PEXEFMT_CB_ALLOCATE_SEGMENTS AllocateSegmentsCb
);

extern NTSTATUS NTAPI ElfFmtCreateSection
(
    IN CONST VOID * FileHeader,
    IN SIZE_T FileHeaderSize,
    IN PVOID File,
    OUT PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
    OUT PULONG Flags,
    IN PEXEFMT_CB_READ_FILE ReadFileCb,
    IN PEXEFMT_CB_ALLOCATE_SEGMENTS AllocateSegmentsCb
);

static PEXEFMT_LOADER ExeFmtpLoaders[] =
{
    PeFmtCreateSection,
#ifdef __ELF
    ElfFmtCreateSection
#endif
};

static
PMM_SECTION_SEGMENT
NTAPI
ExeFmtpAllocateSegments(IN ULONG NrSegments)
{
    SIZE_T SizeOfSegments;
    PMM_SECTION_SEGMENT Segments;

    /* TODO: check for integer overflow */
    SizeOfSegments = sizeof(MM_SECTION_SEGMENT) * NrSegments;

    Segments = ExAllocatePoolWithTag(NonPagedPool,
                                     SizeOfSegments,
                                     TAG_MM_SECTION_SEGMENT);

    if(Segments)
        RtlZeroMemory(Segments, SizeOfSegments);

    return Segments;
}
static
NTSTATUS
NTAPI
ExeFmtpReadFile(IN PVOID File,
                IN PLARGE_INTEGER Offset,
                IN ULONG Length,
                OUT PVOID * Data,
                OUT PVOID * AllocBase,
                OUT PULONG ReadSize)
{
    NTSTATUS Status;
    LARGE_INTEGER FileOffset;
    ULONG AdjustOffset;
    ULONG OffsetAdjustment;
    ULONG BufferSize;
    ULONG UsedSize;
    PVOID Buffer;
    PFILE_OBJECT FileObject = File;
    IO_STATUS_BLOCK Iosb;

    ASSERT_IRQL_LESS(DISPATCH_LEVEL);

    if(Length == 0)
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    FileOffset = *Offset;

    /* Negative/special offset: it cannot be used in this context */
    if(FileOffset.u.HighPart < 0)
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    AdjustOffset = PAGE_ROUND_DOWN(FileOffset.u.LowPart);
    OffsetAdjustment = FileOffset.u.LowPart - AdjustOffset;
    FileOffset.u.LowPart = AdjustOffset;

    BufferSize = Length + OffsetAdjustment;
    BufferSize = PAGE_ROUND_UP(BufferSize);

    /*
     * It's ok to use paged pool, because this is a temporary buffer only used in
     * the loading of executables. The assumption is that MmCreateSection is
     * always called at low IRQLs and that these buffers don't survive a brief
     * initialization phase
     */
    Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize, 'rXmM');
    if (!Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = MiSimpleRead(FileObject, &FileOffset, Buffer, BufferSize, TRUE, &Iosb);

    UsedSize = (ULONG)Iosb.Information;

    if(NT_SUCCESS(Status) && UsedSize < OffsetAdjustment)
    {
        Status = STATUS_IN_PAGE_ERROR;
        ASSERT(!NT_SUCCESS(Status));
    }

    if(NT_SUCCESS(Status))
    {
        *Data = (PVOID)((ULONG_PTR)Buffer + OffsetAdjustment);
        *AllocBase = Buffer;
        *ReadSize = UsedSize - OffsetAdjustment;
    }
    else
    {
        ExFreePoolWithTag(Buffer, 'rXmM');
    }

    return Status;
}

#ifdef NASSERT
# define MmspAssertSegmentsSorted(OBJ_) ((void)0)
# define MmspAssertSegmentsNoOverlap(OBJ_) ((void)0)
# define MmspAssertSegmentsPageAligned(OBJ_) ((void)0)
#else
static
VOID
NTAPI
MmspAssertSegmentsSorted(IN PMM_IMAGE_SECTION_OBJECT ImageSectionObject)
{
    ULONG i;

    for( i = 1; i < ImageSectionObject->NrSegments; ++ i )
    {
        ASSERT(ImageSectionObject->Segments[i].Image.VirtualAddress >=
               ImageSectionObject->Segments[i - 1].Image.VirtualAddress);
    }
}

static
VOID
NTAPI
MmspAssertSegmentsNoOverlap(IN PMM_IMAGE_SECTION_OBJECT ImageSectionObject)
{
    ULONG i;

    MmspAssertSegmentsSorted(ImageSectionObject);

    for( i = 0; i < ImageSectionObject->NrSegments; ++ i )
    {
        ASSERT(ImageSectionObject->Segments[i].Length.QuadPart > 0);

        if(i > 0)
        {
            ASSERT(ImageSectionObject->Segments[i].Image.VirtualAddress >=
                   (ImageSectionObject->Segments[i - 1].Image.VirtualAddress +
                    ImageSectionObject->Segments[i - 1].Length.QuadPart));
        }
    }
}

static
VOID
NTAPI
MmspAssertSegmentsPageAligned(IN PMM_IMAGE_SECTION_OBJECT ImageSectionObject)
{
    ULONG i;

    for( i = 0; i < ImageSectionObject->NrSegments; ++ i )
    {
        ASSERT((ImageSectionObject->Segments[i].Image.VirtualAddress % PAGE_SIZE) == 0);
        ASSERT((ImageSectionObject->Segments[i].Length.QuadPart % PAGE_SIZE) == 0);
    }
}
#endif

static
int
__cdecl
MmspCompareSegments(const void * x,
                    const void * y)
{
    const MM_SECTION_SEGMENT *Segment1 = (const MM_SECTION_SEGMENT *)x;
    const MM_SECTION_SEGMENT *Segment2 = (const MM_SECTION_SEGMENT *)y;

    if (Segment1->Image.VirtualAddress > Segment2->Image.VirtualAddress)
        return 1;
    else if (Segment1->Image.VirtualAddress < Segment2->Image.VirtualAddress)
        return -1;
    else
        return 0;
}

/*
 * Ensures an image section's segments are sorted in memory
 */
static
VOID
NTAPI
MmspSortSegments(IN OUT PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
                 IN ULONG Flags)
{
    if (Flags & EXEFMT_LOAD_ASSUME_SEGMENTS_SORTED)
    {
        MmspAssertSegmentsSorted(ImageSectionObject);
    }
    else
    {
        qsort(ImageSectionObject->Segments,
              ImageSectionObject->NrSegments,
              sizeof(ImageSectionObject->Segments[0]),
              MmspCompareSegments);
    }
}


/*
 * Ensures an image section's segments don't overlap in memory and don't have
 * gaps and don't have a null size. We let them map to overlapping file regions,
 * though - that's not necessarily an error
 */
static
BOOLEAN
NTAPI
MmspCheckSegmentBounds
(
    IN OUT PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
    IN ULONG Flags
)
{
    ULONG i;

    if (Flags & EXEFMT_LOAD_ASSUME_SEGMENTS_NO_OVERLAP)
    {
        MmspAssertSegmentsNoOverlap(ImageSectionObject);
        return TRUE;
    }

    ASSERT(ImageSectionObject->NrSegments >= 1);

    for ( i = 0; i < ImageSectionObject->NrSegments; ++ i )
    {
        if(ImageSectionObject->Segments[i].Length.QuadPart == 0)
        {
            return FALSE;
        }

        if(i > 0)
        {
            /*
             * TODO: relax the limitation on gaps. For example, gaps smaller than a
             * page could be OK (Windows seems to be OK with them), and larger gaps
             * could lead to image sections spanning several discontiguous regions
             * (NtMapViewOfSection could then refuse to map them, and they could
             * e.g. only be allowed as parameters to NtCreateProcess, like on UNIX)
             */
            if ((ImageSectionObject->Segments[i - 1].Image.VirtualAddress +
                    ImageSectionObject->Segments[i - 1].Length.QuadPart) !=
                    ImageSectionObject->Segments[i].Image.VirtualAddress)
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*
 * Merges and pads an image section's segments until they all are page-aligned
 * and have a size that is a multiple of the page size
 */
static
BOOLEAN
NTAPI
MmspPageAlignSegments
(
    IN OUT PMM_IMAGE_SECTION_OBJECT ImageSectionObject,
    IN ULONG Flags
)
{
    ULONG i;
    ULONG LastSegment;
    PMM_SECTION_SEGMENT EffectiveSegment;

    if (Flags & EXEFMT_LOAD_ASSUME_SEGMENTS_PAGE_ALIGNED)
    {
        MmspAssertSegmentsPageAligned(ImageSectionObject);
        return TRUE;
    }

    LastSegment = 0;
    EffectiveSegment = &ImageSectionObject->Segments[LastSegment];

    for ( i = 0; i < ImageSectionObject->NrSegments; ++ i )
    {
        /*
         * The first segment requires special handling
         */
        if (i == 0)
        {
            ULONG_PTR VirtualAddress;
            ULONG_PTR VirtualOffset;

            VirtualAddress = EffectiveSegment->Image.VirtualAddress;

            /* Round down the virtual address to the nearest page */
            EffectiveSegment->Image.VirtualAddress = PAGE_ROUND_DOWN(VirtualAddress);

            /* Round up the virtual size to the nearest page */
            EffectiveSegment->Length.QuadPart = PAGE_ROUND_UP(VirtualAddress + EffectiveSegment->Length.QuadPart) -
                                                EffectiveSegment->Image.VirtualAddress;

            /* Adjust the raw address and size */
            VirtualOffset = VirtualAddress - EffectiveSegment->Image.VirtualAddress;

            if (EffectiveSegment->Image.FileOffset < VirtualOffset)
            {
                return FALSE;
            }

            /*
             * Garbage in, garbage out: unaligned base addresses make the file
             * offset point in curious and odd places, but that's what we were
             * asked for
             */
            EffectiveSegment->Image.FileOffset -= VirtualOffset;
            EffectiveSegment->RawLength.QuadPart += VirtualOffset;
        }
        else
        {
            PMM_SECTION_SEGMENT Segment = &ImageSectionObject->Segments[i];
            ULONG_PTR EndOfEffectiveSegment;

            EndOfEffectiveSegment = (ULONG_PTR)(EffectiveSegment->Image.VirtualAddress + EffectiveSegment->Length.QuadPart);
            ASSERT((EndOfEffectiveSegment % PAGE_SIZE) == 0);

            /*
             * The current segment begins exactly where the current effective
             * segment ended, therefore beginning a new effective segment
             */
            if (EndOfEffectiveSegment == Segment->Image.VirtualAddress)
            {
                LastSegment ++;
                ASSERT(LastSegment <= i);
                ASSERT(LastSegment < ImageSectionObject->NrSegments);

                EffectiveSegment = &ImageSectionObject->Segments[LastSegment];

                if (LastSegment != i)
                {
                    /*
                     * Copy the current segment. If necessary, the effective segment
                     * will be expanded later
                     */
                    *EffectiveSegment = *Segment;
                }

                /*
                 * Page-align the virtual size. We know for sure the virtual address
                 * already is
                 */
                ASSERT((EffectiveSegment->Image.VirtualAddress % PAGE_SIZE) == 0);
                EffectiveSegment->Length.QuadPart = PAGE_ROUND_UP(EffectiveSegment->Length.QuadPart);
            }
            /*
             * The current segment is still part of the current effective segment:
             * extend the effective segment to reflect this
             */
            else if (EndOfEffectiveSegment > Segment->Image.VirtualAddress)
            {
                static const ULONG FlagsToProtection[16] =
                {
                    PAGE_NOACCESS,
                    PAGE_READONLY,
                    PAGE_READWRITE,
                    PAGE_READWRITE,
                    PAGE_EXECUTE_READ,
                    PAGE_EXECUTE_READ,
                    PAGE_EXECUTE_READWRITE,
                    PAGE_EXECUTE_READWRITE,
                    PAGE_WRITECOPY,
                    PAGE_WRITECOPY,
                    PAGE_WRITECOPY,
                    PAGE_WRITECOPY,
                    PAGE_EXECUTE_WRITECOPY,
                    PAGE_EXECUTE_WRITECOPY,
                    PAGE_EXECUTE_WRITECOPY,
                    PAGE_EXECUTE_WRITECOPY
                };

                unsigned ProtectionFlags;

                /*
                 * Extend the file size
                 */

                /* Unaligned segments must be contiguous within the file */
                if (Segment->Image.FileOffset != (EffectiveSegment->Image.FileOffset +
                                                  EffectiveSegment->RawLength.QuadPart))
                {
                    return FALSE;
                }

                EffectiveSegment->RawLength.QuadPart += Segment->RawLength.QuadPart;

                /*
                 * Extend the virtual size
                 */
                ASSERT(PAGE_ROUND_UP(Segment->Image.VirtualAddress + Segment->Length.QuadPart) >= EndOfEffectiveSegment);

                EffectiveSegment->Length.QuadPart = PAGE_ROUND_UP(Segment->Image.VirtualAddress + Segment->Length.QuadPart) -
                                                    EffectiveSegment->Image.VirtualAddress;

                /*
                 * Merge the protection
                 */
                EffectiveSegment->Protection |= Segment->Protection;

                /* Clean up redundance */
                ProtectionFlags = 0;

                if(EffectiveSegment->Protection & PAGE_IS_READABLE)
                    ProtectionFlags |= 1 << 0;

                if(EffectiveSegment->Protection & PAGE_IS_WRITABLE)
                    ProtectionFlags |= 1 << 1;

                if(EffectiveSegment->Protection & PAGE_IS_EXECUTABLE)
                    ProtectionFlags |= 1 << 2;

                if(EffectiveSegment->Protection & PAGE_IS_WRITECOPY)
                    ProtectionFlags |= 1 << 3;

                ASSERT(ProtectionFlags < 16);
                EffectiveSegment->Protection = FlagsToProtection[ProtectionFlags];

                /* If a segment was required to be shared and cannot, fail */
                if(!(Segment->Protection & PAGE_IS_WRITECOPY) &&
                        EffectiveSegment->Protection & PAGE_IS_WRITECOPY)
                {
                    return FALSE;
                }
            }
            /*
             * We assume no holes between segments at this point
             */
            else
            {
                KeBugCheck(MEMORY_MANAGEMENT);
            }
        }
    }
    ImageSectionObject->NrSegments = LastSegment + 1;

    return TRUE;
}

NTSTATUS
ExeFmtpCreateImageSection(PFILE_OBJECT FileObject,
                          PMM_IMAGE_SECTION_OBJECT ImageSectionObject)
{
    LARGE_INTEGER Offset;
    PVOID FileHeader;
    PVOID FileHeaderBuffer;
    ULONG FileHeaderSize;
    ULONG Flags;
    ULONG OldNrSegments;
    NTSTATUS Status;
    ULONG i;

    /*
     * Read the beginning of the file (2 pages). Should be enough to contain
     * all (or most) of the headers
     */
    Offset.QuadPart = 0;

    Status = ExeFmtpReadFile (FileObject,
                              &Offset,
                              PAGE_SIZE * 2,
                              &FileHeader,
                              &FileHeaderBuffer,
                              &FileHeaderSize);

    if (!NT_SUCCESS(Status))
        return Status;

    if (FileHeaderSize == 0)
    {
        ExFreePool(FileHeaderBuffer);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Look for a loader that can handle this executable
     */
    for (i = 0; i < RTL_NUMBER_OF(ExeFmtpLoaders); ++ i)
    {
        Flags = 0;

        Status = ExeFmtpLoaders[i](FileHeader,
                                   FileHeaderSize,
                                   FileObject,
                                   ImageSectionObject,
                                   &Flags,
                                   ExeFmtpReadFile,
                                   ExeFmtpAllocateSegments);

        if (!NT_SUCCESS(Status))
        {
            if (ImageSectionObject->Segments)
            {
                ExFreePool(ImageSectionObject->Segments);
                ImageSectionObject->Segments = NULL;
            }
        }

        if (Status != STATUS_ROS_EXEFMT_UNKNOWN_FORMAT)
            break;
    }

    ExFreePoolWithTag(FileHeaderBuffer, 'rXmM');

    /*
     * No loader handled the format
     */
    if (Status == STATUS_ROS_EXEFMT_UNKNOWN_FORMAT)
    {
        Status = STATUS_INVALID_IMAGE_NOT_MZ;
        ASSERT(!NT_SUCCESS(Status));
    }

    if (!NT_SUCCESS(Status))
        return Status;

    ASSERT(ImageSectionObject->Segments != NULL);
    ASSERT(ImageSectionObject->RefCount > 0);

    /*
     * Some defaults
     */
    /* FIXME? are these values platform-dependent? */
    if (ImageSectionObject->ImageInformation.MaximumStackSize == 0)
        ImageSectionObject->ImageInformation.MaximumStackSize = 0x40000;

    if(ImageSectionObject->ImageInformation.CommittedStackSize == 0)
        ImageSectionObject->ImageInformation.CommittedStackSize = 0x1000;

    if(ImageSectionObject->BasedAddress == NULL)
    {
        if(ImageSectionObject->ImageInformation.ImageCharacteristics & IMAGE_FILE_DLL)
            ImageSectionObject->BasedAddress = (PVOID)0x10000000;
        else
            ImageSectionObject->BasedAddress = (PVOID)0x00400000;
    }

    /*
     * And now the fun part: fixing the segments
     */

    /* Sort them by virtual address */
    MmspSortSegments(ImageSectionObject, Flags);

    /* Ensure they don't overlap in memory */
    if (!MmspCheckSegmentBounds(ImageSectionObject, Flags))
        return STATUS_INVALID_IMAGE_FORMAT;

    /* Ensure they are aligned */
    OldNrSegments = ImageSectionObject->NrSegments;

    if (!MmspPageAlignSegments(ImageSectionObject, Flags))
        return STATUS_INVALID_IMAGE_FORMAT;

    /* Trim them if the alignment phase merged some of them */
    if (ImageSectionObject->NrSegments < OldNrSegments)
    {
        PMM_SECTION_SEGMENT Segments;
        SIZE_T SizeOfSegments;

        SizeOfSegments = sizeof(MM_SECTION_SEGMENT) * ImageSectionObject->NrSegments;

        Segments = ExAllocatePoolWithTag(PagedPool,
                                         SizeOfSegments,
                                         TAG_MM_SECTION_SEGMENT);

        if (Segments == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlCopyMemory(Segments, ImageSectionObject->Segments, SizeOfSegments);
        ExFreePool(ImageSectionObject->Segments);
        ImageSectionObject->Segments = Segments;
    }

    /* And finish their initialization */
    for ( i = 0; i < ImageSectionObject->NrSegments; ++ i )
    {
        ExInitializeFastMutex(&ImageSectionObject->Segments[i].Lock);
        ImageSectionObject->Segments[i].ReferenceCount = &ImageSectionObject->RefCount;
        ImageSectionObject->Segments[i].Flags = &ImageSectionObject->SegFlags;
        MiInitializeSectionPageTable(&ImageSectionObject->Segments[i]);
        ImageSectionObject->Segments[i].FileObject = FileObject;
    }

    ASSERT(ImageSectionObject->RefCount > 0);

    ImageSectionObject->FileObject = FileObject;

    ASSERT(NT_SUCCESS(Status));
    return Status;
}

NTSTATUS
MmCreateImageSection(PSECTION *SectionObject,
                     ACCESS_MASK DesiredAccess,
                     POBJECT_ATTRIBUTES ObjectAttributes,
                     PLARGE_INTEGER UMaximumSize,
                     ULONG SectionPageProtection,
                     ULONG AllocationAttributes,
                     PFILE_OBJECT FileObject)
{
    PSECTION Section;
    NTSTATUS Status;
    PMM_IMAGE_SECTION_OBJECT ImageSectionObject;
    KIRQL OldIrql;


    if (FileObject == NULL)
        return STATUS_INVALID_FILE_FOR_SECTION;

    if (FileObject->SectionObjectPointer == NULL)
    {
        DPRINT1("Denying section creation due to missing cache initialization\n");
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    /*
     * Create the section
     */
    Status = ObCreateObject (ExGetPreviousMode(),
                             MmSectionObjectType,
                             ObjectAttributes,
                             ExGetPreviousMode(),
                             NULL,
                             sizeof(*Section),
                             0,
                             0,
                             (PVOID*)(PVOID)&Section);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /*
     * Initialize it
     */
    RtlZeroMemory(Section, sizeof(*Section));

    /* Mark this as a "ROS" Section */
    Section->u.Flags.filler = 1;

    Section->InitialPageProtection = SectionPageProtection;
    Section->SizeOfSection = *UMaximumSize;
    Section->u.Flags.File = 1;
    Section->u.Flags.Image = 1;
    if (AllocationAttributes & SEC_NO_CHANGE)
        Section->u.Flags.NoChange = 1;

grab_image_section_object:
    OldIrql = MiAcquirePfnLock();

    /* Wait for it to be properly created or deleted */
    ImageSectionObject = FileObject->SectionObjectPointer->ImageSectionObject;
    while(ImageSectionObject && (ImageSectionObject->SegFlags & (MM_SEGMENT_INDELETE | MM_SEGMENT_INCREATE)))
    {
        MiReleasePfnLock(OldIrql);

        KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);

        OldIrql = MiAcquirePfnLock();
        ImageSectionObject = FileObject->SectionObjectPointer->ImageSectionObject;
    }

    if (ImageSectionObject == NULL)
    {
        NTSTATUS StatusExeFmt;

        /* Release the lock because ExAllocatePoolWithTag could need to acquire it */
        MiReleasePfnLock(OldIrql);

        ImageSectionObject = ExAllocatePoolZero(NonPagedPool, sizeof(MM_IMAGE_SECTION_OBJECT), TAG_MM_SECTION_SEGMENT);
        if (ImageSectionObject == NULL)
        {
            ObDereferenceObject(Section);
            return STATUS_NO_MEMORY;
        }

        ImageSectionObject->SegFlags = MM_SEGMENT_INCREATE;
        ImageSectionObject->RefCount = 1;
        ImageSectionObject->SectionCount = 1;

        OldIrql = MiAcquirePfnLock();
        if (FileObject->SectionObjectPointer->ImageSectionObject != NULL)
        {
            MiReleasePfnLock(OldIrql);
            /* Bad luck. Start over */
            ExFreePoolWithTag(ImageSectionObject, TAG_MM_SECTION_SEGMENT);
            goto grab_image_section_object;
        }

        FileObject->SectionObjectPointer->ImageSectionObject = ImageSectionObject;

        MiReleasePfnLock(OldIrql);

        /* Purge the cache */
        CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, NULL);

        StatusExeFmt = ExeFmtpCreateImageSection(FileObject, ImageSectionObject);

        if (!NT_SUCCESS(StatusExeFmt))
        {
            /* Unset */
            OldIrql = MiAcquirePfnLock();
            FileObject->SectionObjectPointer->ImageSectionObject = NULL;
            MiReleasePfnLock(OldIrql);

            if(ImageSectionObject->Segments != NULL)
                ExFreePool(ImageSectionObject->Segments);

            /*
             * If image file is empty, then return that the file is invalid for section
             */
            Status = StatusExeFmt;
            if (StatusExeFmt == STATUS_END_OF_FILE)
            {
                Status = STATUS_INVALID_FILE_FOR_SECTION;
            }

            ExFreePoolWithTag(ImageSectionObject, TAG_MM_SECTION_SEGMENT);
            ObDereferenceObject(Section);
            return Status;
        }

        Section->Segment = (PSEGMENT)ImageSectionObject;
        ASSERT(ImageSectionObject->Segments);
        ASSERT(ImageSectionObject->RefCount > 0);

        /*
         * Lock the file
         */
        Status = MmspWaitForFileLock(FileObject);
        if (!NT_SUCCESS(Status))
        {
            /* Unset */
            OldIrql = MiAcquirePfnLock();
            FileObject->SectionObjectPointer->ImageSectionObject = NULL;
            MiReleasePfnLock(OldIrql);

            ExFreePool(ImageSectionObject->Segments);
            ExFreePool(ImageSectionObject);
            ObDereferenceObject(Section);
            return Status;
        }

        OldIrql = MiAcquirePfnLock();
        ImageSectionObject->SegFlags &= ~MM_SEGMENT_INCREATE;

        /* Take a ref on the file on behalf of the newly created structure */
        ObReferenceObject(FileObject);

        MiReleasePfnLock(OldIrql);

        Status = StatusExeFmt;
    }
    else
    {
        /* If FS driver called for delete, tell them it's not possible anymore. */
        ImageSectionObject->SegFlags &= ~MM_IMAGE_SECTION_FLUSH_DELETE;

        /* Take one ref */
        InterlockedIncrement64(&ImageSectionObject->RefCount);
        ImageSectionObject->SectionCount++;

        MiReleasePfnLock(OldIrql);

        Section->Segment = (PSEGMENT)ImageSectionObject;

        Status = STATUS_SUCCESS;
    }

    if (Section->SizeOfSection.QuadPart == 0)
    {
        /* Mapping overwrites ImageFileSize, so take the header's SizeOfImage when there is one */
        if (ImageSectionObject->SizeOfImage != 0)
            Section->SizeOfSection.QuadPart = PAGE_ROUND_UP_64((ULONGLONG)ImageSectionObject->SizeOfImage);
        else
            Section->SizeOfSection.QuadPart = ImageSectionObject->ImageInformation.ImageFileSize;
    }
    else if (NT_SUCCESS(Status) &&
             (ImageSectionObject->SizeOfImage != 0) &&
             ((ULONGLONG)Section->SizeOfSection.QuadPart >
              (((ULONGLONG)ImageSectionObject->SizeOfImage + PAGE_SIZE - 1) & ~(ULONGLONG)(PAGE_SIZE - 1))))
    {
        /* An image section is never larger than its page-rounded SizeOfImage,
         * which is 0 when the optional header is too short to hold it */
        ObDereferenceObject(Section);
        return STATUS_SECTION_TOO_BIG;
    }

    //KeSetEvent((PVOID)&FileObject->Lock, IO_NO_INCREMENT, FALSE);
    *SectionObject = Section;
    ASSERT(ImageSectionObject->RefCount > 0);

    return Status;
}

/*
 * Pages of commit charge a view of this segment takes: all of them when a
 * page can become private on write (the copy-on-write test of the fault
 * handler: a copy-on-write segment or protection, and a writable view).
 */
static
SIZE_T
MiViewCommitCharge(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ ULONG Protect,
    _In_ SIZE_T ViewSize)
{
    if ((Protect & PAGE_IS_WRITECOPY) ||
        (Segment->WriteCopy && (Protect & PAGE_IS_WRITABLE)))
    {
        return BYTES_TO_PAGES(ViewSize);
    }
    return 0;
}

static NTSTATUS
MmMapViewOfSegment(
    PMMSUPPORT AddressSpace,
    BOOLEAN AsImage,
    PMM_SECTION_SEGMENT Segment,
    PVOID* BaseAddress,
    SIZE_T ViewSize,
    ULONG Protect,
    LONGLONG ViewOffset,
    ULONG AllocationType,
    SIZE_T CommitCharge)
{
    PMEMORY_AREA MArea;
    PEPROCESS Process;
    NTSTATUS Status;
    ULONG Granularity;

    ASSERT(ViewSize != 0);

    if (Segment->WriteCopy)
    {
        /* We have to do this because the not present fault
         * and access fault handlers depend on the protection
         * that should be granted AFTER the COW fault takes
         * place to be in Region->Protect. The not present fault
         * handler changes this to the correct protection for COW when
         * mapping the pages into the process's address space. If a COW
         * fault takes place, the access fault handler sets the page protection
         * to these values for the newly copied pages
         */
        if (Protect == PAGE_WRITECOPY)
            Protect = PAGE_READWRITE;
        else if (Protect == PAGE_EXECUTE_WRITECOPY)
            Protect = PAGE_EXECUTE_READWRITE;
    }

    if (*BaseAddress == NULL)
        Granularity = MM_ALLOCATION_GRANULARITY;
    else
        Granularity = PAGE_SIZE;

#ifdef NEWCC
    if (Segment->Flags & MM_DATAFILE_SEGMENT)
    {
        LARGE_INTEGER FileOffset;
        FileOffset.QuadPart = ViewOffset;
        ObReferenceObject(Section);
        return _MiMapViewOfSegment(AddressSpace, Segment, BaseAddress, ViewSize, Protect, &FileOffset, AllocationType, __FILE__, __LINE__);
    }
#endif
    Status = MmCreateMemoryArea(AddressSpace,
                                MEMORY_AREA_SECTION_VIEW,
                                BaseAddress,
                                ViewSize,
                                Protect,
                                &MArea,
                                AllocationType,
                                Granularity);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Mapping between 0x%p and 0x%p failed (%X).\n",
                (*BaseAddress), (char*)(*BaseAddress) + ViewSize, Status);
        return Status;
    }

    /* Nothing is mapped and nothing refers to the area yet: free it if this fails */
    Status = MmInitializeRegion(&MArea->SectionData.RegionListHead,
                                ViewSize, 0, Protect);
    if (!NT_SUCCESS(Status))
    {
        MmFreeMemoryArea(AddressSpace, MArea, NULL, NULL);
        return Status;
    }

    InterlockedIncrement64(Segment->ReferenceCount);

    /* A file truncation must not cut through a view of a process, even once the section is closed */
    if (((*Segment->Flags) & MM_DATAFILE_SEGMENT) && (AddressSpace != MmGetKernelAddressSpace()))
        InterlockedIncrement(&Segment->UserMapCount);

    MArea->SectionData.Segment = Segment;
    MArea->SectionData.ViewOffset = ViewOffset;

    /* The view owns the charge the caller took for it from now on */
    MArea->SectionData.CommitCharge = CommitCharge;
    Process = MmGetAddressSpaceOwner(AddressSpace);
    if (Process != NULL)
        MiAddProcessCommit(Process, CommitCharge);

    if (AsImage)
    {
        MArea->VadNode.u.VadFlags.VadType = VadImageMap;
    }

    return STATUS_SUCCESS;
}


static VOID
MmFreeSectionPage(PVOID Context, MEMORY_AREA* MemoryArea, PVOID Address,
                  PFN_NUMBER Page, SWAPENTRY SwapEntry, BOOLEAN Dirty)
{
    ULONG_PTR Entry;
    LARGE_INTEGER Offset;
    SWAPENTRY SavedSwapEntry;
    PMM_SECTION_SEGMENT Segment;
    PMMSUPPORT AddressSpace;
    PEPROCESS Process;

    AddressSpace = (PMMSUPPORT)Context;
    Process = MmGetAddressSpaceOwner(AddressSpace);

    Address = (PVOID)PAGE_ROUND_DOWN(Address);

    Offset.QuadPart = ((ULONG_PTR)Address - MA_GetStartingAddress(MemoryArea)) +
                      MemoryArea->SectionData.ViewOffset;

    Segment = MemoryArea->SectionData.Segment;

    Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
    while (Entry && MM_IS_WAIT_PTE(Entry))
    {
        MmUnlockSectionSegment(Segment);
        MmUnlockAddressSpace(AddressSpace);

        KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);

        MmLockAddressSpace(AddressSpace);
        MmLockSectionSegment(Segment);
        Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
    }

    /*
     * For a dirty, datafile, non-private page, there shoulkd be no swap entry
     */
    if (*Segment->Flags & MM_DATAFILE_SEGMENT)
    {
        if (Page == PFN_FROM_SSE(Entry) && Dirty)
        {
            ASSERT(SwapEntry == 0);
        }
    }

    if (SwapEntry != 0)
    {
        /*
         * Sanity check
         */
        MmFreeSwapPage(SwapEntry);
    }
    else if (Page != 0)
    {
        if (IS_SWAP_FROM_SSE(Entry) ||
                Page != PFN_FROM_SSE(Entry))
        {
            ASSERT(Process != NULL);

            /*
             * Just dereference private pages
             */
            SavedSwapEntry = MmGetSavedSwapEntryPage(Page);
            if (SavedSwapEntry != 0)
            {
                MmFreeSwapPage(SavedSwapEntry);
                MmSetSavedSwapEntryPage(Page, 0);
            }
            MmDeleteRmap(Page, Process, Address);
            MmReleasePageMemoryConsumer(MC_USER, Page);
        }
        else
        {
            if (Process)
            {
                MmDeleteRmap(Page, Process, Address);
            }

            /* We don't dirtify for System Space Maps. We let Cc manage that */
            MmUnsharePageEntrySectionSegment(MemoryArea, Segment, &Offset, Process ? Dirty : FALSE, FALSE, NULL);
        }
    }
}

static
VOID
MiWaitForViewPagingIo(
    _In_ PMMSUPPORT AddressSpace,
    _In_ PMEMORY_AREA MemoryArea)
{
    PEPROCESS Process = MmGetAddressSpaceOwner(AddressSpace);
    ULONG_PTR Address, EndAddress;
    SWAPENTRY SwapEntry;
    LARGE_INTEGER Delay;
    BOOLEAN Attached = FALSE;

    /* Paging file I/O with a wait entry only happens in user-mode views */
    if (Process == NULL)
        return;

    if (Process != PsGetCurrentProcess())
    {
        KeAttachProcess(&Process->Pcb);
        Attached = TRUE;
    }

    Delay.QuadPart = -10 * 1000;
    EndAddress = (ULONG_PTR)MM_ROUND_UP(MA_GetEndingAddress(MemoryArea), PAGE_SIZE);
    for (Address = MA_GetStartingAddress(MemoryArea); Address < EndAddress; Address += PAGE_SIZE)
    {
        while (MmIsPageSwapEntry(Process, (PVOID)Address))
        {
            MmGetPageFileMapping(Process, (PVOID)Address, &SwapEntry);
            if (SwapEntry != MM_WAIT_ENTRY)
                break;
            MmUnlockAddressSpace(AddressSpace);
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            MmLockAddressSpace(AddressSpace);
        }
    }

    if (Attached)
        KeDetachProcess();
}

static NTSTATUS
MmUnmapViewOfSegment(PMMSUPPORT AddressSpace,
                     PVOID BaseAddress)
{
    NTSTATUS Status;
    PEPROCESS Process;
    SIZE_T CommitCharge;
    PMEMORY_AREA MemoryArea;
    PMM_SECTION_SEGMENT Segment;
    PLIST_ENTRY CurrentEntry;
    PMM_REGION CurrentRegion;
    PLIST_ENTRY RegionListHead;

    MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace,
                 BaseAddress);
    if (MemoryArea == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    Segment = MemoryArea->SectionData.Segment;

#ifdef NEWCC
    if (Segment->Flags & MM_DATAFILE_SEGMENT)
    {
        MmUnlockAddressSpace(AddressSpace);
        Status = MmUnmapViewOfCacheSegment(AddressSpace, BaseAddress);
        MmLockAddressSpace(AddressSpace);

        return Status;
    }
#endif

    MemoryArea->DeleteInProgress = TRUE;
    CommitCharge = MemoryArea->SectionData.CommitCharge;

    /*
     * Let paging file I/O already started on private pages of the view
     * finish: it left MM_WAIT_ENTRY in the process PTE, dropped the address
     * space lock and still uses the view's regions when it relocks. New I/O
     * does not start on a view being deleted.
     */
    MiWaitForViewPagingIo(AddressSpace, MemoryArea);

    MmLockSectionSegment(Segment);

    RegionListHead = &MemoryArea->SectionData.RegionListHead;
    while (!IsListEmpty(RegionListHead))
    {
        CurrentEntry = RemoveHeadList(RegionListHead);
        CurrentRegion = CONTAINING_RECORD(CurrentEntry, MM_REGION, RegionListEntry);
        ExFreePoolWithTag(CurrentRegion, TAG_MM_REGION);
    }

    if ((*Segment->Flags) & MM_PHYSICALMEMORY_SEGMENT)
    {
        Status = MmFreeMemoryArea(AddressSpace,
                                  MemoryArea,
                                  NULL,
                                  NULL);
    }
    else
    {
        Status = MmFreeMemoryArea(AddressSpace,
                                  MemoryArea,
                                  MmFreeSectionPage,
                                  AddressSpace);
    }
    if (((*Segment->Flags) & MM_DATAFILE_SEGMENT) && (AddressSpace != MmGetKernelAddressSpace()))
        InterlockedDecrement(&Segment->UserMapCount);
    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);

    /* Give back what the view was charged: pageable commitment (MiCommitUserPageable) */
    Process = MmGetAddressSpaceOwner(AddressSpace);
    if (Process != NULL)
        MiSubtractProcessCommit(Process, CommitCharge);
    MiReturnPageableCommit(CommitCharge);

    return Status;
}

/* This functions must be called with a locked address space */
NTSTATUS
NTAPI
MiRosUnmapViewOfSection(
    _In_ PEPROCESS Process,
    _In_ PMEMORY_AREA MemoryArea,
    _In_ PVOID BaseAddress,
    _In_ BOOLEAN SkipDebuggerNotify)
{
    NTSTATUS Status;
    PMMSUPPORT AddressSpace;
    PVOID ImageBaseAddress = 0;

    DPRINT("Opening memory area Process %p BaseAddress %p\n",
           Process, BaseAddress);

    ASSERT(Process);
    ASSERT(MemoryArea);

    AddressSpace = &Process->Vm;

    if (MemoryArea == NULL ||
#ifdef NEWCC
            ((MemoryArea->Type != MEMORY_AREA_SECTION_VIEW) && (MemoryArea->Type != MEMORY_AREA_CACHE)) ||
#else
            (MemoryArea->Type != MEMORY_AREA_SECTION_VIEW) ||
#endif
            MemoryArea->DeleteInProgress)

    {
        if (MemoryArea) ASSERT(MemoryArea->Type != MEMORY_AREA_OWNED_BY_ARM3);

        DPRINT1("Unable to find memory area at address %p.\n", BaseAddress);
        return STATUS_NOT_MAPPED_VIEW;
    }

    if (MemoryArea->VadNode.u.VadFlags.VadType == VadImageMap)
    {
        ULONG i;
        ULONG NrSegments;
        PMM_IMAGE_SECTION_OBJECT ImageSectionObject;
        PMM_SECTION_SEGMENT SectionSegments;
        PMM_SECTION_SEGMENT Segment;
        ULONG MapCount;
        KIRQL OldIrql;

        Segment = MemoryArea->SectionData.Segment;
        ImageSectionObject = ImageSectionObjectFromSegment(Segment);
        SectionSegments = ImageSectionObject->Segments;
        NrSegments = ImageSectionObject->NrSegments;

        MemoryArea->DeleteInProgress = TRUE;

        /* Keep the image section object alive until MapCount is updated */
        InterlockedIncrement64(Segment->ReferenceCount);

        /* Search for the current segment within the section segments
         * and calculate the image base address from the start of its view
         * (BaseAddress can be anywhere in it) */
        for (i = 0; i < NrSegments; i++)
        {
            if (Segment == &SectionSegments[i])
            {
                ImageBaseAddress = (char*)MA_GetStartingAddress(MemoryArea) - PAGE_ROUND_DOWN(SectionSegments[i].Image.VirtualAddress);
                break;
            }
        }
        if (i >= NrSegments)
        {
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        /*
         * Claim the views of every segment before MmUnmapViewOfSegment drops
         * the address space lock to wait for paging file I/O, so that an
         * unmap through another segment's address sees them going away
         */
        for (i = 0; i < NrSegments; i++)
        {
            PMEMORY_AREA SegmentArea = MmLocateMemoryAreaByAddress(AddressSpace,
                (PVOID)((char*)ImageBaseAddress + (ULONG_PTR)SectionSegments[i].Image.VirtualAddress));
            if ((SegmentArea != NULL) && (SegmentArea != MemoryArea) && SegmentArea->DeleteInProgress)
            {
                /* Another thread is unmapping this image */
                MemoryArea->DeleteInProgress = FALSE;
                /* Balance the reference taken above; every other exit path derefs */
                MmDereferenceSegment(Segment);
                return STATUS_NOT_MAPPED_VIEW;
            }
        }
        for (i = 0; i < NrSegments; i++)
        {
            PMEMORY_AREA SegmentArea = MmLocateMemoryAreaByAddress(AddressSpace,
                (PVOID)((char*)ImageBaseAddress + (ULONG_PTR)SectionSegments[i].Image.VirtualAddress));
            if (SegmentArea != NULL)
                SegmentArea->DeleteInProgress = TRUE;
        }

        for (i = 0; i < NrSegments; i++)
        {
            PVOID SBaseAddress = (PVOID)
                                 ((char*)ImageBaseAddress + (ULONG_PTR)SectionSegments[i].Image.VirtualAddress);

            Status = MmUnmapViewOfSegment(AddressSpace, SBaseAddress);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MmUnmapViewOfSegment failed for %p (Process %p) with %lx\n",
                        SBaseAddress, Process, Status);
                ASSERT(NT_SUCCESS(Status));
            }
        }
        DPRINT("One mapping less for %p\n", ImageSectionObject->FileObject->SectionObjectPointer);

        /*
         * Under the PFN lock, which MmFlushImageSection holds while it checks
         * MapCount, so it never sees MapCount == 0 while we hold a reference
         */
        OldIrql = MiAcquirePfnLock();
        MapCount = InterlockedDecrement(&ImageSectionObject->MapCount);
        MmDereferenceSegmentWithLock(Segment, OldIrql);
        if (MapCount != 0)
            ImageBaseAddress = NULL;
    }
    else
    {
        PMM_SECTION_SEGMENT Segment = MemoryArea->SectionData.Segment;
        PMMVAD Vad = &MemoryArea->VadNode;
        PCONTROL_AREA ControlArea  = Vad->ControlArea;
        PFILE_OBJECT FileObject;
        SIZE_T ViewSize;
        LARGE_INTEGER ViewOffset;
        ViewOffset.QuadPart = MemoryArea->SectionData.ViewOffset;

        InterlockedIncrement64(Segment->ReferenceCount);

        ViewSize = PAGE_SIZE + ((Vad->EndingVpn - Vad->StartingVpn) << PAGE_SHIFT);

        Status = MmUnmapViewOfSegment(AddressSpace, BaseAddress);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MmUnmapViewOfSegment failed for %p (Process %p) with %lx\n",
                    BaseAddress, Process, Status);
            ASSERT(NT_SUCCESS(Status));
        }

        /* These might be deleted now */
        Vad = NULL;
        MemoryArea = NULL;

        if (FlagOn(*Segment->Flags, MM_PHYSICALMEMORY_SEGMENT))
        {
            /* Don't bother */
            MmDereferenceSegment(Segment);
            return STATUS_SUCCESS;
        }
        ASSERT(FlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT));

        FileObject = Segment->FileObject;
        FsRtlAcquireFileExclusive(FileObject);

        /* Don't bother for auto-delete closed file. */
        if (FlagOn(FileObject->Flags, FO_DELETE_ON_CLOSE) && FlagOn(FileObject->Flags, FO_CLEANUP_COMPLETE))
        {
            FsRtlReleaseFile(FileObject);
            MmDereferenceSegment(Segment);
            return STATUS_SUCCESS;
        }

        /*
         * Flush only when last mapping is deleted.
         * FIXME: Why ControlArea == NULL? Or rather: is ControlArea ever not NULL here?
         */
        if (ControlArea == NULL || ControlArea->NumberOfMappedViews == 1)
        {
            while (ViewSize > 0)
            {
                ULONG FlushSize = min(ViewSize, PAGE_ROUND_DOWN(MAXULONG));
                MmFlushSegment(FileObject->SectionObjectPointer,
                               &ViewOffset,
                               FlushSize,
                               NULL);
                ViewSize -= FlushSize;
                ViewOffset.QuadPart += FlushSize;
            }
        }

        FsRtlReleaseFile(FileObject);
        MmDereferenceSegment(Segment);
    }

    /* Notify debugger */
    if (ImageBaseAddress && !SkipDebuggerNotify) DbgkUnMapViewOfSection(ImageBaseAddress);

    return STATUS_SUCCESS;
}




/**
 * Queries the information of a section object.
 *
 * @param SectionHandle
 *        Handle to the section object. It must be opened with SECTION_QUERY
 *        access.
 * @param SectionInformationClass
 *        Index to a certain information structure. Can be either
 *        SectionBasicInformation or SectionImageInformation. The latter
 *        is valid only for sections that were created with the SEC_IMAGE
 *        flag.
 * @param SectionInformation
 *        Caller supplies storage for resulting information.
 * @param Length
 *        Size of the supplied storage.
 * @param ResultLength
 *        Data written.
 *
 * @return Status.
 *
 * @implemented
 */
NTSTATUS
NTAPI
NtQuerySection(
    _In_ HANDLE SectionHandle,
    _In_ SECTION_INFORMATION_CLASS SectionInformationClass,
    _Out_ PVOID SectionInformation,
    _In_ SIZE_T SectionInformationLength,
    _Out_opt_ PSIZE_T ResultLength)
{
    PSECTION Section;
    KPROCESSOR_MODE PreviousMode;
    NTSTATUS Status;
    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWrite(SectionInformation,
                          SectionInformationLength,
                          __alignof(ULONG));
            if (ResultLength != NULL)
            {
                ProbeForWrite(ResultLength,
                              sizeof(*ResultLength),
                              __alignof(SIZE_T));
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    if (SectionInformationClass == SectionBasicInformation)
    {
        if (SectionInformationLength < sizeof(SECTION_BASIC_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (SectionInformationClass == SectionImageInformation)
    {
        if (SectionInformationLength < sizeof(SECTION_IMAGE_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else
    {
        return STATUS_INVALID_INFO_CLASS;
    }

    Status = ObReferenceObjectByHandle(SectionHandle,
                                       SECTION_QUERY,
                                       MmSectionObjectType,
                                       PreviousMode,
                                       (PVOID*)(PVOID)&Section,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to reference section: 0x%lx\n", Status);
        return Status;
    }

    switch(SectionInformationClass)
    {
        case SectionBasicInformation:
        {
            SECTION_BASIC_INFORMATION Sbi = { 0 };

            Sbi.Size = Section->SizeOfSection;
            Sbi.BaseAddress = NULL;

            if (Section->u.Flags.File)
                Sbi.Attributes |= SEC_FILE;
            if (Section->u.Flags.Image)
                Sbi.Attributes |= SEC_IMAGE;
            if (Section->u.Flags.Commit)
                Sbi.Attributes |= SEC_COMMIT;
            if (Section->u.Flags.Reserve)
                Sbi.Attributes |= SEC_RESERVE;
            if (Section->u.Flags.Based)
                Sbi.Attributes |= SEC_BASED;

            if (Section->u.Flags.Image)
            {
                if (!MiIsRosSectionObject(Section))
                {
                    /* Not supported yet */
                    ASSERT(FALSE);
                }
            }
            else if (MiIsRosSectionObject(Section))
            {
                Sbi.BaseAddress = (PVOID)((PMM_SECTION_SEGMENT)Section->Segment)->Image.VirtualAddress;
            }
            else
            {
                Sbi.BaseAddress = Section->Segment->BasedAddress;
            }

            _SEH2_TRY
            {
                *((SECTION_BASIC_INFORMATION*)SectionInformation) = Sbi;
                if (ResultLength != NULL)
                {
                    *ResultLength = sizeof(Sbi);
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            break;
        }
        case SectionImageInformation:
        {
            if (!Section->u.Flags.Image)
            {
                Status = STATUS_SECTION_NOT_IMAGE;
            }
            else if (MiIsRosSectionObject(Section))
            {
                PMM_IMAGE_SECTION_OBJECT ImageSectionObject = ((PMM_IMAGE_SECTION_OBJECT)Section->Segment);

                _SEH2_TRY
                {
                    PSECTION_IMAGE_INFORMATION Sii = (PSECTION_IMAGE_INFORMATION)SectionInformation;
                    *Sii = ImageSectionObject->ImageInformation;
                    if (ResultLength != NULL)
                    {
                        *ResultLength = sizeof(*Sii);
                    }
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
            else
            {
                _SEH2_TRY
                {
                    PSECTION_IMAGE_INFORMATION Sii = (PSECTION_IMAGE_INFORMATION)SectionInformation;
                    *Sii = *Section->Segment->u2.ImageInformation;
                    if (ResultLength != NULL)
                        *ResultLength = sizeof(*Sii);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;
            }
            break;
        }
        default:
            DPRINT1("Unknown SectionInformationClass: %d\n", SectionInformationClass);
            Status = STATUS_NOT_SUPPORTED;
    }

    ObDereferenceObject(Section);

    return Status;
}

/**********************************************************************
 * NAME       EXPORTED
 * MmMapViewOfSection
 *
 * DESCRIPTION
 * Maps a view of a section into the virtual address space of a
 * process.
 *
 * ARGUMENTS
 * Section
 *  Pointer to the section object.
 *
 * ProcessHandle
 *  Pointer to the process.
 *
 * BaseAddress
 *  Desired base address (or NULL) on entry;
 *  Actual base address of the view on exit.
 *
 * ZeroBits
 *  Number of high order address bits that must be zero.
 *
 * CommitSize
 *  Size in bytes of the initially committed section of
 *  the view.
 *
 * SectionOffset
 *  Offset in bytes from the beginning of the section
 *  to the beginning of the view.
 *
 * ViewSize
 *  Desired length of map (or zero to map all) on entry
 *  Actual length mapped on exit.
 *
 * InheritDisposition
 *  Specified how the view is to be shared with
 *  child processes.
 *
 * AllocationType
 *  Type of allocation for the pages.
 *
 * Protect
 *  Protection for the committed region of the view.
 *
 * RETURN VALUE
 * Status.
 *
 * @implemented
 */
NTSTATUS NTAPI
MiMapViewOfSection(
    _In_ PVOID SectionObject,
    _In_ PEPROCESS Process,
    _Outptr_result_bytebuffer_(*ViewSize) _Pre_opt_valid_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_range_(ViewShare, ViewUnmap) SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect,
    _In_ ULONG_PTR LowestAddress,
    _In_ ULONG_PTR HighestBound)
{
    PSECTION Section;
    PMMSUPPORT AddressSpace;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN NotAtBase = FALSE;
    BOOLEAN MachineMismatch = FALSE;
    BOOLEAN IsAttached = FALSE;
    KAPC_STATE ApcState;
    ULONG_PTR HighestAddress;
    SIZE_T Unassigned, ViewCommit;

    if (!MiZeroBitsToHighestAddress(ZeroBits, &HighestAddress))
        return MI_PARAM_STATUS(4);
    if (HighestBound && (HighestBound < HighestAddress))
        HighestAddress = HighestBound;

    if (MiIsRosSectionObject(SectionObject) == FALSE)
    {
        DPRINT("Mapping ARM3 section into %s\n", Process->ImageFileName);
        ASSERT(SectionOffset != NULL);
        return MmMapViewOfArm3Section(SectionObject,
                                      Process,
                                      BaseAddress,
                                      ZeroBits,
                                      CommitSize,
                                      SectionOffset,
                                      ViewSize,
                                      InheritDisposition,
                                      AllocationType,
                                      Protect,
                                      LowestAddress,
                                      HighestBound);
    }

    ASSERT(Process);

    if (!Protect || Protect & ~PAGE_FLAGS_VALID_FOR_SECTION)
    {
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    if (PsGetCurrentProcess() != Process)
    {
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        IsAttached = TRUE;
    }

    Section = SectionObject;
    AddressSpace = &Process->Vm;

    if (Section->u.Flags.NoChange)
        AllocationType |= SEC_NO_CHANGE;

    MmLockAddressSpace(AddressSpace);

    /* Address space cleanup has run: nothing may be mapped any more */
    if (Process->VmDeleted)
    {
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }

    /* Only a data view can take the place of a placeholder */
    if ((AllocationType & MEM_REPLACE_PLACEHOLDER) &&
        (Section->u.Flags.Image || Section->u.Flags.PhysicalMemory))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (Section->u.Flags.Image)
    {
        ULONG i;
        ULONG NrSegments;
        ULONG_PTR ImageBase;
        SIZE_T ImageSize;
        PMM_IMAGE_SECTION_OBJECT ImageSectionObject;
        PMM_SECTION_SEGMENT SectionSegments;

        ImageSectionObject = ((PMM_IMAGE_SECTION_OBJECT)Section->Segment);
        SectionSegments = ImageSectionObject->Segments;
        NrSegments = ImageSectionObject->NrSegments;

        ASSERT(ImageSectionObject->RefCount > 0);

        ImageBase = (ULONG_PTR)*BaseAddress;
        if (ImageBase == 0)
        {
            ImageBase = (ULONG_PTR)ImageSectionObject->BasedAddress;
        }

        ImageSize = 0;
        for (i = 0; i < NrSegments; i++)
        {
            ULONG_PTR MaxExtent;
            MaxExtent = (ULONG_PTR)(SectionSegments[i].Image.VirtualAddress +
                                    SectionSegments[i].Length.QuadPart);
            ImageSize = max(ImageSize, MaxExtent);
        }

        ImageSectionObject->ImageInformation.ImageFileSize = (ULONG)ImageSize;

        if (!ImageSize || ImageSize - 1 > HighestAddress ||
            HighestAddress - (ImageSize - 1) < (ULONG_PTR)MM_LOWEST_USER_ADDRESS)
        {
            Status = STATUS_NO_MEMORY;
            goto Exit;
        }
        if (*BaseAddress &&
            ImageBase > HighestAddress - (ImageSize - 1))
        {
            Status = STATUS_INVALID_PARAMETER_4;
            goto Exit;
        }

        /* Check for an illegal base address */
        if ((ImageBase > HighestAddress - (ImageSize - 1)) ||
                ((ImageBase + ImageSize) < ImageSize))
        {
            ASSERT(*BaseAddress == NULL);
            ImageBase = ALIGN_DOWN_BY(HighestAddress + 1 - ImageSize,
                                      MM_VIRTMEM_GRANULARITY);
            NotAtBase = TRUE;
        }
        else if (ImageBase != ALIGN_DOWN_BY(ImageBase, MM_VIRTMEM_GRANULARITY))
        {
            ASSERT(*BaseAddress == NULL);
            ImageBase = ALIGN_DOWN_BY(ImageBase, MM_VIRTMEM_GRANULARITY);
            NotAtBase = TRUE;
        }

        /* Check there is enough space to map the section at that point. */
        if (!MmIsAddressRangeFree(AddressSpace, (PVOID)ImageBase, PAGE_ROUND_UP(ImageSize)))
        {
            /* Fail if the user requested a fixed base address. */
            if ((*BaseAddress) != NULL)
            {
                Status = STATUS_CONFLICTING_ADDRESSES;
                goto Exit;
            }
            /* Otherwise find a gap to map the image. */
            ImageBase = (ULONG_PTR)MmFindGapInRange(AddressSpace,
                                                  PAGE_ROUND_UP(ImageSize),
                                                  MM_VIRTMEM_GRANULARITY,
                                                  FALSE,
                                                  HighestAddress);
            if (ImageBase == 0)
            {
                Status = STATUS_CONFLICTING_ADDRESSES;
                goto Exit;
            }
            /* Remember that we loaded image at a different base address */
            NotAtBase = TRUE;
        }

        /*
         * Every copy-on-write segment can become private in this process:
         * charge the whole image once, before any segment is mapped. Each
         * mapped segment takes its share; what is not handed out yet goes
         * back on failure, the shares go back with the rollback's unmaps.
         */
        Unassigned = 0;
        for (i = 0; i < NrSegments; i++)
            Unassigned += MiViewCommitCharge(&SectionSegments[i], SectionSegments[i].Protection,
                                             (SIZE_T)SectionSegments[i].Length.QuadPart);
        if (!MiChargeCommit(Unassigned, MiCommitUserPageable))
        {
            Status = STATUS_COMMITMENT_LIMIT;
            goto Exit;
        }

        for (i = 0; i < NrSegments; i++)
        {
            PVOID SBaseAddress = (PVOID)
                                 ((char*)ImageBase + (ULONG_PTR)SectionSegments[i].Image.VirtualAddress);
            SIZE_T Share = MiViewCommitCharge(&SectionSegments[i], SectionSegments[i].Protection,
                                              (SIZE_T)SectionSegments[i].Length.QuadPart);

            MmLockSectionSegment(&SectionSegments[i]);
            Status = MmMapViewOfSegment(AddressSpace,
                                        TRUE,
                                        &SectionSegments[i],
                                        &SBaseAddress,
                                        SectionSegments[i].Length.QuadPart,
                                        SectionSegments[i].Protection,
                                        0,
                                        0,
                                        Share);
            MmUnlockSectionSegment(&SectionSegments[i]);
            if (!NT_SUCCESS(Status))
            {
                MiReturnPageableCommit(Unassigned);

                /* roll-back: MmUnmapViewOfSegment takes the segment lock itself */
                while (i--)
                {
                    SBaseAddress =  ((char*)ImageBase + (ULONG_PTR)SectionSegments[i].Image.VirtualAddress);
                    MmUnmapViewOfSegment(AddressSpace, SBaseAddress);
                }

                goto Exit;
            }
            Unassigned -= Share;
        }
        ASSERT(Unassigned == 0);

        *BaseAddress = (PVOID)ImageBase;
        *ViewSize = ImageSize;

        DPRINT("Mapped %p for section pointer %p\n", ImageSectionObject, ImageSectionObject->FileObject->SectionObjectPointer);

        /* One more map */
        InterlockedIncrement(&ImageSectionObject->MapCount);

        /* The view stays mapped, but the caller learns that the image with
         * code is not for this machine (the loader then unmaps it and fails) */
        MachineMismatch = (ImageSectionObject->ImageInformation.Machine != IMAGE_FILE_MACHINE_NATIVE) &&
                          ImageSectionObject->ImageInformation.ImageContainsCode;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
        if ((ImageSectionObject->ImageInformation.Machine == IMAGE_FILE_MACHINE_I386) &&
            (Process->Wow64Process != NULL))
        {
            MachineMismatch = FALSE;
        }
#endif
    }
    else
    {
        PMM_SECTION_SEGMENT Segment = (PMM_SECTION_SEGMENT)Section->Segment;
        LONGLONG ViewOffset, RequestedOffset;
        LONGLONG SectionLimit;
        PMMVAD Placeholder = NULL;

        ASSERT(Segment->RefCount > 0);

        /* A MEM_RESERVE view is the writable kind: it needs a section that can be written */
        if ((AllocationType & MEM_RESERVE) &&
            !(Section->InitialPageProtection & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE)))
        {
            Status = STATUS_SECTION_PROTECTION;
            goto Exit;
        }

        /* check for write access */
        if ((Protect & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE)) &&
                !(Section->InitialPageProtection & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE)))
        {
            Status = STATUS_SECTION_PROTECTION;
            goto Exit;
        }
        /* check for read access */
        if ((Protect & (PAGE_READONLY|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_WRITECOPY)) &&
                !(Section->InitialPageProtection & (PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))
        {
            Status = STATUS_SECTION_PROTECTION;
            goto Exit;
        }
        /* check for execute access */
        if ((Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) &&
                !(Section->InitialPageProtection & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))
        {
            Status = STATUS_SECTION_PROTECTION;
            goto Exit;
        }

        if (SectionOffset == NULL)
        {
            ViewOffset = RequestedOffset = 0;
        }
        else
        {
            /* The view starts on a page, but the caller's offset is what has to lie inside the section */
            RequestedOffset = SectionOffset->QuadPart;
            SectionOffset->QuadPart &= ~(PAGE_SIZE - 1);
            ViewOffset = SectionOffset->QuadPart;
        }

        /* Check if the offset and size would cause an overflow */
        if ((((ULONG64)ViewOffset + *ViewSize) < (ULONG64)ViewOffset) ||
            (((ULONG64)RequestedOffset + *ViewSize) < (ULONG64)RequestedOffset))
        {
            DPRINT1("Section offset overflows\n");
            Status = STATUS_INVALID_VIEW_SIZE;
            goto Exit;
        }

        /* A MEM_RESERVE view of a file may span the whole last page of the section.
         * (Windows lets it run past the end of the section; here it stays within the pages the section has.) */
        SectionLimit = Section->SizeOfSection.QuadPart;
        if ((AllocationType & MEM_RESERVE) && !Section->u.Flags.PhysicalMemory)
            SectionLimit = PAGE_ROUND_UP_64(SectionLimit);

        /* Check if the offset and size are bigger than the section itself */
        if (((ULONG64)RequestedOffset + *ViewSize) > (ULONG64)SectionLimit)
        {
            /* This is allowed for physical memory sections and kernel mode callers */
            if (!Section->u.Flags.PhysicalMemory || (ExGetPreviousMode() == UserMode))
            {
                DPRINT1("Section offset and size are larger than section\n");
                Status = STATUS_INVALID_VIEW_SIZE;
                goto Exit;
            }
        }

        if ((*ViewSize) == 0)
        {
            /* Calculate a view size and make sure it doesn't overflow a SIZE_T */
            ULONG64 CalculatedSize = Section->SizeOfSection.QuadPart - ViewOffset;
            if (CalculatedSize > SIZE_T_MAX)
            {
                DPRINT1("ViewSize is larger than SIZE_T_MAX\n");
                Status = STATUS_INVALID_VIEW_SIZE;
                goto Exit;
            }

            *ViewSize = (SIZE_T)CalculatedSize;
        }
        else if ((ExGetPreviousMode() == UserMode) &&
            (((*ViewSize)+ViewOffset) > Section->SizeOfSection.QuadPart) &&
            (!Section->u.Flags.Reserve))
        {
            /* Dubious */
            (*ViewSize) = MIN(Section->SizeOfSection.QuadPart - ViewOffset, SIZE_T_MAX - PAGE_SIZE);
        }

        *ViewSize = PAGE_ROUND_UP(*ViewSize);

        /* Nothing left to map: a section of size 0, or a view that starts at its end */
        if (*ViewSize == 0)
        {
            Status = STATUS_INVALID_VIEW_SIZE;
            goto Exit;
        }

        if (ZeroBits || LowestAddress || HighestBound)
        {
            if (*BaseAddress)
            {
                if ((ULONG_PTR)*BaseAddress > HighestAddress ||
                    *ViewSize - 1 > HighestAddress - (ULONG_PTR)*BaseAddress)
                {
                    Status = STATUS_INVALID_PARAMETER_4;
                    goto Exit;
                }
            }
            else
            {
                *BaseAddress = MmFindGapInRangeEx(AddressSpace, *ViewSize,
                                                 MM_VIRTMEM_GRANULARITY,
                                                 BooleanFlagOn(AllocationType, MEM_TOP_DOWN),
                                                 LowestAddress,
                                                 HighestAddress);
                if (!*BaseAddress)
                {
                    Status = STATUS_NO_MEMORY;
                    goto Exit;
                }
            }
        }

        /*
         * MEM_REPLACE_PLACEHOLDER: the placeholder of exactly this range leaves the tree, and comes
         * back if the view cannot be mapped. The address space stays locked all along.
         */
        if (AllocationType & MEM_REPLACE_PLACEHOLDER)
        {
            Status = MiCheckPlaceholderForReplace(Process, (ULONG_PTR)*BaseAddress, *ViewSize, &Placeholder);
            if (!NT_SUCCESS(Status)) goto Exit;
        }

        /* A copy-on-write view is charged in full: any page can become private */
        ViewCommit = MiViewCommitCharge(Segment, Protect, *ViewSize);
        if (!MiChargeCommit(ViewCommit, MiCommitUserPageable))
        {
            Status = STATUS_COMMITMENT_LIMIT;
            goto Exit;
        }

        if (Placeholder)
        {
            MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
            MiRemoveNode((PMMADDRESS_NODE)Placeholder, &Process->VadRoot);
            MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
        }

        MmLockSectionSegment(Segment);
        Status = MmMapViewOfSegment(AddressSpace,
                                    FALSE,
                                    Segment,
                                    BaseAddress,
                                    *ViewSize,
                                    Protect,
                                    ViewOffset,
                                    AllocationType & (MEM_TOP_DOWN|SEC_NO_CHANGE),
                                    ViewCommit);
        MmUnlockSectionSegment(Segment);
        if (!NT_SUCCESS(Status))
        {
            MiReturnPageableCommit(ViewCommit);
            if (Placeholder)
            {
                NTSTATUS PlaceholderStatus;
                MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
                PlaceholderStatus = MiInsertPlaceholderVad(Process,
                                                           (PMMVAD_LONG)Placeholder,
                                                           Placeholder->StartingVpn << PAGE_SHIFT,
                                                           (Placeholder->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1));
                MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
                ASSERT(NT_SUCCESS(PlaceholderStatus));
                (void)PlaceholderStatus;
            }
            goto Exit;
        }

        if (Placeholder)
        {
            PMEMORY_AREA MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace, *BaseAddress);

            /* The view gives the placeholder back when it is unmapped with MEM_PRESERVE_PLACEHOLDER */
            ASSERT(MemoryArea != NULL);
            if (MemoryArea) MemoryArea->VadNode.u2.VadFlags2.FromPlaceholder = 1;
            Process->VirtualSize -= *ViewSize;
            ExFreePool(Placeholder);
            PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
        }
    }

    if (MachineMismatch)
        Status = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
    else if (NotAtBase)
        Status = STATUS_IMAGE_NOT_AT_BASE;
    else
        Status = STATUS_SUCCESS;

Exit:

    MmUnlockAddressSpace(AddressSpace);

    if (IsAttached)
    {
        KeUnstackDetachProcess(&ApcState);
    }

    return Status;
}

NTSTATUS
NTAPI
MmMapViewOfSection(
    _In_ PVOID SectionObject,
    _In_ PEPROCESS Process,
    _Outptr_result_bytebuffer_(*ViewSize) _Pre_opt_valid_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_range_(ViewShare, ViewUnmap) SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    return MiMapViewOfSection(SectionObject, Process, BaseAddress, ZeroBits, CommitSize, SectionOffset,
                              ViewSize, InheritDisposition, AllocationType, Protect, 0, 0);
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
MmCanFileBeTruncated(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_opt_ PLARGE_INTEGER NewFileSize)
{
    BOOLEAN Ret;
    PMM_SECTION_SEGMENT Segment;

    /* Check whether an ImageSectionObject exists */
    if (SectionObjectPointer->ImageSectionObject != NULL)
    {
        DPRINT1("ERROR: File can't be truncated because it has an image section\n");
        return FALSE;
    }

    Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
    {
        /* There is no data section. It's fine to do anything. */
        return TRUE;
    }

    MmLockSectionSegment(Segment);
    if (Segment->Extending && (NewFileSize != NULL) &&
        (NewFileSize->QuadPart < ((PFSRTL_COMMON_FCB_HEADER)Segment->FileObject->FsContext)->FileSize.QuadPart))
    {
        /* NtExtendSection is between its file size check and the growth of the section: the file must
           not shrink, neither by the extension's own end of file after a write grew the file further */
        Ret = FALSE;
    }
    else if ((Segment->SectionCount == 0) ||
             ((Segment->SectionCount == 1) && (SectionObjectPointer->SharedCacheMap != NULL)))
    {
        if (Segment->UserMapCount == 0)
        {
            /* If the cache is the only one holding a reference to the segment, then it's fine to resize */
            Ret = TRUE;
        }
        else
        {
            /* A process still maps the file, though its section is closed: it may grow, not shrink */
            PFSRTL_COMMON_FCB_HEADER FcbHeader = Segment->FileObject->FsContext;

            Ret = (NewFileSize != NULL) && (NewFileSize->QuadPart >= FcbHeader->FileSize.QuadPart);
        }
    }
    else if (NewFileSize != NULL)
    {
        /* We can't shrink, but we can extend */
        Ret = NewFileSize->QuadPart >= Segment->RawLength.QuadPart;
#if DBG
        if (!Ret)
        {
            DPRINT1("Cannot truncate data: New Size %I64d, Segment Size %I64d\n", NewFileSize->QuadPart, Segment->RawLength.QuadPart);
        }
#endif
    }
    else
    {
        DPRINT1("ERROR: File can't be truncated because it has references held to its data section\n");
        Ret = FALSE;
    }

    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);

    DPRINT("FIXME: didn't check for outstanding write probes\n");

    return Ret;
}

static
BOOLEAN
MiPurgeImageSegment(PMM_SECTION_SEGMENT Segment)
{
    PCACHE_SECTION_PAGE_TABLE PageTable;

    MmLockSectionSegment(Segment);

    /* Loop over all entries */
    for (PageTable = RtlEnumerateGenericTable(&Segment->PageTable, TRUE);
         PageTable != NULL;
         PageTable = RtlEnumerateGenericTable(&Segment->PageTable, FALSE))
    {
        for (ULONG i = 0; i < _countof(PageTable->PageEntries); i++)
        {
            ULONG_PTR Entry = PageTable->PageEntries[i];
            LARGE_INTEGER Offset;

            if (!Entry)
                continue;

            if (IS_SWAP_FROM_SSE(Entry) || (SHARE_COUNT_FROM_SSE(Entry) > 0))
            {
                /* I/O ongoing or swap entry. Someone mapped this file as we were not looking */
                MmUnlockSectionSegment(Segment);
                return FALSE;
            }

            /* Regular entry */
            ASSERT(!IS_WRITE_SSE(Entry));
            ASSERT(MmGetSavedSwapEntryPage(PFN_FROM_SSE(Entry)) == 0);

            /* Properly remove using the used API */
            Offset.QuadPart = PageTable->FileOffset.QuadPart + (i << PAGE_SHIFT);
            MmSetPageEntrySectionSegment(Segment, &Offset, 0);
            MmReleasePageMemoryConsumer(MC_USER, PFN_FROM_SSE(Entry));
        }
    }

    MmUnlockSectionSegment(Segment);

    return TRUE;
}

/*
 * @implemented
 */
BOOLEAN NTAPI
MmFlushImageSection (IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                     IN MMFLUSH_TYPE FlushType)
{
    switch(FlushType)
    {
        case MmFlushForDelete:
        {
            /*
             * FIXME: Check for outstanding write probes on Data section.
             * How do we do that ?
             */
        }
        /* Fall-through */
        case MmFlushForWrite:
        {
            KIRQL OldIrql = MiAcquirePfnLock();
            PMM_IMAGE_SECTION_OBJECT ImageSectionObject = SectionObjectPointer->ImageSectionObject;

            DPRINT("Deleting or modifying %p\n", SectionObjectPointer);

            /* Wait for concurrent creation or deletion of image to be done */
            ImageSectionObject = SectionObjectPointer->ImageSectionObject;
            while (ImageSectionObject && (ImageSectionObject->SegFlags & (MM_SEGMENT_INCREATE | MM_SEGMENT_INDELETE)))
            {
                MiReleasePfnLock(OldIrql);
                KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
                OldIrql = MiAcquirePfnLock();
                ImageSectionObject = SectionObjectPointer->ImageSectionObject;
            }

            if (!ImageSectionObject)
            {
                DPRINT("No image section object. Accepting\n");
                /* Nothing to do */
                MiReleasePfnLock(OldIrql);
                return TRUE;
            }

            /* Do we have open sections or mappings on it ? */
            if ((ImageSectionObject->SectionCount) || (ImageSectionObject->MapCount))
            {
                /* We do. No way to delete it */
                MiReleasePfnLock(OldIrql);
                DPRINT("Denying. There are mappings open\n");
                return FALSE;
            }

            /* There are no sections open on it, but we must still have pages around. Discard everything */
            ImageSectionObject->SegFlags |= MM_IMAGE_SECTION_FLUSH_DELETE;
            InterlockedIncrement64(&ImageSectionObject->RefCount);
            MiReleasePfnLock(OldIrql);

            DPRINT("Purging\n");

            for (ULONG i = 0; i < ImageSectionObject->NrSegments; i++)
            {
                if (!MiPurgeImageSegment(&ImageSectionObject->Segments[i]))
                    break;
            }

            /* Grab lock again */
            OldIrql = MiAcquirePfnLock();

            if (!(ImageSectionObject->SegFlags & MM_IMAGE_SECTION_FLUSH_DELETE))
            {
                /*
                 * Someone actually created a section while we were not looking.
                 * Drop our ref and deny.
                 * MmDereferenceSegmentWithLock releases Pfn lock
                 */
                MmDereferenceSegmentWithLock(&ImageSectionObject->Segments[0], OldIrql);
                return FALSE;
            }

            /* We should be the last one holding a ref here. */
            ASSERT(ImageSectionObject->RefCount == 1);
            ASSERT(ImageSectionObject->SectionCount == 0);

            /* Dereference the first segment, this will free everything & release the lock */
            MmDereferenceSegmentWithLock(&ImageSectionObject->Segments[0], OldIrql);
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmMapViewInSystemSpace (IN PVOID SectionObject,
                        OUT PVOID * MappedBase,
                        IN OUT PSIZE_T ViewSize)
{
    LARGE_INTEGER SectionOffset;

    SectionOffset.QuadPart = 0;

    return MmMapViewInSystemSpaceEx(SectionObject, MappedBase, ViewSize, &SectionOffset, 0);
}

NTSTATUS
NTAPI
MmMapViewInSystemSpaceEx (
    _In_ PVOID SectionObject,
    _Outptr_result_bytebuffer_ (*ViewSize) PVOID *MappedBase,
    _Inout_ PSIZE_T ViewSize,
    _Inout_ PLARGE_INTEGER SectionOffset,
    _In_ ULONG_PTR Flags
    )
{
    PSECTION Section = SectionObject;
    PMM_SECTION_SEGMENT Segment;
    PMMSUPPORT AddressSpace;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    if (MiIsRosSectionObject(SectionObject) == FALSE)
    {
        return MiMapViewInSystemSpace(SectionObject,
                                      &MmSession,
                                      MappedBase,
                                      ViewSize,
                                      SectionOffset);
    }

    DPRINT("MmMapViewInSystemSpaceEx() called\n");

    /* unsupported for now */
    ASSERT(Section->u.Flags.Image == 0);

    Section = SectionObject;
    Segment = (PMM_SECTION_SEGMENT)Section->Segment;

    if (*ViewSize == 0)
    {
        LONGLONG MapSizeLL;

        /* Page-align the mapping */
        SectionOffset->LowPart = PAGE_ROUND_DOWN(SectionOffset->LowPart);

        if (!NT_SUCCESS(RtlLongLongSub(Section->SizeOfSection.QuadPart, SectionOffset->QuadPart, &MapSizeLL)))
            return STATUS_INVALID_VIEW_SIZE;

        if (!NT_SUCCESS(RtlLongLongToSIZET(MapSizeLL, ViewSize)))
            return STATUS_INVALID_VIEW_SIZE;
    }
    else
    {
        LONGLONG HelperLL;

        /* Get the map end */
        if (!NT_SUCCESS(RtlLongLongAdd(SectionOffset->QuadPart, *ViewSize, &HelperLL)))
            return STATUS_INVALID_VIEW_SIZE;

        /* Round it up, if needed */
        if (HelperLL % PAGE_SIZE)
        {
            if (!NT_SUCCESS(RtlLongLongAdd(HelperLL, PAGE_SIZE - (HelperLL % PAGE_SIZE), &HelperLL)))
                return STATUS_INVALID_VIEW_SIZE;
        }

        /* Now that we have the mapping end, we can align down its start */
        SectionOffset->LowPart = PAGE_ROUND_DOWN(SectionOffset->LowPart);

        /* Get the new size */
        if (!NT_SUCCESS(RtlLongLongSub(HelperLL, SectionOffset->QuadPart, &HelperLL)))
            return STATUS_INVALID_VIEW_SIZE;

        if (!NT_SUCCESS(RtlLongLongToSIZET(HelperLL, ViewSize)))
            return STATUS_INVALID_VIEW_SIZE;
    }

    AddressSpace = MmGetKernelAddressSpace();

    MmLockAddressSpace(AddressSpace);

    MmLockSectionSegment(Segment);

    Status = MmMapViewOfSegment(AddressSpace,
                                Section->u.Flags.Image,
                                Segment,
                                MappedBase,
                                *ViewSize,
                                PAGE_READWRITE,
                                SectionOffset->QuadPart,
                                SEC_RESERVE,
                                0);

    MmUnlockSectionSegment(Segment);
    MmUnlockAddressSpace(AddressSpace);

    return Status;
}

/* This function must be called with address space lock held */
NTSTATUS
NTAPI
MiRosUnmapViewInSystemSpace(IN PVOID MappedBase)
{
    DPRINT("MmUnmapViewInSystemSpace() called\n");

    return MmUnmapViewOfSegment(MmGetKernelAddressSpace(), MappedBase);
}

/**********************************************************************
 * NAME       EXPORTED
 *  MmCreateSection@
 *
 * DESCRIPTION
 *  Creates a section object.
 *
 * ARGUMENTS
 * SectionObject (OUT)
 *  Caller supplied storage for the resulting pointer
 *  to a SECTION_OBJECT instance;
 *
 * DesiredAccess
 *  Specifies the desired access to the section can be a
 *  combination of:
 *   STANDARD_RIGHTS_REQUIRED |
 *   SECTION_QUERY   |
 *   SECTION_MAP_WRITE  |
 *   SECTION_MAP_READ  |
 *   SECTION_MAP_EXECUTE
 *
 * ObjectAttributes [OPTIONAL]
 *  Initialized attributes for the object can be used
 *  to create a named section;
 *
 * MaximumSize
 *  Maximizes the size of the memory section. Must be
 *  non-NULL for a page-file backed section.
 *  If value specified for a mapped file and the file is
 *  not large enough, file will be extended.
 *
 * SectionPageProtection
 *  Can be a combination of:
 *   PAGE_READONLY |
 *   PAGE_READWRITE |
 *   PAGE_WRITEONLY |
 *   PAGE_WRITECOPY
 *
 * AllocationAttributes
 *  Can be a combination of:
 *   SEC_IMAGE |
 *   SEC_RESERVE
 *
 * FileHandle
 *  Handle to a file to create a section mapped to a file
 *  instead of a memory backed section;
 *
 * File
 *  Unknown.
 *
 * RETURN VALUE
 *  Status.
 *
 * @implemented
 */
NTSTATUS NTAPI
MmCreateSection (OUT PVOID  * Section,
                 IN ACCESS_MASK  DesiredAccess,
                 IN POBJECT_ATTRIBUTES ObjectAttributes     OPTIONAL,
                 IN PLARGE_INTEGER  MaximumSize,
                 IN ULONG   SectionPageProtection,
                 IN ULONG   AllocationAttributes,
                 IN HANDLE   FileHandle   OPTIONAL,
                 IN PFILE_OBJECT  FileObject  OPTIONAL)
{
    NTSTATUS Status;
    ULONG Protection;
    PSECTION *SectionObject = (PSECTION *)Section;
    BOOLEAN FileLock = FALSE;
    BOOLEAN HaveFileObject = FALSE;

    // FIXME: Implement support for large pages
    if (AllocationAttributes & SEC_LARGE_PAGES)
    {
        DPRINT1("SEC_LARGE_PAGES is not supported\n");
        return STATUS_INVALID_PARAMETER_6;
    }

    /* Windows 8 and later only build an image section from a file handle:
     * a file object (with or without a handle) is rejected for SEC_IMAGE */
    if ((AllocationAttributes & SEC_IMAGE) && (FileObject != NULL) && MI_IS_WIN8_OR_LATER())
    {
        DPRINT1("A file object cannot back an image section\n");
        return STATUS_INVALID_PARAMETER_6;
    }

    /* Check if an ARM3 section is being created instead */
    if (!(AllocationAttributes & SEC_IMAGE))
    {
        if (!(FileObject) && !(FileHandle))
        {
            return MmCreateArm3Section(Section,
                                       DesiredAccess,
                                       ObjectAttributes,
                                       MaximumSize,
                                       SectionPageProtection,
                                       AllocationAttributes &~ 1,
                                       FileHandle,
                                       FileObject);
        }
    }

    /* Convert section flag to page flag */
    if (AllocationAttributes & SEC_NOCACHE) SectionPageProtection |= PAGE_NOCACHE;

    /* Check to make sure the protection is correct. Nt* does this already */
    Protection = MiMakeProtectionMask(SectionPageProtection);
    if (Protection == MM_INVALID_PROTECTION)
    {
        DPRINT1("Page protection is invalid\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Check if this is going to be a data or image backed file section */
    if ((FileHandle) || (FileObject))
    {
        /* These cannot be mapped with large pages */
        if (AllocationAttributes & SEC_LARGE_PAGES)
        {
            DPRINT1("Large pages cannot be used with an image mapping\n");
            return STATUS_INVALID_PARAMETER_6;
        }

        /* Did the caller pass a file object ? */
        if (FileObject)
        {
            /* Reference the object directly */
            ObReferenceObject(FileObject);
            HaveFileObject = TRUE;
        }
        else
        {
            /* Reference the file handle to get the object */
            Status = ObReferenceObjectByHandle(FileHandle,
                                               MmMakeFileAccess[Protection],
                                               IoFileObjectType,
                                               ExGetPreviousMode(),
                                               (PVOID*)&FileObject,
                                               NULL);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("Failed to get a handle to the FO: %lx\n", Status);
                return Status;
            }

            /* Lock the file */
            Status = FsRtlAcquireToCreateMappedSection(FileObject, SectionPageProtection);
            if (!NT_SUCCESS(Status))
            {
                ObDereferenceObject(FileObject);
                return Status;
            }

            FileLock = TRUE;

            /* Deny access if there are writes on the file */
#if 0
            if ((AllocationAttributes & SEC_IMAGE) && (Status == STATUS_FILE_LOCKED_WITH_WRITERS))
            {
                DPRINT1("Cannot create image maps with writers open on the file!\n");
                Status = STATUS_ACCESS_DENIED;
                goto Quit;
            }
#else
            if ((AllocationAttributes & SEC_IMAGE) && (Status == STATUS_FILE_LOCKED_WITH_WRITERS))
                DPRINT1("Creating image map with writers open on the file!\n");
#endif
        }
    }
    else
    {
        /* A handle must be supplied with SEC_IMAGE, as this is the no-handle path */
        if (AllocationAttributes & SEC_IMAGE) return STATUS_INVALID_FILE_FOR_SECTION;
    }

    if (FileObject == NULL)
    {
        Status = STATUS_INVALID_FILE_FOR_SECTION;
        goto Exit;
    }

    if (AllocationAttributes & SEC_IMAGE)
    {
        Status = MmCreateImageSection(SectionObject,
                                      DesiredAccess,
                                      ObjectAttributes,
                                      MaximumSize,
                                      SectionPageProtection,
                                      AllocationAttributes,
                                      FileObject);

        /* If the file was ivalid, and we got a FileObject passed, fall back to data section */
        if (!NT_SUCCESS(Status) && (Status != STATUS_SECTION_TOO_BIG) && HaveFileObject)
        {
            AllocationAttributes &= ~SEC_IMAGE;
        }
    }

#ifndef NEWCC
    if (!(AllocationAttributes & SEC_IMAGE))
    {
        Status =  MmCreateDataFileSection(SectionObject,
                                          DesiredAccess,
                                          ObjectAttributes,
                                          MaximumSize,
                                          SectionPageProtection,
                                          AllocationAttributes,
                                          FileObject,
                                          FileHandle != NULL);

        /* Views of this section can modify data past the valid data length: file systems keep their lazy
         * writer away from such pages (fastfat, rdbss) when the FCB header says so */
        if (NT_SUCCESS(Status) && FileLock && FileObject->FsContext &&
            (SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
        {
            PFSRTL_COMMON_FCB_HEADER FcbHeader = FileObject->FsContext;
            FcbHeader->Flags |= FSRTL_FLAG_USER_MAPPED_FILE;
        }
    }
#else
    else
    {
        Status = MmCreateCacheSection(SectionObject,
                                      DesiredAccess,
                                      ObjectAttributes,
                                      MaximumSize,
                                      SectionPageProtection,
                                      AllocationAttributes,
                                      FileObject);
    }
#endif

Exit:

    if (FileLock)
        FsRtlReleaseFile(FileObject);
    if (FileObject)
        ObDereferenceObject(FileObject);

    return Status;
}

/* This function is not used. It is left for future use, when per-process
 * address space is considered. */
#if 0
BOOLEAN
NTAPI
MmArePagesResident(
    _In_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ ULONG Length)
{
    PMEMORY_AREA MemoryArea;
    BOOLEAN Ret = TRUE;
    PMM_SECTION_SEGMENT Segment;
    LARGE_INTEGER SegmentOffset, RangeEnd;
    PMMSUPPORT AddressSpace = Process ? &Process->Vm : MmGetKernelAddressSpace();

    MmLockAddressSpace(AddressSpace);

    MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace, Address);
    if (MemoryArea == NULL)
    {
        MmUnlockAddressSpace(AddressSpace);
        return FALSE;
    }

    /* Only supported in old Mm for now */
    ASSERT(MemoryArea->Type == MEMORY_AREA_SECTION_VIEW);
    /* For file mappings */
    ASSERT(MemoryArea->VadNode.u.VadFlags.VadType != VadImageMap);

    Segment = MemoryArea->SectionData.Segment;
    MmLockSectionSegment(Segment);

    SegmentOffset.QuadPart = PAGE_ROUND_DOWN(Address) - MA_GetStartingAddress(MemoryArea)
            + MemoryArea->SectionData.ViewOffset;
    RangeEnd.QuadPart = PAGE_ROUND_UP((ULONG_PTR)Address + Length) - MA_GetStartingAddress(MemoryArea)
            + MemoryArea->SectionData.ViewOffset;

    while (SegmentOffset.QuadPart < RangeEnd.QuadPart)
    {
        ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &SegmentOffset);
        if ((Entry == 0) || IS_SWAP_FROM_SSE(Entry))
        {
            Ret = FALSE;
            break;
        }
        SegmentOffset.QuadPart += PAGE_SIZE;
    }

    MmUnlockSectionSegment(Segment);

    MmUnlockAddressSpace(AddressSpace);
    return Ret;
}
#endif

/* Page tables are created in any order, so look for the one at the highest offset */
_Requires_exclusive_lock_held_(Segment->Lock)
static
LONGLONG
MiGetSegmentPageTableEnd(
    _In_ PMM_SECTION_SEGMENT Segment)
{
    PCACHE_SECTION_PAGE_TABLE PageTable;
    PVOID RestartKey = NULL;
    LONGLONG End = 0;

    while ((PageTable = RtlEnumerateGenericTableWithoutSplaying(&Segment->PageTable, &RestartKey)))
    {
        End = max(End, PageTable->FileOffset.QuadPart + (LONGLONG)_countof(PageTable->PageEntries) * PAGE_SIZE);
    }

    return End;
}

/* Zero [Start, End) in the pages of a file's data segment that are in memory; reads nothing in. End may lie past
 * the segment's pages (MAXLONGLONG: to the end) */
VOID
NTAPI
MmZeroResidentSegmentRange(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ LONGLONG Start,
    _In_ LONGLONG End)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PMM_SECTION_SEGMENT Segment;
    PCACHE_SECTION_PAGE_TABLE PageTable;
    PVOID RestartKey;

    if (Start >= End)
        return;

    Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
        return;

    MmLockSectionSegment(Segment);

    /*
     * Walk the allocated page tables, not every offset: a sparse file cut to a small size would otherwise scan
     * from Start to the highest page at 256-page steps under the lock. For each page table that overlaps the range,
     * zero the resident pages its 256 entries hold.
     */
restart:
    RestartKey = NULL;
    while ((PageTable = RtlEnumerateGenericTableWithoutSplaying(&Segment->PageTable, &RestartKey)))
    {
        LONGLONG TableStart = PageTable->FileOffset.QuadPart;
        LONGLONG TableEnd = TableStart + (LONGLONG)_countof(PageTable->PageEntries) * PAGE_SIZE;
        LONGLONG PageOffset;

        if (TableEnd <= Start || TableStart >= End)
            continue;

        for (PageOffset = max(TableStart, PAGE_ROUND_DOWN_64(Start)); PageOffset < min(TableEnd, End); PageOffset += PAGE_SIZE)
        {
            LONGLONG ZeroStart = max(PageOffset, Start);
            LONGLONG ZeroEnd = min(PageOffset + PAGE_SIZE, End);
            LARGE_INTEGER PageOff;
            ULONG_PTR Entry;
            PUCHAR Address;
            KIRQL Irql;

            PageOff.QuadPart = PageOffset;
            Entry = MmGetPageEntrySectionSegment(Segment, &PageOff);

            /* A read in flight would assign the old contents after us. Dropping the lock invalidates the
             * enumeration, so restart it after the wait. */
            if (MM_IS_WAIT_PTE(Entry))
            {
                MmUnlockSectionSegment(Segment);
                KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
                MmLockSectionSegment(Segment);
                goto restart;
            }

            if ((Entry == 0) || IS_SWAP_FROM_SSE(Entry))
                continue;

            Address = MiMapPageInHyperSpace(Process, PFN_FROM_SSE(Entry), &Irql);
            RtlZeroMemory(Address + (ZeroStart - PageOffset), (SIZE_T)(ZeroEnd - ZeroStart));
            MiUnmapPageInHyperSpace(Process, Address, Irql);
        }
    }

    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);
}

/* Read one page of a data segment from its file */
static
NTSTATUS
MiReadSegmentPage(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ LONGLONG Offset,
    _In_ PFN_NUMBER Page)
{
    UCHAR MdlBase[sizeof(MDL) + sizeof(PFN_NUMBER)];
    PMDL Mdl = (PMDL)MdlBase;
    LARGE_INTEGER FileOffset;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    KEVENT Event;
    KIRQL OldIrql;

    RtlZeroMemory(MdlBase, sizeof(MdlBase));
    MmInitializeMdl(Mdl, NULL, PAGE_SIZE);
    MmBuildMdlFromPages(Mdl, &Page);
    Mdl->MdlFlags |= MDL_PAGES_LOCKED | MDL_IO_PAGE_READ;

    FileOffset.QuadPart = Segment->Image.FileOffset + Offset;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    KeRaiseIrql(APC_LEVEL, &OldIrql);
    Status = IoPageRead(Segment->FileObject, Mdl, &FileOffset, &Event, &Iosb);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, WrPageIn, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
        MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);
    KeLowerIrql(OldIrql);

    if (NT_SUCCESS(Status) || (Status == STATUS_END_OF_FILE))
        MI_COUNT_PAGE_READ(1);

    return (Status == STATUS_END_OF_FILE) ? STATUS_SUCCESS : Status;
}

typedef struct _MI_ZERO_WAIT
{
    ULONGLONG Start;       /* interrupt time of the first wait; 0 until then */
    ULONGLONG Progress;    /* interrupt time reclamation last moved */
    LONG Reclaimed;        /* MiReclaimProgress snapshot */
    BOOLEAN FinalAttempt;  /* one last allocation attempt was allowed past the deadline */
    BOOLEAN MayWait;       /* FALSE for a reclaim thread that must never sleep on reclamation */
} MI_ZERO_WAIT, *PMI_ZERO_WAIT;

/*
 * Wait for memory so a zeroing allocation can be retried, mirroring MmMakeDataSectionResident: kick the
 * balancer and sleep 50 ms between tries, give up once reclamation has stalled for 30 seconds or the whole
 * wait has run two minutes -- with one last attempt past the deadline -- and stop at once if the thread is
 * terminating. The deadline state is seeded on the first wait, so the clock starts at the first shortage.
 * Returns FALSE when the caller must stop waiting and fail the zeroing, which its callers absorb. MayWait is
 * FALSE for a reclaim thread that must not sleep on reclamation; such a thread never waits.
 */
static
BOOLEAN
MiZeroSegmentWaitForMemory(
    _Inout_ PMI_ZERO_WAIT State)
{
    ULONGLONG Now;
    LARGE_INTEGER Delay;

    if (!State->MayWait || PsIsThreadTerminating(PsGetCurrentThread()))
        return FALSE;

    Now = KeQueryInterruptTime();
    if (State->Start == 0)
    {
        State->Start = Now;
        State->Progress = Now;
        State->Reclaimed = MiReclaimProgress;
    }

    MmRebalanceMemoryConsumers();
    Delay.QuadPart = -50 * 10000LL;  /* 50 ms */
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    Now = KeQueryInterruptTime();
    if (MiReclaimProgress != State->Reclaimed)
    {
        State->Reclaimed = MiReclaimProgress;
        State->Progress = Now;
    }

    /* Stop after 30 s with no reclamation, or 2 minutes overall, but make one last attempt first */
    if ((Now - State->Progress >= 30 * 1000 * 10000ULL) || (Now - State->Start >= 120 * 1000 * 10000ULL))
    {
        if (State->FinalAttempt)
            return FALSE;
        State->FinalAttempt = TRUE;
    }

    return TRUE;
}

/*
 * The work of CcZeroData on a cached file, decided page by page under the segment lock:
 * - a page in memory keeps its content (data written through the cache or a view, possibly past the valid data
 *   length, or what the file system returned for it) and is left dirty;
 * - a page not in memory that lies wholly inside [Start, End) becomes a dirty zero page, read from nothing: the
 *   caller passes Start = the boundary of valid data, so the whole page is gap. This is why a file system that
 *   does not zero-fill reads past its valid data length (vfatfs) cannot disclose stale blocks here;
 * - the one page that straddles Start (only the first) is read, so the bytes below Start (valid data) survive,
 *   and [Start, End) within it is zeroed. Start is the file system's true valid-data boundary, passed in; a
 *   caller's cache-map valid data length may lie above Start (vfatfs advances it before the gap is zeroed), so
 *   it must not raise the zero bound, or old disk bytes in [Start, that length) would survive on the read page.
 * Returns STATUS_CANT_WAIT if !Wait and a page would have to be brought in.
 */
NTSTATUS
NTAPI
MmZeroSegmentRange(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ LONGLONG Start,
    _In_ LONGLONG End,
    _In_ BOOLEAN Wait)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PMM_SECTION_SEGMENT Segment;
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER Offset;
    /*
     * Bringing a gap page in needs a NonPagedPool page-table slice and a physical page; both can fail under
     * pressure. We cannot read or publish a page we never locked, so on a shortage we wait for memory and
     * retry. A reclaim thread must not: the balancer, the modified-page writer and the lazy writer are the
     * threads that free the pages, so waiting on them would wait on ourselves. PsIsSystemThread is the decisive
     * guard -- they are all system threads, and fastfat overwrites the mod-write top-level IRP marker before it
     * zeroes, so that marker is not reliable here. A reclaim thread fails at once with STATUS_NO_MEMORY and the
     * page-out path keeps the page dirty and retries; a file-system write absorbs the failure by holding the
     * grown size and valid data length until the zeroing succeeds and rolling them back otherwise, so no
     * grown-but-unzeroed gap is ever exposed.
     */
    MI_ZERO_WAIT WaitState = { 0 };
    WaitState.MayWait = Wait && !PsIsSystemThread(PsGetCurrentThread());

    Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
        return STATUS_NOT_MAPPED_VIEW;

    for (Offset.QuadPart = PAGE_ROUND_DOWN_64(Start); Offset.QuadPart < End; Offset.QuadPart += PAGE_SIZE)
    {
        LONGLONG ZeroStart = max(Offset.QuadPart, Start);
        LONGLONG ZeroEnd = min(Offset.QuadPart + PAGE_SIZE, End);
        ULONG_PTR Entry;
        PFN_NUMBER Page;
        BOOLEAN Resident = FALSE;

        MmLockSectionSegment(Segment);

        /*
         * Claim the page under the segment lock: spin while another thread's read is in flight, keep and dirty
         * a resident page, or put a wait entry on a missing one so nobody else touches it while it is read or
         * zeroed below with the lock dropped. A page that another thread faults in while the lock is dropped
         * reads zero past the valid data length -- the read path clamps the disk read to it, and the file system
         * holds the length at its old value until the zeroing finishes -- so keeping it is correct.
         */
        for (;;)
        {
            Entry = MmGetPageEntrySectionSegment(Segment, &Offset);

            if (MM_IS_WAIT_PTE(Entry))
            {
                /* A fast-I/O caller cannot block on a read in flight: let it take its own path */
                if (!Wait)
                {
                    MmUnlockSectionSegment(Segment);
                    Status = STATUS_CANT_WAIT;
                    goto done;
                }
                /* A reclaim thread must not poll another thread's wait entry either: its holder may itself be in
                 * a memory wait, so this could spin as long as that wait. Fail; the page stays dirty and retries. */
                if (!WaitState.MayWait)
                {
                    MmUnlockSectionSegment(Segment);
                    Status = STATUS_NO_MEMORY;
                    goto done;
                }
                /* Another thread's read is in flight: let it finish. This is not a memory shortage. */
                MmUnlockSectionSegment(Segment);
                KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
                MmLockSectionSegment(Segment);
                continue;
            }

            /* Cc's segment: no page-file entries */
            ASSERT(!IS_SWAP_FROM_SSE(Entry));

            if (Entry != 0)
            {
                /* A resident page keeps its content and is dirtied; its slice exists, so this cannot fail */
                NT_VERIFY(NT_SUCCESS(MmSetPageEntrySectionSegment(Segment, &Offset, DIRTY_SSE(Entry))));
                Resident = TRUE;
                break;
            }

            if (!Wait)
            {
                MmUnlockSectionSegment(Segment);
                Status = STATUS_CANT_WAIT;
                goto done;
            }

            /* Keep everybody else off this page while it is read or zeroed */
            if (NT_SUCCESS(MmSetPageEntrySectionSegment(Segment, &Offset, MAKE_SWAP_SSE(MM_WAIT_ENTRY))))
                break;

            /* The slice allocation failed and nothing is published: wait for memory, or fail if we must not */
            MmUnlockSectionSegment(Segment);
            if (!MiZeroSegmentWaitForMemory(&WaitState))
            {
                Status = STATUS_NO_MEMORY;
                goto done;
            }
            MmLockSectionSegment(Segment);
        }
        MmUnlockSectionSegment(Segment);

        if (Resident)
            continue;

        /*
         * The page comes zeroed. The wait entry set above holds the page while we get one; MmRequestPageMemoryConsumer
         * does not itself wait, so wait for memory the same bounded way, or give up (the finalize below drops the wait
         * entry and the failure returns). A page the range only partly covers (the one that straddles Start, keeping
         * its bytes below Start, and the one that straddles End, keeping its bytes above End) is read first so those
         * bytes survive; only the covered span [ZeroStart, ZeroEnd) is then zeroed. A whole page inside [Start, End)
         * is left as a zero page without a read. A genuine read error is not memory pressure and is left to propagate.
         */
        for (;;)
        {
            Status = MmRequestPageMemoryConsumer(MC_USER, TRUE, &Page);
            if (Status != STATUS_NO_MEMORY)
                break;
            if (!MiZeroSegmentWaitForMemory(&WaitState))
                break;
        }
        if (NT_SUCCESS(Status) &&
            (ZeroStart > Offset.QuadPart || ZeroEnd < Offset.QuadPart + PAGE_SIZE))
        {
            Status = MiReadSegmentPage(Segment, Offset.QuadPart, Page);
            if (NT_SUCCESS(Status) && (ZeroStart < ZeroEnd))
            {
                KIRQL Irql;
                PUCHAR Address = MiMapPageInHyperSpace(Process, Page, &Irql);

                RtlZeroMemory(Address + (ZeroStart - Offset.QuadPart), (SIZE_T)(ZeroEnd - ZeroStart));
                MiUnmapPageInHyperSpace(Process, Address, Irql);
            }
            if (!NT_SUCCESS(Status))
                MmReleasePageMemoryConsumer(MC_USER, Page);
        }

        MmLockSectionSegment(Segment);
        ASSERT(MM_IS_WAIT_PTE(MmGetPageEntrySectionSegment(Segment, &Offset)));
        MmSetPageEntrySectionSegment(Segment, &Offset, NT_SUCCESS(Status) ? DIRTY_SSE(MAKE_SSE(Page << PAGE_SHIFT, 0)) : 0);
        MmUnlockSectionSegment(Segment);

        if (!NT_SUCCESS(Status))
            break;
    }

done:
    MmDereferenceSegment(Segment);
    return Status;
}

/* Like CcPurgeCache but for the in-memory segment */
BOOLEAN
NTAPI
MmPurgeSegment(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_opt_ PLARGE_INTEGER Offset,
    _In_ ULONG Length)
{
    LARGE_INTEGER PurgeStart, PurgeEnd;
    LONGLONG RangeStart;
    PMM_SECTION_SEGMENT Segment;
    BOOLEAN Success = TRUE;

    PurgeStart.QuadPart = Offset ? Offset->QuadPart : 0LL;
    if (Length && Offset)
    {
        if (!NT_SUCCESS(RtlLongLongAdd(PurgeStart.QuadPart, Length, &PurgeEnd.QuadPart)))
            return FALSE;
    }

    Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
    {
        /* Nothing to purge */
        return TRUE;
    }

    MmLockSectionSegment(Segment);

    if (!Length || !Offset)
    {
        /* We must calculate the length for ourselves */
        /* FIXME: All of this is suboptimal */
        ULONG ElemCount = RtlNumberGenericTableElements(&Segment->PageTable);
        if (!ElemCount)
        {
            /* No page. Nothing to purge */
            MmUnlockSectionSegment(Segment);
            MmDereferenceSegment(Segment);
            return TRUE;
        }

        PurgeEnd.QuadPart = MiGetSegmentPageTableEnd(Segment);
    }

    /* Find byte offset of the page to start */
    RangeStart = PurgeStart.QuadPart;
    PurgeStart.QuadPart = PAGE_ROUND_DOWN_64(PurgeStart.QuadPart);

    while (PurgeStart.QuadPart < PurgeEnd.QuadPart)
    {
        ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &PurgeStart);

        if (Entry == 0)
        {
            PurgeStart.QuadPart += PAGE_SIZE;
            continue;
        }

        if (IS_SWAP_FROM_SSE(Entry))
        {
            ASSERT(SWAPENTRY_FROM_SSE(Entry) == MM_WAIT_ENTRY);
            /* The page is currently being read. Meaning someone will need it soon. Bad luck */
            MmUnlockSectionSegment(Segment);
            MmDereferenceSegment(Segment);
            return FALSE;
        }

        if (IS_WRITE_SSE(Entry))
        {
            /* We're trying to purge an entry which is being written. Restart this loop iteration */
            MmUnlockSectionSegment(Segment);
            KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
            MmLockSectionSegment(Segment);
            continue;
        }

        if (IS_DIRTY_SSE(Entry) &&
            (PurgeStart.QuadPart < RangeStart || PurgeStart.QuadPart + PAGE_SIZE > PurgeEnd.QuadPart))
        {
            /*
             * Only partly in the range, and dirty: dropping it would lose the bytes of it outside the
             * range that nobody wrote yet (a file cut in the middle of a page whose cache views are
             * not mapped any more).  Keep it, and tell the caller it could not purge everything.
             */
            Success = FALSE;
            PurgeStart.QuadPart += PAGE_SIZE;
            continue;
        }

        if (SHARE_COUNT_FROM_SSE(Entry) > 0)
        {
            /* This page is currently in use. Bad luck */
            MmUnlockSectionSegment(Segment);
            MmDereferenceSegment(Segment);
            return FALSE;
        }

        /* We can let this page go */
        MmSetPageEntrySectionSegment(Segment, &PurgeStart, 0);
        MmReleasePageMemoryConsumer(MC_USER, PFN_FROM_SSE(Entry));

        PurgeStart.QuadPart += PAGE_SIZE;
    }

    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);
    return Success;
}

BOOLEAN
NTAPI
MmIsDataSectionResident(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ LONGLONG Offset,
    _In_ ULONG Length)
{
    PMM_SECTION_SEGMENT Segment;
    LARGE_INTEGER RangeStart, RangeEnd;
    BOOLEAN Ret = TRUE;

    RangeStart.QuadPart = Offset;
    if (!NT_SUCCESS(RtlLongLongAdd(RangeStart.QuadPart, Length, &RangeEnd.QuadPart)))
        return FALSE;

    Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
        return FALSE;

    /* Find byte offset of the page to start */
    RangeStart.QuadPart = PAGE_ROUND_DOWN_64(RangeStart.QuadPart);

    MmLockSectionSegment(Segment);

    while (RangeStart.QuadPart < RangeEnd.QuadPart)
    {
        ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &RangeStart);
        if ((Entry == 0) || IS_SWAP_FROM_SSE(Entry))
        {
            Ret = FALSE;
            break;
        }

        RangeStart.QuadPart += PAGE_SIZE;
    }

    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);

    return Ret;
}

NTSTATUS
NTAPI
MmMakeDataSectionResident(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ LONGLONG Offset,
    _In_ ULONG Length,
    _In_ PLARGE_INTEGER ValidDataLength,
    _In_ BOOLEAN WaitForPages)
{
    PMM_SECTION_SEGMENT Segment = MiGrabDataSection(SectionObjectPointer);

    /* There must be a segment for this call */
    ASSERT(Segment);

    BOOLEAN OutOfPages = FALSE;
    NTSTATUS Status = MmMakeSegmentResident(Segment, Offset, Length, ValidDataLength, FALSE, &OutOfPages);

    /*
     * No page to read into. If the cache copies file data for a caller
     * (WaitForPages), start the balancer and try again every 50 ms while
     * reclamation progresses: stop when no page has been written back or
     * paged out (MiReclaimProgress) for 30 seconds, or after 2 minutes for
     * this range, with one last attempt. The caller of a copy holds file
     * system resources (at least those of its file), and reclamation can
     * depend on them: the balancer skips a page whose file it cannot lock
     * without waiting (btrfs takes the main resource, which its writer
     * holds). When reclamation stops, the failure goes back up and the
     * caller releases its locks; write-back of other files can still keep
     * such a caller waiting up to the 2 minutes. A pin or map of file
     * system metadata fails at once: its caller can hold volume locks that
     * the write-back needs. System threads do not wait: the balancer and
     * the lazy writer free the pages, and read-ahead is optional. A thread
     * that is being terminated stops between attempts. These checks run
     * between attempts; a page-in that an attempt waits for is not bounded
     * by them. A STATUS_NO_MEMORY that the paging read reports is not
     * retried.
     */
    if (OutOfPages && WaitForPages && !PsIsSystemThread(PsGetCurrentThread()))
    {
        const ULONGLONG StallTime = 30 * 1000 * 10000ULL;    /* 30 s, in 100 ns units */
        const ULONGLONG MaximumTime = 120 * 1000 * 10000ULL; /* 2 min */
        ULONGLONG Start = KeQueryInterruptTime();
        ULONGLONG Progress = Start;
        ULONGLONG Now;
        LONG Reclaimed = MiReclaimProgress;
        BOOLEAN LastAttempt = FALSE;
        LARGE_INTEGER Delay;

        Delay.QuadPart = -50 * 10000LL;  /* 50 ms */
        do
        {
            MmRebalanceMemoryConsumers();
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);

            if (PsIsThreadTerminating(PsGetCurrentThread()))
                break;

            Now = KeQueryInterruptTime();
            if (MiReclaimProgress != Reclaimed)
            {
                Reclaimed = MiReclaimProgress;
                Progress = Now;
            }
            /* One last attempt: pages freed other ways do not move the count */
            LastAttempt = (Now - Progress >= StallTime) || (Now - Start >= MaximumTime);

            OutOfPages = FALSE;
            Status = MmMakeSegmentResident(Segment, Offset, Length, ValidDataLength, FALSE, &OutOfPages);
        } while (OutOfPages && !LastAttempt);
    }

    MmDereferenceSegment(Segment);

    return Status;
}

NTSTATUS
NTAPI
MmMakeSegmentDirty(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ LONGLONG Offset,
    _In_ ULONG Length)
{
    PMM_SECTION_SEGMENT Segment;
    LARGE_INTEGER RangeStart, RangeEnd;
    NTSTATUS Status;

    RangeStart.QuadPart = Offset;
    Status = RtlLongLongAdd(RangeStart.QuadPart, Length, &RangeEnd.QuadPart);
    if (!NT_SUCCESS(Status))
        return Status;

    Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
        return STATUS_NOT_MAPPED_VIEW;

    /* Find byte offset of the page to start */
    RangeStart.QuadPart = PAGE_ROUND_DOWN_64(RangeStart.QuadPart);

    MmLockSectionSegment(Segment);

    while (RangeStart.QuadPart < RangeEnd.QuadPart)
    {
        ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &RangeStart);

        /* Let any pending read proceed */
        while (MM_IS_WAIT_PTE(Entry))
        {
            MmUnlockSectionSegment(Segment);
            KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
            MmLockSectionSegment(Segment);
            Entry = MmGetPageEntrySectionSegment(Segment, &RangeStart);
        }

        /* We are called from Cc, this can't be backed by the page files */
        ASSERT(!IS_SWAP_FROM_SSE(Entry));

        /* If there is no page there, there is nothing to make dirty */
        if (Entry != 0)
        {
            /* Dirtify the entry */
            MmSetPageEntrySectionSegment(Segment, &RangeStart, DIRTY_SSE(Entry));
        }

        RangeStart.QuadPart += PAGE_SIZE;
    }

    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);

    return STATUS_SUCCESS;
}

/* A dirty page of a data file that a cluster write may take: resident, not being written already */
FORCEINLINE
BOOLEAN
MiIsClusterableDirtyEntry(
    _In_ ULONG_PTR Entry)
{
    return (Entry != 0) && !IS_SWAP_FROM_SSE(Entry) && IS_DIRTY_SSE(Entry) && !IS_WRITE_SSE(Entry) &&
           (SHARE_COUNT_FROM_SSE(Entry) < MAX_SHARE_COUNT);
}

/*
 * Writes the dirty page at Start and the dirty pages that follow it (up to MM_FLUSH_CLUSTER_PAGES,
 * not past End) with one paging write, as MmCheckDirtySegment does for one page: each page is held
 * (share count) and marked as being written while the segment is unlocked, and stays dirty when the
 * write fails or the page was dirtied again meanwhile. Returns the pages handled.
 */
_Requires_exclusive_lock_held_(Segment->Lock)
static
ULONG
MiFlushDirtyCluster(
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ PLARGE_INTEGER Start,
    _In_ LONGLONG End)
{
    PFN_NUMBER Pages[MM_FLUSH_CLUSTER_PAGES];
    LARGE_INTEGER Offset = *Start;
    ULONG_PTR Entry;
    NTSTATUS Status;
    ULONG Count = 0, i;

    ASSERT(Segment->Locked);
    ASSERT(FlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT));

    while ((Count < MM_FLUSH_CLUSTER_PAGES) && (Offset.QuadPart < End))
    {
        Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
        if (!MiIsClusterableDirtyEntry(Entry))
            break;
        Pages[Count++] = PFN_FROM_SSE(Entry);
        Offset.QuadPart += PAGE_SIZE;
    }

    /* A lone page, or one already being written: the single page path, as before */
    if (Count <= 1)
    {
        MmCheckDirtySegment(Segment, Start, FALSE, FALSE);
        return 1;
    }

    /* Hold the pages, mark them as being written and clean */
    for (i = 0, Offset = *Start; i < Count; i++, Offset.QuadPart += PAGE_SIZE)
    {
        Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
        Entry = MAKE_SSE(PAGE_FROM_SSE(Entry), SHARE_COUNT_FROM_SSE(Entry) + 1);
        MmSetPageEntrySectionSegment(Segment, &Offset, WRITE_SSE(Entry));
    }

    MmUnlockSectionSegment(Segment);
    Status = MiWritePages(Segment, Start->QuadPart, Pages, Count);
    MmLockSectionSegment(Segment);

    if (!NT_SUCCESS(Status))
        DPRINT1("MiWritePages FAILED: Status 0x%08x (%lu pages at 0x%I64x)\n", Status, Count, Start->QuadPart);

    /* Drop the holds; a page that failed or was dirtied again meanwhile stays dirty */
    for (i = 0, Offset = *Start; i < Count; i++, Offset.QuadPart += PAGE_SIZE)
    {
        BOOLEAN DirtyAgain;

        Entry = MmGetPageEntrySectionSegment(Segment, &Offset);
        ASSERT(PFN_FROM_SSE(Entry) == Pages[i]);
        DirtyAgain = !NT_SUCCESS(Status) || IS_DIRTY_SSE(Entry);
        Entry = MAKE_SSE(Pages[i] << PAGE_SHIFT, SHARE_COUNT_FROM_SSE(Entry) - 1);
        if (DirtyAgain)
            Entry = DIRTY_SSE(Entry);
        MmSetPageEntrySectionSegment(Segment, &Offset, Entry);
    }

    return Count;
}

NTSTATUS
NTAPI
MmFlushSegment(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_opt_ PLARGE_INTEGER Offset,
    _In_ ULONG Length,
    _Out_opt_ PIO_STATUS_BLOCK Iosb)
{
    LARGE_INTEGER FlushStart, FlushEnd;
    NTSTATUS Status;

    if (Offset)
    {
        FlushStart = *Offset;
        Status = RtlLongLongAdd(FlushStart.QuadPart, Length, &FlushEnd.QuadPart);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    if (Iosb)
        Iosb->Information = 0;

    PMM_SECTION_SEGMENT Segment = MiGrabDataSection(SectionObjectPointer);
    if (!Segment)
    {
        /* Nothing to flush */
        goto Quit;
    }

    ASSERT(*Segment->Flags & MM_DATAFILE_SEGMENT);

    MmLockSectionSegment(Segment);

    if (!Offset)
    {
        FlushStart.QuadPart = 0;

        /* FIXME: All of this is suboptimal */
        ULONG ElemCount = RtlNumberGenericTableElements(&Segment->PageTable);
        if (!ElemCount)
        {
            /* No page. Nothing to flush */
            MmUnlockSectionSegment(Segment);
            MmDereferenceSegment(Segment);
            goto Quit;
        }

        FlushEnd.QuadPart = MiGetSegmentPageTableEnd(Segment);
    }

    /* Find byte offset of the page to start */
    FlushStart.QuadPart = PAGE_ROUND_DOWN_64(FlushStart.QuadPart);

    while (FlushStart.QuadPart < FlushEnd.QuadPart)
    {
        ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &FlushStart);
        ULONG Pages = 1;

        if (IS_DIRTY_SSE(Entry))
        {
            Pages = MiFlushDirtyCluster(Segment, &FlushStart, FlushEnd.QuadPart);

            if (Iosb)
                Iosb->Information += Pages * PAGE_SIZE;
        }

        FlushStart.QuadPart += Pages * PAGE_SIZE;
    }

    MmUnlockSectionSegment(Segment);
    MmDereferenceSegment(Segment);

Quit:
    /* FIXME: Handle failures */
    if (Iosb)
        Iosb->Status = STATUS_SUCCESS;

    return STATUS_SUCCESS;
}

/*
 * As MmCheckDirtySegment, and reports in *WriteStatus how the write of the page went (STATUS_SUCCESS when
 * there was nothing to write), for a caller that has to decide whether a page can ever be written
 * (MiShutdownSystem).
 */
_Requires_exclusive_lock_held_(Segment->Lock)
BOOLEAN
NTAPI
MmCheckDirtySegmentEx(
    PMM_SECTION_SEGMENT Segment,
    PLARGE_INTEGER Offset,
    BOOLEAN ForceDirty,
    BOOLEAN PageOut,
    _Out_ PNTSTATUS WriteStatus)
{
    ULONG_PTR Entry;
    NTSTATUS Status;
    PFN_NUMBER Page;

    *WriteStatus = STATUS_SUCCESS;

    ASSERT(Segment->Locked);

    ASSERT((Offset->QuadPart % PAGE_SIZE) == 0);

    DPRINT("Checking segment for file %wZ at offset 0x%I64X.\n", &Segment->FileObject->FileName, Offset->QuadPart);

    Entry = MmGetPageEntrySectionSegment(Segment, Offset);
    if (Entry == 0)
        return FALSE;

    Page = PFN_FROM_SSE(Entry);
    if ((IS_DIRTY_SSE(Entry)) || ForceDirty)
    {
        BOOLEAN DirtyAgain;

        /*
         * We got a dirty entry. This path is for the shared data,
         * be-it regular file maps or shared sections of DLLs
         */
        ASSERT(FlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT) ||
               FlagOn(Segment->Image.Characteristics, IMAGE_SCN_MEM_SHARED));

        /* Insert the cleaned entry back. Mark it as write in progress, and clear the dirty bit. */
        Entry = MAKE_SSE(PAGE_FROM_SSE(Entry), SHARE_COUNT_FROM_SSE(Entry) + 1);
        Entry = WRITE_SSE(Entry);
        MmSetPageEntrySectionSegment(Segment, Offset, Entry);

        MmUnlockSectionSegment(Segment);

        if (FlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT))
        {
            PERESOURCE ResourceToRelease = NULL;
            KIRQL OldIrql;

            /* We have to write it back to the file. Tell the FS driver who we are */
            if (PageOut)
            {
                LARGE_INTEGER EndOffset = *Offset;

                ASSERT(IoGetTopLevelIrp() == NULL);

                /* We need to disable all APCs */
                KeRaiseIrql(APC_LEVEL, &OldIrql);

                EndOffset.QuadPart += PAGE_SIZE;
                Status = FsRtlAcquireFileForModWriteEx(Segment->FileObject,
                                                       &EndOffset,
                                                       &ResourceToRelease);
                if (NT_SUCCESS(Status))
                {
                    IoSetTopLevelIrp((PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP);
                }
                else
                {
                    /* Make sure we will not try to release anything */
                    ResourceToRelease = NULL;
                }
            }
            else
            {
                /* We don't have to lock. Say this is success */
                Status = STATUS_SUCCESS;
            }

            /* Go ahead and write the page, if previous locking succeeded */
            if (NT_SUCCESS(Status))
            {
                DPRINT("Writing page at offset %I64d for file %wZ, Pageout: %s\n",
                        Offset->QuadPart, &Segment->FileObject->FileName, PageOut ? "TRUE" : "FALSE");
                Status = MiWritePage(Segment, Offset->QuadPart, Page);
            }

            if (PageOut)
            {
                IoSetTopLevelIrp(NULL);
                if (ResourceToRelease != NULL)
                {
                    FsRtlReleaseFileForModWrite(Segment->FileObject, ResourceToRelease);
                }
                KeLowerIrql(OldIrql);
            }
        }
        else
        {
            /* This must only be called by the page-out path */
            ASSERT(PageOut);

            /* And this must be for a shared section in a DLL */
            ASSERT(FlagOn(Segment->Image.Characteristics, IMAGE_SCN_MEM_SHARED));

            SWAPENTRY SwapEntry = MmGetSavedSwapEntryPage(Page);
            if (!SwapEntry)
            {
                SwapEntry = MmAllocSwapPage();
            }

            if (SwapEntry)
            {
                Status = MmWriteToSwapPage(SwapEntry, Page);
                if (NT_SUCCESS(Status))
                {
                    MmSetSavedSwapEntryPage(Page, SwapEntry);
                }
                else
                {
                    /* The page may have had this entry saved already: forget it */
                    MmSetSavedSwapEntryPage(Page, 0);
                    MmFreeSwapPage(SwapEntry);
                }
            }
            else
            {
                DPRINT1("Failed to allocate a swap page!\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        MmLockSectionSegment(Segment);
        *WriteStatus = Status;

        /* Get the entry again */
        Entry = MmGetPageEntrySectionSegment(Segment, Offset);
        ASSERT(PFN_FROM_SSE(Entry) == Page);

        if (!NT_SUCCESS(Status))
        {
            /* Damn, this failed. Consider this page as still dirty. A file system refuses a lazy write of a
             * user-mapped page past its valid data length on purpose (STATUS_FILE_LOCK_CONFLICT); do not log
             * that expected one, but keep logging every other failure and real range-lock conflicts. */
            PFSRTL_COMMON_FCB_HEADER FcbHeader = Segment->FileObject ? Segment->FileObject->FsContext : NULL;
            if (Status != STATUS_FILE_LOCK_CONFLICT || FcbHeader == NULL ||
                !FlagOn(FcbHeader->Flags, FSRTL_FLAG_USER_MAPPED_FILE))
            {
                DPRINT1("MiWritePage FAILED: Status 0x%08x!\n", Status);
            }
            DirtyAgain = TRUE;
        }
        else
        {
            /* Check if someone dirtified this page while we were not looking */
            DirtyAgain = IS_DIRTY_SSE(Entry);
        }

        /* Drop the reference we got, deleting the write altogether. */
        Entry = MAKE_SSE(Page << PAGE_SHIFT, SHARE_COUNT_FROM_SSE(Entry) - 1);
        if (DirtyAgain)
        {
            Entry = DIRTY_SSE(Entry);
        }
        MmSetPageEntrySectionSegment(Segment, Offset, Entry);
    }

    /* Were this page hanging there just for the sake of being present ? */
    if (!IS_DIRTY_SSE(Entry) && (SHARE_COUNT_FROM_SSE(Entry) == 0) && PageOut)
    {
        ULONG_PTR NewEntry = 0;
        /* Restore the swap entry here */
        if (!FlagOn(*Segment->Flags, MM_DATAFILE_SEGMENT))
        {
            SWAPENTRY SwapEntry = MmGetSavedSwapEntryPage(Page);
            if (SwapEntry)
                NewEntry = MAKE_SWAP_SSE(SwapEntry);
        }

        /* Yes. Release it */
        MmSetPageEntrySectionSegment(Segment, Offset, NewEntry);
        MmReleasePageMemoryConsumer(MC_USER, Page);
        /* Tell the caller we released the page */
        return TRUE;
    }

    return FALSE;
}

_Requires_exclusive_lock_held_(Segment->Lock)
BOOLEAN
NTAPI
MmCheckDirtySegment(
    PMM_SECTION_SEGMENT Segment,
    PLARGE_INTEGER Offset,
    BOOLEAN ForceDirty,
    BOOLEAN PageOut)
{
    NTSTATUS WriteStatus;

    return MmCheckDirtySegmentEx(Segment, Offset, ForceDirty, PageOut, &WriteStatus);
}

/* This function is not used. It is left for future use, when per-process
 * address space is considered. */
#if 0
NTSTATUS
NTAPI
MmMakePagesDirty(
    _In_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ ULONG Length)
{
    PMEMORY_AREA MemoryArea;
    PMM_SECTION_SEGMENT Segment;
    LARGE_INTEGER SegmentOffset, RangeEnd;
    PMMSUPPORT AddressSpace = Process ? &Process->Vm : MmGetKernelAddressSpace();

    MmLockAddressSpace(AddressSpace);

    MemoryArea = MmLocateMemoryAreaByAddress(AddressSpace, Address);
    if (MemoryArea == NULL)
    {
        DPRINT1("Unable to find memory area at address %p.\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Only supported in old Mm for now */
    ASSERT(MemoryArea->Type == MEMORY_AREA_SECTION_VIEW);
    /* For file mappings */
    ASSERT(MemoryArea->VadNode.u.VadFlags.VadType != VadImageMap);

    Segment = MemoryArea->SectionData.Segment;
    MmLockSectionSegment(Segment);

    SegmentOffset.QuadPart = PAGE_ROUND_DOWN(Address) - MA_GetStartingAddress(MemoryArea)
            + MemoryArea->SectionData.ViewOffset;
    RangeEnd.QuadPart = PAGE_ROUND_UP((ULONG_PTR)Address + Length) - MA_GetStartingAddress(MemoryArea)
            + MemoryArea->SectionData.ViewOffset;

    DPRINT("MmMakePagesResident: Segment %p, 0x%I64x -> 0x%I64x\n", Segment, SegmentOffset.QuadPart, RangeEnd.QuadPart);

    while (SegmentOffset.QuadPart < RangeEnd.QuadPart)
    {
        ULONG_PTR Entry = MmGetPageEntrySectionSegment(Segment, &SegmentOffset);

        /* Let any pending read proceed */
        while (MM_IS_WAIT_PTE(Entry))
        {
            MmUnlockSectionSegment(Segment);
            MmUnlockAddressSpace(AddressSpace);
            KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
            MmLockAddressSpace(AddressSpace);
            MmLockSectionSegment(Segment);
            Entry = MmGetPageEntrySectionSegment(Segment, &SegmentOffset);
        }

        /* We are called from Cc, this can't be backed by the page files */
        ASSERT(!IS_SWAP_FROM_SSE(Entry));

        /* If there is no page there, there is nothing to make dirty */
        if (Entry != 0)
        {
            /* Dirtify the entry */
            MmSetPageEntrySectionSegment(Segment, &SegmentOffset, DIRTY_SSE(Entry));
        }

        SegmentOffset.QuadPart += PAGE_SIZE;
    }

    MmUnlockSectionSegment(Segment);

    MmUnlockAddressSpace(AddressSpace);
    return STATUS_SUCCESS;
}
#endif

/* Grows a ROS data section and its segment to NewSize; a smaller size changes nothing */
static
VOID
MiGrowDataSection(
    _In_ PSECTION Section,
    _In_ PMM_SECTION_SEGMENT Segment,
    _In_ PLARGE_INTEGER NewSize)
{
    if (NewSize->QuadPart <= Section->SizeOfSection.QuadPart)
        return;

    Section->SizeOfSection = *NewSize;

    /* A SEC_RESERVE section keeps its segment, as before the file could grow */
    if (!Section->u.Flags.Reserve)
    {
        MmLockSectionSegment(Segment);
        if (Segment->RawLength.QuadPart < NewSize->QuadPart)
        {
            Segment->RawLength = *NewSize;
            Segment->Length.QuadPart = PAGE_ROUND_UP_64(NewSize->QuadPart);
        }
        MmUnlockSectionSegment(Segment);
    }
}

NTSTATUS
NTAPI
MmExtendSection(
    _In_ PVOID _Section,
    _Inout_ PLARGE_INTEGER NewSize,
    _In_ BOOLEAN IgnoreFileSizeChecking)
{
    PSECTION Section = _Section;
    PMM_SECTION_SEGMENT Segment;
    NTSTATUS Status;

    /* It makes no sense to extend an image mapping */
    if (Section->u.Flags.Image)
        return STATUS_SECTION_NOT_EXTENDED;

    /* Nor is it possible to extend a page file mapping */
    if (!Section->u.Flags.File)
        return STATUS_SECTION_NOT_EXTENDED;

    if (!MiIsRosSectionObject(Section))
        return STATUS_NOT_IMPLEMENTED;

    Segment = (PMM_SECTION_SEGMENT)Section->Segment;

    /* The cache manager: the file system has already set the size, and the section only grows */
    if (IgnoreFileSizeChecking)
    {
        MiGrowDataSection(Section, Segment, NewSize);
        return STATUS_SUCCESS;
    }

    /* NtExtendSection: the section takes any smaller size, and a larger one extends the file */
    if (NewSize->QuadPart < 0)
        return STATUS_SECTION_TOO_BIG;

    /*
     * One extension at a time, so that the file size checked here is still the file size when the
     * section grows. No Mm lock is held across the file-system call, which re-enters CcSetFileSizes.
     */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&MmpExtendSectionLock, TRUE);

    if (NewSize->QuadPart <= Section->SizeOfSection.QuadPart)
    {
        Section->SizeOfSection = *NewSize;
        Status = STATUS_SUCCESS;
    }
    else
    {
        LARGE_INTEGER FileSize;

        /*
         * The global lock serializes extenders only: a write through another handle can grow the file
         * past NewSize before the file system takes the new end of file, and another handle can shrink
         * it before the section grows. A file system asks MmCanFileBeTruncated before it shrinks a file,
         * which refuses any size below the current one while the segment is extending.
         */
        MmLockSectionSegment(Segment);
        Segment->Extending = TRUE;
        MmUnlockSectionSegment(Segment);

        Status = FsRtlGetFileSize(Segment->FileObject, &FileSize);
        if (!NT_SUCCESS(Status))
        {
            Status = STATUS_SECTION_NOT_EXTENDED;
        }
        else if (NewSize->QuadPart > FileSize.QuadPart)
        {
            /* Only a section that can write to the file extends it */
            if (!(Section->InitialPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                Status = STATUS_SECTION_NOT_EXTENDED;
            }
            else
            {
                Status = IoSetInformation(Segment->FileObject,
                                          FileEndOfFileInformation,
                                          sizeof(LARGE_INTEGER),
                                          NewSize);

                /* Refused as a shrink: another writer grew the file to NewSize or more meanwhile */
                if (!NT_SUCCESS(Status) &&
                    NT_SUCCESS(FsRtlGetFileSize(Segment->FileObject, &FileSize)) &&
                    FileSize.QuadPart >= NewSize->QuadPart)
                {
                    Status = STATUS_SUCCESS;
                }
                if (!NT_SUCCESS(Status))
                    Status = STATUS_SECTION_NOT_EXTENDED;
            }
        }

        if (NT_SUCCESS(Status))
            MiGrowDataSection(Section, Segment, NewSize);

        MmLockSectionSegment(Segment);
        Segment->Extending = FALSE;
        MmUnlockSectionSegment(Segment);
    }

    ExReleaseResourceLite(&MmpExtendSectionLock);
    KeLeaveCriticalRegion();

    return Status;
}

/* EOF */
