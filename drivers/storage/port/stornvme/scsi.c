/*
 * PROJECT:         ReactOS NVMe Storport Miniport Driver
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         SCSI to NVMe translation
 * COPYRIGHT:       Copyright 2026 Tomas Srnka
 *
 * Written from the public NVM Express SCSI Translation Reference (revision 1.5),
 * SPC-4/SBC-3 and the NVM Express Base Specification (revision 1.4). No third-party
 * source code was used. Where Windows' own NVMe driver is known to differ from the
 * translation reference in something visible (the INQUIRY strings), Windows is followed.
 *
 * Every function here runs with the interrupt lock held (see stornvme.c).
 */

#include "stornvme.h"

#include <debug.h>

/* SCSI values storport.h leaves out (scsi.h cannot be included next to it) */
#define NVME_SCSIOP_UNMAP                   0x42
#define NVME_SCSIOP_SECURITY_PROTOCOL_IN    0xA2
#define NVME_SCSIOP_SECURITY_PROTOCOL_OUT   0xB5
#define NVME_SA_READ_CAPACITY16             0x10

#define NVME_ASC_NO_SENSE                   0x00
#define NVME_ASC_WRITE_FAULT                0x03
#define NVME_ASC_LUN_NOT_READY              0x04
#define NVME_ASC_DATA_INTEGRITY             0x10
#define NVME_ASC_UNRECOVERED_READ           0x11
#define NVME_ASC_PARAMETER_LIST_LENGTH      0x1A
#define NVME_ASC_MISCOMPARE                 0x1D
#define NVME_ASC_ILLEGAL_COMMAND            0x20
#define NVME_ASC_ILLEGAL_BLOCK              0x21
#define NVME_ASC_INVALID_CDB                0x24
#define NVME_ASC_INVALID_LUN                0x25
#define NVME_ASC_INVALID_FIELD_PARAMETER    0x26
#define NVME_ASC_WRITE_PROTECT              0x27
#define NVME_ASC_SAVING_NOT_SUPPORTED       0x39
#define NVME_ASC_INTERNAL_TARGET_FAILURE    0x44
#define NVME_ASC_ACCESS_DENIED              0x20

#define NVME_ASCQ_FORMAT_IN_PROGRESS        0x04

#define NVME_SENSE_NO_SENSE                 0x00
#define NVME_SENSE_NOT_READY                0x02
#define NVME_SENSE_MEDIUM_ERROR             0x03
#define NVME_SENSE_HARDWARE_ERROR           0x04
#define NVME_SENSE_ILLEGAL_REQUEST          0x05
#define NVME_SENSE_DATA_PROTECT             0x07
#define NVME_SENSE_ABORTED_COMMAND          0x0B
#define NVME_SENSE_MISCOMPARE               0x0E

/* VPD pages */
#define NVME_VPD_SUPPORTED_PAGES            0x00
#define NVME_VPD_SERIAL_NUMBER              0x80
#define NVME_VPD_DEVICE_IDENTIFIERS         0x83
#define NVME_VPD_BLOCK_LIMITS               0xB0
#define NVME_VPD_BLOCK_DEVICE_CHARACTERISTICS 0xB1
#define NVME_VPD_LOGICAL_BLOCK_PROVISIONING 0xB2

/* Mode pages */
#define NVME_MODE_PAGE_CACHING              0x08
#define NVME_MODE_PAGE_CONTROL              0x0A
#define NVME_MODE_PAGE_INFO_EXCEPTIONS      0x1C
#define NVME_MODE_PAGE_ALL                  0x3F

#define NVME_MODE_DPOFUA                    0x10

/* HELPERS ********************************************************************/

static
VOID
PutBe16(
    _Out_writes_(2) PUCHAR p,
    _In_ ULONG v)
{
    p[0] = (UCHAR)(v >> 8);
    p[1] = (UCHAR)v;
}

static
VOID
PutBe32(
    _Out_writes_(4) PUCHAR p,
    _In_ ULONG v)
{
    p[0] = (UCHAR)(v >> 24);
    p[1] = (UCHAR)(v >> 16);
    p[2] = (UCHAR)(v >> 8);
    p[3] = (UCHAR)v;
}

static
VOID
PutBe64(
    _Out_writes_(8) PUCHAR p,
    _In_ ULONGLONG v)
{
    PutBe32(p, (ULONG)(v >> 32));
    PutBe32(p + 4, (ULONG)v);
}

static
ULONG
GetBe16(
    _In_reads_(2) const UCHAR *p)
{
    return ((ULONG)p[0] << 8) | p[1];
}

static
ULONG
GetBe32(
    _In_reads_(4) const UCHAR *p)
{
    return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3];
}

static
ULONGLONG
GetBe64(
    _In_reads_(8) const UCHAR *p)
{
    return ((ULONGLONG)GetBe32(p) << 32) | GetBe32(p + 4);
}

static
BOOLEAN
IsAllZero(
    _In_reads_(Length) const UCHAR *p,
    _In_ ULONG Length)
{
    ULONG i;

    for (i = 0; i < Length; i++)
    {
        if (p[i])
            return FALSE;
    }
    return TRUE;
}

VOID
NvmeScsiSetSense(
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ UCHAR SenseKey,
    _In_ UCHAR Asc,
    _In_ UCHAR Ascq)
{
    UCHAR Sense[18] = {0};
    ULONG Length;

    Sense[0] = 0x70;            /* current error, fixed format */
    Sense[2] = SenseKey;
    Sense[7] = sizeof(Sense) - 8;
    Sense[12] = Asc;
    Sense[13] = Ascq;

    Srb->ScsiStatus = SCSISTAT_CHECK_CONDITION;
    Srb->DataTransferLength = 0;

    if (Srb->SenseInfoBuffer != NULL && Srb->SenseInfoBufferLength != 0 &&
        !(Srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE))
    {
        Length = min(Srb->SenseInfoBufferLength, sizeof(Sense));
        RtlCopyMemory(Srb->SenseInfoBuffer, Sense, Length);
        Srb->SenseInfoBufferLength = (UCHAR)Length;
        Srb->SrbStatus = SRB_STATUS_ERROR | SRB_STATUS_AUTOSENSE_VALID;
    }
    else
    {
        Srb->SrbStatus = SRB_STATUS_ERROR;
    }
}

static
VOID
NvmeFailSrb(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ UCHAR SenseKey,
    _In_ UCHAR Asc,
    _In_ UCHAR Ascq)
{
#if DBG
    StorPortDebugPrint(0, "stornvme: CDB %02x %02x %02x failed: sense %x/%02x/%02x\n",
                       Srb->Cdb[0], Srb->Cdb[1], Srb->Cdb[2], SenseKey, Asc, Ascq);
#endif
    NvmeScsiSetSense(Srb, SenseKey, Asc, Ascq);
    NvmeCompleteSrb(Ext, Srb, 0xFF);
}

/* Copies emulated response data into the SRB buffer and completes the SRB */
static
VOID
NvmeReturnData(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_reads_bytes_(Length) const VOID *Data,
    _In_ ULONG Length,
    _In_ ULONG AllocationLength)
{
    ULONG Copy = min(Length, AllocationLength);

    Copy = min(Copy, Srb->DataTransferLength);
    if (Copy && Srb->DataBuffer)
        RtlCopyMemory(Srb->DataBuffer, Data, Copy);

    Srb->DataTransferLength = Copy;
    Srb->ScsiStatus = SCSISTAT_GOOD;
    NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
}

/* Formats bytes as groups of four hex digits joined by '_' and ended with '.' (as Windows) */
static
ULONG
NvmeFormatEui(
    _Out_writes_(Length * 2 + Length / 2 + 1) PCHAR Out,
    _In_reads_(Length) const UCHAR *Bytes,
    _In_ ULONG Length)
{
    static const CHAR Hex[] = "0123456789ABCDEF";
    ULONG i, n = 0;

    for (i = 0; i < Length; i++)
    {
        if (i && (i % 2) == 0)
            Out[n++] = '_';
        Out[n++] = Hex[Bytes[i] >> 4];
        Out[n++] = Hex[Bytes[i] & 0xF];
    }
    Out[n++] = '.';
    return n;
}

static
BOOLEAN
NvmeDsmSupported(
    _In_ PNVME_EXTENSION Ext)
{
    return (Ext->Oncs & NVME_ONCS_DSM) != 0;
}

/* INQUIRY ********************************************************************/

static
VOID
NvmeInquiry(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    PCDB Cdb = (PCDB)Srb->Cdb;
    UCHAR Buffer[256];
    ULONG AllocationLength = GetBe16(&Srb->Cdb[3]);
    ULONG Length = 0;
    UCHAR PageCode = Srb->Cdb[2];

    RtlZeroMemory(Buffer, sizeof(Buffer));

    if (!(Srb->Cdb[1] & 1))
    {
        /* Standard data */
        if (PageCode != 0)
        {
            NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
            return;
        }

        Buffer[0] = DIRECT_ACCESS_DEVICE;
        Buffer[1] = 0;                  /* not removable */
        Buffer[2] = 0x06;               /* SPC-4 */
        Buffer[3] = 0x02;               /* response data format 2 */
        Buffer[4] = 36 - 5;
        Buffer[5] = 0;
        Buffer[6] = 0;
        Buffer[7] = 0x02;               /* CmdQue */
        RtlCopyMemory(&Buffer[8], "NVMe    ", 8);
        RtlCopyMemory(&Buffer[16], Ext->Mn, 16);
        RtlCopyMemory(&Buffer[32], Ext->Fr, 4);
        Length = 36;
        NvmeReturnData(Ext, Srb, Buffer, Length, AllocationLength);
        return;
    }

    UNREFERENCED_PARAMETER(Cdb);

    Buffer[0] = DIRECT_ACCESS_DEVICE;
    Buffer[1] = PageCode;

    switch (PageCode)
    {
        case NVME_VPD_SUPPORTED_PAGES:
        {
            UCHAR Pages[] = { NVME_VPD_SUPPORTED_PAGES, NVME_VPD_SERIAL_NUMBER,
                              NVME_VPD_DEVICE_IDENTIFIERS, NVME_VPD_BLOCK_LIMITS,
                              NVME_VPD_BLOCK_DEVICE_CHARACTERISTICS,
                              NVME_VPD_LOGICAL_BLOCK_PROVISIONING };

            PutBe16(&Buffer[2], sizeof(Pages));
            RtlCopyMemory(&Buffer[4], Pages, sizeof(Pages));
            Length = 4 + sizeof(Pages);
            break;
        }

        case NVME_VPD_SERIAL_NUMBER:
        {
            ULONG n;

            /* NGUID, then EUI-64, then the controller serial (translation reference 6.1.3) */
            if (!IsAllZero(Ns->Nguid, sizeof(Ns->Nguid)))
                n = NvmeFormatEui((PCHAR)&Buffer[4], Ns->Nguid, sizeof(Ns->Nguid));
            else if (!IsAllZero(Ns->Eui64, sizeof(Ns->Eui64)))
                n = NvmeFormatEui((PCHAR)&Buffer[4], Ns->Eui64, sizeof(Ns->Eui64));
            else
            {
                n = sizeof(Ext->Sn);
                RtlCopyMemory(&Buffer[4], Ext->Sn, n);
            }

            PutBe16(&Buffer[2], n);
            Length = 4 + n;
            break;
        }

        case NVME_VPD_DEVICE_IDENTIFIERS:
        {
            PUCHAR d = &Buffer[4];
            ULONG i;
            static const CHAR Hex[] = "0123456789ABCDEF";

            if (!IsAllZero(Ns->Nguid, sizeof(Ns->Nguid)))
            {
                d[0] = 0x01;            /* binary */
                d[1] = 0x02;            /* LU association, EUI-64 based */
                d[3] = sizeof(Ns->Nguid);
                RtlCopyMemory(&d[4], Ns->Nguid, sizeof(Ns->Nguid));
                d += 4 + sizeof(Ns->Nguid);
            }

            if (!IsAllZero(Ns->Eui64, sizeof(Ns->Eui64)))
            {
                d[0] = 0x01;
                d[1] = 0x02;
                d[3] = sizeof(Ns->Eui64);
                RtlCopyMemory(&d[4], Ns->Eui64, sizeof(Ns->Eui64));
                d += 4 + sizeof(Ns->Eui64);
            }

            /* T10 vendor ID based: "NVMe" + model + serial + namespace ID; always unique */
            d[0] = 0x02;                /* ASCII */
            d[1] = 0x01;                /* LU association, T10 vendor ID */
            d[3] = 8 + 40 + 20 + 8;
            RtlCopyMemory(&d[4], "NVMe    ", 8);
            RtlCopyMemory(&d[12], Ext->Mn, 40);
            RtlCopyMemory(&d[52], Ext->Sn, 20);
            for (i = 0; i < 8; i++)
                d[72 + i] = Hex[(Ns->Nsid >> (28 - 4 * i)) & 0xF];
            d += 4 + d[3];

            Length = (ULONG)(d - Buffer);
            PutBe16(&Buffer[2], Length - 4);
            break;
        }

        case NVME_VPD_BLOCK_LIMITS:
        {
            ULONG MaxBlocks = Ext->MaxTransferBytes >> Ns->BlockShift;

            PutBe16(&Buffer[2], 0x3C);
            PutBe16(&Buffer[6], 1);                     /* optimal granularity */
            PutBe32(&Buffer[8], MaxBlocks);             /* maximum transfer length */
            PutBe32(&Buffer[12], MaxBlocks);            /* optimal transfer length */
            if (NvmeDsmSupported(Ext))
            {
                PutBe32(&Buffer[20], 0xFFFFFFFF);       /* maximum unmap LBA count */
                PutBe32(&Buffer[24], NVME_DSM_RANGES_PER_SLOT); /* maximum descriptors */
                PutBe32(&Buffer[28], 1);                /* optimal unmap granularity */
            }
            Length = 4 + 0x3C;
            break;
        }

        case NVME_VPD_BLOCK_DEVICE_CHARACTERISTICS:
            PutBe16(&Buffer[2], 0x3C);
            PutBe16(&Buffer[4], 0x0001);                /* non-rotating medium */
            Length = 4 + 0x3C;
            break;

        case NVME_VPD_LOGICAL_BLOCK_PROVISIONING:
            PutBe16(&Buffer[2], 4);
            if (NvmeDsmSupported(Ext))
            {
                Buffer[5] = 0x80;                       /* LBPU: UNMAP supported */
                if ((Ns->Dlfeat & 0x7) == 1)
                    Buffer[5] |= 0x04;                  /* LBPRZ: unmapped blocks read zero */
                Buffer[6] = (Ns->Nsfeat & NVME_NSFEAT_THIN) ? 0x02 : 0x01; /* thin/resource */
            }
            Length = 8;
            break;

        default:
            NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
            return;
    }

    NvmeReturnData(Ext, Srb, Buffer, Length, AllocationLength);
}

/* CAPACITY *******************************************************************/

static
VOID
NvmeReadCapacity10(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    UCHAR Buffer[8];
    ULONGLONG LastLba = Ns->BlockCount - 1;

    PutBe32(&Buffer[0], (LastLba > 0xFFFFFFFFULL) ? 0xFFFFFFFF : (ULONG)LastLba);
    PutBe32(&Buffer[4], 1UL << Ns->BlockShift);
    NvmeReturnData(Ext, Srb, Buffer, sizeof(Buffer), sizeof(Buffer));
}

static
VOID
NvmeReadCapacity16(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    UCHAR Buffer[32] = {0};

    PutBe64(&Buffer[0], Ns->BlockCount - 1);
    PutBe32(&Buffer[8], 1UL << Ns->BlockShift);
    if (NvmeDsmSupported(Ext))
    {
        Buffer[14] = 0x80;                              /* LBPME */
        if ((Ns->Dlfeat & 0x7) == 1)
            Buffer[14] |= 0x40;                         /* LBPRZ */
    }

    NvmeReturnData(Ext, Srb, Buffer, sizeof(Buffer), GetBe32(&Srb->Cdb[10]));
}

/* MODE SENSE / MODE SELECT ***************************************************/

static
ULONG
NvmeBuildCachingPage(
    _In_ PNVME_EXTENSION Ext,
    _Out_writes_(20) PUCHAR Page,
    _In_ UCHAR PageControl)
{
    RtlZeroMemory(Page, 20);
    Page[0] = NVME_MODE_PAGE_CACHING;
    Page[1] = 0x12;

    switch (PageControl)
    {
        case 0: /* current */
            if (Ext->WriteCacheEnabled)
                Page[2] |= 0x04;                        /* WCE */
            break;

        case 1: /* changeable */
            if (Ext->Vwc & NVME_VWC_PRESENT)
                Page[2] |= 0x04;
            break;

        case 2: /* default */
            if (Ext->Vwc & NVME_VWC_PRESENT)
                Page[2] |= 0x04;
            break;
    }

    return 20;
}

static
ULONG
NvmeBuildControlPage(
    _Out_writes_(12) PUCHAR Page,
    _In_ UCHAR PageControl)
{
    RtlZeroMemory(Page, 12);
    Page[0] = NVME_MODE_PAGE_CONTROL;
    Page[1] = 0x0A;
    if (PageControl != 1)
    {
        Page[3] = 0x10;                                 /* unrestricted reordering */
        PutBe16(&Page[8], 0xFFFF);                      /* busy timeout: unlimited */
    }
    return 12;
}

/* Informational exceptions control: nothing enabled, nothing changeable */
static
ULONG
NvmeBuildInfoExceptionsPage(
    _Out_writes_(12) PUCHAR Page)
{
    RtlZeroMemory(Page, 12);
    Page[0] = NVME_MODE_PAGE_INFO_EXCEPTIONS;
    Page[1] = 0x0A;
    return 12;
}

static
VOID
NvmeModeSense(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    BOOLEAN Ten = (Srb->Cdb[0] == SCSIOP_MODE_SENSE10);
    BOOLEAN Dbd = (Srb->Cdb[1] & 0x08) != 0;
    UCHAR PageControl = Srb->Cdb[2] >> 6;
    UCHAR PageCode = Srb->Cdb[2] & 0x3F;
    UCHAR SubPage = Srb->Cdb[3];
    ULONG AllocationLength = Ten ? GetBe16(&Srb->Cdb[7]) : Srb->Cdb[4];
    UCHAR Buffer[128];
    ULONG HeaderLength = Ten ? 8 : 4;
    ULONG Length;

    RtlZeroMemory(Buffer, sizeof(Buffer));

    if (PageControl == 3)
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_SAVING_NOT_SUPPORTED, 0);
        return;
    }

    if (SubPage != 0 && !(PageCode == NVME_MODE_PAGE_ALL && SubPage == 0xFF))
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
        return;
    }

    Length = HeaderLength;

    /* Short LBA block descriptor */
    if (!Dbd)
    {
        PUCHAR Bd = &Buffer[Length];

        PutBe32(&Bd[0], (Ns->BlockCount > 0xFFFFFFFFULL) ? 0xFFFFFFFF : (ULONG)Ns->BlockCount);
        Bd[5] = (UCHAR)((1UL << Ns->BlockShift) >> 16);
        Bd[6] = (UCHAR)((1UL << Ns->BlockShift) >> 8);
        Bd[7] = (UCHAR)(1UL << Ns->BlockShift);
        Length += 8;
    }

    switch (PageCode)
    {
        case NVME_MODE_PAGE_CACHING:
            Length += NvmeBuildCachingPage(Ext, &Buffer[Length], PageControl);
            break;

        case NVME_MODE_PAGE_CONTROL:
            Length += NvmeBuildControlPage(&Buffer[Length], PageControl);
            break;

        case NVME_MODE_PAGE_INFO_EXCEPTIONS:
            Length += NvmeBuildInfoExceptionsPage(&Buffer[Length]);
            break;

        case NVME_MODE_PAGE_ALL:
            Length += NvmeBuildCachingPage(Ext, &Buffer[Length], PageControl);
            Length += NvmeBuildControlPage(&Buffer[Length], PageControl);
            Length += NvmeBuildInfoExceptionsPage(&Buffer[Length]);
            break;

        default:
            NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
            return;
    }

    /* Header: no write protect; DPO and FUA are supported */
    if (Ten)
    {
        PutBe16(&Buffer[0], Length - 2);
        Buffer[3] = NVME_MODE_DPOFUA;
        PutBe16(&Buffer[6], Dbd ? 0 : 8);
    }
    else
    {
        Buffer[0] = (UCHAR)(Length - 1);
        Buffer[2] = NVME_MODE_DPOFUA;
        Buffer[3] = Dbd ? 0 : 8;
    }

    NvmeReturnData(Ext, Srb, Buffer, Length, AllocationLength);
}

static
VOID
NvmeModeSelect(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    BOOLEAN Ten = (Srb->Cdb[0] == SCSIOP_MODE_SELECT10);
    ULONG ListLength = Ten ? GetBe16(&Srb->Cdb[7]) : Srb->Cdb[4];
    PUCHAR Data = (PUCHAR)Srb->DataBuffer;
    ULONG HeaderLength = Ten ? 8 : 4;
    ULONG Offset;
    LONG NewWce = -1;

    UNREFERENCED_PARAMETER(Ns);

    ListLength = min(ListLength, Srb->DataTransferLength);
    if (ListLength == 0)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    if (Data == NULL || ListLength < HeaderLength)
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_PARAMETER_LIST_LENGTH, 0);
        return;
    }

    Offset = HeaderLength + (Ten ? GetBe16(&Data[6]) : Data[3]);

    while (Offset + 2 <= ListLength)
    {
        UCHAR Page = Data[Offset] & 0x3F;
        BOOLEAN SubPageFormat = (Data[Offset] & 0x40) != 0;   /* SPF */
        ULONG PageLength;

        /* page_0 format: 2-byte header; sub_page format: 4-byte header, 2-byte length */
        if (SubPageFormat)
        {
            if (Offset + 4 > ListLength)
                break;
            PageLength = GetBe16(&Data[Offset + 2]) + 4;
        }
        else
        {
            PageLength = Data[Offset + 1] + 2;
        }

        if (Offset + PageLength > ListLength)
            break;

        /* The caching page has only the page_0 format */
        if (Page == NVME_MODE_PAGE_CACHING && !SubPageFormat && PageLength >= 3)
            NewWce = (Data[Offset + 2] & 0x04) ? 1 : 0;

        Offset += PageLength;
    }

    /* SP: save the setting, which needs Save in Set Features (ONCS bit 4) */
    if ((Srb->Cdb[1] & 0x01) && !(Ext->Oncs & 0x10))
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_SAVING_NOT_SUPPORTED, 0);
        return;
    }

    if (NewWce < 0 || (BOOLEAN)NewWce == Ext->WriteCacheEnabled)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    if (!(Ext->Vwc & NVME_VWC_PRESENT))
    {
        /* There is no cache to turn on */
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_FIELD_PARAMETER, 0);
        return;
    }

    {
        NVME_COMMAND Cmd = {0};

        Cmd.Opcode = NVME_ADMIN_SET_FEATURES;
        Cmd.Cdw10 = NVME_FEAT_VOLATILE_WC | ((Srb->Cdb[1] & 0x01) ? 0x80000000UL /* SV */ : 0);
        Cmd.Cdw11 = (ULONG)NewWce;
        if (!NvmeSubmitSrbCommand(Ext, &Ext->AdminQueue, &Cmd, Srb, SlotKindSetWce, (ULONG)NewWce, FALSE))
            NvmeCompleteSrb(Ext, Srb, 0xFF);
    }
}

/* READ / WRITE ***************************************************************/

static
VOID
NvmeReadWrite(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    PUCHAR Cdb = Srb->Cdb;
    ULONGLONG Lba;
    ULONG Blocks;
    BOOLEAN Write;
    BOOLEAN Fua = FALSE;
    NVME_COMMAND Cmd = {0};

    switch (Cdb[0])
    {
        case SCSIOP_READ6:
        case SCSIOP_WRITE6:
            Lba = ((ULONG)(Cdb[1] & 0x1F) << 16) | ((ULONG)Cdb[2] << 8) | Cdb[3];
            Blocks = Cdb[4] ? Cdb[4] : 256;
            break;

        case SCSIOP_READ:
        case SCSIOP_WRITE:
            Lba = GetBe32(&Cdb[2]);
            Blocks = GetBe16(&Cdb[7]);
            Fua = (Cdb[1] & 0x08) != 0;
            break;

        case SCSIOP_READ12:
        case SCSIOP_WRITE12:
            Lba = GetBe32(&Cdb[2]);
            Blocks = GetBe32(&Cdb[6]);
            Fua = (Cdb[1] & 0x08) != 0;
            break;

        default: /* READ16 / WRITE16 */
            Lba = GetBe64(&Cdb[2]);
            Blocks = GetBe32(&Cdb[10]);
            Fua = (Cdb[1] & 0x08) != 0;
            break;
    }

    Write = (Cdb[0] == SCSIOP_WRITE6 || Cdb[0] == SCSIOP_WRITE ||
             Cdb[0] == SCSIOP_WRITE12 || Cdb[0] == SCSIOP_WRITE16);

    if (Lba > Ns->BlockCount || Blocks > Ns->BlockCount - Lba)
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_ILLEGAL_BLOCK, 0);
        return;
    }

    if (Blocks == 0)
    {
        Srb->DataTransferLength = 0;
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    /* A buffer too short for the blocks the CDB names is an error, not a shorter transfer:
       moving less than asked for and reporting success would lose data silently */
    if (((ULONGLONG)Blocks << Ns->BlockShift) > Srb->DataTransferLength)
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
        return;
    }
    Srb->DataTransferLength = Blocks << Ns->BlockShift;

    if (Srb->DataTransferLength > Ext->MaxTransferBytes)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
        return;
    }

    Cmd.Opcode = Write ? NVME_CMD_WRITE : NVME_CMD_READ;
    Cmd.Nsid = Ns->Nsid;
    Cmd.Cdw10 = (ULONG)Lba;
    Cmd.Cdw11 = (ULONG)(Lba >> 32);
    /* After a shutdown notification nothing would write the cache back again: a write
       that re-enabled the controller goes through to the medium */
    if (Write && Ext->ShutdownSeen && Ext->WriteCacheEnabled)
        Fua = TRUE;

    Cmd.Cdw12 = (Blocks - 1) | (Fua ? NVME_RW_FUA : 0);

    if (!NvmeSubmitSrbCommand(Ext, &Ext->IoQueue, &Cmd, Srb, SlotKindSrb, 0, TRUE))
        NvmeCompleteSrb(Ext, Srb, 0xFF);
}

/* FLUSH / UNMAP **************************************************************/

static
VOID
NvmeFlushNamespace(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    NVME_COMMAND Cmd = {0};

    /* Without a volatile write cache everything written is already durable */
    if (!(Ext->Vwc & NVME_VWC_PRESENT))
    {
        Srb->DataTransferLength = 0;
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    Cmd.Opcode = NVME_CMD_FLUSH;
    Cmd.Nsid = Ns->Nsid;
    Srb->DataTransferLength = 0;
    Ext->Flushes++;

    if (!NvmeSubmitSrbCommand(Ext, &Ext->IoQueue, &Cmd, Srb, SlotKindSrb, 0, FALSE))
        NvmeCompleteSrb(Ext, Srb, 0xFF);
}

VOID
NvmeScsiFlush(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    if (Srb->PathId != 0 || Srb->TargetId != 0 || Srb->Lun >= Ext->NamespaceCount)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    NvmeFlushNamespace(Ext, Srb, &Ext->Namespaces[Srb->Lun]);
}

static
VOID
NvmeUnmap(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ PNVME_NAMESPACE Ns)
{
    PUCHAR Data = (PUCHAR)Srb->DataBuffer;
    ULONG ListLength = GetBe16(&Srb->Cdb[7]);
    ULONG DescriptorBytes, Count, i, Ranges = 0;
    NVME_DSM_RANGE Range[NVME_DSM_RANGES_PER_SLOT];
    NVME_COMMAND Cmd = {0};
    LONG Slot;

    if (!NvmeDsmSupported(Ext))
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_ILLEGAL_COMMAND, 0);
        return;
    }

    ListLength = min(ListLength, Srb->DataTransferLength);
    if (ListLength == 0)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    if (Data == NULL || ListLength < 8)
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_PARAMETER_LIST_LENGTH, 0);
        return;
    }

    DescriptorBytes = min(GetBe16(&Data[2]), ListLength - 8);
    Count = DescriptorBytes / 16;
    if (Count > NVME_DSM_RANGES_PER_SLOT)
    {
        NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_FIELD_PARAMETER, 0);
        return;
    }

    for (i = 0; i < Count; i++)
    {
        PUCHAR d = &Data[8 + i * 16];
        ULONGLONG Lba = GetBe64(&d[0]);
        ULONG Blocks = GetBe32(&d[8]);

        if (Blocks == 0)
            continue;

        if (Lba > Ns->BlockCount || Blocks > Ns->BlockCount - Lba)
        {
            NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_ILLEGAL_BLOCK, 0);
            return;
        }

        Range[Ranges].Attributes = 0;
        Range[Ranges].LengthInLba = Blocks;
        Range[Ranges].StartingLba = Lba;
        Ranges++;
    }

    Srb->DataTransferLength = 0;
    if (Ranges == 0)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    /* The ranges go in the slot's DMA area, so take the slot first */
    Cmd.Opcode = NVME_CMD_DSM;
    Cmd.Nsid = Ns->Nsid;
    Cmd.Cdw10 = Ranges - 1;
    Cmd.Cdw11 = NVME_DSM_ATTR_DEALLOCATE;

    Slot = -1;
    for (i = 0; i < Ext->IoQueue.SlotCount; i++)
    {
        ULONG Index = (Ext->IoQueue.NextSlot + i) % Ext->IoQueue.SlotCount;
        if (!Ext->IoQueue.Slots[Index].Busy)
        {
            Slot = (LONG)Index;
            break;
        }
    }

    if (Slot < 0)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_BUSY);
        return;
    }

    /* NvmeSubmitSrbCommand picks the same free slot: NextSlot is where the search starts */
    Ext->IoQueue.NextSlot = (USHORT)Slot;
    RtlCopyMemory(Ext->IoQueue.SlotDma + Slot * NVME_SLOT_DMA_BYTES, Range, Ranges * sizeof(NVME_DSM_RANGE));
    Cmd.Prp1 = Ext->IoQueue.SlotDmaPa.QuadPart + (ULONGLONG)Slot * NVME_SLOT_DMA_BYTES;

    if (!NvmeSubmitSrbCommand(Ext, &Ext->IoQueue, &Cmd, Srb, SlotKindSrb, 0, FALSE))
        NvmeCompleteSrb(Ext, Srb, 0xFF);
}

/* OTHER COMMANDS *************************************************************/

static
VOID
NvmeReportLuns(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UCHAR Buffer[8 + 8 * NVME_MAX_NAMESPACES] = {0};
    ULONG i;

    PutBe32(&Buffer[0], Ext->NamespaceCount * 8);
    for (i = 0; i < Ext->NamespaceCount; i++)
        Buffer[8 + i * 8 + 1] = (UCHAR)i;

    NvmeReturnData(Ext, Srb, Buffer, 8 + 8 * Ext->NamespaceCount, GetBe32(&Srb->Cdb[6]));
}

static
VOID
NvmeRequestSense(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UCHAR Sense[18] = {0};

    Sense[0] = 0x70;
    Sense[7] = sizeof(Sense) - 8;
    NvmeReturnData(Ext, Srb, Sense, sizeof(Sense), Srb->Cdb[4]);
}

VOID
NvmeScsiExecute(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PNVME_NAMESPACE Ns;
    UCHAR Opcode = Srb->Cdb[0];

    Srb->ScsiStatus = SCSISTAT_GOOD;

    if (Srb->PathId != 0 || Srb->TargetId != 0)
    {
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_NO_DEVICE);
        return;
    }

    /* REPORT LUNS and INQUIRY on LUN 0 work even without a namespace */
    if (Opcode == SCSIOP_REPORT_LUNS)
    {
        NvmeReportLuns(Ext, Srb);
        return;
    }

    if (Srb->Lun >= Ext->NamespaceCount)
    {
        NvmeCompleteSrb(Ext, Srb, (Srb->Lun == 0) ? SRB_STATUS_NO_DEVICE : SRB_STATUS_INVALID_LUN);
        return;
    }

    Ns = &Ext->Namespaces[Srb->Lun];

    switch (Opcode)
    {
        case SCSIOP_READ6:
        case SCSIOP_WRITE6:
        case SCSIOP_READ:
        case SCSIOP_WRITE:
        case SCSIOP_READ12:
        case SCSIOP_WRITE12:
        case SCSIOP_READ16:
        case SCSIOP_WRITE16:
            NvmeReadWrite(Ext, Srb, Ns);
            break;

        case SCSIOP_SYNCHRONIZE_CACHE:
        case SCSIOP_SYNCHRONIZE_CACHE16:
            NvmeFlushNamespace(Ext, Srb, Ns);
            break;

        case SCSIOP_INQUIRY:
            NvmeInquiry(Ext, Srb, Ns);
            break;

        case SCSIOP_READ_CAPACITY:
            NvmeReadCapacity10(Ext, Srb, Ns);
            break;

        case SCSIOP_SERVICE_ACTION_IN16:
            if ((Srb->Cdb[1] & 0x1F) == NVME_SA_READ_CAPACITY16)
                NvmeReadCapacity16(Ext, Srb, Ns);
            else
                NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
            break;

        case SCSIOP_MODE_SENSE:
        case SCSIOP_MODE_SENSE10:
            NvmeModeSense(Ext, Srb, Ns);
            break;

        case SCSIOP_MODE_SELECT:
        case SCSIOP_MODE_SELECT10:
            NvmeModeSelect(Ext, Srb, Ns);
            break;

        case NVME_SCSIOP_UNMAP:
            NvmeUnmap(Ext, Srb, Ns);
            break;

        case SCSIOP_TEST_UNIT_READY:
        case SCSIOP_START_STOP_UNIT:
        case SCSIOP_MEDIUM_REMOVAL:
        case SCSIOP_VERIFY:
        case SCSIOP_VERIFY12:
        case SCSIOP_VERIFY16:
            Srb->DataTransferLength = 0;
            NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        case SCSIOP_REQUEST_SENSE:
            NvmeRequestSense(Ext, Srb);
            break;

        default:
            NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_ILLEGAL_COMMAND, 0);
            break;
    }
}

/* COMPLETION STATUS **********************************************************/

VOID
NvmeScsiCompleteFromStatus(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ USHORT Status,
    _In_ BOOLEAN TimedOut)
{
    UCHAR Sct = (UCHAR)NVME_CQE_SCT(Status);
    UCHAR Sc = (UCHAR)NVME_CQE_SC(Status);

    if (Sct == NVME_SCT_GENERIC && Sc == NVME_SC_SUCCESS)
    {
        Srb->ScsiStatus = SCSISTAT_GOOD;
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        return;
    }

    StorPortDebugPrint(0, "stornvme: command 0x%02x failed, SCT %u SC 0x%02x%s\n",
                       Srb->Cdb[0], Sct, Sc, TimedOut ? " (timed out)" : "");

    if (TimedOut && Sct == NVME_SCT_GENERIC &&
        (Sc == NVME_SC_ABORT_REQUESTED || Sc == NVME_SC_ABORT_SQ_DELETED))
    {
        Srb->DataTransferLength = 0;
        NvmeCompleteSrb(Ext, Srb, SRB_STATUS_TIMEOUT);
        return;
    }

    switch (Sct)
    {
        case NVME_SCT_GENERIC:
            switch (Sc)
            {
                case NVME_SC_INVALID_OPCODE:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_ILLEGAL_COMMAND, 0);
                    return;
                case NVME_SC_INVALID_FIELD:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
                    return;
                case NVME_SC_DATA_TRANSFER_ERROR:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_NO_SENSE, 0);
                    return;
                case NVME_SC_INTERNAL_ERROR:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_HARDWARE_ERROR, NVME_ASC_INTERNAL_TARGET_FAILURE, 0);
                    return;
                case NVME_SC_INVALID_NAMESPACE:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_LUN, 0);
                    return;
                case NVME_SC_LBA_OUT_OF_RANGE:
                case NVME_SC_CAPACITY_EXCEEDED:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_ILLEGAL_BLOCK, 0);
                    return;
                case NVME_SC_NAMESPACE_NOT_READY:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_NOT_READY, NVME_ASC_LUN_NOT_READY, 0);
                    return;
                case NVME_SC_FORMAT_IN_PROGRESS:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_NOT_READY, NVME_ASC_LUN_NOT_READY, NVME_ASCQ_FORMAT_IN_PROGRESS);
                    return;
                case NVME_SC_RESERVATION_CONFLICT:
                    Srb->ScsiStatus = SCSISTAT_RESERVATION_CONFLICT;
                    Srb->DataTransferLength = 0;
                    NvmeCompleteSrb(Ext, Srb, SRB_STATUS_ERROR);
                    return;
                default:
                    /* Aborts, power loss, sequence errors: worth a retry */
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_ABORTED_COMMAND, NVME_ASC_NO_SENSE, 0);
                    return;
            }

        case NVME_SCT_COMMAND_SPECIFIC:
            if (Sc == NVME_SC_NS_WRITE_PROTECTED || Sc == NVME_SC_ATTEMPTED_WRITE_RO)
                NvmeFailSrb(Ext, Srb, NVME_SENSE_DATA_PROTECT, NVME_ASC_WRITE_PROTECT, 0);
            else
                NvmeFailSrb(Ext, Srb, NVME_SENSE_ILLEGAL_REQUEST, NVME_ASC_INVALID_CDB, 0);
            return;

        case NVME_SCT_MEDIA:
            switch (Sc)
            {
                case NVME_SC_WRITE_FAULT:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_WRITE_FAULT, 0);
                    return;
                case NVME_SC_UNRECOVERED_READ:
                case NVME_SC_DEALLOCATED_LBA:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_UNRECOVERED_READ, 0);
                    return;
                case NVME_SC_GUARD_CHECK:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_DATA_INTEGRITY, 1);
                    return;
                case NVME_SC_APPTAG_CHECK:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_DATA_INTEGRITY, 2);
                    return;
                case NVME_SC_REFTAG_CHECK:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_DATA_INTEGRITY, 3);
                    return;
                case NVME_SC_COMPARE_FAILURE:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MISCOMPARE, NVME_ASC_MISCOMPARE, 0);
                    return;
                case NVME_SC_ACCESS_DENIED:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_DATA_PROTECT, NVME_ASC_ACCESS_DENIED, 2);
                    return;
                default:
                    NvmeFailSrb(Ext, Srb, NVME_SENSE_MEDIUM_ERROR, NVME_ASC_NO_SENSE, 0);
                    return;
            }

        default:
            NvmeFailSrb(Ext, Srb, NVME_SENSE_ABORTED_COMMAND, NVME_ASC_NO_SENSE, 0);
            return;
    }
}
