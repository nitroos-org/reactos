/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for SCSI and ATA pass-through requests of 32-bit processes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The same source runs as a native 64-bit executable and, built for i386, as a WoW64 process (where the
 * 32-bit headers are 12 (SCSI) or 8 (ATA) bytes smaller and every offset behind them moves). It sends
 * INQUIRY (buffered and direct) and ATA IDENTIFY (buffered and direct) to the system disk and to the first
 * CD-ROM drive, then malformed requests. Every result is traced on a line starting with "SPTI"; all sizes in
 * those lines are relative to the header size, so the lines of the two runs must be identical.
 * Needs administrator rights; without them (or without the device) the part is skipped.
 */

#include "precomp.h"

#include <winioctl.h>
#include <ntddscsi.h>

/* The layouts of the compiler's own architecture: Windows' 32-bit and 64-bit definitions */
#ifdef _WIN64
C_ASSERT(sizeof(SCSI_PASS_THROUGH) == 56);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, DataBufferOffset) == 24);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, SenseInfoOffset) == 32);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, Cdb) == 36);
C_ASSERT(sizeof(SCSI_PASS_THROUGH_DIRECT) == 56);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH_DIRECT, DataBuffer) == 24);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH_DIRECT, SenseInfoOffset) == 32);
C_ASSERT(sizeof(ATA_PASS_THROUGH_EX) == 48);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, DataBufferOffset) == 24);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, PreviousTaskFile) == 32);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, CurrentTaskFile) == 40);
C_ASSERT(sizeof(ATA_PASS_THROUGH_DIRECT) == 48);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_DIRECT, DataBuffer) == 24);
#else
C_ASSERT(sizeof(SCSI_PASS_THROUGH) == 44);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, DataTransferLength) == 12);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, TimeOutValue) == 16);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, DataBufferOffset) == 20);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, SenseInfoOffset) == 24);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH, Cdb) == 28);
C_ASSERT(sizeof(SCSI_PASS_THROUGH_DIRECT) == 44);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH_DIRECT, DataBuffer) == 20);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH_DIRECT, SenseInfoOffset) == 24);
C_ASSERT(FIELD_OFFSET(SCSI_PASS_THROUGH_DIRECT, Cdb) == 28);
C_ASSERT(sizeof(ATA_PASS_THROUGH_EX) == 40);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, DataTransferLength) == 8);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, DataBufferOffset) == 20);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, PreviousTaskFile) == 24);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_EX, CurrentTaskFile) == 32);
C_ASSERT(sizeof(ATA_PASS_THROUGH_DIRECT) == 40);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_DIRECT, DataBuffer) == 20);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_DIRECT, PreviousTaskFile) == 24);
C_ASSERT(FIELD_OFFSET(ATA_PASS_THROUGH_DIRECT, CurrentTaskFile) == 32);
#endif

typedef struct
{
    SCSI_PASS_THROUGH Spt;
    ULONG Filler;
    UCHAR Sense[32];
    UCHAR Data[512];
} SPT_BUF;

typedef struct
{
    SCSI_PASS_THROUGH_DIRECT Sptd;
    ULONG Filler;
    UCHAR Sense[32];
} SPTD_BUF;

typedef struct
{
    ATA_PASS_THROUGH_EX Apt;
    ULONG Filler;
    UCHAR Data[512];
} APT_BUF;

typedef struct
{
    ATA_PASS_THROUGH_DIRECT Aptd;
    ULONG Filler;
} APTD_BUF;

#define SPT_SENSE ((ULONG)FIELD_OFFSET(SPT_BUF, Sense))
#define SPT_DATA ((ULONG)FIELD_OFFSET(SPT_BUF, Data))
#define SPTD_SENSE ((ULONG)FIELD_OFFSET(SPTD_BUF, Sense))
#define APT_DATA ((ULONG)FIELD_OFFSET(APT_BUF, Data))

#define PATTERN 0xCC

static ULONG g_Error;
static ULONG g_Returned;

/* One request. The result goes to the trace in sizes relative to the header (the headers differ by
 * architecture); a failed request shows its error and what the system buffer returned. */
static BOOL Send(const char *Name, HANDLE Device, ULONG Code, PVOID In, ULONG InLength, PVOID Out, ULONG OutLength,
                 ULONG Header)
{
    BOOL Ret;
    ULONG Returned = 0xDEADBEEF;

    SetLastError(0xDEADBEEF);
    Ret = DeviceIoControl(Device, Code, In, InLength, Out, OutLength, &Returned, NULL);
    g_Error = Ret ? 0 : GetLastError();
    g_Returned = Returned;
    trace("SPTI %-40s ok=%d err=%lu returned=%s%ld\n", Name, Ret, g_Error,
          (Returned == 0xDEADBEEF) ? "unset:" : "", (Returned == 0xDEADBEEF || !Returned) ? 0L : (long)Returned - (long)Header);
    return Ret;
}

/* A request that must fail with the error Windows gives (measured on Windows 10 22H2, 32-bit and 64-bit alike) */
static BOOL SendE(LONG Expect, const char *Name, HANDLE Device, ULONG Code, PVOID In, ULONG InLength, PVOID Out,
                  ULONG OutLength, ULONG Header)
{
    BOOL Ret = Send(Name, Device, Code, In, InLength, Out, OutLength, Header);
    ok(!Ret && g_Error == (ULONG)Expect, "%s: ok %d, error %lu, expected failure with %ld\n", Name, Ret, g_Error, Expect);
    return Ret;
}

static PVOID AllocPage(void)
{
    PVOID Page = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Page != NULL, "VirtualAlloc failed, error %lu\n", GetLastError());
    return Page;
}

static void InitSpt(SPT_BUF *Buf, const UCHAR *Cdb, UCHAR CdbLength, ULONG Transfer, UCHAR Direction)
{
    RtlFillMemory(Buf, sizeof(*Buf), PATTERN);
    RtlZeroMemory(&Buf->Spt, sizeof(Buf->Spt));
    RtlZeroMemory(Buf->Sense, sizeof(Buf->Sense));
    Buf->Spt.Length = sizeof(SCSI_PASS_THROUGH);
    Buf->Spt.CdbLength = CdbLength;
    Buf->Spt.SenseInfoLength = sizeof(Buf->Sense);
    Buf->Spt.DataIn = Direction;
    Buf->Spt.DataTransferLength = Transfer;
    Buf->Spt.TimeOutValue = 5;
    Buf->Spt.DataBufferOffset = SPT_DATA;
    Buf->Spt.SenseInfoOffset = SPT_SENSE;
    RtlCopyMemory(Buf->Spt.Cdb, Cdb, CdbLength);
}

static void InitSptd(SPTD_BUF *Buf, PVOID Data, const UCHAR *Cdb, UCHAR CdbLength, ULONG Transfer, UCHAR Direction)
{
    RtlZeroMemory(Buf, sizeof(*Buf));
    RtlFillMemory(Buf->Sense, sizeof(Buf->Sense), 0);
    Buf->Sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    Buf->Sptd.CdbLength = CdbLength;
    Buf->Sptd.SenseInfoLength = sizeof(Buf->Sense);
    Buf->Sptd.DataIn = Direction;
    Buf->Sptd.DataTransferLength = Transfer;
    Buf->Sptd.TimeOutValue = 5;
    Buf->Sptd.DataBuffer = Data;
    Buf->Sptd.SenseInfoOffset = SPTD_SENSE;
    RtlCopyMemory(Buf->Sptd.Cdb, Cdb, CdbLength);
}

static void TraceId(const char *What, const UCHAR *Data)
{
    char Vendor[9], Product[17];
    RtlCopyMemory(Vendor, Data + 8, 8);
    Vendor[8] = 0;
    RtlCopyMemory(Product, Data + 16, 16);
    Product[16] = 0;
    trace("SPTI %s: type %02x removable %d version %02x length %u vendor '%s' product '%s'\n", What,
          Data[0] & 0x1f, Data[1] >> 7, Data[2], Data[4], Vendor, Product);
}

static void TestScsi(const char *Label, HANDLE Device, UCHAR PeripheralType)
{
    static const UCHAR Inquiry36[6] = { 0x12, 0, 0, 0, 36, 0 };
    static const UCHAR Inquiry5[6] = { 0x12, 0, 0, 0, 5, 0 };
    static const UCHAR TestUnitReady[6] = { 0 };
    static const UCHAR BadRead[10] = { 0x28, 0, 0xFF, 0xFF, 0xFF, 0xF0, 0, 0, 1, 0 };
    UCHAR First[36];
    SPT_BUF Buf;
    SPTD_BUF Direct;
    PUCHAR Data = AllocPage();
    BOOL Ret;
    SYSTEM_INFO Info;

    if (!Data) return;
    GetSystemInfo(&Info);

    /* Buffered INQUIRY: sense and data follow the header in the one buffer */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Ret = Send("buffered INQUIRY", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
               sizeof(SCSI_PASS_THROUGH));
    ok(Ret, "%s: buffered INQUIRY failed, error %lu\n", Label, g_Error);
    if (Ret)
    {
        ok_eq_ulong(g_Returned, SPT_DATA + 36);
        ok_eq_int(Buf.Spt.ScsiStatus, 0);
        ok_eq_ulong(Buf.Spt.DataTransferLength, 36);
        ok_eq_int(Buf.Spt.SenseInfoLength, 0);
        ok_eq_ulong(Buf.Spt.Length, sizeof(SCSI_PASS_THROUGH));
        ok_eq_ulong((ULONG)Buf.Spt.DataBufferOffset, SPT_DATA);
        ok_eq_ulong(Buf.Spt.SenseInfoOffset, SPT_SENSE);
        ok_eq_int(Buf.Spt.CdbLength, 6);
        ok_eq_int(Buf.Spt.Cdb[0], 0x12);
        ok_eq_int(Buf.Data[0] & 0x1f, PeripheralType);
        ok(Buf.Data[36] == PATTERN && Buf.Data[511] == PATTERN, "%s: data written behind the transfer\n", Label);
        ok(Buf.Filler == ((ULONG)PATTERN * 0x01010101UL), "%s: the filler changed\n", Label);
        TraceId(Label, Buf.Data);
        RtlCopyMemory(First, Buf.Data, sizeof(First));
    }
    else
    {
        RtlZeroMemory(First, sizeof(First));
    }

    /* Only five bytes asked for: the transfer length is the five */
    InitSpt(&Buf, Inquiry5, sizeof(Inquiry5), 5, SCSI_IOCTL_DATA_IN);
    Ret = Send("buffered INQUIRY 5 bytes", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
               sizeof(SCSI_PASS_THROUGH));
    if (Ret)
    {
        ok_eq_ulong(g_Returned, SPT_DATA + 5);
        ok_eq_ulong(Buf.Spt.DataTransferLength, 5);
        ok(Buf.Data[5] == PATTERN, "%s: data written behind the transfer\n", Label);
        ok(!memcmp(Buf.Data, First, 5), "%s: first five bytes differ\n", Label);
    }

    /* Separate input and output buffers of different size */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    {
        SPT_BUF Out;
        RtlFillMemory(&Out, sizeof(Out), 0x77);
        Ret = Send("buffered INQUIRY, separate output", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Out,
                   SPT_DATA + 40, sizeof(SCSI_PASS_THROUGH));
        if (Ret)
        {
            ok_eq_ulong(g_Returned, SPT_DATA + 36);
            ok_eq_ulong(Out.Spt.DataTransferLength, 36);
            ok(!memcmp(Out.Data, First, 36), "%s: data differ in the separate output\n", Label);
            ok(((PUCHAR)&Out)[SPT_DATA + 36] == 0x77, "%s: output written behind the result\n", Label);
        }
    }

    /* Direct INQUIRY: the data goes to a buffer of its own */
    RtlFillMemory(Data, 0x1000, PATTERN);
    InitSptd(&Direct, Data, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Ret = Send("direct INQUIRY", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
               sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    ok(Ret, "%s: direct INQUIRY failed, error %lu\n", Label, g_Error);
    if (Ret)
    {
        ok_eq_ulong(g_Returned, sizeof(SCSI_PASS_THROUGH_DIRECT));
        ok_eq_int(Direct.Sptd.ScsiStatus, 0);
        ok_eq_ulong(Direct.Sptd.DataTransferLength, 36);
        ok_eq_int(Direct.Sptd.SenseInfoLength, 0);
        ok_eq_ulong(Direct.Sptd.Length, sizeof(SCSI_PASS_THROUGH_DIRECT));
        ok(Direct.Sptd.DataBuffer == Data, "%s: DataBuffer changed to %p\n", Label, Direct.Sptd.DataBuffer);
        ok_eq_ulong(Direct.Sptd.SenseInfoOffset, SPTD_SENSE);
        ok_eq_int(Data[0] & 0x1f, PeripheralType);
        ok(!memcmp(Data, First, 36), "%s: direct and buffered INQUIRY differ\n", Label);
        ok(Data[36] == PATTERN, "%s: data written behind the transfer\n", Label);
        TraceId("direct", Data);
    }

    /* The same with the sense area asked for but not needed, and a request without data */
    InitSpt(&Buf, TestUnitReady, sizeof(TestUnitReady), 0, SCSI_IOCTL_DATA_UNSPECIFIED);
    Ret = Send("buffered TEST UNIT READY", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
               sizeof(SCSI_PASS_THROUGH));
    trace("SPTI TEST UNIT READY scsi status %02x sense length %u\n", Buf.Spt.ScsiStatus, Buf.Spt.SenseInfoLength);
    InitSptd(&Direct, NULL, TestUnitReady, sizeof(TestUnitReady), 0, SCSI_IOCTL_DATA_UNSPECIFIED);
    Ret = Send("direct TEST UNIT READY", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
               sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    trace("SPTI TEST UNIT READY scsi status %02x sense length %u\n", Direct.Sptd.ScsiStatus, Direct.Sptd.SenseInfoLength);

    /* A command the device rejects (a read far beyond the end): CHECK CONDITION and the sense bytes in the buffer, behind the header */
    InitSpt(&Buf, BadRead, sizeof(BadRead), 512, SCSI_IOCTL_DATA_IN);
    Ret = Send("buffered bad read", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
               sizeof(SCSI_PASS_THROUGH));
    trace("SPTI bad read scsi status %02x sense length %u sense %02x %02x %02x\n", Buf.Spt.ScsiStatus,
          Buf.Spt.SenseInfoLength, Buf.Sense[0], Buf.Sense[2], Buf.Sense[12]);
    if (Ret && Buf.Spt.ScsiStatus)
    {
        ok(Buf.Spt.SenseInfoLength > 0 && Buf.Spt.SenseInfoLength <= sizeof(Buf.Sense), "%s: sense length %u\n", Label,
           Buf.Spt.SenseInfoLength);
        ok((Buf.Sense[0] & 0x7f) >= 0x70 && (Buf.Sense[0] & 0x7f) <= 0x73, "%s: sense response code %02x\n", Label,
           Buf.Sense[0]);
        ok(Buf.Spt.ScsiStatus == 2, "%s: SCSI status %02x\n", Label, Buf.Spt.ScsiStatus);
    }
    InitSptd(&Direct, Data, BadRead, sizeof(BadRead), 512, SCSI_IOCTL_DATA_IN);
    Ret = Send("direct bad read", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
               sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    trace("SPTI bad read scsi status %02x sense length %u sense %02x %02x %02x\n", Direct.Sptd.ScsiStatus,
          Direct.Sptd.SenseInfoLength, Direct.Sense[0], Direct.Sense[2], Direct.Sense[12]);
    if (Ret && Direct.Sptd.ScsiStatus)
    {
        ok(Direct.Sptd.SenseInfoLength > 0 && Direct.Sptd.SenseInfoLength <= sizeof(Direct.Sense),
           "%s: direct sense length %u\n", Label, Direct.Sptd.SenseInfoLength);
        ok((Direct.Sense[0] & 0x7f) >= 0x70 && (Direct.Sense[0] & 0x7f) <= 0x73, "%s: direct sense response code %02x\n",
           Label, Direct.Sense[0]);
        ok_eq_ulong(g_Returned, SPTD_SENSE + Direct.Sptd.SenseInfoLength);
    }

    /* Malformed requests. Each trace line carries the error; the checks are the ones Windows gives (measured). */
    /* too short for a header */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "buffered, input one byte short", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(SCSI_PASS_THROUGH) - 1, &Buf,
         sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Send("buffered, output one byte short", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(SCSI_PASS_THROUGH) - 1, sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "buffered, no input", Device, IOCTL_SCSI_PASS_THROUGH, NULL, 0, &Buf, sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSptd(&Direct, Data, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "direct, input one byte short", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct,
         sizeof(SCSI_PASS_THROUGH_DIRECT) - 1, &Direct, sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    /* the output too small for the data */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "buffered, output ends inside the data", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         SPT_DATA + 10, sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Send("buffered, input ends inside the data", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, SPT_DATA + 10, &Buf,
         sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "buffered, output ends inside the sense", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         SPT_SENSE + 10, sizeof(SCSI_PASS_THROUGH));
    /* structure size */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.Length = sizeof(SCSI_PASS_THROUGH) + 1;
    SendE(1306, "buffered, Length one too large", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.Length = sizeof(SCSI_PASS_THROUGH) == 44 ? 56 : 44; /* the size of the other architecture */
    SendE(1306, "buffered, Length of the other architecture", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
          sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.Length = 0;
    SendE(1306, "buffered, Length 0", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    /* data offset */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataBufferOffset = 4;
    SendE(87, "buffered, data offset inside header", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataBufferOffset = 0;
    SendE(87, "buffered, data offset 0", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataBufferOffset = sizeof(Buf);
    SendE(87, "buffered, data offset at the end", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataBufferOffset = sizeof(Buf) - 20;
    SendE(87, "buffered, data crosses the end", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataBufferOffset = 0xFFFFFFF0;
    SendE(87, "buffered, data offset 0xFFFFFFF0", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataBufferOffset = SPT_DATA + 2;
    Send("buffered, data offset unaligned by 2", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataTransferLength = sizeof(Buf) - SPT_DATA + 1;
    SendE(87, "buffered, transfer larger than the room", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.DataTransferLength = 0xFFFFFFF0;
    SendE(87, "buffered, transfer 0xFFFFFFF0", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    /* sense offset */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.SenseInfoOffset = 4;
    SendE(87, "buffered, sense offset inside header", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.SenseInfoOffset = sizeof(Buf);
    SendE(87, "buffered, sense offset at the end", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.SenseInfoOffset = 0xFFFFFFF0;
    Send("buffered, sense offset 0xFFFFFFF0", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.SenseInfoOffset = SPT_DATA;
    SendE(87, "buffered, sense overlaps data", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    /* other header fields */
    InitSpt(&Buf, Inquiry36, 17, 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "buffered, CDB length 17", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, 3);
    Send("buffered, data direction 3", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Buf.Spt.TimeOutValue = 0;
    SendE(87, "buffered, timeout 0", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    /* direct data pointers */
    InitSptd(&Direct, NULL, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    SendE(87, "direct, no data pointer", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    {
        PVOID Freed = AllocPage();
        if (Freed)
        {
            VirtualFree(Freed, 0, MEM_RELEASE);
            InitSptd(&Direct, Freed, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
            SendE(1450, "direct, released page", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
                 sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
        }
    }
    InitSptd(&Direct, (PVOID)((ULONG_PTR)Info.lpMaximumApplicationAddress + 1 - 16), Inquiry36, sizeof(Inquiry36), 36,
             SCSI_IOCTL_DATA_IN);
    SendE(1450, "direct, data crosses the end of memory", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct),
         &Direct, sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    InitSptd(&Direct, (PVOID)((ULONG_PTR)Info.lpMaximumApplicationAddress + 1), Inquiry36, sizeof(Inquiry36), 36,
             SCSI_IOCTL_DATA_IN);
    SendE(1450, "direct, data above memory", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    InitSptd(&Direct, Data + 2, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Send("direct, data unaligned by 2", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    InitSptd(&Direct, Data, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Direct.Sptd.SenseInfoOffset = sizeof(Direct);
    SendE(87, "direct, sense offset at the end", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    InitSptd(&Direct, Data, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Direct.Sptd.SenseInfoOffset = 4;
    SendE(87, "direct, sense offset inside header", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct),
         &Direct, sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));
    InitSptd(&Direct, Data, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Direct.Sptd.Length = sizeof(Direct) + 1;
    SendE(1306, "direct, Length wrong", Device, IOCTL_SCSI_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(SCSI_PASS_THROUGH_DIRECT));

    /* a bad guest buffer is an error, never a crash: input and output pointers */
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Send("buffered, output pointer NULL", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), NULL, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    SendE(87, "buffered, input pointer NULL", Device, IOCTL_SCSI_PASS_THROUGH, NULL, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    SendE(998, "buffered, input pointer 0x10", Device, IOCTL_SCSI_PASS_THROUGH, (PVOID)0x10, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));
    SendE(998, "buffered, output pointer above memory", Device, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf),
         (PVOID)((ULONG_PTR)Info.lpMaximumApplicationAddress + 1 - 16), sizeof(Buf), sizeof(SCSI_PASS_THROUGH));
    SendE(998, "buffered, input crosses the end of memory", Device, IOCTL_SCSI_PASS_THROUGH,
         (PVOID)((ULONG_PTR)Info.lpMaximumApplicationAddress + 1 - 16), sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(SCSI_PASS_THROUGH));

    VirtualFree(Data, 0, MEM_RELEASE);
}

/* ATA IDENTIFY DEVICE */
static void TraceIdentify(const char *What, const UCHAR *Data)
{
    char Model[41];
    ULONG i;
    /* words 27 to 46, each stored with its two characters swapped */
    for (i = 0; i < 40; i += 2)
    {
        Model[i] = Data[54 + i + 1];
        Model[i + 1] = Data[54 + i];
    }
    Model[40] = 0;
    trace("SPTI %s: IDENTIFY model '%.40s' word0 %02x%02x sectors28 %02x%02x%02x%02x\n", What, Model, Data[1], Data[0],
          Data[123], Data[122], Data[121], Data[120]);
}

static void InitApt(APT_BUF *Buf, USHORT Flags, UCHAR Command, ULONG Transfer)
{
    RtlFillMemory(Buf, sizeof(*Buf), PATTERN);
    RtlZeroMemory(&Buf->Apt, sizeof(Buf->Apt));
    Buf->Apt.Length = sizeof(ATA_PASS_THROUGH_EX);
    Buf->Apt.AtaFlags = Flags;
    Buf->Apt.DataTransferLength = Transfer;
    Buf->Apt.TimeOutValue = 5;
    Buf->Apt.DataBufferOffset = APT_DATA;
    Buf->Apt.CurrentTaskFile[6] = Command;
}

static void TestAta(HANDLE Disk)
{
    APT_BUF Buf;
    APTD_BUF Direct;
    PUCHAR Data = AllocPage();
    UCHAR First[512];
    BOOL Ret;

    if (!Data) return;

    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Ret = Send("buffered ATA IDENTIFY", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
               sizeof(ATA_PASS_THROUGH_EX));
    trace("SPTI ATA IDENTIFY task file status %02x error %02x, transfer %lu\n", Buf.Apt.CurrentTaskFile[6],
          Buf.Apt.CurrentTaskFile[0], Buf.Apt.DataTransferLength);
    RtlZeroMemory(First, sizeof(First));
    if (Ret)
    {
        ok_eq_ulong(g_Returned, APT_DATA + 512);
        ok_eq_ulong(Buf.Apt.DataTransferLength, 512);
        ok_eq_ulong(Buf.Apt.Length, sizeof(ATA_PASS_THROUGH_EX));
        ok_eq_ulong((ULONG)Buf.Apt.DataBufferOffset, APT_DATA);
        ok_eq_int(Buf.Apt.CurrentTaskFile[6] & 0x01, 0);
        ok_eq_int(Buf.Apt.CurrentTaskFile[6] & 0x80, 0);
        TraceIdentify("buffered", Buf.Data);
        RtlCopyMemory(First, Buf.Data, 512);

        RtlFillMemory(Data, 0x1000, PATTERN);
        RtlZeroMemory(&Direct, sizeof(Direct));
        Direct.Aptd.Length = sizeof(ATA_PASS_THROUGH_DIRECT);
        Direct.Aptd.AtaFlags = ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED;
        Direct.Aptd.DataTransferLength = 512;
        Direct.Aptd.TimeOutValue = 5;
        Direct.Aptd.DataBuffer = Data;
        Direct.Aptd.CurrentTaskFile[6] = 0xEC;
        Ret = Send("direct ATA IDENTIFY", Disk, IOCTL_ATA_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
                   sizeof(Direct), sizeof(ATA_PASS_THROUGH_DIRECT));
        ok(Ret, "direct ATA IDENTIFY failed, error %lu\n", g_Error);
        if (Ret)
        {
            ok_eq_ulong(Direct.Aptd.DataTransferLength, 512);
            ok(Direct.Aptd.DataBuffer == Data, "DataBuffer changed\n");
            ok(!memcmp(Data, First, 512), "direct and buffered IDENTIFY differ\n");
            ok_eq_int(Direct.Aptd.CurrentTaskFile[6] & 0x01, 0);
            TraceIdentify("direct", Data);
        }
    }
    else
    {
        trace("SPTI ATA IDENTIFY is not supported here (error %lu)\n", g_Error);
    }

    /* malformed */
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Send("ATA buffered, input one byte short", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(ATA_PASS_THROUGH_EX) - 1,
         &Buf, sizeof(Buf), sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Send("ATA buffered, output one byte short", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(ATA_PASS_THROUGH_EX) - 1, sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.Length = sizeof(ATA_PASS_THROUGH_EX) + 1;
    Send("ATA buffered, Length wrong", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.Length = sizeof(ATA_PASS_THROUGH_EX) == 40 ? 48 : 40;
    Send("ATA buffered, Length of the other architecture", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.DataBufferOffset = 4;
    Send("ATA buffered, data offset inside header", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(Buf), sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.DataBufferOffset = sizeof(Buf);
    Send("ATA buffered, data offset at the end", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.DataBufferOffset = sizeof(Buf) - 256;
    Send("ATA buffered, data crosses the end", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.DataBufferOffset = 0xFFFFFFF0;
    Send("ATA buffered, data offset 0xFFFFFFF0", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.DataTransferLength = 1024;
    Send("ATA buffered, transfer larger than the room", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf,
         sizeof(Buf), sizeof(ATA_PASS_THROUGH_EX));
    InitApt(&Buf, ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED, 0xEC, 512);
    Buf.Apt.DataTransferLength = 0;
    Send("ATA buffered, data flag but no length", Disk, IOCTL_ATA_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf),
         sizeof(ATA_PASS_THROUGH_EX));
    RtlZeroMemory(&Direct, sizeof(Direct));
    Direct.Aptd.Length = sizeof(ATA_PASS_THROUGH_DIRECT);
    Direct.Aptd.AtaFlags = ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED;
    Direct.Aptd.DataTransferLength = 512;
    Direct.Aptd.TimeOutValue = 5;
    Direct.Aptd.CurrentTaskFile[6] = 0xEC;
    Send("ATA direct, no data pointer", Disk, IOCTL_ATA_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(ATA_PASS_THROUGH_DIRECT));
    {
        SYSTEM_INFO Info;
        GetSystemInfo(&Info);
        Direct.Aptd.DataBuffer = (PVOID)((ULONG_PTR)Info.lpMaximumApplicationAddress + 1 - 256);
        Send("ATA direct, data crosses the end of memory", Disk, IOCTL_ATA_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct),
             &Direct, sizeof(Direct), sizeof(ATA_PASS_THROUGH_DIRECT));
    }
    Direct.Aptd.DataBuffer = Data;
    Direct.Aptd.Length = sizeof(ATA_PASS_THROUGH_DIRECT) == 40 ? 48 : 40;
    Send("ATA direct, Length of the other architecture", Disk, IOCTL_ATA_PASS_THROUGH_DIRECT, &Direct, sizeof(Direct), &Direct,
         sizeof(Direct), sizeof(ATA_PASS_THROUGH_DIRECT));

    VirtualFree(Data, 0, MEM_RELEASE);
}

/* An overlapped handle: the request completes before the call returns, or is waited for */
static void TestOverlapped(void)
{
    static const UCHAR Inquiry36[6] = { 0x12, 0, 0, 0, 36, 0 };
    SPT_BUF Buf;
    OVERLAPPED Overlapped;
    HANDLE Disk;
    ULONG Returned = 0;
    BOOL Ret;

    Disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (Disk == INVALID_HANDLE_VALUE)
    {
        skip("overlapped PhysicalDrive0 not opened, error %lu\n", GetLastError());
        return;
    }
    RtlZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    InitSpt(&Buf, Inquiry36, sizeof(Inquiry36), 36, SCSI_IOCTL_DATA_IN);
    Ret = DeviceIoControl(Disk, IOCTL_SCSI_PASS_THROUGH, &Buf, sizeof(Buf), &Buf, sizeof(Buf), &Returned, &Overlapped);
    if (!Ret && GetLastError() == ERROR_IO_PENDING)
        Ret = GetOverlappedResult(Disk, &Overlapped, &Returned, TRUE);
    trace("SPTI overlapped INQUIRY: ok=%d error %lu returned %ld\n", Ret, Ret ? 0 : GetLastError(),
          Ret ? (long)Returned - (long)sizeof(SCSI_PASS_THROUGH) : 0L);
    ok(Ret, "overlapped INQUIRY failed, error %lu\n", GetLastError());
    if (Ret)
    {
        ok_eq_ulong(Returned, SPT_DATA + 36);
        ok_eq_ulong(Buf.Spt.DataTransferLength, 36);
        ok_eq_int(Buf.Data[0] & 0x1f, 0);
        ok(WaitForSingleObject(Overlapped.hEvent, 0) == WAIT_OBJECT_0, "the event was not signalled\n");
    }
    CloseHandle(Overlapped.hEvent);
    CloseHandle(Disk);
}

START_TEST(ScsiPassThrough)
{
    HANDLE Disk, Cd;

    Disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (Disk == INVALID_HANDLE_VALUE)
    {
        skip("PhysicalDrive0 not opened (administrator rights needed), error %lu\n", GetLastError());
    }
    else
    {
        TestScsi("disk", Disk, 0);
        TestAta(Disk);
        CloseHandle(Disk);
        TestOverlapped();
    }

    Cd = CreateFileW(L"\\\\.\\CdRom0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                     OPEN_EXISTING, 0, NULL);
    if (Cd == INVALID_HANDLE_VALUE)
    {
        skip("CdRom0 not opened, error %lu\n", GetLastError());
    }
    else
    {
        TestScsi("cdrom", Cd, 5);
        CloseHandle(Cd);
    }
}
