/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Virtual Storport miniport with a RAM disk, that calls the Storport routines under test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * One disk (path 0, target 0, LUN 0). The vendor CDB 0xC0 is a control command: its second byte
 * selects what the miniport calls, the data buffer carries the result back (see storest.h).
 */

#include <ntddk.h>
#include <storport.h>
#include "storest.h"

#define RAM_SECTORS      16384
#define PENDING_MAX      32
#define LOG_MAX          64

typedef struct _PENDING
{
    PSCSI_REQUEST_BLOCK Srb;
    LARGE_INTEGER Due;
} PENDING;

typedef struct _STOREST_EXT
{
    PUCHAR Ram;
    KSPIN_LOCK Lock;
    ULONG DelayMs;
    ULONG BusyOnNextRead;
    ULONG ResumeAfterMs;
    LARGE_INTEGER ResumeDue;
    BOOLEAN TimerArmed;
    PENDING Pending[PENDING_MAX];
    STOREST_LOG_ENTRY Log[LOG_MAX];
    ULONG LogCount;
    volatile LONG StateChangeDone;
    volatile LONG SyncValue;
    volatile ULONG SyncIrql;
    PVOID Self;
    STOREST_CONTROL RegData;
} STOREST_EXT, *PSTOREST_EXT;

static
VOID
NTAPI
StorestTimer(PVOID Ext, PVOID Context);

static
BOOLEAN
NTAPI
SyncRoutine(PVOID Hw, PVOID Context);

static
VOID
NowTicks(PVOID Hw, PLARGE_INTEGER Counter, PLARGE_INTEGER Frequency)
{
    StorPortQueryPerformanceCounter(Hw, Frequency, Counter);
}

static
LONGLONG
MsToTicks(PVOID Hw, ULONG Ms)
{
    LARGE_INTEGER Counter, Frequency;

    NowTicks(Hw, &Counter, &Frequency);
    return Frequency.QuadPart * Ms / 1000;
}

static
VOID
ArmTimer(PSTOREST_EXT Ext)
{
    if (!Ext->TimerArmed)
    {
        Ext->TimerArmed = TRUE;
        StorPortNotification(RequestTimerCall, Ext, StorestTimer, 20000);
    }
}

static
VOID
NTAPI
StorestStateChanged(PVOID Hw, PVOID Context, SHORT AddressType, PVOID Address, ULONG Status)
{
    PSTOREST_EXT Ext = Hw;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(AddressType);
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Status);
    InterlockedExchange(&Ext->StateChangeDone, 1);
}

static
VOID
CompleteSrb(PVOID Hw, PSCSI_REQUEST_BLOCK Srb, UCHAR Status)
{
    Srb->SrbStatus = Status;
    StorPortNotification(RequestComplete, Hw, Srb);
}

/* Every 20 ms: finish the delayed requests that are due, resume after a delay */
static
VOID
NTAPI
StorestTimer(PVOID Hw, PVOID Context)
{
    PSTOREST_EXT Ext = Hw;
    LARGE_INTEGER Now;
    ULONG i;
    BOOLEAN Resume = FALSE, More = FALSE;
    PSCSI_REQUEST_BLOCK Done[PENDING_MAX];
    ULONG DoneCount = 0;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(Context);

    NowTicks(Hw, &Now, NULL);
    KeAcquireSpinLock(&Ext->Lock, &OldIrql);
    Ext->TimerArmed = FALSE;
    for (i = 0; i < PENDING_MAX; i++)
    {
        if (Ext->Pending[i].Srb == NULL)
            continue;
        if (Ext->Pending[i].Due.QuadPart <= Now.QuadPart)
        {
            Done[DoneCount++] = Ext->Pending[i].Srb;
            Ext->Pending[i].Srb = NULL;
        }
        else
            More = TRUE;
    }
    if (Ext->ResumeAfterMs != 0)
    {
        if (Ext->ResumeDue.QuadPart <= Now.QuadPart)
        {
            Ext->ResumeAfterMs = 0;
            Resume = TRUE;
        }
        else
            More = TRUE;
    }
    if (More)
        ArmTimer(Ext);
    KeReleaseSpinLock(&Ext->Lock, OldIrql);

    if (Resume)
        StorPortResume(Hw);
    for (i = 0; i < DoneCount; i++)
        CompleteSrb(Hw, Done[i], SRB_STATUS_SUCCESS);
}

static
VOID
DoControl(PSTOREST_EXT Ext, PSCSI_REQUEST_BLOCK Srb)
{
    PVOID Hw = Ext;
    PUCHAR Cdb = Srb->Cdb;
    PSTOREST_CONTROL Data = Srb->DataBuffer;
    ULONG Arg = (Cdb[2] << 24) | (Cdb[3] << 16) | (Cdb[4] << 8) | Cdb[5];
    KIRQL OldIrql;

    if (Data == NULL || Srb->DataTransferLength < sizeof(*Data))
    {
        CompleteSrb(Hw, Srb, SRB_STATUS_INVALID_REQUEST);
        return;
    }
    RtlZeroMemory(Data, sizeof(*Data));

    switch (Cdb[1])
    {
        case STOREST_SET_DELAY:
            Ext->DelayMs = Arg;
            break;

        case STOREST_ARM_BUSY:
            Ext->BusyOnNextRead = Arg;
            Ext->LogCount = 0;
            break;

        case STOREST_GET_LOG:
            {
                LARGE_INTEGER Freq, Dummy;

                NowTicks(Hw, &Dummy, &Freq);
                Data->Value[0] = Ext->LogCount;
                if (Ext->LogCount != 0)
                {
                    /* The first read's start, then the last one's */
                    Data->Value[1] = Ext->Log[0].Ticks.LowPart;
                    Data->Value[2] = Ext->Log[0].Ticks.HighPart;
                    Data->Value[3] = Ext->Log[Ext->LogCount - 1].Ticks.LowPart;
                    Data->Value[4] = Ext->Log[Ext->LogCount - 1].Ticks.HighPart;
                }
                Data->Value[15] = (ULONG)Freq.QuadPart;
            }
            break;

        case STOREST_PAUSE:
            /* Arg = seconds; Cdb[6] = resume after this many 100 ms, 0 = never */
            Data->Status[0] = StorPortPause(Hw, Arg) ? 1 : 0;
            if (Cdb[6] != 0)
            {
                LARGE_INTEGER Now;

                NowTicks(Hw, &Now, NULL);
                KeAcquireSpinLock(&Ext->Lock, &OldIrql);
                Ext->ResumeAfterMs = Cdb[6] * 100;
                Ext->ResumeDue.QuadPart = Now.QuadPart + MsToTicks(Hw, Ext->ResumeAfterMs);
                ArmTimer(Ext);
                KeReleaseSpinLock(&Ext->Lock, OldIrql);
            }
            break;

        case STOREST_REGISTRY:
            /* The reads ran in HwFindAdapter (PASSIVE_LEVEL, as the routines need); this returns what they found */
            RtlCopyMemory(Data, &Ext->RegData, sizeof(*Data));
            break;

        case STOREST_SYNC:
        {
            Ext->SyncValue = 0;
            Data->Status[0] = StorPortSynchronizeAccess(Hw, SyncRoutine, Ext);
            Data->Value[0] = Ext->SyncValue;
            Data->Value[1] = Ext->SyncIrql;
            break;
        }

        case STOREST_PERF:
        {
            LARGE_INTEGER A, B, Freq;
            STARTIO_PERFORMANCE_PARAMETERS Params;

            Data->Status[0] = StorPortQueryPerformanceCounter(Hw, &Freq, &A);
            StorPortStallExecution(200);
            Data->Status[1] = StorPortQueryPerformanceCounter(Hw, NULL, &B);
            Data->Status[2] = StorPortQueryPerformanceCounter(Hw, &Freq, NULL);
            Data->Value[0] = (B.QuadPart > A.QuadPart) ? 1 : 0;
            Data->Value[1] = (Freq.QuadPart > 0) ? 1 : 0;

            Params.Size = sizeof(Params);
            Data->Status[3] = StorPortGetStartIoPerfParams(Hw, Srb, &Params);
            Params.Size = 4;
            Data->Status[4] = StorPortGetStartIoPerfParams(Hw, Srb, &Params);
            Data->Status[5] = StorPortGetStartIoPerfParams(Hw, NULL, &Params);
            break;
        }

        case STOREST_MISC:
        {
            STOR_LOG_EVENT_DETAILS Log;
            STOR_ADDR_BTL8 Address;
            STOR_UNIT_ATTRIBUTES Attributes;
            ULONG Maximum = 0, Irql = 0;

            RtlZeroMemory(&Log, sizeof(Log));
            Log.InterfaceRevision = 0x00000100;
            Log.Size = sizeof(Log);
            Log.ErrorCode = 0x1234;
            Data->Status[0] = StorPortLogSystemEvent(Hw, &Log, &Maximum);
            Log.InterfaceRevision = 0x00000200;
            Data->Status[1] = StorPortLogSystemEvent(Hw, &Log, &Maximum);
            Data->Status[2] = StorPortLogSystemEvent(Hw, NULL, &Maximum);

            RtlZeroMemory(&Address, sizeof(Address));
            Address.Type = STOR_ADDRESS_TYPE_BTL8;
            Address.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
            RtlZeroMemory(&Attributes, sizeof(Attributes));
            Attributes.DeviceAttentionSupported = 1;
            Data->Status[3] = StorPortSetUnitAttributes(Hw, (PSTOR_ADDRESS)&Address, Attributes);
            Address.Lun = 5;
            Data->Status[4] = StorPortSetUnitAttributes(Hw, (PSTOR_ADDRESS)&Address, Attributes);
            Address.Lun = 0;
            Attributes.Reserved = 1;
            Data->Status[5] = StorPortSetUnitAttributes(Hw, (PSTOR_ADDRESS)&Address, Attributes);

            /* A virtual miniport has no message interrupts */
            Data->Status[6] = StorPortAcquireMSISpinLock(Hw, 0, &Irql);
            Data->Status[7] = StorPortReleaseMSISpinLock(Hw, 0, Irql);
            break;
        }

        case STOREST_STATE:
        {
            STOR_ADDR_BTL8 Address;

            RtlZeroMemory(&Address, sizeof(Address));
            Address.Type = STOR_ADDRESS_TYPE_BTL8;
            Address.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
            Ext->StateChangeDone = 0;
            Data->Status[0] = StorPortStateChangeDetected(Hw, STATE_CHANGE_BUS, (PSTOR_ADDRESS)&Address, 0,
                                                          StorestStateChanged, NULL);
            Data->Status[1] = StorPortStateChangeDetected(Hw, STATE_CHANGE_BUS, (PSTOR_ADDRESS)&Address, 0,
                                                          StorestStateChanged, NULL);
            Data->Status[2] = StorPortStateChangeDetected(Hw, 0, NULL, 0, NULL, NULL);
            break;
        }

        case STOREST_STATE_DONE:
            Data->Value[0] = Ext->StateChangeDone;
            break;

        default:
            CompleteSrb(Hw, Srb, SRB_STATUS_INVALID_REQUEST);
            return;
    }

    CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
}

static
BOOLEAN
NTAPI
StorestStartIo(PVOID Hw, PSCSI_REQUEST_BLOCK Srb)
{
    PSTOREST_EXT Ext = Hw;
    PUCHAR Cdb = Srb->Cdb;
    ULONG Lba, Count;
    KIRQL OldIrql;

    if (Srb->Function != SRB_FUNCTION_EXECUTE_SCSI)
    {
        CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
        return TRUE;
    }

    if (Srb->PathId != 0 || Srb->TargetId != 0 || Srb->Lun != 0)
    {
        CompleteSrb(Hw, Srb, SRB_STATUS_SELECTION_TIMEOUT);
        return TRUE;
    }

    switch (Cdb[0])
    {
        case SCSIOP_TEST_UNIT_READY:
            CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
            break;

        case SCSIOP_INQUIRY:
        {
            PINQUIRYDATA Inquiry = Srb->DataBuffer;
            ULONG Length = min(Srb->DataTransferLength, sizeof(INQUIRYDATA));

            if (Cdb[1] & 1)
            {
                /* No vital product data pages */
                CompleteSrb(Hw, Srb, SRB_STATUS_INVALID_REQUEST);
                break;
            }
            RtlZeroMemory(Inquiry, Srb->DataTransferLength);
            if (Length >= 36)
            {
                Inquiry->DeviceType = DIRECT_ACCESS_DEVICE;
                Inquiry->ResponseDataFormat = 2;
                Inquiry->AdditionalLength = 31;
                RtlCopyMemory(Inquiry->VendorId, "NITROTST", 8);
                RtlCopyMemory(Inquiry->ProductId, "STORAGE TEST    ", 16);
                RtlCopyMemory(Inquiry->ProductRevisionLevel, "1.00", 4);
            }
            Srb->DataTransferLength = Length;
            CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
            break;
        }

        case SCSIOP_READ_CAPACITY:
        {
            PULONG Data = Srb->DataBuffer;

            Data[0] = RtlUlongByteSwap(RAM_SECTORS - 1);
            Data[1] = RtlUlongByteSwap(512);
            Srb->DataTransferLength = 8;
            CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
            break;
        }

        case SCSIOP_MODE_SENSE:
            RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);
            if (Srb->DataTransferLength >= 4)
                ((PUCHAR)Srb->DataBuffer)[0] = 3;
            CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
            break;

        case SCSIOP_READ:
        case SCSIOP_WRITE:
            Lba = RtlUlongByteSwap(*(UNALIGNED ULONG *)&Cdb[2]);
            Count = (Cdb[7] << 8) | Cdb[8];
            if (Lba + Count > RAM_SECTORS || Count * 512 > Srb->DataTransferLength)
            {
                CompleteSrb(Hw, Srb, SRB_STATUS_INVALID_REQUEST);
                break;
            }

            if (Cdb[0] == SCSIOP_READ)
            {
                RtlCopyMemory(Srb->DataBuffer, Ext->Ram + Lba * 512, Count * 512);
                if (Ext->LogCount < LOG_MAX)
                    NowTicks(Hw, &Ext->Log[Ext->LogCount++].Ticks, NULL);
            }
            else
                RtlCopyMemory(Ext->Ram + Lba * 512, Srb->DataBuffer, Count * 512);

            if (Cdb[0] == SCSIOP_READ && Ext->BusyOnNextRead != 0)
            {
                /* The request being started is outstanding: the others wait for it */
                ULONG Busy = Ext->BusyOnNextRead;

                Ext->BusyOnNextRead = 0;
                StorPortBusy(Hw, Busy);
            }

            if (Ext->DelayMs != 0 && Cdb[0] == SCSIOP_READ)
            {
                LARGE_INTEGER Now;
                ULONG i;

                NowTicks(Hw, &Now, NULL);
                KeAcquireSpinLock(&Ext->Lock, &OldIrql);
                for (i = 0; i < PENDING_MAX && Ext->Pending[i].Srb != NULL; i++)
                    ;
                if (i < PENDING_MAX)
                {
                    Ext->Pending[i].Srb = Srb;
                    Ext->Pending[i].Due.QuadPart = Now.QuadPart + MsToTicks(Hw, Ext->DelayMs);
                    ArmTimer(Ext);
                    KeReleaseSpinLock(&Ext->Lock, OldIrql);
                    break;
                }
                KeReleaseSpinLock(&Ext->Lock, OldIrql);
            }
            CompleteSrb(Hw, Srb, SRB_STATUS_SUCCESS);
            break;

        case 0xC0:
            DoControl(Ext, Srb);
            break;

        default:
            CompleteSrb(Hw, Srb, SRB_STATUS_INVALID_REQUEST);
            break;
    }

    return TRUE;
}

static
BOOLEAN
NTAPI
SyncRoutine(PVOID Hw, PVOID Context)
{
    PSTOREST_EXT Ext = Context;

    UNREFERENCED_PARAMETER(Hw);
    Ext->SyncIrql = KeGetCurrentIrql();
    Ext->SyncValue = 0x5A5A;
    return TRUE;
}

/* StorPortRegistryRead and the registry buffer routines, called as a miniport calls them: while it starts */
static
VOID
RegistryProbe(PSTOREST_EXT Ext)
{
    PVOID Hw = Ext;
    PSTOREST_CONTROL R = &Ext->RegData;
    ULONG Length, Again = 4;
    PUCHAR Buffer;
    struct { PCSTR Name; ULONG Global, Type, Room; } Probe[] = {
        { "TestDword",    1, MINIPORT_REG_DWORD, 4 },
        { "TestString",   1, MINIPORT_REG_SZ,    16 },
        { "TestString",   1, MINIPORT_REG_SZ,    2 },
        { "NoSuchValue",  1, MINIPORT_REG_DWORD, 4 },
        { "TestDword",    1, MINIPORT_REG_SZ,    4 },
        { "PerAdapter",   0, MINIPORT_REG_DWORD, 4 },
    };
    ULONG i;

    RtlZeroMemory(R, sizeof(*R));
    Length = 64;
    Buffer = StorPortAllocateRegistryBuffer(Hw, &Length);
    if (Buffer == NULL)
        return;
    R->Value[15] = 1;                                                    /* a buffer was granted */
    R->Value[14] = (StorPortAllocateRegistryBuffer(Hw, &Again) == NULL); /* and a second one was refused */

    for (i = 0; i < RTL_NUMBER_OF(Probe); i++)
    {
        Length = Probe[i].Room;
        R->Status[i] = StorPortRegistryRead(Hw, (PUCHAR)Probe[i].Name, Probe[i].Global, Probe[i].Type, Buffer, &Length);
        R->Value[i] = Length;
        if (i == 0 || i == 5)
            R->Value[8 + (i ? 1 : 0)] = *(PULONG)Buffer;                   /* the DWORDs */
        if (i == 1)
            RtlCopyMemory(R->Text, Buffer, 16);                           /* the string */
    }
    StorPortFreeRegistryBuffer(Hw, Buffer);
    Length = 4;
    Buffer = StorPortAllocateRegistryBuffer(Hw, &Length);                 /* after the free another one is granted */
    R->Value[13] = (Buffer != NULL);
    if (Buffer != NULL)
        StorPortFreeRegistryBuffer(Hw, Buffer);
}

static
ULONG
NTAPI
StorestFindAdapter(PVOID Hw, PVOID HwContext, PVOID BusInformation, PVOID LowerDevice,
                   PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION Config, PBOOLEAN Again)
{
    PSTOREST_EXT Ext = Hw;

    UNREFERENCED_PARAMETER(HwContext);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(LowerDevice);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

    Config->NumberOfBuses = 1;
    Config->MaximumNumberOfTargets = 1;
    Config->MaximumNumberOfLogicalUnits = 1;
    Config->MaximumTransferLength = 64 * 1024;
    Config->NumberOfPhysicalBreaks = 16;
    Config->ScatterGather = TRUE;
    Config->Master = TRUE;
    Config->CachesData = FALSE;
    Config->TaggedQueuing = TRUE;
    Config->MultipleRequestPerLu = TRUE;
    Config->AutoRequestSense = TRUE;
    Config->NeedPhysicalAddresses = TRUE;
    Config->MapBuffers = STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE;
    Config->AlignmentMask = 3;
    Config->InterruptMode = LevelSensitive;
    Ext->Self = Hw;
    RegistryProbe(Ext);
    return SP_RETURN_FOUND;
}

static
BOOLEAN
NTAPI
StorestInitialize(PVOID Hw)
{
    PSTOREST_EXT Ext = Hw;
    PVOID Ram = NULL;

    KeInitializeSpinLock(&Ext->Lock);
    if (Ext->Ram == NULL &&
        StorPortAllocatePool(Hw, RAM_SECTORS * 512, 'tSTS', &Ram) != STOR_STATUS_SUCCESS)
        return FALSE;
    if (Ram != NULL)
    {
        RtlZeroMemory(Ram, RAM_SECTORS * 512);
        Ext->Ram = Ram;
    }
    return TRUE;
}

static
VOID
NTAPI
StorestFree(PVOID Hw)
{
    PSTOREST_EXT Ext = Hw;

    if (Ext->Ram != NULL)
    {
        StorPortFreePool(Hw, Ext->Ram);
        Ext->Ram = NULL;
    }
}

static
BOOLEAN
NTAPI
StorestReset(PVOID Hw, ULONG PathId)
{
    UNREFERENCED_PARAMETER(Hw);
    UNREFERENCED_PARAMETER(PathId);
    return TRUE;
}

static
SCSI_ADAPTER_CONTROL_STATUS
NTAPI
StorestControl(PVOID Hw, SCSI_ADAPTER_CONTROL_TYPE Type, PVOID Parameters)
{
    UNREFERENCED_PARAMETER(Hw);

    if (Type == ScsiQuerySupportedControlTypes)
    {
        PSCSI_SUPPORTED_CONTROL_TYPE_LIST List = Parameters;

        if (List->MaxControlType > ScsiQuerySupportedControlTypes)
            List->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;
        return ScsiAdapterControlSuccess;
    }
    return ScsiAdapterControlUnsuccessful;
}

NTSTATUS
NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    VIRTUAL_HW_INITIALIZATION_DATA Init;

    RtlZeroMemory(&Init, sizeof(Init));
    Init.HwInitializationDataSize = sizeof(Init);
    Init.AdapterInterfaceType = Internal;
    Init.HwInitialize = StorestInitialize;
    Init.HwStartIo = StorestStartIo;
    Init.HwFindAdapter = StorestFindAdapter;
    Init.HwResetBus = StorestReset;
    Init.HwAdapterControl = StorestControl;
    Init.HwFreeAdapterResources = StorestFree;
    Init.DeviceExtensionSize = sizeof(STOREST_EXT);
    Init.MapBuffers = STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE;
    Init.TaggedQueuing = TRUE;
    Init.AutoRequestSense = TRUE;
    Init.MultipleRequestPerLu = TRUE;
    Init.FeatureSupport = STOR_FEATURE_VIRTUAL_MINIPORT;
    Init.SrbTypeFlags = SRB_TYPE_FLAG_SCSI_REQUEST_BLOCK;
    Init.AddressTypeFlags = ADDRESS_TYPE_FLAG_BTL8;

    return StorPortInitialize(DriverObject, RegistryPath, (PVOID)&Init, NULL);
}
