/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NT implementation of the ngos bridge used by the Linux-API shim
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"
#include "../shim/include/ngos.h"

C_ASSERT(sizeof(KEVENT) <= sizeof(struct ngos_ev));
C_ASSERT(sizeof(KSPIN_LOCK) == sizeof(uintptr_t));
C_ASSERT(NGP_STAGES == NG_PROFILE_STAGES);

NG_PROFILE NgProfile;

unsigned long long ngos_ticks(void)
{
#if DBG
    return __rdtsc();
#else
    return 0;
#endif
}

void ngos_prof(int id, unsigned long long since, unsigned long long bytes)
{
#if DBG
    NG_PROF_STAT *S = &NgProfile.Stage[id];
    S->Count++;
    S->Ticks += __rdtsc() - since;
    S->Bytes += bytes;
    /* every one of these stages runs under CoreLock (the device stages do not: unlocked paging transfers) */
    switch (id)
    {
        case NGP_COMMIT: NgHoldTicks[NG_HT_COMMIT] += __rdtsc() - since; break;
        case NGP_SET_SIZE: NgHoldTicks[NG_HT_SET_SIZE] += __rdtsc() - since; break;
        case NGP_WRITE: NgHoldTicks[NG_HT_WRITE] += __rdtsc() - since; break;
        case NGP_WRITEBACK: NgHoldTicks[NG_HT_WRITEBACK] += __rdtsc() - since; break;
        case NGP_JNL_COMMIT: NgHoldTicks[NG_HT_JNL] += __rdtsc() - since; break;
    }
#else
    (void)id; (void)since; (void)bytes;
#endif
}

void *ngos_alloc(size_t n)
{
    return ExAllocatePoolWithTag(NonPagedPool, n, TAG_NTFSNG_CORE);
}

void ngos_free(void *p)
{
    if (p)
        ExFreePoolWithTag(p, TAG_NTFSNG_CORE);
}

void ngos_print(const char *s)
{
    DbgPrint("%s", s);
}

void ngos_bugcheck(const char *what, const char *file, int line)
{
    DbgPrint("ntfsng: fatal: %s (%s:%d)\n", what, file, line);
    KeBugCheckEx(FILE_SYSTEM, (ULONG_PTR)what, (ULONG_PTR)file, (ULONG_PTR)line, 0x4e544e47);
}

void ngos_ev_init(struct ngos_ev *ev, int synchronization, int signaled)
{
    KeInitializeEvent((PKEVENT)ev, synchronization ? SynchronizationEvent : NotificationEvent,
                      signaled ? TRUE : FALSE);
}

void ngos_ev_set(struct ngos_ev *ev)
{
    KeSetEvent((PKEVENT)ev, IO_NO_INCREMENT, FALSE);
}

void ngos_ev_clear(struct ngos_ev *ev)
{
    KeClearEvent((PKEVENT)ev);
}

void ngos_ev_wait(struct ngos_ev *ev)
{
    KeWaitForSingleObject(ev, Executive, KernelMode, FALSE, NULL);
}

int ngos_ev_trywait(struct ngos_ev *ev)
{
    LARGE_INTEGER Zero;
    Zero.QuadPart = 0;
    return KeWaitForSingleObject(ev, Executive, KernelMode, FALSE, &Zero) == STATUS_SUCCESS;
}

int ngos_ev_state(struct ngos_ev *ev)
{
    return KeReadStateEvent((PKEVENT)ev) != 0;
}

unsigned char ngos_spin_lock(uintptr_t *lock)
{
    KIRQL Old;
    KeAcquireSpinLock((PKSPIN_LOCK)lock, &Old);
    return Old;
}

void ngos_spin_unlock(uintptr_t *lock, unsigned char irql)
{
    KeReleaseSpinLock((PKSPIN_LOCK)lock, irql);
}

void *ngos_current_thread(void)
{
    return KeGetCurrentThread();
}

void ngos_yield(void)
{
    LARGE_INTEGER Delay;
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
        return;
    Delay.QuadPart = -10000; /* 1 ms */
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

void ngos_sleep_ms(unsigned int ms)
{
    LARGE_INTEGER Delay;
    Delay.QuadPart = -10000LL * ms;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG Class, PVOID Info, ULONG Length, PULONG ReturnLength);

/* SystemBasicInformation (class 0) as documented in winternl.h. */
typedef struct
{
    ULONG Reserved, TimerResolution, PageSize, NumberOfPhysicalPages, LowestPhysicalPageNumber,
          HighestPhysicalPageNumber, AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress, MaximumUserModeAddress, ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} NG_SYSTEM_BASIC_INFORMATION;

unsigned long ngos_physical_pages(void)
{
    static ULONG Pages;
    NG_SYSTEM_BASIC_INFORMATION Info;
    /* Asked once: a failed query is not retried later, perhaps under a spin lock. */
    if (!Pages)
        Pages = NT_SUCCESS(ZwQuerySystemInformation(0, &Info, sizeof(Info), NULL)) && Info.NumberOfPhysicalPages ?
                Info.NumberOfPhysicalPages : 65536;
    return Pages;
}

unsigned long ngos_jiffies(void)
{
    LARGE_INTEGER Ticks;
    KeQueryTickCount(&Ticks);
    return (unsigned long)Ticks.QuadPart;
}

void ngos_time(long long *sec, long *nsec)
{
    LARGE_INTEGER Now;
    ULONGLONG Unix100ns;
    KeQuerySystemTime(&Now);
    Unix100ns = (ULONGLONG)Now.QuadPart - 116444736000000000ULL;
    *sec = (long long)(Unix100ns / 10000000ULL);
    *nsec = (long)((Unix100ns % 10000000ULL) * 100);
}

/*
 * Devices whose stack refuses flushes but whose disk reports no volatile write cache (NgFlushUsable at
 * mount): only there does a refused flush count as done.
 */
static PDEVICE_OBJECT NgFlushOptional[32];
static KSPIN_LOCK NgFlushOptionalLock;

VOID NgSetFlushOptional(PDEVICE_OBJECT Device)
{
    KIRQL Irql;
    ULONG i;
    KeAcquireSpinLock(&NgFlushOptionalLock, &Irql);
    for (i = 0; i < RTL_NUMBER_OF(NgFlushOptional); i++)
        if (!NgFlushOptional[i] || NgFlushOptional[i] == Device)
        {
            NgFlushOptional[i] = Device;
            break;
        }
    KeReleaseSpinLock(&NgFlushOptionalLock, Irql);
}

static BOOLEAN NgIsFlushOptional(PDEVICE_OBJECT Device)
{
    KIRQL Irql;
    ULONG i;
    BOOLEAN Found = FALSE;
    KeAcquireSpinLock(&NgFlushOptionalLock, &Irql);
    for (i = 0; i < RTL_NUMBER_OF(NgFlushOptional) && !Found; i++)
        Found = NgFlushOptional[i] == Device;
    KeReleaseSpinLock(&NgFlushOptionalLock, Irql);
    return Found;
}

/*
 * The waiter gets the boost a disk completion gives the thread of a synchronous request on Windows
 * (IO_DISK_INCREMENT): stopping completion here also stops the I/O manager from applying it, and
 * without it the waiter queued behind every busy thread of its priority after each transfer.
 */
static IO_COMPLETION_ROUTINE NgReadCompletion;
static NTSTATUS NTAPI NgReadCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent((PKEVENT)Context, IO_DISK_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * Transfers to or from the volume's storage device.  The IRP is freed here rather than
 * by the I/O manager, so completion needs no APC: core I/O can happen on a paging-I/O
 * path entered at APC_LEVEL, where IoBuildSynchronousFsdRequest's APC-based completion
 * would never run.
 */
#define NG_IO_WRITE_THROUGH 1   /* SL_WRITE_THROUGH on the write */
#define NG_IO_REFUSAL_OK    2   /* a flush the stack does not implement counts as done */
static int NgDevIo(UCHAR Major, PDEVICE_OBJECT Device, unsigned long long off, void *buf, unsigned int len, ULONG Flags)
{
    LARGE_INTEGER Offset;
    IO_STATUS_BLOCK Iosb;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;
#if DBG
    ULONGLONG T0 = __rdtsc();
#endif

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Offset.QuadPart = (LONGLONG)off;
    Irp = IoBuildAsynchronousFsdRequest(Major, Device, Major == IRP_MJ_FLUSH_BUFFERS ? NULL : buf,
                                        Major == IRP_MJ_FLUSH_BUFFERS ? 0 : len,
                                        Major == IRP_MJ_FLUSH_BUFFERS ? NULL : &Offset, &Iosb);
    if (!Irp)
        return NG_DEV_NOT_SENT;
    /* No SL_WRITE_THROUGH: durability comes from the flushes at each commit (and FUA is not honoured everywhere). */
    IoGetNextIrpStackLocation(Irp)->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    if (Flags & NG_IO_WRITE_THROUGH)
        IoGetNextIrpStackLocation(Irp)->Flags |= SL_WRITE_THROUGH;
    IoSetCompletionRoutine(Irp, NgReadCompletion, &Event, TRUE, TRUE, TRUE);
    Status = IoCallDriver(Device, Irp);
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    Status = Irp->IoStatus.Status;
    if (Irp->Flags & IRP_BUFFERED_IO)
    {
        /* Completion stopped before the I/O manager's copy-back: do it here. */
        if (NT_SUCCESS(Status) && Major == IRP_MJ_READ)
            RtlCopyMemory(buf, Irp->AssociatedIrp.SystemBuffer, len);
        if (Irp->Flags & IRP_DEALLOCATE_BUFFER)
            ExFreePool(Irp->AssociatedIrp.SystemBuffer);
        Irp->AssociatedIrp.SystemBuffer = NULL;
    }
    if (Irp->MdlAddress)
    {
        MmUnlockPages(Irp->MdlAddress);
        IoFreeMdl(Irp->MdlAddress);
        Irp->MdlAddress = NULL;
    }
    IoFreeIrp(Irp);
#if DBG
    ngos_prof(Major == IRP_MJ_READ ? NGP_DEV_READ : Major == IRP_MJ_WRITE ? NGP_DEV_WRITE : NGP_DEV_FLUSH, T0,
              Major == IRP_MJ_FLUSH_BUFFERS ? 0 : len);
    NgStackSample();
#endif
    if (!NT_SUCCESS(Status))
    {
        /*
         * A disk without a write cache may not implement flush.  On any other disk a refused flush is
         * a failed one: it voids every durability step of the journal.
         */
        if (Major == IRP_MJ_FLUSH_BUFFERS && (Status == STATUS_INVALID_DEVICE_REQUEST || Status == STATUS_NOT_SUPPORTED ||
                                             Status == STATUS_NOT_IMPLEMENTED) && ((Flags & NG_IO_REFUSAL_OK) || NgIsFlushOptional(Device)))
            return 0;
        DPRINT1("ntfsng: device %s at %I64u len %u failed 0x%lx\n",
                Major == IRP_MJ_READ ? "read" : Major == IRP_MJ_WRITE ? "write" : "flush", off, len, Status);
        return -1;
    }
    return 0;
}

int ngos_dev_read(void *dev, unsigned long long off, void *buf, unsigned int len)
{
    return NgDevIo(IRP_MJ_READ, dev, off, buf, len, 0);
}

int ngos_dev_write(void *dev, unsigned long long off, void *buf, unsigned int len)
{
    return NgDevIo(IRP_MJ_WRITE, dev, off, buf, len, 0);
}

int ngos_dev_flush(void *dev)
{
    return NgDevIo(IRP_MJ_FLUSH_BUFFERS, dev, 0, NULL, 0, 0);
}

/*
 * Writes through a volume handle (formatters, the lock holder, a dismounted volume) bypass the journal
 * and its flushes: each one is durable when it completes.  The write asks for write-through and is
 * followed by a cache flush, for stacks that drop FUA; a stack that does not implement flush keeps
 * what write-through gave.
 */
int NgDevWriteDurable(PDEVICE_OBJECT Device, unsigned long long off, void *buf, unsigned int len)
{
    return NgDevIo(IRP_MJ_WRITE, Device, off, buf, len, NG_IO_WRITE_THROUGH);
}

int NgDevFlushDurable(PDEVICE_OBJECT Device)
{
    return NgDevIo(IRP_MJ_FLUSH_BUFFERS, Device, 0, NULL, 0, NG_IO_REFUSAL_OK);
}
