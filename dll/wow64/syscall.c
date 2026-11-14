/* ReactOS WoW64 NT argument translation. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"
#include <mountmgr.h>
#include <mountdev.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <ntddbeep.h>
#include <ntddscsi.h>
#include <winsock2.h>
#include <tdi.h>
#include <tcpioctl.h>
#include <drivers/afd/shared.h>

/* Control codes winioctl.h and ntifs.h hide behind the Windows version or the kernel headers */
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_MARK_HANDLE
#define FSCTL_MARK_HANDLE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 63, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* Native layouts of the file system control buffers that hold a handle (MOVE_FILE_DATA, DUPLICATE_EXTENTS_DATA
 * and MARK_HANDLE_INFO). Declared here because winioctl.h and ntifs.h hide them behind the Windows version. */
typedef struct
{
    HANDLE FileHandle;
    LARGE_INTEGER StartingVcn;
    LARGE_INTEGER StartingLcn;
    ULONG ClusterCount;
} WOW64_MOVE_FILE_DATA;

typedef struct
{
    HANDLE FileHandle;
    LARGE_INTEGER SourceFileOffset;
    LARGE_INTEGER TargetFileOffset;
    LARGE_INTEGER ByteCount;
} WOW64_DUPLICATE_EXTENTS_DATA;

typedef struct
{
    ULONG UsnSourceInfo;
    HANDLE VolumeHandle;
    ULONG HandleInfo;
} WOW64_MARK_HANDLE_INFO;

enum
{
#define WOW64_SYSCALL(Name, Source, Target, SourceSlots, TargetSlots, Flags) W64_##Name = Source,
#include <reactos/wow64/nt32to64.inc>
#undef WOW64_SYSCALL
};

static const char *ServiceNames[] =
{
#define WOW64_SYSCALL(Name, Source, Target, SourceSlots, TargetSlots, Flags) #Name,
#include <reactos/wow64/nt32to64.inc>
#undef WOW64_SYSCALL
};

/* The number of 32-bit argument slots of each service */
static const UCHAR ServiceSlots[] =
{
#define WOW64_SYSCALL(Name, Source, Target, SourceSlots, TargetSlots, Flags) SourceSlots,
#include <reactos/wow64/nt32to64.inc>
#undef WOW64_SYSCALL
};

/* Large enough for every service (the most is 17) */
#define WOW64_MAX_ARGUMENTS 24

static ULONG ServiceArgumentCount(ULONG Number)
{
    ULONG Count;
    if (Number < RTL_NUMBER_OF(ServiceSlots)) Count = ServiceSlots[Number];
    else switch (Number)
    {
    case WOW64_SERVICE_CSR: Count = 2; break;            /* CsrWow64Call@8 */
    case 0x10001: Count = 4; break;                      /* RtlpWow64GetNativeSystemInformation@16 */
    case 0x10002: Count = 2; break;                      /* RtlpWow64EnableFsRedirectionEx@8 */
    case WOW64_SERVICE_CREATE_PROCESS: Count = 1; break; /* RtlWow64CreateProcess@4 */
    default: Count = 0; break;
    }
    return min(Count, WOW64_MAX_ARGUMENTS);
}

static const char *ServiceName(ULONG Service)
{
    if (Service < RTL_NUMBER_OF(ServiceNames)) return ServiceNames[Service];
    if (Service == WOW64_SERVICE_CSR) return "CsrClientCallServer";
    if (Service == WOW64_SERVICE_CREATE_PROCESS) return "CreateProcess";
    return "unknown";
}

/* Keys of the reported requests, never 0. When the table is full, further new
 * items are summarized by a single line instead of being printed on every call. */
static volatile LONG64 ReportedKeys[512];
static volatile LONG ReportedFull;

BOOLEAN Wow64FirstReport(ULONG Service, ULONG Kind, ULONG Value)
{
    LONG64 Key;
    ULONG i;
    /* A guest can pass any service number: one bucket for those outside the known
     * ranges, keyed by the number itself */
    if (Service >= RTL_NUMBER_OF(ServiceNames) && Service != WOW64_SERVICE_CSR &&
        Service != WOW64_SERVICE_CREATE_PROCESS)
    {
        Value = Service;
        Service = 0xfffff;
    }
    Key = (LONG64)(0x8000000000000000ULL | ((ULONG64)Service << 36) | ((ULONG64)(Kind & 0xf) << 32) | Value);
    for (i = 0; i < RTL_NUMBER_OF(ReportedKeys); ++i)
    {
        LONG64 Old = ReportedKeys[i];
        if (!Old) Old = InterlockedCompareExchange64(&ReportedKeys[i], Key, 0);
        if (!Old) return TRUE;
        if (Old == Key) return FALSE;
    }
    if (!InterlockedExchange(&ReportedFull, 1))
        DbgPrint("WoW64: more than %lu unsupported items, no further ones are reported, pid %lx\n",
                 (ULONG)RTL_NUMBER_OF(ReportedKeys), HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess));
    return FALSE;
}

NTSTATUS Wow64Unsupported(ULONG Service, ULONG Kind, ULONG Value, BOOLEAN *Reported)
{
    static const char *Kinds[] = {"class", "class", "ioctl", "fsctl", "mode", "attribute", "api", "server", "operation"};
    *Reported = TRUE;
    if (Wow64FirstReport(Service, Kind, Value))
    {
        if (Kind == WOW64_UNSUPPORTED_SERVICE)
            DbgPrint("WoW64: unsupported service %lx (%s) class %lu, pid %lx\n", Service,
                     ServiceName(Service), Value, HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess));
        else
            DbgPrint(Kind == WOW64_UNSUPPORTED_CLASS || Kind == WOW64_UNSUPPORTED_CSR_SERVER ||
                     Kind == WOW64_UNSUPPORTED_OPERATION ? "WoW64: unsupported %s (%lx) %s %lu, pid %lx\n" :
                     "WoW64: unsupported %s (%lx) %s 0x%08lx, pid %lx\n", ServiceName(Service), Service,
                     Kind < RTL_NUMBER_OF(Kinds) ? Kinds[Kind] : "value", Value,
                     HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess));
    }
    return Kind == WOW64_UNSUPPORTED_SERVICE || Kind == WOW64_UNSUPPORTED_OPERATION ?
           STATUS_INVALID_SYSTEM_SERVICE : STATUS_NOT_SUPPORTED;
}

static UNICODE_STRING *String32(UNICODE_STRING *To, const WOW64_STRING *From)
{
    if (!From) return NULL;
    To->Length = From->Length;
    To->MaximumLength = From->MaximumLength;
    To->Buffer = PTR32(From->Buffer);
    return To;
}

static PSECURITY_DESCRIPTOR Security32(SECURITY_DESCRIPTOR *To, PSECURITY_DESCRIPTOR From)
{
    /* Self-relative descriptors have a fixed-width representation. Absolute
     * descriptors instead contain four guest pointers (NLS and registry APIs
     * routinely pass them). The kernel still captures/probes the SID/ACLs. */
    if (From && !(((PISECURITY_DESCRIPTOR)From)->Control & SE_SELF_RELATIVE))
    {
        const SECURITY_DESCRIPTOR_RELATIVE *FromSd = From;
        To->Revision = FromSd->Revision;
        To->Sbz1 = FromSd->Sbz1;
        To->Control = FromSd->Control;
        To->Owner = PTR32(FromSd->Owner);
        To->Group = PTR32(FromSd->Group);
        To->Sacl = PTR32(FromSd->Sacl);
        To->Dacl = PTR32(FromSd->Dacl);
        return To;
    }
    return From;
}

static NTSTATUS Attributes32(OBJECT_ATTRIBUTES *To, UNICODE_STRING *Name,
                             SECURITY_DESCRIPTOR *Descriptor, ULONG Address)
{
    const WOW64_OBJECT_ATTRIBUTES *From = PTR32(Address);
    RtlZeroMemory(To, sizeof(*To));
    if (!From) return STATUS_SUCCESS;
    if (From->Length != sizeof(*From)) return STATUS_INVALID_PARAMETER;
    InitializeObjectAttributes(To, String32(Name, PTR32(From->ObjectName)),
                               From->Attributes, HANDLE32(From->RootDirectory),
                               Security32(Descriptor, PTR32(From->SecurityDescriptor)));
    To->SecurityQualityOfService = PTR32(From->SecurityQualityOfService);
    return STATUS_SUCCESS;
}

static VOID StoreIo(ULONG Address, const IO_STATUS_BLOCK *Io)
{
    WOW64_IOSB *To = PTR32(Address);
    if (To)
    {
        To->Status = Io->Status;
        To->Information = (ULONG)Io->Information;
    }
}

/* Resources remain owned here until every translated output was copied.
 * Native calls only see native temporaries, so their own output probes cannot
 * validate the guest destinations. */
typedef struct
{
    HANDLE Handle;
    HANDLE HandleProcess;
    HANDLE Process;
    PVOID Base;
    BOOLEAN Mapped;
    PVOID Buffer;
    HANDLE Thread;
    HANDLE ThreadProcess;
    BOOLEAN Reported; /* an unsupported request, already reported once */
} WOW64_CLEANUP;

/* The records of the classes that carry a target name: FileRenameInformation, FileLinkInformation,
 * FileMoveClusterInformation and the Ex and bypass variants. Flags is a BOOLEAN ReplaceIfExists
 * (a cluster count for FileMoveClusterInformation) in the classic classes and a ULONG in the Ex ones. */
typedef struct
{
    ULONG Flags, Root, Length;
    WCHAR Name[1];
} WOW64_RENAME_INFORMATION;
C_ASSERT(sizeof(WOW64_RENAME_INFORMATION) == 16);

typedef struct { ULONG Port, Key; } WOW64_COMPLETION_INFORMATION;
typedef struct { ULONG Handle, Flags; } WOW64_HANDLE_FLAGS_INFORMATION;
typedef struct { ULONG Pointer, Length; } WOW64_POINTER_LENGTH_INFORMATION;
typedef struct { ULONG DestinationFile, Length; UCHAR Data[1]; } WOW64_TRACKING_INFORMATION;

typedef struct
{
    LARGE_INTEGER PerProcessUserTimeLimit, PerJobUserTimeLimit;
    ULONG LimitFlags, MinimumWorkingSetSize, MaximumWorkingSetSize;
    ULONG ActiveProcessLimit, Affinity, PriorityClass, SchedulingClass;
} WOW64_JOB_BASIC_LIMIT;

typedef struct
{
    WOW64_JOB_BASIC_LIMIT Basic;
    IO_COUNTERS IoInfo;
    ULONG ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
} WOW64_JOB_EXTENDED_LIMIT;
C_ASSERT(sizeof(WOW64_JOB_BASIC_LIMIT) == 48);
/* NtPowerInformation records passed through unchanged */
C_ASSERT(sizeof(SYSTEM_BATTERY_STATE) == 32);
C_ASSERT(sizeof(SYSTEM_POWER_CAPABILITIES) == 76);
C_ASSERT(sizeof(PROCESSOR_POWER_INFORMATION) == 24);
C_ASSERT(sizeof(EXECUTION_STATE) == 4);
C_ASSERT(sizeof(WOW64_JOB_EXTENDED_LIMIT) == 112);

/* The 32-bit loader's PROCESS_TLS_INFORMATION (16-byte entries) as a native
 * request with PROCESS_TLS_WOW64, so the kernel changes the TEB32 vectors of
 * the threads. The request is checked as writable guest memory and read once;
 * results go back per entry. The loader holds its lock and owns the request,
 * so only the process unmapping it meanwhile can still lose the results (as
 * for the native caller, see PspSetProcessTlsInformation). */
typedef struct { ULONG Flags, NewTlsData, OldTlsData, ThreadId; } WOW64_THREAD_TLS_INFORMATION;
C_ASSERT(sizeof(WOW64_THREAD_TLS_INFORMATION) == 16);
C_ASSERT(FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData) == 16);


/* Read one byte per page, plus the last byte, so that a bad guest range faults here under
 * the dispatcher SEH instead of in the kernel after the request was queued */
VOID ProbeInput(ULONG Address, ULONG Size)
{
    volatile const UCHAR *Bytes = PTR32(Address);
    ULONG i;
    UCHAR Sink = 0;
    if (!Size) return;
    for (i = 0; i < Size; i += PAGE_SIZE)
        Sink |= Bytes[i];
    Sink |= Bytes[Size - 1];
    (void)Sink;
}

/* Size bytes at a guest address lie below the guest's highest address */
static BOOLEAN GuestRange32(ULONG Address, ULONG64 Size)
{
    return (ULONG64)Address + Size <= (ULONG64)Wow64HighestUserAddress + 1;
}

/* A range a guest names for a memory service: it starts and ends inside the guest's address space. The
 * memory above (the layer's own allocations, below 4 GiB for a process that is not large address aware)
 * is not the guest's to allocate, free, protect, lock, map or unmap. */
static BOOLEAN GuestMemoryRange(PVOID Base, ULONG64 Size)
{
    ULONG64 Start = (ULONG_PTR)Base;

    return Start <= Wow64HighestUserAddress && Start + Size <= (ULONG64)Wow64HighestUserAddress + 1;
}

/*
 * The status of a refused range, as Windows 10 22H2 gives it to a 32-bit process (measured, with and
 * without large address awareness): a range that reaches into the memory above the highest address is
 * a conflict with it for an allocation, a protection change, a free or a mapping, and a range that
 * starts above is an invalid parameter for a protection change, a free in the 64 KiB that the layer
 * reserves, and a mapping; it is a conflict for an allocation, an unallocated address for a free
 * elsewhere above, a view that is not mapped for an unmap and an access violation for a lock.
 */
enum { GuestMemoryAlloc, GuestMemoryProtect, GuestMemoryFree, GuestMemoryLock, GuestMemoryMap, GuestMemoryUnmap };

static NTSTATUS GuestMemoryRefused(ULONG Operation, PVOID Base)
{
    ULONG64 Start = (ULONG_PTR)Base;

    if (Start <= Wow64HighestUserAddress) return STATUS_CONFLICTING_ADDRESSES;
    switch (Operation)
    {
    case GuestMemoryAlloc: return STATUS_CONFLICTING_ADDRESSES;
    case GuestMemoryFree:
        return Start <= (ULONG64)Wow64HighestUserAddress + 0x10000 ? STATUS_INVALID_PARAMETER : STATUS_MEMORY_NOT_ALLOCATED;
    case GuestMemoryLock: return STATUS_ACCESS_VIOLATION;
    case GuestMemoryUnmap: return STATUS_NOT_MAPPED_VIEW;
    default: return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS SetProcessTls32(HANDLE Process, ULONG Address, ULONG Length, WOW64_CLEANUP *Cleanup)
{
    PROCESS_TLS_INFORMATION *Guest = PTR32(Address), *Native;
    WOW64_THREAD_TLS_INFORMATION *Entries = (PVOID)((PUCHAR)Guest + FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData));
    ULONG Flags, Count, i;
    SIZE_T Size;
    NTSTATUS Status;

    if (Length < FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData)) return STATUS_INFO_LENGTH_MISMATCH;
    if ((ULONG64)Address + Length > (ULONG64)Wow64HighestUserAddress + 1) return STATUS_INVALID_PARAMETER;
    Flags = Guest->Flags;
    Count = Guest->ThreadDataCount;
    /* Only this layer asks for the 32-bit vectors */
    if (Flags & PROCESS_TLS_WOW64) return STATUS_INVALID_PARAMETER;
    if (Count > (Length - FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData)) / sizeof(*Entries) ||
        Count > (MAXULONG - FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData)) / sizeof(THREAD_TLS_INFORMATION))
        return STATUS_INVALID_PARAMETER;
    /* The whole guest request must be guest memory and writable before any
     * thread's TLS changes: the results are written back afterwards */
    ProbeOutput(Address, FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData) + Count * sizeof(*Entries));
    Size = FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData) + (SIZE_T)Count * sizeof(THREAD_TLS_INFORMATION);
    Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Native) return STATUS_NO_MEMORY;
    Native->Flags = Flags | PROCESS_TLS_WOW64;
    Native->OperationType = Guest->OperationType;
    Native->ThreadDataCount = Count;
    Native->TlsIndex = Guest->TlsIndex;
    for (i = 0; i < Count; ++i)
        Native->ThreadData[i].NewTlsData = UlongToPtr(Entries[i].NewTlsData);
    Status = NtSetInformationProcess(Process, ProcessTlsInformation, Native, (ULONG)Size);
    for (i = 0; i < Count; ++i)
    {
        Entries[i].Flags = Native->ThreadData[i].Flags;
        if (Native->ThreadData[i].Flags & THREAD_TLS_INFORMATION_ASSIGNED)
        {
            Entries[i].OldTlsData = PtrToUlong(Native->ThreadData[i].OldTlsData);
            Entries[i].ThreadId = HandleToUlong(Native->ThreadData[i].ThreadId);
        }
    }
    Guest->ThreadDataCount = Native->ThreadDataCount;
    return Status;
}

VOID ProbeOutput(ULONG Address, ULONG Size)
{
    /* A locked compare-exchange of a byte with its own value is a write the
     * hardware performs atomically: it faults on read-only or unmapped memory
     * but cannot lose a concurrent store by another guest thread (a plain
     * read then write-back could). One byte per page, plus the last byte,
     * covers every page of the range. */
    volatile CHAR *Bytes = PTR32(Address);
    ULONG i;
    if (!Size) return;
    for (i = 0; i < Size; i += PAGE_SIZE)
        _InterlockedCompareExchange8(&Bytes[i], 0, 0);
    _InterlockedCompareExchange8(&Bytes[Size - 1], 0, 0);
}

/* Size bytes at a guest address lie below the guest's highest address */
BOOLEAN GuestSpan(ULONG Address, ULONG64 Size)
{
    return (ULONG64)Address + Size <= (ULONG64)Wow64HighestUserAddress + 1;
}

/* A handle output of a failed call becomes NULL. Windows' WoW64 layer stores NULL whatever the
 * native service left in its output (measured on Windows 10 22H2 for the open and create services,
 * NtDuplicateObject, the token services and NtCreateThread; the native 64-bit services often leave
 * the variable alone). 32-bit code that closes an unchecked handle after a failed open would
 * otherwise close whatever the variable held, possibly a live handle of the process. The address
 * was probed before the call; the store is still checked against the guest range and guarded, so
 * a page the guest released meanwhile only loses the NULL and never changes the status. */
static VOID StoreNullHandle32(ULONG Address)
{
    if (!Address || !GuestSpan(Address, sizeof(ULONG))) return;
    _SEH2_TRY
    {
        *(volatile ULONG *)PTR32(Address) = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;
}

/* Hand the handle a native call created to the guest, or NULL when the call failed. A fault while
 * storing a created handle leaves it in Cleanup, so Wow64SystemServiceFull closes it. */
static NTSTATUS ReturnHandle32(ULONG Address, NTSTATUS Status, WOW64_CLEANUP *Cleanup)
{
    if (NT_SUCCESS(Status))
    {
        *(ULONG *)PTR32(Address) = HandleToUlong(Cleanup->Handle);
        Cleanup->Handle = NULL;
        return Status;
    }
    /* Failed native calls do not transfer handle ownership */
    Cleanup->Handle = NULL;
    StoreNullHandle32(Address);
    return Status;
}

/*
 * IOCTL_AFD_GET_CONTEXT of a 32-bit msafd. AFD answers with its own SOCK_SHARED_INFO
 * (the one it keeps the socket state in) only when the output buffer has exactly the
 * native size; otherwise it returns the opaque blob the guest stored with SET_CONTEXT,
 * whose State never changes after an accept. SO_UPDATE_ACCEPT_CONTEXT and
 * SO_UPDATE_CONNECT_CONTEXT read the State to learn that AcceptEx or ConnectEx connected
 * the socket, so a guest that asks with its own, smaller, structure size gets AFD's
 * structure converted to the guest layout: the same fields, hWnd narrowed to 32 bits.
 */
#define WOW64_SOCK_SHARED_INFO_SIZE 140
#define WOW64_SOCK_SHARED_HEAD      (FIELD_OFFSET(SOCK_SHARED_INFO, SocketLastError) + sizeof(INT))
#define WOW64_SOCK_SHARED_TAIL      (FIELD_OFFSET(SOCK_SHARED_INFO, WSRemoteAddress) + sizeof(SOCKADDR) - \
                                     FIELD_OFFSET(SOCK_SHARED_INFO, Unknown))
C_ASSERT(WOW64_SOCK_SHARED_HEAD == 84);
C_ASSERT(WOW64_SOCK_SHARED_TAIL == 52);
C_ASSERT(WOW64_SOCK_SHARED_HEAD + sizeof(ULONG) + WOW64_SOCK_SHARED_TAIL == WOW64_SOCK_SHARED_INFO_SIZE);

static NTSTATUS AfdGetContext32(const ULONG *a)
{
    SOCK_SHARED_INFO Native;
    IO_STATUS_BLOCK Io = {{0}};
    UCHAR *Guest = PTR32(a[8]);
    NTSTATUS Status;

    ProbeOutput(a[8], WOW64_SOCK_SHARED_INFO_SIZE);
    ProbeOutput(a[4], sizeof(WOW64_IOSB));
    RtlZeroMemory(&Native, sizeof(Native));
    /* AFD completes this request inline; the guest's event is still signalled by the kernel. */
    Status = NtDeviceIoControlFile(HANDLE32(a[0]), HANDLE32(a[1]), NULL, NULL, &Io, IOCTL_AFD_GET_CONTEXT,
                                   NULL, 0, &Native, sizeof(Native));
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(HANDLE32(a[0]), FALSE, NULL);
        Status = Io.Status;
    }
    if (NT_SUCCESS(Status))
    {
        ULONG Hwnd = PtrToUlong(Native.hWnd);
        RtlCopyMemory(Guest, &Native, WOW64_SOCK_SHARED_HEAD);
        RtlCopyMemory(Guest + WOW64_SOCK_SHARED_HEAD, &Hwnd, sizeof(Hwnd));
        RtlCopyMemory(Guest + WOW64_SOCK_SHARED_HEAD + sizeof(Hwnd), &Native.Unknown, WOW64_SOCK_SHARED_TAIL);
        Io.Information = WOW64_SOCK_SHARED_INFO_SIZE;
    }
    StoreIo(a[4], &Io);
    return Status;
}

/* The handle refers to the calling process */
static BOOLEAN IsCurrentProcess(HANDLE Process)
{
    PROCESS_BASIC_INFORMATION Info;
    if (Process == NtCurrentProcess()) return TRUE;
    return NT_SUCCESS(NtQueryInformationProcess(Process, ProcessBasicInformation, &Info, sizeof(Info), NULL)) &&
           Info.UniqueProcessId == (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
}

/* MemorySectionName: the guest's counted-string header is 8 bytes. Query the native form into a
 * scratch buffer that holds any name, then apply the guest's buffer size as Windows WoW64 does
 * (measured on Server 2008 R2 and Windows 10): an address above the guest's range is invalid; a
 * buffer smaller than the header fails with STATUS_INFO_LENGTH_MISMATCH and one smaller than
 * header, name and terminator with STATUS_BUFFER_OVERFLOW, both with only the required length
 * stored; otherwise the header, the name and its terminator. The buffer need not be aligned. */
static NTSTATUS SectionName32(HANDLE Process, ULONG Address, ULONG Buffer, ULONG Length,
                              ULONG ReturnLength, WOW64_CLEANUP *Cleanup)
{
    /* The native MaximumLength is a USHORT: keep it even and below 64 KiB */
    const ULONG NativeLength = sizeof(MEMORY_SECTION_NAME) + MAXUSHORT + 1;
    MEMORY_SECTION_NAME *Native;
    WOW64_STRING UNALIGNED *Guest = PTR32(Buffer);
    SIZE_T Bytes = 0;
    ULONG Needed;
    NTSTATUS Status;

    if (Address > Wow64HighestUserAddress) return STATUS_INVALID_PARAMETER;
    if (ReturnLength)
    {
        if (!GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(ReturnLength, sizeof(ULONG));
    }
    Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeLength);
    if (!Native) return STATUS_NO_MEMORY;
    Status = NtQueryVirtualMemory(Process, PTR32(Address), MemorySectionName, Native, NativeLength, &Bytes);
    if (!NT_SUCCESS(Status)) return Status;
    /* The guest MaximumLength (Length + 2) must fit a USHORT */
    if (Native->SectionFileName.Length > MAXUSHORT - sizeof(WCHAR)) return STATUS_NAME_TOO_LONG;
    Needed = sizeof(WOW64_STRING) + Native->SectionFileName.Length + sizeof(WCHAR);
    if (Length < Needed)
    {
        if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = Needed;
        return Length < sizeof(WOW64_STRING) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_BUFFER_OVERFLOW;
    }
    /* Writable before anything is stored, so a fault leaves no partial header */
    if (!Buffer || !GuestSpan(Buffer, Needed)) return STATUS_ACCESS_VIOLATION;
    ProbeOutput(Buffer, Needed);
    Guest->Length = Native->SectionFileName.Length;
    Guest->MaximumLength = Native->SectionFileName.Length + sizeof(WCHAR);
    Guest->Buffer = Buffer + sizeof(WOW64_STRING);
    RtlCopyMemory((PUCHAR)Guest + sizeof(WOW64_STRING), Native->SectionFileName.Buffer, Native->SectionFileName.Length);
    *(WCHAR UNALIGNED *)((PUCHAR)Guest + Needed - sizeof(WCHAR)) = UNICODE_NULL;
    /* Last, as the native service does, in case it lies inside the buffer */
    if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = Needed;
    return STATUS_SUCCESS;
}

/* MemoryWorkingSetInformation (class 1) of a 32-bit caller: the count and the entries are ULONGs and only the pages
 * below the guest's highest address are listed (the low 12 bits keep the attributes). Measured on Windows 10 22H2:
 * a buffer of fewer than 4 bytes fails with STATUS_INFO_LENGTH_MISMATCH, a buffer too small for the list gets only
 * the count, BaseAddress above the guest's range is invalid, and ReturnLength is the size of the list. */
static NTSTATUS WorkingSetList32(HANDLE Process, ULONG Address, ULONG Buffer, ULONG Length, ULONG ReturnLength,
                                 WOW64_CLEANUP *Cleanup)
{
    SIZE_T NativeSize = 0x10000, Bytes;
    ULONG_PTR *List;
    ULONG Count = 0, Needed, i, Pass;
    ULONG UNALIGNED *Guest = PTR32(Buffer);
    NTSTATUS Status;

    if (Length < sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
    if (Address > Wow64HighestUserAddress) return STATUS_INVALID_PARAMETER;
    if (ReturnLength)
    {
        if (!GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(ReturnLength, sizeof(ULONG));
    }
    if (!GuestSpan(Buffer, Length)) return STATUS_ACCESS_VIOLATION;
    ProbeOutput(Buffer, Length);

    for (Pass = 0; ; Pass++)
    {
        if (Cleanup->Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, Cleanup->Buffer);
        List = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeSize);
        if (!List) return STATUS_NO_MEMORY;
        Status = NtQueryVirtualMemory(Process, NULL, 1 /* MemoryWorkingSetInformation */, List, NativeSize, &Bytes);
        if (Status != STATUS_INFO_LENGTH_MISMATCH) break;
        /* The list grows while it is being asked for: leave room */
        NativeSize = sizeof(ULONG_PTR) + ((SIZE_T)List[0] + 256 * (Pass + 1)) * sizeof(ULONG_PTR);
        if (Pass >= 16) return Status;
    }
    if (!NT_SUCCESS(Status)) return Status;

    for (i = 0; i < List[0]; i++)
        if ((List[1 + i] & ~(ULONG_PTR)(PAGE_SIZE - 1)) <= Wow64HighestUserAddress) Count++;
    Needed = sizeof(ULONG) + Count * sizeof(ULONG);
    *Guest = Count;
    if (Length < Needed) return STATUS_INFO_LENGTH_MISMATCH;

    Count = 0;
    for (i = 0; i < List[0]; i++)
    {
        if ((List[1 + i] & ~(ULONG_PTR)(PAGE_SIZE - 1)) <= Wow64HighestUserAddress)
            Guest[1 + Count++] = (ULONG)List[1 + i];
    }
    *Guest = Count;
    if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = sizeof(ULONG) + Count * sizeof(ULONG);
    return STATUS_SUCCESS;
}

static ULONG Narrow(SIZE_T Value);

/* MemoryWorkingSetExInformation (class 4) of a 32-bit caller: an array of {ULONG VirtualAddress, ULONG attributes}
 * (8 bytes); a buffer of fewer than 8 bytes fails with STATUS_INFO_LENGTH_MISMATCH, a trailing partial entry is
 * ignored and ReturnLength is the size of the whole entries (measured on Windows 10 22H2 under WoW64). */
static NTSTATUS WorkingSetEx32(HANDLE Process, ULONG Buffer, ULONG Length, ULONG ReturnLength)
{
    struct { PVOID VirtualAddress; ULONG_PTR Attributes; } Native[32];
    ULONG UNALIGNED *Guest = PTR32(Buffer);
    ULONG Count = Length / 8, Done = 0, Batch, i;
    NTSTATUS Status;

    if (Length < 8) return STATUS_INFO_LENGTH_MISMATCH;
    if (ReturnLength)
    {
        if (!GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(ReturnLength, sizeof(ULONG));
    }
    if (!GuestSpan(Buffer, Count * 8)) return STATUS_ACCESS_VIOLATION;
    ProbeOutput(Buffer, Count * 8);

    while (Done < Count)
    {
        Batch = min(Count - Done, (ULONG)RTL_NUMBER_OF(Native));
        for (i = 0; i < Batch; i++)
        {
            Native[i].VirtualAddress = (PVOID)(ULONG_PTR)Guest[2 * (Done + i)];
            Native[i].Attributes = 0;
        }
        Status = NtQueryVirtualMemory(Process, NULL, 4 /* MemoryWorkingSetExInformation */, Native,
                                      Batch * sizeof(Native[0]), NULL);
        if (!NT_SUCCESS(Status)) return Status;
        for (i = 0; i < Batch; i++) Guest[2 * (Done + i) + 1] = (ULONG)Native[i].Attributes;
        Done += Batch;
    }
    if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = Count * 8;
    return STATUS_SUCCESS;
}

/* MemoryImageInformation (class 6) of a 32-bit caller: {ULONG ImageBase, ULONG SizeOfImage, ULONG ImageFlags}
 * (12 bytes, at least 12 needed). Measured on Windows 10 22H2: an address above the guest's range is invalid
 * before anything is stored; the length 12 is stored before the process and the address are looked at. */
static NTSTATUS ImageInfo32(HANDLE Process, ULONG Address, ULONG Buffer, ULONG Length, ULONG ReturnLength)
{
    struct { PVOID ImageBase; SIZE_T SizeOfImage; ULONG ImageFlags; } Native;
    ULONG UNALIGNED *Guest = PTR32(Buffer);
    NTSTATUS Status;

    if (Length < 12) return STATUS_INFO_LENGTH_MISMATCH;
    if (Address > Wow64HighestUserAddress) return STATUS_INVALID_PARAMETER;
    if (ReturnLength)
    {
        if (!GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(ReturnLength, sizeof(ULONG));
    }
    if (!GuestSpan(Buffer, 12)) return STATUS_ACCESS_VIOLATION;
    ProbeOutput(Buffer, 12);
    if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = 12;

    RtlZeroMemory(&Native, sizeof(Native));
    Status = NtQueryVirtualMemory(Process, PTR32(Address), 6 /* MemoryImageInformation */, &Native, sizeof(Native), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    Guest[0] = PtrToUlong(Native.ImageBase);
    Guest[1] = Narrow(Native.SizeOfImage);
    Guest[2] = Native.ImageFlags;
    return STATUS_SUCCESS;
}

/* NtQueryInformationProcess classes with a different or alignment-sensitive 32-bit form. Each
 * native result goes through a native temporary and is stored with the semantics measured on
 * Windows Server 2008 R2 and Windows 10 WoW64: exact lengths (VM_COUNTERS or VM_COUNTERS_EX for
 * the memory counters, only the 36-byte query form for the device map); the I/O counters must
 * be 4-byte aligned, the others need no alignment; the memory counters are ULONGs; the image
 * name has an 8-byte header and MaximumLength = Length + 2, and a short buffer fails with
 * STATUS_INFO_LENGTH_MISMATCH and the required length. The output and return length are probed
 * before the native query; the return length is stored last on success, except for the image
 * name, where it comes before the name (and is also stored for a short buffer). */
typedef struct
{
    ULONG PeakVirtualSize, VirtualSize, PageFaultCount, PeakWorkingSetSize, WorkingSetSize;
    ULONG QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
    ULONG PagefileUsage, PeakPagefileUsage, PrivateUsage;
} WOW64_VM_COUNTERS_EX;
C_ASSERT(sizeof(WOW64_VM_COUNTERS_EX) == 48);

/* QUOTA_LIMITS and QUOTA_LIMITS_EX as the 32-bit side lays them out: TimeLimit at offset 20
 * (gcc: 28 and 52 bytes) or 24 (MSVC pads the LARGE_INTEGER: 32 and 56 bytes). All four lengths
 * are accepted. GlobalMemoryStatusEx and Get/SetProcessWorkingSetSize go through this class
 * (kernel32 passes the extended form). WOW64_QUOTA_LIMITS_EX is the unpadded extended form. */
typedef struct
{
    ULONG PagedPoolLimit, NonPagedPoolLimit, MinimumWorkingSetSize, MaximumWorkingSetSize, PagefileLimit;
    ULONG TimeLimitLow, TimeLimitHigh;
    ULONG Reserved[4];
    ULONG Flags, CpuRateLimit;
} WOW64_QUOTA_LIMITS_EX;
C_ASSERT(sizeof(WOW64_QUOTA_LIMITS_EX) == 52);
#define WOW64_QUOTA_TIME_OFFSET 20

static ULONG Narrow(SIZE_T Value);

static BOOLEAN QuotaLength32(ULONG Length, BOOLEAN *Padded)
{
    switch (Length)
    {
    case 28: case 52: *Padded = FALSE; return TRUE;
    case 32: case 56: *Padded = TRUE; return TRUE;
    }
    return FALSE;
}

/* The unlimited quota (native -1) stays -1 in 32 bits; a size above 4 GiB clamps */
static ULONG NarrowQuota(SIZE_T Value)
{
    return Value == MAXULONG_PTR ? MAXULONG : Narrow(Value);
}
static SIZE_T WidenQuota(ULONG Value)
{
    return Value == MAXULONG ? MAXULONG_PTR : Value;
}
C_ASSERT(sizeof(IO_COUNTERS) == 48 && sizeof(KERNEL_USER_TIMES) == 32);
C_ASSERT(RTL_FIELD_SIZE(PROCESS_DEVICEMAP_INFORMATION, Query) == 36);

/* A counter above 4 GiB reads 0xffffffff, as on Windows WoW64 (measured on Server 2008 R2 and
 * Windows 10 for a 64-bit process with 12-16 GiB virtual, 5 GiB working set and 6 GiB commit:
 * every such counter came back as 0xffffffff with STATUS_SUCCESS) */
static ULONG Narrow(SIZE_T Value)
{
    return Value > MAXULONG ? MAXULONG : (ULONG)Value;
}

static NTSTATUS QueryProcess32(HANDLE Process, ULONG Class, ULONG Buffer, ULONG Length,
                               ULONG ReturnLength, WOW64_CLEANUP *Cleanup)
{
    union
    {
        IO_COUNTERS Io;
        KERNEL_USER_TIMES Times;
        VM_COUNTERS_EX Vm;
        QUOTA_LIMITS_EX Quota;
        PROCESS_DEVICEMAP_INFORMATION DeviceMap;
    } Native;
    ULONG Size;
    NTSTATUS Status;

    if (ReturnLength)
    {
        if (!GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(ReturnLength, sizeof(ULONG));
    }
    switch (Class)
    {
    case ProcessIoCounters: Size = sizeof(Native.Io); break;
    case ProcessTimes: Size = sizeof(Native.Times); break;
    case ProcessVmCounters:
        Size = Length == FIELD_OFFSET(WOW64_VM_COUNTERS_EX, PrivateUsage) ? Length : sizeof(WOW64_VM_COUNTERS_EX);
        break;
    case ProcessDeviceMap: Size = RTL_FIELD_SIZE(PROCESS_DEVICEMAP_INFORMATION, Query); break;
    case ProcessQuotaLimits:
    {
        BOOLEAN Padded;
        if (!QuotaLength32(Length, &Padded)) return STATUS_INFO_LENGTH_MISMATCH;
        Size = Length;
        break;
    }
    case ProcessImageFileName:
    {
        /* The native MaximumLength is a USHORT: the scratch buffer holds any name */
        const ULONG NativeLength = sizeof(UNICODE_STRING) + MAXUSHORT;
        UNICODE_STRING *Name;
        WOW64_STRING UNALIGNED *Guest = PTR32(Buffer);
        ULONG Needed;
        Name = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeLength);
        if (!Name) return STATUS_NO_MEMORY;
        Status = NtQueryInformationProcess(Process, Class, Name, NativeLength, NULL);
        if (!NT_SUCCESS(Status)) return Status;
        if (Name->Length > MAXUSHORT - sizeof(WCHAR)) return STATUS_NAME_TOO_LONG;
        Needed = sizeof(WOW64_STRING) + Name->Length + sizeof(WCHAR);
        if (Length < Needed)
        {
            if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = Needed;
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        /* Writable before anything is stored, so a fault leaves no partial header */
        if (!Buffer || !GuestSpan(Buffer, Needed)) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(Buffer, Needed);
        /* Windows WoW64 stores the return length before the name (a return length inside
         * the buffer is overwritten by the name) */
        if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = Needed;
        Guest->Length = Name->Length;
        Guest->MaximumLength = Name->Length + sizeof(WCHAR);
        Guest->Buffer = Buffer + sizeof(WOW64_STRING);
        RtlCopyMemory((PUCHAR)Guest + sizeof(WOW64_STRING), Name->Buffer, Name->Length);
        *(WCHAR UNALIGNED *)((PUCHAR)Guest + Needed - sizeof(WCHAR)) = UNICODE_NULL;
        return STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_INFO_CLASS;
    }
    if (Length != Size) return STATUS_INFO_LENGTH_MISMATCH;
    if (Class == ProcessIoCounters && (Buffer & (sizeof(ULONG) - 1))) return STATUS_DATATYPE_MISALIGNMENT;
    if (!Buffer || !GuestSpan(Buffer, Size)) return STATUS_ACCESS_VIOLATION;
    ProbeOutput(Buffer, Size);
    switch (Class)
    {
    case ProcessVmCounters:
    {
        WOW64_VM_COUNTERS_EX Guest;
        Status = NtQueryInformationProcess(Process, Class, &Native.Vm, sizeof(Native.Vm), NULL);
        if (!NT_SUCCESS(Status)) return Status;
        Guest.PeakVirtualSize = Narrow(Native.Vm.PeakVirtualSize);
        Guest.VirtualSize = Narrow(Native.Vm.VirtualSize);
        Guest.PageFaultCount = Native.Vm.PageFaultCount;
        Guest.PeakWorkingSetSize = Narrow(Native.Vm.PeakWorkingSetSize);
        Guest.WorkingSetSize = Narrow(Native.Vm.WorkingSetSize);
        Guest.QuotaPeakPagedPoolUsage = Narrow(Native.Vm.QuotaPeakPagedPoolUsage);
        Guest.QuotaPagedPoolUsage = Narrow(Native.Vm.QuotaPagedPoolUsage);
        Guest.QuotaPeakNonPagedPoolUsage = Narrow(Native.Vm.QuotaPeakNonPagedPoolUsage);
        Guest.QuotaNonPagedPoolUsage = Narrow(Native.Vm.QuotaNonPagedPoolUsage);
        Guest.PagefileUsage = Narrow(Native.Vm.PagefileUsage);
        Guest.PeakPagefileUsage = Narrow(Native.Vm.PeakPagefileUsage);
        Guest.PrivateUsage = Narrow(Native.Vm.PrivateUsage);
        RtlCopyMemory(PTR32(Buffer), &Guest, Size);
        break;
    }
    case ProcessQuotaLimits:
    {
        WOW64_QUOTA_LIMITS_EX Guest;
        BOOLEAN Padded;
        PUCHAR Out = PTR32(Buffer);
        QuotaLength32(Size, &Padded);
        Status = NtQueryInformationProcess(Process, Class, &Native.Quota, sizeof(Native.Quota), NULL);
        if (!NT_SUCCESS(Status)) return Status;
        RtlZeroMemory(&Guest, sizeof(Guest));
        Guest.PagedPoolLimit = NarrowQuota(Native.Quota.PagedPoolLimit);
        Guest.NonPagedPoolLimit = NarrowQuota(Native.Quota.NonPagedPoolLimit);
        Guest.MinimumWorkingSetSize = NarrowQuota(Native.Quota.MinimumWorkingSetSize);
        Guest.MaximumWorkingSetSize = NarrowQuota(Native.Quota.MaximumWorkingSetSize);
        Guest.PagefileLimit = NarrowQuota(Native.Quota.PagefileLimit);
        Guest.TimeLimitLow = Native.Quota.TimeLimit.LowPart;
        Guest.TimeLimitHigh = Native.Quota.TimeLimit.HighPart;
        Guest.Flags = Native.Quota.Flags;
        Guest.CpuRateLimit = Native.Quota.CpuRateLimit.RateData;
        if (!Padded) RtlCopyMemory(Out, &Guest, Size);
        else
        {
            RtlCopyMemory(Out, &Guest, WOW64_QUOTA_TIME_OFFSET);
            RtlZeroMemory(Out + WOW64_QUOTA_TIME_OFFSET, sizeof(ULONG));
            RtlCopyMemory(Out + WOW64_QUOTA_TIME_OFFSET + sizeof(ULONG),
                          (PUCHAR)&Guest + WOW64_QUOTA_TIME_OFFSET, Size - WOW64_QUOTA_TIME_OFFSET - sizeof(ULONG));
        }
        break;
    }
    default:
        /* The same layout for both sizes */
        Status = NtQueryInformationProcess(Process, Class, &Native, Size, NULL);
        if (!NT_SUCCESS(Status)) return Status;
        RtlCopyMemory(PTR32(Buffer), &Native, Size);
        break;
    }
    if (ReturnLength) *(ULONG UNALIGNED *)PTR32(ReturnLength) = Size;
    return STATUS_SUCCESS;
}

/* TOKEN_GROUPS classes: the 32-bit layout has 4-byte SID pointers, so query the
 * native form into a scratch buffer and rebuild it in the guest buffer. Measured on
 * Windows WOW64: the token is checked before the buffer, the buffer need not be
 * aligned, and the length is stored before the data. */
static NTSTATUS TokenGroups32(HANDLE Token, TOKEN_INFORMATION_CLASS Class, ULONG Buffer,
                              ULONG Length, ULONG ReturnLength, WOW64_CLEANUP *Cleanup)
{
    PTOKEN_GROUPS Native;
    ULONG Bytes = 0, Needed, SidBytes = 0, Offset, Sid, i;
    UCHAR *Guest;
    NTSTATUS Status;

    if (!ReturnLength || !GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    Status = NtQueryInformationToken(Token, Class, NULL, 0, &Bytes);
    if (Status != STATUS_BUFFER_TOO_SMALL) return Status;
    if (Bytes < sizeof(TOKEN_GROUPS)) Bytes = sizeof(TOKEN_GROUPS);
    Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
    if (!Native) return STATUS_NO_MEMORY;
    Status = NtQueryInformationToken(Token, Class, Native, Bytes, &Bytes);
    if (!NT_SUCCESS(Status)) return Status;
    /* Bounded by the native result, which is far below 4 GiB */
    for (i = 0; i < Native->GroupCount; ++i)
        SidBytes += RtlLengthSid(Native->Groups[i].Sid);
    Needed = sizeof(ULONG) + Native->GroupCount * 2 * sizeof(ULONG) + SidBytes;
    *(ULONG *)PTR32(ReturnLength) = Needed;
    if (Length < Needed) return STATUS_BUFFER_TOO_SMALL;
    if (!Buffer || !GuestSpan(Buffer, Needed)) return STATUS_ACCESS_VIOLATION;
    /* Unaligned stores: the guest buffer may be misaligned */
    Guest = PTR32(Buffer);
    *(ULONG UNALIGNED *)Guest = Native->GroupCount;
    Offset = sizeof(ULONG) + Native->GroupCount * 2 * sizeof(ULONG);
    for (i = 0; i < Native->GroupCount; ++i)
    {
        Sid = RtlLengthSid(Native->Groups[i].Sid);
        *(ULONG UNALIGNED *)(Guest + 4 + 8 * i) = Buffer + Offset;
        *(ULONG UNALIGNED *)(Guest + 8 + 8 * i) = Native->Groups[i].Attributes;
        RtlCopyMemory(Guest + Offset, Native->Groups[i].Sid, Sid);
        Offset += Sid;
    }
    return STATUS_SUCCESS;
}

/* TokenDefaultDacl: TOKEN_DEFAULT_DACL is one ACL pointer followed by the ACL, which has
 * no pointers. Same order as TokenGroups32. */
static NTSTATUS TokenDefaultDacl32(HANDLE Token, ULONG Buffer, ULONG Length, ULONG ReturnLength,
                                   WOW64_CLEANUP *Cleanup)
{
    PTOKEN_DEFAULT_DACL Native;
    ULONG Bytes = 0, Needed, AclBytes;
    UCHAR *Guest;
    NTSTATUS Status;

    if (!ReturnLength || !GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    Status = NtQueryInformationToken(Token, TokenDefaultDacl, NULL, 0, &Bytes);
    if (Status != STATUS_BUFFER_TOO_SMALL) return Status;
    if (Bytes < sizeof(TOKEN_DEFAULT_DACL)) Bytes = sizeof(TOKEN_DEFAULT_DACL);
    Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
    if (!Native) return STATUS_NO_MEMORY;
    Status = NtQueryInformationToken(Token, TokenDefaultDacl, Native, Bytes, &Bytes);
    if (Status == STATUS_BUFFER_TOO_SMALL && Bytes >= sizeof(TOKEN_DEFAULT_DACL))
    {
        /* The DACL grew meanwhile: report what the 32-bit form now needs */
        *(ULONG *)PTR32(ReturnLength) = Bytes - sizeof(TOKEN_DEFAULT_DACL) + sizeof(ULONG);
        return Status;
    }
    if (!NT_SUCCESS(Status)) return Status;
    AclBytes = Native->DefaultDacl ? Native->DefaultDacl->AclSize : 0;
    Needed = sizeof(ULONG) + AclBytes;
    *(ULONG *)PTR32(ReturnLength) = Needed;
    if (Length < Needed) return STATUS_BUFFER_TOO_SMALL;
    if (!Buffer || !GuestSpan(Buffer, Needed)) return STATUS_ACCESS_VIOLATION;
    Guest = PTR32(Buffer);
    *(ULONG UNALIGNED *)Guest = AclBytes ? Buffer + sizeof(ULONG) : 0;
    if (AclBytes) RtlCopyMemory(Guest + sizeof(ULONG), Native->DefaultDacl, AclBytes);
    return STATUS_SUCCESS;
}

/* A token class the 64-bit service answers in native form: query it into Cleanup->Buffer, growing if the
 * token changed between the size query and the data query. The token is checked before the guest buffer. */
static NTSTATUS TokenQueryNative(HANDLE Token, TOKEN_INFORMATION_CLASS Class, ULONG ReturnLength,
                                 WOW64_CLEANUP *Cleanup, PVOID *Native)
{
    ULONG Bytes = 0, Try;
    NTSTATUS Status;

    if (!ReturnLength || !GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    Status = NtQueryInformationToken(Token, Class, NULL, 0, &Bytes);
    for (Try = 0; Try < 4 && Status == STATUS_BUFFER_TOO_SMALL; ++Try)
    {
        if (Cleanup->Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, Cleanup->Buffer);
        Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
        if (!Cleanup->Buffer) return STATUS_NO_MEMORY;
        Status = NtQueryInformationToken(Token, Class, Cleanup->Buffer, Bytes, &Bytes);
    }
    if (NT_SUCCESS(Status)) *Native = Cleanup->Buffer;
    return Status;
}

/* The guest's length bookkeeping of a variable-size token result: the length goes out first, then the
 * buffer is checked */
static NTSTATUS TokenResult32(ULONG Buffer, ULONG Length, ULONG ReturnLength, ULONG Needed)
{
    *(ULONG UNALIGNED *)PTR32(ReturnLength) = Needed;
    if (Length < Needed) return STATUS_BUFFER_TOO_SMALL;
    if (!Buffer || !GuestSpan(Buffer, Needed)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* Bytes of Count 32-bit SID_AND_ATTRIBUTES entries and their SIDs, each SID padded to 4 bytes (the
 * layout of Windows WOW64: 13 groups take 104 + 208 bytes) */
static ULONG SidArray32Bytes(PSID_AND_ATTRIBUTES Native, ULONG Count)
{
    ULONG Bytes = Count * 8, i;
    for (i = 0; i < Count; ++i) Bytes += (RtlLengthSid(Native[i].Sid) + 3) & ~3UL;
    return Bytes;
}

/* Writes the array at Offset in the guest buffer at address Buffer; returns the offset after it */
static ULONG SidArray32Write(ULONG Buffer, ULONG Offset, PSID_AND_ATTRIBUTES Native, ULONG Count)
{
    UCHAR *Guest = PTR32(Buffer);
    ULONG Sids = Offset + Count * 8, Length, i;

    for (i = 0; i < Count; ++i)
    {
        Length = RtlLengthSid(Native[i].Sid);
        *(ULONG UNALIGNED *)(Guest + Offset + 8 * i) = Buffer + Sids;
        *(ULONG UNALIGNED *)(Guest + Offset + 8 * i + 4) = Native[i].Attributes;
        RtlCopyMemory(Guest + Sids, Native[i].Sid, Length);
        Sids += (Length + 3) & ~3UL;
    }
    return Sids;
}

/* TokenGroupsAndPrivileges: nine ULONGs and a LUID, then the user and groups, the restricted SIDs and the
 * privileges (Windows WOW64 layout, measured). Windows under-reports the length of a successful result and
 * reports the 64-bit size for a short buffer; this reports the real 32-bit size both times. */
static NTSTATUS TokenGroupsAndPrivileges32(HANDLE Token, ULONG Buffer, ULONG Length, ULONG ReturnLength,
                                           WOW64_CLEANUP *Cleanup)
{
    PTOKEN_GROUPS_AND_PRIVILEGES Native;
    ULONG SidLength, RestrictedLength, PrivilegesLength, Needed, Offset, *Out;
    NTSTATUS Status;

    Status = TokenQueryNative(Token, TokenGroupsAndPrivileges, ReturnLength, Cleanup, (PVOID *)&Native);
    if (!NT_SUCCESS(Status)) return Status;
    SidLength = SidArray32Bytes(Native->Sids, Native->SidCount);
    RestrictedLength = Native->RestrictedSidCount ? SidArray32Bytes(Native->RestrictedSids, Native->RestrictedSidCount) : 0;
    PrivilegesLength = Native->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES);
    Needed = 11 * sizeof(ULONG) + SidLength + RestrictedLength + PrivilegesLength;
    Status = TokenResult32(Buffer, Length, ReturnLength, Needed);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(PTR32(Buffer), Needed);
    Out = PTR32(Buffer);
    Offset = 11 * sizeof(ULONG);
    ((ULONG UNALIGNED *)Out)[0] = Native->SidCount;
    ((ULONG UNALIGNED *)Out)[1] = SidLength;
    ((ULONG UNALIGNED *)Out)[2] = Native->SidCount ? Buffer + Offset : 0;
    SidArray32Write(Buffer, Offset, Native->Sids, Native->SidCount);
    Offset += SidLength;
    ((ULONG UNALIGNED *)Out)[3] = Native->RestrictedSidCount;
    ((ULONG UNALIGNED *)Out)[4] = RestrictedLength;
    if (Native->RestrictedSidCount)
    {
        ((ULONG UNALIGNED *)Out)[5] = Buffer + Offset;
        SidArray32Write(Buffer, Offset, Native->RestrictedSids, Native->RestrictedSidCount);
        Offset += RestrictedLength;
    }
    ((ULONG UNALIGNED *)Out)[6] = Native->PrivilegeCount;
    ((ULONG UNALIGNED *)Out)[7] = PrivilegesLength;
    if (Native->PrivilegeCount)
    {
        ((ULONG UNALIGNED *)Out)[8] = Buffer + Offset;
        RtlCopyMemory((UCHAR *)Out + Offset, Native->Privileges, PrivilegesLength);
    }
    ((ULONG UNALIGNED *)Out)[9] = Native->AuthenticationId.LowPart;
    ((ULONG UNALIGNED *)Out)[10] = Native->AuthenticationId.HighPart;
    return STATUS_SUCCESS;
}

/* The native TOKEN_ACCESS_INFORMATION of Windows 10 (the kernel's own copy of the layout); the 32-bit one
 * has 4-byte pointers, a 14 ULONG header and 136-byte SID hashes */
typedef struct
{
    PSID_AND_ATTRIBUTES_HASH SidHash;
    PSID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    PTOKEN_PRIVILEGES Privileges;
    LUID AuthenticationId;
    ULONG TokenType;
    ULONG ImpersonationLevel;
    ULONG MandatoryPolicy;
    ULONG Flags;
    ULONG AppContainerNumber;
    PSID PackageSid;
    PSID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    PSID TrustLevelSid;
    PVOID SecurityAttributes;
} NATIVE_TOKEN_ACCESS_INFORMATION;

#define ACCESS_INFO32_HEADER (14 * sizeof(ULONG))
#define SID_HASH32_BYTES ((2 + SID_HASH_SIZE) * sizeof(ULONG))

/* TokenAccessInformation: header, SID hash with its SIDs, restricted SID hash (with SIDs when there are any),
 * capability hash (with its SIDs for a lowbox token), privileges, and a lowbox token's package SID. A 32-bit
 * result of the same token has the length Windows reports (1068 bytes for 13 groups and 24 privileges). */
static NTSTATUS TokenAccessInformation32(HANDLE Token, ULONG Buffer, ULONG Length, ULONG ReturnLength,
                                         WOW64_CLEANUP *Cleanup)
{
    NATIVE_TOKEN_ACCESS_INFORMATION *Native;
    ULONG SidLength, RestrictedLength = 0, CapabilitiesLength = 0, PackageLength = 0, PrivilegesLength, Needed, Offset, i;
    UCHAR *Guest;
    NTSTATUS Status;

    Status = TokenQueryNative(Token, TokenAccessInformation, ReturnLength, Cleanup, (PVOID *)&Native);
    if (!NT_SUCCESS(Status)) return Status;
    SidLength = SidArray32Bytes(Native->SidHash->SidAttr, Native->SidHash->SidCount);
    if (Native->RestrictedSidHash->SidCount)
        RestrictedLength = SidArray32Bytes(Native->RestrictedSidHash->SidAttr, Native->RestrictedSidHash->SidCount);
    if (Native->CapabilitiesHash->SidCount)
        CapabilitiesLength = SidArray32Bytes(Native->CapabilitiesHash->SidAttr, Native->CapabilitiesHash->SidCount);
    if (Native->PackageSid) PackageLength = (RtlLengthSid(Native->PackageSid) + 3) & ~3UL;
    PrivilegesLength = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + Native->Privileges->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES);
    Needed = ACCESS_INFO32_HEADER + 3 * SID_HASH32_BYTES + SidLength + RestrictedLength + CapabilitiesLength +
             PrivilegesLength + PackageLength;
    Status = TokenResult32(Buffer, Length, ReturnLength, Needed);
    if (!NT_SUCCESS(Status)) return Status;

    Guest = PTR32(Buffer);
    RtlZeroMemory(Guest, Needed);
#define OUT32(Index) (((ULONG UNALIGNED *)Guest)[Index])
    OUT32(3) = Native->AuthenticationId.LowPart;
    OUT32(4) = Native->AuthenticationId.HighPart;
    OUT32(5) = Native->TokenType;
    OUT32(6) = Native->ImpersonationLevel;
    OUT32(7) = Native->MandatoryPolicy;
    OUT32(8) = Native->Flags;
    OUT32(9) = Native->AppContainerNumber;

    Offset = ACCESS_INFO32_HEADER;
    OUT32(0) = Buffer + Offset;
    ((ULONG UNALIGNED *)(Guest + Offset))[0] = Native->SidHash->SidCount;
    ((ULONG UNALIGNED *)(Guest + Offset))[1] = Buffer + Offset + SID_HASH32_BYTES;
    for (i = 0; i < SID_HASH_SIZE; ++i) ((ULONG UNALIGNED *)(Guest + Offset))[2 + i] = (ULONG)Native->SidHash->Hash[i];
    Offset += SID_HASH32_BYTES;
    SidArray32Write(Buffer, Offset, Native->SidHash->SidAttr, Native->SidHash->SidCount);
    Offset += SidLength;

    OUT32(1) = Buffer + Offset;
    ((ULONG UNALIGNED *)(Guest + Offset))[0] = Native->RestrictedSidHash->SidCount;
    for (i = 0; i < SID_HASH_SIZE; ++i)
        ((ULONG UNALIGNED *)(Guest + Offset))[2 + i] = (ULONG)Native->RestrictedSidHash->Hash[i];
    if (Native->RestrictedSidHash->SidCount)
    {
        ((ULONG UNALIGNED *)(Guest + Offset))[1] = Buffer + Offset + SID_HASH32_BYTES;
        SidArray32Write(Buffer, Offset + SID_HASH32_BYTES, Native->RestrictedSidHash->SidAttr, Native->RestrictedSidHash->SidCount);
    }
    Offset += SID_HASH32_BYTES + RestrictedLength;

    /* The capabilities of a lowbox token (none for others) */
    OUT32(11) = Buffer + Offset;
    ((ULONG UNALIGNED *)(Guest + Offset))[0] = Native->CapabilitiesHash->SidCount;
    for (i = 0; i < SID_HASH_SIZE; ++i)
        ((ULONG UNALIGNED *)(Guest + Offset))[2 + i] = (ULONG)Native->CapabilitiesHash->Hash[i];
    if (Native->CapabilitiesHash->SidCount)
    {
        ((ULONG UNALIGNED *)(Guest + Offset))[1] = Buffer + Offset + SID_HASH32_BYTES;
        SidArray32Write(Buffer, Offset + SID_HASH32_BYTES, Native->CapabilitiesHash->SidAttr, Native->CapabilitiesHash->SidCount);
    }
    Offset += SID_HASH32_BYTES + CapabilitiesLength;

    OUT32(2) = Buffer + Offset;
    ((ULONG UNALIGNED *)(Guest + Offset))[0] = Native->Privileges->PrivilegeCount;
    RtlCopyMemory(Guest + Offset + sizeof(ULONG), Native->Privileges->Privileges,
                  Native->Privileges->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES));
    Offset += PrivilegesLength;

    /* The package SID of a lowbox token, after the privileges as in the native answer */
    if (PackageLength)
    {
        OUT32(10) = Buffer + Offset;
        RtlCopyMemory(Guest + Offset, Native->PackageSid, RtlLengthSid(Native->PackageSid));
    }
#undef OUT32
    return STATUS_SUCCESS;
}

/* A class whose result is one SID pointer, NULL without an AppContainer or a protected process, else
 * followed by the SID (TOKEN_APPCONTAINER_INFORMATION of a lowbox token): a 4-byte pointer and the SID in the
 * guest */
static NTSTATUS TokenPointer32(HANDLE Token, TOKEN_INFORMATION_CLASS Class, ULONG Buffer, ULONG Length, ULONG ReturnLength)
{
    union { PVOID Pointer; UCHAR Bytes[sizeof(PVOID) + SECURITY_MAX_SID_SIZE]; } Native;
    ULONG Bytes = 0, SidLength = 0;
    NTSTATUS Status;

    if (!ReturnLength || !GuestSpan(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    Native.Pointer = NULL;
    Status = NtQueryInformationToken(Token, Class, &Native, sizeof(Native), &Bytes);
    if (!NT_SUCCESS(Status)) return Status;
    if (Native.Pointer) SidLength = RtlLengthSid(Native.Pointer);
    Status = TokenResult32(Buffer, Length, ReturnLength, sizeof(ULONG) + SidLength);
    if (!NT_SUCCESS(Status)) return Status;
    if (SidLength) RtlCopyMemory((UCHAR *)PTR32(Buffer) + sizeof(ULONG), Native.Pointer, SidLength);
    *(ULONG UNALIGNED *)PTR32(Buffer) = SidLength ? Buffer + sizeof(ULONG) : 0;
    return STATUS_SUCCESS;
}

/* A 32-bit TOKEN_GROUPS argument in the native layout. The SIDs stay in guest memory,
 * where the kernel captures them as caller data; Count was read and range-checked once. */
static PTOKEN_GROUPS GroupsFrom32(ULONG Guest, ULONG Count, PUCHAR *Next)
{
    ULONG *Source = PTR32(Guest), i;
    PTOKEN_GROUPS Groups;

    if (!Guest) return NULL;
    Groups = (PTOKEN_GROUPS)*Next;
    Groups->GroupCount = Count;
    for (i = 0; i < Count; ++i)
    {
        ULONG Sid = Source[1 + 2 * i];
        /* The SID must lie in the guest range too. The kernel reads it again; a count raised
         * meanwhile reaches at most 60 bytes further, into the reserved page past the limit. */
        if (Sid && (!GuestSpan(Sid, FIELD_OFFSET(SID, SubAuthority)) ||
                    !GuestSpan(Sid, FIELD_OFFSET(SID, SubAuthority) +
                               (ULONG64)((SID *)PTR32(Sid))->SubAuthorityCount * sizeof(ULONG))))
            return (PTOKEN_GROUPS)-1;
        Groups->Groups[i].Sid = PTR32(Sid);
        Groups->Groups[i].Attributes = Source[2 + 2 * i];
    }
    *Next += FIELD_OFFSET(TOKEN_GROUPS, Groups) + (SIZE_T)Count * sizeof(SID_AND_ATTRIBUTES);
    return Groups;
}

/* The element count of a guest group or privilege array, after checking that the
 * whole array lies in the guest's range */
static NTSTATUS GuestArrayCount(ULONG Address, ULONG ElementSize, PULONG Count)
{
    *Count = 0;
    if (!Address) return STATUS_SUCCESS;
    if (!GuestSpan(Address, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    *Count = *(ULONG *)PTR32(Address);
    if (*Count > WOW64_MAX_ARRAY_COUNT) return STATUS_INVALID_PARAMETER;
    if (!GuestSpan(Address, sizeof(ULONG) + (ULONG64)*Count * ElementSize)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* NtFilterToken: SidsToDisable and RestrictedSids hold SID pointers; TOKEN_PRIVILEGES
 * has the same layout for both sizes and goes through as is. */
static NTSTATUS FilterToken32(const ULONG *a, WOW64_CLEANUP *Cleanup)
{
    ULONG DisableCount, RestrictCount, PrivilegeCount;
    SIZE_T Bytes = 1;
    PUCHAR Next;
    PTOKEN_GROUPS Disable, Restrict;
    NTSTATUS Status;

    if (!a[5] || !GuestSpan(a[5], sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    ProbeOutput(a[5], sizeof(ULONG));
    Status = GuestArrayCount(a[2], 2 * sizeof(ULONG), &DisableCount);
    if (!NT_SUCCESS(Status)) return Status;
    Status = GuestArrayCount(a[3], sizeof(LUID_AND_ATTRIBUTES), &PrivilegeCount);
    if (!NT_SUCCESS(Status)) return Status;
    Status = GuestArrayCount(a[4], 2 * sizeof(ULONG), &RestrictCount);
    if (!NT_SUCCESS(Status)) return Status;
    if (a[2]) Bytes += FIELD_OFFSET(TOKEN_GROUPS, Groups) + (SIZE_T)DisableCount * sizeof(SID_AND_ATTRIBUTES);
    if (a[4]) Bytes += FIELD_OFFSET(TOKEN_GROUPS, Groups) + (SIZE_T)RestrictCount * sizeof(SID_AND_ATTRIBUTES);
    Next = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
    if (!Next) return STATUS_NO_MEMORY;
    Disable = GroupsFrom32(a[2], DisableCount, &Next);
    if (Disable == (PTOKEN_GROUPS)-1) return STATUS_ACCESS_VIOLATION;
    Restrict = GroupsFrom32(a[4], RestrictCount, &Next);
    if (Restrict == (PTOKEN_GROUPS)-1) return STATUS_ACCESS_VIOLATION;
    Status = NtFilterToken(HANDLE32(a[0]), a[1], Disable, PTR32(a[3]), Restrict, &Cleanup->Handle);
    return ReturnHandle32(a[5], Status, Cleanup);
}

/* NtAccessCheckByType*: OBJECT_TYPE_LIST holds a GUID pointer, so an entry is 8 bytes in the guest
 * and 16 natively. The guest list is read once into a native list in Cleanup->Buffer; the GUIDs stay
 * in guest memory, where the kernel probes and captures them, and the kernel checks the count and
 * the levels. A zero count or a NULL list goes through as it is (the kernel decides). */
typedef struct { USHORT Level, Sbz; ULONG ObjectType; } WOW64_OBJECT_TYPE_LIST;

static NTSTATUS ObjectTypeList32(ULONG Address, ULONG Count, POBJECT_TYPE_LIST *List, WOW64_CLEANUP *Cleanup)
{
    const WOW64_OBJECT_TYPE_LIST *From = PTR32(Address);
    POBJECT_TYPE_LIST To;
    ULONG i;

    *List = PTR32(Address);
    if (!Address || !Count) return STATUS_SUCCESS;
    if (Count > WOW64_MAX_ARRAY_COUNT) return STATUS_INVALID_PARAMETER;
    if (!GuestSpan(Address, (ULONG64)Count * sizeof(*From))) return STATUS_ACCESS_VIOLATION;
    To = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, (SIZE_T)Count * sizeof(*To));
    if (!To) return STATUS_NO_MEMORY;
    for (i = 0; i < Count; ++i)
    {
        To[i].Level = From[i].Level;
        To[i].Sbz = From[i].Sbz;
        To[i].ObjectType = PTR32(From[i].ObjectType);
    }
    *List = To;
    return STATUS_SUCCESS;
}

/* NtCreateLowBoxToken: the capabilities are 32-bit SID_AND_ATTRIBUTES whose SIDs stay in guest memory, where
 * the kernel captures them, and the handles are 4 bytes each. Both arrays are read once into native arrays in
 * Cleanup->Buffer; the counts go to the kernel as they are, which applies its own limits. */
static NTSTATUS LowBoxArrays32(ULONG Capabilities, ULONG CapabilityCount, ULONG Handles, ULONG HandleCount,
                               WOW64_CLEANUP *Cleanup, PSID_AND_ATTRIBUTES *NativeCapabilities, HANDLE **NativeHandles)
{
    PSID_AND_ATTRIBUTES Native;
    HANDLE *NativeHandle;
    ULONG *Source, Sid, i;

    *NativeCapabilities = CapabilityCount ? NULL : PTR32(Capabilities);
    *NativeHandles = HandleCount ? NULL : PTR32(Handles);
    if (CapabilityCount > WOW64_MAX_ARRAY_COUNT || HandleCount > WOW64_MAX_ARRAY_COUNT) return STATUS_INVALID_PARAMETER;
    if (CapabilityCount && (!Capabilities || !GuestSpan(Capabilities, (ULONG64)CapabilityCount * 2 * sizeof(ULONG))))
        return STATUS_ACCESS_VIOLATION;
    if (HandleCount && (!Handles || !GuestSpan(Handles, (ULONG64)HandleCount * sizeof(ULONG))))
        return STATUS_ACCESS_VIOLATION;
    if (!CapabilityCount && !HandleCount) return STATUS_SUCCESS;

    Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0,
                                               (SIZE_T)CapabilityCount * sizeof(SID_AND_ATTRIBUTES) +
                                               (SIZE_T)HandleCount * sizeof(HANDLE));
    if (!Native) return STATUS_NO_MEMORY;
    Source = PTR32(Capabilities);
    for (i = 0; i < CapabilityCount; ++i)
    {
        Sid = Source[2 * i];
        /* As GroupsFrom32: the SID must lie in the guest range; the kernel reads and validates it */
        if (Sid && (!GuestSpan(Sid, FIELD_OFFSET(SID, SubAuthority)) ||
                    !GuestSpan(Sid, FIELD_OFFSET(SID, SubAuthority) +
                               (ULONG64)((SID *)PTR32(Sid))->SubAuthorityCount * sizeof(ULONG))))
            return STATUS_ACCESS_VIOLATION;
        Native[i].Sid = PTR32(Sid);
        Native[i].Attributes = Source[2 * i + 1];
    }
    NativeHandle = (HANDLE *)&Native[CapabilityCount];
    Source = PTR32(Handles);
    for (i = 0; i < HandleCount; ++i)
        NativeHandle[i] = HANDLE32(Source[i]);
    if (CapabilityCount) *NativeCapabilities = Native;
    if (HandleCount) *NativeHandles = NativeHandle;
    return STATUS_SUCCESS;
}

/* A 32-bit process sees the 32-bit view unless it asks for the other one.
 * That default belongs to names resolved from the root. A relative open
 * without a selector keeps the view its parent handle was opened with
 * (the configuration manager remembers it per handle), as Windows does. */
static ACCESS_MASK
KeyViewAccess(const OBJECT_ATTRIBUTES *Attributes, ACCESS_MASK Access)
{
    if (!(Access & KEY_WOW64_RES) && (!Attributes || !Attributes->RootDirectory))
        Access |= KEY_WOW64_32KEY;
    return Access;
}

/* The IO_STATUS_BLOCK of a request that is over when the call returns. The guest's block is probed
 * first (the kernel only sees a local one) and is the starting point of the local one: the kernel
 * writes it only for a request it started, and a request refused before that leaves the guest's
 * block as it was, as on Windows. A NULL block is for the kernel to judge. */
IO_STATUS_BLOCK *IoBegin(ULONG Address, IO_STATUS_BLOCK *Io)
{
    const volatile WOW64_IOSB *From = PTR32(Address);
    if (!Address) return NULL;
    ProbeOutput(Address, sizeof(WOW64_IOSB));
    Io->Status = (NTSTATUS)From->Status;
    Io->Information = From->Information;
    return Io;
}

VOID IoEnd(ULONG Address, const IO_STATUS_BLOCK *Io)
{
    if (Address) StoreIo(Address, Io);
}

/* NtSetInformationFile. A record is converted when its 32-bit layout differs from the native one
 * (it holds a handle or a pointer); every field is read from the guest once, and name lengths are
 * checked against the guest buffer before anything is copied. All other classes have the same
 * layout in both ABIs, so the kernel judges them (class, length, contents) itself. */
static NTSTATUS Wow64SetInformationFile(const ULONG *a, WOW64_CLEANUP *Cleanup)
{
    HANDLE File = HANDLE32(a[0]);
    ULONG Class = a[4], Length = a[3];
    PVOID Guest = PTR32(a[2]);
    IO_STATUS_BLOCK Io, *Iosb;
    NTSTATUS Status;

    switch (Class)
    {
    /* The access check bypass variants are for kernel callers: Windows refuses them (as the I/O manager
     * does for any class it does not know) before it looks at the length or the buffer. */
    case FileRenameInformationBypassAccessCheck:
    case FileLinkInformationBypassAccessCheck:
    case FileRenameInformationExBypassAccessCheck:
    case FileLinkInformationExBypassAccessCheck:
        return STATUS_INVALID_INFO_CLASS;
    case FileRenameInformation:
    case FileLinkInformation:
    case FileMoveClusterInformation:
    case FileRenameInformationEx:
    case FileLinkInformationEx:
    {
        const WOW64_RENAME_INFORMATION *From = Guest;
        typedef struct { ULONG Flags; HANDLE Root; ULONG Length; WCHAR Name[1]; } NATIVE;
        UNICODE_STRING Name;
        OBJECT_ATTRIBUTES Attributes;
        PVOID Redirected = NULL;
        NATIVE *To;
        ULONG Bytes, Flags, Root;
        if (Length < sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        Flags = From->Flags;
        Root = From->Root;
        Bytes = From->Length;
        if (Bytes > Length - FIELD_OFFSET(WOW64_RENAME_INFORMATION, Name) ||
            Bytes > MAXUSHORT || (Bytes & 1))
            return STATUS_INVALID_PARAMETER;
        Iosb = IoBegin(a[1], &Io);
        /* The classic classes read a BOOLEAN (or a cluster count) */
        if (Class == FileRenameInformation || Class == FileLinkInformation) Flags = (UCHAR)Flags;
        Name.Buffer = (PWSTR)From->Name;
        Name.Length = Name.MaximumLength = Bytes;
        InitializeObjectAttributes(&Attributes, &Name, 0, HANDLE32(Root), NULL);
        _SEH2_TRY
        {
            Status = Wow64RedirectFile(&Attributes, &Name, &Redirected);
            if (NT_SUCCESS(Status))
            {
                Bytes = sizeof(*To) + Name.Length;
                To = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Bytes);
                if (!To) Status = STATUS_NO_MEMORY;
                else
                {
                    To->Flags = Flags;
                    To->Root = Attributes.RootDirectory;
                    To->Length = Name.Length;
                    RtlCopyMemory(To->Name, Name.Buffer, Name.Length);
                    Status = NtSetInformationFile(File, Iosb, To, Bytes, Class);
                    IoEnd(a[1], &Io);
                }
            }
        }
        _SEH2_FINALLY
        {
            if (Redirected) RtlFreeHeap(RtlGetProcessHeap(), 0, Redirected);
        }
        _SEH2_END;
        return Status;
    }
    case FileCompletionInformation:
    case FileReplaceCompletionInformation:
    {
        const WOW64_COMPLETION_INFORMATION *From = Guest;
        FILE_COMPLETION_INFORMATION To;
        if (Length < sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        Iosb = IoBegin(a[1], &Io);
        To.Port = HANDLE32(From->Port);
        To.Key = PTR32(From->Key);
        Status = NtSetInformationFile(File, Iosb, &To, sizeof(To), Class);
        IoEnd(a[1], &Io);
        return Status;
    }
    case FileMemoryPartitionInformation:
    {
        const WOW64_HANDLE_FLAGS_INFORMATION *From = Guest;
        struct { HANDLE Handle; ULONG Flags; } To = {0};
        if (Length < sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        Iosb = IoBegin(a[1], &Io);
        To.Handle = HANDLE32(From->Handle);
        To.Flags = From->Flags;
        Status = NtSetInformationFile(File, Iosb, &To, sizeof(To), Class);
        IoEnd(a[1], &Io);
        return Status;
    }
    case FileIoStatusBlockRangeInformation:
    {
        const WOW64_POINTER_LENGTH_INFORMATION *From = Guest;
        struct { PVOID Pointer; ULONG Length; } To = {0};
        if (Length < sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        Iosb = IoBegin(a[1], &Io);
        To.Pointer = PTR32(From->Pointer);
        To.Length = From->Length;
        Status = NtSetInformationFile(File, Iosb, &To, sizeof(To), Class);
        IoEnd(a[1], &Io);
        return Status;
    }
    case FileMailslotSetInformation:
    {
        PVOID To; /* FILE_MAILSLOT_SET_INFORMATION: a pointer to the read timeout */
        if (Length < sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        Iosb = IoBegin(a[1], &Io);
        To = PTR32(*(const ULONG *)Guest);
        Status = NtSetInformationFile(File, Iosb, &To, sizeof(To), Class);
        IoEnd(a[1], &Io);
        return Status;
    }
    case FileTrackingInformation:
    {
        const WOW64_TRACKING_INFORMATION *From = Guest;
        typedef struct { HANDLE DestinationFile; ULONG Length; UCHAR Data[1]; } NATIVE;
        NATIVE *To;
        ULONG Bytes, Destination, Count;
        if (Length < sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        Destination = From->DestinationFile;
        Count = From->Length;
        Bytes = Length - FIELD_OFFSET(WOW64_TRACKING_INFORMATION, Data); /* the data the guest gave */
        Iosb = IoBegin(a[1], &Io);
        To = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
                                               sizeof(*To) + Bytes);
        if (!To) return STATUS_NO_MEMORY;
        To->DestinationFile = HANDLE32(Destination);
        To->Length = Count;
        RtlCopyMemory(To->Data, From->Data, Bytes);
        Status = NtSetInformationFile(File, Iosb, To, FIELD_OFFSET(NATIVE, Data) + Bytes, Class);
        IoEnd(a[1], &Io);
        return Status;
    }
    default:
        Iosb = IoBegin(a[1], &Io);
        Status = NtSetInformationFile(File, Iosb, Guest, Length, Class);
        IoEnd(a[1], &Io);
        return Status;
    }
}

/* The i386 MEM_EXTENDED_PARAMETER array of NtAllocateVirtualMemoryEx and NtMapViewOfSectionEx: the same
 * 16-byte records (type, then an 8-byte union whose low half holds a pointer or a handle); the address
 * requirement it points to has 32-bit addresses. A placement the caller does not bound stays below the
 * process' highest 32-bit address: then a requirement with that highest address is added (Placement).
 * The counts and types are checked again by the kernel on the native copy. */
#define WOW64_MAX_EXTENDED_PARAMETERS 8
static NTSTATUS ExtendedParameters32(ULONG Address, ULONG Count, BOOLEAN Placement,
                                     MEM_EXTENDED_PARAMETER *Params, MEM_ADDRESS_REQUIREMENTS *Requirements,
                                     ULONG *NativeCount)
{
    const struct { ULONG64 Type; ULONG64 Value; } *From = PTR32(Address);
    struct { ULONG Lowest, Highest, Alignment; } Requirements32;
    const VOID *Guest;
    BOOLEAN HaveRequirements = FALSE;
    ULONG i;

    *NativeCount = 0;
    if (Count && !Address) return STATUS_INVALID_PARAMETER;
    if (Count >= WOW64_MAX_EXTENDED_PARAMETERS) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < Count; i++)
    {
        struct { ULONG64 Type; ULONG64 Value; } Record;
        /* One read of each guest record as well */
        RtlCopyMemory(&Record, &From[i], sizeof(Record));
        RtlZeroMemory(&Params[i], sizeof(Params[i]));
        Params[i].Type = Record.Type & 0xFF;
        Params[i].Reserved = Record.Type >> 8;
        Params[i].ULong64 = Record.Value;
        switch (Params[i].Type)
        {
        case MemExtendedParameterAddressRequirements:
            if (HaveRequirements) return STATUS_INVALID_PARAMETER;
            HaveRequirements = TRUE;
            /* One copy of the guest's 12 bytes: what is checked is what is converted */
            Guest = PTR32((ULONG)Record.Value);
            if (!Guest) return STATUS_ACCESS_VIOLATION;
            RtlCopyMemory(&Requirements32, Guest, sizeof(Requirements32));
            /* Addresses beyond the 32-bit user space are not valid for this process */
            if (Requirements32.Highest > Wow64HighestUserAddress ||
                Requirements32.Lowest > Wow64HighestUserAddress)
            {
                return STATUS_INVALID_PARAMETER;
            }
            Requirements->LowestStartingAddress = PTR32(Requirements32.Lowest);
            Requirements->HighestEndingAddress = PTR32(Requirements32.Highest);
            Requirements->Alignment = Requirements32.Alignment;
            /* A 32-bit process has no addresses above its highest one */
            if (!Requirements->HighestEndingAddress && Placement)
                Requirements->HighestEndingAddress = ULongToPtr(Wow64HighestUserAddress);
            Params[i].Pointer = Requirements;
            break;
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            Params[i].Handle = HANDLE32((ULONG)Record.Value);
            break;
        default:
            break;
        }
    }
    if (Placement && !HaveRequirements)
    {
        RtlZeroMemory(&Params[i], sizeof(Params[i]));
        RtlZeroMemory(Requirements, sizeof(*Requirements));
        Requirements->HighestEndingAddress = ULongToPtr(Wow64HighestUserAddress);
        Params[i].Type = MemExtendedParameterAddressRequirements;
        Params[i].Pointer = Requirements;
        i++;
    }
    *NativeCount = i;
    return STATUS_SUCCESS;
}

/* NtCompactKeys: the guest array holds Count 32-bit handles, the kernel wants Count native ones. The
 * array is read (one touch per page) before anything is allocated, so a Count the guest has no
 * memory for is an access violation, as for the native caller, and never a huge allocation. */
static NTSTATUS CompactKeys32(ULONG Count, ULONG Array, WOW64_CLEANUP *Cleanup)
{
    const ULONG *From;
    HANDLE *To;
    ULONG i;
    if (!Count) return NtCompactKeys(0, NULL);
    if (!GuestSpan(Array, (ULONG64)Count * sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    ProbeInput(Array, Count * sizeof(ULONG));
    To = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, (SIZE_T)Count * sizeof(HANDLE));
    if (!To) return STATUS_INSUFFICIENT_RESOURCES;
    From = PTR32(Array);
    for (i = 0; i < Count; i++) To[i] = HANDLE32(((volatile const ULONG *)From)[i]);
    return NtCompactKeys(Count, To);
}

/* NtQueryMultipleValueKey: every KEY_VALUE_ENTRY of the guest array (16 bytes) holds a pointer to a
 * UNICODE_STRING (itself with a 32-bit buffer pointer), the native one (24 bytes) the native
 * pointer. The names are converted into one native block, and DataLength, DataOffset and Type are
 * copied back to the guest array whatever the status (the kernel fills them in for the buffer
 * overflow case as well). The value buffer holds the data only: the same bytes in both ABIs, as are
 * the two length variables, so the kernel works on the guest's own memory. */
typedef struct { ULONG ValueName, DataLength, DataOffset, Type; } WOW64_KEY_VALUE_ENTRY;
C_ASSERT(sizeof(WOW64_KEY_VALUE_ENTRY) == 16);

static NTSTATUS QueryMultipleValueKey32(const ULONG *a, WOW64_CLEANUP *Cleanup)
{
    volatile WOW64_KEY_VALUE_ENTRY *Guest = PTR32(a[1]);
    PKEY_VALUE_ENTRY Entries = NULL;
    UNICODE_STRING *Names;
    NTSTATUS Status;
    ULONG Count = a[2], i;
    if (Count)
    {
        if (!GuestSpan(a[1], (ULONG64)Count * sizeof(*Guest))) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(a[1], Count * sizeof(*Guest));
        Entries = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
                                                    (SIZE_T)Count * (sizeof(*Entries) + sizeof(*Names)));
        if (!Entries) return STATUS_INSUFFICIENT_RESOURCES;
        Names = (UNICODE_STRING *)(Entries + Count);
        for (i = 0; i < Count; i++)
        {
            ULONG Name = Guest[i].ValueName;
            Entries[i].ValueName = Name ? String32(&Names[i], PTR32(Name)) : NULL;
            Entries[i].DataLength = Guest[i].DataLength;
            Entries[i].DataOffset = Guest[i].DataOffset;
            Entries[i].Type = Guest[i].Type;
        }
    }
    else
        Entries = PTR32(a[1]);
    Status = NtQueryMultipleValueKey(HANDLE32(a[0]), Entries, Count, PTR32(a[3]), PTR32(a[4]), PTR32(a[5]));
    if (Count)
    {
        for (i = 0; i < Count; i++)
        {
            Guest[i].DataLength = Entries[i].DataLength;
            Guest[i].DataOffset = Entries[i].DataOffset;
            Guest[i].Type = Entries[i].Type;
        }
    }
    return Status;
}

/* NtQueryOpenSubKeysEx fills a buffer with a ULONG count and an array of { process id, key name }
 * entries; the names follow the array. The native array entry is a HANDLE and a UNICODE_STRING
 * (24 bytes, array at offset 8), the guest one 12 bytes (array at offset 4) with a 32-bit name
 * pointer. The kernel gets a buffer twice the guest's (a guest layout that fits needs less than
 * that natively), and when it answers that it needs more it is asked again with the size it named,
 * so the guest's required size can be worked out from the entries. The result is repacked into the
 * guest's buffer: header, entries, then the names in order, each pointer inside the guest buffer.
 * A guest buffer that is too small gets the kernel's status and the size the guest layout needs. */
typedef struct { ULONG Process; WOW64_STRING KeyName; } WOW64_KEY_PID;
typedef struct { HANDLE Process; UNICODE_STRING KeyName; } NATIVE_KEY_PID;
C_ASSERT(sizeof(WOW64_KEY_PID) == 12);

static NTSTATUS QueryOpenSubKeysEx32(const ULONG *a, WOW64_CLEANUP *Cleanup)
{
    OBJECT_ATTRIBUTES Attributes;
    SECURITY_DESCRIPTOR Descriptor;
    UNICODE_STRING Name;
    ULONG GuestLength = a[1], NativeLength, Required = 0, Count, i, Need, Offset;
    ULONG64 Wanted;
    PUCHAR Native;
    NATIVE_KEY_PID *From;
    WOW64_KEY_PID *To;
    NTSTATUS Status;
    int Attempt;

    Status = Attributes32(&Attributes, &Name, &Descriptor, a[0]);
    if (!NT_SUCCESS(Status)) return Status;
    if (a[3]) ProbeOutput(a[3], sizeof(ULONG));
    if (GuestLength)
    {
        if (!GuestSpan(a[2], GuestLength)) return STATUS_ACCESS_VIOLATION;
        ProbeOutput(a[2], GuestLength);
    }
    Wanted = (ULONG64)GuestLength * 2 + sizeof(NATIVE_KEY_PID);
    if (Wanted > 0x10000000) return STATUS_INSUFFICIENT_RESOURCES;
    NativeLength = (ULONG)Wanted;
    for (Attempt = 0; ; Attempt++)
    {
        if (Cleanup->Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, Cleanup->Buffer);
        Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, NativeLength);
        if (!Native) return STATUS_INSUFFICIENT_RESOURCES;
        Required = 0;
        Status = NtQueryOpenSubKeysEx(a[0] ? &Attributes : NULL, NativeLength, Native, &Required);
        if ((Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) ||
            Required <= NativeLength || Required > 0x10000000 || Attempt == 2)
            break;
        NativeLength = Required;
    }
    if (!NT_SUCCESS(Status))
    {
        /* Nothing to convert; a size the kernel named is the native one, which the guest layout
         * does not use, so only the status is passed on */
        return Status;
    }
    /* Validate the kernel's answer before using it */
    Count = *(ULONG *)Native;
    if ((ULONG64)Count * sizeof(NATIVE_KEY_PID) + 8 > NativeLength) return STATUS_INFO_LENGTH_MISMATCH;
    From = (NATIVE_KEY_PID *)(Native + 8);
    Need = sizeof(ULONG) + Count * sizeof(WOW64_KEY_PID);
    for (i = 0; i < Count; i++)
    {
        PUCHAR Text = (PUCHAR)From[i].KeyName.Buffer;
        if (From[i].KeyName.Length & 1) return STATUS_INFO_LENGTH_MISMATCH;
        if (From[i].KeyName.Length &&
            (Text < Native || (ULONG64)(Text - Native) + From[i].KeyName.Length > NativeLength))
            return STATUS_INFO_LENGTH_MISMATCH;
        Need += From[i].KeyName.Length;
    }
    if (a[3]) *(volatile ULONG *)PTR32(a[3]) = Need;
    if (Need > GuestLength) return STATUS_BUFFER_TOO_SMALL;
    *(volatile ULONG *)PTR32(a[2]) = Count;
    To = (WOW64_KEY_PID *)((PUCHAR)PTR32(a[2]) + sizeof(ULONG));
    Offset = sizeof(ULONG) + Count * sizeof(WOW64_KEY_PID);
    for (i = 0; i < Count; i++)
    {
        To[i].Process = HandleToUlong(From[i].Process);
        To[i].KeyName.Length = From[i].KeyName.Length;
        To[i].KeyName.MaximumLength = From[i].KeyName.Length;
        To[i].KeyName.Buffer = From[i].KeyName.Length ? a[2] + Offset : 0;
        RtlCopyMemory((PUCHAR)PTR32(a[2]) + Offset, From[i].KeyName.Buffer, From[i].KeyName.Length);
        Offset += From[i].KeyName.Length;
    }
    return Status;
}

/* a is Wow64SystemService's local copy of the guest argument list: counts and pointers
 * read from it (e.g. the NtWaitForMultipleObjects and NtRaiseHardError counts) cannot
 * change between their check and their use. What they point to is still guest memory. */
static NTSTATUS Dispatch(ULONG Number, const ULONG *a, WOW64_CLEANUP *Cleanup)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    SECURITY_DESCRIPTOR Descriptor;
    UNICODE_STRING Name;
    IO_STATUS_BLOCK Io = {{0}};
    PVOID Base;
    SIZE_T Size;
    ULONG Length;
    ACCESS_MASK KeyAccess;
    BOOLEAN NativeSystemInformation = Number == 0x10001;

#define H(i) HANDLE32(a[i])
#define P(i) PTR32(a[i])
#define U(i) (*(ULONG *)P(i))
#define ATTR(i) do { Status = Attributes32(&Attributes, &Name, &Descriptor, a[i]); \
    if (!NT_SUCCESS(Status)) return Status; } while (0)
#define OA(i) (a[i] ? &Attributes : NULL)
#define FILEATTR(i) do { ATTR(i); \
    Status = Wow64RedirectFile(&Attributes, &Name, &Cleanup->Buffer); \
    if (!NT_SUCCESS(Status)) return Status; } while (0)
#define PROBE(i) ProbeOutput(a[i], sizeof(ULONG))
#define RETURN_HANDLE_AT(i) return ReturnHandle32(a[i], Status, Cleanup)
#define RETURN_HANDLE() RETURN_HANDLE_AT(0)
#define UNSUPPORTED(Kind, Value) return Wow64Unsupported(Number, WOW64_UNSUPPORTED_##Kind, Value, &Cleanup->Reported)
    if (Number == WOW64_SERVICE_CSR) return Wow64CsrDispatch(a[0], P(1), &Cleanup->Reported);
    if (Number == WOW64_SERVICE_CREATE_PROCESS) return Wow64CreateProcess(P(0), &Cleanup->Reported);
    if (Number == 0x10002)
    {
        WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
        /* Write the old token before changing state: a bad output pointer
         * must leave redirection enabled, including nested disable calls. */
        U(1) = Cpu->FsRedirectionDisabled;
        Cpu->FsRedirectionDisabled = a[0];
        return STATUS_SUCCESS;
    }
    if (NativeSystemInformation) Number = W64_NtQuerySystemInformation;
    switch (Number)
    {
    case W64_NtCallbackReturn: return Wow64WinCallbackReturn(P(0), a[1], a[2]);
    case W64_NtCreateThread:
    {
        CLIENT_ID Id;
        PROBE(0);
        if (a[4]) ProbeOutput(a[4], 2 * sizeof(ULONG));
        ATTR(2);
        Cleanup->ThreadProcess = H(3);
        Status = Wow64CreateThread(&Cleanup->Thread, THREAD_ALL_ACCESS, OA(2), H(3), &Id, P(5), P(6), TRUE);
        if (NT_SUCCESS(Status))
        {
            /* The thread is created with THREAD_ALL_ACCESS so this routine can set its
             * start address, publish TEB32 and resume it. The guest handle, however, must
             * carry exactly the access the guest's own NtCreateThread would have been
             * granted: its DesiredAccess capped to what the thread object can grant.
             * A guest THREAD_ALL_ACCESS (0x1fffff) includes undefined specific bits
             * (0xf000) that the created handle never received -- its granted access is
             * 0x1f0fff through the thread generic mapping. Requesting those extra bits in
             * the duplicate is a self-inflicted access elevation that ObDuplicateObject
             * correctly denies for user mode (STATUS_ACCESS_DENIED), which previously
             * broke every WoW64 thread creation (e.g. Chromium's broker init). Clamp the
             * request to the source handle's granted access so the duplicate reproduces
             * native NtCreateThread semantics. MAXIMUM_ALLOWED is passed through unchanged
             * (ObDuplicateObject resolves it to the source handle's access). */
            ACCESS_MASK Access = a[1];
            OBJECT_BASIC_INFORMATION Obi;
            if (!(Access & MAXIMUM_ALLOWED) &&
                NT_SUCCESS(NtQueryObject(Cleanup->Thread, ObjectBasicInformation,
                                         &Obi, sizeof(Obi), NULL)))
                Access &= Obi.GrantedAccess;
            Status = NtDuplicateObject(NtCurrentProcess(), Cleanup->Thread, NtCurrentProcess(),
                                        &Cleanup->Handle, Access, a[2] ? Attributes.Attributes & OBJ_INHERIT : 0, 0);
        }
        if (NT_SUCCESS(Status))
        {
            U(0) = HandleToUlong(Cleanup->Handle);
            if (a[4])
            {
                ((ULONG *)P(4))[0] = HandleToUlong(Id.UniqueProcess);
                ((ULONG *)P(4))[1] = HandleToUlong(Id.UniqueThread);
            }
            if (!a[7]) Status = NtResumeThread(Cleanup->Thread, NULL);
            if (NT_SUCCESS(Status))
            {
                NtClose(Cleanup->Thread);
                Cleanup->Thread = NULL;
                Cleanup->Handle = NULL;
            }
        }
        /* The dispatcher closes the duplicate and aborts the thread; the guest sees NULL */
        if (!NT_SUCCESS(Status)) StoreNullHandle32(a[0]);
        return Status;
    }
    case W64_NtGetContextThread:
        return Wow64GetSetContextThread(H(0), P(1), FALSE);
    case W64_NtSetContextThread:
        return Wow64GetSetContextThread(H(0), P(1), TRUE);
    case W64_NtQueueApcThread:
        return NtQueueApcThread(H(0), (PKNORMAL_ROUTINE)(ULONG_PTR)(-((LONG64)a[1] << 2)), P(2), P(3), P(4));
    case W64_NtQueueApcThreadEx:
        return NtQueueApcThreadEx(H(0), H(1), (PKNORMAL_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)), P(3), P(4), P(5));
    case W64_NtSetIoCompletionEx:
        return NtSetIoCompletionEx(H(0), H(1), P(2), P(3), a[4], a[5]);
    case W64_NtCreateWaitCompletionPacket:
        PROBE(0);
        ATTR(2); Status = NtCreateWaitCompletionPacket(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtAssociateWaitCompletionPacket:
        return NtAssociateWaitCompletionPacket(H(0), H(1), H(2), P(3), P(4), a[5], a[6], (PBOOLEAN)P(7));
    case W64_NtCancelWaitCompletionPacket:
        return NtCancelWaitCompletionPacket(H(0), (BOOLEAN)a[1]);
    case W64_NtAllocateReserveObject:
        PROBE(0);
        ATTR(1); Status = NtAllocateReserveObject(&Cleanup->Handle, OA(1), a[2]); RETURN_HANDLE();
    case W64_NtDuplicateObject:
        if (a[3]) PROBE(3);
        Cleanup->HandleProcess = H(2);
        Status = NtDuplicateObject(H(0), H(1), H(2), a[3] ? &Cleanup->Handle : NULL, a[4], a[5], a[6]);
        /* Moving a handle out of this process closes it as NtClose does */
        if (NT_SUCCESS(Status) && (a[6] & DUPLICATE_CLOSE_SOURCE) && IsCurrentProcess(H(0))) Wow64LpcForget(a[1]);
        if (a[3]) { RETURN_HANDLE_AT(3); }
        return Status;
    case W64_NtQueryInformationThread:
        /* The native service does not fail with STATUS_NOT_SUPPORTED for the classes
         * Wow64QueryThread forwards, so this status means an untranslated class */
        Status = Wow64QueryThread(H(0), a[1], P(2), a[3], P(4));
        if (Status == STATUS_NOT_SUPPORTED) UNSUPPORTED(CLASS, a[1]);
        return Status;
    case W64_NtReadVirtualMemory:
    case W64_NtWriteVirtualMemory:
    {
        SIZE_T Bytes = 0;
        if (a[4]) PROBE(4);
        if (Number == W64_NtReadVirtualMemory)
            Status = NtReadVirtualMemory(H(0), P(1), P(2), a[3], &Bytes);
        else
            Status = NtWriteVirtualMemory(H(0), P(1), P(2), a[3], &Bytes);
        if (a[4]) U(4) = (ULONG)Bytes;
        return Status;
    }
    case W64_NtOpenSemaphore:
        PROBE(0); ATTR(2); Status = NtOpenSemaphore(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtOpenMutant:
        PROBE(0); ATTR(2); Status = NtOpenMutant(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtClose:
        Wow64LpcForget(a[0]);
        return NtClose(H(0));
    case W64_NtConnectPort:
        PROBE(0);
        Status = Wow64LpcConnect(Number, a, &Cleanup->Handle, &Cleanup->Reported);
        RETURN_HANDLE();
    case W64_NtRequestWaitReplyPort:
        return Wow64LpcRequest(Number, a[0], a[1], a[2], &Cleanup->Reported);
    case W64_NtContinue: return Wow64Continue(P(0), a[1]);
    case W64_NtQueryObject:
        if (a[1] == ObjectBasicInformation || a[1] == ObjectHandleFlagInformation)
            return NtQueryObject(H(0), a[1], P(2), a[3], P(4));
        if (a[1] == ObjectNameInformation)
        {
            OBJECT_NAME_INFORMATION *Native;
            WOW64_STRING *Guest = P(2);
            ULONG Needed = 0, GuestNeeded, Extra = sizeof(UNICODE_STRING) - sizeof(WOW64_STRING);
            if (a[3] > MAXULONG - Extra) return STATUS_INVALID_PARAMETER;
            if (a[4]) PROBE(4);
            ULONG NativeLen = min(a[3], WOW64_MAX_INFO_BUFFER) + Extra;
            Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeLen);
            if (!Native) return STATUS_NO_MEMORY;
            Status = NtQueryObject(H(0), a[1], Native, NativeLen, &Needed);
            GuestNeeded = Needed >= sizeof(UNICODE_STRING) ? Needed - Extra : Needed;
            if (a[4]) U(4) = GuestNeeded;
            if (NT_SUCCESS(Status))
            {
                if (a[3] < sizeof(*Guest) ||
                    Native->Name.MaximumLength > a[3] - sizeof(*Guest))
                    return STATUS_INFO_LENGTH_MISMATCH;
                Guest->Length = Native->Name.Length;
                Guest->MaximumLength = Native->Name.MaximumLength;
                Guest->Buffer = Native->Name.Buffer ? PtrToUlong(Guest + 1) : 0;
                if (Native->Name.Buffer)
                    RtlCopyMemory(Guest + 1, Native->Name.Buffer, Native->Name.MaximumLength);
            }
            return Status;
        }
        if (a[1] == ObjectTypeInformation)
        {
            /* OBJECT_TYPE_INFORMATION is a UNICODE_STRING followed by a fixed
             * tail of ULONG/BYTE fields (no pointers). Only the leading string
             * header differs in width (16 vs 8 bytes); the tail is byte-identical.
             * Mirror the ObjectNameInformation thunk: query into a native buffer
             * widened by that difference, narrow the string header, copy the
             * identical tail, then append the type-name characters. */
            OBJECT_TYPE_INFORMATION *Native;
            WOW64_STRING *Guest = P(2);
            ULONG Needed = 0, GuestNeeded;
            ULONG TailOffset = FIELD_OFFSET(OBJECT_TYPE_INFORMATION, TotalNumberOfObjects);
            ULONG TailSize = sizeof(OBJECT_TYPE_INFORMATION) - TailOffset;
            ULONG GuestSize = sizeof(WOW64_STRING) + TailSize;
            ULONG Extra = sizeof(OBJECT_TYPE_INFORMATION) - GuestSize;
            if (a[3] > MAXULONG - Extra) return STATUS_INVALID_PARAMETER;
            if (a[4]) PROBE(4);
            ULONG NativeLen = min(a[3], WOW64_MAX_INFO_BUFFER) + Extra;
            Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeLen);
            if (!Native) return STATUS_NO_MEMORY;
            Status = NtQueryObject(H(0), a[1], Native, NativeLen, &Needed);
            GuestNeeded = Needed >= sizeof(OBJECT_TYPE_INFORMATION) ? Needed - Extra : Needed;
            if (a[4]) U(4) = GuestNeeded;
            if (NT_SUCCESS(Status))
            {
                if (a[3] < GuestSize ||
                    Native->TypeName.MaximumLength > a[3] - GuestSize)
                    return STATUS_INFO_LENGTH_MISMATCH;
                RtlCopyMemory((PUCHAR)Guest + sizeof(WOW64_STRING),
                              (PUCHAR)Native + TailOffset, TailSize);
                Guest->Length = Native->TypeName.Length;
                Guest->MaximumLength = Native->TypeName.MaximumLength;
                Guest->Buffer = Native->TypeName.Buffer ? PtrToUlong((PUCHAR)Guest + GuestSize) : 0;
                if (Native->TypeName.Buffer)
                    RtlCopyMemory((PUCHAR)Guest + GuestSize, Native->TypeName.Buffer,
                                  Native->TypeName.MaximumLength);
            }
            return Status;
        }
        if (a[1] == ObjectTypesInformation)
        {
            /* A ULONG count, then one OBJECT_TYPE_INFORMATION per type, each followed by
             * its name and aligned to the pointer size (8 native, 4 guest). Narrow every
             * string header as ObjectTypeInformation does and repack the entries. */
            PUCHAR Native, Guest = P(2);
            ULONG Needed = 0, GuestNeeded, Count, i, NativeOffset, GuestOffset;
            ULONG TailOffset = FIELD_OFFSET(OBJECT_TYPE_INFORMATION, TotalNumberOfObjects);
            ULONG TailSize = sizeof(OBJECT_TYPE_INFORMATION) - TailOffset;
            ULONG GuestSize = sizeof(WOW64_STRING) + TailSize;
            if (a[4]) PROBE(4);
            Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, WOW64_MAX_INFO_BUFFER);
            if (!Native) return STATUS_NO_MEMORY;
            Status = NtQueryObject(H(0), a[1], Native, WOW64_MAX_INFO_BUFFER, &Needed);
            if (!NT_SUCCESS(Status)) return Status;
            Count = *(ULONG *)Native;
            GuestNeeded = ALIGN_UP(sizeof(ULONG), ULONG);
            NativeOffset = ALIGN_UP(sizeof(ULONG), ULONG_PTR);
            for (i = 0; i < Count; ++i)
            {
                OBJECT_TYPE_INFORMATION *Entry = (OBJECT_TYPE_INFORMATION *)(Native + NativeOffset);
                ULONG NameSize = ALIGN_UP(Entry->TypeName.MaximumLength, ULONG_PTR);
                if (NativeOffset > Needed || sizeof(*Entry) + NameSize > Needed - NativeOffset)
                    return STATUS_INFO_LENGTH_MISMATCH;
                GuestNeeded += GuestSize + ALIGN_UP(Entry->TypeName.MaximumLength, ULONG);
                NativeOffset += sizeof(*Entry) + NameSize;
            }
            if (a[4]) U(4) = GuestNeeded;
            if (a[3] < GuestNeeded) return STATUS_INFO_LENGTH_MISMATCH;
            *(ULONG *)Guest = Count;
            NativeOffset = ALIGN_UP(sizeof(ULONG), ULONG_PTR);
            GuestOffset = ALIGN_UP(sizeof(ULONG), ULONG);
            for (i = 0; i < Count; ++i)
            {
                OBJECT_TYPE_INFORMATION *Entry = (OBJECT_TYPE_INFORMATION *)(Native + NativeOffset);
                WOW64_STRING *Name = (WOW64_STRING *)(Guest + GuestOffset);
                ULONG Max = Entry->TypeName.MaximumLength;
                RtlCopyMemory(Guest + GuestOffset + sizeof(WOW64_STRING),
                              (PUCHAR)Entry + TailOffset, TailSize);
                Name->Length = Entry->TypeName.Length;
                Name->MaximumLength = Max;
                Name->Buffer = Entry->TypeName.Buffer ? PtrToUlong(Guest + GuestOffset + GuestSize) : 0;
                if (Entry->TypeName.Buffer)
                    RtlCopyMemory(Guest + GuestOffset + GuestSize, Entry->TypeName.Buffer, Max);
                GuestOffset += GuestSize + ALIGN_UP(Max, ULONG);
                NativeOffset += sizeof(*Entry) + ALIGN_UP(Max, ULONG_PTR);
            }
            return STATUS_SUCCESS;
        }
        UNSUPPORTED(CLASS, a[1]);
    case W64_NtSetInformationObject:
        if (a[1] == ObjectHandleFlagInformation)
            return NtSetInformationObject(H(0), a[1], P(2), a[3]);
        UNSUPPORTED(CLASS, a[1]);
    case W64_NtRaiseException: return Wow64RaiseException(P(0), P(1), a[2]);
    case W64_NtRaiseHardError:
    {
        /* kernel32 reports an unhandled exception this way when no crash
         * reporter runs. Widen the ULONG_PTR array; string parameters are
         * UNICODE_STRING pointers. The service must still reject a bad
         * record in its own order (count, response options, response
         * pointer, then the parameters), with the status i386 returns:
         * a misaligned guest pointer is passed on as it is, and one that
         * cannot be read is replaced by the reserved, inaccessible page
         * above the guest address limit (never by the guest record read
         * at the native width). */
        ULONG_PTR Parameters[MAXIMUM_HARDERROR_PARAMETERS];
        UNICODE_STRING Strings[MAXIMUM_HARDERROR_PARAMETERS];
        ULONG_PTR Inaccessible = (ULONG_PTR)Wow64HighestUserAddress + 1;
        const ULONG *From = P(3);
        PVOID Native = P(3);
        ULONG i;
        if (a[1] > MAXIMUM_HARDERROR_PARAMETERS) return STATUS_INVALID_PARAMETER_2;
        if (From && !(a[3] & (sizeof(ULONG) - 1)))
        {
            _SEH2_TRY
            {
                for (i = 0; i < a[1]; ++i)
                {
                    Parameters[i] = From[i];
                    if (!(a[2] & (1 << i)) || !Parameters[i] || (Parameters[i] & (sizeof(ULONG) - 1)))
                        continue;
                    _SEH2_TRY
                    {
                        String32(&Strings[i], PTR32(Parameters[i]));
                        Parameters[i] = (ULONG_PTR)&Strings[i];
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        Parameters[i] = Inaccessible;
                    }
                    _SEH2_END;
                }
                Native = Parameters;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Native = (PVOID)Inaccessible;
            }
            _SEH2_END;
        }
        /* The thread error mode of a 32-bit thread (SetThreadErrorMode, which the .NET runtime uses
         * around its library loads) lives in the 32-bit TEB; the kernel reads the native one. Carry
         * the no-critical-error-UI bit over for the call, so a failed load returns instead of
         * putting up a box the program asked not to get. */
        PTEB Teb = NtCurrentTeb();
        ULONG OldMode = Teb->HardErrorMode;
        NTSTATUS Status;
        if (WOW64_TEB32(Teb)->HardErrorMode & RTL_SEM_FAILCRITICALERRORS)
            Teb->HardErrorMode = OldMode | RTL_SEM_FAILCRITICALERRORS;
        Status = NtRaiseHardError(a[0], a[1], a[2], Native, a[4], P(5));
        Teb->HardErrorMode = OldMode;
        return Status;
    }
    case W64_NtGetCurrentProcessorNumber:
        /* The result is the processor number, not an NTSTATUS. The thunk runs on the guest thread's own
         * native thread, so this is the processor the guest code was running on. */
        return NtGetCurrentProcessorNumber();
    case W64_NtGetCurrentProcessorNumberEx:
    {
        /* PROCESSOR_NUMBER has the same layout in both ABIs. The native ntdll only exports the Rtl
         * function at the 0x601 level (the Nt one is exported from 0xA00 on), so use that, and fail
         * like the system service when the guest buffer cannot be written. */
        PROCESSOR_NUMBER Number;
        RtlGetCurrentProcessorNumberEx(&Number);
        _SEH2_TRY
        {
            *(PROCESSOR_NUMBER *)P(0) = Number;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        _SEH2_END;
        return STATUS_SUCCESS;
    }
    /* User-mode debugging: debug.c converts the client ID and the wait state change */
    case W64_NtCreateDebugObject:
        PROBE(0); ATTR(2); Status = NtCreateDebugObject(&Cleanup->Handle, a[1], OA(2), a[3]); RETURN_HANDLE();
    case W64_NtDebugContinue: return Wow64DebugContinue(a);
    case W64_NtWaitForDebugEvent: return Wow64WaitForDebugEvent(a);
    case W64_NtSetInformationDebugObject: /* the one class is a ULONG, ReturnLength too */
        return NtSetInformationDebugObject(H(0), a[1], P(2), a[3], P(4));
    /* NtWaitForMultipleObjects32 (0x127) has no thunk on purpose: the guest ntdll calls 0x118 for
     * NtWaitForMultipleObjects and nothing in this tree uses the 0x127 export, so a direct call is "unsupported". */
    case W64_NtWaitForMultipleObjects:
    {
        HANDLE Handles[MAXIMUM_WAIT_OBJECTS];
        ULONG i;
        /* The kernel's own status for a bad count, as an i386 caller gets it */
        if (!a[0] || a[0] > MAXIMUM_WAIT_OBJECTS) return STATUS_INVALID_PARAMETER_1;
        for (i = 0; i < a[0]; ++i) Handles[i] = HANDLE32(((ULONG *)P(1))[i]);
        return NtWaitForMultipleObjects(a[0], Handles, a[2], a[3], P(4));
    }
    case W64_NtAllocateVirtualMemory:
        PROBE(1); PROBE(3);
        Base = PTR32(U(1)); Size = U(3);
        if (Base && !GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryAlloc, Base);
        /* MEM_COMMIT with a null base also creates a new reservation. Existing
         * reservations stay owned by the caller and must never be released. */
        Cleanup->Process = H(0);
        Cleanup->Mapped = FALSE;
        Length = !Base || (a[4] & MEM_RESERVE);
        Status = NtAllocateVirtualMemory(H(0), &Base, Wow64ZeroBits(a[2]),
                                         &Size, a[4], a[5]);
        if (NT_SUCCESS(Status))
        {
            if (Length) Cleanup->Base = Base;
            U(1) = PtrToUlong(Base); U(3) = Size;
            Cleanup->Base = NULL;
        }
        return Status;
    case W64_NtAllocateVirtualMemoryEx:
    {
        MEM_EXTENDED_PARAMETER Params[WOW64_MAX_EXTENDED_PARAMETERS];
        MEM_ADDRESS_REQUIREMENTS Requirements;
        ULONG Count;
        PROBE(1); PROBE(2);
        Base = PTR32(U(1)); Size = U(2);
        if (Base && !GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryAlloc, Base);
        /* Only a new allocation gets the 32-bit limit; an address excludes a requirement */
        Status = ExtendedParameters32(a[5], a[6], Base == NULL, Params, &Requirements, &Count);
        if (!NT_SUCCESS(Status)) return Status;
        Cleanup->Process = H(0);
        Cleanup->Mapped = FALSE;
        /* A replaced placeholder stays the caller's, like an existing reservation */
        Length = (!Base || (a[3] & MEM_RESERVE)) && !(a[3] & MEM_REPLACE_PLACEHOLDER);
        Status = NtAllocateVirtualMemoryEx(H(0), &Base, &Size, a[3], a[4], Count ? Params : NULL, Count);
        if (NT_SUCCESS(Status))
        {
            if (Length) Cleanup->Base = Base;
            U(1) = PtrToUlong(Base); U(2) = Size;
            Cleanup->Base = NULL;
        }
        return Status;
    }
    case W64_NtLockVirtualMemory:
    case W64_NtUnlockVirtualMemory:
        /* VirtualLock/VirtualUnlock: the base and size come back rounded to pages, like NtProtectVirtualMemory's */
        PROBE(1); PROBE(2);
        Base = PTR32(U(1)); Size = U(2);
        if (!GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryLock, Base);
        Status = (Number == W64_NtLockVirtualMemory) ? NtLockVirtualMemory(H(0), &Base, &Size, a[3])
                                                     : NtUnlockVirtualMemory(H(0), &Base, &Size, a[3]);
        if (NT_SUCCESS(Status)) { U(1) = PtrToUlong(Base); U(2) = Size; }
        return Status;
    case W64_NtFreeVirtualMemory:
        PROBE(1); PROBE(2);
        Base = PTR32(U(1)); Size = U(2);
        if (!GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryFree, Base);
        Status = NtFreeVirtualMemory(H(0), &Base, &Size, a[3]);
        if (NT_SUCCESS(Status)) { U(1) = PtrToUlong(Base); U(2) = Size; }
        return Status;
    case W64_NtProtectVirtualMemory:
        PROBE(1); PROBE(2); PROBE(4);
        Base = PTR32(U(1)); Size = U(2);
        if (!GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryProtect, Base);
        Status = NtProtectVirtualMemory(H(0), &Base, &Size, a[3], P(4));
        if (NT_SUCCESS(Status)) { U(1) = PtrToUlong(Base); U(2) = Size; }
        return Status;
    case W64_NtFlushVirtualMemory:
        /* FlushViewOfFile: the base and size are updated (rounded to pages) like NtProtectVirtualMemory's, and
         * the block describes the write that was started */
        PROBE(1); PROBE(2);
        Base = PTR32(U(1)); Size = U(2);
        if (!GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryProtect, Base);
        Status = NtFlushVirtualMemory(H(0), &Base, &Size, IoBegin(a[3], &Io));
        IoEnd(a[3], &Io);
        if (NT_SUCCESS(Status)) { U(1) = PtrToUlong(Base); U(2) = Size; }
        return Status;
    case W64_NtQueryVirtualMemory:
    {
        MEMORY_BASIC_INFORMATION Info;
        struct { ULONG Base, AllocationBase, AllocationProtect, Size, State, Protect, Type; } *Info32 = P(3);
        if (a[2] == MemorySectionName)
        {
            /* The kernel resolves the name in the caller's address space whatever the handle
             * (MmGetFileNameForAddress), so another process would get the caller's mapping */
            HANDLE Process = NtCurrentProcess();
            /* A private duplicate (same access), so the guest cannot swap the handle
             * between the check and the query; Wow64SystemService closes it */
            if (H(0) != NtCurrentProcess())
            {
                Status = NtDuplicateObject(NtCurrentProcess(), H(0), NtCurrentProcess(), &Cleanup->Handle,
                                           0, 0, DUPLICATE_SAME_ACCESS);
                if (!NT_SUCCESS(Status)) return Status;
                Process = Cleanup->Handle;
            }
            if (!IsCurrentProcess(Process)) UNSUPPORTED(MODE, 3);
            return SectionName32(Process, a[1], a[3], a[4], a[5], Cleanup);
        }
        if (a[2] == 1 /* MemoryWorkingSetInformation */)
            return WorkingSetList32(H(0), a[1], a[3], a[4], a[5], Cleanup);
        /* MemorySharedCommitInformation does not exist for a WoW64 caller (Windows 10 22H2) */
        if (a[2] == 5) return STATUS_INVALID_INFO_CLASS;
        if (a[2] == MemoryRegionInformation || a[2] == 7 /* MemoryRegionInformationEx */)
        {
            /* The 32-bit layout is seven ULONGs; as on Windows (measured on Windows 10 22H2) the whole
             * structure is required, a null buffer is not written (and succeeds), and a bad ReturnLength
             * is ignored */
            MEMORY_REGION_INFORMATION Region;
            struct { ULONG AllocationBase, AllocationProtect, RegionType, RegionSize, CommitSize, PartitionId,
                     NodePreference; } *Region32 = P(3);
            if (a[4] < sizeof(*Region32)) return STATUS_INFO_LENGTH_MISMATCH;
            if ((ULONG64)a[1] > (ULONG64)Wow64HighestUserAddress) return STATUS_INVALID_PARAMETER;
            if (a[3]) ProbeOutput(a[3], sizeof(*Region32));
            if (a[2] == 7 && a[5])
            {
                /* The Ex class stores the length before the process is looked at (measured) */
                _SEH2_TRY
                {
                    U(5) = sizeof(*Region32);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                }
                _SEH2_END;
            }
            Status = NtQueryVirtualMemory(H(0), P(1), a[2], &Region, sizeof(Region), NULL);
            if (!NT_SUCCESS(Status)) return Status;
            if (a[3])
            {
                Region32->AllocationBase = PtrToUlong(Region.AllocationBase);
                Region32->AllocationProtect = Region.AllocationProtect;
                Region32->RegionType = Region.RegionType;
                Region32->RegionSize = (ULONG)min(Region.RegionSize, (SIZE_T)MAXULONG);
                Region32->CommitSize = (ULONG)min(Region.CommitSize, (SIZE_T)MAXULONG);
                Region32->PartitionId = (ULONG)Region.PartitionId;
                Region32->NodePreference = (ULONG)Region.NodePreference;
            }
            if (a[5])
            {
                _SEH2_TRY
                {
                    U(5) = sizeof(*Region32);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                }
                _SEH2_END;
            }
            return STATUS_SUCCESS;
        }
        if (a[2] == 4 /* MemoryWorkingSetExInformation */) return WorkingSetEx32(H(0), a[3], a[4], a[5]);
        if (a[2] == 6 /* MemoryImageInformation */) return ImageInfo32(H(0), a[1], a[3], a[4], a[5]);
        if (a[2] != MemoryBasicInformation && a[2] != 8 /* MemoryPrivilegedBasicInformation */) UNSUPPORTED(CLASS, a[2]);
        if (a[4] < sizeof(*Info32)) return STATUS_INFO_LENGTH_MISMATCH;
        if (a[2] == 8 && a[5])
        {
            /* Class 8 stores the length before the process is looked at (measured) */
            _SEH2_TRY
            {
                U(5) = sizeof(*Info32);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
            }
            _SEH2_END;
        }
        Status = NtQueryVirtualMemory(H(0), P(1), a[2], &Info, sizeof(Info), NULL);
        if (NT_SUCCESS(Status))
        {
            Info32->Base = PtrToUlong(Info.BaseAddress);
            Info32->AllocationBase = PtrToUlong(Info.AllocationBase);
            Info32->AllocationProtect = Info.AllocationProtect;
            Info32->Size = min(Info.RegionSize, (SIZE_T)MAXULONG);
            Info32->State = Info.State; Info32->Protect = Info.Protect; Info32->Type = Info.Type;
            if (a[5]) U(5) = sizeof(*Info32);
        }
        return Status;
    }
    case W64_NtUnmapViewOfSection:
        if (!GuestMemoryRange(P(1), 0)) return GuestMemoryRefused(GuestMemoryUnmap, P(1));
        return NtUnmapViewOfSection(H(0), P(1));
    case W64_NtUnmapViewOfSectionEx:
        if (!GuestMemoryRange(P(1), 0)) return GuestMemoryRefused(GuestMemoryUnmap, P(1));
        return NtUnmapViewOfSectionEx(H(0), P(1), a[2]);
    case W64_NtMapViewOfSectionEx:
    {
        MEM_EXTENDED_PARAMETER Params[WOW64_MAX_EXTENDED_PARAMETERS];
        MEM_ADDRESS_REQUIREMENTS Requirements;
        ULONG Count;
        PROBE(2); PROBE(4);
        if (a[3]) ProbeOutput(a[3], sizeof(LARGE_INTEGER));
        Base = PTR32(U(2)); Size = U(4);
        /* AT_ROUND_TO_PAGE is not for WoW64; an address must be in the 32-bit user space */
        if (a[5] & 0x40000000 /* AT_ROUND_TO_PAGE */) return STATUS_INVALID_PARAMETER;
        if (!GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryMap, Base);
        Cleanup->Process = H(1);
        Cleanup->Mapped = TRUE;
        if (!Base && !a[8])
        {
            /* No address and no requirement: the process' 32-bit limit, as NtMapViewOfSection has it
             * (a placeholder is replaced at its address, so this is never a replacement) */
            Status = NtMapViewOfSection(H(0), H(1), &Base, Wow64ZeroBits(0), 0, P(3), &Size, ViewUnmap, a[5], a[6]);
            if ((Status >= STATUS_INVALID_PARAMETER_1) && (Status <= STATUS_INVALID_PARAMETER_12))
                Status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            Status = ExtendedParameters32(a[7], a[8], Base == NULL, Params, &Requirements, &Count);
            if (!NT_SUCCESS(Status)) return Status;
            Status = NtMapViewOfSectionEx(H(0), H(1), &Base, P(3), &Size, a[5], a[6], Count ? Params : NULL, Count);
        }
        if (NT_SUCCESS(Status))
        {
            /* A view that replaced a placeholder is not undone on a bad output: unmapping it would
             * free the caller's range instead of giving the placeholder back */
            if (!(a[5] & MEM_REPLACE_PLACEHOLDER)) Cleanup->Base = Base;
            U(2) = PtrToUlong(Base); U(4) = Size;
            Cleanup->Base = NULL;
        }
        return Status;
    }
    case W64_NtMapViewOfSection:
        PROBE(2); PROBE(6);
        if (a[5]) ProbeOutput(a[5], sizeof(LARGE_INTEGER));
        Base = PTR32(U(2)); Size = U(6);
        if (Base && !GuestMemoryRange(Base, Size)) return GuestMemoryRefused(GuestMemoryMap, Base);
        Cleanup->Process = H(1);
        Cleanup->Mapped = TRUE;
        {
            /* The kernel names an image view to a debugger by &TEB->NtTib.ArbitraryUserPointer of
             * the native TEB: give it the name the 32-bit loader put in TEB32, as Windows does */
            PVOID SavedName = NtCurrentTeb()->NtTib.ArbitraryUserPointer;
            NtCurrentTeb()->NtTib.ArbitraryUserPointer = PTR32(WOW64_TEB32(NtCurrentTeb())->NtTib.ArbitraryUserPointer);
            Status = NtMapViewOfSection(H(0), H(1), &Base, Wow64ZeroBits(a[3]),
                                        a[4], P(5), &Size, a[7], a[8], a[9]);
            NtCurrentTeb()->NtTib.ArbitraryUserPointer = SavedName;
        }
        if (NT_SUCCESS(Status))
        {
            Cleanup->Base = Base;
            U(2) = PtrToUlong(Base); U(6) = Size;
            Cleanup->Base = NULL;
        }
        return Status;
    case W64_NtCreateSection:
        PROBE(0);
        ATTR(2);
        Status = NtCreateSection(&Cleanup->Handle, a[1], OA(2), P(3), a[4], a[5], H(6));
        RETURN_HANDLE();
    case W64_NtQuerySection:
        if (a[1] == SectionImageInformation)
        {
            SECTION_IMAGE_INFORMATION From;
            struct { ULONG Transfer, ZeroBits, MaximumStack, CommitStack; UCHAR Tail[32]; } *To = P(2);
            if (a[3] < sizeof(*To)) return STATUS_INFO_LENGTH_MISMATCH;
            Status = NtQuerySection(H(0), a[1], &From, sizeof(From), NULL);
            if (NT_SUCCESS(Status))
            {
                To->Transfer = PtrToUlong(From.TransferAddress);
                To->ZeroBits = From.ZeroBits;
                To->MaximumStack = (ULONG)From.MaximumStackSize;
                To->CommitStack = (ULONG)From.CommittedStackSize;
                RtlCopyMemory(To->Tail, (PUCHAR)&From + FIELD_OFFSET(SECTION_IMAGE_INFORMATION, SubSystemType), sizeof(To->Tail));
                if (a[4]) U(4) = sizeof(*To);
            }
            return Status;
        }
        if (a[1] == SectionBasicInformation)
        {
            SECTION_BASIC_INFORMATION From;
            struct { ULONG Base, Attributes; LARGE_INTEGER Size; } *To = P(2);
            if (a[3] < sizeof(*To)) return STATUS_INFO_LENGTH_MISMATCH;
            Status = NtQuerySection(H(0), a[1], &From, sizeof(From), NULL);
            if (NT_SUCCESS(Status))
            {
                To->Base = PtrToUlong(From.BaseAddress); To->Attributes = From.Attributes;
                To->Size = From.Size;
                if (a[4]) U(4) = sizeof(*To);
            }
            return Status;
        }
        UNSUPPORTED(CLASS, a[1]);
    case W64_NtOpenSection:
        PROBE(0);
        ATTR(2); Status = NtOpenSection(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtOpenDirectoryObject:
        PROBE(0);
        ATTR(2); Status = NtOpenDirectoryObject(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtCreateDirectoryObject:
        PROBE(0);
        ATTR(2); Status = NtCreateDirectoryObject(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtCreateSymbolicLinkObject:
    {
        UNICODE_STRING Target;
        PROBE(0);
        ATTR(2);
        Status = NtCreateSymbolicLinkObject(&Cleanup->Handle, a[1], OA(2), String32(&Target, P(3)));
        RETURN_HANDLE();
    }
    case W64_NtOpenSymbolicLinkObject:
        PROBE(0);
        ATTR(2); Status = NtOpenSymbolicLinkObject(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtQuerySymbolicLinkObject:
    {
        WOW64_STRING *Target = P(1);
        /* No descriptor to translate: the kernel gets the NULL an i386 caller would pass
         * and fails the call the same way, never a descriptor left uninitialised here */
        if (!Target) return NtQuerySymbolicLinkObject(H(0), NULL, P(2));
        String32(&Name, Target);
        Status = NtQuerySymbolicLinkObject(H(0), &Name, P(2));
        Target->Length = Name.Length;
        return Status;
    }
    case W64_NtQueryDirectoryObject:
    {
        typedef struct { WOW64_STRING Name, TypeName; } DIRECTORY32;
        OBJECT_DIRECTORY_INFORMATION *From;
        DIRECTORY32 *To = P(1);
        ULONG Index, Bytes = 0, Count = 0, NativeLength, Required, i;
        PUCHAR Strings;
        const ULONG Extra = 2 * (sizeof(*From) - sizeof(*To));
        PROBE(5);
        if (a[6]) PROBE(6);
        ProbeOutput(a[1], a[2]);
        if (a[2] > MAXULONG - Extra) return STATUS_INVALID_PARAMETER;
        Index = a[4] ? 0 : U(5);
        NativeLength = min(a[2], WOW64_MAX_INFO_BUFFER) + Extra;
        From = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, NativeLength);
        if (!From) return STATUS_NO_MEMORY;
        Status = NtQueryDirectoryObject(H(0), From, NativeLength, a[3], a[4], &Index, &Bytes);
        if (!NT_SUCCESS(Status))
        {
            if (a[6]) U(6) = Status == STATUS_BUFFER_TOO_SMALL && Bytes >= Extra ? Bytes - Extra :
                              Bytes >= sizeof(*From) ? Bytes - (sizeof(*From) - sizeof(*To)) : Bytes;
            return Status;
        }
        /* The kernel supplies an array terminated by an empty entry, with
         * both counted strings behind it. The extra space above pays for
         * widening one result and its terminator, even for a single query. */
        while ((Count + 1) * sizeof(*From) <= Bytes && From[Count].Name.Buffer)
            ++Count;
        if ((Count + 1) * sizeof(*From) > Bytes) return STATUS_INFO_LENGTH_MISMATCH;
        Required = Bytes - (Count + 1) * (sizeof(*From) - sizeof(*To));
        if (a[6]) U(6) = Required;
        if (Required > a[2]) return STATUS_BUFFER_TOO_SMALL;
        Strings = (PUCHAR)(To + Count + 1);
        for (i = 0; i < Count; ++i)
        {
            UNICODE_STRING *Source[2] = {&From[i].Name, &From[i].TypeName};
            WOW64_STRING *Destination[2] = {&To[i].Name, &To[i].TypeName};
            ULONG j;
            for (j = 0; j < 2; ++j)
            {
                Destination[j]->Length = Source[j]->Length;
                Destination[j]->MaximumLength = Source[j]->MaximumLength;
                Destination[j]->Buffer = PtrToUlong(Strings);
                RtlCopyMemory(Strings, Source[j]->Buffer, Source[j]->MaximumLength);
                Strings += Source[j]->MaximumLength;
            }
        }
        RtlZeroMemory(To + Count, sizeof(*To));
        U(5) = Index;
        return Status;
    }
    case W64_NtOpenKey:
        PROBE(0);
        ATTR(2);
        KeyAccess = KeyViewAccess(OA(2), a[1]);
        Status = NtOpenKey(&Cleanup->Handle, KeyAccess, OA(2)); RETURN_HANDLE();
    case W64_NtOpenKeyEx:
        PROBE(0);
        ATTR(2);
        KeyAccess = KeyViewAccess(OA(2), a[1]);
        Status = NtOpenKeyEx(&Cleanup->Handle, KeyAccess, OA(2), a[3]); RETURN_HANDLE();
    /* Transacted registry access: the kernel looks at the transaction handle first (invalid handle, wrong type) and
     * no transaction can exist. Measured on Windows 10 22H2 for a 32-bit caller: an invalid transaction handle is
     * STATUS_INVALID_HANDLE whatever the other arguments are (also a NULL output pointer or attributes), and only
     * with a handle that exists a NULL attributes pointer, an attributes block with no name or an output
     * pointer that cannot be written (a NULL one is fine) is STATUS_ACCESS_VIOLATION. */
    case W64_NtOpenKeyTransacted:
        Status = NtOpenKeyTransacted(&Cleanup->Handle, a[1], NULL, H(3));
        if (Status == STATUS_INVALID_HANDLE) return Status;
        if (!a[2]) return STATUS_ACCESS_VIOLATION;
        ATTR(2);
        if (!Attributes.ObjectName) return STATUS_ACCESS_VIOLATION;
        if (a[0]) PROBE(0);
        KeyAccess = KeyViewAccess(OA(2), a[1]);
        Status = NtOpenKeyTransacted(&Cleanup->Handle, KeyAccess, OA(2), H(3)); RETURN_HANDLE();
    case W64_NtOpenKeyTransactedEx:
        Status = NtOpenKeyTransactedEx(&Cleanup->Handle, a[1], NULL, a[3], H(4));
        if (Status == STATUS_INVALID_HANDLE) return Status;
        if (!a[2]) return STATUS_ACCESS_VIOLATION;
        ATTR(2);
        if (!Attributes.ObjectName) return STATUS_ACCESS_VIOLATION;
        if (a[0]) PROBE(0);
        KeyAccess = KeyViewAccess(OA(2), a[1]);
        Status = NtOpenKeyTransactedEx(&Cleanup->Handle, KeyAccess, OA(2), a[3], H(4)); RETURN_HANDLE();
    case W64_NtCreateKeyTransacted:
    {
        UNICODE_STRING Class;
        Status = NtCreateKeyTransacted(&Cleanup->Handle, a[1], NULL, a[3], NULL, a[5], H(6), NULL);
        if (Status == STATUS_INVALID_HANDLE) return Status;
        if (!a[2]) return STATUS_ACCESS_VIOLATION;
        ATTR(2);
        if (!Attributes.ObjectName) return STATUS_ACCESS_VIOLATION;
        if (a[0]) PROBE(0);
        KeyAccess = KeyViewAccess(OA(2), a[1]);
        Status = NtCreateKeyTransacted(&Cleanup->Handle, KeyAccess, OA(2), a[3], String32(&Class, P(4)), a[5], H(6), P(7));
        RETURN_HANDLE();
    }
    case W64_NtCreateKey:
    {
        UNICODE_STRING Class;
        PROBE(0);
        ATTR(2);
        KeyAccess = KeyViewAccess(OA(2), a[1]);
        Status = NtCreateKey(&Cleanup->Handle, KeyAccess, OA(2), a[3], String32(&Class, P(4)), a[5], P(6));
        RETURN_HANDLE();
    }
    case W64_NtCompactKeys:
        return CompactKeys32(a[0], a[1], Cleanup);
    case W64_NtQueryMultipleValueKey:
        return QueryMultipleValueKey32(a, Cleanup);
    case W64_NtQueryOpenSubKeysEx:
        return QueryOpenSubKeysEx32(a, Cleanup);
    case W64_NtNotifyChangeKey:
    case W64_NtNotifyChangeMultipleKeys:
    {
        /* NtNotifyChangeMultipleKeys has two more leading arguments (count and
         * slave objects); only the single key form is supported. The kernel
         * completes the request later: it gets the explicit IOSB32 marker and
         * the encoded APC routine, like NtReadFile, and writes the guest block. */
        ULONG Skip = Number == W64_NtNotifyChangeKey ? 0 : 2;
        PIO_APC_ROUTINE Routine = a[2 + Skip] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2 + Skip] << 2)) : NULL;
        PVOID Iosb = NULL;
        if (Skip && a[1]) UNSUPPORTED(OPERATION, a[1]);
        if (a[4 + Skip])
        {
            ProbeOutput(a[4 + Skip], sizeof(WOW64_IOSB));
            Iosb = (PVOID)(0x8000000000000000ULL | a[4 + Skip]);
        }
        return NtNotifyChangeMultipleKeys(H(0), 0, NULL, H(1 + Skip), Routine, P(3 + Skip), Iosb,
                                          a[5 + Skip], (BOOLEAN)a[6 + Skip], NULL, 0, (BOOLEAN)a[9 + Skip]);
    }
    case W64_NtQueryValueKey:
        return NtQueryValueKey(H(0), String32(&Name, P(1)), a[2], P(3), a[4], P(5));
    case W64_NtSetValueKey:
        return NtSetValueKey(H(0), String32(&Name, P(1)), a[2], a[3], P(4), a[5]);
    case W64_NtRenameKey: return NtRenameKey(H(0), String32(&Name, P(1)));
    case W64_NtDeleteValueKey: return NtDeleteValueKey(H(0), String32(&Name, P(1)));
    /* Hive load, unload and replace. The key names are native registry paths (no file redirection); the
     * hive file name is redirected like any other file open, so a 32-bit caller naming system32 gets the
     * view it expects. */
    case W64_NtLoadKey:
    case W64_NtLoadKey2:
    case W64_NtLoadKeyEx:
    {
        OBJECT_ATTRIBUTES KeyAttributes;
        UNICODE_STRING KeyName;
        SECURITY_DESCRIPTOR KeyDescriptor;
        Status = Attributes32(&KeyAttributes, &KeyName, &KeyDescriptor, a[0]);
        if (!NT_SUCCESS(Status)) return Status;
        FILEATTR(1);
        if (Number == W64_NtLoadKey)
            return NtLoadKey(a[0] ? &KeyAttributes : NULL, OA(1));
        if (Number == W64_NtLoadKey2)
            return NtLoadKey2(a[0] ? &KeyAttributes : NULL, OA(1), a[2]);
        return NtLoadKeyEx(a[0] ? &KeyAttributes : NULL, OA(1), a[2], H(3));
    }
    case W64_NtUnloadKey:
        ATTR(0); return NtUnloadKey(OA(0));
    case W64_NtUnloadKey2:
        ATTR(0); return NtUnloadKey2(OA(0), a[1]);
    case W64_NtUnloadKeyEx:
        ATTR(0); return NtUnloadKeyEx(OA(0), H(1));
    case W64_NtQueryOpenSubKeys:
        PROBE(1); ATTR(0);
        Status = NtQueryOpenSubKeys(OA(0), &Length);
        if (NT_SUCCESS(Status)) U(1) = Length;
        return Status;
    case W64_NtReplaceKey:
    {
        OBJECT_ATTRIBUTES OldAttributes;
        UNICODE_STRING OldName;
        SECURITY_DESCRIPTOR OldDescriptor;
        Status = Attributes32(&OldAttributes, &OldName, &OldDescriptor, a[2]);
        if (!NT_SUCCESS(Status)) return Status;
        FILEATTR(0);
        return NtReplaceKey(OA(0), H(1), a[2] ? &OldAttributes : NULL);
    }
    case W64_NtApphelpCacheControl:
        /* Lookup, Remove and Update take an APPHELP_CACHE_SERVICE_LOOKUP { UNICODE_STRING ImageName; HANDLE ImageHandle; };
         * the other services take no data. Read once; the kernel probes the name. */
        if (a[0] <= ApphelpCacheServiceUpdate)
        {
            const struct { WOW64_STRING ImageName; ULONG ImageHandle; } *From = P(1);
            APPHELP_CACHE_SERVICE_LOOKUP To;

            if (!From) return NtApphelpCacheControl(a[0], NULL);
            String32(&To.ImageName, &From->ImageName);
            To.ImageHandle = HANDLE32(From->ImageHandle);
            return NtApphelpCacheControl(a[0], &To);
        }
        return NtApphelpCacheControl(a[0], NULL);
    case W64_NtCreateJobObject:
        PROBE(0); ATTR(2);
        Status = NtCreateJobObject(&Cleanup->Handle, a[1], OA(2));
        RETURN_HANDLE();
    case W64_NtOpenJobObject:
        PROBE(0); ATTR(2);
        Status = NtOpenJobObject(&Cleanup->Handle, a[1], OA(2));
        RETURN_HANDLE();
    case W64_NtSetInformationJobObject:
        if (a[1] == JobObjectBasicLimitInformation || a[1] == JobObjectExtendedLimitInformation)
        {
            const WOW64_JOB_EXTENDED_LIMIT *From = P(2);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION To = {0};
            BOOLEAN Extended = a[1] == JobObjectExtendedLimitInformation;
            if (a[3] != (Extended ? sizeof(*From) : sizeof(From->Basic)))
                return STATUS_INFO_LENGTH_MISMATCH;
            To.BasicLimitInformation.PerProcessUserTimeLimit = From->Basic.PerProcessUserTimeLimit;
            To.BasicLimitInformation.PerJobUserTimeLimit = From->Basic.PerJobUserTimeLimit;
            To.BasicLimitInformation.LimitFlags = From->Basic.LimitFlags;
            To.BasicLimitInformation.MinimumWorkingSetSize = From->Basic.MinimumWorkingSetSize;
            To.BasicLimitInformation.MaximumWorkingSetSize = From->Basic.MaximumWorkingSetSize;
            To.BasicLimitInformation.ActiveProcessLimit = From->Basic.ActiveProcessLimit;
            To.BasicLimitInformation.Affinity = From->Basic.Affinity;
            To.BasicLimitInformation.PriorityClass = From->Basic.PriorityClass;
            To.BasicLimitInformation.SchedulingClass = From->Basic.SchedulingClass;
            if (Extended)
            {
                To.IoInfo = From->IoInfo;
                To.ProcessMemoryLimit = From->ProcessMemoryLimit;
                To.JobMemoryLimit = From->JobMemoryLimit;
                To.PeakProcessMemoryUsed = From->PeakProcessMemoryUsed;
                To.PeakJobMemoryUsed = From->PeakJobMemoryUsed;
            }
            return NtSetInformationJobObject(H(0), a[1], &To,
                       Extended ? sizeof(To) : sizeof(To.BasicLimitInformation));
        }
        if (a[1] == JobObjectBasicUIRestrictions || a[1] == JobObjectAssociateCompletionPortInformation)
        {
            /* The arguments live on the guest stack: read each once */
            HANDLE Job = H(0);
            ULONG Class = a[1], Buffer = a[2], Length = a[3];
            if (Class == JobObjectBasicUIRestrictions)
            {
                ULONG Restrictions;
                if (Length != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
                if (!GuestRange32(Buffer, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
                Restrictions = *(ULONG *)PTR32(Buffer);
                return NtSetInformationJobObject(Job, Class, &Restrictions, sizeof(Restrictions));
            }
            else
            {
                /* { PVOID CompletionKey; HANDLE CompletionPort; } with 4-byte members. The key
                 * comes back zero-extended through NtRemoveIoCompletion, which truncates it. */
                JOBOBJECT_ASSOCIATE_COMPLETION_PORT Port;
                ULONG Guest[2];
                if (Length != sizeof(Guest)) return STATUS_INFO_LENGTH_MISMATCH;
                if (!GuestRange32(Buffer, sizeof(Guest))) return STATUS_ACCESS_VIOLATION;
                RtlCopyMemory(Guest, PTR32(Buffer), sizeof(Guest));
                Port.CompletionKey = PTR32(Guest[0]);
                Port.CompletionPort = HANDLE32(Guest[1]);
                return NtSetInformationJobObject(Job, Class, &Port, sizeof(Port));
            }
        }
        UNSUPPORTED(CLASS, a[1]);
    case W64_NtQueryInformationJobObject:
    {
        /* The arguments live on the guest stack: read each once */
        HANDLE Job = H(0);
        ULONG Class = a[1], Buffer = a[2], Length = a[3], ReturnLength = a[4];
        if (ReturnLength && !GuestRange32(ReturnLength, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
        switch (Class)
        {
        case JobObjectBasicUIRestrictions:            /* one DWORD */
        case JobObjectBasicAccountingInformation:     /* LARGE_INTEGERs and ULONGs */
        case JobObjectBasicAndIoAccountingInformation:
            if (!GuestRange32(Buffer, Length)) return STATUS_ACCESS_VIOLATION;
            return NtQueryInformationJobObject(Job, Class, PTR32(Buffer), Length, PTR32(ReturnLength));
        case 11: /* JobObjectGroupInformation: an array of USHORT, same layout */
        case 15: /* JobObjectCpuRateControlInformation: two ULONGs, same layout */
            if (!GuestRange32(Buffer, Length)) return STATUS_ACCESS_VIOLATION;
            return NtQueryInformationJobObject(Job, Class, PTR32(Buffer), Length, PTR32(ReturnLength));
        case 14: /* JobObjectGroupInformationEx: GROUP_AFFINITY entries, 12 bytes in a 32-bit process */
        {
            struct { ULONG Mask; USHORT Group; USHORT Reserved[3]; } *To32 = PTR32(Buffer);
            GROUP_AFFINITY From14;
            if (ReturnLength) ProbeOutput(ReturnLength, sizeof(ULONG));
            if (Length % sizeof(*To32) != 0 || Length == 0)
            {
                if (ReturnLength) *(ULONG *)PTR32(ReturnLength) = Length ? Length : sizeof(*To32);
                return Length ? STATUS_INVALID_PARAMETER : STATUS_BUFFER_TOO_SMALL;
            }
            if (!GuestRange32(Buffer, sizeof(*To32))) return STATUS_ACCESS_VIOLATION;
            Status = NtQueryInformationJobObject(Job, Class, &From14, sizeof(From14), NULL);
            if (!NT_SUCCESS(Status)) return Status;
            ProbeOutput(Buffer, sizeof(*To32));
            To32->Mask = (ULONG)From14.Mask;
            To32->Group = From14.Group;
            To32->Reserved[0] = To32->Reserved[1] = To32->Reserved[2] = 0;
            if (ReturnLength) *(ULONG *)PTR32(ReturnLength) = sizeof(*To32);
            return STATUS_SUCCESS;
        }
        case JobObjectBasicLimitInformation:
        case JobObjectExtendedLimitInformation:
        {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION From;
            WOW64_JOB_EXTENDED_LIMIT *To = PTR32(Buffer);
            BOOLEAN Extended = Class == JobObjectExtendedLimitInformation;
            ULONG Size = Extended ? sizeof(*To) : sizeof(To->Basic);
            if (Length != Size) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestRange32(Buffer, Size)) return STATUS_ACCESS_VIOLATION;
            if (ReturnLength) ProbeOutput(ReturnLength, sizeof(ULONG));
            Status = NtQueryInformationJobObject(Job, Class, &From,
                         Extended ? sizeof(From) : sizeof(From.BasicLimitInformation), NULL);
            if (!NT_SUCCESS(Status)) return Status;
            ProbeOutput(Buffer, Size);
            To->Basic.PerProcessUserTimeLimit = From.BasicLimitInformation.PerProcessUserTimeLimit;
            To->Basic.PerJobUserTimeLimit = From.BasicLimitInformation.PerJobUserTimeLimit;
            To->Basic.LimitFlags = From.BasicLimitInformation.LimitFlags;
            To->Basic.MinimumWorkingSetSize = (ULONG)min(From.BasicLimitInformation.MinimumWorkingSetSize, (SIZE_T)MAXULONG);
            To->Basic.MaximumWorkingSetSize = (ULONG)min(From.BasicLimitInformation.MaximumWorkingSetSize, (SIZE_T)MAXULONG);
            To->Basic.ActiveProcessLimit = From.BasicLimitInformation.ActiveProcessLimit;
            To->Basic.Affinity = (ULONG)From.BasicLimitInformation.Affinity;
            To->Basic.PriorityClass = From.BasicLimitInformation.PriorityClass;
            To->Basic.SchedulingClass = From.BasicLimitInformation.SchedulingClass;
            if (Extended)
            {
                To->IoInfo = From.IoInfo;
                To->ProcessMemoryLimit = (ULONG)min(From.ProcessMemoryLimit, (SIZE_T)MAXULONG);
                To->JobMemoryLimit = (ULONG)min(From.JobMemoryLimit, (SIZE_T)MAXULONG);
                To->PeakProcessMemoryUsed = (ULONG)min(From.PeakProcessMemoryUsed, (SIZE_T)MAXULONG);
                To->PeakJobMemoryUsed = (ULONG)min(From.PeakJobMemoryUsed, (SIZE_T)MAXULONG);
            }
            if (ReturnLength) *(ULONG *)PTR32(ReturnLength) = Size;
            return STATUS_SUCCESS;
        }
        default: UNSUPPORTED(CLASS, Class);
        }
    }
    case W64_NtCreateEvent:
        PROBE(0);
        ATTR(2); Status = NtCreateEvent(&Cleanup->Handle, a[1], OA(2), a[3], a[4]); RETURN_HANDLE();
    case W64_NtOpenEvent:
        PROBE(0);
        ATTR(2); Status = NtOpenEvent(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtCreateSemaphore:
        PROBE(0);
        ATTR(2); Status = NtCreateSemaphore(&Cleanup->Handle, a[1], OA(2), a[3], a[4]); RETURN_HANDLE();
    case W64_NtCreateMutant:
        PROBE(0);
        ATTR(2); Status = NtCreateMutant(&Cleanup->Handle, a[1], OA(2), a[3]); RETURN_HANDLE();
    case W64_NtCreateTimer:
        PROBE(0);
        ATTR(2); Status = NtCreateTimer(&Cleanup->Handle, a[1], OA(2), a[3]); RETURN_HANDLE();
    case W64_NtOpenTimer:
        PROBE(0);
        ATTR(2); Status = NtOpenTimer(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtSetTimer:
        return NtSetTimer(H(0), P(1), a[2] ? (PTIMER_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL,
                          P(3), a[4], a[5], P(6));
    case W64_NtCreateTimer2:
        /* Object attributes are refused by the service; translated anyway so it sees what the caller passed */
        PROBE(0);
        ATTR(2); Status = NtCreateTimer2(&Cleanup->Handle, P(1), OA(2), a[3], a[4]); RETURN_HANDLE();
    case W64_NtSetTimer2:
        /* LARGE_INTEGERs and T2_SET_PARAMETERS (ULONG, ULONG, LONGLONG) have the same layout in both ABIs */
        return NtSetTimer2(H(0), P(1), P(2), P(3));
    case W64_NtSetTimerEx:
    {
        /* TIMER_SET_COALESCABLE_TIMER_INFO holds pointers: 32 bytes here, 48 natively. Windows' WOW64
         * accepts a 32-bit length of at least the structure (measured: +8 succeeds, -1 is a length
         * mismatch); other classes and short lengths go through for the service to refuse. */
        struct
        {
            LARGE_INTEGER DueTime;
            ULONG TimerApcRoutine, TimerContext, WakeContext, Period, TolerableDelay, PreviousState;
        } Info32;
        TIMER_SET_COALESCABLE_TIMER_INFO Info;

        C_ASSERT(sizeof(Info32) == 32);
        if (a[1] != TimerSetCoalescableTimer || a[3] < sizeof(Info32))
            return NtSetTimerEx(H(0), a[1], P(2), a[3]);
        _SEH2_TRY
        {
            RtlCopyMemory(&Info32, P(2), sizeof(Info32));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
        Info.DueTime = Info32.DueTime;
        /* The APC routine is encoded as for NtSetTimer */
        Info.TimerApcRoutine = Info32.TimerApcRoutine ?
            (PTIMER_APC_ROUTINE)(ULONG_PTR)(-((LONG64)Info32.TimerApcRoutine << 2)) : NULL;
        Info.TimerContext = ULongToPtr(Info32.TimerContext);
        /* The kernel does not use the wake context (no wake timers); its 32-bit layout differs */
        Info.WakeContext = NULL;
        Info.Period = Info32.Period;
        Info.TolerableDelay = Info32.TolerableDelay;
        Info.PreviousState = ULongToPtr(Info32.PreviousState);
        return NtSetTimerEx(H(0), TimerSetCoalescableTimer, &Info, sizeof(Info));
    }
    case W64_NtCreateIoCompletion:
        PROBE(0);
        ATTR(2); Status = NtCreateIoCompletion(&Cleanup->Handle, a[1], OA(2), a[3]); RETURN_HANDLE();
    case W64_NtOpenIoCompletion:
        PROBE(0);
        ATTR(2); Status = NtOpenIoCompletion(&Cleanup->Handle, a[1], OA(2)); RETURN_HANDLE();
    case W64_NtQueryIoCompletion:
        return NtQueryIoCompletion(H(0), a[1], P(2), a[3], P(4));
    case W64_NtSetIoCompletion:
        return NtSetIoCompletion(H(0), P(1), P(2), a[3], a[4]);
    case W64_NtRemoveIoCompletion:
    {
        PVOID Key, Context;
        PROBE(1); PROBE(2); ProbeOutput(a[3], sizeof(WOW64_IOSB));
        Status = NtRemoveIoCompletion(H(0), &Key, &Context, &Io, P(4));
        if (Status == STATUS_SUCCESS)
        {
            U(1) = PtrToUlong(Key);
            U(2) = PtrToUlong(Context);
            StoreIo(a[3], &Io);
        }
        return Status;
    }
    case W64_NtRemoveIoCompletionEx:
    {
        /* Widen the FILE_IO_COMPLETION_INFORMATION array: the 32-bit entry is
         * { ULONG KeyContext; ULONG ApcContext; WOW64_IOSB; } == 16 bytes, the
         * native one 32 bytes. Remove into a native array, then narrow each of
         * the reported entries. */
        typedef struct { ULONG KeyContext, ApcContext; WOW64_IOSB IoStatusBlock; } WOW64_IO_COMPLETION;
        FILE_IO_COMPLETION_INFORMATION *Native;
        WOW64_IO_COMPLETION *Guest = P(1);
        ULONG Count = a[2], Removed = 0, i;
        if (!Count || Count > WOW64_MAX_ARRAY_COUNT) return STATUS_INVALID_PARAMETER;
        if (!GuestSpan(a[1], (ULONG64)Count * sizeof(*Guest))) return STATUS_ACCESS_VIOLATION;
        PROBE(3);
        ProbeOutput(a[1], Count * sizeof(*Guest));
        Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Count * sizeof(*Native));
        if (!Native) return STATUS_NO_MEMORY;
        Status = NtRemoveIoCompletionEx(H(0), Native, Count, &Removed, P(4), a[5]);
        if (Status == STATUS_SUCCESS)
        {
            if (Removed > Count) Removed = Count;
            for (i = 0; i < Removed; ++i)
            {
                Guest[i].KeyContext = PtrToUlong(Native[i].KeyContext);
                Guest[i].ApcContext = PtrToUlong(Native[i].ApcContext);
                Guest[i].IoStatusBlock.Status = Native[i].IoStatusBlock.Status;
                Guest[i].IoStatusBlock.Information = (ULONG)Native[i].IoStatusBlock.Information;
            }
            U(3) = Removed;
        }
        return Status;
    }
    case W64_NtCreateKeyedEvent:
        PROBE(0);
        ATTR(2); Status = NtCreateKeyedEvent(&Cleanup->Handle, a[1], OA(2), a[3]); RETURN_HANDLE();
    case W64_NtOpenFile:
        PROBE(0); ProbeOutput(a[3], sizeof(WOW64_IOSB));
        FILEATTR(2);
        Status = NtOpenFile(&Cleanup->Handle, a[1], OA(2), &Io, a[4], a[5]);
        /* Failed native calls do not transfer handle ownership. In particular,
         * an undefined failure output must not be closed if StoreIo faults. */
        if (!NT_SUCCESS(Status)) Cleanup->Handle = NULL;
        StoreIo(a[3], &Io); RETURN_HANDLE();
    case W64_NtCreateFile:
        PROBE(0); ProbeOutput(a[3], sizeof(WOW64_IOSB));
        FILEATTR(2);
        Status = NtCreateFile(&Cleanup->Handle, a[1], OA(2), &Io, P(4), a[5], a[6], a[7], a[8], P(9), a[10]);
        if (!NT_SUCCESS(Status)) Cleanup->Handle = NULL;
        StoreIo(a[3], &Io); RETURN_HANDLE();
    case W64_NtCreateNamedPipeFile:
        PROBE(0); ProbeOutput(a[3], sizeof(WOW64_IOSB));
        FILEATTR(2);
        Status = NtCreateNamedPipeFile(&Cleanup->Handle, a[1], OA(2), &Io,
                                       a[4], a[5], a[6], a[7], a[8], a[9],
                                       a[10], a[11], a[12], P(13));
        if (!NT_SUCCESS(Status)) Cleanup->Handle = NULL;
        StoreIo(a[3], &Io); RETURN_HANDLE();
    case W64_NtCreateMailslotFile:
        PROBE(0); ProbeOutput(a[3], sizeof(WOW64_IOSB));
        FILEATTR(2);
        Status = NtCreateMailslotFile(&Cleanup->Handle, a[1], OA(2), &Io, a[4], a[5], a[6], P(7));
        if (!NT_SUCCESS(Status)) Cleanup->Handle = NULL;
        StoreIo(a[3], &Io); RETURN_HANDLE();
    case W64_NtLockFile:
        return NtLockFile(H(0), H(1),
                         a[2] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL,
                         P(3), (PVOID)(0x8000000000000000ULL | a[4]),
                         P(5), P(6), a[7], a[8], a[9]);
    case W64_NtUnlockFile:
        ProbeOutput(a[1], sizeof(WOW64_IOSB));
        /* Native unlock waits for completion, including asynchronous handles. */
        Status = NtUnlockFile(H(0), &Io, P(2), P(3), a[4]);
        StoreIo(a[1], &Io);
        return Status;
    case W64_NtDeviceIoControlFile:
    {
        PIO_APC_ROUTINE Routine = a[2] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL;
        PIO_STATUS_BLOCK Iosb = (PVOID)(0x8000000000000000ULL | a[4]);
        PVOID Input = P(6);
        ULONG InputLength = a[7];
        AFD_RECV_INFO Transfer;
        AFD_SEND_INFO_UDP Datagram;
        AFD_RECV_INFO_MSG RecvDatagram;
        AFD_ACCEPT_DATA Accept;
        AFD_SUPER_ACCEPT_INFO SuperAccept;
        /* These requests contain counted strings/addresses or opaque bytes.
         * AFD requests carrying handles or WSABUF arrays need translation. */
        switch (a[5])
        {
        case IOCTL_AFD_BIND:
        case IOCTL_AFD_CONNECT:
        case IOCTL_AFD_START_LISTEN:
        case IOCTL_AFD_WAIT_FOR_LISTEN:
        case IOCTL_AFD_DISCONNECT:
        case IOCTL_AFD_GET_INFO:
        case IOCTL_AFD_SET_INFO:
        case IOCTL_AFD_GET_SOCK_NAME:
        case IOCTL_AFD_GET_PEER_NAME:
        case IOCTL_AFD_SET_CONTEXT:
        case IOCTL_AFD_GET_CONTEXT_SIZE:
            break;
        case IOCTL_AFD_GET_CONTEXT: /* opaque socket-context blob; output only, symmetric of SET_CONTEXT. */
            /* The guest's own SOCK_SHARED_INFO size gets AFD's current structure, converted.
             * Only this ioctl code: other requests may carry a 140-byte output buffer too. */
            if (a[9] == WOW64_SOCK_SHARED_INFO_SIZE && !a[2] && !a[3] && a[8])
                return AfdGetContext32(a);
            break;
        case IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH:
        /* The rest of the mount manager and mount device requests: counted names and offsets inside one buffer,
         * no pointers (GetVolumeNameForVolumeMountPoint, mount points, drive letters). */
        case IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS:
        case IOCTL_MOUNTMGR_CREATE_POINT:
        case IOCTL_MOUNTMGR_DELETE_POINTS:
        case IOCTL_MOUNTMGR_QUERY_POINTS:
        case IOCTL_MOUNTMGR_DELETE_POINTS_DBONLY:
        case IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER:
        case IOCTL_MOUNTMGR_AUTO_DL_ASSIGNMENTS:
        case IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED:
        case IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED:
        case IOCTL_MOUNTMGR_CHANGE_NOTIFY:
        case IOCTL_MOUNTMGR_KEEP_LINKS_WHEN_OFFLINE:
        case IOCTL_MOUNTMGR_CHECK_UNPROCESSED_VOLUMES:
        case IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION:
        case IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT:
        case IOCTL_MOUNTMGR_SET_AUTO_MOUNT:
        case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
        case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
        case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
        case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
        /* DISK_PERFORMANCE: LARGE_INTEGERs at multiples of 8, the same bytes in both ABIs. */
        case IOCTL_DISK_PERFORMANCE:
        /* Volume extents (LARGE_INTEGERs at multiples of 8) and the storage property query: no pointers. */
        case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
        case IOCTL_STORAGE_QUERY_PROPERTY:
        /* Beep: BEEP_SET_PARAMETERS, two ULONGs (frequency, duration), no output. */
        case IOCTL_BEEP_SET:
        case IOCTL_TCP_QUERY_INFORMATION_EX: /* TCP captures the guest context offset. */
        case IOCTL_TCP_SET_INFORMATION_EX: /* setsockopt partner: TDIObjectID + BufferSize + inline bytes, no pointers. */
        case IOCTL_SET_IP_ADDRESS: /* AddIPAddress: three integers, no pointers. */
        case IOCTL_DELETE_IP_ADDRESS: /* DeleteIPAddress: one integer. */
        case IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST: /* NotifyAddrChange: no data; pends with the guest IOSB. */
        case IOCTL_IP_ADDCHANGE_CANCEL_REQUEST: /* CancelIPChangeNotify: no data. */
        case IOCTL_IP_ROUTECHANGE_NOTIFY_REQUEST: /* NotifyRouteChange: no data; pends with the guest IOSB. */
        case IOCTL_ICMP_ECHO_REQUEST: /* IcmpSendEcho2: the request has no pointers; tcpip writes the 32-bit reply layout. */
        case IOCTL_AFD_GET_TDI_HANDLES: /* AFD captures the 32-bit output handles. */
        case IOCTL_AFD_EVENT_SELECT: /* AFD captures event handles and the in/out record. */
        case IOCTL_AFD_ENUM_NETWORK_EVENTS:
        case IOCTL_AFD_SELECT: /* AFD owns the translated output until completion. */
            break;
        case IOCTL_AFD_ACCEPT:
            if (InputLength < 3 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
            Accept.UseSAN = ((ULONG *)Input)[0];
            Accept.SequenceNumber = ((ULONG *)Input)[1];
            Accept.ListenHandle = HANDLE32(((ULONG *)Input)[2]);
            Input = &Accept;
            InputLength = sizeof(Accept);
            break;
        case IOCTL_AFD_SET_CONNECT_DATA_SIZE:
        case IOCTL_AFD_SET_CONNECT_OPTIONS_SIZE:
        case IOCTL_AFD_SET_DISCONNECT_DATA_SIZE:
        case IOCTL_AFD_SET_DISCONNECT_OPTIONS_SIZE:
        case IOCTL_AFD_SET_CONNECT_DATA: /* opaque bytes in; AFD copies them under its own probe. */
        case IOCTL_AFD_SET_CONNECT_OPTIONS:
        case IOCTL_AFD_SET_DISCONNECT_DATA:
        case IOCTL_AFD_SET_DISCONNECT_OPTIONS:
            break;
        case IOCTL_AFD_GET_CONNECT_DATA: /* opaque bytes out, written by AFD straight to the guest buffer. */
        case IOCTL_AFD_GET_CONNECT_OPTIONS:
        case IOCTL_AFD_GET_DISCONNECT_DATA:
        case IOCTL_AFD_GET_DISCONNECT_OPTIONS:
            /* AFD copies into the output buffer without a probe of its own, so a
             * bad guest buffer must fail here, not fault in the kernel. */
            if (a[9]) ProbeOutput(a[8], a[9]);
            break;
        case IOCTL_AFD_SUPER_ACCEPT:
        {
            /* 32-bit AFD_SUPER_ACCEPT_INFO: SanActive and FixAddressAlignment
             * bytes, the accept socket HANDLE, then the three lengths (20 bytes).
             * The native request is padded to 32 bytes; AFD copies it when it
             * locks the request, so a stack copy is enough even when the accept
             * stays pending. The output buffer (data + addresses) is probed and
             * locked by AFD itself. */
            const ULONG *From = Input;
            if (InputLength < 5 * sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
            RtlZeroMemory(&SuperAccept, sizeof(SuperAccept));
            SuperAccept.SanActive = ((const UCHAR *)Input)[0];
            SuperAccept.FixAddressAlignment = ((const UCHAR *)Input)[1];
            SuperAccept.AcceptHandle = HANDLE32(From[1]);
            SuperAccept.ReceiveDataLength = From[2];
            SuperAccept.LocalAddressLength = From[3];
            SuperAccept.RemoteAddressLength = From[4];
            Input = &SuperAccept;
            InputLength = sizeof(SuperAccept);
            break;
        }
        case IOCTL_AFD_SUPER_CONNECT:
        {
            /* ConnectEx. The request is a SanActive byte followed by an inline TDI
             * TRANSPORT_ADDRESS: counts, lengths and address bytes, no pointer and no
             * handle, so the 32-bit and native layouts are identical and the request
             * passes through (AFD validates the address against the input length).
             * The initial send data is the METHOD_NEITHER output buffer, which AFD
             * probes and copies while it still owns the IRP; the guest OVERLAPPED is
             * the IOSB. Fail a bad input, send buffer or IOSB here, in the guest. */
            if (InputLength < FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress) + sizeof(ULONG) +
                              2 * sizeof(USHORT))
                return STATUS_INVALID_PARAMETER;
            if (!GuestSpan(a[6], InputLength)) return STATUS_ACCESS_VIOLATION;
            ProbeInput(a[6], InputLength);
            if (a[9])
            {
                if (!P(8) || !GuestSpan(a[8], a[9])) return STATUS_ACCESS_VIOLATION;
                ProbeInput(a[8], a[9]);
            }
            break;
        }
        case IOCTL_AFD_SEND_DATAGRAM:
        {
            /* 32-bit AFD_SEND_INFO_UDP: BufferArray, BufferCount, AfdFlags,
             * then TDI_REQUEST_SEND_DATAGRAM (unused by AFD) and
             * TDI_CONNECTION_INFORMATION. AfdPacketSocketWriteData reads only
             * BufferArray/BufferCount and the destination
             * (TdiConnection.RemoteAddress/RemoteAddressLength). Widen the WSABUF
             * array like IOCTL_AFD_SEND and widen the opaque address pointer; the
             * kernel captures the TRANSPORT_ADDRESS target itself. */
            const ULONG *From = Input;
            const ULONG *Buffers;
            ULONG i;
            if (InputLength < 14 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
            RtlZeroMemory(&Datagram, sizeof(Datagram));
            Datagram.BufferCount = From[1];
            Datagram.AfdFlags = From[2];
            Buffers = PTR32(From[0]);
            if (!Datagram.BufferCount ||
                Datagram.BufferCount > WOW64_MAX_ARRAY_COUNT)
                return STATUS_INVALID_PARAMETER;
            Datagram.BufferArray = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0,
                                        Datagram.BufferCount * sizeof(AFD_WSABUF));
            if (!Datagram.BufferArray) return STATUS_NO_MEMORY;
            for (i = 0; i < Datagram.BufferCount; ++i)
            {
                Datagram.BufferArray[i].len = Buffers[2 * i];
                Datagram.BufferArray[i].buf = PTR32(Buffers[2 * i + 1]);
            }
            Datagram.TdiConnection.RemoteAddressLength = From[12];
            Datagram.TdiConnection.RemoteAddress = PTR32(From[13]);
            Input = &Datagram;
            InputLength = sizeof(Datagram);
            break;
        }
        case IOCTL_AFD_RECV_DATAGRAM:
        {
            /* 32-bit AFD_RECV_INFO_UDP: BufferArray, BufferCount, AfdFlags,
             * TdiFlags, Address, AddressLength (all 32-bit). Widen the WSABUF
             * array like IOCTL_AFD_RECV and widen the source-address buffer and
             * address-length pointers; AFD locks the guest buffers and writes
             * the sender sockaddr and its length back through them (the sockaddr
             * layout itself is identical in 32 and 64 bits).
             * WSARecvMsg (AFD_RECV_MSG) adds ControlBuffer, ControlLength and
             * MsgFlags pointers (widened the same way), Options and CmsgHdrSize
             * (the guest's WSACMSGHDR size, 12, which AFD lays the control
             * messages out by). */
            const ULONG *From = Input;
            const ULONG *Buffers;
            ULONG i;
            if (InputLength < 6 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
            RtlZeroMemory(&RecvDatagram, sizeof(RecvDatagram));
            RecvDatagram.Udp.BufferCount = From[1];
            RecvDatagram.Udp.AfdFlags = From[2];
            RecvDatagram.Udp.TdiFlags = From[3];
            RecvDatagram.Udp.Address = PTR32(From[4]);
            RecvDatagram.Udp.AddressLength = PTR32(From[5]);
            if (RecvDatagram.Udp.AfdFlags & AFD_RECV_MSG)
            {
                if (InputLength < 11 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
                RecvDatagram.ControlBuffer = PTR32(From[6]);
                RecvDatagram.ControlLength = PTR32(From[7]);
                RecvDatagram.MsgFlags = PTR32(From[8]);
                RecvDatagram.Options = From[9];
                RecvDatagram.CmsgHdrSize = From[10];
            }
            Buffers = PTR32(From[0]);
            if (!RecvDatagram.Udp.BufferCount ||
                RecvDatagram.Udp.BufferCount > WOW64_MAX_ARRAY_COUNT)
                return STATUS_INVALID_PARAMETER;
            RecvDatagram.Udp.BufferArray = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0,
                                        RecvDatagram.Udp.BufferCount * sizeof(AFD_WSABUF));
            if (!RecvDatagram.Udp.BufferArray) return STATUS_NO_MEMORY;
            for (i = 0; i < RecvDatagram.Udp.BufferCount; ++i)
            {
                RecvDatagram.Udp.BufferArray[i].len = Buffers[2 * i];
                RecvDatagram.Udp.BufferArray[i].buf = PTR32(Buffers[2 * i + 1]);
            }
            Input = &RecvDatagram;
            InputLength = (RecvDatagram.Udp.AfdFlags & AFD_RECV_MSG) ? sizeof(RecvDatagram) :
                                                                       sizeof(RecvDatagram.Udp);
            break;
        }
        case IOCTL_AFD_SEND:
        case IOCTL_AFD_RECV:
        {
            const ULONG *From = Input;
            const ULONG *Buffers;
            ULONG i;
            if (InputLength < 4 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
            Transfer.BufferCount = From[1];
            Transfer.AfdFlags = From[2];
            Transfer.TdiFlags = From[3];
            Buffers = PTR32(From[0]);
            /* AFD's capture adds two pointer-sized mapping fields per buffer
             * and uses a ULONG byte count. Bound that allocation as well. */
            if (!Transfer.BufferCount ||
                Transfer.BufferCount > WOW64_MAX_ARRAY_COUNT)
                return STATUS_INVALID_PARAMETER;
            Transfer.BufferArray = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0,
                                        Transfer.BufferCount * sizeof(AFD_WSABUF));
            if (!Transfer.BufferArray) return STATUS_NO_MEMORY;
            for (i = 0; i < Transfer.BufferCount; ++i)
            {
                Transfer.BufferArray[i].len = Buffers[2 * i];
                Transfer.BufferArray[i].buf = PTR32(Buffers[2 * i + 1]);
            }
            /* AFD captures both the request and the descriptors and locks the
             * actual user buffers before returning STATUS_PENDING. */
            Input = &Transfer;
            InputLength = sizeof(Transfer);
            break;
        }
        case IOCTL_SCSI_PASS_THROUGH:
        case IOCTL_SCSI_PASS_THROUGH_DIRECT:
        case IOCTL_ATA_PASS_THROUGH:
        case IOCTL_ATA_PASS_THROUGH_DIRECT:
            /* The headers hold ULONG_PTR/PVOID fields (scsi.c). The result is stored before this returns,
             * so a guest APC routine cannot be called back: refused as a QueryDirectoryFile does. */
            if (a[2]) UNSUPPORTED(MODE, 1);
            return Wow64ScsiPassThrough(a);
        default:
            /* Codes whose buffers are pointer-free and the same in both ABIs (ioctl.c) */
            if (!Wow64IsPlainIoctl(a[5]))
                UNSUPPORTED(IOCTL, a[5]);
            break;
        }
        ProbeOutput(a[4], sizeof(WOW64_IOSB));
        return NtDeviceIoControlFile(H(0), H(1), Routine, P(3), Iosb,
                                      a[5], Input, InputLength, P(8), a[9]);
    }
    case W64_NtFsControlFile:
    {
        PIO_APC_ROUTINE Routine = a[2] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL;
        PVOID Input = P(6);
        ULONG InputLength = a[7];
        union
        {
            WOW64_MOVE_FILE_DATA Move;
            WOW64_DUPLICATE_EXTENTS_DATA Extents;
            WOW64_MARK_HANDLE_INFO Mark;
        } Wide;
        const ULONG *Guest = Input;
#define GuestQuad(Low) ((LONGLONG)((Low)[0] | ((ULONGLONG)(Low)[1] << 32)))
        /* These pipe operations carry opaque bytes or fixed-width records.
         * Keep the guest IOSB alive through pending listen/transceive requests. */
        switch (a[5])
        {
        case FSCTL_PIPE_PEEK: case FSCTL_PIPE_LISTEN: case FSCTL_PIPE_DISCONNECT:
        case FSCTL_PIPE_WAIT: case FSCTL_PIPE_TRANSCEIVE:
        /* No buffers (impersonate) or opaque bytes: a name in, a number out (GetNamedPipeClientProcessId). */
        case FSCTL_PIPE_IMPERSONATE:
        case FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE:
        case FSCTL_PIPE_SET_CONNECTION_ATTRIBUTE:
        /* The reparse point operations carry a flat REPARSE_DATA_BUFFER (no embedded
         * pointers) in or out; the generic passthrough call suffices. */
        case FSCTL_GET_REPARSE_POINT:
        case FSCTL_SET_REPARSE_POINT:
        case FSCTL_DELETE_REPARSE_POINT:
            break;
        /* A volume handle in a 32-bit slot: widen it. The 32-bit layout is {handle, padding to 8 for the
         * LARGE_INTEGERs, ...} (32 bytes); a packed layout (GCC without 8-byte alignment) is 28 bytes. */
        case FSCTL_MOVE_FILE:
        case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
        {
            ULONG Skew;
            if (InputLength >= 32) Skew = 0;
            else if (InputLength >= 28) Skew = 1;
            else return STATUS_BUFFER_TOO_SMALL;
            RtlZeroMemory(&Wide, sizeof(Wide));
            if (a[5] == FSCTL_MOVE_FILE)
            {
                Wide.Move.FileHandle = HANDLE32(Guest[0]);
                Wide.Move.StartingVcn.QuadPart = GuestQuad(&Guest[2 - Skew]);
                Wide.Move.StartingLcn.QuadPart = GuestQuad(&Guest[4 - Skew]);
                Wide.Move.ClusterCount = Guest[6 - Skew];
                Input = &Wide.Move; InputLength = sizeof(Wide.Move);
            }
            else
            {
                Wide.Extents.FileHandle = HANDLE32(Guest[0]);
                Wide.Extents.SourceFileOffset.QuadPart = GuestQuad(&Guest[2 - Skew]);
                Wide.Extents.TargetFileOffset.QuadPart = GuestQuad(&Guest[4 - Skew]);
                Wide.Extents.ByteCount.QuadPart = GuestQuad(&Guest[6 - Skew]);
                Input = &Wide.Extents; InputLength = sizeof(Wide.Extents);
            }
            break;
        }
        /* MARK_HANDLE_INFO32 {UsnSourceInfo, VolumeHandle, HandleInfo} */
        case FSCTL_MARK_HANDLE:
            if (InputLength < 3 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
            RtlZeroMemory(&Wide, sizeof(Wide));
            Wide.Mark.UsnSourceInfo = Guest[0];
            Wide.Mark.VolumeHandle = HANDLE32(Guest[1]);
            Wide.Mark.HandleInfo = Guest[2];
            Input = &Wide.Mark; InputLength = sizeof(Wide.Mark);
            break;
        default:
            /* Codes whose buffers are pointer-free and the same in both ABIs (ioctl.c) */
            if (!Wow64IsPlainFsctl(a[5]))
                UNSUPPORTED(FSCTL, a[5]);
            break;
        }
#undef GuestQuad
        return NtFsControlFile(H(0), H(1), Routine, P(3), (PVOID)(0x8000000000000000ULL | a[4]),
                               a[5], Input, InputLength, P(8), a[9]);
    }
    case W64_NtQueryAttributesFile:
        FILEATTR(0); return NtQueryAttributesFile(OA(0), P(1));
    case W64_NtQueryFullAttributesFile:
        FILEATTR(0); return NtQueryFullAttributesFile(OA(0), P(1));
    case W64_NtDeleteFile:
        FILEATTR(0); return NtDeleteFile(OA(0));
    case W64_NtFlushBuffersFile:
        /* The block is a local one in both cases: the kernel completes the request before it returns, a
         * synchronous handle through the file object lock and an asynchronous one through its own event and
         * wait (FlushFileBuffers on an overlapped pipe handle waits for the peer to read). A request
         * refused before it started leaves the guest block as it was. */
        Status = NtFlushBuffersFile(H(0), IoBegin(a[1], &Io));
        IoEnd(a[1], &Io);
        return Status;
    case W64_NtFlushBuffersFileEx:
        /* The parameter block is reserved and has to be NULL, so there is nothing to translate; the checks
         * that precede the handle are made by the service on the values as they are. */
        Status = NtFlushBuffersFileEx(H(0), a[1], P(2), a[3], IoBegin(a[4], &Io));
        IoEnd(a[4], &Io);
        return Status;
    case W64_NtQueryWnfStateData:
        /* Every argument is a pointer to the same layout in both ABIs (state name, type id, change stamp and
         * buffer size are plain integers or GUIDs) and the kernel probes them: nothing to translate. */
        return NtQueryWnfStateData(P(0), P(1), P(2), P(3), P(4), P(5));
    case W64_NtQueryEaFile:
        /* Extended attribute lists are flat records: the same bytes in both ABIs */
        Status = NtQueryEaFile(H(0), IoBegin(a[1], &Io), P(2), a[3], (BOOLEAN)a[4], P(5), a[6], P(7), (BOOLEAN)a[8]);
        IoEnd(a[1], &Io); return Status;
    case W64_NtSetEaFile:
        Status = NtSetEaFile(H(0), IoBegin(a[1], &Io), P(2), a[3]);
        IoEnd(a[1], &Io); return Status;
    case W64_NtSetInformationFile:
        return Wow64SetInformationFile(a, Cleanup);
    case W64_NtQueryInformationFile:
        /* No class has a handle or a pointer in a query result, so all of them have the same layout in both ABIs. */
        Status = NtQueryInformationFile(H(0), IoBegin(a[1], &Io), P(2), a[3], a[4]);
        IoEnd(a[1], &Io); return Status;
    case W64_NtQueryDirectoryFile:
        /* Directory entries have the same layout in both ABIs. The entries are written by the file system before
         * the call returns, but an asynchronous handle may be given a pending request: the guest block is only
         * written after it completed. The APC routine and context belong to the guest (they would need the
         * completion to call back into it). */
        if (a[2] || a[3]) UNSUPPORTED(MODE, 1);
        Status = NtQueryDirectoryFile(H(0), H(1), NULL, NULL, IoBegin(a[4], &Io), P(5), a[6], a[7],
                                       (BOOLEAN)a[8], String32(&Name, P(9)), (BOOLEAN)a[10]);
        if (Status == STATUS_PENDING && a[4])
        {
            Status = NtWaitForSingleObject(a[1] ? H(1) : H(0), FALSE, NULL);
            if (NT_SUCCESS(Status)) Status = Io.Status;
        }
        IoEnd(a[4], &Io); return Status;
    case W64_NtQueryVolumeInformationFile:
    case W64_NtSetVolumeInformationFile:
        /* The volume records have the same layout in both ABIs */
        if (Number == W64_NtQueryVolumeInformationFile)
            Status = NtQueryVolumeInformationFile(H(0), IoBegin(a[1], &Io), P(2), a[3], a[4]);
        else
            Status = NtSetVolumeInformationFile(H(0), IoBegin(a[1], &Io), P(2), a[3], a[4]);
        IoEnd(a[1], &Io); return Status;
    case W64_NtReadFile:
    case W64_NtWriteFile:
    {
        PIO_APC_ROUTINE Routine = a[2] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL;
        PIO_STATUS_BLOCK Iosb = (PVOID)(0x8000000000000000ULL | a[4]);
        ProbeOutput(a[4], sizeof(WOW64_IOSB));
        /* The kernel captures this explicit IOSB32 marker in the IRP. Its
         * completion writes the guest block before signaling or queuing APCs,
         * with no per-request user allocation to leak on thread termination. */
        if (Number == W64_NtReadFile)
            return NtReadFile(H(0), H(1), Routine, P(3), Iosb, P(5), a[6], P(7), P(8));
        return NtWriteFile(H(0), H(1), Routine, P(3), Iosb, P(5), a[6], P(7), P(8));
    }
    case W64_NtCancelIoFile:
        ProbeOutput(a[1], sizeof(WOW64_IOSB));
        Status = NtCancelIoFile(H(0), &Io);
        StoreIo(a[1], &Io); return Status;
    case W64_NtCancelIoFileEx:
        /* The request to cancel is only compared with the IOSB pointer the
         * kernel keeps in each IRP. For requests issued through these thunks
         * that is the guest address (the explicit IOSB32 marker is stripped
         * on capture), so pass it zero-extended and without the marker. */
        ProbeOutput(a[2], sizeof(WOW64_IOSB));
        Status = NtCancelIoFileEx(H(0), a[1] ? (PIO_STATUS_BLOCK)(ULONG_PTR)a[1] : NULL, &Io);
        StoreIo(a[2], &Io); return Status;
    case W64_NtCancelSynchronousIoFile:
        /* Like NtCancelIoFileEx the request to cancel is compared with the guest address kept in the IRP */
        ProbeOutput(a[2], sizeof(WOW64_IOSB));
        Status = NtCancelSynchronousIoFile(H(0), a[1] ? (PIO_STATUS_BLOCK)(ULONG_PTR)a[1] : NULL, &Io);
        StoreIo(a[2], &Io); return Status;
    case W64_NtCompareObjects:
        return NtCompareObjects(H(0), H(1));
    case W64_NtAlertThreadByThreadId:
        return NtAlertThreadByThreadId(H(0));
    case W64_NtWaitForAlertByThreadId:
        /* The address is not used; the timeout has the same layout in both ABIs */
        return NtWaitForAlertByThreadId(P(0), (PLARGE_INTEGER)P(1));
    case W64_NtNotifyChangeDirectoryFile:
    {
        /* The kernel completes the request later: like NtReadFile it gets the
         * explicit IOSB32 marker and the encoded APC routine, and writes the
         * guest block. FILE_NOTIFY_INFORMATION is the same in both layouts. */
        PIO_APC_ROUTINE Routine = a[2] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL;
        ProbeOutput(a[4], sizeof(WOW64_IOSB));
        return NtNotifyChangeDirectoryFile(H(0), H(1), Routine, P(3), (PVOID)(0x8000000000000000ULL | a[4]),
                                           P(5), a[6], a[7], (BOOLEAN)a[8]);
    }
    case W64_NtNotifyChangeDirectoryFileEx:
    {
        /* NtNotifyChangeDirectoryFile with the information class as the tenth argument; the records
         * (FILE_NOTIFY_INFORMATION, FILE_NOTIFY_EXTENDED_INFORMATION) are the same in both layouts. */
        PIO_APC_ROUTINE Routine = a[2] ? (PIO_APC_ROUTINE)(ULONG_PTR)(-((LONG64)a[2] << 2)) : NULL;
        ProbeOutput(a[4], sizeof(WOW64_IOSB));
        return NtNotifyChangeDirectoryFileEx(H(0), H(1), Routine, P(3), (PVOID)(0x8000000000000000ULL | a[4]),
                                             P(5), a[6], a[7], (BOOLEAN)a[8], a[9]);
    }
    case W64_NtOpenProcess:
    case W64_NtOpenThread:
    {
        CLIENT_ID Id, *ClientId = NULL;
        PROBE(0);
        ATTR(2);
        if (a[3])
        {
            Id.UniqueProcess = HANDLE32(((ULONG *)P(3))[0]);
            Id.UniqueThread = HANDLE32(((ULONG *)P(3))[1]);
            ClientId = &Id;
        }
        if (Number == W64_NtOpenThread)
            Status = NtOpenThread(&Cleanup->Handle, a[1], OA(2), ClientId);
        else Status = NtOpenProcess(&Cleanup->Handle, a[1], OA(2), ClientId);
        RETURN_HANDLE();
    }
    case W64_NtAdjustPrivilegesToken:
        return NtAdjustPrivilegesToken(H(0), a[1], P(2), a[3], P(4), P(5));
    case W64_NtDuplicateToken:
        PROBE(5); ATTR(2);
        Status = NtDuplicateToken(H(0), a[1], OA(2), a[3], a[4], &Cleanup->Handle);
        RETURN_HANDLE_AT(5);
    case W64_NtAccessCheck:
        return NtAccessCheck(Security32(&Descriptor, P(0)), H(1), a[2], P(3), P(4), P(5), P(6), P(7));
    case W64_NtAccessCheckByType:
    case W64_NtAccessCheckByTypeResultList:
    {
        POBJECT_TYPE_LIST List;
        Status = ObjectTypeList32(a[4], a[5], &List, Cleanup);
        if (!NT_SUCCESS(Status)) return Status;
        if (Number == W64_NtAccessCheckByType)
            return NtAccessCheckByType(Security32(&Descriptor, P(0)), P(1), H(2), a[3], List, a[5], P(6), P(7), P(8),
                                       P(9), P(10));
        return NtAccessCheckByTypeResultList(Security32(&Descriptor, P(0)), P(1), H(2), a[3], List, a[5], P(6), P(7),
                                             P(8), P(9), P(10));
    }
    case W64_NtSetSecurityObject:
        return NtSetSecurityObject(H(0), a[1], Security32(&Descriptor, P(2)));
    case W64_NtQuerySecurityObject:
        return NtQuerySecurityObject(H(0), a[1], P(2), a[3], P(4));
    case W64_NtOpenProcessToken:
        PROBE(2);
        Status = NtOpenProcessToken(H(0), a[1], &Cleanup->Handle);
        RETURN_HANDLE_AT(2);
    case W64_NtOpenThreadToken:
        PROBE(3);
        Status = NtOpenThreadToken(H(0), a[1], a[2], &Cleanup->Handle);
        RETURN_HANDLE_AT(3);
    case W64_NtOpenProcessTokenEx:
        PROBE(3);
        Status = NtOpenProcessTokenEx(H(0), a[1], a[2], &Cleanup->Handle);
        RETURN_HANDLE_AT(3);
    case W64_NtOpenThreadTokenEx:
        PROBE(4);
        Status = NtOpenThreadTokenEx(H(0), a[1], a[2], a[3], &Cleanup->Handle);
        RETURN_HANDLE_AT(4);
    case W64_NtFilterToken:
        return FilterToken32(a, Cleanup);
    case W64_NtCreateLowBoxToken:
    {
        /* The package SID has the same layout in both ABIs and goes through as is */
        PSID_AND_ATTRIBUTES Capabilities;
        HANDLE *Handles;
        PROBE(0); ATTR(3);
        Status = LowBoxArrays32(a[6], a[5], a[8], a[7], Cleanup, &Capabilities, &Handles);
        if (NT_SUCCESS(Status))
            Status = NtCreateLowBoxToken(&Cleanup->Handle, H(1), a[2], OA(3), P(4), a[5], Capabilities, a[7], Handles);
        RETURN_HANDLE_AT(0);
    }
    case W64_NtImpersonateAnonymousToken:
        return NtImpersonateAnonymousToken(H(0));
    case W64_NtPrivilegeCheck:
        /* PRIVILEGE_SET has no pointer and 4-byte fields (a LUID_AND_ATTRIBUTES is 12 bytes in both ABIs) */
        return NtPrivilegeCheck(H(0), P(1), P(2));
    case W64_NtCompareTokens:
        return NtCompareTokens(H(0), H(1), P(2));
    case W64_NtQueryInformationToken:
        /* TOKEN_MANDATORY_LABEL has the layout of TOKEN_USER: a SID_AND_ATTRIBUTES and the SID */
        if (a[1] == TokenUser || a[1] == TokenOwner || a[1] == TokenPrimaryGroup || a[1] == TokenIntegrityLevel)
        {
            union { TOKEN_USER User; UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } Info;
            ULONG Bytes, Prefix = (a[1] == TokenUser || a[1] == TokenIntegrityLevel) ? 2 * sizeof(ULONG) : sizeof(ULONG);
            PROBE(4);
            Status = NtQueryInformationToken(H(0), a[1], &Info, sizeof(Info), &Bytes);
            if (!NT_SUCCESS(Status)) return Status;
            Bytes = RtlLengthSid(Info.User.User.Sid);
            U(4) = Prefix + Bytes;
            if (a[3] < Prefix + Bytes) return STATUS_BUFFER_TOO_SMALL;
            ProbeOutput(a[2], Prefix + Bytes);
            ((ULONG *)P(2))[0] = a[2] + Prefix;
            if (Prefix == 2 * sizeof(ULONG)) ((ULONG *)P(2))[1] = Info.User.User.Attributes;
            RtlCopyMemory((BYTE *)P(2) + Prefix, Info.User.User.Sid, Bytes);
            return STATUS_SUCCESS;
        }
        switch (a[1])
        {
        case TokenType: case TokenImpersonationLevel: case TokenStatistics:
        case TokenSource: case TokenSandBoxInert: case TokenOrigin:
        case 32: /* TokenAppContainerNumber */ case 40: /* TokenIsRestricted */
        case TokenPrivileges: case TokenSessionId: case TokenElevationType:
        case TokenElevation: case TokenIsAppContainer: case TokenHasRestrictions:
        case TokenVirtualizationAllowed: case TokenVirtualizationEnabled:
        case TokenUIAccess: case TokenMandatoryPolicy:
            return NtQueryInformationToken(H(0), a[1], P(2), a[3], P(4));
        case TokenLinkedToken:
        {
            /* A 32-bit caller passes the size of its own handle, 4 bytes (measured on Windows
             * WOW64: any other length is STATUS_INFO_LENGTH_MISMATCH, and the token is
             * checked next). The kernel answers for its 8 byte handle. */
            HANDLE Linked = NULL;
            ULONG Bytes = 0;
            PROBE(4);
            if (a[3] != sizeof(ULONG)) { U(4) = sizeof(ULONG); return STATUS_INFO_LENGTH_MISMATCH; }
            Status = NtQueryInformationToken(H(0), a[1], &Linked, sizeof(Linked), &Bytes);
            U(4) = sizeof(ULONG);
            if (!NT_SUCCESS(Status)) return Status;
            ProbeOutput(a[2], sizeof(ULONG));
            *(ULONG *)P(2) = (ULONG)(ULONG_PTR)Linked;
            return STATUS_SUCCESS;
        }
        case TokenGroups: case TokenRestrictedSids: case TokenLogonSid:
        case 30: /* TokenCapabilities */
            return TokenGroups32(H(0), a[1], a[2], a[3], a[4], Cleanup);
        case TokenGroupsAndPrivileges:
            return TokenGroupsAndPrivileges32(H(0), a[2], a[3], a[4], Cleanup);
        case TokenAccessInformation:
            return TokenAccessInformation32(H(0), a[2], a[3], a[4], Cleanup);
        case 31: /* TokenAppContainerSid */ case 41: /* TokenProcessTrustLevel */
            return TokenPointer32(H(0), a[1], a[2], a[3], a[4]);
        case TokenDefaultDacl:
            return TokenDefaultDacl32(H(0), a[2], a[3], a[4], Cleanup);
        default: UNSUPPORTED(CLASS, a[1]);
        }
    case W64_NtSetInformationToken:
        if (a[1] == TokenOwner || a[1] == TokenPrimaryGroup || a[1] == TokenDefaultDacl)
        {
            PVOID Pointer;
            if (a[3] < sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            Pointer = PTR32(U(2));
            return NtSetInformationToken(H(0), a[1], &Pointer, sizeof(Pointer));
        }
        if (a[1] == TokenSessionId)
            return NtSetInformationToken(H(0), a[1], P(2), a[3]);
        if (a[1] == TokenIntegrityLevel)
        {
            /* TOKEN_MANDATORY_LABEL: a 4-byte SID pointer and the attributes; the kernel
             * captures the SID from guest memory */
            TOKEN_MANDATORY_LABEL Label;
            UCHAR Sid[SECURITY_MAX_SID_SIZE];
            ULONG Header[2], Buffer = a[2], Length = a[3], SidBytes;
            UCHAR Count;
            /* The arguments live on the guest stack and the label in guest memory: read once */
            if (Length < sizeof(Header)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestSpan(Buffer, sizeof(Header))) return STATUS_ACCESS_VIOLATION;
            RtlCopyMemory(Header, PTR32(Buffer), sizeof(Header));
            Label.Label.Attributes = Header[1];
            Label.Label.Sid = NULL;
            if (Header[0])
            {
                if (!GuestSpan(Header[0], FIELD_OFFSET(SID, SubAuthority))) return STATUS_ACCESS_VIOLATION;
                Count = ((SID *)PTR32(Header[0]))->SubAuthorityCount;
                if (Count > SID_MAX_SUB_AUTHORITIES) return STATUS_INVALID_PARAMETER;
                SidBytes = FIELD_OFFSET(SID, SubAuthority) + Count * sizeof(ULONG);
                if (!GuestSpan(Header[0], SidBytes)) return STATUS_ACCESS_VIOLATION;
                RtlCopyMemory(Sid, PTR32(Header[0]), SidBytes);
                ((SID *)Sid)->SubAuthorityCount = Count;
                Label.Label.Sid = Sid;
            }
            return NtSetInformationToken(H(0), TokenIntegrityLevel, &Label, sizeof(Label));
        }
        UNSUPPORTED(CLASS, a[1]);
    case W64_NtQueryInformationProcess:
        if (a[1] == ProcessBasicInformation)
        {
            PROCESS_BASIC_INFORMATION Native;
            ULONG_PTR Peb;
            struct { LONG Exit; ULONG Peb, Affinity; LONG Priority; ULONG Id, Parent; } *Guest = P(2);
            if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
            Status = NtQueryInformationProcess(H(0), ProcessBasicInformation, &Native, sizeof(Native), NULL);
            if (!NT_SUCCESS(Status)) return Status;
            Status = NtQueryInformationProcess(H(0), ProcessWow64Information, &Peb, sizeof(Peb), NULL);
            if (!NT_SUCCESS(Status)) return Status;
            Guest->Exit = Native.ExitStatus;
            Guest->Peb = (ULONG)Peb;
            Guest->Affinity = Native.AffinityMask;
            Guest->Priority = Native.BasePriority;
            Guest->Id = Native.UniqueProcessId;
            Guest->Parent = Native.InheritedFromUniqueProcessId;
            if (a[4]) U(4) = sizeof(*Guest);
            return STATUS_SUCCESS;
        }
        if (a[1] == ProcessWow64Information)
        {
            ULONG_PTR Peb;
            if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            Status = NtQueryInformationProcess(H(0), a[1], &Peb, sizeof(Peb), NULL);
            if (NT_SUCCESS(Status)) U(2) = (ULONG)Peb;
            if (a[4]) U(4) = sizeof(ULONG);
            return Status;
        }
        if (a[1] == ProcessImageFileName || a[1] == ProcessImageFileNameWin32 ||
            a[1] == 60 /* ProcessCommandLineInformation, Windows 8.1 */)
        {
            /* A UNICODE_STRING followed by its characters: the guest header is
             * eight bytes, the native one sixteen, and the buffer pointer is
             * rewritten to the characters behind the guest header. */
            UNICODE_STRING *Native;
            WOW64_STRING *Guest = P(2);
            ULONG Needed = 0, Extra = sizeof(UNICODE_STRING) - sizeof(WOW64_STRING);
            if (a[3] > MAXULONG - Extra) return STATUS_INVALID_PARAMETER;
            if (a[4]) PROBE(4);
            ULONG NativeLen = min(a[3], WOW64_MAX_INFO_BUFFER) + Extra;
            Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeLen);
            if (!Native) return STATUS_NO_MEMORY;
            Status = NtQueryInformationProcess(H(0), a[1], Native, NativeLen, &Needed);
            if (a[4] && Needed) U(4) = Needed >= sizeof(UNICODE_STRING) ? Needed - Extra : Needed;
            if (NT_SUCCESS(Status))
            {
                Guest->Length = Native->Length;
                Guest->MaximumLength = Native->MaximumLength;
                Guest->Buffer = Native->Buffer ? PtrToUlong(Guest + 1) : 0;
                if (Native->Buffer)
                    RtlCopyMemory(Guest + 1, Native->Buffer, Native->MaximumLength);
            }
            return Status;
        }
        if (a[1] == ProcessDebugPort)
        {
            /* The debug port is a pointer-sized value that only ever reports
             * 0 or -1 (debugged) to user mode; narrow it to the guest's ULONG. */
            ULONG_PTR Port;
            if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            if (a[4]) PROBE(4);
            Status = NtQueryInformationProcess(H(0), a[1], &Port, sizeof(Port), NULL);
            if (NT_SUCCESS(Status)) U(2) = (ULONG)Port;
            if (a[4]) U(4) = sizeof(ULONG);
            return Status;
        }
        switch (a[1])
        {
        case ProcessDefaultHardErrorMode: case ProcessExecuteFlags: case ProcessPriorityClass:
        case ProcessSessionInformation: case ProcessBreakOnTermination: case ProcessCookie:
        case ProcessHandleCount: case 58 /* ProcessHandleTable, Windows 8.1 */:
            /* A ULONG, and the handle values as a ULONG array */
            return NtQueryInformationProcess(H(0), a[1], P(2), a[3], P(4));
        case 52 /* ProcessMitigationPolicy: { ULONG Policy; ULONG Flags }, the same in both widths. The sandbox of a
                 * 32-bit Firefox asks it for the Win32k lockdown of its own process (GetProcessMitigationPolicy,
                 * ProcessSystemCallDisablePolicy); refused, the process thinks it is not locked down and creates the
                 * window that the lockdown interception then refuses */:
            return NtQueryInformationProcess(H(0), a[1], P(2), a[3], P(4));
        case ProcessIoCounters: case ProcessTimes: case ProcessVmCounters: case ProcessDeviceMap:
        case ProcessImageFileName: case ProcessQuotaLimits:
            return QueryProcess32(H(0), a[1], a[2], a[3], a[4], Cleanup);
        default: UNSUPPORTED(CLASS, a[1]);
        }
    case W64_NtSetInformationProcess:
        if (a[1] == ProcessTlsInformation) return SetProcessTls32(H(0), a[2], a[3], Cleanup);
        if (a[1] == ProcessAffinityMask)
        {
            ULONG_PTR Affinity;
            if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            Affinity = U(2);
            return NtSetInformationProcess(H(0), a[1], &Affinity, sizeof(Affinity));
        }
        switch (a[1])
        {
        case ProcessDefaultHardErrorMode: case ProcessExecuteFlags: case ProcessPriorityClass:
            return NtSetInformationProcess(H(0), a[1], P(2), a[3]);
        case 52 /* ProcessMitigationPolicy: the Win32k lockdown of the process, set by a 32-bit CreateProcess for
                 * its child and by SetProcessMitigationPolicy; the request is 8 bytes in both widths */:
            return NtSetInformationProcess(H(0), a[1], P(2), a[3]);
        case ProcessAccessToken:
        {
            /* PROCESS_ACCESS_TOKEN: the primary token and the initial thread of a
             * suspended child (CreateProcessAsUser), two guest handles */
            PROCESS_ACCESS_TOKEN Native;
            const ULONG *In = P(2);
            if (a[3] != 2 * sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!a[2] || !GuestSpan(a[2], a[3])) return STATUS_ACCESS_VIOLATION;
            Native.Token = HANDLE32(In[0]);
            Native.Thread = HANDLE32(In[1]);
            return NtSetInformationProcess(H(0), a[1], &Native, sizeof(Native));
        }
        case ProcessQuotaLimits:
        {
            WOW64_QUOTA_LIMITS_EX Guest;
            QUOTA_LIMITS_EX Native;
            BOOLEAN Padded;
            PUCHAR In = P(2);
            if (!QuotaLength32(a[3], &Padded)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!a[2] || !GuestSpan(a[2], a[3])) return STATUS_ACCESS_VIOLATION;
            RtlZeroMemory(&Guest, sizeof(Guest));
            if (!Padded) RtlCopyMemory(&Guest, In, a[3]);
            else
            {
                RtlCopyMemory(&Guest, In, WOW64_QUOTA_TIME_OFFSET);
                RtlCopyMemory((PUCHAR)&Guest + WOW64_QUOTA_TIME_OFFSET, In + WOW64_QUOTA_TIME_OFFSET + sizeof(ULONG),
                              a[3] - WOW64_QUOTA_TIME_OFFSET - sizeof(ULONG));
            }
            /* 0xffffffff is the (SIZE_T)-1 of SetProcessWorkingSetSize(-1, -1), which trims the set */
            RtlZeroMemory(&Native, sizeof(Native));
            Native.PagedPoolLimit = WidenQuota(Guest.PagedPoolLimit);
            Native.NonPagedPoolLimit = WidenQuota(Guest.NonPagedPoolLimit);
            Native.MinimumWorkingSetSize = WidenQuota(Guest.MinimumWorkingSetSize);
            Native.MaximumWorkingSetSize = WidenQuota(Guest.MaximumWorkingSetSize);
            Native.PagefileLimit = WidenQuota(Guest.PagefileLimit);
            Native.TimeLimit.LowPart = Guest.TimeLimitLow;
            Native.TimeLimit.HighPart = Guest.TimeLimitHigh;
            Native.Reserved1 = Guest.Reserved[0];
            Native.Reserved2 = Guest.Reserved[1];
            Native.Reserved3 = Guest.Reserved[2];
            Native.Reserved4 = Guest.Reserved[3];
            Native.Flags = Guest.Flags;
            Native.CpuRateLimit.RateData = Guest.CpuRateLimit;
            return NtSetInformationProcess(H(0), a[1], &Native, sizeof(Native));
        }
        default: UNSUPPORTED(CLASS, a[1]);
        }
    case W64_NtSetInformationThread:
        switch (a[1])
        {
        case ThreadZeroTlsCell:
        {
            ULONG Index;
            if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            Index = U(2);
            if (Index >= TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS) return STATUS_INVALID_PARAMETER;
            Index |= 0x80000000;
            return NtSetInformationThread(H(0), a[1], &Index, sizeof(Index));
        }
        case ThreadQuerySetWin32StartAddress: case ThreadAffinityMask:
        case ThreadPriorityBoost:
        {
            ULONG_PTR Value;
            if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            Value = U(2);
            return NtSetInformationThread(H(0), a[1], &Value, sizeof(Value));
        }
        case ThreadImpersonationToken:
        {
            /* SetThreadToken and RevertToSelf: a token handle, or NULL */
            HANDLE Token;
            if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            Token = HANDLE32(U(2));
            return NtSetInformationThread(H(0), a[1], &Token, sizeof(Token));
        }
        case ThreadHideFromDebugger: case ThreadPriority: case ThreadBasePriority:
        case ThreadBreakOnTermination: case ThreadIdealProcessor:
            return NtSetInformationThread(H(0), a[1], P(2), a[3]);
        case ThreadNameInformation:
        {
            /* THREAD_NAME_INFORMATION is a UNICODE_STRING: widen the 8-byte
             * guest header; the kernel captures and probes the characters. */
            if (a[3] != sizeof(WOW64_STRING)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestSpan(a[2], sizeof(WOW64_STRING))) return STATUS_ACCESS_VIOLATION;
            return NtSetInformationThread(H(0), a[1], String32(&Name, P(2)), sizeof(Name));
        }
        default: UNSUPPORTED(CLASS, a[1]);
        }
    case W64_NtPowerInformation:
        switch (a[0])
        {
        case SystemBatteryState: case SystemPowerCapabilities:
        case ProcessorInformation: case SystemExecutionState:
            /* Fixed-size records of ULONG, BOOLEAN and enumeration fields, the same for
             * both sizes; the native service checks lengths and probes the buffers. They
             * must lie in the guest's range, which the native probe cannot tell. */
            if ((a[1] && !GuestSpan(a[1], a[2])) || (a[3] && !GuestSpan(a[3], a[4])))
                return STATUS_ACCESS_VIOLATION;
            return NtPowerInformation(a[0], P(1), a[2], P(3), a[4]);
        default: UNSUPPORTED(CLASS, a[0]);
        }
    case W64_NtQueryTimerResolution:
    {
        ULONG Minimum, Maximum, Actual;
        PROBE(0); PROBE(1); PROBE(2);
        Status = NtQueryTimerResolution(&Minimum, &Maximum, &Actual);
        if (NT_SUCCESS(Status)) { U(0) = Minimum; U(1) = Maximum; U(2) = Actual; }
        return Status;
    }
    case W64_NtSetTimerResolution:
        /* timeBeginPeriod; the current resolution is a ULONG in both ABIs */
        return NtSetTimerResolution(a[0], (BOOLEAN)a[1], P(2));
    case W64_NtQuerySystemInformation:
        if (a[0] == SystemBasicInformation)
        {
            SYSTEM_BASIC_INFORMATION From;
            WOW64_SYSTEM_BASIC_INFORMATION *To = P(1);
            if (a[2] != sizeof(*To)) return STATUS_INFO_LENGTH_MISMATCH;
            Status = NtQuerySystemInformation(a[0], &From, sizeof(From), NULL);
            if (NT_SUCCESS(Status))
            {
                RtlCopyMemory(To, &From, 7 * sizeof(ULONG));
                To->MinimumUserModeAddress = 0x10000;
                To->MaximumUserModeAddress = NativeSystemInformation ? 0xfffeffff : Wow64HighestUserAddress;
                To->ActiveProcessorsAffinityMask = (ULONG)From.ActiveProcessorsAffinityMask;
                To->NumberOfProcessors = From.NumberOfProcessors;
                if (a[3]) U(3) = sizeof(*To);
            }
            return Status;
        }
        switch (a[0])
        {
        case SystemProcessorInformation:
            Status = NtQuerySystemInformation(a[0], P(1), a[2], P(3));
            if (NT_SUCCESS(Status) && !NativeSystemInformation)
                ((SYSTEM_PROCESSOR_INFORMATION *)P(1))->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
            return Status;
        case SystemNumaProcessorMap:
            /* The same layout for both: two ULONGs, then the ULONGLONG affinity mask of each node */
            return NtQuerySystemInformation(a[0], P(1), a[2], P(3));
        case SystemRangeStartInformation:
            /* The end of the guest's user range, as on Windows WoW64 (measured on Server 2008 R2
             * and Windows 10: 0x7fff0000 for an image that is not large address aware) */
            if (NativeSystemInformation) UNSUPPORTED(CLASS, a[0]);
            /* Windows WoW64 checks the length before the buffers. Both buffers must lie in the
             * guest's range and be writable before anything is stored. */
            if (a[2] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestSpan(a[1], sizeof(ULONG)) || (a[3] && !GuestSpan(a[3], sizeof(ULONG))))
                return STATUS_ACCESS_VIOLATION;
            PROBE(1);
            if (a[3]) PROBE(3);
            U(1) = Wow64HighestUserAddress + 1;
            if (a[3]) U(3) = sizeof(ULONG);
            return STATUS_SUCCESS;
        case SystemLogicalProcessorInformation:
        {
            /* SYSTEM_LOGICAL_PROCESSOR_INFORMATION differs only in the leading
             * ULONG_PTR mask and the padding before the 8-byte-aligned union:
             * native is 32 bytes with the union at 16, the 32-bit form 24 bytes
             * with it at 8; the 16-byte union tail is byte-identical. Query into
             * a native array sized from the required length and narrow each
             * entry, mirroring the Windows WoW64 two-call size protocol. */
            typedef struct { ULONG ProcessorMask, Relationship; UCHAR Union[16]; } WOW64_SLPI;
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION *Native;
            ULONG NativeNeeded = 0, Count, GuestNeeded, i;
            C_ASSERT(sizeof(WOW64_SLPI) == 24);
            C_ASSERT(sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) == 32);
            C_ASSERT(FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION, ProcessorCore) == 16);
            if (a[3]) PROBE(3);
            Status = NtQuerySystemInformation(a[0], NULL, 0, &NativeNeeded);
            if (Status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(Status)) return Status;
            if (!NativeNeeded || NativeNeeded % sizeof(*Native)) return STATUS_UNSUCCESSFUL;
            Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeNeeded);
            if (!Native) return STATUS_NO_MEMORY;
            Status = NtQuerySystemInformation(a[0], Native, NativeNeeded, &NativeNeeded);
            if (!NT_SUCCESS(Status)) return Status;
            Count = NativeNeeded / sizeof(*Native);
            GuestNeeded = Count * sizeof(WOW64_SLPI);
            if (a[3]) U(3) = GuestNeeded;
            if (a[2] < GuestNeeded) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestSpan(a[1], GuestNeeded)) return STATUS_ACCESS_VIOLATION;
            ProbeOutput(a[1], GuestNeeded);
            for (i = 0; i < Count; ++i)
            {
                WOW64_SLPI *G = (WOW64_SLPI *)((PUCHAR)PTR32(a[1]) + i * sizeof(WOW64_SLPI));
                G->ProcessorMask = (ULONG)Native[i].ProcessorMask;
                G->Relationship = Native[i].Relationship;
                RtlCopyMemory(G->Union, &Native[i].ProcessorCore, sizeof(G->Union));
            }
            return STATUS_SUCCESS;
        }
        case SystemFileCacheInformation:
        case SystemFileCacheInformationEx:
        {
            /* SYSTEM_FILECACHE_INFORMATION with 32-bit SIZE_T fields: nine ULONGs, 36 bytes.
             * Sizes that do not fit are saturated, as the Windows WoW64 layer shows it
             * (MaximumWorkingSet 0xffffffff measured on Windows 10). */
            typedef struct { ULONG CurrentSize, PeakSize, PageFaultCount, MinimumWorkingSet, MaximumWorkingSet,
                             CurrentSizeIncludingTransitionInPages, PeakSizeIncludingTransitionInPages,
                             TransitionRePurposeCount, Flags; } WOW64_SFCI;
            SYSTEM_FILECACHE_INFORMATION From;
            WOW64_SFCI *To = P(1);
            C_ASSERT(sizeof(WOW64_SFCI) == 36);
#define SAT32(v) ((ULONG)min((ULONGLONG)(v), (ULONGLONG)0xffffffff))
            if (a[3]) PROBE(3);
            if (a[2] < sizeof(*To))
            {
                if (a[3]) U(3) = sizeof(*To);
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if (!GuestSpan(a[1], sizeof(*To))) return STATUS_ACCESS_VIOLATION;
            ProbeOutput(a[1], sizeof(*To));
            Status = NtQuerySystemInformation(a[0], &From, sizeof(From), NULL);
            if (!NT_SUCCESS(Status)) return Status;
            To->CurrentSize = SAT32(From.CurrentSize);
            To->PeakSize = SAT32(From.PeakSize);
            To->PageFaultCount = From.PageFaultCount;
            To->MinimumWorkingSet = SAT32(From.MinimumWorkingSet);
            To->MaximumWorkingSet = SAT32(From.MaximumWorkingSet);
            To->CurrentSizeIncludingTransitionInPages = SAT32(From.CurrentSizeIncludingTransitionInPages);
            To->PeakSizeIncludingTransitionInPages = SAT32(From.PeakSizeIncludingTransitionInPages);
            To->TransitionRePurposeCount = From.TransitionRePurposeCount;
            To->Flags = From.Flags;
#undef SAT32
            if (a[3]) U(3) = sizeof(*To);
            return STATUS_SUCCESS;
        }
        case SystemPageFileInformation:
        {
            /* One entry per paging file, each followed by its NT name. The 32-bit
             * entry is 24 bytes (UNICODE_STRING is 8); narrow every entry and
             * repack the names, mirroring the two-call size protocol. */
            typedef struct { ULONG NextEntryOffset, TotalSize, TotalInUse, PeakUsage; WOW64_STRING PageFileName; } WOW64_SPFI;
            SYSTEM_PAGEFILE_INFORMATION *Native;
            ULONG NativeNeeded = 0, GuestNeeded = 0, Offset, GuestOffset = 0, Tries;
            C_ASSERT(sizeof(WOW64_SPFI) == 24);
            if (a[3]) PROBE(3);
            if (a[2] < sizeof(WOW64_SPFI))
            {
                if (a[3]) U(3) = sizeof(WOW64_SPFI);
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            NativeNeeded = 0x400;
            for (Tries = 0; ; Tries++)
            {
                if (Cleanup->Buffer) { RtlFreeHeap(RtlGetProcessHeap(), 0, Cleanup->Buffer); Cleanup->Buffer = NULL; }
                Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeNeeded);
                if (!Native) return STATUS_NO_MEMORY;
                Status = NtQuerySystemInformation(a[0], Native, NativeNeeded, &NativeNeeded);
                if (Status != STATUS_INFO_LENGTH_MISMATCH || Tries >= 8) break;
            }
            if (Status == STATUS_INFO_LENGTH_MISMATCH)
            {
                /* Paging files kept appearing: report a size that covers the native one */
                if (a[3]) U(3) = NativeNeeded;
                return Status;
            }
            if (!NT_SUCCESS(Status)) return Status;
            /* Validate the native list (entries and names inside the returned length) */
            for (Offset = 0; NativeNeeded >= sizeof(*Native); )
            {
                SYSTEM_PAGEFILE_INFORMATION *N = (SYSTEM_PAGEFILE_INFORMATION *)((PUCHAR)Native + Offset);
                PUCHAR NameEnd;
                if (Offset > NativeNeeded || NativeNeeded - Offset < sizeof(*N)) return STATUS_INFO_LENGTH_MISMATCH;
                NameEnd = (PUCHAR)N->PageFileName.Buffer + N->PageFileName.Length;
                if ((PUCHAR)N->PageFileName.Buffer < (PUCHAR)(N + 1) || NameEnd < (PUCHAR)N->PageFileName.Buffer ||
                    NameEnd > (PUCHAR)Native + NativeNeeded)
                    return STATUS_INFO_LENGTH_MISMATCH;
                GuestNeeded += ALIGN_UP_BY(sizeof(WOW64_SPFI) + N->PageFileName.Length + sizeof(WCHAR), sizeof(ULONG));
                if (!N->NextEntryOffset) break;
                if (N->NextEntryOffset < sizeof(*N)) return STATUS_INFO_LENGTH_MISMATCH;
                Offset += N->NextEntryOffset;
            }
            if (a[3]) U(3) = GuestNeeded;
            if (a[2] < GuestNeeded) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestNeeded) return STATUS_SUCCESS;
            if (!GuestSpan(a[1], GuestNeeded)) return STATUS_ACCESS_VIOLATION;
            ProbeOutput(a[1], GuestNeeded);
            for (Offset = 0; ; )
            {
                SYSTEM_PAGEFILE_INFORMATION *N = (SYSTEM_PAGEFILE_INFORMATION *)((PUCHAR)Native + Offset);
                WOW64_SPFI *G = (WOW64_SPFI *)((PUCHAR)PTR32(a[1]) + GuestOffset);
                PWCHAR Name = (PWCHAR)(G + 1);
                ULONG Entry = ALIGN_UP_BY(sizeof(WOW64_SPFI) + N->PageFileName.Length + sizeof(WCHAR), sizeof(ULONG));
                G->TotalSize = N->TotalSize;
                G->TotalInUse = N->TotalInUse;
                G->PeakUsage = N->PeakUsage;
                RtlCopyMemory(Name, N->PageFileName.Buffer, N->PageFileName.Length);
                Name[N->PageFileName.Length / sizeof(WCHAR)] = UNICODE_NULL;
                G->PageFileName.Length = N->PageFileName.Length;
                G->PageFileName.MaximumLength = N->PageFileName.Length + sizeof(WCHAR);
                G->PageFileName.Buffer = (ULONG)(ULONG_PTR)Name;
                if (!N->NextEntryOffset)
                {
                    G->NextEntryOffset = 0;
                    break;
                }
                G->NextEntryOffset = Entry;
                GuestOffset += Entry;
                Offset += N->NextEntryOffset;
            }
            return STATUS_SUCCESS;
        }
        case SystemProcessInformation:
        {
            /* Toolhelp32 snapshots, psapi/EnumProcesses and most process
             * enumerators use this class. Query the native list (growing the
             * buffer as processes come and go), then narrow every process and
             * thread entry to the 32-bit layout (0xB8 + 0x40 per thread) and
             * copy the image name after the threads, 8-byte aligned, as the
             * 32-bit kernel lays it out. */
            typedef struct
            {
                LARGE_INTEGER KernelTime, UserTime, CreateTime;
                ULONG WaitTime, StartAddress, UniqueProcess, UniqueThread;
                LONG Priority, BasePriority;
                ULONG ContextSwitches, ThreadState, WaitReason, Pad;
            } WOW64_SYSTEM_THREAD_INFORMATION;
            typedef struct
            {
                ULONG NextEntryOffset, NumberOfThreads;
                LARGE_INTEGER WorkingSetPrivateSize;
                ULONG HardFaultCount, NumberOfThreadsHighWatermark;
                ULONGLONG CycleTime;
                LARGE_INTEGER CreateTime, UserTime, KernelTime;
                WOW64_STRING ImageName;
                LONG BasePriority;
                ULONG UniqueProcessId, InheritedFromUniqueProcessId, HandleCount, SessionId, PageDirectoryBase;
                ULONG PeakVirtualSize, VirtualSize, PageFaultCount, PeakWorkingSetSize, WorkingSetSize;
                ULONG QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
                ULONG PagefileUsage, PeakPagefileUsage, PrivatePageCount;
                LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount;
                LARGE_INTEGER ReadTransferCount, WriteTransferCount, OtherTransferCount;
            } WOW64_SYSTEM_PROCESS_INFORMATION;
            SYSTEM_PROCESS_INFORMATION *Np;
            PUCHAR Native = NULL, Guest;
            ULONG NativeSize = 0x10000, Offset, GuestNeeded, GuestOffset, i, Retries = 0;
            C_ASSERT(sizeof(WOW64_SYSTEM_THREAD_INFORMATION) == 0x40);
            C_ASSERT(sizeof(WOW64_SYSTEM_PROCESS_INFORMATION) == 0xB8);
            if (NativeSystemInformation) UNSUPPORTED(CLASS, a[0]);
            if (a[3]) PROBE(3);
            for (;;)
            {
                if (Native) RtlFreeHeap(RtlGetProcessHeap(), 0, Native);
                Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeSize);
                if (!Native) return STATUS_NO_MEMORY;
                Status = NtQuerySystemInformation(a[0], Native, NativeSize, &Offset);
                if (Status != STATUS_INFO_LENGTH_MISMATCH || ++Retries > 16) break;
                NativeSize = max(NativeSize * 2, Offset + 0x4000);
            }
            if (!NT_SUCCESS(Status)) return Status;
            /* Size of the 32-bit form */
            GuestNeeded = 0;
            for (Offset = 0;;)
            {
                Np = (SYSTEM_PROCESS_INFORMATION *)(Native + Offset);
                GuestNeeded += sizeof(WOW64_SYSTEM_PROCESS_INFORMATION) +
                               Np->NumberOfThreads * sizeof(WOW64_SYSTEM_THREAD_INFORMATION);
                if (Np->ImageName.Buffer)
                    GuestNeeded += ALIGN_UP_BY(Np->ImageName.MaximumLength ? Np->ImageName.MaximumLength :
                                               Np->ImageName.Length + sizeof(WCHAR), 8);
                if (!Np->NextEntryOffset) break;
                Offset += Np->NextEntryOffset;
            }
            if (a[3]) U(3) = GuestNeeded;
            if (a[2] < GuestNeeded) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestSpan(a[1], GuestNeeded)) return STATUS_ACCESS_VIOLATION;
            ProbeOutput(a[1], GuestNeeded);
            Guest = PTR32(a[1]);
            for (Offset = 0, GuestOffset = 0;;)
            {
                WOW64_SYSTEM_PROCESS_INFORMATION *Gp = (WOW64_SYSTEM_PROCESS_INFORMATION *)(Guest + GuestOffset);
                SYSTEM_THREAD_INFORMATION *Nt;
                WOW64_SYSTEM_THREAD_INFORMATION *Gt;
                ULONG Size;
                Np = (SYSTEM_PROCESS_INFORMATION *)(Native + Offset);
                Nt = (SYSTEM_THREAD_INFORMATION *)(Np + 1);
                Gt = (WOW64_SYSTEM_THREAD_INFORMATION *)(Gp + 1);
                RtlZeroMemory(Gp, sizeof(*Gp));
                Gp->NumberOfThreads = Np->NumberOfThreads;
                Gp->WorkingSetPrivateSize = Np->WorkingSetPrivateSize;
                Gp->HardFaultCount = Np->HardFaultCount;
                Gp->NumberOfThreadsHighWatermark = Np->NumberOfThreadsHighWatermark;
                Gp->CycleTime = Np->CycleTime;
                Gp->CreateTime = Np->CreateTime;
                Gp->UserTime = Np->UserTime;
                Gp->KernelTime = Np->KernelTime;
                Gp->BasePriority = Np->BasePriority;
                Gp->UniqueProcessId = HandleToUlong(Np->UniqueProcessId);
                Gp->InheritedFromUniqueProcessId = HandleToUlong(Np->InheritedFromUniqueProcessId);
                Gp->HandleCount = Np->HandleCount;
                Gp->SessionId = Np->SessionId;
                Gp->PageDirectoryBase = (ULONG)Np->PageDirectoryBase;
#define CLAMP32(x) ((ULONG)min((SIZE_T)(x), (SIZE_T)MAXULONG))
                Gp->PeakVirtualSize = CLAMP32(Np->PeakVirtualSize);
                Gp->VirtualSize = CLAMP32(Np->VirtualSize);
                Gp->PageFaultCount = Np->PageFaultCount;
                Gp->PeakWorkingSetSize = CLAMP32(Np->PeakWorkingSetSize);
                Gp->WorkingSetSize = CLAMP32(Np->WorkingSetSize);
                Gp->QuotaPeakPagedPoolUsage = CLAMP32(Np->QuotaPeakPagedPoolUsage);
                Gp->QuotaPagedPoolUsage = CLAMP32(Np->QuotaPagedPoolUsage);
                Gp->QuotaPeakNonPagedPoolUsage = CLAMP32(Np->QuotaPeakNonPagedPoolUsage);
                Gp->QuotaNonPagedPoolUsage = CLAMP32(Np->QuotaNonPagedPoolUsage);
                Gp->PagefileUsage = CLAMP32(Np->PagefileUsage);
                Gp->PeakPagefileUsage = CLAMP32(Np->PeakPagefileUsage);
                Gp->PrivatePageCount = CLAMP32(Np->PrivatePageCount);
#undef CLAMP32
                Gp->ReadOperationCount = Np->ReadOperationCount;
                Gp->WriteOperationCount = Np->WriteOperationCount;
                Gp->OtherOperationCount = Np->OtherOperationCount;
                Gp->ReadTransferCount = Np->ReadTransferCount;
                Gp->WriteTransferCount = Np->WriteTransferCount;
                Gp->OtherTransferCount = Np->OtherTransferCount;
                for (i = 0; i < Np->NumberOfThreads; ++i)
                {
                    Gt[i].KernelTime = Nt[i].KernelTime;
                    Gt[i].UserTime = Nt[i].UserTime;
                    Gt[i].CreateTime = Nt[i].CreateTime;
                    Gt[i].WaitTime = Nt[i].WaitTime;
                    Gt[i].StartAddress = (ULONG)(ULONG_PTR)Nt[i].StartAddress;
                    Gt[i].UniqueProcess = HandleToUlong(Nt[i].ClientId.UniqueProcess);
                    Gt[i].UniqueThread = HandleToUlong(Nt[i].ClientId.UniqueThread);
                    Gt[i].Priority = Nt[i].Priority;
                    Gt[i].BasePriority = Nt[i].BasePriority;
                    Gt[i].ContextSwitches = Nt[i].ContextSwitches;
                    Gt[i].ThreadState = Nt[i].ThreadState;
                    Gt[i].WaitReason = Nt[i].WaitReason;
                    Gt[i].Pad = 0;
                }
                Size = sizeof(*Gp) + Np->NumberOfThreads * sizeof(*Gt);
                if (Np->ImageName.Buffer)
                {
                    ULONG Max = Np->ImageName.MaximumLength ? Np->ImageName.MaximumLength :
                                Np->ImageName.Length + sizeof(WCHAR);
                    PUCHAR Name = (PUCHAR)Gp + Size;
                    RtlZeroMemory(Name, ALIGN_UP_BY(Max, 8));
                    RtlCopyMemory(Name, Np->ImageName.Buffer, min(Np->ImageName.Length, Max));
                    Gp->ImageName.Length = Np->ImageName.Length;
                    Gp->ImageName.MaximumLength = (USHORT)Max;
                    Gp->ImageName.Buffer = (ULONG)(ULONG_PTR)Name;
                    Size += ALIGN_UP_BY(Max, 8);
                }
                if (!Np->NextEntryOffset) break;
                Gp->NextEntryOffset = Size;
                GuestOffset += Size;
                Offset += Np->NextEntryOffset;
            }
            return STATUS_SUCCESS;
        }
        case SystemHandleInformation:
        {
            /* The system-wide handle table, as pss, psapi and the process explorers read it. The native
             * entry (24 bytes, with a 64-bit object pointer) narrows to the 16 bytes of the 32-bit form. */
            typedef struct
            {
                USHORT UniqueProcessId, CreatorBackTraceIndex;
                UCHAR ObjectTypeIndex, HandleAttributes;
                USHORT HandleValue;
                ULONG Object, GrantedAccess;
            } WOW64_SYSTEM_HANDLE_ENTRY;
            typedef struct
            {
                ULONG NumberOfHandles;
                WOW64_SYSTEM_HANDLE_ENTRY Handles[1];
            } WOW64_SYSTEM_HANDLE_INFORMATION;
            SYSTEM_HANDLE_INFORMATION *Nh;
            WOW64_SYSTEM_HANDLE_INFORMATION *Gh;
            PUCHAR Native = NULL;
            ULONG NativeSize = 0x40000, Offset, GuestNeeded, i, Retries = 0;
            C_ASSERT(sizeof(WOW64_SYSTEM_HANDLE_ENTRY) == 16);
            if (NativeSystemInformation) UNSUPPORTED(CLASS, a[0]);
            if (a[3]) PROBE(3);
            for (;;)
            {
                if (Native) RtlFreeHeap(RtlGetProcessHeap(), 0, Native);
                Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeSize);
                if (!Native) return STATUS_NO_MEMORY;
                Status = NtQuerySystemInformation(a[0], Native, NativeSize, &Offset);
                if (Status != STATUS_INFO_LENGTH_MISMATCH || ++Retries > 16) break;
                NativeSize = max(NativeSize * 2, Offset + 0x4000);
            }
            if (!NT_SUCCESS(Status)) return Status;
            Nh = (SYSTEM_HANDLE_INFORMATION *)Native;
            GuestNeeded = FIELD_OFFSET(WOW64_SYSTEM_HANDLE_INFORMATION, Handles) +
                          Nh->NumberOfHandles * sizeof(WOW64_SYSTEM_HANDLE_ENTRY);
            if (a[3]) U(3) = GuestNeeded;
            if (a[2] < GuestNeeded) return STATUS_INFO_LENGTH_MISMATCH;
            if (!GuestSpan(a[1], GuestNeeded)) return STATUS_ACCESS_VIOLATION;
            ProbeOutput(a[1], GuestNeeded);
            Gh = PTR32(a[1]);
            Gh->NumberOfHandles = Nh->NumberOfHandles;
            for (i = 0; i < Nh->NumberOfHandles; ++i)
            {
                Gh->Handles[i].UniqueProcessId = Nh->Handles[i].UniqueProcessId;
                Gh->Handles[i].CreatorBackTraceIndex = Nh->Handles[i].CreatorBackTraceIndex;
                Gh->Handles[i].ObjectTypeIndex = Nh->Handles[i].ObjectTypeIndex;
                Gh->Handles[i].HandleAttributes = Nh->Handles[i].HandleAttributes;
                Gh->Handles[i].HandleValue = Nh->Handles[i].HandleValue;
                Gh->Handles[i].Object = (ULONG)(ULONG_PTR)Nh->Handles[i].Object;
                Gh->Handles[i].GrantedAccess = Nh->Handles[i].GrantedAccess;
            }
            return STATUS_SUCCESS;
        }
        case SystemExtendedHandleInformation:
        {
            /* The extended handle table. The 32-bit form is measured on Windows 10 22H2 WoW64: an 8-byte header
             * (ULONG count, ULONG reserved) and 28-byte entries of 32-bit fields. Object is the low 32 bits of the
             * kernel address, as in class 16. A buffer shorter than the header and one entry is refused with that
             * length (36) and nothing stored; a longer but too short one receives the header with the full count
             * and as many whole entries as fit, then STATUS_INFO_LENGTH_MISMATCH with the length of the whole
             * table. The reserved field is stored as zero (Windows leaves it uninitialised). */
            typedef struct
            {
                ULONG Object, UniqueProcessId, HandleValue, GrantedAccess;
                USHORT CreatorBackTraceIndex, ObjectTypeIndex;
                ULONG HandleAttributes, Reserved;
            } WOW64_SYSTEM_HANDLE_ENTRY_EX;
            typedef struct
            {
                ULONG NumberOfHandles, Reserved;
                WOW64_SYSTEM_HANDLE_ENTRY_EX Handles[1];
            } WOW64_SYSTEM_HANDLE_INFORMATION_EX;
            SYSTEM_HANDLE_INFORMATION_EX *Nh;
            WOW64_SYSTEM_HANDLE_INFORMATION_EX *Gh;
            PUCHAR Native = NULL;
            ULONG NativeSize = 0x40000, Offset, Count, Fit, GuestNeeded, GuestWritten, i, Retries = 0;
            C_ASSERT(sizeof(WOW64_SYSTEM_HANDLE_ENTRY_EX) == 28);
            C_ASSERT(sizeof(WOW64_SYSTEM_HANDLE_INFORMATION_EX) == 36);
            if (NativeSystemInformation) UNSUPPORTED(CLASS, a[0]);
            if (a[3]) PROBE(3);
            if (a[2] < sizeof(WOW64_SYSTEM_HANDLE_INFORMATION_EX))
            {
                if (a[3]) U(3) = sizeof(WOW64_SYSTEM_HANDLE_INFORMATION_EX);
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            for (;;)
            {
                if (Native) RtlFreeHeap(RtlGetProcessHeap(), 0, Native);
                Native = Cleanup->Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeSize);
                if (!Native) return STATUS_NO_MEMORY;
                Status = NtQuerySystemInformation(a[0], Native, NativeSize, &Offset);
                if (Status != STATUS_INFO_LENGTH_MISMATCH || ++Retries > 16) break;
                NativeSize = max(NativeSize * 2, Offset + 0x4000);
            }
            if (!NT_SUCCESS(Status)) return Status;
            Nh = (SYSTEM_HANDLE_INFORMATION_EX *)Native;
            /* The count is the kernel's, but never read past what the native call returned */
            Count = (ULONG)min(Nh->NumberOfHandles,
                               (NativeSize - FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles)) / sizeof(Nh->Handles[0]));
            GuestNeeded = FIELD_OFFSET(WOW64_SYSTEM_HANDLE_INFORMATION_EX, Handles) + Count * sizeof(WOW64_SYSTEM_HANDLE_ENTRY_EX);
            Fit = min(Count, (a[2] - FIELD_OFFSET(WOW64_SYSTEM_HANDLE_INFORMATION_EX, Handles)) / sizeof(WOW64_SYSTEM_HANDLE_ENTRY_EX));
            GuestWritten = FIELD_OFFSET(WOW64_SYSTEM_HANDLE_INFORMATION_EX, Handles) + Fit * sizeof(WOW64_SYSTEM_HANDLE_ENTRY_EX);
            if (!GuestSpan(a[1], GuestWritten)) return STATUS_ACCESS_VIOLATION;
            ProbeOutput(a[1], GuestWritten);
            if (a[3]) U(3) = GuestNeeded;
            Gh = PTR32(a[1]);
            Gh->NumberOfHandles = Count;
            Gh->Reserved = 0;
            for (i = 0; i < Fit; ++i)
            {
                Gh->Handles[i].Object = (ULONG)(ULONG_PTR)Nh->Handles[i].Object;
                Gh->Handles[i].UniqueProcessId = (ULONG)Nh->Handles[i].UniqueProcessId;
                Gh->Handles[i].HandleValue = (ULONG)Nh->Handles[i].HandleValue;
                Gh->Handles[i].GrantedAccess = Nh->Handles[i].GrantedAccess;
                Gh->Handles[i].CreatorBackTraceIndex = Nh->Handles[i].CreatorBackTraceIndex;
                Gh->Handles[i].ObjectTypeIndex = Nh->Handles[i].ObjectTypeIndex;
                Gh->Handles[i].HandleAttributes = Nh->Handles[i].HandleAttributes;
                Gh->Handles[i].Reserved = 0;
            }
            return Fit < Count ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;
        }
        case SystemCurrentTimeZoneInformation: /* RTL_TIME_ZONE_INFORMATION has no pointers. */
        case SystemTimeOfDayInformation:
        case SystemPerformanceInformation: /* LARGE_INTEGER/ULONG counters, no pointers, same layout. */
        case SystemTimeAdjustmentInformation: /* { ULONG, ULONG, BOOLEAN }, no pointers. */
        case SystemProcessorPerformanceInformation: /* an array of 48-byte records of LARGE_INTEGER and ULONG fields, no pointers; Windows WoW64 returns the native records too. */
            return NtQuerySystemInformation(a[0], P(1), a[2], P(3));
        default: UNSUPPORTED(CLASS, a[0]);
        }
    case W64_NtSetSystemInformation:
        switch (a[0])
        {
        case SystemCurrentTimeZoneInformation: /* RTL_TIME_ZONE_INFORMATION (172 bytes), no pointers, same layout; the kernel checks SeTimeZonePrivilege. */
        case SystemDynamicTimeZoneInformation: /* RTL_DYNAMIC_TIME_ZONE_INFORMATION (432 bytes), no pointers, same layout; the kernel checks the length, then SeTimeZonePrivilege. */
        case SystemTimeAdjustmentInformation: /* SYSTEM_SET_TIME_ADJUST_INFORMATION { ULONG, BOOLEAN } is 8 bytes in both ABIs; the kernel checks SeSystemtimePrivilege and the length. */
            return NtSetSystemInformation(a[0], P(1), a[2]);
        default: UNSUPPORTED(CLASS, a[0]);
        }
    default:
        /* Name the information class of the class-based services as well */
        switch (Number)
        {
        case W64_NtQueryInformationJobObject: case W64_NtQueryInformationPort:
            Length = a[1]; break;
        default: Length = 0; break;
        }
        UNSUPPORTED(SERVICE, Length);
    }
}

NTSTATUS NTAPI Wow64SystemServiceFull(ULONG Number, ULONG *Arguments)
{
    NTSTATUS Status;
    WOW64_CLEANUP Cleanup = {0};
    WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    /* The argument list is on the guest stack, where other guest threads can change it.
     * The NT thunks see only this copy, read once, so a value they checked stays the
     * value they use. */
    ULONG Captured[WOW64_MAX_ARGUMENTS] = {0};
    /* Assembly has finished every save, including EAX and FXSAVE. Keep the
     * flag set outside this routine: that also covers the low-address gate,
     * the instructions following CALL and the final IRET itself. */
    Cpu->ContextEaxChanged = FALSE;
    Cpu->InTransition = 0;
    _ReadWriteBarrier();
    /* All pointer expansion occurs in user mode. Faulting captures become
     * NT errors; no untyped 32-bit argument list is sent to the kernel. */
    _SEH2_TRY
    {
        if (Number >= 0x1000 && Number < 0x2000)
            Status = Wow64WinSystemService(Number, Arguments);
        else
        {
            RtlCopyMemory(Captured, Arguments, ServiceArgumentCount(Number) * sizeof(ULONG));
            Status = Dispatch(Number, Captured, &Cleanup);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (Cleanup.Thread)
        Wow64AbortThread(Cleanup.Thread, Cleanup.ThreadProcess, Status);
    if (Cleanup.Handle)
    {
        if (Cleanup.HandleProcess)
            NtDuplicateObject(Cleanup.HandleProcess, Cleanup.Handle, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
        else NtClose(Cleanup.Handle);
    }
    if (Cleanup.Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, Cleanup.Buffer);
    if (Cleanup.Base)
    {
        if (Cleanup.Mapped)
            NtUnmapViewOfSection(Cleanup.Process, Cleanup.Base);
        else
        {
            SIZE_T Size = 0;
            NtFreeVirtualMemory(Cleanup.Process, &Cleanup.Base, &Size, MEM_RELEASE);
        }
    }
#if DBG
    if (!NT_SUCCESS(Status) && !Cleanup.Reported && Number != W64_NtQueryDebugFilterState &&
        !(Number >= 0x1000 && Number < 0x2000))
        DbgPrint("WoW64: service %lx returned %08lx\n", Number, Status);
#endif
    _ReadWriteBarrier();
    Cpu->InTransition = 1;
    _ReadWriteBarrier();
    if (!Cpu->ContextEaxChanged) Cpu->Eax = Status;
    return Status;
}
