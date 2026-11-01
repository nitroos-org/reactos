/* ReactOS WoW64 private definitions. SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#define NTOS_MODE_USER
#include <ndk/ntndk.h>
#include <pseh/pseh2.h>
#include <reactos/wow64context.h>

#define PTR32(Value) ((PVOID)(ULONG_PTR)(ULONG)(Value))
#define HANDLE32(Value) ((HANDLE)(LONG_PTR)(LONG)(Value))

typedef struct { ULONG Status, Information; } WOW64_IOSB;
typedef struct { USHORT Length, MaximumLength; ULONG Buffer; } WOW64_STRING;
typedef struct
{
    ULONG Length, RootDirectory, ObjectName, Attributes;
    ULONG SecurityDescriptor, SecurityQualityOfService;
} WOW64_OBJECT_ATTRIBUTES;

typedef struct { WOW64_STRING DosPath; ULONG Handle; } WOW64_CURDIR;
typedef struct { USHORT Flags, Length; ULONG TimeStamp; WOW64_STRING DosPath; } WOW64_DRIVE;
typedef struct
{
    ULONG MaximumLength, Length, Flags, DebugFlags;
    ULONG ConsoleHandle, ConsoleFlags, StandardInput, StandardOutput, StandardError;
    WOW64_CURDIR CurrentDirectory;
    WOW64_STRING DllPath, ImagePathName, CommandLine;
    ULONG Environment;
    ULONG StartingX, StartingY, CountX, CountY, CountCharsX, CountCharsY;
    ULONG FillAttribute, WindowFlags, ShowWindowFlags;
    WOW64_STRING WindowTitle, DesktopInfo, ShellInfo, RuntimeData;
    WOW64_DRIVE CurrentDirectories[32];
    ULONG EnvironmentSize;
} WOW64_PARAMETERS;

NTSTATUS NTAPI Wow64SystemService(ULONG Number, ULONG *Arguments);

/* Requests this layer does not translate. Wow64Unsupported prints one debug line
 * per process for each (service, kind, value), sets *Reported so that
 * Wow64SystemService does not print its generic failure line for the call, and
 * returns the status the guest has always received: STATUS_INVALID_SYSTEM_SERVICE
 * for a service without a translation, STATUS_NOT_SUPPORTED otherwise. */
enum
{
    WOW64_UNSUPPORTED_SERVICE,   /* no translation; value: the information class, if any */
    WOW64_UNSUPPORTED_CLASS,     /* information class */
    WOW64_UNSUPPORTED_IOCTL,     /* device I/O control code */
    WOW64_UNSUPPORTED_FSCTL,     /* file system control code */
    WOW64_UNSUPPORTED_MODE,      /* 1: asynchronous request, 2: handle not opened for synchronous I/O,
                                    3: request on another process */
    WOW64_UNSUPPORTED_ATTRIBUTE, /* process/thread attribute */
    WOW64_UNSUPPORTED_CSR_API,   /* (server << 16) | API number */
    WOW64_UNSUPPORTED_CSR_SERVER,/* server DLL index of a connection */
    WOW64_UNSUPPORTED_OPERATION  /* private CSR operation number */
};
#define WOW64_SERVICE_CSR 0x10000
#define WOW64_SERVICE_CREATE_PROCESS 0x10003
BOOLEAN Wow64FirstReport(ULONG Service, ULONG Kind, ULONG Value);
NTSTATUS Wow64Unsupported(ULONG Service, ULONG Kind, ULONG Value, BOOLEAN *Reported);
/* ioctl.c: control codes passed to the native call without translation */
BOOLEAN Wow64IsPlainIoctl(ULONG Code);
BOOLEAN Wow64IsPlainFsctl(ULONG Code);
NTSTATUS Wow64Allocate(SIZE_T Size, PVOID *Base);
/* syscall.c guest-memory helpers used by scsi.c */
VOID ProbeInput(ULONG Address, ULONG Size);
VOID ProbeOutput(ULONG Address, ULONG Size);
BOOLEAN GuestSpan(ULONG Address, ULONG64 Size);
IO_STATUS_BLOCK *IoBegin(ULONG Address, IO_STATUS_BLOCK *Io);
VOID IoEnd(ULONG Address, const IO_STATUS_BLOCK *Io);
/* scsi.c: SCSI and ATA pass-through of a 32-bit caller (the arguments of NtDeviceIoControlFile) */
NTSTATUS Wow64ScsiPassThrough(const ULONG *a);
extern ULONG Wow64HighestUserAddress;
ULONG_PTR Wow64ZeroBits(ULONG ZeroBits);

NTSTATUS Wow64CopyString(WOW64_STRING *To, const UNICODE_STRING *From);
NTSTATUS Wow64CsrDispatch(ULONG Operation, ULONG *Arguments, BOOLEAN *Reported);
BOOLEAN Wow64CsrThreadStart(PCONTEXT Context, ULONG *Routine, ULONG *Parameter);
NTSTATUS Wow64LpcConnect(ULONG Number, const ULONG *Arguments, HANDLE *Handle, BOOLEAN *Reported);
NTSTATUS Wow64LpcRequest(ULONG Number, ULONG Handle, ULONG Request, ULONG Reply, BOOLEAN *Reported);
VOID Wow64LpcForget(ULONG Handle);
extern PVOID Wow64ExceptionDispatcher;
NTSTATUS Wow64Continue(const WOW64_CONTEXT *Context, BOOLEAN TestAlert);
NTSTATUS Wow64GetSetContextThread(HANDLE Thread, WOW64_CONTEXT *Guest, BOOLEAN Set);
NTSTATUS Wow64InitializeRedirection(VOID);
NTSTATUS Wow64RedirectFile(OBJECT_ATTRIBUTES *Attributes, UNICODE_STRING *Name, PVOID *Buffer);

typedef struct
{
    ULONG Reserved, TimerResolution, PageSize, NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber, HighestPhysicalPageNumber, AllocationGranularity;
    ULONG MinimumUserModeAddress, MaximumUserModeAddress, ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} WOW64_SYSTEM_BASIC_INFORMATION;

NTSTATUS Wow64CreateEnvironment(PVOID *Environment);
NTSTATUS Wow64CreateProcess(PVOID Request, BOOLEAN *Reported);

VOID Wow64InitializeTeb(TEB32 *, const TEB *, PTEB, const INITIAL_TEB *);
VOID Wow64AbortThread(HANDLE, HANDLE, NTSTATUS);
NTSTATUS Wow64CreateThread(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, HANDLE,
                           CLIENT_ID *, const WOW64_CONTEXT *, const ULONG *, BOOLEAN);
/* Caps on host allocations sized by guest-supplied lengths or counts. Counted
 * strings are at most 64 KiB each, so a larger native query buffer is never
 * useful; element arrays (WSABUFs, completion entries, token SIDs) stay far
 * below the count cap in real use. */
#define WOW64_MAX_INFO_BUFFER 0x30000UL
#define WOW64_MAX_ARRAY_COUNT 0x10000UL

NTSTATUS Wow64QueryThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
/* debug.c: NtDebugContinue and NtWaitForDebugEvent of a 32-bit debugger (the captured arguments) */
NTSTATUS Wow64DebugContinue(const ULONG *);
NTSTATUS Wow64WaitForDebugEvent(const ULONG *);

extern PVOID Wow64ApcDispatcher;

NTSTATUS Wow64RaiseException(const EXCEPTION_RECORD32 *, const WOW64_CONTEXT *, BOOLEAN);
