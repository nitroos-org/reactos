/*
 * PROJECT:     ReactOS Kernel-Mode Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Test driver for ObRegisterCallbacks. At load it checks the argument
 *              validation and the altitude rules, then registers two process
 *              callbacks: A (altitude 321000) strips PROCESS_SET_QUOTA,
 *              B (altitude 400000.5) strips
 *              PROCESS_TERMINATE. obcbcheck.exe sees the result in the access of
 *              the handles it opens and duplicates. Lines "OBCBTEST: ..." go to
 *              the debugger; the order of the callbacks is checked there.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <ntddk.h>

/* The headers declare these only for Vista SP1 and later; the test builds for the default target */
NTKERNELAPI NTSTATUS NTAPI ObRegisterCallbacks(_In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
                                               _Outptr_ PVOID *RegistrationHandle);
NTKERNELAPI VOID NTAPI ObUnRegisterCallbacks(_In_ PVOID RegistrationHandle);
NTKERNELAPI USHORT NTAPI ObGetFilterVersion(VOID);

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE        0x0001
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA        0x0100
#endif

static PVOID RegA, RegB;
static PDEVICE_OBJECT Device;

NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(IN PEPROCESS Process);

/* Only the test client obcbcheck.exe is filtered; every other process (csrss, process creation) is untouched */
static
BOOLEAN
IsClient(PVOID Process)
{
    return !_strnicmp(PsGetProcessImageFileName(Process), "obcbcheck", 9);
}
static LONG Fails;

#define CHECK(cond, text) \
    do { if (!(cond)) { Fails++; DbgPrint("OBCBTEST: FAIL %s\n", text); } \
         else DbgPrint("OBCBTEST: ok   %s\n", text); } while (0)

static
OB_PREOP_CALLBACK_STATUS
NTAPI
PreA(PVOID Context, POB_PRE_OPERATION_INFORMATION Info)
{
    if (!IsClient(Info->Object)) return OB_PREOP_SUCCESS;
    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
        DbgPrint("OBCBTEST: pre  A dup\n");
    }
    else
    {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
        DbgPrint("OBCBTEST: pre  A create (context %p)\n", Context);
    }
    Info->CallContext = (PVOID)(ULONG_PTR)'A';
    return OB_PREOP_SUCCESS;
}

static
OB_PREOP_CALLBACK_STATUS
NTAPI
PreB(PVOID Context, POB_PRE_OPERATION_INFORMATION Info)
{
    if (!IsClient(Info->Object)) return OB_PREOP_SUCCESS;
    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
    else
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
    DbgPrint("OBCBTEST: pre  B\n");
    Info->CallContext = (PVOID)(ULONG_PTR)'B';
    return OB_PREOP_SUCCESS;
}

static
VOID
NTAPI
PostA(PVOID Context, POB_POST_OPERATION_INFORMATION Info)
{
    if (!IsClient(Info->Object)) return;
    DbgPrint("OBCBTEST: post A context=%c status=%08lx granted=%08lx\n",
             (char)(ULONG_PTR)Info->CallContext, Info->ReturnStatus,
             Info->Parameters->CreateHandleInformation.GrantedAccess);
}

static
VOID
NTAPI
PostB(PVOID Context, POB_POST_OPERATION_INFORMATION Info)
{
    if (!IsClient(Info->Object)) return;
    DbgPrint("OBCBTEST: post B context=%c\n", (char)(ULONG_PTR)Info->CallContext);
}

static
NTSTATUS
Register(PCWSTR Altitude, POB_PRE_OPERATION_CALLBACK Pre, POB_POST_OPERATION_CALLBACK Post, PVOID *Handle)
{
    OB_OPERATION_REGISTRATION Op;
    OB_CALLBACK_REGISTRATION Reg;

    Op.ObjectType = PsProcessType;
    Op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Op.PreOperation = Pre;
    Op.PostOperation = Post;
    Reg.Version = OB_FLT_REGISTRATION_VERSION;
    Reg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&Reg.Altitude, Altitude);
    Reg.RegistrationContext = (PVOID)0x1234;
    Reg.OperationRegistration = &Op;
    return ObRegisterCallbacks(&Reg, Handle);
}

static
VOID
NTAPI
DriverUnload(PDRIVER_OBJECT DriverObject)
{
    if (RegB) ObUnRegisterCallbacks(RegB);
    if (RegA) ObUnRegisterCallbacks(RegA);
    if (Device) IoDeleteDevice(Device);
    DbgPrint("OBCBTEST: unloaded, callbacks unregistered\n");
}

NTSTATUS
NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PVOID Dummy = NULL;
    NTSTATUS Status;
    OB_CALLBACK_REGISTRATION Reg;
    OB_OPERATION_REGISTRATION Op;

    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\ObCbTest");

    /* A driver without a device is not a legacy driver and is not unloaded */
    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &Device);
    if (!NT_SUCCESS(Status)) return Status;
    DriverObject->DriverUnload = DriverUnload;

    CHECK(ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION, "ObGetFilterVersion is 0x0100");

    /* bad version, bad altitude, no callback at all */
    Op.ObjectType = PsProcessType;
    Op.Operations = OB_OPERATION_HANDLE_CREATE;
    Op.PreOperation = PreA;
    Op.PostOperation = NULL;
    Reg.Version = 0x0200;
    Reg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&Reg.Altitude, L"321000");
    Reg.RegistrationContext = NULL;
    Reg.OperationRegistration = &Op;
    CHECK(ObRegisterCallbacks(&Reg, &Dummy) == STATUS_INVALID_PARAMETER, "bad version is refused");
    Reg.Version = OB_FLT_REGISTRATION_VERSION;
    RtlInitUnicodeString(&Reg.Altitude, L"abc");
    CHECK(ObRegisterCallbacks(&Reg, &Dummy) == STATUS_INVALID_PARAMETER, "non numeric altitude is refused");
    RtlInitUnicodeString(&Reg.Altitude, L"321000");
    Op.PreOperation = NULL;
    CHECK(ObRegisterCallbacks(&Reg, &Dummy) == STATUS_INVALID_PARAMETER, "no pre and no post callback is refused");

    Status = Register(L"321000", PreA, PostA, &RegA);
    CHECK(NT_SUCCESS(Status) && RegA, "register A at 321000");
    Status = Register(L"400000.5", PreB, PostB, &RegB);
    CHECK(NT_SUCCESS(Status) && RegB, "register B at 400000.5");
    CHECK(Register(L"321000", PreA, PostA, &Dummy) == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION,
          "the same altitude twice collides");
    CHECK(Register(L"0321000.0", PreA, PostA, &Dummy) == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION,
          "an equal altitude spelled differently collides");

    DbgPrint("OBCBTEST: load done, %ld failure(s)\n", Fails);
    return Fails ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
