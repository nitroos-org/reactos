/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for IoCreateSystemThread
 *              (semantics from the public WDK documentation)
 */

#include <kmt_test.h>

typedef NTSTATUS (NTAPI *PIO_CREATE_SYSTEM_THREAD)(PVOID, PHANDLE, ULONG, POBJECT_ATTRIBUTES,
                                                   HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID);

typedef struct _THREAD_CONTEXT
{
    KEVENT Started;
    KEVENT Go;
    BOOLEAN ReturnFromRoutine;
} THREAD_CONTEXT;

static
VOID
NTAPI
ThreadRoutine(
    _In_ PVOID Context)
{
    THREAD_CONTEXT *Ctx = Context;

    KeSetEvent(&Ctx->Started, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(&Ctx->Go, Executive, KernelMode, FALSE, NULL);
    if (Ctx->ReturnFromRoutine)
        return;
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
LONG
RefCount(
    _In_ PVOID Object)
{
    return OBJECT_TO_OBJECT_HEADER(Object)->PointerCount;
}

static
VOID
RunOnce(
    _In_ PIO_CREATE_SYSTEM_THREAD pIoCreateSystemThread,
    _In_ PVOID IoObject,
    _In_ BOOLEAN ReturnFromRoutine)
{
    THREAD_CONTEXT Ctx;
    HANDLE Handle;
    PKTHREAD Thread;
    NTSTATUS Status;
    LONG Before, During, After;
    LARGE_INTEGER Timeout;
    ULONG i;

    KeInitializeEvent(&Ctx.Started, NotificationEvent, FALSE);
    KeInitializeEvent(&Ctx.Go, NotificationEvent, FALSE);
    Ctx.ReturnFromRoutine = ReturnFromRoutine;

    Before = RefCount(KmtDriverObject);
    Status = pIoCreateSystemThread(IoObject, &Handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                   ThreadRoutine, &Ctx);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    Status = ObReferenceObjectByHandle(Handle, SYNCHRONIZE, *PsThreadType, KernelMode,
                                       (PVOID *)&Thread, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    Timeout.QuadPart = -100 * 1000 * 10 * 10; /* 10 s */
    Status = KeWaitForSingleObject(&Ctx.Started, Executive, KernelMode, FALSE, &Timeout);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /* while the thread runs, the driver object is held */
    During = RefCount(KmtDriverObject);
    ok(During > Before, "driver reference count %ld did not grow over %ld\n", During, Before);

    KeSetEvent(&Ctx.Go, IO_NO_INCREMENT, FALSE);
    if (NT_SUCCESS(Status))
    {
        Status = KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, &Timeout);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }
    ObDereferenceObject(Thread);
    ZwClose(Handle);

    /* the reference is released while the thread is exiting: allow a moment */
    Timeout.QuadPart = -10 * 1000 * 10;
    for (i = 0; i < 500; i++)
    {
        After = RefCount(KmtDriverObject);
        if (After <= Before)
            break;
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
    }
    ok_eq_long(After, Before);
}

START_TEST(IoCreateSystemThread)
{
    PIO_CREATE_SYSTEM_THREAD pIoCreateSystemThread;
    HANDLE Handle = NULL;
    NTSTATUS Status;

    pIoCreateSystemThread = KmtGetSystemRoutineAddress(L"IoCreateSystemThread");
    ok(pIoCreateSystemThread != NULL, "IoCreateSystemThread is not exported\n");
    if (!pIoCreateSystemThread)
        return;

    /* the documented IoObject is a driver or device object */
    RunOnce(pIoCreateSystemThread, KmtDriverObject, FALSE);
    RunOnce(pIoCreateSystemThread, KmtDriverObject, TRUE);
    if (KmtDriverObject->DeviceObject)
        RunOnce(pIoCreateSystemThread, KmtDriverObject->DeviceObject, FALSE);

    /* bad parameters */
    Status = pIoCreateSystemThread(NULL, &Handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, ThreadRoutine, NULL);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    Status = pIoCreateSystemThread(KmtDriverObject, &Handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, NULL);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
}
