/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for the "WithTag" object manager
 *              routines of Windows 7 and later, ObGetObjectPointerCount and
 *              ObIsKernelHandle
 */

#include <kmt_test.h>

typedef LONG_PTR (FASTCALL *POBF_TAGGED)(PVOID, ULONG);
typedef NTSTATUS (NTAPI *POB_BY_HANDLE_TAG)(HANDLE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, ULONG, PVOID *, POBJECT_HANDLE_INFORMATION);
typedef NTSTATUS (NTAPI *POB_BY_POINTER_TAG)(PVOID, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, ULONG);
typedef VOID (NTAPI *POB_DEFER_TAG)(PVOID, ULONG);
typedef NTSTATUS (NTAPI *POB_OPEN_BY_POINTER_TAG)(PVOID, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, ULONG, PHANDLE);
typedef ULONG (NTAPI *POB_GET_COUNT)(PVOID);
typedef BOOLEAN (NTAPI *POB_IS_KERNEL_HANDLE)(HANDLE);

#define TEST_TAG 'gTbO'

START_TEST(ObWithTag)
{
    POBF_TAGGED pRef = KmtGetSystemRoutineAddress(L"ObfReferenceObjectWithTag");
    POBF_TAGGED pDeref = KmtGetSystemRoutineAddress(L"ObfDereferenceObjectWithTag");
    POB_BY_HANDLE_TAG pByHandle = KmtGetSystemRoutineAddress(L"ObReferenceObjectByHandleWithTag");
    POB_BY_POINTER_TAG pByPointer = KmtGetSystemRoutineAddress(L"ObReferenceObjectByPointerWithTag");
    POB_DEFER_TAG pDefer = KmtGetSystemRoutineAddress(L"ObDereferenceObjectDeferDeleteWithTag");
    POB_OPEN_BY_POINTER_TAG pOpen = KmtGetSystemRoutineAddress(L"ObOpenObjectByPointerWithTag");
    POB_GET_COUNT pCount = KmtGetSystemRoutineAddress(L"ObGetObjectPointerCount");
    POB_IS_KERNEL_HANDLE pIsKernel = KmtGetSystemRoutineAddress(L"ObIsKernelHandle");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE EventHandle = NULL, Copy = NULL;
    PKEVENT Event = NULL, Same = NULL;
    NTSTATUS Status;
    LONG Base;

    ok(pRef && pDeref && pByHandle && pByPointer && pDefer && pOpen && pCount && pIsKernel,
       "a tagged object manager routine is not exported\n");
    if (!(pRef && pDeref && pByHandle && pByPointer && pDefer && pOpen && pCount && pIsKernel))
        return;

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateEvent(&EventHandle, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    ok(pIsKernel(EventHandle), "OBJ_KERNEL_HANDLE handle %p not a kernel handle\n", EventHandle);
    ok(!pIsKernel((HANDLE)(ULONG_PTR)0x44), "user-style handle reported as kernel handle\n");

    Status = pByHandle(EventHandle, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, TEST_TAG, (PVOID *)&Event, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        /* the reference is counted like the untagged one */
        Base = (LONG)pCount(Event);
        ok(Base >= 2, "pointer count %ld\n", Base);

        ok_eq_ulong(pCount(Event), (ULONG)Base);
        pRef(Event, TEST_TAG);
        ok_eq_ulong(pCount(Event), (ULONG)Base + 1);
        pDeref(Event, TEST_TAG);
        ok_eq_ulong(pCount(Event), (ULONG)Base);

        Status = pByPointer(Event, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, TEST_TAG);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_ulong(pCount(Event), (ULONG)Base + 1);
        pDeref(Event, TEST_TAG);

        /* a wrong type is refused for a user mode request (kernel mode requests skip the type check) */
        Status = pByPointer(Event, EVENT_ALL_ACCESS, *IoFileObjectType, UserMode, TEST_TAG);
        ok_eq_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);

        Status = pOpen(Event, OBJ_KERNEL_HANDLE, NULL, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, TEST_TAG, &Copy);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = ObReferenceObjectByHandle(Copy, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID *)&Same, NULL);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok_eq_pointer(Same, Event);
            if (Same)
                ObDereferenceObject(Same);
            ZwClose(Copy);
        }

        pDefer(Event, TEST_TAG);
    }
    ZwClose(EventHandle);
}
