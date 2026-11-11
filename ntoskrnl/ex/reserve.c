/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Memory reserve objects (NtAllocateReserveObject): "UserApcReserve" and "IoCompletionReserve"
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

POBJECT_TYPE ExUserApcReserveObjectType;
POBJECT_TYPE ExIoCompletionReserveObjectType;

/*
 * Measured on Windows 10 22H2: both types have the generic mapping below, the valid access mask 0xF0003, the invalid
 * attributes OBJ_PERMANENT | OBJ_EXCLUSIVE | OBJ_OPENIF and the non-paged pool, a new handle has the full access
 * (0xF0003) and is not inheritable unless the caller asks for it.
 */
#define RESERVE_OBJECT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x3)

static
GENERIC_MAPPING ExpReserveMapping =
{
    STANDARD_RIGHTS_READ | 0x1,
    STANDARD_RIGHTS_WRITE | 0x2,
    STANDARD_RIGHTS_EXECUTE,
    RESERVE_OBJECT_ALL_ACCESS
};

/* FUNCTIONS *****************************************************************/

static
CODE_SEG("INIT")
BOOLEAN
ExpCreateReserveObjectType(IN PCWSTR TypeName,
                           OUT POBJECT_TYPE *ObjectType)
{
    OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
    UNICODE_STRING Name;

    RtlZeroMemory(&ObjectTypeInitializer, sizeof(ObjectTypeInitializer));
    RtlInitUnicodeString(&Name, TypeName);
    ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
    ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(EX_RESERVE_OBJECT);
    ObjectTypeInitializer.GenericMapping = ExpReserveMapping;
    ObjectTypeInitializer.PoolType = NonPagedPool;
    ObjectTypeInitializer.ValidAccessMask = RESERVE_OBJECT_ALL_ACCESS;
    ObjectTypeInitializer.InvalidAttributes = OBJ_PERMANENT | OBJ_EXCLUSIVE | OBJ_OPENIF;
    return NT_SUCCESS(ObCreateObjectType(&Name, &ObjectTypeInitializer, NULL, ObjectType));
}

CODE_SEG("INIT")
BOOLEAN
NTAPI
ExpInitializeReserveObjectImplementation(VOID)
{
    return ExpCreateReserveObjectType(L"UserApcReserve", &ExUserApcReserveObjectType) &&
           ExpCreateReserveObjectType(L"IoCompletionReserve", &ExIoCompletionReserveObjectType);
}

/*
 * @name NtAllocateReserveObject
 *
 *    Windows 7 and later. Creates the object that holds the storage of one APC (type 0, UserApcReserve) or of one
 *    I/O completion packet (type 1, IoCompletionReserve), so that queueing it later cannot fail for memory.
 *    Only the APC reserve is used here (NtQueueApcThreadEx); the I/O completion reserve is created and can be
 *    closed, and is rejected where an APC reserve is expected, as on Windows.
 */
NTSTATUS
NTAPI
NtAllocateReserveObject(OUT PHANDLE MemoryReserveHandle,
                        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                        IN MEMORY_RESERVE_TYPE Type)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEX_RESERVE_OBJECT Reserve;
    HANDLE Handle;
    NTSTATUS Status;
    PAGED_CODE();

    /* Check if we were called from user-mode */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWriteHandle(MemoryReserveHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Only the two types exist */
    if ((ULONG)Type > MemoryReserveObjectTypeIoCompletion) return STATUS_INVALID_PARAMETER;

    /* Create the object */
    Status = ObCreateObject(PreviousMode,
                            (Type == MemoryReserveObjectTypeUserApc) ? ExUserApcReserveObjectType :
                                                                       ExIoCompletionReserveObjectType,
                            ObjectAttributes,
                            PreviousMode,
                            NULL,
                            sizeof(EX_RESERVE_OBJECT),
                            0,
                            0,
                            (PVOID *)&Reserve);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(Reserve, sizeof(*Reserve));

    /* Insert it (this dereferences it on failure) */
    Status = ObInsertObject(Reserve, NULL, RESERVE_OBJECT_ALL_ACCESS, 0, NULL, &Handle);
    if (!NT_SUCCESS(Status)) return Status;

    _SEH2_TRY
    {
        *MemoryReserveHandle = Handle;
    }
    _SEH2_EXCEPT(ExSystemExceptionFilter())
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}
