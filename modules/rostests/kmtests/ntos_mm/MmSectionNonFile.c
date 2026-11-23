/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A section on a file object that no file system backs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * A handle to a device that is not a file system (or to a driver that keeps its own structure in FsContext) has no
 * section object pointers and cannot back a section. Creating a section on it must fail with
 * STATUS_INVALID_FILE_FOR_SECTION without touching FsContext: the section synchronization used to take
 * FsContext as an FSRTL_COMMON_FCB_HEADER and acquire its Resource first, so for a driver whose context is
 * something else the kernel used a field of that structure as an ERESOURCE pointer.
 *
 * The test creates a device of the kmtest driver, opens it, and puts its own context in the file object's
 * FsContext, as a driver's create would:
 *  1. a context laid out like a header whose Resource is a resource the test holds exclusively from this thread.
 *     The section is created from a system thread through the handle (each protection, data and image). A kernel
 *     that acquires the "header" waits for the test's hold: the test waits 5 s, reports that, and releases the
 *     hold so the thread finishes. A kernel that refuses first returns at once. The same through the file object
 *     (MmCreateSection with a file object, no handle).
 *  2. only when 1 returned without waiting: a context whose Resource field holds a small integer (the layout of a
 *     driver whose first fields are counters), which a kernel that acquired it would dereference.
 * FsContext is set back to NULL before the handle is closed (the kmtest driver's cleanup expects that).
 */

#include <kmt_test.h>

#define WAIT_TIMEOUT_100NS (-5LL * 10 * 1000 * 1000) /* 5 s */

typedef struct _SECTION_CALL
{
    HANDLE FileHandle;
    PFILE_OBJECT FileObject; /* used when FileHandle is NULL */
    ULONG Protection;
    ULONG Attributes;
    NTSTATUS Status;
} SECTION_CALL, *PSECTION_CALL;

static
VOID
NTAPI
SectionThread(PVOID Context)
{
    PSECTION_CALL Call = Context;
    LARGE_INTEGER Size;
    PVOID Section = NULL;
    HANDLE SectionHandle = NULL;
    OBJECT_ATTRIBUTES Attributes;

    Size.QuadPart = PAGE_SIZE;
    if (Call->FileHandle)
    {
        InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        Call->Status = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &Attributes, &Size,
                                       Call->Protection, Call->Attributes, Call->FileHandle);
        if (NT_SUCCESS(Call->Status))
            ZwClose(SectionHandle);
    }
    else
    {
        Call->Status = MmCreateSection(&Section, SECTION_ALL_ACCESS, NULL, &Size, Call->Protection,
                                       Call->Attributes, NULL, Call->FileObject);
        if (NT_SUCCESS(Call->Status))
            ObDereferenceObject(Section);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Runs the call on a system thread; returns TRUE if it did not finish within the timeout (it then finishes
   after Held is released) */
static
BOOLEAN
RunSectionCall(PSECTION_CALL Call, PERESOURCE Held)
{
    HANDLE Thread;
    PVOID ThreadObject;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    BOOLEAN Waited = FALSE;

    Call->Status = STATUS_PENDING;
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, SectionThread, Call);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;
    Status = ObReferenceObjectByHandle(Thread, SYNCHRONIZE, *PsThreadType, KernelMode, &ThreadObject, NULL);
    ZwClose(Thread);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Timeout.QuadPart = WAIT_TIMEOUT_100NS;
    Status = KeWaitForSingleObject(ThreadObject, Executive, KernelMode, FALSE, &Timeout);
    if (Status == STATUS_TIMEOUT)
    {
        Waited = TRUE;
        if (Held)
        {
            /* Let it go on, so the test ends in order */
            ExReleaseResourceLite(Held);
            KeLeaveCriticalRegion();
        }
        KeWaitForSingleObject(ThreadObject, Executive, KernelMode, FALSE, NULL);
        if (Held)
        {
            KeEnterCriticalRegion();
            ExAcquireResourceExclusiveLite(Held, TRUE);
        }
    }
    ObDereferenceObject(ThreadObject);
    return Waited;
}

static const struct
{
    ULONG Protection;
    ULONG Attributes;
} Rows[] =
{
    { PAGE_READONLY,          SEC_COMMIT },
    { PAGE_READWRITE,         SEC_COMMIT },
    { PAGE_WRITECOPY,         SEC_COMMIT },
    { PAGE_EXECUTE,           SEC_COMMIT },
    { PAGE_EXECUTE_READ,      SEC_COMMIT },
    { PAGE_EXECUTE_READWRITE, SEC_COMMIT },
    { PAGE_READONLY,          SEC_RESERVE },
    { PAGE_READWRITE,         SEC_NOCACHE | SEC_COMMIT },
    { PAGE_EXECUTE,           SEC_IMAGE },
    { PAGE_READONLY,          SEC_IMAGE },
};

START_TEST(MmSectionNonFile)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Kmtest-MmSectionNonFile");
    PDEVICE_OBJECT Device = NULL;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE FileHandle = NULL;
    PFILE_OBJECT FileObject = NULL;
    ERESOURCE Resource;
    /* Room for a header and more; the first context's Resource is the test's, the second's is a small number */
    union
    {
        FSRTL_COMMON_FCB_HEADER Header;
        UCHAR Bytes[256];
    } Context;
    SECTION_CALL Call;
    BOOLEAN AnyWaited = FALSE;
    ULONG i, Pass;
    NTSTATUS Status;

    Status = IoCreateDevice(KmtDriverObject, sizeof(KMT_DEVICE_EXTENSION), &Name, FILE_DEVICE_UNKNOWN, 0, FALSE,
                            &Device);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    RtlZeroMemory(Device->DeviceExtension, sizeof(KMT_DEVICE_EXTENSION));
    Device->Flags &= ~DO_DEVICE_INITIALIZING;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenFile(&FileHandle, FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE | SYNCHRONIZE, &Attributes,
                        &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    Status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    ok(FileObject->SectionObjectPointer == NULL, "the device's file object has section object pointers\n");
    ok(Device->DriverObject->FastIoDispatch == NULL ||
       Device->DriverObject->FastIoDispatch->AcquireFileForNtCreateSection == NULL,
       "the kmtest driver has a section acquire routine\n");

    ExInitializeResourceLite(&Resource);

    /* 1. a header-like context with the test's resource, held exclusively by this thread */
    RtlZeroMemory(&Context, sizeof(Context));
    Context.Header.Resource = &Resource;
    FileObject->FsContext = &Context;
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Resource, TRUE);
    for (Pass = 0; Pass < 2; Pass++)
    {
        for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
        {
            BOOLEAN Waited;

            Call.FileHandle = Pass == 0 ? FileHandle : NULL;
            Call.FileObject = FileObject;
            Call.Protection = Rows[i].Protection;
            Call.Attributes = Rows[i].Attributes;
            Waited = RunSectionCall(&Call, &Resource);
            ok(!Waited, "%s, protection 0x%lx attributes 0x%lx: the section create acquired the device's context\n",
               Pass == 0 ? "handle" : "file object", Call.Protection, Call.Attributes);
            AnyWaited |= Waited;
            /* A file object is refused for an image section on Windows 8 and later before anything else */
            if (Pass == 1 && (Call.Attributes & SEC_IMAGE) && Call.Status == STATUS_INVALID_PARAMETER_6)
                continue;
            ok(Call.Status == STATUS_INVALID_FILE_FOR_SECTION,
               "%s, protection 0x%lx attributes 0x%lx: status 0x%lx, expected STATUS_INVALID_FILE_FOR_SECTION\n",
               Pass == 0 ? "handle" : "file object", Call.Protection, Call.Attributes, Call.Status);
        }
    }
    ExReleaseResourceLite(&Resource);
    KeLeaveCriticalRegion();
    ok(!ExIsResourceAcquiredLite(&Resource), "the test's resource is still held\n");

    /* 2. a context whose Resource field holds a small number: only on a kernel that did not acquire in 1 */
    if (AnyWaited)
    {
        skip(FALSE, "the section create acquired the device's context: the non-header context is not tried\n");
    }
    else
    {
        RtlZeroMemory(&Context, sizeof(Context));
        Context.Header.Resource = (PERESOURCE)(ULONG_PTR)0x10;
        Context.Header.PagingIoResource = (PERESOURCE)(ULONG_PTR)0x20;
        for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
        {
            Call.FileHandle = FileHandle;
            Call.FileObject = FileObject;
            Call.Protection = Rows[i].Protection;
            Call.Attributes = Rows[i].Attributes;
            ok(!RunSectionCall(&Call, NULL), "protection 0x%lx attributes 0x%lx: the create did not return\n",
               Call.Protection, Call.Attributes);
            ok(Call.Status == STATUS_INVALID_FILE_FOR_SECTION,
               "non-header context, protection 0x%lx attributes 0x%lx: status 0x%lx\n",
               Call.Protection, Call.Attributes, Call.Status);
        }
    }

    FileObject->FsContext = NULL;
    ExDeleteResourceLite(&Resource);

Cleanup:
    if (FileObject)
    {
        FileObject->FsContext = NULL;
        ObDereferenceObject(FileObject);
    }
    if (FileHandle)
        ZwClose(FileHandle);
    IoDeleteDevice(Device);
}
