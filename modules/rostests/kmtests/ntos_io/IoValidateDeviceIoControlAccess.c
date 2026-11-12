/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for IoValidateDeviceIoControlAccess
 *              (semantics from the public WDK documentation)
 */

#include <kmt_test.h>

START_TEST(IoValidateDeviceIoControlAccess)
{
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;
    FILE_OBJECT FileObject;
    NTSTATUS Status;

    Irp = IoAllocateIrp(2, FALSE);
    ok(Irp != NULL, "IoAllocateIrp failed\n");
    if (!Irp)
        return;
    IoSetNextIrpStackLocation(Irp);
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.IoControlCode = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
    RtlZeroMemory(&FileObject, sizeof(FileObject));
    IoStack->FileObject = &FileObject;

    /* kernel mode requests are never refused */
    Irp->RequestorMode = KernelMode;
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /* user mode, file opened with no access */
    Irp->RequestorMode = UserMode;
    Status = IoValidateDeviceIoControlAccess(Irp, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS);
    ok_eq_hex(Status, STATUS_ACCESS_DENIED);
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS);
    ok_eq_hex(Status, STATUS_ACCESS_DENIED);

    /* read access only */
    FileObject.ReadAccess = TRUE;
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS);
    ok_eq_hex(Status, STATUS_ACCESS_DENIED);
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    ok_eq_hex(Status, STATUS_ACCESS_DENIED);

    /* both */
    FileObject.WriteAccess = TRUE;
    Status = IoValidateDeviceIoControlAccess(Irp, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    ok_eq_hex(Status, STATUS_SUCCESS);

    IoFreeIrp(Irp);
}
