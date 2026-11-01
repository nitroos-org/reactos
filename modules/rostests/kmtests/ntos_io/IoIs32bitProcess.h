/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IoIs32bitProcess test: shared driver/user declarations
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#ifndef _KMTEST_IOIS32BITPROCESS_H_
#define _KMTEST_IOIS32BITPROCESS_H_

/*
 * Two codes a 32-bit process may send as they are (the WoW64 layer passes IOCTL_DISK_GET_DRIVE_GEOMETRY and
 * IOCTL_DISK_GET_DRIVE_GEOMETRY_EX unchanged, any other code is refused): the first completes in the
 * dispatch routine, the second pends and completes from a system thread.
 */
#define IOIS32_CODE_SYNC    0x00070000 /* IOCTL_DISK_GET_DRIVE_GEOMETRY */
#define IOIS32_CODE_PENDING 0x000700A0 /* IOCTL_DISK_GET_DRIVE_GEOMETRY_EX */
/* IOCTL_DISK_GET_PARTITION_INFO_EX: input a major function code, output what the driver saw for the last request
 * of that function (IOIS32_LAST) */
#define IOIS32_CODE_LAST    0x00070048
/* Sent by the driver to itself, as a kernel-mode request */
#define IOIS32_CODE_KERNEL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _IOIS32_REPORT
{
    ULONG ForIrp;        /* IoIs32bitProcess(Irp) */
    ULONG ForCurrent;    /* IoIs32bitProcess(NULL): the thread the dispatch routine or work item runs in */
    ULONG ForKernelIrp;  /* IoIs32bitProcess(Irp) of a request the driver sent to itself from that thread */
    ULONG RequestorMode; /* Irp->RequestorMode */
    ULONG KernelIosb;    /* the request's IO_STATUS_BLOCK pointer is a kernel address */
    ULONG Completion;    /* 1: in the dispatch routine, 2: from a work item */
} IOIS32_REPORT;

/* The requests the I/O manager sends with an IO_STATUS_BLOCK of its own (create, query and set information,
 * flush, unlock, query volume information) were the ones IoIs32bitProcess() used to answer FALSE for */
/* IRP_MJ_xxx, which the user-mode headers lack (the driver checks the values) */
#define IOIS32_MJ_CREATE                   0x00
#define IOIS32_MJ_QUERY_INFORMATION        0x05
#define IOIS32_MJ_SET_INFORMATION          0x06
#define IOIS32_MJ_FLUSH_BUFFERS            0x09
#define IOIS32_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IOIS32_MJ_LOCK_CONTROL             0x11

typedef struct _IOIS32_LAST
{
    ULONG Seen;          /* the driver got a request of that function */
    ULONG ForIrp;        /* IoIs32bitProcess(Irp) */
    ULONG RequestorMode; /* Irp->RequestorMode */
    ULONG KernelIosb;    /* the request's IO_STATUS_BLOCK pointer is a kernel address */
} IOIS32_LAST;

#endif
