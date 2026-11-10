/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for RtlNtStatusToDosError of the statuses a failed storage transfer produces
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* The values were measured on Windows 10 22H2 (2026-11-10, ntdll!RtlNtStatusToDosError). */
static const struct
{
    NTSTATUS Status;
    ULONG Error;
} Cases[] =
{
    { (NTSTATUS)0xC00000E9, ERROR_IO_DEVICE },          /* STATUS_UNEXPECTED_IO_ERROR */
    { (NTSTATUS)0xC0000185, ERROR_IO_DEVICE },          /* STATUS_IO_DEVICE_ERROR */
    { (NTSTATUS)0xC000009C, ERROR_CRC },                /* STATUS_DEVICE_DATA_ERROR */
    { (NTSTATUS)0xC000009D, ERROR_DEVICE_NOT_CONNECTED },
    { (NTSTATUS)0xC0000032, ERROR_DISK_CORRUPT },       /* STATUS_DISK_CORRUPT_ERROR */
    { (NTSTATUS)0xC0000102, ERROR_FILE_CORRUPT },       /* STATUS_FILE_CORRUPT_ERROR */
    { (NTSTATUS)0xC000003E, ERROR_CRC },                /* STATUS_DATA_ERROR */
    { (NTSTATUS)0xC000003F, ERROR_CRC },                /* STATUS_CRC_ERROR */
    { (NTSTATUS)0xC00000A2, ERROR_WRITE_PROTECT },      /* STATUS_MEDIA_WRITE_PROTECTED */
    { (NTSTATUS)0xC00000A3, ERROR_NOT_READY },          /* STATUS_DEVICE_NOT_READY */
    { (NTSTATUS)0xC000016A, ERROR_DISK_OPERATION_FAILED },
    { (NTSTATUS)0xC000026E, ERROR_NOT_READY },          /* STATUS_VOLUME_DISMOUNTED */
    { (NTSTATUS)0xC000007F, ERROR_DISK_FULL },
    { (NTSTATUS)0xC00000B5, ERROR_SEM_TIMEOUT },        /* STATUS_IO_TIMEOUT */
    { (NTSTATUS)0xC0000098, ERROR_FILE_INVALID },
};

START_TEST(RtlNtStatusToDosError)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        ULONG Error = RtlNtStatusToDosError(Cases[i].Status);
        ok(Error == Cases[i].Error, "RtlNtStatusToDosError(0x%08lx) = %lu, expected %lu\n",
           Cases[i].Status, Error, Cases[i].Error);
    }
}
