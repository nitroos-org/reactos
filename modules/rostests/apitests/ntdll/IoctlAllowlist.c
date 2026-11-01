/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for the I/O and file system control codes a 32-bit process sends to drivers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The same source runs as a native executable and, built for i386, as a WoW64 process. Every result is
 * traced on a line that starts with "IOCL"; the lines of the two runs must be identical. A code that the
 * WoW64 layer does not pass fails with ERROR_NOT_SUPPORTED in the 32-bit run only, which these checks reject.
 */

#include "precomp.h"

#include <winioctl.h>
#include <ntddstor.h>
#include <ntddscsi.h>
/* winioctl.h also defines these serial constants (same values); ntddser.h redefines them */
#undef IOCTL_SERIAL_LSRMST_INSERT
#undef SERIAL_LSRMST_LSR_DATA
#undef SERIAL_LSRMST_LSR_NODATA
#undef SERIAL_LSRMST_MST
#undef SERIAL_LSRMST_ESCAPE
#include <ntddser.h>
#include <ntddkbd.h>
#include <ntddmou.h>
#include <ntddbeep.h>


/* winioctl.h of the Windows 7 level lacks these */
#ifndef FSCTL_IS_VOLUME_MOUNTED
#define FSCTL_IS_VOLUME_MOUNTED CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_SET_ZERO_DATA
#define FSCTL_SET_ZERO_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_QUERY_ALLOCATED_RANGES
#define FSCTL_QUERY_ALLOCATED_RANGES CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 51, METHOD_NEITHER, FILE_READ_DATA)
#endif
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_MARK_HANDLE
#define FSCTL_MARK_HANDLE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 63, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
typedef struct { BOOLEAN SetSparse; } TEST_SPARSE_BUFFER;
typedef struct { LARGE_INTEGER FileOffset; LARGE_INTEGER BeyondFinalZero; } TEST_ZERO_DATA;
typedef struct { LARGE_INTEGER FileOffset; LARGE_INTEGER Length; } TEST_ALLOCATED_RANGE;

#define IOCL(Name, Ret, Err, Bytes) \
    trace("IOCL %-44s %s err=%lu bytes=%lu\n", Name, (Ret) ? "ok" : "failed", (Ret) ? 0ul : (ULONG)(Err), (ULONG)(Bytes))

/* The 64-bit run decides what is possible; the 32-bit run must not turn a success into error 50 */
#define CHECK_PASSED(Name, Ret, Err) \
    ok((Ret) || (Err) != ERROR_NOT_SUPPORTED, "%s failed with ERROR_NOT_SUPPORTED\n", Name)

static BOOL Send(HANDLE Device, ULONG Code, const char *Name, PVOID In, ULONG InLength, PVOID Out, ULONG OutLength,
                 PULONG Returned, PULONG Error)
{
    BOOL Ret;

    *Returned = 0;
    SetLastError(0xdeadbeef);
    Ret = DeviceIoControl(Device, Code, In, InLength, Out, OutLength, (PDWORD)Returned, NULL);
    *Error = Ret ? 0 : GetLastError();
    IOCL(Name, Ret, *Error, *Returned);
    CHECK_PASSED(Name, Ret, *Error);
    return Ret;
}

#define SEND(Device, Code, In, InLength, Out, OutLength) \
    Send(Device, Code, #Code, In, InLength, Out, OutLength, &Returned, &Error)

static void TestDisk(void)
{
    union
    {
        DISK_GEOMETRY Geometry;
        DISK_GEOMETRY_EX GeometryEx;
        UCHAR Buffer[512];
    } Out;
    PARTITION_INFORMATION Partition;
    PARTITION_INFORMATION_EX PartitionEx;
    GET_LENGTH_INFORMATION Length;
    STORAGE_DEVICE_NUMBER Number;
    STORAGE_HOTPLUG_INFO Hotplug;
    UCHAR Layout[4096];
    HANDLE Volume, Disk;
    ULONG Returned, Error;
    BOOL Ret;
    BOOLEAN Writable;

    Volume = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(Volume != INVALID_HANDLE_VALUE, "opening the volume failed, error %lu\n", GetLastError());
    if (Volume != INVALID_HANDLE_VALUE)
    {
        RtlFillMemory(&Out, sizeof(Out), 0x55);
        Ret = SEND(Volume, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &Out.Geometry, sizeof(Out.Geometry));
        if (Ret)
        {
            ok_eq_ulong(Returned, sizeof(DISK_GEOMETRY));
            ok(Out.Geometry.BytesPerSector >= 512 && !(Out.Geometry.BytesPerSector & (Out.Geometry.BytesPerSector - 1)),
               "BytesPerSector %lu\n", Out.Geometry.BytesPerSector);
            ok(Out.Geometry.Cylinders.QuadPart > 0, "Cylinders %I64d\n", Out.Geometry.Cylinders.QuadPart);
            trace("IOCL geometry: media %lu cylinders %I64d tracks %lu sectors %lu bytes %lu\n", (ULONG)Out.Geometry.MediaType,
                  Out.Geometry.Cylinders.QuadPart, Out.Geometry.TracksPerCylinder, Out.Geometry.SectorsPerTrack,
                  Out.Geometry.BytesPerSector);
        }

        RtlFillMemory(&Out, sizeof(Out), 0x55);
        Ret = SEND(Volume, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &Out, sizeof(Out));
        if (Ret)
        {
            ULONGLONG Product = (ULONGLONG)Out.GeometryEx.Geometry.Cylinders.QuadPart *
                                Out.GeometryEx.Geometry.TracksPerCylinder * Out.GeometryEx.Geometry.SectorsPerTrack *
                                Out.GeometryEx.Geometry.BytesPerSector;
            ok(Returned >= FIELD_OFFSET(DISK_GEOMETRY_EX, Data), "returned %lu\n", Returned);
            ok(Out.GeometryEx.DiskSize.QuadPart >= (LONGLONG)Product, "DiskSize %I64d, geometry product %I64u\n",
               Out.GeometryEx.DiskSize.QuadPart, Product);
            trace("IOCL geometry ex: disk size %I64d offset of the data %lu\n", Out.GeometryEx.DiskSize.QuadPart,
                  (ULONG)FIELD_OFFSET(DISK_GEOMETRY_EX, Data));
        }

        RtlFillMemory(&Length, sizeof(Length), 0x55);
        Ret = SEND(Volume, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &Length, sizeof(Length));
        if (Ret)
        {
            ok_eq_ulong(Returned, sizeof(Length));
            ok(Length.Length.QuadPart > 0, "Length %I64d\n", Length.Length.QuadPart);
            trace("IOCL length: %I64d\n", Length.Length.QuadPart);
        }

        RtlFillMemory(&Partition, sizeof(Partition), 0x55);
        Ret = SEND(Volume, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &Partition, sizeof(Partition));
        if (Ret)
        {
            ok_eq_ulong(Returned, sizeof(Partition));
            ok(Partition.PartitionLength.QuadPart > 0, "PartitionLength %I64d\n", Partition.PartitionLength.QuadPart);
            trace("IOCL partition: offset %I64d length %I64d number %lu type %u\n", Partition.StartingOffset.QuadPart,
                  Partition.PartitionLength.QuadPart, Partition.PartitionNumber, Partition.PartitionType);
        }

        RtlFillMemory(&PartitionEx, sizeof(PartitionEx), 0x55);
        Ret = SEND(Volume, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &PartitionEx, sizeof(PartitionEx));
        if (Ret)
        {
            ok_eq_ulong(Returned, sizeof(PartitionEx));
            ok(PartitionEx.PartitionLength.QuadPart > 0, "PartitionLength %I64d\n", PartitionEx.PartitionLength.QuadPart);
            trace("IOCL partition ex: style %d offset %I64d length %I64d number %lu\n", (int)PartitionEx.PartitionStyle,
                  PartitionEx.StartingOffset.QuadPart, PartitionEx.PartitionLength.QuadPart, PartitionEx.PartitionNumber);
        }

        RtlFillMemory(&Number, sizeof(Number), 0x55);
        Ret = SEND(Volume, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &Number, sizeof(Number));
        if (Ret)
        {
            ok_eq_ulong(Returned, sizeof(Number));
            trace("IOCL device number: type %lu number %lu partition %lu\n", Number.DeviceType, Number.DeviceNumber,
                  Number.PartitionNumber);
        }

        RtlFillMemory(&Hotplug, sizeof(Hotplug), 0x55);
        Ret = SEND(Volume, IOCTL_STORAGE_GET_HOTPLUG_INFO, NULL, 0, &Hotplug, sizeof(Hotplug));
        if (Ret)
            trace("IOCL hotplug: size %lu media removable %u\n", Hotplug.Size, Hotplug.MediaRemovable);

        Writable = 0x55;
        Ret = SEND(Volume, IOCTL_DISK_IS_WRITABLE, NULL, 0, NULL, 0);
        (void)Ret;
        (void)Writable;
        SEND(Volume, IOCTL_DISK_CHECK_VERIFY, NULL, 0, NULL, 0);
        SEND(Volume, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, NULL, 0);
        SEND(Volume, IOCTL_STORAGE_CHECK_VERIFY2, NULL, 0, NULL, 0);
        SEND(Volume, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0);
        SEND(Volume, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &Returned, sizeof(ULONG));
        {
            /* Read-only queries of the classes the allow list now has: the 32-bit run must answer as the 64-bit one */
            static const struct { ULONG Code; const char *Name; ULONG OutLength; } Queries[] =
            {
                { IOCTL_DISK_GET_MEDIA_TYPES, "IOCTL_DISK_GET_MEDIA_TYPES", 512 },
                { IOCTL_STORAGE_GET_MEDIA_TYPES_EX, "IOCTL_STORAGE_GET_MEDIA_TYPES_EX", 512 },
                { IOCTL_STORAGE_PREDICT_FAILURE, "IOCTL_STORAGE_PREDICT_FAILURE", 520 },
                { FSCTL_GET_NTFS_VOLUME_DATA, "FSCTL_GET_NTFS_VOLUME_DATA", 128 },
                { FSCTL_FILESYSTEM_GET_STATISTICS, "FSCTL_FILESYSTEM_GET_STATISTICS", 4096 },
            };
            UCHAR Answer[4096];
            ULONG q;

            for (q = 0; q < RTL_NUMBER_OF(Queries); ++q)
            {
                RtlFillMemory(Answer, sizeof(Answer), 0x55);
                Send(Volume, Queries[q].Code, Queries[q].Name, NULL, 0, Answer, Queries[q].OutLength, &Returned, &Error);
            }
        }
        CloseHandle(Volume);
    }

    Disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Disk == INVALID_HANDLE_VALUE)
    {
        skip("Cannot open PhysicalDrive0: %lu\n", GetLastError());
        return;
    }

    RtlFillMemory(&Out, sizeof(Out), 0x55);
    Ret = SEND(Disk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &Out, sizeof(Out));
    if (Ret)
        trace("IOCL disk geometry ex: media %lu bytes per sector %lu disk size %I64d\n",
              (ULONG)Out.GeometryEx.Geometry.MediaType, Out.GeometryEx.Geometry.BytesPerSector,
              Out.GeometryEx.DiskSize.QuadPart);

    RtlFillMemory(Layout, sizeof(Layout), 0x55);
    Ret = SEND(Disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, Layout, sizeof(Layout));
    if (Ret)
    {
        PDRIVE_LAYOUT_INFORMATION_EX Info = (PVOID)Layout;
        ok(Info->PartitionCount >= 1, "%lu partitions\n", Info->PartitionCount);
        trace("IOCL layout ex: style %d partitions %lu first offset %I64d length %I64d\n", (int)Info->PartitionStyle,
              Info->PartitionCount, Info->PartitionEntry[0].StartingOffset.QuadPart,
              Info->PartitionEntry[0].PartitionLength.QuadPart);
    }

    RtlFillMemory(Layout, sizeof(Layout), 0x55);
    Ret = SEND(Disk, IOCTL_DISK_GET_DRIVE_LAYOUT, NULL, 0, Layout, sizeof(Layout));
    if (Ret)
    {
        PDRIVE_LAYOUT_INFORMATION Info = (PVOID)Layout;
        trace("IOCL layout: partitions %lu first offset %I64d length %I64d\n", Info->PartitionCount,
              Info->PartitionEntry[0].StartingOffset.QuadPart, Info->PartitionEntry[0].PartitionLength.QuadPart);
    }
    CloseHandle(Disk);
}

static HANDLE OpenFileCreate(PCWSTR Path)
{
    return CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void TestFiles(void)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH], Target[MAX_PATH], Junction[MAX_PATH];
    HANDLE Handle;
    ULONG Returned, Error, i;
    USHORT Compression;
    TEST_SPARSE_BUFFER Sparse;
    TEST_ZERO_DATA Zero;
    TEST_ALLOCATED_RANGE Query, Ranges[4];
    STARTING_VCN_INPUT_BUFFER Vcn;
    union
    {
        RETRIEVAL_POINTERS_BUFFER Buffer;
        UCHAR Bytes[512];
    } Pointers;
    UCHAR Data[8192];
    BOOL Ret;

    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    StringCchPrintfW(Dir + wcslen(Dir), RTL_NUMBER_OF(Dir) - wcslen(Dir), L"wioctl%lu", GetCurrentProcessId());
    RemoveDirectoryW(Dir);
    ok(CreateDirectoryW(Dir, NULL), "CreateDirectory failed, error %lu\n", GetLastError());
    StringCchPrintfW(File, RTL_NUMBER_OF(File), L"%ls\\file.bin", Dir);
    StringCchPrintfW(Target, RTL_NUMBER_OF(Target), L"%ls\\target", Dir);
    StringCchPrintfW(Junction, RTL_NUMBER_OF(Junction), L"%ls\\junction", Dir);

    Handle = OpenFileCreate(File);
    ok(Handle != INVALID_HANDLE_VALUE, "creating the file failed, error %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
    {
        for (i = 0; i < sizeof(Data); ++i)
            Data[i] = (UCHAR)i;
        ok(WriteFile(Handle, Data, sizeof(Data), &Returned, NULL), "WriteFile failed\n");
        FlushFileBuffers(Handle);

        /* Compression state */
        Compression = 0x5555;
        Ret = SEND(Handle, FSCTL_GET_COMPRESSION, NULL, 0, &Compression, sizeof(Compression));
        if (Ret)
        {
            ok_eq_ulong(Returned, sizeof(USHORT));
            trace("IOCL compression format: %u\n", Compression);
        }
        Compression = COMPRESSION_FORMAT_NONE;
        SEND(Handle, FSCTL_SET_COMPRESSION, &Compression, sizeof(Compression), NULL, 0);

        /* The extents of the file */
        Vcn.StartingVcn.QuadPart = 0;
        RtlFillMemory(&Pointers, sizeof(Pointers), 0x55);
        Ret = SEND(Handle, FSCTL_GET_RETRIEVAL_POINTERS, &Vcn, sizeof(Vcn), &Pointers, sizeof(Pointers));
        if (Ret)
        {
            ok(Pointers.Buffer.ExtentCount >= 1, "%lu extents\n", Pointers.Buffer.ExtentCount);
            trace("IOCL retrieval pointers: extents %lu starting vcn %I64d first next vcn %I64d offsets %lu %lu\n",
                  Pointers.Buffer.ExtentCount, Pointers.Buffer.StartingVcn.QuadPart,
                  Pointers.Buffer.Extents[0].NextVcn.QuadPart, (ULONG)FIELD_OFFSET(RETRIEVAL_POINTERS_BUFFER, StartingVcn),
                  (ULONG)FIELD_OFFSET(RETRIEVAL_POINTERS_BUFFER, Extents));
        }
        else
            ok(Error != ERROR_MORE_DATA || Returned == 0, "partial data on error\n");

        /* Sparse and allocated ranges */
        Sparse.SetSparse = TRUE;
        Ret = SEND(Handle, FSCTL_SET_SPARSE, &Sparse, sizeof(Sparse), NULL, 0);
        if (Ret)
        {
            DWORD Attributes = GetFileAttributesW(File);
            ok(Attributes & FILE_ATTRIBUTE_SPARSE_FILE, "the file is not sparse, attributes %lx\n", Attributes);
            Zero.FileOffset.QuadPart = 4096;
            Zero.BeyondFinalZero.QuadPart = 8192;
            SEND(Handle, FSCTL_SET_ZERO_DATA, &Zero, sizeof(Zero), NULL, 0);
            Query.FileOffset.QuadPart = 0;
            Query.Length.QuadPart = sizeof(Data);
            RtlFillMemory(Ranges, sizeof(Ranges), 0x55);
            Ret = SEND(Handle, FSCTL_QUERY_ALLOCATED_RANGES, &Query, sizeof(Query), Ranges, sizeof(Ranges));
            if (Ret)
            {
                ok(Returned % sizeof(TEST_ALLOCATED_RANGE) == 0, "returned %lu\n", Returned);
                for (i = 0; i < Returned / sizeof(TEST_ALLOCATED_RANGE); ++i)
                    trace("IOCL allocated range %lu: offset %I64d length %I64d\n", i, Ranges[i].FileOffset.QuadPart,
                          Ranges[i].Length.QuadPart);
            }
        }
        /* The controls that carry a handle (the translated ones): 32 bytes with the handle in the first,
         * pointer-sized slot and the 8-byte fields at 8, 16 and 24; MARK_HANDLE_INFO has no 8-byte field */
        {
            UCHAR Move[32];
#ifdef _WIN64
            UCHAR Mark[24];
#else
            UCHAR Mark[12];
#endif
            RtlZeroMemory(Move, sizeof(Move));
            *(ULONG_PTR *)Move = (ULONG_PTR)Handle;
            *(ULONG *)(Move + 24) = 1;
            SEND(Handle, FSCTL_MOVE_FILE, Move, sizeof(Move), NULL, 0);
            SEND(Handle, FSCTL_DUPLICATE_EXTENTS_TO_FILE, Move, sizeof(Move), NULL, 0);
            RtlZeroMemory(Mark, sizeof(Mark));
#ifdef _WIN64
            *(HANDLE *)(Mark + 8) = Handle;
#else
            *(HANDLE *)(Mark + 4) = Handle;
#endif
            SEND(Handle, FSCTL_MARK_HANDLE, Mark, sizeof(Mark), NULL, 0);
        }
        CloseHandle(Handle);
    }

    /* A junction: set, get and delete the reparse point */
    if (CreateDirectoryW(Target, NULL) && CreateDirectoryW(Junction, NULL))
    {
        struct
        {
            ULONG Tag;
            USHORT DataLength, Reserved;
            USHORT SubstituteOffset, SubstituteLength, PrintOffset, PrintLength;
            WCHAR PathBuffer[2 * MAX_PATH + 8];
        } Reparse;
        WCHAR Substitute[MAX_PATH + 8];
        USHORT SubstituteBytes;
        const ULONG HeaderBytes = 8;

        StringCchPrintfW(Substitute, RTL_NUMBER_OF(Substitute), L"\\??\\%ls", Target);
        SubstituteBytes = (USHORT)(wcslen(Substitute) * sizeof(WCHAR));
        RtlZeroMemory(&Reparse, sizeof(Reparse));
        Reparse.Tag = IO_REPARSE_TAG_MOUNT_POINT;
        Reparse.SubstituteOffset = 0;
        Reparse.SubstituteLength = SubstituteBytes;
        Reparse.PrintOffset = SubstituteBytes + sizeof(WCHAR);
        Reparse.PrintLength = 0;
        RtlCopyMemory(Reparse.PathBuffer, Substitute, SubstituteBytes);
        Reparse.DataLength = (USHORT)(8 + SubstituteBytes + 2 * sizeof(WCHAR));

        Handle = CreateFileW(Junction, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        ok(Handle != INVALID_HANDLE_VALUE, "opening the junction directory failed, error %lu\n", GetLastError());
        if (Handle != INVALID_HANDLE_VALUE)
        {
            Ret = SEND(Handle, FSCTL_SET_REPARSE_POINT, &Reparse, HeaderBytes + Reparse.DataLength, NULL, 0);
            if (Ret)
            {
                RtlFillMemory(&Reparse, sizeof(Reparse), 0x55);
                Ret = SEND(Handle, FSCTL_GET_REPARSE_POINT, NULL, 0, &Reparse, sizeof(Reparse));
                if (Ret)
                {
                    ok_eq_hex(Reparse.Tag, IO_REPARSE_TAG_MOUNT_POINT);
                    ok_eq_ulong(Reparse.SubstituteLength, SubstituteBytes);
                    trace("IOCL reparse: tag %lx data length %u substitute %u print offset %u returned %lu\n", Reparse.Tag,
                          Reparse.DataLength, Reparse.SubstituteLength, Reparse.PrintOffset, Returned);
                }
                Reparse.DataLength = 0;
                RtlZeroMemory(&Reparse.SubstituteOffset, 8);
                Reparse.Tag = IO_REPARSE_TAG_MOUNT_POINT;
                SEND(Handle, FSCTL_DELETE_REPARSE_POINT, &Reparse, HeaderBytes, NULL, 0);
            }
            CloseHandle(Handle);
        }
    }

    DeleteFileW(File);
    RemoveDirectoryW(Junction);
    RemoveDirectoryW(Target);
    RemoveDirectoryW(Dir);
}

static void TestPipe(void)
{
    HANDLE Server, Client;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    ULONG Written;
    DWORD Available, Read;
    union
    {
        FILE_PIPE_PEEK_BUFFER Peek;
        UCHAR Bytes[64];
    } Buffer;
    WCHAR PipeName[64];

    StringCchPrintfW(PipeName, RTL_NUMBER_OF(PipeName), L"\\\\.\\pipe\\wioctl%lu", GetCurrentProcessId());
    Server = CreateNamedPipeW(PipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 256, 256, 0, NULL);
    ok(Server != INVALID_HANDLE_VALUE, "CreateNamedPipe failed, error %lu\n", GetLastError());
    if (Server == INVALID_HANDLE_VALUE)
        return;
    Client = CreateFileW(PipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(Client != INVALID_HANDLE_VALUE, "opening the pipe failed, error %lu\n", GetLastError());
    if (Client == INVALID_HANDLE_VALUE)
    {
        CloseHandle(Server);
        return;
    }
    ok(WriteFile(Client, "hello", 5, &Written, NULL), "WriteFile failed\n");

    /* The file system control the pipe handle takes, sent directly and through PeekNamedPipe */
    RtlFillMemory(&Buffer, sizeof(Buffer), 0x55);
    RtlZeroMemory(&Iosb, sizeof(Iosb));
    Status = NtFsControlFile(Server, NULL, NULL, NULL, &Iosb, FSCTL_PIPE_PEEK, NULL, 0, &Buffer, sizeof(Buffer));
    trace("IOCL %-44s status %s info %lu\n", "FSCTL_PIPE_PEEK", NT_SUCCESS(Status) ? "ok" : "failed", (ULONG)Iosb.Information);
    ok(NT_SUCCESS(Status), "FSCTL_PIPE_PEEK returned %lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        ok_eq_ulong(Buffer.Peek.ReadDataAvailable, 5);
        ok(!memcmp(Buffer.Peek.Data, "hello", 5), "data %.5s\n", Buffer.Peek.Data);
        trace("IOCL pipe peek: state %lu available %lu messages %lu message length %lu info %lu offset of data %lu\n",
              Buffer.Peek.NamedPipeState, Buffer.Peek.ReadDataAvailable, Buffer.Peek.NumberOfMessages,
              Buffer.Peek.MessageLength, (ULONG)Iosb.Information, (ULONG)FIELD_OFFSET(FILE_PIPE_PEEK_BUFFER, Data));
    }
    Available = 0;
    ok(PeekNamedPipe(Server, Buffer.Bytes, 3, &Read, &Available, NULL), "PeekNamedPipe failed, error %lu\n", GetLastError());
    ok_eq_ulong(Read, 3);
    ok_eq_ulong(Available, 5);
    trace("IOCL PeekNamedPipe: read %lu available %lu\n", Read, Available);
    CloseHandle(Client);
    CloseHandle(Server);
}

static void TestSerial(void)
{
    WCHAR Name[32];
    HANDLE Port = INVALID_HANDLE_VALUE;
    DCB Dcb;
    COMMTIMEOUTS Timeouts, Back;
    COMMPROP Properties;
    COMSTAT Status;
    DWORD Errors, Modem, Mask, Returned, Error, i;
    SERIAL_BAUD_RATE Baud;
    SERIAL_LINE_CONTROL Line;
    SERIAL_HANDFLOW Flow;
    BOOL Ret;

    for (i = 1; i <= 4 && Port == INVALID_HANDLE_VALUE; ++i)
    {
        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"\\\\.\\COM%lu", i);
        Port = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (Port == INVALID_HANDLE_VALUE)
    {
        skip("No serial port to open: %lu\n", GetLastError());
        return;
    }

    /* Only reads and rewrites of the values the port has: kernel32's comm calls are IOCTL_SERIAL_* */
    RtlZeroMemory(&Dcb, sizeof(Dcb));
    Dcb.DCBlength = sizeof(Dcb);
    Ret = GetCommState(Port, &Dcb);
    IOCL("GetCommState", Ret, GetLastError(), 0);
    CHECK_PASSED("GetCommState", Ret, GetLastError());
    if (Ret)
    {
        trace("IOCL dcb: baud %lu bits %u parity %u stop %u flags %lx\n", Dcb.BaudRate, Dcb.ByteSize, Dcb.Parity, Dcb.StopBits,
              (ULONG)((ULONG *)&Dcb)[2]);
        Ret = SetCommState(Port, &Dcb);
        IOCL("SetCommState", Ret, GetLastError(), 0);
        CHECK_PASSED("SetCommState", Ret, GetLastError());
    }
    Ret = GetCommTimeouts(Port, &Timeouts);
    IOCL("GetCommTimeouts", Ret, GetLastError(), 0);
    CHECK_PASSED("GetCommTimeouts", Ret, GetLastError());
    if (Ret)
    {
        ok(SetCommTimeouts(Port, &Timeouts), "SetCommTimeouts failed, error %lu\n", GetLastError());
        ok(GetCommTimeouts(Port, &Back), "GetCommTimeouts failed\n");
        ok(!memcmp(&Timeouts, &Back, sizeof(Timeouts)), "the timeouts changed\n");
        trace("IOCL timeouts: %lu %lu %lu %lu %lu\n", Back.ReadIntervalTimeout, Back.ReadTotalTimeoutMultiplier,
              Back.ReadTotalTimeoutConstant, Back.WriteTotalTimeoutMultiplier, Back.WriteTotalTimeoutConstant);
    }
    RtlZeroMemory(&Properties, sizeof(Properties));
    Ret = GetCommProperties(Port, &Properties);
    IOCL("GetCommProperties", Ret, GetLastError(), 0);
    CHECK_PASSED("GetCommProperties", Ret, GetLastError());
    if (Ret)
        trace("IOCL properties: length %u version %u service %lx max baud %lx\n", Properties.wPacketLength,
              Properties.wPacketVersion, Properties.dwServiceMask, Properties.dwMaxBaud);
    Ret = GetCommModemStatus(Port, &Modem);
    IOCL("GetCommModemStatus", Ret, GetLastError(), 0);
    CHECK_PASSED("GetCommModemStatus", Ret, GetLastError());
    RtlZeroMemory(&Status, sizeof(Status));
    Ret = ClearCommError(Port, &Errors, &Status);
    IOCL("ClearCommError", Ret, GetLastError(), 0);
    CHECK_PASSED("ClearCommError", Ret, GetLastError());
    Ret = GetCommMask(Port, &Mask);
    IOCL("GetCommMask", Ret, GetLastError(), 0);
    CHECK_PASSED("GetCommMask", Ret, GetLastError());
    Ret = PurgeComm(Port, PURGE_RXCLEAR);
    IOCL("PurgeComm", Ret, GetLastError(), 0);
    CHECK_PASSED("PurgeComm", Ret, GetLastError());

    /* The raw structures, which the comm calls above build from */
    RtlFillMemory(&Baud, sizeof(Baud), 0x55);
    if (Send(Port, IOCTL_SERIAL_GET_BAUD_RATE, "IOCTL_SERIAL_GET_BAUD_RATE", NULL, 0, &Baud, sizeof(Baud), &Returned, &Error))
        trace("IOCL baud: %lu\n", Baud.BaudRate);
    RtlFillMemory(&Line, sizeof(Line), 0x55);
    if (Send(Port, IOCTL_SERIAL_GET_LINE_CONTROL, "IOCTL_SERIAL_GET_LINE_CONTROL", NULL, 0, &Line, sizeof(Line), &Returned, &Error))
        trace("IOCL line: stop %u parity %u bits %u\n", Line.StopBits, Line.Parity, Line.WordLength);
    RtlFillMemory(&Flow, sizeof(Flow), 0x55);
    if (Send(Port, IOCTL_SERIAL_GET_HANDFLOW, "IOCTL_SERIAL_GET_HANDFLOW", NULL, 0, &Flow, sizeof(Flow), &Returned, &Error))
        trace("IOCL handflow: control %lx flow %lx xon %ld xoff %ld\n", Flow.ControlHandShake, Flow.FlowReplace, Flow.XonLimit,
              Flow.XoffLimit);
    CloseHandle(Port);
}

static void TestMemoryEncryption(void)
{
    typedef NTSTATUS (WINAPI *PFN)(PVOID, ULONG, ULONG);
    PFN Encrypt, Decrypt;
    HMODULE Advapi32 = LoadLibraryW(L"advapi32.dll");
    UCHAR Plain[32], Work[32];
    ULONG Flag, i;
    NTSTATUS Status;

    Encrypt = (PFN)GetProcAddress(Advapi32, "SystemFunction040");
    Decrypt = (PFN)GetProcAddress(Advapi32, "SystemFunction041");
    if (!Encrypt || !Decrypt)
    {
        skip("RtlEncryptMemory is not exported\n");
        return;
    }
    for (i = 0; i < sizeof(Plain); ++i)
        Plain[i] = (UCHAR)(i * 7 + 1);
    /* RTL_ENCRYPT_OPTION_SAME_PROCESS, CROSS_PROCESS and SAME_LOGON: three KSecDD codes */
    for (Flag = 0; Flag < 3; ++Flag)
    {
        memcpy(Work, Plain, sizeof(Work));
        Status = Encrypt(Work, sizeof(Work), Flag);
        trace("IOCL RtlEncryptMemory flag %lu: %s changed %d\n", Flag, NT_SUCCESS(Status) ? "ok" : "failed",
              memcmp(Work, Plain, sizeof(Work)) != 0);
        ok(NT_SUCCESS(Status), "RtlEncryptMemory(%lu) returned %lx\n", Flag, Status);
        if (!NT_SUCCESS(Status))
            continue;
        ok(memcmp(Work, Plain, sizeof(Work)) != 0, "the memory was not encrypted\n");
        Status = Decrypt(Work, sizeof(Work), Flag);
        trace("IOCL RtlDecryptMemory flag %lu: %s restored %d\n", Flag, NT_SUCCESS(Status) ? "ok" : "failed",
              memcmp(Work, Plain, sizeof(Work)) == 0);
        ok(NT_SUCCESS(Status), "RtlDecryptMemory(%lu) returned %lx\n", Flag, Status);
        ok(!memcmp(Work, Plain, sizeof(Work)), "the memory was not restored\n");
    }
    FreeLibrary(Advapi32);
}

static HANDLE OpenDevice(PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    return NT_SUCCESS(Status) ? Handle : NULL;
}

static void TestInputDevices(void)
{
    HANDLE Keyboard, Mouse;
    KEYBOARD_ATTRIBUTES KeyboardAttributes;
    KEYBOARD_TYPEMATIC_PARAMETERS Typematic;
    KEYBOARD_INDICATOR_PARAMETERS Indicators;
    MOUSE_ATTRIBUTES MouseAttributes;
    ULONG Returned, Error;

    Keyboard = OpenDevice(L"\\Device\\KeyboardClass0");
    if (!Keyboard)
        skip("No keyboard class device\n");
    else
    {
        RtlFillMemory(&KeyboardAttributes, sizeof(KeyboardAttributes), 0x55);
        if (SEND(Keyboard, IOCTL_KEYBOARD_QUERY_ATTRIBUTES, NULL, 0, &KeyboardAttributes, sizeof(KeyboardAttributes)))
            trace("IOCL keyboard: type %u subtype %u function keys %u indicators %u keys %u input data queue %lu\n",
                  KeyboardAttributes.KeyboardIdentifier.Type, KeyboardAttributes.KeyboardIdentifier.Subtype,
                  KeyboardAttributes.NumberOfFunctionKeys, KeyboardAttributes.NumberOfIndicators,
                  KeyboardAttributes.NumberOfKeysTotal, KeyboardAttributes.InputDataQueueLength);
        RtlFillMemory(&Typematic, sizeof(Typematic), 0x55);
        if (SEND(Keyboard, IOCTL_KEYBOARD_QUERY_TYPEMATIC, NULL, 0, &Typematic, sizeof(Typematic)))
            trace("IOCL typematic: rate %u delay %u\n", Typematic.Rate, Typematic.Delay);
        RtlFillMemory(&Indicators, sizeof(Indicators), 0x55);
        if (SEND(Keyboard, IOCTL_KEYBOARD_QUERY_INDICATORS, NULL, 0, &Indicators, sizeof(Indicators)))
            trace("IOCL indicators: unit %u flags %x\n", Indicators.UnitId, Indicators.LedFlags);
        CloseHandle(Keyboard);
    }

    Mouse = OpenDevice(L"\\Device\\PointerClass0");
    if (!Mouse)
        skip("No pointer class device\n");
    else
    {
        RtlFillMemory(&MouseAttributes, sizeof(MouseAttributes), 0x55);
        if (SEND(Mouse, IOCTL_MOUSE_QUERY_ATTRIBUTES, NULL, 0, &MouseAttributes, sizeof(MouseAttributes)))
            trace("IOCL mouse: id %u buttons %u rate %u queue %lu\n", MouseAttributes.MouseIdentifier,
                  MouseAttributes.NumberOfButtons, MouseAttributes.SampleRate, MouseAttributes.InputDataQueueLength);
        CloseHandle(Mouse);
    }
}


#include "IoctlAllowlistCodes.h"

/* Every added code, sent without buffers to the null device: a code the WoW64 layer passes reaches the driver,
 * which refuses it with its own status; one it does not pass fails with STATUS_NOT_SUPPORTED. */
static void TestAddedCodes(void)
{
    HANDLE Null;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    ULONG i, Blocked = 0;
    BOOL Wow64 = FALSE;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&Name, L"\\Device\\Null");
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Null, SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    ok(NT_SUCCESS(Status), "opening the null device returned %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    for (i = 0; i < RTL_NUMBER_OF(AddedCodes); ++i)
    {
        RtlZeroMemory(&Iosb, sizeof(Iosb));
        if (AddedCodes[i].FsControl)
            Status = NtFsControlFile(Null, NULL, NULL, NULL, &Iosb, AddedCodes[i].Code, NULL, 0, NULL, 0);
        else
            Status = NtDeviceIoControlFile(Null, NULL, NULL, NULL, &Iosb, AddedCodes[i].Code, NULL, 0, NULL, 0);
        trace("IOCL all %08lx %-46s %08lx\n", AddedCodes[i].Code, AddedCodes[i].Name, Status);
        if (Status == STATUS_NOT_SUPPORTED)
        {
            ok(0, "%s (%08lx) is not passed to the driver\n", AddedCodes[i].Name, AddedCodes[i].Code);
            Blocked++;
        }
    }
    trace("IOCL all: %lu codes, %lu blocked\n", (ULONG)RTL_NUMBER_OF(AddedCodes), Blocked);

    /* A code with pointers that is left out stays refused in a 32-bit process, and only there */
    IsWow64Process(GetCurrentProcess(), &Wow64);
    RtlZeroMemory(&Iosb, sizeof(Iosb));
    Status = NtDeviceIoControlFile(Null, NULL, NULL, NULL, &Iosb, IOCTL_SCSI_PASS_THROUGH_DIRECT, NULL, 0, NULL, 0);
    trace("IOCL IOCTL_SCSI_PASS_THROUGH_DIRECT (left out) status is %s\n",
          Status == STATUS_NOT_SUPPORTED ? "refused" : "passed on");
    if (Wow64)
        ok_hex(Status, STATUS_NOT_SUPPORTED);
    else
        ok(Status != STATUS_NOT_SUPPORTED, "the native run refused the code\n");
    NtClose(Null);
}

START_TEST(IoctlAllowlist)
{
    TestDisk();
    TestFiles();
    TestPipe();
    TestSerial();
    TestMemoryEncryption();
    TestInputDevices();
    TestAddedCodes();
}
