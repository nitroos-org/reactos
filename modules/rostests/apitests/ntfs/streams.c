/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: named streams of a file that has an attribute list (many streams, extension records)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define STREAM_SHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define STREAM_APPEND 7000
#define STREAM_MAX (40000 + STREAM_APPEND)

/* Sizes cycle through resident (300, 1) and non-resident (6000, 40000) streams. */
static ULONG StreamSize(ULONG File, ULONG Stream)
{
    switch ((Stream + File) % 4)
    {
        case 0: return 300;
        case 1: return 6000;
        case 2: return 1;
        default: return 40000;
    }
}

static VOID StreamFill(PUCHAR Buffer, ULONG Length, ULONG File, ULONG Stream)
{
    ULONG i;
    for (i = 0; i < Length; i++)
        Buffer[i] = (UCHAR)(File * 17 + Stream * 31 + i * 7 + (i >> 8));
}

static VOID StreamPath(PWSTR Out, ULONG File, ULONG Stream)
{
    WCHAR Name[32];
    _snwprintf(Name, RTL_NUMBER_OF(Name), L"f%lu:s%lu", File, Stream);
    NtPath(Out, Name);
}

/* Locks and dismounts the test directory's volume: the next open mounts it again, with nothing cached. */
static BOOLEAN RemountTestVolume(PCWSTR TestDir)
{
    WCHAR Root[MAX_PATH], Volume[16];
    HANDLE Handle;
    DWORD Bytes;
    BOOL Ok;

    if (!GetVolumePathNameW(TestDir, Root, MAX_PATH) || wcslen(Root) != 3 || Root[1] != L':')
        return FALSE;
    _snwprintf(Volume, RTL_NUMBER_OF(Volume), L"\\\\.\\%c:", Root[0]);
    Handle = CreateFileW(Volume, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Handle == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = DeviceIoControl(Handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &Bytes, NULL);
    if (!Ok)
        trace("FSCTL_LOCK_VOLUME failed %lu\n", GetLastError());
    else if (!(Ok = DeviceIoControl(Handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &Bytes, NULL)))
        trace("FSCTL_DISMOUNT_VOLUME failed %lu\n", GetLastError());
    CloseHandle(Handle);
    return Ok;
}

/* Flushes every cached stream of the test directory's volume through a volume handle. */
static BOOLEAN FlushTestVolume(PCWSTR TestDir, DWORD *Error)
{
    WCHAR Root[MAX_PATH], Volume[16];
    HANDLE Handle;
    BOOL Ok;

    *Error = 0;
    if (!GetVolumePathNameW(TestDir, Root, MAX_PATH) || wcslen(Root) != 3 || Root[1] != L':')
        return FALSE;
    _snwprintf(Volume, RTL_NUMBER_OF(Volume), L"\\\\.\\%c:", Root[0]);
    Handle = CreateFileW(Volume, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (Handle == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = FlushFileBuffers(Handle);
    *Error = Ok ? 0 : GetLastError();
    CloseHandle(Handle);
    return TRUE;
}

/* The state after CreateStreams (Mutated FALSE) or after MutateStreams: class Stream % 4 grew by 7000 bytes (0),
 * was cut to half (1), was deleted (2) or untouched (3). */
static ULONG StreamWanted(ULONG File, ULONG Stream, BOOLEAN Mutated, BOOLEAN *Gone)
{
    ULONG Size = StreamSize(File, Stream);

    *Gone = FALSE;
    if (!Mutated)
        return Size;
    switch (Stream % 4)
    {
        case 0: return Size + STREAM_APPEND;
        case 1: return Size / 2;
        case 2: *Gone = TRUE; return 0;
        default: return Size;
    }
}

static VOID CreateStreams(ULONG File, ULONG Count, PUCHAR Buffer)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle;
    DWORD Done;
    ULONG Stream, Size;

    _snwprintf(Path, MAX_PATH - 1, L"%ls\\f%lu", NtTestDir(), File);
    Handle = CreateFileW(Path, GENERIC_WRITE, STREAM_SHARE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Path, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(Handle);
    for (Stream = 0; Stream < Count; Stream++)
    {
        StreamPath(Path, File, Stream);
        Size = StreamSize(File, Stream);
        StreamFill(Buffer, Size, File, Stream);
        Handle = CreateFileW(Path, GENERIC_WRITE, STREAM_SHARE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(Handle != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Path, GetLastError());
        if (Handle == INVALID_HANDLE_VALUE)
            continue;
        ok(WriteFile(Handle, Buffer, Size, &Done, NULL) && Done == Size, "Writing %ls: %lu\n", Path, GetLastError());
        CloseHandle(Handle);
    }
}

static VOID MutateStreams(ULONG File, ULONG Count, PUCHAR Buffer)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle;
    DWORD Done;
    ULONG Stream, Size;

    for (Stream = 0; Stream < Count; Stream++)
    {
        StreamPath(Path, File, Stream);
        Size = StreamSize(File, Stream);
        if (Stream % 4 == 2)
        {
            ok(DeleteFileW(Path), "Deleting %ls: %lu\n", Path, GetLastError());
            continue;
        }
        Handle = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, STREAM_SHARE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(Handle != INVALID_HANDLE_VALUE, "Opening %ls: %lu\n", Path, GetLastError());
        if (Handle == INVALID_HANDLE_VALUE)
            continue;
        if (Stream % 4 == 0)
        {
            StreamFill(Buffer, Size + STREAM_APPEND, File, Stream);
            SetFilePointer(Handle, Size, NULL, FILE_BEGIN);
            ok(WriteFile(Handle, Buffer + Size, STREAM_APPEND, &Done, NULL) && Done == STREAM_APPEND, "Appending to %ls: %lu\n", Path, GetLastError());
        }
        else if (Stream % 4 == 1)
        {
            SetFilePointer(Handle, Size / 2, NULL, FILE_BEGIN);
            ok(SetEndOfFile(Handle), "Cutting %ls: %lu\n", Path, GetLastError());
        }
        CloseHandle(Handle);
    }
}

static VOID CheckStreams(ULONG File, ULONG Count, BOOLEAN Mutated, PUCHAR Buffer, PUCHAR Expected, PCSTR When)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle;
    DWORD Done;
    ULONG Stream, Want;
    BOOLEAN Gone;

    for (Stream = 0; Stream < Count; Stream++)
    {
        StreamPath(Path, File, Stream);
        Want = StreamWanted(File, Stream, Mutated, &Gone);
        Handle = CreateFileW(Path, GENERIC_READ, STREAM_SHARE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (Gone)
        {
            ok(Handle == INVALID_HANDLE_VALUE, "%s: %ls still exists\n", When, Path);
            if (Handle != INVALID_HANDLE_VALUE)
                CloseHandle(Handle);
            continue;
        }
        ok(Handle != INVALID_HANDLE_VALUE, "%s: opening %ls: %lu\n", When, Path, GetLastError());
        if (Handle == INVALID_HANDLE_VALUE)
            continue;
        StreamFill(Expected, Want, File, Stream);
        RtlZeroMemory(Buffer, STREAM_MAX + 16);
        ok(ReadFile(Handle, Buffer, Want + 10, &Done, NULL) && Done == Want, "%s: reading %ls: %lu bytes of %lu (%lu)\n",
           When, Path, Done, Want, GetLastError());
        ok(!memcmp(Buffer, Expected, Want), "%s: the data of %ls is wrong\n", When, Path);
        CloseHandle(Handle);
    }
}

/*
 * A file with 8 or more named streams has an $ATTRIBUTE_LIST, and its streams live in extension records.  The stream data
 * must reach the disk with its initialized size: a lookup of the stream's attribute through the stream's own inode (not
 * the base file's) failed with -ENOENT for an attribute in an extension record, so the paging write failed for good, a flush
 * reported it, and shutdown looped on the dirty page (the guest never powered off); for 2 and 4 streams the lookup
 * found a private copy of the base record, and the initialized size was lost (the stream read back as zeros after the
 * volume was mounted again).  Streams of 300, 6000, 1 and 40000 bytes; 4 streams are the control without an attribute list.
 */
START_TEST(NtfsStreamsAttrList)
{
    static const ULONG Counts[] = { 4, 8, 14, 30 };
    PUCHAR Buffer, Expected;
    ULONG i;
    DWORD Error;
    BOOLEAN Remounted;

    if (!NtInit("NtfsStreamsAttrList"))
        return;
    Buffer = HeapAlloc(GetProcessHeap(), 0, STREAM_MAX + 16);
    Expected = HeapAlloc(GetProcessHeap(), 0, STREAM_MAX + 16);
    if (!Buffer || !Expected)
    {
        skip("Out of memory\n");
        goto cleanup;
    }
    for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
        CreateStreams(i, Counts[i], Buffer);
    /* The streams are closed with their data in the cache: a page that cannot be written leaves it dirty for good
     * (the flush of the volume reports it, shutdown loops on it). */
    if (FlushTestVolume(NtTestDir(), &Error))
        ok(!Error, "Flushing the volume failed: %lu\n", Error);
    for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
        CheckStreams(i, Counts[i], FALSE, Buffer, Expected, "created");
    Remounted = RemountTestVolume(NtTestDir());
    if (Remounted)
        for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
            CheckStreams(i, Counts[i], FALSE, Buffer, Expected, "after the remount");
    else
        skip("The volume of %ls cannot be locked (the system volume): the data after a remount is not checked\n", NtTestDir());

    for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
        MutateStreams(i, Counts[i], Buffer);
    if (FlushTestVolume(NtTestDir(), &Error))
        ok(!Error, "Flushing the volume after the changes failed: %lu\n", Error);
    for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
        CheckStreams(i, Counts[i], TRUE, Buffer, Expected, "changed");
    if (Remounted && RemountTestVolume(NtTestDir()))
        for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
            CheckStreams(i, Counts[i], TRUE, Buffer, Expected, "changed, after the remount");

cleanup:
    if (Buffer)
        HeapFree(GetProcessHeap(), 0, Buffer);
    if (Expected)
        HeapFree(GetProcessHeap(), 0, Expected);
    NtCleanup();
}
