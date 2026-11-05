/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: named streams of a file that has an attribute list (many streams, extension records)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define STREAM_SHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define STREAM_APPEND 7000
#define STREAM_EXTRA 9000
#define STREAM_MAX (40000 + STREAM_APPEND + STREAM_EXTRA + 3000)

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

/*
 * The expected content of a stream is REPLAYED on a byte array: round 0 is the state after CreateStreams, round 1 after
 * MutateStreams(1), round 2 after MutateStreams(2).  Class Stream % 6:
 *   round 1: 0 append 7000, 1 cut to half, 2 delete, 3 untouched, 4 cut to 0 and write 500 (non-resident -> resident,
 *            then resident growth), 5 SetEndOfFile up by 9000 (zero filled)
 *   round 2: 0 cut to 0, 1 SetEndOfFile up by 3000, 2 recreate (5000 bytes), 3 delete, 4 append 100, 5 untouched
 */
static ULONG StreamModel(ULONG File, ULONG Stream, ULONG Round, PUCHAR Ex, BOOLEAN *Gone)
{
    ULONG Len = StreamSize(File, Stream), Cls = Stream % 6;

    RtlZeroMemory(Ex, STREAM_MAX + 16);
    StreamFill(Ex, Len, File, Stream);
    *Gone = FALSE;
    if (Round >= 1)
    {
        switch (Cls)
        {
            case 0: StreamFill(Ex, Len + STREAM_APPEND, File, Stream); Len += STREAM_APPEND; break;
            case 1: RtlZeroMemory(Ex + Len / 2, Len - Len / 2); Len /= 2; break;
            case 2: *Gone = TRUE; Len = 0; RtlZeroMemory(Ex, STREAM_MAX); break;
            case 4: RtlZeroMemory(Ex, Len); StreamFill(Ex, 500, File, Stream); Len = 500; break;
            case 5: Len += STREAM_EXTRA; break;
        }
    }
    if (Round >= 2)
    {
        switch (Cls)
        {
            case 0: RtlZeroMemory(Ex, Len); Len = 0; break;
            case 1: Len += 3000; break;
            case 2: *Gone = FALSE; RtlZeroMemory(Ex, STREAM_MAX); StreamFill(Ex, 5000, File, Stream); Len = 5000; break;
            case 3: *Gone = TRUE; Len = 0; RtlZeroMemory(Ex, STREAM_MAX); break;
            case 4: StreamFill(Ex, Len + 100, File, Stream); Len += 100; break;
        }
    }
    return Len;
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

static BOOLEAN WriteRange(HANDLE Handle, PUCHAR Ex, ULONG Offset, ULONG Count, PCWSTR Path)
{
    DWORD Done;

    SetFilePointer(Handle, Offset, NULL, FILE_BEGIN);
    ok(WriteFile(Handle, Ex + Offset, Count, &Done, NULL) && Done == Count, "Writing %lu bytes at %lu of %ls: %lu\n",
       Count, Offset, Path, GetLastError());
    return TRUE;
}

static VOID SetEnd(HANDLE Handle, ULONG Length, PCWSTR What, PCWSTR Path)
{
    SetFilePointer(Handle, Length, NULL, FILE_BEGIN);
    ok(SetEndOfFile(Handle), "%ls (%lu) %ls: %lu\n", What, Length, Path, GetLastError());
}

/* Applies round Round (1 or 2) to the streams of one file. */
static VOID MutateStreams(ULONG File, ULONG Count, ULONG Round, PUCHAR Buffer)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle;
    ULONG Stream, Cls, Before, After;
    BOOLEAN Gone;

    for (Stream = 0; Stream < Count; Stream++)
    {
        Cls = Stream % 6;
        StreamPath(Path, File, Stream);
        Before = StreamModel(File, Stream, Round - 1, Buffer, &Gone);
        After = StreamModel(File, Stream, Round, Buffer, &Gone);
        if (Round == 1 ? Cls == 3 : Cls == 5)
            continue;
        if ((Round == 1 && Cls == 2) || (Round == 2 && Cls == 3))
        {
            ok(DeleteFileW(Path), "Deleting %ls: %lu\n", Path, GetLastError());
            continue;
        }
        Handle = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, STREAM_SHARE, NULL,
                             (Round == 2 && Cls == 2) ? CREATE_NEW : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(Handle != INVALID_HANDLE_VALUE, "Opening %ls for round %lu: %lu\n", Path, Round, GetLastError());
        if (Handle == INVALID_HANDLE_VALUE)
            continue;
        if (Round == 1)
        {
            if (Cls == 0) WriteRange(Handle, Buffer, Before, STREAM_APPEND, Path);
            else if (Cls == 1) SetEnd(Handle, Before / 2, L"Cutting", Path);
            else if (Cls == 4) { SetEnd(Handle, 0, L"Cutting to 0", Path); WriteRange(Handle, Buffer, 0, 500, Path); }
            else SetEnd(Handle, Before + STREAM_EXTRA, L"Extending", Path);
        }
        else
        {
            if (Cls == 0) SetEnd(Handle, 0, L"Cutting to 0", Path);
            else if (Cls == 1) SetEnd(Handle, Before + 3000, L"Extending", Path);
            else if (Cls == 2) WriteRange(Handle, Buffer, 0, 5000, Path);
            else WriteRange(Handle, Buffer, Before, 100, Path);
        }
        (void)After;
        CloseHandle(Handle);
    }
}

static VOID CheckStreams(ULONG File, ULONG Count, ULONG Round, PUCHAR Buffer, PUCHAR Expected, PCSTR When)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle;
    DWORD Done;
    ULONG Stream, Want;
    BOOLEAN Gone;
    LARGE_INTEGER Size;

    for (Stream = 0; Stream < Count; Stream++)
    {
        StreamPath(Path, File, Stream);
        Want = StreamModel(File, Stream, Round, Expected, &Gone);
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
        Size.QuadPart = -1;
        ok(GetFileSizeEx(Handle, &Size) && Size.QuadPart == Want, "%s: size of %ls is %I64d, wanted %lu\n", When, Path,
           Size.QuadPart, Want);
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
 * volume was mounted again).  Streams of 300, 6000, 1 and 40000 bytes; 4 and 6 streams stay in the base record (no attribute list).
 * Two rounds of changes follow (append, cut, cut to 0 and rewrite, extend, delete, recreate: StreamModel), each flushed, verified and
 * verified again after a remount: streams in the base and in the extension records, resident -> non-resident growth and the way back.
 */
START_TEST(NtfsStreamsAttrList)
{
    static const ULONG Counts[] = { 4, 8, 14, 30, 6, 1 };
    PUCHAR Buffer, Expected;
    ULONG i, Round;
    DWORD Error;
    BOOLEAN Remounted = FALSE;
    static const CHAR *Names[] = { "created", "round 1", "round 2" };
    static const CHAR *NamesRemount[] = { "created, after the remount", "round 1, after the remount", "round 2, after the remount" };

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
    for (Round = 0; Round <= 2; Round++)
    {
        if (Round)
            for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
                MutateStreams(i, Counts[i], Round, Buffer);
        /* The streams are closed with their data in the cache: a page that cannot be written leaves it dirty for good
         * (the flush of the volume reports it, shutdown loops on it). */
        if (FlushTestVolume(NtTestDir(), &Error))
            ok(!Error, "Flushing the volume after round %lu failed: %lu\n", Round, Error);
        for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
            CheckStreams(i, Counts[i], Round, Buffer, Expected, Names[Round]);
        if (Round == 0)
            Remounted = RemountTestVolume(NtTestDir());
        else if (Remounted)
            Remounted = RemountTestVolume(NtTestDir());
        if (Remounted)
            for (i = 0; i < RTL_NUMBER_OF(Counts); i++)
                CheckStreams(i, Counts[i], Round, Buffer, Expected, NamesRemount[Round]);
        else if (Round == 0)
            skip("The volume of %ls cannot be locked (the system volume): the data after a remount is not checked\n", NtTestDir());
    }

cleanup:
    if (Buffer)
        HeapFree(GetProcessHeap(), 0, Buffer);
    if (Expected)
        HeapFree(GetProcessHeap(), 0, Expected);
    NtCleanup();
}
