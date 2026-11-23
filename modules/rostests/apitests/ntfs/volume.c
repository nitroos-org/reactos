/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: the volume label, the volume lock and the file system attributes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SHARE_RW (FILE_SHARE_READ | FILE_SHARE_WRITE)
#define LABEL_MAX 32

static WCHAR LabelRoot[MAX_PATH], VolumePath[MAX_PATH];

/* The test directory's volume: its root (LabelRoot) and a name that opens the volume itself (VolumePath). */
static BOOLEAN LabelInit(PCSTR TestName)
{
    size_t Len;

    if (!NtInit(TestName))
        return FALSE;
    if (!GetVolumePathNameW(NtTestDir(), LabelRoot, MAX_PATH))
    {
        skip("GetVolumePathNameW failed %lu\n", GetLastError());
        return FALSE;
    }
    if (wcslen(LabelRoot) == 3 && LabelRoot[1] == L':')
    {
        _snwprintf(VolumePath, RTL_NUMBER_OF(VolumePath), L"\\\\.\\%c:", LabelRoot[0]);
    }
    else if (GetVolumeNameForVolumeMountPointW(LabelRoot, VolumePath, MAX_PATH) &&
             (Len = wcslen(VolumePath)) > 1 && VolumePath[Len - 1] == L'\\')
    {
        VolumePath[Len - 1] = UNICODE_NULL;
    }
    else
    {
        skip("No volume name for %ls\n", LabelRoot);
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN GetLabel(PWSTR Out)
{
    Out[0] = UNICODE_NULL;
    return GetVolumeInformationW(LabelRoot, Out, MAX_PATH, NULL, NULL, NULL, NULL, 0);
}

/* The label as FileFsVolumeInformation reports it, raw, with its length in bytes; FALSE if the query failed. */
static BOOLEAN NtQueryLabel(PWSTR Out, ULONG *Bytes)
{
    ULONGLONG Buffer[(sizeof(FILE_FS_VOLUME_INFORMATION) + MAX_PATH * sizeof(WCHAR)) / sizeof(ULONGLONG)];
    PFILE_FS_VOLUME_INFORMATION Info = (PFILE_FS_VOLUME_INFORMATION)Buffer;
    IO_STATUS_BLOCK Iosb;
    HANDLE Volume;
    NTSTATUS Status;

    Out[0] = UNICODE_NULL;
    *Bytes = 0;
    /* A volume handle with attribute access only is a direct device open on Windows: use the root. */
    Status = NtOpen(LabelRoot, FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_RW, FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, &Volume);
    if (!NT_SUCCESS(Status))
    {
        trace("Volume open for the query: 0x%08lx\n", Status);
        return FALSE;
    }
    Status = NtQueryVolumeInformationFile(Volume, &Iosb, Info, sizeof(Buffer), FileFsVolumeInformation);
    NtClose(Volume);
    if (!NT_SUCCESS(Status) || Info->VolumeLabelLength >= MAX_PATH * sizeof(WCHAR))
    {
        trace("FileFsVolumeInformation: 0x%08lx, label length %lu\n", Status, Info->VolumeLabelLength);
        return FALSE;
    }
    RtlCopyMemory(Out, Info->VolumeLabel, Info->VolumeLabelLength);
    Out[Info->VolumeLabelLength / sizeof(WCHAR)] = UNICODE_NULL;
    *Bytes = Info->VolumeLabelLength;
    return TRUE;
}

/* NtSetVolumeInformationFile(FileFsLabelInformation) with a label of LabelBytes bytes in an Info of InfoLength bytes. */
static NTSTATUS NtSetLabel(HANDLE Handle, PCWSTR Label, ULONG LabelBytes, ULONG InfoLength)
{
    ULONGLONG Buffer[(sizeof(FILE_FS_LABEL_INFORMATION) + 128 * sizeof(WCHAR)) / sizeof(ULONGLONG)];
    PFILE_FS_LABEL_INFORMATION Info = (PFILE_FS_LABEL_INFORMATION)Buffer;
    IO_STATUS_BLOCK Iosb;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Info->VolumeLabelLength = LabelBytes;
    if (Label)
        RtlCopyMemory(Info->VolumeLabel, Label, min(LabelBytes, sizeof(Buffer) - FIELD_OFFSET(FILE_FS_LABEL_INFORMATION, VolumeLabel)));
    return NtSetVolumeInformationFile(Handle, &Iosb, Info, InfoLength, FileFsLabelInformation);
}

static NTSTATUS OpenVolume(ACCESS_MASK Access, PHANDLE Handle)
{
    return NtOpen(VolumePath, Access | SYNCHRONIZE, SHARE_RW, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, Handle);
}

/* Sets the label to Bytes bytes of Label through the native call, exactly as given, and checks it took. */
static BOOLEAN RestoreLabel(PCWSTR Label, ULONG Bytes)
{
    WCHAR Got[MAX_PATH];
    ULONG GotBytes;
    HANDLE Handle;
    NTSTATUS Status;

    Status = OpenVolume(FILE_WRITE_DATA, &Handle);
    if (NT_SUCCESS(Status))
    {
        Status = NtSetLabel(Handle, Label, Bytes, sizeof(FILE_FS_LABEL_INFORMATION) + Bytes);
        NtClose(Handle);
    }
    ok(Status == STATUS_SUCCESS, "Restoring the label: 0x%08lx\n", Status);
    return NT_SUCCESS(Status) && NtQueryLabel(Got, &GotBytes) && GotBytes == Bytes && !memcmp(Got, Label, Bytes);
}

/* SetVolumeLabelW, then the label both query paths report must be Expect. */
static VOID SetAndCheck(int Line, PCWSTR Label, BOOL ExpectOk, DWORD ExpectError, PCWSTR Expect)
{
    WCHAR Got[MAX_PATH], NtGot[MAX_PATH];
    ULONG Bytes;
    BOOL Ret;
    DWORD Error;

    SetLastError(0xdeadbeef);
    Ret = SetVolumeLabelW(LabelRoot, Label);
    Error = GetLastError();
    ok_(__FILE__, Line)(Ret == ExpectOk, "SetVolumeLabelW(\"%ls\") returned %d, error %lu\n",
                        Label ? Label : L"(null)", Ret, Error);
    if (!ExpectOk)
        ok_(__FILE__, Line)(Error == ExpectError, "SetVolumeLabelW(\"%ls\") error %lu, expected %lu\n",
                            Label ? Label : L"(null)", Error, ExpectError);
    ok_(__FILE__, Line)(GetLabel(Got), "GetVolumeInformationW failed %lu\n", GetLastError());
    ok_(__FILE__, Line)(!wcscmp(Got, Expect), "Label is \"%ls\", expected \"%ls\"\n", Got, Expect);
    ok_(__FILE__, Line)(NtQueryLabel(NtGot, &Bytes), "FileFsVolumeInformation failed\n");
    ok_(__FILE__, Line)(Bytes == wcslen(Expect) * sizeof(WCHAR) && !wcscmp(NtGot, Expect),
                        "FileFsVolumeInformation label \"%ls\" (%lu bytes), expected \"%ls\"\n", NtGot, Bytes, Expect);
}
#define SetAndCheck(Label, ExpectOk, ExpectError, Expect) SetAndCheck(__LINE__, Label, ExpectOk, ExpectError, Expect)

/* A native label set must fail with Expect and leave the label at Before. */
static VOID NativeRefused(int Line, HANDLE Handle, PCWSTR Label, ULONG LabelBytes, ULONG InfoLength, NTSTATUS Expect,
                          PCWSTR Before, PCSTR What)
{
    WCHAR Got[MAX_PATH];
    NTSTATUS Status = NtSetLabel(Handle, Label, LabelBytes, InfoLength);
    ok_(__FILE__, Line)(Status == Expect, "%s: 0x%08lx, expected 0x%08lx\n", What, Status, Expect);
    ok_(__FILE__, Line)(GetLabel(Got) && !wcscmp(Got, Before), "%s: label is \"%ls\", expected \"%ls\"\n", What, Got, Before);
}
#define NativeRefused(Handle, Label, LabelBytes, InfoLength, Expect, Before, What) \
    NativeRefused(__LINE__, Handle, Label, LabelBytes, InfoLength, Expect, Before, What)

/*
 * Set, read back, replace with the same label, the 32-character limit, characters, clearing,
 * and the NtSetVolumeInformationFile checks.  The volume's own label is restored at the end.
 */
START_TEST(NtfsVolumeLabel)
{
    static const WCHAR Max[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
    static const WCHAR TooLong[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
    /* NTFS takes characters that FAT labels and file names refuse, control characters included. */
    static const WCHAR Chars[] = L"*?/\\|<>\":+=,;[].\t\x01\x7f";
    static const WCHAR NonAscii[] = L"P\x0159\x00edli\x0161 \x017elu\x0165ou\x010dk\x00fd k\x016f\x0148 \x00fap\x011bl \x65e5\x672c";
    static const WCHAR Odd[] = L"Odd";
    WCHAR Original[MAX_PATH], Label[MAX_PATH], Got[MAX_PATH], Path[MAX_PATH];
    HANDLE Handle;
    NTSTATUS Status;
    ULONG i, Bytes, OriginalBytes;

    if (!LabelInit("NtfsVolumeLabel"))
        return;
    ok(wcslen(Max) == LABEL_MAX && wcslen(TooLong) == LABEL_MAX + 1, "Test labels have the wrong length\n");
    /* The volume's own label, raw, so that it can be put back exactly; nothing changes without it. */
    if (!NtQueryLabel(Original, &OriginalBytes))
    {
        skip("Cannot read the label of %ls\n", LabelRoot);
        return;
    }
    trace("Volume %ls (%ls), label of %lu bytes\n", LabelRoot, VolumePath, OriginalBytes);

    SetAndCheck(L"NtfsApiLabel", TRUE, 0, L"NtfsApiLabel");
    /* The same label again, as a property sheet closed with OK would set it. */
    SetAndCheck(L"NtfsApiLabel", TRUE, 0, L"NtfsApiLabel");
    /* Case and spaces are kept as given. */
    SetAndCheck(L"MiXeD case Label", TRUE, 0, L"MiXeD case Label");
    SetAndCheck(L" lead and trail ", TRUE, 0, L" lead and trail ");
    SetAndCheck(NonAscii, TRUE, 0, NonAscii);
    SetAndCheck(Max, TRUE, 0, Max);
    SetAndCheck(TooLong, FALSE, ERROR_LABEL_TOO_LONG, Max);
    for (i = 0; Chars[i]; i++)
    {
        _snwprintf(Label, RTL_NUMBER_OF(Label), L"A%cB", Chars[i]);
        SetAndCheck(Label, TRUE, 0, Label);
    }
    SetAndCheck(NULL, TRUE, 0, L"");
    SetAndCheck(L"NtfsApiLabel", TRUE, 0, L"NtfsApiLabel");
    SetAndCheck(L"", TRUE, 0, L"");

    /* The native call needs a volume handle with write access. */
    Status = OpenVolume(FILE_READ_DATA, &Handle);
    ok(Status == STATUS_SUCCESS, "Volume open for read: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        NativeRefused(Handle, L"NoWrite", 14, sizeof(FILE_FS_LABEL_INFORMATION) + 14, STATUS_ACCESS_DENIED, L"",
                      "Volume handle without write access");
        NtClose(Handle);
    }
    Status = OpenVolume(FILE_WRITE_DATA, &Handle);
    ok(Status == STATUS_SUCCESS, "Volume open for write: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Status = NtSetLabel(Handle, L"Native", 12, FIELD_OFFSET(FILE_FS_LABEL_INFORMATION, VolumeLabel) + 12);
        ok(Status == STATUS_SUCCESS, "Native label: 0x%08lx\n", Status);
        ok(GetLabel(Got) && !wcscmp(Got, L"Native"), "Label is \"%ls\"\n", Got);
        NativeRefused(Handle, L"Short", 10, FIELD_OFFSET(FILE_FS_LABEL_INFORMATION, VolumeLabel) + 4, STATUS_INVALID_PARAMETER,
                      L"Native", "Label longer than the buffer");
        NativeRefused(Handle, L"Tiny", 0, 2, STATUS_INFO_LENGTH_MISMATCH, L"Native", "Buffer smaller than the structure");
        NativeRefused(Handle, TooLong, (LABEL_MAX + 1) * sizeof(WCHAR), sizeof(FILE_FS_LABEL_INFORMATION) + 128,
                      STATUS_INVALID_VOLUME_LABEL, L"Native", "Native label too long");
        /* An odd byte count: Windows 10 refuses it, Server 2008 R2 drops the odd byte. */
        Status = NtSetLabel(Handle, Odd, 5, sizeof(FILE_FS_LABEL_INFORMATION) + 6);
        GetLabel(Got);
        ok((Status == STATUS_INVALID_VOLUME_LABEL && !wcscmp(Got, L"Native")) || (Status == STATUS_SUCCESS && !wcscmp(Got, L"Od")),
           "Odd length: 0x%08lx, label \"%ls\"\n", Status, Got);
        /* The label is stored as given: an embedded NUL and an unpaired surrogate are kept. */
        Status = NtSetLabel(Handle, L"A\0B", 6, sizeof(FILE_FS_LABEL_INFORMATION) + 6);
        ok(Status == STATUS_SUCCESS, "Embedded NUL: 0x%08lx\n", Status);
        ok(NtQueryLabel(Got, &Bytes) && Bytes == 6 && !memcmp(Got, L"A\0B", 6), "Embedded NUL: %lu bytes\n", Bytes);
        Status = NtSetLabel(Handle, L"A\xd800" L"B", 6, sizeof(FILE_FS_LABEL_INFORMATION) + 6);
        ok(Status == STATUS_SUCCESS, "Unpaired surrogate: 0x%08lx\n", Status);
        ok(NtQueryLabel(Got, &Bytes) && Bytes == 6 && !memcmp(Got, L"A\xd800" L"B", 6), "Unpaired surrogate: %lu bytes\n", Bytes);
        Status = NtSetLabel(Handle, NULL, 0, sizeof(FILE_FS_LABEL_INFORMATION));
        ok(Status == STATUS_SUCCESS, "Native empty label: 0x%08lx\n", Status);
        ok(GetLabel(Got) && !wcscmp(Got, L""), "Label is \"%ls\"\n", Got);
        NtClose(Handle);
    }
    /* A directory or file handle of the volume, even with write access, does not set the label. */
    Status = NtOpen(LabelRoot, FILE_WRITE_DATA | SYNCHRONIZE, SHARE_RW, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                    NULL, &Handle);
    ok(Status == STATUS_SUCCESS, "Root directory open for write: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        NativeRefused(Handle, L"RootDir", 14, sizeof(FILE_FS_LABEL_INFORMATION) + 14, STATUS_ACCESS_DENIED, L"",
                      "Root directory handle");
        NtClose(Handle);
    }
    NtPath(Path, L"file.txt");
    Status = NtOpen(Path, FILE_WRITE_DATA | SYNCHRONIZE, SHARE_RW, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                    NULL, &Handle);
    ok(Status == STATUS_SUCCESS, "File create: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        NativeRefused(Handle, L"AFile", 10, sizeof(FILE_FS_LABEL_INFORMATION) + 10, STATUS_ACCESS_DENIED, L"", "File handle");
        NtClose(Handle);
    }

    ok(RestoreLabel(Original, OriginalBytes), "The label of %ls was not restored\n", LabelRoot);
    NtCleanup();
}

/* What the first run of NtfsVolumeLabelReboot leaves for the second: both labels, raw. */
typedef struct _LABEL_MARKER
{
    ULONG Magic;
    ULONG OriginalBytes;
    WCHAR Original[LABEL_MAX];
    ULONG ExpectedBytes;
    WCHAR Expected[LABEL_MAX];
} LABEL_MARKER;
#define LABEL_MARKER_MAGIC 0x4c424c4e

/*
 * A label survives a restart.  The first run (only with NTFS_APITEST_LABEL_REBOOT set, so a run of
 * every test leaves the label alone) records the volume's own label and a new one next to the test
 * directory, then sets the new label; the run after a restart checks it and restores the old one.
 * The record goes only once the old label is back.
 */
START_TEST(NtfsVolumeLabelReboot)
{
    WCHAR Marker[MAX_PATH], Got[MAX_PATH], Expected[LABEL_MAX + 1];
    LABEL_MARKER M;
    ULONG Bytes;
    HANDLE File;
    DWORD Done;
    BOOL Ok;

    if (!LabelInit("NtfsVolumeLabelReboot"))
        return;
    if (wcslen(NtTestDir()) + 7 > RTL_NUMBER_OF(Marker))
    {
        skip("The test directory path is too long for the marker\n");
        return;
    }
    _snwprintf(Marker, RTL_NUMBER_OF(Marker), L"%ls.label", NtTestDir());
    File = CreateFileW(Marker, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        if (!GetEnvironmentVariableW(L"NTFS_APITEST_LABEL_REBOOT", Got, RTL_NUMBER_OF(Got)))
        {
            skip("Set NTFS_APITEST_LABEL_REBOOT to set a label, then restart and run the test again\n");
            return;
        }
        RtlZeroMemory(&M, sizeof(M));
        M.Magic = LABEL_MARKER_MAGIC;
        if (!NtQueryLabel(Got, &Bytes) || Bytes > sizeof(M.Original))
        {
            skip("Cannot read the label of %ls\n", LabelRoot);
            return;
        }
        M.OriginalBytes = Bytes;
        RtlCopyMemory(M.Original, Got, Bytes);
        _snwprintf(M.Expected, LABEL_MAX, L"Reboot\x017e%04lx", GetTickCount() & 0xffff);
        M.ExpectedBytes = (ULONG)wcslen(M.Expected) * sizeof(WCHAR);
        File = CreateFileW(Marker, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_FLAG_WRITE_THROUGH, NULL);
        ok(File != INVALID_HANDLE_VALUE, "Creating %ls failed %lu\n", Marker, GetLastError());
        if (File == INVALID_HANDLE_VALUE)
            return;
        Ok = WriteFile(File, &M, sizeof(M), &Done, NULL) && Done == sizeof(M);
        ok(Ok, "Writing %ls failed %lu (%lu bytes)\n", Marker, GetLastError(), Done);
        CloseHandle(File);
        if (!Ok)
        {
            DeleteFileW(Marker);
            return;
        }
        ok(SetVolumeLabelW(LabelRoot, M.Expected), "SetVolumeLabelW failed %lu\n", GetLastError());
        ok(NtQueryLabel(Got, &Bytes) && Bytes == M.ExpectedBytes && !memcmp(Got, M.Expected, Bytes), "The new label did not take\n");
        trace("NTFSLABEL:SET %ls; restart and run NtfsVolumeLabelReboot again\n", M.Expected + 7);
        return;
    }
    Ok = ReadFile(File, &M, sizeof(M), &Done, NULL) && Done == sizeof(M) && M.Magic == LABEL_MARKER_MAGIC &&
         M.OriginalBytes <= sizeof(M.Original) && M.ExpectedBytes <= sizeof(M.Expected) &&
         !(M.OriginalBytes & 1) && !(M.ExpectedBytes & 1);
    CloseHandle(File);
    ok(Ok, "%ls is malformed (%lu bytes)\n", Marker, Done);
    if (!Ok)
        return;
    ok(NtQueryLabel(Got, &Bytes), "FileFsVolumeInformation failed\n");
    ok(Bytes == M.ExpectedBytes && !memcmp(Got, M.Expected, Bytes), "The label did not survive the restart (%lu bytes)\n", Bytes);
    RtlCopyMemory(Expected, M.Expected, M.ExpectedBytes);
    Expected[M.ExpectedBytes / sizeof(WCHAR)] = UNICODE_NULL;
    trace("NTFSLABEL:CHECKED %ls\n", Bytes == M.ExpectedBytes && !memcmp(Got, M.Expected, Bytes) && Bytes > 7 * sizeof(WCHAR) ?
          Expected + 7 : L"(different)");
    if (RestoreLabel(M.Original, M.OriginalBytes))
        ok(DeleteFileW(Marker), "DeleteFileW(%ls) failed %lu\n", Marker, GetLastError());
    else
        ok(FALSE, "The old label is not back; %ls is kept for another run\n", Marker);
}

static NTSTATUS VolumeFsctl(HANDLE Handle, ULONG Code)
{
    IO_STATUS_BLOCK Iosb;
    return NtFsControlFile(Handle, NULL, NULL, NULL, &Iosb, Code, NULL, 0, NULL, 0);
}

/*
 * FSCTL_LOCK_VOLUME through a new volume handle; a granted lock is released and the handle closed
 * (Windows dismounts the volume under a handle that locked and unlocked it).
 */
static NTSTATUS TryLock(VOID)
{
    HANDLE Handle;
    NTSTATUS Status = OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Handle);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = VolumeFsctl(Handle, FSCTL_LOCK_VOLUME);
    if (NT_SUCCESS(Status) && VolumeFsctl(Handle, FSCTL_UNLOCK_VOLUME) != STATUS_SUCCESS)
        Status = STATUS_UNSUCCESSFUL;
    NtClose(Handle);
    return Status;
}
#define LockExpect(Expect, What) do { NTSTATUS St_ = TryLock(); ok(St_ == (Expect), "%s: lock 0x%08lx, expected 0x%08lx\n", What, St_, (NTSTATUS)(Expect)); } while (0)
/* ReactOS refuses the lock while a section survives; Windows 10 grants it, Server 2008 R2 grants it unless a view is mapped. */
#define LockRefusedOnReactOS(What) do { NTSTATUS St_ = TryLock(); ok(St_ == STATUS_ACCESS_DENIED || (!is_reactos() && St_ == STATUS_SUCCESS), "%s: lock 0x%08lx\n", What, St_); } while (0)

/* A lock through a new handle that may be refused for a moment (a process's image is released at its last reference). */
static NTSTATUS TryLockSoon(VOID)
{
    NTSTATUS Status;
    ULONG i;
    for (i = 0; (Status = TryLock()) == STATUS_ACCESS_DENIED && i < 20; i++)
        Sleep(250);
    return Status;
}

/* Locks and dismounts the volume through a new handle: the next open mounts it again, with nothing cached. */
static BOOLEAN Remount(VOID)
{
    HANDLE Handle;
    NTSTATUS Status = OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Handle);
    if (!NT_SUCCESS(Status))
        return FALSE;
    Status = VolumeFsctl(Handle, FSCTL_LOCK_VOLUME);
    if (NT_SUCCESS(Status))
        Status = VolumeFsctl(Handle, FSCTL_DISMOUNT_VOLUME);
    NtClose(Handle);
    return NT_SUCCESS(Status);
}

/* The test program copied to Name in the test directory, the volume then mounted again: the copy has no data section. */
static BOOLEAN CopyImage(PCWSTR Name, PWSTR Path)
{
    WCHAR Self[MAX_PATH];

    NtPath(Path, Name);
    if (!GetModuleFileNameW(NULL, Self, MAX_PATH) || !CopyFileW(Self, Path, FALSE))
    {
        ok(FALSE, "Copying the test program to %ls failed %lu\n", Path, GetLastError());
        return FALSE;
    }
    if (!Remount())
    {
        ok(FALSE, "Mounting %ls again failed\n", LabelRoot);
        return FALSE;
    }
    return TRUE;
}

/* An image section of Path, its file handle closed. */
static NTSTATUS ImageSection(PCWSTR Path, PHANDLE Section)
{
    HANDLE File;
    NTSTATUS Status = NtOpen(Path, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                             FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, &File);
    *Section = NULL;
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtCreateSection(Section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, File);
    NtClose(File);
    return Status;
}

/*
 * The volume lock and executables of the volume: a mapped image, an image section without a view and a
 * started program all keep the volume from being locked, as on Windows (Windows 10 and Server 2008 R2
 * refuse all three).  The copy is mounted again first, so that it has only the image section: a data
 * section alone already made the lock fail.
 */
static VOID LockAndImages(VOID)
{
    WCHAR Path[MAX_PATH];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE Section;
    PVOID Base = NULL;
    SIZE_T Size = 0;
    NTSTATUS Status, MapStatus;

    if (!CopyImage(L"img.exe", Path))
        return;
    Status = ImageSection(Path, &Section);
    ok(Status == STATUS_SUCCESS, "Image section of %ls: 0x%08lx\n", Path, Status);
    if (NT_SUCCESS(Status))
    {
        MapStatus = NtMapViewOfSection(Section, NtCurrentProcess(), &Base, 0, 0, NULL, &Size, ViewUnmap, 0, PAGE_EXECUTE_READ);
        ok(NT_SUCCESS(MapStatus), "Image view: 0x%08lx\n", MapStatus);
        LockExpect(STATUS_ACCESS_DENIED, "Image section and view, file handle closed");
        NtClose(Section);
        if (NT_SUCCESS(MapStatus))
        {
            LockExpect(STATUS_ACCESS_DENIED, "Image view only, section handle closed");
            NtUnmapViewOfSection(NtCurrentProcess(), Base);
        }
        LockExpect(STATUS_SUCCESS, "Image view unmapped");
    }
    Status = ImageSection(Path, &Section);
    ok(Status == STATUS_SUCCESS, "Image section of %ls: 0x%08lx\n", Path, Status);
    if (NT_SUCCESS(Status))
    {
        LockExpect(STATUS_ACCESS_DENIED, "Image section without a view");
        NtClose(Section);
        LockExpect(STATUS_SUCCESS, "Image section closed");
    }
    if (!Remount())
        ok(FALSE, "Mounting %ls again failed\n", LabelRoot);
    /* Suspended: its image is mapped, and it runs nothing. */
    if (CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi))
    {
        LockExpect(STATUS_ACCESS_DENIED, "Program started from the volume");
        TerminateProcess(Pi.hProcess, 0);
        WaitForSingleObject(Pi.hProcess, 10000);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
        Status = TryLockSoon();
        ok(Status == STATUS_SUCCESS, "Program ended: lock 0x%08lx\n", Status);
    }
    else
    {
        ok(FALSE, "Starting %ls failed %lu\n", Path, GetLastError());
    }
}

/* Reads or writes Length bytes at Offset through a volume handle; a short transfer is STATUS_UNSUCCESSFUL. */
static NTSTATUS VolumeIo(HANDLE Handle, BOOLEAN Write, LONGLONG Offset, PVOID Buffer, ULONG Length)
{
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Li;
    NTSTATUS Status;
    Li.QuadPart = Offset;
    Iosb.Information = 0;
    Status = Write ? NtWriteFile(Handle, NULL, NULL, NULL, &Iosb, Buffer, Length, &Li, NULL)
                   : NtReadFile(Handle, NULL, NULL, NULL, &Iosb, Buffer, Length, &Li, NULL);
    if (NT_SUCCESS(Status) && Iosb.Information != Length)
        Status = STATUS_UNSUCCESSFUL;
    return Status;
}

/*
 * The holder writes the disk directly (4 KiB past the boot code, with the bytes already there), then
 * unlocks it or closes its handle: the volume is dismounted under that handle, which then reads and
 * writes nothing (STATUS_VOLUME_DISMOUNTED, as on Windows 10), and the next open mounts the volume again,
 * writable, with its label.
 */
static VOID LockDirectWrite(BOOLEAN Unlock)
{
    WCHAR Got[MAX_PATH], Before[MAX_PATH], Path[MAX_PATH];
    PCSTR What = Unlock ? "unlock" : "close";
    HANDLE Lock = NULL, File;
    NTSTATUS Status;
    DWORD Flags = 0, Done;
    PVOID Sector = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);

    if (!Sector)
        return;
    GetLabel(Before);
    Status = OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Lock);
    if (NT_SUCCESS(Status))
        Status = VolumeFsctl(Lock, FSCTL_LOCK_VOLUME);
    ok(Status == STATUS_SUCCESS, "Lock before the direct write (%s): 0x%08lx\n", What, Status);
    if (NT_SUCCESS(Status))
    {
        Status = VolumeIo(Lock, FALSE, 65536, Sector, 4096);
        ok(Status == STATUS_SUCCESS, "Read through the holder's handle: 0x%08lx\n", Status);
        if (NT_SUCCESS(Status))
        {
            Status = VolumeIo(Lock, TRUE, 65536, Sector, 4096);
            ok(Status == STATUS_SUCCESS, "Direct write of the lock holder: 0x%08lx\n", Status);
        }
        if (Unlock)
        {
            Status = VolumeFsctl(Lock, FSCTL_UNLOCK_VOLUME);
            ok(Status == STATUS_SUCCESS, "Unlock after the direct write: 0x%08lx\n", Status);
            Status = VolumeIo(Lock, FALSE, 65536, Sector, 4096);
            ok(Status == STATUS_VOLUME_DISMOUNTED, "Read through the old holder's handle: 0x%08lx\n", Status);
            Status = VolumeIo(Lock, TRUE, 65536, Sector, 4096);
            ok(Status == STATUS_VOLUME_DISMOUNTED, "Write through the old holder's handle: 0x%08lx\n", Status);
            Status = VolumeFsctl(Lock, FSCTL_LOCK_VOLUME);
            ok(Status == STATUS_VOLUME_DISMOUNTED, "Lock through the old holder's handle: 0x%08lx\n", Status);
        }
    }
    if (Lock)
        NtClose(Lock);
    /* Mounted again: writable, the label as before. */
    Got[0] = UNICODE_NULL;
    if (GetVolumeInformationW(LabelRoot, Got, MAX_PATH, NULL, NULL, &Flags, NULL, 0))
    {
        ok(!(Flags & FILE_READ_ONLY_VOLUME), "Read-only after the direct write and the %s (flags 0x%lx)\n", What, Flags);
        ok(!wcscmp(Got, Before), "Label after the %s is \"%ls\", expected \"%ls\"\n", What, Got, Before);
    }
    else
    {
        ok(FALSE, "GetVolumeInformationW after the %s failed %lu\n", What, GetLastError());
    }
    NtPath(Path, L"after.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Creating %ls after the %s failed %lu\n", Path, What, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        ok(WriteFile(File, "after", 5, &Done, NULL) && Done == 5, "WriteFile after the %s failed %lu\n", What, GetLastError());
        CloseHandle(File);
    }
    VirtualFree(Sector, 0, MEM_RELEASE);
}

/*
 * FSCTL_DISMOUNT_VOLUME by the holder: its handle reads and writes the disk directly until it unlocks,
 * and afterwards nothing (STATUS_VOLUME_DISMOUNTED, as on Windows 10); the next open mounts the volume.
 */
static VOID LockDismountUnlock(VOID)
{
    HANDLE Lock = NULL;
    NTSTATUS Status;
    DWORD Flags = 0;
    PVOID Sector = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);

    if (!Sector)
        return;
    Status = OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Lock);
    if (NT_SUCCESS(Status))
        Status = VolumeFsctl(Lock, FSCTL_LOCK_VOLUME);
    ok(Status == STATUS_SUCCESS, "Lock before the dismount: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Status = VolumeFsctl(Lock, FSCTL_DISMOUNT_VOLUME);
        ok(Status == STATUS_SUCCESS, "Dismount: 0x%08lx\n", Status);
        Status = VolumeIo(Lock, FALSE, 65536, Sector, 4096);
        ok(Status == STATUS_SUCCESS, "Read through the dismounted, locked handle: 0x%08lx\n", Status);
        if (NT_SUCCESS(Status))
        {
            Status = VolumeIo(Lock, TRUE, 65536, Sector, 4096);
            ok(Status == STATUS_SUCCESS, "Write through the dismounted, locked handle: 0x%08lx\n", Status);
        }
        Status = VolumeFsctl(Lock, FSCTL_UNLOCK_VOLUME);
        ok(Status == STATUS_SUCCESS, "Unlock after the dismount: 0x%08lx\n", Status);
        Status = VolumeIo(Lock, FALSE, 65536, Sector, 4096);
        ok(Status == STATUS_VOLUME_DISMOUNTED, "Read through the dismounted handle after the unlock: 0x%08lx\n", Status);
        Status = VolumeIo(Lock, TRUE, 65536, Sector, 4096);
        ok(Status == STATUS_VOLUME_DISMOUNTED, "Write through the dismounted handle after the unlock: 0x%08lx\n", Status);
    }
    if (Lock)
        NtClose(Lock);
    ok(GetVolumeInformationW(LabelRoot, NULL, 0, NULL, NULL, &Flags, NULL, 0) && !(Flags & FILE_READ_ONLY_VOLUME),
       "After the dismount: error %lu, flags 0x%lx\n", GetLastError(), Flags);
    VirtualFree(Sector, 0, MEM_RELEASE);
}

/* A file of Size bytes of Fill in the test directory, its handle closed; the mapping and view of Protect stay. */
static BOOLEAN MapClosedFile(PCWSTR Name, DWORD Protect, BYTE Fill, HANDLE *Section, PBYTE *View)
{
    BYTE Data[4096];
    WCHAR Path[MAX_PATH];
    HANDLE File;
    DWORD Done, i;
    BOOL Ok = TRUE;

    *Section = NULL;
    *View = NULL;
    NtPath(Path, Name);
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Creating %ls failed %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    memset(Data, Fill, sizeof(Data));
    for (i = 0; Ok && i < 16; i++)
        Ok = WriteFile(File, Data, sizeof(Data), &Done, NULL) && Done == sizeof(Data);
    ok(Ok, "Writing %ls failed %lu\n", Path, GetLastError());
    if (Ok)
        *Section = CreateFileMappingW(File, NULL, Protect, 0, 0, NULL);
    ok(*Section != NULL, "CreateFileMappingW(%ls) failed %lu\n", Path, GetLastError());
    if (*Section)
        *View = MapViewOfFile(*Section, Protect == PAGE_READWRITE ? FILE_MAP_WRITE : FILE_MAP_READ, 0, 0, 0);
    ok(*View != NULL, "MapViewOfFile(%ls) failed %lu\n", Path, GetLastError());
    CloseHandle(File);
    if (!*View && *Section)
    {
        CloseHandle(*Section);
        *Section = NULL;
    }
    return *View != NULL;
}

/*
 * The volume lock and mapped files: on ReactOS no lock while a section of a file survives its handle
 * (once the holder writes the disk directly, the section's page writes could not be honoured); after
 * a view goes, what it wrote is in the file and the lock is granted.  No lock while an executable of
 * the volume is mapped as an image or runs.  After a direct write of the holder the end of the lock
 * dismounts the volume, and the next open mounts it again.  A locked volume takes no label,
 * neither through the holder's handle nor through another open; with files open and mapped the label
 * changes.  Needs a volume nothing else uses (set NTFS_APITEST_DIR to a directory on it): it skips if
 * the volume cannot be locked at all, as the system volume cannot.
 */
START_TEST(NtfsVolumeLock)
{
    WCHAR Original[MAX_PATH], Got[MAX_PATH], Path[MAX_PATH], Before[MAX_PATH];
    HANDLE Lock, Section, File;
    PBYTE View;
    NTSTATUS Status;
    ULONG OriginalBytes, i;
    DWORD Done;
    BYTE Byte;
    BOOL Ret;

    if (!LabelInit("NtfsVolumeLock"))
        return;
    if (!NtQueryLabel(Original, &OriginalBytes))
    {
        skip("Cannot read the label of %ls\n", LabelRoot);
        NtCleanup();
        return;
    }
    Status = OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Lock);
    ok(Status == STATUS_SUCCESS, "Volume open: 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        NtCleanup();
        return;
    }
    /* Another program may hold the volume for a moment (an indexer, a virus scanner on Windows). */
    for (i = 0; i < 20 && (Status = VolumeFsctl(Lock, FSCTL_LOCK_VOLUME)) == STATUS_ACCESS_DENIED; i++)
        Sleep(500);
    if (!NT_SUCCESS(Status))
    {
        skip("%ls cannot be locked (0x%08lx): it is in use\n", LabelRoot, Status);
        NtClose(Lock);
        NtCleanup();
        return;
    }
    VolumeFsctl(Lock, FSCTL_UNLOCK_VOLUME);
    NtClose(Lock);

    /* A writable view whose file handle is closed. */
    if (MapClosedFile(L"rw.bin", PAGE_READWRITE, 'A', &Section, &View))
    {
        View[0] = 'B';
        LockRefusedOnReactOS("Writable section and view, file handle closed");
        CloseHandle(Section);
        LockRefusedOnReactOS("Writable view only, section handle closed");
        UnmapViewOfFile(View);
        LockExpect(STATUS_SUCCESS, "View unmapped");
        /* What the view wrote reached the file. */
        NtPath(Path, L"rw.bin");
        File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        Byte = 0;
        ok(File != INVALID_HANDLE_VALUE && ReadFile(File, &Byte, 1, &Done, NULL) && Done == 1 && Byte == 'B',
           "The byte written through the view is 0x%02x\n", Byte);
        if (File != INVALID_HANDLE_VALUE)
            CloseHandle(File);
    }
    /* A read-only view, and a section without a view. */
    if (MapClosedFile(L"ro.bin", PAGE_READONLY, 'C', &Section, &View))
    {
        LockRefusedOnReactOS("Read-only section and view, file handle closed");
        UnmapViewOfFile(View);
        LockRefusedOnReactOS("Section without a view, file handle closed");
        CloseHandle(Section);
        LockExpect(STATUS_SUCCESS, "Section closed");
    }

    /* With a file open for writing and another mapped and written, the label changes. */
    NtPath(Path, L"open.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Creating %ls failed %lu\n", Path, GetLastError());
    if (File != INVALID_HANDLE_VALUE && MapClosedFile(L"rw2.bin", PAGE_READWRITE, 'D', &Section, &View))
    {
        ok(WriteFile(File, "open", 4, &Done, NULL) && Done == 4, "WriteFile failed %lu\n", GetLastError());
        View[1] = 'E';
        SetAndCheck(L"OpenFiles", TRUE, 0, L"OpenFiles");
        LockExpect(STATUS_ACCESS_DENIED, "Open and mapped files");
        ok(View[0] == 'D' && View[1] == 'E', "The view reads 0x%02x 0x%02x\n", View[0], View[1]);
        UnmapViewOfFile(View);
        CloseHandle(Section);
    }
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);

    LockAndImages();
    LockDirectWrite(TRUE);
    LockDirectWrite(FALSE);
    LockDismountUnlock();

    /* Locked: a label set through the holder's handle or another open is refused, and the label stays.
     */
    GetLabel(Before);
    Lock = NULL;
    Status = OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Lock);
    ok(Status == STATUS_SUCCESS, "Volume open: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
        Status = VolumeFsctl(Lock, FSCTL_LOCK_VOLUME);
    ok(Status == STATUS_SUCCESS, "Lock: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Status = NtSetLabel(Lock, L"HolderLabel", 22, sizeof(FILE_FS_LABEL_INFORMATION) + 22);
        /* Windows 10 reports the volume dismounted, Server 2008 R2 STATUS_FILE_INVALID. */
        ok(Status == STATUS_ACCESS_DENIED || (!is_reactos() && !NT_SUCCESS(Status)),
           "Label through the lock holder's handle: 0x%08lx\n", Status);
        SetLastError(0xdeadbeef);
        Ret = SetVolumeLabelW(LabelRoot, L"LockedLabel");
        ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "SetVolumeLabelW on the locked volume: %d, error %lu\n", Ret, GetLastError());
        VolumeFsctl(Lock, FSCTL_UNLOCK_VOLUME);
    }
    if (Lock)
        NtClose(Lock);
    ok(GetLabel(Got) && !wcscmp(Got, Before), "Label after the refused sets is \"%ls\", expected \"%ls\"\n", Got, Before);
    ok(RestoreLabel(Original, OriginalBytes), "The label of %ls was not restored\n", LabelRoot);
    NtCleanup();
}

/*
 * Who may manage a volume through a volume handle (read its allocation bitmap, lock and dismount it).
 * As NTFS on Windows (Server 2008 R2 and Windows 10, black-box): the opener whose token the volume
 * device's ACL grants both read and write data access, or who holds SeManageVolumePrivilege enabled,
 * whatever the handle was opened for; anybody else gets STATUS_ACCESS_DENIED, however the handle was
 * opened.  The default ACL of a volume device lets a non-administrator open the volume for traverse,
 * read attributes and read control only; such a handle still queries the volume (NTFS volume data, the
 * dirty flag) but reads no sectors and manages nothing.
 */
/* Whether the volume device's ACL grants Token (a primary or impersonation token) all of Access. */
static BOOLEAN AclGrants(HANDLE Token, ACCESS_MASK Access)
{
    static GENERIC_MAPPING Mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
    BYTE Sd[4096], PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted = 0;
    BOOL Status = FALSE;
    ULONG Length;
    HANDLE Volume, Imp;

    MapGenericMask(&Access, &Mapping);
    if (!NT_SUCCESS(OpenVolume(READ_CONTROL, &Volume)))
        return FALSE;
    if (NT_SUCCESS(NtQuerySecurityObject(Volume, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                                 DACL_SECURITY_INFORMATION, Sd, sizeof(Sd), &Length)) &&
        DuplicateToken(Token, SecurityImpersonation, &Imp))
    {
        if (!AccessCheck(Sd, Imp, Access, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status))
            Status = FALSE;
        CloseHandle(Imp);
    }
    NtClose(Volume);
    return Status != FALSE;
}

static NTSTATUS GetBitmap(HANDLE Handle)
{
    IO_STATUS_BLOCK Iosb;
    LONGLONG Start = 0;
    ULONGLONG Out[8];
    NTSTATUS Status = NtFsControlFile(Handle, NULL, NULL, NULL, &Iosb, FSCTL_GET_VOLUME_BITMAP, &Start, sizeof(Start), Out, sizeof(Out));
    /* A small buffer: a volume of more than 384 clusters does not fit. */
    return Status == STATUS_BUFFER_OVERFLOW ? STATUS_SUCCESS : Status;
}

/* The volume operations through a handle opened with Access: open, sector read, queries, bitmap, lock. */
static VOID CheckVolumeHandle(int Line, PCSTR Who, ACCESS_MASK Access, BOOLEAN Manage, BOOLEAN Lockable)
{
    IO_STATUS_BLOCK Iosb;
    NTFS_VOLUME_DATA_BUFFER Data;
    ULONG Dirty;
    HANDLE Handle;
    NTSTATUS Status;
    PVOID Sector = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);

    Status = OpenVolume(Access, &Handle);
    ok_(__FILE__, Line)(Status == STATUS_SUCCESS, "%s, access 0x%lx: volume open 0x%08lx\n", Who, Access, Status);
    if (!NT_SUCCESS(Status))
    {
        VirtualFree(Sector, 0, MEM_RELEASE);
        return;
    }
    Status = NtFsControlFile(Handle, NULL, NULL, NULL, &Iosb, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &Data, sizeof(Data));
    ok_(__FILE__, Line)(Status == STATUS_SUCCESS, "%s, access 0x%lx: FSCTL_GET_NTFS_VOLUME_DATA 0x%08lx\n", Who, Access, Status);
    Status = NtFsControlFile(Handle, NULL, NULL, NULL, &Iosb, FSCTL_IS_VOLUME_DIRTY, NULL, 0, &Dirty, sizeof(Dirty));
    ok_(__FILE__, Line)(Status == STATUS_SUCCESS, "%s, access 0x%lx: FSCTL_IS_VOLUME_DIRTY 0x%08lx\n", Who, Access, Status);
    if (Sector)
    {
        Status = VolumeIo(Handle, FALSE, 0, Sector, 4096);
        ok_(__FILE__, Line)(Status == ((Access & (FILE_READ_DATA | GENERIC_READ)) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED),
                            "%s, access 0x%lx: sector read 0x%08lx\n", Who, Access, Status);
    }
    Status = GetBitmap(Handle);
    ok_(__FILE__, Line)(Status == (Manage ? STATUS_SUCCESS : STATUS_ACCESS_DENIED),
                        "%s, access 0x%lx: FSCTL_GET_VOLUME_BITMAP 0x%08lx\n", Who, Access, Status);
    if (!Manage || Lockable)
    {
        /* Refused before it can fail for a volume in use, so the system volume tests the refusal too. */
        ULONG Try;
        /* Something else may have the volume open for a moment (an indexer, a virus scanner on Windows). */
        for (Try = 0; (Status = VolumeFsctl(Handle, FSCTL_LOCK_VOLUME)) == STATUS_ACCESS_DENIED && Manage && Try < 20; Try++)
            Sleep(250);
        ok_(__FILE__, Line)(Status == (Manage ? STATUS_SUCCESS : STATUS_ACCESS_DENIED),
                            "%s, access 0x%lx: FSCTL_LOCK_VOLUME 0x%08lx\n", Who, Access, Status);
        if (NT_SUCCESS(Status))
            ok_(__FILE__, Line)(VolumeFsctl(Handle, FSCTL_UNLOCK_VOLUME) == STATUS_SUCCESS, "%s: unlock failed\n", Who);
        else if (!Manage)
        {
            Status = VolumeFsctl(Handle, FSCTL_DISMOUNT_VOLUME);
            ok_(__FILE__, Line)(Status == STATUS_ACCESS_DENIED, "%s, access 0x%lx: FSCTL_DISMOUNT_VOLUME 0x%08lx\n", Who, Access, Status);
        }
    }
    NtClose(Handle);
    VirtualFree(Sector, 0, MEM_RELEASE);
}

static BOOLEAN HasPrivilege(HANDLE Token, PCWSTR Name)
{
    UCHAR Buffer[1024];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Len, i;
    LUID Luid;

    if (!LookupPrivilegeValueW(NULL, Name, &Luid) ||
        !GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Len))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
        if (Privileges->Privileges[i].Luid.LowPart == Luid.LowPart && Privileges->Privileges[i].Luid.HighPart == Luid.HighPart)
            return TRUE;
    return FALSE;
}

START_TEST(NtfsVolumeOpen)
{
    static const ACCESS_MASK UserAccess[] = { FILE_EXECUTE, FILE_EXECUTE | FILE_READ_ATTRIBUTES, GENERIC_EXECUTE };
    static const ACCESS_MASK AdminAccess[] = { FILE_EXECUTE, FILE_EXECUTE | FILE_READ_ATTRIBUTES, GENERIC_READ, GENERIC_READ | GENERIC_WRITE };
    static const ACCESS_MASK DataAccess[] = { GENERIC_READ, FILE_READ_DATA, FILE_WRITE_DATA };
    BOOLEAN Lockable = FALSE, UserManage, PreHeld = FALSE;
    HANDLE Handle, Token = NULL, Logon;
    NTSTATUS Status;
    ULONG i;

    if (!LabelInit("NtfsVolumeOpen"))
        return;

    /* A volume that can be locked at all (not the system volume) also has the granted locks checked. */
    if (NT_SUCCESS(OpenVolume(FILE_READ_DATA | FILE_WRITE_DATA, &Handle)))
    {
        for (i = 0; i < 20 && (Status = VolumeFsctl(Handle, FSCTL_LOCK_VOLUME)) == STATUS_ACCESS_DENIED; i++)
            Sleep(500);
        if (NT_SUCCESS(Status))
        {
            Lockable = TRUE;
            VolumeFsctl(Handle, FSCTL_UNLOCK_VOLUME);
        }
        NtClose(Handle);
    }
    {
        UCHAR Buffer[256];
        DWORD Len;
        LPSTR Sid = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        {
            if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Len))
                ConvertSidToStringSidA(((PTOKEN_USER)Buffer)->User.Sid, &Sid);
            CloseHandle(Token);
            Token = NULL;
        }
        trace("Volume %ls, %slockable, running as %s\n", VolumePath, Lockable ? "" : "not ", Sid ? Sid : "?");
        if (Sid)
            LocalFree(Sid);
    }

    /* An administrator manages the volume through any volume handle, a traverse-only one too. */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &Token) ||
        !AclGrants(Token, FILE_READ_DATA | FILE_WRITE_DATA))
        skip("The ACL of %ls does not grant this administrator read and write data access\n", VolumePath);
    else
    {
        for (i = 0; i < RTL_NUMBER_OF(AdminAccess); i++)
            CheckVolumeHandle(__LINE__, "Administrator", AdminAccess[i], TRUE, Lockable);
    }
    if (Token)
        CloseHandle(Token);
    Token = NULL;

    if (!NtHaveUser())
    {
        NtCleanup();
        return;
    }
    /* The default device ACL (ReactOS's always) gives a non-administrator no data access to the volume. */
    ok(!is_reactos() || (!AclGrants(UserToken, FILE_READ_DATA) && !AclGrants(UserToken, FILE_WRITE_DATA)),
       "The ACL of %ls grants the test user data access\n", VolumePath);
    /* Read or write data access alone is not enough to manage the volume; both are. */
    UserManage = AclGrants(UserToken, FILE_READ_DATA | FILE_WRITE_DATA);
    for (i = 0; i < RTL_NUMBER_OF(DataAccess); i++)
    {
        BOOLEAN Expect = AclGrants(UserToken, DataAccess[i]);
        NtBeginUser();
        Status = OpenVolume(DataAccess[i], &Handle);
        NtEndUser();
        ok(Status == (Expect ? STATUS_SUCCESS : STATUS_ACCESS_DENIED), "Non-administrator, access 0x%lx: volume open 0x%08lx\n",
           DataAccess[i], Status);
        if (NT_SUCCESS(Status))
        {
            NtClose(Handle);
            NtBeginUser();
            CheckVolumeHandle(__LINE__, "Non-administrator", DataAccess[i], UserManage, Lockable);
            NtEndUser();
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(UserAccess); i++)
    {
        if (!AclGrants(UserToken, UserAccess[i]))
            continue;
        NtBeginUser();
        CheckVolumeHandle(__LINE__, "Non-administrator", UserAccess[i], UserManage, Lockable);
        NtEndUser();
    }

    /* The non-administrator who holds SeManageVolumePrivilege manages the volume once it enables it. */
    Logon = NtLogonUser();
    Token = NULL;
    if (Logon && DuplicateTokenEx(Logon, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token))
        PreHeld = HasPrivilege(Token, L"SeManageVolumePrivilege");
    if (Token)
        CloseHandle(Token);
    if (Logon)
        CloseHandle(Logon);
    Token = Logon = NULL;
    if (UserManage || !AclGrants(UserToken, FILE_EXECUTE | FILE_READ_ATTRIBUTES))
        skip("The ACL of %ls decides for the test user without the privilege\n", VolumePath);
    else if (!PreHeld && !NtUserRight(L"SeManageVolumePrivilege", TRUE))
        skip("Cannot grant SeManageVolumePrivilege to the test user\n");
    else
    {
        Logon = NtLogonUser();
        if (!Logon || !DuplicateTokenEx(Logon, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token))
            ok(FALSE, "No logon of the test user with the privilege\n");
        else if (!HasPrivilege(Token, L"SeManageVolumePrivilege"))
            skip("A new logon of the test user has no SeManageVolumePrivilege\n");
        else
        {
            ok(SetThreadToken(NULL, Token), "SetThreadToken failed %lu\n", GetLastError());
            CheckVolumeHandle(__LINE__, "Privilege held, not enabled", FILE_EXECUTE | FILE_READ_ATTRIBUTES, FALSE, Lockable);
            RevertToSelf();
            ok(NtSetPrivilege(Token, L"SeManageVolumePrivilege", TRUE), "Enabling SeManageVolumePrivilege failed\n");
            ok(SetThreadToken(NULL, Token), "SetThreadToken failed %lu\n", GetLastError());
            CheckVolumeHandle(__LINE__, "Privilege enabled", FILE_EXECUTE | FILE_READ_ATTRIBUTES, TRUE, Lockable);
            RevertToSelf();
        }
        if (Token)
            CloseHandle(Token);
        if (Logon)
            CloseHandle(Logon);
        /* Taken back at once: only a grant this test made. */
        if (!PreHeld && !NtUserRight(L"SeManageVolumePrivilege", FALSE))
            trace("SeManageVolumePrivilege of the test user was not taken back\n");
    }
    NtCleanup();
}

/* FSCTL_GET_NTFS_VOLUME_DATA on a volume handle; Windows refuses it on a handle without FILE_READ_DATA. */
static NTSTATUS NtVolumeData(ULONG Length, PVOID Buffer, ULONG_PTR *Information)
{
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;

    *Information = 0;
    Status = OpenVolume(FILE_READ_DATA, &Handle);
    if (!NT_SUCCESS(Status))
        return Status;
    Iosb.Information = 0;
    Status = NtFsControlFile(Handle, NULL, NULL, NULL, &Iosb, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, Buffer, Length);
    *Information = Iosb.Information;
    NtClose(Handle);
    return Status;
}

/* The major NTFS version of the test directory's volume (the extended FSCTL_GET_NTFS_VOLUME_DATA output), 0 if unknown. */
static UCHAR NtVolumeMajor(VOID)
{
    struct { NTFS_VOLUME_DATA_BUFFER Data; NTFS_EXTENDED_VOLUME_DATA Extended; } Buffer;
    ULONG_PTR Information;

    RtlZeroMemory(&Buffer, sizeof(Buffer));
    if (!NT_SUCCESS(NtVolumeData(sizeof(Buffer), &Buffer, &Information)) || Information < sizeof(Buffer))
        return 0;
    return (UCHAR)Buffer.Extended.MajorVersion;
}

/*
 * The file system attributes FileFsAttributeInformation reports for the test directory's volume.
 * Each flag checked here is reported by Windows 10 and Server 2008 R2 NTFS (0x03e706ff and
 * 0x03e700ff on their system volumes) and implemented by ntfsng: FSCTL_SET/GET/DELETE_REPARSE_POINT
 * and junction traversal (exercised by kernel32_apitest VolumeMountPoint and userenv_apitest, not
 * here), hard links (NtfsHardLink) and open by file ID (NtfsOpenById).  On ReactOS the set is
 * exact: a flag for a feature the driver does not implement must not be reported.
 */
START_TEST(NtfsVolumeAttributes)
{
    static const struct { ULONG Flag; PCSTR Name; } Expected[] =
    {
        { FILE_CASE_PRESERVED_NAMES, "FILE_CASE_PRESERVED_NAMES" },
        { FILE_UNICODE_ON_DISK, "FILE_UNICODE_ON_DISK" },
        { FILE_PERSISTENT_ACLS, "FILE_PERSISTENT_ACLS" },
        { FILE_SUPPORTS_REPARSE_POINTS, "FILE_SUPPORTS_REPARSE_POINTS" },
        { FILE_NAMED_STREAMS, "FILE_NAMED_STREAMS" },
        { FILE_SUPPORTS_HARD_LINKS, "FILE_SUPPORTS_HARD_LINKS" },
        { FILE_SUPPORTS_OPEN_BY_FILE_ID, "FILE_SUPPORTS_OPEN_BY_FILE_ID" },
    };
    ULONGLONG Buffer[(sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + MAX_PATH * sizeof(WCHAR)) / sizeof(ULONGLONG)];
    PFILE_FS_ATTRIBUTE_INFORMATION Info = (PFILE_FS_ATTRIBUTE_INFORMATION)Buffer;
    WCHAR FsName[MAX_PATH];
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;
    DWORD Flags = 0, MaxComponent = 0;
    ULONG i, All = 0;
    UCHAR Major;

    if (!LabelInit("NtfsVolumeAttributes"))
        return;
    Major = NtVolumeMajor();
    ok(Major != 0, "No NTFS version from FSCTL_GET_NTFS_VOLUME_DATA\n");
    Status = NtOpen(NtTestDir(), FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_RW | FILE_SHARE_DELETE, FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, &Handle);
    ok(Status == STATUS_SUCCESS, "Opening %ls: 0x%08lx\n", NtTestDir(), Status);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(Buffer, sizeof(Buffer));
        Status = NtQueryVolumeInformationFile(Handle, &Iosb, Info, sizeof(Buffer), FileFsAttributeInformation);
        NtClose(Handle);
        ok(Status == STATUS_SUCCESS, "FileFsAttributeInformation: 0x%08lx\n", Status);
    }
    if (NT_SUCCESS(Status))
    {
        trace("%ls: FileSystemAttributes 0x%08lx\n", LabelRoot, Info->FileSystemAttributes);
        ok(Info->FileSystemNameLength == 8 && !memcmp(Info->FileSystemName, L"NTFS", 8),
           "File system name \"%.*ls\"\n", (int)(Info->FileSystemNameLength / sizeof(WCHAR)), Info->FileSystemName);
        ok(Info->MaximumComponentNameLength == 255, "MaximumComponentNameLength %lu\n", Info->MaximumComponentNameLength);
        for (i = 0; i < RTL_NUMBER_OF(Expected); i++)
        {
            /* An NTFS 1.x/2.x volume has no $Extend\$Reparse, hence no reparse points. */
            if (Expected[i].Flag == FILE_SUPPORTS_REPARSE_POINTS && Major && Major < 3)
            {
                ok(!(Info->FileSystemAttributes & FILE_SUPPORTS_REPARSE_POINTS) || !is_reactos(),
                   "Reparse points reported on an NTFS %u volume: 0x%08lx\n", Major, Info->FileSystemAttributes);
                continue;
            }
            ok(Info->FileSystemAttributes & Expected[i].Flag, "%s (0x%08lx) not reported: 0x%08lx\n",
               Expected[i].Name, Expected[i].Flag, Info->FileSystemAttributes);
            All |= Expected[i].Flag;
        }
        ok(!(Info->FileSystemAttributes & FILE_READ_ONLY_VOLUME), "Writable volume reported read-only: 0x%08lx\n",
           Info->FileSystemAttributes);
        if (is_reactos())
            ok(!(Info->FileSystemAttributes & ~All), "Unexpected flags reported: 0x%08lx\n", Info->FileSystemAttributes & ~All);

        /* GetVolumeInformationW passes the same flags through. */
        if (GetVolumeInformationW(LabelRoot, NULL, 0, NULL, &MaxComponent, &Flags, FsName, RTL_NUMBER_OF(FsName)))
        {
            ok(Flags == Info->FileSystemAttributes, "GetVolumeInformationW flags 0x%08lx, native 0x%08lx\n",
               Flags, Info->FileSystemAttributes);
            ok(MaxComponent == 255, "GetVolumeInformationW component length %lu\n", MaxComponent);
            ok(!wcscmp(FsName, L"NTFS"), "GetVolumeInformationW file system \"%ls\"\n", FsName);
        }
        else
        {
            ok(FALSE, "GetVolumeInformationW failed %lu\n", GetLastError());
        }
    }
    NtCleanup();
}

/*
 * FSCTL_GET_NTFS_VOLUME_DATA: the base block, then whole fields of NTFS_EXTENDED_VOLUME_DATA as far
 * as they fit, ByteCount saying how many bytes of it.  Measured on Server 2008 R2 (8-byte extended
 * block) and Windows 10 (32 bytes: physical sector size, LFS version and trim limits follow; no
 * extended block at all for 100 bytes).  ntfsng follows Server 2008 R2.
 */
START_TEST(NtfsVolumeData)
{
    struct { NTFS_VOLUME_DATA_BUFFER Data; NTFS_EXTENDED_VOLUME_DATA Extended; UCHAR Rest[160]; } Buffer;
    ULONG_PTR Information;
    NTSTATUS Status;
    USHORT Major;

    if (!LabelInit("NtfsVolumeData"))
        return;

    Status = NtVolumeData(sizeof(NTFS_VOLUME_DATA_BUFFER) - 1, &Buffer, &Information);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "Short buffer: 0x%08lx\n", Status);

    memset(&Buffer, 0xcc, sizeof(Buffer));
    Status = NtVolumeData(sizeof(NTFS_VOLUME_DATA_BUFFER), &Buffer, &Information);
    ok(Status == STATUS_SUCCESS, "Base block: 0x%08lx\n", Status);
    ok(Information == sizeof(NTFS_VOLUME_DATA_BUFFER), "Base block: %Iu bytes\n", Information);
    ok(Buffer.Extended.ByteCount == 0xcccccccc, "Written past the buffer: 0x%08lx\n", Buffer.Extended.ByteCount);
    ok(Buffer.Data.BytesPerSector >= 512 && Buffer.Data.BytesPerCluster >= Buffer.Data.BytesPerSector &&
       Buffer.Data.BytesPerFileRecordSegment &&
       Buffer.Data.ClustersPerFileRecordSegment == Buffer.Data.BytesPerFileRecordSegment / Buffer.Data.BytesPerCluster,
       "Geometry %lu %lu %lu %lu\n", Buffer.Data.BytesPerSector, Buffer.Data.BytesPerCluster,
       Buffer.Data.BytesPerFileRecordSegment, Buffer.Data.ClustersPerFileRecordSegment);
    ok(Buffer.Data.FreeClusters.QuadPart <= Buffer.Data.TotalClusters.QuadPart, "Free %I64d of %I64d clusters\n",
       Buffer.Data.FreeClusters.QuadPart, Buffer.Data.TotalClusters.QuadPart);

    /* Room for ByteCount only: Server 2008 R2 returns it (as ntfsng does), Windows 10 only the base block. */
    memset(&Buffer, 0xcc, sizeof(Buffer));
    Status = NtVolumeData(sizeof(NTFS_VOLUME_DATA_BUFFER) + 4, &Buffer, &Information);
    ok(Status == STATUS_SUCCESS, "ByteCount only: 0x%08lx\n", Status);
    ok((Information == sizeof(NTFS_VOLUME_DATA_BUFFER) + 4 && Buffer.Extended.ByteCount == 4) ||
       (!is_reactos() && Information == sizeof(NTFS_VOLUME_DATA_BUFFER) && Buffer.Extended.ByteCount == 0xcccccccc),
       "ByteCount only: %Iu bytes, ByteCount 0x%08lx\n", Information, Buffer.Extended.ByteCount);
    ok(Buffer.Extended.MajorVersion == 0xcccc, "ByteCount only: MajorVersion written: 0x%04x\n", Buffer.Extended.MajorVersion);

    /* Room for ByteCount and MajorVersion, not MinorVersion. */
    memset(&Buffer, 0xcc, sizeof(Buffer));
    Status = NtVolumeData(sizeof(NTFS_VOLUME_DATA_BUFFER) + 7, &Buffer, &Information);
    ok(Status == STATUS_SUCCESS, "Partial extended block: 0x%08lx\n", Status);
    ok(Information == sizeof(NTFS_VOLUME_DATA_BUFFER) + 6, "Partial extended block: %Iu bytes\n", Information);
    ok(Buffer.Extended.ByteCount == 6, "Partial ByteCount %lu\n", Buffer.Extended.ByteCount);
    Major = Buffer.Extended.MajorVersion;
    ok(Major >= 1 && Major <= 3, "Partial MajorVersion %u\n", Major);
    ok(Buffer.Extended.MinorVersion == 0xcccc, "Partial MinorVersion written: 0x%04x\n", Buffer.Extended.MinorVersion);

    memset(&Buffer, 0xcc, sizeof(Buffer));
    Status = NtVolumeData(sizeof(NTFS_VOLUME_DATA_BUFFER) + sizeof(NTFS_EXTENDED_VOLUME_DATA), &Buffer, &Information);
    ok(Status == STATUS_SUCCESS, "Extended block: 0x%08lx\n", Status);
    ok(Information == sizeof(NTFS_VOLUME_DATA_BUFFER) + sizeof(NTFS_EXTENDED_VOLUME_DATA), "Extended block: %Iu bytes\n", Information);
    ok(Buffer.Extended.ByteCount == sizeof(NTFS_EXTENDED_VOLUME_DATA), "ByteCount %lu\n", Buffer.Extended.ByteCount);
    ok(Buffer.Extended.MajorVersion == Major && Buffer.Extended.MinorVersion <= 2, "Version %u.%u\n",
       Buffer.Extended.MajorVersion, Buffer.Extended.MinorVersion);

    /* A large buffer: the whole extended block, ByteCount matching the returned length. */
    memset(&Buffer, 0xcc, sizeof(Buffer));
    Status = NtVolumeData(sizeof(Buffer), &Buffer, &Information);
    ok(Status == STATUS_SUCCESS, "Large buffer: 0x%08lx\n", Status);
    ok(Information >= sizeof(NTFS_VOLUME_DATA_BUFFER) + sizeof(NTFS_EXTENDED_VOLUME_DATA) && Information < sizeof(Buffer),
       "Large buffer: %Iu bytes\n", Information);
    ok(Buffer.Extended.ByteCount == Information - sizeof(NTFS_VOLUME_DATA_BUFFER), "ByteCount %lu for %Iu bytes\n",
       Buffer.Extended.ByteCount, Information);
    if (is_reactos())
        ok(Information == sizeof(NTFS_VOLUME_DATA_BUFFER) + sizeof(NTFS_EXTENDED_VOLUME_DATA), "Large buffer: %Iu bytes\n", Information);
    NtCleanup();
}
