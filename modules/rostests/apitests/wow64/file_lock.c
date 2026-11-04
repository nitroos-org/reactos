/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     MSI compound-file locking: contention, pending completion and guest IOSBs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* MSI compound-file locking: contention, pending completion and guest IOSBs. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

int main(int argc, char **argv)
{
    typedef LONG (WINAPI *LOCK)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN);
    LOCK NtLock = (LOCK)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtLockFile");
    WCHAR Temp[MAX_PATH], Path[MAX_PATH];
    HANDLE First, Second, Event;
    OVERLAPPED Owner = {0}, Other = {0};
    struct { ULONG_PTR Status, Information; DWORD Guard[2]; } Io;
    LARGE_INTEGER Offset, Length;
    DWORD Bytes;
    LONG Status;
    CHECK(GetTempPathW(MAX_PATH, Temp));
    CHECK(GetTempFileNameW(Temp, L"w6l", 0, Path));
    First = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    Second = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(First != INVALID_HANDLE_VALUE && Second != INVALID_HANDLE_VALUE && Event && NtLock);
    if (First == INVALID_HANDLE_VALUE || Second == INVALID_HANDLE_VALUE || !Event || !NtLock) goto done;
    CHECK(WriteFile(First, "fixture", 7, &Bytes, NULL) && Bytes == 7);
    Owner.Offset = Other.Offset = 1;
    Other.hEvent = Event;
    CHECK(LockFileEx(First, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 3, 0, &Owner));
    CHECK(!LockFileEx(Second, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 3, 0, &Other));
    CHECK(GetLastError() == ERROR_LOCK_VIOLATION);
    Offset.QuadPart = 1; Length.QuadPart = 3;
    Io.Status = (ULONG_PTR)-1; Io.Information = 0;
    Io.Guard[0] = 0x12345678; Io.Guard[1] = 0xabcdef01;
    ResetEvent(Event);
    /* --pending isolates the shared FsRtlProcessFileLock debug assertion on
     * a queued conflict. The ordinary MSI path fails conflicts immediately. */
    if (argc <= 1) CHECK(UnlockFileEx(First, 0, 3, 0, &Owner));
    Status = NtLock(Second, Event, NULL, NULL, &Io, &Offset, &Length, 0, argc <= 1, TRUE);
    CHECK(argc > 1 ? Status == 0x103 : Status == 0 || Status == 0x103);
    if (Status == 0 || Status == 0x103)
    {
        if (argc > 1)
        {
            CHECK(WaitForSingleObject(Event, 0) == WAIT_TIMEOUT);
            CHECK(UnlockFileEx(First, 0, 3, 0, &Owner));
        }
        CHECK(WaitForSingleObject(Event, 10000) == WAIT_OBJECT_0);
        printf("LOCK IOSB: status=%lx information=%Ix\n", (ULONG)Io.Status, Io.Information);
        /* Native FastIoLock does not define Information on this filesystem. */
        CHECK(Io.Status == 0);
        CHECK(Io.Guard[0] == 0x12345678 && Io.Guard[1] == 0xabcdef01);
        CHECK(UnlockFileEx(Second, 0, 3, 0, &Other));
    }
    else if (argc > 1) UnlockFileEx(First, 0, 3, 0, &Owner);
    /* A bad guest output must be rejected before acquiring the lock. */
    Status = NtLock(Second, NULL, NULL, NULL, (PVOID)1, &Offset, &Length, 0, TRUE, TRUE);
    CHECK(Status < 0);
    CHECK(LockFileEx(First, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 3, 0, &Owner));
    CHECK(UnlockFileEx(First, 0, 3, 0, &Owner));
done:
    if (Event) CloseHandle(Event);
    if (Second != INVALID_HANDLE_VALUE) CloseHandle(Second);
    if (First != INVALID_HANDLE_VALUE) CloseHandle(First);
    CHECK(DeleteFileW(Path));
    printf("FILE LOCK: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
