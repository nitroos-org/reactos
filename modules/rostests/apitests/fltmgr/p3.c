/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the filter manager for the IRQL, teardown and port rules of the WDK which need
 *              a file system the tests control (fltfakefs) or a filter which breaks a rule on purpose
 */

#include "precomp.h"
#include "fltfakefs.h"

#define FAKE_SERVICE    L"FltFakeFs"

#ifndef FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT
#define FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT 0x00000008
#endif

static HANDLE FakeControl = INVALID_HANDLE_VALUE;

/* The fake file system: loaded once, it stays until the next boot */
static
BOOL
LoadFakeFs(void)
{
    SC_HANDLE Manager, Service;
    WCHAR Image[MAX_PATH];
    PWCHAR Slash;
    BOOL Ret;

    if (FakeControl != INVALID_HANDLE_VALUE)
        return TRUE;

    GetModuleFileNameW(NULL, Image, RTL_NUMBER_OF(Image));
    Slash = wcsrchr(Image, L'\\');
    if (!Slash)
        return FALSE;
    Slash[1] = UNICODE_NULL;
    StringCbCatW(Image, sizeof(Image), L"fltfakefs.sys");

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Manager)
        return FALSE;
    Service = CreateServiceW(Manager, FAKE_SERVICE, FAKE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, Image, NULL, NULL, NULL, NULL, NULL);
    if (!Service && GetLastError() == ERROR_SERVICE_EXISTS)
        Service = OpenServiceW(Manager, FAKE_SERVICE, SERVICE_ALL_ACCESS);
    CloseServiceHandle(Manager);
    if (!Service)
        return FALSE;
    Ret = StartServiceW(Service, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    if (!Ret)
        trace("Can't start the fake file system: %lu\n", GetLastError());
    CloseServiceHandle(Service);
    if (!Ret)
        return FALSE;

    FakeControl = CreateFileW(L"\\\\.\\FltFakeFsCtl", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return FakeControl != INVALID_HANDLE_VALUE;
}

static
BOOL
FakeStats(PFLTFAKEFS_STATS Stats)
{
    DWORD Bytes;

    ZeroMemory(Stats, sizeof(*Stats));
    return DeviceIoControl(FakeControl, FLTFAKEFS_IOCTL_GET_STATS, NULL, 0, Stats, sizeof(*Stats), &Bytes, NULL);
}

/* Opens a file of the fake volume, which the first open mounts */
static
NTSTATUS
OpenFake(PCWSTR Name, PHANDLE Handle)
{
    WCHAR Buffer[MAX_PATH];
    UNICODE_STRING Path;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;

    StringCbPrintfW(Buffer, sizeof(Buffer), L"%ls\\fltmgr_test\\%ls", FLTFAKEFS_DISK_NAME, Name);
    RtlInitUnicodeString(&Path, Buffer);
    InitializeObjectAttributes(&Attributes, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    *Handle = NULL;
    return NtCreateFile(Handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/*
 * A file system which completes a create at DISPATCH_LEVEL, from a DPC: the post-create of a filter
 * runs at PASSIVE_LEVEL in the thread of the create all the same, and so does the record the filter
 * manager keeps of the open (stream contexts), which takes a fast mutex.
 */
static
void
test_CreateCompletedAtDispatch(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    FLTFAKEFS_STATS F0, F1;
    HANDLE File;
    NTSTATUS Status;
    ULONG i;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    FakeStats(&F0);

    for (i = 0; i < 20; i++)
    {
        Status = OpenFake(i & 1 ? L"create.dat" : L"create.dpc", &File);
        ok(Status == STATUS_SUCCESS, "Open %lu: 0x%lx\n", i, Status);
        if (NT_SUCCESS(Status))
            NtClose(File);
    }

    FakeStats(&F1);
    SampleStats(&P, &S);
    ok(F1.DpcCompletions - F0.DpcCompletions >= 10, "%lu creates completed from a DPC\n", F1.DpcCompletions - F0.DpcCompletions);
    ok(S.CreatePosts >= 20, "%lu post-creates seen\n", S.CreatePosts);
    ok(S.CreatePostNotPassive == 0, "%lu post-creates above PASSIVE_LEVEL\n", S.CreatePostNotPassive);
    ok(S.CreatePostOtherThread == 0, "%lu post-creates in another thread\n", S.CreatePostOtherThread);
    ok(S.Contexts[FLTSAMPLE_CTX_STREAM_NEW] + S.Contexts[FLTSAMPLE_CTX_STREAM_HITS] >= 20,
       "Stream contexts on the fake volume: %lu new, %lu found\n",
       S.Contexts[FLTSAMPLE_CTX_STREAM_NEW], S.Contexts[FLTSAMPLE_CTX_STREAM_HITS]);

    UnloadSample(&P, TRUE);
}

/*
 * The file system deletes the device of a volume which is gone, without a dismount (the medium went
 * away): the instances on it are torn down and the volume leaves the filter manager's list. A new
 * mount of the disk is a new volume, with new instances.
 */
static
void
test_VolumeDeviceDeleted(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S0, S;
    FLTFAKEFS_STATS F0, F;
    HANDLE File;
    NTSTATUS Status;
    DWORD Bytes;
    ULONG i;
    BOOL Ret = FALSE;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    /* Mounted, with an instance on it */
    Status = OpenFake(L"gone.dat", &File);
    ok(Status == STATUS_SUCCESS, "Open: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(File);
    FakeStats(&F0);
    SampleStats(&P, &S0);
    ok(F0.Mounted, "The fake volume isn't mounted\n");

    for (i = 0; i < 50 && !Ret; i++)
    {
        Ret = DeviceIoControl(FakeControl, FLTFAKEFS_IOCTL_DELETE_VOLUME, NULL, 0, NULL, 0, &Bytes, NULL);
        if (!Ret)
            Sleep(100);
    }
    ok(Ret, "The fake file system didn't delete its volume: %lu\n", GetLastError());

    /* The teardown runs in a worker */
    for (i = 0; i < 100; i++)
    {
        SampleStats(&P, &S);
        if (S.InstanceTeardownCompletes > S0.InstanceTeardownCompletes && S.VolumeCount < S0.VolumeCount)
            break;
        Sleep(50);
    }
    ok(S.InstanceTeardownCompletes == S0.InstanceTeardownCompletes + 1,
       "Teardowns: %lu before, %lu after\n", S0.InstanceTeardownCompletes, S.InstanceTeardownCompletes);
    ok(S.LastTeardownReason == FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT, "Teardown reason %lu\n", S.LastTeardownReason);
    ok(S.VolumeCount == S0.VolumeCount - 1, "Volumes: %lu before, %lu after\n", S0.VolumeCount, S.VolumeCount);
    ok(S.LiveInstances == S0.LiveInstances - 1, "Live instances: %lu before, %lu after\n", S0.LiveInstances, S.LiveInstances);

    /* Mounted again: a new volume and a new instance */
    Status = OpenFake(L"gone.dat", &File);
    ok(Status == STATUS_SUCCESS, "Open after the delete: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
        NtClose(File);
    FakeStats(&F);
    SampleStats(&P, &S);
    ok(F.Mounts == F0.Mounts + 1, "Mounts: %lu before, %lu after\n", F0.Mounts, F.Mounts);
    ok(S.VolumeCount == S0.VolumeCount, "Volumes: %lu before, %lu after the new mount\n", S0.VolumeCount, S.VolumeCount);
    ok(S.LiveInstances == S0.LiveInstances, "Live instances: %lu before, %lu after the new mount\n",
       S0.LiveInstances, S.LiveInstances);

    UnloadSample(&P, TRUE);
}

START_TEST(p3voldel)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }
    if (!LoadFakeFs())
    {
        skip("No fake file system\n");
        return;
    }

    test_VolumeDeviceDeleted();
}

/* Writes Size bytes of a pattern, not cached: the data isn't in the cache afterwards */
static
BOOL
WriteUncached(PCWSTR Path, DWORD Size)
{
    HANDLE File;
    PUCHAR Buffer;
    DWORD Written = 0, i;

    DeleteFileW(Path);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Buffer = VirtualAlloc(NULL, Size, MEM_COMMIT, PAGE_READWRITE);
    if (Buffer)
    {
        for (i = 0; i < Size; i++)
            Buffer[i] = (UCHAR)(i * 7 + 3);
        WriteFile(File, Buffer, Size, &Written, NULL);
        VirtualFree(Buffer, 0, MEM_RELEASE);
    }
    CloseHandle(File);
    return Written == Size;
}

/*
 * FltDoCompletionProcessingWhenSafe and paging I/O: the WDK says it can't post paging I/O to a worker.
 * Below DISPATCH_LEVEL the callback runs at once, at DISPATCH_LEVEL the call returns FALSE. Paging reads
 * come from a cached read (the cache manager) and from a mapped view.
 */
static
void
test_SafePagingRead(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH], Path2[MAX_PATH];
    HANDLE File, Section;
    PUCHAR Buffer, View;
    DWORD Read = 0, i;
    ULONG Sum = 0;

    MakeTestFile(L"p3paging.safe", Path, RTL_NUMBER_OF(Path));
    MakeTestFile(L"p3paging2.safe", Path2, RTL_NUMBER_OF(Path2));
    ok(WriteUncached(Path, 65536 * 2), "Can't write %ls\n", Path);
    ok(WriteUncached(Path2, 65536 * 2), "Can't write %ls\n", Path2);
    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    /* A cached read: the cache manager reads the pages in */
    Buffer = VirtualAlloc(NULL, 65536 * 2, MEM_COMMIT, PAGE_READWRITE);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE && Buffer)
    {
        ok(ReadFile(File, Buffer, 65536 * 2, &Read, NULL) && Read == 65536 * 2, "Cached read: %lu bytes, %lu\n",
           Read, GetLastError());
        ok(Buffer[4097] == (UCHAR)(4097 * 7 + 3), "Wrong data read\n");
        CloseHandle(File);
    }

    /* A mapped view: the memory manager reads the pages in */
    File = CreateFileW(Path2, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        Section = CreateFileMappingW(File, NULL, PAGE_READONLY, 0, 0, NULL);
        ok(Section != NULL, "CreateFileMapping failed: %lu\n", GetLastError());
        if (Section)
        {
            View = MapViewOfFile(Section, FILE_MAP_READ, 0, 0, 0);
            ok(View != NULL, "MapViewOfFile failed: %lu\n", GetLastError());
            if (View)
            {
                for (i = 0; i < 65536 * 2; i += 4096)
                    Sum += View[i + 5];
                ok(View[8197] == (UCHAR)(8197 * 7 + 3), "Wrong data in the view\n");
                UnmapViewOfFile(View);
            }
            CloseHandle(Section);
        }
        CloseHandle(File);
    }

    SampleStats(&P, &S);
    trace("Paging reads through FltDoCompletionProcessingWhenSafe: %lu, posted %lu, refused %lu (sum %lu)\n",
          S.SafePagingCalls, S.SafePagingPosted, S.SafePagingRefused, Sum);
    ok(S.SafePagingCalls > 0, "No paging read of a .safe file was seen, the test says nothing\n");
    ok(S.SafePagingPosted == 0, "%lu paging reads were posted to a worker\n", S.SafePagingPosted);

    if (Buffer)
        VirtualFree(Buffer, 0, MEM_RELEASE);
    UnloadSample(&P, TRUE);
    DeleteFileW(Path);
    DeleteFileW(Path2);
}

START_TEST(p3safe)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_SafePagingRead();
}

START_TEST(p3create)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }
    if (!LoadFakeFs())
    {
        skip("No fake file system\n");
        return;
    }

    test_CreateCompletedAtDispatch();
}
