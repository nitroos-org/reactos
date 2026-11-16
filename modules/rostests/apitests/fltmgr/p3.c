/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the filter manager for the IRQL, teardown and port rules of the WDK which need
 *              a file system the tests control (fltfakefs) or a filter which breaks a rule on purpose
 */

#include "precomp.h"
#include <stdlib.h>
#include <fltuser.h>
#include "fltfakefs.h"

#ifndef STATUS_PORT_DISCONNECTED
#define STATUS_PORT_DISCONNECTED ((NTSTATUS)0xC0000037L)
#endif

#define FAKE_SERVICE    L"FltFakeFs"

#ifndef FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT
#define FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT 0x00000008
#define FLTFL_INSTANCE_TEARDOWN_INTERNAL_ERROR  0x00000010
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

static void test_DeletedVolumeHeld(void);
static void test_VolumeDeleteRounds(void);

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
    test_DeletedVolumeHeld();
    test_VolumeDeleteRounds();
}

/* Writes Size bytes of a pattern, not cached: the data isn't in the cache afterwards */
static
BOOL
WriteUncached(PCWSTR Path, DWORD Size)
{
    HANDLE File;
    PUCHAR Buffer;
    DWORD Written = 0, Done = 0, Chunk, i;

    DeleteFileW(Path);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    /* In pieces of at most 1 MB: one uncached write of a big file is more than an MDL can describe */
    Buffer = VirtualAlloc(NULL, min(Size, 1024 * 1024), MEM_COMMIT, PAGE_READWRITE);
    if (Buffer)
    {
        while (Done < Size)
        {
            Chunk = min(Size - Done, 1024 * 1024);
            for (i = 0; i < Chunk; i++)
                Buffer[i] = (UCHAR)((Done + i) * 7 + 3);
            if (!WriteFile(File, Buffer, Chunk, &Written, NULL) || Written != Chunk)
                break;
            Done += Chunk;
        }
        VirtualFree(Buffer, 0, MEM_RELEASE);
    }
    CloseHandle(File);
    return Done == Size;
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

/*
 * A filter which returns FLT_POSTOP_MORE_PROCESSING_REQUIRED from the post-operation of a fast I/O read
 * (the WDK forbids it) and calls FltCompletePendedPostOperation from a worker later: the callback data
 * must still be there then. The filter manager waits for that call before the read returns.
 */
static
void
test_FastIoParkedPost(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File;
    UCHAR Buffer[4096];
    DWORD Read, i, Early = 0;
    ULONG Flags;

    MakeTestFile(L"p3fpark.dat", Path, RTL_NUMBER_OF(Path));
    ok(WriteUncached(Path, 65536), "Can't write %ls\n", Path);
    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        goto Quit;

    /* The first read sets up the cache, the next ones can be fast I/O */
    ok(ReadFile(File, Buffer, sizeof(Buffer), &Read, NULL), "Read failed: %lu\n", GetLastError());

    Flags = FLTSAMPLE_RV_PARK_FASTIO_POST;
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0), "Can't set the flags\n");
    for (i = 0; i < 32; i++)
    {
        SetFilePointer(File, (i % 16) * 4096, NULL, FILE_BEGIN);
        ok(ReadFile(File, Buffer, sizeof(Buffer), &Read, NULL) && Read == sizeof(Buffer), "Read %lu failed: %lu\n",
           i, GetLastError());
        ok(Buffer[5] == (UCHAR)(((i % 16) * 4096 + 5) * 7 + 3), "Read %lu: wrong data\n", i);

        /* Every parked post-operation was finished before the read returned */
        SampleStats(&P, &S);
        if (S.RvParkDone != S.RvParked)
            Early++;
    }
    Flags = 0;
    SampleIoctl(&P, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0);
    CloseHandle(File);

    SampleStats(&P, &S);
    trace("Fast I/O post-operations parked %lu, finished by the filter %lu\n", S.RvParked, S.RvParkDone);
    ok(S.RvParked > 0, "No fast I/O read was parked, the test says nothing\n");
    ok(Early == 0, "%lu reads returned before the filter finished their post-operation\n", Early);

Quit:
    UnloadSample(&P, TRUE);
    DeleteFileW(Path);
}

START_TEST(p3fpark)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_FastIoParkedPost();
}

/* Can a section (file mapping) be made for the file? Returns the error, 0 for yes */
static
DWORD
MapError(PCWSTR Path)
{
    HANDLE File, Section;
    DWORD Error = 0;

    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return GetLastError() | 0x80000000;
    Section = CreateFileMappingW(File, NULL, PAGE_READONLY, 0, 0, NULL);
    if (Section)
        CloseHandle(Section);
    else
        Error = GetLastError();
    CloseHandle(File);
    return Error;
}

/*
 * IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: a filter registered for it sees every section created
 * for a file of its volume, and can refuse it (what anti-virus filters do to keep a file from being
 * executed). The sample refuses the sections of .nosec files.
 */
static
void
test_SectionSync(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH], Path2[MAX_PATH];
    DWORD Error;

    MakeTestFile(L"p3section.nosec", Path, RTL_NUMBER_OF(Path));
    MakeTestFile(L"p3section.dat", Path2, RTL_NUMBER_OF(Path2));
    ok(WriteUncached(Path, 4096), "Can't write %ls\n", Path);
    ok(WriteUncached(Path2, 4096), "Can't write %ls\n", Path2);

    /* Without the filter both can be mapped */
    ok(MapError(Path) == 0, "Mapping %ls without the filter: %lu\n", Path, MapError(Path));

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    Error = MapError(Path);
    ok(Error == ERROR_ACCESS_DENIED, "Mapping %ls: %lu, expected ERROR_ACCESS_DENIED\n", Path, Error);
    Error = MapError(Path2);
    ok(Error == 0, "Mapping %ls: %lu\n", Path2, Error);

    SampleStats(&P, &S);
    trace("Section synchronization: %lu pre, %lu post, %lu refused\n", S.SectionSyncPre, S.SectionSyncPost, S.SectionSyncDenied);
    ok(S.SectionSyncPre >= 2, "%lu pre-operations\n", S.SectionSyncPre);
    ok(S.SectionSyncDenied >= 1, "%lu refused\n", S.SectionSyncDenied);
    ok(S.SectionSyncPost >= 1, "%lu post-operations\n", S.SectionSyncPost);
    ok(S.SectionSyncBadData == 0, "%lu without FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION\n", S.SectionSyncBadData);

    UnloadSample(&P, TRUE);

    /* And without the filter again */
    ok(MapError(Path) == 0, "Mapping %ls after the filter: %lu\n", Path, MapError(Path));
    DeleteFileW(Path);
    DeleteFileW(Path2);
}

#define TEST_STATUS_FILE_LOCKED_WITH_ONLY_READERS   0x0000012AL
#define TEST_STATUS_FILE_LOCKED_WITH_WRITERS        0x0000012BL

/* Until the acquires of an FsFilter operation have their releases (the lazy writer may be between them) */
static
void
WaitBalanced(PSAMPLE Sample, PFLTSAMPLE_STATS Stats, ULONG Acquire, ULONG Release)
{
    ULONG i;

    for (i = 0; i < 50; i++)
    {
        SampleStats(Sample, Stats);
        if (Stats->FsFilterPost[Acquire] - Stats->FsFilterFailed[Acquire] == Stats->FsFilterPre[Release] &&
            Stats->FsFilterPre[Release] == Stats->FsFilterPost[Release])
        {
            break;
        }
        Sleep(100);
    }
}

/*
 * The release of a section synchronization and the cache flush's acquire and release (FsRtl calls the
 * FsFilter callbacks of every driver in the file system's stack for them): a section created for a .fsf
 * file, a view of it written and flushed. And below the filter manager the file system's own callback
 * for a section's acquire (fastfat has one) is reached: the post-operation sees its status.
 */
static
void
test_FsFilterOperations(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File, Section;
    PUCHAR View = NULL;
    ULONG i;

    MakeTestFile(L"p3section.fsf", Path, RTL_NUMBER_OF(Path));
    ok(WriteUncached(Path, 65536), "Can't write %ls\n", Path);

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Can't open %ls: %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE)
    {
        UnloadSample(&P, TRUE);
        return;
    }
    Section = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
    ok(Section != NULL, "CreateFileMapping failed: %lu\n", GetLastError());
    if (Section)
    {
        View = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
        ok(View != NULL, "MapViewOfFile failed: %lu\n", GetLastError());
    }
    if (View)
    {
        for (i = 0; i < 65536; i += 4096)
            View[i + 7] = (UCHAR)(i >> 12) + 1;
        ok(FlushViewOfFile(View, 0), "FlushViewOfFile failed: %lu\n", GetLastError());
        UnmapViewOfFile(View);
    }
    if (Section)
        CloseHandle(Section);
    ok(FlushFileBuffers(File), "FlushFileBuffers failed: %lu\n", GetLastError());

    WaitBalanced(&P, &S, FLTSAMPLE_FSF_ACQUIRE_CCFLUSH, FLTSAMPLE_FSF_RELEASE_CCFLUSH);
    trace("FsFilter: section %lu/%lu (release %lu/%lu), cache flush acquire %lu/%lu release %lu/%lu, last section status 0x%lx\n",
          S.SectionSyncPre, S.SectionSyncPost,
          S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_SECTION], S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_SECTION],
          S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH], S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH],
          S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH], S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_CCFLUSH],
          S.LastSectionSyncPostStatus);

    /* The section: acquired and released */
    ok(S.SectionSyncPre >= 1 && S.SectionSyncPost >= 1, "section acquire: %lu pre, %lu post\n", S.SectionSyncPre, S.SectionSyncPost);
    ok(S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_SECTION] >= 1, "%lu section release pre-operations\n",
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_SECTION]);
    ok(S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_SECTION] == S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_SECTION],
       "section release: %lu post for %lu pre\n", S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_SECTION],
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_SECTION]);

    /* The cache flush of the view: acquired and released */
    ok(S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH] >= 1, "%lu cache flush acquire pre-operations\n",
       S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH]);
    ok(S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH] == S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH],
       "cache flush acquire: %lu post for %lu pre\n", S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH],
       S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH]);
    ok(S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH] >= 1, "%lu cache flush release pre-operations\n",
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH]);
    ok(S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH] ==
       S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH] - S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH],
       "cache flush: %lu releases for %lu acquires (%lu failed)\n", S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH],
       S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH], S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH]);
    ok(S.FsFilterOtherThread == 0, "%lu post-operations in another thread\n", S.FsFilterOtherThread);
    ok(S.SectionSyncBadData == 0, "%lu without FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION\n", S.SectionSyncBadData);

    /* The file system below: fastfat acquires the file itself and says who can write it */
    if (CurrentFileSystem() == FLTAPI_FSTYPE_FAT)
    {
        ok(S.LastSectionSyncPostStatus == TEST_STATUS_FILE_LOCKED_WITH_ONLY_READERS ||
           S.LastSectionSyncPostStatus == TEST_STATUS_FILE_LOCKED_WITH_WRITERS,
           "fastfat's section callback not reached: post-operation status 0x%lx\n", S.LastSectionSyncPostStatus);
    }
    else
    {
        ok(S.LastSectionSyncPostStatus == 0, "post-operation status 0x%lx\n", S.LastSectionSyncPostStatus);
    }

    /* The data is there */
    if (View)
    {
        UCHAR Byte = 0;
        DWORD Read = 0;
        LARGE_INTEGER Offset;

        Offset.QuadPart = 4096 * 3 + 7;
        SetFilePointerEx(File, Offset, NULL, FILE_BEGIN);
        ok(ReadFile(File, &Byte, 1, &Read, NULL) && Read == 1 && Byte == 4, "read back %u (%lu bytes)\n", Byte, Read);
    }

    CloseHandle(File);
    UnloadSample(&P, TRUE);
    DeleteFileW(Path);
}

/*
 * The modified page writer: the dirty pages of a mapped .fsf file, written to the file when memory
 * runs short, each under an acquire / release for the modified page writer, which the filter sees.
 * The pressure comes from committing and touching more private memory than the machine has; if no page
 * of the file was written by the modified page writer in the time, the test says so (skip).
 */
static
void
test_ModifiedPageWriter(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File, Section;
    PUCHAR View = NULL;
    MEMORYSTATUSEX Memory;
    PVOID Chunks[256];
    ULONG Count = 0, i;
    SIZE_T FileSize = 16 * 1024 * 1024, Chunk = 32 * 1024 * 1024, j;
    ULONGLONG Target, Total = 0;
    DWORD Start;

    /* The dirty pages of the file are part of the pressure (where the commit limit stops the private memory early) */
    Memory.dwLength = sizeof(Memory);
    GlobalMemoryStatusEx(&Memory);
    if (Memory.ullTotalPhys / 4 > FileSize)
        FileSize = (SIZE_T)min(Memory.ullTotalPhys / 4, 256 * 1024 * 1024) & ~(SIZE_T)(1024 * 1024 - 1);

    MakeTestFile(L"p3modwr.fsf", Path, RTL_NUMBER_OF(Path));
    ok(WriteUncached(Path, (DWORD)FileSize), "Can't write %ls\n", Path);

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Can't open %ls: %lu\n", Path, GetLastError());
    Section = File != INVALID_HANDLE_VALUE ? CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL) : NULL;
    if (Section)
        View = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
    ok(View != NULL, "Can't map %ls: %lu\n", Path, GetLastError());
    if (View == NULL)
    {
        if (Section)
            CloseHandle(Section);
        if (File != INVALID_HANDLE_VALUE)
            CloseHandle(File);
        UnloadSample(&P, TRUE);
        DeleteFileW(Path);
        return;
    }
    for (j = 0; j < FileSize; j += 4096)
        View[j] = (UCHAR)(j >> 12) | 1;

    Memory.dwLength = sizeof(Memory);
    GlobalMemoryStatusEx(&Memory);
    Target = Memory.ullTotalPhys + Memory.ullTotalPhys / 2;
    Start = GetTickCount();
    while (Total < Target && Count < RTL_NUMBER_OF(Chunks) && GetTickCount() - Start < 180000)
    {
        PUCHAR Block = VirtualAlloc(NULL, Chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (Block == NULL)
        {
            /* Out of commit or address space: keep touching what we have, page by page again */
            if (Count == 0)
                break;
            Block = Chunks[(GetTickCount() / 1000) % Count];
            for (j = 0; j < Chunk; j += 4096)
                Block[j]++;
        }
        else
        {
            Chunks[Count++] = Block;
            for (j = 0; j < Chunk; j += 4096)
                Block[j] = 1;
            Total += Chunk;
        }
        SampleStats(&P, &S);
        if (S.ModWriterWrites > 0 && S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE] > 0)
            break;
    }
    for (i = 0; i < Count; i++)
        VirtualFree(Chunks[i], 0, MEM_RELEASE);

    WaitBalanced(&P, &S, FLTSAMPLE_FSF_ACQUIRE_MODWRITE, FLTSAMPLE_FSF_RELEASE_MODWRITE);
    trace("Modified page writer: %lu writes, acquire %lu/%lu (%lu failed), release %lu/%lu; %I64u MB committed in %lu ms\n",
          S.ModWriterWrites, S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_MODWRITE], S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_MODWRITE],
          S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_MODWRITE], S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE],
          S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_MODWRITE], Total >> 20, GetTickCount() - Start);

    if (S.ModWriterWrites == 0)
    {
        skip("No page of the file was written by the modified page writer\n");
    }
    else
    {
        ok(S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_MODWRITE] >= S.ModWriterWrites,
           "%lu modified page writer acquires for %lu writes\n", S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_MODWRITE], S.ModWriterWrites);
        ok(S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_MODWRITE] == S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_MODWRITE],
           "acquire: %lu post for %lu pre\n", S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_MODWRITE], S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_MODWRITE]);
        ok(S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE] >= 1, "%lu modified page writer releases\n",
           S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE]);
        ok(S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_MODWRITE] == S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE],
           "release: %lu post for %lu pre\n", S.FsFilterPost[FLTSAMPLE_FSF_RELEASE_MODWRITE], S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE]);
        ok(S.FsFilterOtherThread == 0, "%lu post-operations in another thread\n", S.FsFilterOtherThread);
    }

    /* What was written comes back */
    for (j = 0; j < FileSize; j += 4096)
    {
        if (View[j] != ((UCHAR)(j >> 12) | 1))
            break;
    }
    ok(j == FileSize, "View differs at 0x%Ix: 0x%x, expected 0x%x (written by WriteUncached: 0x%x)\n", j,
       j < FileSize ? View[j] : 0, (UCHAR)(j >> 12) | 1, (UCHAR)(j * 7 + 3));
    if (j < FileSize)
    {
        SIZE_T Bad = 0;

        for (; j < FileSize; j += 4096)
        {
            if (View[j] != ((UCHAR)(j >> 12) | 1))
                Bad++;
        }
        trace("%lu of %lu pages differ\n", (ULONG)Bad, (ULONG)(FileSize / 4096));
    }

    UnmapViewOfFile(View);
    CloseHandle(Section);
    CloseHandle(File);
    UnloadSample(&P, TRUE);
    DeleteFileW(Path);
}

START_TEST(p3section)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_SectionSync();
    test_FsFilterOperations();
    test_ModifiedPageWriter();
}

typedef struct _ASK_THREAD
{
    HANDLE Port;
    HRESULT Result;
    DWORD Bytes;
    FLTSAMPLE_ASK_RESULT Ask;

} ASK_THREAD;

/* The client asks the filter to ask it something, waiting for ever for the answer, which never comes */
static
DWORD
WINAPI
AskForeverThread(PVOID Parameter)
{
    ASK_THREAD *T = Parameter;
    UCHAR Buffer[64];
    PFLTSAMPLE_MSG Message = (PFLTSAMPLE_MSG)Buffer;

    Message->Code = FLTSAMPLE_MSG_ASK;
    Message->Arg = 16;
    *(PULONG)Message->Data = 0;
    T->Result = FilterSendMessage(T->Port, Message, FIELD_OFFSET(FLTSAMPLE_MSG, Data) + sizeof(ULONG),
                                  &T->Ask, sizeof(T->Ask), &T->Bytes);
    return 0;
}

static
DWORD
WINAPI
CloseClientThread(PVOID Parameter)
{
    return SampleIoctl(Parameter, FLTSAMPLE_IOCTL_CLOSE_CLIENT, NULL, 0, NULL, 0) ? 0 : 1;
}

/*
 * FltSendMessage with no timeout to a client which doesn't answer, and the filter closes its client port
 * meanwhile (from another thread: its unload, a service stop, the DisconnectNotify of another client):
 * FltCloseClientPort doesn't wait for the answer, it disconnects the port, which ends the send.
 */
static
void
test_ClosePortWhileSending(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    ASK_THREAD T = { 0 };
    HANDLE Ask, Close;
    HRESULT hr;
    DWORD Wait;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    T.Port = INVALID_HANDLE_VALUE;
    hr = FilterConnectCommunicationPort(L"\\FltSamplePPort", 0, NULL, 0, NULL, &T.Port);
    ok(SUCCEEDED(hr), "Connect failed: 0x%lx\n", (ULONG)hr);
    if (FAILED(hr))
        goto Quit;

    T.Result = E_PENDING;
    Ask = CreateThread(NULL, 0, AskForeverThread, &T, 0, NULL);
    /* Until the filter's message is waiting for us */
    for (Wait = 0; Wait < 100; Wait++)
    {
        SampleStats(&P, &S);
        if (S.PortMessages > 0)
            break;
        Sleep(20);
    }
    Sleep(200);
    ok(T.Result == E_PENDING, "The ask returned already: 0x%lx\n", (ULONG)T.Result);

    Close = CreateThread(NULL, 0, CloseClientThread, &P, 0, NULL);
    Wait = WaitForSingleObject(Close, 10000);
    ok(Wait == WAIT_OBJECT_0, "FltCloseClientPort still waits after 10 s for an answer that never comes\n");
    Wait = WaitForSingleObject(Ask, 10000);
    ok(Wait == WAIT_OBJECT_0, "The send to the closed port still waits\n");
    if (Wait == WAIT_OBJECT_0)
    {
        ok(SUCCEEDED(T.Result), "FilterSendMessage: 0x%lx\n", (ULONG)T.Result);
        ok(T.Ask.Status == STATUS_PORT_DISCONNECTED, "FltSendMessage returned 0x%lx\n", T.Ask.Status);
    }

    /* Whatever happened above, this ends it: the client's own disconnect wakes the send */
    CloseHandle(T.Port);
    WaitForSingleObject(Ask, 10000);
    WaitForSingleObject(Close, 10000);
    CloseHandle(Ask);
    CloseHandle(Close);
Quit:
    UnloadSample(&P, TRUE);
}

START_TEST(p3port)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_ClosePortWhileSending();
}

/*
 * An instance whose InstanceSetup said yes but which can't be attached after all (here: the filter
 * attached another instance of the same name to the volume from inside the setup; also when the
 * filter is being unloaded meanwhile) gets its teardown callbacks: every successful setup is paired
 * with an InstanceTeardownComplete, where filters free what they set up for the instance.
 */
static
void
test_TeardownAfterRefusedAttach(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S0, S1, S2;
    ATTACH_RESULT Result;
    ULONG Flags;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result)), "Detach failed\n");
    SampleStats(&P, &S0);
    ok(S0.LiveInstances == 0, "%lu instances left after the detach\n", S0.LiveInstances);

    Flags = FLTSAMPLE_RV_NESTED_ATTACH;
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0), "Can't set the flags\n");
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_ATTACH_ALL, NULL, 0, &Result, sizeof(Result)), "Attach failed\n");
    trace("Attach: %lu done, %lu failed, last status 0x%lx\n", Result.Done, Result.Failed, Result.LastStatus);
    ok(Result.Failed > 0, "No attach was refused, the test says nothing\n");
    Flags = 0;
    SampleIoctl(&P, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0);
    SampleStats(&P, &S1);

    /* The nested instances are attached, the refused ones are torn down already */
    ok(S1.LiveInstances == Result.Failed, "%lu live instances for %lu volumes\n", S1.LiveInstances, Result.Failed);
    ok(S1.InstanceSetups - S0.InstanceSetups == 2 * Result.Failed, "%lu setups\n", S1.InstanceSetups - S0.InstanceSetups);
    ok(S1.InstanceTeardownCompletes - S0.InstanceTeardownCompletes == Result.Failed, "%lu teardowns for %lu refused\n",
       S1.InstanceTeardownCompletes - S0.InstanceTeardownCompletes, Result.Failed);
    ok(S1.LastTeardownReason == FLTFL_INSTANCE_TEARDOWN_INTERNAL_ERROR, "Teardown reason %lu\n", S1.LastTeardownReason);

    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result)), "Detach failed\n");
    SampleStats(&P, &S2);
    ok(S2.LiveInstances == 0, "%lu instances whose setup was never undone\n", S2.LiveInstances);
    ok(S2.InstanceSetups == S2.InstanceTeardownCompletes, "%lu setups, %lu teardowns\n", S2.InstanceSetups,
       S2.InstanceTeardownCompletes);

    UnloadSample(&P, TRUE);
}

START_TEST(p3refuse)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_TeardownAfterRefusedAttach();
}

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_FLT_CONTEXT_ALREADY_DEFINED
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED ((NTSTATUS)0xC01C0016L)
#endif

static
HANDLE
OpenUncached(PCWSTR Path)
{
    return CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_FLAG_NO_BUFFERING, NULL);
}

/* A read of a .sctx file: the sample tries FltSetStreamContext, the status of that comes back */
static
LONG
SctxRead(PSAMPLE Sample, HANDLE File, PUCHAR Buffer)
{
    FLTSAMPLE_STATS S0, S;
    DWORD Read;

    SampleStats(Sample, &S0);
    SetFilePointer(File, 0, NULL, FILE_BEGIN);
    ok(ReadFile(File, Buffer, 4096, &Read, NULL), "Read failed: %lu\n", GetLastError());
    SampleStats(Sample, &S);
    ok(S.SctxReads == S0.SctxReads + 1, "The filter saw %lu reads\n", S.SctxReads - S0.SctxReads);
    return S.LastSctxStatus;
}

/*
 * Stream contexts only for streams whose opens the filter manager followed (it has to know when the
 * stream's last file object is closed). A file opened before the filter came has none, and its late
 * close ends nothing. When no instance follows the opens any more (the last one is detached), what
 * was recorded goes: a file opened and one closed meanwhile must not leave the stream looking known.
 */
static
void
test_StreamContextRecords(void)
{
    SAMPLE P = { { 0 } };
    WCHAR Path[MAX_PATH];
    HANDLE Early, Late, Before, During;
    PUCHAR Buffer;
    ATTACH_RESULT Result;
    LONG Status;

    MakeTestFile(L"p3stream.sctx", Path, RTL_NUMBER_OF(Path));
    ok(WriteUncached(Path, 65536), "Can't write %ls\n", Path);
    Buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);

    /* Opened before the filter */
    Early = OpenUncached(Path);
    ok(Early != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        CloseHandle(Early);
        return;
    }

    Status = SctxRead(&P, Early, Buffer);
    ok(Status == STATUS_NOT_SUPPORTED, "Stream context on a stream opened before the filter: 0x%lx\n", Status);

    /* A file object whose create was seen: its stream has the context the sample set at the create */
    Late = OpenUncached(Path);
    ok(Late != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    Status = SctxRead(&P, Late, Buffer);
    ok(Status == STATUS_FLT_CONTEXT_ALREADY_DEFINED, "Stream context of a followed stream: 0x%lx\n", Status);

    /* The close of the early file object, whose create wasn't seen, doesn't end the stream */
    CloseHandle(Early);
    Status = SctxRead(&P, Late, Buffer);
    ok(Status == STATUS_FLT_CONTEXT_ALREADY_DEFINED, "After the close of the unseen file object: 0x%lx\n", Status);

    /* Nobody follows the opens: Before stays open, During is opened, Late is closed, all unseen */
    Before = OpenUncached(Path);
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result)), "Detach failed\n");
    During = OpenUncached(Path);
    CloseHandle(Late);
    CloseHandle(Before);
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_ATTACH_ALL, NULL, 0, &Result, sizeof(Result)), "Attach failed\n");

    /* Followed again: During's create wasn't seen, so its stream isn't one we know */
    Status = SctxRead(&P, During, Buffer);
    ok(Status == STATUS_NOT_SUPPORTED, "Stream context on a stream opened while nobody followed: 0x%lx\n", Status);
    CloseHandle(During);

    UnloadSample(&P, TRUE);
    VirtualFree(Buffer, 0, MEM_RELEASE);
    DeleteFileW(Path);
}

START_TEST(p3stream)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_StreamContextRecords();
}

/*
 * A pre-operation pended by the filter and completed from a DPC (FltCompletePendedPreOperation at
 * DISPATCH_LEVEL): the rest of the operation goes on in a worker thread, which must use the address
 * space of the process which sent it. Cached writes: the file system copies from the caller's buffer.
 */
static
void
test_PendCompletedAtDispatch(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File;
    UCHAR Buffer[4096], Check[4096];
    DWORD Bytes, i, j, Bad = 0, Failed = 0;

    MakeTestFile(L"p3pend.pdpc", Path, RTL_NUMBER_OF(Path));
    DeleteFileW(Path);
    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        for (i = 0; i < 16; i++)
        {
            for (j = 0; j < sizeof(Buffer); j++)
                Buffer[j] = (UCHAR)(i * 13 + j * 5 + 1);
            if (!WriteFile(File, Buffer, sizeof(Buffer), &Bytes, NULL) || Bytes != sizeof(Buffer))
                Failed++;
        }
        CloseHandle(File);
    }
    ok(Failed == 0, "%lu writes failed, last error %lu\n", Failed, GetLastError());

    SampleStats(&P, &S);
    trace("Writes pended %lu, completed from a DPC %lu\n", S.PendDpc, S.PendDpcCompleted);
    ok(S.PendDpc >= 16, "%lu writes pended\n", S.PendDpc);
    ok(S.PendDpcCompleted == S.PendDpc, "%lu pended, %lu completed\n", S.PendDpc, S.PendDpcCompleted);
    UnloadSample(&P, TRUE);

    /* What is in the file is what was written */
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        for (i = 0; i < 16; i++)
        {
            ZeroMemory(Check, sizeof(Check));
            if (!ReadFile(File, Check, sizeof(Check), &Bytes, NULL) || Bytes != sizeof(Check))
            {
                Bad++;
                continue;
            }
            for (j = 0; j < sizeof(Check); j++)
            {
                if (Check[j] != (UCHAR)(i * 13 + j * 5 + 1))
                {
                    Bad++;
                    break;
                }
            }
        }
        CloseHandle(File);
    }
    ok(Bad == 0, "%lu of 16 blocks don't hold what was written\n", Bad);
    DeleteFileW(Path);
}

START_TEST(p3pdpc)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_PendCompletedAtDispatch();
}

/*
 * FilterSendMessage: the filter's message callback gets the client's own buffers, which a filter ported
 * from Windows probes (ProbeForRead / ProbeForWrite) and accesses in try/except blocks (WDK,
 * PFLT_MESSAGE_NOTIFY). A filter which says it returned more than it wrote gives the client nothing but
 * the client's own bytes.
 */
static
void
test_MessageBuffers(void)
{
    SAMPLE P = { { 0 } };
    HANDLE Port = INVALID_HANDLE_VALUE;
    HRESULT hr;
    struct { ULONG Code; ULONG Arg; ULONG64 Where[2]; } Message;
    FLTSAMPLE_WHERE_RESULT Where;
    UCHAR Out[256], In[16];
    DWORD Bytes = 0, i, Foreign = 0;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    hr = FilterConnectCommunicationPort(L"\\FltSamplePPort", 0, NULL, 0, NULL, &Port);
    ok(SUCCEEDED(hr), "Connect failed: 0x%lx\n", (ULONG)hr);
    if (FAILED(hr))
        goto Quit;

    C_ASSERT(FIELD_OFFSET(FLTSAMPLE_MSG, Data) == 8);
    ZeroMemory(&Message, sizeof(Message));
    Message.Code = FLTSAMPLE_MSG_WHERE;
    Message.Where[0] = (ULONG64)(ULONG_PTR)&Message;
    Message.Where[1] = (ULONG64)(ULONG_PTR)&Where;
    ZeroMemory(&Where, sizeof(Where));
    hr = FilterSendMessage(Port, &Message, sizeof(Message), &Where, sizeof(Where), &Bytes);
    ok(hr == S_OK, "FilterSendMessage: 0x%lx\n", (ULONG)hr);
    ok(Bytes == sizeof(Where), "%lu bytes back\n", Bytes);
    ok(Where.PreviousModeUser, "The callback didn't run for a user mode caller\n");
    ok(Where.InputIsClients, "The filter didn't get the client's input buffer\n");
    ok(Where.OutputIsClients, "The filter didn't get the client's output buffer\n");
    ok(Where.ProbesOk, "ProbeForRead / ProbeForWrite of the message buffers failed in the filter\n");

    /* Over-reporting: the client's buffer keeps its own bytes */
    ZeroMemory(In, sizeof(In));
    ((PFLTSAMPLE_MSG)In)->Code = FLTSAMPLE_MSG_OVERREPORT;
    memset(In + 8, 'm', sizeof(In) - 8);
    memset(Out, 0xCC, sizeof(Out));
    hr = FilterSendMessage(Port, In, sizeof(In), Out, sizeof(Out), &Bytes);
    ok(hr == S_OK, "FilterSendMessage: 0x%lx\n", (ULONG)hr);
    ok(Bytes == sizeof(Out), "%lu bytes back\n", Bytes);
    for (i = 0; i < sizeof(Out); i++)
    {
        if (Out[i] != 0xCC)
            Foreign++;
    }
    ok(Foreign == 0, "%lu bytes of the output buffer were not the client's own\n", Foreign);

    /* A length without a buffer: the filter doesn't get (NULL, length) */
    {
        FLTSAMPLE_STATS S;

        hr = FilterSendMessage(Port, NULL, 16, NULL, 16, &Bytes);
        trace("FilterSendMessage(NULL, 16, NULL, 16): 0x%lx\n", (ULONG)hr);
        SampleStats(&P, &S);
        ok(S.MsgNullWithLength == 0, "%lu messages reached the filter as a NULL buffer with a length\n", S.MsgNullWithLength);
    }

    CloseHandle(Port);
Quit:
    UnloadSample(&P, TRUE);
}

START_TEST(p3msg)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_MessageBuffers();
}

/*
 * The last reference of a context released at DISPATCH_LEVEL (a post-operation in a completion
 * routine): the cleanup callback runs later in a worker, at IRQL <= APC_LEVEL (WDK, FltReleaseContext).
 */
static
void
test_ContextReleasedAtDispatch(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S0, S;
    HANDLE File;
    NTSTATUS Status;
    IO_STATUS_BLOCK Iosb;
    UCHAR Buffer[512];
    LARGE_INTEGER Offset;
    ULONG i;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    Status = OpenFake(L"ctxrel.dpc", &File);
    ok(Status == STATUS_SUCCESS, "Open: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        goto Quit;

    SampleStats(&P, &S0);
    for (i = 0; i < 20; i++)
    {
        Offset.QuadPart = 0;
        Status = NtReadFile(File, NULL, NULL, NULL, &Iosb, Buffer, sizeof(Buffer), &Offset, NULL);
        ok(Status == STATUS_SUCCESS, "Read %lu: 0x%lx\n", i, Status);
    }
    NtClose(File);

    /* The cleanups run in a worker */
    for (i = 0; i < 100; i++)
    {
        SampleStats(&P, &S);
        if (S.Contexts[FLTSAMPLE_CTX_CLEANED] - S0.Contexts[FLTSAMPLE_CTX_CLEANED] >= 20)
            break;
        Sleep(50);
    }
    trace("Post-reads %lu, at DISPATCH_LEVEL %lu, contexts cleaned %lu\n", S.DpcReadPosts - S0.DpcReadPosts,
          S.DpcReadPostsAtDispatch - S0.DpcReadPostsAtDispatch,
          S.Contexts[FLTSAMPLE_CTX_CLEANED] - S0.Contexts[FLTSAMPLE_CTX_CLEANED]);
    ok(S.DpcReadPostsAtDispatch - S0.DpcReadPostsAtDispatch >= 10, "Only %lu post-reads at DISPATCH_LEVEL, the test says little\n",
       S.DpcReadPostsAtDispatch - S0.DpcReadPostsAtDispatch);
    ok(S.Contexts[FLTSAMPLE_CTX_CLEANED] - S0.Contexts[FLTSAMPLE_CTX_CLEANED] >= 20, "%lu contexts cleaned\n",
       S.Contexts[FLTSAMPLE_CTX_CLEANED] - S0.Contexts[FLTSAMPLE_CTX_CLEANED]);
    ok(S.CleanupAboveApc == 0, "%lu cleanup callbacks above APC_LEVEL\n", S.CleanupAboveApc);

Quit:
    UnloadSample(&P, TRUE);
}

START_TEST(p3ctxdpc)
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

    test_ContextReleasedAtDispatch();
}

/* Pool tags: outstanding allocations (allocs - frees, paged + non-paged) per tag */
typedef struct _TAG_COUNT
{
    ULONG Tag;
    LONG Outstanding;
    SIZE_T Bytes;

} TAG_COUNT;

static
ULONG
SnapshotPoolTags(TAG_COUNT *Tags, ULONG Max)
{
    PSYSTEM_POOLTAG_INFORMATION Info;
    ULONG Size = 1024 * 1024, Count = 0, i;
    NTSTATUS Status;

    Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Info)
        return 0;
    Status = NtQuerySystemInformation(SystemPoolTagInformation, Info, Size, &Size);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Info->Count && Count < Max; i++)
        {
            Tags[Count].Tag = Info->TagInfo[i].TagUlong;
            Tags[Count].Outstanding = (LONG)(Info->TagInfo[i].PagedAllocs - Info->TagInfo[i].PagedFrees) +
                                      (LONG)(Info->TagInfo[i].NonPagedAllocs - Info->TagInfo[i].NonPagedFrees);
            Tags[Count].Bytes = Info->TagInfo[i].PagedUsed + Info->TagInfo[i].NonPagedUsed;
            Count++;
        }
    }
    else
    {
        trace("SystemPoolTagInformation: 0x%lx\n", Status);
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Count;
}

static
const TAG_COUNT *
FindTag(const TAG_COUNT *Tags, ULONG Count, ULONG Tag)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        if (Tags[i].Tag == Tag)
            return &Tags[i];
    }
    return NULL;
}

/* The filter manager's tags ('..MF' in the source: "FM.." in memory) and the sample's */
static
BOOL
IsFilterTag(ULONG Tag)
{
    const UCHAR *c = (const UCHAR *)&Tag;

    return (c[0] == 'F' && c[1] == 'M') || Tag == 'lSlF';
}

/* Mounts the fake volume (an open does it) */
static
BOOL
MountFake(void)
{
    HANDLE File;
    NTSTATUS Status;

    Status = OpenFake(L"round.dat", &File);
    if (NT_SUCCESS(Status))
        NtClose(File);
    return NT_SUCCESS(Status);
}

/* The fake file system deletes its volume device; then the filter manager's worker takes the volume down */
static
BOOL
DeleteFake(PSAMPLE Sample, ULONG VolumesBefore)
{
    FLTSAMPLE_STATS S;
    DWORD Bytes;
    ULONG i;
    BOOL Ret = FALSE;

    for (i = 0; i < 50 && !Ret; i++)
    {
        Ret = DeviceIoControl(FakeControl, FLTFAKEFS_IOCTL_DELETE_VOLUME, NULL, 0, NULL, 0, &Bytes, NULL);
        if (!Ret)
            Sleep(100);
    }
    if (!Ret)
        return FALSE;
    for (i = 0; i < 100; i++)
    {
        SampleStats(Sample, &S);
        if (S.VolumeCount < VolumesBefore)
            return TRUE;
        Sleep(50);
    }
    return FALSE;
}

/*
 * A filter keeps a reference to a volume whose device goes (FltEnumerateVolumes): the volume stays
 * usable for it, and FltGetVolumeProperties / FltGetVolumeName say what they said before, from what the
 * filter manager took when it made the volume, not from the deleted devices.
 */
static
void
test_DeletedVolumeHeld(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S0, S;
    FLTSAMPLE_HELD_VOLUME Held;
    WCHAR Name[] = FLTFAKEFS_DISK_NAME;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    ok(MountFake(), "Can't mount the fake volume\n");
    SampleStats(&P, &S0);
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_HOLD_VOLUME, Name, sizeof(Name) - sizeof(WCHAR), NULL, 0),
       "The filter didn't find %ls: %lu\n", Name, GetLastError());

    ok(DeleteFake(&P, S0.VolumeCount), "The fake volume wasn't taken down\n");

    ZeroMemory(&Held, sizeof(Held));
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_RELEASE_VOLUME, NULL, 0, &Held, sizeof(Held)), "Release: %lu\n", GetLastError());
    trace("Held volume: before 0x%lx type %lu flags 0x%lx sector %lu '%ls' '%ls'; after 0x%lx type %lu flags 0x%lx sector %lu '%ls' '%ls'\n",
          Held.Before.Status, Held.Before.DeviceType, Held.Before.DeviceObjectFlags, Held.Before.SectorSize,
          Held.Before.DriverName, Held.Before.VolumeName,
          Held.After.Status, Held.After.DeviceType, Held.After.DeviceObjectFlags, Held.After.SectorSize,
          Held.After.DriverName, Held.After.VolumeName);
    ok(Held.Held == 1, "No volume held\n");
    ok(Held.Before.Status == 0 && Held.After.Status == 0, "FltGetVolumeProperties: 0x%lx before, 0x%lx after\n",
       Held.Before.Status, Held.After.Status);
    ok(Held.After.DeviceType == Held.Before.DeviceType && Held.After.DeviceObjectFlags == Held.Before.DeviceObjectFlags &&
       Held.After.SectorSize == Held.Before.SectorSize &&
       Held.After.AlignmentRequirement == Held.Before.AlignmentRequirement &&
       Held.After.DeviceCharacteristics == Held.Before.DeviceCharacteristics,
       "The properties changed with the device gone\n");
    ok(!wcscmp(Held.After.DriverName, Held.Before.DriverName) && !wcscmp(Held.After.VolumeName, Held.Before.VolumeName),
       "Names: '%ls' '%ls' -> '%ls' '%ls'\n", Held.Before.DriverName, Held.Before.VolumeName,
       Held.After.DriverName, Held.After.VolumeName);
    ok(!_wcsicmp(Held.Before.VolumeName, FLTFAKEFS_DISK_NAME), "Volume name '%ls'\n", Held.Before.VolumeName);

    /* And the disk mounts again */
    ok(MountFake(), "Can't mount the fake volume again\n");
    SampleStats(&P, &S);
    ok(S.VolumeCount == S0.VolumeCount, "Volumes: %lu before, %lu after the new mount\n", S0.VolumeCount, S.VolumeCount);

    UnloadSample(&P, TRUE);
}

/*
 * Mount, delete, mount, ... the volume objects of the filter manager and their names go with their
 * volume devices: after 60 rounds no more of them are allocated than after the first.
 */
static
void
test_VolumeDeleteRounds(void)
{
    static TAG_COUNT Before[8192], After[8192];
    ULONG BeforeCount = 0, AfterCount, Rounds = 60, Done = 0, i;
    const TAG_COUNT *Old, *New;
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    LONG Volumes, Strings;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    for (i = 0; i <= Rounds; i++)
    {
        if (!MountFake())
        {
            ok(0, "Round %lu: can't mount the fake volume\n", i);
            break;
        }
        SampleStats(&P, &S);
        if (!DeleteFake(&P, S.VolumeCount))
        {
            ok(0, "Round %lu: the fake volume wasn't taken down\n", i);
            break;
        }
        if (i == 0)
        {
            Sleep(500);
            BeforeCount = SnapshotPoolTags(Before, RTL_NUMBER_OF(Before));
        }
        Done++;
    }

    Sleep(2000);
    AfterCount = SnapshotPoolTags(After, RTL_NUMBER_OF(After));
    ok(Done == Rounds + 1, "%lu of %lu rounds\n", Done, Rounds + 1);

    Old = FindTag(Before, BeforeCount, 'ovMF');
    New = FindTag(After, AfterCount, 'ovMF');
    Volumes = (New ? New->Outstanding : 0) - (Old ? Old->Outstanding : 0);
    Old = FindTag(Before, BeforeCount, 'suMF');
    New = FindTag(After, AfterCount, 'suMF');
    Strings = (New ? New->Outstanding : 0) - (Old ? Old->Outstanding : 0);
    trace("%lu mount / delete rounds: FMvo %+ld, FMus %+ld\n", Done - 1, Volumes, Strings);
    ok(Volumes <= 1, "FMvo: %+ld allocations after %lu rounds\n", Volumes, Done - 1);
    ok(Strings <= 2, "FMus: %+ld allocations after %lu rounds\n", Strings, Done - 1);

    /* Leave it mounted, as the other tests expect */
    MountFake();
    UnloadSample(&P, TRUE);
}

/* Does a work item queued on the system's delayed queue run within Milliseconds? */
static
BOOL
DelayedQueueRuns(PSAMPLE Sample, ULONG Milliseconds)
{
    ULONG Value = Milliseconds;

    return SampleIoctl(Sample, FLTSAMPLE_IOCTL_DELAYED_PING, &Value, sizeof(Value), &Value, sizeof(Value)) && Value == 1;
}

static LONG
OutstandingTag(ULONG Tag)
{
    static TAG_COUNT Tags[8192];
    ULONG Count = SnapshotPoolTags(Tags, RTL_NUMBER_OF(Tags));
    const TAG_COUNT *Found = FindTag(Tags, Count, Tag);

    return Found ? Found->Outstanding : 0;
}

/*
 * A filter which never drops a volume reference (the sample is told to keep 32, one per deleted volume):
 * the deleted volumes wait for it, as they do on Windows, but the wait is not on a worker of the system's
 * delayed queue. That queue has 12 threads, and the balance manager adds up to 16 more when it sees the
 * queue stand still: when each leaked volume holds one of the 28, nothing queued on it runs again, not the
 * next volume's deletion, not any other driver's work item.
 * The volumes are freed once the filter lets go.
 */
static
void
test_LeakedVolumeReferences(void)
{
    const ULONG Rounds = 32;
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Name[] = FLTFAKEFS_DISK_NAME;
    LONG Before, Held = 0;
    ULONG Taken = 0, Deleted = 0, Dropped = 0, i;

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    ok(MountFake(), "Can't mount the fake volume\n");
    ok(DelayedQueueRuns(&P, 5000), "The delayed queue does not run before the test\n");
    Sleep(500);
    Before = OutstandingTag('ovMF');

    for (i = 0; i < Rounds; i++)
    {
        if (!MountFake())
        {
            ok(0, "Round %lu: can't mount the fake volume\n", i);
            break;
        }
        SampleStats(&P, &S);
        if (SampleIoctl(&P, FLTSAMPLE_IOCTL_LEAK_VOLUME, Name, sizeof(Name) - sizeof(WCHAR), NULL, 0))
            Taken++;
        if (DeleteFake(&P, S.VolumeCount))
            Deleted++;
    }
    ok(Taken == Rounds, "%lu of %lu volumes held\n", Taken, Rounds);
    ok(Deleted == Rounds, "%lu of %lu deleted volumes were taken down: the delayed queue is blocked\n", Deleted, Rounds);

    ok(DelayedQueueRuns(&P, 5000), "A work item of the delayed queue does not run: the queue is starved\n");

    Held = OutstandingTag('ovMF') - Before;
    trace("%lu volumes deleted while held: FMvo %+ld\n", Deleted, Held);
    /* (the volume which was mounted when the count was taken is the first one deleted, and not held) */
    ok(Held >= (LONG)Taken - 1, "FMvo %+ld: a volume was freed while a filter held a reference\n", Held);

    /* A volume which waits longer than 30 s for its references says so, once, on the debug port */
    Sleep(32000);
    ok(DelayedQueueRuns(&P, 5000), "The delayed queue does not run after the wait\n");

    /* The references go: the volumes with them */
    ok(SampleIoctl(&P, FLTSAMPLE_IOCTL_DROP_LEAKED, NULL, 0, &Dropped, sizeof(Dropped)), "Drop: %lu\n", GetLastError());
    ok(Dropped == Taken, "%lu references dropped, %lu taken\n", Dropped, Taken);
    for (i = 0; i < 100; i++)
    {
        Held = OutstandingTag('ovMF') - Before;
        if (Held <= 0)
            break;
        Sleep(100);
    }
    trace("After the references are dropped: FMvo %+ld\n", Held);
    ok(Held <= 0, "FMvo %+ld: the volumes are not freed after the last reference is dropped\n", Held);
    ok(DelayedQueueRuns(&P, 5000), "The delayed queue does not run at the end\n");

    /* Leave it mounted, as the other tests expect */
    MountFake();
    UnloadSample(&P, TRUE);
}

START_TEST(p3volleak)
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

    test_LeakedVolumeReferences();
}

/*
 * The life of a filter, over and over: load (instances on every volume), files opened, written and
 * read with contexts, a client on the port, detach and attach every volume, unload. Afterwards no
 * pool tag of the filter manager or the sample has more allocations outstanding than before.
 * P3LOOP_COUNT (environment) sets the number of rounds, 200 by default.
 */
static
void
test_LoadUnloadLoop(void)
{
    static TAG_COUNT Before[8192], After[8192];
    ULONG BeforeCount, AfterCount, Rounds = 200, Done = 0, i, Leaks = 0;
    WCHAR Path[MAX_PATH];
    char Value[16];
    DWORD Bytes;
    UCHAR Buffer[4096];

    if (GetEnvironmentVariableA("P3LOOP_COUNT", Value, sizeof(Value)))
        Rounds = strtoul(Value, NULL, 10);
    MakeTestFile(L"p3loop.dat", Path, RTL_NUMBER_OF(Path));

    for (i = 0; i <= Rounds; i++)
    {
        SAMPLE P = { { 0 } };
        ATTACH_RESULT Result;
        HANDLE File, Port = INVALID_HANDLE_VALUE;
        UCHAR Ping[12] = { FLTSAMPLE_MSG_PING, 0, 0, 0, 0, 0, 0, 0, 'p', 'i', 'n', 'g' };
        UCHAR Echo[16];

        /* The first round warms up whatever is allocated once (lookasides, the first load) */
        if (i == 1)
        {
            Sleep(500);
            BeforeCount = SnapshotPoolTags(Before, RTL_NUMBER_OF(Before));
        }

        if (!LoadSample(&P, L"FltSampleL", L"384000.5", 0xFFFF))
        {
            ok(0, "Round %lu: can't load the sample filter\n", i);
            break;
        }

        File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (File != INVALID_HANDLE_VALUE)
        {
            memset(Buffer, (int)i, sizeof(Buffer));
            WriteFile(File, Buffer, sizeof(Buffer), &Bytes, NULL);
            SetFilePointer(File, 0, NULL, FILE_BEGIN);
            ReadFile(File, Buffer, sizeof(Buffer), &Bytes, NULL);
            CloseHandle(File);
        }
        if (SUCCEEDED(FilterConnectCommunicationPort(L"\\FltSampleLPort", 0, NULL, 0, NULL, &Port)))
        {
            FilterSendMessage(Port, Ping, sizeof(Ping), Echo, sizeof(Echo), &Bytes);
            CloseHandle(Port);
        }
        SampleIoctl(&P, FLTSAMPLE_IOCTL_DETACH_ALL, NULL, 0, &Result, sizeof(Result));
        SampleIoctl(&P, FLTSAMPLE_IOCTL_ATTACH_ALL, NULL, 0, &Result, sizeof(Result));

        if (!UnloadSample(&P, TRUE))
        {
            ok(0, "Round %lu: the sample filter didn't unload\n", i);
            break;
        }
        Done++;
    }
    DeleteFileW(Path);

    /* Workers (context cleanup, detach) finish asynchronously */
    Sleep(2000);
    AfterCount = SnapshotPoolTags(After, RTL_NUMBER_OF(After));
    trace("%lu rounds, %lu pool tags before, %lu after\n", Done, BeforeCount, AfterCount);
    ok(Done == Rounds + 1, "%lu of %lu rounds done\n", Done, Rounds + 1);
    ok(AfterCount > 0, "No pool tag information\n");

    for (i = 0; i < AfterCount; i++)
    {
        const TAG_COUNT *Old = FindTag(Before, BeforeCount, After[i].Tag);
        LONG Delta = After[i].Outstanding - (Old ? Old->Outstanding : 0);
        const UCHAR *c = (const UCHAR *)&After[i].Tag;

        if (IsFilterTag(After[i].Tag))
        {
            trace("Tag %c%c%c%c: %ld outstanding (%+ld), %lu bytes\n", c[0], c[1], c[2], c[3],
                  After[i].Outstanding, Delta, (ULONG)After[i].Bytes);
            if (Delta > 2)
            {
                ok(0, "Tag %c%c%c%c: %ld more allocations outstanding after %lu rounds\n", c[0], c[1], c[2], c[3], Delta, Done);
                Leaks++;
            }
        }
        else if (Delta >= (LONG)Rounds)
        {
            /* Something else which grows with every round: worth a look, not ours to judge */
            trace("Tag %c%c%c%c (not the filter manager's) grew by %ld\n", c[0], c[1], c[2], c[3], Delta);
        }
    }
    ok(Leaks == 0, "%lu filter manager / sample pool tags leak\n", Leaks);
}

START_TEST(p3loop)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_LoadUnloadLoop();
}

/*
 * Sections and the cache under the FsFilter callbacks, for a while: threads which write files, map
 * them, write the views, flush them (the cache flush's acquire / release), unmap, truncate, read back;
 * one thread which now and then commits more memory than the machine has (the modified page writer).
 * The sample filter counts every FsFilter operation on the .fsf files. Nothing may fail, the data read
 * back is what was written, and the acquires have their releases.
 * FLTMGR_SECSTRESS_SECONDS (environment) sets the time, 60 s by default.
 */
typedef struct _SECSTRESS
{
    ULONG Index;
    volatile LONG *Stop;
    ULONG Rounds;
    ULONG Failures;
    DWORD LastError;

} SECSTRESS;

static
DWORD
WINAPI
SectionStressThread(PVOID Parameter)
{
    SECSTRESS *T = Parameter;
    WCHAR Name[32], Path[MAX_PATH];
    ULONG Size;
    UCHAR Byte;
    DWORD Read;
    LARGE_INTEGER Offset;

    StringCbPrintfW(Name, sizeof(Name), L"p3secstr%lu.fsf", T->Index);
    MakeTestFile(Name, Path, RTL_NUMBER_OF(Path));

    while (!*T->Stop)
    {
        HANDLE File, Section = NULL;
        PUCHAR View = NULL;
        ULONG i, Pages;
        BOOL Good = TRUE;

        Size = (1 + (T->Rounds % 16)) * 65536;
        Pages = Size / 4096;
        File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_ALWAYS, 0, NULL);
        if (File == INVALID_HANDLE_VALUE)
        {
            T->Failures++;
            T->LastError = GetLastError();
            Sleep(10);
            continue;
        }
        Offset.QuadPart = Size;
        Good = SetFilePointerEx(File, Offset, NULL, FILE_BEGIN) && SetEndOfFile(File);
        if (Good)
            Section = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (Section)
            View = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0);
        if (View)
        {
            for (i = 0; i < Pages; i++)
                View[i * 4096 + (T->Rounds % 4000)] = (UCHAR)(T->Rounds + i);
            if (!FlushViewOfFile(View, (T->Rounds & 1) ? 0 : Size / 2))
                Good = FALSE;
            UnmapViewOfFile(View);
        }
        else
        {
            Good = FALSE;
        }
        if (Section)
            CloseHandle(Section);

        /* Cached I/O on the same file: read back through the cache, written, flushed */
        if (Good)
        {
            Offset.QuadPart = (LONGLONG)(Pages - 1) * 4096 + (T->Rounds % 4000);
            Good = SetFilePointerEx(File, Offset, NULL, FILE_BEGIN) &&
                   ReadFile(File, &Byte, 1, &Read, NULL) && Read == 1 && Byte == (UCHAR)(T->Rounds + Pages - 1);
            Byte = 0x5A;
            Good = Good && SetFilePointerEx(File, Offset, NULL, FILE_BEGIN) && WriteFile(File, &Byte, 1, &Read, NULL);
            Good = Good && FlushFileBuffers(File);
        }

        /* And a truncation every other round, the section is gone */
        if (Good && (T->Rounds & 1))
        {
            Offset.QuadPart = 4096;
            Good = SetFilePointerEx(File, Offset, NULL, FILE_BEGIN) && SetEndOfFile(File);
        }
        if (!Good)
        {
            T->Failures++;
            T->LastError = GetLastError();
        }
        CloseHandle(File);
        T->Rounds++;
    }

    DeleteFileW(Path);
    return 0;
}

static
DWORD
WINAPI
MemoryPressureThread(PVOID Parameter)
{
    SECSTRESS *T = Parameter;
    MEMORYSTATUSEX Memory;
    SIZE_T Chunk = 32 * 1024 * 1024, j;
    PVOID Chunks[128];
    ULONG Count, i;
    ULONGLONG Total;

    Memory.dwLength = sizeof(Memory);
    GlobalMemoryStatusEx(&Memory);
    while (!*T->Stop)
    {
        Count = 0;
        Total = 0;
        while (!*T->Stop && Total < Memory.ullTotalPhys + Memory.ullTotalPhys / 4 && Count < RTL_NUMBER_OF(Chunks))
        {
            PUCHAR Block = VirtualAlloc(NULL, Chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (Block == NULL)
                break;
            for (j = 0; j < Chunk; j += 4096)
                Block[j] = 1;
            Chunks[Count++] = Block;
            Total += Chunk;
        }
        for (i = 0; i < Count; i++)
            VirtualFree(Chunks[i], 0, MEM_RELEASE);
        T->Rounds++;
        for (i = 0; i < 50 && !*T->Stop; i++)
            Sleep(100);
    }
    return 0;
}

static
void
test_SectionStress(void)
{
    SAMPLE P = { { 0 } };
    FLTSAMPLE_STATS S;
    SECSTRESS T[5];
    HANDLE Threads[5];
    volatile LONG Stop = 0;
    ULONG Seconds = 60, i, Rounds = 0, Failures = 0;
    char Value[16];

    if (GetEnvironmentVariableA("FLTMGR_SECSTRESS_SECONDS", Value, sizeof(Value)))
        Seconds = strtoul(Value, NULL, 10);

    if (!LoadSample(&P, L"FltSampleP", L"383000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(T); i++)
    {
        ZeroMemory(&T[i], sizeof(T[i]));
        T[i].Index = i;
        T[i].Stop = &Stop;
        Threads[i] = CreateThread(NULL, 0, i == 0 ? MemoryPressureThread : SectionStressThread, &T[i], 0, NULL);
        ok(Threads[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
    }

    Sleep(Seconds * 1000);
    InterlockedExchange(&Stop, 1);
    for (i = 0; i < RTL_NUMBER_OF(T); i++)
    {
        if (Threads[i])
        {
            ok(WaitForSingleObject(Threads[i], 120000) == WAIT_OBJECT_0, "Thread %lu didn't stop\n", i);
            CloseHandle(Threads[i]);
        }
        if (i > 0)
        {
            Rounds += T[i].Rounds;
            Failures += T[i].Failures;
            if (T[i].Failures)
                trace("Thread %lu: %lu failures of %lu rounds, last error %lu\n", i, T[i].Failures, T[i].Rounds, T[i].LastError);
        }
    }

    WaitBalanced(&P, &S, FLTSAMPLE_FSF_ACQUIRE_CCFLUSH, FLTSAMPLE_FSF_RELEASE_CCFLUSH);
    WaitBalanced(&P, &S, FLTSAMPLE_FSF_ACQUIRE_MODWRITE, FLTSAMPLE_FSF_RELEASE_MODWRITE);
    trace("%lu s: %lu rounds, %lu pressure cycles, %lu failures; section %lu/%lu release %lu, cache flush %lu/%lu, "
          "modified page writer %lu/%lu (%lu writes)\n",
          Seconds, Rounds, T[0].Rounds, Failures, S.SectionSyncPre, S.SectionSyncPost,
          S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_SECTION], S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH],
          S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH], S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_MODWRITE],
          S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE], S.ModWriterWrites);
    ok(Rounds > 0, "No round done\n");
    ok(Failures == 0, "%lu failures\n", Failures);
    ok(S.FsFilterPre[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH] > 0, "No cache flush seen\n");
    ok(S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH] - S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH] ==
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH], "cache flush: %lu acquires (%lu failed), %lu releases\n",
       S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH], S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_CCFLUSH],
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_CCFLUSH]);
    ok(S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_MODWRITE] - S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_MODWRITE] ==
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE], "modified page writer: %lu acquires (%lu failed), %lu releases\n",
       S.FsFilterPost[FLTSAMPLE_FSF_ACQUIRE_MODWRITE], S.FsFilterFailed[FLTSAMPLE_FSF_ACQUIRE_MODWRITE],
       S.FsFilterPre[FLTSAMPLE_FSF_RELEASE_MODWRITE]);
    ok(S.FsFilterOtherThread == 0, "%lu post-operations in another thread\n", S.FsFilterOtherThread);

    UnloadSample(&P, TRUE);
}

START_TEST(p3secstress)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_SectionStress();
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
