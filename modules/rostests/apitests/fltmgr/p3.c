/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the filter manager for the IRQL, teardown and port rules of the WDK which need
 *              a file system the tests control (fltfakefs) or a filter which breaks a rule on purpose
 */

#include "precomp.h"
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

START_TEST(p3section)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_SectionSync();
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
