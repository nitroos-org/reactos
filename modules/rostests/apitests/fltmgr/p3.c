/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the filter manager for the IRQL, teardown and port rules of the WDK which need
 *              a file system the tests control (fltfakefs) or a filter which breaks a rule on purpose
 */

#include "precomp.h"
#include "fltfakefs.h"

#define FAKE_SERVICE    L"FltFakeFs"

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
