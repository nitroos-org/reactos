/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     MUP test driver: a UNC provider, registered by device object
 *              (\Device\<name> becomes a link to \Device\Mup\;<name>) and by name,
 *              receives the opens of \Device\Mup\;<name>\... without the prefix
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

#include "MupProvider.h"

/* Declared by the headers only for newer NTDDI_VERSIONs than this driver is built for */
typedef NTSTATUS (NTAPI *P_FsRtlRegisterUncProviderEx)(PHANDLE MupHandle, PCUNICODE_STRING RedirDevName,
                                                      PDEVICE_OBJECT DeviceObject, ULONG Flags);
static P_FsRtlRegisterUncProviderEx pFsRtlRegisterUncProviderEx;

static KMT_IRP_HANDLER TestIrpHandler;

#define PROVIDER_NAME L"KmtestMupEx"
#define LEGACY_NAME L"Kmtest-MupProvider" /* the device of the test driver */
#define CACHE_PREFIX L"\\kmcache\\" /* the UNC server the provider claims, one share at a time */

static PDEVICE_OBJECT TestDevice;

/* What the create handler saw in the last create IRP */
static struct
{
    ULONG Creates;
    ULONG Queries;
    PDEVICE_OBJECT Device;
    WCHAR Name[128];
} Seen;

NTSTATUS
TestEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _Out_ PCWSTR *DeviceName,
    _Inout_ INT *Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    *DeviceName = L"MupProvider";
    *Flags = TESTENTRY_NO_EXCLUSIVE_DEVICE |
             TESTENTRY_BUFFERED_IO_DEVICE |
             TESTENTRY_NO_READONLY_DEVICE;

    KmtRegisterIrpHandler(IRP_MJ_CREATE, NULL, TestIrpHandler);
    KmtRegisterIrpHandler(IRP_MJ_DEVICE_CONTROL, NULL, TestIrpHandler);

    return STATUS_SUCCESS;
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}

static
NTSTATUS
DoCreate(
    _In_ PCWSTR Path,
    _Out_opt_ PDEVICE_OBJECT *Device)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    PFILE_OBJECT FileObject;
    HANDLE Handle;
    NTSTATUS Status;

    if (Device != NULL)
        *Device = NULL;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&Handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(Status))
    {
        if (Device != NULL &&
            NT_SUCCESS(ObReferenceObjectByHandle(Handle, 0, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, NULL)))
        {
            *Device = FileObject->DeviceObject;
            ObDereferenceObject(FileObject);
        }
        ObCloseHandle(Handle, KernelMode);
    }
    return Status;
}

/* An open that must reach the provider, with the name Expected */
static
VOID
ExpectOpen(
    _In_ PCWSTR Path,
    _In_ PCWSTR Expected,
    _In_ NTSTATUS ExpectedStatus,
    _In_ int Line)
{
    ULONG Before = Seen.Creates;
    PDEVICE_OBJECT Device;
    NTSTATUS Status;

    Seen.Name[0] = L'#';
    Seen.Name[1] = UNICODE_NULL;
    Seen.Device = NULL;
    Status = DoCreate(Path, &Device);
    ok(Status == ExpectedStatus, "line %d: %ls: status 0x%08lx, expected 0x%08lx\n", Line, Path, Status, ExpectedStatus);
    ok(Seen.Creates == Before + 1, "line %d: %ls: %lu creates reached the provider\n", Line, Path, Seen.Creates - Before);
    ok(!wcscmp(Seen.Name, Expected), "line %d: %ls: the provider got \"%ls\", expected \"%ls\"\n", Line, Path, Seen.Name, Expected);
    ok(Seen.Device == TestDevice, "line %d: %ls: create on %p, expected %p\n", Line, Path, Seen.Device, TestDevice);
    /* The file object of an open that succeeded is the provider's */
    if (NT_SUCCESS(Status))
        ok(Device == TestDevice, "line %d: %ls: file object on %p, expected %p\n", Line, Path, Device, TestDevice);
}

/* An open that MUP must refuse without asking the provider */
static
VOID
ExpectRefused(
    _In_ PCWSTR Path,
    _In_ NTSTATUS ExpectedStatus,
    _In_ int Line)
{
    ULONG Before = Seen.Creates;
    NTSTATUS Status;

    Status = DoCreate(Path, NULL);
    ok(Status == ExpectedStatus, "line %d: %ls: status 0x%08lx, expected 0x%08lx\n", Line, Path, Status, ExpectedStatus);
    ok(Seen.Creates == Before, "line %d: %ls: %lu creates reached the provider\n", Line, Path, Seen.Creates - Before);
}

#define EXPECT_OPEN(p, e) ExpectOpen(p, e, STATUS_SUCCESS, __LINE__)
#define EXPECT_OPEN_STATUS(p, e, s) ExpectOpen(p, e, s, __LINE__)
#define EXPECT_REFUSED(p, s) ExpectRefused(p, s, __LINE__)

static
NTSTATUS
QueryLink(
    _In_ PCWSTR Path,
    _Out_writes_(Chars) PWSTR Target,
    _In_ USHORT Chars)
{
    UNICODE_STRING Name, Value;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    NTSTATUS Status;

    Target[0] = UNICODE_NULL;
    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenSymbolicLinkObject(&Handle, SYMBOLIC_LINK_QUERY, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return Status;

    Value.Buffer = Target;
    Value.Length = 0;
    Value.MaximumLength = (Chars - 1) * sizeof(WCHAR);
    Status = ZwQuerySymbolicLinkObject(Handle, &Value, NULL);
    if (NT_SUCCESS(Status))
        Target[Value.Length / sizeof(WCHAR)] = UNICODE_NULL;
    ObCloseHandle(Handle, KernelMode);
    return Status;
}

/* The descriptor of a provider link: owner administrators, the 4 ACEs of Windows' links */
static
VOID
CheckLinkSecurity(
    _In_ PCWSTR Path)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR Sd;
    ULONG Length = 0;
    PSID Owner = NULL;
    PACL Dacl = NULL;
    BOOLEAN Defaulted, Present = FALSE;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenSymbolicLinkObject(&Handle, READ_CONTROL, &ObjectAttributes);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    Sd = ExAllocatePoolWithTag(PagedPool, 512, 'tpuM');
    if (!skip(Sd != NULL, "No memory\n"))
    {
        Status = ZwQuerySecurityObject(Handle, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Sd, 512, &Length);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = RtlGetOwnerSecurityDescriptor(Sd, &Owner, &Defaulted);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok(Owner != NULL && RtlEqualSid(Owner, SeExports->SeAliasAdminsSid), "%ls: owner is not administrators\n", Path);
            Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
            ok_eq_hex(Status, STATUS_SUCCESS);
            ok(Present && Dacl != NULL && Dacl->AceCount == 4, "%ls: DACL present %u, %u ACEs\n",
               Path, Present, (Dacl != NULL) ? Dacl->AceCount : 0);
        }
        ExFreePoolWithTag(Sd, 'tpuM');
    }
    ObCloseHandle(Handle, KernelMode);
}

/* \Device\Mup and \??\UNC as on Windows, whether a provider is registered or not */
static
VOID
TestMupNamespace(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Mup");
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_FS_DEVICE_INFORMATION DeviceInfo;
    UCHAR Buffer[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 64];
    WCHAR Target[128];
    HANDLE Handle;
    NTSTATUS Status;

    Status = QueryLink(L"\\GLOBAL??\\UNC", Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_wstr(Target, L"\\Device\\Mup");

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&Handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* Windows 10 22H2 and Server 2022: DeviceType 0x14, Characteristics 0x20010 */
    RtlZeroMemory(&DeviceInfo, sizeof(DeviceInfo));
    Status = ZwQueryVolumeInformationFile(Handle, &IoStatusBlock, &DeviceInfo, sizeof(DeviceInfo), FileFsDeviceInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_hex(DeviceInfo.DeviceType, FILE_DEVICE_NETWORK_FILE_SYSTEM);
    ok_eq_hex(DeviceInfo.Characteristics, FILE_REMOTE_DEVICE | FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL);

    /* Server 2022: no attribute information for MUP itself */
    Status = ZwQueryVolumeInformationFile(Handle, &IoStatusBlock, Buffer, sizeof(Buffer), FileFsAttributeInformation);
    ok_eq_hex(Status, STATUS_INVALID_DEVICE_REQUEST);

    ObCloseHandle(Handle, KernelMode);
}

static
VOID
TestRegisteredByDevice(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\" PROVIDER_NAME);
    WCHAR Target[128];
    HANDLE MupHandle = NULL;
    NTSTATUS Status;

    Status = QueryLink(L"\\Device\\" PROVIDER_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);

    Status = pFsRtlRegisterUncProviderEx(&MupHandle, &Name, TestDevice, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* As on Windows: \Device\LanmanRedirector -> \Device\Mup\;LanmanRedirector */
    Status = QueryLink(L"\\Device\\" PROVIDER_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_wstr(Target, L"\\Device\\Mup\\;" PROVIDER_NAME);
    CheckLinkSecurity(L"\\Device\\" PROVIDER_NAME);

    /* Through the link, and with the MUP name: the provider gets the rest */
    EXPECT_OPEN(L"\\Device\\" PROVIDER_NAME L"\\server\\share\\file.txt", L"\\server\\share\\file.txt");
    EXPECT_OPEN(L"\\Device\\Mup\\;" PROVIDER_NAME L"\\server\\share", L"\\server\\share");
    /* The provider name is not case sensitive */
    EXPECT_OPEN(L"\\Device\\Mup\\;kmtestmupex\\server\\share", L"\\server\\share");
    /* A drive letter connection: the \;X:<logon id> part is the provider's */
    EXPECT_OPEN(L"\\Device\\" PROVIDER_NAME L"\\;Z:0000000000000000\\server\\share\\dir",
                L"\\;Z:0000000000000000\\server\\share\\dir");
    /* Nothing after the provider name (Windows opens the provider) */
    EXPECT_OPEN(L"\\Device\\Mup\\;" PROVIDER_NAME, L"");
    /* The status of the provider comes back */
    EXPECT_OPEN_STATUS(L"\\Device\\Mup\\;" PROVIDER_NAME L"\\fail\\share", L"\\fail\\share", STATUS_BAD_NETWORK_NAME);

    /* Not a provider: Windows 10 says STATUS_OBJECT_PATH_INVALID */
    EXPECT_REFUSED(L"\\Device\\Mup\\;KmtestMupE\\server\\share", STATUS_OBJECT_PATH_INVALID);
    EXPECT_REFUSED(L"\\Device\\Mup\\;KmtestMupExX\\server\\share", STATUS_OBJECT_PATH_INVALID);
    EXPECT_REFUSED(L"\\Device\\Mup\\;KmtestMupEx;x\\server\\share", STATUS_OBJECT_PATH_INVALID);
    EXPECT_REFUSED(L"\\Device\\Mup\\;\\server\\share", STATUS_OBJECT_PATH_INVALID);
    EXPECT_REFUSED(L"\\Device\\Mup\\;", STATUS_OBJECT_PATH_INVALID);

    /* Closes the (kernel) handle to MUP of a provider registered by device object */
    FsRtlDeregisterUncProvider(MupHandle);

    /* The link goes with the registration */
    Status = QueryLink(L"\\Device\\" PROVIDER_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    EXPECT_REFUSED(L"\\Device\\Mup\\;" PROVIDER_NAME L"\\server\\share", STATUS_OBJECT_PATH_INVALID);

    /* And comes back with a new one */
    Status = pFsRtlRegisterUncProviderEx(&MupHandle, &Name, TestDevice, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = QueryLink(L"\\Device\\" PROVIDER_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_wstr(Target, L"\\Device\\Mup\\;" PROVIDER_NAME);
    EXPECT_OPEN(L"\\Device\\" PROVIDER_NAME L"\\server\\again", L"\\server\\again");
    FsRtlDeregisterUncProvider(MupHandle);
    Status = QueryLink(L"\\Device\\" PROVIDER_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);
}

static
VOID
TestRegisteredByName(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\" LEGACY_NAME);
    WCHAR Target[128];
    HANDLE MupHandle = NULL;
    NTSTATUS Status;

    Status = FsRtlRegisterUncProvider(&MupHandle, &Name, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* The name is the device of the provider, which stays as it is */
    Status = QueryLink(L"\\Device\\" LEGACY_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);

    /* \;<name> is rerouted to the device */
    EXPECT_OPEN(L"\\Device\\Mup\\;" LEGACY_NAME L"\\server\\share\\x", L"\\server\\share\\x");
    EXPECT_OPEN(L"\\Device\\Mup\\;" LEGACY_NAME L"\\;Y:0000000000000000\\server\\share",
                L"\\;Y:0000000000000000\\server\\share");

    /* The handle of a provider registered by name is for the caller to close */
    FsRtlDeregisterUncProvider(MupHandle);
    ZwClose(MupHandle);

    /* The device is still there */
    Status = QueryLink(L"\\Device\\" LEGACY_NAME, Target, RTL_NUMBER_OF(Target));
    ok_eq_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    EXPECT_OPEN(L"\\Device\\" LEGACY_NAME L"\\direct", L"\\direct");
    EXPECT_REFUSED(L"\\Device\\Mup\\;" LEGACY_NAME L"\\server\\share", STATUS_OBJECT_PATH_INVALID);
}

/* An open of a UNC path that reaches the provider, with the number of path queries it cost */
static
VOID
ExpectCachedOpen(
    _In_ PCWSTR Path,
    _In_ PCWSTR Expected,
    _In_ ULONG ExpectedQueries,
    _In_ int Line)
{
    ULONG Before = Seen.Queries;

    ExpectOpen(Path, Expected, STATUS_SUCCESS, Line);
    ok(Seen.Queries - Before == ExpectedQueries, "line %d: %ls: %lu path queries, expected %lu\n",
       Line, Path, Seen.Queries - Before, ExpectedQueries);
}

/* An open of a UNC path that fails, with no create reaching the provider */
static
VOID
ExpectFailedOpen(
    _In_ PCWSTR Path,
    _In_ int Line)
{
    ULONG Before = Seen.Creates;
    NTSTATUS Status;

    Status = DoCreate(Path, NULL);
    ok(!NT_SUCCESS(Status), "line %d: %ls: status 0x%08lx\n", Line, Path, Status);
    ok(Seen.Creates == Before, "line %d: %ls: %lu creates reached the provider\n", Line, Path, Seen.Creates - Before);
}

/*
 * The table of known prefixes: a provider that accepted a prefix is not asked again for the
 * next open under it (until the prefix expires), a prefix of a provider that deregistered is
 * forgotten, and so is one whose provider registers again
 */
static
VOID
TestKnownPrefixes(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\" PROVIDER_NAME);
    UNICODE_STRING LegacyName = RTL_CONSTANT_STRING(L"\\Device\\" LEGACY_NAME);
    HANDLE MupHandle = NULL, LegacyHandle = NULL;
    NTSTATUS Status;

    Status = pFsRtlRegisterUncProviderEx(&MupHandle, &Name, TestDevice, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* The first open under a prefix asks the provider, the next ones do not */
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share\\a", L"\\kmcache\\share\\a", 1, __LINE__);
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share\\b", L"\\kmcache\\share\\b", 0, __LINE__);
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share\\a", L"\\kmcache\\share\\a", 0, __LINE__);
    ExpectCachedOpen(L"\\Device\\Mup\\KMCACHE\\SHARE\\sub\\c", L"\\KMCACHE\\SHARE\\sub\\c", 0, __LINE__);
    /* Another share is another prefix, a share that merely starts alike is not the same */
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\other\\a", L"\\kmcache\\other\\a", 1, __LINE__);
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share2\\a", L"\\kmcache\\share2\\a", 1, __LINE__);
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share\\a", L"\\kmcache\\share\\a", 0, __LINE__);
    /* A path nobody claims is asked for every time and fails */
    {
        ULONG Before = Seen.Queries;

        ExpectFailedOpen(L"\\Device\\Mup\\kmnone\\share\\a", __LINE__);
        ExpectFailedOpen(L"\\Device\\Mup\\kmnone\\share\\a", __LINE__);
        ok(Seen.Queries - Before == 2, "%lu path queries for two failing opens\n", Seen.Queries - Before);
    }

    /* The provider deregisters: its prefixes are of no use any more */
    FsRtlDeregisterUncProvider(MupHandle);
    ExpectFailedOpen(L"\\Device\\Mup\\kmcache\\share\\a", __LINE__);
    ExpectFailedOpen(L"\\Device\\Mup\\kmcache\\other\\a", __LINE__);

    /* And registers again: a prefix of the old registration is not used for the new one */
    MupHandle = NULL;
    Status = pFsRtlRegisterUncProviderEx(&MupHandle, &Name, TestDevice, 0);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share\\a", L"\\kmcache\\share\\a", 1, __LINE__);
    ExpectCachedOpen(L"\\Device\\Mup\\kmcache\\share\\a", L"\\kmcache\\share\\a", 0, __LINE__);

    /* Two providers claim one prefix: whichever MUP picked, the opens work while either is there */
    Status = FsRtlRegisterUncProvider(&LegacyHandle, &LegacyName, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ExpectOpen(L"\\Device\\Mup\\kmcache\\both\\a", L"\\kmcache\\both\\a", STATUS_SUCCESS, __LINE__);
        ExpectOpen(L"\\Device\\Mup\\kmcache\\both\\b", L"\\kmcache\\both\\b", STATUS_SUCCESS, __LINE__);

        FsRtlDeregisterUncProvider(LegacyHandle);
        ZwClose(LegacyHandle);
        ExpectOpen(L"\\Device\\Mup\\kmcache\\both\\c", L"\\kmcache\\both\\c", STATUS_SUCCESS, __LINE__);
        ExpectOpen(L"\\Device\\Mup\\kmcache\\share\\c", L"\\kmcache\\share\\c", STATUS_SUCCESS, __LINE__);
    }

    FsRtlDeregisterUncProvider(MupHandle);
    ExpectFailedOpen(L"\\Device\\Mup\\kmcache\\both\\d", __LINE__);
    ExpectFailedOpen(L"\\Device\\Mup\\kmcache\\share\\d", __LINE__);
}

/*
 * UNC opens while the provider registers and deregisters by device object: every open goes
 * through MUP's prefix query loop, which must not use the device of a provider that
 * deregistered meanwhile (deregistration clears and releases it)
 */
static volatile LONG RaceStop;
static volatile LONG RaceOpens, RaceOpened;

static
VOID
NTAPI
RaceOpenThread(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    while (!RaceStop)
    {
        if (NT_SUCCESS(DoCreate(L"\\Device\\Mup\\kmrace\\share\\x", NULL)))
            InterlockedIncrement(&RaceOpened);
        InterlockedIncrement(&RaceOpens);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
TestQueryRace(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\" PROVIDER_NAME);
    OBJECT_ATTRIBUTES ObjectAttributes;
    PVOID Threads[2] = { NULL, NULL };
    HANDLE MupHandle, ThreadHandle;
    ULONG i, Cycles = 0;
    NTSTATUS Status;

    RaceStop = 0;
    RaceOpens = RaceOpened = 0;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
    {
        Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, RaceOpenThread, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            break;
        Status = ObReferenceObjectByHandle(ThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode, &Threads[i], NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ObCloseHandle(ThreadHandle, KernelMode);
    }

    for (i = 0; i < 400; i++)
    {
        MupHandle = NULL;
        Status = pFsRtlRegisterUncProviderEx(&MupHandle, &Name, TestDevice, 0);
        if (!NT_SUCCESS(Status))
        {
            ok_eq_hex(Status, STATUS_SUCCESS);
            break;
        }
        FsRtlDeregisterUncProvider(MupHandle);
        Cycles++;
    }

    RaceStop = 1;
    for (i = 0; i < RTL_NUMBER_OF(Threads); i++)
    {
        if (Threads[i] != NULL)
        {
            KeWaitForSingleObject(Threads[i], Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(Threads[i]);
        }
    }

    ok(Cycles == 400, "%lu registration cycles\n", Cycles);
    ok(RaceOpens > 0, "no open ran during the registrations\n");
    ok(RaceOpened == 0, "%ld opens of a name no provider claims succeeded\n", RaceOpened);
    trace("%lu registration cycles, %ld opens during them\n", Cycles, RaceOpens);
}

static
NTSTATUS
TestIrpHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack)
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    Irp->IoStatus.Information = 0;

    if (IoStack->MajorFunction == IRP_MJ_CREATE)
    {
        PUNICODE_STRING FileName = &IoStack->FileObject->FileName;
        USHORT Chars = min(FileName->Length / sizeof(WCHAR), RTL_NUMBER_OF(Seen.Name) - 1);

        Seen.Creates++;
        Seen.Device = DeviceObject;
        RtlCopyMemory(Seen.Name, FileName->Buffer, Chars * sizeof(WCHAR));
        Seen.Name[Chars] = UNICODE_NULL;

        if (Chars >= 5 && !_wcsnicmp(Seen.Name, L"\\fail", 5))
            Status = STATUS_BAD_NETWORK_NAME;
        else
            Irp->IoStatus.Information = FILE_OPENED;
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_REDIR_QUERY_PATH ||
             IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_REDIR_QUERY_PATH_EX)
    {
        PWSTR Path;
        ULONG Chars, Accepted;

        /* Both are METHOD_NEITHER: the request is Type3InputBuffer, the response goes to UserBuffer */
        if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_REDIR_QUERY_PATH_EX)
        {
            PQUERY_PATH_REQUEST_EX Request = IoStack->Parameters.DeviceIoControl.Type3InputBuffer;

            Path = Request->PathName.Buffer;
            Chars = Request->PathName.Length / sizeof(WCHAR);
        }
        else
        {
            PQUERY_PATH_REQUEST Request = IoStack->Parameters.DeviceIoControl.Type3InputBuffer;

            Path = Request->FilePathName;
            Chars = Request->PathNameLength / sizeof(WCHAR);
        }

        /* MUP asks every provider for every UNC path: only \kmcache\<share> is ours */
        Seen.Queries++;
        Accepted = 0;
        if (Chars > RTL_NUMBER_OF(CACHE_PREFIX) - 1 &&
            !_wcsnicmp(Path, CACHE_PREFIX, RTL_NUMBER_OF(CACHE_PREFIX) - 1))
        {
            Accepted = RTL_NUMBER_OF(CACHE_PREFIX) - 1;
            while (Accepted < Chars && Path[Accepted] != L'\\')
                Accepted++;
        }

        if (Accepted != 0)
        {
            ((PQUERY_PATH_RESPONSE)Irp->UserBuffer)->LengthAccepted = Accepted * sizeof(WCHAR);
            Irp->IoStatus.Information = sizeof(QUERY_PATH_RESPONSE);
        }
        else
        {
            Status = STATUS_BAD_NETWORK_PATH;
        }
    }
    else if (((IoStack->Parameters.DeviceIoControl.IoControlCode & 0xFFC) >> 2) == IOCTL_RUN_MUP_TEST)
    {
        UNICODE_STRING Routine = RTL_CONSTANT_STRING(L"FsRtlRegisterUncProviderEx");

        pFsRtlRegisterUncProviderEx = MmGetSystemRoutineAddress(&Routine);
        if (pFsRtlRegisterUncProviderEx == NULL)
        {
            skip(FALSE, "FsRtlRegisterUncProviderEx is not exported\n");
        }
        else
        {
            TestDevice = DeviceObject;
            TestMupNamespace();
            TestRegisteredByDevice();
            TestRegisteredByName();
            TestKnownPrefixes();
            TestQueryRace();
            TestDevice = NULL;
        }
    }
    else
    {
        Status = STATUS_NOT_SUPPORTED;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
