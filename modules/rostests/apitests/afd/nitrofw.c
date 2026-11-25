/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The firewall filter's contract with the firewall service: \Device\NitroFw takes a policy blob
 *              (IOCTL_NITROFW_SET_POLICY) the way mpssvc pushes it, validates it completely before it replaces
 *              the policy, orders pushes by generation, reports the policy and the state of enforcement
 *              (IOCTL_NITROFW_GET_STATUS) and takes it away (IOCTL_NITROFW_CLEAR_POLICY).
 *              Loopback is never filtered: what a rule does to a packet from another host is a lab row (a NIC and a
 *              second machine), see the evidence of the ticket; here only the contract and the loopback pass.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"
#include <winioctl.h>
#include <winsvc.h>
#include <reactos/nitrofw.h>

#define TEST_GENERATION_BASE 0x1000000000000000ULL

static
NTSTATUS
FwIoctl(
    _In_ HANDLE File,
    _In_ ULONG Code,
    _In_opt_ PVOID In,
    _In_ ULONG InLen,
    _Out_opt_ PVOID Out,
    _In_ ULONG OutLen)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK Iosb;

    Iosb.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(File, NULL, NULL, NULL, &Iosb, Code, In, InLen, Out, OutLen);
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(File, FALSE, NULL);
        Status = Iosb.Status;
    }
    return Status;
}

static
NTSTATUS
FwOpen(
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(NITROFW_DEVICE_NAME);
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(Handle,
                        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                        &Attributes,
                        &Iosb,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT,
                        NULL,
                        0);
}

/* The policy: every profile enabled, default inbound block; Rules is 0 or 1 TCP allow rule for local port 7001 */
static
ULONG
BuildPolicy(
    _Out_ PUCHAR Buffer,
    _In_ ULONGLONG Generation,
    _In_ ULONG Flags,
    _In_ ULONG RuleCount,
    _In_ ULONG IfTypes)
{
    PNITROFW_POLICY Policy = (PNITROFW_POLICY)Buffer;
    PNITROFW_RULE Rule;
    PNITROFW_PORT_RANGE Port;
    ULONG i, Size = sizeof(NITROFW_POLICY);

    RtlZeroMemory(Buffer, 4096);
    Policy->Magic = NITROFW_POLICY_MAGIC;
    Policy->AbiVersion = NITROFW_ABI_VERSION;
    Policy->Flags = Flags;
    Policy->Generation = Generation;
    Policy->ActiveProfiles = NITROFW_PROFILE_ALL;
    Policy->RuleCount = RuleCount;
    Policy->RulesOffset = sizeof(NITROFW_POLICY);
    for (i = 0; i < NITROFW_PROFILE_COUNT; i++)
    {
        Policy->Profile[i].Flags = NITROFW_PROFILE_ENABLED;
        Policy->Profile[i].DefaultInbound = NITROFW_ACTION_BLOCK;
        Policy->Profile[i].DefaultOutbound = NITROFW_ACTION_ALLOW;
    }
    if (RuleCount)
    {
        Rule = (PNITROFW_RULE)(Buffer + Size);
        Rule->Size = sizeof(NITROFW_RULE) + sizeof(NITROFW_PORT_RANGE) * 1;
        Rule->Size = (Rule->Size + 7) & ~7UL;
        Rule->Action = NITROFW_ACTION_ALLOW;
        Rule->Direction = NITROFW_DIR_IN;
        Rule->Protocol = IPPROTO_TCP;
        Rule->ProfileMask = NITROFW_PROFILE_ALL;
        Rule->IfTypes = IfTypes;
        Rule->LocalPortCount = 1;
        Rule->LocalPortOffset = sizeof(NITROFW_RULE);
        Port = (PNITROFW_PORT_RANGE)((PUCHAR)Rule + sizeof(NITROFW_RULE));
        Port->Low = Port->High = 7001;
        Size += Rule->Size;
    }
    Policy->TotalSize = Size;
    return Size;
}

static
BOOLEAN
GetStatus(
    _In_ HANDLE File,
    _Out_ PNITROFW_STATUS Status)
{
    NTSTATUS NtStatus;

    RtlZeroMemory(Status, sizeof(*Status));
    NtStatus = FwIoctl(File, IOCTL_NITROFW_GET_STATUS, NULL, 0, Status, sizeof(*Status));
    ok_hex(NtStatus, STATUS_SUCCESS);
    return NT_SUCCESS(NtStatus);
}

/* A listener on loopback and a connection to it: loopback passes whatever the policy says */
static
VOID
TestLoopbackPasses(VOID)
{
    SOCKET Listener, Client;
    struct sockaddr_in Address;
    int Length = sizeof(Address);
    ULONG Mode = 1;

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    RtlZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) == 0, "bind failed %d\n", WSAGetLastError());
    ok(listen(Listener, 1) == 0, "listen failed %d\n", WSAGetLastError());
    ok(getsockname(Listener, (struct sockaddr *)&Address, &Length) == 0, "getsockname failed\n");
    ioctlsocket(Client, FIONBIO, &Mode);
    connect(Client, (struct sockaddr *)&Address, sizeof(Address));
    {
        fd_set Write;
        struct timeval Timeout = { 5, 0 };
        FD_ZERO(&Write);
        FD_SET(Client, &Write);
        ok(select(0, NULL, &Write, NULL, &Timeout) == 1, "a loopback connect does not complete under a block policy\n");
    }
    closesocket(Client);
    closesocket(Listener);
}

static
VOID
RestartService(VOID)
{
    SC_HANDLE Manager, Service;
    SERVICE_STATUS ServiceStatus;
    ULONG i;

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Manager)
        return;
    Service = OpenServiceW(Manager, L"mpssvc", SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (Service)
    {
        /* A stopped service clears the policy, a started one pushes what the registry holds again */
        ControlService(Service, SERVICE_CONTROL_STOP, &ServiceStatus);
        for (i = 0; i < 50 && QueryServiceStatus(Service, &ServiceStatus) &&
                    ServiceStatus.dwCurrentState != SERVICE_STOPPED; i++)
            Sleep(100);
        StartServiceW(Service, 0, NULL);
        CloseServiceHandle(Service);
    }
    CloseServiceHandle(Manager);
}

START_TEST(nitrofw)
{
    HANDLE File;
    NTSTATUS Status;
    NITROFW_VERSION_INFO Version;
    NITROFW_STATUS Info, Before;
    static UCHAR Blob[4096];
    ULONG Size;
    ULONGLONG Generation;
    WSADATA WsaData;
    PNITROFW_POLICY Policy = (PNITROFW_POLICY)Blob;

    Status = FwOpen(&File);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        skip("the firewall filter is not loaded (boot option /NOFIREWALL)\n");
        return;
    }
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    WSAStartup(MAKEWORD(2, 2), &WsaData);

    /* the version */
    RtlZeroMemory(&Version, sizeof(Version));
    Status = FwIoctl(File, IOCTL_NITROFW_GET_VERSION, NULL, 0, &Version, sizeof(Version));
    ok_hex(Status, STATUS_SUCCESS);
    ok_int(Version.AbiVersion, NITROFW_ABI_VERSION);
    ok((Version.Features & NITROFW_FEATURE_INBOUND) != 0, "no inbound filtering: features %lx\n", Version.Features);
    ok_int(Version.MaxRules, NITROFW_MAX_RULES);

    /* the policy that is in force now (the service's), to be told apart from ours */
    GetStatus(File, &Before);
    Generation = max(Before.Generation, TEST_GENERATION_BASE) + 1;

    /* a policy with one allow rule: accepted, reported, enforcing (enabled profile, flag set) */
    Size = BuildPolicy(Blob, Generation, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL);
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status) && GetStatus(File, &Info))
    {
        ok(Info.Generation == Generation, "generation %I64x, expected %I64x\n", Info.Generation, Generation);
        ok_int(Info.RuleCount, 1);
        ok_hex(Info.ActiveProfiles, NITROFW_PROFILE_ALL);
        ok((Info.Flags & NITROFW_POLICY_ENFORCE) != 0, "flags %lx\n", Info.Flags);
        ok((Info.KernelState & NITROFW_KSTATE_ENFORCING) != 0, "not enforcing: state %lx\n", Info.KernelState);
    }
    TestLoopbackPasses();

    /* a generation that is not larger is rejected and changes nothing */
    Size = BuildPolicy(Blob, Generation, NITROFW_POLICY_ENFORCE, 0, NITROFW_IFTYPE_ALL);
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_REVISION_MISMATCH);
    if (GetStatus(File, &Info))
    {
        ok(Info.Generation == Generation, "generation %I64x after a stale push\n", Info.Generation);
        ok_int(Info.RuleCount, 1);
    }

    /* invalid blobs: the old policy stays */
    Size = BuildPolicy(Blob, Generation + 1, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL);
    Policy->Magic ^= 1;
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    Size = BuildPolicy(Blob, Generation + 1, NITROFW_POLICY_ENFORCE, 1, 0);        /* no interface type */
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    Size = BuildPolicy(Blob, Generation + 1, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL | 0x100);
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    Size = BuildPolicy(Blob, Generation + 1, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL);
    Policy->TotalSize = Size + 8;                                                  /* longer than the input */
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    Size = BuildPolicy(Blob, Generation + 1, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL);
    ((PNITROFW_RULE)(Blob + sizeof(NITROFW_POLICY)))->LocalPortOffset = Size;     /* list outside the rule */
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    Size = BuildPolicy(Blob, Generation + 1, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL);
    ((PNITROFW_RULE)(Blob + sizeof(NITROFW_POLICY)))->IcmpCount = 1;               /* ICMP entries, protocol TCP */
    ((PNITROFW_RULE)(Blob + sizeof(NITROFW_POLICY)))->IcmpOffset = sizeof(NITROFW_RULE);
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);

    Size = BuildPolicy(Blob, NITROFW_MAX_GENERATION + 1, NITROFW_POLICY_ENFORCE, 0, NITROFW_IFTYPE_ALL);
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok(Status == STATUS_INVALID_PARAMETER || Status == STATUS_REVISION_MISMATCH, "a generation past the limit: %lx\n", Status);

    if (GetStatus(File, &Info))
    {
        ok(Info.Generation == Generation, "generation %I64x after invalid pushes\n", Info.Generation);
        ok_int(Info.RuleCount, 1);
    }

    /* observe only: nothing is dropped */
    Size = BuildPolicy(Blob, Generation + 2, 0, 1, NITROFW_IFTYPE_ALL);
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (GetStatus(File, &Info))
        ok((Info.KernelState & NITROFW_KSTATE_ENFORCING) == 0, "enforcing without the flag: state %lx\n", Info.KernelState);

    /* every profile off: nothing is dropped either */
    Size = BuildPolicy(Blob, Generation + 3, NITROFW_POLICY_ENFORCE, 1, NITROFW_IFTYPE_ALL);
    Policy->Profile[0].Flags = Policy->Profile[1].Flags = Policy->Profile[2].Flags = 0;
    Status = FwIoctl(File, IOCTL_NITROFW_SET_POLICY, Blob, Size, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (GetStatus(File, &Info))
        ok((Info.KernelState & NITROFW_KSTATE_ENFORCING) == 0, "enforcing with no enabled profile: state %lx\n", Info.KernelState);

    /* the policy is taken away */
    Status = FwIoctl(File, IOCTL_NITROFW_CLEAR_POLICY, NULL, 0, NULL, 0);
    ok_hex(Status, STATUS_SUCCESS);
    if (GetStatus(File, &Info))
    {
        ok(Info.Generation == 0, "generation %I64x after clear\n", Info.Generation);
        ok_int(Info.RuleCount, 0);
        ok((Info.KernelState & NITROFW_KSTATE_ENFORCING) == 0, "enforcing after clear: state %lx\n", Info.KernelState);
    }

    NtClose(File);
    WSACleanup();

    /* the service's policy is back as the registry holds it */
    RestartService();
}
