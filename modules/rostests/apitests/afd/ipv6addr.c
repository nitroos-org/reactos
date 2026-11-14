/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     IPv6 transport addresses at AFD, before the stack has IPv6 sockets: an AFD endpoint of the family
 *              AF_INET6 takes a complete TA_IP6_ADDRESS to the transport (which refuses it while it has no IPv6
 *              sockets: a defined error, never success with the switch off), and an address that is not complete
 *              for its type, or longer than what was supplied, is refused by AFD itself.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ws2ipdef.h>
#include <tdiaddr.h>
#include <winreg.h>

static
BOOL
Ipv6SwitchOn(void)
{
    HKEY Key;
    DWORD Type, Value = 0, Size = sizeof(Value);
    BOOL On = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                      0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(Key, L"Ipv6Enable", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Value != 0)
            On = TRUE;
        RegCloseKey(Key);
    }
    return On;
}

static
NTSTATUS
AfdRawIoctl6(
    _In_ HANDLE Socket,
    _In_ ULONG Code,
    _In_opt_ PVOID In,
    _In_ ULONG InLen,
    _In_opt_ PVOID Out,
    _In_ ULONG OutLen)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Event;

    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return Status;

    IoStatus.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(Socket, Event, NULL, NULL, &IoStatus, Code, In, InLen, Out, OutLen);
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(Event, FALSE, NULL);
        Status = IoStatus.Status;
    }

    NtClose(Event);
    return Status;
}

/* The IOCTL_AFD_BIND buffer of an IPv6 address, as msafd sends it */
#define BIND6_LENGTH (FIELD_OFFSET(AFD_BIND_DATA, Address) + TDIADDR_TA_LENGTH_IP6)

static
void
MakeBind6(
    _Out_writes_bytes_(BIND6_LENGTH + 16) PUCHAR Buffer)
{
    SOCKADDR_IN6_LH Sa;
    PAFD_BIND_DATA Bind = (PAFD_BIND_DATA)Buffer;
    ULONG Length;

    memset(Buffer, 0, BIND6_LENGTH + 16);
    memset(&Sa, 0, sizeof(Sa));
    Sa.sin6_family = AF_INET6;
    ((PUCHAR)&Sa.sin6_addr)[15] = 1; /* ::1 */
    Bind->ShareType = AFD_SHARE_UNIQUE;
    Length = TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), &Bind->Address, TDIADDR_TA_LENGTH_IP6);
    ok(Length == TDIADDR_TA_LENGTH_IP6, "the test address: %lu\n", Length);
}

START_TEST(ipv6addr)
{
    NTSTATUS Status;
    HANDLE Socket;
    UCHAR Buffer[BIND6_LENGTH + 16];
    PAFD_BIND_DATA Bind = (PAFD_BIND_DATA)Buffer;
    BOOL On = Ipv6SwitchOn();
    int i;

    trace("IPv6 switch (Tcpip\\Parameters\\Ipv6Enable): %s\n", On ? "on" : "off");

    for (i = 0; i < 2; i++)
    {
        int Type = i ? SOCK_DGRAM : SOCK_STREAM;
        int Proto = i ? IPPROTO_UDP : IPPROTO_TCP;
        const char *Name = i ? "UDP" : "TCP";

        /* A complete address: AFD hands it to the transport. With the switch off the answer is never success
         * (the transport says no: what comes back is a defined error status) */
        Status = AfdCreateSocket(&Socket, AF_INET6, Type, Proto);
        ok(Status == STATUS_SUCCESS, "%s: AfdCreateSocket failed: %lx\n", Name, Status);
        if (!NT_SUCCESS(Status))
            continue;

        MakeBind6(Buffer);
        Status = AfdRawIoctl6(Socket, IOCTL_AFD_BIND, Buffer, BIND6_LENGTH, Buffer, BIND6_LENGTH);
        ok(Status != STATUS_SUCCESS || On, "%s: an IPv6 bind succeeded with the switch off\n", Name);
        trace("%s: IPv6 bind of [::1]:0: %lx\n", Name, Status);
        NtClose(Socket);

        /* An address declared shorter than IPv6 needs: AFD refuses it, whatever the switch says */
        Status = AfdCreateSocket(&Socket, AF_INET6, Type, Proto);
        ok(Status == STATUS_SUCCESS, "%s: AfdCreateSocket failed: %lx\n", Name, Status);
        if (!NT_SUCCESS(Status))
            continue;
        MakeBind6(Buffer);
        Bind->Address.Address[0].AddressLength = 4;
        Status = AfdRawIoctl6(Socket, IOCTL_AFD_BIND, Buffer, BIND6_LENGTH, Buffer, BIND6_LENGTH);
        ok(Status == STATUS_INVALID_PARAMETER, "%s: a 4 byte IPv6 address: %lx\n", Name, Status);
        Bind->Address.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6 - 1;
        Status = AfdRawIoctl6(Socket, IOCTL_AFD_BIND, Buffer, BIND6_LENGTH, Buffer, BIND6_LENGTH);
        ok(Status == STATUS_INVALID_PARAMETER, "%s: a 25 byte IPv6 address: %lx\n", Name, Status);

        /* An address that claims more than the buffer holds */
        MakeBind6(Buffer);
        Bind->Address.Address[0].AddressLength = 0x200;
        Status = AfdRawIoctl6(Socket, IOCTL_AFD_BIND, Buffer, BIND6_LENGTH, Buffer, BIND6_LENGTH);
        ok(Status == STATUS_INVALID_PARAMETER, "%s: an overlong IPv6 address: %lx\n", Name, Status);

        /* A complete address in a buffer that stops short of it */
        MakeBind6(Buffer);
        Status = AfdRawIoctl6(Socket, IOCTL_AFD_BIND, Buffer, BIND6_LENGTH - 1, Buffer, BIND6_LENGTH);
        ok(Status != STATUS_SUCCESS, "%s: an IPv6 address cut short by one byte: %lx\n", Name, Status);
        Status = AfdRawIoctl6(Socket, IOCTL_AFD_BIND, Buffer, FIELD_OFFSET(AFD_BIND_DATA, Address) + 8, Buffer, BIND6_LENGTH);
        ok(Status != STATUS_SUCCESS, "%s: an IPv6 address with only its header: %lx\n", Name, Status);
        NtClose(Socket);
    }
}
