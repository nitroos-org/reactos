/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The IPv6 state the stack reports (tcpip.sys IP_IPV6_TABLE_ENTRY_ID), for the IPv6 socket tests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <tdiinfo.h>
#include <tcpioctl.h>

C_ASSERT(TEST_IPV6_STATE_ON == TCP_IPV6_STATE_ON);
C_ASSERT(TEST_IPV6_STATE_SOCKETS == TCP_IPV6_STATE_SOCKETS);

/* The TCP_IPV6_STATE_ flags of the stack: 0 while IPv6 is off, and when the stack cannot be asked (a stack that
   does not know the request, Windows for one) */
ULONG
Ipv6StackFlags(void)
{
    static UCHAR Answer[0x10000];
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    TCP_REQUEST_QUERY_INFORMATION_EX Request;
    PTCP_IPV6_TABLE_HEADER Header = (PTCP_IPV6_TABLE_HEADER)Answer;
    HANDLE File;
    NTSTATUS Status;
    ULONG Flags = 0;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&File, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
        return 0;

    RtlZeroMemory(&Request, sizeof(Request));
    Request.ID.toi_class = INFO_CLASS_PROTOCOL;
    Request.ID.toi_type = INFO_TYPE_PROVIDER;
    Request.ID.toi_id = IP_IPV6_TABLE_ENTRY_ID;
    Request.ID.toi_entity.tei_entity = CL_NL_ENTITY;
    Request.ID.toi_entity.tei_instance = 0;

    RtlZeroMemory(Answer, sizeof(TCP_IPV6_TABLE_HEADER));
    Iosb.Information = 0;
    Status = NtDeviceIoControlFile(File, NULL, NULL, NULL, &Iosb, IOCTL_TCP_QUERY_INFORMATION_EX,
                                   &Request, sizeof(Request), Answer, sizeof(Answer));
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(File, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (NT_SUCCESS(Status) && Iosb.Information >= sizeof(*Header) && (Header->Enabled & TCP_IPV6_STATE_ON))
        Flags = Header->Enabled;

    NtClose(File);
    return Flags;
}

/* IPv6 sockets are made: the stack has IPv6 on and takes IPv6 addresses for its sockets */
BOOL
Ipv6SocketsOn(void)
{
    ULONG Flags = Ipv6StackFlags();

    return (Flags & TEST_IPV6_STATE_ON) && (Flags & TEST_IPV6_STATE_SOCKETS);
}
