/*
 * PROJECT:     ReactOS WinSock 2.2 Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Whether the stack has IPv6 on, and which addresses it has (for getaddrinfo)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ws2_32.h>

#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <tdiinfo.h>
#include <tcpioctl.h>

/*
 * tcpip.sys answers IP_IPV6_TABLE_ENTRY_ID: the IPv6 switch (Tcpip\Parameters\Ipv6Enable) as it was when the stack
 * started, the interfaces and their IPv6 addresses. A stack that does not know the request, or any failure, counts
 * as IPv6 off, and getaddrinfo then answers as it does on a system without IPv6.
 */

/* 0 = not asked yet, 1 = off, 2 = on. The switch is read once by the stack when it starts, so a definite answer
   holds for the life of the process */
static volatile LONG WsIpv6Known;

static
NTSTATUS
WsQueryIpv6Table(PHANDLE File, PVOID Buffer, ULONG BufferLength, PULONG Information)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    TCP_REQUEST_QUERY_INFORMATION_EX Request;
    NTSTATUS Status;

    if (*File == NULL)
    {
        InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(File, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(Status))
        {
            *File = NULL;
            return Status;
        }
    }

    RtlZeroMemory(&Request, sizeof(Request));
    Request.ID.toi_class = INFO_CLASS_PROTOCOL;
    Request.ID.toi_type = INFO_TYPE_PROVIDER;
    Request.ID.toi_id = IP_IPV6_TABLE_ENTRY_ID;
    Request.ID.toi_entity.tei_entity = CL_NL_ENTITY;
    Request.ID.toi_entity.tei_instance = 0;

    Status = NtDeviceIoControlFile(*File, NULL, NULL, NULL, &Iosb, IOCTL_TCP_QUERY_INFORMATION_EX,
                                   &Request, sizeof(Request), Buffer, BufferLength);
    if (Status == STATUS_PENDING)
    {
        Status = NtWaitForSingleObject(*File, FALSE, NULL);
        if (NT_SUCCESS(Status))
            Status = Iosb.Status;
    }
    *Information = (ULONG)Iosb.Information;
    return Status;
}

/*
 * TRUE when the stack has IPv6 on. With Info, the addresses it has (the interface that carries them is not
 * needed here): Info->NonLoopback counts the addresses that can be used as a source (preferred or deprecated,
 * not tentative) on a non-loopback interface. It is 0 when the stack could not be asked. A token that is
 * denied the device is cached as "off" for the life of the process.
 */
BOOL
WsQueryIpv6(PWS_IPV6_INFO Info)
{
    HANDLE File = NULL;
    PTCP_IPV6_TABLE_HEADER Header;
    PTCP_IPV6_INTERFACE_ROW Interfaces;
    PTCP_IPV6_ADDRESS_ROW Addresses;
    TCP_IPV6_TABLE_HEADER Small;
    PUCHAR Blob = NULL;
    ULONG Size = 0, Got, Tries, i, k;
    NTSTATUS Status;
    BOOL Result = FALSE;
    LONG Known = WsIpv6Known;

    if (Info)
        RtlZeroMemory(Info, sizeof(*Info));

    if (Known == 1)
        return FALSE;
    if (Known == 2 && !Info)
        return TRUE;

    /* The size of the answer first (the table is the same, or longer, the next time) */
    RtlZeroMemory(&Small, sizeof(Small));
    Status = WsQueryIpv6Table(&File, &Small, sizeof(Small), &Got);
    if (!NT_SUCCESS(Status))
    {
        /* A token that may not open the device (sandboxed, restricted) cannot be asked the next time either:
           decide once, as off, instead of retrying the open on every call */
        if (!File && Status == STATUS_ACCESS_DENIED && Known == 0)
            InterlockedExchange(&WsIpv6Known, 1);
        goto Done;
    }
    /* Off is the header alone, with Enabled 0: anything longer did not fit and is only a size */
    if (Got == sizeof(*Header) && Small.Enabled == 0)
    {
        InterlockedExchange(&WsIpv6Known, 1);
        goto Done;
    }

    for (Tries = 0; Tries < 4; Tries++)
    {
        Size = Got;
        if (Size < sizeof(*Header) || Size > 0x100000)
            goto Done;

        Blob = HeapAlloc(WsSockHeap, 0, Size);
        if (!Blob)
            goto Done;

        Status = WsQueryIpv6Table(&File, Blob, Size, &Got);
        if (!NT_SUCCESS(Status))
            goto Done;
        if (Got <= Size)
            break;

        /* it grew while we asked */
        HeapFree(WsSockHeap, 0, Blob);
        Blob = NULL;
    }
    if (!Blob || Got > Size || Got < sizeof(*Header))
        goto Done;

    Header = (PTCP_IPV6_TABLE_HEADER)Blob;
    if (!Header->Enabled)
    {
        InterlockedExchange(&WsIpv6Known, 1);
        goto Done;
    }

    InterlockedExchange(&WsIpv6Known, 2);
    Result = TRUE;

    if (Info && Header->InterfaceCount <= 0xFFFF && Header->AddressCount <= 0xFFFF &&
        (SIZE_T)sizeof(*Header) + (SIZE_T)Header->InterfaceCount * sizeof(*Interfaces) +
        (SIZE_T)Header->AddressCount * sizeof(*Addresses) <= Got)
    {
        Interfaces = (PTCP_IPV6_INTERFACE_ROW)(Header + 1);
        Addresses = (PTCP_IPV6_ADDRESS_ROW)(Interfaces + Header->InterfaceCount);

        for (i = 0; i < Header->AddressCount; i++)
        {
            BOOL Loopback = FALSE;

            for (k = 0; k < Header->InterfaceCount; k++)
            {
                if (Interfaces[k].IfIndex == Addresses[i].IfIndex)
                    Loopback = (Interfaces[k].Flags & TCP_IPV6_IF_LOOPBACK) != 0;
            }
            /* NL_DAD_STATE: 3 deprecated, 4 preferred */
            if (Loopback || (Addresses[i].DadState != 3 && Addresses[i].DadState != 4))
                continue;

            Info->NonLoopback++;
        }
    }

Done:
    if (Blob)
        HeapFree(WsSockHeap, 0, Blob);
    if (File)
        NtClose(File);
    return Result;
}
