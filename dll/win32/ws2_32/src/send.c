/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS WinSock 2 API
 * FILE:        dll/win32/ws2_32/src/send.c
 * PURPOSE:     Socket Sending Support.
 * PROGRAMMER:  Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES ******************************************************************/

#include <ws2_32.h>
#include <ws2tcpip.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
INT
WSAAPI
send(IN SOCKET s,
     IN CONST CHAR FAR* buf,
     IN INT len,
     IN INT flags)
{
    PWSSOCKET Socket;
    INT Status;
    INT ErrorCode;
    LPWSATHREADID ThreadId;
    WSABUF Buffers;
    DWORD BytesSent;
    DPRINT("send: %lx, %lx, %lx, %p\n", s, flags, len, buf);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickPrologTid(&ThreadId)) == ERROR_SUCCESS)
    {
        /* Get the Socket Context */
        if ((Socket = WsSockGetSocket(s)))
        {
            /* Setup the buffers */
            Buffers.buf = (PCHAR)buf;
            Buffers.len = len;

            /* Make the call */
            Status = Socket->Provider->Service.lpWSPSend(s,
                                                         &Buffers,
                                                         1,
                                                         &BytesSent,
                                                         (DWORD)flags,
                                                         NULL,
                                                         NULL,
                                                         ThreadId,
                                                         &ErrorCode);
            /* Deference the Socket Context */
            WsSockDereference(Socket);

            /* Return Provider Value */
            if (Status == ERROR_SUCCESS) return BytesSent;

            /* If everything seemed fine, then the WSP call failed itself */
            if (ErrorCode == NO_ERROR) ErrorCode = WSASYSCALLFAILURE;
        }
        else
        {
            /* No Socket Context Found */
            ErrorCode = WSAENOTSOCK;
        }
    }

    /* Return with an Error */
    SetLastError(ErrorCode);
    return SOCKET_ERROR;
}

/*
 * @implemented
 */
INT
WSAAPI
sendto(IN SOCKET s,
       IN CONST CHAR FAR* buf,
       IN INT len,
       IN INT flags,
       IN CONST struct sockaddr *to,
       IN INT tolen)
{
    PWSSOCKET Socket;
    INT Status;
    INT ErrorCode;
    LPWSATHREADID ThreadId;
    WSABUF Buffers;
    DWORD BytesSent;
    DPRINT("sendto: %lx, %lx, %lx, %p\n", s, flags, len, buf);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickPrologTid(&ThreadId)) == ERROR_SUCCESS)
    {
        /* Get the Socket Context */
        if ((Socket = WsSockGetSocket(s)))
        {
            /* A destination shorter than the generic sockaddr cannot hold an address (WSAEFAULT on Windows) */
            if (to && tolen < (INT)sizeof(struct sockaddr))
            {
                WsSockDereference(Socket);
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }

            /* Setup the buffers */
            Buffers.buf = (PCHAR)buf;
            Buffers.len = len;

            /* Make the call */
            Status = Socket->Provider->Service.lpWSPSendTo(s,
                                                           &Buffers,
                                                           1,
                                                           &BytesSent,
                                                           (DWORD)flags,
                                                           to,
                                                           tolen,
                                                           NULL,
                                                           NULL,
                                                           ThreadId,
                                                           &ErrorCode);
            /* Deference the Socket Context */
            WsSockDereference(Socket);

            /* Return Provider Value */
            if (Status == ERROR_SUCCESS) return BytesSent;

            /* If everything seemed fine, then the WSP call failed itself */
            if (ErrorCode == NO_ERROR) ErrorCode = WSASYSCALLFAILURE;
        }
        else
        {
            /* No Socket Context Found */
            ErrorCode = WSAENOTSOCK;
        }
    }

    /* Return with an Error */
    SetLastError(ErrorCode);
    return SOCKET_ERROR;
}

/*
 * @implemented
 */
INT
WSAAPI
WSASend(IN SOCKET s,
        IN LPWSABUF lpBuffers,
        IN DWORD dwBufferCount,
        OUT LPDWORD lpNumberOfBytesSent,
        IN DWORD dwFlags,
        IN LPWSAOVERLAPPED lpOverlapped,
        IN LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    PWSSOCKET Socket;
    INT Status;
    INT ErrorCode;
    LPWSATHREADID ThreadId;
    DPRINT("WSASend: %lx, %lx, %lx, %p\n", s, dwFlags, dwBufferCount, lpBuffers);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickPrologTid(&ThreadId)) == ERROR_SUCCESS)
    {
        /* Get the Socket Context */
        if ((Socket = WsSockGetSocket(s)))
        {
            /* Make the call */
            Status = Socket->Provider->Service.lpWSPSend(s,
                                                         lpBuffers,
                                                         dwBufferCount,
                                                         lpNumberOfBytesSent,
                                                         dwFlags,
                                                         lpOverlapped,
                                                         lpCompletionRoutine,
                                                         ThreadId,
                                                         &ErrorCode);
            /* Deference the Socket Context */
            WsSockDereference(Socket);

            /* Return Provider Value */
            if (Status == ERROR_SUCCESS) return Status;

            /* If everything seemed fine, then the WSP call failed itself */
            if (ErrorCode == NO_ERROR) ErrorCode = WSASYSCALLFAILURE;
        }
        else
        {
            /* No Socket Context Found */
            ErrorCode = WSAENOTSOCK;
        }
    }

    /* Return with an Error */
    SetLastError(ErrorCode);
    return SOCKET_ERROR;
}

/*
 * @implemented
 */
INT
WSAAPI
WSASendDisconnect(IN SOCKET s,
                  IN LPWSABUF lpOutboundDisconnectData)
{
    PWSPROCESS Process;
    PWSTHREAD Thread;
    PWSSOCKET Socket;
    INT ErrorCode;
    INT Status;
    DPRINT("WSASendDisconnect: %lx %p\n", s, lpOutboundDisconnectData);

    /* Enter prolog */
    if ((ErrorCode = WsApiProlog(&Process, &Thread)) == ERROR_SUCCESS)
    {
        /* Get the Socket Context */
        if ((Socket = WsSockGetSocket(s)))
        {
            /* Make the call */
            Status = Socket->Provider->Service.lpWSPSendDisconnect(s,
                                                                   lpOutboundDisconnectData,
                                                                   &ErrorCode);
            /* Deference the Socket Context */
            WsSockDereference(Socket);

            /* Return Provider Value */
            if (Status == ERROR_SUCCESS) return ERROR_SUCCESS;

            /* If everything seemed fine, then the WSP call failed itself */
            if (ErrorCode == NO_ERROR) ErrorCode = WSASYSCALLFAILURE;
        }
        else
        {
            /* No Socket Context Found */
            ErrorCode = WSAENOTSOCK;
        }
    }

    /* Return with an Error */
    SetLastError(ErrorCode);
    return SOCKET_ERROR;
}


/*
 * Checks the ancillary data of WSASendMsg. A buffer and a length go together, and every header fits. On an
 * IPv4 socket the level is IP and the type one of those Windows knows, with a payload of the size that type
 * needs (measured on Windows Server 2008 R2 and Windows 10, which also know more types): options (1), type of
 * service (3), do not fragment (14), packet information (19), time to live (21) and routing header (32).
 * Neither AFD nor the TCP/IP driver has an interface for per-message options, so a request that is well
 * formed is refused with WSAEOPNOTSUPP, except for packet information that asks for what the socket does
 * anyway (its own bound address, any interface), instead of being dropped without its effect.
 *
 * Two more that Rust's quinn-udp (Firefox HTTP/3) puts on its datagrams are carried out or ignored, as it
 * cannot work without: UDP_SEND_MSG_SIZE (level UDP, type 2, a segment size; the datagram is sent as several
 * of that size, see WSASendMsg) and IP_ECN (type 50, 0 to 3 on Windows 10, anything else is invalid). The
 * ECN codepoint cannot be put into the IP header: the packet goes out Not-ECT, which QUIC's ECN validation
 * treats as a path that does not carry ECN.
 */
#define WS_CMSG_IP_OPTIONS       1
#define WS_CMSG_IP_TOS           3
#define WS_CMSG_IP_DONTFRAGMENT 14
#define WS_CMSG_IP_PKTINFO      19
#define WS_CMSG_IP_TTL          21
#define WS_CMSG_IP_RTHDR        32
#define WS_CMSG_IP_ECN          50
#define WS_CMSG_UDP_SEND_MSG_SIZE 2

/* Not inlined: inside the SEH frame of WSASendMsg the i386 optimizer lost the result of the loop */
static
DECLSPEC_NOINLINE
INT
WsCheckSendMsgControl(IN PWSSOCKET Socket,
                      IN SOCKET Handle,
                      IN INT SocketType,
                      IN LPWSABUF Control,
                      OUT PULONG SegmentSize)
{
    PUCHAR Cursor = (PUCHAR)Control->buf;
    ULONG Remaining = Control->len;
    LPWSACMSGHDR Header;
    ULONGLONG Step;
    INT Family = Socket->CatalogEntry->ProtocolInfo.iAddressFamily;
    BOOLEAN Unsupported = FALSE;

    *SegmentSize = 0;

    if ((Control->buf == NULL) != (Control->len == 0))
        return WSAEFAULT;

    /* A malformed header anywhere is reported before the refusal of a well formed request: the refusal is only the result at the end */
    while (Remaining)
    {
        ULONG Payload;

        if (Remaining < sizeof(WSACMSGHDR))
            return WSAEINVAL;

        Header = (LPWSACMSGHDR)Cursor;
        if (Header->cmsg_len < sizeof(WSACMSGHDR) || Header->cmsg_len > Remaining)
            return WSAEINVAL;
        Payload = (ULONG)(Header->cmsg_len - sizeof(WSACMSGHDR));

        if (Family == AF_INET && Header->cmsg_level == IPPROTO_UDP)
        {
            /* A segment size: the only message of this level, for a datagram socket */
            if (Header->cmsg_type != WS_CMSG_UDP_SEND_MSG_SIZE || SocketType != SOCK_DGRAM ||
                Payload < sizeof(ULONG))
                return WSAEINVAL;
            *SegmentSize = *(UNALIGNED ULONG *)WSA_CMSG_DATA(Header);
        }
        else if (Family == AF_INET)
        {
            if (Header->cmsg_level != IPPROTO_IP)
                return WSAEINVAL;

            switch (Header->cmsg_type)
            {
                case WS_CMSG_IP_OPTIONS:
                    if (Payload == 1)
                        return WSAEINVAL;
                    Unsupported = TRUE;
                    break;
                case WS_CMSG_IP_TOS:
                case WS_CMSG_IP_DONTFRAGMENT:
                case WS_CMSG_IP_TTL:
                    if (Payload < sizeof(INT))
                        return WSAEINVAL;
                    Unsupported = TRUE;
                    break;
                case WS_CMSG_IP_PKTINFO:
                {
                    IN_PKTINFO *Info = (IN_PKTINFO *)WSA_CMSG_DATA(Header);
                    SOCKADDR_IN Local;
                    INT LocalLength = sizeof(Local), LocalError = NO_ERROR;

                    if (Payload < sizeof(IN_PKTINFO))
                        return WSAEINVAL;

                    /* No source and no interface asks for nothing at all, which Windows refuses */
                    if (Info->ipi_addr.s_addr == 0 && Info->ipi_ifindex == 0)
                        return WSAEINVAL;

                    if (Info->ipi_ifindex != 0 ||
                        Socket->Provider->Service.lpWSPGetSockName(Handle, (LPSOCKADDR)&Local, &LocalLength, &LocalError) ||
                        Local.sin_family != AF_INET || Local.sin_addr.s_addr != Info->ipi_addr.s_addr)
                    {
                        Unsupported = TRUE;
                    }
                    break;
                }
                case WS_CMSG_IP_ECN:
                    if (Payload < sizeof(INT) || *(UNALIGNED ULONG *)WSA_CMSG_DATA(Header) > 3)
                        return WSAEINVAL;
                    break;
                case WS_CMSG_IP_RTHDR:
                    if (Payload != 0)
                        return WSAEINVAL;
                    Unsupported = TRUE;
                    break;
                default:
                    return WSAEINVAL;
            }
        }
        else
        {
            /* Other families: the form is checked, the requests cannot be carried out */
            if (Header->cmsg_level != IPPROTO_IP && Header->cmsg_level != IPPROTO_IPV6)
                return WSAEINVAL;
            Unsupported = TRUE;
        }

        Step = ((ULONGLONG)Header->cmsg_len + TYPE_ALIGNMENT(WSACMSGHDR) - 1) & ~((ULONGLONG)TYPE_ALIGNMENT(WSACMSGHDR) - 1);
        if (Step >= Remaining)
            break;
        Cursor += Step;
        Remaining -= (ULONG)Step;
    }

    return Unsupported ? WSAEOPNOTSUPP : NO_ERROR;
}

/* The largest datagram of an IPv4 UDP socket, and of an IPv4 raw socket (an IPv4 header of 20 bytes is added to it) */
#define WS_MAX_UDP_PAYLOAD 65507
#define WS_MAX_RAW_PAYLOAD 65515

typedef struct _WS_SENDMSG_APC
{
    LPWSAOVERLAPPED_COMPLETION_ROUTINE Routine;
    LPWSAOVERLAPPED Overlapped;
    DWORD Bytes;
} WS_SENDMSG_APC, *PWS_SENDMSG_APC;

static
VOID
NTAPI
WsSendMsgApc(IN ULONG_PTR Parameter)
{
    PWS_SENDMSG_APC Apc = (PWS_SENDMSG_APC)Parameter;
    WS_SENDMSG_APC Copy = *Apc;

    HeapFree(GetProcessHeap(), 0, Apc);
    Copy.Routine(NO_ERROR, Copy.Bytes, Copy.Overlapped, 0);
}

/*
 * The overlapped structure must be writable before anything is sent: the provider acquires resources
 * for the request first and cannot release them when its own write to the structure faults.
 */
static
BOOLEAN
WsProbeOverlapped(IN LPWSAOVERLAPPED Overlapped)
{
    BOOLEAN Writable = TRUE;

    _SEH2_TRY
    {
        volatile UCHAR *Bytes = (volatile UCHAR *)Overlapped;

        Bytes[0] = Bytes[0];
        Bytes[sizeof(*Overlapped) - 1] = Bytes[sizeof(*Overlapped) - 1];
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Writable = FALSE;
    }
    _SEH2_END;

    return Writable;
}

/*
 * A request with an overlapped structure on a socket that was not opened as overlapped is sent at once; the structure
 * is then completed here, as Windows does for it: the byte count, and the completion routine when there is one, else
 * the event (the event is ignored when a routine is given). The context of the routine is reserved before the
 * datagram is sent, so that the completion cannot be lost afterwards.
 */
static
VOID
WsCompleteInlineSend(IN LPWSAOVERLAPPED Overlapped,
                     IN PWS_SENDMSG_APC Apc,
                     IN DWORD Bytes)
{
    Overlapped->Internal = 0;
    Overlapped->InternalHigh = Bytes;

    if (!Apc)
    {
        if (Overlapped->hEvent)
            SetEvent((HANDLE)((ULONG_PTR)Overlapped->hEvent & ~(ULONG_PTR)1));
        return;
    }

    Apc->Overlapped = Overlapped;
    Apc->Bytes = Bytes;
    /* The datagram is gone: a routine that cannot be queued runs here rather than never */
    if (!QueueUserAPC(WsSendMsgApc, GetCurrentThread(), (ULONG_PTR)Apc))
        WsSendMsgApc((ULONG_PTR)Apc);
}

/*
 * Windows binds an unbound IPv4 socket to a wildcard address and port at the start of WSASendMsg, so that the
 * socket is bound also when the call then fails (the winetest sock test expects it).
 */
static
VOID
WsBindForSendMsg(IN PWSSOCKET Socket,
                 IN SOCKET Handle)
{
    SOCKADDR_IN Local;
    INT LocalLength = sizeof(Local), LocalError = NO_ERROR;

    if (Socket->CatalogEntry->ProtocolInfo.iAddressFamily != AF_INET)
        return;

    if (Socket->Provider->Service.lpWSPGetSockName(Handle, (LPSOCKADDR)&Local, &LocalLength, &LocalError) &&
        LocalError == WSAEINVAL)
    {
        RtlZeroMemory(&Local, sizeof(Local));
        Local.sin_family = AF_INET;
        Socket->Provider->Service.lpWSPBind(Handle, (LPSOCKADDR)&Local, sizeof(Local), &LocalError);
    }
}

/*
 * @implemented
 *
 * Only datagram and raw sockets, as on Windows. The message is sent with the
 * provider's send or send-to call. Ancillary data is checked but not applied.
 *
 * AFD sends only the first buffer of a datagram, so a synchronous send of a
 * message with several buffers gathers them into one here. An overlapped one
 * on an overlapped socket would need the gathered storage to outlive the call;
 * that is not supported and fails with WSAEOPNOTSUPP instead of losing data.
 * On a socket that was not opened as overlapped the send is done at once and the
 * overlapped structure completed here, as Windows does.
 */
INT
WSAAPI
WSASendMsg(IN SOCKET s,
           IN LPWSAMSG lpMsg,
           IN DWORD dwFlags,
           OUT LPDWORD lpNumberOfBytesSent,
           IN LPWSAOVERLAPPED lpOverlapped,
           IN LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    PWSSOCKET Socket;
    INT Status;
    INT ErrorCode;
    INT SocketType = 0;
    INT OptionLength;
    LPWSATHREADID ThreadId;
    WSAMSG Msg;
    SOCKADDR_STORAGE Name;
    WSABUF Single;
    LPWSABUF SendBuffers = NULL;
    LPWSABUF volatile Snapshot = NULL;
    DWORD volatile Sent = 0;
    DWORD Index;
    ULONGLONG Total = 0;
    PCHAR volatile Gathered = NULL;
    PWS_SENDMSG_APC volatile CompletionApc = NULL;
    BOOLEAN Inline;
    ULONG SegmentSize = 0;
    BOOLEAN Segmented = FALSE;
    DPRINT("WSASendMsg: %lx, %p, %lx\n", s, lpMsg, dwFlags);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickPrologTid(&ThreadId)) != ERROR_SUCCESS)
        goto Fail;

    if (!lpMsg)
    {
        ErrorCode = WSAEFAULT;
        goto Fail;
    }

    /* Get the Socket Context */
    if (!(Socket = WsSockGetSocket(s)))
    {
        ErrorCode = WSAENOTSOCK;
        goto Fail;
    }

    /* A socket that was not opened as overlapped sends at once; the overlapped structure is completed here */
    Inline = (lpOverlapped && !Socket->Overlapped);

    ErrorCode = NO_ERROR;
    _SEH2_TRY
    {
        /* The caller's memory is read once; the checks below use the copy */
        Msg = *lpMsg;

        if (!Msg.lpBuffers || !Msg.dwBufferCount)
        {
            ErrorCode = WSAEINVAL;
        }
        else if (Msg.dwBufferCount > MAXLONG / sizeof(WSABUF))
        {
            ErrorCode = WSAENOBUFS;
        }
        else
        {
            /* The descriptors are copied, so that the caller cannot change them between the checks and the use */
            Snapshot = HeapAlloc(GetProcessHeap(), 0, Msg.dwBufferCount * sizeof(WSABUF));
            if (!Snapshot)
            {
                ErrorCode = WSAENOBUFS;
            }
            else
            {
                RtlCopyMemory(Snapshot, Msg.lpBuffers, Msg.dwBufferCount * sizeof(WSABUF));
                Msg.lpBuffers = Snapshot;
                for (Index = 0; Index < Msg.dwBufferCount; Index++)
                {
                    if (!Msg.lpBuffers[Index].buf && Msg.lpBuffers[Index].len)
                    {
                        ErrorCode = WSAEFAULT;
                        break;
                    }
                    Total += Msg.lpBuffers[Index].len;
                }
            }
        }

        if (ErrorCode == NO_ERROR && (dwFlags & ~(MSG_OOB | MSG_DONTROUTE | MSG_PARTIAL)))
            ErrorCode = WSAEOPNOTSUPP;

        if (ErrorCode == NO_ERROR)
        {
            OptionLength = sizeof(SocketType);
            if (Socket->Provider->Service.lpWSPGetSockOpt(s, SOL_SOCKET, SO_TYPE, (PCHAR)&SocketType, &OptionLength, &ErrorCode))
            {
                if (ErrorCode == NO_ERROR) ErrorCode = WSASYSCALLFAILURE;
            }
            else if (SocketType != SOCK_DGRAM && SocketType != SOCK_RAW)
            {
                ErrorCode = WSAEINVAL;
            }
            else if (Total > MAXLONG ||
                     (Socket->CatalogEntry->ProtocolInfo.iAddressFamily == AF_INET &&
                      Total > (SocketType == SOCK_DGRAM ? WS_MAX_UDP_PAYLOAD : WS_MAX_RAW_PAYLOAD)))
            {
                ErrorCode = WSAEMSGSIZE;
            }
        }

        /* The destination: required unless the socket is connected, and of the socket's address family */
        if (ErrorCode == NO_ERROR)
        {
            if (Msg.name)
            {
                INT ExpectedLength;

                if (Msg.namelen < (INT)sizeof(Msg.name->sa_family) || Msg.namelen > (INT)sizeof(Name))
                {
                    ErrorCode = WSAEFAULT;
                }
                else
                {
                    /* The provider gets a copy that cannot fault half way */
                    RtlCopyMemory(&Name, Msg.name, Msg.namelen);
                    Msg.name = (LPSOCKADDR)&Name;

                    if (Msg.name->sa_family != Socket->CatalogEntry->ProtocolInfo.iAddressFamily)
                    {
                        ErrorCode = WSAEAFNOSUPPORT;
                    }
                    else
                    {
                        switch (Msg.name->sa_family)
                        {
                            case AF_INET:
                                ExpectedLength = sizeof(SOCKADDR_IN);
                                break;
                            case AF_INET6:
                                ExpectedLength = sizeof(SOCKADDR_IN6);
                                break;
                            default:
                                ExpectedLength = sizeof(SOCKADDR);
                                break;
                        }
                        if (Msg.namelen != ExpectedLength)
                            ErrorCode = WSAEFAULT;
                    }
                }
            }
            else if (Msg.namelen)
            {
                ErrorCode = WSAEFAULT;
            }
            else
            {
                SOCKADDR_STORAGE Peer;
                INT PeerLength = sizeof(Peer);
                INT PeerError = NO_ERROR;

                /* Without a destination the socket must have a peer */
                if (Socket->Provider->Service.lpWSPGetPeerName(s, (LPSOCKADDR)&Peer, &PeerLength, &PeerError))
                {
                    if (PeerError == WSAENOTCONN)
                        ErrorCode = WSAEINVAL;
                    else
                        ErrorCode = (PeerError != NO_ERROR) ? PeerError : WSASYSCALLFAILURE;
                }
            }
        }

        if (ErrorCode == NO_ERROR)
            ErrorCode = WsCheckSendMsgControl(Socket, s, SocketType, &Msg.Control, &SegmentSize);

        /* A segment size smaller than the message splits it into datagrams of that size (the last one is smaller) */
        if (ErrorCode == NO_ERROR && SegmentSize && Total > SegmentSize)
        {
            Segmented = TRUE;
            if (lpOverlapped && !Inline)
                ErrorCode = WSAEOPNOTSUPP;
        }

        /* A synchronous send has to report its byte count */
        if (ErrorCode == NO_ERROR && !lpNumberOfBytesSent && !lpOverlapped)
        {
            ErrorCode = WSAEFAULT;
            WsBindForSendMsg(Socket, s);
        }

        /* The structure is probed here, not by the provider */
        if (ErrorCode == NO_ERROR && lpOverlapped && !WsProbeOverlapped(lpOverlapped))
            ErrorCode = WSAEFAULT;

        /* The completion of a send that is done here needs its context before anything is sent */
        if (ErrorCode == NO_ERROR && Inline && lpCompletionRoutine)
        {
            CompletionApc = HeapAlloc(GetProcessHeap(), 0, sizeof(*CompletionApc));
            if (!CompletionApc)
                ErrorCode = WSAENOBUFS;
            else
                CompletionApc->Routine = lpCompletionRoutine;
        }

        /* One buffer goes to the provider as it is; several are gathered */
        if (ErrorCode == NO_ERROR)
        {
            if (Msg.dwBufferCount == 1)
            {
                SendBuffers = Msg.lpBuffers;
            }
            else if (lpOverlapped && !Inline)
            {
                ErrorCode = WSAEOPNOTSUPP;
            }
            else
            {
                if (Total)
                {
                    Gathered = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Total);
                    if (!Gathered)
                    {
                        ErrorCode = WSAENOBUFS;
                    }
                    else
                    {
                        PCHAR Cursor = Gathered;

                        for (Index = 0; Index < Msg.dwBufferCount; Index++)
                        {
                            RtlCopyMemory(Cursor, Msg.lpBuffers[Index].buf, Msg.lpBuffers[Index].len);
                            Cursor += Msg.lpBuffers[Index].len;
                        }
                    }
                }
                Single.buf = Gathered;
                Single.len = (ULONG)Total;
                SendBuffers = &Single;
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ErrorCode = WSAEFAULT;
    }
    _SEH2_END;

    if (ErrorCode == NO_ERROR)
    {
        Status = SOCKET_ERROR;
        _SEH2_TRY
        {
            ULONG Offset = 0;
            WSABUF Segment;
            DWORD SentNow;

            Sent = 0;
            do
            {
                LPWSABUF Buffers = SendBuffers;

                SentNow = 0;
                if (Segmented)
                {
                    Segment.buf = SendBuffers->buf + Offset;
                    Segment.len = (ULONG)min((ULONGLONG)SegmentSize, Total - Offset);
                    Buffers = &Segment;
                }

                if (Msg.name)
                {
                    Status = Socket->Provider->Service.lpWSPSendTo(s,
                                                                   Buffers,
                                                                   1,
                                                                   &SentNow,
                                                                   dwFlags,
                                                                   Msg.name,
                                                                   Msg.namelen,
                                                                   Inline ? NULL : lpOverlapped,
                                                                   Inline ? NULL : lpCompletionRoutine,
                                                                   ThreadId,
                                                                   &ErrorCode);
                }
                else
                {
                    Status = Socket->Provider->Service.lpWSPSend(s,
                                                                 Buffers,
                                                                 1,
                                                                 &SentNow,
                                                                 dwFlags,
                                                                 Inline ? NULL : lpOverlapped,
                                                                 Inline ? NULL : lpCompletionRoutine,
                                                                 ThreadId,
                                                                 &ErrorCode);
                }

                if (Status != ERROR_SUCCESS)
                    break;
                Sent += SentNow;
                Offset += SentNow;
            } while (Segmented && Offset < Total);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Bad overlapped storage or buffer memory: the provider touches them directly */
            Status = SOCKET_ERROR;
            ErrorCode = WSAEFAULT;
        }
        _SEH2_END;

        if (Gathered)
            HeapFree(GetProcessHeap(), 0, Gathered);
        if (Snapshot)
            HeapFree(GetProcessHeap(), 0, Snapshot);

        /* Deference the Socket Context */
        WsSockDereference(Socket);

        if (Status != ERROR_SUCCESS && CompletionApc)
            HeapFree(GetProcessHeap(), 0, CompletionApc);

        if (Status == ERROR_SUCCESS)
        {
            if (Inline)
                WsCompleteInlineSend(lpOverlapped, CompletionApc, Sent);

            /* The byte count of a send that completed; the provider leaves a failed or pending one alone */
            if (lpNumberOfBytesSent)
            {
                _SEH2_TRY
                {
                    *lpNumberOfBytesSent = Sent;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    ErrorCode = WSAEFAULT;
                    Status = SOCKET_ERROR;
                }
                _SEH2_END;
            }
            if (Status == ERROR_SUCCESS)
                return ERROR_SUCCESS;
        }
        else if (ErrorCode == NO_ERROR)
        {
            /* If everything seemed fine, then the WSP call failed itself */
            ErrorCode = WSASYSCALLFAILURE;
        }
    }
    else
    {
        if (Gathered)
            HeapFree(GetProcessHeap(), 0, Gathered);
        if (Snapshot)
            HeapFree(GetProcessHeap(), 0, Snapshot);
        if (CompletionApc)
            HeapFree(GetProcessHeap(), 0, CompletionApc);
        WsSockDereference(Socket);
    }

Fail:
    /* Return with an Error */
    SetLastError(ErrorCode);
    return SOCKET_ERROR;
}

/*
 * @implemented
 */
INT
WSAAPI
WSASendTo(IN SOCKET s,
          IN LPWSABUF lpBuffers,
          IN DWORD dwBufferCount,
          OUT LPDWORD lpNumberOfBytesSent,
          IN DWORD dwFlags,
          IN CONST struct sockaddr *lpTo,
          IN INT iToLen,
          IN LPWSAOVERLAPPED lpOverlapped,
          IN LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    PWSSOCKET Socket;
    INT Status;
    INT ErrorCode;
    LPWSATHREADID ThreadId;
    DPRINT("WSASendTo: %lx, %lx, %lx, %p\n", s, dwFlags, dwBufferCount, lpBuffers);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickPrologTid(&ThreadId)) == ERROR_SUCCESS)
    {
        /* Get the Socket Context */
        if ((Socket = WsSockGetSocket(s)))
        {
            /* A destination shorter than the generic sockaddr cannot hold an address (WSAEFAULT on Windows) */
            if (lpTo && iToLen < (INT)sizeof(struct sockaddr))
            {
                WsSockDereference(Socket);
                SetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }

            /* Make the call */
            Status = Socket->Provider->Service.lpWSPSendTo(s,
                                                           lpBuffers,
                                                           dwBufferCount,
                                                           lpNumberOfBytesSent,
                                                           dwFlags,
                                                           lpTo,
                                                           iToLen,
                                                           lpOverlapped,
                                                           lpCompletionRoutine,
                                                           ThreadId,
                                                           &ErrorCode);
            /* Deference the Socket Context */
            WsSockDereference(Socket);

            /* Return Provider Value */
            if (Status == ERROR_SUCCESS) return Status;

            /* If everything seemed fine, then the WSP call failed itself */
            if (ErrorCode == NO_ERROR) ErrorCode = WSASYSCALLFAILURE;
        }
        else
        {
            /* No Socket Context Found */
            ErrorCode = WSAENOTSOCK;
        }
    }

    /* Return with an Error */
    SetLastError(ErrorCode);
    return SOCKET_ERROR;
}
