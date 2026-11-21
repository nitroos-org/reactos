/*
 * PROJECT:     ReactOS WinSock 2 API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     WSAConnectByNameA / WSAConnectByNameW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * WSAConnectByName resolves a name and connects the caller's TCP socket to one of its addresses. Windows Server 2022
 * (measured 2026-11-20, a dual-stack name whose IPv6 path is dead) does not wait for one address to time out before it
 * tries the next: it sends one SYN to the first address and, with no answer 300 ms later, a SYN to the next one, and
 * the call returned after 344 ms over IPv4 where connect() to the addresses in turn took 21 s.
 *
 * Here the addresses are tried the same way with sockets of this function's own (non-blocking, the next one started
 * after 300 ms without an answer or at once when one fails), and the caller's socket is then connected to the address
 * that answered first. That first answer comes from such a probe connection, which is closed again: the server sees one
 * short connection more than with Windows, which hands the caller's socket the connection itself. When every other
 * address has failed, the caller's socket goes to the last one directly (no probe).
 *
 * The caller's socket: an AF_INET6 socket is offered IPv4 addresses too (as IPv4-mapped addresses) unless it is
 * IPV6_V6ONLY; an AF_INET socket only IPv4 addresses. timeout bounds the whole call (WSAETIMEDOUT when it runs out);
 * without one each address has the time of the stack's own connection attempt. On success the local and remote
 * addresses are returned when asked for; the caller sets SO_UPDATE_CONNECT_CONTEXT, as the documentation says.
 */

/* INCLUDES ******************************************************************/

#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#include <ws2_32.h>
#include <ws2tcpip.h>

#define NDEBUG
#include <debug.h>

/* inside ws2_32 FreeAddrInfoW is freeaddrinfo (ws2_32.spec, addrinfo.c) */
#define FreeAddrInfoW(a)    freeaddrinfo((LPADDRINFO)(a))

#define CBN_STAGGER_MS  300     /* no answer from an address for this long: the next one is tried as well */
#define CBN_MAX_TRIES   16      /* addresses tried at most (select() set and the work per call stay bounded) */

typedef struct _CBN_TRY
{
    SOCKET Socket;
    SOCKADDR_STORAGE Address;
    int AddressLength;
} CBN_TRY;

/* FUNCTIONS *****************************************************************/

static DWORD CbnLeft(DWORD Start, DWORD Limit)
{
    DWORD Spent = GetTickCount() - Start;

    if (Limit == INFINITE)
        return INFINITE;
    return (Spent >= Limit) ? 0 : Limit - Spent;
}

/* Start a probe connection to Try->Address; FALSE when it failed at once (*Error) */
static BOOL CbnStart(CBN_TRY *Try, int *Error)
{
    u_long NonBlocking = 1;

    Try->Socket = socket(Try->Address.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (Try->Socket == INVALID_SOCKET)
    {
        *Error = WSAGetLastError();
        return FALSE;
    }
    if (ioctlsocket(Try->Socket, FIONBIO, &NonBlocking) == SOCKET_ERROR ||
        (connect(Try->Socket, (SOCKADDR *)&Try->Address, Try->AddressLength) == SOCKET_ERROR &&
         WSAGetLastError() != WSAEWOULDBLOCK))
    {
        *Error = WSAGetLastError();
        closesocket(Try->Socket);
        Try->Socket = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

/* The address of the first probe that connects (staggered as Windows does); FALSE with *Error otherwise */
static BOOL CbnRace(CBN_TRY *Tries, ULONG Count, DWORD Start, DWORD Limit, ULONG *Winner, int *Error)
{
    ULONG Next = 0, i, Pending = 0;
    DWORD LastStart = 0;
    BOOL Found = FALSE;

    *Error = WSAEHOSTUNREACH;
    while (!Found)
    {
        fd_set Write, Except;
        struct timeval Tv, *PTv = NULL;
        DWORD Wait = CbnLeft(Start, Limit), Stagger;
        int Ready;

        /* the last address with no other attempt pending: the caller's socket goes to it directly (no probe) */
        if (Next == Count - 1 && Pending == 0)
        {
            *Winner = Next;
            Found = TRUE;
            break;
        }
        /* the next address: at the start, after the stagger time, or at once when none is pending any more */
        if (Next < Count && (Next == 0 || Pending == 0 || GetTickCount() - LastStart >= CBN_STAGGER_MS))
        {
            if (CbnStart(&Tries[Next], Error))
                Pending++;
            LastStart = GetTickCount();
            Next++;
            continue;
        }
        if (Pending == 0)
            break;
        if (Wait == 0)
        {
            *Error = WSAETIMEDOUT;
            break;
        }

        FD_ZERO(&Write);
        FD_ZERO(&Except);
        for (i = 0; i < Next; i++)
        {
            if (Tries[i].Socket != INVALID_SOCKET)
            {
                FD_SET(Tries[i].Socket, &Write);
                FD_SET(Tries[i].Socket, &Except);
            }
        }
        if (Next < Count)
        {
            Stagger = CBN_STAGGER_MS - min(GetTickCount() - LastStart, CBN_STAGGER_MS);
            if (Wait == INFINITE || Stagger < Wait)
                Wait = Stagger;
        }
        if (Wait != INFINITE)
        {
            Tv.tv_sec = Wait / 1000;
            Tv.tv_usec = (Wait % 1000) * 1000;
            PTv = &Tv;
        }
        Ready = select(0, NULL, &Write, &Except, PTv);
        if (Ready == SOCKET_ERROR)
        {
            *Error = WSAGetLastError();
            break;
        }
        for (i = 0; i < Next && Ready > 0; i++)
        {
            int SoError = 0, Len = sizeof(SoError);

            if (Tries[i].Socket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(Tries[i].Socket, &Write))
            {
                *Winner = i;
                Found = TRUE;
                break;
            }
            if (FD_ISSET(Tries[i].Socket, &Except))
            {
                getsockopt(Tries[i].Socket, SOL_SOCKET, SO_ERROR, (char *)&SoError, &Len);
                *Error = SoError ? SoError : WSAECONNREFUSED;
                closesocket(Tries[i].Socket);
                Tries[i].Socket = INVALID_SOCKET;
                Pending--;
            }
        }
    }

    for (i = 0; i < Next; i++)
    {
        if (Tries[i].Socket != INVALID_SOCKET)
        {
            closesocket(Tries[i].Socket);
            Tries[i].Socket = INVALID_SOCKET;
        }
    }
    return Found;
}

/* Connect s (blocking or not) to Address within what is left of Limit */
static BOOL CbnConnect(SOCKET s, const SOCKADDR *Address, int Length, DWORD Start, DWORD Limit, int *Error)
{
    fd_set Write, Except;
    struct timeval Tv, *PTv = NULL;
    DWORD Wait;
    int SoError = 0, Len = sizeof(SoError);

    if (connect(s, Address, Length) == 0)
        return TRUE;
    *Error = WSAGetLastError();
    if (*Error != WSAEWOULDBLOCK)
        return FALSE;

    /* a non-blocking socket of the caller: wait here, the call is synchronous */
    Wait = CbnLeft(Start, Limit);
    FD_ZERO(&Write);
    FD_ZERO(&Except);
    FD_SET(s, &Write);
    FD_SET(s, &Except);
    if (Wait != INFINITE)
    {
        Tv.tv_sec = Wait / 1000;
        Tv.tv_usec = (Wait % 1000) * 1000;
        PTv = &Tv;
    }
    switch (select(0, NULL, &Write, &Except, PTv))
    {
        case 0:
            *Error = WSAETIMEDOUT;
            return FALSE;
        case SOCKET_ERROR:
            *Error = WSAGetLastError();
            return FALSE;
    }
    if (FD_ISSET(s, &Write))
        return TRUE;
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&SoError, &Len);
    *Error = SoError ? SoError : WSAECONNREFUSED;
    return FALSE;
}

/* the address in the form the caller's socket takes (IPv4 as IPv4-mapped for an AF_INET6 socket) */
static void CbnForSocket(int Family, const SOCKADDR_STORAGE *In, int InLength, SOCKADDR_STORAGE *Out, int *OutLength)
{
    if (Family == AF_INET6 && In->ss_family == AF_INET)
    {
        const SOCKADDR_IN *V4 = (const SOCKADDR_IN *)In;
        SOCKADDR_IN6 *V6 = (SOCKADDR_IN6 *)Out;

        ZeroMemory(V6, sizeof(*V6));
        V6->sin6_family = AF_INET6;
        V6->sin6_port = V4->sin_port;
        V6->sin6_addr.s6_addr[10] = 0xff;
        V6->sin6_addr.s6_addr[11] = 0xff;
        CopyMemory(&V6->sin6_addr.s6_addr[12], &V4->sin_addr, 4);
        *OutLength = sizeof(*V6);
        return;
    }
    CopyMemory(Out, In, InLength);
    *OutLength = InLength;
}

static BOOL CbnCopyOut(LPDWORD Length, LPSOCKADDR Address, const SOCKADDR_STORAGE *From, int FromLength)
{
    if (!Length || !Address)
        return TRUE;
    if (*Length < (DWORD)FromLength)
    {
        *Length = FromLength;
        return FALSE;
    }
    CopyMemory(Address, From, FromLength);
    *Length = FromLength;
    return TRUE;
}

BOOL
WSAAPI
WSAConnectByNameW(IN SOCKET s,
                  IN LPWSTR nodename,
                  IN LPWSTR servicename,
                  IN OUT LPDWORD LocalAddressLength,
                  OUT LPSOCKADDR LocalAddress,
                  IN OUT LPDWORD RemoteAddressLength,
                  OUT LPSOCKADDR RemoteAddress,
                  IN const struct timeval *timeout,
                  LPWSAOVERLAPPED Reserved)
{
    WSAPROTOCOL_INFOW Info;
    int InfoLength = sizeof(Info), Error = 0, V6Only = 1, OptLength = sizeof(V6Only), Length;
    ADDRINFOW Hints, *List = NULL, *Item;
    CBN_TRY *Tries;
    ULONG Count = 0, Winner = 0;
    DWORD Start = GetTickCount(), Limit = INFINITE;
    SOCKADDR_STORAGE Target, Local, Remote;
    int LocalLength = sizeof(Local), RemoteLength = sizeof(Remote);

    if (Reserved || !nodename || !servicename)
    {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    if (timeout)
    {
        if (timeout->tv_sec < 0 || timeout->tv_usec < 0)
        {
            SetLastError(WSAEINVAL);
            return FALSE;
        }
        Limit = (DWORD)min((ULONGLONG)timeout->tv_sec * 1000 + timeout->tv_usec / 1000, (ULONGLONG)(INFINITE - 1));
    }
    /* the caller's socket: its family decides which addresses it can take */
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *)&Info, &InfoLength) == SOCKET_ERROR)
        return FALSE;
    if (Info.iSocketType != SOCK_STREAM || (Info.iAddressFamily != AF_INET && Info.iAddressFamily != AF_INET6))
    {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    if (Info.iAddressFamily == AF_INET6)
        getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&V6Only, &OptLength);

    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = (Info.iAddressFamily == AF_INET6 && !V6Only) ? AF_UNSPEC : Info.iAddressFamily;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_protocol = IPPROTO_TCP;
    Error = GetAddrInfoW(nodename, servicename, &Hints, &List);
    if (Error)
    {
        SetLastError(Error);
        return FALSE;
    }

    Tries = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CBN_MAX_TRIES * sizeof(*Tries));
    if (!Tries)
    {
        FreeAddrInfoW(List);
        SetLastError(WSA_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    for (Item = List; Item && Count < CBN_MAX_TRIES; Item = Item->ai_next)
    {
        if ((Item->ai_family != AF_INET && Item->ai_family != AF_INET6) || Item->ai_addrlen > sizeof(SOCKADDR_STORAGE))
            continue;
        Tries[Count].Socket = INVALID_SOCKET;
        CopyMemory(&Tries[Count].Address, Item->ai_addr, Item->ai_addrlen);
        Tries[Count].AddressLength = (int)Item->ai_addrlen;
        Count++;
    }
    FreeAddrInfoW(List);

    if (!Count)
    {
        HeapFree(GetProcessHeap(), 0, Tries);
        SetLastError(WSAHOST_NOT_FOUND);
        return FALSE;
    }

    /* one address: the caller's socket connects to it at once; more: the first that answers */
    if (Count > 1 && !CbnRace(Tries, Count, Start, Limit, &Winner, &Error))
    {
        HeapFree(GetProcessHeap(), 0, Tries);
        SetLastError(Error);
        return FALSE;
    }
    CbnForSocket(Info.iAddressFamily, &Tries[Winner].Address, Tries[Winner].AddressLength, &Target, &Length);
    HeapFree(GetProcessHeap(), 0, Tries);
    if (!CbnConnect(s, (SOCKADDR *)&Target, Length, Start, Limit, &Error))
    {
        SetLastError(Error);
        return FALSE;
    }

    if ((LocalAddressLength && LocalAddress && getsockname(s, (SOCKADDR *)&Local, &LocalLength) == SOCKET_ERROR) ||
        (RemoteAddressLength && RemoteAddress && getpeername(s, (SOCKADDR *)&Remote, &RemoteLength) == SOCKET_ERROR))
        return FALSE;
    if (!CbnCopyOut(LocalAddressLength, LocalAddress, &Local, LocalLength) ||
        !CbnCopyOut(RemoteAddressLength, RemoteAddress, &Remote, RemoteLength))
    {
        SetLastError(WSAEFAULT);
        return FALSE;
    }
    return TRUE;
}

BOOL
WSAAPI
WSAConnectByNameA(IN SOCKET s,
                  IN LPCSTR nodename,
                  IN LPCSTR servicename,
                  IN OUT LPDWORD LocalAddressLength,
                  OUT LPSOCKADDR LocalAddress,
                  IN OUT LPDWORD RemoteAddressLength,
                  OUT LPSOCKADDR RemoteAddress,
                  IN const struct timeval *timeout,
                  LPWSAOVERLAPPED Reserved)
{
    LPWSTR Node = NULL, Service = NULL;
    int NodeLength, ServiceLength;
    BOOL Result;
    DWORD Error;

    if (!nodename || !servicename)
    {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    NodeLength = MultiByteToWideChar(CP_ACP, 0, nodename, -1, NULL, 0);
    ServiceLength = MultiByteToWideChar(CP_ACP, 0, servicename, -1, NULL, 0);
    if (NodeLength <= 0 || ServiceLength <= 0)
    {
        SetLastError(WSAEINVAL);
        return FALSE;
    }
    Node = HeapAlloc(GetProcessHeap(), 0, NodeLength * sizeof(WCHAR));
    Service = HeapAlloc(GetProcessHeap(), 0, ServiceLength * sizeof(WCHAR));
    if (!Node || !Service)
    {
        if (Node)
            HeapFree(GetProcessHeap(), 0, Node);
        if (Service)
            HeapFree(GetProcessHeap(), 0, Service);
        SetLastError(WSA_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    MultiByteToWideChar(CP_ACP, 0, nodename, -1, Node, NodeLength);
    MultiByteToWideChar(CP_ACP, 0, servicename, -1, Service, ServiceLength);

    Result = WSAConnectByNameW(s, Node, Service, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress,
                               timeout, Reserved);
    Error = GetLastError();
    HeapFree(GetProcessHeap(), 0, Node);
    HeapFree(GetProcessHeap(), 0, Service);
    SetLastError(Error);
    return Result;
}
