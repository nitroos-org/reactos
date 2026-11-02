/*
 * PROJECT:     ReactOS HTTP Server API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     URL prefix registrations, their matching rules and the listening sockets
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Matching rules as measured on Windows 10 with http.sys: a registration names a port, a host (a name, an
 * address, "+" the strong wildcard, "*" the weak wildcard) and an absolute path prefix, compared without
 * regard to case. Names, addresses and the strong wildcard compete together and the longest path wins
 * (a name beats "+" on equal paths); the weak wildcard is only looked at when nothing else matches.
 * No URL ACLs are checked: any process may register any prefix.
 */

#include "httpapip.h"

static DWORD WINAPI ListenerThread(PVOID Param)
{
    LISTENER *L = Param;
    HANDLE H[2];

    H[0] = L->hSockEvt;
    H[1] = L->hStop;
    for (;;)
    {
        WSANETWORKEVENTS Ne;

        if (WaitForMultipleObjects(2, H, FALSE, INFINITE) != WAIT_OBJECT_0)
            break;
        if (WSAEnumNetworkEvents(L->Sock, L->hSockEvt, &Ne))
            break;
        for (;;)
        {
            SOCKADDR_STORAGE Ra, La;
            int Rl = sizeof(Ra), Ll = sizeof(La);
            SOCKET S = accept(L->Sock, (SOCKADDR *)&Ra, &Rl);

            if (S == INVALID_SOCKET)
                break;
            if (getsockname(S, (SOCKADDR *)&La, &Ll))
            {
                closesocket(S);
                continue;
            }
            Conn_New(S, &La, &Ra);
        }
    }
    CloseHandle(L->hSockEvt);
    CloseHandle(L->hStop);
    HeapFree(GetProcessHeap(), 0, L);
    return 0;
}

static BOOL SameAddr(const SOCKADDR_STORAGE *A, const SOCKADDR_STORAGE *B)
{
    if (A->ss_family != B->ss_family)
        return FALSE;
    if (A->ss_family == AF_INET)
        return ((SOCKADDR_IN *)A)->sin_addr.s_addr == ((SOCKADDR_IN *)B)->sin_addr.s_addr;
    return !memcmp(&((SOCKADDR_IN6 *)A)->sin6_addr, &((SOCKADDR_IN6 *)B)->sin6_addr, 16);
}

static BOOL IsAny(const SOCKADDR_STORAGE *A)
{
    return A->ss_family == AF_INET && !((SOCKADDR_IN *)A)->sin_addr.s_addr;
}

/* Does something accept connections at this address? (The probe is a connect to the loopback address of the
 * same family when the address is "any".) */
static BOOL Port_Alive(const SOCKADDR_STORAGE *Addr, int Len)
{
    SOCKADDR_STORAGE To = *Addr;
    SOCKET S;
    BOOL Alive;

    if (Addr->ss_family == AF_INET && !((SOCKADDR_IN *)&To)->sin_addr.s_addr)
        ((SOCKADDR_IN *)&To)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    S = socket(Addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (S == INVALID_SOCKET)
        return TRUE;
    Alive = !connect(S, (SOCKADDR *)&To, Len);
    closesocket(S);
    return Alive;
}

/* g_Lock held */
static ULONG Listener_Open(USHORT Port, const SOCKADDR_STORAGE *Ip)
{
    LISTENER *L;
    SOCKADDR_STORAGE Addr;
    int Len, Bad, Err;
    HANDLE hThread;

    RtlZeroMemory(&Addr, sizeof(Addr));
    if (Ip)
        Addr = *Ip;
    else
        Addr.ss_family = AF_INET; /* INADDR_ANY */
    if (Addr.ss_family == AF_INET)
    {
        ((SOCKADDR_IN *)&Addr)->sin_port = htons(Port);
        Len = sizeof(SOCKADDR_IN);
    }
    else
    {
        ((SOCKADDR_IN6 *)&Addr)->sin6_port = htons(Port);
        Len = sizeof(SOCKADDR_IN6);
    }

    L = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*L));
    if (!L)
        return ERROR_NOT_ENOUGH_MEMORY;
    L->Port = Port;
    L->Addr = Addr;
    L->AddrLen = Len;
    L->Sock = socket(Addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (L->Sock == INVALID_SOCKET)
    {
        HeapFree(GetProcessHeap(), 0, L);
        return ERROR_NOT_SUPPORTED;
    }
    Bad = bind(L->Sock, (SOCKADDR *)&Addr, Len);
    Err = Bad ? WSAGetLastError() : 0;
    if (Bad && Err == WSAEADDRINUSE && !Port_Alive(&Addr, Len))
    {
        /* Nothing listens there, so what holds the port is the tail of closed connections (TIME_WAIT), which
         * Windows does not count; ReactOS does unless the socket asks to share the address. */
        BOOL On = TRUE;

        closesocket(L->Sock);
        L->Sock = socket(Addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (L->Sock == INVALID_SOCKET)
        {
            HeapFree(GetProcessHeap(), 0, L);
            return ERROR_NOT_SUPPORTED;
        }
        setsockopt(L->Sock, SOL_SOCKET, SO_REUSEADDR, (char *)&On, sizeof(On));
        Bad = bind(L->Sock, (SOCKADDR *)&Addr, Len);
        Err = Bad ? WSAGetLastError() : 0;
    }
    if (!Bad)
    {
        Bad = listen(L->Sock, SOMAXCONN);
        Err = Bad ? WSAGetLastError() : 0;
    }
    if (Bad)
    {
        closesocket(L->Sock);
        HeapFree(GetProcessHeap(), 0, L);
        return Err == WSAEADDRINUSE ? ERROR_SHARING_VIOLATION : (Err == WSAEACCES ? ERROR_ACCESS_DENIED : (ULONG)Err);
    }
    L->hSockEvt = CreateEventW(NULL, FALSE, FALSE, NULL);
    L->hStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!L->hSockEvt || !L->hStop || WSAEventSelect(L->Sock, L->hSockEvt, FD_ACCEPT))
    {
        if (L->hSockEvt)
            CloseHandle(L->hSockEvt);
        if (L->hStop)
            CloseHandle(L->hStop);
        closesocket(L->Sock);
        HeapFree(GetProcessHeap(), 0, L);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    hThread = CreateThread(NULL, 0, ListenerThread, L, 0, NULL);
    if (!hThread)
    {
        CloseHandle(L->hSockEvt);
        CloseHandle(L->hStop);
        closesocket(L->Sock);
        HeapFree(GetProcessHeap(), 0, L);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    CloseHandle(hThread);
    HL_ADD(&g_Listeners, &L->Link);
    return ERROR_SUCCESS;
}

/* g_Lock held */
static void Listener_Close(LISTENER *L)
{
    HL_DEL(&L->Link);
    /* close the socket now so that the port can be taken again at once; the thread frees the rest */
    L->Stop = TRUE;
    closesocket(L->Sock);
    SetEvent(L->hStop);
}

/* g_Lock held */
BOOL Url_PortListening(USHORT Port)
{
    HL *E;

    for (E = g_Listeners.Next; E != &g_Listeners; E = E->Next)
        if (HL_ENTRY(E, LISTENER, Link)->Port == Port)
            return TRUE;
    return FALSE;
}

/* g_Lock held. Makes the listening sockets of a port the ones that the registrations need: one on every address
 * as soon as one registration names a host or a wildcard, else one per address literal. (Windows lets an address
 * and "any" share a port, ReactOS does not.) */
static ULONG Port_Reconcile(USHORT Port)
{
    HL *E, *N;
    BOOL NeedAny = FALSE;
    ULONG Err = ERROR_SUCCESS;

    for (E = g_Urls.Next; E != &g_Urls; E = E->Next)
    {
        URLREG *U = HL_ENTRY(E, URLREG, Link);

        if (U->Port == Port && !U->HostIsIp)
            NeedAny = TRUE;
    }
    for (E = g_Listeners.Next; E != &g_Listeners; E = N)
    {
        LISTENER *L = HL_ENTRY(E, LISTENER, Link);
        BOOL Keep = FALSE;

        N = E->Next;
        if (L->Port != Port)
            continue;
        if (NeedAny)
            Keep = IsAny(&L->Addr);
        else if (!IsAny(&L->Addr))
        {
            HL *F;

            for (F = g_Urls.Next; F != &g_Urls; F = F->Next)
            {
                URLREG *U = HL_ENTRY(F, URLREG, Link);

                if (U->Port == Port && U->HostIsIp && SameAddr(&U->Ip, &L->Addr))
                    Keep = TRUE;
            }
        }
        if (!Keep)
            Listener_Close(L);
    }
    for (E = g_Urls.Next; E != &g_Urls && !Err; E = E->Next)
    {
        URLREG *U = HL_ENTRY(E, URLREG, Link);
        HL *F;
        BOOL Have = FALSE;

        if (U->Port != Port || (NeedAny && U->HostIsIp))
            continue;
        for (F = g_Listeners.Next; F != &g_Listeners; F = F->Next)
        {
            LISTENER *L = HL_ENTRY(F, LISTENER, Link);

            if (L->Port == Port && (NeedAny ? IsAny(&L->Addr) : (!IsAny(&L->Addr) && SameAddr(&U->Ip, &L->Addr))))
                Have = TRUE;
        }
        if (!Have)
            Err = Listener_Open(Port, NeedAny ? NULL : &U->Ip);
    }
    /* ReactOS does not let a port be bound while a connection of it is alive: with nothing listening any more,
     * the idle connections that came in on it go too */
    if (!Url_PortListening(Port))
        Conn_RetirePort(Port);
    return Err;
}

static void LowerW(WCHAR *S)
{
    for (; *S; S++)
        if (*S >= L'A' && *S <= L'Z')
            *S += L'a' - L'A';
}

static WCHAR *DupW(const WCHAR *S, ULONG Len)
{
    WCHAR *D = HeapAlloc(GetProcessHeap(), 0, (Len + 1) * sizeof(WCHAR));

    if (D)
    {
        memcpy(D, S, Len * sizeof(WCHAR));
        D[Len] = 0;
    }
    return D;
}

static void Url_Free(URLREG *U)
{
    HeapFree(GetProcessHeap(), 0, U->Host);
    HeapFree(GetProcessHeap(), 0, U->Path);
    HeapFree(GetProcessHeap(), 0, U->Full);
    HeapFree(GetProcessHeap(), 0, U);
}

/* Strict dotted quad */
static BOOL ParseV4(const WCHAR *S, SOCKADDR_IN *Out)
{
    ULONG Part, Count = 0, Digits;
    UCHAR B[4];

    for (;;)
    {
        Part = Digits = 0;
        while (*S >= L'0' && *S <= L'9' && Digits < 4)
        {
            Part = Part * 10 + (*S++ - L'0');
            Digits++;
        }
        if (!Digits || Part > 255 || Count > 3)
            return FALSE;
        B[Count++] = (UCHAR)Part;
        if (!*S)
            break;
        if (*S++ != L'.')
            return FALSE;
    }
    if (Count != 4)
        return FALSE;
    RtlZeroMemory(Out, sizeof(*Out));
    Out->sin_family = AF_INET;
    memcpy(&Out->sin_addr, B, 4);
    return TRUE;
}

/* Splits "http://host:port/path" into a new registration (without owner); returns a Win32 error */
static ULONG Url_Parse(const WCHAR *Url, URLREG **Out)
{
    const WCHAR *P, *HostStart, *HostEnd, *PortStart;
    ULONG Port = 0, HostLen, Len = (ULONG)wcslen(Url);
    URLREG *U;
    WCHAR Tmp[260];

    if (Len > 2000)
        return ERROR_INVALID_PARAMETER;
    if (!_wcsnicmp(Url, L"https://", 8))
        return ERROR_NOT_SUPPORTED; /* no TLS in this server */
    if (_wcsnicmp(Url, L"http://", 7))
        return ERROR_INVALID_PARAMETER;
    HostStart = Url + 7;
    if (*HostStart == L'[')
    {
        HostEnd = wcschr(HostStart, L']');
        if (!HostEnd)
            return ERROR_INVALID_PARAMETER;
        HostEnd++;
    }
    else
    {
        for (HostEnd = HostStart; *HostEnd && *HostEnd != L':' && *HostEnd != L'/'; HostEnd++)
            ;
    }
    if (*HostEnd != L':' || HostEnd == HostStart)
        return ERROR_INVALID_PARAMETER; /* the port is not optional */
    PortStart = HostEnd + 1;
    for (P = PortStart; *P >= L'0' && *P <= L'9'; P++)
    {
        Port = Port * 10 + (*P - L'0');
        if (Port > 65535)
            return ERROR_INVALID_PARAMETER;
    }
    if (P == PortStart || Port == 0 || *P != L'/')
        return ERROR_INVALID_PARAMETER;
    for (HostLen = 0; P[HostLen]; HostLen++)
        if (P[HostLen] <= L' ' || P[HostLen] == L'?' || P[HostLen] == L'#' || P[HostLen] == L'%' || P[HostLen] > 0x7e)
            return ERROR_INVALID_PARAMETER;

    HostLen = (ULONG)(HostEnd - HostStart);
    if (HostLen == 0 || HostLen > 255)
        return ERROR_INVALID_PARAMETER;
    U = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*U));
    if (!U)
        return ERROR_NOT_ENOUGH_MEMORY;
    U->Port = (USHORT)Port;
    U->Host = DupW(HostStart, HostLen);
    U->Path = DupW(P, (ULONG)wcslen(P));
    U->Full = DupW(Url, Len);
    if (!U->Host || !U->Path || !U->Full)
    {
        Url_Free(U);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    LowerW(U->Host);
    LowerW(U->Path);
    U->PathLen = (ULONG)wcslen(U->Path);
    if (HostLen == 1 && U->Host[0] == L'+')
        U->HostKind = 1;
    else if (HostLen == 1 && U->Host[0] == L'*')
        U->HostKind = 2;
    else
    {
        int AddrLen = sizeof(U->Ip);

        /* an address literal listens on that address only */
        if (U->Host[0] == L'[' && HostLen > 2 && HostLen < 100)
        {
            memcpy(Tmp, U->Host + 1, (HostLen - 2) * sizeof(WCHAR));
            Tmp[HostLen - 2] = 0;
            if (!WSAStringToAddressW(Tmp, AF_INET6, NULL, (SOCKADDR *)&U->Ip, &AddrLen) && U->Ip.ss_family == AF_INET6)
                U->HostIsIp = TRUE;
            else
            {
                Url_Free(U);
                return ERROR_INVALID_PARAMETER;
            }
        }
        else if (ParseV4(U->Host, (SOCKADDR_IN *)&U->Ip))
            U->HostIsIp = TRUE;
    }
    *Out = U;
    return ERROR_SUCCESS;
}

/* g_Lock held */
static ULONG Url_RegisterOnce(UGROUP *G, RQ *Q, const WCHAR *Url, ULONGLONG Ctx)
{
    URLREG *U;
    HL *E;
    ULONG Err;

    Err = Url_Parse(Url, &U);
    if (Err)
        return Err;
    for (E = g_Urls.Next; E != &g_Urls; E = E->Next)
    {
        URLREG *O = HL_ENTRY(E, URLREG, Link);

        if (O->Port == U->Port && O->HostKind == U->HostKind && !wcscmp(O->Host, U->Host) && !wcscmp(O->Path, U->Path))
        {
            Url_Free(U);
            return ERROR_ALREADY_EXISTS;
        }
    }
    U->Context = Ctx;
    U->Group = G;
    U->Queue = Q;
    HL_ADD(&g_Urls, &U->Link);
    HL_ADD(G ? &G->Urls : &Q->Urls, &U->GroupLink);
    Err = Port_Reconcile(U->Port);
    if (Err)
    {
        /* back to what the earlier registrations need */
        HL_DEL(&U->Link);
        HL_DEL(&U->GroupLink);
        Port_Reconcile(U->Port);
        Url_Free(U);
        return Err;
    }
    return ERROR_SUCCESS;
}

static void Url_Unlink(URLREG *U)
{
    USHORT Port = U->Port;

    HL_DEL(&U->Link);
    HL_DEL(&U->GroupLink);
    Url_Free(U);
    Port_Reconcile(Port);
}

/* g_Lock held */
ULONG Url_Remove(UGROUP *G, RQ *Q, const WCHAR *Url)
{
    URLREG *Probe;
    HL *Head = G ? &G->Urls : &Q->Urls, *E;
    ULONG Err = Url_Parse(Url, &Probe);

    if (Err)
        return Err == ERROR_NOT_SUPPORTED ? ERROR_FILE_NOT_FOUND : Err;
    Err = ERROR_FILE_NOT_FOUND;
    for (E = Head->Next; E != Head; E = E->Next)
    {
        URLREG *O = HL_ENTRY(E, URLREG, GroupLink);

        if (O->Port == Probe->Port && O->HostKind == Probe->HostKind && !wcscmp(O->Host, Probe->Host) && !wcscmp(O->Path, Probe->Path))
        {
            Url_Unlink(O);
            Err = ERROR_SUCCESS;
            break;
        }
    }
    Url_Free(Probe);
    return Err;
}

/* g_Lock held. Either everything of one group, or (queue closing) the version 1 ones of the queue and the
 * binding of every group that points at it */
void Url_RemoveAll(UGROUP *G, RQ *Q)
{
    HL *Head, *E;

    if (G)
    {
        while (!HL_EMPTY(&G->Urls))
            Url_Unlink(HL_ENTRY(G->Urls.Next, URLREG, GroupLink));
        return;
    }
    while (!HL_EMPTY(&Q->Urls))
        Url_Unlink(HL_ENTRY(Q->Urls.Next, URLREG, GroupLink));
    for (Head = g_Sessions.Next; Head != &g_Sessions; Head = Head->Next)
    {
        SESSION *S = HL_ENTRY(Head, SESSION, Link);

        for (E = S->Groups.Next; E != &S->Groups; E = E->Next)
        {
            UGROUP *Gr = HL_ENTRY(E, UGROUP, SessionLink);

            if (Gr->Queue == Q)
                Gr->Queue = NULL;
        }
    }
}

/* g_Lock held */
URLREG *Url_Match(const WCHAR *Host, USHORT Port, const SOCKADDR_STORAGE *Local, const WCHAR *Path, ULONG PathLen)
{
    HL *E;
    URLREG *Best = NULL;

    for (E = g_Urls.Next; E != &g_Urls; E = E->Next)
    {
        URLREG *U = HL_ENTRY(E, URLREG, Link);
        ULONG Pl = U->PathLen;

        if (U->Port != Port)
            continue;
        if (U->HostKind == 0)
        {
            if (!(U->HostIsIp ? SameAddr(&U->Ip, Local) : !_wcsicmp(U->Host, Host)))
                continue;
        }
        /* "/a/" also takes "/a" */
        if (Pl > 1 && U->Path[Pl - 1] == L'/' && PathLen == Pl - 1)
            Pl--;
        if (PathLen < Pl || _wcsnicmp(U->Path, Path, Pl))
            continue;
        if (Best)
        {
            int TierU = U->HostKind == 2, TierB = Best->HostKind == 2;

            if (TierU != TierB)
            {
                if (TierU)
                    continue;
            }
            else if (U->PathLen < Best->PathLen || (U->PathLen == Best->PathLen && U->HostKind >= Best->HostKind))
                continue;
        }
        Best = U;
    }
    return Best;
}

/* g_Lock held (once). A port that was just given up may still be held by connections that are on their way out:
 * give them a moment. */
ULONG Url_Register(UGROUP *G, RQ *Q, const WCHAR *Url, ULONGLONG Ctx)
{
    ULONG Err;
    int Try = 0;
    USHORT Port = 0;
    const WCHAR *C;

    for (C = Url + 7; *C && *C != L':'; C++)
        ;
    if (*C == L':')
        Port = (USHORT)wcstoul(C + 1, NULL, 10);
    for (;;)
    {
        Err = Url_RegisterOnce(G, Q, Url, Ctx);
        if (Err != ERROR_SHARING_VIOLATION || !Port || ++Try > 30 || !Conn_PortBusy(Port))
            return Err;
        LeaveCriticalSection(&g_Lock);
        Sleep(100);
        EnterCriticalSection(&g_Lock);
    }
}
