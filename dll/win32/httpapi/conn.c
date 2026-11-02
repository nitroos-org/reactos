/*
 * PROJECT:     ReactOS HTTP Server API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     HTTP/1.1 connections: request parsing, request and entity body delivery, responses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Every accepted connection has a thread that owns reading from the socket: it reads and parses a request
 * head, hands the request to the queue of the best matching URL registration and then serves the commands
 * of the program (entity body reads, disconnect waits) until the response is complete, after which the
 * next request on the connection is read. Responses are sent from the thread of the caller.
 * Only plain HTTP/1.1 and 1.0 are served: no TLS, no authentication, no HTTP/2, no Upgrade/opaque mode.
 */

#include "httpapip.h"

static const char *ReqKnownNames[HttpHeaderRequestMaximum] =
{
    "Cache-Control", "Connection", "Date", "Keep-Alive", "Pragma", "Trailer", "Transfer-Encoding", "Upgrade",
    "Via", "Warning", "Allow", "Content-Length", "Content-Type", "Content-Encoding", "Content-Language",
    "Content-Location", "Content-MD5", "Content-Range", "Expires", "Last-Modified", "Accept", "Accept-Charset",
    "Accept-Encoding", "Accept-Language", "Authorization", "Cookie", "Expect", "From", "Host", "If-Match",
    "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards",
    "Proxy-Authorization", "Referer", "Range", "TE", "Translate", "User-Agent"
};

static const char *RespKnownNames[HttpHeaderResponseMaximum] =
{
    "Cache-Control", "Connection", "Date", "Keep-Alive", "Pragma", "Trailer", "Transfer-Encoding", "Upgrade",
    "Via", "Warning", "Allow", "Content-Length", "Content-Type", "Content-Encoding", "Content-Language",
    "Content-Location", "Content-MD5", "Content-Range", "Expires", "Last-Modified", "Accept-Ranges", "Age",
    "ETag", "Location", "Proxy-Authenticate", "Retry-After", "Server", "Set-Cookie", "Vary", "WWW-Authenticate"
};

static const char *VerbNames[] =
{
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "TRACK", "MOVE", "COPY",
    "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK", "SEARCH"
};

static const char *Reason(USHORT Code)
{
    switch (Code)
    {
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        case 505: return "HTTP Version Not Supported";
        default: return "Error";
    }
}

/* ---------------------------------------------------------------- arena, buffers */

static void *Arena_Alloc(REQ *R, ULONG Size, ULONG Align)
{
    ULONG Off = (R->ArenaUsed + Align - 1) & ~(Align - 1);

    if (Off + Size > R->ArenaCap)
        return NULL;
    R->ArenaUsed = Off + Size;
    return R->Arena + Off;
}

static char *Arena_Str(REQ *R, const char *S, ULONG Len)
{
    char *D = Arena_Alloc(R, Len + 1, 1);

    if (D)
    {
        memcpy(D, S, Len);
        D[Len] = 0;
    }
    return D;
}

static void Req_Free(REQ *R)
{
    while (R->Pins > 0)
        Sleep(1);
    HeapFree(GetProcessHeap(), 0, R->Arena);
    HeapFree(GetProcessHeap(), 0, R);
}

/* g_Lock held */
static BOOL Conn_Append(CONN *C, const void *Data, ULONG Len)
{
    if (C->Pos == C->Len)
        C->Pos = C->Len = 0;
    if (C->Len + Len > C->Cap)
    {
        ULONG Live = C->Len - C->Pos, NewCap;
        PUCHAR N;

        if (C->Pos)
        {
            memmove(C->Buf, C->Buf + C->Pos, Live);
            C->Pos = 0;
            C->Len = Live;
        }
        if (C->Len + Len > C->Cap)
        {
            NewCap = C->Cap ? C->Cap : 8192;
            while (NewCap < C->Len + Len)
                NewCap *= 2;
            N = C->Buf ? HeapReAlloc(GetProcessHeap(), 0, C->Buf, NewCap) : HeapAlloc(GetProcessHeap(), 0, NewCap);
            if (!N)
                return FALSE;
            C->Buf = N;
            C->Cap = NewCap;
        }
    }
    memcpy(C->Buf + C->Len, Data, Len);
    C->Len += Len;
    return TRUE;
}

/* Reads what the socket has, without waiting. Returns the number of bytes added, 0 when there is nothing
 * (yet) and -1 when the peer has closed or the connection failed. */
static int Conn_Pull(CONN *C)
{
    UCHAR Tmp[16384];
    int Total = 0;

    for (;;)
    {
        int N;

        EnterCriticalSection(&g_Lock);
        if (C->Len - C->Pos >= HPI_MAX_BUFFERED)
        {
            LeaveCriticalSection(&g_Lock);
            return Total;
        }
        LeaveCriticalSection(&g_Lock);
        N = recv(C->Sock, (char *)Tmp, sizeof(Tmp), 0);
        if (N > 0)
        {
            EnterCriticalSection(&g_Lock);
            Conn_Append(C, Tmp, N);
            LeaveCriticalSection(&g_Lock);
            Total += N;
            continue;
        }
        if (N == 0)
        {
            EnterCriticalSection(&g_Lock);
            C->PeerClosed = TRUE;
            LeaveCriticalSection(&g_Lock);
            return Total ? Total : -1;
        }
        if (WSAGetLastError() == WSAEWOULDBLOCK)
            return Total;
        EnterCriticalSection(&g_Lock);
        C->PeerClosed = C->Dead = TRUE;
        LeaveCriticalSection(&g_Lock);
        return Total ? Total : -1;
    }
}

static void Conn_Events(CONN *C)
{
    WSANETWORKEVENTS Ne;

    if (!WSAEnumNetworkEvents(C->Sock, C->hSockEvt, &Ne) && (Ne.lNetworkEvents & FD_CLOSE) && Ne.iErrorCode[FD_CLOSE_BIT])
    {
        EnterCriticalSection(&g_Lock);
        C->PeerClosed = C->Dead = TRUE;
        LeaveCriticalSection(&g_Lock);
    }
}

static BOOL Conn_SendAll(CONN *C, const void *Data, ULONG Len)
{
    const char *P = Data;
    BOOL Ok = TRUE;

    EnterCriticalSection(&C->SendLock);
    if (C->SendBroken || C->Dead)
        Ok = FALSE;
    while (Ok && Len)
    {
        int N = send(C->Sock, P, Len > 0x100000 ? 0x100000 : Len, 0);

        if (N > 0)
        {
            P += N;
            Len -= N;
        }
        else if (WSAGetLastError() == WSAEWOULDBLOCK)
        {
            fd_set W;
            struct timeval Tv = { 60, 0 };

            FD_ZERO(&W);
            FD_SET(C->Sock, &W);
            if (select(0, NULL, &W, NULL, &Tv) <= 0)
                Ok = FALSE;
        }
        else
            Ok = FALSE;
    }
    if (!Ok)
        C->SendBroken = TRUE;
    LeaveCriticalSection(&C->SendLock);
    return Ok;
}

static void FormatDate(char *Out)
{
    static const char *Days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *Months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    SYSTEMTIME T;

    GetSystemTime(&T);
    sprintf(Out, "%s, %02u %s %04u %02u:%02u:%02u GMT", Days[T.wDayOfWeek % 7], T.wDay, Months[(T.wMonth - 1) % 12],
            T.wYear, T.wHour, T.wMinute, T.wSecond);
}

static void Conn_SendError(CONN *C, USHORT Code)
{
    char Body[256], Date[40], Out[768];
    int BodyLen, Len;

    FormatDate(Date);
    BodyLen = sprintf(Body, "<!DOCTYPE HTML><HTML><HEAD><TITLE>%s</TITLE></HEAD><BODY><h2>%s</h2><hr><p>HTTP Error %u.</p></BODY></HTML>",
                      Reason(Code), Reason(Code), Code);
    Len = sprintf(Out, "HTTP/1.1 %u %s\r\nContent-Type: text/html; charset=us-ascii\r\nServer: Microsoft-HTTPAPI/2.0\r\n"
                       "Date: %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", Code, Reason(Code), Date, BodyLen, Body);
    Conn_SendAll(C, Out, Len);
}

/* ---------------------------------------------------------------- request head parsing */

static int Lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static BOOL IEq(const char *A, ULONG Al, const char *B)
{
    ULONG i;

    if (strlen(B) != Al)
        return FALSE;
    for (i = 0; i < Al; i++)
        if (Lower((UCHAR)A[i]) != Lower((UCHAR)B[i]))
            return FALSE;
    return TRUE;
}

static BOOL HasToken(const char *V, ULONG Len, const char *Token)
{
    ULONG i = 0, Tl = (ULONG)strlen(Token);

    while (i < Len)
    {
        ULONG S, E;

        while (i < Len && (V[i] == ',' || V[i] == ' ' || V[i] == '\t'))
            i++;
        S = i;
        while (i < Len && V[i] != ',')
            i++;
        E = i;
        while (E > S && (V[E - 1] == ' ' || V[E - 1] == '\t'))
            E--;
        if (E - S == Tl && IEq(V + S, Tl, Token))
            return TRUE;
    }
    return FALSE;
}

static BOOL Hex(int c, int *V)
{
    if (c >= '0' && c <= '9') { *V = c - '0'; return TRUE; }
    if (c >= 'a' && c <= 'f') { *V = c - 'a' + 10; return TRUE; }
    if (c >= 'A' && c <= 'F') { *V = c - 'A' + 10; return TRUE; }
    return FALSE;
}

static BOOL TokenChar(UCHAR c)
{
    return c > 0x20 && c < 0x7f && !strchr("()<>@,;:\\\"/[]?={}", c);
}

/* Builds Full, HostName and the offsets from the raw target and the Host header. Returns an HTTP status on failure. */
static int Cook(REQ *R, const char *Raw, ULONG RawLen, const SOCKADDR_STORAGE *Local)
{
    char HostBuf[300];
    char AddrText[80];
    const char *Host, *Rest, *PathEnd, *Query = NULL;
    ULONG HostLen = 0, QueryLen = 0, RestLen, PathRawLen, i, n;
    PUCHAR Dec;
    WCHAR *Wide, *Out, *Full;
    int WideLen;
    USHORT Port;
    BOOL Star = FALSE;
    char PortText[8];

    if (Local->ss_family == AF_INET)
        Port = ntohs(((SOCKADDR_IN *)Local)->sin_port);
    else
        Port = ntohs(((SOCKADDR_IN6 *)Local)->sin6_port);
    sprintf(PortText, "%u", Port);

    if (RawLen == 1 && Raw[0] == '*')
    {
        Star = TRUE;
        Rest = Raw;
        RestLen = 0;
    }
    else if (Raw[0] == '/')
    {
        Rest = Raw;
        RestLen = RawLen;
    }
    else if (RawLen > 7 && !_strnicmp(Raw, "http://", 7))
    {
        const char *A = Raw + 7, *AEnd = A;

        while (AEnd < Raw + RawLen && *AEnd != '/' && *AEnd != '?' && *AEnd != '#')
            AEnd++;
        Rest = AEnd;
        RestLen = (ULONG)(Raw + RawLen - AEnd);
        for (Host = A; Host < AEnd; Host++)
            if (*Host == '@')
                A = Host + 1;
        Host = A;
        HostLen = (ULONG)(AEnd - A);
    }
    else
        return 400;

    /* the host: from the absolute URI, else the Host header, else the address the request came to */
    if (!HostLen)
    {
        if (R->Known[HttpHeaderHost].Len)
        {
            Host = R->Known[HttpHeaderHost].Value;
            HostLen = R->Known[HttpHeaderHost].Len;
        }
        else
        {
            WCHAR Txt[80];
            DWORD Tl = 80;
            SOCKADDR_STORAGE Copy = *Local;

            if (Local->ss_family == AF_INET)
                ((SOCKADDR_IN *)&Copy)->sin_port = 0;
            else
                ((SOCKADDR_IN6 *)&Copy)->sin6_port = 0;
            if (WSAAddressToStringW((SOCKADDR *)&Copy, Local->ss_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6), NULL, Txt, &Tl))
                return 400;
            for (i = 0; Txt[i] && i < 70; i++)
                AddrText[i] = (char)Txt[i];
            AddrText[i] = 0;
            if (Local->ss_family == AF_INET6)
            {
                /* WSAAddressToString writes "[addr]:0" for a zero port only when a port is set; be safe */
                char *Colon = strstr(AddrText, "]:");

                if (Colon)
                    Colon[1] = 0;
            }
            Host = AddrText;
            HostLen = (ULONG)strlen(AddrText);
        }
    }
    /* strip a port */
    if (HostLen && Host[0] == '[')
    {
        const char *Close = memchr(Host, ']', HostLen);

        if (!Close)
            return 400;
        HostLen = (ULONG)(Close - Host) + 1;
    }
    else
    {
        const char *Colon = memchr(Host, ':', HostLen);

        if (Colon)
            HostLen = (ULONG)(Colon - Host);
    }
    if (!HostLen || HostLen > 253)
        return 400;
    for (i = 0; i < HostLen; i++)
    {
        UCHAR c = Host[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_' ||
              c == '[' || c == ']' || c == ':'))
            return 400;
    }
    memcpy(HostBuf, Host, HostLen);
    HostBuf[HostLen] = 0;

    /* path and query of the target */
    PathEnd = Rest;
    while (PathEnd < Rest + RestLen && *PathEnd != '?' && *PathEnd != '#')
        PathEnd++;
    PathRawLen = (ULONG)(PathEnd - Rest);
    if (*PathEnd == '?' && PathEnd < Rest + RestLen)
    {
        const char *Q = PathEnd, *QEnd = Q;

        while (QEnd < Rest + RestLen && *QEnd != '#')
            QEnd++;
        Query = Q;
        QueryLen = (ULONG)(QEnd - Q);
    }
    for (i = 0; i < QueryLen; i++)
        if ((UCHAR)Query[i] < 0x21 || (UCHAR)Query[i] == 0x7f)
            return 400;

    Dec = HeapAlloc(GetProcessHeap(), 0, PathRawLen + 1);
    Wide = HeapAlloc(GetProcessHeap(), 0, (PathRawLen + 2) * sizeof(WCHAR) * 2);
    if (!Dec || !Wide)
    {
        HeapFree(GetProcessHeap(), 0, Dec);
        HeapFree(GetProcessHeap(), 0, Wide);
        return 503;
    }
    n = 0;
    if (!Star)
    {
        for (i = 0; i < PathRawLen; i++)
        {
            UCHAR c = Rest[i];
            int H1, H2;

            if (c == '%')
            {
                if (i + 2 >= PathRawLen || !Hex(Rest[i + 1], &H1) || !Hex(Rest[i + 2], &H2))
                {
                    HeapFree(GetProcessHeap(), 0, Dec);
                    HeapFree(GetProcessHeap(), 0, Wide);
                    return 400;
                }
                c = (UCHAR)(H1 * 16 + H2);
                i += 2;
            }
            else if (c < 0x21 || c == 0x7f)
            {
                HeapFree(GetProcessHeap(), 0, Dec);
                HeapFree(GetProcessHeap(), 0, Wide);
                return 400;
            }
            if (c < 0x20 || c == 0x7f)
            {
                HeapFree(GetProcessHeap(), 0, Dec);
                HeapFree(GetProcessHeap(), 0, Wide);
                return 400;
            }
            Dec[n++] = c;
        }
        WideLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)Dec, n, Wide, PathRawLen + 1);
        if (!WideLen && n)
        {
            for (i = 0; i < n; i++)
                Wide[i] = Dec[i];
            WideLen = n;
        }
    }
    else
    {
        Wide[0] = L'*';
        WideLen = 1;
    }
    HeapFree(GetProcessHeap(), 0, Dec);

    /* normalize: backslashes are slashes, empty and "." segments vanish, ".." removes a segment */
    Out = Wide + PathRawLen + 2;
    if (Star)
    {
        Out[0] = L'*';
        n = 1;
    }
    else
    {
        BOOL Trail = FALSE;
        int Pos = 0;

        n = 0;
        Out[n++] = L'/';
        while (Pos < WideLen)
        {
            int S = Pos, L;

            while (Pos < WideLen && Wide[Pos] != L'/' && Wide[Pos] != L'\\')
                Pos++;
            L = Pos - S;
            Trail = (Pos < WideLen);
            if (Pos < WideLen)
                Pos++;
            if (L == 0 || (L == 1 && Wide[S] == L'.'))
            {
                if (L == 1)
                    Trail = TRUE;
                continue;
            }
            if (L == 2 && Wide[S] == L'.' && Wide[S + 1] == L'.')
            {
                if (n > 1)
                {
                    n--;
                    while (n > 1 && Out[n - 1] != L'/')
                        n--;
                }
                Trail = TRUE;
                continue;
            }
            if (n > 1)
                Out[n++] = L'/';
            memcpy(Out + n, Wide + S, L * sizeof(WCHAR));
            n += L;
        }
        if (Trail && n > 1)
            Out[n++] = L'/';
    }

    R->HostOff = 7;
    R->HostChars = HostLen + 1 + (ULONG)strlen(PortText);
    R->PathOff = R->HostOff + R->HostChars;
    R->PathChars = n;
    R->QueryOff = R->PathOff + n;
    R->QueryChars = QueryLen;
    R->FullChars = R->QueryOff + QueryLen;
    Full = Arena_Alloc(R, (R->FullChars + 1) * sizeof(WCHAR), sizeof(WCHAR));
    R->HostName = Arena_Alloc(R, (HostLen + 1) * sizeof(WCHAR), sizeof(WCHAR));
    if (!Full || !R->HostName)
    {
        HeapFree(GetProcessHeap(), 0, Wide);
        return 503;
    }
    {
        ULONG k, o = 0;
        const char *Pre = "http://";

        for (k = 0; k < 7; k++)
            Full[o++] = Pre[k];
        for (k = 0; k < HostLen; k++)
        {
            Full[o++] = (UCHAR)HostBuf[k];
            R->HostName[k] = (WCHAR)Lower((UCHAR)HostBuf[k]);
        }
        R->HostName[HostLen] = 0;
        Full[o++] = L':';
        for (k = 0; PortText[k]; k++)
            Full[o++] = PortText[k];
        memcpy(Full + o, Out, n * sizeof(WCHAR));
        o += n;
        for (k = 0; k < QueryLen; k++)
            Full[o++] = (UCHAR)Query[k];
        Full[o] = 0;
    }
    R->Full = Full;
    HeapFree(GetProcessHeap(), 0, Wide);
    return 0;
}

static REQ *ParseHead(CONN *C, const UCHAR *Head, ULONG HeadLen, int *Err)
{
    REQ *R;
    char *T;
    ULONG Lines = 0, i, Pos, LineEnd;
    char *Method, *Target, *Ver;
    ULONG MethodLen, TargetLen;
    HTTP_UNKNOWN_HEADER *Unk;
    ULONG UnkMax;

    *Err = 400;
    R = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*R));
    T = HeapAlloc(GetProcessHeap(), 0, HeadLen + 1);
    if (!R || !T)
    {
        *Err = 503;
        goto Fail;
    }
    memcpy(T, Head, HeadLen);
    T[HeadLen] = 0;
    R->ArenaCap = HeadLen * 16 + 4096;
    R->Arena = HeapAlloc(GetProcessHeap(), 0, R->ArenaCap);
    if (!R->Arena)
    {
        *Err = 503;
        goto Fail;
    }
    for (i = 0; i < HeadLen; i++)
        if (T[i] == '\n')
            Lines++;
    if (memchr(T, 0, HeadLen))
        goto Fail;
    UnkMax = Lines + 1;
    Unk = Arena_Alloc(R, UnkMax * sizeof(HTTP_UNKNOWN_HEADER), 8);
    if (!Unk)
        goto Fail;
    R->Unk = Unk;
    R->Conn = C;

    /* request line */
    Pos = 0;
    while (Pos < HeadLen && T[Pos] != '\n')
        Pos++;
    LineEnd = Pos;
    if (LineEnd && T[LineEnd - 1] == '\r')
        T[LineEnd - 1] = 0;
    T[LineEnd] = 0;
    Method = T;
    Target = strchr(Method, ' ');
    if (!Target)
        goto Fail;
    *Target++ = 0;
    Ver = strchr(Target, ' ');
    if (!Ver)
        goto Fail;
    *Ver++ = 0;
    MethodLen = (ULONG)strlen(Method);
    TargetLen = (ULONG)strlen(Target);
    if (!MethodLen || !TargetLen)
        goto Fail;
    for (i = 0; i < MethodLen; i++)
        if (!TokenChar((UCHAR)Method[i]))
            goto Fail;
    if (!strncmp(Ver, "HTTP/", 5) && Ver[5] >= '0' && Ver[5] <= '9' && Ver[6] == '.' && Ver[7] >= '0' && Ver[7] <= '9' && !Ver[8])
    {
        R->VerMajor = Ver[5] - '0';
        R->VerMinor = Ver[7] - '0';
        if (R->VerMajor != 1 || R->VerMinor > 1)
        {
            *Err = 505;
            goto Fail;
        }
    }
    else
        goto Fail;

    /* header fields */
    Pos = LineEnd + 1;
    for (;;)
    {
        char *Line, *Colon, *Val;
        ULONG NameLen, ValLen, k;

        if (Pos >= HeadLen)
            break;
        Line = T + Pos;
        while (Pos < HeadLen && T[Pos] != '\n')
            Pos++;
        T[Pos] = 0;
        Pos++;
        NameLen = (ULONG)strlen(Line);
        if (NameLen && Line[NameLen - 1] == '\r')
            Line[--NameLen] = 0;
        if (!NameLen)
            break;
        if (Line[0] == ' ' || Line[0] == '\t')
            goto Fail;
        Colon = strchr(Line, ':');
        if (!Colon || Colon == Line)
            goto Fail;
        NameLen = (ULONG)(Colon - Line);
        for (k = 0; k < NameLen; k++)
            if (!TokenChar((UCHAR)Line[k]))
                goto Fail;
        Val = Colon + 1;
        while (*Val == ' ' || *Val == '\t')
            Val++;
        ValLen = (ULONG)strlen(Val);
        while (ValLen && (Val[ValLen - 1] == ' ' || Val[ValLen - 1] == '\t'))
            ValLen--;
        if (ValLen > 65535 || NameLen > 65535)
            goto Fail;

        for (k = 0; k < HttpHeaderRequestMaximum; k++)
            if (IEq(Line, NameLen, ReqKnownNames[k]))
                break;
        if (k < HttpHeaderRequestMaximum)
        {
            KNOWNV *K = &R->Known[k];

            if (K->Len)
            {
                char *J = Arena_Alloc(R, K->Len + 2 + ValLen + 1, 1);

                if (!J || K->Len + 2 + ValLen > 65535)
                    goto Fail;
                memcpy(J, K->Value, K->Len);
                memcpy(J + K->Len, ", ", 2);
                memcpy(J + K->Len + 2, Val, ValLen);
                J[K->Len + 2 + ValLen] = 0;
                K->Value = J;
                K->Len = (USHORT)(K->Len + 2 + ValLen);
            }
            else
            {
                K->Value = Arena_Str(R, Val, ValLen);
                K->Len = (USHORT)ValLen;
                if (!K->Value)
                    goto Fail;
            }
        }
        else
        {
            ULONG u;

            for (u = 0; u < R->UnkCount; u++)
                if (IEq(Line, NameLen, Unk[u].pName))
                    break;
            if (u < R->UnkCount)
            {
                char *J = Arena_Alloc(R, Unk[u].RawValueLength + 2 + ValLen + 1, 1);

                if (!J || Unk[u].RawValueLength + 2 + ValLen > 65535)
                    goto Fail;
                memcpy(J, Unk[u].pRawValue, Unk[u].RawValueLength);
                memcpy(J + Unk[u].RawValueLength, ", ", 2);
                memcpy(J + Unk[u].RawValueLength + 2, Val, ValLen);
                J[Unk[u].RawValueLength + 2 + ValLen] = 0;
                Unk[u].pRawValue = J;
                Unk[u].RawValueLength = (USHORT)(Unk[u].RawValueLength + 2 + ValLen);
            }
            else
            {
                Unk[R->UnkCount].pName = Arena_Str(R, Line, NameLen);
                Unk[R->UnkCount].pRawValue = Arena_Str(R, Val, ValLen);
                if (!Unk[R->UnkCount].pName || !Unk[R->UnkCount].pRawValue)
                    goto Fail;
                Unk[R->UnkCount].NameLength = (USHORT)NameLen;
                Unk[R->UnkCount].RawValueLength = (USHORT)ValLen;
                R->UnkCount++;
            }
        }
    }

    /* verb */
    R->Verb = HttpVerbUnknown;
    for (i = 0; i < sizeof(VerbNames) / sizeof(VerbNames[0]); i++)
        if (!strcmp(Method, VerbNames[i]))
        {
            R->Verb = HttpVerbOPTIONS + i;
            break;
        }
    if (R->Verb == HttpVerbUnknown)
    {
        R->UnknownVerb = Arena_Str(R, Method, MethodLen);
        R->UnknownVerbLen = MethodLen;
        if (!R->UnknownVerb)
            goto Fail;
    }
    R->Head = (R->Verb == HttpVerbHEAD);
    R->RawUrl = Arena_Str(R, Target, TargetLen);
    R->RawUrlLen = TargetLen;
    if (!R->RawUrl || TargetLen > 65535)
        goto Fail;

    if (R->VerMinor == 1 && !R->Known[HttpHeaderHost].Len)
        goto Fail;

    /* body framing: a message with both a length and chunking is refused (request smuggling) */
    if (R->Known[HttpHeaderTransferEncoding].Len)
    {
        if (!IEq(R->Known[HttpHeaderTransferEncoding].Value, R->Known[HttpHeaderTransferEncoding].Len, "chunked"))
        {
            *Err = 501;
            goto Fail;
        }
        if (R->Known[HttpHeaderContentLength].Len)
            goto Fail;
        R->BodyKind = BODY_CHUNKED;
        R->CState = CS_SIZE;
    }
    else if (R->Known[HttpHeaderContentLength].Len)
    {
        ULONGLONG V = 0;
        const char *P = R->Known[HttpHeaderContentLength].Value;

        for (i = 0; i < R->Known[HttpHeaderContentLength].Len; i++)
        {
            if (P[i] < '0' || P[i] > '9' || V > 0x0fffffffffffffffULL)
                goto Fail;
            V = V * 10 + (P[i] - '0');
        }
        if (V)
        {
            R->BodyKind = BODY_LENGTH;
            R->BodyRemain = V;
        }
    }
    if (R->BodyKind == BODY_NONE)
        R->BodyDone = TRUE;

    if (R->Known[HttpHeaderConnection].Len)
    {
        const char *V = R->Known[HttpHeaderConnection].Value;
        ULONG L = R->Known[HttpHeaderConnection].Len;

        if (HasToken(V, L, "close"))
            R->CloseAfter = TRUE;
        else if (R->VerMinor == 0 && HasToken(V, L, "keep-alive"))
            R->KeepAliveHdr = TRUE;
    }
    if (R->VerMinor == 0 && !R->KeepAliveHdr)
        R->CloseAfter = TRUE;

    *Err = Cook(R, R->RawUrl, R->RawUrlLen, &C->Local);
    if (*Err)
        goto Fail;
    HeapFree(GetProcessHeap(), 0, T);
    return R;

Fail:
    HeapFree(GetProcessHeap(), 0, T);
    if (R)
    {
        HeapFree(GetProcessHeap(), 0, R->Arena);
        HeapFree(GetProcessHeap(), 0, R);
    }
    return NULL;
}

/* ---------------------------------------------------------------- entity body */

/* g_Lock held. Moves up to Max decoded body bytes out of the connection buffer without waiting. */
static ULONG Body_Take(CONN *C, REQ *R, PUCHAR Dst, ULONG Max)
{
    ULONG Out = 0;

    while (Out < Max && !R->BodyDone && !R->BodyErr)
    {
        ULONG Avail = C->Len - C->Pos, N;
        PUCHAR P = C->Buf + C->Pos, Nl;

        if (R->BodyKind == BODY_LENGTH)
        {
            N = Max - Out;
            if (N > Avail)
                N = Avail;
            if ((ULONGLONG)N > R->BodyRemain)
                N = (ULONG)R->BodyRemain;
            if (!N)
                break;
            memcpy(Dst + Out, P, N);
            C->Pos += N;
            Out += N;
            R->BodyRemain -= N;
            if (!R->BodyRemain)
                R->BodyDone = TRUE;
            continue;
        }

        switch (R->CState)
        {
            case CS_SIZE:
            {
                ULONGLONG Size = 0;
                ULONG k = 0;
                int V;

                Nl = Avail ? memchr(P, '\n', Avail) : NULL;
                if (!Nl)
                {
                    if (Avail > 4096)
                        R->BodyErr = TRUE;
                    return Out;
                }
                while (k < Avail && Hex(P[k], &V))
                {
                    if (Size > 0x07ffffffffffffffULL)
                    {
                        R->BodyErr = TRUE;
                        return Out;
                    }
                    Size = Size * 16 + V;
                    k++;
                }
                if (!k || (P[k] != ';' && P[k] != ' ' && P[k] != '\t' && P[k] != '\r' && P[k] != '\n'))
                {
                    R->BodyErr = TRUE;
                    return Out;
                }
                C->Pos += (ULONG)(Nl - P) + 1;
                if (!Size)
                    R->CState = CS_TRAILER;
                else
                {
                    R->BodyRemain = Size;
                    R->CState = CS_DATA;
                }
                break;
            }
            case CS_DATA:
                N = Max - Out;
                if (N > Avail)
                    N = Avail;
                if ((ULONGLONG)N > R->BodyRemain)
                    N = (ULONG)R->BodyRemain;
                if (!N)
                    return Out;
                memcpy(Dst + Out, P, N);
                C->Pos += N;
                Out += N;
                R->BodyRemain -= N;
                if (!R->BodyRemain)
                    R->CState = CS_DATACRLF;
                break;
            case CS_DATACRLF:
                if (!Avail)
                    return Out;
                if (P[0] == '\n')
                    C->Pos++;
                else if (P[0] == '\r')
                {
                    if (Avail < 2)
                        return Out;
                    if (P[1] != '\n')
                    {
                        R->BodyErr = TRUE;
                        return Out;
                    }
                    C->Pos += 2;
                }
                else
                {
                    R->BodyErr = TRUE;
                    return Out;
                }
                R->CState = CS_SIZE;
                break;
            case CS_TRAILER:
                Nl = Avail ? memchr(P, '\n', Avail) : NULL;
                if (!Nl)
                {
                    if (Avail > 8192)
                        R->BodyErr = TRUE;
                    return Out;
                }
                N = (ULONG)(Nl - P) + 1;
                if (N == 1 || (N == 2 && P[0] == '\r'))
                {
                    R->CState = CS_DONE;
                    R->BodyDone = TRUE;
                }
                C->Pos += N;
                break;
            default:
                R->BodyDone = TRUE;
                break;
        }
    }
    return Out;
}

/* ---------------------------------------------------------------- delivering requests */

static REQ *Queue_FindReq(RQ *Q, ULONGLONG Id)
{
    HL *E;

    for (E = Q->Reqs.Next; E != &Q->Reqs; E = E->Next)
    {
        REQ *R = HL_ENTRY(E, REQ, Link);

        if (R->Id == Id && Id)
            return R;
    }
    return NULL;
}

/* g_Lock held. POST_OK with the bytes used, or POST_MORE with the size needed (the request then keeps its id
 * and waits to be fetched with it). */
static int Render(REQ *R, RQ *Q, ULONG Flags, void *Buf, ULONG Size, ULONG *Bytes)
{
    CONN *C = R->Conn;
    ULONG Hdr = Q->V2 ? sizeof(HPI_REQUEST_V2) : sizeof(HPI_REQUEST_V1);
    ULONG Off = Hdr, OffLocal, OffRemote, OffUnk, OffRaw, OffVerb = 0, OffFull, BodyOff, i;
    PUCHAR B = Buf;
    HPI_REQUEST_V1 *V1 = Buf;
    HTTP_UNKNOWN_HEADER *Unk;
    WCHAR *Full;
    ULONG LocalLen = C->Local.ss_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);
    ULONG RemoteLen = C->Remote.ss_family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);
    ULONG Used;

    OffLocal = Off;
    Off += 32;
    OffRemote = Off;
    Off += 32;
    OffUnk = Off;
    Off += R->UnkCount * sizeof(HTTP_UNKNOWN_HEADER);
    OffRaw = Off;
    Off += R->RawUrlLen + 1;
    if (R->UnknownVerbLen)
    {
        OffVerb = Off;
        Off += R->UnknownVerbLen + 1;
    }
    for (i = 0; i < HttpHeaderRequestMaximum; i++)
        if (R->Known[i].Len)
            Off += R->Known[i].Len + 1;
    for (i = 0; i < R->UnkCount; i++)
        Off += R->Unk[i].NameLength + 1 + R->Unk[i].RawValueLength + 1;
    Off = (Off + 1) & ~1u;
    OffFull = Off;
    Off += (R->FullChars + 1) * sizeof(WCHAR);
    Off = (Off + 7) & ~7u;
    BodyOff = Off;

    if (Size < BodyOff)
    {
        *Bytes = BodyOff;
        if (Size >= sizeof(HPI_REQUEST_V1))
            V1->RequestId = R->Id;
        R->State = REQ_PEEKED;
        return POST_MORE;
    }

    RtlZeroMemory(B, Hdr);
    V1->ConnectionId = C->Id;
    V1->RawConnectionId = C->Id;
    V1->RequestId = R->Id;
    V1->UrlContext = R->UrlContext;
    V1->Version.MajorVersion = R->VerMajor;
    V1->Version.MinorVersion = R->VerMinor;
    V1->Verb = R->Verb;
    memcpy(B + OffLocal, &C->Local, LocalLen);
    memcpy(B + OffRemote, &C->Remote, RemoteLen);
    V1->Address.pLocalAddress = (SOCKADDR *)(B + OffLocal);
    V1->Address.pRemoteAddress = (SOCKADDR *)(B + OffRemote);
    memcpy(B + OffRaw, R->RawUrl, R->RawUrlLen + 1);
    V1->pRawUrl = (char *)(B + OffRaw);
    V1->RawUrlLength = (USHORT)R->RawUrlLen;
    if (R->UnknownVerbLen)
    {
        memcpy(B + OffVerb, R->UnknownVerb, R->UnknownVerbLen + 1);
        V1->pUnknownVerb = (char *)(B + OffVerb);
        V1->UnknownVerbLength = (USHORT)R->UnknownVerbLen;
    }

    Full = (WCHAR *)(B + OffFull);
    memcpy(Full, R->Full, (R->FullChars + 1) * sizeof(WCHAR));
    V1->CookedUrl.pFullUrl = Full;
    V1->CookedUrl.FullUrlLength = (USHORT)(R->FullChars * sizeof(WCHAR));
    V1->CookedUrl.pHost = Full + R->HostOff;
    V1->CookedUrl.HostLength = (USHORT)(R->HostChars * sizeof(WCHAR));
    V1->CookedUrl.pAbsPath = Full + R->PathOff;
    V1->CookedUrl.AbsPathLength = (USHORT)(R->PathChars * sizeof(WCHAR));
    if (R->QueryChars)
    {
        V1->CookedUrl.pQueryString = Full + R->QueryOff;
        V1->CookedUrl.QueryStringLength = (USHORT)(R->QueryChars * sizeof(WCHAR));
    }

    {
        PUCHAR S = B + OffRaw + R->RawUrlLen + 1 + (R->UnknownVerbLen ? R->UnknownVerbLen + 1 : 0);

        for (i = 0; i < HttpHeaderRequestMaximum; i++)
        {
            if (!R->Known[i].Len)
                continue;
            memcpy(S, R->Known[i].Value, R->Known[i].Len + 1);
            V1->Headers.KnownHeaders[i].pRawValue = (char *)S;
            V1->Headers.KnownHeaders[i].RawValueLength = R->Known[i].Len;
            S += R->Known[i].Len + 1;
        }
        Unk = (HTTP_UNKNOWN_HEADER *)(B + OffUnk);
        for (i = 0; i < R->UnkCount; i++)
        {
            memcpy(S, R->Unk[i].pName, R->Unk[i].NameLength + 1);
            Unk[i].pName = (char *)S;
            Unk[i].NameLength = R->Unk[i].NameLength;
            S += R->Unk[i].NameLength + 1;
            memcpy(S, R->Unk[i].pRawValue, R->Unk[i].RawValueLength + 1);
            Unk[i].pRawValue = (char *)S;
            Unk[i].RawValueLength = R->Unk[i].RawValueLength;
            S += R->Unk[i].RawValueLength + 1;
        }
        if (R->UnkCount)
        {
            V1->Headers.pUnknownHeaders = Unk;
            V1->Headers.UnknownHeaderCount = (USHORT)R->UnkCount;
        }
    }
    V1->BytesReceived = R->BytesRecv;

    Used = BodyOff;
    if ((Flags & HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY) && R->BodyKind && !R->BodyDone &&
        Size > BodyOff + sizeof(HPI_DATA_CHUNK))
    {
        ULONG N = Body_Take(C, R, B + BodyOff + sizeof(HPI_DATA_CHUNK), Size - BodyOff - sizeof(HPI_DATA_CHUNK));

        if (N)
        {
            HPI_DATA_CHUNK *Ch = (HPI_DATA_CHUNK *)(B + BodyOff);

            Ch->DataChunkType = HttpDataChunkFromMemory;
            Ch->u.FromMemory.pBuffer = B + BodyOff + sizeof(HPI_DATA_CHUNK);
            Ch->u.FromMemory.BufferLength = N;
            V1->EntityChunkCount = 1;
            V1->pEntityChunks = Ch;
            Used = BodyOff + sizeof(HPI_DATA_CHUNK) + N;
        }
    }
    if (R->BodyKind && !R->BodyDone)
        V1->Flags |= HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS;
    R->State = REQ_DELIVERED;
    *Bytes = Used;
    return POST_OK;
}

/* g_Lock held: hands a new request to the first caller waiting for one */
static void Queue_Deliver(RQ *Q, REQ *R)
{
    HL *E;

    for (E = Q->Waiters.Next; E != &Q->Waiters; E = E->Next)
    {
        WAITER *W = HL_ENTRY(E, WAITER, Link);
        ULONG Bytes;
        int Kind = Render(R, Q, W->Flags, W->Buf, W->Size, &Bytes);

        Waiter_Complete(Q, W, Kind == POST_OK ? ERROR_SUCCESS : ERROR_MORE_DATA, Kind, Bytes);
        return;
    }
}

/* ---------------------------------------------------------------- connection thread */

static void Cmd_Complete(CMD *K, ULONG Status, int Kind, ULONG Bytes)
{
    HL_DEL(&K->Link);
    if (K->Ovl)
    {
        Post_Completion(K->Queue, K->Ovl, Kind, Bytes);
        HeapFree(GetProcessHeap(), 0, K);
    }
    else
    {
        K->Result = Status;
        K->Got = Bytes;
        K->Done = TRUE;
        SetEvent(K->hDone);
    }
}

/* g_Lock held. Serves the commands of the program; TRUE when the first one waits for data from the socket */
static BOOL Conn_Process(CONN *C, REQ *R)
{
    HL *E, *N;

    for (E = C->Cmds.Next; E != &C->Cmds; E = N)
    {
        CMD *K = HL_ENTRY(E, CMD, Link);
        ULONG Got;

        N = E->Next;
        if (K->Kind == CMD_DISC)
        {
            /* a FIN is only the end of the request direction: http.sys keeps the request valid, and answers it, until the
         * connection is reset */
        if (C->Dead || C->Abort)
                Cmd_Complete(K, ERROR_SUCCESS, POST_OK, 0);
            continue;
        }
        if (C->Abort || C->Dead || R->BodyErr)
        {
            Cmd_Complete(K, ERROR_CONNECTION_INVALID, POST_CANCEL, 0);
            continue;
        }
        Got = Body_Take(C, R, K->Buf + K->Got, K->Size - K->Got);
        K->Got += Got;
        if (R->BodyErr)
            Cmd_Complete(K, ERROR_CONNECTION_INVALID, POST_CANCEL, 0);
        else if (K->Got == K->Size || (K->Got && !(K->Flags & 1)) || R->BodyDone)
            Cmd_Complete(K, K->Got ? ERROR_SUCCESS : ERROR_HANDLE_EOF, POST_OK, K->Got);
        else if (C->PeerClosed)
            Cmd_Complete(K, ERROR_CONNECTION_INVALID, POST_CANCEL, 0);
        else
            return TRUE;
    }
    return FALSE;
}

static ULONG FindHeadEnd(const UCHAR *P, ULONG Len)
{
    ULONG i;

    for (i = 0; i < Len; i++)
    {
        if (P[i] != '\n')
            continue;
        if (i + 1 < Len && P[i + 1] == '\n')
            return i + 2;
        if (i + 2 < Len && P[i + 1] == '\r' && P[i + 2] == '\n')
            return i + 3;
    }
    return 0;
}

static void Conn_Teardown(CONN *C)
{
    HL *E;

    EnterCriticalSection(&g_Lock);
    C->Dead = TRUE;
    while (!HL_EMPTY(&C->Cmds))
    {
        CMD *K = HL_ENTRY(C->Cmds.Next, CMD, Link);

        if (K->Kind == CMD_DISC)
            Cmd_Complete(K, ERROR_SUCCESS, POST_OK, 0);
        else
            Cmd_Complete(K, ERROR_CONNECTION_INVALID, POST_CANCEL, 0);
    }
    HL_DEL(&C->Link);
    LeaveCriticalSection(&g_Lock);

    EnterCriticalSection(&C->SendLock);
    if (C->Abort || C->SendBroken)
    {
        struct linger Li = { 1, 0 };

        setsockopt(C->Sock, SOL_SOCKET, SO_LINGER, (char *)&Li, sizeof(Li));
        closesocket(C->Sock);
    }
    else
    {
        /* finish the stream properly: the peer must see the whole response before the close */
        UCHAR Tmp[512];
        DWORD Start = GetTickCount();

        shutdown(C->Sock, SD_SEND);
        while (GetTickCount() - Start < 1500)
        {
            fd_set Rd;
            struct timeval Tv = { 0, 200000 };
            int N;

            FD_ZERO(&Rd);
            FD_SET(C->Sock, &Rd);
            if (select(0, &Rd, NULL, NULL, &Tv) > 0)
            {
                N = recv(C->Sock, (char *)Tmp, sizeof(Tmp), 0);
                if (N == 0 || (N < 0 && WSAGetLastError() != WSAEWOULDBLOCK))
                    break;
            }
        }
        closesocket(C->Sock);
    }
    LeaveCriticalSection(&C->SendLock);
    (void)E;
    DeleteCriticalSection(&C->SendLock);
    CloseHandle(C->hSockEvt);
    CloseHandle(C->hCmdEvt);
    HeapFree(GetProcessHeap(), 0, C->Buf);
    HeapFree(GetProcessHeap(), 0, C);
}

/* Serves one delivered request until its response is complete or the connection is gone */
static void Conn_Serve(CONN *C, REQ *R)
{
    HANDLE H[2];

    H[0] = C->hSockEvt;
    H[1] = C->hCmdEvt;
    for (;;)
    {
        BOOL Need, Done;
        DWORD W;

        EnterCriticalSection(&g_Lock);
        Need = Conn_Process(C, R);
        Done = R->RespDone || C->Abort || C->Dead;
        LeaveCriticalSection(&g_Lock);
        if (Done)
            return;
        if (Need && Conn_Pull(C) != 0)
            continue;
        EnterCriticalSection(&g_Lock);
        Done = C->PeerClosed;
        LeaveCriticalSection(&g_Lock);
        W = WaitForMultipleObjects(Done ? 1 : 2, Done ? &H[1] : H, FALSE, INFINITE);
        if (!Done && W == WAIT_OBJECT_0)
        {
            Conn_Events(C);
            Conn_Pull(C);
        }
    }
}

static DWORD WINAPI ConnThread(PVOID Param)
{
    CONN *C = Param;
    HANDLE H[2];

    H[0] = C->hSockEvt;
    H[1] = C->hCmdEvt;
    for (;;)
    {
        ULONG HeadLen = 0;
        BOOL Stop = FALSE, TooBig = FALSE, Closed = FALSE;
        REQ *R;
        int Err;
        RQ *Q;
        URLREG *U;

        for (;;)
        {
            int N;
            DWORD W;

            EnterCriticalSection(&g_Lock);
            while (C->Pos < C->Len && (C->Buf[C->Pos] == '\r' || C->Buf[C->Pos] == '\n'))
                C->Pos++;
            HeadLen = C->Len > C->Pos ? FindHeadEnd(C->Buf + C->Pos, C->Len - C->Pos) : 0;
            TooBig = !HeadLen && (C->Len - C->Pos) >= HPI_MAX_HEAD;
            Stop = C->Abort || C->Dead;
            Closed = C->PeerClosed;
            LeaveCriticalSection(&g_Lock);
            if (HeadLen || TooBig || Stop || Closed)
                break;
            N = Conn_Pull(C);
            if (N != 0)
                continue;
            W = WaitForMultipleObjects(2, H, FALSE, HPI_IDLE_TIMEOUT);
            if (W == WAIT_TIMEOUT)
            {
                Stop = TRUE;
                break;
            }
            if (W == WAIT_OBJECT_0)
                Conn_Events(C);
        }
        if (!HeadLen)
        {
            if (TooBig)
                Conn_SendError(C, 400);
            break;
        }

        R = ParseHead(C, C->Buf + C->Pos, HeadLen, &Err);
        if (!R)
        {
            Conn_SendError(C, (USHORT)Err);
            break;
        }
        EnterCriticalSection(&g_Lock);
        C->Pos += HeadLen;
        {
            ULONG Buffered = C->Len - C->Pos;

            if (R->BodyKind == BODY_LENGTH && (ULONGLONG)Buffered > R->BodyRemain)
                Buffered = (ULONG)R->BodyRemain;
            if (!R->BodyKind)
                Buffered = 0;
            R->BytesRecv = (ULONGLONG)HeadLen + Buffered;
        }
        U = Url_Match(R->HostName, C->Local.ss_family == AF_INET ? ntohs(((SOCKADDR_IN *)&C->Local)->sin_port) :
                      ntohs(((SOCKADDR_IN6 *)&C->Local)->sin6_port), &C->Local, R->Full + R->PathOff, R->PathChars);
        Q = U ? (U->Queue ? U->Queue : (U->Group ? U->Group->Queue : NULL)) : NULL;
        if (!U || !Q || Q->Shutdown || Q->Closed)
        {
            LeaveCriticalSection(&g_Lock);
            Conn_SendError(C, U ? 503 : 404);
            Req_Free(R);
            break;
        }
        R->Queue = Q;
        R->UrlContext = U->Context;
        R->Id = New_Id();
        R->State = REQ_READY;
        HL_ADD(&Q->Reqs, &R->Link);
        C->Cur = R;
        Queue_Deliver(Q, R);
        LeaveCriticalSection(&g_Lock);

        Conn_Serve(C, R);

        /* the response is done (or the connection is): let go of the request */
        EnterCriticalSection(&g_Lock);
        Stop = C->Abort || C->Dead || !R->RespDone || R->CloseAfter || !Url_PortListening(C->LPort);
        HL_DEL(&R->Link);
        C->Cur = NULL;
        LeaveCriticalSection(&g_Lock);
        if (!Stop && R->BodyKind && !R->BodyDone)
        {
            /* a body the program never read is skipped, within reason, so that the next request can be found */
            DWORD Start = GetTickCount();
            ULONGLONG Skipped = 0;
            UCHAR Junk[2048];

            while (!R->BodyDone && !R->BodyErr)
            {
                ULONG N;
                BOOL Gone;

                EnterCriticalSection(&g_Lock);
                N = Body_Take(C, R, Junk, sizeof(Junk));
                Gone = C->Abort || C->Dead;
                LeaveCriticalSection(&g_Lock);
                Skipped += N;
                if (Gone || Skipped > 0x100000 || GetTickCount() - Start > 5000)
                {
                    Stop = TRUE;
                    break;
                }
                if (N || R->BodyDone || R->BodyErr)
                    continue;
                if (Conn_Pull(C) > 0)
                    continue;
                EnterCriticalSection(&g_Lock);
                Gone = C->PeerClosed;
                LeaveCriticalSection(&g_Lock);
                if (Gone)
                {
                    Stop = TRUE;
                    break;
                }
                WaitForSingleObject(C->hSockEvt, 500);
                Conn_Events(C);
            }
            if (R->BodyErr)
                Stop = TRUE;
        }
        Req_Free(R);
        if (Stop)
            break;
    }
    Conn_Teardown(C);
    return 0;
}

/* getsockname of an accepted socket gives the address that the listener is bound to; when that is "any address"
 * (ReactOS does so), the address the peer was reached on is what a UDP socket connected to the peer reports */
static void Conn_FixLocal(SOCKADDR_STORAGE *Local, const SOCKADDR_STORAGE *Remote)
{
    SOCKET U;
    SOCKADDR_IN Peer, Mine;
    int Len = sizeof(Mine);

    if (Local->ss_family != AF_INET || ((SOCKADDR_IN *)Local)->sin_addr.s_addr || Remote->ss_family != AF_INET)
        return;
    U = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (U == INVALID_SOCKET)
        return;
    Peer = *(SOCKADDR_IN *)Remote;
    Peer.sin_port = htons(9);
    if (!connect(U, (SOCKADDR *)&Peer, sizeof(Peer)) && !getsockname(U, (SOCKADDR *)&Mine, &Len) && Mine.sin_family == AF_INET)
        ((SOCKADDR_IN *)Local)->sin_addr = Mine.sin_addr;
    closesocket(U);
}

void Conn_New(SOCKET S, const SOCKADDR_STORAGE *Local, const SOCKADDR_STORAGE *Remote)
{
    CONN *C = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*C));
    BOOL On = TRUE;
    HANDLE hThread;

    if (!C)
    {
        closesocket(S);
        return;
    }
    C->Sock = S;
    C->Local = *Local;
    C->Remote = *Remote;
    Conn_FixLocal(&C->Local, &C->Remote);
    C->Id = New_Id();
    C->LPort = ntohs(C->Local.ss_family == AF_INET ? ((SOCKADDR_IN *)&C->Local)->sin_port : ((SOCKADDR_IN6 *)&C->Local)->sin6_port);
    C->hSockEvt = CreateEventW(NULL, TRUE, FALSE, NULL);
    C->hCmdEvt = CreateEventW(NULL, FALSE, FALSE, NULL);
    InitializeCriticalSection(&C->SendLock);
    HL_INIT(&C->Cmds);
    setsockopt(S, IPPROTO_TCP, TCP_NODELAY, (char *)&On, sizeof(On));
    if (!C->hSockEvt || !C->hCmdEvt || WSAEventSelect(S, C->hSockEvt, FD_READ | FD_CLOSE))
    {
        if (C->hSockEvt)
            CloseHandle(C->hSockEvt);
        if (C->hCmdEvt)
            CloseHandle(C->hCmdEvt);
        DeleteCriticalSection(&C->SendLock);
        closesocket(S);
        HeapFree(GetProcessHeap(), 0, C);
        return;
    }
    EnterCriticalSection(&g_Lock);
    HL_ADD(&g_Conns, &C->Link);
    LeaveCriticalSection(&g_Lock);
    hThread = CreateThread(NULL, 0, ConnThread, C, 0, NULL);
    if (!hThread)
    {
        EnterCriticalSection(&g_Lock);
        HL_DEL(&C->Link);
        LeaveCriticalSection(&g_Lock);
        CloseHandle(C->hSockEvt);
        CloseHandle(C->hCmdEvt);
        DeleteCriticalSection(&C->SendLock);
        closesocket(S);
        HeapFree(GetProcessHeap(), 0, C);
        return;
    }
    CloseHandle(hThread);
}

/* g_Lock held */
void Queue_AbortRequests(RQ *Q)
{
    HL *E;

    for (E = Q->Reqs.Next; E != &Q->Reqs; E = E->Next)
    {
        REQ *R = HL_ENTRY(E, REQ, Link);

        R->Aborted = TRUE;
        R->Conn->Abort = TRUE;
        SetEvent(R->Conn->hCmdEvt);
    }
}

/* ---------------------------------------------------------------- calls of the program */

ULONG Req_Receive(HANDLE Queue, ULONGLONG Id, ULONG Flags, void *Buf, ULONG Size, ULONG *Ret, OVERLAPPED *Ovl)
{
    RQ *Q;
    REQ *R = NULL;
    ULONG Bytes, Res;
    int Kind;

    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    if (!Q || Q->Shutdown)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    if (!Buf || Size < (Q->V2 ? sizeof(HPI_REQUEST_V2) : sizeof(HPI_REQUEST_V1)))
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (Id)
    {
        R = Queue_FindReq(Q, Id);
        if (!R || R->State != REQ_PEEKED)
        {
            LeaveCriticalSection(&g_Lock);
            return ERROR_CONNECTION_INVALID;
        }
    }
    else
    {
        HL *E;

        for (E = Q->Reqs.Next; E != &Q->Reqs; E = E->Next)
            if (HL_ENTRY(E, REQ, Link)->State == REQ_READY)
            {
                R = HL_ENTRY(E, REQ, Link);
                break;
            }
    }
    if (R)
    {
        Kind = Render(R, Q, Flags, Buf, Size, &Bytes);
        Res = Kind == POST_OK ? ERROR_SUCCESS : ERROR_MORE_DATA;
        Res = Op_Finish(Q, Ovl, Res, Kind, Bytes, Ret);
        LeaveCriticalSection(&g_Lock);
        return Res;
    }
    else
    {
        WAITER *W = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*W));

        if (!W)
        {
            LeaveCriticalSection(&g_Lock);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        W->Ovl = Ovl;
        W->Flags = Flags;
        W->Buf = Buf;
        W->Size = Size;
        if (!Ovl)
        {
            W->hDone = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!W->hDone)
            {
                LeaveCriticalSection(&g_Lock);
                HeapFree(GetProcessHeap(), 0, W);
                return ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        HL_ADD(&Q->Waiters, &W->Link);
        LeaveCriticalSection(&g_Lock);
        if (Ovl)
        {
            if (Ret)
                *Ret = 0;
            return ERROR_IO_PENDING;
        }
        WaitForSingleObject(W->hDone, INFINITE);
        Res = W->Result;
        if (Ret)
            *Ret = W->Bytes;
        CloseHandle(W->hDone);
        HeapFree(GetProcessHeap(), 0, W);
        return Res;
    }
}

static CMD *Cmd_New(RQ *Q, REQ *R, int Kind, OVERLAPPED *Ovl)
{
    CMD *K = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*K));

    if (!K)
        return NULL;
    K->Kind = Kind;
    K->Queue = Q;
    K->Req = R;
    K->Ovl = Ovl;
    if (!Ovl)
    {
        K->hDone = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!K->hDone)
        {
            HeapFree(GetProcessHeap(), 0, K);
            return NULL;
        }
    }
    return K;
}

/* g_Lock held on entry, released here */
static ULONG Cmd_Run(CONN *C, CMD *K, ULONG *Ret)
{
    ULONG Res;

    HL_ADD(&C->Cmds, &K->Link);
    SetEvent(C->hCmdEvt);
    if (K->Ovl)
    {
        LeaveCriticalSection(&g_Lock);
        if (Ret)
            *Ret = 0;
        return ERROR_IO_PENDING;
    }
    LeaveCriticalSection(&g_Lock);
    WaitForSingleObject(K->hDone, INFINITE);
    Res = K->Result;
    if (Ret)
        *Ret = K->Got;
    CloseHandle(K->hDone);
    HeapFree(GetProcessHeap(), 0, K);
    return Res;
}

ULONG Req_Body(HANDLE Queue, ULONGLONG Id, ULONG Flags, void *Buf, ULONG Size, ULONG *Ret, OVERLAPPED *Ovl)
{
    RQ *Q;
    REQ *R;
    CMD *K;

    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    if (!Q || Q->Shutdown)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    R = Queue_FindReq(Q, Id);
    if (!R || R->State != REQ_DELIVERED || R->Conn->Dead || R->Conn->Abort)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_CONNECTION_INVALID;
    }
    if (!Buf || !Size)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_PARAMETER;
    }
    if (R->BodyDone)
    {
        LeaveCriticalSection(&g_Lock);
        if (Ret)
            *Ret = 0;
        return ERROR_HANDLE_EOF;
    }
    K = Cmd_New(Q, R, CMD_BODY, Ovl);
    if (!K)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    K->Buf = Buf;
    K->Size = Size;
    K->Flags = Flags;
    return Cmd_Run(R->Conn, K, Ret);
}

ULONG Req_Cancel(HANDLE Queue, ULONGLONG Id, OVERLAPPED *Ovl)
{
    RQ *Q;
    REQ *R;
    ULONG Res;

    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    if (!Q)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    R = Queue_FindReq(Q, Id);
    if (!R)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_CONNECTION_INVALID;
    }
    R->Aborted = TRUE;
    R->Conn->Abort = TRUE;
    SetEvent(R->Conn->hCmdEvt);
    Res = Op_Finish(Q, Ovl, ERROR_SUCCESS, POST_OK, 0, NULL);
    LeaveCriticalSection(&g_Lock);
    return Res;
}

ULONG Req_WaitDisconnect(HANDLE Queue, ULONGLONG ConnId, OVERLAPPED *Ovl)
{
    RQ *Q;
    HL *E;
    CONN *C = NULL;
    CMD *K;

    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    if (!Q)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    for (E = g_Conns.Next; E != &g_Conns; E = E->Next)
        if (HL_ENTRY(E, CONN, Link)->Id == ConnId)
        {
            C = HL_ENTRY(E, CONN, Link);
            break;
        }
    if (!C)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_CONNECTION_INVALID;
    }
    K = Cmd_New(Q, NULL, CMD_DISC, Ovl);
    if (!K)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return Cmd_Run(C, K, NULL);
}

/* ---------------------------------------------------------------- responses */

typedef struct _OB { PUCHAR P; ULONG Len, Cap; } OB;

static BOOL OB_Add(OB *O, const void *D, ULONG N)
{
    if (O->Len + N > O->Cap)
    {
        ULONG Cap = O->Cap ? O->Cap : 2048;
        PUCHAR P;

        while (Cap < O->Len + N)
            Cap *= 2;
        P = O->P ? HeapReAlloc(GetProcessHeap(), 0, O->P, Cap) : HeapAlloc(GetProcessHeap(), 0, Cap);
        if (!P)
            return FALSE;
        O->P = P;
        O->Cap = Cap;
    }
    memcpy(O->P + O->Len, D, N);
    O->Len += N;
    return TRUE;
}

static BOOL OB_Str(OB *O, const char *S)
{
    return OB_Add(O, S, (ULONG)strlen(S));
}

static BOOL ValueOk(const char *V, ULONG Len)
{
    ULONG i;

    for (i = 0; i < Len; i++)
        if (V[i] == '\r' || V[i] == '\n' || V[i] == 0)
            return FALSE;
    return TRUE;
}

static BOOL OB_Header(OB *O, const char *Name, ULONG NameLen, const char *Val, ULONG ValLen)
{
    return OB_Add(O, Name, NameLen) && OB_Add(O, ": ", 2) && OB_Add(O, Val, ValLen) && OB_Add(O, "\r\n", 2);
}

typedef struct _HPI_RESPONSE_V2
{
    HTTP_RESPONSE_V1 s;
    USHORT ResponseInfoCount;
    HTTP_RESPONSE_INFO *pResponseInfo;
} HPI_RESPONSE_V2;

static ULONG Build_Headers(OB *O, REQ *R, void *Resp, BOOL V2, ULONG Flags, ULONGLONG Total, BOOL *Interim,
                           BOOL *BodyAllowed, BOOL *Unframed, BOOL *Close)
{
    HTTP_RESPONSE_V1 *V1 = Resp;
    HPI_RESPONSE_V2 *R2 = Resp;
    ULONG Status = V1->StatusCode, id, i, u;
    BOOL HasCL = FALSE, HasTE = FALSE, HasDate = FALSE, HasServer = FALSE, HasConn = FALSE;
    char Tmp[96], Date[40];
    USHORT Infos = V2 ? R2->ResponseInfoCount : 0;

    if (Status < 100 || Status > 999)
        return ERROR_INVALID_PARAMETER;
    *Interim = Status < 200 && Status != 101;
    *BodyAllowed = !R->Head && Status != 204 && Status != 304 && !*Interim;
    if (V1->pReason && V1->ReasonLength && !ValueOk(V1->pReason, V1->ReasonLength))
        return ERROR_INVALID_PARAMETER;
    sprintf(Tmp, "HTTP/1.1 %lu ", Status);
    if (!OB_Str(O, Tmp))
        return ERROR_NOT_ENOUGH_MEMORY;
    if (V1->pReason && V1->ReasonLength)
        OB_Add(O, V1->pReason, V1->ReasonLength);
    OB_Str(O, "\r\n");

    for (i = 0; i < Infos; i++)
    {
        HTTP_RESPONSE_INFO *Info = &R2->pResponseInfo[i];
        HPI_MULTIPLE_KNOWN_HEADERS *M;

        if (Info->Type != HttpResponseInfoTypeMultipleKnownHeaders)
            return ERROR_NOT_SUPPORTED; /* authentication, QoS, channel binding */
        M = Info->pInfo;
        if (!M || M->HeaderId >= HttpHeaderResponseMaximum)
            return ERROR_INVALID_PARAMETER;
    }
    for (id = 0; id < HttpHeaderResponseMaximum; id++)
    {
        HTTP_KNOWN_HEADER *K = &V1->Headers.KnownHeaders[id];
        BOOL Any = FALSE;
        const char *Name = RespKnownNames[id];

        if (K->pRawValue && K->RawValueLength)
        {
            if (!ValueOk(K->pRawValue, K->RawValueLength))
                return ERROR_INVALID_PARAMETER;
            OB_Header(O, Name, (ULONG)strlen(Name), K->pRawValue, K->RawValueLength);
            Any = TRUE;
        }
        for (i = 0; i < Infos; i++)
        {
            HPI_MULTIPLE_KNOWN_HEADERS *M = R2->pResponseInfo[i].pInfo;

            if (M->HeaderId != id)
                continue;
            for (u = 0; u < M->KnownHeaderCount; u++)
            {
                if (!M->KnownHeaders[u].pRawValue || !M->KnownHeaders[u].RawValueLength)
                    continue;
                if (!ValueOk(M->KnownHeaders[u].pRawValue, M->KnownHeaders[u].RawValueLength))
                    return ERROR_INVALID_PARAMETER;
                OB_Header(O, Name, (ULONG)strlen(Name), M->KnownHeaders[u].pRawValue, M->KnownHeaders[u].RawValueLength);
                Any = TRUE;
            }
        }
        if (Any)
        {
            if (id == HttpHeaderContentLength)
                HasCL = TRUE;
            else if (id == HttpHeaderTransferEncoding)
                HasTE = TRUE;
            else if (id == HttpHeaderDate)
                HasDate = TRUE;
            else if (id == HttpHeaderServer)
                HasServer = TRUE;
            else if (id == HttpHeaderConnection)
                HasConn = TRUE;
        }
    }
    if (!*Interim && !HasServer)
        OB_Str(O, "Server: Microsoft-HTTPAPI/2.0\r\n");
    for (i = 0; i < V1->Headers.UnknownHeaderCount; i++)
    {
        HTTP_UNKNOWN_HEADER *K = &V1->Headers.pUnknownHeaders[i];
        ULONG k;

        if (!K->pName || !K->NameLength)
            return ERROR_INVALID_PARAMETER;
        for (k = 0; k < K->NameLength; k++)
            if (!TokenChar((UCHAR)K->pName[k]))
                return ERROR_INVALID_PARAMETER;
        if (K->RawValueLength && (!K->pRawValue || !ValueOk(K->pRawValue, K->RawValueLength)))
            return ERROR_INVALID_PARAMETER;
        OB_Header(O, K->pName, K->NameLength, K->pRawValue ? K->pRawValue : "", K->pRawValue ? K->RawValueLength : 0);
    }
    if (!*Interim)
    {
        *Unframed = *BodyAllowed && !HasCL && !HasTE && (Flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA);
        *Close = R->CloseAfter || (Flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT) || (*Unframed && R->VerMinor == 0);
        if (!HasDate)
        {
            FormatDate(Date);
            OB_Str(O, "Date: ");
            OB_Str(O, Date);
            OB_Str(O, "\r\n");
        }
        if (!HasConn)
        {
            if (*Close)
                OB_Str(O, "Connection: close\r\n");
            else if (R->KeepAliveHdr)
                OB_Str(O, "Connection: keep-alive\r\n");
        }
        if (!HasCL && !HasTE && *BodyAllowed && !(Flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
        {
            sprintf(Tmp, "Content-Length: %I64u\r\n", Total);
            OB_Str(O, Tmp);
        }
    }
    return OB_Str(O, "\r\n") ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}

ULONG Req_Send(HANDLE Queue, ULONGLONG Id, ULONG Flags, HTTP_RESPONSE *Resp, ULONG ChunkCount, HPI_DATA_CHUNK *Chunks,
               ULONG *Ret, OVERLAPPED *Ovl, BOOL IsResponse)
{
    RQ *Q;
    REQ *R;
    CONN *C;
    OB O = { NULL, 0, 0 };
    ULONGLONG Total = 0;
    ULONG i, Res = ERROR_SUCCESS, Sent = 0;
    BOOL Interim = FALSE, BodyAllowed, Unframed = FALSE, Close = FALSE, V2;

    if (Flags & HTTP_SEND_RESPONSE_FLAG_OPAQUE)
        return ERROR_NOT_SUPPORTED;
    EnterCriticalSection(&g_Lock);
    Q = Queue_Find(Queue);
    if (!Q)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_HANDLE;
    }
    R = Queue_FindReq(Q, Id);
    if (!R || R->State != REQ_DELIVERED || R->RespDone || R->Conn->Dead || R->Conn->Abort)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_CONNECTION_INVALID;
    }
    if (IsResponse == R->RespStarted)
    {
        LeaveCriticalSection(&g_Lock);
        return ERROR_INVALID_PARAMETER;
    }
    R->Pins++;
    C = R->Conn;
    V2 = Q->V2;
    LeaveCriticalSection(&g_Lock);

    BodyAllowed = !R->Head;
    for (i = 0; i < ChunkCount && Res == ERROR_SUCCESS; i++)
    {
        if (Chunks[i].DataChunkType == HttpDataChunkFromMemory)
        {
            if (!Chunks[i].u.FromMemory.pBuffer && Chunks[i].u.FromMemory.BufferLength)
                Res = ERROR_INVALID_PARAMETER;
            Total += Chunks[i].u.FromMemory.BufferLength;
        }
        else if (Chunks[i].DataChunkType == HttpDataChunkFromFileHandle)
        {
            ULONGLONG Len = Chunks[i].u.FromFileHandle.Length;

            if (Len == (ULONGLONG)-1)
            {
                LARGE_INTEGER Size;

                if (!GetFileSizeEx(Chunks[i].u.FromFileHandle.FileHandle, &Size) ||
                    (ULONGLONG)Size.QuadPart < Chunks[i].u.FromFileHandle.StartingOffset)
                    Res = ERROR_INVALID_PARAMETER;
                else
                    Total += (ULONGLONG)Size.QuadPart - Chunks[i].u.FromFileHandle.StartingOffset;
            }
            else
                Total += Len;
        }
        else
            Res = ERROR_INVALID_PARAMETER; /* no fragment cache */
    }

    if (Res == ERROR_SUCCESS && IsResponse)
        Res = Build_Headers(&O, R, Resp, V2, Flags, Total, &Interim, &BodyAllowed, &Unframed, &Close);
    else if (Res == ERROR_SUCCESS)
        Close = (Flags & HTTP_SEND_RESPONSE_FLAG_DISCONNECT) != 0;

    for (i = 0; i < ChunkCount && Res == ERROR_SUCCESS && BodyAllowed && !Interim; i++)
    {
        if (Chunks[i].DataChunkType == HttpDataChunkFromMemory)
        {
            const char *P = Chunks[i].u.FromMemory.pBuffer;
            ULONG Left = Chunks[i].u.FromMemory.BufferLength;

            while (Left && Res == ERROR_SUCCESS)
            {
                ULONG N = Left > 65536 ? 65536 : Left;

                if (!OB_Add(&O, P, N))
                    Res = ERROR_NOT_ENOUGH_MEMORY;
                P += N;
                Left -= N;
                if (O.Len >= 65536)
                {
                    if (!Conn_SendAll(C, O.P, O.Len))
                        Res = ERROR_CONNECTION_INVALID;
                    Sent += O.Len;
                    O.Len = 0;
                }
            }
        }
        else
        {
            HANDLE File = Chunks[i].u.FromFileHandle.FileHandle;
            ULONGLONG Off = Chunks[i].u.FromFileHandle.StartingOffset, Left = Chunks[i].u.FromFileHandle.Length;
            UCHAR Block[16384];
            HANDLE Ev = CreateEventW(NULL, TRUE, FALSE, NULL);

            while (Left && Res == ERROR_SUCCESS)
            {
                OVERLAPPED Ov;
                DWORD Got = 0, Want = (Left == (ULONGLONG)-1 || Left > sizeof(Block)) ? sizeof(Block) : (DWORD)Left;

                RtlZeroMemory(&Ov, sizeof(Ov));
                Ov.Offset = (DWORD)Off;
                Ov.OffsetHigh = (DWORD)(Off >> 32);
                Ov.hEvent = Ev;
                if (!ReadFile(File, Block, Want, &Got, &Ov))
                {
                    if (GetLastError() == ERROR_IO_PENDING)
                    {
                        if (!GetOverlappedResult(File, &Ov, &Got, TRUE))
                            Got = 0;
                    }
                    else
                        Got = 0;
                }
                if (!Got)
                {
                    if (Left != (ULONGLONG)-1)
                        Res = ERROR_INVALID_PARAMETER;
                    break;
                }
                if (!OB_Add(&O, Block, Got))
                    Res = ERROR_NOT_ENOUGH_MEMORY;
                Off += Got;
                if (Left != (ULONGLONG)-1)
                    Left -= Got;
                if (O.Len >= 65536)
                {
                    if (!Conn_SendAll(C, O.P, O.Len))
                        Res = ERROR_CONNECTION_INVALID;
                    Sent += O.Len;
                    O.Len = 0;
                }
            }
            if (Ev)
                CloseHandle(Ev);
        }
    }
    if (Res == ERROR_SUCCESS && O.Len)
    {
        if (!Conn_SendAll(C, O.P, O.Len))
            Res = ERROR_CONNECTION_INVALID;
        Sent += O.Len;
    }
    HeapFree(GetProcessHeap(), 0, O.P);

    EnterCriticalSection(&g_Lock);
    if (Res == ERROR_CONNECTION_INVALID)
    {
        C->Abort = TRUE;
    }
    else if (Res == ERROR_SUCCESS && !Interim)
    {
        if (IsResponse)
            R->RespStarted = TRUE;
        if (Unframed)
            R->Unframed = TRUE;
        if (Close)
            R->CloseAfter = TRUE;
        if (!(Flags & HTTP_SEND_RESPONSE_FLAG_MORE_DATA))
        {
            if (R->Unframed)
                R->CloseAfter = TRUE;
            R->RespDone = TRUE;
        }
    }
    SetEvent(C->hCmdEvt);
    R->Pins--;
    if (Res == ERROR_SUCCESS)
        Res = Op_Finish(Q, Ovl, ERROR_SUCCESS, POST_OK, Sent, Ret);
    LeaveCriticalSection(&g_Lock);
    return Res;
}

/* g_Lock held: connections that wait for a request are dropped, those with a request in service finish it */
void Conn_RetirePort(USHORT Port)
{
    HL *E;

    for (E = g_Conns.Next; E != &g_Conns; E = E->Next)
    {
        CONN *C = HL_ENTRY(E, CONN, Link);

        if (C->LPort == Port && !C->Cur)
        {
            C->Abort = TRUE;
            SetEvent(C->hCmdEvt);
        }
    }
}

BOOL Conn_PortBusy(USHORT Port)
{
    HL *E;

    for (E = g_Conns.Next; E != &g_Conns; E = E->Next)
        if (HL_ENTRY(E, CONN, Link)->LPort == Port)
            return TRUE;
    return FALSE;
}
