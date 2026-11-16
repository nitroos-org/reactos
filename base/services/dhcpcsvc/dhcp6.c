/*
 * PROJECT:     ReactOS DHCP client service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DHCPv6 client (RFC 8415), stateless part: Information-Request, DNS servers, domain search list
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * One client thread for all interfaces, one small state machine per interface (D6IF):
 *
 *   IDLE    the interface has no reason for DHCPv6 (no socket)
 *   DELAY   the flag arrived; wait a random time up to INF_MAX_DELAY, then send (RFC 8415 18.2.6)
 *   INFORM  an Information-Request is out, retransmitted with the RFC 8415 15 back-off until a Reply comes
 *   BOUND   a Reply was accepted; the next Information-Request is due after the Information Refresh Time
 *
 * The decision "what does this interface ask the DHCPv6 servers for" is made in one place (WantedMode). The stateful
 * client (the M flag: Solicit/Advertise/Request/Reply with IA_NA) adds modes and states beside these, on the same
 * socket and timers; the kernel only has to install what it learns (addresses), the service owns the exchange.
 *
 * What a Reply gave is written to the registry (dhcp6.h) where the IP Helper API reads it: DNS servers and the
 * domain list join the per-interface lists GetAdaptersAddresses reports and the resolver uses.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <ip2string.h>

#include "dhcp6.h"

NTSYSAPI ULONG __cdecl DbgPrint(PCCH Format, ...);
#define D6_LOG(...) DbgPrint("DHCPCSVC6: " __VA_ARGS__)

/* RFC 8415 section 7 */
#define D6_PORT_CLIENT      546
#define D6_PORT_SERVER      547
#define D6_REPLY            7
#define D6_INFORMATION_REQUEST 11

#define D6_OPT_CLIENTID     1
#define D6_OPT_SERVERID     2
#define D6_OPT_ORO          6
#define D6_OPT_ELAPSED      8
#define D6_OPT_STATUS       13
#define D6_OPT_DNS          23
#define D6_OPT_DOMAINS      24
#define D6_OPT_REFRESH      32
#define D6_OPT_INF_MAX_RT   83

#define INF_MAX_DELAY_MS    1000        /* 7.6 */
#define INF_TIMEOUT_MS      1000
#define INF_MAX_RT_MS       3600000UL   /* 3600 s; a Reply may carry option 83 */
#define IRT_DEFAULT_S       86400UL     /* RFC 8415 7.6, 21.23 */
#define IRT_MINIMUM_S       600UL

#define D6_MAX_DNS          8
#define D6_MAX_DOMAINS      16
#define D6_MAX_DOMAIN_LEN   254
#define D6_MAX_DUID         130
#define D6_MAX_PACKET       1500

#define SCAN_INTERVAL_MS    5000        /* safety net beside the interface change notification */

/* IP_ADAPTER_IPV6_MANAGED_ADDRESS_CONFIGURATION_SUPPORTED of Windows 7: not in the headers of this tree */
#define D6_ADAPTER_MANAGED  0x0200

typedef enum _D6STATE { D6S_IDLE, D6S_DELAY, D6S_INFORM, D6S_BOUND } D6STATE;
typedef enum _D6MODE { D6M_NONE, D6M_INFORMATION } D6MODE; /* the stateful mode (M flag) is added here */

typedef struct _D6IF
{
    struct _D6IF *Next;
    DWORD IfIndex;
    CHAR Name[64];                  /* adapter GUID with braces: the Tcpip6 interface key */
    UCHAR Mac[8];
    ULONG MacLen;
    UCHAR LinkLocal[16];
    BOOL Seen;
    D6MODE Mode;
    D6STATE State;
    SOCKET Sock;
    ULONGLONG Due;                  /* timer: delay end, retransmission or refresh */
    BOOL HasDue;
    ULONGLONG FirstSent;
    ULONG Rt;                       /* current retransmission time, ms */
    ULONG MaxRt;                    /* INF_MAX_RT in force, ms */
    ULONG Sent;
    UCHAR Xid[3];
    BOOL Published;
    ULONG Replies;
} D6IF;

typedef struct _D6REPLY
{
    UCHAR Server[D6_MAX_DUID];
    ULONG ServerLen;
    ULONG Status;
    UCHAR Dns[D6_MAX_DNS][16];
    ULONG DnsCount;
    CHAR Domains[D6_MAX_DOMAINS][D6_MAX_DOMAIN_LEN];
    ULONG DomainCount;
    BOOL HasRefresh;
    ULONG Refresh;
    BOOL HasInfMaxRt;
    ULONG InfMaxRt;
} D6REPLY;

BOOLEAN WINAPI SystemFunction036(PVOID Buffer, ULONG Length); /* RtlGenRandom */

static D6IF *Interfaces;
static UCHAR Duid[D6_MAX_DUID];
static ULONG DuidLen;
static WSAEVENT SockEvent;

/* ---- small helpers ---- */

static ULONGLONG NowMs(void)
{
    static DWORD Last;
    static ULONGLONG High;
    DWORD Tick = GetTickCount();

    if (Tick < Last)
        High += 0x100000000ULL;
    Last = Tick;
    return High + Tick;
}

static ULONG Rand32(void)
{
    ULONG Value;

    if (!SystemFunction036(&Value, sizeof(Value)))
    {
        static ULONG Fallback;

        Fallback = Fallback * 1664525UL + 1013904223UL + GetTickCount();
        Value = Fallback;
    }
    return Value;
}

/* Base + Base * RAND, RAND uniform in [-0.1, +0.1] (RFC 8415 15) */
static ULONG Jitter(ULONG Base)
{
    LONG Permille = (LONG)(Rand32() % 201) - 100;
    LONGLONG Value = (LONGLONG)Base + (LONGLONG)Base * Permille / 1000;

    return Value < 1 ? 1 : (ULONG)Value;
}

static USHORT GetBe16(const UCHAR *P) { return (USHORT)((P[0] << 8) | P[1]); }
static ULONG GetBe32(const UCHAR *P) { return ((ULONG)P[0] << 24) | ((ULONG)P[1] << 16) | ((ULONG)P[2] << 8) | P[3]; }
static VOID PutBe16(UCHAR *P, USHORT V) { P[0] = (UCHAR)(V >> 8); P[1] = (UCHAR)V; }

static BOOL IsLinkLocal(const UCHAR *A) { return A[0] == 0xFE && (A[1] & 0xC0) == 0x80; }

static VOID AddressText(const UCHAR *Address, PSTR Text)
{
    RtlIpv6AddressToStringA((const IN6_ADDR *)Address, Text);
}

/* ---- registry ---- */

static HKEY OpenInterfaceKey(PCSTR Name, BOOL Create)
{
    CHAR Path[256];
    HKEY Key = NULL;

    _snprintf(Path, sizeof(Path), DHCP6_INTERFACES_KEY "\\%s", Name);
    Path[sizeof(Path) - 1] = '\0';
    if (Create)
    {
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL) != ERROR_SUCCESS)
            return NULL;
    }
    else if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ | KEY_WRITE, &Key) != ERROR_SUCCESS)
        return NULL;
    return Key;
}

static VOID SetString(HKEY Key, PCSTR Value, PCSTR Text)
{
    if (Text && Text[0])
        RegSetValueExA(Key, Value, 0, REG_SZ, (const BYTE *)Text, (DWORD)strlen(Text) + 1);
    else
        RegDeleteValueA(Key, Value);
}

static VOID SetDword(HKEY Key, PCSTR Value, DWORD Data)
{
    RegSetValueExA(Key, Value, 0, REG_DWORD, (const BYTE *)&Data, sizeof(Data));
}

static VOID DeleteLearnedValues(HKEY Key)
{
    RegDeleteValueA(Key, DHCP6_VALUE_NAMESERVER);
    RegDeleteValueA(Key, DHCP6_VALUE_SEARCHLIST);
    RegDeleteValueA(Key, DHCP6_VALUE_SERVER);
    RegDeleteValueA(Key, DHCP6_VALUE_REFRESH);
    RegDeleteValueA(Key, DHCP6_VALUE_OPTIONS);
    RegDeleteValueA(Key, DHCP6_VALUE_REPLIES);
}

/* What was learned is not kept: remove it from every interface key (service start and stop) */
static VOID ClearAllLearned(VOID)
{
    HKEY Parent;
    DWORD Index;
    CHAR Name[128];

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, DHCP6_INTERFACES_KEY, 0, KEY_READ, &Parent) != ERROR_SUCCESS)
        return;
    for (Index = 0; ; Index++)
    {
        DWORD Size = sizeof(Name);
        HKEY Key;

        if (RegEnumKeyExA(Parent, Index, Name, &Size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        Key = OpenInterfaceKey(Name, FALSE);
        if (Key)
        {
            DeleteLearnedValues(Key);
            RegCloseKey(Key);
        }
    }
    RegCloseKey(Parent);
}

/* The machine's DUID (DUID-LLT: type 1, hardware type 1, seconds since 2000-01-01 UTC, link-layer address of an
   adapter), stored once as Tcpip6\Parameters Dhcpv6DUID (REG_BINARY), as Windows 10 does. Nothing is made without
   an Ethernet address to base it on. */
static BOOL EnsureDuid(const UCHAR *Mac, ULONG MacLen)
{
    HKEY Key;
    DWORD Type, Size;

    if (DuidLen)
        return TRUE;

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, DHCP6_PARAMETERS_KEY, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL)
        != ERROR_SUCCESS)
        return FALSE;

    Size = sizeof(Duid);
    if (RegQueryValueExA(Key, DHCP6_VALUE_DUID, NULL, &Type, Duid, &Size) == ERROR_SUCCESS &&
        Type == REG_BINARY && Size >= 4 && Size <= D6_MAX_DUID)
    {
        DuidLen = Size;
    }
    else if (Mac && MacLen == 6)
    {
        FILETIME Now;
        ULARGE_INTEGER Time;
        /* 2000-01-01 00:00:00 UTC as a FILETIME */
        const ULONGLONG Epoch2000 = 125911584000000000ULL;
        ULONG Seconds;

        GetSystemTimeAsFileTime(&Now);
        Time.LowPart = Now.dwLowDateTime;
        Time.HighPart = Now.dwHighDateTime;
        Seconds = (ULONG)((Time.QuadPart - Epoch2000) / 10000000ULL);

        PutBe16(Duid, 1);
        PutBe16(Duid + 2, 1);
        Duid[4] = (UCHAR)(Seconds >> 24);
        Duid[5] = (UCHAR)(Seconds >> 16);
        Duid[6] = (UCHAR)(Seconds >> 8);
        Duid[7] = (UCHAR)Seconds;
        memcpy(Duid + 8, Mac, 6);
        DuidLen = 14;
        RegSetValueExA(Key, DHCP6_VALUE_DUID, 0, REG_BINARY, Duid, DuidLen);
        D6_LOG("DUID-LLT created\n");
    }
    RegCloseKey(Key);
    return DuidLen != 0;
}

/* IAID of an interface, as the Windows 10 oracle shows it: interface index in the top byte, first three bytes of the
   link-layer address below (one sample: index 6, 02-A4-5E-B1-E2-59 -> 100836446 = 0x0602A45E) */
static ULONG IaidOf(const D6IF *If)
{
    return ((If->IfIndex & 0xFF) << 24) | ((ULONG)If->Mac[0] << 16) | ((ULONG)If->Mac[1] << 8) | If->Mac[2];
}

static VOID PublishIdentity(const D6IF *If)
{
    HKEY Key = OpenInterfaceKey(If->Name, TRUE);

    if (Key)
    {
        DWORD Type, Size = sizeof(DWORD), Old = 0;
        ULONG Iaid = IaidOf(If);

        if (RegQueryValueExA(Key, DHCP6_VALUE_IAID, NULL, &Type, (LPBYTE)&Old, &Size) != ERROR_SUCCESS ||
            Type != REG_DWORD || Old != Iaid)
            SetDword(Key, DHCP6_VALUE_IAID, Iaid);
        RegCloseKey(Key);
    }
}

static VOID Withdraw(D6IF *If)
{
    HKEY Key;

    if (!If->Published)
        return;
    If->Published = FALSE;
    Key = OpenInterfaceKey(If->Name, FALSE);
    if (Key)
    {
        DeleteLearnedValues(Key);
        RegCloseKey(Key);
    }
    D6_LOG("interface %lu: DHCPv6 data removed\n", If->IfIndex);
}

static VOID Publish(D6IF *If, const D6REPLY *R, const UCHAR *Options, ULONG OptionsLen, const UCHAR *ServerAddress)
{
    HKEY Key = OpenInterfaceKey(If->Name, TRUE);
    CHAR Text[16 * 48], One[64];
    CHAR Domains[D6_MAX_DOMAINS * D6_MAX_DOMAIN_LEN];
    ULONG i;

    if (!Key)
        return;

    Text[0] = '\0';
    for (i = 0; i < R->DnsCount; i++)
    {
        AddressText(R->Dns[i], One);
        if (Text[0])
            strcat(Text, " ");
        strcat(Text, One);
    }
    SetString(Key, DHCP6_VALUE_NAMESERVER, Text);

    Domains[0] = '\0';
    for (i = 0; i < R->DomainCount; i++)
    {
        if (Domains[0])
            strcat(Domains, " ");
        strcat(Domains, R->Domains[i]);
    }
    SetString(Key, DHCP6_VALUE_SEARCHLIST, Domains);

    if (ServerAddress)
    {
        AddressText(ServerAddress, One);
        SetString(Key, DHCP6_VALUE_SERVER, One);
    }
    SetDword(Key, DHCP6_VALUE_REFRESH, R->HasRefresh ? R->Refresh : (DWORD)IRT_DEFAULT_S);
    if (OptionsLen)
        RegSetValueExA(Key, DHCP6_VALUE_OPTIONS, 0, REG_BINARY, Options, OptionsLen);
    If->Replies++;
    /* last: a reader that waits for a new reply count sees the data complete */
    SetDword(Key, DHCP6_VALUE_REPLIES, If->Replies);
    RegCloseKey(Key);
    If->Published = TRUE;
}

/* ---- messages ---- */

/* A DNS name list as DHCPv6 carries it (RFC 8415 section 10: labels, no compression, each name ends in a zero
   byte). Names the stack's resolver could not search with are dropped, and parsing stops at the first malformed
   one. Returns the number of names. */
static ULONG ParseDomains(const UCHAR *P, ULONG Len, CHAR Names[][D6_MAX_DOMAIN_LEN], ULONG Max)
{
    ULONG Pos = 0, Count = 0;

    while (Pos < Len && Count < Max)
    {
        CHAR Name[D6_MAX_DOMAIN_LEN];
        ULONG NameLen = 0, k;
        BOOL Done = FALSE, Bad = FALSE;

        while (Pos < Len && !Done && !Bad)
        {
            ULONG Label = P[Pos++];

            if (Label == 0)
            {
                Done = TRUE;
            }
            else if ((Label & 0xC0) != 0 || Label > 63 || Pos + Label > Len || NameLen + Label + 1 >= D6_MAX_DOMAIN_LEN)
            {
                Bad = TRUE;
            }
            else
            {
                if (NameLen)
                    Name[NameLen++] = '.';
                for (k = 0; k < Label; k++)
                {
                    UCHAR c = P[Pos++];

                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
                        Bad = TRUE;
                    Name[NameLen++] = (CHAR)c;
                }
            }
        }
        if (Bad || !Done)
            break; /* a name without its end or with a bad label ends the list */
        if (NameLen == 0 || NameLen > 253)
            continue;
        Name[NameLen] = '\0';
        for (k = 0; k < Count; k++)
        {
            if (!_stricmp(Names[k], Name))
                break;
        }
        if (k == Count)
        {
            strcpy(Names[Count], Name);
            Count++;
        }
    }
    return Count;
}

/* Parses a Reply for If (message type, transaction id, Server Identifier, our Client Identifier when present);
   FALSE: not for us or malformed */
static BOOL ParseReply(const D6IF *If, const UCHAR *Msg, ULONG Len, D6REPLY *R)
{
    ULONG Pos = 4;

    memset(R, 0, sizeof(*R));
    if (Len < 4 || Msg[0] != D6_REPLY || memcmp(Msg + 1, If->Xid, 3) != 0)
        return FALSE;

    while (Pos < Len)
    {
        USHORT Code, OptLen;
        const UCHAR *Data;

        if (Len - Pos < 4)
            return FALSE;
        Code = GetBe16(Msg + Pos);
        OptLen = GetBe16(Msg + Pos + 2);
        Pos += 4;
        if (OptLen > Len - Pos)
            return FALSE;
        Data = Msg + Pos;
        Pos += OptLen;

        switch (Code)
        {
            case D6_OPT_CLIENTID:
                if (OptLen != DuidLen || memcmp(Data, Duid, DuidLen) != 0)
                    return FALSE;
                break;
            case D6_OPT_SERVERID:
                if (OptLen == 0 || OptLen > D6_MAX_DUID)
                    return FALSE;
                memcpy(R->Server, Data, OptLen);
                R->ServerLen = OptLen;
                break;
            case D6_OPT_STATUS:
                if (OptLen >= 2)
                    R->Status = GetBe16(Data);
                break;
            case D6_OPT_DNS:
                if (OptLen % 16 == 0)
                {
                    ULONG k;
                    static const UCHAR Zero[16];

                    for (k = 0; k < (ULONG)OptLen / 16 && R->DnsCount < D6_MAX_DNS; k++)
                    {
                        const UCHAR *A = Data + 16 * k;
                        ULONG j;
                        BOOL Dup = FALSE;

                        if (!memcmp(A, Zero, 16) || A[0] == 0xFF)
                            continue;
                        for (j = 0; j < R->DnsCount; j++)
                            Dup |= !memcmp(R->Dns[j], A, 16);
                        if (!Dup)
                            memcpy(R->Dns[R->DnsCount++], A, 16);
                    }
                }
                break;
            case D6_OPT_DOMAINS:
                R->DomainCount = ParseDomains(Data, OptLen, R->Domains, D6_MAX_DOMAINS);
                break;
            case D6_OPT_REFRESH:
                if (OptLen == 4)
                {
                    R->HasRefresh = TRUE;
                    R->Refresh = GetBe32(Data);
                }
                break;
            case D6_OPT_INF_MAX_RT:
                if (OptLen == 4)
                {
                    ULONG V = GetBe32(Data);

                    /* RFC 8415 21.25: values under 60 or over 86400 s are ignored */
                    if (V >= 60 && V <= 86400)
                    {
                        R->HasInfMaxRt = TRUE;
                        R->InfMaxRt = V;
                    }
                }
                break;
            default:
                break;
        }
    }
    return R->ServerLen != 0;
}

static ULONG BuildInformationRequest(D6IF *If, ULONGLONG Now, UCHAR *Out)
{
    ULONG Pos = 0;
    ULONGLONG Hundredths = (If->Sent == 0) ? 0 : (Now - If->FirstSent) / 10;

    Out[Pos++] = D6_INFORMATION_REQUEST;
    memcpy(Out + Pos, If->Xid, 3);
    Pos += 3;

    PutBe16(Out + Pos, D6_OPT_CLIENTID);
    PutBe16(Out + Pos + 2, (USHORT)DuidLen);
    memcpy(Out + Pos + 4, Duid, DuidLen);
    Pos += 4 + DuidLen;

    PutBe16(Out + Pos, D6_OPT_ELAPSED);
    PutBe16(Out + Pos + 2, 2);
    PutBe16(Out + Pos + 4, Hundredths > 0xFFFF ? 0xFFFF : (USHORT)Hundredths);
    Pos += 6;

    /* Option Request: DNS servers, domain search list, information refresh time, INF_MAX_RT */
    PutBe16(Out + Pos, D6_OPT_ORO);
    PutBe16(Out + Pos + 2, 8);
    PutBe16(Out + Pos + 4, D6_OPT_DNS);
    PutBe16(Out + Pos + 6, D6_OPT_DOMAINS);
    PutBe16(Out + Pos + 8, D6_OPT_REFRESH);
    PutBe16(Out + Pos + 10, D6_OPT_INF_MAX_RT);
    Pos += 12;
    return Pos;
}

/* ---- per interface ---- */

static VOID CloseSocket(D6IF *If)
{
    if (If->Sock != INVALID_SOCKET)
    {
        WSAEventSelect(If->Sock, NULL, 0);
        closesocket(If->Sock);
        If->Sock = INVALID_SOCKET;
    }
}

/* What the interface asks the DHCPv6 servers for. Today: O (or M, until the stateful client exists: a stateful
   server answers an Information-Request with the same options) means an Information-Request. */
static D6MODE WantedMode(BOOL Managed, BOOL Other)
{
    return (Managed || Other) ? D6M_INFORMATION : D6M_NONE;
}

static VOID StartExchange(D6IF *If, ULONGLONG Now, BOOL Immediate)
{
    ULONG XidValue = Rand32(); /* Rand32 has a fallback for a refusing generator; a transaction id need not be secret */

    If->Xid[0] = (UCHAR)(XidValue >> 16);
    If->Xid[1] = (UCHAR)(XidValue >> 8);
    If->Xid[2] = (UCHAR)XidValue;
    If->Sent = 0;
    If->Rt = 0;
    If->FirstSent = Now;
    If->State = D6S_DELAY;
    If->Due = Now + (Immediate ? 0 : (Rand32() % (INF_MAX_DELAY_MS + 1)));
    If->HasDue = TRUE;
}

static BOOL OpenSocket(D6IF *If)
{
    SOCKADDR_IN6 Local;
    DWORD Index = If->IfIndex;

    If->Sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (If->Sock == INVALID_SOCKET)
    {
        D6_LOG("interface %lu: socket failed %d\n", If->IfIndex, WSAGetLastError());
        return FALSE;
    }
    memset(&Local, 0, sizeof(Local));
    Local.sin6_family = AF_INET6;
    Local.sin6_port = htons(D6_PORT_CLIENT);
    memcpy(&Local.sin6_addr, If->LinkLocal, 16);
    Local.sin6_scope_id = If->IfIndex;
    if (bind(If->Sock, (PSOCKADDR)&Local, sizeof(Local)) != 0 ||
        setsockopt(If->Sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *)&Index, sizeof(Index)) != 0 ||
        WSAEventSelect(If->Sock, SockEvent, FD_READ) != 0)
    {
        D6_LOG("interface %lu: bind/option failed %d\n", If->IfIndex, WSAGetLastError());
        closesocket(If->Sock);
        If->Sock = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

/* RFC 8415 15: the first RT is IRT + RAND*IRT, the next ones 2*RTprev + RAND*RTprev, and an RT above MRT becomes
   MRT + RAND*MRT (RAND in [-0.1, +0.1]). Previous is 0 before the first transmission; times in ms. */
static ULONG NextRetransmitTime(ULONG Previous, ULONG MaxRt)
{
    ULONG Base = (Previous == 0) ? INF_TIMEOUT_MS : (Previous > 0x7FFFFFFFUL / 2 ? 0x7FFFFFFFUL : Previous * 2);
    ULONG Rt = Jitter(Base);

    if (Rt > MaxRt)
        Rt = Jitter(MaxRt);
    return Rt;
}

static VOID SendInformationRequest(D6IF *If, ULONGLONG Now)
{
    UCHAR Packet[D6_MAX_PACKET];
    SOCKADDR_IN6 To;
    ULONG Len;

    Len = BuildInformationRequest(If, Now, Packet);

    memset(&To, 0, sizeof(To));
    To.sin6_family = AF_INET6;
    To.sin6_port = htons(D6_PORT_SERVER);
    /* ff02::1:2, All_DHCP_Relay_Agents_and_Servers */
    To.sin6_addr.u.Byte[0] = 0xFF;
    To.sin6_addr.u.Byte[1] = 0x02;
    To.sin6_addr.u.Byte[13] = 0x01;
    To.sin6_addr.u.Byte[15] = 0x02;
    To.sin6_scope_id = If->IfIndex;
    if (sendto(If->Sock, (const char *)Packet, Len, 0, (PSOCKADDR)&To, sizeof(To)) == SOCKET_ERROR)
        D6_LOG("interface %lu: sendto failed %d\n", If->IfIndex, WSAGetLastError());
    If->Sent++;

    /* Information-Request has no retransmission count or duration limit (MRC = MRD = 0) */
    If->Rt = NextRetransmitTime(If->Rt, If->MaxRt);
    If->State = D6S_INFORM;
    If->Due = Now + If->Rt;
    If->HasDue = TRUE;
    D6_LOG("interface %lu: Information-Request %lu sent, next in %lu ms\n", If->IfIndex, If->Sent, If->Rt);
}

static VOID AcceptReply(D6IF *If, const D6REPLY *R, const UCHAR *Msg, ULONG Len, const SOCKADDR_IN6 *From, ULONGLONG Now)
{
    ULONGLONG RefreshMs;

    If->MaxRt = R->HasInfMaxRt ? R->InfMaxRt * 1000UL : INF_MAX_RT_MS;
    Publish(If, R, Msg + 4, Len - 4, From->sin6_addr.u.Byte);

    /* Information Refresh Time (RFC 8415 21.23): not less than 600 s, 0xFFFFFFFF = never, default 86400 s */
    if (R->HasRefresh && R->Refresh == 0xFFFFFFFFUL)
    {
        If->HasDue = FALSE;
        RefreshMs = 0;
    }
    else
    {
        ULONG Seconds = R->HasRefresh ? R->Refresh : IRT_DEFAULT_S;

        if (Seconds < IRT_MINIMUM_S)
            Seconds = IRT_MINIMUM_S;
        RefreshMs = (ULONGLONG)Seconds * 1000;
        If->Due = Now + RefreshMs;
        If->HasDue = TRUE;
    }
    If->State = D6S_BOUND;
    D6_LOG("interface %lu: Reply: %lu DNS servers, %lu domains, refresh %s\n", If->IfIndex, R->DnsCount, R->DomainCount,
           If->HasDue ? "armed" : "never");
}

/* Datagrams read per interface and wake: a flood on the link cannot hold the thread here (FD_READ is recorded again
   while datagrams are queued, and the thread comes back at least every scan interval) */
#define D6_READ_BUDGET      64

static VOID ReadSocket(D6IF *If, ULONGLONG Now)
{
    ULONG Budget;

    for (Budget = D6_READ_BUDGET; Budget; Budget--)
    {
        UCHAR Packet[D6_MAX_PACKET];
        SOCKADDR_IN6 From;
        int FromLen = sizeof(From), Len;
        D6REPLY Reply;

        Len = recvfrom(If->Sock, (char *)Packet, sizeof(Packet), 0, (PSOCKADDR)&From, &FromLen);
        if (Len == SOCKET_ERROR)
        {
            /* a datagram larger than the buffer is dropped by recvfrom; the ones queued behind it are still read */
            if (WSAGetLastError() == WSAEMSGSIZE)
                continue;
            break;
        }
        if (Len < 4 || From.sin6_family != AF_INET6 || ntohs(From.sin6_port) != D6_PORT_SERVER)
            continue;
        /* Only a Reply to the Information-Request that is out: once one was accepted (BOUND) the exchange is over and
           its transaction id is no longer outstanding (RFC 8415 16, 18.2.10), so a late or repeated Reply with it
           neither replaces the data nor moves the refresh time */
        if (If->State != D6S_INFORM)
            continue;
        if (!ParseReply(If, Packet, (ULONG)Len, &Reply))
            continue;
        if (Reply.Status != 0)
        {
            D6_LOG("interface %lu: Reply with status %lu ignored\n", If->IfIndex, Reply.Status);
            continue;
        }
        AcceptReply(If, &Reply, Packet, (ULONG)Len, &From, Now);
    }
}

static VOID Teardown(D6IF *If)
{
    CloseSocket(If);
    Withdraw(If);
    If->State = D6S_IDLE;
    If->HasDue = FALSE;
    If->Mode = D6M_NONE;
}

/* ---- interface table ---- */

static D6IF *FindInterface(DWORD IfIndex)
{
    D6IF *If;

    for (If = Interfaces; If; If = If->Next)
    {
        if (If->IfIndex == IfIndex)
            return If;
    }
    return NULL;
}

/* One look at the adapters the stack has with IPv6: the ones with a usable link-local address and an Ethernet
   type get a state entry; the flags of their router advertisements decide the mode. */
static VOID Scan(ULONGLONG Now)
{
    PIP_ADAPTER_ADDRESSES Addresses = NULL, A;
    ULONG Size = 16 * 1024, Pass;
    DWORD Error = ERROR_BUFFER_OVERFLOW;
    D6IF *If, **Link;

    for (Pass = 0; Pass < 3 && Error == ERROR_BUFFER_OVERFLOW; Pass++)
    {
        if (Addresses)
            HeapFree(GetProcessHeap(), 0, Addresses);
        Addresses = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Addresses)
            return;
        Error = GetAdaptersAddresses(AF_INET6,
                                     GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
                                     GAA_FLAG_SKIP_FRIENDLY_NAME,
                                     NULL, Addresses, &Size);
    }

    for (If = Interfaces; If; If = If->Next)
        If->Seen = FALSE;

    for (A = (Error == NO_ERROR) ? Addresses : NULL; A; A = A->Next)
    {
        PIP_ADAPTER_UNICAST_ADDRESS U;
        UCHAR LinkLocal[16];
        BOOL HaveLinkLocal = FALSE;
        DWORD IfIndex = A->Ipv6IfIndex ? A->Ipv6IfIndex : A->IfIndex;
        D6MODE Mode;
        BOOL Fresh = FALSE;

        if ((A->IfType != IF_TYPE_ETHERNET_CSMACD && A->IfType != IF_TYPE_IEEE80211) || A->OperStatus != IfOperStatusUp ||
            A->PhysicalAddressLength != 6 || !A->AdapterName || strlen(A->AdapterName) >= sizeof(If->Name))
            continue;

        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            const SOCKADDR_IN6 *Sa = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;

            if (Sa && Sa->sin6_family == AF_INET6 && IsLinkLocal(Sa->sin6_addr.u.Byte) &&
                U->DadState == IpDadStatePreferred)
            {
                memcpy(LinkLocal, Sa->sin6_addr.u.Byte, 16);
                HaveLinkLocal = TRUE;
                break;
            }
        }
        if (!HaveLinkLocal)
            continue;

        If = FindInterface(IfIndex);
        if (!If)
        {
            If = calloc(1, sizeof(*If));
            if (!If)
                continue;
            If->IfIndex = IfIndex;
            If->Sock = INVALID_SOCKET;
            If->MaxRt = INF_MAX_RT_MS;
            If->Next = Interfaces;
            Interfaces = If;
            Fresh = TRUE;
        }
        If->Seen = TRUE;
        strcpy(If->Name, A->AdapterName);
        memcpy(If->Mac, A->PhysicalAddress, 6);
        If->MacLen = 6;

        /* a new link-local address (or a first one): the socket is bound to the old one */
        if (memcmp(If->LinkLocal, LinkLocal, 16) != 0)
        {
            if (!Fresh && If->Mode != D6M_NONE)
                D6_LOG("interface %lu: link-local address changed\n", If->IfIndex);
            memcpy(If->LinkLocal, LinkLocal, 16);
            if (If->Sock != INVALID_SOCKET)
            {
                Teardown(If);
            }
        }

        EnsureDuid(If->Mac, If->MacLen);
        PublishIdentity(If);

        Mode = WantedMode((A->Flags & D6_ADAPTER_MANAGED) != 0, (A->Flags & IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG) != 0);
        if (Mode == D6M_NONE && If->Mode != D6M_NONE)
        {
            D6_LOG("interface %lu: no M or O flag any more, DHCPv6 stops\n", If->IfIndex);
            Teardown(If);
        }
        else if (Mode != D6M_NONE && If->Mode == D6M_NONE && DuidLen)
        {
            if (OpenSocket(If))
            {
                If->Mode = Mode;
                If->MaxRt = INF_MAX_RT_MS;
                StartExchange(If, Now, FALSE);
                D6_LOG("interface %lu: M/O flag seen, Information-Request starts\n", If->IfIndex);
            }
        }
    }

    /* adapters that went away or lost their link-local address */
    for (Link = &Interfaces; (If = *Link) != NULL; )
    {
        if (!If->Seen)
        {
            *Link = If->Next;
            Teardown(If);
            free(If);
        }
        else
            Link = &If->Next;
    }

    if (Addresses)
        HeapFree(GetProcessHeap(), 0, Addresses);
}

static VOID Timers(ULONGLONG Now)
{
    D6IF *If;

    for (If = Interfaces; If; If = If->Next)
    {
        if (If->Mode == D6M_NONE || !If->HasDue || If->Due > Now || If->Sock == INVALID_SOCKET)
            continue;

        switch (If->State)
        {
            case D6S_DELAY:
            case D6S_INFORM:
                SendInformationRequest(If, Now);
                break;
            case D6S_BOUND:
                /* the Information Refresh Time is over: ask again, the old data stays until the Reply */
                StartExchange(If, Now, TRUE);
                SendInformationRequest(If, Now);
                break;
            default:
                break;
        }
    }
}

static VOID ForceAll(ULONGLONG Now)
{
    D6IF *If;

    for (If = Interfaces; If; If = If->Next)
    {
        if (If->Mode != D6M_NONE && If->Sock != INVALID_SOCKET)
        {
            StartExchange(If, Now, TRUE);
            SendInformationRequest(If, Now);
        }
    }
}

/* NotifyIpInterfaceChange and CancelMibChangeNotify2 are looked up when the thread starts: the client works (with
   the poll of the scan interval) where iphlpapi has no such exports */
typedef DWORD (WINAPI *PNOTIFY_INTERFACE)(USHORT Family, PVOID Callback, PVOID Context, BOOLEAN Initial, HANDLE *Handle);
typedef DWORD (WINAPI *PCANCEL_NOTIFY)(HANDLE Handle);

static VOID WINAPI InterfaceChanged(PVOID Context, PVOID Row, ULONG Type)
{
    SetEvent((HANDLE)Context);
}

static ULONGLONG NextDue(ULONGLONG Now, ULONGLONG NextScan)
{
    D6IF *If;
    ULONGLONG Due = NextScan;

    for (If = Interfaces; If; If = If->Next)
    {
        if (If->Mode != D6M_NONE && If->HasDue && If->Due < Due)
            Due = If->Due;
    }
    return Due < Now ? Now : Due;
}

static DWORD WINAPI Dhcp6Thread(LPVOID Context)
{
    HANDLE StopEvent = Context, NotifyEvent, ForceEvent = NULL, Handles[4], NotifyHandle = NULL;
    SECURITY_ATTRIBUTES Sa;
    PSECURITY_DESCRIPTOR Sd = NULL;
    WSADATA Wsa;
    ULONGLONG NextScan = 0;
    PNOTIFY_INTERFACE Notify;
    PCANCEL_NOTIFY Cancel;

    if (WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
        return 1;
    SockEvent = WSACreateEvent();
    NotifyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (SockEvent == WSA_INVALID_EVENT || !NotifyEvent)
    {
        WSACleanup();
        return 1;
    }

    /* SYSTEM and administrators only may ask for a new Information-Request */
    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    Sa.lpSecurityDescriptor = NULL;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &Sd, NULL))
        Sa.lpSecurityDescriptor = Sd;
    ForceEvent = CreateEventW(Sd ? &Sa : NULL, FALSE, FALSE, DHCP6_FORCE_EVENT_NAME);
    if (Sd)
        LocalFree(Sd);

    ClearAllLearned();
    {
        HMODULE Iphlpapi = GetModuleHandleW(L"iphlpapi.dll");

        Notify = Iphlpapi ? (PNOTIFY_INTERFACE)GetProcAddress(Iphlpapi, "NotifyIpInterfaceChange") : NULL;
        Cancel = Iphlpapi ? (PCANCEL_NOTIFY)GetProcAddress(Iphlpapi, "CancelMibChangeNotify2") : NULL;
        if (Notify && Cancel)
            Notify(AF_INET6, InterfaceChanged, NotifyEvent, FALSE, &NotifyHandle);
    }

    Handles[0] = StopEvent;
    Handles[1] = SockEvent;
    Handles[2] = NotifyEvent;
    Handles[3] = ForceEvent ? ForceEvent : NotifyEvent;

    for (;;)
    {
        ULONGLONG Now = NowMs(), Due;
        DWORD Wait, Result;

        if (Now >= NextScan)
        {
            Scan(Now);
            NextScan = Now + SCAN_INTERVAL_MS;
        }
        Timers(NowMs());

        Now = NowMs();
        Due = NextDue(Now, NextScan);
        Wait = (DWORD)(Due - Now);
        Result = WaitForMultipleObjects(ForceEvent ? 4 : 3, Handles, FALSE, Wait);
        if (Result == WAIT_OBJECT_0)
            break;
        if (Result == WAIT_OBJECT_0 + 2)
        {
            /* an interface changed: look again soon (changes come in bursts) */
            Now = NowMs();
            if (NextScan > Now + 300)
                NextScan = Now + 300;
        }
        else if (Result == WAIT_OBJECT_0 + 3 && ForceEvent)
        {
            Scan(NowMs());
            ForceAll(NowMs());
        }

        WSAResetEvent(SockEvent);
        {
            D6IF *If;

            Now = NowMs();
            for (If = Interfaces; If; If = If->Next)
            {
                if (If->Sock != INVALID_SOCKET)
                    ReadSocket(If, Now);
            }
        }
    }

    if (NotifyHandle && Cancel)
        Cancel(NotifyHandle);
    while (Interfaces)
    {
        D6IF *If = Interfaces;

        Interfaces = If->Next;
        Teardown(If);
        free(If);
    }
    ClearAllLearned();
    if (ForceEvent)
        CloseHandle(ForceEvent);
    CloseHandle(NotifyEvent);
    WSACloseEvent(SockEvent);
    WSACleanup();
    return 0;
}

HANDLE StartDhcp6Client(HANDLE hStopEvent)
{
    HANDLE Thread = CreateThread(NULL, 0, Dhcp6Thread, hStopEvent, 0, NULL);

    return Thread ? Thread : INVALID_HANDLE_VALUE;
}
