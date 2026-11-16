/*
 * PROJECT:     ReactOS DHCP client service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DHCPv6 client (RFC 8415): Information-Request (O flag) and addresses through IA_NA (M flag)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * One client thread for all interfaces, one small state machine per interface (D6IF). What an interface asks the
 * DHCPv6 servers for is decided in one place (WantedMode):
 *
 * Information-Request mode (router flag O):
 *   IDLE    the interface has no reason for DHCPv6 (no socket)
 *   DELAY   the flag arrived; wait a random time up to INF_MAX_DELAY, then send (RFC 8415 18.2.6)
 *   INFORM  an Information-Request is out, retransmitted with the RFC 8415 15 back-off until a Reply comes
 *   BOUND   a Reply was accepted; the next Information-Request is due after the Information Refresh Time
 *
 * Stateful mode (router flag M): Solicit, Advertise, Request, Reply with one IA_NA, then
 *   DELAY    random delay (or a cool-down after a failure or a Decline), then the first Solicit
 *   SOLICIT  Solicit out, Advertisements collected (the best preference wins; 255, or any one after the first
 *            retransmission interval, wins at once)
 *   REQUEST  Request to the chosen server (at most 10 tries, then Solicit again)
 *   LEASED   the addresses are installed (through the IP Helper create/set/delete calls: origin DHCP, the lifetimes
 *            of the server, /128); Renew at T1, Rebind at T2, an address goes when its valid lifetime ends
 *   RENEW / REBIND   Renew to the server, then Rebind to any server
 *   CONFIRM  the link changed: ask whether the addresses still are on the link (RFC 8415 18.2.3)
 *   DECLINE  duplicate address detection found an address in use: tell the server, take it out of the stack (an address
 *            the stack already has from another source, e.g. configured by an administrator, is declined the same way
 *            and left as it is)
 *   RELEASE  ipconfig /release6: the addresses leave the stack first, then the Release goes out
 *   RELEASED nothing is asked until ipconfig /renew6
 * A message is only taken while our request for it is outstanding (a Reply in BOUND or LEASED is dropped: the
 * transaction id of a finished exchange must not replace what the client holds). Every datagram read is bounded
 * and every length is checked against the buffer before use. The kernel keeps the addresses (tcpip.sys ages their
 * lifetimes); this service owns the exchange.
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
#ifdef D6_UNIT /* the unit test is built with the host compiler's headers */
#include <netioapi.h>
#else
#include <wine/netioapi.h>
#endif

#include "dhcp6.h"

NTSYSAPI ULONG __cdecl DbgPrint(PCCH Format, ...);
#define D6_LOG(...) DbgPrint("DHCPCSVC6: " __VA_ARGS__)

/* RFC 8415 section 7 */
#define D6_PORT_CLIENT      546
#define D6_PORT_SERVER      547
#define D6_SOLICIT          1
#define D6_ADVERTISE        2
#define D6_REQUEST          3
#define D6_CONFIRM          4
#define D6_RENEW            5
#define D6_REBIND           6
#define D6_REPLY            7
#define D6_RELEASE          8
#define D6_DECLINE          9
#define D6_INFORMATION_REQUEST 11

#define D6_OPT_CLIENTID     1
#define D6_OPT_SERVERID     2
#define D6_OPT_IA_NA        3
#define D6_OPT_IAADDR       5
#define D6_OPT_ORO          6
#define D6_OPT_PREFERENCE   7
#define D6_OPT_ELAPSED      8
#define D6_OPT_STATUS       13
#define D6_OPT_DNS          23
#define D6_OPT_DOMAINS      24
#define D6_OPT_REFRESH      32
#define D6_OPT_SOL_MAX_RT   82
#define D6_OPT_INF_MAX_RT   83

/* status codes, RFC 8415 section 21.13 */
#define D6_STATUS_SUCCESS       0
#define D6_STATUS_NOADDRSAVAIL  2
#define D6_STATUS_NOBINDING     3
#define D6_STATUS_NOTONLINK     4

#define INF_MAX_DELAY_MS    1000        /* 7.6 */
#define INF_TIMEOUT_MS      1000
#define INF_MAX_RT_MS       3600000UL   /* 3600 s; a Reply may carry option 83 */
#define IRT_DEFAULT_S       86400UL     /* RFC 8415 7.6, 21.23 */
#define IRT_MINIMUM_S       600UL

/* RFC 8415 section 7.6, milliseconds */
#define SOL_MAX_DELAY_MS    1000
#define SOL_TIMEOUT_MS      1000
#define SOL_MAX_RT_MS       3600000UL   /* option 82 may change it */
#define REQ_TIMEOUT_MS      1000
#define REQ_MAX_RT_MS       30000UL
#define REQ_MAX_RC          10
#define CNF_TIMEOUT_MS      1000
#define CNF_MAX_RT_MS       4000UL
#define CNF_MAX_RD_MS       10000UL
#define REN_TIMEOUT_MS      10000
#define REN_MAX_RT_MS       600000UL
#define REB_TIMEOUT_MS      10000
#define REB_MAX_RT_MS       600000UL
#define REL_TIMEOUT_MS      1000
#define REL_MAX_RC          4
#define DEC_TIMEOUT_MS      1000
#define DEC_MAX_RC          4

#define D6_MAX_DNS          8
#define D6_MAX_DOMAINS      16
#define D6_MAX_DOMAIN_LEN   254
#define D6_MAX_DUID         130
#define D6_MAX_PACKET       4096        /* a message we build: the options we send are few */
#define D6_MAX_RECV         65535       /* a message we read: a Reply with many options is several fragments, up to the
                                           largest UDP datagram (the stack reassembles it; nothing is cut or dropped) */
#define D6_MAX_ADDRS        4           /* addresses of one IA_NA the client takes (the stack has 8 address slots) */
#define D6_NEVER            0xFFFFFFFFFFFFFFFFULL
#define D6_INFINITE         0xFFFFFFFFUL /* a lifetime or timer of "never" */
#define D6_DAD_POLL_MS      250
#define D6_COMMAND_WAIT_MS  15000       /* ipconfig /renew6 /release6 wait this long for the outcome */
#define D6_DECLINE_WAIT_MS  10000       /* wait after a Decline before asking again, times the number of Declines */
#define D6_FAIL_WAIT_MS     5000        /* the same for a failed exchange (no usable answer) */
#define D6_MAX_WAIT_MS      300000UL

#define SCAN_INTERVAL_MS    5000        /* safety net beside the interface change notification */

/* IP_ADAPTER_IPV6_MANAGED_ADDRESS_CONFIGURATION_SUPPORTED of Windows 7: not in the headers of this tree */
#define D6_ADAPTER_MANAGED  0x0200

typedef enum _D6STATE
{
    D6S_IDLE, D6S_DELAY, D6S_INFORM, D6S_BOUND,
    D6S_SOLICIT, D6S_REQUEST, D6S_LEASED, D6S_RENEW, D6S_REBIND, D6S_CONFIRM, D6S_DECLINE, D6S_RELEASE, D6S_RELEASED
} D6STATE;
typedef enum _D6MODE { D6M_NONE, D6M_INFORMATION, D6M_STATEFUL } D6MODE;

/* one address of an IA_NA as a message carries it */
typedef struct _D6IAADDR
{
    UCHAR Addr[16];
    ULONG Pref;
    ULONG Valid;
} D6IAADDR;

/* an address the client holds */
typedef struct _D6ADDR
{
    D6IAADDR Ia;                    /* as the server gave it */
    ULONGLONG Expire;               /* absolute, ms; D6_NEVER for an infinite valid lifetime */
    BOOL Installed;                 /* the stack has it (as far as this client knows) */
    BOOL DadDone;                   /* duplicate address detection ended with a usable address */
    BOOL Foreign;                   /* the stack holds it from another source (configured, router advertisement,
                                       temporary): left as it is and declined like a duplicate */
} D6ADDR;

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
    ULONGLONG Due;                  /* the next time anything of this interface is due (Information-Request mode:
                                       the delay end, retransmission or refresh; stateful mode: Rearm computes it) */
    BOOL HasDue;
    ULONGLONG FirstSent;
    ULONG Rt;                       /* current retransmission time, ms */
    ULONG MaxRt;                    /* INF_MAX_RT in force, ms */
    ULONG Sent;
    UCHAR Xid[3];
    BOOL Published;
    ULONG Replies;

    /* ---- stateful mode ---- */
    UCHAR MsgType;                  /* the message our outstanding transaction sends */
    ULONG Irt, Mrt, Mrc;            /* retransmission parameters of that message (ms, ms, count; 0 = none) */
    ULONGLONG RetransDue;           /* the next transmission (or the delay end, or the end of a cool-down) */
    ULONGLONG Deadline;             /* CONFIRM: the end of the exchange */
    ULONG SolMaxRt;                 /* SOL_MAX_RT in force, ms */
    UCHAR Srv[D6_MAX_DUID];         /* the server of the lease / the Request */
    ULONG SrvLen;
    UCHAR SrvAddr[16];
    BOOL HaveAdv;                   /* the best Advertisement so far */
    UCHAR AdvSrv[D6_MAX_DUID];
    ULONG AdvSrvLen;
    UCHAR AdvAddr[16];
    UCHAR AdvPref;
    D6IAADDR AdvAddrs[D6_MAX_ADDRS];
    ULONG AdvAddrCount;
    D6ADDR Lease[D6_MAX_ADDRS];
    ULONG LeaseCount;
    D6IAADDR Gone[D6_MAX_ADDRS];    /* the addresses a Release or Decline in progress names */
    ULONG GoneCount;
    ULONGLONG T1Due, T2Due;         /* absolute, D6_NEVER = never */
    ULONG T1, T2;                   /* seconds, as published */
    BOOL DadPending;
    ULONGLONG DadDue;
    BOOL Away;                      /* the adapter is gone (link down) while a lease is held: Confirm when it returns */
    ULONG Cmd;                      /* ipconfig /renew6 (1) or /release6 (2) in progress */
    ULONGLONG CmdDue;
    ULONG DeclineCount;
    ULONG FailCount;
} D6IF;

typedef struct _D6REPLY
{
    UCHAR Type;
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
    BOOL HasSolMaxRt;
    ULONG SolMaxRt;
    UCHAR Preference;
    BOOL HasIa;                     /* an IA_NA with our IAID that passed the checks (RFC 8415 21.4) */
    ULONG IaStatus;
    ULONG T1, T2;
    D6IAADDR Addrs[D6_MAX_ADDRS];
    ULONG AddrCount;
} D6REPLY;

BOOLEAN WINAPI SystemFunction036(PVOID Buffer, ULONG Length); /* RtlGenRandom */

static D6IF *Interfaces;
static UCHAR Duid[D6_MAX_DUID];
static ULONG DuidLen;
static WSAEVENT SockEvent;

/* IP Helper address calls, looked up when the thread starts (the exports are Vista and later) */
typedef VOID (WINAPI *PINIT_UNICAST)(PMIB_UNICASTIPADDRESS_ROW Row);
typedef DWORD (WINAPI *PUNICAST_CALL)(PMIB_UNICASTIPADDRESS_ROW Row);
static PINIT_UNICAST pInitializeUnicast;
static PUNICAST_CALL pCreateUnicast, pSetUnicast, pDeleteUnicast, pGetUnicast;

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

/* The reply count of an interface is one sequence for the whole service, so it never goes back: an interface that
   is dropped and learned again (a link that flapped, an adapter disabled and enabled) does not count 1, 2, ... a
   second time, and a client that waits for the count to differ from the one it read (Dhcpv6RequestParams with a forced
   request) does not wait out its limit because the new count equals the old one. The first value is the time in
   seconds, so a restarted service does not repeat a count a client may still hold */
static ULONG ReplySequence;

static ULONG NextReplyCount(void)
{
    if (ReplySequence == 0)
    {
        FILETIME Now;
        ULARGE_INTEGER Time;

        GetSystemTimeAsFileTime(&Now);
        Time.LowPart = Now.dwLowDateTime;
        Time.HighPart = Now.dwHighDateTime;
        ReplySequence = (ULONG)((Time.QuadPart / 10000000ULL) & 0x3FFFFFFFUL);
    }
    if (++ReplySequence == 0)
        ReplySequence = 1;
    return ReplySequence;
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

static ULONGLONG MinU64(ULONGLONG A, ULONGLONG B) { return A < B ? A : B; }

static USHORT GetBe16(const UCHAR *P) { return (USHORT)((P[0] << 8) | P[1]); }
static ULONG GetBe32(const UCHAR *P) { return ((ULONG)P[0] << 24) | ((ULONG)P[1] << 16) | ((ULONG)P[2] << 8) | P[3]; }
static VOID PutBe16(UCHAR *P, USHORT V) { P[0] = (UCHAR)(V >> 8); P[1] = (UCHAR)V; }
static VOID PutBe32(UCHAR *P, ULONG V) { P[0] = (UCHAR)(V >> 24); P[1] = (UCHAR)(V >> 16); P[2] = (UCHAR)(V >> 8); P[3] = (UCHAR)V; }

static BOOL IsLinkLocal(const UCHAR *A) { return A[0] == 0xFE && (A[1] & 0xC0) == 0x80; }

/* An address a server may lease: not unspecified, loopback, multicast, link-local, or in the IPv4 compatible and
   mapped ranges (the stack refuses those too) */
static BOOL UsableAddress(const UCHAR *A)
{
    ULONG i;
    BOOL Zero12 = TRUE;

    if (A[0] == 0xFF || IsLinkLocal(A))
        return FALSE;
    for (i = 0; i < 12; i++)
        Zero12 &= (A[i] == 0);
    if (Zero12)
        return FALSE; /* ::, ::1 and ::a.b.c.d */
    if (A[0] == 0 && A[1] == 0 && A[2] == 0 && A[3] == 0 && A[4] == 0 && A[5] == 0 && A[6] == 0 && A[7] == 0 &&
        A[8] == 0 && A[9] == 0 && A[10] == 0xFF && A[11] == 0xFF)
        return FALSE; /* ::ffff:a.b.c.d */
    return TRUE;
}

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
    RegDeleteValueA(Key, DHCP6_VALUE_STATEFUL);
    RegDeleteValueA(Key, DHCP6_VALUE_ADDRESSES);
    RegDeleteValueA(Key, DHCP6_VALUE_T1);
    RegDeleteValueA(Key, DHCP6_VALUE_T2);
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
            RegDeleteValueA(Key, DHCP6_VALUE_COMMAND);
            RegDeleteValueA(Key, DHCP6_VALUE_COMMAND_RESULT);
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
    HKEY Key = OpenInterfaceKey(If->Name, FALSE);

    if (Key)
    {
        DeleteLearnedValues(Key);
        RegCloseKey(Key);
    }
    if (If->Published)
        D6_LOG("interface %lu: DHCPv6 data removed\n", If->IfIndex);
    If->Published = FALSE;
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
    If->Replies = NextReplyCount();
    /* last: a reader that waits for a new reply count sees the data complete */
    SetDword(Key, DHCP6_VALUE_REPLIES, If->Replies);
    RegCloseKey(Key);
    If->Published = TRUE;
}

/* A Reply to a Renew or Rebind that carries no DNS data: the old data stays, only the count moves */
static VOID CountReply(D6IF *If, const UCHAR *ServerAddress)
{
    HKEY Key = OpenInterfaceKey(If->Name, TRUE);
    CHAR One[64];

    if (!Key)
        return;
    if (ServerAddress)
    {
        AddressText(ServerAddress, One);
        SetString(Key, DHCP6_VALUE_SERVER, One);
    }
    If->Replies = NextReplyCount();
    SetDword(Key, DHCP6_VALUE_REPLIES, If->Replies);
    RegCloseKey(Key);
    If->Published = TRUE;
}

/* Dhcpv6Stateful, the leased addresses and T1/T2 of an interface */
static VOID PublishLease(const D6IF *If)
{
    HKEY Key = OpenInterfaceKey(If->Name, TRUE);
    CHAR Text[D6_MAX_ADDRS * 48], One[64];
    ULONG i;

    if (!Key)
        return;
    SetDword(Key, DHCP6_VALUE_STATEFUL, 1);
    Text[0] = '\0';
    for (i = 0; i < If->LeaseCount; i++)
    {
        AddressText(If->Lease[i].Ia.Addr, One);
        if (Text[0])
            strcat(Text, " ");
        strcat(Text, One);
    }
    SetString(Key, DHCP6_VALUE_ADDRESSES, Text);
    if (If->LeaseCount)
    {
        SetDword(Key, DHCP6_VALUE_T1, If->T1);
        SetDword(Key, DHCP6_VALUE_T2, If->T2);
    }
    else
    {
        RegDeleteValueA(Key, DHCP6_VALUE_T1);
        RegDeleteValueA(Key, DHCP6_VALUE_T2);
    }
    RegCloseKey(Key);
}

/* the outcome of an ipconfig command: result first, then the command value goes (that is what ipconfig waits for) */
static VOID CompleteCommand(D6IF *If, DWORD Error)
{
    HKEY Key;

    if (!If->Cmd)
        return;
    Key = OpenInterfaceKey(If->Name, FALSE);
    if (Key)
    {
        SetDword(Key, DHCP6_VALUE_COMMAND_RESULT, Error);
        RegDeleteValueA(Key, DHCP6_VALUE_COMMAND);
        RegCloseKey(Key);
    }
    D6_LOG("interface %lu: command %lu done, error %lu\n", If->IfIndex, If->Cmd, Error);
    If->Cmd = 0;
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

/* The options of an IAADDR (RFC 8415 21.6): only the Status Code is read. FALSE: the options are malformed */
static BOOL ParseIaAddrOptions(const UCHAR *P, ULONG Len, ULONG *Status)
{
    ULONG Pos = 0;

    *Status = D6_STATUS_SUCCESS;
    while (Pos < Len)
    {
        USHORT Code, OptLen;

        if (Len - Pos < 4)
            return FALSE;
        Code = GetBe16(P + Pos);
        OptLen = GetBe16(P + Pos + 2);
        Pos += 4;
        if (OptLen > Len - Pos)
            return FALSE;
        if (Code == D6_OPT_STATUS && OptLen >= 2)
            *Status = GetBe16(P + Pos);
        Pos += OptLen;
    }
    return TRUE;
}

/* One IA_NA option (RFC 8415 21.4) of a message from a server. Only the first one with our IAID counts. FALSE:
   malformed (the whole message is dropped). An IA_NA whose T1 is above its T2 (both set) is discarded as if the
   server had not sent it (21.4); an address with a preferred lifetime above its valid one is ignored (21.6). */
static BOOL ParseIaNa(const D6IF *If, const UCHAR *Data, ULONG Len, D6REPLY *R)
{
    ULONG Pos = 12, T1, T2, Status = D6_STATUS_SUCCESS, Count = 0;
    D6IAADDR Addrs[D6_MAX_ADDRS];

    if (Len < 12)
        return FALSE;
    if (GetBe32(Data) != IaidOf(If) || R->HasIa)
        return TRUE; /* not ours, or a second one for the same IAID */
    T1 = GetBe32(Data + 4);
    T2 = GetBe32(Data + 8);

    while (Pos < Len)
    {
        USHORT Code, OptLen;
        const UCHAR *Opt;

        if (Len - Pos < 4)
            return FALSE;
        Code = GetBe16(Data + Pos);
        OptLen = GetBe16(Data + Pos + 2);
        Pos += 4;
        if (OptLen > Len - Pos)
            return FALSE;
        Opt = Data + Pos;
        Pos += OptLen;

        if (Code == D6_OPT_IAADDR)
        {
            ULONG AddrStatus, Pref, Valid, k;
            BOOL Dup = FALSE;

            if (OptLen < 24)
                return FALSE;
            if (!ParseIaAddrOptions(Opt + 24, OptLen - 24, &AddrStatus))
                return FALSE;
            Pref = GetBe32(Opt + 16);
            Valid = GetBe32(Opt + 20);
            if (AddrStatus != D6_STATUS_SUCCESS || !UsableAddress(Opt) || Pref > Valid)
                continue;
            for (k = 0; k < Count; k++)
                Dup |= !memcmp(Addrs[k].Addr, Opt, 16);
            if (Dup || Count >= D6_MAX_ADDRS)
                continue;
            memcpy(Addrs[Count].Addr, Opt, 16);
            Addrs[Count].Pref = Pref;
            Addrs[Count].Valid = Valid;
            Count++;
        }
        else if (Code == D6_OPT_STATUS && OptLen >= 2)
        {
            Status = GetBe16(Opt);
        }
    }

    if (T1 != 0 && T2 != 0 && T1 > T2)
        return TRUE;
    R->HasIa = TRUE;
    R->IaStatus = Status;
    R->T1 = T1;
    R->T2 = T2;
    memcpy(R->Addrs, Addrs, sizeof(Addrs[0]) * Count);
    R->AddrCount = Count;
    return TRUE;
}

/* Parses an Advertise or Reply for If (message type, transaction id, Server Identifier, our Client Identifier: when
   present, or required with Strict); FALSE: not for us or malformed */
static BOOL ParseMessage(const D6IF *If, const UCHAR *Msg, ULONG Len, BOOL Strict, D6REPLY *R)
{
    ULONG Pos = 4;
    BOOL HaveClient = FALSE;

    memset(R, 0, sizeof(*R));
    if (Len < 4 || (Msg[0] != D6_REPLY && Msg[0] != D6_ADVERTISE) || memcmp(Msg + 1, If->Xid, 3) != 0)
        return FALSE;
    R->Type = Msg[0];

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
                HaveClient = TRUE;
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
            case D6_OPT_PREFERENCE:
                if (OptLen == 1)
                    R->Preference = Data[0];
                break;
            case D6_OPT_IA_NA:
                if (!ParseIaNa(If, Data, OptLen, R))
                    return FALSE;
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
            case D6_OPT_SOL_MAX_RT:
                if (OptLen == 4)
                {
                    ULONG V = GetBe32(Data);

                    /* RFC 8415 21.24: values under 60 or over 86400 s are ignored */
                    if (V >= 60 && V <= 86400)
                    {
                        R->HasSolMaxRt = TRUE;
                        R->SolMaxRt = V;
                    }
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
    if (Strict && !HaveClient)
        return FALSE;
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

/* The message of the outstanding transaction of a stateful interface (RFC 8415 18.2): client id, elapsed time,
   server id (Request, Renew, Release, Decline), one IA_NA with the addresses the message names (T1 and T2 are 0:
   the client has no preference), and the option request */
static ULONG BuildStateful(D6IF *If, ULONGLONG Now, UCHAR *Out)
{
    ULONG Pos = 0, i, Count = 0;
    ULONGLONG Hundredths = (If->Sent == 0) ? 0 : (Now - If->FirstSent) / 10;
    D6IAADDR List[D6_MAX_ADDRS];

    switch (If->MsgType)
    {
        case D6_REQUEST:
            for (i = 0; i < If->AdvAddrCount; i++)
                List[Count++] = If->AdvAddrs[i];
            break;
        case D6_RENEW:
        case D6_REBIND:
            for (i = 0; i < If->LeaseCount; i++)
                List[Count++] = If->Lease[i].Ia;
            break;
        case D6_CONFIRM:
            for (i = 0; i < If->LeaseCount; i++)
            {
                List[Count] = If->Lease[i].Ia;
                List[Count].Pref = 0;
                List[Count].Valid = 0;
                Count++;
            }
            break;
        case D6_RELEASE:
        case D6_DECLINE:
            for (i = 0; i < If->GoneCount; i++)
            {
                List[Count] = If->Gone[i];
                List[Count].Pref = 0;
                List[Count].Valid = 0;
                Count++;
            }
            break;
        default: /* Solicit: no address of its own */
            break;
    }

    Out[Pos++] = If->MsgType;
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

    if ((If->MsgType == D6_REQUEST || If->MsgType == D6_RENEW || If->MsgType == D6_RELEASE ||
         If->MsgType == D6_DECLINE) && If->SrvLen)
    {
        PutBe16(Out + Pos, D6_OPT_SERVERID);
        PutBe16(Out + Pos + 2, (USHORT)If->SrvLen);
        memcpy(Out + Pos + 4, If->Srv, If->SrvLen);
        Pos += 4 + If->SrvLen;
    }

    PutBe16(Out + Pos, D6_OPT_IA_NA);
    PutBe16(Out + Pos + 2, (USHORT)(12 + Count * 28));
    PutBe32(Out + Pos + 4, IaidOf(If));
    PutBe32(Out + Pos + 8, 0);
    PutBe32(Out + Pos + 12, 0);
    Pos += 16;
    for (i = 0; i < Count; i++)
    {
        PutBe16(Out + Pos, D6_OPT_IAADDR);
        PutBe16(Out + Pos + 2, 24);
        memcpy(Out + Pos + 4, List[i].Addr, 16);
        PutBe32(Out + Pos + 20, List[i].Pref);
        PutBe32(Out + Pos + 24, List[i].Valid);
        Pos += 28;
    }

    if (If->MsgType != D6_RELEASE && If->MsgType != D6_DECLINE && If->MsgType != D6_CONFIRM)
    {
        PutBe16(Out + Pos, D6_OPT_ORO);
        PutBe16(Out + Pos + 2, 6);
        PutBe16(Out + Pos + 4, D6_OPT_DNS);
        PutBe16(Out + Pos + 6, D6_OPT_DOMAINS);
        PutBe16(Out + Pos + 8, D6_OPT_SOL_MAX_RT);
        Pos += 10;
    }
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

/* What the interface asks the DHCPv6 servers for: the M flag means addresses (the options come with them), the O
   flag alone an Information-Request. */
static D6MODE WantedMode(BOOL Managed, BOOL Other)
{
    return Managed ? D6M_STATEFUL : (Other ? D6M_INFORMATION : D6M_NONE);
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

/* The same for the stateful messages: IRT and MRT of the message, and the first RT of a Solicit is never below IRT
   (RAND in [0, +0.1], RFC 8415 18.2.1) */
static ULONG NextStatefulRt(const D6IF *If)
{
    ULONGLONG Base;
    ULONG Rt;

    if (If->Rt == 0)
        Base = If->Irt;
    else
        Base = If->Rt > 0x7FFFFFFFUL / 2 ? 0x7FFFFFFFUL : (ULONGLONG)If->Rt * 2;

    if (If->Rt == 0 && If->MsgType == D6_SOLICIT)
        Rt = (ULONG)(Base + Base * (Rand32() % 101) / 1000);
    else
        Rt = Jitter((ULONG)Base);
    if (If->Mrt && Rt > If->Mrt)
        Rt = Jitter(If->Mrt);
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

/* ---- stateful client: the stack side ---- */

static VOID FillRow(const D6IF *If, const UCHAR *Addr, ULONG Pref, ULONG Valid, MIB_UNICASTIPADDRESS_ROW *Row)
{
    pInitializeUnicast(Row);
    Row->Address.si_family = AF_INET6;
    Row->Address.Ipv6.sin6_family = AF_INET6;
    memcpy(&Row->Address.Ipv6.sin6_addr, Addr, 16);
    Row->InterfaceIndex = If->IfIndex;
    Row->PrefixOrigin = IpPrefixOriginDhcp;
    Row->SuffixOrigin = IpSuffixOriginDhcp;
    Row->ValidLifetime = Valid;
    Row->PreferredLifetime = Pref;
    Row->OnLinkPrefixLength = 128; /* the on-link prefix comes from the router advertisement */
    Row->SkipAsSource = FALSE;
}

/* TRUE: the stack has the address on this interface; *Ours: with the DHCP origin (put there by this client, or by the
   service before a restart) */
static BOOL StackHas(D6IF *If, const UCHAR *Addr, BOOL *Ours)
{
    MIB_UNICASTIPADDRESS_ROW Row;

    *Ours = FALSE;
    if (!pGetUnicast || !pInitializeUnicast)
        return FALSE;
    FillRow(If, Addr, 0, 0, &Row);
    if (pGetUnicast(&Row) != NO_ERROR)
        return FALSE;
    *Ours = (Row.PrefixOrigin == IpPrefixOriginDhcp && Row.SuffixOrigin == IpSuffixOriginDhcp);
    return TRUE;
}

/* Puts an address into the stack with the lifetimes the server gave (a change of the lifetimes when it is there
   already). OnlyCreate: an address that is there is left alone (its lifetimes already run down). *Foreign: the stack
   has the address from another source (an administrator configured it, a router advertisement formed it, a temporary
   address): it is not changed (its origin, prefix length, lifetimes and persistent record stay) and not taken. */
static BOOL InstallAddress(D6IF *If, const D6IAADDR *Ia, BOOL OnlyCreate, BOOL *Foreign)
{
    MIB_UNICASTIPADDRESS_ROW Row;
    DWORD Error;
    BOOL Ours;

    *Foreign = FALSE;
    if (!pCreateUnicast || !pSetUnicast || !pInitializeUnicast)
        return FALSE;
    FillRow(If, Ia->Addr, Ia->Pref, Ia->Valid, &Row);
    Error = pCreateUnicast(&Row);
    if (Error == ERROR_OBJECT_ALREADY_EXISTS)
    {
        if (StackHas(If, Ia->Addr, &Ours) && !Ours)
        {
            D6_LOG("interface %lu: a leased address is in the stack from another source, not taken\n", If->IfIndex);
            *Foreign = TRUE;
            return FALSE;
        }
        if (OnlyCreate)
            return TRUE;
        FillRow(If, Ia->Addr, Ia->Pref, Ia->Valid, &Row);
        Error = pSetUnicast(&Row);
    }
    if (Error != NO_ERROR)
        D6_LOG("interface %lu: installing an address failed, error %lu\n", If->IfIndex, Error);
    return Error == NO_ERROR;
}

static VOID RemoveAddress(D6IF *If, const UCHAR *Addr)
{
    MIB_UNICASTIPADDRESS_ROW Row;
    BOOL Ours;

    if (!pDeleteUnicast || !pInitializeUnicast)
        return;
    /* only an address with the DHCP origin: one that is the stack's or an administrator's (meanwhile) stays, and so
       does its persistent record (a deletion takes the address out of both stores) */
    if (pGetUnicast && (!StackHas(If, Addr, &Ours) || !Ours))
        return;
    FillRow(If, Addr, 0, 0, &Row);
    pDeleteUnicast(&Row); /* gone already (its valid lifetime ended in the stack): nothing to do */
}

/* 1: tentative, 2: the stack found the address in use, 0: usable or not there */
static ULONG DadOf(D6IF *If, const UCHAR *Addr)
{
    MIB_UNICASTIPADDRESS_ROW Row;

    if (!pGetUnicast || !pInitializeUnicast)
        return 0;
    FillRow(If, Addr, 0, 0, &Row);
    if (pGetUnicast(&Row) != NO_ERROR)
        return 0;
    if (Row.DadState == IpDadStateTentative)
        return 1;
    return Row.DadState == IpDadStateDuplicate ? 2 : 0;
}

/* ---- stateful client: the lease ---- */

static BOOL HoldsLease(const D6IF *If)
{
    return If->Mode == D6M_STATEFUL && If->LeaseCount != 0;
}

static ULONGLONG ExpireOf(ULONGLONG Now, ULONG Valid)
{
    return Valid == D6_INFINITE ? D6_NEVER : Now + (ULONGLONG)Valid * 1000;
}

static LONG LeaseFind(const D6IF *If, const UCHAR *Addr)
{
    ULONG i;

    for (i = 0; i < If->LeaseCount; i++)
    {
        if (!memcmp(If->Lease[i].Ia.Addr, Addr, 16))
            return (LONG)i;
    }
    return -1;
}

static VOID LeaseRemoveAt(D6IF *If, ULONG Index)
{
    ULONG i;

    for (i = Index + 1; i < If->LeaseCount; i++)
        If->Lease[i - 1] = If->Lease[i];
    If->LeaseCount--;
}

static BOOL AnyDadPending(const D6IF *If)
{
    ULONG i;

    for (i = 0; i < If->LeaseCount; i++)
    {
        if (!If->Lease[i].DadDone)
            return TRUE;
    }
    return FALSE;
}

static ULONGLONG EarliestExpire(const D6IF *If)
{
    ULONGLONG Min = D6_NEVER;
    ULONG i;

    for (i = 0; i < If->LeaseCount; i++)
        Min = MinU64(Min, If->Lease[i].Expire);
    return Min;
}

/* The next time anything of a stateful interface is due */
static VOID Rearm(D6IF *If)
{
    ULONGLONG Due = D6_NEVER;

    if (If->Mode != D6M_STATEFUL)
        return;
    if (If->LeaseCount)
        Due = MinU64(Due, EarliestExpire(If));
    if (If->Cmd)
        Due = MinU64(Due, If->CmdDue);
    if (!If->Away)
    {
        if (If->DadPending)
            Due = MinU64(Due, If->DadDue);
        switch (If->State)
        {
            case D6S_DELAY:
            case D6S_SOLICIT:
            case D6S_REQUEST:
            case D6S_REBIND:
            case D6S_DECLINE:
            case D6S_RELEASE:
                Due = MinU64(Due, If->RetransDue);
                break;
            case D6S_RENEW:
                Due = MinU64(Due, MinU64(If->RetransDue, If->T2Due));
                break;
            case D6S_CONFIRM:
                Due = MinU64(Due, MinU64(If->RetransDue, If->Deadline));
                break;
            case D6S_LEASED:
                Due = MinU64(Due, If->T1Due);
                break;
            default:
                break;
        }
    }
    If->HasDue = (Due != D6_NEVER);
    If->Due = Due;
}

static VOID ResetLease(D6IF *If)
{
    If->LeaseCount = 0;
    If->GoneCount = 0;
    If->HaveAdv = FALSE;
    If->AdvAddrCount = 0;
    If->SrvLen = 0;
    If->T1Due = If->T2Due = D6_NEVER;
    If->T1 = If->T2 = 0;
    If->DadPending = FALSE;
}

/* A new transaction: its id, retransmission parameters (RFC 8415 7.6) and state */
static VOID BeginMessage(D6IF *If, UCHAR Type, ULONGLONG Now)
{
    SystemFunction036(If->Xid, 3);
    If->MsgType = Type;
    If->Sent = 0;
    If->Rt = 0;
    If->FirstSent = Now;
    If->Deadline = D6_NEVER;
    If->Mrc = 0;
    switch (Type)
    {
        case D6_SOLICIT:
            If->Irt = SOL_TIMEOUT_MS; If->Mrt = If->SolMaxRt; If->State = D6S_SOLICIT;
            break;
        case D6_REQUEST:
            If->Irt = REQ_TIMEOUT_MS; If->Mrt = REQ_MAX_RT_MS; If->Mrc = REQ_MAX_RC; If->State = D6S_REQUEST;
            break;
        case D6_CONFIRM:
            If->Irt = CNF_TIMEOUT_MS; If->Mrt = CNF_MAX_RT_MS; If->Deadline = Now + CNF_MAX_RD_MS; If->State = D6S_CONFIRM;
            break;
        case D6_RENEW:
            If->Irt = REN_TIMEOUT_MS; If->Mrt = REN_MAX_RT_MS; If->State = D6S_RENEW;
            break;
        case D6_REBIND:
            If->Irt = REB_TIMEOUT_MS; If->Mrt = REB_MAX_RT_MS; If->State = D6S_REBIND;
            break;
        case D6_RELEASE:
            If->Irt = REL_TIMEOUT_MS; If->Mrt = 0; If->Mrc = REL_MAX_RC; If->State = D6S_RELEASE;
            break;
        default: /* D6_DECLINE */
            If->Irt = DEC_TIMEOUT_MS; If->Mrt = 0; If->Mrc = DEC_MAX_RC; If->State = D6S_DECLINE;
            break;
    }
}

/* Sends the message of the outstanding transaction and arms its retransmission */
static VOID TransmitMessage(D6IF *If, ULONGLONG Now)
{
    UCHAR Packet[D6_MAX_PACKET];
    SOCKADDR_IN6 To;
    ULONG Len;

    if (If->Sock != INVALID_SOCKET)
    {
        Len = BuildStateful(If, Now, Packet);
        memset(&To, 0, sizeof(To));
        To.sin6_family = AF_INET6;
        To.sin6_port = htons(D6_PORT_SERVER);
        To.sin6_addr.u.Byte[0] = 0xFF;
        To.sin6_addr.u.Byte[1] = 0x02;
        To.sin6_addr.u.Byte[13] = 0x01;
        To.sin6_addr.u.Byte[15] = 0x02;
        To.sin6_scope_id = If->IfIndex;
        if (sendto(If->Sock, (const char *)Packet, Len, 0, (PSOCKADDR)&To, sizeof(To)) == SOCKET_ERROR)
            D6_LOG("interface %lu: sendto failed %d\n", If->IfIndex, WSAGetLastError());
    }
    If->Sent++;
    If->Rt = NextStatefulRt(If);
    If->RetransDue = Now + If->Rt;
    D6_LOG("interface %lu: message %u sent (%lu), next in %lu ms\n", If->IfIndex, If->MsgType, If->Sent, If->Rt);
    Rearm(If);
}

/* The first Solicit after DelayMs (a cool-down after a failure or a Decline adds to the random start delay) */
static VOID StartSolicit(D6IF *If, ULONGLONG Now, ULONG DelayMs)
{
    If->HaveAdv = FALSE;
    If->AdvAddrCount = 0;
    If->MsgType = D6_SOLICIT;
    If->State = D6S_DELAY;
    If->RetransDue = Now + DelayMs;
    Rearm(If);
}

static ULONG FailDelay(const D6IF *If)
{
    ULONGLONG Wait = (ULONGLONG)If->FailCount * D6_FAIL_WAIT_MS;

    return (ULONG)(Wait > D6_MAX_WAIT_MS ? D6_MAX_WAIT_MS : Wait);
}

/* No usable answer: the data of the lease goes, ask again after a cool-down */
static VOID LeaseLost(D6IF *If, ULONGLONG Now, BOOL Failure)
{
    ULONG i;

    for (i = 0; i < If->LeaseCount; i++)
        RemoveAddress(If, If->Lease[i].Ia.Addr);
    ResetLease(If);
    Withdraw(If);
    PublishLease(If);
    if (Failure)
        If->FailCount++;
    if (If->Away)
    {
        Rearm(If);
        return; /* the interface comes back (or goes for good): Scan decides */
    }
    StartSolicit(If, Now, Rand32() % (SOL_MAX_DELAY_MS + 1) + FailDelay(If));
}

/* The times of a lease from the Reply and the addresses: T1/T2 of the server, or 0.5 and 0.8 of the shortest
   preferred lifetime when it leaves them to the client (RFC 8415 14.2); a time of "never" stays never */
static VOID SetTimes(D6IF *If, ULONG ServerT1, ULONG ServerT2, ULONGLONG Now)
{
    ULONG MinPref = D6_INFINITE, T1, T2, i;

    for (i = 0; i < If->LeaseCount; i++)
    {
        if (If->Lease[i].Ia.Pref < MinPref)
            MinPref = If->Lease[i].Ia.Pref;
    }
    T1 = ServerT1;
    T2 = ServerT2;
    if (T1 == 0)
        T1 = (MinPref == D6_INFINITE) ? D6_INFINITE : MinPref / 2;
    if (T2 == 0)
        T2 = (MinPref == D6_INFINITE) ? D6_INFINITE : (ULONG)((ULONGLONG)MinPref * 8 / 10);
    if (T1 != D6_INFINITE && T1 < 1)
        T1 = 1;
    if (T2 != D6_INFINITE && T2 < T1)
        T2 = T1;
    If->T1 = T1;
    If->T2 = T2;
    If->T1Due = (T1 == D6_INFINITE) ? D6_NEVER : Now + (ULONGLONG)T1 * 1000;
    If->T2Due = (T2 == D6_INFINITE) ? D6_NEVER : Now + (ULONGLONG)T2 * 1000;
}

/* A Reply to a Request, Renew or Rebind with a usable IA_NA: the addresses join or refresh the lease (a valid
   lifetime of 0 ends one), reach the stack, and the times restart */
static VOID AcceptLease(D6IF *If, const D6REPLY *R, const UCHAR *Msg, ULONG Len, const SOCKADDR_IN6 *From, ULONGLONG Now)
{
    ULONG i;
    BOOL Renewing = (If->State == D6S_RENEW || If->State == D6S_REBIND), Foreign;

    /* the server of the lease: the one that answered a Request, or a Rebind */
    if (If->State != D6S_RENEW)
    {
        memcpy(If->Srv, R->Server, R->ServerLen);
        If->SrvLen = R->ServerLen;
    }
    memcpy(If->SrvAddr, From->sin6_addr.u.Byte, 16);

    for (i = 0; i < R->AddrCount; i++)
    {
        const D6IAADDR *Ia = &R->Addrs[i];
        LONG At = LeaseFind(If, Ia->Addr);

        if (Ia->Valid == 0)
        {
            if (At >= 0)
            {
                RemoveAddress(If, Ia->Addr);
                LeaseRemoveAt(If, (ULONG)At);
            }
            continue;
        }
        if (At < 0)
        {
            if (If->LeaseCount >= D6_MAX_ADDRS)
                continue;
            At = (LONG)If->LeaseCount++;
            memset(&If->Lease[At], 0, sizeof(If->Lease[At]));
        }
        If->Lease[At].Ia = *Ia;
        If->Lease[At].Expire = ExpireOf(Now, Ia->Valid);
        If->Lease[At].Installed = InstallAddress(If, Ia, FALSE, &Foreign);
        If->Lease[At].Foreign = Foreign;
        if (Foreign)
            If->Lease[At].DadDone = FALSE; /* the next DAD check declines it */
        else if (!If->Lease[At].Installed)
            If->Lease[At].DadDone = TRUE; /* nothing to wait for */
    }

    if (If->LeaseCount == 0)
    {
        LeaseLost(If, Now, TRUE);
        return;
    }

    SetTimes(If, R->T1, R->T2, Now);
    If->FailCount = 0;
    if (R->HasSolMaxRt)
        If->SolMaxRt = R->SolMaxRt * 1000UL;
    if (Renewing && R->DnsCount == 0 && R->DomainCount == 0)
        CountReply(If, From->sin6_addr.u.Byte);
    else
        Publish(If, R, Msg + 4, Len - 4, From->sin6_addr.u.Byte);
    If->DadPending = AnyDadPending(If);
    If->DadDue = Now + D6_DAD_POLL_MS;
    If->State = D6S_LEASED;
    PublishLease(If);
    D6_LOG("interface %lu: lease: %lu address(es), T1 %lu s, T2 %lu s\n", If->IfIndex, If->LeaseCount, If->T1, If->T2);
    if (If->Cmd == DHCP6_COMMAND_RENEW)
        CompleteCommand(If, ERROR_SUCCESS);
    Rearm(If);
}

static VOID BeginRequest(D6IF *If, ULONGLONG Now)
{
    memcpy(If->Srv, If->AdvSrv, If->AdvSrvLen);
    If->SrvLen = If->AdvSrvLen;
    memcpy(If->SrvAddr, If->AdvAddr, 16);
    BeginMessage(If, D6_REQUEST, Now);
    TransmitMessage(If, Now);
}

static VOID BeginRenew(D6IF *If, ULONGLONG Now)
{
    BeginMessage(If, D6_RENEW, Now);
    TransmitMessage(If, Now);
}

static VOID BeginRebind(D6IF *If, ULONGLONG Now)
{
    BeginMessage(If, D6_REBIND, Now);
    TransmitMessage(If, Now);
}

static VOID BeginConfirm(D6IF *If, ULONGLONG Now)
{
    BeginMessage(If, D6_CONFIRM, Now);
    TransmitMessage(If, Now);
}

/* The addresses leave the stack first (RFC 8415 18.2.7), then the Release goes to the server */
static VOID BeginRelease(D6IF *If, ULONGLONG Now)
{
    ULONG i;

    If->GoneCount = 0;
    for (i = 0; i < If->LeaseCount; i++)
    {
        If->Gone[If->GoneCount++] = If->Lease[i].Ia;
        RemoveAddress(If, If->Lease[i].Ia.Addr);
    }
    If->LeaseCount = 0;
    If->DadPending = FALSE;
    If->T1Due = If->T2Due = D6_NEVER;
    BeginMessage(If, D6_RELEASE, Now);
    TransmitMessage(If, Now);
    Withdraw(If);
    PublishLease(If);
}

static VOID FinishRelease(D6IF *If)
{
    If->GoneCount = 0;
    If->SrvLen = 0;
    If->State = D6S_RELEASED;
    If->HasDue = FALSE;
    D6_LOG("interface %lu: released\n", If->IfIndex);
    CompleteCommand(If, ERROR_SUCCESS);
    Rearm(If);
}

/* Duplicate address detection found these addresses in use: out of the stack and out of the lease, then the
   Decline (RFC 8415 18.2.8) */
static VOID BeginDecline(D6IF *If, const UCHAR Dup[][16], ULONG DupCount, ULONGLONG Now)
{
    ULONG i;

    If->GoneCount = 0;
    for (i = 0; i < DupCount; i++)
    {
        LONG At = LeaseFind(If, Dup[i]);

        if (At >= 0)
        {
            If->Gone[If->GoneCount++] = If->Lease[At].Ia;
            RemoveAddress(If, Dup[i]);
            LeaseRemoveAt(If, (ULONG)At);
        }
    }
    If->DadPending = AnyDadPending(If);
    If->DeclineCount++;
    D6_LOG("interface %lu: %lu address(es) in use, Decline\n", If->IfIndex, If->GoneCount);
    BeginMessage(If, D6_DECLINE, Now);
    TransmitMessage(If, Now);
    PublishLease(If);
}

static VOID FinishDecline(D6IF *If, ULONGLONG Now)
{
    ULONGLONG Wait = (ULONGLONG)If->DeclineCount * D6_DECLINE_WAIT_MS;

    If->GoneCount = 0;
    if (If->LeaseCount)
    {
        If->State = D6S_LEASED;
        Rearm(If);
        return;
    }
    ResetLease(If);
    Withdraw(If);
    PublishLease(If);
    StartSolicit(If, Now, (ULONG)(Wait > D6_MAX_WAIT_MS ? D6_MAX_WAIT_MS : Wait));
}

/* Poll the stack for the end of duplicate address detection of the addresses just installed */
static VOID CheckDad(D6IF *If, ULONGLONG Now)
{
    UCHAR Dup[D6_MAX_ADDRS][16];
    ULONG i, DupCount = 0;
    BOOL Pending = FALSE;

    for (i = 0; i < If->LeaseCount; i++)
    {
        ULONG Dad;

        if (If->Lease[i].DadDone)
            continue;
        Dad = If->Lease[i].Foreign ? 2 : DadOf(If, If->Lease[i].Ia.Addr);
        if (Dad == 2)
            memcpy(Dup[DupCount++], If->Lease[i].Ia.Addr, 16);
        else if (Dad == 1)
            Pending = TRUE;
        else
            If->Lease[i].DadDone = TRUE;
    }
    if (DupCount)
    {
        if (If->State == D6S_LEASED)
        {
            BeginDecline(If, (const UCHAR (*)[16])Dup, DupCount, Now);
            return;
        }
        Pending = TRUE; /* a transaction is in flight: look again when it is over */
    }
    else if (!Pending)
    {
        /* every address passed: the exchange worked, the next Decline starts from nothing */
        If->DeclineCount = 0;
    }
    If->DadPending = Pending;
    If->DadDue = Now + (Pending ? D6_DAD_POLL_MS * 4 : 0);
    Rearm(If);
}

/* Addresses whose valid lifetime ended leave the lease; the last one going ends it */
static BOOL ExpireLease(D6IF *If, ULONGLONG Now)
{
    ULONG i = 0;
    BOOL Changed = FALSE;

    while (i < If->LeaseCount)
    {
        if (If->Lease[i].Expire <= Now)
        {
            D6_LOG("interface %lu: an address expired\n", If->IfIndex);
            RemoveAddress(If, If->Lease[i].Ia.Addr);
            LeaseRemoveAt(If, i);
            Changed = TRUE;
        }
        else
            i++;
    }
    if (!Changed)
        return FALSE;
    If->DadPending = AnyDadPending(If);
    if (If->LeaseCount == 0)
    {
        LeaseLost(If, Now, FALSE);
        return TRUE;
    }
    PublishLease(If);
    return FALSE;
}

/* A stateful interface's timers: command wait, lease expiry, DAD polling, then the state's own */
static VOID StatefulTimer(D6IF *If, ULONGLONG Now)
{
    if (If->Cmd && Now >= If->CmdDue)
        CompleteCommand(If, ERROR_TIMEOUT);
    if (ExpireLease(If, Now))
        return;
    if (If->Away)
    {
        Rearm(If);
        return;
    }
    if (If->DadPending && Now >= If->DadDue)
    {
        CheckDad(If, Now);
        if (If->State == D6S_DECLINE)
            return;
    }

    switch (If->State)
    {
        case D6S_DELAY:
            if (Now >= If->RetransDue)
            {
                BeginMessage(If, D6_SOLICIT, Now);
                TransmitMessage(If, Now);
            }
            break;
        case D6S_SOLICIT:
            if (Now >= If->RetransDue)
            {
                if (If->HaveAdv)
                    BeginRequest(If, Now);
                else
                    TransmitMessage(If, Now);
            }
            break;
        case D6S_REQUEST:
            if (Now >= If->RetransDue)
            {
                if (If->Mrc && If->Sent >= If->Mrc)
                {
                    D6_LOG("interface %lu: no answer to the Request, Solicit again\n", If->IfIndex);
                    If->FailCount++;
                    StartSolicit(If, Now, Rand32() % (SOL_MAX_DELAY_MS + 1) + FailDelay(If));
                }
                else
                    TransmitMessage(If, Now);
            }
            break;
        case D6S_LEASED:
            if (Now >= If->T1Due)
                BeginRenew(If, Now);
            break;
        case D6S_RENEW:
            if (Now >= If->T2Due)
                BeginRebind(If, Now);
            else if (Now >= If->RetransDue)
                TransmitMessage(If, Now);
            break;
        case D6S_REBIND:
            if (Now >= If->RetransDue)
                TransmitMessage(If, Now);
            break;
        case D6S_CONFIRM:
            if (Now >= If->Deadline)
            {
                /* no answer in CNF_MAX_RD: keep using the addresses (RFC 8415 18.2.3) */
                If->State = D6S_LEASED;
            }
            else if (Now >= If->RetransDue)
                TransmitMessage(If, Now);
            break;
        case D6S_RELEASE:
            if (Now >= If->RetransDue)
            {
                if (If->Sent >= If->Mrc)
                    FinishRelease(If);
                else
                    TransmitMessage(If, Now);
            }
            break;
        case D6S_DECLINE:
            if (Now >= If->RetransDue)
            {
                if (If->Sent >= If->Mrc)
                    FinishDecline(If, Now);
                else
                    TransmitMessage(If, Now);
            }
            break;
        default:
            break;
    }
    Rearm(If);
}

/* A message for a stateful interface in a state that has a request outstanding */
static VOID HandleStateful(D6IF *If, const UCHAR *Packet, ULONG Len, const SOCKADDR_IN6 *From, ULONGLONG Now)
{
    D6REPLY R;
    BOOL FromServer;

    switch (If->State)
    {
        case D6S_SOLICIT: case D6S_REQUEST: case D6S_RENEW: case D6S_REBIND: case D6S_CONFIRM:
        case D6S_RELEASE: case D6S_DECLINE:
            break;
        default:
            return; /* no request out: the transaction id of a finished exchange is not taken */
    }
    if (!ParseMessage(If, Packet, Len, TRUE, &R))
        return;
    if (From->sin6_addr.u.Byte[0] == 0xFF)
        return;
    /* the server a Request, Renew, Release or Decline went to is the one that answers it */
    FromServer = (If->SrvLen == R.ServerLen && memcmp(If->Srv, R.Server, R.ServerLen) == 0);

    if (If->State == D6S_SOLICIT)
    {
        if (R.Type != D6_ADVERTISE)
            return;
        if (R.Status != D6_STATUS_SUCCESS || !R.HasIa || R.IaStatus != D6_STATUS_SUCCESS || R.AddrCount == 0)
        {
            D6_LOG("interface %lu: Advertise without an address (status %lu/%lu) ignored\n", If->IfIndex, R.Status, R.IaStatus);
            return;
        }
        if (R.HasSolMaxRt)
        {
            If->SolMaxRt = R.SolMaxRt * 1000UL;
            If->Mrt = If->SolMaxRt;
        }
        if (!If->HaveAdv || R.Preference > If->AdvPref)
        {
            If->HaveAdv = TRUE;
            memcpy(If->AdvSrv, R.Server, R.ServerLen);
            If->AdvSrvLen = R.ServerLen;
            memcpy(If->AdvAddr, From->sin6_addr.u.Byte, 16);
            If->AdvPref = R.Preference;
            memcpy(If->AdvAddrs, R.Addrs, sizeof(R.Addrs[0]) * R.AddrCount);
            If->AdvAddrCount = R.AddrCount;
        }
        /* preference 255 wins at once; after the first retransmission interval the first Advertisement does */
        if (R.Preference == 255 || If->Sent > 1)
            BeginRequest(If, Now);
        return;
    }

    if (R.Type != D6_REPLY)
        return;

    switch (If->State)
    {
        case D6S_REQUEST:
            if (!FromServer)
                return;
            if (R.Status != D6_STATUS_SUCCESS || !R.HasIa || R.IaStatus != D6_STATUS_SUCCESS || R.AddrCount == 0)
            {
                D6_LOG("interface %lu: Reply to the Request without an address (status %lu/%lu)\n", If->IfIndex,
                       R.Status, R.IaStatus);
                If->FailCount++;
                StartSolicit(If, Now, Rand32() % (SOL_MAX_DELAY_MS + 1) + FailDelay(If));
                return;
            }
            AcceptLease(If, &R, Packet, Len, From, Now);
            break;

        case D6S_RENEW:
        case D6S_REBIND:
            if (If->State == D6S_RENEW && !FromServer)
                return;
            if (R.Status == D6_STATUS_NOBINDING || (R.HasIa && R.IaStatus == D6_STATUS_NOBINDING))
            {
                /* the server has no record of the addresses: start over (RFC 8415 18.2.10.1) */
                D6_LOG("interface %lu: NoBinding, Solicit again\n", If->IfIndex);
                LeaseLost(If, Now, FALSE);
                return;
            }
            if (R.Status != D6_STATUS_SUCCESS || !R.HasIa || R.IaStatus != D6_STATUS_SUCCESS)
                return; /* keep retransmitting */
            AcceptLease(If, &R, Packet, Len, From, Now);
            break;

        case D6S_CONFIRM:
            if (R.Status == D6_STATUS_NOTONLINK)
            {
                D6_LOG("interface %lu: NotOnLink, the addresses go\n", If->IfIndex);
                LeaseLost(If, Now, FALSE);
            }
            else if (R.Status == D6_STATUS_SUCCESS)
            {
                ULONG i;

                /* still on the link: make sure the stack has them (a disabled adapter lost them) */
                for (i = 0; i < If->LeaseCount; i++)
                {
                    BOOL Was = If->Lease[i].Installed, Foreign;

                    If->Lease[i].Installed = InstallAddress(If, &If->Lease[i].Ia, TRUE, &Foreign);
                    If->Lease[i].Foreign = Foreign;
                    if ((!Was && If->Lease[i].Installed) || Foreign)
                        If->Lease[i].DadDone = FALSE;
                }
                If->DadPending = AnyDadPending(If);
                If->DadDue = Now + D6_DAD_POLL_MS;
                If->State = D6S_LEASED;
                Rearm(If);
            }
            break;

        case D6S_RELEASE:
            if (FromServer)
                FinishRelease(If);
            break;

        case D6S_DECLINE:
            if (FromServer)
                FinishDecline(If, Now);
            break;

        default:
            break;
    }
}

/* ipconfig /renew6 and /release6 for this interface */
static VOID RunCommand(D6IF *If, ULONG Command, ULONGLONG Now)
{
    If->Cmd = Command;
    If->CmdDue = Now + D6_COMMAND_WAIT_MS;
    if (Command == DHCP6_COMMAND_RELEASE)
    {
        if (!HoldsLease(If))
        {
            If->GoneCount = 0;
            If->State = D6S_RELEASED;
            If->HasDue = FALSE;
            CompleteCommand(If, ERROR_SUCCESS);
        }
        else if (If->Sock == INVALID_SOCKET)
        {
            ULONG i;

            for (i = 0; i < If->LeaseCount; i++)
                RemoveAddress(If, If->Lease[i].Ia.Addr);
            ResetLease(If);
            Withdraw(If);
            PublishLease(If);
            If->State = D6S_RELEASED;
            CompleteCommand(If, ERROR_SUCCESS);
        }
        else
            BeginRelease(If, Now);
    }
    else if (HoldsLease(If) && If->State != D6S_RELEASE)
    {
        BeginRenew(If, Now);
    }
    else
    {
        /* nothing leased (released, or still asking): ask now */
        If->FailCount = 0;
        StartSolicit(If, Now, 0);
    }
    Rearm(If);
}

/* Datagrams read per interface and pass: a flood on the link cannot hold the thread here. What is still queued when
   the budget is spent is not forgotten: the caller goes round again without waiting (stop event, timers and the other
   interfaces are looked at between the passes), so a Reply that sits behind a burst is read at once and not at the
   next timer */
#define D6_READ_BUDGET      64

/* TRUE: the budget ran out, more may be queued */
static BOOL ReadSocket(D6IF *If, ULONGLONG Now)
{
    /* only the DHCPv6 thread reads, so one buffer serves every interface (64 KB is too much for its stack) */
    static UCHAR Packet[D6_MAX_RECV];
    ULONG Budget;

    for (Budget = D6_READ_BUDGET; Budget; Budget--)
    {
        SOCKADDR_IN6 From;
        int FromLen = sizeof(From), Len;
        D6REPLY Reply;

        Len = recvfrom(If->Sock, (char *)Packet, D6_MAX_RECV, 0, (PSOCKADDR)&From, &FromLen);
        if (Len == SOCKET_ERROR)
        {
            /* a datagram larger than the buffer (more than any UDP datagram) is dropped by recvfrom; the ones queued
               behind it are still read */
            if (WSAGetLastError() == WSAEMSGSIZE)
                continue;
            break;
        }
        if (Len < 4 || From.sin6_family != AF_INET6 || ntohs(From.sin6_port) != D6_PORT_SERVER)
            continue;
        if (If->Mode == D6M_STATEFUL)
        {
            HandleStateful(If, Packet, (ULONG)Len, &From, Now);
            continue;
        }
        /* Only a Reply to the Information-Request that is out: once one was accepted (BOUND) the exchange is over and
           its transaction id is no longer outstanding (RFC 8415 16, 18.2.10), so a late or repeated Reply with it
           neither replaces the data nor moves the refresh time */
        if (If->State != D6S_INFORM)
            continue;
        if (!ParseMessage(If, Packet, (ULONG)Len, FALSE, &Reply) || Reply.Type != D6_REPLY)
            continue;
        if (Reply.Status != 0)
        {
            D6_LOG("interface %lu: Reply with status %lu ignored\n", If->IfIndex, Reply.Status);
            continue;
        }
        AcceptReply(If, &Reply, Packet, (ULONG)Len, &From, Now);
    }
    return Budget == 0;
}

static VOID Teardown(D6IF *If)
{
    CloseSocket(If);
    ResetLease(If);
    Withdraw(If);
    If->State = D6S_IDLE;
    If->HasDue = FALSE;
    If->Mode = D6M_NONE;
    If->Away = FALSE;
    CompleteCommand(If, ERROR_NOT_FOUND);
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

/* A stateful interface starts asking (or Confirms what it holds) with a socket on its link-local address */
static VOID StartStateful(D6IF *If, ULONGLONG Now)
{
    If->Mode = D6M_STATEFUL;
    If->MaxRt = INF_MAX_RT_MS;
    If->SolMaxRt = SOL_MAX_RT_MS;
    If->Away = FALSE;
    PublishLease(If);
    if (HoldsLease(If))
    {
        D6_LOG("interface %lu: link changed, Confirm\n", If->IfIndex);
        BeginConfirm(If, Now);
    }
    else
    {
        StartSolicit(If, Now, Rand32() % (SOL_MAX_DELAY_MS + 1));
        D6_LOG("interface %lu: M flag seen, Solicit starts\n", If->IfIndex);
    }
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
            If->SolMaxRt = SOL_MAX_RT_MS;
            If->T1Due = If->T2Due = D6_NEVER;
            If->Next = Interfaces;
            Interfaces = If;
            Fresh = TRUE;
        }
        If->Seen = TRUE;
        strcpy(If->Name, A->AdapterName);
        memcpy(If->Mac, A->PhysicalAddress, 6);
        If->MacLen = 6;

        /* a new link-local address (or a first one): the socket is bound to the old one. A lease is not given up
           for that: the socket moves and the client Confirms */
        if (memcmp(If->LinkLocal, LinkLocal, 16) != 0)
        {
            if (!Fresh && If->Mode != D6M_NONE)
                D6_LOG("interface %lu: link-local address changed\n", If->IfIndex);
            memcpy(If->LinkLocal, LinkLocal, 16);
            if (If->Sock != INVALID_SOCKET)
            {
                if (HoldsLease(If))
                    CloseSocket(If);
                else
                    Teardown(If);
            }
        }

        EnsureDuid(If->Mac, If->MacLen);
        PublishIdentity(If);

        Mode = WantedMode((A->Flags & D6_ADAPTER_MANAGED) != 0, (A->Flags & IP_ADAPTER_IPV6_OTHER_STATEFUL_CONFIG) != 0);
        /* the M flag never goes 1 -> 0 without an advertisement, and a lease is kept while it runs even then */
        if (HoldsLease(If))
            Mode = D6M_STATEFUL;
        if (Mode == D6M_NONE && If->Mode != D6M_NONE)
        {
            D6_LOG("interface %lu: no M or O flag any more, DHCPv6 stops\n", If->IfIndex);
            Teardown(If);
        }
        else if (Mode != D6M_NONE && If->Mode != D6M_NONE && Mode != If->Mode)
        {
            D6_LOG("interface %lu: the flags changed the DHCPv6 mode\n", If->IfIndex);
            Teardown(If);
        }

        if (Mode != D6M_NONE && If->Mode == D6M_NONE && DuidLen)
        {
            if (OpenSocket(If))
            {
                if (Mode == D6M_STATEFUL)
                    StartStateful(If, Now);
                else
                {
                    If->Mode = Mode;
                    If->MaxRt = INF_MAX_RT_MS;
                    StartExchange(If, Now, FALSE);
                    D6_LOG("interface %lu: M/O flag seen, Information-Request starts\n", If->IfIndex);
                }
            }
        }
        else if (If->Mode == D6M_STATEFUL && If->Sock == INVALID_SOCKET && DuidLen)
        {
            /* the adapter came back (or its link-local address changed) while a lease is held */
            if (OpenSocket(If))
                StartStateful(If, Now);
        }
    }

    /* adapters that went away or lost their link-local address: one that holds a lease stays (its addresses run
       down on their own and Confirm answers whether they are still good when the link returns) */
    for (Link = &Interfaces; (If = *Link) != NULL; )
    {
        if (!If->Seen)
        {
            if (HoldsLease(If))
            {
                if (!If->Away)
                {
                    D6_LOG("interface %lu: adapter gone with a lease, kept\n", If->IfIndex);
                    If->Away = TRUE;
                    CloseSocket(If);
                    If->State = D6S_LEASED;
                    Rearm(If);
                }
                Link = &If->Next;
                continue;
            }
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
        if (If->Mode == D6M_NONE || !If->HasDue || If->Due > Now)
            continue;
        if (If->Mode == D6M_STATEFUL)
        {
            StatefulTimer(If, Now);
            continue;
        }
        if (If->Sock == INVALID_SOCKET)
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

/* Dhcpv6RequestParams(force): a new Information-Request, or for a stateful interface a Renew (the Reply carries
   the options again) or, with nothing leased, the Solicit */
static VOID ForceAll(ULONGLONG Now)
{
    D6IF *If;

    for (If = Interfaces; If; If = If->Next)
    {
        if (If->Mode == D6M_INFORMATION && If->Sock != INVALID_SOCKET)
        {
            StartExchange(If, Now, TRUE);
            SendInformationRequest(If, Now);
        }
        else if (If->Mode == D6M_STATEFUL && If->Sock != INVALID_SOCKET && !If->Away && If->State != D6S_RELEASED)
        {
            if (If->State == D6S_LEASED)
                BeginRenew(If, Now);
            else if (!HoldsLease(If) && (If->State == D6S_DELAY || If->State == D6S_SOLICIT))
                StartSolicit(If, Now, 0);
        }
    }
}

/* The commands of ipconfig /renew6 and /release6: a value in the interface key (administrators only), the event
   wakes the client */
static VOID CheckCommands(ULONGLONG Now)
{
    D6IF *If;

    for (If = Interfaces; If; If = If->Next)
    {
        HKEY Key;
        DWORD Command = 0, Size = sizeof(Command), Type;

        if (If->Cmd || If->Mode != D6M_STATEFUL)
            continue;
        Key = OpenInterfaceKey(If->Name, FALSE);
        if (!Key)
            continue;
        if (RegQueryValueExA(Key, DHCP6_VALUE_COMMAND, NULL, &Type, (LPBYTE)&Command, &Size) != ERROR_SUCCESS ||
            Type != REG_DWORD || (Command != DHCP6_COMMAND_RENEW && Command != DHCP6_COMMAND_RELEASE))
        {
            if (Command != 0)
                RegDeleteValueA(Key, DHCP6_VALUE_COMMAND); /* not a command: gone */
            RegCloseKey(Key);
            continue;
        }
        RegCloseKey(Key);
        D6_LOG("interface %lu: command %lu\n", If->IfIndex, Command);
        RunCommand(If, Command, Now);
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

static HANDLE MakeAdminEvent(PCWSTR Name)
{
    SECURITY_ATTRIBUTES Sa;
    PSECURITY_DESCRIPTOR Sd = NULL;
    HANDLE Event;

    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    Sa.lpSecurityDescriptor = NULL;
    /* SYSTEM and administrators only */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &Sd, NULL))
        Sa.lpSecurityDescriptor = Sd;
    Event = CreateEventW(Sd ? &Sa : NULL, FALSE, FALSE, Name);
    if (Sd)
        LocalFree(Sd);
    return Event;
}

static DWORD WINAPI Dhcp6Thread(LPVOID Context)
{
    HANDLE StopEvent = Context, NotifyEvent, ForceEvent = NULL, CommandEvent = NULL, Handles[5], NotifyHandle = NULL;
    WSADATA Wsa;
    ULONGLONG NextScan = 0;
    BOOL MoreQueued = FALSE;
    PNOTIFY_INTERFACE Notify;
    PCANCEL_NOTIFY Cancel;
    DWORD HandleCount, ForceIndex = 0, CommandIndex = 0;

    if (WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
        return 1;
    SockEvent = WSACreateEvent();
    NotifyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (SockEvent == WSA_INVALID_EVENT || !NotifyEvent)
    {
        WSACleanup();
        return 1;
    }

    /* SYSTEM and administrators only may ask for a new Information-Request, a Renew or a Release */
    ForceEvent = MakeAdminEvent(DHCP6_FORCE_EVENT_NAME);
    CommandEvent = MakeAdminEvent(DHCP6_COMMAND_EVENT_NAME);

    ClearAllLearned();
    {
        HMODULE Iphlpapi = GetModuleHandleW(L"iphlpapi.dll");

        Notify = Iphlpapi ? (PNOTIFY_INTERFACE)GetProcAddress(Iphlpapi, "NotifyIpInterfaceChange") : NULL;
        Cancel = Iphlpapi ? (PCANCEL_NOTIFY)GetProcAddress(Iphlpapi, "CancelMibChangeNotify2") : NULL;
        if (Notify && Cancel)
            Notify(AF_INET6, InterfaceChanged, NotifyEvent, FALSE, &NotifyHandle);
        pInitializeUnicast = Iphlpapi ? (PINIT_UNICAST)GetProcAddress(Iphlpapi, "InitializeUnicastIpAddressEntry") : NULL;
        pCreateUnicast = Iphlpapi ? (PUNICAST_CALL)GetProcAddress(Iphlpapi, "CreateUnicastIpAddressEntry") : NULL;
        pSetUnicast = Iphlpapi ? (PUNICAST_CALL)GetProcAddress(Iphlpapi, "SetUnicastIpAddressEntry") : NULL;
        pDeleteUnicast = Iphlpapi ? (PUNICAST_CALL)GetProcAddress(Iphlpapi, "DeleteUnicastIpAddressEntry") : NULL;
        pGetUnicast = Iphlpapi ? (PUNICAST_CALL)GetProcAddress(Iphlpapi, "GetUnicastIpAddressEntry") : NULL;
    }

    HandleCount = 0;
    Handles[HandleCount++] = StopEvent;
    Handles[HandleCount++] = SockEvent;
    Handles[HandleCount++] = NotifyEvent;
    if (ForceEvent)
    {
        ForceIndex = HandleCount;
        Handles[HandleCount++] = ForceEvent;
    }
    if (CommandEvent)
    {
        CommandIndex = HandleCount;
        Handles[HandleCount++] = CommandEvent;
    }

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
        Wait = MoreQueued ? 0 : (DWORD)(Due - Now);
        Result = WaitForMultipleObjects(HandleCount, Handles, FALSE, Wait);
        if (Result == WAIT_OBJECT_0)
            break;
        if (Result == WAIT_OBJECT_0 + 2)
        {
            /* an interface changed: look again soon (changes come in bursts) */
            Now = NowMs();
            if (NextScan > Now + 300)
                NextScan = Now + 300;
        }
        else if (ForceIndex && Result == WAIT_OBJECT_0 + ForceIndex)
        {
            Scan(NowMs());
            ForceAll(NowMs());
        }
        else if (CommandIndex && Result == WAIT_OBJECT_0 + CommandIndex)
        {
            Scan(NowMs());
            CheckCommands(NowMs());
        }

        WSAResetEvent(SockEvent);
        {
            D6IF *If;

            Now = NowMs();
            MoreQueued = FALSE;
            for (If = Interfaces; If; If = If->Next)
            {
                if (If->Sock != INVALID_SOCKET && ReadSocket(If, Now))
                    MoreQueued = TRUE;
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
    if (CommandEvent)
        CloseHandle(CommandEvent);
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
