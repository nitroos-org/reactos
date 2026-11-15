/*
 * PROJECT:     ReactOS pathping utility
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Trace the route to a host (ICMP echo with a growing TTL), then measure the loss at each hop
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The first phase finds the routers on the path with echo requests of TTL 1, 2, 3... The second phase sends
 * -q echo requests (spaced -p milliseconds apart) at every hop, with the TTL of the hop, and reports the loss
 * and the round trip time up to each router, and the loss attributed to the router (node) and to the link
 * before it. An answer that came from a router on the path implies that every router before it forwarded the
 * request, so the loss "up to a hop" is first reduced to the smallest loss seen at that hop or any later one:
 * what stays above it at a hop is the router answering some of its own requests only (the node), the rise
 * from the hop before is the link.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <windef.h>
#include <winbase.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <wine/netioapi.h>

#include <strsafe.h>

#include <conutils.h>

#define PACKET_SIZE             32
#define SIZEOF_ICMP_ERROR       8
#define SIZEOF_IO_STATUS_BLOCK  8
#define MAX_HOPS_LIMIT          255

#ifdef _WIN64
typedef ICMP_ECHO_REPLY32 ECHO_REPLY4;
#else
typedef ICMP_ECHO_REPLY ECHO_REPLY4;
#endif

typedef struct _OPTIONS
{
    BOOL NoResolve;
    ULONG MaxHops;
    ULONG Timeout;
    ULONG Period;
    ULONG Queries;
    int Family;
    PCWSTR Target;
} OPTIONS;

typedef struct _HOP
{
    BOOL Known;
    SOCKADDR_INET Address;
    ULONG Replies;
    ULONG64 RttTotal;
    ULONG Lost;         /* lost up to this hop, as measured */
    ULONG Effective;    /* ... reduced to what the hop and the ones after it show */
} HOP;

static OPTIONS Options = { FALSE, 30, 3000, 250, 100, AF_UNSPEC, NULL };

static
VOID
PrintUsage(VOID)
{
    ConPuts(StdOut,
            L"\nUsage: pathping [-g host-list] [-h maximum_hops] [-i address] [-n]\n"
            L"                [-p period] [-q num_queries] [-w timeout]\n"
            L"                [-4] [-6] target_name\n\n"
            L"Options:\n"
            L"    -g host-list     Loose source route along host-list.\n"
            L"    -h maximum_hops  Maximum number of hops to search for target.\n"
            L"    -i address       Use the specified source address.\n"
            L"    -n               Do not resolve addresses to hostnames.\n"
            L"    -p period        Wait period milliseconds between pings.\n"
            L"    -q num_queries   Number of queries per hop.\n"
            L"    -w timeout       Timeout in milliseconds for each reply.\n"
            L"    -4               Force using IPv4.\n"
            L"    -6               Force using IPv6.\n");
}

static
BOOL
ParseNumber(
    _In_ PCWSTR Text,
    _In_ ULONG Minimum,
    _In_ ULONG Maximum,
    _Out_ PULONG Value)
{
    PWSTR End;
    ULONG Number;

    if (*Text == UNICODE_NULL || *Text == L'-')
        return FALSE;
    Number = wcstoul(Text, &End, 10);
    if (*End != UNICODE_NULL || Number < Minimum || Number > Maximum)
        return FALSE;
    *Value = Number;
    return TRUE;
}

/* 0: run, 1: usage shown (error), 2: message shown (error) */
static
int
ParseCommandLine(
    _In_ int argc,
    _In_ WCHAR **argv)
{
    int i;

    for (i = 1; i < argc; i++)
    {
        PCWSTR Arg = argv[i];
        WCHAR Option;
        PCWSTR Value;
        ULONG Number;

        if (Arg[0] != L'-' && Arg[0] != L'/')
        {
            if (Options.Target != NULL)
            {
                PrintUsage();
                return 1;
            }
            Options.Target = Arg;
            continue;
        }

        if (Arg[1] == UNICODE_NULL || Arg[2] != UNICODE_NULL)
        {
            ConPrintf(StdOut, L"Bad option %s.\n", Arg);
            PrintUsage();
            return 2;
        }

        Option = (WCHAR)towlower(Arg[1]);
        switch (Option)
        {
            case L'n':
                Options.NoResolve = TRUE;
                break;
            case L'4':
                Options.Family = AF_INET;
                break;
            case L'6':
                Options.Family = AF_INET6;
                break;
            case L'h':
            case L'q':
            case L'w':
            case L'p':
            {
                ULONG Minimum = 1, Maximum = MAX_HOPS_LIMIT;

                if (++i >= argc)
                {
                    PrintUsage();
                    return 1;
                }
                Value = argv[i];
                if (Option == L'q') { Maximum = 10000; }
                if (Option == L'w') { Maximum = 0xffffffff; }
                if (Option == L'p') { Minimum = 0; Maximum = 0xffffffff; }
                if (!ParseNumber(Value, Minimum, Maximum, &Number))
                {
                    ConPrintf(StdOut, L"Bad value for option -%c.\n", Option);
                    return 2;
                }
                if (Option == L'h') Options.MaxHops = Number;
                else if (Option == L'q') Options.Queries = Number;
                else if (Option == L'w') Options.Timeout = Number;
                else Options.Period = Number;
                break;
            }
            default:
                /* -g, -i, -R, -S and -T need options of the echo request the stack does not take yet */
                ConPrintf(StdOut, L"Bad option %s.\n", Arg);
                PrintUsage();
                return 2;
        }
    }

    if (Options.Target == NULL)
    {
        PrintUsage();
        return 1;
    }
    return 0;
}

/* Text of an address: 127.0.0.1, ::1, fe80::1%6 */
static
VOID
FormatSocketAddress(
    _In_ const SOCKADDR_INET *Address,
    _Out_writes_(64) PWSTR Text)
{
    DWORD Length = 64;
    SOCKADDR_INET Copy = *Address;

    Text[0] = UNICODE_NULL;
    Copy.Ipv4.sin_port = 0;
    if (Address->si_family == AF_INET6)
    {
        Copy.Ipv6.sin6_port = 0;
        Copy.Ipv6.sin6_flowinfo = 0;
    }
    WSAAddressToStringW((LPSOCKADDR)&Copy,
                        (Address->si_family == AF_INET6) ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN),
                        NULL, Text, &Length);
}

/* "name [address]" when the address has a name and names are wanted, else "address" */
static
VOID
FormatHost(
    _In_ const SOCKADDR_INET *Address,
    _Out_writes_(NI_MAXHOST + 80) PWSTR Text)
{
    WCHAR Name[NI_MAXHOST], Numeric[64];
    SOCKADDR_INET Copy = *Address;

    FormatSocketAddress(Address, Numeric);
    if (!Options.NoResolve)
    {
        if (Address->si_family == AF_INET6)
            Copy.Ipv6.sin6_port = 0;
        else
            Copy.Ipv4.sin_port = 0;
        if (GetNameInfoW((LPSOCKADDR)&Copy,
                         (Address->si_family == AF_INET6) ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN),
                         Name, ARRAYSIZE(Name), NULL, 0, NI_NAMEREQD) == 0)
        {
            StringCchPrintfW(Text, NI_MAXHOST + 80, L"%s [%s]", Name, Numeric);
            return;
        }
    }
    wcscpy(Text, Numeric);
}

static
BOOL
SameAddress(
    _In_ const SOCKADDR_INET *a,
    _In_ const SOCKADDR_INET *b)
{
    if (a->si_family != b->si_family)
        return FALSE;
    if (a->si_family == AF_INET6)
        return memcmp(&a->Ipv6.sin6_addr, &b->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    return a->Ipv4.sin_addr.s_addr == b->Ipv4.sin_addr.s_addr;
}

typedef struct _PROBER
{
    HANDLE Icmp;
    int Family;
    SOCKADDR_INET Target;
    PVOID Reply;
    DWORD ReplySize;
} PROBER;

typedef struct _ANSWER
{
    ULONG Status;           /* IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, IP_REQ_TIMED_OUT, ... */
    ULONG Rtt;
    SOCKADDR_INET From;
} ANSWER;

/* The send calls return 0 for a request that was answered by an ICMP error (TTL exceeded, destination
   unreachable) as well as for one that was not answered: the error is that IP_STATUS and the reply buffer holds
   the sender then. Any other error (and the time out) means no answer. */
static
BOOL
ErrorHasReply(
    _In_ DWORD Error,
    _Inout_ ANSWER *Answer)
{
    switch (Error)
    {
        case IP_DEST_NET_UNREACHABLE:
        case IP_DEST_HOST_UNREACHABLE:
        case IP_DEST_PROT_UNREACHABLE:
        case IP_DEST_PORT_UNREACHABLE:
        case IP_PACKET_TOO_BIG:
        case IP_TTL_EXPIRED_TRANSIT:
        case IP_TTL_EXPIRED_REASSEM:
        case IP_PARAM_PROBLEM:
            return TRUE;
    }
    Answer->Status = Error;
    return FALSE;
}

/* One echo request with the given TTL. Answered: the status of the reply (even an error one) and its sender. */
static
BOOL
Probe(
    _Inout_ PROBER *Prober,
    _In_ ULONG Ttl,
    _Out_ ANSWER *Answer)
{
    BYTE Data[PACKET_SIZE];
    IP_OPTION_INFORMATION Info;
    DWORD Count;
    ULONG i;

    for (i = 0; i < sizeof(Data); i++)
        Data[i] = (BYTE)('a' + i % 23);
    ZeroMemory(&Info, sizeof(Info));
    Info.Ttl = (UCHAR)Ttl;
    ZeroMemory(Answer, sizeof(*Answer));
    ZeroMemory(Prober->Reply, Prober->ReplySize);
    Answer->Status = IP_REQ_TIMED_OUT;

    if (Prober->Family == AF_INET6)
    {
        struct sockaddr_in6 Source, Destination;
        PICMPV6_ECHO_REPLY Reply = Prober->Reply;

        ZeroMemory(&Source, sizeof(Source));
        Source.sin6_family = AF_INET6;
        memcpy(&Destination, &Prober->Target.Ipv6, sizeof(Destination));
        Count = Icmp6SendEcho2(Prober->Icmp, NULL, NULL, NULL, &Source, &Destination, Data, (WORD)sizeof(Data),
                               &Info, Prober->Reply, Prober->ReplySize, Options.Timeout);
        if (Count == 0 && !ErrorHasReply(GetLastError(), Answer))
            return TRUE;
        Answer->Status = Reply->Status;
        Answer->Rtt = Reply->RoundTripTime;
        Answer->From.si_family = AF_INET6;
        memcpy(&Answer->From.Ipv6.sin6_addr, Reply->Address.sin6_addr, sizeof(IN6_ADDR));
        /* the scope only means something for a link-local sender */
        if (IN6_IS_ADDR_LINKLOCAL(&Answer->From.Ipv6.sin6_addr))
            Answer->From.Ipv6.sin6_scope_id = Reply->Address.sin6_scope_id;
    }
    else
    {
        ECHO_REPLY4 *Reply = Prober->Reply;

        Count = IcmpSendEcho2(Prober->Icmp, NULL, NULL, NULL, Prober->Target.Ipv4.sin_addr.s_addr, Data,
                              (WORD)sizeof(Data), &Info, Prober->Reply, Prober->ReplySize, Options.Timeout);
        if (Count == 0 && !ErrorHasReply(GetLastError(), Answer))
            return TRUE;
        Answer->Status = Reply->Status;
        Answer->Rtt = Reply->RoundTripTime;
        Answer->From.si_family = AF_INET;
        Answer->From.Ipv4.sin_addr.s_addr = Reply->Address;
    }
    return TRUE;
}

static
BOOL
Resolve(
    _Out_ SOCKADDR_INET *Target,
    _Out_ BOOL *IsLiteral)
{
    ADDRINFOW Hints, *Result = NULL;
    SOCKADDR_INET Parsed;
    INT Length = sizeof(Parsed);

    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = Options.Family;

    ZeroMemory(Target, sizeof(*Target));
    ZeroMemory(&Parsed, sizeof(Parsed));
    *IsLiteral = FALSE;

    /* a literal address of the other family than forced is an error, not a name lookup */
    if (WSAStringToAddressW((LPWSTR)Options.Target, AF_INET, NULL, (LPSOCKADDR)&Parsed, &Length) == 0 ||
        (Length = sizeof(Parsed), WSAStringToAddressW((LPWSTR)Options.Target, AF_INET6, NULL, (LPSOCKADDR)&Parsed, &Length) == 0))
    {
        if (Options.Family != AF_UNSPEC && Parsed.si_family != Options.Family)
            return FALSE;
        *Target = Parsed;
        *IsLiteral = TRUE;
        return TRUE;
    }

    if (GetAddrInfoW(Options.Target, NULL, &Hints, &Result) != 0 || Result == NULL)
        return FALSE;
    if (Result->ai_family != AF_INET && Result->ai_family != AF_INET6)
    {
        FreeAddrInfoW(Result);
        return FALSE;
    }
    memcpy(Target, Result->ai_addr, Result->ai_addrlen);
    FreeAddrInfoW(Result);
    return TRUE;
}

static
BOOL
IsUnspecifiedAddress(
    _In_ const SOCKADDR_INET *Address)
{
    static const IN6_ADDR Zero = {{{0}}};

    if (Address->si_family == AF_INET6)
        return memcmp(&Address->Ipv6.sin6_addr, &Zero, sizeof(Zero)) == 0;
    return Address->si_family != AF_INET || Address->Ipv4.sin_addr.s_addr == 0;
}

/* The address the stack would send from to reach the target (GetBestRoute2 gives it with the route) */
static
BOOL
GetInterfaceAddress(
    _In_ const SOCKADDR_INET *Target,
    _Out_ SOCKADDR_INET *Source)
{
    MIB_IPFORWARD_ROW2 Row;

    ZeroMemory(Source, sizeof(*Source));
    if (GetBestRoute2(NULL, 0, NULL, Target, 0, &Row, Source) != NO_ERROR)
        return FALSE;
    return !IsUnspecifiedAddress(Source);
}

/* The local address a packet to the target leaves from: hop 0 */
static
BOOL
GetSourceAddress(
    _In_ const SOCKADDR_INET *Target,
    _Out_ SOCKADDR_INET *Source)
{
    SOCKET s;
    SOCKADDR_INET To = *Target;
    int Length = sizeof(*Source);
    BOOL Ok = FALSE;

    ZeroMemory(Source, sizeof(*Source));
    s = socket(Target->si_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return FALSE;
    if (Target->si_family == AF_INET6)
        To.Ipv6.sin6_port = htons(9);
    else
        To.Ipv4.sin_port = htons(9);
    if (connect(s, (LPSOCKADDR)&To, (Target->si_family == AF_INET6) ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN)) == 0 &&
        getsockname(s, (LPSOCKADDR)Source, &Length) == 0)
        Ok = TRUE;
    closesocket(s);

    if (Ok && !IsUnspecifiedAddress(Source))
        return TRUE;

    /* the stack leaves a connected datagram socket without a source for some targets (an IPv6 loopback
       target): the address then is the target itself for loopback, else an address of the interface that
       leads to the target */
    if (Target->si_family == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&Target->Ipv6.sin6_addr))
    {
        *Source = *Target;
        return TRUE;
    }
    return GetInterfaceAddress(Target, Source);
}

static
VOID
PrintStatistic(
    _In_ ULONG Lost,
    _In_ ULONG Sent)
{
    ConPrintf(StdOut, L"%6lu/%4lu =%3lu%%", Lost, Sent, Sent ? (Lost * 100 / Sent) : 0);
}

static
int
RunPathPing(VOID)
{
    PROBER Prober;
    SOCKADDR_INET Target, Source;
    HOP *Hops = NULL;
    BOOL Literal, Reached = FALSE, HaveSource;
    WCHAR Text[NI_MAXHOST + 80], Numeric[64];
    ULONG Hop, Count = 0, Round, Seconds;
    ULONG64 Index = 0;
    DWORD Start;
    ULONG ReplySize;
    int Result = 1;

    ZeroMemory(&Prober, sizeof(Prober));

    if (!Resolve(&Target, &Literal))
    {
        ConPrintf(StdOut, L"Unable to resolve target system name %s.\n", Options.Target);
        return 1;
    }

    Prober.Family = Target.si_family;
    Prober.Target = Target;
    ReplySize = PACKET_SIZE + SIZEOF_ICMP_ERROR + SIZEOF_IO_STATUS_BLOCK +
                ((Target.si_family == AF_INET6) ? sizeof(ICMPV6_ECHO_REPLY) : sizeof(ECHO_REPLY4));
    Prober.ReplySize = ReplySize;
    Prober.Reply = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReplySize);
    Hops = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Options.MaxHops + 1) * sizeof(HOP));
    if (Prober.Reply == NULL || Hops == NULL)
        goto Done;

    Prober.Icmp = (Target.si_family == AF_INET6) ? Icmp6CreateFile() : IcmpCreateFile();
    if (Prober.Icmp == INVALID_HANDLE_VALUE)
    {
        ConPrintf(StdOut, L"Unable to contact IP driver. Error code %lu.\n", GetLastError());
        goto Done;
    }

    FormatSocketAddress(&Target, Numeric);
    if (Literal)
        ConPrintf(StdOut, L"\nTracing route to %s over a maximum of %lu hops\n\n", Numeric, Options.MaxHops);
    else
        ConPrintf(StdOut, L"\nTracing route to %s [%s]\nover a maximum of %lu hops:\n\n",
                  Options.Target, Numeric, Options.MaxHops);

    HaveSource = GetSourceAddress(&Target, &Source);
    if (HaveSource)
    {
        FormatHost(&Source, Text);
        ConPrintf(StdOut, L"  0  %s \n", Text);
    }

    /* phase 1: the routers on the path */
    for (Hop = 1; Hop <= Options.MaxHops && !Reached; Hop++)
    {
        ANSWER Answer;

        Count = Hop;
        if (!Probe(&Prober, Hop, &Answer))
            break;

        if (Answer.Status == IP_REQ_TIMED_OUT)
        {
            ConPrintf(StdOut, L"%3lu     *\n", Hop);
            continue;
        }

        Hops[Hop].Known = TRUE;
        Hops[Hop].Address = Answer.From;
        FormatHost(&Answer.From, Text);
        ConPrintf(StdOut, L"%3lu  %s \n", Hop, Text);

        if (Answer.Status == IP_SUCCESS || SameAddress(&Answer.From, &Target))
            Reached = TRUE;
        else if (Answer.Status != IP_TTL_EXPIRED_TRANSIT)
        {
            /* the path ends at a router that cannot go on (destination unreachable and the like) */
            Reached = TRUE;
        }
    }

    /* phase 2: loss and round trip time up to each hop */
    Seconds = (ULONG)((ULONG64)Count * Options.Queries * Options.Period / 1000);
    ConPrintf(StdOut, L"\nComputing statistics for %lu seconds...\n", Seconds);
    ConPuts(StdOut, L"            Source to Here   This Node/Link\n");
    ConPuts(StdOut, L"Hop  RTT    Lost/Sent = Pct  Lost/Sent = Pct  Address\n");

    Start = GetTickCount();
    for (Round = 0; Round < Options.Queries; Round++)
    {
        for (Hop = 1; Hop <= Count; Hop++, Index++)
        {
            ANSWER Answer;
            ULONG64 Due = Index * Options.Period, Now = (DWORD)(GetTickCount() - Start);

            if (Due > Now)
                Sleep((DWORD)(Due - Now));
            if (!Probe(&Prober, Hop, &Answer))
                continue;
            if (Answer.Status == IP_SUCCESS || Answer.Status == IP_TTL_EXPIRED_TRANSIT)
            {
                Hops[Hop].Replies++;
                Hops[Hop].RttTotal += Answer.Rtt;
                if (!Hops[Hop].Known)
                {
                    Hops[Hop].Known = TRUE;
                    Hops[Hop].Address = Answer.From;
                }
            }
        }
    }

    for (Hop = 1; Hop <= Count; Hop++)
        Hops[Hop].Lost = Options.Queries - Hops[Hop].Replies;
    /* what a later hop shows implies what the earlier ones forwarded */
    for (Hop = Count; Hop >= 1; Hop--)
    {
        Hops[Hop].Effective = Hops[Hop].Lost;
        if (Hop < Count && Hops[Hop + 1].Effective < Hops[Hop].Effective)
            Hops[Hop].Effective = Hops[Hop + 1].Effective;
    }

    if (HaveSource)
    {
        FormatHost(&Source, Text);
        ConPrintf(StdOut, L"  0                                           %s \n", Text);
    }
    else
    {
        ConPuts(StdOut, L"  0\n");
    }

    for (Hop = 1; Hop <= Count; Hop++)
    {
        ULONG Link = Hops[Hop].Effective - (Hop > 1 ? Hops[Hop - 1].Effective : 0);
        ULONG Node = Hops[Hop].Lost - Hops[Hop].Effective;

        ConPuts(StdOut, L"                           ");
        PrintStatistic(Link, Options.Queries);
        ConPuts(StdOut, L"   |\n");

        ConPrintf(StdOut, L"%3lu", Hop);
        if (Hops[Hop].Replies != 0)
        {
            WCHAR Rtt[16];

            StringCchPrintfW(Rtt, ARRAYSIZE(Rtt), L"%lums", (ULONG)(Hops[Hop].RttTotal / Hops[Hop].Replies));
            ConPrintf(StdOut, L"%7s", Rtt);
        }
        else
        {
            ConPrintf(StdOut, L"%7s", L"---");
        }
        PrintStatistic(Hops[Hop].Lost, Options.Queries);
        PrintStatistic(Node, Options.Queries);
        if (Hops[Hop].Known)
        {
            FormatHost(&Hops[Hop].Address, Text);
            ConPrintf(StdOut, L"  %s \n", Text);
        }
        else
        {
            ConPuts(StdOut, L"  \n");
        }
    }

    ConPuts(StdOut, L"\nTrace complete.\n");
    Result = 0;

Done:
    if (Prober.Icmp != NULL && Prober.Icmp != INVALID_HANDLE_VALUE)
        IcmpCloseHandle(Prober.Icmp);
    if (Prober.Reply)
        HeapFree(GetProcessHeap(), 0, Prober.Reply);
    if (Hops)
        HeapFree(GetProcessHeap(), 0, Hops);
    return Result;
}

int
wmain(
    _In_ int argc,
    _In_ WCHAR **argv)
{
    WSADATA Wsa;
    int Result;

    ConInitStdStreams();

    Result = ParseCommandLine(argc, argv);
    if (Result != 0)
        return 1;

    if (WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
    {
        ConPuts(StdOut, L"Unable to initialize Windows Sockets.\n");
        return 1;
    }

    Result = RunPathPing();
    WSACleanup();
    return Result;
}
