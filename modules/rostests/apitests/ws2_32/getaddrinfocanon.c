/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     getaddrinfo with AI_CANONNAME: the canonical name of a name that is an alias is the target of the
 *              CNAME records (the last one of a chain), as on Windows 10 and Server 2022; the name itself when it
 *              is no alias; nothing without the flag. The name comes with the answer: a name answered on this
 *              machine (this machine's name, a row of the hosts file) needs no DNS server for it.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The names of this machine are checked first, with the time of every call: they are answered at once whether or
 * not a DNS server can be reached (a lookup that asks an unreachable server waits for its timeouts, 30 s). With
 * NITRO_HOSTS_TEST=1 a row with a dotted name is added to the hosts file for the time of the test (the file is put
 * back as it was).
 *
 * The aliases need the DNS server of the harness that the machine uses as its name server (dnscache_srv.py:
 * "chain<T>-X" is a CNAME to "l2-chain<T>-X", which is a CNAME to "l3-chain<T>-X", which has the address; "ttl<T>-X"
 * has the address itself, all under cache.test). Without it that part is skipped (the first lookup is the probe).
 */

#include "ws2_32.h"
#include <winnls.h>
#include <iphlpapi.h>

#define LOCAL_MAX_MS    100

static char Uniq[32];

static
INT
Lookup(const char *Name, int Family, int Flags, struct addrinfo **Result)
{
    struct addrinfo Hints;

    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = Family;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = Flags;
    *Result = NULL;
    return getaddrinfo(Name, NULL, &Hints, Result);
}

static
double
NowMs(void)
{
    LARGE_INTEGER Counter, Frequency;

    QueryPerformanceCounter(&Counter);
    QueryPerformanceFrequency(&Frequency);
    return (double)Counter.QuadPart * 1000.0 / (double)Frequency.QuadPart;
}

/* Expected NULL: no canonical name expected; "*": any canonical name. MaxMs: 0 = not timed */
static
void
CheckCanonTimed(const char *Name, int Family, int Flags, const char *Expected, const char *What, double MaxMs)
{
    struct addrinfo *Result;
    double Start = NowMs(), Elapsed;
    INT Error = Lookup(Name, Family, Flags, &Result);

    Elapsed = NowMs() - Start;
    trace("%s: getaddrinfo(%s, family %d, flags 0x%x) = %d in %.1f ms, canonical name \"%s\"\n", What, Name, Family,
          Flags, Error, Elapsed, (Error == 0 && Result->ai_canonname) ? Result->ai_canonname : "(null)");
    if (MaxMs > 0)
        ok(Elapsed < MaxMs, "%s: getaddrinfo(%s) took %.1f ms, expected less than %.0f ms\n", What, Name, Elapsed, MaxMs);
    ok(Error == 0, "%s: getaddrinfo(%s) failed: %d\n", What, Name, Error);
    if (Error != 0)
        return;
    if (Expected && strcmp(Expected, "*") == 0)
    {
        ok(Result->ai_canonname != NULL && Result->ai_canonname[0] != '\0',
           "%s: no canonical name for %s\n", What, Name);
    }
    else if (Expected)
    {
        ok(Result->ai_canonname != NULL && _stricmp(Result->ai_canonname, Expected) == 0,
           "%s: canonical name of %s is \"%s\", expected \"%s\"\n",
           What, Name, Result->ai_canonname ? Result->ai_canonname : "(null)", Expected);
    }
    else
    {
        ok(Result->ai_canonname == NULL, "%s: canonical name without the flag: \"%s\"\n", What, Result->ai_canonname);
    }
    freeaddrinfo(Result);
}

static
void
CheckCanon(const char *Name, int Family, int Flags, const char *Expected, const char *What)
{
    CheckCanonTimed(Name, Family, Flags, Expected, What, 0);
}

/* The hosts file: its path and its content before the test */
static char HostsPath[MAX_PATH];
static char *HostsSaved;
static DWORD HostsSavedSize;

static
BOOL
WriteFileAll(const char *Path, const char *Data, DWORD Size)
{
    HANDLE File = CreateFileA(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Written = 0;
    BOOL Ret;

    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = (Size == 0) || (WriteFile(File, Data, Size, &Written, NULL) && Written == Size);
    CloseHandle(File);
    return Ret;
}

/* Adds Row to the hosts file (the original is kept for RestoreHosts) */
static
BOOL
AddHostsRow(const char *Row)
{
    char Dir[MAX_PATH];
    HANDLE File;
    DWORD Size, Read = 0, RowLength = (DWORD)strlen(Row);
    char *Data;
    BOOL Ret;

    if (!GetSystemDirectoryA(Dir, sizeof(Dir)))
        return FALSE;
    _snprintf(HostsPath, sizeof(HostsPath), "%s\\drivers\\etc\\hosts", Dir);

    File = CreateFileA(HostsPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        HostsSaved = NULL;
        HostsSavedSize = 0;
    }
    else
    {
        Size = GetFileSize(File, NULL);
        HostsSaved = HeapAlloc(GetProcessHeap(), 0, Size + 1);
        if (!HostsSaved || !ReadFile(File, HostsSaved, Size, &Read, NULL) || Read != Size)
        {
            CloseHandle(File);
            return FALSE;
        }
        CloseHandle(File);
        HostsSavedSize = Size;
    }

    Data = HeapAlloc(GetProcessHeap(), 0, HostsSavedSize + RowLength + 4);
    if (!Data)
        return FALSE;
    if (HostsSavedSize)
        memcpy(Data, HostsSaved, HostsSavedSize);
    Size = HostsSavedSize;
    Data[Size++] = '\r';
    Data[Size++] = '\n';
    memcpy(Data + Size, Row, RowLength);
    Size += RowLength;
    Data[Size++] = '\r';
    Data[Size++] = '\n';
    Ret = WriteFileAll(HostsPath, Data, Size);
    HeapFree(GetProcessHeap(), 0, Data);
    return Ret;
}

static
void
RestoreHosts(void)
{
    if (HostsSaved)
    {
        ok(WriteFileAll(HostsPath, HostsSaved, HostsSavedSize), "the hosts file could not be put back\n");
        HeapFree(GetProcessHeap(), 0, HostsSaved);
        HostsSaved = NULL;
    }
    else if (HostsPath[0])
    {
        DeleteFileA(HostsPath);
    }
}

/*
 * The names this machine answers itself: each one in less than LOCAL_MAX_MS, with or without a DNS server that
 * answers (the canonical name is the name, it needs no query of a server)
 */
static
void
TestLocalNames(void)
{
    char HostName[256], Fqdn[300];
    static const char HostsName[] = "gaicanon-hosts.dotted.test";
    PFIXED_INFO Info;
    ULONG Size = 0;
    int Family, Round;
    static const int Families[] = { AF_INET, AF_UNSPEC };
    const char *Env = getenv("NITRO_HOSTS_TEST");
    BOOL HostsRow = FALSE;

    HostName[0] = Fqdn[0] = '\0';
    GetNetworkParams(NULL, &Size);
    Info = HeapAlloc(GetProcessHeap(), 0, Size ? Size : sizeof(*Info));
    if (Info && GetNetworkParams(Info, &Size) == ERROR_SUCCESS)
    {
        lstrcpynA(HostName, Info->HostName, sizeof(HostName));
        if (Info->DomainName[0])
            _snprintf(Fqdn, sizeof(Fqdn), "%s.%s", Info->HostName, Info->DomainName);
    }
    if (Info)
        HeapFree(GetProcessHeap(), 0, Info);
    trace("host name \"%s\", primary DNS suffix name \"%s\"\n", HostName, Fqdn);

    if (Env && strcmp(Env, "1") == 0)
    {
        HostsRow = AddHostsRow("192.0.2.77 gaicanon-hosts.dotted.test");
        ok(HostsRow, "the row could not be added to the hosts file\n");
    }
    else
    {
        skip("NITRO_HOSTS_TEST is not 1: no row is added to the hosts file\n");
    }

    /* twice: the first call of a name and a later one */
    for (Round = 0; Round < 2; Round++)
    {
        for (Family = 0; Family < 2; Family++)
        {
            if (HostName[0])
            {
                CheckCanonTimed(HostName, Families[Family], AI_CANONNAME, "*", "this machine", LOCAL_MAX_MS);
                CheckCanonTimed(HostName, Families[Family], 0, NULL, "this machine, no flag", LOCAL_MAX_MS);
            }
            if (Fqdn[0])
            {
                CheckCanonTimed(Fqdn, Families[Family], AI_CANONNAME, Fqdn, "this machine with its DNS suffix",
                                LOCAL_MAX_MS);
            }
            if (HostsRow)
            {
                CheckCanonTimed(HostsName, Families[Family], AI_CANONNAME, HostsName, "dotted name of the hosts file",
                                LOCAL_MAX_MS);
                CheckCanonTimed(HostsName, Families[Family], 0, NULL, "dotted name of the hosts file, no flag",
                                LOCAL_MAX_MS);
            }
            CheckCanonTimed("localhost", Families[Family], AI_CANONNAME, "*", "localhost", LOCAL_MAX_MS);
        }
    }
    if (!Fqdn[0])
        skip("no primary DNS suffix: the name of this machine with it is not checked\n");

    if (HostsRow)
    {
        struct hostent *Host = gethostbyname(HostsName);

        ok(Host != NULL && Host->h_name && _stricmp(Host->h_name, HostsName) == 0,
           "gethostbyname of the hosts row: h_name \"%s\"\n", Host && Host->h_name ? Host->h_name : "(null)");
    }

    if (HostsRow || HostsSaved)
        RestoreHosts();
}

/* gethostbyname of an alias: h_name is the end of the chain, the aliases of the chain are in h_aliases */
static
void
CheckHostent(const char *Name, const char *Target, const char *Middle)
{
    struct hostent *Host = gethostbyname(Name);
    BOOL HasName = FALSE, HasMiddle = FALSE;
    char **Alias;

    ok(Host != NULL, "gethostbyname(%s) failed: %d\n", Name, WSAGetLastError());
    if (!Host)
        return;
    ok(Host->h_name && _stricmp(Host->h_name, Target) == 0, "gethostbyname(%s): h_name \"%s\", expected \"%s\"\n",
       Name, Host->h_name ? Host->h_name : "(null)", Target);
    for (Alias = Host->h_aliases; Alias && *Alias; Alias++)
    {
        trace("gethostbyname(%s): alias \"%s\"\n", Name, *Alias);
        if (_stricmp(*Alias, Name) == 0)
            HasName = TRUE;
        if (_stricmp(*Alias, Middle) == 0)
            HasMiddle = TRUE;
        ok(_stricmp(*Alias, Target) != 0, "gethostbyname(%s): the canonical name is listed as an alias\n", Name);
    }
    ok(HasName && HasMiddle, "gethostbyname(%s): the aliases \"%s\" and \"%s\" are not both in h_aliases (%d %d)\n",
       Name, Name, Middle, HasName, HasMiddle);
}

START_TEST(getaddrinfocanon)
{
    WSADATA Data;
    char Probe[128], Plain[128], Chain[128], Target[128], Chain2[128], Middle[128];
    struct addrinfo *Result;
    ADDRINFOW HintsW, *ResultW;
    WCHAR NameW[128];
    INT Error;
    int Family;
    static const int Families[] = { AF_INET, AF_UNSPEC };

    WSAStartup(MAKEWORD(2, 2), &Data);
    _snprintf(Uniq, sizeof(Uniq), "gc%lx", (unsigned long)GetTickCount());

    TestLocalNames();

    _snprintf(Probe, sizeof(Probe), "ttl30-probe-%s.cache.test", Uniq);
    Error = Lookup(Probe, AF_INET, 0, &Result);
    if (Error != 0)
    {
        skip("no test DNS server (probe: %d)\n", Error);
        WSACleanup();
        return;
    }
    freeaddrinfo(Result);

    for (Family = 0; Family < 2; Family++)
    {
        /* a new name for every family: no answer of the resolver cache of the other family is involved */
        _snprintf(Plain, sizeof(Plain), "ttl300-plain%d-%s.cache.test", Family, Uniq);
        _snprintf(Chain, sizeof(Chain), "chain300-alias%d-%s.cache.test", Family, Uniq);
        _snprintf(Chain2, sizeof(Chain2), "chain300-again%d-%s.cache.test", Family, Uniq);
        _snprintf(Target, sizeof(Target), "l3-chain300-alias%d-%s.cache.test", Family, Uniq);

        /* a name that is no alias is its own canonical name */
        CheckCanon(Plain, Families[Family], AI_CANONNAME, Plain, "no alias");
        CheckCanon(Plain, Families[Family], 0, NULL, "no alias, no flag");

        /* an alias: the target of the last CNAME record, then the same from the cache of the resolver */
        CheckCanon(Chain, Families[Family], AI_CANONNAME, Target, "alias, from the server");
        CheckCanon(Chain, Families[Family], AI_CANONNAME, Target, "alias, from the cache");
        CheckCanon(Chain, Families[Family], 0, NULL, "alias, no flag");

        /* the same for a name that was asked for without the flag first (its answer is cached) */
        CheckCanon(Chain2, Families[Family], 0, NULL, "alias asked without the flag");
        _snprintf(Target, sizeof(Target), "l3-chain300-again%d-%s.cache.test", Family, Uniq);
        CheckCanon(Chain2, Families[Family], AI_CANONNAME, Target, "alias, answer cached by the lookup without the flag");
    }

    /* gethostbyname: the same answer, from the server and from the cache */
    _snprintf(Chain, sizeof(Chain), "chain300-hostent-%s.cache.test", Uniq);
    _snprintf(Middle, sizeof(Middle), "l2-chain300-hostent-%s.cache.test", Uniq);
    _snprintf(Target, sizeof(Target), "l3-chain300-hostent-%s.cache.test", Uniq);
    CheckHostent(Chain, Target, Middle);
    CheckHostent(Chain, Target, Middle);

    /* the wide function */
    _snprintf(Chain, sizeof(Chain), "chain300-wide-%s.cache.test", Uniq);
    _snprintf(Target, sizeof(Target), "l3-chain300-wide-%s.cache.test", Uniq);
    MultiByteToWideChar(CP_ACP, 0, Chain, -1, NameW, ARRAYSIZE(NameW));
    ZeroMemory(&HintsW, sizeof(HintsW));
    HintsW.ai_family = AF_INET;
    HintsW.ai_socktype = SOCK_STREAM;
    HintsW.ai_flags = AI_CANONNAME;
    Error = GetAddrInfoW(NameW, NULL, &HintsW, &ResultW);
    ok(Error == 0, "GetAddrInfoW failed: %d\n", Error);
    if (Error == 0)
    {
        WCHAR TargetW[128];

        MultiByteToWideChar(CP_ACP, 0, Target, -1, TargetW, ARRAYSIZE(TargetW));
        ok(ResultW->ai_canonname != NULL && _wcsicmp(ResultW->ai_canonname, TargetW) == 0,
           "GetAddrInfoW: canonical name \"%S\", expected \"%S\"\n",
           ResultW->ai_canonname ? ResultW->ai_canonname : L"(null)", TargetW);
        FreeAddrInfoW(ResultW);
    }

    WSACleanup();
}
