/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     getaddrinfo with AI_CANONNAME: the canonical name of a name that is an alias is the target of the
 *              CNAME records (the last one of a chain), as on Windows 10 and Server 2022; the name itself when it
 *              is no alias; nothing without the flag
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Needs the DNS server of the harness that the machine uses as its name server (dnscache_srv.py: "chain<T>-X" is a
 * CNAME to "l2-chain<T>-X", which is a CNAME to "l3-chain<T>-X", which has the address; "ttl<T>-X" has the address
 * itself, all under cache.test). Without it the test is skipped (the first lookup is the probe).
 */

#include "ws2_32.h"
#include <winnls.h>

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
void
CheckCanon(const char *Name, int Family, int Flags, const char *Expected, const char *What)
{
    struct addrinfo *Result;
    INT Error = Lookup(Name, Family, Flags, &Result);

    ok(Error == 0, "%s: getaddrinfo(%s) failed: %d\n", What, Name, Error);
    if (Error != 0)
        return;
    if (Expected)
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

START_TEST(getaddrinfocanon)
{
    WSADATA Data;
    char Probe[128], Plain[128], Chain[128], Target[128], Chain2[128];
    struct addrinfo *Result;
    ADDRINFOW HintsW, *ResultW;
    WCHAR NameW[128];
    INT Error;
    int Family;
    static const int Families[] = { AF_INET, AF_UNSPEC };

    WSAStartup(MAKEWORD(2, 2), &Data);
    _snprintf(Uniq, sizeof(Uniq), "gc%lx", (unsigned long)GetTickCount());

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
