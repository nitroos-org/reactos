/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Multicast groups and source filters of a datagram socket: MCAST_JOIN_GROUP, MCAST_LEAVE_GROUP,
 *              MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE, MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP,
 *              IP_ADD/DROP_MEMBERSHIP, IP_ADD/DROP_SOURCE_MEMBERSHIP, IP_BLOCK/UNBLOCK_SOURCE, IPV6_ADD/DROP_MEMBERSHIP,
 *              SIOCSMSFILTER/SIOCGMSFILTER and SIO_SET/GET_MULTICAST_FILTER, IPv4 and IPv6
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every answer is compared with what Windows Server 2022 gave for the same request (64 and 32 bit identical;
 * mcastfilter.inc, from the probe of evidence v6mld2-20261116), except the limits listed in Differs. The sources
 * and groups are documentation and administratively scoped addresses: nothing is sent. unbound_rows checks what
 * NitroOS does by design where Windows has no row (groups waiting for the bind).
 */

#include "ws2_32.h"
#include <iphlpapi.h>
#include <mstcpip.h>
#include <stdlib.h>

/* Text and binary addresses through ntdll (the same on every Windows version this test runs on) */
static int
mc_pton(int af, const char *text, void *out)
{
    PCSTR end;

    if (af == AF_INET)
        return NT_SUCCESS(RtlIpv4StringToAddressA(text, TRUE, &end, out));
    return NT_SUCCESS(RtlIpv6StringToAddressA(text, &end, out));
}

static const char *
mc_ntop(int af, const void *address, char *text, size_t size)
{
    (void)size;
    if (af == AF_INET)
        RtlIpv4AddressToStringA(address, text);
    else
        RtlIpv6AddressToStringA(address, text);
    return text;
}
#define inet_pton mc_pton
#define inet_ntop mc_ntop

#ifndef GROUP_FILTER_SIZE
#define GROUP_FILTER_SIZE(n) (sizeof(GROUP_FILTER) - sizeof(SOCKADDR_STORAGE) + (n) * sizeof(SOCKADDR_STORAGE))
#endif

static ULONG If4, If6;          /* interface indexes */
static IN_ADDR IfAddr4;         /* the interface's IPv4 address */

static const char *G4[] = { "239.77.1.1", "239.77.1.2", "239.77.1.3", "239.77.1.4", "239.77.1.5", "239.77.1.6",
                            "239.77.1.7", "239.77.1.8", "239.77.1.9", "239.77.1.10" };
static const char *G6[] = { "ff15::4d32:1", "ff15::4d32:2", "ff15::4d32:3", "ff15::4d32:4", "ff15::4d32:5",
                            "ff15::4d32:6", "ff15::4d32:7", "ff15::4d32:8", "ff15::4d32:9", "ff15::4d32:a" };
static const char *S4[] = { "198.51.100.1", "198.51.100.2", "198.51.100.3" };
static const char *S6[] = { "2001:db8:6d::1", "2001:db8:6d::2", "2001:db8:6d::3" };

static void
mkaddr(int fam, const char *text, SOCKADDR_STORAGE *ss)
{
    memset(ss, 0, sizeof(*ss));
    if (fam == 4)
    {
        SOCKADDR_IN *a = (SOCKADDR_IN *)ss;
        a->sin_family = AF_INET;
        inet_pton(AF_INET, text, &a->sin_addr);
    }
    else
    {
        SOCKADDR_IN6 *a = (SOCKADDR_IN6 *)ss;
        a->sin6_family = AF_INET6;
        inet_pton(AF_INET6, text, &a->sin6_addr);
    }
}

/* the n-th generated source (limits): 198.51.(n/250).(n%250+1) / 2001:db8:6e::n */
static void
gensrc(int fam, int n, SOCKADDR_STORAGE *ss)
{
    char b[64];
    if (fam == 4)
        sprintf(b, "198.%d.%d.%d", 18 + n / 62500, (n / 250) % 250, n % 250 + 1);
    else
        sprintf(b, "2001:db8:6e::%x:%x", n / 65536, n % 65536 + 1);
    mkaddr(fam, b, ss);
}

static void
gengrp(int fam, int n, SOCKADDR_STORAGE *ss)
{
    char b[64];
    if (fam == 4)
        sprintf(b, "239.78.%d.%d", n / 250, n % 250 + 1);
    else
        sprintf(b, "ff15::4e32:%x", n + 1);
    mkaddr(fam, b, ss);
}

static const char *
astr(const SOCKADDR_STORAGE *ss, char *b, size_t n)
{
    if (ss->ss_family == AF_INET)
        inet_ntop(AF_INET, &((SOCKADDR_IN *)ss)->sin_addr, b, n);
    else if (ss->ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((SOCKADDR_IN6 *)ss)->sin6_addr, b, n);
    else
        sprintf(b, "fam%d", ss->ss_family);
    return b;
}

typedef struct _MCAST_EXPECT {
    const char *Name;
    const char *Result;
    const char *Extra;
} MCAST_EXPECT;

#include "mcastfilter.inc"

/* Where NitroOS differs by design (release notes): at most 1024 sources per group (WSAENOBUFS beyond) and 20 groups
   per socket (the stack's limit, WSAEADDRNOTAVAIL beyond); Windows took 1100 sources and 300 groups */
static const MCAST_EXPECT Differs[] = {
    { "4.E01.max-ssm-sources", "E10055", "count=1024" },
    { "4.E05.max-blocked", "E10055", "count=1024" },
    { "4.E07.max-groups", "E10049", "count=20" },
    { "6.E01.max-ssm-sources", "E10055", "count=1024" },
    { "6.E05.max-blocked", "E10055", "count=1024" },
    { "6.E07.max-groups", "E10049", "count=20" },
};

static ULONG Checked;

static void
row(const char *name, int rc, const char *extra)
{
    char result[32];
    const MCAST_EXPECT *e = NULL;
    ULONG i;

    if (rc == 0)
        strcpy(result, "OK");
    else
        sprintf(result, "E%d", WSAGetLastError());
    for (i = 0; i < ARRAYSIZE(Differs) && !e; i++)
        if (!strcmp(Differs[i].Name, name))
            e = &Differs[i];
    for (i = 0; i < ARRAYSIZE(Expected) && !e; i++)
        if (!strcmp(Expected[i].Name, name))
            e = &Expected[i];
    ok(e != NULL, "%s: no expectation\n", name);
    if (!e)
        return;
    Checked++;
    ok(!strcmp(result, e->Result), "%s: %s, expected %s\n", name, result, e->Result);
    ok(!strcmp(extra ? extra : "", e->Extra), "%s: '%s', expected '%s'\n", name, extra ? extra : "", e->Extra);
}

static int lvl(int fam) { return fam == 4 ? IPPROTO_IP : IPPROTO_IPV6; }
static ULONG ifx(int fam) { return fam == 4 ? If4 : If6; }

static int
grp(SOCKET s, int level, int opt, int fam, ULONG ifidx, const SOCKADDR_STORAGE *g)
{
    GROUP_REQ r;
    (void)fam;
    memset(&r, 0, sizeof(r));
    r.gr_interface = ifidx;
    r.gr_group = *g;
    return setsockopt(s, level, opt, (char *)&r, sizeof(r));
}

static int
gsrc(SOCKET s, int level, int opt, ULONG ifidx, const SOCKADDR_STORAGE *g, const SOCKADDR_STORAGE *src)
{
    GROUP_SOURCE_REQ r;
    memset(&r, 0, sizeof(r));
    r.gsr_interface = ifidx;
    r.gsr_group = *g;
    r.gsr_source = *src;
    return setsockopt(s, level, opt, (char *)&r, sizeof(r));
}

/* SIOCGMSFILTER with room for Cap sources: "mode=M n=N [list] bytes=B" */
static void
getf(SOCKET s, const char *name, ULONG ifidx, const SOCKADDR_STORAGE *g, int cap)
{
    char buf[4096], extra[2048], a[64];
    GROUP_FILTER *f = (GROUP_FILTER *)buf;
    DWORD ret = 0, size = GROUP_FILTER_SIZE(cap), i;
    int rc;

    memset(buf, 0xCC, sizeof(buf));
    memset(f, 0, sizeof(GROUP_FILTER));
    f->gf_interface = ifidx;
    f->gf_group = *g;
    f->gf_numsrc = cap;
    rc = WSAIoctl(s, SIOCGMSFILTER, f, size, f, size, &ret, NULL, NULL);
    if (rc == 0)
    {
        int n = sprintf(extra, "mode=%d n=%lu bytes=%lu", f->gf_fmode, f->gf_numsrc, ret);
        for (i = 0; i < f->gf_numsrc && i < (DWORD)cap && i < 16; i++)
            n += sprintf(extra + n, " %s", astr(&f->gf_slist[i], a, sizeof(a)));
        row(name, 0, extra);
    }
    else
    {
        sprintf(extra, "bytes=%lu", ret);
        row(name, rc, extra);
    }
}

static int
setf(SOCKET s, ULONG ifidx, const SOCKADDR_STORAGE *g, int mode, int n, const SOCKADDR_STORAGE *src, DWORD sizeadj)
{
    DWORD ret = 0, size = GROUP_FILTER_SIZE(n) + sizeadj;
    GROUP_FILTER *f = calloc(1, GROUP_FILTER_SIZE(n) + 256);
    int i, rc;

    f->gf_interface = ifidx;
    f->gf_group = *g;
    f->gf_fmode = mode;
    f->gf_numsrc = n;
    for (i = 0; i < n; i++)
        f->gf_slist[i] = src[i];
    rc = WSAIoctl(s, SIOCSMSFILTER, f, size, NULL, 0, &ret, NULL, NULL);
    free(f);
    return rc;
}

/* SIO_GET_MULTICAST_FILTER (IPv4, ip_msfilter) with room for Cap sources */
static void
getf4(SOCKET s, const char *name, const char *group, IN_ADDR iface, int cap)
{
    char buf[2048], extra[1024], a[64];
    IP_MSFILTER *f = (IP_MSFILTER *)buf;
    DWORD ret = 0, size = IP_MSFILTER_SIZE(cap), i;
    int rc;

    memset(buf, 0xCC, sizeof(buf));
    memset(f, 0, sizeof(IP_MSFILTER));
    inet_pton(AF_INET, group, &f->imsf_multiaddr);
    f->imsf_interface = iface;
    f->imsf_numsrc = cap;
    rc = WSAIoctl(s, SIO_GET_MULTICAST_FILTER, f, size, f, size, &ret, NULL, NULL);
    if (rc == 0)
    {
        int n = sprintf(extra, "mode=%d n=%lu bytes=%lu", f->imsf_fmode, f->imsf_numsrc, ret);
        for (i = 0; i < f->imsf_numsrc && i < (DWORD)cap && i < 16; i++)
            n += sprintf(extra + n, " %s", inet_ntop(AF_INET, &f->imsf_slist[i], a, sizeof(a)));
        row(name, 0, extra);
    }
    else
    {
        sprintf(extra, "bytes=%lu", ret);
        row(name, rc, extra);
    }
}

static int
setf4(SOCKET s, const char *group, IN_ADDR iface, int mode, int n, const char **src, DWORD sizeadj)
{
    char buf[2048];
    IP_MSFILTER *f = (IP_MSFILTER *)buf;
    DWORD ret = 0;
    int i;

    memset(buf, 0, sizeof(buf));
    inet_pton(AF_INET, group, &f->imsf_multiaddr);
    f->imsf_interface = iface;
    f->imsf_fmode = mode;
    f->imsf_numsrc = n;
    for (i = 0; i < n; i++)
        inet_pton(AF_INET, src[i], &f->imsf_slist[i]);
    return WSAIoctl(s, SIO_SET_MULTICAST_FILTER, f, IP_MSFILTER_SIZE(n) + sizeadj, NULL, 0, &ret, NULL, NULL);
}

static int
mreqsrc(SOCKET s, int opt, const char *group, const char *src, IN_ADDR iface, int len)
{
    IP_MREQ_SOURCE r;
    memset(&r, 0, sizeof(r));
    inet_pton(AF_INET, group, &r.imr_multiaddr);
    inet_pton(AF_INET, src, &r.imr_sourceaddr);
    r.imr_interface = iface;
    return setsockopt(s, IPPROTO_IP, opt, (char *)&r, len ? len : (int)sizeof(r));
}

static int
mreq4(SOCKET s, int opt, const char *group, IN_ADDR iface)
{
    IP_MREQ r;
    memset(&r, 0, sizeof(r));
    inet_pton(AF_INET, group, &r.imr_multiaddr);
    r.imr_interface = iface;
    return setsockopt(s, IPPROTO_IP, opt, (char *)&r, sizeof(r));
}

static int
mreq6(SOCKET s, int opt, const char *group, ULONG ifidx)
{
    IPV6_MREQ r;
    memset(&r, 0, sizeof(r));
    inet_pton(AF_INET6, group, &r.ipv6mr_multiaddr);
    r.ipv6mr_interface = ifidx;
    return setsockopt(s, IPPROTO_IPV6, opt, (char *)&r, sizeof(r));
}

static SOCKET
usock(int fam, int bindit)
{
    SOCKET s = socket(fam == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
    {
        ok(0, "socket(%d) failed: %d\n", fam, WSAGetLastError());
        return INVALID_SOCKET;
    }
    if (bindit)
    {
        SOCKADDR_STORAGE a;
        memset(&a, 0, sizeof(a));
        a.ss_family = fam == 4 ? AF_INET : AF_INET6;
        ok(bind(s, (SOCKADDR *)&a, fam == 4 ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6)) == 0,
           "bind(%d) failed: %d\n", fam, WSAGetLastError());
    }
    return s;
}

static BOOLEAN
find_interface(void)
{
    ULONG size = 64 * 1024;
    IP_ADAPTER_ADDRESSES *aa = malloc(size), *a;
    char b[64];

    if (!aa || GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &size))
    {
        free(aa);
        return FALSE;
    }
    for (a = aa; a; a = a->Next)
    {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->OperStatus != IfOperStatusUp)
            continue;
        If4 = a->IfIndex;
        If6 = a->Ipv6IfIndex;
        for (u = a->FirstUnicastAddress; u; u = u->Next)
            if (u->Address.lpSockaddr->sa_family == AF_INET)
            {
                IfAddr4 = ((SOCKADDR_IN *)u->Address.lpSockaddr)->sin_addr;
                break;
            }
        break;
    }
    trace("interface if4=%lu if6=%lu addr4=%s\n", If4, If6, inet_ntop(AF_INET, &IfAddr4, b, sizeof(b)));
    free(aa);
    return If4 != 0 && IfAddr4.s_addr != 0;
}

static void
family_rows(int fam)
{
    char name[96], extra[128];
    SOCKADDR_STORAGE g[10], s[3], other, uni, any, mc;
    const char **gt = fam == 4 ? G4 : G6, **st = fam == 4 ? S4 : S6;
    int L = lvl(fam), i, n, rc;
    ULONG I = ifx(fam);
    SOCKET so;
    DWORD v;
    int vl;

#define R(nm, expr) do { sprintf(name, "%d.%s", fam, nm); row(name, (expr), NULL); } while (0)
#define F(nm, grp_, cap) do { sprintf(name, "%d.%s", fam, nm); getf(so, name, I, &g[grp_], cap); } while (0)

    for (i = 0; i < 10; i++)
        mkaddr(fam, gt[i], &g[i]);
    for (i = 0; i < 3; i++)
        mkaddr(fam, st[i], &s[i]);
    mkaddr(fam == 4 ? 6 : 4, fam == 4 ? G6[0] : G4[0], &other);
    mkaddr(fam, fam == 4 ? "192.0.2.1" : "2001:db8::1", &uni);
    mkaddr(fam, fam == 4 ? "0.0.0.0" : "::", &any);
    mkaddr(fam, fam == 4 ? "239.77.9.9" : "ff15::99", &mc);

    /* A: any-source join, blocks, leaves */
    so = usock(fam, 1);
    R("A01.join", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[0]));
    R("A02.join-again", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[0]));
    R("A03.block-s1", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[0], &s[0]));
    R("A04.block-s1-again", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[0], &s[0]));
    F("A05.getf", 0, 8);
    R("A06.block-s2", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[0], &s[1]));
    F("A07.getf", 0, 8);
    R("A08.unblock-s1", gsrc(so, L, MCAST_UNBLOCK_SOURCE, I, &g[0], &s[0]));
    R("A09.unblock-s1-again", gsrc(so, L, MCAST_UNBLOCK_SOURCE, I, &g[0], &s[0]));
    R("A10.unblock-s3-never", gsrc(so, L, MCAST_UNBLOCK_SOURCE, I, &g[0], &s[2]));
    R("A11.joinsrc-on-asm", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[0], &s[0]));
    R("A12.leavesrc-blocked-on-asm", gsrc(so, L, MCAST_LEAVE_SOURCE_GROUP, I, &g[0], &s[1]));
    F("A13.getf", 0, 8);
    R("A14.leave", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[0]));
    R("A15.leave-again", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[0]));
    F("A16.getf-after-leave", 0, 8);
    R("A17.block-not-joined", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[1], &s[0]));
    R("A18.unblock-not-joined", gsrc(so, L, MCAST_UNBLOCK_SOURCE, I, &g[1], &s[0]));
    R("A19.leavesrc-not-joined", gsrc(so, L, MCAST_LEAVE_SOURCE_GROUP, I, &g[1], &s[0]));
    R("A20.join-if0", grp(so, L, MCAST_JOIN_GROUP, fam, 0, &g[2]));
    sprintf(name, "%d.A21.getf-if0", fam); getf(so, name, 0, &g[2], 8);
    F("A22.getf-ifI-of-if0-join", 2, 8);
    R("A23.leave-ifI-of-if0-join", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[2]));
    R("A24.leave-if0", grp(so, L, MCAST_LEAVE_GROUP, fam, 0, &g[2]));
    closesocket(so);

    /* B: source-specific joins */
    so = usock(fam, 1);
    R("B01.joinsrc-s1", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[1], &s[0]));
    R("B02.joinsrc-s1-again", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[1], &s[0]));
    R("B03.joinsrc-s2", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[1], &s[1]));
    F("B04.getf", 1, 8);
    R("B05.block-in-include", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[1], &s[2]));
    R("B06.unblock-in-include", gsrc(so, L, MCAST_UNBLOCK_SOURCE, I, &g[1], &s[0]));
    R("B07.join-asm-on-ssm", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[1]));
    R("B08.leavesrc-s3-absent", gsrc(so, L, MCAST_LEAVE_SOURCE_GROUP, I, &g[1], &s[2]));
    R("B09.leavesrc-s1", gsrc(so, L, MCAST_LEAVE_SOURCE_GROUP, I, &g[1], &s[0]));
    F("B10.getf", 1, 8);
    R("B11.leavesrc-s2-last", gsrc(so, L, MCAST_LEAVE_SOURCE_GROUP, I, &g[1], &s[1]));
    F("B12.getf-after-last", 1, 8);
    R("B13.leave-after-last", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[1]));
    R("B14.joinsrc-g4-s1", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[3], &s[0]));
    R("B15.leave-group-of-ssm", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[3]));
    F("B16.getf-after", 3, 8);
    R("B17.joinsrc-if0", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, 0, &g[4], &s[0]));
    R("B18.leavesrc-if0", gsrc(so, L, MCAST_LEAVE_SOURCE_GROUP, 0, &g[4], &s[0]));
    closesocket(so);

    /* D: errors */
    so = usock(fam, 1);
    R("D01.join-unicast", grp(so, L, MCAST_JOIN_GROUP, fam, I, &uni));
    {
        GROUP_REQ r;
        memset(&r, 0, sizeof(r));
        r.gr_interface = I;
        r.gr_group = g[5];
        R("D02.join-short", setsockopt(so, L, MCAST_JOIN_GROUP, (char *)&r, sizeof(r) - 1));
        R("D03.join-len8", setsockopt(so, L, MCAST_JOIN_GROUP, (char *)&r, 8));
        R("D04.join-null", setsockopt(so, L, MCAST_JOIN_GROUP, NULL, sizeof(r)));
    }
    R("D05.join-other-family", grp(so, L, MCAST_JOIN_GROUP, fam, I, &other));
    R("D06.join-if9999", grp(so, L, MCAST_JOIN_GROUP, fam, 9999, &g[5]));
    R("D07.joinsrc-mcast-source", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[5], &mc));
    R("D08.joinsrc-any-source", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[5], &any));
    R("D09.joinsrc-unicast-group", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &uni, &s[0]));
    {
        SOCKADDR_STORAGE os;
        mkaddr(fam == 4 ? 6 : 4, fam == 4 ? S6[0] : S4[0], &os);
        R("D10.joinsrc-other-family-src", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[5], &os));
    }
    {
        GROUP_SOURCE_REQ r;
        memset(&r, 0, sizeof(r));
        r.gsr_interface = I;
        r.gsr_group = g[5];
        r.gsr_source = s[0];
        R("D11.joinsrc-short", setsockopt(so, L, MCAST_JOIN_SOURCE_GROUP, (char *)&r, sizeof(r) - 1));
        R("D12.joinsrc-grplen", setsockopt(so, L, MCAST_JOIN_SOURCE_GROUP, (char *)&r, sizeof(GROUP_REQ)));
    }
    {
        SOCKADDR_STORAGE z;
        memset(&z, 0, sizeof(z));
        R("D13.join-family0", grp(so, L, MCAST_JOIN_GROUP, fam, I, &z));
    }
    R("D14.join-g5", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[5]));
    for (i = MCAST_JOIN_GROUP; i <= MCAST_LEAVE_SOURCE_GROUP; i++)
    {
        char b[512];
        int bl = sizeof(b);
        sprintf(name, "%d.D15.getsockopt-%d", fam, i);
        rc = getsockopt(so, L, i, b, &bl);
        sprintf(extra, "len=%d", bl);
        row(name, rc, extra);
    }
    R("D16.join-at-other-level", grp(so, fam == 4 ? IPPROTO_IPV6 : IPPROTO_IP, MCAST_JOIN_GROUP, fam, I, &g[6]));
    R("D17.join-other-group-at-other-level", grp(so, fam == 4 ? IPPROTO_IPV6 : IPPROTO_IP, MCAST_JOIN_GROUP, fam, I, &other));
    {
        char b[sizeof(GROUP_REQ) + 32];
        GROUP_REQ *r = (GROUP_REQ *)b;
        memset(b, 0, sizeof(b));
        r->gr_interface = I;
        r->gr_group = g[7];
        R("D18.join-len+32", setsockopt(so, L, MCAST_JOIN_GROUP, b, sizeof(b)));
    }
    closesocket(so);

    so = socket(fam == 4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    R("D19.tcp-join", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[5]));
    sprintf(name, "%d.D20.tcp-getf", fam); getf(so, name, I, &g[5], 8);
    closesocket(so);

    so = usock(fam, 0);
    R("D21.unbound-join", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[5]));
    R("D22.unbound-joinsrc", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[6], &s[0]));
    sprintf(name, "%d.D23.unbound-getf", fam); getf(so, name, I, &g[6], 8);
    R("D24.unbound-block", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[5], &s[0]));
    {
        SOCKADDR_STORAGE a;
        memset(&a, 0, sizeof(a));
        a.ss_family = fam == 4 ? AF_INET : AF_INET6;
        R("D25.bind-after", bind(so, (SOCKADDR *)&a, fam == 4 ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6)));
    }
    sprintf(name, "%d.D26.getf-after-bind", fam); getf(so, name, I, &g[6], 8);
    sprintf(name, "%d.D27.getf-asm-after-bind", fam); getf(so, name, I, &g[5], 8);
    closesocket(so);

    /* E: limits */
    so = usock(fam, 1);
    for (n = 0; n < 1100; n++)
    {
        SOCKADDR_STORAGE src;
        gensrc(fam, n, &src);
        if (gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[8], &src))
            break;
    }
    sprintf(name, "%d.E01.max-ssm-sources", fam);
    sprintf(extra, "count=%d", n);
    row(name, n < 1100 ? -1 : 0, extra);
    F("E02.getf-cap8", 8, 8);
    R("E03.leave", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[8]));
    R("E04.join-asm", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[9]));
    for (n = 0; n < 1100; n++)
    {
        SOCKADDR_STORAGE src;
        gensrc(fam, n, &src);
        if (gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[9], &src))
            break;
    }
    sprintf(name, "%d.E05.max-blocked", fam);
    sprintf(extra, "count=%d", n);
    row(name, n < 1100 ? -1 : 0, extra);
    R("E06.leave", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[9]));
    for (n = 0; n < 300; n++)
    {
        SOCKADDR_STORAGE gg;
        gengrp(fam, n, &gg);
        if (grp(so, L, MCAST_JOIN_GROUP, fam, I, &gg))
            break;
    }
    sprintf(name, "%d.E07.max-groups", fam);
    sprintf(extra, "count=%d", n);
    row(name, n < 300 ? -1 : 0, extra);
    for (i = 0; i < n; i++)
    {
        SOCKADDR_STORAGE gg;
        gengrp(fam, i, &gg);
        grp(so, L, MCAST_LEAVE_GROUP, fam, I, &gg);
    }
    closesocket(so);
    so = usock(fam, 1);
    {
        static SOCKADDR_STORAGE many[400];
        for (i = 0; i < 400; i++)
            gensrc(fam, i, &many[i]);
        sprintf(name, "%d.E08.setf-include-%d", fam, 64);
        row(name, setf(so, I, &g[8], MCAST_INCLUDE, 64, many, 0), NULL);
        F("E09.getf-cap8", 8, 8);
        sprintf(name, "%d.E10.setf-include-%d", fam, 400);
        row(name, setf(so, I, &g[8], MCAST_INCLUDE, 400, many, 0), NULL);
        F("E11.getf-cap8", 8, 8);
    }
    closesocket(so);

    /* F: SIOCSMSFILTER / SIOCGMSFILTER */
    so = usock(fam, 1);
    R("F01.setf-in-s1s2-new", setf(so, I, &g[4], MCAST_INCLUDE, 2, s, 0));
    F("F02.getf", 4, 8);
    F("F03.getf-cap0", 4, 0);
    F("F04.getf-cap1", 4, 1);
    R("F05.setf-ex-empty", setf(so, I, &g[4], MCAST_EXCLUDE, 0, s, 0));
    F("F06.getf", 4, 8);
    R("F07.setf-ex-s3", setf(so, I, &g[4], MCAST_EXCLUDE, 1, &s[2], 0));
    F("F08.getf", 4, 8);
    R("F09.joinsrc-after-setf-ex", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[4], &s[0]));
    R("F10.setf-in-empty", setf(so, I, &g[4], MCAST_INCLUDE, 0, s, 0));
    F("F11.getf-after-in-empty", 4, 8);
    R("F12.leave-after-in-empty", grp(so, L, MCAST_LEAVE_GROUP, fam, I, &g[4]));
    R("F13.setf-short", setf(so, I, &g[4], MCAST_INCLUDE, 2, s, (DWORD)-1));
    R("F14.setf-mode2", setf(so, I, &g[4], 2, 1, s, 0));
    R("F15.setf-unicast", setf(so, I, &uni, MCAST_INCLUDE, 1, s, 0));
    R("F16.setf-other-family", setf(so, I, &other, MCAST_INCLUDE, 1, s, 0));
    R("F17.setf-if0", setf(so, 0, &g[4], MCAST_EXCLUDE, 1, s, 0));
    sprintf(name, "%d.F18.getf-if0", fam); getf(so, name, 0, &g[4], 8);
    F("F19.getf-ifI", 4, 8);
    R("F20.setf-in-dup-sources", setf(so, I, &g[3], MCAST_INCLUDE, 2, (SOCKADDR_STORAGE[]){ s[0], s[0] }, 0));
    F("F21.getf-dup", 3, 8);
    {
        GROUP_FILTER f;
        DWORD ret = 0;
        memset(&f, 0, sizeof(f));
        f.gf_interface = I;
        f.gf_group = g[4];
        R("F22.getf-no-output", WSAIoctl(so, SIOCGMSFILTER, &f, sizeof(f), NULL, 0, &ret, NULL, NULL));
        R("F23.getf-short-input", WSAIoctl(so, SIOCGMSFILTER, &f, 8, &f, sizeof(f), &ret, NULL, NULL));
    }
    sprintf(name, "%d.F24.getf-not-joined", fam); getf(so, name, I, &g[7], 8);
    closesocket(so);

    /* H: the family's own legacy options mixed with MCAST_* */
    so = usock(fam, 1);
    if (fam == 6)
    {
        R("H01.ipv6-add-membership", mreq6(so, IPV6_ADD_MEMBERSHIP, G6[6], I));
        R("H02.block-s1", gsrc(so, L, MCAST_BLOCK_SOURCE, I, &g[6], &s[0]));
        F("H03.getf", 6, 8);
        R("H04.mcast-join-same", grp(so, L, MCAST_JOIN_GROUP, fam, I, &g[6]));
        R("H05.ipv6-add-again", mreq6(so, IPV6_ADD_MEMBERSHIP, G6[6], I));
        R("H06.ipv6-drop", mreq6(so, IPV6_DROP_MEMBERSHIP, G6[6], I));
        F("H07.getf-after-drop", 6, 8);
        R("H08.joinsrc-then-ipv6-drop", gsrc(so, L, MCAST_JOIN_SOURCE_GROUP, I, &g[7], &s[0]));
        R("H09.ipv6-drop-of-ssm", mreq6(so, IPV6_DROP_MEMBERSHIP, G6[7], I));
        R("H10.ipv6-add-on-ssm", mreq6(so, IPV6_ADD_MEMBERSHIP, G6[7], I));
        R("H11.ip-add-source-on-v6", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[0], S4[0], IfAddr4, 0));
        R("H12.sio-set-mf-on-v6", setf4(so, G4[0], IfAddr4, MCAST_INCLUDE, 1, S4, 0));
        sprintf(name, "6.H13.sio-get-mf-on-v6"); getf4(so, name, G4[0], IfAddr4, 8);
        {
            DWORD off = 0;
            closesocket(so);
            so = usock(6, 0);
            setsockopt(so, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
            {
                SOCKADDR_IN6 a;
                memset(&a, 0, sizeof(a));
                a.sin6_family = AF_INET6;
                bind(so, (SOCKADDR *)&a, sizeof(a));
            }
            {
                SOCKADDR_STORAGE g4;
                mkaddr(4, G4[1], &g4);
                R("H14.dual-mcast-join-v4group-at-ip", grp(so, IPPROTO_IP, MCAST_JOIN_GROUP, 4, If4, &g4));
                R("H15.dual-mcast-join-v4group-at-ipv6", grp(so, IPPROTO_IPV6, MCAST_JOIN_GROUP, 4, If6, &g4));
                R("H16.dual-ip-add-membership", mreq4(so, IP_ADD_MEMBERSHIP, G4[2], IfAddr4));
                R("H17.dual-ip-add-source", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[3], S4[0], IfAddr4, 0));
                sprintf(name, "6.H18.dual-getf-v4group"); getf(so, name, If4, &g4, 8);
            }
        }
    }
    else
    {
        IN_ADDR none;
        none.s_addr = 0;
        R("H01.ip-add-membership", mreq4(so, IP_ADD_MEMBERSHIP, G4[6], IfAddr4));
        R("H02.ip-add-source-on-asm", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[6], S4[0], IfAddr4, 0));
        R("H03.ip-block-s1", mreqsrc(so, IP_BLOCK_SOURCE, G4[6], S4[0], IfAddr4, 0));
        R("H04.ip-block-s1-again", mreqsrc(so, IP_BLOCK_SOURCE, G4[6], S4[0], IfAddr4, 0));
        getf4(so, "4.H05.sio-get-mf", G4[6], IfAddr4, 8);
        getf4(so, "4.H06.sio-get-mf-iface0", G4[6], none, 8);
        F("H07.getf-msfilter", 6, 8);
        R("H08.mcast-unblock-s1", gsrc(so, L, MCAST_UNBLOCK_SOURCE, I, &g[6], &s[0]));
        R("H09.ip-unblock-s1-again", mreqsrc(so, IP_UNBLOCK_SOURCE, G4[6], S4[0], IfAddr4, 0));
        R("H10.ip-drop-membership", mreq4(so, IP_DROP_MEMBERSHIP, G4[6], IfAddr4));
        R("H11.ip-add-source-s1", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[7], S4[0], IfAddr4, 0));
        R("H12.ip-add-source-s1-again", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[7], S4[0], IfAddr4, 0));
        R("H13.ip-add-source-s2", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[7], S4[1], IfAddr4, 0));
        getf4(so, "4.H14.sio-get-mf", G4[7], IfAddr4, 8);
        getf4(so, "4.H15.sio-get-mf-cap0", G4[7], IfAddr4, 0);
        R("H16.ip-add-membership-on-ssm", mreq4(so, IP_ADD_MEMBERSHIP, G4[7], IfAddr4));
        R("H17.ip-drop-source-s1", mreqsrc(so, IP_DROP_SOURCE_MEMBERSHIP, G4[7], S4[0], IfAddr4, 0));
        R("H18.ip-drop-source-s1-again", mreqsrc(so, IP_DROP_SOURCE_MEMBERSHIP, G4[7], S4[0], IfAddr4, 0));
        R("H19.ip-drop-membership-of-ssm", mreq4(so, IP_DROP_MEMBERSHIP, G4[7], IfAddr4));
        getf4(so, "4.H20.sio-get-mf-after", G4[7], IfAddr4, 8);
        R("H21.sio-set-mf-in-s1", setf4(so, G4[8], IfAddr4, MCAST_INCLUDE, 1, S4, 0));
        getf4(so, "4.H22.sio-get-mf", G4[8], IfAddr4, 8);
        R("H23.sio-set-mf-ex-empty", setf4(so, G4[8], IfAddr4, MCAST_EXCLUDE, 0, S4, 0));
        getf4(so, "4.H24.sio-get-mf", G4[8], IfAddr4, 8);
        R("H25.sio-set-mf-in-empty", setf4(so, G4[8], IfAddr4, MCAST_INCLUDE, 0, S4, 0));
        getf4(so, "4.H26.sio-get-mf-after-in-empty", G4[8], IfAddr4, 8);
        R("H27.sio-set-mf-short", setf4(so, G4[8], IfAddr4, MCAST_INCLUDE, 2, S4, (DWORD)-1));
        R("H28.sio-set-mf-iface0", setf4(so, G4[9], none, MCAST_EXCLUDE, 1, S4, 0));
        getf4(so, "4.H29.sio-get-mf-iface0", G4[9], none, 8);
        getf4(so, "4.H30.sio-get-mf-ifaddr", G4[9], IfAddr4, 8);
        R("H31.ip-add-source-short", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[5], S4[0], IfAddr4, 8));
        R("H32.ip-add-source-iface0", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[5], S4[0], none, 0));
        F("H33.getf-of-iface0-join", 5, 8);
        {
            char b[64];
            int bl = sizeof(b);
            rc = getsockopt(so, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, b, &bl);
            sprintf(extra, "len=%d", bl);
            row("4.H34.getsockopt-ip-add-source", rc, extra);
            bl = sizeof(b);
            rc = getsockopt(so, IPPROTO_IP, IP_ADD_MEMBERSHIP, b, &bl);
            sprintf(extra, "len=%d", bl);
            row("4.H35.getsockopt-ip-add-membership", rc, extra);
        }
        R("H36.ip-add-membership-unicast", mreq4(so, IP_ADD_MEMBERSHIP, "192.0.2.1", IfAddr4));
        R("H37.ip-add-source-mcast-src", mreqsrc(so, IP_ADD_SOURCE_MEMBERSHIP, G4[4], "239.1.1.1", IfAddr4, 0));
        R("H38.ip-drop-not-joined", mreq4(so, IP_DROP_MEMBERSHIP, G4[4], IfAddr4));
        R("H39.ip-add-membership-bad-iface", mreq4(so, IP_ADD_MEMBERSHIP, G4[4], (IN_ADDR){ .s_addr = htonl(0xC0000263) }));
        {
            IN_ADDR idx;
            idx.s_addr = htonl(If4);
            R("H40.ip-add-membership-iface-index", mreq4(so, IP_ADD_MEMBERSHIP, G4[3], idx));
            getf4(so, "4.H41.sio-get-mf-by-index", G4[3], idx, 8);
            getf4(so, "4.H42.sio-get-mf-by-addr", G4[3], IfAddr4, 8);
        }
    }
    closesocket(so);
    (void)v; (void)vl;
#undef R
#undef F
}

/* GROUP_FILTER of a group the socket joined: whether SIOCGMSFILTER finds it */
static BOOL
joined(SOCKET s, ULONG ifidx, const SOCKADDR_STORAGE *g)
{
    char buf[GROUP_FILTER_SIZE(1)];
    GROUP_FILTER *f = (GROUP_FILTER *)buf;
    DWORD ret = 0;

    memset(buf, 0, sizeof(buf));
    f->gf_interface = ifidx;
    f->gf_group = *g;
    f->gf_numsrc = 1;
    return WSAIoctl(s, SIOCGMSFILTER, f, sizeof(buf), f, sizeof(buf), &ret, NULL, NULL) == 0;
}

/*
 * What NitroOS does by design where Windows has no row (the table above is Windows'): a socket's groups before the
 * bind wait in the Winsock helper (bounded: 20 per family, the stack's own limit, however often one is joined and
 * left), the stack gets them at the bind, and one it refuses there is dropped and fails the bind
 */
static void
unbound_rows(int fam)
{
    SOCKADDR_STORAGE gg, any;
    SOCKET so, a, b;
    int L = lvl(fam), n, rc = 0, bad = 0;
    ULONG I = ifx(fam);
    int len = fam == 4 ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);

    memset(&any, 0, sizeof(any));
    any.ss_family = fam == 4 ? AF_INET : AF_INET6;

    /* the limit holds before the bind too */
    so = usock(fam, 0);
    for (n = 0; n < 40; n++)
    {
        gengrp(fam, 100 + n, &gg);
        if (grp(so, L, MCAST_JOIN_GROUP, fam, I, &gg))
        {
            rc = WSAGetLastError();
            break;
        }
    }
    ok(n == 20 && rc == WSAEADDRNOTAVAIL, "%d: unbound joins stopped at %d with %d, want 20 and %d\n", fam, n, rc,
       WSAEADDRNOTAVAIL);
    gengrp(fam, 100, &gg);
    ok(grp(so, L, MCAST_LEAVE_GROUP, fam, I, &gg) == 0, "%d: unbound leave failed: %d\n", fam, WSAGetLastError());
    ok(!joined(so, I, &gg), "%d: left group still reported\n", fam);
    closesocket(so);

    /* a join and leave loop does not grow what waits for the bind */
    so = usock(fam, 0);
    gengrp(fam, 100, &gg);
    for (n = 0; n < 5000; n++)
    {
        if (grp(so, L, MCAST_JOIN_GROUP, fam, I, &gg) || grp(so, L, MCAST_LEAVE_GROUP, fam, I, &gg))
            bad++;
    }
    ok(bad == 0, "%d: %d of 5000 unbound join/leave pairs failed\n", fam, bad);
    ok(grp(so, L, MCAST_JOIN_GROUP, fam, I, &gg) == 0, "%d: unbound join failed: %d\n", fam, WSAGetLastError());
    ok(bind(so, (SOCKADDR *)&any, len) == 0, "%d: bind failed: %d\n", fam, WSAGetLastError());
    ok(joined(so, I, &gg), "%d: group lost at the bind\n", fam);
    closesocket(so);

    if (fam != 6)
        return;

    /* the stack's limit of groups one process holds (32 of the machine's table) is hit at the bind: the bind fails,
       the refused groups are dropped, the ones taken stay */
    a = usock(fam, 0);
    b = usock(fam, 0);
    for (n = 0; n < 20; n++)
    {
        gengrp(fam, 200 + n, &gg);
        ok(grp(a, L, MCAST_JOIN_GROUP, fam, I, &gg) == 0, "%d: a join %d failed: %d\n", fam, n, WSAGetLastError());
        gengrp(fam, 300 + n, &gg);
        ok(grp(b, L, MCAST_JOIN_GROUP, fam, I, &gg) == 0, "%d: b join %d failed: %d\n", fam, n, WSAGetLastError());
    }
    ok(bind(a, (SOCKADDR *)&any, len) == 0, "%d: bind of a failed: %d\n", fam, WSAGetLastError());
    rc = bind(b, (SOCKADDR *)&any, len);
    ok(rc != 0 && WSAGetLastError() == WSAEADDRNOTAVAIL, "%d: bind of b: %d, error %d, want a refusal (%d)\n", fam, rc,
       WSAGetLastError(), WSAEADDRNOTAVAIL);
    gengrp(fam, 300, &gg);
    ok(joined(b, I, &gg), "%d: first group of b lost\n", fam);
    gengrp(fam, 319, &gg);
    ok(!joined(b, I, &gg), "%d: refused group of b still reported as joined\n", fam);
    closesocket(b);
    closesocket(a);
}

START_TEST(mcastfilter)
{
    WSADATA wsa;
    SOCKET s6;

    ok(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "WSAStartup failed\n");
    if (!find_interface())
    {
        skip("no adapter with an IPv4 address\n");
        WSACleanup();
        return;
    }
    family_rows(4);
    unbound_rows(4);
    s6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s6 == INVALID_SOCKET || If6 == 0)
    {
        skip("no IPv6 (socket %d, interface %lu)\n", s6 == INVALID_SOCKET ? WSAGetLastError() : 0, If6);
    }
    else
    {
        GROUP_REQ r;

        /* IPv6 sockets exist but no adapter takes IPv6 (DisabledComponents): nothing to join on */
        memset(&r, 0, sizeof(r));
        r.gr_interface = If6;
        mkaddr(6, "ff15::4d32:fe", &r.gr_group);
        if (setsockopt(s6, IPPROTO_IPV6, MCAST_JOIN_GROUP, (char *)&r, sizeof(r)))
            skip("no IPv6 multicast on interface %lu: %d\n", If6, WSAGetLastError());
        else
        {
            family_rows(6);
            unbound_rows(6);
        }
    }
    if (s6 != INVALID_SOCKET)
        closesocket(s6);
    trace("%lu rows checked\n", Checked);
    WSACleanup();
}
