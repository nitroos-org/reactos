/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Stable random IPv6 interface identifiers (RFC 7217) for link-local and SLAAC addresses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Without this, lwIP forms the link-local address from the adapter's MAC (modified EUI-64, RFC 4291 2.5.1)
 * and every SLAAC address from the link-local one, so each global source address carries the MAC. As
 * Windows does by default (netsh interface ipv6 show global: "Randomize Identifiers: enabled"), the
 * identifiers are random instead, but stable: RFC 7217 section 5,
 *
 *   identifier = F(prefix, interface, DAD counter, secret key)
 *
 * with F = SipHash-2-4 (a keyed pseudorandom function, 64-bit output) keyed with a 128-bit secret, over the
 * 64-bit prefix, the adapter's hardware address (the interface input: stable across reboots and renumbering
 * of interface indexes; it is hashed with the secret, never visible) and the DAD counter. No network id
 * (optional in RFC 7217). The same machine therefore gets the same address on the same network after a
 * reboot, another address on every other prefix, and two machines cloned from one disk still differ (their
 * adapters' addresses do). An identifier RFC 5453 reserves is skipped like a duplicate.
 *
 * The secret is made at the first start with IPv6 on and kept in
 * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\StableIdentifiers, value SecretKey (REG_BINARY,
 * 16 bytes). The key is created with a protected DACL: SYSTEM and Administrators only, so a standard user
 * cannot read it (Tcpip6\Parameters itself is readable by everybody) once the configuration manager enforces
 * key descriptors on open (it stores and reports them already). Without the key (no Tcpip6 service
 * key, a registry failure) a secret made for this start is used: the addresses are random, only not stable.
 *
 * Duplicate address detection (RFC 7217 section 6): when DAD finds a tentative address of ours in use, the
 * next counter value makes a new identifier, at most IDGEN_RETRIES (3) times, then the address stays
 * duplicated as lwIP leaves it. lwIP calls LibNd6DadFailed (LWIP_HOOK_ND6_DAD_FAILED) and LibNd6SlaacAddress
 * (LWIP_HOOK_ND6_SLAAC_ADDRESS) from nd6.c, with the core lock held.
 *
 * Tcpip6\Parameters\RandomizeIdentifiers (REG_DWORD): 0 returns to the MAC-derived identifiers (what
 * `netsh interface ipv6 set global randomizeidentifiers=disabled` selects on Windows); absent or anything
 * else = random. Both values are read once, at the start of the driver, with IPv6 on; nothing is read or
 * written with IPv6 off.
 */

#include "precomp.h"

#include <ntifs.h>
#include <ndk/rtlfuncs.h>

#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64))
#include <immintrin.h>
#endif

#define TAG_IID6            'dI6T'
#define IID6_SECRET_SIZE    16
/* RFC 7217 section 6 */
#define IID6_IDGEN_RETRIES  3

#define IID6_PARAMETERS     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
#define IID6_SECRET_KEY     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\StableIdentifiers"

BOOLEAN TCP6RandomizeIdentifiers;
static UCHAR Iid6Secret[IID6_SECRET_SIZE];

/* ---- SipHash-2-4 (Aumasson, Bernstein, "SipHash: a fast short-input PRF", 2012) ---- */

#define SIP_ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIP_ROUND(v0, v1, v2, v3) \
    do { \
        v0 += v1; v1 = SIP_ROTL(v1, 13); v1 ^= v0; v0 = SIP_ROTL(v0, 32); \
        v2 += v3; v3 = SIP_ROTL(v3, 16); v3 ^= v2; \
        v0 += v3; v3 = SIP_ROTL(v3, 21); v3 ^= v0; \
        v2 += v1; v1 = SIP_ROTL(v1, 17); v1 ^= v2; v2 = SIP_ROTL(v2, 32); \
    } while (0)

static
ULONGLONG
Iid6Load64(const UCHAR *p)
{
    ULONGLONG v = 0;
    int i;

    for (i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static
ULONGLONG
Iid6SipHash(const UCHAR Key[16], const UCHAR *Data, ULONG Length)
{
    ULONGLONG k0 = Iid6Load64(Key), k1 = Iid6Load64(Key + 8);
    ULONGLONG v0 = 0x736f6d6570736575ULL ^ k0;
    ULONGLONG v1 = 0x646f72616e646f6dULL ^ k1;
    ULONGLONG v2 = 0x6c7967656e657261ULL ^ k0;
    ULONGLONG v3 = 0x7465646279746573ULL ^ k1;
    ULONGLONG m, b = (ULONGLONG)Length << 56;
    ULONG i, Left = Length & 7;

    for (i = 0; i + 8 <= Length; i += 8)
    {
        m = Iid6Load64(Data + i);
        v3 ^= m;
        SIP_ROUND(v0, v1, v2, v3);
        SIP_ROUND(v0, v1, v2, v3);
        v0 ^= m;
    }
    while (Left)
    {
        Left--;
        b |= (ULONGLONG)Data[i + Left] << (8 * Left);
    }
    v3 ^= b;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ---- the identifier ---- */

/* RFC 5453: the all-zero (subnet-router anycast) identifier, the reserved Ethernet-derived range
   0200:5EFF:FE00:0000-5213 and the subnet anycast range FDFF:FFFF:FFFF:FF80-FFFF */
static
BOOLEAN
Iid6IsReserved(const UCHAR *Iid)
{
    static const UCHAR Zero[8] = { 0 };
    static const UCHAR Eth[5] = { 0x02, 0x00, 0x5e, 0xff, 0xfe };
    static const UCHAR Anycast[7] = { 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if (RtlCompareMemory(Iid, Zero, 8) == 8)
        return TRUE;
    if (RtlCompareMemory(Iid, Eth, 5) == 5 && Iid[5] == 0 && ((ULONG)Iid[6] << 8 | Iid[7]) <= 0x5213)
        return TRUE;
    if (RtlCompareMemory(Iid, Anycast, 7) == 7 && Iid[7] >= 0x80)
        return TRUE;
    return FALSE;
}

/* The address for Prefix (its first 64 bits) on netif with DAD counter Counter, in Address (zoned);
   FALSE when that identifier is reserved (the caller tries the next counter) */
static
BOOLEAN
Iid6Make(struct netif *netif, const ip6_addr_t *Prefix, UCHAR Counter, ip6_addr_t *Address)
{
    UCHAR Input[8 + 1 + NETIF_MAX_HWADDR_LEN + 1];
    ULONG Length = 0;
    ULONGLONG Id;
    UCHAR Iid[8];
    int i;

    /* prefix (network order) | hardware address length | hardware address | DAD counter */
    RtlCopyMemory(Input, Prefix->addr, 8);
    Length = 8;
    Input[Length++] = netif->hwaddr_len;
    RtlCopyMemory(Input + Length, netif->hwaddr, netif->hwaddr_len);
    Length += netif->hwaddr_len;
    Input[Length++] = Counter;

    Id = Iid6SipHash(Iid6Secret, Input, Length);
    for (i = 0; i < 8; i++)
        Iid[i] = (UCHAR)(Id >> (8 * i));
    if (Iid6IsReserved(Iid))
        return FALSE;

    Address->addr[0] = Prefix->addr[0];
    Address->addr[1] = Prefix->addr[1];
    RtlCopyMemory(&Address->addr[2], Iid, 8);
    ip6_addr_clear_zone(Address);
    ip6_addr_assign_zone(Address, IP6_UNICAST, netif);
    return TRUE;
}

/* The first usable identifier for Prefix from counter From on; FALSE after IDGEN_RETRIES */
static
BOOLEAN
Iid6MakeFrom(struct netif *netif, const ip6_addr_t *Prefix, UCHAR From, ip6_addr_t *Address)
{
    UCHAR Counter;

    for (Counter = From; Counter <= IID6_IDGEN_RETRIES; Counter++)
    {
        if (Iid6Make(netif, Prefix, Counter, Address))
            return TRUE;
    }
    return FALSE;
}

/* Whether identifiers of this interface are made here (an Ethernet address to key them with) */
static
BOOLEAN
Iid6Applies(struct netif *netif)
{
    return TCPIpv6Enabled && TCP6RandomizeIdentifiers && netif->hwaddr_len == 6;
}

/* TCPInterfaceInit6 (core lock held): the link-local address of an Ethernet interface, tentative.
   FALSE when the identifiers are not randomized (the caller forms the EUI-64 one) */
BOOLEAN
TCP6SetStableLinkLocal(struct netif *netif)
{
    ip6_addr_t Prefix, Address;

    if (!Iid6Applies(netif))
        return FALSE;

    IP6_ADDR(&Prefix, PP_HTONL(0xfe800000UL), 0, 0, 0);
    if (!Iid6MakeFrom(netif, &Prefix, 0, &Address))
        return FALSE;   /* four reserved identifiers in a row: not in this universe */

    netif_ip6_addr_set(netif, 0, &Address);
    netif_ip6_addr_set_state(netif, 0, IP6_ADDR_TENTATIVE);
    return TRUE;
}

/* LWIP_HOOK_ND6_SLAAC_ADDRESS (nd6.c, core lock held): the address stateless autoconfiguration forms for
   Prefix; 0 = lwIP forms it from the link-local identifier as before */
int
LibNd6SlaacAddress(struct netif *netif, const ip6_addr_t *Prefix, ip6_addr_t *Address)
{
    if (!Iid6Applies(netif))
        return 0;
    return Iid6MakeFrom(netif, Prefix, 0, Address) ? 1 : 0;
}

/* LWIP_HOOK_ND6_DAD_FAILED (nd6.c, core lock held): DAD found the address in slot Index in use. A tentative
   address of ours gets the identifier of the next DAD counter and starts DAD again; 1 = done, lwIP leaves the
   slot alone. 0 = lwIP marks it duplicated (not one of ours, no counter left, or the address was already in
   use: an established address is not changed under its connections) */
int
LibNd6DadFailed(struct netif *netif, s8_t Index)
{
    const ip6_addr_t *Current = netif_ip6_addr(netif, Index);
    ip6_addr_t Prefix, Candidate;
    UCHAR Counter;

    if (!Iid6Applies(netif) || !ip6_addr_istentative(netif_ip6_addr_state(netif, Index)))
        return 0;

    IP6_ADDR(&Prefix, Current->addr[0], Current->addr[1], 0, 0);
    for (Counter = 0; Counter <= IID6_IDGEN_RETRIES; Counter++)
    {
        if (Iid6Make(netif, &Prefix, Counter, &Candidate) && ip6_addr_zoneless_eq(&Candidate, Current))
            break;
    }
    if (Counter >= IID6_IDGEN_RETRIES)
    {
        if (Counter == IID6_IDGEN_RETRIES)
            DbgPrint("TCPIP: IPv6 address %d of interface %u is a duplicate after %u new identifiers, given up\n",
                     (int)Index, (UINT)netif->num, (UINT)IID6_IDGEN_RETRIES);
        return 0;
    }
    if (!Iid6MakeFrom(netif, &Prefix, Counter + 1, &Candidate))
        return 0;

    DbgPrint("TCPIP: IPv6 address %d of interface %u is a duplicate, new identifier (DAD counter %u)\n",
             (int)Index, (UINT)netif->num, (UINT)Counter + 1);
    netif_ip6_addr_set(netif, Index, &Candidate);
    /* Restart DAD: from the next count on (the state changes even when it was TENTATIVE with no probe sent) */
    netif_ip6_addr_set_state(netif, Index, IP6_ADDR_TENTATIVE);
    return 1;
}

/* For the self-test (selftest6.c): the address for Prefix with DAD counter Counter */
BOOLEAN
TCP6StableAddress(struct netif *netif, const ip6_addr_t *Prefix, UCHAR Counter, ip6_addr_t *Address)
{
    return Iid6Make(netif, Prefix, Counter, Address);
}

/* ---- the secret ---- */

#if defined(_M_IX86) || defined(_M_AMD64)
static
BOOLEAN
Iid6Rdrand(PULONG Value)
{
#if defined(__GNUC__) || defined(__clang__)
    UCHAR Ok;

    __asm__ __volatile__("rdrand %0; setc %1" : "=r"(*Value), "=qm"(Ok) : : "cc");
    return Ok != 0;
#else
    unsigned int v;
    int Ok = _rdrand32_step(&v);

    *Value = v;
    return Ok != 0;
#endif
}
#endif

/* 16 bytes for a new secret. The processor's random number generator when it has one (RDRAND), always mixed
   with timing: the cycle counter around the interrupt and performance counters, read many times */
static
VOID
Iid6NewSecret(UCHAR Secret[IID6_SECRET_SIZE])
{
    ULONGLONG Pool[48];
    UCHAR Key[16];
    ULONGLONG Half;
    ULONG i, j = 0, Value;
    LARGE_INTEGER Time;
    BOOLEAN HaveRdrand = FALSE;

    RtlZeroMemory(Pool, sizeof(Pool));
    RtlZeroMemory(Key, sizeof(Key));

#if defined(_M_IX86) || defined(_M_AMD64)
    HaveRdrand = ExIsProcessorFeaturePresent(PF_RDRAND_INSTRUCTION_AVAILABLE);
    if (HaveRdrand)
    {
        /* 8 x 32 bits; the instruction may fail transiently (Intel: retry up to 10 times) */
        for (i = 0; i < 8; i++)
        {
            ULONG Try;

            for (Try = 0; Try < 10 && !Iid6Rdrand(&Value); Try++)
                ;
            Pool[j++] = Value;
        }
    }
#endif

    KeQuerySystemTime(&Time);
    Pool[j++] = (ULONGLONG)Time.QuadPart;
    Pool[j++] = KeQueryInterruptTime();
    for (i = 0; j < RTL_NUMBER_OF(Pool); i++)
    {
        Time = KeQueryPerformanceCounter(NULL);
#if defined(_M_IX86) || defined(_M_AMD64)
        Pool[j++] = (ULONGLONG)Time.QuadPart ^ (__rdtsc() << 17) ^ i;
#else
        Pool[j++] = (ULONGLONG)Time.QuadPart ^ i;
#endif
    }
    Pool[0] ^= (ULONG_PTR)&Pool;

    /* Two halves of the pool's hash under two fixed keys */
    Half = Iid6SipHash(Key, (const UCHAR *)Pool, sizeof(Pool));
    RtlCopyMemory(Secret, &Half, 8);
    Key[0] = 1;
    Half = Iid6SipHash(Key, (const UCHAR *)Pool, sizeof(Pool));
    RtlCopyMemory(Secret + 8, &Half, 8);

    RtlSecureZeroMemory(Pool, sizeof(Pool));
    DbgPrint("TCPIP: new IPv6 identifier secret (%s)\n", HaveRdrand ? "RDRAND and timing" : "timing only");
}

/* The DACL of the secret's key: SYSTEM and Administrators, full access, nobody else; not inherited from the
   parent (protected), inherited by any subkey */
static
NTSTATUS
Iid6MakeSecurity(PSECURITY_DESCRIPTOR Sd, PACL *Dacl)
{
    ULONG Size;
    PACL Acl;
    NTSTATUS Status;

    Size = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) +
           RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid);
    Acl = ExAllocatePoolWithTag(PagedPool, Size, TAG_IID6);
    if (!Acl)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = RtlCreateAcl(Acl, Size, ACL_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAceEx(Acl, ACL_REVISION, CONTAINER_INHERIT_ACE, KEY_ALL_ACCESS,
                                          SeExports->SeLocalSystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAceEx(Acl, ACL_REVISION, CONTAINER_INHERIT_ACE, KEY_ALL_ACCESS,
                                          SeExports->SeAliasAdminsSid);
    if (NT_SUCCESS(Status))
        Status = RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Acl, TAG_IID6);
        return Status;
    }
    ((PISECURITY_DESCRIPTOR)Sd)->Control |= SE_DACL_PROTECTED;
    *Dacl = Acl;
    return STATUS_SUCCESS;
}

/* Whether the key's DACL is the one Iid6MakeSecurity makes: protected, two ACEs, SYSTEM and Administrators */
static
BOOLEAN
Iid6KeySecurityIsOurs(HANDLE Key)
{
    PISECURITY_DESCRIPTOR_RELATIVE Sd;
    BOOLEAN Present = FALSE, Defaulted = FALSE, Ours = FALSE;
    PACL Acl = NULL;
    PACCESS_ALLOWED_ACE Ace;
    ULONG Needed = 0, i;

    if (ZwQuerySecurityObject(Key, DACL_SECURITY_INFORMATION, NULL, 0, &Needed) != STATUS_BUFFER_TOO_SMALL || !Needed)
        return FALSE;
    Sd = ExAllocatePoolWithTag(PagedPool, Needed, TAG_IID6);
    if (!Sd)
        return FALSE;
    if (NT_SUCCESS(ZwQuerySecurityObject(Key, DACL_SECURITY_INFORMATION, Sd, Needed, &Needed)) &&
        (Sd->Control & SE_DACL_PROTECTED) &&
        NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Acl, &Defaulted)) && Present && Acl &&
        Acl->AceCount == 2)
    {
        Ours = TRUE;
        for (i = 0; i < 2 && Ours; i++)
        {
            Ours = NT_SUCCESS(RtlGetAce(Acl, i, (PVOID *)&Ace)) && Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                   (RtlEqualSid(&Ace->SidStart, SeExports->SeLocalSystemSid) ||
                    RtlEqualSid(&Ace->SidStart, SeExports->SeAliasAdminsSid));
        }
    }
    ExFreePoolWithTag(Sd, TAG_IID6);
    return Ours;
}

/* Reads the secret, or makes and stores one; Iid6Secret holds a secret afterwards in any case */
static
VOID
Iid6LoadSecret(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(IID6_SECRET_KEY);
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"SecretKey");
    OBJECT_ATTRIBUTES Attributes;
    SECURITY_DESCRIPTOR Sd;
    PACL Dacl = NULL;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + IID6_SECRET_SIZE];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length, Disposition;
    NTSTATUS Status;

    if (!NT_SUCCESS(Iid6MakeSecurity(&Sd, &Dacl)))
    {
        Iid6NewSecret(Iid6Secret);
        DbgPrint("TCPIP: IPv6 identifier secret not kept (no security descriptor)\n");
        return;
    }

    /* The parent (Tcpip6\Parameters, made by the network install) must exist: this does not create it */
    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &Sd);
    Status = ZwCreateKey(&Key, KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL | WRITE_DAC, &Attributes, 0, NULL,
                         REG_OPTION_NON_VOLATILE, &Disposition);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Dacl, TAG_IID6);
        Iid6NewSecret(Iid6Secret);
        DbgPrint("TCPIP: IPv6 identifier secret not kept (key: 0x%lx)\n", Status);
        return;
    }

    /* A key made while setup runs (the configuration manager stores no descriptor then: it inherits) or
       changed since gets the DACL again, at the first start where it can be stored */
    if (!Iid6KeySecurityIsOurs(Key))
    {
        Status = ZwSetSecurityObject(Key, DACL_SECURITY_INFORMATION, &Sd);
        DbgPrint("TCPIP: IPv6 identifier secret key DACL set again: 0x%lx\n", Status);
    }
    ExFreePoolWithTag(Dacl, TAG_IID6);

    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Status) && Info->Type == REG_BINARY && Info->DataLength == IID6_SECRET_SIZE)
    {
        RtlCopyMemory(Iid6Secret, Info->Data, IID6_SECRET_SIZE);
    }
    else
    {
        Iid6NewSecret(Iid6Secret);
        Status = ZwSetValueKey(Key, &ValueName, 0, REG_BINARY, Iid6Secret, IID6_SECRET_SIZE);
        if (NT_SUCCESS(Status))
            ZwFlushKey(Key);
        else
            DbgPrint("TCPIP: IPv6 identifier secret not kept (value: 0x%lx)\n", Status);
    }
    RtlSecureZeroMemory(Buffer, sizeof(Buffer));
    ZwClose(Key);
}

/* TCPReadIpv6Switch, with IPv6 on, before any interface registers (PASSIVE_LEVEL) */
VOID
TCP6ReadIdentifierSettings(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(IID6_PARAMETERS);
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"RandomizeIdentifiers");
    OBJECT_ATTRIBUTES Attributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length;

    TCP6RandomizeIdentifiers = TRUE;

    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
    {
        if (NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
            Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG) && *(PULONG)Info->Data == 0)
        {
            TCP6RandomizeIdentifiers = FALSE;
        }
        ZwClose(Key);
    }

    if (!TCP6RandomizeIdentifiers)
    {
        DbgPrint("TCPIP: IPv6 identifiers from the MAC (RandomizeIdentifiers = 0)\n");
        return;
    }

    Iid6LoadSecret();
}
