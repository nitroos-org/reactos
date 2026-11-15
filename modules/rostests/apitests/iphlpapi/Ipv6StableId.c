/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 interface identifiers: with the default (Tcpip6\Parameters\RandomizeIdentifiers absent or not
 *              0) no address of an Ethernet adapter carries the MAC (modified EUI-64); each is the stable random
 *              identifier of RFC 7217 under the secret the stack keeps (so the same after a restart); the secret's
 *              key's descriptor refuses a standard user (the open itself is todo on reactos until key descriptors
 *              are enforced). With RandomizeIdentifiers = 0 the identifiers
 *              are the MAC's EUI-64 again. Windows 10 22H2 reports a random link-local identifier with the origins
 *              WellKnown / Link (Get-NetIPAddress), and "Randomize Identifiers: enabled" by default.
 *              A secret made during setup is marked (FromSetup) and replaced at the first normal boot: the mark
 *              is gone when this test runs. Without an Ethernet link-local address (no network adapter, DAD
 *              not finished within 20 s) the address checks are skipped.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#define PARAMETERS_KEY  L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
#define SECRET_KEY      L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\StableIdentifiers"

/* SipHash-2-4, written from the paper (Aumasson, Bernstein 2012) independently of the driver's copy */
static ULONGLONG Rotl(ULONGLONG x, int b) { return (x << b) | (x >> (64 - b)); }

static void Round(ULONGLONG v[4])
{
    v[0] += v[1]; v[1] = Rotl(v[1], 13); v[1] ^= v[0]; v[0] = Rotl(v[0], 32);
    v[2] += v[3]; v[3] = Rotl(v[3], 16); v[3] ^= v[2];
    v[0] += v[3]; v[3] = Rotl(v[3], 21); v[3] ^= v[0];
    v[2] += v[1]; v[1] = Rotl(v[1], 17); v[1] ^= v[2]; v[2] = Rotl(v[2], 32);
}

static ULONGLONG Le64(const BYTE *p)
{
    ULONGLONG r = 0;
    int i;
    for (i = 7; i >= 0; i--)
        r = (r << 8) | p[i];
    return r;
}

static ULONGLONG SipHash24(const BYTE Key[16], const BYTE *Data, ULONG Length)
{
    ULONGLONG k0 = Le64(Key), k1 = Le64(Key + 8), m, v[4];
    BYTE Last[8] = { 0 };
    ULONG i;

    v[0] = 0x736f6d6570736575ULL ^ k0;
    v[1] = 0x646f72616e646f6dULL ^ k1;
    v[2] = 0x6c7967656e657261ULL ^ k0;
    v[3] = 0x7465646279746573ULL ^ k1;
    for (i = 0; i + 8 <= Length; i += 8)
    {
        m = Le64(Data + i);
        v[3] ^= m; Round(v); Round(v); v[0] ^= m;
    }
    memcpy(Last, Data + i, Length - i);
    Last[7] = (BYTE)Length;
    m = Le64(Last);
    v[3] ^= m; Round(v); Round(v); v[0] ^= m;
    v[2] ^= 0xff;
    Round(v); Round(v); Round(v); Round(v);
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

/* RFC 7217 identifier as the stack forms it: F(prefix | 6 | MAC | DAD counter) under the secret */
static void StableIid(const BYTE Secret[16], const BYTE *Prefix, const BYTE *Mac, BYTE Counter, BYTE Iid[8])
{
    BYTE Input[16];
    ULONGLONG h;
    int i;

    memcpy(Input, Prefix, 8);
    Input[8] = 6;
    memcpy(Input + 9, Mac, 6);
    Input[15] = Counter;
    h = SipHash24(Secret, Input, sizeof(Input));
    for (i = 0; i < 8; i++)
        Iid[i] = (BYTE)(h >> (8 * i));
}

static BOOL IsEui64(const BYTE *Iid, const BYTE *Mac)
{
    return Iid[0] == (Mac[0] ^ 2) && Iid[1] == Mac[1] && Iid[2] == Mac[2] && Iid[3] == 0xff && Iid[4] == 0xfe &&
           Iid[5] == Mac[3] && Iid[6] == Mac[4] && Iid[7] == Mac[5];
}

static BOOL ReadRandomize(void)
{
    HKEY Key;
    DWORD Value = 1, Size = sizeof(Value), Type = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return TRUE;
    if (RegQueryValueExW(Key, L"RandomizeIdentifiers", NULL, &Type, (BYTE *)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD || Size != sizeof(Value))
        Value = 1;
    RegCloseKey(Key);
    return Value != 0;
}

static BOOL ReadSecret(BYTE Secret[16])
{
    HKEY Key;
    DWORD Size = 16, Type = 0;
    LONG Error;
    static const BYTE Zero[16] = { 0 };

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECRET_KEY, 0, KEY_QUERY_VALUE, &Key);
    ok(Error == ERROR_SUCCESS, "administrator: secret key open error %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(Key, L"SecretKey", NULL, &Type, Secret, &Size);
    RegCloseKey(Key);
    ok(Error == ERROR_SUCCESS && Type == REG_BINARY && Size == 16, "SecretKey: error %ld type %lu size %lu\n",
       Error, Type, Size);
    ok(memcmp(Secret, Zero, 16) != 0, "SecretKey is all zero\n");
    return Error == ERROR_SUCCESS && Type == REG_BINARY && Size == 16;
}

/* The key's DACL: protected, SYSTEM and Administrators only */
static void TestSecretDacl(void)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    BOOL Present = FALSE, Defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL Control = 0;
    DWORD Revision, Size = 0, i;
    HKEY Key;
    LONG Error;
    BYTE SystemSid[SECURITY_MAX_SID_SIZE], AdminsSid[SECURITY_MAX_SID_SIZE];
    DWORD SidSize;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECRET_KEY, 0, READ_CONTROL, &Key);
    ok(Error == ERROR_SUCCESS, "secret key READ_CONTROL error %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;
    RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, NULL, &Size);
    Sd = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    Error = RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd, &Size);
    RegCloseKey(Key);
    ok(Error == ERROR_SUCCESS, "RegGetKeySecurity error %ld\n", Error);
    if (Error != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Sd);
        return;
    }
    GetSecurityDescriptorControl(Sd, &Control, &Revision);
    ok(Control & SE_DACL_PROTECTED, "DACL not protected (control 0x%x)\n", Control);
    ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present && Dacl, "no DACL\n");

    SidSize = sizeof(SystemSid);
    CreateWellKnownSid(WinLocalSystemSid, NULL, SystemSid, &SidSize);
    SidSize = sizeof(AdminsSid);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminsSid, &SidSize);
    ok(Present && Dacl && Dacl->AceCount == 2, "%u ACEs, want exactly 2\n", Dacl ? Dacl->AceCount : 0);
    for (i = 0; Present && Dacl && i < Dacl->AceCount; i++)
    {
        ACCESS_ALLOWED_ACE *Ace;

        if (!GetAce(Dacl, i, (void **)&Ace))
            continue;
        ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ACE %lu type %u\n", i, Ace->Header.AceType);
        if (Ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        ok(EqualSid(&Ace->SidStart, SystemSid) || EqualSid(&Ace->SidStart, AdminsSid),
           "ACE %lu allows access to another account\n", i);
        ok(Ace->Mask == KEY_ALL_ACCESS, "ACE %lu mask 0x%lx\n", i, Ace->Mask);
        ok(Ace->Header.AceFlags == CONTAINER_INHERIT_ACE, "ACE %lu flags 0x%x\n", i, Ace->Header.AceFlags);
        if (i == 1 && Dacl->AceCount == 2)
        {
            ACCESS_ALLOWED_ACE *First;

            if (GetAce(Dacl, 0, (void **)&First))
                ok(EqualSid(&First->SidStart, SystemSid) != EqualSid(&Ace->SidStart, SystemSid),
                   "SYSTEM is not in exactly one of the two ACEs\n");
        }
    }
    HeapFree(GetProcessHeap(), 0, Sd);
}

/* A standard user: the same process token without its user and its administrators group (both deny-only) and
   without privileges, as an impersonation token. The key's stored descriptor must refuse it: AccessCheck against
   the descriptor the key reports, and the open itself. The parent key opens (control). */
static void TestSecretDeniedToUser(void)
{
    HANDLE Token = NULL, Filtered = NULL, Imp = NULL;
    BYTE AdminsSid[SECURITY_MAX_SID_SIZE], UserBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    TOKEN_USER *User = (TOKEN_USER *)UserBuffer;
    DWORD SidSize = sizeof(AdminsSid), Length, Size = 0;
    SID_AND_ATTRIBUTES Disable[2];
    WCHAR Name[64] = L"?", Domain[64] = L"?";
    DWORD NameLength = ARRAYSIZE(Name), DomainLength = ARRAYSIZE(Domain);
    SID_NAME_USE Use;
    GENERIC_MAPPING Mapping = { KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS };
    BYTE PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted = 0;
    BOOL Status = TRUE;
    PSECURITY_DESCRIPTOR Sd = NULL;
    HKEY Key;
    LONG Error;

    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminsSid, &SidSize);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token) ||
        !GetTokenInformation(Token, TokenUser, UserBuffer, sizeof(UserBuffer), &Length))
    {
        skip("no process token (error %lu)\n", GetLastError());
        if (Token)
            CloseHandle(Token);
        return;
    }
    LookupAccountSidW(NULL, User->User.Sid, Name, &NameLength, Domain, &DomainLength, &Use);
    trace("test runs as %ls\\%ls\n", Domain, Name);
    Disable[0].Sid = AdminsSid;
    Disable[0].Attributes = 0;
    Disable[1].Sid = User->User.Sid;
    Disable[1].Attributes = 0;
    if (!CreateRestrictedToken(Token, DISABLE_MAX_PRIVILEGE, 2, Disable, 0, NULL, 0, NULL, &Filtered) ||
        !DuplicateTokenEx(Filtered, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Imp))
    {
        skip("no restricted token (error %lu)\n", GetLastError());
        if (Filtered)
            CloseHandle(Filtered);
        CloseHandle(Token);
        return;
    }

    /* The descriptor as the key reports it (owner, group, DACL), checked for the standard user */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECRET_KEY, 0, READ_CONTROL, &Key);
    ok(Error == ERROR_SUCCESS, "secret key READ_CONTROL error %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        SECURITY_INFORMATION Info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

        RegGetKeySecurity(Key, Info, NULL, &Size);
        Sd = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
        Error = RegGetKeySecurity(Key, Info, Sd, &Size);
        ok(Error == ERROR_SUCCESS, "RegGetKeySecurity error %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            ok(AccessCheck(Sd, Imp, KEY_QUERY_VALUE, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status),
               "AccessCheck error %lu\n", GetLastError());
            ok(!Status, "the stored descriptor grants a standard user 0x%lx on the secret\n", Granted);
        }
        HeapFree(GetProcessHeap(), 0, Sd);
        RegCloseKey(Key);
    }

    ok(ImpersonateLoggedOnUser(Imp), "ImpersonateLoggedOnUser error %lu\n", GetLastError());
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key);
    ok(Error == ERROR_SUCCESS, "standard user: Tcpip6\\Parameters open error %ld (control)\n", Error);
    if (Error == ERROR_SUCCESS)
        RegCloseKey(Key);
    /* This kernel stores and reports key descriptors but does not enforce them on open yet (registry ACL
       enforcement, slice R8): todo until it does */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECRET_KEY, 0, KEY_QUERY_VALUE, &Key);
    todo_if(is_reactos())
    ok(Error == ERROR_ACCESS_DENIED, "standard user: secret key open error %ld, want ERROR_ACCESS_DENIED\n", Error);
    if (Error == ERROR_SUCCESS)
        RegCloseKey(Key);
    RevertToSelf();

    CloseHandle(Imp);
    CloseHandle(Filtered);
    CloseHandle(Token);
}

/* A secret made during setup carries FromSetup = 1 until the first normal boot replaces it: gone by now */
static void TestSetupMarkGone(void)
{
    HKEY Key;
    DWORD Value = 0, Size = sizeof(Value), Type = 0;
    LONG Error;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECRET_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return;
    Error = RegQueryValueExW(Key, L"FromSetup", NULL, &Type, (BYTE *)&Value, &Size);
    RegCloseKey(Key);
    ok(Error == ERROR_FILE_NOT_FOUND || (Error == ERROR_SUCCESS && Type == REG_DWORD && Value == 0),
       "FromSetup still set after setup: error %ld type %lu value %lu\n", Error, Type, Value);
}

static BOOL HasEthernetLinkLocal(IP_ADAPTER_ADDRESSES *List)
{
    IP_ADAPTER_ADDRESSES *A;
    IP_ADAPTER_UNICAST_ADDRESS *U;

    for (A = List; A; A = A->Next)
    {
        if (A->IfType != IF_TYPE_ETHERNET_CSMACD || A->PhysicalAddressLength != 6)
            continue;
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            const SOCKADDR_IN6 *S = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;

            if (S->sin6_family == AF_INET6 && S->sin6_addr.s6_addr[0] == 0xfe &&
                (S->sin6_addr.s6_addr[1] & 0xc0) == 0x80)
                return TRUE;
        }
    }
    return FALSE;
}

/* The address list, waiting up to 20 s for an Ethernet adapter's link-local address (DAD takes about a second
   after the link comes up). *Any: the list has any address at all (not even ::1 with IPv6 off). */
static IP_ADAPTER_ADDRESSES *GetList(BOOL *Any, BOOL *LinkLocalFound)
{
    IP_ADAPTER_ADDRESSES *List = NULL, *A;
    IP_ADAPTER_UNICAST_ADDRESS *U;
    ULONG Size, Error = ERROR_SUCCESS;
    int Try;

    *Any = FALSE;
    *LinkLocalFound = FALSE;
    for (Try = 0; Try < 21; Try++)
    {
        HeapFree(GetProcessHeap(), 0, List);
        Size = 64 * 1024;
        List = HeapAlloc(GetProcessHeap(), 0, Size);
        Error = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                     GAA_FLAG_SKIP_DNS_SERVER, NULL, List, &Size);
        ok(Error == ERROR_SUCCESS || Error == ERROR_NO_DATA, "GetAdaptersAddresses error %lu\n", Error);
        *Any = FALSE;
        for (A = (Error == ERROR_SUCCESS) ? List : NULL; A; A = A->Next)
        {
            for (U = A->FirstUnicastAddress; U; U = U->Next)
                *Any = TRUE;
        }
        if (!*Any)
            break;      /* IPv6 off: waiting does not help */
        if (Error == ERROR_SUCCESS && HasEthernetLinkLocal(List))
        {
            *LinkLocalFound = TRUE;
            break;
        }
        if (Try < 20)
            Sleep(1000);
    }
    if (Error != ERROR_SUCCESS)
        *Any = FALSE;
    return List;
}

START_TEST(Ipv6StableId)
{
    IP_ADAPTER_ADDRESSES *List, *A;
    IP_ADAPTER_UNICAST_ADDRESS *U;
    BOOL Randomize = ReadRandomize(), HaveSecret = FALSE, Any, LinkLocalFound;
    BYTE Secret[16];
    ULONG Checked = 0;
    WCHAR Text[64];
    DWORD TextLength;
    WSADATA Wsa;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    List = GetList(&Any, &LinkLocalFound);
    if (!Any)
    {
        /* With IPv6 off the stack has no address, not even ::1 */
        skip("no IPv6 address at all (IPv6 off)\n");
        HeapFree(GetProcessHeap(), 0, List);
        WSACleanup();
        return;
    }

    trace("RandomizeIdentifiers: %s\n", Randomize ? "on (default)" : "off");
    if (Randomize)
    {
        HaveSecret = ReadSecret(Secret);
        TestSecretDacl();
        TestSetupMarkGone();
        TestSecretDeniedToUser();
    }

    if (!LinkLocalFound)
    {
        skip("no Ethernet adapter with an IPv6 link-local address within 20 s (no network adapter or link)\n");
        HeapFree(GetProcessHeap(), 0, List);
        WSACleanup();
        return;
    }

    for (A = List; A; A = A->Next)
    {
        if (A->IfType != IF_TYPE_ETHERNET_CSMACD || A->PhysicalAddressLength != 6)
            continue;
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            const SOCKADDR_IN6 *S = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;
            const BYTE *Addr = S->sin6_addr.s6_addr;
            BOOL Eui = IsEui64(Addr + 8, A->PhysicalAddress);
            BOOL IsLinkLocal = Addr[0] == 0xfe && (Addr[1] & 0xc0) == 0x80;

            if (S->sin6_family != AF_INET6)
                continue;
            TextLength = ARRAYSIZE(Text);
            WSAAddressToStringW(U->Address.lpSockaddr, U->Address.iSockaddrLength, NULL, Text, &TextLength);
            trace("adapter %lu address %ls origins %d/%d\n", A->IfIndex, Text, U->PrefixOrigin, U->SuffixOrigin);
            Checked++;
            if (IsLinkLocal)
            {
                ok(U->PrefixOrigin == IpPrefixOriginWellKnown && U->SuffixOrigin == IpSuffixOriginLinkLayerAddress,
                   "%ls: origins %d/%d, Windows: WellKnown/Link\n", Text, U->PrefixOrigin, U->SuffixOrigin);
            }

            if (!Randomize)
            {
                ok(Eui, "%ls: RandomizeIdentifiers=0 but not the MAC's EUI-64\n", Text);
                continue;
            }
            ok(!Eui, "%ls: the identifier is the MAC's EUI-64\n", Text);
            if (HaveSecret)
            {
                BYTE Iid[8], Counter;
                BOOL Match = FALSE;

                for (Counter = 0; Counter <= 3 && !Match; Counter++)
                {
                    StableIid(Secret, Addr, A->PhysicalAddress, Counter, Iid);
                    Match = memcmp(Iid, Addr + 8, 8) == 0;
                }
                ok(Match, "%ls: not F(prefix, MAC, counter 0-3) under the stored secret\n", Text);
                if (Match && Counter != 1)
                    trace("%ls: DAD counter %u\n", Text, Counter - 1);
            }
        }
    }
    trace("%lu Ethernet addresses checked\n", Checked);

    HeapFree(GetProcessHeap(), 0, List);
    WSACleanup();
}
