/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The account database checks the caller's token against the security descriptor of the server,
 *              the domain, the user, the group or the alias when a handle is opened, and every operation checks
 *              the right it needs against what the handle was granted. A standard user can neither create
 *              accounts, nor change group memberships, nor reset another account's password.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected results (SamAccessCheck.inc) were measured on Windows Server 2022 (build 20348) with the same
 * callers (LogonUser of a scratch standard user and a scratch administrator, LocalService, NetworkService, an
 * anonymous token, a standard user's token with restricting SIDs) and the same scratch accounts. Run as an
 * administrator or LocalSystem. The scratch accounts are created and removed by the test.
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <windef.h>
#include <winbase.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>

#ifndef LOGON32_LOGON_SERVICE
#define LOGON32_LOGON_SERVICE 5
#endif
#ifndef LOGON32_LOGON_NETWORK_CLEARTEXT
#define LOGON32_LOGON_NETWORK_CLEARTEXT 8
#endif

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } US;
typedef LONG (WINAPI *F_SamConnect)(US *, PHANDLE, ACCESS_MASK, PVOID);
typedef LONG (WINAPI *F_SamOpenDomain)(HANDLE, ACCESS_MASK, PSID, PHANDLE);
typedef LONG (WINAPI *F_SamOpenObj)(HANDLE, ACCESS_MASK, ULONG, PHANDLE);
typedef LONG (WINAPI *F_SamClose)(HANDLE);
typedef LONG (WINAPI *F_SamFree)(PVOID);
typedef LONG (WINAPI *F_SamLookupDomain)(HANDLE, US *, PSID *);
typedef LONG (WINAPI *F_SamCreate)(HANDLE, US *, ACCESS_MASK, PHANDLE, PULONG);
typedef LONG (WINAPI *F_SamDelete)(HANDLE);

static F_SamConnect pSamConnect;
static F_SamOpenDomain pSamOpenDomain;
static F_SamOpenObj pSamOpenUser, pSamOpenAlias, pSamOpenGroup;
static F_SamClose pSamClose;
static F_SamLookupDomain pSamLookupDomain;
static F_SamCreate pSamCreateUser, pSamCreateAlias;
static F_SamDelete pSamDeleteUser, pSamDeleteAlias;

static const struct
{
    PCSTR Caller;
    PCSTR Probe;
    PCSTR Result;
} Expected[] =
{
#include "SamAccessCheck.inc"
};

static WCHAR g_Pw[4][16];       /* standard user, administrator, other account, target account */
static PCSTR g_Caller;
static ULONG g_Checks;

static WCHAR NStd[] = L"spt_std", NAdm[] = L"spt_adm", NOth[] = L"spt_oth", NTgt[] = L"spt_tgt", NAlias[] = L"spt_alias";

/* The probes that write or create something. A token with restricting SIDs is checked against them only: the kernel
   checks the restricting SIDs differently from Windows (it lets such a token read more), which is not about the account
   database */
static BOOL IsWriteProbe(PCSTR Probe)
{
    static const PCSTR Words[] = { "Create", "NetUserAdd", "NetUserSetInfo", "NetUserDel", "NetLocalGroupAdd", "NetLocalGroupDel",
        "NetLocalGroupSetInfo", "AddMembers", "DelMembers", "WRITE", "FORCE_PASSWORD", "DELETE", "ADD_MEMBER", "REMOVE_MEMBER",
        "ADMINISTER", "SHUTDOWN", "INITIALIZE", "GENERIC_ALL", "LsaAdd", "LsaRemove", "LsaStore", "LsaSet" };
    ULONG i;

    for (i = 0; i < sizeof(Words) / sizeof(Words[0]); i++)
        if (strstr(Probe, Words[i]))
            return TRUE;
    return FALSE;
}

/* Compares one result with the one measured on Windows for the current caller; probes without an entry are not checked */
static void Row(PCSTR Probe, PCSTR Fmt, ...)
{
    char Res[64];
    va_list Ap;
    ULONG i;

    if (!strcmp(g_Caller, "restricted") && !IsWriteProbe(Probe))
        return;

    va_start(Ap, Fmt);
    vsnprintf(Res, sizeof(Res), Fmt, Ap);
    va_end(Ap);

    for (i = 0; i < sizeof(Expected) / sizeof(Expected[0]); i++)
    {
        if (!strcmp(Expected[i].Caller, g_Caller) && !strcmp(Expected[i].Probe, Probe))
        {
            g_Checks++;
            if (!strcmp(g_Caller, "anon") && strcmp(Expected[i].Result, "0") && strcmp(Expected[i].Result, "0x00000000"))
            {
                /* An anonymous caller cannot connect: the error codes of that differ (Windows: invalid handle / 6 / 127, here
                   the status of the failed RPC bind), what counts is that nothing succeeds */
                ok(strcmp(Res, "0") && strcmp(Res, "0x00000000"), "%s: %s: succeeded, expected a failure\n", g_Caller, Probe);
                return;
            }
            ok(!strcmp(Expected[i].Result, Res), "%s: %s: %s, expected %s\n", g_Caller, Probe, Res, Expected[i].Result);
            return;
        }
    }
}

#define ROWNET(name, call) do { DWORD _r = (DWORD)(call); Row(name, "%lu", _r); } while (0)

static void MakePw(PWSTR Out, int Tag)
{
    static const WCHAR Set[] = L"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    int i;

    srand(GetTickCount() + Tag * 7919);
    for (i = 0; i < 8; i++)
        Out[i] = Set[rand() % (ARRAYSIZE(Set) - 1)];
    Out[8] = L'A'; Out[9] = L'a'; Out[10] = L'7'; Out[11] = (WCHAR)(L'0' + Tag); Out[12] = 0;
}

static void AddScratch(PCWSTR Name, PCWSTR Pw, BOOL Admin)
{
    USER_INFO_1 u;
    DWORD Pe = 0;
    LOCALGROUP_MEMBERS_INFO_3 m;
    NET_API_STATUS st;

    NetUserDel(NULL, Name);
    ZeroMemory(&u, sizeof(u));
    u.usri1_name = (PWSTR)Name;
    u.usri1_password = (PWSTR)Pw;
    u.usri1_priv = USER_PRIV_USER;
    u.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    st = NetUserAdd(NULL, 1, (PBYTE)&u, &Pe);
    ok(st == NERR_Success, "NetUserAdd(%ls) failed with %lu\n", Name, st);
    if (Admin)
    {
        m.lgrmi3_domainandname = (PWSTR)Name;
        st = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (PBYTE)&m, 1);
        ok(st == NERR_Success, "NetLocalGroupAddMembers(%ls) failed with %lu\n", Name, st);
    }
}

static void SetPw(PCWSTR Name, PCWSTR Pw)
{
    USER_INFO_1003 p;
    DWORD Pe = 0;

    p.usri1003_password = (PWSTR)Pw;
    NetUserSetInfo(NULL, Name, 1003, (PBYTE)&p, &Pe);
}

static void CleanFor(PCSTR Caller)
{
    WCHAR n[64];
    LOCALGROUP_MEMBERS_INFO_3 m;
    WCHAR dn[300];

    _snwprintf(n, 39, L"spn_%hs", Caller); NetUserDel(NULL, n);
    _snwprintf(n, 39, L"spa_%hs", Caller); NetLocalGroupDel(NULL, n);
    _snwprintf(n, 39, L"spc_%hs", Caller); NetUserDel(NULL, n);
    _snwprintf(dn, 39, L"%ls", NTgt);
    m.lgrmi3_domainandname = dn;
    NetLocalGroupDelMembers(NULL, L"Administrators", 3, (PBYTE)&m, 1);
    NetLocalGroupDelMembers(NULL, L"Users", 3, (PBYTE)&m, 1);
}

/* ---------------------------------------------------------------- the rows of one caller */

typedef struct { PCSTR Name; ACCESS_MASK Mask; } RIGHT;

#define G { "GENERIC_READ", GENERIC_READ }, { "GENERIC_WRITE", GENERIC_WRITE }, { "GENERIC_EXECUTE", GENERIC_EXECUTE }, \
          { "GENERIC_ALL", GENERIC_ALL }, { "MAXIMUM_ALLOWED", MAXIMUM_ALLOWED }

static const RIGHT SrvRights[] = {
    { "ZERO", 0 }, { "CONNECT", 1 }, { "SHUTDOWN", 2 }, { "INITIALIZE", 4 }, { "CREATE_DOMAIN", 8 },
    { "ENUMERATE_DOMAINS", 0x10 }, { "LOOKUP_DOMAIN", 0x20 }, G, { "READ_CONTROL", READ_CONTROL },
    { "WRITE_DAC", WRITE_DAC }, { "ACCESS_SYSTEM_SECURITY", ACCESS_SYSTEM_SECURITY }, { NULL, 0 } };
static const RIGHT DomRights[] = {
    { "ZERO", 0 }, { "READ_PASSWORD_PARAMETERS", 1 }, { "WRITE_PASSWORD_PARAMS", 2 }, { "READ_OTHER_PARAMETERS", 4 },
    { "WRITE_OTHER_PARAMETERS", 8 }, { "CREATE_USER", 0x10 }, { "CREATE_GROUP", 0x20 }, { "CREATE_ALIAS", 0x40 },
    { "GET_ALIAS_MEMBERSHIP", 0x80 }, { "LIST_ACCOUNTS", 0x100 }, { "LOOKUP", 0x200 }, { "ADMINISTER_SERVER", 0x400 },
    G, { "READ_CONTROL", READ_CONTROL }, { "WRITE_DAC", WRITE_DAC }, { "DELETE", DELETE }, { NULL, 0 } };
static const RIGHT UsrRights[] = {
    { "ZERO", 0 }, { "READ_GENERAL", 1 }, { "READ_PREFERENCES", 2 }, { "WRITE_PREFERENCES", 4 }, { "READ_LOGON", 8 },
    { "READ_ACCOUNT", 0x10 }, { "WRITE_ACCOUNT", 0x20 }, { "CHANGE_PASSWORD", 0x40 }, { "FORCE_PASSWORD_CHANGE", 0x80 },
    { "LIST_GROUPS", 0x100 }, { "READ_GROUP_INFORMATION", 0x200 }, { "WRITE_GROUP_INFORMATION", 0x400 }, G,
    { "READ_CONTROL", READ_CONTROL }, { "WRITE_DAC", WRITE_DAC }, { "WRITE_OWNER", WRITE_OWNER }, { "DELETE", DELETE }, { NULL, 0 } };
static const RIGHT AlsRights[] = {
    { "ZERO", 0 }, { "ADD_MEMBER", 1 }, { "REMOVE_MEMBER", 2 }, { "LIST_MEMBERS", 4 }, { "READ_INFORMATION", 8 },
    { "WRITE_ACCOUNT", 0x10 }, G, { "READ_CONTROL", READ_CONTROL }, { "WRITE_DAC", WRITE_DAC }, { "DELETE", DELETE }, { NULL, 0 } };
static const RIGHT GrpRights[] = {
    { "ZERO", 0 }, { "READ_INFORMATION", 1 }, { "WRITE_ACCOUNT", 2 }, { "ADD_MEMBER", 4 }, { "REMOVE_MEMBER", 8 },
    { "LIST_MEMBERS", 0x10 }, { "GENERIC_READ", GENERIC_READ }, { "GENERIC_ALL", GENERIC_ALL },
    { "MAXIMUM_ALLOWED", MAXIMUM_ALLOWED }, { "READ_CONTROL", READ_CONTROL }, { NULL, 0 } };

static ULONG RidOf(PCWSTR Name)
{
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof(Sid), dl = 256;
    WCHAR Dom[256];
    SID_NAME_USE Use;

    if (!LookupAccountNameW(NULL, Name, Sid, &sl, Dom, &dl, &Use))
        return 0;
    return *GetSidSubAuthority(Sid, *GetSidSubAuthorityCount(Sid) - 1);
}

static void OpenRows(PCSTR Fmt, const RIGHT *Rights, ULONG Kind, HANDLE Parent, ULONG Rid)
{
    char Name[128];
    HANDLE h;
    LONG st;
    int i;

    for (i = 0; Rights[i].Name; i++)
    {
        h = NULL;
        if (Kind == 0) st = pSamOpenUser(Parent, Rights[i].Mask, Rid, &h);
        else if (Kind == 1) st = pSamOpenAlias(Parent, Rights[i].Mask, Rid, &h);
        else st = pSamOpenGroup(Parent, Rights[i].Mask, Rid, &h);
        snprintf(Name, sizeof(Name), "%s %s", Fmt, Rights[i].Name);
        Row(Name, "0x%08lx", (unsigned long)st);
        if (st == 0) pSamClose(h);
    }
}

static void RawRows(PCWSTR Self)
{
    HANDLE Srv = NULL, Acc = NULL, Bi = NULL, h;
    PSID AccSid = NULL, BiSid = NULL;
    US Us;
    WCHAR Cn[MAX_COMPUTERNAME_LENGTH + 2];
    DWORD Cl = MAX_COMPUTERNAME_LENGTH + 1;
    char Name[128];
    LONG st;
    int i;
    ULONG Tgt = RidOf(NTgt), SelfRid = RidOf(Self), AliasRid = RidOf(NAlias);

    for (i = 0; SrvRights[i].Name; i++)
    {
        h = NULL;
        st = pSamConnect(NULL, &h, SrvRights[i].Mask, NULL);
        snprintf(Name, sizeof(Name), "SamConnect %s", SrvRights[i].Name);
        Row(Name, "0x%08lx", (unsigned long)st);
        if (st == 0) pSamClose(h);
    }

    st = pSamConnect(NULL, &Srv, MAXIMUM_ALLOWED, NULL);
    if (st != 0)
        st = pSamConnect(NULL, &Srv, 1, NULL);
    if (st != 0)
        return;

    GetComputerNameW(Cn, &Cl);
    Us.Buffer = Cn; Us.Length = (USHORT)(Cl * 2); Us.MaximumLength = Us.Length + 2;
    st = pSamLookupDomain(Srv, &Us, &AccSid);
    if (st != 0)
        AccSid = NULL;
    {
        static WCHAR Builtin[] = L"Builtin";
        Us.Buffer = Builtin; Us.Length = 14; Us.MaximumLength = 16;
        st = pSamLookupDomain(Srv, &Us, &BiSid);
        if (st != 0)
            BiSid = NULL;
    }

    if (AccSid)
    {
        for (i = 0; DomRights[i].Name; i++)
        {
            h = NULL;
            st = pSamOpenDomain(Srv, DomRights[i].Mask, AccSid, &h);
            snprintf(Name, sizeof(Name), "SamOpenDomain(Account) %s", DomRights[i].Name);
            Row(Name, "0x%08lx", (unsigned long)st);
            if (st == 0) pSamClose(h);
        }
        st = pSamOpenDomain(Srv, MAXIMUM_ALLOWED, AccSid, &Acc);
        if (st != 0)
            st = pSamOpenDomain(Srv, 0x200, AccSid, &Acc);
        if (st != 0)
            Acc = NULL;
    }
    if (BiSid)
    {
        for (i = 0; DomRights[i].Name; i++)
        {
            h = NULL;
            st = pSamOpenDomain(Srv, DomRights[i].Mask, BiSid, &h);
            snprintf(Name, sizeof(Name), "SamOpenDomain(Builtin) %s", DomRights[i].Name);
            Row(Name, "0x%08lx", (unsigned long)st);
            if (st == 0) pSamClose(h);
        }
        st = pSamOpenDomain(Srv, MAXIMUM_ALLOWED, BiSid, &Bi);
        if (st != 0)
            st = pSamOpenDomain(Srv, 0x200, BiSid, &Bi);
        if (st != 0)
            Bi = NULL;
    }

    if (Acc)
    {
        ULONG Nr;
        HANDLE Nh;
        WCHAR Cn2[40];

        OpenRows("SamOpenUser Administrator(500)", UsrRights, 0, Acc, 500);
        if (Tgt) OpenRows("SamOpenUser target", UsrRights, 0, Acc, Tgt);
        if (SelfRid) OpenRows("SamOpenUser self", UsrRights, 0, Acc, SelfRid);
        OpenRows("SamOpenGroup None(513)", GrpRights, 2, Acc, 513);
        if (AliasRid) OpenRows("SamOpenAlias scratch", AlsRights, 1, Acc, AliasRid);

        _snwprintf(Cn2, 39, L"spc_%hs", g_Caller);
        Us.Buffer = Cn2; Us.Length = (USHORT)(wcslen(Cn2) * 2); Us.MaximumLength = Us.Length + 2;
        st = pSamCreateUser(Acc, &Us, 0x000F07FF, &Nh, &Nr);
        Row("SamCreateUserInDomain", "0x%08lx", (unsigned long)st);
        if (st == 0) pSamDeleteUser(Nh);
        _snwprintf(Cn2, 39, L"spa_%hs", g_Caller);
        Us.Buffer = Cn2; Us.Length = (USHORT)(wcslen(Cn2) * 2); Us.MaximumLength = Us.Length + 2;
        st = pSamCreateAlias(Acc, &Us, 0x000F001F, &Nh, &Nr);
        Row("SamCreateAliasInDomain", "0x%08lx", (unsigned long)st);
        if (st == 0) pSamDeleteAlias(Nh);
        pSamClose(Acc);
    }
    if (Bi)
    {
        OpenRows("SamOpenAlias Administrators(544)", AlsRights, 1, Bi, 544);
        OpenRows("SamOpenAlias Users(545)", AlsRights, 1, Bi, 545);
        pSamClose(Bi);
    }
    pSamClose(Srv);
}

/*
 * Methods that act on more than the handle they are given, as a standard user (the expected codes were measured on Windows
 * Server 2022 with the same calls): removing an administrator account from every alias of the Builtin domain, the logon
 * statistics and all the fields of a user through a handle opened for no access, and a user handle that is used after the
 * handle of its domain has been closed.
 */
typedef LONG (WINAPI *F_SamRemoveForeign)(HANDLE, PSID);
typedef LONG (WINAPI *F_SamQueryUser)(HANDLE, ULONG, PVOID *);
typedef LONG (WINAPI *F_SamFreeMemory)(PVOID);
static F_SamRemoveForeign pSamRemoveForeign;
static F_SamQueryUser pSamQueryUser;
static F_SamFreeMemory pSamFreeMemory;

static BOOL IsAdministratorsMember(PCWSTR Name)
{
    LOCALGROUP_MEMBERS_INFO_3 *m = NULL;
    DWORD n = 0, t = 0, i;
    BOOL Found = FALSE;
    WCHAR Cn[MAX_COMPUTERNAME_LENGTH + 2], Full[300];
    DWORD Cl = MAX_COMPUTERNAME_LENGTH + 1;

    GetComputerNameW(Cn, &Cl);
    _snwprintf(Full, ARRAYSIZE(Full) - 1, L"%ls\\%ls", Cn, Name);
    Full[ARRAYSIZE(Full) - 1] = 0;
    if (NetLocalGroupGetMembers(NULL, L"Administrators", 3, (LPBYTE *)&m, MAX_PREFERRED_LENGTH, &n, &t, NULL) != NERR_Success)
        return FALSE;
    for (i = 0; i < n; i++)
        if (!_wcsicmp(m[i].lgrmi3_domainandname, Full))
            Found = TRUE;
    NetApiBufferFree(m);
    return Found;
}

static void ReviewRows(PCWSTR Self)
{
    HANDLE Srv = NULL, Acc = NULL, Bi = NULL, u = NULL;
    PSID AccSid = NULL, BiSid = NULL;
    BYTE AdmSid[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof(AdmSid), dl = 256;
    WCHAR Dom[256], Cn[MAX_COMPUTERNAME_LENGTH + 2];
    DWORD Cl = MAX_COMPUTERNAME_LENGTH + 1;
    static WCHAR Builtin[] = L"Builtin";
    SID_NAME_USE Use;
    PVOID Buf;
    US Us;
    LONG st;
    ULONG AdmRid, SelfRid = RidOf(Self);

    if (!pSamRemoveForeign || !pSamQueryUser || !LookupAccountNameW(NULL, NAdm, AdmSid, &sl, Dom, &dl, &Use))
    {
        skip("%s: review rows not run\n", g_Caller);
        return;
    }
    AdmRid = *GetSidSubAuthority(AdmSid, *GetSidSubAuthorityCount(AdmSid) - 1);

    if (pSamConnect(NULL, &Srv, 0x21, NULL) != 0)
        return;
    GetComputerNameW(Cn, &Cl);
    Us.Buffer = Cn; Us.Length = (USHORT)(Cl * 2); Us.MaximumLength = Us.Length + 2;
    if (pSamLookupDomain(Srv, &Us, &AccSid) != 0)
        AccSid = NULL;
    Us.Buffer = Builtin; Us.Length = 14; Us.MaximumLength = 16;
    if (pSamLookupDomain(Srv, &Us, &BiSid) != 0)
        BiSid = NULL;

    if (BiSid && pSamOpenDomain(Srv, 0x200, BiSid, &Bi) == 0)
    {
        st = pSamRemoveForeign(Bi, (PSID)AdmSid);
        Row("SamRemoveMemberFromForeignDomain(Builtin) administrator account", "0x%08lx", (unsigned long)st);
        pSamClose(Bi);
    }
    if (AccSid && pSamOpenDomain(Srv, 0x200, AccSid, &Acc) == 0)
    {
        st = pSamRemoveForeign(Acc, (PSID)AdmSid);
        Row("SamRemoveMemberFromForeignDomain(Account) administrator account", "0x%08lx", (unsigned long)st);

        if (pSamOpenUser(Acc, 0, AdmRid, &u) == 0)
        {
            Buf = NULL;
            st = pSamQueryUser(u, 19 /* UserInternal2Information */, &Buf);
            Row("SamQueryInformationUser no-access handle UserInternal2Information", "0x%08lx", (unsigned long)st);
            if (Buf && pSamFreeMemory) pSamFreeMemory(Buf);
            Buf = NULL;
            st = pSamQueryUser(u, 21 /* UserAllInformation */, &Buf);
            Row("SamQueryInformationUser no-access handle UserAllInformation", "0x%08lx", (unsigned long)st);
            if (Buf && pSamFreeMemory) pSamFreeMemory(Buf);
            pSamClose(u);
        }

        /* The user handle outlives the handle of its domain (contract: it keeps working) */
        u = NULL;
        if (SelfRid && pSamOpenUser(Acc, 1 /* USER_READ_GENERAL */, SelfRid, &u) == 0)
        {
            pSamClose(Acc);
            Acc = NULL;
            Buf = NULL;
            st = pSamQueryUser(u, 1 /* UserGeneralInformation */, &Buf);
            ok(st == 0, "%s: user handle after the domain handle was closed: 0x%08lx\n", g_Caller, (unsigned long)st);
            if (Buf && pSamFreeMemory) pSamFreeMemory(Buf);
            pSamClose(u);
        }
        if (Acc)
            pSamClose(Acc);
    }
    pSamClose(Srv);

    ok(IsAdministratorsMember(NAdm), "%s: the administrator account was removed from Administrators\n", g_Caller);
}

static void NetRows(PCWSTR Self, PCWSTR SelfPw, PCWSTR TgtPw)
{
    static const DWORD Levels[] = { 0, 1, 2, 3, 4, 10, 11, 20, 23 };
    static const DWORD EnumLevels[] = { 0, 1, 2, 3, 10, 20 };
    PCWSTR Who[3];
    static const char *WhoName[3] = { "self", "target", "Administrator" };
    PBYTE Buf;
    DWORD Er, Tot, i, w, Pe = 0;
    char Name[128];
    WCHAR Mn[64], An[64], Dn[300];

    Who[0] = Self; Who[1] = NTgt; Who[2] = L"Administrator";

    for (w = 0; w < 3; w++)
    {
        for (i = 0; i < ARRAYSIZE(Levels); i++)
        {
            Buf = NULL;
            snprintf(Name, sizeof(Name), "NetUserGetInfo %s L%lu", WhoName[w], Levels[i]);
            ROWNET(Name, NetUserGetInfo(NULL, Who[w], Levels[i], &Buf));
            if (Buf) NetApiBufferFree(Buf);
        }
    }
    for (i = 0; i < ARRAYSIZE(EnumLevels); i++)
    {
        Buf = NULL; Er = Tot = 0;
        snprintf(Name, sizeof(Name), "NetUserEnum L%lu", EnumLevels[i]);
        ROWNET(Name, NetUserEnum(NULL, EnumLevels[i], 0, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot, NULL));
        if (Buf) NetApiBufferFree(Buf);
    }
    for (w = 0; w < 2; w++)
    {
        Buf = NULL; Er = Tot = 0;
        snprintf(Name, sizeof(Name), "NetUserGetGroups %s", WhoName[w]);
        ROWNET(Name, NetUserGetGroups(NULL, Who[w], 0, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot));
        if (Buf) NetApiBufferFree(Buf);
        Buf = NULL; Er = Tot = 0;
        snprintf(Name, sizeof(Name), "NetUserGetLocalGroups %s", WhoName[w]);
        ROWNET(Name, NetUserGetLocalGroups(NULL, Who[w], 0, 0, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot));
        if (Buf) NetApiBufferFree(Buf);
    }
    for (i = 0; i < 4; i++)
    {
        Buf = NULL;
        snprintf(Name, sizeof(Name), "NetUserModalsGet L%lu", i);
        ROWNET(Name, NetUserModalsGet(NULL, i, &Buf));
        if (Buf) NetApiBufferFree(Buf);
    }
    for (i = 1; i <= 3; i++)
    {
        PVOID p = NULL;
        DWORD Cnt = 0;

        snprintf(Name, sizeof(Name), "NetQueryDisplayInformation L%lu", i);
        ROWNET(Name, NetQueryDisplayInformation(NULL, i, 0, 100, MAX_PREFERRED_LENGTH, &Cnt, &p));
        if (p) NetApiBufferFree(p);
    }
    Buf = NULL; Er = Tot = 0;
    ROWNET("NetLocalGroupEnum L0", NetLocalGroupEnum(NULL, 0, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot, NULL)); if (Buf) NetApiBufferFree(Buf);
    Buf = NULL; ROWNET("NetLocalGroupEnum L1", NetLocalGroupEnum(NULL, 1, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot, NULL)); if (Buf) NetApiBufferFree(Buf);
    Buf = NULL; ROWNET("NetLocalGroupGetInfo scratch L1", NetLocalGroupGetInfo(NULL, NAlias, 1, &Buf)); if (Buf) NetApiBufferFree(Buf);
    Buf = NULL; ROWNET("NetLocalGroupGetInfo Administrators L1", NetLocalGroupGetInfo(NULL, L"Administrators", 1, &Buf)); if (Buf) NetApiBufferFree(Buf);
    Buf = NULL; ROWNET("NetLocalGroupGetMembers scratch L1", NetLocalGroupGetMembers(NULL, NAlias, 1, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot, NULL)); if (Buf) NetApiBufferFree(Buf);
    Buf = NULL; ROWNET("NetLocalGroupGetMembers Administrators L1", NetLocalGroupGetMembers(NULL, L"Administrators", 1, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot, NULL)); if (Buf) NetApiBufferFree(Buf);
    Buf = NULL; ROWNET("NetLocalGroupGetMembers Users L1", NetLocalGroupGetMembers(NULL, L"Users", 1, &Buf, MAX_PREFERRED_LENGTH, &Er, &Tot, NULL)); if (Buf) NetApiBufferFree(Buf);

    {
        BYTE Sid[SECURITY_MAX_SID_SIZE];
        DWORD sl, dl;
        WCHAR Dom[256];
        SID_NAME_USE Use;
        BOOL b;

        sl = sizeof(Sid); dl = 256; b = LookupAccountNameW(NULL, L"Administrator", Sid, &sl, Dom, &dl, &Use);
        Row("LookupAccountName Administrator", "%lu", b ? 0 : GetLastError());
        sl = sizeof(Sid); dl = 256; b = LookupAccountNameW(NULL, L"BUILTIN\\Administrators", Sid, &sl, Dom, &dl, &Use);
        Row("LookupAccountName BUILTIN\\Administrators", "%lu", b ? 0 : GetLastError());
        sl = sizeof(Sid); dl = 256; b = LookupAccountNameW(NULL, L"Everyone", Sid, &sl, Dom, &dl, &Use);
        Row("LookupAccountName Everyone", "%lu", b ? 0 : GetLastError());
        sl = sizeof(Sid); dl = 256; b = LookupAccountNameW(NULL, L"NT AUTHORITY\\SYSTEM", Sid, &sl, Dom, &dl, &Use);
        Row("LookupAccountName NT AUTHORITY\\SYSTEM", "%lu", b ? 0 : GetLastError());
        sl = sizeof(Sid); dl = 256; b = LookupAccountNameW(NULL, NTgt, Sid, &sl, Dom, &dl, &Use);
        Row("LookupAccountName target", "%lu", b ? 0 : GetLastError());
    }

    /* writes */
    _snwprintf(Mn, 39, L"spn_%hs", g_Caller);
    {
        USER_INFO_1 u;
        USER_INFO_1003 p3;
        USER_INFO_1011 fn;
        USER_INFO_1007 cm;
        USER_INFO_1008 fl;
        USER_INFO_1003 ps, pt;

        ZeroMemory(&u, sizeof(u));
        u.usri1_name = Mn; u.usri1_password = L"Zz9!NewPw1x"; u.usri1_priv = USER_PRIV_USER; u.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        ROWNET("NetUserAdd L1", NetUserAdd(NULL, 1, (PBYTE)&u, &Pe));
        ROWNET("NetUserDel (own new)", NetUserDel(NULL, Mn));

        p3.usri1003_password = L"Zz9!NewPw1x"; fn.usri1011_full_name = L"sp full name"; cm.usri1007_comment = L"sp comment";
        fl.usri1008_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        for (w = 0; w < 2; w++)
        {
            snprintf(Name, sizeof(Name), "NetUserSetInfo %s L1003 (reset password)", WhoName[w]); ROWNET(Name, NetUserSetInfo(NULL, Who[w], 1003, (PBYTE)&p3, &Pe));
            snprintf(Name, sizeof(Name), "NetUserSetInfo %s L1011 (full name)", WhoName[w]); ROWNET(Name, NetUserSetInfo(NULL, Who[w], 1011, (PBYTE)&fn, &Pe));
            snprintf(Name, sizeof(Name), "NetUserSetInfo %s L1007 (comment)", WhoName[w]); ROWNET(Name, NetUserSetInfo(NULL, Who[w], 1007, (PBYTE)&cm, &Pe));
            snprintf(Name, sizeof(Name), "NetUserSetInfo %s L1008 (flags)", WhoName[w]); ROWNET(Name, NetUserSetInfo(NULL, Who[w], 1008, (PBYTE)&fl, &Pe));
        }
        /* put the known passwords back (the callers that may reset them did) */
        ps.usri1003_password = (PWSTR)SelfPw; pt.usri1003_password = (PWSTR)TgtPw;
        NetUserSetInfo(NULL, Self, 1003, (PBYTE)&ps, &Pe);
        NetUserSetInfo(NULL, NTgt, 1003, (PBYTE)&pt, &Pe);
    }
    ROWNET("NetUserChangePassword self (old password known)", NetUserChangePassword(NULL, Self, SelfPw, L"Zz9!NewPw1x"));
    ROWNET("NetUserChangePassword self back", NetUserChangePassword(NULL, Self, L"Zz9!NewPw1x", SelfPw));
    ROWNET("NetUserChangePassword target (old password known)", NetUserChangePassword(NULL, NTgt, TgtPw, L"Zz9!NewPw1x"));
    ROWNET("NetUserChangePassword self (wrong old password)", NetUserChangePassword(NULL, Self, L"wrongOld#1x", L"Zz9!NewPw1x"));

    {
        LOCALGROUP_INFO_1 g1;
        LOCALGROUP_INFO_1002 c2;
        LOCALGROUP_MEMBERS_INFO_3 m3;
        WCHAR Cn[MAX_COMPUTERNAME_LENGTH + 2];
        DWORD Cl = MAX_COMPUTERNAME_LENGTH + 1;

        _snwprintf(An, 39, L"spa_%hs", g_Caller);
        g1.lgrpi1_name = An; g1.lgrpi1_comment = L"sp";
        ROWNET("NetLocalGroupAdd L1", NetLocalGroupAdd(NULL, 1, (PBYTE)&g1, &Pe));
        ROWNET("NetLocalGroupDel (own new)", NetLocalGroupDel(NULL, An));
        c2.lgrpi1002_comment = L"sp group comment";
        ROWNET("NetLocalGroupSetInfo scratch L1002", NetLocalGroupSetInfo(NULL, NAlias, 1002, (PBYTE)&c2, &Pe));
        GetComputerNameW(Cn, &Cl);
        _snwprintf(Dn, 39, L"%ls\\%ls", Cn, NTgt);
        m3.lgrmi3_domainandname = Dn;
        ROWNET("NetLocalGroupAddMembers scratch (target)", NetLocalGroupAddMembers(NULL, NAlias, 3, (PBYTE)&m3, 1));
        ROWNET("NetLocalGroupDelMembers scratch (target)", NetLocalGroupDelMembers(NULL, NAlias, 3, (PBYTE)&m3, 1));
        ROWNET("NetLocalGroupAddMembers Administrators (target)", NetLocalGroupAddMembers(NULL, L"Administrators", 3, (PBYTE)&m3, 1));
        ROWNET("NetLocalGroupDelMembers Administrators (target)", NetLocalGroupDelMembers(NULL, L"Administrators", 3, (PBYTE)&m3, 1));
        ROWNET("NetLocalGroupAddMembers Users (target)", NetLocalGroupAddMembers(NULL, L"Users", 3, (PBYTE)&m3, 1));
        ROWNET("NetLocalGroupDelMembers Users (target)", NetLocalGroupDelMembers(NULL, L"Users", 3, (PBYTE)&m3, 1));
    }
}

/* May the caller create another instance of the pipe of a system RPC server? (Clients would connect to it and hand the caller their calls.)
   Not asked of the administrator: if the answer is yes it would put a rogue instance there for a moment. */
static void PipeRows(void)
{
    /* The pipes of the servers that run on NitroOS (a name without a server is simply created by whoever asks, here as on Windows) */
    static const PCSTR Names[] = { "samr", "lsarpc", "wkssvc", "srvsvc", "ntsvcs", "atsvc", "eventlog", "epmapper" };
    char Name[96], Path[128];
    HANDLE h;
    ULONG i;

    if (!strcmp(g_Caller, "admin"))
        return;
    for (i = 0; i < sizeof(Names) / sizeof(Names[0]); i++)
    {
        snprintf(Path, sizeof(Path), "\\\\.\\pipe\\%s", Names[i]);
        h = CreateNamedPipeA(Path, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 255, 512, 512, 0, NULL);
        snprintf(Name, sizeof(Name), "CreateNamedPipe %s (another instance)", Names[i]);
        if (h == INVALID_HANDLE_VALUE)
        {
            Row(Name, "%lu", GetLastError());
        }
        else
        {
            CloseHandle(h);
            Row(Name, "0");
        }
    }
}

/* ---------------------------------------------------------------- the policy of the LSA */

static const RIGHT PolRights[] = {
    { "VIEW_LOCAL_INFORMATION", 1 }, { "VIEW_AUDIT_INFORMATION", 2 }, { "GET_PRIVATE_INFORMATION", 4 }, { "TRUST_ADMIN", 8 },
    { "CREATE_ACCOUNT", 0x10 }, { "CREATE_SECRET", 0x20 }, { "CREATE_PRIVILEGE", 0x40 }, { "SET_DEFAULT_QUOTA_LIMITS", 0x80 },
    { "SET_AUDIT_REQUIREMENTS", 0x100 }, { "AUDIT_LOG_ADMIN", 0x200 }, { "SERVER_ADMIN", 0x400 }, { "LOOKUP_NAMES", 0x800 },
    { "GENERIC_READ", GENERIC_READ }, { "GENERIC_WRITE", GENERIC_WRITE }, { "GENERIC_EXECUTE", GENERIC_EXECUTE },
    { "GENERIC_ALL", GENERIC_ALL }, { "MAXIMUM_ALLOWED", MAXIMUM_ALLOWED }, { "READ_CONTROL", READ_CONTROL },
    { "WRITE_DAC", WRITE_DAC }, { NULL, 0 } };

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } LSAUS;
typedef struct { ULONG Length; HANDLE RootDirectory; PVOID ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } LSAOA;
typedef LONG (WINAPI *F_LsaOpenPolicy)(LSAUS *, LSAOA *, ACCESS_MASK, PHANDLE);
typedef LONG (WINAPI *F_LsaClose)(HANDLE);
typedef LONG (WINAPI *F_LsaRights)(HANDLE, PSID, LSAUS *, ULONG);
typedef LONG (WINAPI *F_LsaRemoveRights)(HANDLE, PSID, BOOLEAN, LSAUS *, ULONG);
typedef LONG (WINAPI *F_LsaEnumRights)(HANDLE, PSID, LSAUS **, PULONG);
typedef LONG (WINAPI *F_LsaEnumWithRight)(HANDLE, LSAUS *, PVOID *, PULONG);
typedef LONG (WINAPI *F_LsaStore)(HANDLE, LSAUS *, LSAUS *);
typedef LONG (WINAPI *F_LsaQueryPol)(HANDLE, ULONG, PVOID *);
typedef LONG (WINAPI *F_LsaSetPol)(HANDLE, ULONG, PVOID);
typedef LONG (WINAPI *F_LsaFree)(PVOID);

static void LsaRows(void)
{
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    F_LsaOpenPolicy pOpen = (F_LsaOpenPolicy)GetProcAddress(hAdv, "LsaOpenPolicy");
    F_LsaClose pClose = (F_LsaClose)GetProcAddress(hAdv, "LsaClose");
    F_LsaRights pAdd = (F_LsaRights)GetProcAddress(hAdv, "LsaAddAccountRights");
    F_LsaRemoveRights pRemove = (F_LsaRemoveRights)GetProcAddress(hAdv, "LsaRemoveAccountRights");
    F_LsaEnumRights pEnum = (F_LsaEnumRights)GetProcAddress(hAdv, "LsaEnumerateAccountRights");
    F_LsaEnumWithRight pEnumWith = (F_LsaEnumWithRight)GetProcAddress(hAdv, "LsaEnumerateAccountsWithUserRight");
    F_LsaStore pStore = (F_LsaStore)GetProcAddress(hAdv, "LsaStorePrivateData");
    F_LsaQueryPol pQuery = (F_LsaQueryPol)GetProcAddress(hAdv, "LsaQueryInformationPolicy");
    F_LsaSetPol pSet = (F_LsaSetPol)GetProcAddress(hAdv, "LsaSetInformationPolicy");
    F_LsaFree pFree = (F_LsaFree)GetProcAddress(hAdv, "LsaFreeMemory");
    LSAOA oa;
    HANDLE h = NULL;
    LONG st;
    char Name[128];
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof(Sid), dl = 256;
    WCHAR Dom[256];
    SID_NAME_USE Use;
    LSAUS r1, r2, Key, Data;
    WCHAR Kn[] = L"SPSEC_USERHANDLE", Dt[] = L"sp-value";
    PVOID q;
    int i;

    if (!pOpen || !pClose || !pAdd || !pRemove || !pEnum || !pEnumWith || !pStore || !pQuery || !pSet || !pFree)
        return;
    if (!LookupAccountNameW(NULL, NTgt, Sid, &sl, Dom, &dl, &Use))
        return;

    for (i = 0; PolRights[i].Name; i++)
    {
        ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa); h = NULL;
        st = pOpen(NULL, &oa, PolRights[i].Mask, &h);
        snprintf(Name, sizeof(Name), "LsaOpenPolicy %s", PolRights[i].Name);
        Row(Name, "0x%08lx", (unsigned long)st);
        if (st == 0) pClose(h);
    }
    ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa); h = NULL;
    st = pOpen(NULL, &oa, 0, &h);
    Row("LsaOpenPolicy ZERO", "0x%08lx", (unsigned long)st);
    if (st == 0) pClose(h);

    /* what a caller can do with the handle that every user can open */
    ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa); h = NULL;
    st = pOpen(NULL, &oa, 0x800 | 1, &h);
    Row("LsaOpenPolicy LOOKUP_NAMES+VIEW_LOCAL (the handle of the rows below)", "0x%08lx", (unsigned long)st);
    if (st == 0)
    {
        WCHAR Sv[] = L"SeServiceLogonRight", Ba[] = L"SeBatchLogonRight";
        LSAUS *Rr = NULL;
        ULONG Cnt = 0;

        r1.Buffer = Sv; r1.Length = 19 * 2; r1.MaximumLength = r1.Length + 2;
        r2.Buffer = Ba; r2.Length = 17 * 2; r2.MaximumLength = r2.Length + 2;
        st = pAdd(h, (PSID)Sid, &r1, 1);
        Row("LsaAddAccountRights (user handle) SeServiceLogonRight to target", "0x%08lx", (unsigned long)st);
        pRemove(h, (PSID)Sid, FALSE, &r1, 1);
        st = pRemove(h, (PSID)Sid, FALSE, &r2, 1);
        Row("LsaRemoveAccountRights (user handle) SeBatchLogonRight from target", "0x%08lx", (unsigned long)st);
        st = pEnum(h, (PSID)Sid, &Rr, &Cnt);
        Row("LsaEnumerateAccountRights (user handle) target", "0x%08lx", (unsigned long)st);
        if (Rr) pFree(Rr);
        Key.Buffer = Kn; Key.Length = (USHORT)(wcslen(Kn) * 2); Key.MaximumLength = Key.Length + 2;
        Data.Buffer = Dt; Data.Length = (USHORT)(wcslen(Dt) * 2); Data.MaximumLength = Data.Length + 2;
        st = pStore(h, &Key, &Data);
        Row("LsaStorePrivateData (user handle)", "0x%08lx", (unsigned long)st);
        if (st == 0) pStore(h, &Key, NULL);
        q = NULL;
        st = pQuery(h, 8, &q);
        Row("LsaQueryInformationPolicy DefaultQuota (user handle)", "0x%08lx", (unsigned long)st);
        if (st == 0 && q)
        {
            st = pSet(h, 8, q);
            Row("LsaSetInformationPolicy DefaultQuota (user handle)", "0x%08lx", (unsigned long)st);
            pFree(q);
        }
        pClose(h);
    }
    {
        WCHAR Ba[] = L"SeInteractiveLogonRight";
        PVOID Acc = NULL;
        ULONG Cnt = 0;

        ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa); h = NULL;
        st = pOpen(NULL, &oa, 0x800 | 1, &h);
        if (st == 0)
        {
            r1.Buffer = Ba; r1.Length = 23 * 2; r1.MaximumLength = r1.Length + 2;
            st = pEnumWith(h, &r1, &Acc, &Cnt);
            Row("LsaEnumerateAccountsWithUserRight SeInteractiveLogonRight", "0x%08lx", (unsigned long)st);
            if (Acc) pFree(Acc);
            pClose(h);
        }
    }
}

/* The state that LsaRows expects: the target holds SeBatchLogonRight and not SeServiceLogonRight (done as the test's own caller) */
static void LsaReset(void)
{
    HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
    F_LsaOpenPolicy pOpen = (F_LsaOpenPolicy)GetProcAddress(hAdv, "LsaOpenPolicy");
    F_LsaClose pClose = (F_LsaClose)GetProcAddress(hAdv, "LsaClose");
    F_LsaRights pAdd = (F_LsaRights)GetProcAddress(hAdv, "LsaAddAccountRights");
    F_LsaRemoveRights pRemove = (F_LsaRemoveRights)GetProcAddress(hAdv, "LsaRemoveAccountRights");
    LSAOA oa;
    HANDLE h = NULL;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof(Sid), dl = 256;
    WCHAR Dom[256], Ba[] = L"SeBatchLogonRight", Sv[] = L"SeServiceLogonRight";
    SID_NAME_USE Use;
    LSAUS r1, r2;

    if (!pOpen || !pClose || !pAdd || !pRemove || !LookupAccountNameW(NULL, NTgt, Sid, &sl, Dom, &dl, &Use))
        return;
    ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa);
    if (pOpen(NULL, &oa, 0x1fff | 0xf0000, &h) != 0)
        return;
    r1.Buffer = Ba; r1.Length = 17 * 2; r1.MaximumLength = r1.Length + 2;
    r2.Buffer = Sv; r2.Length = 19 * 2; r2.MaximumLength = r2.Length + 2;
    pRemove(h, (PSID)Sid, FALSE, &r2, 1);
    pAdd(h, (PSID)Sid, &r1, 1);
    pClose(h);
}

/* ---------------------------------------------------------------- callers */

static HANDLE CallerToken(PCSTR Caller, PBOOL Anonymous)
{
    HANDLE Token = NULL, Self = NULL, Restricted = NULL;
    SID_AND_ATTRIBUTES Sa[2];
    BYTE Sid1[SECURITY_MAX_SID_SIZE], Sid2[SECURITY_MAX_SID_SIZE];
    DWORD Len1 = sizeof(Sid1), Len2 = sizeof(Sid2);

    *Anonymous = FALSE;
    if (!strcmp(Caller, "anon"))
    {
        *Anonymous = TRUE;
        return INVALID_HANDLE_VALUE;
    }
    if (!strcmp(Caller, "std"))
        LogonUserW(NStd, L".", g_Pw[0], LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "stdnet"))
    {
        if (!LogonUserW(NStd, L".", g_Pw[0], LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token))
            LogonUserW(NStd, L".", g_Pw[0], LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, &Token);
    }
    else if (!strcmp(Caller, "admin"))
        LogonUserW(NAdm, L".", g_Pw[1], LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "localservice"))
        LogonUserW(L"LocalService", L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "networkservice"))
        LogonUserW(L"NetworkService", L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    else if (!strcmp(Caller, "restricted"))
    {
        if (LogonUserW(NStd, L".", g_Pw[0], LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Self))
        {
            CreateWellKnownSid(WinWorldSid, NULL, Sid1, &Len1);
            CreateWellKnownSid(WinBuiltinUsersSid, NULL, Sid2, &Len2);
            Sa[0].Sid = Sid1; Sa[0].Attributes = 0;
            Sa[1].Sid = Sid2; Sa[1].Attributes = 0;
            if (CreateRestrictedToken(Self, 0, 0, NULL, 0, NULL, 2, Sa, &Restricted))
                Token = Restricted;
            CloseHandle(Self);
        }
    }
    return Token;
}

static void RunCaller(PCSTR Caller, PCWSTR Self, PCWSTR SelfPw)
{
    BOOL Anonymous;
    HANDLE Token = CallerToken(Caller, &Anonymous);
    BOOL Entered;

    if (!Anonymous && Token == NULL)
    {
        skip("%s: no token (LogonUser failed with %lu)\n", Caller, GetLastError());
        return;
    }

    /* The same state for every caller */
    SetPw(NStd, g_Pw[0]); SetPw(NAdm, g_Pw[1]); SetPw(NOth, g_Pw[2]); SetPw(NTgt, g_Pw[3]);
    CleanFor(Caller);
    LsaReset();

    g_Caller = Caller;
    if (Anonymous)
        Entered = ImpersonateAnonymousToken(GetCurrentThread());
    else
        Entered = ImpersonateLoggedOnUser(Token);
    ok(Entered, "%s: impersonation failed with %lu\n", Caller, GetLastError());
    if (Entered && !strcmp(Caller, "restricted"))
    {
        /* A token with restricting SIDs cannot bind to the pipe of the account database here (it can on Windows): not a
           question of access to the account database, and not tested then */
        HANDLE h = NULL;
        LONG st = pSamConnect(NULL, &h, 1, NULL);

        if (st == 0)
            pSamClose(h);
        else
        {
            skip("restricted: SamConnect failed with 0x%08lx: tokens with restricting SIDs cannot connect\n", (unsigned long)st);
            RevertToSelf();
            Entered = FALSE;
        }
    }
    if (Entered)
    {
        PipeRows();
        RawRows(Self);
        if (!strcmp(Caller, "std"))
            ReviewRows(Self);
        NetRows(Self, SelfPw, g_Pw[3]);
        LsaRows();
        RevertToSelf();
    }
    if (!Anonymous)
        CloseHandle(Token);
    CleanFor(Caller);
}

START_TEST(SamAccessCheck)
{
    HMODULE hSam = LoadLibraryW(L"samlib.dll");
    LOCALGROUP_INFO_1 g = { L"spt_alias", L"sp" };
    DWORD Pe;
    HANDLE Tok;
    TOKEN_ELEVATION_TYPE et;
    BOOL Admin;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD Len = sizeof(Sid);
    int i;

    if (!hSam)
    {
        skip("samlib.dll not available\n");
        return;
    }
    pSamConnect = (F_SamConnect)GetProcAddress(hSam, "SamConnect");
    pSamOpenDomain = (F_SamOpenDomain)GetProcAddress(hSam, "SamOpenDomain");
    pSamOpenUser = (F_SamOpenObj)GetProcAddress(hSam, "SamOpenUser");
    pSamOpenAlias = (F_SamOpenObj)GetProcAddress(hSam, "SamOpenAlias");
    pSamOpenGroup = (F_SamOpenObj)GetProcAddress(hSam, "SamOpenGroup");
    pSamClose = (F_SamClose)GetProcAddress(hSam, "SamCloseHandle");
    pSamLookupDomain = (F_SamLookupDomain)GetProcAddress(hSam, "SamLookupDomainInSamServer");
    pSamCreateUser = (F_SamCreate)GetProcAddress(hSam, "SamCreateUserInDomain");
    pSamCreateAlias = (F_SamCreate)GetProcAddress(hSam, "SamCreateAliasInDomain");
    pSamDeleteUser = (F_SamDelete)GetProcAddress(hSam, "SamDeleteUser");
    pSamDeleteAlias = (F_SamDelete)GetProcAddress(hSam, "SamDeleteAlias");
    pSamRemoveForeign = (F_SamRemoveForeign)GetProcAddress(hSam, "SamRemoveMemberFromForeignDomain");
    pSamQueryUser = (F_SamQueryUser)GetProcAddress(hSam, "SamQueryInformationUser");
    pSamFreeMemory = (F_SamFreeMemory)GetProcAddress(hSam, "SamFreeMemory");
    if (!pSamConnect || !pSamOpenDomain || !pSamOpenUser || !pSamOpenAlias || !pSamOpenGroup || !pSamClose || !pSamLookupDomain ||
        !pSamCreateUser || !pSamCreateAlias || !pSamDeleteUser || !pSamDeleteAlias)
    {
        skip("samlib.dll lacks an entry point\n");
        return;
    }

    /* The scratch accounts need an administrator or LocalSystem */
    Admin = FALSE;
    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Sid, &Len) && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Tok))
    {
        CheckTokenMembership(NULL, Sid, &Admin);
        CloseHandle(Tok);
    }
    (void)et;
    if (!Admin)
    {
        skip("must run as an administrator\n");
        return;
    }

    for (i = 0; i < 4; i++)
        MakePw(g_Pw[i], i);
    AddScratch(NStd, g_Pw[0], FALSE);
    AddScratch(NAdm, g_Pw[1], TRUE);
    AddScratch(NOth, g_Pw[2], FALSE);
    AddScratch(NTgt, g_Pw[3], FALSE);
    NetLocalGroupDel(NULL, NAlias);
    ok(NetLocalGroupAdd(NULL, 1, (PBYTE)&g, &Pe) == NERR_Success, "NetLocalGroupAdd failed\n");

    RunCaller("admin", NAdm, g_Pw[1]);
    RunCaller("std", NStd, g_Pw[0]);
    RunCaller("stdnet", NStd, g_Pw[0]);
    RunCaller("restricted", NStd, g_Pw[0]);
    RunCaller("localservice", NOth, g_Pw[2]);
    RunCaller("networkservice", NOth, g_Pw[2]);
    RunCaller("anon", NOth, g_Pw[2]);

    trace("%lu rows compared with the measurements\n", g_Checks);
    ok(g_Checks > 500, "only %lu rows were compared\n", g_Checks);

    NetUserDel(NULL, NStd); NetUserDel(NULL, NAdm); NetUserDel(NULL, NOth); NetUserDel(NULL, NTgt);
    NetLocalGroupDel(NULL, NAlias);
    FreeLibrary(hSam);
}
