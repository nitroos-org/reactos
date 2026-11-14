/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Who may connect to a communication port: the descriptor the filter gives the port, or
 *              the default one (the system and the administrators), checked against the caller's token
 */

#include "precomp.h"
#include <fltuser.h>
#include <lm.h>
#include <sddl.h>

#define SERVICE_P   L"FltSampleP"
#define PORT_P      L"\\FltSamplePPort"

static WCHAR UserName[] = L"fltportuser";
static WCHAR Password[] = L"Flt-Port-7pw!q";

static HANDLE PlainUserToken;       /* impersonation token of a plain user, NULL if we couldn't get one */
static HANDLE RestrictedToken;      /* our own token with the user and the administrators for deny only */
static BOOL PlainUserIsAdmin;
static BOOL UserCreated;
static NET_API_STATUS (WINAPI *pNetUserAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
static NET_API_STATUS (WINAPI *pNetUserDel)(LPCWSTR, LPCWSTR);

static
PSID
AdminsSid(void)
{
    static SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    static PSID Sid;

    if (Sid == NULL)
        AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Sid);
    return Sid;
}

/* Lists the user and the groups of a token; TRUE if the administrators group is enabled in it */
static
BOOL
DescribeToken(HANDLE Token, PCSTR What)
{
    UCHAR UserBuffer[256];
    PTOKEN_USER User = (PTOKEN_USER)UserBuffer;
    PTOKEN_GROUPS Groups;
    DWORD Size = 0, i;
    LPWSTR String;
    BOOL IsAdmin = FALSE;

    if (GetTokenInformation(Token, TokenUser, User, sizeof(UserBuffer), &Size) &&
        ConvertSidToStringSidW(User->User.Sid, &String))
    {
        trace("%s: user %ls attributes 0x%lx\n", What, String, User->User.Attributes);
        LocalFree(String);
    }

    Size = 0;
    GetTokenInformation(Token, TokenGroups, NULL, 0, &Size);
    Groups = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Groups && GetTokenInformation(Token, TokenGroups, Groups, Size, &Size))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if (ConvertSidToStringSidW(Groups->Groups[i].Sid, &String))
            {
                trace("%s: group %ls attributes 0x%lx\n", What, String, Groups->Groups[i].Attributes);
                LocalFree(String);
            }
            if (EqualSid(Groups->Groups[i].Sid, AdminsSid()) &&
                (Groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
            {
                IsAdmin = TRUE;
            }
        }
    }
    if (Groups)
        HeapFree(GetProcessHeap(), 0, Groups);

    return IsAdmin;
}

static
HANDLE
ToImpersonation(HANDLE Token)
{
    HANDLE Impersonation = NULL;

    if (!DuplicateTokenEx(Token, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, SecurityImpersonation,
                          TokenImpersonation, &Impersonation))
    {
        return NULL;
    }
    return Impersonation;
}

/* A token like ours, in which neither our user nor the administrators group grants anything */
static
void
MakeRestrictedToken(void)
{
    UCHAR UserBuffer[256];
    PTOKEN_USER User = (PTOKEN_USER)UserBuffer;
    SID_AND_ATTRIBUTES Disable[2];
    HANDLE Process = NULL, Restricted = NULL;
    DWORD Size;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process))
        return;

    if (GetTokenInformation(Process, TokenUser, User, sizeof(UserBuffer), &Size))
    {
        Disable[0].Sid = User->User.Sid;
        Disable[0].Attributes = 0;
        Disable[1].Sid = AdminsSid();
        Disable[1].Attributes = 0;
        if (CreateRestrictedToken(Process, 0, 2, Disable, 0, NULL, 0, NULL, &Restricted))
        {
            RestrictedToken = ToImpersonation(Restricted);
            CloseHandle(Restricted);
        }
    }
    CloseHandle(Process);

    ok(RestrictedToken != NULL, "No restricted token: %lu\n", GetLastError());
    if (RestrictedToken)
        ok(!DescribeToken(RestrictedToken, "restricted"), "The restricted token still is an administrator\n");
}

/* A plain user, member of Users only, logged on interactively */
static
void
MakePlainUser(void)
{
    USER_INFO_1 Info = { 0 };
    NET_API_STATUS NetStatus;
    HANDLE Token = NULL;
    HMODULE NetApi;

    /* netapi32 by name: the test executable doesn't import it */
    NetApi = LoadLibraryW(L"netapi32.dll");
    pNetUserAdd = NetApi ? (PVOID)GetProcAddress(NetApi, "NetUserAdd") : NULL;
    pNetUserDel = NetApi ? (PVOID)GetProcAddress(NetApi, "NetUserDel") : NULL;
    if (!pNetUserAdd || !pNetUserDel)
    {
        skip("No netapi32\n");
        return;
    }

    /* A leftover of an earlier run goes first */
    pNetUserDel(NULL, UserName);

    Info.usri1_name = UserName;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetStatus = pNetUserAdd(NULL, 1, (LPBYTE)&Info, NULL);
    ok(NetStatus == NERR_Success, "NetUserAdd: %lu\n", NetStatus);
    if (NetStatus != NERR_Success)
        return;
    UserCreated = TRUE;

    if (!LogonUserW(UserName, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        ok(0, "LogonUser of the plain user failed: %lu\n", GetLastError());
        return;
    }

    PlainUserIsAdmin = DescribeToken(Token, "plain user");
    PlainUserToken = ToImpersonation(Token);
    CloseHandle(Token);
    ok(PlainUserToken != NULL, "No impersonation token of the plain user: %lu\n", GetLastError());
    ok(!PlainUserIsAdmin, "The plain user's token has the administrators group enabled\n");
}

/* Connects to the port as the given token (NULL: ourselves), closes the connection again */
static
HRESULT
ConnectAs(HANDLE Token)
{
    HANDLE Port = INVALID_HANDLE_VALUE;
    HRESULT hr;

    if (Token && !SetThreadToken(NULL, Token))
        return HRESULT_FROM_WIN32(GetLastError());

    hr = FilterConnectCommunicationPort(PORT_P, 0, NULL, 0, NULL, &Port);

    if (Token)
        RevertToSelf();

    if (SUCCEEDED(hr))
        CloseHandle(Port);
    return hr;
}

static
BOOL
LoadWithPortSecurity(PSAMPLE Sample, DWORD PortSecurity)
{
    HKEY Key;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" SERVICE_P, 0, NULL, 0,
                        KEY_ALL_ACCESS, NULL, &Key, NULL) != ERROR_SUCCESS)
    {
        return FALSE;
    }
    RegSetValueExW(Key, L"PortSecurity", 0, REG_DWORD, (PBYTE)&PortSecurity, sizeof(PortSecurity));
    RegCloseKey(Key);

    /* No volume: only the port matters here */
    return LoadSample(Sample, SERVICE_P, L"383000.5", 0);
}

static
void
RunCase(DWORD PortSecurity, PCSTR Name, BOOL OthersAllowed)
{
    SAMPLE S = { { 0 } };
    FLTSAMPLE_STATS Stats;
    HRESULT hr, Expected = OthersAllowed ? S_OK : E_ACCESSDENIED;

    if (!LoadWithPortSecurity(&S, PortSecurity))
    {
        ok(0, "%s: can't load the sample filter\n", Name);
        return;
    }

    /* We are an administrator (or the system): in, whatever the case */
    hr = ConnectAs(NULL);
    ok(hr == S_OK, "%s: administrator connect 0x%lx\n", Name, (ULONG)hr);

    if (RestrictedToken)
    {
        hr = ConnectAs(RestrictedToken);
        ok(hr == Expected, "%s: restricted token connect 0x%lx, expected 0x%lx\n", Name, (ULONG)hr, (ULONG)Expected);
    }

    if (PlainUserToken && !PlainUserIsAdmin)
    {
        hr = ConnectAs(PlainUserToken);
        ok(hr == Expected, "%s: plain user connect 0x%lx, expected 0x%lx\n", Name, (ULONG)hr, (ULONG)Expected);
    }
    else
    {
        skip("%s: no plain user token\n", Name);
    }

    /* Again as ourselves: a refused connect leaves nothing behind (the port takes one connection) */
    hr = ConnectAs(NULL);
    ok(hr == S_OK, "%s: administrator connect after the others 0x%lx\n", Name, (ULONG)hr);

    if (SampleStats(&S, &Stats))
        ok(Stats.PortConnects == Stats.PortDisconnects, "%s: connects %lu, disconnects %lu\n", Name,
           Stats.PortConnects, Stats.PortDisconnects);

    UnloadSample(&S, TRUE);
}

START_TEST(portsec)
{
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    MakeRestrictedToken();
    MakePlainUser();

    /* No descriptor from the filter: the system and the administrators */
    RunCase(PORT_SECURITY_NONE, "default", FALSE);
    /* The descriptor of FltBuildDefaultSecurityDescriptor: the same */
    RunCase(PORT_SECURITY_BUILT_DEFAULT, "built default", FALSE);
    /* Control: a descriptor that lets everybody in, so the refusals above are the descriptor's doing */
    RunCase(PORT_SECURITY_EVERYONE, "everyone", TRUE);

    if (PlainUserToken)
        CloseHandle(PlainUserToken);
    if (RestrictedToken)
        CloseHandle(RestrictedToken);
    if (UserCreated)
        pNetUserDel(NULL, UserName);
}
