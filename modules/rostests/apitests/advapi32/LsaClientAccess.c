/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Who may read the data of a logon session and who may register a policy change notification
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (build 20348) with a throw-away standard user, an administrator, SYSTEM, LocalService
 * and NetworkService:
 *  - LsaEnumerateLogonSessions lists every session for everybody;
 *  - LsaGetLogonSessionData: the administrator and SYSTEM get the data of every session; the standard user, LocalService and
 *    NetworkService get it for their own session only and STATUS_ACCESS_DENIED for every other;
 *  - LsaRegisterPolicyChangeNotification with an event: the administrator, SYSTEM, LocalService and NetworkService succeed
 *    (4096 events of one process, no limit reached), the standard user gets STATUS_ACCESS_DENIED; a handle that is not an
 *    event (a mutex) gets STATUS_INVALID_HANDLE.
 * Here: the administrator and the standard user (a throw-away account, impersonated).
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>

typedef NTSTATUS (NTAPI *LSAENUMERATELOGONSESSIONS)(PULONG, PLUID *);
typedef NTSTATUS (NTAPI *LSAGETLOGONSESSIONDATA)(PLUID, PSECURITY_LOGON_SESSION_DATA *);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);

static LSAENUMERATELOGONSESSIONS pLsaEnumerateLogonSessions;
static LSAGETLOGONSESSIONDATA pLsaGetLogonSessionData;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

typedef NTSTATUS (NTAPI *LSAPOLICYNOTIFY)(POLICY_NOTIFICATION_INFORMATION_CLASS, HANDLE);
static LSAPOLICYNOTIFY pLsaRegisterPolicyChangeNotification;
static LSAPOLICYNOTIFY pLsaUnregisterPolicyChangeNotification;

static WCHAR TestUser[] = L"lsaclientacc";
static WCHAR TestPassword[] = L"Lsa-Client-Acc-2026!";

static void
CheckSessions(PCSTR Who, PLUID Own, BOOL Admin, ULONG ExpectedCount)
{
    PLUID List = NULL;
    ULONG Count = 0, i, Seen = 0, Denied = 0, OwnSeen = 0;
    NTSTATUS Status;

    Status = pLsaEnumerateLogonSessions(&Count, &List);
    ok(Status == STATUS_SUCCESS, "%s: LsaEnumerateLogonSessions returned 0x%08lx\n", Who, Status);
    if (Status != STATUS_SUCCESS)
        return;
    ok(Count >= ExpectedCount, "%s: %lu sessions listed, the administrator saw %lu\n", Who, Count, ExpectedCount);

    for (i = 0; i < Count; i++)
    {
        PSECURITY_LOGON_SESSION_DATA Data = NULL;
        BOOL IsOwn = Own && List[i].LowPart == Own->LowPart && List[i].HighPart == Own->HighPart;

        Status = pLsaGetLogonSessionData(&List[i], &Data);
        if (Admin || IsOwn)
        {
            /* a session that ended between the two calls is not a failure of the check */
            ok(Status == STATUS_SUCCESS || Status == STATUS_NO_SUCH_LOGON_SESSION,
               "%s: data of session %lx:%lx%s returned 0x%08lx\n", Who, List[i].HighPart, List[i].LowPart, IsOwn ? " (own)" : "", Status);
            if (Status == STATUS_SUCCESS)
            {
                Seen++;
                if (IsOwn)
                    OwnSeen++;
            }
        }
        else
        {
            ok(Status == STATUS_ACCESS_DENIED, "%s: data of the session %lx:%lx of somebody else returned 0x%08lx\n",
               Who, List[i].HighPart, List[i].LowPart, Status);
            if (Status == STATUS_ACCESS_DENIED)
                Denied++;
        }
        if (Data)
            pLsaFreeReturnBuffer(Data);
    }
    if (!Admin)
    {
        ok(OwnSeen == 1, "%s: the data of the own session was returned %lu times\n", Who, OwnSeen);
        ok(Denied == Count - 1, "%s: %lu of %lu sessions were refused\n", Who, Denied, Count);
    }
    else
    {
        trace("%s: %lu of %lu sessions returned their data\n", Who, Seen, Count);
    }
    pLsaFreeReturnBuffer(List);
}

static void
CheckRegistration(PCSTR Who, BOOL Allowed)
{
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL), Mutex = CreateMutexW(NULL, FALSE, NULL);
    NTSTATUS Status;

    Status = pLsaRegisterPolicyChangeNotification(PolicyNotifyAuditEventsInformation, Event);
    if (Allowed)
    {
        ok(Status == STATUS_SUCCESS, "%s: registering an event returned 0x%08lx\n", Who, Status);
        if (Status == STATUS_SUCCESS)
            pLsaUnregisterPolicyChangeNotification(PolicyNotifyAuditEventsInformation, Event);

        Status = pLsaRegisterPolicyChangeNotification(PolicyNotifyAuditEventsInformation, Mutex);
        ok(Status == STATUS_INVALID_HANDLE, "%s: registering a mutex returned 0x%08lx\n", Who, Status);
        if (Status == STATUS_SUCCESS)
            pLsaUnregisterPolicyChangeNotification(PolicyNotifyAuditEventsInformation, Mutex);
    }
    else
    {
        ok(Status == STATUS_ACCESS_DENIED, "%s: registering an event returned 0x%08lx\n", Who, Status);
        if (Status == STATUS_SUCCESS)
            pLsaUnregisterPolicyChangeNotification(PolicyNotifyAuditEventsInformation, Event);
    }
    CloseHandle(Event);
    CloseHandle(Mutex);
}

START_TEST(LsaClientAccess)
{
    HMODULE hSecur32 = LoadLibraryW(L"secur32.dll");
    USER_INFO_1 Info;
    DWORD ParmErr = 0, Length;
    NET_API_STATUS NetStatus;
    HANDLE Token = NULL;
    TOKEN_STATISTICS Stats;
    PLUID Dummy = NULL;
    ULONG AdminCount = 0;

    if (!hSecur32)
    {
        skip("no secur32\n");
        return;
    }
    pLsaEnumerateLogonSessions = (LSAENUMERATELOGONSESSIONS)GetProcAddress(hSecur32, "LsaEnumerateLogonSessions");
    pLsaGetLogonSessionData = (LSAGETLOGONSESSIONDATA)GetProcAddress(hSecur32, "LsaGetLogonSessionData");
    pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(hSecur32, "LsaFreeReturnBuffer");
    pLsaRegisterPolicyChangeNotification = (LSAPOLICYNOTIFY)GetProcAddress(hSecur32, "LsaRegisterPolicyChangeNotification");
    pLsaUnregisterPolicyChangeNotification = (LSAPOLICYNOTIFY)GetProcAddress(hSecur32, "LsaUnregisterPolicyChangeNotification");
    if (!pLsaEnumerateLogonSessions || !pLsaGetLogonSessionData || !pLsaFreeReturnBuffer ||
        !pLsaRegisterPolicyChangeNotification || !pLsaUnregisterPolicyChangeNotification)
    {
        skip("secur32 has no LsaEnumerateLogonSessions / LsaGetLogonSessionData\n");
        return;
    }

    /* The administrator that runs the test */
    if (pLsaEnumerateLogonSessions(&AdminCount, &Dummy) == STATUS_SUCCESS)
        pLsaFreeReturnBuffer(Dummy);
    CheckSessions("administrator", NULL, TRUE, 0);
    CheckRegistration("administrator", TRUE);

    /* A throw-away standard user (its account exists only for the test) */
    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = TestUser;
    Info.usri1_password = TestPassword;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetUserDel(NULL, TestUser);
    NetStatus = NetUserAdd(NULL, 1, (LPBYTE)&Info, &ParmErr);
    if (NetStatus != NERR_Success)
    {
        skip("cannot make the test account (%lu)\n", NetStatus);
        return;
    }

    if (!LogonUserW(TestUser, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip("cannot log the test account on (%lu)\n", GetLastError());
    }
    else
    {
        if (!GetTokenInformation(Token, TokenStatistics, &Stats, sizeof(Stats), &Length))
        {
            skip("no token statistics (%lu)\n", GetLastError());
        }
        else if (!ImpersonateLoggedOnUser(Token))
        {
            skip("cannot impersonate the test account (%lu)\n", GetLastError());
        }
        else
        {
            CheckSessions("standard user", &Stats.AuthenticationId, FALSE, AdminCount);
            CheckRegistration("standard user", FALSE);
            RevertToSelf();
        }
        CloseHandle(Token);
    }
    NetUserDel(NULL, TestUser);
}
