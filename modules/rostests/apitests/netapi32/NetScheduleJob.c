/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The AT service (NetScheduleJob*) runs commands as SYSTEM, so only administrators may use it
 *
 * Asserts the contract, nothing more: a caller that is not an administrator is refused every call with
 * ERROR_ACCESS_DENIED and changes nothing; an administrator can add, look at, list and delete a job.
 * The standard user is the process itself when it is not an administrator (the standard-user golden),
 * otherwise a filtered thread token (Administrators deny-only, no privileges).
 *
 * Windows 10 (build 19045) answers every NetScheduleJob* call with ERROR_NOT_SUPPORTED for administrators
 * and filtered tokens alike while the AT service is not enabled, so the access check cannot be measured
 * there; the expectation is the documented one (ERROR_ACCESS_DENIED), hence the is_reactos() gating.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winnt.h>
#include <lm.h>

#define MARKER L"cmd.exe /c rem atsvc-apitest-never-run"

static HANDLE StdImpersonation;
static BOOL ProcessIsAdmin;

static BOOL
IsAdminNow(void)
{
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    PSID Admins = NULL;
    BOOL Member = FALSE;

    if (!AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &Admins))
        return FALSE;
    if (!CheckTokenMembership(NULL, Admins, &Member))
        Member = FALSE;
    FreeSid(Admins);
    return Member;
}

static BOOL
InitTokens(void)
{
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    HANDLE Process, Filtered = NULL;
    PSID Admins = NULL;
    SID_AND_ATTRIBUTES Deny;
    BOOL Ok;

    ProcessIsAdmin = IsAdminNow();
    if (!ProcessIsAdmin)
        return TRUE;    /* the process is the standard user */

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }
    AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                             0, 0, 0, 0, 0, 0, &Admins);
    Deny.Sid = Admins;
    Deny.Attributes = 0;
    Ok = CreateRestrictedToken(Process, DISABLE_MAX_PRIVILEGE, 1, &Deny, 0, NULL, 0, NULL, &Filtered);
    if (!Ok)
    {
        skip("CreateRestrictedToken failed: %lu\n", GetLastError());
    }
    else
    {
        Ok = DuplicateTokenEx(Filtered, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                              TokenImpersonation, &StdImpersonation);
        if (!Ok)
            skip("DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(Filtered);
    }
    FreeSid(Admins);
    CloseHandle(Process);
    return Ok;
}

static BOOL
BeStandard(void)
{
    if (!StdImpersonation)
        return TRUE;
    if (!ImpersonateLoggedOnUser(StdImpersonation))
    {
        ok(0, "ImpersonateLoggedOnUser failed: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

static void
BeSelf(void)
{
    if (StdImpersonation)
        RevertToSelf();
}

static DWORD
FutureTime(void)
{
    SYSTEMTIME st;

    /* about twelve hours from now: a job that is deleted at once never gets near it */
    GetLocalTime(&st);
    return (((st.wHour + 12) % 24) * 60 + st.wMinute) * 60 * 1000;
}

/* Number of jobs, and how many of them carry our command, as seen by the caller */
static NET_API_STATUS
CountJobs(DWORD *Total, DWORD *Ours)
{
    LPBYTE Buf = NULL;
    DWORD Read = 0, Tot = 0, Resume = 0, i;
    NET_API_STATUS st;

    *Ours = 0;
    st = NetScheduleJobEnum(NULL, &Buf, MAX_PREFERRED_LENGTH, &Read, &Tot, &Resume);
    if (st == NERR_Success)
    {
        AT_ENUM *e = (AT_ENUM *)Buf;
        for (i = 0; i < Read; i++)
            if (e[i].Command && !wcscmp(e[i].Command, MARKER))
                (*Ours)++;
    }
    *Total = Tot;
    if (Buf)
        NetApiBufferFree(Buf);
    return st;
}

static void
TestDenied(DWORD ExistingJob, const char *who)
{
    AT_INFO Info;
    LPBYTE Buf;
    DWORD Id = 0x12345678, Read, Total, Resume;
    NET_API_STATUS st;

    ZeroMemory(&Info, sizeof(Info));
    Info.JobTime = FutureTime();
    Info.Command = (LPWSTR)MARKER;

    st = NetScheduleJobAdd(NULL, (LPBYTE)&Info, &Id);
    ok(st == ERROR_ACCESS_DENIED, "%s: NetScheduleJobAdd = %lu, expected %lu\n", who, st, ERROR_ACCESS_DENIED);

    /* the check comes before the parameter check: a refused caller learns nothing about the input */
    Info.Command = NULL;
    st = NetScheduleJobAdd(NULL, (LPBYTE)&Info, &Id);
    ok(st == ERROR_ACCESS_DENIED, "%s: NetScheduleJobAdd(no command) = %lu, expected %lu\n",
       who, st, ERROR_ACCESS_DENIED);

    Buf = NULL; Read = Total = Resume = 0;
    st = NetScheduleJobEnum(NULL, &Buf, MAX_PREFERRED_LENGTH, &Read, &Total, &Resume);
    ok(st == ERROR_ACCESS_DENIED, "%s: NetScheduleJobEnum = %lu, expected %lu\n", who, st, ERROR_ACCESS_DENIED);
    ok(Buf == NULL && Read == 0 && Total == 0, "%s: NetScheduleJobEnum returned data\n", who);
    if (Buf)
        NetApiBufferFree(Buf);

    Buf = NULL;
    st = NetScheduleJobGetInfo(NULL, ExistingJob, &Buf);
    ok(st == ERROR_ACCESS_DENIED, "%s: NetScheduleJobGetInfo = %lu, expected %lu\n", who, st, ERROR_ACCESS_DENIED);
    ok(Buf == NULL, "%s: NetScheduleJobGetInfo returned data\n", who);
    if (Buf)
        NetApiBufferFree(Buf);

    st = NetScheduleJobDel(NULL, ExistingJob, ExistingJob);
    ok(st == ERROR_ACCESS_DENIED, "%s: NetScheduleJobDel = %lu, expected %lu\n", who, st, ERROR_ACCESS_DENIED);
}

START_TEST(NetScheduleJob)
{
    AT_INFO Info;
    LPBYTE Buf;
    DWORD Id = 0, Total, Ours, Total2, Ours2;
    NET_API_STATUS st;

    if (!is_reactos())
    {
        skip("Windows 10 reports ERROR_NOT_SUPPORTED for the AT service by default\n");
        return;
    }
    if (!InitTokens())
        return;

    if (!ProcessIsAdmin)
    {
        /* the standard-user golden: nothing can be added as an administrator here */
        trace("running as a standard user\n");
        TestDenied(1, "standard");
        return;
    }

    /* administrator: add, get, list, delete */
    st = CountJobs(&Total, &Ours);
    ok(st == NERR_Success, "admin: NetScheduleJobEnum = %lu\n", st);
    ok(Ours == 0, "admin: %lu jobs of ours left over\n", Ours);

    ZeroMemory(&Info, sizeof(Info));
    Info.JobTime = FutureTime();
    Info.Command = (LPWSTR)MARKER;
    st = NetScheduleJobAdd(NULL, (LPBYTE)&Info, &Id);
    ok(st == NERR_Success, "admin: NetScheduleJobAdd = %lu\n", st);
    if (st != NERR_Success)
        goto cleanup;

    st = CountJobs(&Total2, &Ours2);
    ok(st == NERR_Success && Ours2 == 1 && Total2 == Total + 1,
       "admin: after add: Enum %lu, ours %lu, total %lu (was %lu)\n", st, Ours2, Total2, Total);

    Buf = NULL;
    st = NetScheduleJobGetInfo(NULL, Id, &Buf);
    ok(st == NERR_Success, "admin: NetScheduleJobGetInfo = %lu\n", st);
    if (Buf)
    {
        ok(!wcscmp(((AT_INFO *)Buf)->Command, MARKER), "admin: GetInfo returned the wrong command\n");
        NetApiBufferFree(Buf);
    }

    /* not an administrator: refused, and the job is neither changed nor deleted */
    if (BeStandard())
    {
        TestDenied(Id, "filtered");
        BeSelf();
    }

    st = CountJobs(&Total2, &Ours2);
    ok(st == NERR_Success && Ours2 == 1 && Total2 == Total + 1,
       "admin: after the refused calls: Enum %lu, ours %lu, total %lu (expected %lu)\n",
       st, Ours2, Total2, Total + 1);

cleanup:
    if (Id)
    {
        st = NetScheduleJobDel(NULL, Id, Id);
        ok(st == NERR_Success, "admin: NetScheduleJobDel = %lu\n", st);
    }
    st = CountJobs(&Total2, &Ours2);
    ok(st == NERR_Success && Ours2 == 0 && Total2 == Total,
       "admin: after delete: Enum %lu, ours %lu, total %lu (expected %lu)\n", st, Ours2, Total2, Total);

    if (StdImpersonation)
        CloseHandle(StdImpersonation);
}
