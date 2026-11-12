/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Service SIDs and virtual service accounts (NT SERVICE\<service>), and
 *              GetNamedSecurityInfo on a named kernel object
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ntsecapi.h>
#include <sddl.h>
#include <aclapi.h>
#include <wincrypt.h>

/*
 * Measured on Windows 10 22H2 (64-bit process):
 *   LookupAccountName(NT SERVICE\EventLog, any letter case) = S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122,
 *     domain "NT SERVICE", SidTypeWellKnownGroup. The five numbers after 80 are the little-endian
 *     DWORDs of the SHA-1 of the upper-case service name in UTF-16LE.
 *   NT SERVICE\Winmgmt = S-1-5-80-3750560858-172214265-3889451188-1914796615-4100997547.
 *   NT SERVICE = S-1-5-80 (SidTypeDomain); NT SERVICE\ALL SERVICES = S-1-5-80-0 (SidTypeWellKnownGroup).
 *   A service that does not exist: ERROR_NONE_MAPPED, and LsaLookupNames2 STATUS_NONE_MAPPED.
 *   LookupAccountSid of S-1-5-80-<hash of EventLog> = EventLog in domain NT SERVICE; of a SID with
 *   a hash that matches no service, or with four numbers instead of five: ERROR_NONE_MAPPED.
 *   GetNamedSecurityInfo(SE_KERNEL_OBJECT): ERROR_FILE_NOT_FOUND for a name that does not exist,
 *   ERROR_INVALID_HANDLE for an empty name, 0 with an owner and a DACL for an event, mutex,
 *   semaphore, waitable timer, file mapping and job that has the name.
 */

static void CheckName(PCWSTR Name, PCSTR ExpectedSid, SID_NAME_USE ExpectedUse)
{
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    WCHAR Domain[128];
    DWORD cbSid = sizeof(SidBuffer), cchDomain = ARRAYSIZE(Domain);
    SID_NAME_USE Use = 0;
    LPSTR SidString = NULL;
    BOOL Ret;

    Ret = LookupAccountNameW(NULL, Name, SidBuffer, &cbSid, Domain, &cchDomain, &Use);
    ok(Ret, "LookupAccountName(%ls) failed, error %lu\n", Name, GetLastError());
    if (!Ret)
        return;

    ok(ConvertSidToStringSidA(SidBuffer, &SidString), "ConvertSidToStringSid failed\n");
    if (SidString)
    {
        ok(strcmp(SidString, ExpectedSid) == 0, "%ls: SID %s, expected %s\n", Name, SidString, ExpectedSid);
        LocalFree(SidString);
    }
    ok(cbSid == GetLengthSid(SidBuffer), "%ls: size %lu, SID is %lu\n", Name, cbSid, GetLengthSid(SidBuffer));
    ok(wcscmp(Domain, L"NT SERVICE") == 0, "%ls: domain %ls\n", Name, Domain);
    ok(Use == ExpectedUse, "%ls: use %d, expected %d\n", Name, Use, ExpectedUse);
}

static void CheckSid(PCSTR SidString, PCWSTR ExpectedName, SID_NAME_USE ExpectedUse)
{
    PSID Sid = NULL;
    WCHAR Name[128], Domain[128];
    DWORD cchName = ARRAYSIZE(Name), cchDomain = ARRAYSIZE(Domain);
    SID_NAME_USE Use = 0;
    BOOL Ret;

    ok(ConvertStringSidToSidA(SidString, &Sid), "ConvertStringSidToSid(%s) failed\n", SidString);
    if (!Sid)
        return;

    SetLastError(0xdeadbeef);
    Ret = LookupAccountSidW(NULL, Sid, Name, &cchName, Domain, &cchDomain, &Use);
    if (ExpectedName)
    {
        ok(Ret, "LookupAccountSid(%s) failed, error %lu\n", SidString, GetLastError());
        if (Ret)
        {
            ok(_wcsicmp(Name, ExpectedName) == 0, "%s: name %ls, expected %ls\n", SidString, Name, ExpectedName);
            ok(wcscmp(Domain, L"NT SERVICE") == 0, "%s: domain %ls\n", SidString, Domain);
            ok(Use == ExpectedUse, "%s: use %d, expected %d\n", SidString, Use, ExpectedUse);
        }
    }
    else
    {
        ok(!Ret, "LookupAccountSid(%s) succeeded, name %ls\n", SidString, Name);
        ok(GetLastError() == ERROR_NONE_MAPPED, "%s: error %lu\n", SidString, GetLastError());
    }
    LocalFree(Sid);
}

static void TestLsaNames(void)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_HANDLE Policy;
    LSA_UNICODE_STRING Name;
    PLSA_REFERENCED_DOMAIN_LIST Domains = NULL;
    PLSA_TRANSLATED_SID2 Sids = NULL;
    NTSTATUS Status;
    LPSTR SidString = NULL;
    static const WCHAR Good[] = L"NT Service\\EventLog";
    static const WCHAR Bad[] = L"NT Service\\NitroNoSuchService123";

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_LOOKUP_NAMES, &Policy);
    ok(Status == STATUS_SUCCESS, "LsaOpenPolicy %lx\n", Status);
    if (Status != STATUS_SUCCESS)
        return;

    Name.Buffer = (PWSTR)Good;
    Name.Length = sizeof(Good) - sizeof(WCHAR);
    Name.MaximumLength = sizeof(Good);
    Status = LsaLookupNames2(Policy, 0x80000000, 1, &Name, &Domains, &Sids);
    ok(Status == STATUS_SUCCESS, "LsaLookupNames2 %lx\n", Status);
    if (Status == STATUS_SUCCESS)
    {
        ok(Sids[0].Use == SidTypeWellKnownGroup, "use %d\n", Sids[0].Use);
        ok(Sids[0].DomainIndex == 0 && Domains->Entries == 1, "domain index %ld, %lu domains\n", Sids[0].DomainIndex, Domains->Entries);
        ok(ConvertSidToStringSidA(Sids[0].Sid, &SidString), "ConvertSidToStringSid failed\n");
        if (SidString)
        {
            ok(strcmp(SidString, "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122") == 0, "SID %s\n", SidString);
            LocalFree(SidString);
        }
        ok(Domains->Entries && wcsncmp(Domains->Domains[0].Name.Buffer, L"NT SERVICE", 10) == 0, "domain name\n");
        LsaFreeMemory(Domains);
        LsaFreeMemory(Sids);
    }

    Domains = NULL;
    Sids = NULL;
    Name.Buffer = (PWSTR)Bad;
    Name.Length = sizeof(Bad) - sizeof(WCHAR);
    Name.MaximumLength = sizeof(Bad);
    Status = LsaLookupNames2(Policy, 0x80000000, 1, &Name, &Domains, &Sids);
    ok(Status == STATUS_NONE_MAPPED, "LsaLookupNames2 of a missing service: %lx\n", Status);
    if (Domains)
        LsaFreeMemory(Domains);
    if (Sids)
        LsaFreeMemory(Sids);

    LsaClose(Policy);
}

/* The SID the formula gives for a name, with the CryptoAPI SHA-1 as the independent implementation */
static BOOL ComputeServiceSid(PCWSTR Name, WCHAR *Out, size_t Cch)
{
    HCRYPTPROV Prov = 0;
    HCRYPTHASH Hash = 0;
    WCHAR Upper[128];
    DWORD Digest[5], Size = sizeof(Digest);
    BOOL Ok = FALSE;

    wcscpy(Upper, Name);
    _wcsupr(Upper);
    if (!CryptAcquireContextW(&Prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;
    if (CryptCreateHash(Prov, CALG_SHA1, 0, 0, &Hash))
    {
        if (CryptHashData(Hash, (BYTE *)Upper, (DWORD)wcslen(Upper) * sizeof(WCHAR), 0) &&
            CryptGetHashParam(Hash, HP_HASHVAL, (BYTE *)Digest, &Size, 0) && Size == sizeof(Digest))
        {
            StringCchPrintfW(Out, Cch, L"S-1-5-80-%lu-%lu-%lu-%lu-%lu", Digest[0], Digest[1], Digest[2], Digest[3], Digest[4]);
            Ok = TRUE;
        }
        CryptDestroyHash(Hash);
    }
    CryptReleaseContext(Prov, 0);
    return Ok;
}

static void TestScratchService(void)
{
    static const WCHAR Svc[] = L"NitroSvcSidScratch";
    SC_HANDLE Scm, Service;
    WCHAR Expected[128], Account[128];
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = sizeof(SidBuffer), cchDomain = 128;
    WCHAR Domain[128];
    SID_NAME_USE Use;
    LPWSTR SidString = NULL;

    if (!ComputeServiceSid(Svc, Expected, ARRAYSIZE(Expected)))
    {
        skip("CryptoAPI SHA-1 is not available\n");
        return;
    }

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Scm)
    {
        skip("no access to the service control manager (error %lu)\n", GetLastError());
        return;
    }

    Service = CreateServiceW(Scm, Svc, Svc, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                             SERVICE_ERROR_NORMAL, L"C:\\nitro-svcsid-test.exe", NULL, NULL, NULL, NULL, NULL);
    if (!Service)
    {
        skip("CreateService failed, error %lu\n", GetLastError());
        CloseServiceHandle(Scm);
        return;
    }

    StringCchPrintfW(Account, ARRAYSIZE(Account), L"NT SERVICE\\%ls", Svc);
    ok(LookupAccountNameW(NULL, Account, SidBuffer, &cbSid, Domain, &cchDomain, &Use),
       "LookupAccountName(%ls) failed, error %lu\n", Account, GetLastError());
    if (ConvertSidToStringSidW(SidBuffer, &SidString))
    {
        ok(wcscmp(SidString, Expected) == 0, "SID %ls, expected %ls\n", SidString, Expected);
        LocalFree(SidString);
    }

    ok(DeleteService(Service), "DeleteService failed, error %lu\n", GetLastError());
    CloseServiceHandle(Service);
    CloseServiceHandle(Scm);
}

static void CheckKernelObject(PCWSTR Name, const char *Kind)
{
    PSID Owner = NULL;
    PACL Dacl = NULL;
    PSECURITY_DESCRIPTOR Sd = NULL;
    DWORD Ret;

    Ret = GetNamedSecurityInfoW((LPWSTR)Name, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                &Owner, NULL, &Dacl, NULL, &Sd);
    ok(Ret == ERROR_SUCCESS, "%s %ls: GetNamedSecurityInfo %lu\n", Kind, Name, Ret);
    if (Ret == ERROR_SUCCESS)
    {
        ok(Owner != NULL && IsValidSid(Owner), "%s: owner %p\n", Kind, Owner);
        ok(Dacl != NULL, "%s: no DACL\n", Kind);
        LocalFree(Sd);
    }
}

static void TestKernelObjects(void)
{
    WCHAR Name[80];
    DWORD Pid = GetCurrentProcessId();
    PSECURITY_DESCRIPTOR Sd = NULL;
    HANDLE Event, Mutex, Semaphore, Timer, Section, Job;
    DWORD Ret;

    Ret = GetNamedSecurityInfoW((LPWSTR)L"Global\\NitroSvcSidNoSuchObject", SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd);
    ok(Ret == ERROR_FILE_NOT_FOUND, "missing object: %lu\n", Ret);
    Ret = GetNamedSecurityInfoW((LPWSTR)L"", SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd);
    ok(Ret == ERROR_INVALID_HANDLE, "empty name: %lu\n", Ret);

    StringCchPrintfW(Name, ARRAYSIZE(Name), L"Global\\NitroSvcSidE%lu", Pid);
    Event = CreateEventW(NULL, TRUE, FALSE, Name);
    ok(Event != NULL, "CreateEvent failed %lu\n", GetLastError());
    if (Event) CheckKernelObject(Name, "event");
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"Global\\NitroSvcSidM%lu", Pid);
    Mutex = CreateMutexW(NULL, FALSE, Name);
    if (Mutex) CheckKernelObject(Name, "mutex");
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"Global\\NitroSvcSidS%lu", Pid);
    Semaphore = CreateSemaphoreW(NULL, 0, 1, Name);
    if (Semaphore) CheckKernelObject(Name, "semaphore");
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"Global\\NitroSvcSidT%lu", Pid);
    Timer = CreateWaitableTimerW(NULL, TRUE, Name);
    if (Timer) CheckKernelObject(Name, "timer");
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"Global\\NitroSvcSidF%lu", Pid);
    Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, Name);
    if (Section) CheckKernelObject(Name, "section");
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"Global\\NitroSvcSidJ%lu", Pid);
    Job = CreateJobObjectW(NULL, Name);
    if (Job) CheckKernelObject(Name, "job");

    if (Event) CloseHandle(Event);
    if (Mutex) CloseHandle(Mutex);
    if (Semaphore) CloseHandle(Semaphore);
    if (Timer) CloseHandle(Timer);
    if (Section) CloseHandle(Section);
    if (Job) CloseHandle(Job);
}

START_TEST(ServiceSid)
{
    CheckName(L"NT SERVICE\\EventLog", "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122", SidTypeWellKnownGroup);
    CheckName(L"nt service\\EVENTLOG", "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122", SidTypeWellKnownGroup);
    CheckName(L"NT SERVICE\\Winmgmt", "S-1-5-80-3750560858-172214265-3889451188-1914796615-4100997547", SidTypeWellKnownGroup);
    CheckName(L"NT SERVICE", "S-1-5-80", SidTypeDomain);
    CheckName(L"NT SERVICE\\ALL SERVICES", "S-1-5-80-0", SidTypeWellKnownGroup);

    {
        BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
        WCHAR Domain[128];
        DWORD cbSid = sizeof(SidBuffer), cchDomain = ARRAYSIZE(Domain);
        SID_NAME_USE Use;
        BOOL Ret = LookupAccountNameW(NULL, L"NT SERVICE\\NitroNoSuchService123", SidBuffer, &cbSid, Domain, &cchDomain, &Use);
        ok(!Ret && GetLastError() == ERROR_NONE_MAPPED, "missing service: %d, error %lu\n", Ret, GetLastError());
    }

    CheckSid("S-1-5-80", L"NT SERVICE", SidTypeDomain);
    CheckSid("S-1-5-80-0", L"ALL SERVICES", SidTypeWellKnownGroup);
    CheckSid("S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122", L"EventLog", SidTypeWellKnownGroup);
    CheckSid("S-1-5-80-1-2-3-4-5", NULL, SidTypeUnknown);
    CheckSid("S-1-5-80-880578595-1860270145-482643319-2788375705", NULL, SidTypeUnknown);

    TestLsaNames();
    TestScratchService();
    TestKernelObjects();
}
