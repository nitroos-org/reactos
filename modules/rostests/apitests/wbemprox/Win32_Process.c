/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Win32_Process as a standard user: times and creation date of processes the user cannot open
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * On Windows the WMI provider runs with its own privileges, so a standard user still gets CreationDate,
 * KernelModeTime and the memory counters of SYSTEM processes. Clients such as btop4win depend on it: for a
 * process they cannot open they read CreationDate from WMI and parse it as yyyymmddHHMMSS.
 */

#include <apitest.h>

#define COBJMACROS
#include <initguid.h>
#include <wbemcli.h>

/* Is the Administrators group enabled (not deny-only) in the effective token of this thread? */
static
BOOL
AdminsEnabled(PSID AdminsSid)
{
    HANDLE hToken;
    BYTE Buffer[4096];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;
    BOOL Ret = TRUE; /* unknown: assume the worst for the test */

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return Ret;
    if (GetTokenInformation(hToken, TokenGroups, Buffer, sizeof(Buffer), &Length))
    {
        Ret = FALSE;
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if (EqualSid(Groups->Groups[i].Sid, AdminsSid))
            {
                Ret = (Groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                      !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY);
                break;
            }
        }
    }
    CloseHandle(hToken);
    return Ret;
}

static
BOOL
EnterStandardUser(BOOL *Impersonating)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_AND_ATTRIBUTES Admins;
    PSID AdminsSid = NULL;
    HANDLE hToken = NULL, hRestricted = NULL, hImpersonation = NULL;
    BOOL IsAdmin = FALSE, Ret = FALSE;

    *Impersonating = FALSE;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminsSid))
        return FALSE;
    IsAdmin = AdminsEnabled(AdminsSid);
    if (!IsAdmin)
    {
        Ret = TRUE;
        goto Quit;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
        goto Quit;
    Admins.Sid = AdminsSid;
    Admins.Attributes = 0;
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 1, &Admins, 0, NULL, 0, NULL, &hRestricted))
        goto Quit;
    if (!DuplicateTokenEx(hRestricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenImpersonation, &hImpersonation))
        goto Quit;
    if (!SetThreadToken(NULL, hImpersonation))
        goto Quit;
    *Impersonating = TRUE;
    Ret = TRUE;

Quit:
    if (hImpersonation) CloseHandle(hImpersonation);
    if (hRestricted) CloseHandle(hRestricted);
    if (hToken) CloseHandle(hToken);
    FreeSid(AdminsSid);
    return Ret;
}

/* yyyymmddHHMMSS.mmmmmm+UUU */
static
BOOL
IsCimDateTime(const WCHAR *Str)
{
    ULONG i;

    if (!Str || wcslen(Str) != 25)
        return FALSE;
    for (i = 0; i < 14; i++)
        if (Str[i] < L'0' || Str[i] > L'9')
            return FALSE;
    return Str[14] == L'.' && (Str[21] == L'+' || Str[21] == L'-');
}

static
BOOL
CanOpenProcess(DWORD Pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);

    if (!hProcess)
        return FALSE;
    CloseHandle(hProcess);
    return TRUE;
}

static
void
test_Process_StandardUser(IWbemServices *Services)
{
    IEnumWbemClassObject *Enum = NULL;
    IWbemClassObject *Obj;
    BSTR Wql, Query;
    ULONG Returned, Rows = 0, Inaccessible = 0;
    HRESULT hr;

    Wql = SysAllocString(L"WQL");
    Query = SysAllocString(L"SELECT * FROM Win32_Process");
    hr = IWbemServices_ExecQuery(Services, Wql, Query,
                                 WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &Enum);
    ok(hr == S_OK, "ExecQuery failed: 0x%08lx\n", hr);
    SysFreeString(Wql);
    SysFreeString(Query);
    if (hr != S_OK)
        return;

    while (IEnumWbemClassObject_Next(Enum, 10000, 1, &Obj, &Returned) == S_OK && Returned)
    {
        VARIANT Pid, Created, Kernel, Terminated;
        DWORD ProcessId;

        VariantInit(&Pid);
        VariantInit(&Created);
        VariantInit(&Kernel);
        hr = IWbemClassObject_Get(Obj, L"ProcessId", 0, &Pid, NULL, NULL);
        ok(hr == S_OK, "Get(ProcessId) failed: 0x%08lx\n", hr);
        ProcessId = V_UI4(&Pid);
        Rows++;

        /* System (4) and the idle process (0) have no creation time here */
        if (ProcessId > 4 && !CanOpenProcess(ProcessId))
        {
            Inaccessible++;
            hr = IWbemClassObject_Get(Obj, L"CreationDate", 0, &Created, NULL, NULL);
            ok(hr == S_OK, "pid %lu: Get(CreationDate) failed: 0x%08lx\n", ProcessId, hr);
            ok(V_VT(&Created) == VT_BSTR && IsCimDateTime(V_BSTR(&Created)),
               "pid %lu: CreationDate is vt %u '%ls' for a process this user cannot open\n",
               ProcessId, V_VT(&Created), V_VT(&Created) == VT_BSTR ? V_BSTR(&Created) : L"");

            hr = IWbemClassObject_Get(Obj, L"KernelModeTime", 0, &Kernel, NULL, NULL);
            ok(hr == S_OK, "pid %lu: Get(KernelModeTime) failed: 0x%08lx\n", ProcessId, hr);
            ok(V_VT(&Kernel) == VT_BSTR && V_BSTR(&Kernel) && V_BSTR(&Kernel)[0],
               "pid %lu: KernelModeTime is vt %u '%ls'\n", ProcessId, V_VT(&Kernel),
               V_VT(&Kernel) == VT_BSTR ? V_BSTR(&Kernel) : L"");
        }

        /* A NULL property leaves no stale pointer behind: clients that read V_BSTR() of a VT_NULL
         * variant (btop4win) get NULL. TerminationDate is NULL for every live process. */
        memset(&Terminated, 0xAA, sizeof(Terminated));
        hr = IWbemClassObject_Get(Obj, L"TerminationDate", 0, &Terminated, NULL, NULL);
        ok(hr == S_OK, "pid %lu: Get(TerminationDate) failed: 0x%08lx\n", ProcessId, hr);
        if (hr == S_OK && V_VT(&Terminated) == VT_NULL)
            ok(V_BSTR(&Terminated) == NULL, "pid %lu: NULL value left %p in the variant payload\n",
               ProcessId, V_BSTR(&Terminated));

        VariantClear(&Pid);
        VariantClear(&Created);
        VariantClear(&Kernel);
        IWbemClassObject_Release(Obj);
    }
    IEnumWbemClassObject_Release(Enum);

    ok(Rows > 1, "Win32_Process returned %lu rows\n", Rows);
    trace("%lu rows, %lu of them processes this user cannot open\n", Rows, Inaccessible);
}

START_TEST(Win32_Process)
{
    IWbemLocator *Locator = NULL;
    IWbemServices *Services = NULL;
    BSTR Namespace;
    BOOL Impersonating;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx failed: 0x%08lx\n", hr);
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&Locator);
    if (hr != S_OK)
    {
        skip("WbemLocator not available: 0x%08lx\n", hr);
        CoUninitialize();
        return;
    }
    Namespace = SysAllocString(L"ROOT\\CIMV2");
    hr = IWbemLocator_ConnectServer(Locator, Namespace, NULL, NULL, NULL, 0, NULL, NULL, &Services);
    SysFreeString(Namespace);
    ok(hr == S_OK, "ConnectServer failed: 0x%08lx\n", hr);

    if (hr == S_OK)
    {
        if (!EnterStandardUser(&Impersonating))
        {
            skip("Could not create a standard user token: %lu\n", GetLastError());
        }
        else
        {
            test_Process_StandardUser(Services);
            if (Impersonating)
                SetThreadToken(NULL, NULL);
        }
        IWbemServices_Release(Services);
    }
    IWbemLocator_Release(Locator);
    CoUninitialize();
}
