/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The first use of secur32 in a process from many threads at once: every thread finds the NTLM and
 *              Negotiate packages (the packages are loaded once, and a thread that comes while they are being loaded
 *              waits for them), and every package is listed once. Run it as the first test of its process.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define THREADS 16

static HANDLE g_go;
static LONG g_ntlm_bad, g_nego_bad;
static SECURITY_STATUS g_ntlm_last, g_nego_last;

static DWORD WINAPI worker(LPVOID arg)
{
    CredHandle cred;
    TimeStamp ts;
    SECURITY_STATUS st;

    WaitForSingleObject(g_go, INFINITE);
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cred,
                                   &ts);
    if (st == SEC_E_OK)
        FreeCredentialsHandle(&cred);
    else
    {
        InterlockedIncrement(&g_ntlm_bad);
        g_ntlm_last = st;
    }
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &cred,
                                   &ts);
    if (st == SEC_E_OK)
        FreeCredentialsHandle(&cred);
    else
    {
        InterlockedIncrement(&g_nego_bad);
        g_nego_last = st;
    }
    return 0;
}

START_TEST(SspiInitRace)
{
    HANDLE threads[THREADS];
    PSecPkgInfoW info = NULL;
    ULONG count = 0, i, ntlm = 0, nego = 0;
    SECURITY_STATUS st;
    int n;

    g_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(g_go != NULL, "CreateEvent failed: %lu\n", GetLastError());
    if (!g_go) return;
    for (n = 0; n < THREADS; n++)
    {
        threads[n] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        ok(threads[n] != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!threads[n]) return;
    }
    Sleep(100);
    SetEvent(g_go);
    WaitForMultipleObjects(THREADS, threads, TRUE, INFINITE);
    for (n = 0; n < THREADS; n++) CloseHandle(threads[n]);
    CloseHandle(g_go);

    ok(g_ntlm_bad == 0, "NTLM: %ld of %d threads found no package (last 0x%08lx)\n", g_ntlm_bad, THREADS,
       (unsigned long)g_ntlm_last);
    ok(g_nego_bad == 0, "Negotiate: %ld of %d threads found no package (last 0x%08lx)\n", g_nego_bad, THREADS,
       (unsigned long)g_nego_last);

    st = EnumerateSecurityPackagesW(&count, &info);
    ok(st == SEC_E_OK, "EnumerateSecurityPackagesW: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_E_OK || !info) return;
    for (i = 0; i < count; i++)
    {
        if (!lstrcmpiW(info[i].Name, L"NTLM")) ntlm++;
        if (!lstrcmpiW(info[i].Name, L"Negotiate")) nego++;
    }
    ok(ntlm == 1, "NTLM listed %lu times of %lu packages\n", ntlm, count);
    ok(nego == 1, "Negotiate listed %lu times of %lu packages\n", nego, count);
    FreeContextBuffer(info);
}
