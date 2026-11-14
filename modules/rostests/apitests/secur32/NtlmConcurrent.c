/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Many threads of one process use the local security authority and the NTLM package at the same time:
 *              each opens the policy and queries it, looks up its own account, and runs same-machine NTLM exchanges
 *              with the default credentials. Every call must succeed and every CHALLENGE must offer the local call:
 *              the RPC connections of the process to the LSA share one association group, so a context handle
 *              made on one connection is valid on the others.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <string.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <ntsecapi.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define THREADS     12
#define ITERATIONS  25
#define ROUNDS      2
#define NTLMSSP_NEGOTIATE_LOCAL_CALL 0x00004000

static LONG g_policy_open_bad, g_policy_query_bad, g_sid_bad, g_sspi_bad, g_sspi_notlocal, g_sspi_ok;
static LONG g_last_status, g_last_error, g_last_sspi;

static void policy_once(void)
{
    LSA_OBJECT_ATTRIBUTES attrs;
    LSA_HANDLE policy;
    PVOID info = NULL;
    NTSTATUS status;

    memset(&attrs, 0, sizeof(attrs));
    attrs.Length = sizeof(attrs);
    status = LsaOpenPolicy(NULL, &attrs, POLICY_VIEW_LOCAL_INFORMATION, &policy);
    if (status != STATUS_SUCCESS)
    {
        InterlockedIncrement(&g_policy_open_bad);
        g_last_status = status;
        return;
    }
    status = LsaQueryInformationPolicy(policy, PolicyPrimaryDomainInformation, &info);
    if (status != STATUS_SUCCESS)
    {
        InterlockedIncrement(&g_policy_query_bad);
        g_last_status = status;
    }
    else
        LsaFreeMemory(info);
    LsaClose(policy);
}

static void sid_once(void)
{
    BYTE buf[256];
    WCHAR name[256], domain[256];
    DWORD size, name_len = ARRAYSIZE(name), domain_len = ARRAYSIZE(domain);
    SID_NAME_USE use;
    HANDLE token;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return;
    if (!GetTokenInformation(token, TokenUser, buf, sizeof(buf), &size))
    {
        CloseHandle(token);
        return;
    }
    CloseHandle(token);
    if (!LookupAccountSidW(NULL, ((TOKEN_USER *)buf)->User.Sid, name, &name_len, domain, &domain_len, &use))
    {
        InterlockedIncrement(&g_sid_bad);
        g_last_error = GetLastError();
    }
}

/* one exchange of the default credentials of the caller with an inbound context of this process */
static void sspi_once(void)
{
    CredHandle cc, sc;
    CtxtHandle cctx, sctx;
    TimeStamp ts;
    ULONG attr;
    BYTE t1[4096], t2[4096], t3[4096];
    SecBuffer ib, ob;
    SecBufferDesc ind = { SECBUFFER_VERSION, 1, &ib }, outd = { SECBUFFER_VERSION, 1, &ob };
    SECURITY_STATUS st, a2 = SEC_E_INTERNAL_ERROR;
    ULONG n1, n2, cflags = 0;
    BOOL have_c = FALSE, have_s = FALSE;

    if (AcquireCredentialsHandleA(NULL, (SEC_CHAR *)"NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cc, &ts))
    {
        InterlockedIncrement(&g_sspi_bad);
        return;
    }
    if (AcquireCredentialsHandleA(NULL, (SEC_CHAR *)"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &sc, &ts))
    {
        FreeCredentialsHandle(&cc);
        InterlockedIncrement(&g_sspi_bad);
        return;
    }

    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = t1; ob.cbBuffer = sizeof(t1);
    st = InitializeSecurityContextA(&cc, NULL, NULL, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, NULL, 0,
                                    &cctx, &outd, &attr, &ts);
    n1 = ob.cbBuffer;
    if (st != SEC_I_CONTINUE_NEEDED)
        goto done;
    have_c = TRUE;

    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = t1; ib.cbBuffer = n1;
    ob.pvBuffer = t2; ob.cbBuffer = sizeof(t2);
    st = AcceptSecurityContext(&sc, NULL, &ind, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, &sctx, &outd, &attr, &ts);
    n2 = ob.cbBuffer;
    if (st != SEC_I_CONTINUE_NEEDED)
        goto done;
    have_s = TRUE;
    if (n2 >= 24)
        cflags = *(ULONG *)(t2 + 20);
    if (!(cflags & NTLMSSP_NEGOTIATE_LOCAL_CALL))
        InterlockedIncrement(&g_sspi_notlocal);

    ib.pvBuffer = t2; ib.cbBuffer = n2;
    ob.pvBuffer = t3; ob.cbBuffer = sizeof(t3);
    st = InitializeSecurityContextA(&cc, &cctx, NULL, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, &ind, 0,
                                    &cctx, &outd, &attr, &ts);
    if (st != SEC_E_OK)
        goto done;

    ib.pvBuffer = t3; ib.cbBuffer = ob.cbBuffer;
    ob.pvBuffer = t1; ob.cbBuffer = sizeof(t1);
    a2 = AcceptSecurityContext(&sc, &sctx, &ind, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, &sctx, &outd, &attr, &ts);
    st = a2;
done:
    if (st == SEC_E_OK && a2 == SEC_E_OK)
        InterlockedIncrement(&g_sspi_ok);
    else
    {
        InterlockedIncrement(&g_sspi_bad);
        g_last_sspi = st;
    }
    if (have_s) DeleteSecurityContext(&sctx);
    if (have_c) DeleteSecurityContext(&cctx);
    FreeCredentialsHandle(&cc);
    FreeCredentialsHandle(&sc);
}

static DWORD WINAPI worker(LPVOID arg)
{
    int i;

    for (i = 0; i < ITERATIONS; i++)
    {
        policy_once();
        sid_once();
        sspi_once();
    }
    return 0;
}

START_TEST(NtlmConcurrent)
{
    HANDLE threads[THREADS];
    int round, i;

    for (round = 0; round < ROUNDS; round++)
    {
        for (i = 0; i < THREADS; i++)
        {
            threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
            ok(threads[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
            if (!threads[i])
                return;
        }
        WaitForMultipleObjects(THREADS, threads, TRUE, INFINITE);
        for (i = 0; i < THREADS; i++)
            CloseHandle(threads[i]);
    }

    ok(g_policy_open_bad == 0, "LsaOpenPolicy failed %ld times (last 0x%08lx)\n", g_policy_open_bad, g_last_status);
    ok(g_policy_query_bad == 0, "LsaQueryInformationPolicy failed %ld times (last 0x%08lx)\n", g_policy_query_bad,
       g_last_status);
    ok(g_sid_bad == 0, "LookupAccountSid failed %ld times (last error %ld)\n", g_sid_bad, g_last_error);
    ok(g_sspi_notlocal == 0, "%ld CHALLENGEs without the local call\n", g_sspi_notlocal);
    ok(g_sspi_bad == 0, "%ld exchanges failed (last 0x%08lx)\n", g_sspi_bad, g_last_sspi);
    ok(g_sspi_ok == ROUNDS * THREADS * ITERATIONS, "%ld of %d exchanges completed\n", g_sspi_ok,
       ROUNDS * THREADS * ITERATIONS);
}
