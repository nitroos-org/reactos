/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Every way of setting the password of an existing local account replaces the hashes that the
 *              logon checks: afterwards the new password is accepted and the previous ones are refused, by the
 *              NTLM package (a loopback exchange of this process) and by LogonUser.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define PW_INITIAL  L"Pw#Initial1"
#define PW_1003     L"Pw#Level1003"
#define PW_1        L"Pw#Level1x"
#define PW_2        L"Pw#Level2x"
#define PW_3        L"Pw#Level3x"
#define PW_4        L"Pw#Level4x"
#define PW_CHANGE   L"Pw#Changed1"
#define PW_NETEXE   L"Pw#NetExe1"
#define PW_LONG     L"Pw#AVeryLongPassword1234567890"

static WCHAR g_user[32];
static WCHAR g_domain[MAX_COMPUTERNAME_LENGTH + 2] = L".";   /* the computer name once known */

typedef struct
{
    BYTE neg[512], chal[1024], auth[2048];
} messages;

/* A loopback NTLM exchange with explicit credentials; TRUE when the server accepted the client */
static BOOL ntlm_logon(const WCHAR *user, const WCHAR *password)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    CredHandle cc, sc;
    CtxtHandle cctx, sctx;
    SecBufferDesc od, idesc;
    SecBuffer ob, ib;
    TimeStamp ts;
    ULONG attr;
    SECURITY_STATUS st;
    BOOL accepted = FALSE;
    messages *m = calloc(1, sizeof(*m));
    ULONG neglen, challen;

    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)user;
    id.UserLength = (ULONG)wcslen(user);
    id.Domain = (unsigned short *)g_domain;
    id.DomainLength = (ULONG)wcslen(g_domain);
    id.Password = (unsigned short *)password;
    id.PasswordLength = (ULONG)wcslen(password);
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &cc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK)
    {
        free(m);
        return FALSE;
    }
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &sc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK)
    {
        FreeCredentialsHandle(&cc);
        free(m);
        return FALSE;
    }

    od.ulVersion = idesc.ulVersion = SECBUFFER_VERSION;
    od.cBuffers = idesc.cBuffers = 1;
    od.pBuffers = &ob;
    idesc.pBuffers = &ib;

    /* NEGOTIATE */
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = m->neg; ob.cbBuffer = sizeof(m->neg);
    st = InitializeSecurityContextW(&cc, NULL, (SEC_WCHAR *)L"host", 0, 0, SECURITY_NETWORK_DREP, NULL, 0,
                                    &cctx, &od, &attr, &ts);
    ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
    if (st != SEC_I_CONTINUE_NEEDED)
        goto done;
    neglen = ob.cbBuffer;

    /* CHALLENGE */
    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = m->neg; ib.cbBuffer = neglen;
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = m->chal; ob.cbBuffer = sizeof(m->chal);
    st = AcceptSecurityContext(&sc, NULL, &idesc, 0, SECURITY_NETWORK_DREP, &sctx, &od, &attr, &ts);
    ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
    if (st != SEC_I_CONTINUE_NEEDED)
        goto done;
    challen = ob.cbBuffer;

    /* AUTHENTICATE */
    ib.pvBuffer = m->chal; ib.cbBuffer = challen;
    ob.pvBuffer = m->auth; ob.cbBuffer = sizeof(m->auth);
    st = InitializeSecurityContextW(&cc, &cctx, (SEC_WCHAR *)L"host", 0, 0, SECURITY_NETWORK_DREP, &idesc, 0,
                                    &cctx, &od, &attr, &ts);
    if (st != SEC_E_OK)
    {
        DeleteSecurityContext(&sctx);
        goto done;
    }

    ib.pvBuffer = m->auth; ib.cbBuffer = ob.cbBuffer;
    ob.pvBuffer = m->chal; ob.cbBuffer = sizeof(m->chal);
    st = AcceptSecurityContext(&sc, &sctx, &idesc, 0, SECURITY_NETWORK_DREP, &sctx, &od, &attr, &ts);
    if (st == SEC_E_OK)
    {
        accepted = TRUE;
        DeleteSecurityContext(&sctx);
    }
    else
    {
        ok(st == SEC_E_LOGON_DENIED, "the server answered 0x%08lx\n", (unsigned long)st);
        DeleteSecurityContext(&sctx);
    }
    DeleteSecurityContext(&cctx);

done:
    FreeCredentialsHandle(&sc);
    FreeCredentialsHandle(&cc);
    free(m);
    return accepted;
}

static BOOL local_logon(const WCHAR *user, const WCHAR *password, DWORD type)
{
    HANDLE token = NULL;
    BOOL ret = LogonUserW((LPWSTR)user, g_domain, (LPWSTR)password, type, LOGON32_PROVIDER_DEFAULT, &token);

    if (ret)
        CloseHandle(token);
    return ret;
}

/* The password "good" works everywhere, every one of "bad" (NULL terminated) works nowhere */
static void check_passwords(const char *path, const WCHAR *good, const WCHAR *const *bad)
{
    ok(ntlm_logon(g_user, good), "%s: NTLM does not accept the new password\n", path);
    ok(local_logon(g_user, good, LOGON32_LOGON_INTERACTIVE),
       "%s: the interactive logon does not accept the new password (%lu)\n", path, GetLastError());

    for (; *bad != NULL; bad++)
    {
        if (!wcscmp(*bad, good))
            continue;
        ok(!ntlm_logon(g_user, *bad), "%s: NTLM still accepts the old password %ls\n", path, *bad);
        ok(!local_logon(g_user, *bad, LOGON32_LOGON_INTERACTIVE),
           "%s: the interactive logon still accepts the old password %ls\n", path, *bad);
    }
}

#define MAX_PREVIOUS 16
static const WCHAR *g_previous[MAX_PREVIOUS + 1];
static int g_nprevious;

/* The new password is accepted, all the earlier ones are refused; then it joins the earlier ones */
static void check_set(const char *path, NET_API_STATUS st, const WCHAR *newpw)
{
    ok(st == NERR_Success, "%s: failed with %lu\n", path, (unsigned long)st);
    if (st != NERR_Success)
        return;
    check_passwords(path, newpw, g_previous);
    g_previous[g_nprevious++] = newpw;
    g_previous[g_nprevious] = NULL;
}

static void set_level1(const WCHAR *pw)
{
    USER_INFO_1 ui;
    DWORD err = 0;

    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = g_user;
    ui.usri1_password = (LPWSTR)pw;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    check_set("NetUserSetInfo 1", NetUserSetInfo(NULL, g_user, 1, (LPBYTE)&ui, &err), pw);
}

static void set_level2(const WCHAR *pw)
{
    USER_INFO_2 *ui = NULL;
    NET_API_STATUS st;
    DWORD err = 0;

    st = NetUserGetInfo(NULL, g_user, 2, (LPBYTE *)&ui);
    ok(st == NERR_Success, "NetUserGetInfo 2 failed with %lu\n", (unsigned long)st);
    if (st != NERR_Success)
        return;
    ui->usri2_password = (LPWSTR)pw;
    check_set("NetUserSetInfo 2", NetUserSetInfo(NULL, g_user, 2, (LPBYTE)ui, &err), pw);
    NetApiBufferFree(ui);
}

static void set_level3(const WCHAR *pw)
{
    USER_INFO_3 *ui = NULL;
    NET_API_STATUS st;
    DWORD err = 0;

    st = NetUserGetInfo(NULL, g_user, 3, (LPBYTE *)&ui);
    ok(st == NERR_Success, "NetUserGetInfo 3 failed with %lu\n", (unsigned long)st);
    if (st != NERR_Success)
        return;
    ui->usri3_password = (LPWSTR)pw;
    ui->usri3_password_expired = 0;
    check_set("NetUserSetInfo 3", NetUserSetInfo(NULL, g_user, 3, (LPBYTE)ui, &err), pw);
    NetApiBufferFree(ui);
}

static void set_level4(const WCHAR *pw)
{
    USER_INFO_4 *ui = NULL;
    NET_API_STATUS st;
    DWORD err = 0;

    st = NetUserGetInfo(NULL, g_user, 4, (LPBYTE *)&ui);
    ok(st == NERR_Success, "NetUserGetInfo 4 failed with %lu\n", (unsigned long)st);
    if (st != NERR_Success)
        return;
    ui->usri4_password = (LPWSTR)pw;
    ui->usri4_password_expired = 0;
    check_set("NetUserSetInfo 4", NetUserSetInfo(NULL, g_user, 4, (LPBYTE)ui, &err), pw);
    NetApiBufferFree(ui);
}

static void set_level1003(const WCHAR *pw)
{
    USER_INFO_1003 ui;
    DWORD err = 0;

    ui.usri1003_password = (LPWSTR)pw;
    check_set("NetUserSetInfo 1003", NetUserSetInfo(NULL, g_user, 1003, (LPBYTE)&ui, &err), pw);
}

static void set_change(const WCHAR *oldpw, const WCHAR *newpw)
{
    check_set("NetUserChangePassword", NetUserChangePassword(g_domain, g_user, oldpw, newpw), newpw);
}

/* "net user NAME PASSWORD", the command line tool that people change passwords with */
static void set_net_exe(const WCHAR *pw)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR cmd[256];
    DWORD code = 0xdeadbeef;

    _snwprintf(cmd, ARRAYSIZE(cmd), L"net.exe user %ls %ls", g_user, pw);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        skip("net.exe cannot be started (%lu)\n", GetLastError());
        return;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    check_set("net user NAME PASSWORD", code == 0 ? NERR_Success : code, pw);
}

START_TEST(NetUserPassword)
{
    USER_INFO_4 ui;
    DWORD err = 0, n = ARRAYSIZE(g_domain);
    NET_API_STATUS st;
    char **argv;
    int argc;

    if (!GetComputerNameW(g_domain, &n))
        wcscpy(g_domain, L".");

    /* "NetUserPassword probe USER PASSWORD": print whether NTLM and the interactive logon accept (a manual check) */
    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "probe"))
    {
        WCHAR user[64], pw[64];

        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, user, ARRAYSIZE(user));
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, pw, ARRAYSIZE(pw));
        printf("PROBE %s ntlm=%d interactive=%d\n", argv[3], ntlm_logon(user, pw),
               local_logon(user, pw, LOGON32_LOGON_INTERACTIVE));
        return;
    }

    _snwprintf(g_user, ARRAYSIZE(g_user), L"pwtest%lu", GetCurrentProcessId() % 100000);
    NetUserDel(NULL, g_user);

    /* added the way "net user NAME PASSWORD /add" does it */
    memset(&ui, 0, sizeof(ui));
    ui.usri4_name = g_user;
    ui.usri4_password = (LPWSTR)PW_INITIAL;
    ui.usri4_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    ui.usri4_acct_expires = TIMEQ_FOREVER;
    ui.usri4_primary_group_id = DOMAIN_GROUP_RID_USERS;
    st = NetUserAdd(NULL, 4, (LPBYTE)&ui, &err);
    if (st != NERR_Success)
    {
        skip("NetUserAdd failed (%lu), an elevated administrator is needed\n", (unsigned long)st);
        return;
    }

    /* the new account: its password is the one it was created with */
    g_previous[0] = NULL;
    g_nprevious = 0;
    check_passwords("NetUserAdd", PW_INITIAL, g_previous);
    g_previous[g_nprevious++] = PW_INITIAL;

    /* every way of setting the password of the existing account */
    set_level1003(PW_1003);
    set_level1(PW_1);
    set_level2(PW_2);
    set_level3(PW_3);
    set_level4(PW_4);
    set_change(PW_4, PW_CHANGE);
    set_net_exe(PW_NETEXE);

    /* a password longer than 14 characters has no LM hash; the earlier LM hash must not stay either */
    set_level1003(PW_LONG);
    set_level1003(PW_1003);
    /* and back, the same password twice in a row is fine */
    set_level4(PW_4);

    st = NetUserDel(NULL, g_user);
    ok(st == NERR_Success, "NetUserDel failed with %lu\n", (unsigned long)st);
}
