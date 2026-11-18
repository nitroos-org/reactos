/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for libsmb2.dll: the error map, failure classification, and (with a configured server)
 *              connect, I/O, signing and the measured error codes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Smb2ErrorMap needs no server. Smb2Server runs only when these environment variables name a server
 * (otherwise it skips):
 *   NITRO_SMB2_TEST_SERVER    host, IPv4 address or [IPv6 literal]
 *   NITRO_SMB2_TEST_SHARE     a writable share
 *   NITRO_SMB2_TEST_USER      [DOMAIN\]user with write access
 *   NITRO_SMB2_TEST_PASSWORD  its password
 */

#include <apitest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <smb2.h>
#include <libsmb2.h>
#include <libsmb2-nitro.h>

static struct smb2_context *new_context(void)
{
    struct smb2_context *smb2 = smb2_init_context();

    ok(smb2 != NULL, "smb2_init_context failed\n");
    if (smb2)
        smb2_set_timeout(smb2, 15);
    return smb2;
}

static void test_status_map(void)
{
    static const struct { uint32_t status, win32; } rows[] =
    {
        { 0x00000000, 0 },
        { 0x00000103, 0 },          /* STATUS_PENDING: not an error */
        { 0xC000006D, 1326 },       /* STATUS_LOGON_FAILURE: measured (smb00 row 19) */
        { 0xC00000CC, 53 },         /* STATUS_BAD_NETWORK_NAME: measured 53, not 67 (row 21) */
        { 0xC0000022, 5 },          /* STATUS_ACCESS_DENIED: measured (rows 6, 23) */
        { 0xC0000072, 1331 },       /* STATUS_ACCOUNT_DISABLED: RtlNtStatusToDosError */
        { 0xC0000034, 2 },          /* STATUS_OBJECT_NAME_NOT_FOUND: RtlNtStatusToDosError */
        { 0xC0000064, 1317 },       /* STATUS_NO_SUCH_USER: RtlNtStatusToDosError (ERROR_NO_SUCH_USER) */
    };
    UINT i;

    for (i = 0; i < ARRAYSIZE(rows); i++)
        ok(NitroSmb2StatusToWin32(rows[i].status) == rows[i].win32, "status 0x%08x: %u, expected %u\n",
           rows[i].status, NitroSmb2StatusToWin32(rows[i].status), rows[i].win32);
}

static void expect_connect_error(const char *server, uint32_t expected, const char *what)
{
    struct smb2_context *smb2 = new_context();
    struct nitro_smb2_auth_info ai;
    int rc;

    if (!smb2)
        return;
    rc = NitroSmb2SetCredentials(smb2, "nobody", NULL, "x", NULL);
    ok(rc == 0, "%s: NitroSmb2SetCredentials %d (%s)\n", what, rc, smb2_get_error(smb2));
    rc = smb2_connect_share(smb2, server, "share", NULL);
    ok(rc < 0, "%s: connect succeeded\n", what);
    ok(NitroSmb2ErrorToWin32(smb2, rc) == expected, "%s: win32 %u, expected %u (rc %d, %s)\n", what,
       NitroSmb2ErrorToWin32(smb2, rc), expected, rc, smb2_get_error(smb2));
    memset(&ai, 0, sizeof(ai));
    ai.size = sizeof(ai);
    ok(NitroSmb2GetAuthInfo(smb2, &ai) == 0, "%s: NitroSmb2GetAuthInfo failed\n", what);
    ok(ai.tcp_connected == 0 && ai.authenticated == 0, "%s: tcp %d auth %d\n", what, ai.tcp_connected,
       ai.authenticated);
    ok(ai.explicit_credentials == 1 && strcmp(ai.package, "Negotiate") == 0, "%s: explicit %d package %s\n",
       what, ai.explicit_credentials, ai.package);
    smb2_destroy_context(smb2);
}

START_TEST(Smb2ErrorMap)
{
    WSADATA wsa;
    struct nitro_smb2_auth_info ai;
    struct smb2_context *smb2;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    test_status_map();
    ok(NitroSmb2ErrorToWin32(NULL, 0) == 0, "rc 0 must map to 0\n");

    /* no SMB server on this machine: refused at once; a name that cannot resolve */
    expect_connect_error("nosuchhost-smb2engine.invalid", 53, "unresolved name");
    expect_connect_error("127.0.0.1", 53, "refused (IPv4)");
    expect_connect_error("[::1]", 53, "refused (IPv6)");

    /* argument checks of the NitroOS additions */
    smb2 = new_context();
    if (smb2)
    {
        ok(NitroSmb2SetCredentials(smb2, "user", NULL, NULL, NULL) == -EINVAL, "user without a password\n");
        ok(NitroSmb2SetCredentials(smb2, NULL, NULL, "pw", NULL) == -EINVAL, "password without a user\n");
        ok(NitroSmb2SetCredentials(smb2, "u", NULL, "pw", "NoSuchPackage") < 0, "unknown package accepted\n");
        memset(&ai, 0, sizeof(ai));
        ai.size = sizeof(ai);
        ok(NitroSmb2GetAuthInfo(smb2, &ai) == 0 && ai.reason == NITRO_SMB2_REASON_SSPI && ai.sspi_status != 0,
           "reason %d status 0x%08x\n", ai.reason, ai.sspi_status);
        ai.size = 4;
        ok(NitroSmb2GetAuthInfo(smb2, &ai) == -EINVAL, "wrong size accepted\n");
        smb2_destroy_context(smb2);
    }
    WSACleanup();
}

static const char *server, *share, *user, *password;

static struct smb2_context *connect_as(const char *u, const char *p, const char *sh, int sign, int *prc)
{
    struct smb2_context *smb2 = new_context();
    char domain[128] = "", name[128];
    const char *bs;

    *prc = -ENOMEM;
    if (!smb2)
        return NULL;
    bs = strchr(u, '\\');
    if (bs)
    {
        _snprintf(domain, sizeof(domain) - 1, "%.*s", (int)(bs - u), u);
        u = bs + 1;
    }
    _snprintf(name, sizeof(name) - 1, "%s", u);
    name[sizeof(name) - 1] = 0;
    if (sign)
        smb2_set_sign(smb2, 1);
    *prc = NitroSmb2SetCredentials(smb2, name, domain[0] ? domain : NULL, p, NULL);
    if (*prc == 0)
        *prc = smb2_connect_share(smb2, server, sh, NULL);
    return smb2;
}

static void test_io(struct smb2_context *smb2)
{
    static const char file[] = "smb2engine-apitest.bin", dir[] = "smb2engine-apitest-dir";
    const uint32_t size = 200 * 1024;
    uint8_t *out = malloc(size), *in = malloc(size);
    struct smb2fh *fh;
    struct smb2_stat_64 st;
    uint32_t i, done;
    int r;

    if (!out || !in)
    {
        skip("out of memory\n");
        free(out);
        free(in);
        return;
    }
    for (i = 0; i < size; i++)
        out[i] = (uint8_t)(i * 7 + (i >> 9));
    memset(in, 0, size);

    fh = smb2_open(smb2, file, O_WRONLY | O_CREAT | O_TRUNC);
    ok(fh != NULL, "open for write: %s\n", smb2_get_error(smb2));
    if (fh)
    {
        for (done = 0; done < size; done += (uint32_t)r)
        {
            r = smb2_write(smb2, fh, out + done, size - done);
            if (r <= 0)
                break;
        }
        ok(done == size, "wrote %u of %u: %s\n", done, size, smb2_get_error(smb2));
        ok(smb2_close(smb2, fh) == 0, "close: %s\n", smb2_get_error(smb2));
    }
    ok(smb2_stat(smb2, file, &st) == 0 && st.smb2_size == size, "stat: size %llu\n",
       (unsigned long long)st.smb2_size);
    fh = smb2_open(smb2, file, O_RDONLY);
    ok(fh != NULL, "open for read: %s\n", smb2_get_error(smb2));
    if (fh)
    {
        for (done = 0; done < size; done += (uint32_t)r)
        {
            r = smb2_read(smb2, fh, in + done, size - done);
            if (r <= 0)
                break;
        }
        ok(done == size && memcmp(in, out, size) == 0, "read back %u bytes, content %s\n", done,
           memcmp(in, out, size) ? "differs" : "equal");
        ok(smb2_close(smb2, fh) == 0, "close: %s\n", smb2_get_error(smb2));
    }
    ok(smb2_unlink(smb2, file) == 0, "unlink: %s\n", smb2_get_error(smb2));
    ok(smb2_stat(smb2, file, &st) < 0, "file still there after unlink\n");
    ok(smb2_mkdir(smb2, dir) == 0, "mkdir: %s\n", smb2_get_error(smb2));
    ok(smb2_stat(smb2, dir, &st) == 0 && st.smb2_type == SMB2_TYPE_DIRECTORY, "stat dir: type %u\n",
       st.smb2_type);
    ok(smb2_rmdir(smb2, dir) == 0, "rmdir: %s\n", smb2_get_error(smb2));
    free(out);
    free(in);
}

START_TEST(Smb2Server)
{
    WSADATA wsa;
    struct smb2_context *smb2;
    struct nitro_smb2_auth_info ai;
    char *bad;
    int rc;

    server = getenv("NITRO_SMB2_TEST_SERVER");
    share = getenv("NITRO_SMB2_TEST_SHARE");
    user = getenv("NITRO_SMB2_TEST_USER");
    password = getenv("NITRO_SMB2_TEST_PASSWORD");
    if (!server || !share || !user || !password)
    {
        skip("NITRO_SMB2_TEST_SERVER/SHARE/USER/PASSWORD not set\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* explicit credentials, I/O */
    smb2 = connect_as(user, password, share, 0, &rc);
    ok(rc == 0, "connect: rc %d win32 %u: %s\n", rc, NitroSmb2ErrorToWin32(smb2, rc), smb2 ? smb2_get_error(smb2) : "");
    if (smb2 && rc == 0)
    {
        memset(&ai, 0, sizeof(ai));
        ai.size = sizeof(ai);
        ok(NitroSmb2GetAuthInfo(smb2, &ai) == 0, "auth info\n");
        ok(ai.authenticated && ai.explicit_credentials && ai.session_key_length == 16,
           "authenticated %d explicit %d key %u\n", ai.authenticated, ai.explicit_credentials,
           ai.session_key_length);
        ok(!(ai.session_flags & 3), "guest/null session flags 0x%x\n", ai.session_flags);
        ok(!ai.spnego || ai.server_token_verified, "SPNEGO without the server's token checked\n");
        trace("dialect 0x%04x spnego %d\n", smb2_get_dialect(smb2), ai.spnego);
        test_io(smb2);
        smb2_disconnect_share(smb2);
    }
    smb2_destroy_context(smb2);

    /* signing required by us */
    smb2 = connect_as(user, password, share, 1, &rc);
    ok(rc == 0, "connect with signing: rc %d: %s\n", rc, smb2 ? smb2_get_error(smb2) : "");
    if (smb2 && rc == 0)
        smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);

    /* wrong password: 1326 (wire STATUS_LOGON_FAILURE) */
    bad = malloc(strlen(password) + 2);
    if (bad)
    {
        strcpy(bad, password);
        strcat(bad, "x");
        smb2 = connect_as(user, bad, share, 0, &rc);
        ok(rc < 0, "wrong password accepted\n");
        ok(NitroSmb2ErrorToWin32(smb2, rc) == 1326, "wrong password: win32 %u nt 0x%08x\n",
           NitroSmb2ErrorToWin32(smb2, rc), smb2_get_nterror(smb2));
        smb2_destroy_context(smb2);
        free(bad);
    }

    /* credentials that could not be acquired: no connection with any others (not the caller's own) */
    smb2 = new_context();
    if (smb2)
    {
        ok(NitroSmb2SetCredentials(smb2, "u", NULL, password, "NoSuchPackage") < 0, "unknown package accepted\n");
        rc = smb2_connect_share(smb2, server, share, NULL);
        memset(&ai, 0, sizeof(ai));
        ai.size = sizeof(ai);
        NitroSmb2GetAuthInfo(smb2, &ai);
        ok(rc < 0 && !ai.authenticated && ai.reason == NITRO_SMB2_REASON_SSPI,
           "connected after failed credentials: rc %d authenticated %d reason %d\n", rc, ai.authenticated, ai.reason);
        smb2_destroy_context(smb2);
    }

    /* unknown share: 53 (wire STATUS_BAD_NETWORK_NAME) */
    smb2 = connect_as(user, password, "nosuchshare-smb2engine", 0, &rc);
    ok(rc < 0, "unknown share accepted\n");
    ok(NitroSmb2ErrorToWin32(smb2, rc) == 53, "unknown share: win32 %u nt 0x%08x\n",
       NitroSmb2ErrorToWin32(smb2, rc), smb2_get_nterror(smb2));
    smb2_destroy_context(smb2);
    WSACleanup();
}
