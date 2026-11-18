/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     smbcli: command-line SMB2/3 test client on libsmb2.dll (interop matrix, transfers, leak loop)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * smbcli [options] COMMAND //SERVER/SHARE [ARGS]
 *   SERVER: a name, an IPv4 address or a bracketed IPv6 literal ([fd00::1]), optionally :port
 * Commands:
 *   info                      connect only, print dialect, signing, encryption and authentication
 *   ls PATH | stat PATH | rm PATH | mkdir PATH | rmdir PATH
 *   get REMOTE LOCAL | put LOCAL REMOTE
 *   putgen REMOTE BYTES [SEED] upload a generated stream, print its SHA-256
 *   getsum REMOTE             download, print size and SHA-256 (nothing stored)
 *   loop SECONDS REMOTE BYTES connect, putgen, getsum (checked), rm, disconnect, again; one
 *                             line per minute with this process's handle count and private bytes
 * Options:
 *   -v 2.1|3.0|3.02|3.1.1|any  dialect (default any: 2.0.2 to 3.1.1)
 *   -s                         require signing (it is always offered)
 *   -e / -E                    require encryption / never encrypt (default: when the share asks)
 *   -U [DOMAIN\]USER           explicit credentials; password from -P or SMBCLI_PASSWORD
 *   -L [DOMAIN\]USER           single sign-on as this local user: LogonUser (password from -Q or
 *                              SMBCLI_LOGON_PASSWORD), impersonate around credential acquisition only
 *                              (the engine service model), then revert; with -I for the whole run
 *   (neither -U nor -L)        single sign-on as the caller
 *   -k PACKAGE                 SSPI package (default Negotiate)
 *   -t SECONDS                 timeout (default 30)
 * Last line: "RESULT ok ..." or "RESULT fail win32=N nt=0x... ..."; the exit code is the Win32 error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>

#include <smb2.h>
#include <libsmb2.h>
#include <libsmb2-nitro.h>

#define CHUNK_MAX (1024 * 1024)

static struct
{
    enum smb2_negotiate_version version;
    int sign;
    int seal;            /* -1 default, 0 never, 1 required */
    const char *user, *password;
    const char *logon_user, *logon_password;
    int impersonate_all;
    const char *package;
    int timeout;
    char server[256], share[256];
} opt;

static HANDLE logon_token;

static void split_user(const char *in, char *domain, size_t cd, char *user, size_t cu)
{
    const char *bs = strchr(in, '\\');

    if (bs)
    {
        _snprintf(domain, cd, "%.*s", (int)(bs - in), in);
        _snprintf(user, cu, "%s", bs + 1);
    }
    else
    {
        domain[0] = 0;
        _snprintf(user, cu, "%s", in);
    }
    domain[cd - 1] = 0;
    user[cu - 1] = 0;
}

static void wipe(char *s)
{
    if (s)
        SecureZeroMemory(s, strlen(s));
}

static int fail(struct smb2_context *smb2, int rc, const char *what)
{
    uint32_t w = NitroSmb2ErrorToWin32(smb2, rc);
    struct nitro_smb2_auth_info ai;

    memset(&ai, 0, sizeof(ai));
    ai.size = sizeof(ai);
    NitroSmb2GetAuthInfo(smb2, &ai);
    printf("RESULT fail win32=%u nt=0x%08x rc=%d stage=%s reason=%d sspi=0x%08x tcp=%d neg=%d auth=%d err=\"%s\"\n",
           (unsigned)w, (unsigned)smb2_get_nterror(smb2), rc, what, ai.reason, (unsigned)ai.sspi_status,
           ai.tcp_connected, ai.negotiated, ai.authenticated, smb2_get_error(smb2));
    return w ? (int)w : 1;
}

static const char *dialect_name(uint16_t d)
{
    switch (d)
    {
        case SMB2_VERSION_0202: return "2.0.2";
        case SMB2_VERSION_0210: return "2.1";
        case SMB2_VERSION_0300: return "3.0";
        case SMB2_VERSION_0302: return "3.0.2";
        case SMB2_VERSION_0311: return "3.1.1";
    }
    return "?";
}

static void print_info(struct smb2_context *smb2)
{
    struct nitro_smb2_auth_info ai;

    memset(&ai, 0, sizeof(ai));
    ai.size = sizeof(ai);
    NitroSmb2GetAuthInfo(smb2, &ai);
    printf("INFO dialect=%s max_read=%u max_write=%u package=%s explicit=%d spnego=%d server_token_verified=%d "
           "session_flags=0x%04x session_key=%u\n",
           dialect_name(smb2_get_dialect(smb2)), (unsigned)smb2_get_max_read_size(smb2),
           (unsigned)smb2_get_max_write_size(smb2), ai.package, ai.explicit_credentials, ai.spnego,
           ai.server_token_verified, ai.session_flags, ai.session_key_length);
}

/* Acquire credentials (in the impersonated context for -L) and connect. */
static struct smb2_context *connect_share(int *prc)
{
    struct smb2_context *smb2 = smb2_init_context();
    int rc;

    *prc = -ENOMEM;
    if (smb2 == NULL)
    {
        printf("RESULT fail win32=8 smb2_init_context\n");
        return NULL;
    }
    smb2_set_version(smb2, opt.version);
    smb2_set_timeout(smb2, opt.timeout);
    if (opt.sign)
        smb2_set_sign(smb2, 1);
    if (opt.seal >= 0)
        smb2_set_seal(smb2, opt.seal);

    if (opt.user)
    {
        char domain[256], user[256];

        split_user(opt.user, domain, sizeof(domain), user, sizeof(user));
        rc = NitroSmb2SetCredentials(smb2, user, domain[0] ? domain : NULL, opt.password, opt.package);
    }
    else
    {
        if (logon_token && !opt.impersonate_all && !ImpersonateLoggedOnUser(logon_token))
        {
            printf("RESULT fail win32=%lu ImpersonateLoggedOnUser\n", GetLastError());
            smb2_destroy_context(smb2);
            return NULL;
        }
        rc = NitroSmb2SetCredentials(smb2, NULL, NULL, NULL, opt.package);
        if (logon_token && !opt.impersonate_all)
            RevertToSelf();
    }
    if (rc < 0)
    {
        *prc = rc;
        exit(fail(smb2, rc, "credentials"));
    }
    rc = smb2_connect_share(smb2, opt.server, opt.share, NULL);
    *prc = rc;
    if (rc < 0)
        return smb2;
    return smb2;
}

static int sha256_begin(BCRYPT_ALG_HANDLE *alg, BCRYPT_HASH_HANDLE *h)
{
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return -1;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(*alg, h, NULL, 0, NULL, 0, 0)))
        return -1;
    return 0;
}

static void sha256_end(BCRYPT_ALG_HANDLE alg, BCRYPT_HASH_HANDLE h, char hex[65])
{
    UCHAR d[32];
    int i;

    BCryptFinishHash(h, d, sizeof(d), 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    for (i = 0; i < 32; i++)
        sprintf(hex + 2 * i, "%02x", d[i]);
}

/* deterministic pattern: xorshift64 stream from the seed */
static void gen_fill(uint8_t *buf, size_t n, uint64_t *state)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        uint64_t x = *state;

        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        buf[i] = (uint8_t)(x >> 24);
    }
}

static size_t chunk_for(struct smb2_context *smb2, int write)
{
    size_t m = write ? smb2_get_max_write_size(smb2) : smb2_get_max_read_size(smb2);

    if (m == 0 || m > CHUNK_MAX)
        m = CHUNK_MAX;
    return m;
}

static int do_putgen(struct smb2_context *smb2, const char *path, uint64_t bytes, uint64_t seed, char hex[65],
                     double *secs)
{
    struct smb2fh *fh;
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE h;
    uint64_t left = bytes, state = seed ? seed : 0x9E3779B97F4A7C15ULL;
    size_t chunk = chunk_for(smb2, 1);
    uint8_t *buf = malloc(chunk);
    LARGE_INTEGER f, t0, t1;
    int rc = 0;

    if (buf == NULL || sha256_begin(&alg, &h) < 0)
        return -ENOMEM;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    fh = smb2_open(smb2, path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fh == NULL)
    {
        free(buf);
        return -EIO;
    }
    while (left > 0)
    {
        size_t n = left > chunk ? chunk : (size_t)left, off = 0;

        gen_fill(buf, n, &state);
        BCryptHashData(h, buf, (ULONG)n, 0);
        while (off < n)
        {
            int w = smb2_write(smb2, fh, buf + off, (uint32_t)(n - off));

            if (w <= 0)
            {
                rc = w < 0 ? w : -EIO;
                goto out;
            }
            off += (size_t)w;
        }
        left -= n;
    }
out:
    if (smb2_close(smb2, fh) < 0 && rc == 0)
        rc = -EIO;
    QueryPerformanceCounter(&t1);
    *secs = (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart;
    sha256_end(alg, h, hex);
    free(buf);
    return rc;
}

static int do_getsum(struct smb2_context *smb2, const char *path, uint64_t *size, char hex[65], double *secs,
                     FILE *out)
{
    struct smb2fh *fh;
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE h;
    size_t chunk = chunk_for(smb2, 0);
    uint8_t *buf = malloc(chunk);
    LARGE_INTEGER f, t0, t1;
    int rc = 0;

    *size = 0;
    if (buf == NULL || sha256_begin(&alg, &h) < 0)
        return -ENOMEM;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    fh = smb2_open(smb2, path, O_RDONLY);
    if (fh == NULL)
    {
        free(buf);
        return -EIO;
    }
    for (;;)
    {
        int r = smb2_read(smb2, fh, buf, (uint32_t)chunk);

        if (r < 0)
        {
            rc = r;
            break;
        }
        if (r == 0)
            break;
        BCryptHashData(h, buf, (ULONG)r, 0);
        if (out && fwrite(buf, 1, (size_t)r, out) != (size_t)r)
        {
            rc = -EIO;
            break;
        }
        *size += (uint64_t)r;
    }
    if (smb2_close(smb2, fh) < 0 && rc == 0)
        rc = -EIO;
    QueryPerformanceCounter(&t1);
    *secs = (double)(t1.QuadPart - t0.QuadPart) / (double)f.QuadPart;
    sha256_end(alg, h, hex);
    free(buf);
    return rc;
}

static int do_put(struct smb2_context *smb2, const char *local, const char *remote, uint64_t *size)
{
    FILE *in = fopen(local, "rb");
    struct smb2fh *fh;
    size_t chunk = chunk_for(smb2, 1), n;
    uint8_t *buf;
    int rc = 0;

    *size = 0;
    if (in == NULL)
        return -ENOENT;
    buf = malloc(chunk);
    fh = buf ? smb2_open(smb2, remote, O_WRONLY | O_CREAT | O_TRUNC) : NULL;
    if (fh == NULL)
    {
        fclose(in);
        free(buf);
        return -EIO;
    }
    while ((n = fread(buf, 1, chunk, in)) > 0)
    {
        size_t off = 0;

        while (off < n)
        {
            int w = smb2_write(smb2, fh, buf + off, (uint32_t)(n - off));

            if (w <= 0)
            {
                rc = w < 0 ? w : -EIO;
                goto out;
            }
            off += (size_t)w;
        }
        *size += n;
    }
out:
    if (smb2_close(smb2, fh) < 0 && rc == 0)
        rc = -EIO;
    fclose(in);
    free(buf);
    return rc;
}

static int do_ls(struct smb2_context *smb2, const char *path)
{
    struct smb2dir *dir = smb2_opendir(smb2, path);
    struct smb2dirent *ent;
    int n = 0;

    if (dir == NULL)
        return -EIO;
    while ((ent = smb2_readdir(smb2, dir)) != NULL)
    {
        printf("LS %-4s %12llu %s\n", ent->st.smb2_type == SMB2_TYPE_DIRECTORY ? "DIR" : "FILE",
               (unsigned long long)ent->st.smb2_size, ent->name);
        n++;
    }
    smb2_closedir(smb2, dir);
    printf("LS entries=%d\n", n);
    return 0;
}

static void process_counters(DWORD *handles, SIZE_T *priv)
{
    PROCESS_MEMORY_COUNTERS_EX pmc;

    *handles = 0;
    *priv = 0;
    GetProcessHandleCount(GetCurrentProcess(), handles);
    memset(&pmc, 0, sizeof(pmc));
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc)))
        *priv = pmc.PrivateUsage;
}

static int do_loop(int seconds, const char *path, uint64_t bytes)
{
    DWORD start = GetTickCount(), last = 0, handles;
    SIZE_T priv;
    unsigned long cycles = 0, failures = 0;

    process_counters(&handles, &priv);
    printf("LOOP t=0 cycles=0 failures=0 handles=%lu private=%lu\n", handles, (unsigned long)priv);
    fflush(stdout);
    while ((GetTickCount() - start) / 1000 < (DWORD)seconds)
    {
        int rc;
        struct smb2_context *smb2 = connect_share(&rc);
        char h1[65], h2[65];
        double s1, s2;
        uint64_t size;

        cycles++;
        if (smb2 == NULL || rc < 0 ||
            do_putgen(smb2, path, bytes, cycles, h1, &s1) < 0 ||
            do_getsum(smb2, path, &size, h2, &s2, NULL) < 0 ||
            size != bytes || strcmp(h1, h2) != 0 ||
            smb2_unlink(smb2, path) < 0)
        {
            failures++;
            if (failures <= 5)
                printf("LOOP failure cycle=%lu err=\"%s\"\n", cycles, smb2 ? smb2_get_error(smb2) : "init");
        }
        if (smb2)
        {
            if (rc >= 0)
                smb2_disconnect_share(smb2);
            smb2_destroy_context(smb2);
        }
        if ((GetTickCount() - start) / 60000 != last)
        {
            last = (GetTickCount() - start) / 60000;
            process_counters(&handles, &priv);
            printf("LOOP t=%lu cycles=%lu failures=%lu handles=%lu private=%lu\n", last * 60, cycles, failures,
                   handles, (unsigned long)priv);
            fflush(stdout);
        }
    }
    process_counters(&handles, &priv);
    printf("LOOP end cycles=%lu failures=%lu handles=%lu private=%lu\n", cycles, failures, handles,
           (unsigned long)priv);
    printf("RESULT %s loop cycles=%lu failures=%lu\n", failures ? "fail win32=1" : "ok", cycles, failures);
    return failures ? 1 : 0;
}

static int usage(void)
{
    printf("usage: smbcli [-v 2.1|3.0|3.02|3.1.1|any] [-s] [-e|-E] [-U [DOM\\]user [-P pw]] "
           "[-L [DOM\\]user [-Q pw] [-I]] [-k package] [-t secs] COMMAND //server/share [args]\n");
    return 87;
}

static int parse_unc(const char *unc)
{
    const char *p, *s;

    if (strncmp(unc, "//", 2) != 0 && strncmp(unc, "\\\\", 2) != 0)
        return -1;
    p = unc + 2;
    s = strpbrk(p, "/\\");
    if (s == NULL || s == p || s - p >= (int)sizeof(opt.server) || strlen(s + 1) == 0 ||
        strlen(s + 1) >= sizeof(opt.share))
        return -1;
    memcpy(opt.server, p, (size_t)(s - p));
    opt.server[s - p] = 0;
    strcpy(opt.share, s + 1);
    return 0;
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    struct smb2_context *smb2;
    const char *cmd;
    char *pw_copy = NULL, *logon_pw_copy = NULL;
    int i, rc, ret = 0;

    opt.version = SMB2_VERSION_ANY;
    opt.seal = -1;
    opt.timeout = 30;
    setvbuf(stdout, NULL, _IONBF, 0);

    for (i = 1; i < argc && argv[i][0] == '-'; i++)
    {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;

        if (!strcmp(a, "-s")) opt.sign = 1;
        else if (!strcmp(a, "-e")) opt.seal = 1;
        else if (!strcmp(a, "-E")) opt.seal = 0;
        else if (!strcmp(a, "-I")) opt.impersonate_all = 1;
        else if (v == NULL) return usage();
        else if (!strcmp(a, "-v"))
        {
            i++;
            if (!strcmp(v, "2.1")) opt.version = SMB2_VERSION_0210;
            else if (!strcmp(v, "2.0.2")) opt.version = SMB2_VERSION_0202;
            else if (!strcmp(v, "3.0")) opt.version = SMB2_VERSION_0300;
            else if (!strcmp(v, "3.02")) opt.version = SMB2_VERSION_0302;
            else if (!strcmp(v, "3.1.1")) opt.version = SMB2_VERSION_0311;
            else if (!strcmp(v, "any")) opt.version = SMB2_VERSION_ANY;
            else return usage();
        }
        else if (!strcmp(a, "-U")) { opt.user = v; i++; }
        else if (!strcmp(a, "-P")) { opt.password = v; i++; }
        else if (!strcmp(a, "-L")) { opt.logon_user = v; i++; }
        else if (!strcmp(a, "-Q")) { opt.logon_password = v; i++; }
        else if (!strcmp(a, "-k")) { opt.package = v; i++; }
        else if (!strcmp(a, "-t")) { opt.timeout = atoi(v); i++; }
        else return usage();
    }
    if (argc - i < 2 || parse_unc(argv[i + 1]) < 0)
        return usage();
    cmd = argv[i];
    i += 2;

    if (opt.user && opt.password == NULL && getenv("SMBCLI_PASSWORD"))
        opt.password = pw_copy = _strdup(getenv("SMBCLI_PASSWORD"));
    if (opt.user && opt.password == NULL)
    {
        printf("RESULT fail win32=87 no password for -U\n");
        return 87;
    }
    if (opt.logon_user)
    {
        char domain[256], user[256];

        if (opt.logon_password == NULL && getenv("SMBCLI_LOGON_PASSWORD"))
            opt.logon_password = logon_pw_copy = _strdup(getenv("SMBCLI_LOGON_PASSWORD"));
        split_user(opt.logon_user, domain, sizeof(domain), user, sizeof(user));
        if (!LogonUserA(user, domain[0] ? domain : ".", (LPSTR)(opt.logon_password ? opt.logon_password : ""),
                        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &logon_token))
        {
            printf("RESULT fail win32=%lu LogonUser\n", GetLastError());
            return (int)GetLastError();
        }
        wipe(logon_pw_copy);
        if (opt.impersonate_all && !ImpersonateLoggedOnUser(logon_token))
        {
            printf("RESULT fail win32=%lu ImpersonateLoggedOnUser\n", GetLastError());
            return (int)GetLastError();
        }
    }
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (!strcmp(cmd, "loop"))
    {
        if (argc - i < 3)
            return usage();
        ret = do_loop(atoi(argv[i]), argv[i + 1], _strtoui64(argv[i + 2], NULL, 10));
        wipe(pw_copy);
        return ret;
    }

    smb2 = connect_share(&rc);
    wipe(pw_copy);
    if (smb2 == NULL)
        return 8;
    if (rc < 0)
    {
        ret = fail(smb2, rc, "connect");
        smb2_destroy_context(smb2);
        return ret;
    }
    print_info(smb2);

    rc = 0;
    if (!strcmp(cmd, "info"))
        ;
    else if (!strcmp(cmd, "ls") && argc - i >= 1)
        rc = do_ls(smb2, argv[i]);
    else if (!strcmp(cmd, "stat") && argc - i >= 1)
    {
        struct smb2_stat_64 st;

        rc = smb2_stat(smb2, argv[i], &st);
        if (rc == 0)
            printf("STAT type=%u size=%llu\n", (unsigned)st.smb2_type, (unsigned long long)st.smb2_size);
    }
    else if (!strcmp(cmd, "rm") && argc - i >= 1)
        rc = smb2_unlink(smb2, argv[i]);
    else if (!strcmp(cmd, "mkdir") && argc - i >= 1)
        rc = smb2_mkdir(smb2, argv[i]);
    else if (!strcmp(cmd, "rmdir") && argc - i >= 1)
        rc = smb2_rmdir(smb2, argv[i]);
    else if (!strcmp(cmd, "putgen") && argc - i >= 2)
    {
        char hex[65];
        double secs;
        uint64_t bytes = _strtoui64(argv[i + 1], NULL, 10);

        rc = do_putgen(smb2, argv[i], bytes, argc - i >= 3 ? _strtoui64(argv[i + 2], NULL, 10) : 0, hex, &secs);
        if (rc == 0)
            printf("PUT bytes=%llu sha256=%s secs=%.3f MBps=%.1f\n", (unsigned long long)bytes, hex, secs,
                   secs > 0 ? bytes / secs / 1048576.0 : 0.0);
    }
    else if ((!strcmp(cmd, "getsum") && argc - i >= 1) || (!strcmp(cmd, "get") && argc - i >= 2))
    {
        char hex[65];
        double secs;
        uint64_t size;
        FILE *out = NULL;

        if (!strcmp(cmd, "get") && (out = fopen(argv[i + 1], "wb")) == NULL)
            rc = -ENOENT;
        else
        {
            rc = do_getsum(smb2, argv[i], &size, hex, &secs, out);
            if (out)
                fclose(out);
            if (rc == 0)
                printf("GET bytes=%llu sha256=%s secs=%.3f MBps=%.1f\n", (unsigned long long)size, hex, secs,
                       secs > 0 ? size / secs / 1048576.0 : 0.0);
        }
    }
    else if (!strcmp(cmd, "put") && argc - i >= 2)
    {
        uint64_t size;

        rc = do_put(smb2, argv[i], argv[i + 1], &size);
        if (rc == 0)
            printf("PUT bytes=%llu\n", (unsigned long long)size);
    }
    else
    {
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return usage();
    }

    if (rc < 0)
        ret = fail(smb2, rc, cmd);
    else
        printf("RESULT ok %s\n", cmd);
    smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);
    if (logon_token)
        CloseHandle(logon_token);
    WSACleanup();
    return ret;
}
