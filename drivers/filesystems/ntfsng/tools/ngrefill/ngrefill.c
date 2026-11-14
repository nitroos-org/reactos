/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Guest-side check that a write that follows a delete on a full volume is not refused
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * usage: ngrefill DIR [CYCLES [MAXWAIT_MS]]
 *   1. Fills the volume of DIR with 1 MB files, then 4 KB files, until the first failure (disk full).
 *   2. CYCLES (default 40) times: deletes k (1..30) random 1 MB files and at once writes a new file of 80 % of the freed
 *      bytes, then 20 small files.  The space was just freed, so the write must not be refused; a refusal is retried every
 *      25 ms for up to 4 s and counted, with the time it took.  The driver may leave the clusters of a free that no journal
 *      commit covers yet alone, but it must find the rest of the volume (an allocator that gives up on a bitmap page after
 *      a reserved range hides the free clusters of the page: 13-15 % of the cycles were refused for 2.1 s).
 *   3. Every surviving file is read back and checked against its key (a block of another file = corruption).
 *   Then it reads the driver's retry counter (FSCTL_NG_PROFILE, stage 31: a growth that failed with ENOSPC while frees were
 *   uncommitted and committed once to try again).  Free space that the allocator cannot find is the only way to get there, so the
 *   count must stay 0 here.
 *   Lines: NGR:... to stdout and the debugger.  Verdict lines NGR:PASS / NGR:FAIL; exit 0 when all PASS.
 *   PASS needs: no refused first attempt, longest wait <= MAXWAIT_MS (default 1000), no missing or corrupt file, retry count 0.
 */
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MB (1u << 20)
#define FSCTL_NG_PROFILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0xA42, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define NGP_RESV_RETRY 31
typedef struct { ULONGLONG Count, Ticks, Bytes; } PSTAT;
typedef struct { ULONG Version, Stages; ULONGLONG TicksPerSecond; PSTAT Stage[64]; } PROFILE;

static char Dir[MAX_PATH];
static unsigned CrcT[256];
static unsigned long long Rs;
static char FailWhere[48];

static void out(const char *fmt, ...)
{
    char line[400];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 2] = 0;
    strcat(line, "\n");
    OutputDebugStringA(line);
    fputs(line, stdout);
    fflush(stdout);
}

static unsigned rnd(void)
{
    Rs = Rs * 6364136223846793005ULL + 1442695040888963407ULL;
    return (unsigned)(Rs >> 33);
}

static unsigned crc32b(unsigned c, const unsigned char *p, unsigned n)
{
    c = ~c;
    while (n--)
        c = CrcT[(c ^ *p++) & 0xff] ^ (c >> 8);
    return ~c;
}

static double now_ms(void)
{
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return c.QuadPart * 1000.0 / f.QuadPart;
}

/* 4 KB block b of file n: {magic, key n, block b, crc of the rest} */
static void block(unsigned char *p, unsigned n, unsigned b)
{
    unsigned *h = (unsigned *)p, i;
    unsigned long long s = ((unsigned long long)n << 20) ^ b ^ 0x5555;
    for (i = 16; i < 4096; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] = (unsigned char)(s >> 33);
    }
    h[0] = 0x4c4c5546;
    h[1] = n;
    h[2] = b;
    h[3] = crc32b(0, p + 16, 4096 - 16);
}

static void path(char *p, unsigned n)
{
    sprintf(p, "%s\\f%06u.dat", Dir, n);
}

/* Writes file n of @size bytes; 0, or the GetLastError of the failure (the partial file is deleted). */
static DWORD put(unsigned n, unsigned size)
{
    char p[MAX_PATH];
    static unsigned char buf[64 * 1024];
    HANDLE h;
    unsigned off;

    path(p, n);
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        strcpy(FailWhere, "create");
        return GetLastError();
    }
    for (off = 0; off < size; off += sizeof(buf)) {
        unsigned len = size - off > sizeof(buf) ? sizeof(buf) : size - off, k;
        DWORD w;
        for (k = 0; k < len; k += 4096)
            block(buf + k, n, (off + k) / 4096);
        if (!WriteFile(h, buf, len, &w, NULL) || w != len) {
            DWORD e = GetLastError();
            sprintf(FailWhere, "write@%uKB", off >> 10);
            CloseHandle(h);
            DeleteFileA(p);
            return e ? e : ERROR_DISK_FULL;
        }
    }
    if (!CloseHandle(h)) {
        DWORD e = GetLastError();
        strcpy(FailWhere, "close");
        DeleteFileA(p);
        return e;
    }
    return 0;
}

static unsigned long long freebytes(void)
{
    ULARGE_INTEGER a, t, f;
    char d[4] = "C:\\";
    d[0] = Dir[0];
    a.QuadPart = 0;
    GetDiskFreeSpaceExA(d, &a, &t, &f);
    return a.QuadPart;
}

/* The retry count of the driver, or -1 when the volume handle or the FSCTL is not available. */
static long long retries(void)
{
    char vol[] = "\\\\.\\C:";
    static PROFILE P;
    DWORD n;
    HANDLE h;
    long long r = -1;

    vol[4] = Dir[0];
    h = CreateFileA(vol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    if (DeviceIoControl(h, FSCTL_NG_PROFILE, NULL, 0, &P, sizeof(P), &n, NULL) && n == sizeof(P))
        r = (long long)P.Stage[NGP_RESV_RETRY].Count;
    CloseHandle(h);
    return r;
}

typedef struct { unsigned n, size; } FILEREC;
static FILEREC *Files;
static unsigned NF, Next = 1;

int main(int argc, char **argv)
{
    unsigned i, cycles = 40, failed_first = 0, bad = 0, nchk = 0, small_fail = 0;
    double t0, maxretry = 0, maxsucc = 0, maxwait = 1000;
    DWORD e;
    long long r0, r1;
    int fails = 0;

    for (i = 0; i < 256; i++) {
        unsigned c = i, k;
        for (k = 0; k < 8; k++)
            c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
        CrcT[i] = c;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: ngrefill DIR [CYCLES [MAXWAIT_MS]]\n");
        return 2;
    }
    lstrcpynA(Dir, argv[1], MAX_PATH);
    if (argc > 2)
        cycles = atoi(argv[2]);
    if (argc > 3)
        maxwait = atoi(argv[3]);
    Rs = GetTickCount();
    CreateDirectoryA(Dir, NULL);
    Files = calloc(1 << 20, sizeof(FILEREC));
    if (!Files)
        return 3;
    setvbuf(stdout, NULL, _IONBF, 0);
    r0 = retries();
    out("NGR:START free=%llu MB retries=%lld", freebytes() >> 20, r0);
    t0 = now_ms();
    for (;;) {
        e = put(Next, MB);
        if (e)
            break;
        Files[NF].n = Next++;
        Files[NF++].size = MB;
    }
    out("NGR:FILL1 files=%u gle=%lu t=%.0f ms free=%llu KB", NF, e, now_ms() - t0, freebytes() >> 10);
    for (;;) {
        e = put(Next, 4096);
        if (e)
            break;
        Files[NF].n = Next++;
        Files[NF++].size = 4096;
    }
    out("NGR:FILL2 gle=%lu free=%llu KB", e, freebytes() >> 10);
    for (i = 0; i < cycles; i++) {
        unsigned k = 1 + rnd() % 30, j, freed = 0, sz;
        double td, tf = 0, ts = 0;
        DWORD ee = 0;
        char fw[48] = "-";

        for (j = 0; j < k && NF; j++) {
            unsigned x, tries = 0;
            char p[MAX_PATH];
            do { x = rnd() % NF; } while (Files[x].size != MB && ++tries < 1000);
            if (Files[x].size != MB)
                break;
            path(p, Files[x].n);
            if (DeleteFileA(p)) {
                freed += MB;
                Files[x] = Files[--NF];
            }
        }
        if (!freed)
            continue;
        td = now_ms();
        sz = (unsigned)((freed / 10) * 8 / 4096) * 4096;
        if (sz < 4096)
            sz = 4096;
        for (;;) {
            ee = put(Next, sz);
            if (!ee)
                break;
            if (!tf) {
                tf = now_ms() - td;
                strcpy(fw, FailWhere);
            }
            if (now_ms() - td > 4000)
                break;
            Sleep(25);
        }
        if (!ee) {
            ts = now_ms() - td;
            Files[NF].n = Next++;
            Files[NF++].size = sz;
        } else
            fails++;
        if (tf)
            failed_first++;
        if (tf > maxretry)
            maxretry = tf;
        if (ts > maxsucc)
            maxsucc = ts;
        if (tf || ee)
            out("NGR:CYCLE %u del=%u MB new=%u KB first_fail=%.0f ms success=%.0f ms gle=%lu fail_at=%s", i, freed >> 20, sz >> 10, tf, ts, ee, fw);
        for (j = 0; j < 20; j++) {
            e = put(Next, 4096);
            if (e) {
                small_fail++;
                break;
            }
            Files[NF].n = Next++;
            Files[NF++].size = 4096;
        }
    }
    r1 = retries();
    out("NGR:SUMMARY cycles=%u first_attempt_failed=%u max_first_fail_ms=%.0f max_success_ms=%.0f small_fail_cycles=%u retries=%lld",
        cycles, failed_first, maxretry, maxsucc, small_fail, r1 < 0 ? r1 : r1 - r0);
    for (i = 0; i < NF; i++) {
        char p[MAX_PATH];
        static unsigned char b[4096];
        HANDLE h;
        unsigned off, blk = 0;
        DWORD r;

        path(p, Files[i].n);
        h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            bad++;
            out("NGR:MISSING f%06u", Files[i].n);
            continue;
        }
        nchk++;
        for (off = 0; off < Files[i].size; off += 4096, blk++) {
            unsigned *hd = (unsigned *)b;
            if (!ReadFile(h, b, 4096, &r, NULL) || r != 4096 || hd[0] != 0x4c4c5546 || hd[1] != Files[i].n || hd[2] != blk ||
                hd[3] != crc32b(0, b + 16, 4096 - 16)) {
                bad++;
                out("NGR:CORRUPT f%06u block %u (key %u block %u)", Files[i].n, blk, hd[1], hd[2]);
                break;
            }
        }
        CloseHandle(h);
    }
    out("NGR:VERIFY files=%u bad=%u", nchk, bad);
    out("NGR:%s no-refusal first_attempt_failed=%u unrecovered=%d", failed_first == 0 && !fails ? "PASS" : "FAIL", failed_first, fails);
    out("NGR:%s wait max_success_ms=%.0f limit=%.0f", maxsucc <= maxwait ? "PASS" : "FAIL", maxsucc, maxwait);
    out("NGR:%s verify bad=%u", bad == 0 ? "PASS" : "FAIL", bad);
    out("NGR:%s retry-count %lld", r1 < 0 ? "SKIP" : (r1 - r0 == 0 ? "PASS" : "FAIL"), r1 < 0 ? r1 : r1 - r0);
    out("NGR:DONE");
    return (failed_first || fails || maxsucc > maxwait || bad || (r1 >= 0 && r1 != r0)) ? 1 : 0;
}
