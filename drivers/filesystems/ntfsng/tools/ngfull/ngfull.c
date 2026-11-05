/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Guest-side check that a failed extend on a full volume costs no disk writes and changes nothing
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * usage: ngfull DIR [ATTEMPTS [PAUSE_MS [COMFLAG [FREECL]]]]
 *   Makes DIR with a 64 KB nonresident file F (pattern), a 100-byte resident file G and a filler that takes
 *   every free cluster.  Then ATTEMPTS (default 1000) failing extends: SetEndOfFile beyond the end of F in
 *   different sizes (one cluster, 512 bytes past the last cluster, 1 MB, 64 MB), WriteFile appends to F and a
 *   growth of G past its MFT record.  Each must fail with ERROR_DISK_FULL and leave size and contents alone.
 *   Then the filler is deleted and the same extends must succeed.
 *   With FREECL (default 0) the filler is cut back so that FREECL clusters stay free and every extend asks for more than that: the
 *   allocator then finds some space and runs out, the case of a big extend on a nearly full volume.
 *   NGF: lines go to stdout, the debugger and, when COMFLAG is 1, to COM2.  With PAUSE_MS the loop is fenced by
 *   NGF:LOOP-START / NGF:LOOP-END markers and a pause on each side, so the host can sample the block device
 *   counters (QMP query-blockstats) at each marker; counters between the markers are the failed attempts' cost.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int Pass, Fail;
static unsigned char bigbuf[9 * 1048576];
static HANDLE Com = INVALID_HANDLE_VALUE;
static DWORD Cluster = 4096;

static void out(const char *fmt, ...)
{
    char line[600];
    DWORD n;
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 2] = 0;
    strcat(line, "\n");
    OutputDebugStringA(line);
    fputs(line, stdout);
    fflush(stdout);
    if (Com != INVALID_HANDLE_VALUE)
        WriteFile(Com, line, (DWORD)strlen(line), &n, NULL);
}

static void report(const char *name, int ok, const char *detail)
{
    out("NGF:%s %s %s", ok ? "PASS" : "FAIL", name, detail ? detail : "");
    if (ok) Pass++; else Fail++;
}

static unsigned char pat(unsigned i) { return (unsigned char)((i * 7 + 3) & 0xff); }

static int setsize(HANDLE h, LONGLONG size, DWORD *err)
{
    LARGE_INTEGER li;
    li.QuadPart = size;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) { *err = GetLastError(); return 0; }
    if (!SetEndOfFile(h)) { *err = GetLastError(); return 0; }
    *err = 0;
    return 1;
}

static LONGLONG getsize(HANDLE h)
{
    LARGE_INTEGER li;
    li.QuadPart = -1;
    GetFileSizeEx(h, &li);
    return li.QuadPart;
}

static int check_pattern(HANDLE h, DWORD len)
{
    static unsigned char buf[65536];
    DWORD got = 0, i;
    LARGE_INTEGER z;
    z.QuadPart = 0;
    SetFilePointerEx(h, z, NULL, FILE_BEGIN);
    if (!ReadFile(h, buf, len, &got, NULL) || got != len)
        return 0;
    for (i = 0; i < len; i++)
        if (buf[i] != pat(i))
            return 0;
    return 1;
}

static int isfull(DWORD e) { return e == ERROR_DISK_FULL || e == ERROR_HANDLE_DISK_FULL; }

int main(int argc, char **argv)
{
    char dir[MAX_PATH], path[MAX_PATH], root[4];
    static unsigned char data[65536];
    HANDLE F, G, Fill;
    DWORD i, freecl = 0, attempts = 1000, pause = 0, err, w, bad = 0, notfull = 0, spc, bps, fc, tc;
    LONGLONG sizeF = 65536, sizeG = 100, fb;
    static const LONGLONG grow[] = { 0, 512, 65536, 1048576, 67108864 };
    char d[200];

    if (argc < 2) { fputs("usage: ngfull DIR [ATTEMPTS [PAUSE_MS [COMFLAG [FREECL]]]]\n", stderr); return 2; }
    strncpy(dir, argv[1], sizeof(dir) - 1);
    if (argc > 2) attempts = atoi(argv[2]);
    if (argc > 3) pause = atoi(argv[3]);
    if (argc > 4 && atoi(argv[4]) == 1)
        Com = CreateFileA("\\\\.\\COM2", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (argc > 5) freecl = atoi(argv[5]);
    CreateDirectoryA(dir, NULL);
    root[0] = dir[0]; root[1] = ':'; root[2] = '\\'; root[3] = 0;
    if (GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc))
        Cluster = spc * bps;
    out("NGF:INFO cluster %lu free %lu clusters", (unsigned long)Cluster, (unsigned long)fc);

    for (i = 0; i < sizeof(data); i++) data[i] = pat(i);
    _snprintf(path, sizeof(path) - 1, "%s\\F.bin", dir);
    F = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    _snprintf(path, sizeof(path) - 1, "%s\\G.bin", dir);
    G = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    if (F == INVALID_HANDLE_VALUE || G == INVALID_HANDLE_VALUE) { report("setup", 0, "create F/G"); goto done; }
    WriteFile(F, data, 65536, &w, NULL);
    WriteFile(G, data, 100, &w, NULL);
    FlushFileBuffers(F);
    FlushFileBuffers(G);

    /* Fill: 1 MB, then cluster-sized writes, until a write fails */
    _snprintf(path, sizeof(path) - 1, "%s\\FILL.bin", dir);
    Fill = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Fill == INVALID_HANDLE_VALUE) { report("setup", 0, "create filler"); goto done; }
    {
        static unsigned char big[1048576];
        DWORD sz[3];
        int k;
        sz[0] = sizeof(big); sz[1] = 65536; sz[2] = Cluster;
        for (k = 0; k < 3; k++)
            while (WriteFile(Fill, big, sz[k], &w, NULL) && w == sz[k])
                ;
    }
    if (freecl)
    {
        LONGLONG fs = getsize(Fill) - (LONGLONG)freecl * Cluster;
        if (!setsize(Fill, fs, &err))
            out("NGF:INFO trim of filler failed %lu", (unsigned long)err);
    }
    FlushFileBuffers(Fill);
    out("NGF:INFO filler %I64d bytes", getsize(Fill));
    GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc);
    out("NGF:INFO free clusters after fill %lu", (unsigned long)fc);

    sizeF = getsize(F);
    /* F's size is 64 KB = cluster aligned: any growth needs clusters */
    fb = (LONGLONG)freecl * Cluster;
    if (setsize(F, sizeF + fb + Cluster, &err) || !isfull(err))
    {
        _snprintf(d, sizeof(d), "precondition: one cluster extend err %lu", (unsigned long)err);
        report("full-volume", 0, d);
        if (err == 0) { setsize(F, sizeF, &err); }
    }
    else
        report("full-volume", 1, "one-cluster extend fails with disk full");

    if (pause)
    {
        out("NGF:QUIET-START");
        Sleep(pause);
    }
    GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc);
    out("NGF:INFO free clusters before loop %lu", (unsigned long)fc);
    out("NGF:LOOP-START attempts=%lu", (unsigned long)attempts);
    for (i = 0; i < attempts; i++)
    {
        int kind = i % 7;
        DWORD e = 0;
        int ok;
        if (kind < 5)
        {
            LONGLONG ns = sizeF + fb + (kind == 1 ? Cluster + 512 : grow[kind] ? grow[kind] : Cluster);
            ok = setsize(F, ns, &e);
        }
        else if (kind == 5)
        {
            if (fb + Cluster > (LONGLONG)sizeof(bigbuf))
                ok = setsize(F, sizeF + fb + 67108864, &e);    /* the free space is larger than the buffer: a SetEndOfFile instead */
            else
            {
                LARGE_INTEGER li;
                li.QuadPart = sizeF;
                SetFilePointerEx(F, li, NULL, FILE_BEGIN);
                ok = WriteFile(F, bigbuf, (DWORD)(fb + Cluster), &w, NULL);
                e = ok ? 0 : GetLastError();
            }
        }
        else
            ok = setsize(G, fb + 1048576, &e);
        if (ok) bad++;
        else if (!isfull(e)) notfull++;
    }
    out("NGF:LOOP-END");
    if (pause)
        Sleep(pause);
    GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc);
    out("NGF:INFO free clusters after loop %lu", (unsigned long)fc);
    _snprintf(d, sizeof(d), "%lu attempts, %lu succeeded, %lu with another error", (unsigned long)attempts, (unsigned long)bad, (unsigned long)notfull);
    report("failed-extends", bad == 0 && notfull == 0, d);

    _snprintf(d, sizeof(d), "F %I64d (was %I64d), G %I64d (was %I64d)", getsize(F), sizeF, getsize(G), sizeG);
    report("sizes-unchanged", getsize(F) == sizeF && getsize(G) == sizeG, d);
    report("contents-unchanged", check_pattern(F, 65536) && check_pattern(G, 100), NULL);

    if (fb)
    {
        /* The boundary: a growth by exactly the free space (as it is now) fits, and gives it all back when cut again */
        DWORD fcx;
        LONGLONG want;
        int ok;
        GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc);
        fcx = fc;
        want = sizeF + (LONGLONG)fcx * Cluster;
        ok = setsize(F, want, &err) && getsize(F) == want;
        _snprintf(d, sizeof(d), "%lu free clusters: err %lu size %I64d (asked %I64d)", (unsigned long)fcx, (unsigned long)err, getsize(F), want);
        report("exact-fit-extend", ok, d);
        report("exact-fit-shrink", setsize(F, sizeF, &err) && getsize(F) == sizeF && check_pattern(F, 65536), NULL);
        GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc);
        _snprintf(d, sizeof(d), "free clusters %lu (was %lu)", (unsigned long)fc, (unsigned long)fcx);
        report("exact-fit-free-restored", fc == fcx, d);
    }

    /* Free space: the same extends succeed, old data kept, new data zero */
    CloseHandle(Fill);
    DeleteFileA(path);
    for (w = 0; w < 20; w++)
    {
        GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc);
        if (fc > 1024) break;
        Sleep(500);
    }
    report("extend-after-free-F", setsize(F, sizeF + 1048576, &err) && getsize(F) == sizeF + 1048576, NULL);
    report("extend-after-free-G", setsize(G, 1048576, &err) && getsize(G) == 1048576, NULL);
    {
        unsigned char z[4096];
        LARGE_INTEGER li;
        DWORD got = 1, nz = 0, k;
        li.QuadPart = sizeF;
        SetFilePointerEx(F, li, NULL, FILE_BEGIN);
        ReadFile(F, z, 4096, &got, NULL);
        for (k = 0; k < got; k++) nz |= z[k];
        report("new-range-zero", got == 4096 && nz == 0, NULL);
        report("old-data-kept", check_pattern(F, 65536) && check_pattern(G, 100), NULL);
    }
done:
    if (F != INVALID_HANDLE_VALUE) CloseHandle(F);
    if (G != INVALID_HANDLE_VALUE) CloseHandle(G);
    out("NGF:DONE pass=%d fail=%d", Pass, Fail);
    return Fail != 0;
}
