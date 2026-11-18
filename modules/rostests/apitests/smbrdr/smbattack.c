/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     smbattack: load, cancel, device-control and identity tests of the SMB mini-redirector
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Defensive tests of our own driver, run in test VMs only:
 *   smbattack load DIR SECONDS THREADS     mixed file operations under DIR (\\server\share\dir), per-status counts,
 *                                          "SLOW" for an operation that took longer than 150 s
 *   smbattack cancel DIR SECONDS THREADS   overlapped reads/writes cancelled with CancelIoEx, and threads with
 *                                          requests in flight terminated with TerminateThread
 *   smbattack flood FILE THREADS SECONDS   THREADS writers of 1 MiB at once (to FILE-0..FILE-<n>); prints the driver's pool
 *                                          tags while they run
 *   smbattack closestorm FILE N ROUNDS     N threads open FILE, write, then close at the same moment
 *   smbattack ioctl COUNT SEED [PATH [FLAGS]] COUNT calls (FLAGS: nosection, mupsection, nobadptr) with random codes, classes and buffers (device and file
 *                                          system controls, read, write, query/set information, directory,
 *                                          volume, flush, section, lock, EA, security)
 *                                          on the redirector's devices (and PATH, a file on a share)
 *   smbattack attach                       open the engine device and attach: as is, and without
 *                                          SeImpersonatePrivilege (restricted token)
 *   smbattack levels UNC                   open UNC while impersonating at each level and with special tokens
 *   smbattack open NTPATH                  one NtCreateFile of an NT path (cross-session drive names)
 *   smbattack whoami                       user SID, logon id, administrators enabled, SeImpersonatePrivilege held
 *   smbattack badbuf UNC                   write and read a file of a share with an unmapped user buffer
 *   smbattack section NTPATH               NtCreateSection (read-only, commit) on a handle to NTPATH
 *   smbattack probe UNC                    open, read, directory and volume query of UNC, with times
 *   smbattack asuser USER PW OUT CMDLINE   run CMDLINE as USER (new logon session) with its output appended
 *                                          to OUT, wait, exit with its code
 * Output: "ATTACK <test> key=value ..." lines; exit code 0 unless the test could not run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <winioctl.h>
#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/mmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/setypes.h>
#include <ntstatus.h>
#include <sddl.h>
#include <drivers/smbrdr/smbupcall.h>

#define MAXST 64
typedef struct { NTSTATUS st[MAXST]; LONG n[MAXST]; LONG other; CRITICAL_SECTION cs; } STATS;

static void stat_add(STATS *s, NTSTATUS st)
{
    int i;
    EnterCriticalSection(&s->cs);
    for (i = 0; i < MAXST; i++)
    {
        if (s->n[i] && s->st[i] == st) { s->n[i]++; break; }
        if (!s->n[i]) { s->st[i] = st; s->n[i] = 1; break; }
    }
    if (i == MAXST)
        s->other++;
    LeaveCriticalSection(&s->cs);
}

static void stat_print(const char *test, STATS *s)
{
    int i;
    printf("ATTACK %s statuses:", test);
    for (i = 0; i < MAXST && s->n[i]; i++)
        printf(" %08lx=%ld", s->st[i], s->n[i]);
    printf(" other=%ld\n", s->other);
    fflush(stdout);
}

static ULONG rnd(ULONG *s)
{
    ULONG x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return *s = x ? x : 0x9E3779B9u;
}

static NTSTATUS nt_open(const WCHAR *path, ACCESS_MASK access, ULONG disposition, ULONG options, HANDLE *h)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(h, access | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
                        options | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* \\server\share\x -> \??\UNC\server\share\x */
static void nt_name(const WCHAR *unc, WCHAR *out, size_t n)
{
    if (unc[0] == L'\\' && unc[1] == L'\\')
        _snwprintf(out, n - 1, L"\\??\\UNC\\%ls", unc + 2);
    else
        _snwprintf(out, n - 1, L"%ls", unc);
    out[n - 1] = 0;
}

/* load *********************************************************************/

static struct { const WCHAR *dir; DWORD until; STATS st; LONG ops, slow; } Load;

static NTSTATUS timed(NTSTATUS st, DWORD t0, const char *what)
{
    DWORD dt = GetTickCount() - t0;
    if (dt > 150000)
    {
        InterlockedIncrement(&Load.slow);
        printf("ATTACK load SLOW %s %lu ms status %08lx\n", what, dt, st);
        fflush(stdout);
    }
    stat_add(&Load.st, st);
    InterlockedIncrement(&Load.ops);
    return st;
}

static DWORD WINAPI load_thread(LPVOID p)
{
    ULONG s = (ULONG)(ULONG_PTR)p * 7919u + GetTickCount();
    static const FILE_INFORMATION_CLASS dircls[] = { FileDirectoryInformation, FileFullDirectoryInformation,
        FileBothDirectoryInformation, FileNamesInformation, FileIdBothDirectoryInformation, FileIdFullDirectoryInformation };
    static const FILE_INFORMATION_CLASS qcls[] = { FileBasicInformation, FileStandardInformation, FileInternalInformation,
        FileEaInformation, FileNetworkOpenInformation, FileAttributeTagInformation, FileStreamInformation,
        FileNameInformation, FileAllInformation, FilePositionInformation };
    static const FS_INFORMATION_CLASS vcls[] = { FileFsVolumeInformation, FileFsSizeInformation, FileFsFullSizeInformation,
        FileFsAttributeInformation, FileFsDeviceInformation };
    UCHAR *buf = malloc(2 * 1024 * 1024 + 64);
    WCHAR path[600], path2[600], nt[700];
    IO_STATUS_BLOCK iosb;
    HANDLE h;
    NTSTATUS st;
    DWORD t0;

    while (GetTickCount() < Load.until)
    {
        ULONG op = rnd(&s) % 10, len = rnd(&s) % 64 ? (rnd(&s) % 70000) : (rnd(&s) % (2 * 1024 * 1024));
        LARGE_INTEGER off;

        _snwprintf(path, ARRAYSIZE(path) - 1, L"%ls\\f%lu.bin", Load.dir, rnd(&s) % 8);
        path[ARRAYSIZE(path) - 1] = 0;
        nt_name(path, nt, ARRAYSIZE(nt));
        off.QuadPart = (rnd(&s) % 4) ? rnd(&s) % (2 * 1024 * 1024) : ((LONGLONG)rnd(&s) << 20);
        t0 = GetTickCount();
        switch (op)
        {
            case 0: case 1:
                st = timed(nt_open(nt, GENERIC_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, &h), t0, "open");
                if (NT_SUCCESS(st))
                {
                    t0 = GetTickCount();
                    timed(NtReadFile(h, NULL, NULL, NULL, &iosb, buf, len, &off, NULL), t0, "read");
                    NtClose(h);
                }
                break;
            case 2:
                st = timed(nt_open(nt, GENERIC_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, &h), t0, "open-w");
                if (NT_SUCCESS(st))
                {
                    memset(buf, (int)op, len);
                    t0 = GetTickCount();
                    timed(NtWriteFile(h, NULL, NULL, NULL, &iosb, buf, len, &off, NULL), t0, "write");
                    t0 = GetTickCount();
                    timed(NtFlushBuffersFile(h, &iosb), t0, "flush");
                    NtClose(h);
                }
                break;
            case 3:
            {
                _snwprintf(path2, ARRAYSIZE(path2) - 1, L"%ls", Load.dir);
                path2[ARRAYSIZE(path2) - 1] = 0;
                nt_name(path2, nt, ARRAYSIZE(nt));
                st = timed(nt_open(nt, FILE_LIST_DIRECTORY, FILE_OPEN, FILE_DIRECTORY_FILE, &h), t0, "open-dir");
                if (NT_SUCCESS(st))
                {
                    FILE_INFORMATION_CLASS c = dircls[rnd(&s) % ARRAYSIZE(dircls)];
                    ULONG bl = 1 + rnd(&s) % 4096;
                    BOOLEAN restart = TRUE;
                    int k;
                    for (k = 0; k < 4; k++)
                    {
                        t0 = GetTickCount();
                        st = timed(NtQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, bl, c, (BOOLEAN)(rnd(&s) & 1),
                                                        NULL, restart), t0, "dir");
                        restart = FALSE;
                        if (!NT_SUCCESS(st))
                            break;
                    }
                    NtClose(h);
                }
                break;
            }
            case 4:
                st = timed(nt_open(nt, FILE_READ_ATTRIBUTES, FILE_OPEN_IF, 0, &h), t0, "open-q");
                if (NT_SUCCESS(st))
                {
                    t0 = GetTickCount();
                    timed(NtQueryInformationFile(h, &iosb, buf, rnd(&s) % 1024, qcls[rnd(&s) % ARRAYSIZE(qcls)]), t0, "qinfo");
                    t0 = GetTickCount();
                    timed(NtQueryVolumeInformationFile(h, &iosb, buf, rnd(&s) % 1024, vcls[rnd(&s) % ARRAYSIZE(vcls)]), t0, "qvol");
                    NtClose(h);
                }
                break;
            case 5:
                st = timed(nt_open(nt, FILE_WRITE_ATTRIBUTES, FILE_OPEN_IF, 0, &h), t0, "open-s");
                if (NT_SUCCESS(st))
                {
                    FILE_BASIC_INFORMATION b;
                    memset(&b, 0, sizeof(b));
                    b.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
                    t0 = GetTickCount();
                    timed(NtSetInformationFile(h, &iosb, &b, sizeof(b), FileBasicInformation), t0, "setbasic");
                    NtClose(h);
                }
                break;
            case 6:
            {
                st = timed(nt_open(nt, DELETE, FILE_OPEN_IF, 0, &h), t0, "open-ren");
                if (NT_SUCCESS(st))
                {
                    struct { FILE_RENAME_INFORMATION r; WCHAR more[300]; } ri;
                    const WCHAR *names[] = { L"r1.bin", L"..\\..\\escape.bin", L"\\other\\share\\x.bin", L"a:b", L"" };
                    const WCHAR *nm = names[rnd(&s) % ARRAYSIZE(names)];
                    memset(&ri, 0, sizeof(ri));
                    ri.r.ReplaceIfExists = TRUE;
                    ri.r.FileNameLength = (ULONG)wcslen(nm) * sizeof(WCHAR);
                    memcpy(ri.r.FileName, nm, ri.r.FileNameLength);
                    t0 = GetTickCount();
                    timed(NtSetInformationFile(h, &iosb, &ri, sizeof(ri), FileRenameInformation), t0, "rename");
                    NtClose(h);
                }
                break;
            }
            case 7:
                st = timed(nt_open(nt, DELETE, FILE_OPEN, FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE, &h), t0, "delete");
                if (NT_SUCCESS(st))
                    NtClose(h);
                break;
            case 8:
            {
                /* odd names: embedded NUL, colon streams, dots, very long */
                static const WCHAR *odd[] = { L"a\0b", L"x:stream", L"x::$DATA", L"..", L".", L"dirx\\..\\..\\up",
                                              L"trailing.", L"trailing ", L"*?<>|" };
                const WCHAR *o = odd[rnd(&s) % ARRAYSIZE(odd)];
                UNICODE_STRING name;
                OBJECT_ATTRIBUTES oa;
                WCHAR full[1200];
                size_t base;
                _snwprintf(path2, ARRAYSIZE(path2) - 1, L"%ls\\", Load.dir);
                path2[ARRAYSIZE(path2) - 1] = 0;
                nt_name(path2, full, 600);
                base = wcslen(full);
                memcpy(full + base, o, (o == odd[0] ? 3 : wcslen(o)) * sizeof(WCHAR));
                name.Buffer = full;
                name.Length = name.MaximumLength = (USHORT)((base + (o == odd[0] ? 3 : wcslen(o))) * sizeof(WCHAR));
                if (rnd(&s) % 8 == 0)
                {
                    size_t i, n = min(ARRAYSIZE(full), base + 500);
                    for (i = base; i < n; i++)
                        full[i] = L'a' + (WCHAR)(i % 26);
                    name.Length = name.MaximumLength = (USHORT)(n * sizeof(WCHAR));
                }
                InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
                st = timed(NtCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN_IF,
                                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0), t0, "odd-name");
                if (NT_SUCCESS(st))
                    NtClose(h);
                break;
            }
            default:
            {
                WIN32_FIND_DATAW fd;
                HANDLE f;
                _snwprintf(path2, ARRAYSIZE(path2) - 1, L"%ls\\*", Load.dir);
                path2[ARRAYSIZE(path2) - 1] = 0;
                f = FindFirstFileW(path2, &fd);
                if (f != INVALID_HANDLE_VALUE)
                {
                    while (FindNextFileW(f, &fd));
                    FindClose(f);
                }
                timed(f == INVALID_HANDLE_VALUE ? (NTSTATUS)(0xE0000000 | GetLastError()) : STATUS_SUCCESS, t0, "find");
                break;
            }
        }
    }
    free(buf);
    return 0;
}

static int do_load(const WCHAR *dir, int seconds, int threads)
{
    HANDLE *t = calloc(threads, sizeof(HANDLE));
    int i;

    Load.dir = dir;
    Load.until = GetTickCount() + seconds * 1000;
    InitializeCriticalSection(&Load.st.cs);
    for (i = 0; i < threads; i++)
        t[i] = CreateThread(NULL, 0, load_thread, (LPVOID)(ULONG_PTR)(i + 1), 0, NULL);
    for (i = 0; i < threads; i++)
    {
        WaitForSingleObject(t[i], INFINITE);
        CloseHandle(t[i]);
    }
    printf("ATTACK load ops=%ld slow=%ld\n", Load.ops, Load.slow);
    stat_print("load", &Load.st);
    return 0;
}

/* cancel *******************************************************************/

static struct { const WCHAR *dir; DWORD until; STATS st; LONG issued, cancelled, terminated; } Cn;

static DWORD WINAPI cancel_io_thread(LPVOID p)
{
    ULONG s = (ULONG)(ULONG_PTR)p * 31u + GetTickCount();
    UCHAR *buf = malloc(1024 * 1024);
    WCHAR path[600];

    _snwprintf(path, ARRAYSIZE(path) - 1, L"%ls\\c%lu.bin", Cn.dir, (ULONG)(ULONG_PTR)p);
    path[ARRAYSIZE(path) - 1] = 0;
    while (GetTickCount() < Cn.until)
    {
        HANDLE f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                               FILE_FLAG_OVERLAPPED, NULL);
        OVERLAPPED ov[4];
        DWORD n;
        int k;

        if (f == INVALID_HANDLE_VALUE)
        {
            stat_add(&Cn.st, 0xE0000000 | GetLastError());
            Sleep(10);
            continue;
        }
        memset(ov, 0, sizeof(ov));
        for (k = 0; k < 4; k++)
        {
            BOOL ok;
            ov[k].hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            ov[k].Offset = rnd(&s) % (1024 * 1024);
            ok = (k & 1) ? WriteFile(f, buf, 1 + rnd(&s) % (1024 * 1024), NULL, &ov[k])
                         : ReadFile(f, buf, 1 + rnd(&s) % (1024 * 1024), NULL, &ov[k]);
            InterlockedIncrement(&Cn.issued);
            if (!ok && GetLastError() != ERROR_IO_PENDING)
                stat_add(&Cn.st, 0xE0000000 | GetLastError());
        }
        if (rnd(&s) % 2)
            Sleep(rnd(&s) % 50);
        if (CancelIoEx(f, NULL))
            InterlockedIncrement(&Cn.cancelled);
        for (k = 0; k < 4; k++)
        {
            if (GetOverlappedResult(f, &ov[k], &n, TRUE))
                stat_add(&Cn.st, STATUS_SUCCESS);
            else
                stat_add(&Cn.st, 0xE0000000 | GetLastError());
            CloseHandle(ov[k].hEvent);
        }
        CloseHandle(f);
    }
    free(buf);
    return 0;
}

/* Terminated at any point: no heap, no loader, no CRT; only system calls on prebuilt names */
static WCHAR VictimPath[4][700];
static UCHAR VictimBuf[4][1024 * 1024];

static DWORD WINAPI victim_thread(LPVOID p)
{
    ULONG i = (ULONG)(ULONG_PTR)p % 4;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;

    off.QuadPart = 0;
    for (;;)
    {
        HANDLE f;
        if (!NT_SUCCESS(nt_open(VictimPath[i], GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, &f)))
            continue;
        NtReadFile(f, NULL, NULL, NULL, &iosb, VictimBuf[i], sizeof(VictimBuf[i]), &off, NULL);
        NtWriteFile(f, NULL, NULL, NULL, &iosb, VictimBuf[i], 65536, &off, NULL);
        NtClose(f);
    }
    return 0;
}

static int do_cancel(const WCHAR *dir, int seconds, int threads)
{
    HANDLE *t = calloc(threads, sizeof(HANDLE));
    ULONG s = GetTickCount();
    int i;

    Cn.dir = dir;
    Cn.until = GetTickCount() + seconds * 1000;
    InitializeCriticalSection(&Cn.st.cs);
    for (i = 0; i < 4; i++)
    {
        WCHAR unc[600];
        _snwprintf(unc, ARRAYSIZE(unc) - 1, L"%ls\\v%d.bin", dir, i);
        unc[ARRAYSIZE(unc) - 1] = 0;
        nt_name(unc, VictimPath[i], ARRAYSIZE(VictimPath[i]));
    }
    for (i = 0; i < threads; i++)
        t[i] = CreateThread(NULL, 0, cancel_io_thread, (LPVOID)(ULONG_PTR)(i + 1), 0, NULL);
    /* terminate threads that are inside the redirector */
    while (GetTickCount() < Cn.until)
    {
        HANDLE v = CreateThread(NULL, 0, victim_thread, (LPVOID)(ULONG_PTR)(rnd(&s) % 4), 0, NULL);
        Sleep(20 + rnd(&s) % 200);
        TerminateThread(v, 77);
        if (WaitForSingleObject(v, 200000) != WAIT_OBJECT_0)
            printf("ATTACK cancel STUCK terminated thread did not exit in 200 s\n");
        CloseHandle(v);
        InterlockedIncrement(&Cn.terminated);
    }
    for (i = 0; i < threads; i++)
    {
        if (WaitForSingleObject(t[i], 300000) != WAIT_OBJECT_0)
            printf("ATTACK cancel STUCK io thread %d\n", i);
        CloseHandle(t[i]);
    }
    printf("ATTACK cancel issued=%ld cancelled=%ld terminated=%ld\n", Cn.issued, Cn.cancelled, Cn.terminated);
    stat_print("cancel", &Cn.st);
    return 0;
}

/* flood (pool budget) ******************************************************/

static struct { const WCHAR *file; DWORD until; LONG writes, fails; LONG ok[1024]; LONG errs[64]; DWORD errcode[64]; CRITICAL_SECTION cs; } Fl;

/* Block k of writer t = 16-byte tag "T<t> K<k>" then (t*131 + k*7 + j) & 0xff,
 * so that the server's copy can be checked against the successful writes (block k = the k-th successful write) */
static void flood_fill(UCHAR *buf, ULONG t, ULONG k)
{
    ULONG j;
    for (j = 0; j < 1024 * 1024; j++)
        buf[j] = (UCHAR)(t * 131 + k * 7 + j);
    _snprintf((char *)buf, 16, "T%04lu K%08lu", t, k);
}

static void flood_err(DWORD e)
{
    int i;
    EnterCriticalSection(&Fl.cs);
    for (i = 0; i < 64; i++)
        if (Fl.errs[i] == 0 || Fl.errcode[i] == e) { Fl.errcode[i] = e; Fl.errs[i]++; break; }
    LeaveCriticalSection(&Fl.cs);
}

static DWORD WINAPI flood_thread(LPVOID p)
{
    UCHAR *buf = malloc(1024 * 1024);
    WCHAR name[600];
    HANDLE f;
    DWORD n;
    ULONG t = (ULONG)(ULONG_PTR)p, k = 0;

    /* one file per thread (FILE-<n>): many handles of one file closing at once is "closestorm" */
    _snwprintf(name, ARRAYSIZE(name) - 1, L"%ls-%lu", Fl.file, t);
    name[ARRAYSIZE(name) - 1] = 0;
    f = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);

    if (f == INVALID_HANDLE_VALUE)
    {
        flood_err(GetLastError());
        InterlockedIncrement(&Fl.fails);
        return 0;
    }
    flood_fill(buf, t, k);
    while (GetTickCount() < Fl.until)
    {
        if (WriteFile(f, buf, 1024 * 1024, &n, NULL) && n == 1024 * 1024)
        {
            InterlockedIncrement(&Fl.writes);
            k++;
            flood_fill(buf, t, k);
        }
        else
        {
            flood_err(n != 0 && n != 1024 * 1024 ? 0xFFFF0000 | (n >> 12) : GetLastError());
            InterlockedIncrement(&Fl.fails);
            if (n != 0)
            {
                /* a short write moved the file pointer: put it back to the block boundary */
                LARGE_INTEGER z;
                z.QuadPart = (LONGLONG)k * 1024 * 1024;
                SetFilePointerEx(f, z, NULL, FILE_BEGIN);
            }
        }
    }
    if (!CloseHandle(f))
        flood_err(0xC1000000 | GetLastError());
    if (t < 1024)
        Fl.ok[t] = (LONG)k;
    free(buf);
    return 0;
}

static void pool_tags(const char *when)
{
    ULONG len = 1 << 20, i;
    SYSTEM_POOLTAG_INFORMATION *pi = malloc(len);
    NTSTATUS st = NtQuerySystemInformation(SystemPoolTagInformation, pi, len, &len);

    if (!NT_SUCCESS(st))
    {
        printf("ATTACK flood pool query failed %08lx\n", st);
        free(pi);
        return;
    }
    for (i = 0; i < pi->Count; i++)
    {
        SYSTEM_POOLTAG *t = &pi->TagInfo[i];
        if (!memcmp(t->Tag, "SbRm", 4) || !memcmp(t->Tag, "SbRq", 4) || !memcmp(t->Tag, "SbRp", 4))
            printf("ATTACK flood %s tag=%.4s paged-used=%Iu nonpaged-used=%Iu\n", when, t->Tag, t->PagedUsed, t->NonPagedUsed);
    }
    fflush(stdout);
    free(pi);
}

static int do_flood(const WCHAR *file, int threads, int seconds)
{
    HANDLE *t = calloc(threads, sizeof(HANDLE));
    int i, k;

    Fl.file = file;
    InitializeCriticalSection(&Fl.cs);
    Fl.until = GetTickCount() + seconds * 1000;
    pool_tags("before");
    for (i = 0; i < threads; i++)
        t[i] = CreateThread(NULL, 64 * 1024, flood_thread, (LPVOID)(ULONG_PTR)i, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    for (k = 0; k < seconds; k += 5)
    {
        Sleep(5000);
        pool_tags("during");
    }
    for (i = 0; i < threads; i++)
    {
        WaitForSingleObject(t[i], INFINITE);
        CloseHandle(t[i]);
    }
    pool_tags("after");
    printf("ATTACK flood threads=%d writes=%ld fails=%ld\n", threads, Fl.writes, Fl.fails);
    for (i = 0; i < 64 && Fl.errs[i]; i++)
        printf("ATTACK flood error %lu (0x%08lx) count=%ld\n", Fl.errcode[i], Fl.errcode[i], Fl.errs[i]);
    for (i = 0; i < threads && i < 1024; i++)
        printf("ATTACK flood file %d blocks=%ld\n", i, Fl.ok[i]);
    return 0;
}

/* closestorm: N threads open one file, write a little, wait for each other, close at once; ROUNDS times */

static struct { const WCHAR *file; LONG ready, go; LONG opened; } Cs;

static DWORD WINAPI closestorm_thread(LPVOID p)
{
    HANDLE f = CreateFileW(Cs.file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    DWORD n;
    char b[16] = "closestorm";

    if (f != INVALID_HANDLE_VALUE)
    {
        InterlockedIncrement(&Cs.opened);
        WriteFile(f, b, sizeof(b), &n, NULL);
    }
    InterlockedIncrement(&Cs.ready);
    while (!Cs.go)
        Sleep(1);
    if (f != INVALID_HANDLE_VALUE)
        CloseHandle(f);
    return 0;
}

static int do_closestorm(const WCHAR *file, int threads, int rounds)
{
    HANDLE *t = calloc(threads, sizeof(HANDLE));
    int r, i;

    Cs.file = file;
    for (r = 0; r < rounds; r++)
    {
        Cs.ready = Cs.go = Cs.opened = 0;
        for (i = 0; i < threads; i++)
            t[i] = CreateThread(NULL, 64 * 1024, closestorm_thread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
        while (Cs.ready < threads)
            Sleep(10);
        Cs.go = 1;
        for (i = 0; i < threads; i++)
        {
            WaitForSingleObject(t[i], INFINITE);
            CloseHandle(t[i]);
        }
        printf("ATTACK closestorm round %d opened %ld of %d\n", r, Cs.opened, threads);
    }
    return 0;
}

/* ioctl ********************************************************************/

static int do_ioctl(int count, ULONG seed, const WCHAR *unc, const WCHAR *flags)
{
    static const WCHAR *devs[] = { L"\\Device\\NitroSmbEngine", L"\\Device\\NitroSmbRedirector", L"\\Device\\LanmanRedirector",
                                   L"\\Device\\Mup", L"\\Device\\Mup\\;LanmanRedirector", NULL };
    static const ACCESS_MASK acc[] = { 0, FILE_READ_ATTRIBUTES, GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE, MAXIMUM_ALLOWED };
    static const ULONG known[] = { IOCTL_SMBRDR_ENGINE_ATTACH, IOCTL_SMBRDR_ENGINE_GET, IOCTL_SMBRDR_ENGINE_REPLY,
                                   IOCTL_SMBRDR_ENGINE_DETACH, IOCTL_SMBRDR_QUERY_STATE,
                                   CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 99, METHOD_NEITHER, FILE_ANY_ACCESS),   /* QUERY_PATH */
                                   CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 100, METHOD_NEITHER, FILE_ANY_ACCESS),  /* QUERY_PATH_EX */
                                   CTL_CODE(FILE_DEVICE_MULTI_UNC_PROVIDER, 1, METHOD_BUFFERED, FILE_ANY_ACCESS),
                                   CTL_CODE(FILE_DEVICE_MULTI_UNC_PROVIDER, 2, METHOD_BUFFERED, FILE_ANY_ACCESS),
                                   0x900a8, 0x140390, 0x14011c };
    static const ULONG_PTR badptr[] = { 0, 1, 0x1000, 0x7FFE0000, (ULONG_PTR)-4096, (ULONG_PTR)0x80000000u };
    HANDLE h[16];
    BOOL mup[16];
    BOOL mupsection = flags && wcsstr(flags, L"mupsection");
    BOOL nosection = flags && wcsstr(flags, L"nosection");
    BOOL nobadptr = flags && wcsstr(flags, L"nobadptr");
    int nh = 0, i, j;
    UCHAR *in = VirtualAlloc(NULL, 2 * 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    UCHAR *out = VirtualAlloc(NULL, 2 * 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    STATS st;
    ULONG s = seed ? seed : 1;
    IO_STATUS_BLOCK iosb;

    memset(&st, 0, sizeof(st));
    InitializeCriticalSection(&st.cs);
    for (i = 0; devs[i]; i++)
    {
        for (j = 0; j < (int)ARRAYSIZE(acc); j++)
        {
            HANDLE x;
            NTSTATUS r = nt_open(devs[i], acc[j], FILE_OPEN, 0, &x);
            printf("ATTACK ioctl open %ls access %#lx -> %08lx\n", devs[i], acc[j], r);
            if (NT_SUCCESS(r))
            {
                if (nh < 15 && j == ARRAYSIZE(acc) - 1)
                {
                    mup[nh] = !wcscmp(devs[i], L"\\Device\\Mup");
                    h[nh++] = x;
                }
                else
                    NtClose(x);
            }
        }
    }
    if (unc)
    {
        WCHAR nt[700];
        nt_name(unc, nt, ARRAYSIZE(nt));
        if (NT_SUCCESS(nt_open(nt, GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF, 0, &h[nh])))
            mup[nh++] = FALSE;
        else
            printf("ATTACK ioctl open %ls failed\n", unc);
    }
    printf("ATTACK ioctl handles=%d\n", nh);
    fflush(stdout);
    if (!nh)
        return 0;

    for (i = 0; i < count; i++)
    {
        ULONG hi = rnd(&s) % nh;
        HANDLE x = h[hi];
        ULONG code, inl = 0, outl = 0, r = rnd(&s);
        PVOID ip = in, op = out;
        NTSTATUS rs;

        if (r % 3 == 0)
            code = known[rnd(&s) % ARRAYSIZE(known)];
        else
        {
            static const ULONG types[] = { FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_DEVICE_NETWORK_REDIRECTOR,
                                           FILE_DEVICE_MULTI_UNC_PROVIDER, FILE_DEVICE_FILE_SYSTEM, FILE_DEVICE_DISK };
            code = CTL_CODE(rnd(&s) % 4 ? types[rnd(&s) % ARRAYSIZE(types)] : (rnd(&s) & 0xFFFF),
                            rnd(&s) % 4096, rnd(&s) % 4, rnd(&s) % 4);
        }
        switch (rnd(&s) % 4)
        {
            case 0: inl = 0; break;
            case 1: inl = rnd(&s) % 64; break;
            case 2: inl = rnd(&s) % 4096; break;
            default: inl = rnd(&s) % (SMBUP_MAX_MESSAGE + 8192); break;
        }
        outl = (rnd(&s) % 3) ? rnd(&s) % 4096 : rnd(&s) % (SMBUP_MAX_MESSAGE + 8192);
        for (j = 0; j < (int)min(inl, 512); j++)
            in[j] = (UCHAR)rnd(&s);
        if (inl >= sizeof(SMBUP_HEADER) && rnd(&s) % 2)
        {
            /* something that looks like the protocol */
            SMBUP_HEADER *hd = (SMBUP_HEADER *)in;
            hd->Magic = SMBUP_MAGIC; hd->Version = SMBUP_VERSION; hd->HeaderSize = sizeof(*hd);
            hd->TotalSize = inl; hd->Opcode = (USHORT)(rnd(&s) % 18); hd->RequestId = rnd(&s) % 64;
        }
        /* "nobadptr": no invalid buffers (rdbss stops the kernel on an invalid read/write buffer, see "smbattack badbuf") */
        if (!nobadptr && rnd(&s) % 16 == 0)
            ip = (PVOID)badptr[rnd(&s) % ARRAYSIZE(badptr)];
        if (!nobadptr && rnd(&s) % 16 == 0)
            op = (PVOID)badptr[rnd(&s) % ARRAYSIZE(badptr)];
        switch (rnd(&s) % 16)
        {
            /* the other entry points of the same handles: what a caller can send to rdbss's device FCB */
            case 0:
            {
                LARGE_INTEGER bo;
                bo.QuadPart = rnd(&s) % 3 ? 0 : (LONGLONG)rnd(&s);
                rs = NtReadFile(x, NULL, NULL, NULL, &iosb, op, outl, &bo, NULL);
                break;
            }
            case 1:
            {
                LARGE_INTEGER bo;
                bo.QuadPart = rnd(&s) % 3 ? 0 : (LONGLONG)rnd(&s);
                rs = NtWriteFile(x, NULL, NULL, NULL, &iosb, ip, inl, &bo, NULL);
                break;
            }
            case 2: rs = NtQueryInformationFile(x, &iosb, op, outl, (FILE_INFORMATION_CLASS)(1 + rnd(&s) % 70)); break;
            case 3: rs = NtSetInformationFile(x, &iosb, ip, inl, (FILE_INFORMATION_CLASS)(1 + rnd(&s) % 70)); break;
            case 4: rs = NtQueryVolumeInformationFile(x, &iosb, op, outl, (FS_INFORMATION_CLASS)(1 + rnd(&s) % 14)); break;
            case 5: rs = NtSetVolumeInformationFile(x, &iosb, ip, inl, (FS_INFORMATION_CLASS)(1 + rnd(&s) % 14)); break;
            case 6:
                rs = NtQueryDirectoryFile(x, NULL, NULL, NULL, &iosb, op, outl, (FILE_INFORMATION_CLASS)(1 + rnd(&s) % 70),
                                          (BOOLEAN)(rnd(&s) & 1), NULL, (BOOLEAN)(rnd(&s) & 1));
                break;
            case 7: rs = NtFlushBuffersFile(x, &iosb); break;
            case 8:
            {
                HANDLE sec;
                LARGE_INTEGER sz;
                /* A section of a handle to \Device\Mup itself stops the kernel (MmCreateSection takes MUP's
                 * VCB for an FCB header, see "smbattack section"): left out unless the flags say "mupsection".
                 * "nosection" leaves out every section (rdbss image section reads assert on Debug builds) */
                if ((mup[hi] && !mupsection) || nosection)
                {
                    rs = (NTSTATUS)0xEEEE0008;
                    break;
                }
                sz.QuadPart = rnd(&s) % 3 ? 0 : 4096;
                rs = NtCreateSection(&sec, SECTION_MAP_READ, NULL, sz.QuadPart ? &sz : NULL, PAGE_READONLY,
                                     rnd(&s) % 4 ? SEC_COMMIT : SEC_IMAGE, x);
                if (NT_SUCCESS(rs))
                    NtClose(sec);
                break;
            }
            case 9:
            {
                LARGE_INTEGER bo, ln;
                bo.QuadPart = rnd(&s); ln.QuadPart = 1 + rnd(&s) % 100;
                rs = NtLockFile(x, NULL, NULL, NULL, &iosb, &bo, &ln, 0, TRUE, (BOOLEAN)(rnd(&s) & 1));
                break;
            }
            case 10: rs = NtQueryEaFile(x, &iosb, op, outl, FALSE, NULL, 0, NULL, TRUE); break;
            case 11:
            {
                ULONG need;
                rs = NtQuerySecurityObject(x, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, op, outl, &need);
                break;
            }
            case 12: case 13:
                rs = NtFsControlFile(x, NULL, NULL, NULL, &iosb, code, ip, inl, op, outl);
                break;
            default:
                rs = NtDeviceIoControlFile(x, NULL, NULL, NULL, &iosb, code, ip, inl, op, outl);
                break;
        }
        stat_add(&st, rs);
        if (i % 100000 == 0)
        {
            printf("ATTACK ioctl progress %d\n", i);
            fflush(stdout);
        }
    }
    printf("ATTACK ioctl count=%d\n", count);
    stat_print("ioctl", &st);
    for (i = 0; i < nh; i++)
        NtClose(h[i]);
    return 0;
}

/* attach *******************************************************************/

static NTSTATUS try_attach(void)
{
    HANDLE h;
    SMBUP_ATTACH a;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = nt_open(L"\\Device\\NitroSmbEngine", GENERIC_READ | GENERIC_WRITE, FILE_OPEN, 0, &h);

    if (!NT_SUCCESS(st))
    {
        printf("ATTACK attach open -> %08lx\n", st);
        return st;
    }
    a.Magic = SMBUP_MAGIC; a.Version = SMBUP_VERSION; a.Reserved = 0; a.MaxMessageSize = SMBUP_MAX_MESSAGE; a.Reserved2 = 0;
    st = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_SMBRDR_ENGINE_ATTACH, &a, sizeof(a), NULL, 0);
    printf("ATTACK attach ioctl -> %08lx\n", st);
    NtClose(h);
    return st;
}

static int do_attach(void)
{
    HANDLE tok, rtok;
    LUID_AND_ATTRIBUTES del;

    printf("ATTACK attach as-is\n");
    try_attach();
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok) &&
        LookupPrivilegeValueW(NULL, L"SeImpersonatePrivilege", &del.Luid))
    {
        del.Attributes = 0;
        if (CreateRestrictedToken(tok, 0, 0, NULL, 1, &del, 0, NULL, &rtok))
        {
            HANDLE itok;
            if (DuplicateTokenEx(rtok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &itok) &&
                SetThreadToken(NULL, itok))
            {
                printf("ATTACK attach without-SeImpersonatePrivilege\n");
                try_attach();
                RevertToSelf();
                CloseHandle(itok);
            }
            else
                printf("ATTACK attach could not impersonate the restricted token %lu\n", GetLastError());
            CloseHandle(rtok);
        }
        CloseHandle(tok);
    }
    return 0;
}

/* levels *******************************************************************/

static void level_open(const char *what, const WCHAR *unc)
{
    WCHAR nt[700];
    HANDLE h;
    NTSTATUS st;

    nt_name(unc, nt, ARRAYSIZE(nt));
    st = nt_open(nt, FILE_READ_ATTRIBUTES, FILE_OPEN, 0, &h);
    printf("ATTACK levels %s -> %08lx\n", what, st);
    if (NT_SUCCESS(st))
        NtClose(h);
}

static int do_levels(const WCHAR *unc)
{
    HANDLE tok, imp, rtok;
    SECURITY_IMPERSONATION_LEVEL lv;
    static const char *names[] = { "anonymous", "identification", "impersonation", "delegation" };

    level_open("primary", unc);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok))
        return 1;
    for (lv = SecurityAnonymous; lv <= SecurityDelegation; lv++)
    {
        if (DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, NULL, lv, TokenImpersonation, &imp) && SetThreadToken(NULL, imp))
        {
            level_open(names[lv], unc);
            RevertToSelf();
            CloseHandle(imp);
        }
        else
            printf("ATTACK levels %s setup failed %lu\n", names[lv], GetLastError());
    }
    if (ImpersonateAnonymousToken(GetCurrentThread()))
    {
        level_open("anonymous-token", unc);
        RevertToSelf();
    }
    if (CreateRestrictedToken(tok, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &rtok))
    {
        if (DuplicateTokenEx(rtok, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &imp) && SetThreadToken(NULL, imp))
        {
            level_open("filtered(no restricted sids)-delegation", unc);
            RevertToSelf();
            CloseHandle(imp);
        }
        CloseHandle(rtok);
    }
    {
        SID_AND_ATTRIBUTES rs;
        SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
        PSID restricted;
        if (AllocateAndInitializeSid(&nt, 1, SECURITY_RESTRICTED_CODE_RID, 0, 0, 0, 0, 0, 0, 0, &restricted))
        {
            rs.Sid = restricted;
            rs.Attributes = 0;
            if (CreateRestrictedToken(tok, 0, 0, NULL, 0, NULL, 1, &rs, &rtok))
            {
                if (DuplicateTokenEx(rtok, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &imp) &&
                    SetThreadToken(NULL, imp))
                {
                    level_open("restricted-sids-delegation", unc);
                    RevertToSelf();
                    CloseHandle(imp);
                }
                CloseHandle(rtok);
            }
            FreeSid(restricted);
        }
    }
    CloseHandle(tok);
    return 0;
}

/* asuser *******************************************************************/

/* CMDLINE runs as USER with its output appended to OUTFILE (created writable for everyone first) */
static int do_asuser(const WCHAR *user, const WCHAR *pw, const WCHAR *outfile, const WCHAR *cmdline)
{
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    WCHAR cmd[2048];
    HANDLE tok, f;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 255;

    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
    f = CreateFileW(outfile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE)
        CloseHandle(f);
    _snwprintf(cmd, ARRAYSIZE(cmd) - 1, L"cmd.exe /c %ls >> %ls 2>&1", cmdline, outfile);
    cmd[ARRAYSIZE(cmd) - 1] = 0;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!LogonUserW((LPWSTR)user, L".", (LPWSTR)pw, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tok))
    {
        printf("ATTACK asuser LogonUser %ls failed %lu\n", user, GetLastError());
        return 250;
    }
    if (!CreateProcessAsUserW(tok, NULL, cmd, NULL, NULL, FALSE, 0, NULL, L"C:\\", &si, &pi))
    {
        DWORD e = GetLastError();
        /* Not CreateProcessWithTokenW: in this tree it starts the process as the caller */
        if (!CreateProcessWithLogonW((LPWSTR)user, L".", (LPWSTR)pw, 0, NULL, cmd, 0, NULL, L"C:\\", &si, &pi))
        {
            printf("ATTACK asuser CreateProcess as %ls failed %lu / %lu\n", user, e, GetLastError());
            CloseHandle(tok);
            return 251;
        }
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    printf("ATTACK asuser %ls exit %lu\n", user, code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(tok);
    return (int)code;
}

/* probe: one open, read, directory query and volume query of UNC, each with status and time */
static int do_probe(const WCHAR *unc)
{
    WCHAR nt[700], dir[700];
    IO_STATUS_BLOCK iosb;
    UCHAR buf[4096];
    LARGE_INTEGER off;
    HANDLE h;
    NTSTATUS st;
    DWORD t0;
    WCHAR *slash;

    nt_name(unc, nt, ARRAYSIZE(nt));
    t0 = GetTickCount();
    st = nt_open(nt, GENERIC_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, &h);
    printf("ATTACK probe open %ls -> %08lx %lu ms\n", unc, st, GetTickCount() - t0);
    if (NT_SUCCESS(st))
    {
        off.QuadPart = 0;
        t0 = GetTickCount();
        st = NtReadFile(h, NULL, NULL, NULL, &iosb, buf, sizeof(buf), &off, NULL);
        printf("ATTACK probe read -> %08lx %lu ms\n", st, GetTickCount() - t0);
        NtClose(h);
    }
    wcscpy(dir, nt);
    slash = wcsrchr(dir, L'\\');
    if (slash)
        *slash = 0;
    t0 = GetTickCount();
    st = nt_open(dir, FILE_LIST_DIRECTORY, FILE_OPEN, FILE_DIRECTORY_FILE, &h);
    printf("ATTACK probe open-dir -> %08lx %lu ms\n", st, GetTickCount() - t0);
    if (NT_SUCCESS(st))
    {
        t0 = GetTickCount();
        st = NtQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf, sizeof(buf), FileDirectoryInformation, FALSE, NULL, TRUE);
        printf("ATTACK probe dir -> %08lx %lu ms\n", st, GetTickCount() - t0);
        t0 = GetTickCount();
        st = NtQueryVolumeInformationFile(h, &iosb, buf, sizeof(buf), FileFsAttributeInformation);
        printf("ATTACK probe volume -> %08lx %lu ms\n", st, GetTickCount() - t0);
        NtClose(h);
    }
    return 0;
}

int wmain(int argc, WCHAR **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc >= 5 && !wcscmp(argv[1], L"load"))
        return do_load(argv[2], _wtoi(argv[3]), _wtoi(argv[4]));
    if (argc >= 5 && !wcscmp(argv[1], L"cancel"))
        return do_cancel(argv[2], _wtoi(argv[3]), _wtoi(argv[4]));
    if (argc >= 5 && !wcscmp(argv[1], L"flood"))
        return do_flood(argv[2], _wtoi(argv[3]), _wtoi(argv[4]));
    if (argc >= 5 && !wcscmp(argv[1], L"closestorm"))
        return do_closestorm(argv[2], _wtoi(argv[3]), _wtoi(argv[4]));
    if (argc >= 4 && !wcscmp(argv[1], L"ioctl"))
        return do_ioctl(_wtoi(argv[2]), (ULONG)_wtoi(argv[3]), argc >= 5 ? argv[4] : NULL, argc >= 6 ? argv[5] : NULL);
    if (argc >= 2 && !wcscmp(argv[1], L"attach"))
        return do_attach();
    if (argc >= 3 && !wcscmp(argv[1], L"levels"))
        return do_levels(argv[2]);
    if (argc >= 3 && !wcscmp(argv[1], L"open"))
    {
        HANDLE h;
        NTSTATUS st = nt_open(argv[2], FILE_READ_ATTRIBUTES, FILE_OPEN, 0, &h);
        printf("ATTACK open %ls -> %08lx\n", argv[2], st);
        if (NT_SUCCESS(st))
            NtClose(h);
        return 0;
    }
    if (argc >= 6 && !wcscmp(argv[1], L"asuser"))
        return do_asuser(argv[2], argv[3], argv[4], argv[5]);
    if (argc >= 2 && !wcscmp(argv[1], L"whoami"))
    {
        UCHAR buf[4096];
        HANDLE tok;
        DWORD len, i;
        TOKEN_STATISTICS st;
        char *sid = NULL;
        BOOL admin = FALSE, imp = FALSE;
        LUID impluid;

        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
        GetTokenInformation(tok, TokenStatistics, &st, sizeof(st), &len);
        if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len))
            ConvertSidToStringSidA(((TOKEN_USER *)buf)->User.Sid, &sid);
        if (GetTokenInformation(tok, TokenGroups, buf, sizeof(buf), &len))
            for (i = 0; i < ((TOKEN_GROUPS *)buf)->GroupCount; i++)
            {
                char *g = NULL;
                ConvertSidToStringSidA(((TOKEN_GROUPS *)buf)->Groups[i].Sid, &g);
                if (g && !strcmp(g, "S-1-5-32-544") && (((TOKEN_GROUPS *)buf)->Groups[i].Attributes & SE_GROUP_ENABLED))
                    admin = TRUE;
                if (g) LocalFree(g);
            }
        LookupPrivilegeValueW(NULL, L"SeImpersonatePrivilege", &impluid);
        if (GetTokenInformation(tok, TokenPrivileges, buf, sizeof(buf), &len))
            for (i = 0; i < ((TOKEN_PRIVILEGES *)buf)->PrivilegeCount; i++)
                if (((TOKEN_PRIVILEGES *)buf)->Privileges[i].Luid.LowPart == impluid.LowPart)
                    imp = TRUE;
        printf("ATTACK whoami user=%s logon=%08lx%08lx admin=%d seimpersonate=%d\n", sid ? sid : "?",
               st.AuthenticationId.HighPart, st.AuthenticationId.LowPart, admin, imp);
        return 0;
    }
    if (argc >= 3 && !wcscmp(argv[1], L"badbuf"))
    {
        /* one write and one read of a file on a share with a user buffer that is not mapped */
        WCHAR nt[700];
        HANDLE h;
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER off;
        NTSTATUS st;

        nt_name(argv[2], nt, ARRAYSIZE(nt));
        st = nt_open(nt, GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, &h);
        printf("ATTACK badbuf open %ls -> %08lx\n", argv[2], st);
        if (NT_SUCCESS(st))
        {
            off.QuadPart = 0;
            st = NtWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)0x1000, 4096, &off, NULL);
            printf("ATTACK badbuf write -> %08lx\n", st);
            st = NtReadFile(h, NULL, NULL, NULL, &iosb, (PVOID)0x1000, 4096, &off, NULL);
            printf("ATTACK badbuf read -> %08lx\n", st);
            NtClose(h);
        }
        return 0;
    }
    if (argc >= 3 && !wcscmp(argv[1], L"section"))
    {
        HANDLE h, sec;
        NTSTATUS st = nt_open(argv[2], GENERIC_READ, FILE_OPEN, 0, &h);
        printf("ATTACK section open %ls -> %08lx\n", argv[2], st);
        if (NT_SUCCESS(st))
        {
            st = NtCreateSection(&sec, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, h);
            printf("ATTACK section create -> %08lx\n", st);
            if (NT_SUCCESS(st))
                NtClose(sec);
            NtClose(h);
        }
        return 0;
    }
    if (argc >= 3 && !wcscmp(argv[1], L"probe"))
        return do_probe(argv[2]);
    printf("usage: see the comment at the top of smbattack.c\n");
    return 87;
}
