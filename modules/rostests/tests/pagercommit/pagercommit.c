/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Directed test of P4 commit accounting (pageable private commitment)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * pagercommit.exe [x=MB] [y=MB] [y2=MB] [pf=MB] [path=C:\pctest.sys]
 *
 * Boot with NitroPager on, NitroPagerDebug non-zero (and /NITROPAGERDEBUG on a
 * free build) and NO paging file. Both phases are differential: they measure
 * the room left to RAM-bound commitment (pagefile-backed SEC_COMMIT sections,
 * charged as MiCommitUser, created until one is refused) before and after one
 * event, so what the rest of the system commits meanwhile is noise only.
 *
 * A (review finding 1): X MB committed before any paging file exists is plain
 *   user commitment. Then a paging file is created and Y MB committed (counted
 *   as pageable private). Freeing X must give X back to the RAM-bound room; if
 *   the free took X out of the pageable count (credit not matching the charge),
 *   the room stays where it was.
 * B (review finding 2): Y2 MB counted as pageable private raises the RAM-bound
 *   ceiling while the paging file backs it. Once the only paging file is retired
 *   for good (test command: cluster writes report STATUS_FILE_INVALID, under
 *   write load) that must stop: the room drops by about Y2.
 */

#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG NTSTATUS_T;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } USTR;
typedef NTSTATUS_T (NTAPI *PFN_NTCPF)(USTR *, PLARGE_INTEGER, PLARGE_INTEGER, ULONG);
typedef NTSTATUS_T (NTAPI *PFN_NTSSI)(ULONG, PVOID, ULONG);

#define MLI_CLASS 80
#define CMD_EMPTY_WORKING_SETS 2
#define CMD_FLUSH_MODIFIED 3
#define CMD_INVALIDATE_WRITES (0x4E500000 + 13)
#define SECTION_MB 2
#define MAX_SECTIONS 4096

static HANDLE gSections[MAX_SECTIONS];
static PFN_NTSSI pSsi;

static const char *Arg(int argc, char **argv, const char *key, const char *def)
{
    size_t n = strlen(key);
    int i;
    for (i = 1; i < argc; i++)
        if (!strncmp(argv[i], key, n) && argv[i][n] == '=')
            return argv[i] + n + 1;
    return def;
}

static void Say(const char *fmt, ...)
{
    va_list ap;
    SYSTEMTIME t;
    GetSystemTime(&t);
    printf("[%02u:%02u:%02u] ", t.wHour, t.wMinute, t.wSecond);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static BOOL EnablePriv(const char *name)
{
    HANDLE t;
    TOKEN_PRIVILEGES tp;
    BOOL ok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid) &&
         AdjustTokenPrivileges(t, FALSE, &tp, 0, NULL, NULL) && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(t);
    return ok;
}

static void Commit(ULONG *Total, ULONG *Limit)
{
    MEMORYSTATUSEX m;
    m.dwLength = sizeof(m);
    GlobalMemoryStatusEx(&m);
    *Limit = (ULONG)(m.ullTotalPageFile >> 20);
    *Total = (ULONG)((m.ullTotalPageFile - m.ullAvailPageFile) >> 20);
}

/* MB of pagefile-backed committed sections the system accepts now (RAM-bound tier) */
static ULONG RoomOnce(void)
{
    ULONG n = 0, i;
    while (n < MAX_SECTIONS)
    {
        gSections[n] = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT, 0, SECTION_MB << 20, NULL);
        if (gSections[n] == NULL)
            break;
        n++;
    }
    for (i = 0; i < n; i++)
        CloseHandle(gSections[i]);
    return n * SECTION_MB;
}

static ULONG Room(const char *what)
{
    ULONG r[3], t, Total, Limit;
    int i, j;
    for (i = 0; i < 3; i++)
    {
        Sleep(500);
        r[i] = RoomOnce();
    }
    for (i = 0; i < 3; i++)
        for (j = i + 1; j < 3; j++)
            if (r[j] < r[i]) { t = r[i]; r[i] = r[j]; r[j] = t; }
    Commit(&Total, &Limit);
    Say("room %-28s median %4lu MB (%lu %lu %lu)  commit %lu/%lu MB", what, r[1], r[0], r[1], r[2], Total, Limit);
    return r[1];
}

static NTSTATUS_T MlCmd(ULONG cmd)
{
    NTSTATUS_T st = pSsi ? pSsi(MLI_CLASS, &cmd, sizeof(cmd)) : -1;
    Say("memory list command 0x%lx: status 0x%08lx", cmd, (ULONG)st);
    return st;
}

static PVOID Alloc(ULONG MB, BOOL Touch)
{
    PUCHAR p = VirtualAlloc(NULL, (SIZE_T)MB << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T i;
    if (p && Touch)
        for (i = 0; i < ((SIZE_T)MB << 20); i += 4096)
            p[i] = (UCHAR)(i >> 12);
    Say("alloc %lu MB%s: %s (error %lu)", MB, Touch ? " touched" : "", p ? "ok" : "FAILED", p ? 0 : GetLastError());
    return p;
}

int main(int argc, char **argv)
{
    ULONG X = strtoul(Arg(argc, argv, "x", "128"), NULL, 0);
    ULONG Y = strtoul(Arg(argc, argv, "y", "256"), NULL, 0);
    ULONG Y2 = strtoul(Arg(argc, argv, "y2", "256"), NULL, 0);
    ULONG PfMB = strtoul(Arg(argc, argv, "pf", "2048"), NULL, 0);
    const char *Path = Arg(argc, argv, "path", "C:\\pctest.sys");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    PFN_NTCPF pCpf = (PFN_NTCPF)GetProcAddress(nt, "NtCreatePagingFile");
    WCHAR wpath[MAX_PATH];
    USTR Name;
    LARGE_INTEGER Min, Max;
    NTSTATUS_T st;
    ULONG R1, R2, R3, R4, R5, Total, Limit;
    PVOID px, py, py2;
    BOOL PassA, PassB, RanB = FALSE;
    int k;

    pSsi = (PFN_NTSSI)GetProcAddress(nt, "NtSetSystemInformation");
    Commit(&Total, &Limit);
    Say("PAGERCOMMIT start x=%lu y=%lu y2=%lu pf=%lu commit %lu/%lu MB", X, Y, Y2, PfMB, Total, Limit);
    if (Limit > 2 * 1024 + 64)
        Say("WARNING: commit limit %lu MB: is there a paging file already? (boot without one)", Limit);

    /* A: X MB before any paging file exists: plain user commitment */
    px = Alloc(X, FALSE);

    _snwprintf(wpath, MAX_PATH - 1, L"\\??\\%hs", Path);
    wpath[MAX_PATH - 1] = 0;
    Name.Buffer = wpath;
    Name.Length = (USHORT)(wcslen(wpath) * sizeof(WCHAR));
    Name.MaximumLength = Name.Length + sizeof(WCHAR);
    Min.QuadPart = Max.QuadPart = (LONGLONG)PfMB << 20;
    Say("SeCreatePagefilePrivilege %s, SeProfileSingleProcessPrivilege %s",
        EnablePriv("SeCreatePagefilePrivilege") ? "on" : "NOT on",
        EnablePriv("SeProfileSingleProcessPrivilege") ? "on" : "NOT on");
    st = pCpf ? pCpf(&Name, &Min, &Max, 0) : -1;
    Commit(&Total, &Limit);
    Say("NtCreatePagingFile %s %lu MB: 0x%08lx, commit %lu/%lu MB", Path, PfMB, (ULONG)st, Total, Limit);
    if (st < 0 || !px)
    {
        Say("PAGERCOMMIT:RESULT A=SETUP-FAIL B=NOT-RUN");
        return 2;
    }

    /* Y MB with the paging file: counted as pageable private */
    py = Alloc(Y, FALSE);
    R1 = Room("A1 X+Y held");
    VirtualFree(px, 0, MEM_RELEASE);
    Say("freed X (%lu MB, charged before the paging file)", X);
    R2 = Room("A2 X freed");
    VirtualFree(py, 0, MEM_RELEASE);
    Say("freed Y (%lu MB, charged with the paging file)", Y);
    R3 = Room("A3 Y freed");
    /* Freeing X must make room for about X; freeing Y (counted) changes little */
    PassA = py && ((LONG)(R2 - R1) >= (LONG)(X * 3 / 4)) && (labs((LONG)R3 - (LONG)R2) <= (LONG)(X / 4));
    Say("A: R2-R1 = %ld MB (want >= %lu), R3-R2 = %ld MB (want |.| <= %lu): %s",
        (LONG)(R2 - R1), X * 3 / 4, (LONG)R3 - (LONG)R2, X / 4, PassA ? "PASS" : "FAIL");

    /* B: Y2 MB counted, then the only paging file retires for good under write load */
    py2 = Alloc(Y2, FALSE);
    R4 = Room("B1 Y2 held, file backs");
    if (py2 && MlCmd(CMD_INVALIDATE_WRITES) >= 0)
    {
        RanB = TRUE;
        for (k = 0; k < 3; k++)
        {
            /* Dirty Y2 and push it to the paging file: every cluster write now fails STATUS_FILE_INVALID */
            SIZE_T i;
            for (i = 0; i < ((SIZE_T)Y2 << 20); i += 4096)
                ((PUCHAR)py2)[i] = (UCHAR)(k + (i >> 12));
            MlCmd(CMD_EMPTY_WORKING_SETS);
            MlCmd(CMD_FLUSH_MODIFIED);
            Sleep(3000);
        }
        R5 = Room("B2 file retired");
        PassB = ((LONG)(R4 - R5) >= (LONG)(Y2 * 3 / 4));
        Say("B: R4-R5 = %ld MB (want >= %lu): %s", (LONG)(R4 - R5), Y2 * 3 / 4, PassB ? "PASS" : "FAIL");
        /* The data must still be there (pages that could not be written stay in memory) */
        for (k = 0; k < (int)(Y2 << 8); k += 97)
            if (((PUCHAR)py2)[(SIZE_T)k << 12] != (UCHAR)(2 + k))
            {
                Say("B: data mismatch at page %d", k);
                PassB = FALSE;
                break;
            }
    }
    else
    {
        PassB = FALSE;
    }

    Say("PAGERCOMMIT:RESULT A=%s B=%s", PassA ? "PASS" : "FAIL", RanB ? (PassB ? "PASS" : "FAIL") : "NOT-RUN");
    return (PassA && PassB) ? 0 : 1;
}
