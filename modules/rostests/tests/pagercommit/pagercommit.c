/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Directed test of P4 commit accounting (pageable private commitment)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * pagercommit.exe [x=MB] [y=MB] [y2=MB] [r=MB] [ph=MB] [pf=MB] [path=C:\pctest.sys] [pfhelper=EXE]
 * pagercommit.exe mkpf [pf=MB] [path=...]   create the paging file only (a WoW64 process cannot:
 *                                            the 32-bit test runs the 64-bit build as pfhelper)
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
 * C (split and partial frees, review rvp4b 5): region P (R MB) committed before
 *   the paging file exists and region Q (R MB) after it. For each: decommit the
 *   second quarter, release the third quarter (the VAD is split in two), then
 *   release the two halves separately. Every step of P gives a quarter back to
 *   the RAM-bound room; no step of Q changes it (what Q returns leaves the
 *   pageable count as well). A split half that lost or gained the mark shows.
 * D (placeholder replacement): a PH MB placeholder replaced by committed memory
 *   with the paging file present is counted as pageable private: neither the
 *   replacement nor its release changes the RAM-bound room.
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
typedef NTSTATUS_T (NTAPI *PFN_NTFVM)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef PVOID (WINAPI *PFN_VA2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, PVOID, ULONG);
#define PC_MEM_RESERVE_PLACEHOLDER 0x00040000
#define PC_MEM_REPLACE_PLACEHOLDER 0x00004000
#define NOISE_MB 32

#define MLI_CLASS 80
#define CMD_EMPTY_WORKING_SETS 2
#define CMD_FLUSH_MODIFIED 3
#define CMD_INVALIDATE_WRITES (0x4E500000 + 13)
#define SECTION_MB 2
#define MAX_SECTIONS 4096

static HANDLE gSections[MAX_SECTIONS];
static PFN_NTSSI pSsi;
static PFN_NTFVM pFree;

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

static BOOL NtFree(PVOID Base, SIZE_T Bytes, ULONG Type, const char *what)
{
    PVOID b = Base;
    SIZE_T n = Bytes;
    NTSTATUS_T st = pFree(GetCurrentProcess(), &b, &n, Type);
    Say("NtFreeVirtualMemory %s (%s, %lu MB at +0x%lx): 0x%08lx", what, (Type == MEM_RELEASE) ? "release" : "decommit",
        (ULONG)(Bytes >> 20), (ULONG)((ULONG_PTR)Base & 0xFFFFFFF), (ULONG)st);
    return st >= 0;
}

/* C: decommit Q2, release Q3 (split), release [Q1 Q2], release Q4; each step's room change against Want (MB, or 0) */
static BOOL SplitCase(const char *name, PUCHAR Base, ULONG MB, BOOL Counted)
{
    SIZE_T q = ((SIZE_T)MB << 20) / 4;
    ULONG r[5];
    LONG d;
    BOOL ok = (Base != NULL);
    int i;
    char what[64];

    if (!ok)
        return FALSE;
    sprintf(what, "C %s start", name);
    r[0] = Room(what);
    ok &= NtFree(Base + q, q, MEM_DECOMMIT, "Q2");
    sprintf(what, "C %s Q2 decommitted", name);
    r[1] = Room(what);
    ok &= NtFree(Base + 2 * q, q, MEM_RELEASE, "Q3 (split)");
    sprintf(what, "C %s Q3 released", name);
    r[2] = Room(what);
    ok &= NtFree(Base, 0, MEM_RELEASE, "Q1+Q2 half");
    sprintf(what, "C %s first half released", name);
    r[3] = Room(what);
    ok &= NtFree(Base + 3 * q, 0, MEM_RELEASE, "Q4 half");
    sprintf(what, "C %s second half released", name);
    r[4] = Room(what);
    for (i = 1; i < 5; i++)
    {
        d = (LONG)r[i] - (LONG)r[i - 1];
        /* The first half gives back Q1 only (Q2 was decommitted already) */
        if (Counted ? (labs(d) > NOISE_MB) : (d < (LONG)(MB / 4) * 3 / 4) || (d > (LONG)(MB / 4) + NOISE_MB))
            ok = FALSE;
        Say("C %s step %d: room %+ld MB (want %s)", name, i, d, Counted ? "about 0" : "about a quarter");
    }
    Say("C %s: %s", name, ok ? "PASS" : "FAIL");
    return ok;
}

static BOOL MakePagingFile(const char *Path, ULONG PfMB)
{
    PFN_NTCPF pCpf = (PFN_NTCPF)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreatePagingFile");
    WCHAR wpath[MAX_PATH];
    USTR Name;
    LARGE_INTEGER Min, Max;
    NTSTATUS_T st;
    ULONG Total, Limit;

    _snwprintf(wpath, MAX_PATH - 1, L"\\??\\%hs", Path);
    wpath[MAX_PATH - 1] = 0;
    Name.Buffer = wpath;
    Name.Length = (USHORT)(wcslen(wpath) * sizeof(WCHAR));
    Name.MaximumLength = Name.Length + sizeof(WCHAR);
    Min.QuadPart = Max.QuadPart = (LONGLONG)PfMB << 20;
    Say("SeCreatePagefilePrivilege %s", EnablePriv("SeCreatePagefilePrivilege") ? "on" : "NOT on");
    st = pCpf ? pCpf(&Name, &Min, &Max, 0) : -1;
    Commit(&Total, &Limit);
    Say("NtCreatePagingFile %s %lu MB: 0x%08lx, commit %lu/%lu MB", Path, PfMB, (ULONG)st, Total, Limit);
    return st >= 0;
}

int main(int argc, char **argv)
{
    ULONG X = strtoul(Arg(argc, argv, "x", "128"), NULL, 0);
    ULONG Y = strtoul(Arg(argc, argv, "y", "256"), NULL, 0);
    ULONG Y2 = strtoul(Arg(argc, argv, "y2", "256"), NULL, 0);
    ULONG PfMB = strtoul(Arg(argc, argv, "pf", "2048"), NULL, 0);
    ULONG RMB = strtoul(Arg(argc, argv, "r", "256"), NULL, 0);
    ULONG PhMB = strtoul(Arg(argc, argv, "ph", "128"), NULL, 0);
    PFN_VA2 pVa2;
    const char *Helper;
    PVOID pp, pq, ph, pr;
    ULONG D0, D1, D2;
    BOOL PassC, PassD, RanD = FALSE;
    const char *Path = Arg(argc, argv, "path", "C:\\pctest.sys");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    NTSTATUS_T st;
    ULONG R1, R2, R3, R4, R5, Total, Limit;
    PVOID px, py, py2;
    BOOL PassA, PassB, RanB = FALSE;
    int k;

    pSsi = (PFN_NTSSI)GetProcAddress(nt, "NtSetSystemInformation");
    pFree = (PFN_NTFVM)GetProcAddress(nt, "NtFreeVirtualMemory");
    pVa2 = (PFN_VA2)GetProcAddress(LoadLibraryA("kernelbase.dll"), "VirtualAlloc2");
    if (!pVa2)
        pVa2 = (PFN_VA2)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc2");
    Commit(&Total, &Limit);
    if ((argc > 1) && !strcmp(argv[1], "mkpf"))
        return MakePagingFile(Path, PfMB) ? 0 : 1;

    Say("PAGERCOMMIT start x=%lu y=%lu y2=%lu pf=%lu commit %lu/%lu MB", X, Y, Y2, PfMB, Total, Limit);
    if (Limit > 2 * 1024 + 64)
        Say("WARNING: commit limit %lu MB: is there a paging file already? (boot without one)", Limit);

    /* A: X MB before any paging file exists: plain user commitment (and C: region P) */
    px = Alloc(X, FALSE);
    pp = Alloc(RMB, FALSE);

    Say("SeProfileSingleProcessPrivilege %s", EnablePriv("SeProfileSingleProcessPrivilege") ? "on" : "NOT on");
    Helper = Arg(argc, argv, "pfhelper", NULL);
    if (Helper)
    {
        char cmd[MAX_PATH * 2];
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        DWORD code = 1;

        sprintf(cmd, "\"%s\" mkpf pf=%lu path=%s", Helper, PfMB, Path);
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, INFINITE);
            GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        Say("paging file helper \"%s\": exit %lu", cmd, code);
        st = (code == 0) ? 0 : -1;
    }
    else
    {
        st = MakePagingFile(Path, PfMB) ? 0 : -1;
    }
    if (st < 0 || !px)
    {
        Say("PAGERCOMMIT:RESULT A=SETUP-FAIL B=NOT-RUN");
        return 2;
    }

    /* Y MB with the paging file: counted as pageable private (and C: region Q) */
    py = Alloc(Y, FALSE);
    pq = Alloc(RMB, FALSE);
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

    /* C: split and partial frees, P (not counted) and Q (counted) */
    PassC = SplitCase("P", pp, RMB, FALSE);
    PassC = SplitCase("Q", pq, RMB, TRUE) && PassC;

    /* D: placeholder replaced by committed memory, with the paging file: counted */
    PassD = FALSE;
    if (pVa2)
    {
        RanD = TRUE;
        D0 = Room("D start");
        ph = pVa2(NULL, NULL, (SIZE_T)PhMB << 20, MEM_RESERVE | PC_MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0);
        pr = ph ? pVa2(NULL, ph, (SIZE_T)PhMB << 20, MEM_RESERVE | MEM_COMMIT | PC_MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0) : NULL;
        Say("placeholder %p, replaced %p (error %lu)", ph, pr, pr ? 0 : GetLastError());
        D1 = Room("D replaced");
        if (pr)
            VirtualFree(pr, 0, MEM_RELEASE);
        else if (ph)
            VirtualFree(ph, 0, MEM_RELEASE);
        D2 = Room("D released");
        PassD = pr && (labs((LONG)D1 - (LONG)D0) <= NOISE_MB) && (labs((LONG)D2 - (LONG)D1) <= NOISE_MB);
        Say("D: replaced %+ld MB, released %+ld MB (want about 0 each): %s",
            (LONG)D1 - (LONG)D0, (LONG)D2 - (LONG)D1, PassD ? "PASS" : "FAIL");
    }
    else
    {
        Say("D: VirtualAlloc2 not found");
    }

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

    Say("PAGERCOMMIT:RESULT A=%s C=%s D=%s B=%s (%d-bit)", PassA ? "PASS" : "FAIL", PassC ? "PASS" : "FAIL",
        RanD ? (PassD ? "PASS" : "FAIL") : "NOT-RUN", RanB ? (PassB ? "PASS" : "FAIL") : "NOT-RUN", (int)(sizeof(PVOID) * 8));
    return (PassA && PassC && (PassD || !RanD) && PassB) ? 0 : 1;
}
