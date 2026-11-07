/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A file that is shrunk and grown again reads zeros in the regrown range (never the bytes it had
 *              before the truncation), through the file handle, through a second handle, unbuffered and mapped,
 *              with and without memory pressure.  Runs on any file system: the directory comes from
 *              FSREGROW_DIR (default C:\fsregrow); FSREGROW_ITER sets the rounds per variant (default 12);
 *              FSREGROW_PRESSURE=1 runs a thread that keeps emptying the working set and touching memory.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifdef FSREGROW_STANDALONE
/* Built on its own (system mingw) to run the same checks on another Windows. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
static int FailCount;
#define ok(c, ...) do { if (!(c)) { FailCount++; printf("FAIL: " __VA_ARGS__); } } while (0)
#define trace(...) printf(__VA_ARGS__)
#define skip(...) printf("SKIP: " __VA_ARGS__)
#define START_TEST(n) static void func_##n(void); int main(int argc, char **argv) { if (argc > 1) SetEnvironmentVariableA("FSREGROW_DIR", argv[1]); if (argc > 2) SetEnvironmentVariableA("FSREGROW_PRESSURE", argv[2]); func_##n(); printf("FSREGROW-DONE failures=%d\n", FailCount); return FailCount != 0; } static void func_##n(void)
#else
#include <apitest.h>
#include <stdio.h>
#endif

#define OLD_BYTE 0xfd
#define MAXSZ (2 * 1024 * 1024)

static WCHAR Dir[MAX_PATH];
static volatile LONG StopPressure;
static ULONG Seed = 12345;
static ULONG Fails, Printed;
static volatile LONG UserMappedSkips;

static ULONG Rnd(ULONG Mod)
{
    Seed = Seed * 1103515245 + 12345;
    return ((Seed >> 8) & 0xffffff) % Mod;
}

static DWORD WINAPI PressureThread(PVOID Arg)
{
    BOOL (WINAPI *Empty)(HANDLE) = NULL;
    HMODULE Psapi = LoadLibraryW(L"psapi.dll");
    ULONG n = 0;
    if (Psapi)
        Empty = (PVOID)GetProcAddress(Psapi, "EmptyWorkingSet");
    while (!StopPressure)
    {
        PUCHAR Mem;
        if (Empty)
            Empty(GetCurrentProcess());
        /* touch and drop 64 MB now and then: steals pages from the file's cached ones */
        if ((n++ % 4) == 0 && (Mem = VirtualAlloc(NULL, 64 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        {
            ULONG i;
            for (i = 0; i < (64u << 20); i += 4096)
                Mem[i] = 1;
            VirtualFree(Mem, 0, MEM_RELEASE);
        }
        Sleep(1);
    }
    return 0;
}

static VOID Report(PCSTR What, PCSTR Variant, ULONG Round, LONGLONG S0, LONGLONG S1, LONGLONG S2, LONGLONG Off, UCHAR Got)
{
    Fails++;
    if (Printed++ < 40)
        ok(0, "%s [%s r%lu sizes %I64d->%I64d->%I64d]: byte at %I64d is 0x%02x, expected 0x00\n", What, Variant, Round, S0, S1, S2, Off, Got);
}

/* Checks Buf (data of the file from Base on): zeros in [S1,S2), the pattern below S1. */
static VOID CheckBuf(PCSTR What, PCSTR Variant, ULONG Round, LONGLONG S0, LONGLONG S1, LONGLONG S2, const UCHAR *Buf, LONGLONG Base, ULONG Len)
{
    ULONG i;
    BOOLEAN Bad = FALSE;
    for (i = 0; i < Len; i++)
    {
        LONGLONG Off = Base + i;
        if (Off >= S1 && Off < S2 && Buf[i] != 0)
        {
            Report(What, Variant, Round, S0, S1, S2, Off, Buf[i]);
            Bad = TRUE;
            break;
        }
        if (Off < S1 && Buf[i] != OLD_BYTE)
        {
            Fails++;
            if (Printed++ < 40)
                ok(0, "%s [%s r%lu]: surviving byte at %I64d is 0x%02x, expected 0x%02x\n", What, Variant, Round, Off, Buf[i], OLD_BYTE);
            Bad = TRUE;
            break;
        }
    }
    (void)Bad;
}

static VOID FillMapped(HANDLE File, LONGLONG Size, BOOL Flush)
{
    HANDLE Map = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, (DWORD)Size, NULL);
    PUCHAR View;
    if (!Map)
    {
        ok(0, "CreateFileMapping for the fill failed: %lu\n", GetLastError());
        return;
    }
    View = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, (SIZE_T)Size);
    if (View)
    {
        memset(View, OLD_BYTE, (SIZE_T)Size);
        if (Flush)
            FlushViewOfFile(View, 0);
        UnmapViewOfFile(View);
    }
    else
        ok(0, "MapViewOfFile for the fill failed: %lu\n", GetLastError());
    CloseHandle(Map);
}

static BOOL SetEofOnce(HANDLE File, LONGLONG Size, BOOL UseInfo, PBOOL Mapped)
{
    *Mapped = FALSE;
    if (UseInfo)
    {
        /* FileEndOfFileInformation (20) through ntdll, the call SetFileInformationByHandle makes */
        LONGLONG Eof = Size;
        ULONG_PTR Iosb[2];
        LONG Status;
        LONG (NTAPI *SetInfo)(HANDLE, PVOID, PVOID, ULONG, ULONG) =
            (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile");
        if (!SetInfo)
            return FALSE;
        Status = SetInfo(File, Iosb, &Eof, sizeof(Eof), 20);
        *Mapped = (Status == (LONG)0xC0000243); /* STATUS_USER_MAPPED_FILE */
        return Status >= 0;
    }
    else
    {
        LARGE_INTEGER Li;
        Li.QuadPart = Size;
        if (SetFilePointerEx(File, Li, NULL, FILE_BEGIN) && SetEndOfFile(File))
            return TRUE;
        *Mapped = (GetLastError() == ERROR_USER_MAPPED_FILE);
        return FALSE;
    }
}

static BOOL SetEof(HANDLE File, LONGLONG Size, BOOL UseInfo)
{
    BOOL Mapped;
    ULONG Try;
    BOOL Ok = SetEofOnce(File, Size, UseInfo, &Mapped);

    /* A mapping this thread just closed can still show as a user mapping to the truncation check for a moment
     * (see the CREATE_ALWAYS retry in SeqThread): transient and unrelated to the checks here, so retry briefly. */
    for (Try = 0; !Ok && Mapped && Try < 50; Try++)
    {
        Sleep(10);
        Ok = SetEofOnce(File, Size, UseInfo, &Mapped);
        if (Ok)
            trace("size change succeeded after %lu retries (transient user-mapped refusal)\n", Try + 1);
    }
    if (!Ok && Mapped)
        SetLastError(ERROR_USER_MAPPED_FILE);
    return Ok;
}

static VOID ReadAll(HANDLE File, PUCHAR Buf, LONGLONG Size, PBOOL Ok)
{
    LARGE_INTEGER Li;
    DWORD Got = 0, N;
    Li.QuadPart = 0;
    SetFilePointerEx(File, Li, NULL, FILE_BEGIN);
    *Ok = TRUE;
    while (Got < Size)
    {
        if (!ReadFile(File, Buf + Got, (DWORD)min(Size - Got, 65536), &N, NULL) || !N)
        {
            *Ok = FALSE;
            return;
        }
        Got += N;
    }
}

/* One round; Mapped: the old data was written through a view; Flush: written out before the shrink;
 * Reopen: the handle is closed and opened again before the shrink; UseInfo: SetFileInformationByHandle. */
static VOID Round(PCWSTR Path, ULONG Idx, BOOL Mapped, BOOL Flush, BOOL Reopen, BOOL UseInfo, BOOL Aligned, PUCHAR Buf, PUCHAR Fill)
{
    CHAR Variant[64];
    LONGLONG S0, S1, S2;
    HANDLE F, F2, Map;
    DWORD N;
    PUCHAR View;
    BOOL Ok;
    LARGE_INTEGER Li;

    sprintf(Variant, "%s%s%s%s%s", Mapped ? "map" : "write", Flush ? ",flush" : "", Reopen ? ",reopen" : "", UseInfo ? ",info" : ",seteof", Aligned ? ",aligned" : "");
    S0 = 512 * 1024 + Rnd(MAXSZ - 512 * 1024 - 8192);
    S1 = 4096 + Rnd((ULONG)S0 - 4096);
    switch (Rnd(3))
    {
        case 0: S2 = S1 + 1 + Rnd(8192); break;                  /* small regrow */
        case 1: S2 = S1 + 1 + Rnd((ULONG)(S0 - S1) + 1); break;  /* inside the old data */
        default: S2 = S0 + Rnd(MAXSZ - (ULONG)S0); break;         /* beyond the old size */
    }
    if (Aligned)
    {
        /* cluster/page aligned sizes: the file size equals the allocation size when the file system is called */
        LONGLONG G = (Idx & 1) ? 65536 : 4096;
        S0 = (S0 + G - 1) / G * G;
        S1 = S1 / G * G;
        if (S1 < G)
            S1 = G;
        S2 = (S2 + G - 1) / G * G;
        if (S2 <= S1)
            S2 = S1 + G;
    }
    if (S2 <= S1)
        S2 = S1 + 4096;

    F = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    if (F == INVALID_HANDLE_VALUE)
    {
        ok(0, "Creating %ls failed: %lu\n", Path, GetLastError());
        return;
    }
    if (Mapped)
    {
        ok(SetEof(F, S0, FALSE), "Sizing failed %lu\n", GetLastError());
        FillMapped(F, S0, Flush);
    }
    else
    {
        LONGLONG Done = 0;
        while (Done < S0)
        {
            DWORD C = (DWORD)min(S0 - Done, 65536);
            if (!WriteFile(F, Fill, C, &N, NULL) || N != C)
            {
                ok(0, "Write failed %lu\n", GetLastError());
                break;
            }
            Done += C;
        }
        if (Flush)
            FlushFileBuffers(F);
    }
    if (Reopen)
    {
        CloseHandle(F);
        F = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (F == INVALID_HANDLE_VALUE)
        {
            ok(0, "Reopening failed %lu\n", GetLastError());
            return;
        }
    }
    ok(SetEof(F, S1, UseInfo), "Shrink to %I64d failed %lu\n", S1, GetLastError());
    ok(SetEof(F, S2, UseInfo), "Regrow to %I64d failed %lu\n", S2, GetLastError());
    ok(0 == 0, "");

    /* (a) the same handle */
    ReadAll(F, Buf, S2, &Ok);
    ok(Ok, "ReadFile (same handle) failed %lu\n", GetLastError());
    if (Ok)
        CheckBuf("same handle", Variant, Idx, S0, S1, S2, Buf, 0, (ULONG)S2);
    /* (b) a mapped view of the whole file */
    Map = CreateFileMappingW(F, NULL, PAGE_READONLY, 0, 0, NULL);
    if (Map && (View = MapViewOfFile(Map, FILE_MAP_READ, 0, 0, (SIZE_T)S2)))
    {
        CheckBuf("mapped view", Variant, Idx, S0, S1, S2, View, 0, (ULONG)S2);
        UnmapViewOfFile(View);
    }
    else
        ok(0, "Mapping the regrown file failed: %lu\n", GetLastError());
    if (Map)
        CloseHandle(Map);
    /* (c) a second, unbuffered handle: whole sectors from the sector holding S1 */
    F2 = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    if (F2 != INVALID_HANDLE_VALUE)
    {
        LONGLONG From = S1 & ~4095LL, To = (S2 + 4095) & ~4095LL;
        PUCHAR Al = VirtualAlloc(NULL, (SIZE_T)(To - From), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Li.QuadPart = From;
        if (Al && SetFilePointerEx(F2, Li, NULL, FILE_BEGIN) && ReadFile(F2, Al, (DWORD)(To - From), &N, NULL))
        {
            ULONG Valid = (ULONG)min((LONGLONG)N, S2 - From);
            /* only [S1,S2) is judged: the head of the first sector holds survivors */
            CheckBuf("unbuffered", Variant, Idx, S0, S1, S2, Al + (S1 - From), S1, (ULONG)(From + Valid - S1));
        }
        else
            ok(0, "Unbuffered read failed: %lu\n", GetLastError());
        if (Al)
            VirtualFree(Al, 0, MEM_RELEASE);
        CloseHandle(F2);
    }
    CloseHandle(F);
    /* (d) after everything is closed, a fresh open */
    F = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (F != INVALID_HANDLE_VALUE)
    {
        ReadAll(F, Buf, S2, &Ok);
        if (Ok)
            CheckBuf("fresh open", Variant, Idx, S0, S1, S2, Buf, 0, (ULONG)S2);
        CloseHandle(F);
    }
    DeleteFileW(Path);
}


/* ---- the mixed sequence: the operations of a file under a data-path stress (rewrite, cached overwrite, append,
 * truncate/grow, mapped write), each thread on its own file, all bytes checked against a shadow copy ---- */
#define BLK 65536
#define MAXBLK 96
typedef struct { ULONG Id; WCHAR Path[MAX_PATH]; ULONG Rounds; ULONGLONG Rng; PUCHAR Exp; PUCHAR Buf; PUCHAR Al; LONG Bad; } SEQ;

static ULONG SRnd(SEQ *q, ULONG Mod)
{
    q->Rng = q->Rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return (ULONG)(q->Rng >> 33) % Mod;
}

static UCHAR SPat(ULONG Id, ULONG V, ULONG O)
{
    ULONG x = Id * 2654435761u ^ V * 40503u ^ (O >> 2) * 2246822519u;
    x ^= x >> 15; x *= 2654435761u; x ^= x >> 13;
    return (UCHAR)(x >> ((O & 3) * 8));
}

static VOID SFill(SEQ *q, ULONG V, ULONG O, ULONG N, PUCHAR Out)
{
    ULONG i;
    for (i = 0; i < N; i++)
        Out[i] = SPat(q->Id, V, O + i);
}

static BOOL SWrite(HANDLE H, ULONG Off, const UCHAR *B, ULONG N)
{
    OVERLAPPED Ov;
    DWORD W = 0;
    memset(&Ov, 0, sizeof(Ov));
    Ov.Offset = Off;
    return WriteFile(H, B, N, &W, &Ov) && W == N;
}

/* Compares the whole file with the shadow, cached and unbuffered; returns TRUE if it matches. */
static BOOL SVerify(SEQ *q, ULONG Size, PCSTR After, PCSTR Last)
{
    ULONG Mode;
    for (Mode = 0; Mode < 2; Mode++)
    {
        HANDLE H = CreateFileW(q->Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                               Mode ? FILE_FLAG_NO_BUFFERING : 0, NULL);
        DWORD Rd = 0;
        ULONG Want = Mode ? (Size + 4095) & ~4095u : Size, i;
        LARGE_INTEGER Sz;
        if (H == INVALID_HANDLE_VALUE)
        {
            ok(0, "[t%lu] open for verify failed %lu\n", q->Id, GetLastError());
            return FALSE;
        }
        GetFileSizeEx(H, &Sz);
        if (Sz.QuadPart != Size)
        {
            ok(0, "[t%lu after %s] size %I64d, expected %lu\n", q->Id, After, Sz.QuadPart, Size);
            CloseHandle(H);
            return FALSE;
        }
        if (!ReadFile(H, Mode ? q->Al : q->Buf, Want, &Rd, NULL) || Rd != Size)
        {
            ok(0, "[t%lu after %s] read %lu of %lu failed %lu\n", q->Id, After, Rd, Size, GetLastError());
            CloseHandle(H);
            return FALSE;
        }
        CloseHandle(H);
        for (i = 0; i < Size; i++)
        {
            UCHAR Got = (Mode ? q->Al : q->Buf)[i];
            if (Got != q->Exp[i])
            {
                Fails++;
                if (Printed++ < 40)
                    ok(0, "[t%lu %s] after %s (history %s): byte %lu is 0x%02x, expected 0x%02x (%s, file size %lu)\n", q->Id,
                       Mode ? "unbuffered" : "cached", After, Last, i, Got, q->Exp[i], q->Exp[i] ? "data" : "zero", Size);
                InterlockedIncrement(&q->Bad);
                return FALSE;
            }
        }
    }
    return TRUE;
}

static DWORD WINAPI SeqThread(PVOID Arg)
{
    SEQ *q = Arg;
    ULONG Size = 0, V = 0, Round;
    BOOL Exists = FALSE;
    CHAR Hist[160] = "", Tmp[160];

    for (Round = 0; Round < q->Rounds; Round++)
    {
        ULONG Op = SRnd(q, 100), O, N, b0, b1, NewSz;
        PCSTR Name;
        HANDLE H;
        BOOL Check = FALSE;

        V++;
        if (!Exists || Op < 15)
        {
            ULONG Sz = 4096 + SRnd(q, MAXBLK * BLK - 4096);
            Name = "rewrite";
            if (SRnd(q, 3) == 0)
                Sz = SRnd(q, MAXBLK) * BLK + SRnd(q, BLK);
            if (Sz < 4096)
                Sz = 4096;
            H = CreateFileW(q->Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
            /* The truncation check of a file whose mapping this thread just closed can still see the cache's
             * own section for a moment (the cache map is gone, its section reference is dropped after the
             * dirty data was written): ERROR_USER_MAPPED_FILE, transient and unrelated to the regrow checks.
             * Retry briefly; a success after a retry is traced. */
            for (O = 0; H == INVALID_HANDLE_VALUE && GetLastError() == ERROR_USER_MAPPED_FILE && O < 50; O++)
            {
                Sleep(10);
                H = CreateFileW(q->Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
                if (H != INVALID_HANDLE_VALUE)
                    trace("[t%lu] rewrite open succeeded after %lu retries (transient 1224)\n", q->Id, O + 1);
            }
            if (H == INVALID_HANDLE_VALUE && GetLastError() == ERROR_USER_MAPPED_FILE)
            {
                /* Still refused after the retries: leave the file as it is and go on (counted, traced at the end) */
                InterlockedIncrement(&UserMappedSkips);
                continue;
            }
            if (H == INVALID_HANDLE_VALUE)
            {
                ok(0, "[t%lu] rewrite open failed %lu\n", q->Id, GetLastError());
                return 1;
            }
            for (O = 0; O < Sz; O += N)
            {
                N = (SRnd(q, 8) + 1) * 16384;
                N = min(Sz - O, N);
                SFill(q, V, O, N, q->Buf);
                if (!SWrite(H, O, q->Buf, N))
                    ok(0, "[t%lu] rewrite write failed %lu\n", q->Id, GetLastError());
            }
            CloseHandle(H);
            SFill(q, V, 0, Sz, q->Exp);
            Size = Sz;
            Exists = TRUE;
        }
        else if (Op < 35)
        {
            ULONG nb = (Size + BLK - 1) / BLK;
            Name = "overwrite";
            b0 = SRnd(q, nb);
            b1 = b0 + 1 + SRnd(q, nb - b0 < 8 ? nb - b0 : 8);
            H = CreateFileW(q->Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (H != INVALID_HANDLE_VALUE)
            {
                ULONG e = min(b1 * BLK, Size);
                SFill(q, V, b0 * BLK, e - b0 * BLK, q->Buf);
                if (SWrite(H, b0 * BLK, q->Buf, e - b0 * BLK))
                    memcpy(q->Exp + b0 * BLK, q->Buf, e - b0 * BLK);
                CloseHandle(H);
            }
        }
        else if (Op < 50)
        {
            ULONG Add = 1 + SRnd(q, 4 * BLK), NS = min(Size + Add, MAXBLK * BLK);
            Name = "extend";
            if (NS > Size)
            {
                O = Size / BLK * BLK;
                H = CreateFileW(q->Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (H != INVALID_HANDLE_VALUE)
                {
                    SFill(q, V, O, NS - O, q->Buf);
                    if (SWrite(H, O, q->Buf, NS - O))
                    {
                        memcpy(q->Exp + O, q->Buf, NS - O);
                        Size = NS;
                    }
                    CloseHandle(H);
                }
            }
        }
        else if (Op < 62)
        {
            ULONG G = Size + SRnd(q, 3 * BLK);
            LARGE_INTEGER Li;
            NewSz = SRnd(q, 2) ? SRnd(q, Size + 1) : min(G, MAXBLK * BLK);
            if (!NewSz)
                NewSz = 1;
            Name = NewSz < Size ? "shrink" : "grow";
            H = CreateFileW(q->Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (H != INVALID_HANDLE_VALUE)
            {
                Li.QuadPart = NewSz;
                if (SetFilePointerEx(H, Li, NULL, FILE_BEGIN) && SetEndOfFile(H))
                {
                    if (NewSz > Size)
                    {
                        memset(q->Exp + Size, 0, NewSz - Size);
                        Check = TRUE;
                        /* the tail block as pwchk models it: written whole over the part below the new size */
                        if ((Size % BLK) && SRnd(q, 2))
                        {
                            ULONG tb = Size / BLK, e = min((tb + 1) * BLK, NewSz);
                            SFill(q, V, tb * BLK, e - tb * BLK, q->Buf);
                            if (SWrite(H, tb * BLK, q->Buf, e - tb * BLK))
                                memcpy(q->Exp + tb * BLK, q->Buf, e - tb * BLK);
                            Name = "grow+tail";
                        }
                    }
                    Size = NewSz;
                }
                else if (GetLastError() == ERROR_USER_MAPPED_FILE)
                    InterlockedIncrement(&UserMappedSkips); /* see the CREATE_ALWAYS case above */
                else
                    ok(0, "[t%lu] setsize failed %lu\n", q->Id, GetLastError());
                CloseHandle(H);
            }
        }
        else
        {
            ULONG nb = (Size + BLK - 1) / BLK;
            HANDLE Map;
            PUCHAR View;
            Name = "mapped";
            b0 = SRnd(q, nb);
            b1 = b0 + 1 + SRnd(q, nb - b0 < 8 ? nb - b0 : 8);
            H = CreateFileW(q->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (H != INVALID_HANDLE_VALUE)
            {
                Map = CreateFileMappingW(H, NULL, PAGE_READWRITE, 0, 0, NULL);
                View = Map ? MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0) : NULL;
                if (View)
                {
                    ULONG e = min(b1 * BLK, Size);
                    SFill(q, V, b0 * BLK, e - b0 * BLK, View + b0 * BLK);
                    memcpy(q->Exp + b0 * BLK, View + b0 * BLK, e - b0 * BLK);
                    if (SRnd(q, 2))
                        FlushViewOfFile(View + b0 * BLK, e - b0 * BLK);
                    UnmapViewOfFile(View);
                }
                else
                    ok(0, "[t%lu] map failed %lu\n", q->Id, GetLastError());
                if (Map)
                    CloseHandle(Map);
                CloseHandle(H);
            }
        }
        sprintf(Tmp, "%s>%lu;%s", Name, Size, Hist);
        Tmp[sizeof(Hist) - 1] = 0;
        strcpy(Hist, Tmp);
        if (Check || SRnd(q, 4) == 0)
            if (!SVerify(q, Size, Name, Hist))
            {
                /* the shadow is wrong from here on only if the read was: stop this thread */
                break;
            }
    }
    return 0;
}


/* Cache churn: a file bigger than the cache written once, then read through again and again (cached,
 * sequential: read-ahead, views recycled by the cache manager). */
static WCHAR ChurnPath[MAX_PATH];
static ULONG ChurnMb;
static volatile LONG StopChurn;

static DWORD WINAPI ChurnThread(PVOID Arg)
{
    HANDLE H = CreateFileW(ChurnPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    PUCHAR Buf = VirtualAlloc(NULL, 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG i;
    DWORD N;
    LARGE_INTEGER Li;
    if (H == INVALID_HANDLE_VALUE || !Buf)
        return 1;
    memset(Buf, 0x5a, 1 << 20);
    for (i = 0; i < ChurnMb; i++)
        WriteFile(H, Buf, 1 << 20, &N, NULL);
    while (!StopChurn)
    {
        Li.QuadPart = 0;
        SetFilePointerEx(H, Li, NULL, FILE_BEGIN);
        for (i = 0; i < ChurnMb * 16 && !StopChurn; i++)
            if (!ReadFile(H, Buf, 65536, &N, NULL) || !N)
                break;
    }
    CloseHandle(H);
    DeleteFileW(ChurnPath);
    return 0;
}

static VOID RunSequence(PCWSTR Dir, ULONG Threads, ULONG Rounds)
{
    SEQ Q[8];
    HANDLE Th[8];
    ULONG i;
    if (Threads > 8)
        Threads = 8;
    for (i = 0; i < Threads; i++)
    {
        memset(&Q[i], 0, sizeof(Q[i]));
        Q[i].Id = i + 1;
        Q[i].Rounds = Rounds;
        Q[i].Rng = 0x9e3779b97f4a7c15ULL * (i + 1) + GetTickCount();
        _snwprintf(Q[i].Path, MAX_PATH - 1, L"%ls\\seq%02lu.bin", Dir, i);
        Q[i].Exp = VirtualAlloc(NULL, MAXBLK * BLK + 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Q[i].Buf = VirtualAlloc(NULL, MAXBLK * BLK + 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Q[i].Al = VirtualAlloc(NULL, MAXBLK * BLK + 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Th[i] = CreateThread(NULL, 0, SeqThread, &Q[i], 0, NULL);
    }
    for (i = 0; i < Threads; i++)
    {
        WaitForSingleObject(Th[i], 3600000);
        CloseHandle(Th[i]);
        DeleteFileW(Q[i].Path);
    }
}

START_TEST(FsRegrow)
{
    WCHAR Path[MAX_PATH], Env[MAX_PATH];
    ULONG Iter = 12, v, r;
    HANDLE Thr = NULL;
    PUCHAR Buf, Fill;
    ULONG Pressure = 0;

    if (GetEnvironmentVariableW(L"FSREGROW_DIR", Dir, MAX_PATH))
        ;
    else
        wcscpy(Dir, L"C:\\fsregrow");
    if (GetEnvironmentVariableW(L"FSREGROW_ITER", Env, MAX_PATH))
        Iter = _wtoi(Env);
    if (GetEnvironmentVariableW(L"FSREGROW_PRESSURE", Env, MAX_PATH))
        Pressure = _wtoi(Env);
    if (!CreateDirectoryW(Dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        trace("CreateDirectory %ls failed: %lu\n", Dir, GetLastError());
    _snwprintf(Path, MAX_PATH - 1, L"%ls\\regrow.bin", Dir);
    Buf = VirtualAlloc(NULL, MAXSZ + 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Fill = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Buf || !Fill)
    {
        skip("No memory\n");
        return;
    }
    memset(Fill, OLD_BYTE, 65536);
    if (Pressure)
        Thr = CreateThread(NULL, 0, PressureThread, NULL, 0, NULL);
    if (!GetEnvironmentVariableW(L"FSREGROW_SEQ", Env, MAX_PATH) || _wtoi(Env) != 0)
    {
        for (v = 0; v < 32; v++)
            for (r = 0; r < Iter; r++)
                Round(Path, r, v & 1, !!(v & 2), !!(v & 4), !!(v & 8), !!(v & 16), Buf, Fill);
    }
    if (GetEnvironmentVariableW(L"FSREGROW_SEQROUNDS", Env, MAX_PATH) && _wtoi(Env) > 0)
    {
        HANDLE ChurnTh = NULL;
        WCHAR E2[MAX_PATH];
        if (GetEnvironmentVariableW(L"FSREGROW_CHURNMB", E2, MAX_PATH) && _wtoi(E2) > 0)
        {
            ChurnMb = _wtoi(E2);
            _snwprintf(ChurnPath, MAX_PATH - 1, L"%ls\\churn.bin", Dir);
            ChurnTh = CreateThread(NULL, 0, ChurnThread, NULL, 0, NULL);
        }
        ULONG Thr4 = 4;
        if (GetEnvironmentVariableW(L"FSREGROW_SEQTHREADS", Env, MAX_PATH))
            Thr4 = _wtoi(Env);
        GetEnvironmentVariableW(L"FSREGROW_SEQROUNDS", Env, MAX_PATH);
        RunSequence(Dir, Thr4, _wtoi(Env));
        if (ChurnTh)
        {
            StopChurn = 1;
            WaitForSingleObject(ChurnTh, 60000);
            CloseHandle(ChurnTh);
        }
    }
    if (Thr)
    {
        StopPressure = 1;
        WaitForSingleObject(Thr, 10000);
        CloseHandle(Thr);
    }
    trace("FSREGROW: dir=%ls iter=%lu pressure=%lu failures=%lu\n", Dir, Iter, Pressure, Fails);
    if (UserMappedSkips)
        trace("FSREGROW: %ld size changes/rewrites refused with ERROR_USER_MAPPED_FILE after the retries were skipped\n", UserMappedSkips);
    RemoveDirectoryW(Dir);
}
