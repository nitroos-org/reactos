/*
 * PROJECT:     NitroOS compatibility log tool
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Shared declarations
 */

#ifndef _NITRODIAG_H
#define _NITRODIAG_H

#define COBJMACROS
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <wingdi.h>
#include <winreg.h>
#include <winver.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <reactos/buildno.h>

#include "resource.h"

#define ND_STATUS_ORDINAL_NOT_FOUND     0xC0000138
#define ND_STATUS_ENTRYPOINT_NOT_FOUND  0xC0000139
#define ND_STATUS_INVALID_IMAGE_FORMAT  0xC000007B
#define ND_STATUS_DLL_INIT_FAILED       0xC0000142
#define ND_STATUS_APP_INIT_FAILURE      0xC0000145
#define ND_STATUS_ILLEGAL_DLL_RELOC     0xC0000269
#define ND_STATUS_MACHINE_MISMATCH      0xC000010E
#define ND_EXCEPTION_WINE_STUB          0x80000100
#define ND_EXCEPTION_CPP                0xE06D7363
#define ND_EXCEPTION_WX86_BREAKPOINT    0x4000001F
#define ND_EXCEPTION_WX86_SINGLE_STEP   0x4000001E
#define ND_DBG_PRINTEXCEPTION_C         0x40010006
#ifndef VOLUME_NAME_DOS
#define VOLUME_NAME_DOS 0
#endif
#define ND_DBG_PRINTEXCEPTION_WIDE_C    0x4001000A

/* ---- growable wide-character buffer ---- */
typedef struct _WBUF
{
    WCHAR *p;
    size_t len;
    size_t cap;
} WBUF;

void WbAppend(WBUF *b, const WCHAR *s);
void WbPrintf(WBUF *b, const WCHAR *fmt, ...);
void WbFree(WBUF *b);

/* ---- options ---- */
typedef struct _ND_OPTIONS
{
    WCHAR OutDir[MAX_PATH];     /* /out */
    WCHAR OutZip[MAX_PATH];     /* /zip: the exact file name */
    BOOL  Quiet;                /* /quiet */
    BOOL  NoDump;               /* /nodump */
    BOOL  NoSnaps;              /* /nosnaps: leave the loader's debug text off */
    BOOL  Screenshot;           /* /screenshot */
    BOOL  Raw;                  /* /raw: every debug event in the timeline */
    BOOL  Pick;                 /* /pick: ask for the program */
    BOOL  Imports;              /* /imports: always run the import check */
    DWORD TimeoutSec;           /* /timeout, 0 = none */
    DWORD AttachPid;            /* /attach */
    LPWSTR CmdLine;             /* what is given to CreateProcess (target + arguments, as typed) */
    WCHAR  Target[MAX_PATH];    /* the program, resolved */
    WCHAR  WorkDir[MAX_PATH];   /* working directory, "" = ours */
    BOOL  Gui;                  /* started without a console: dialogs */
} ND_OPTIONS;

extern ND_OPTIONS g_Opt;

/* ---- results ---- */
#define ND_MAX_MODS     512
#define ND_MAX_STUBS    64
#define ND_MAX_LDRERR   32
#define ND_MAX_CRASH    8
#define ND_MAX_PROCS    64

typedef struct _ND_MODULE
{
    ULONG64 Base;
    DWORD   Size;
    WCHAR   Path[MAX_PATH];
    WCHAR   Version[40];
} ND_MODULE;

typedef struct _ND_BP
{
    ULONG64 Addr;
    BYTE    Orig;
    BYTE    Kind;               /* ND_BP_* */
    BYTE    Is32;
    BYTE    Armed;
} ND_BP;

#define ND_BP_HARDERR   1
#define ND_BP_ISDBG     2
#define ND_MAX_BPS      6

typedef struct _ND_PROC
{
    DWORD     Pid;
    HANDLE    hProcess;
    BOOL      Wow64;            /* 32-bit process on a 64-bit system */
    BOOL      IsRoot;
    BOOL      Exited;
    BOOL      SymInit;
    BOOL      SawInitialBp;
    DWORD     ExitCode;
    DWORD     StartTick;
    DWORD     EndTick;
    DWORD     ParentPid;
    WCHAR     Image[MAX_PATH];
    ULONG64   ImageBase;
    ND_MODULE *Mods;
    int       nMods;
    int       capMods;
    ND_BP     Bps[ND_MAX_BPS];
    int       nBps;
    DWORD     StepTid;          /* thread stepping over a breakpoint */
    int       StepBp;
    DWORD     IsDbgCalls;
    DWORD     nThreads;
    DWORD     nFirstChance;
    DWORD     LastDllInit;      /* index of the last module loaded */
} ND_PROC;

typedef struct _ND_STUB
{
    CHAR  Dll[64];
    CHAR  Func[128];
    DWORD Count;
} ND_STUB;

typedef struct _ND_LDRERR
{
    DWORD   Pid;
    DWORD   Status;
    WCHAR   Name[MAX_PATH];     /* param 0 (DLL path, function name) */
    WCHAR   Module[MAX_PATH];   /* param 1 (importing module / search path) */
    ULONG   Ordinal;
    BOOL    HasOrdinal;
    BOOL    ByLoader;           /* learned from the loader's text, not the hard error */
} ND_LDRERR;

typedef struct _ND_CRASH
{
    DWORD   Pid, Tid;
    DWORD   Code;
    ULONG64 Addr;
    ULONG64 Info0, Info1;
    DWORD   NumInfo;
    WCHAR   Where[MAX_PATH + 40];
    WCHAR   DumpName[64];
    WBUF    Detail;             /* registers + stack */
} ND_CRASH;

#define ND_MAX_SHAPES   256
typedef struct _ND_SHAPE
{
    ULONG64 Hash;
    DWORD   Count;
    WCHAR   Sample[110];
} ND_SHAPE;

typedef struct _ND_RESULT
{
    DWORD     StartTick;
    FILETIME  StartTime;
    DWORD     RootPid;
    BOOL      CreateFailed;
    DWORD     CreateError;
    BOOL      StillRunning;     /* ended by /timeout or by the user */
    BOOL      StoppedByUser;
    DWORD     TimeoutSec;
    BOOL      Attached;

    ND_STUB   Stubs[ND_MAX_STUBS];
    int       nStubs;
    ND_LDRERR LdrErr[ND_MAX_LDRERR];
    int       nLdrErr;
    ND_CRASH  Crash[ND_MAX_CRASH];
    int       nCrash;

    DWORD     nDebugStrings;
    DWORD     nDebugStringsDropped;
    DWORD     nSnapLines;
    DWORD     nProcsStarted;
    DWORD     nHardErrors;
    DWORD     nFirstChance;
    DWORD     nUnhandledCpp;
    ND_SHAPE  Shapes[ND_MAX_SHAPES];
    int       nShapes;
    int       nImpProblems;
    WCHAR     BadImage[300];
    WCHAR     FirstImpProblem[300];
    BOOL      CppThrown;
    BOOL      DebuggerQuery;    /* the program asked IsDebuggerPresent() */
    DWORD     DebuggerQueryCount;

    WBUF      Timeline;
    WBUF      Snapshot;         /* /timeout or stop: modules + thread stacks */
    WBUF      ImportReport;
    WBUF      Extras;
    WCHAR     LastDebugText[160];
    WCHAR     LastLoadedModule[MAX_PATH];

    /* temp files to be added to the zip (minidumps) */
    WCHAR     DumpFiles[ND_MAX_CRASH][MAX_PATH];
    int       nDumps;
} ND_RESULT;

extern ND_RESULT g_Res;
extern ND_PROC   g_Procs[ND_MAX_PROCS];
extern int       g_nProcs;

/* ---- trace.c ---- */
int  TraceRun(void);
void Tl(const WCHAR *fmt, ...);
ULONG ElapsedMs(void);
BOOL RequestStop(void);

/* ---- imports.c ---- */
void ImportsCheck(const WCHAR *exe, BOOL is32target, WBUF *out, int *nProblems);
BOOL PeMachine(const WCHAR *path, WORD *Machine);
BOOL PeFindExportRva(const WCHAR *path, const char *name, DWORD *rva);

/* ---- report.c ---- */
void BuildReport(WBUF *out);
const WCHAR *StatusName(DWORD code);
const WCHAR *ExceptionName(DWORD code);
void WriteSystemHeader(WBUF *out);
void FileVersionOf(const WCHAR *path, WCHAR *out, size_t cch);

/* ---- main.c ---- */
BOOL SaveZip(const WCHAR *zipPath, const BYTE *report, DWORD reportLen);
void MakeReportName(WCHAR *out, size_t cch);
BOOL TakeScreenshot(const WCHAR *file);
void ShowStatusWindow(BOOL show);
BOOL PumpStatusWindow(void);

#endif
