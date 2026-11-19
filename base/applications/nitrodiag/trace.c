/*
 * PROJECT:     NitroOS compatibility log tool
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The debug loop: starts the program as a debuggee and records what user mode can see
 */

#include "nitrodiag.h"
#include <ctype.h>

ND_RESULT g_Res;
ND_PROC   g_Procs[ND_MAX_PROCS];
int       g_nProcs;

static volatile LONG g_StopRequested;
static DWORD g_SeenTimelineBytes;

#define TL_MAX_CHARS        (1024 * 1024)
#define FIRSTCHANCE_MAX_LOG 60
#define STACK_MAX_FRAMES    40

/* ---- a 32-bit (x86) thread context, laid out as the documented CONTEXT of the i386 headers ---- */
typedef struct _ND_CTX32
{
    DWORD ContextFlags;
    DWORD Dr[6];
    BYTE  FloatSave[112];
    DWORD SegGs, SegFs, SegEs, SegDs;
    DWORD Edi, Esi, Ebx, Edx, Ecx, Eax;
    DWORD Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    BYTE  Ext[512];
} ND_CTX32;
#define ND_CTX32_FULL   0x10007

typedef struct _ND_PBI
{
    LONG_PTR ExitStatus;
    PVOID    PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG_PTR BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} ND_PBI;

typedef union _ND_CTX
{
    CONTEXT  Native;
    ND_CTX32 X86;
} ND_CTX;

typedef struct _ND_REGS
{
    BOOL    Is32;
    ULONG64 Ip, Sp, Fp, Ax, Cx, Dx, R8, R9;
    DWORD   Flags;
} ND_REGS;

typedef LONG (WINAPI *PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef BOOL (WINAPI *PFN_W64GTC)(HANDLE, PVOID);
typedef BOOL (WINAPI *PFN_W64STC)(HANDLE, const VOID *);
typedef BOOL (WINAPI *PFN_ISW64)(HANDLE, PBOOL);

static PFN_NTQIP  pNtQueryInformationProcess;
static PFN_W64GTC pWow64GetThreadContext;
static PFN_W64STC pWow64SetThreadContext;
static PFN_ISW64  pIsWow64Process;

/* ---- helpers ---- */

ULONG ElapsedMs(void)
{
    return GetTickCount() - g_Res.StartTick;
}

BOOL RequestStop(void)
{
    InterlockedExchange(&g_StopRequested, 1);
    return TRUE;
}

void Tl(const WCHAR *fmt, ...)
{
    WCHAR line[1200];
    WCHAR head[32];
    va_list ap;
    ULONG ms = ElapsedMs();

    if (g_Res.Timeline.len > TL_MAX_CHARS)
    {
        g_SeenTimelineBytes++;
        return;
    }
    StringCchPrintfW(head, _countof(head), L"[%4lu.%03lu] ", ms / 1000, ms % 1000);
    va_start(ap, fmt);
    StringCchVPrintfW(line, _countof(line), fmt, ap);
    va_end(ap);
    WbAppend(&g_Res.Timeline, head);
    WbAppend(&g_Res.Timeline, line);
    WbAppend(&g_Res.Timeline, L"\r\n");
}

static ND_PROC *ProcFind(DWORD pid)
{
    int i;
    for (i = 0; i < g_nProcs; i++)
        if (g_Procs[i].Pid == pid)
            return &g_Procs[i];
    return NULL;
}

static ND_PROC *ProcNew(DWORD pid)
{
    ND_PROC *p;
    if (g_nProcs >= ND_MAX_PROCS)
        return NULL;
    p = &g_Procs[g_nProcs++];
    ZeroMemory(p, sizeof(*p));
    p->Pid = pid;
    p->StartTick = GetTickCount();
    return p;
}

static BOOL ReadMem(ND_PROC *p, ULONG64 addr, void *buf, SIZE_T len)
{
    SIZE_T got = 0;
    if (!addr)
        return FALSE;
    if (!ReadProcessMemory(p->hProcess, (LPCVOID)(ULONG_PTR)addr, buf, len, &got) || got != len)
        return FALSE;
    return TRUE;
}

/* NUL-terminated ANSI text of the target, read up to the end of what is readable */
static BOOL ReadStrA(ND_PROC *p, ULONG64 addr, char *out, SIZE_T cch)
{
    SIZE_T n = 0;
    out[0] = 0;
    while (n + 1 < cch)
    {
        SIZE_T chunk = 0x1000 - (SIZE_T)((addr + n) & 0xFFF);
        SIZE_T got = 0;
        SIZE_T i;
        if (chunk > cch - 1 - n)
            chunk = cch - 1 - n;
        if (!ReadProcessMemory(p->hProcess, (LPCVOID)(ULONG_PTR)(addr + n), out + n, chunk, &got) || !got)
            break;
        for (i = 0; i < got; i++)
        {
            if (!out[n + i])
            {
                return TRUE;
            }
        }
        n += got;
    }
    out[n] = 0;
    return n != 0;
}

/* a UNICODE_STRING of the target (layout of the target's bitness) */
static BOOL ReadUstr(ND_PROC *p, ULONG64 addr, BOOL is32, WCHAR *out, SIZE_T cch)
{
    USHORT len = 0;
    ULONG64 buf = 0;
    SIZE_T bytes;
    out[0] = 0;
    if (!addr || !ReadMem(p, addr, &len, sizeof(len)))
        return FALSE;
    if (is32)
    {
        DWORD b32 = 0;
        if (!ReadMem(p, addr + 4, &b32, sizeof(b32)))
            return FALSE;
        buf = b32;
    }
    else if (!ReadMem(p, addr + 8, &buf, sizeof(buf)))
        return FALSE;
    bytes = len;
    if (bytes > (cch - 1) * sizeof(WCHAR))
        bytes = (cch - 1) * sizeof(WCHAR);
    if (!bytes)
        return TRUE;
    if (!ReadMem(p, buf, out, bytes))
        return FALSE;
    out[bytes / sizeof(WCHAR)] = 0;
    return TRUE;
}

/* "module.dll+0xOFF" of an address in a process, or "0xADDR" if no module has it */
static void WhereIs(ND_PROC *p, ULONG64 addr, WCHAR *out, size_t cch)
{
    int i, best = -1;
    for (i = 0; i < p->nMods; i++)
    {
        ND_MODULE *m = &p->Mods[i];
        if (addr >= m->Base && addr < m->Base + (m->Size ? m->Size : 0x1000))
        {
            best = i;
            break;
        }
    }
    if (best >= 0)
    {
        const WCHAR *name = wcsrchr(p->Mods[best].Path, L'\\');
        name = name ? name + 1 : p->Mods[best].Path;
        StringCchPrintfW(out, cch, L"%s+0x%I64x", name, addr - p->Mods[best].Base);
    }
    else
        StringCchPrintfW(out, cch, L"0x%I64x", addr);
}

/* ---- threads ---- */

static BOOL GetRegs(ND_PROC *p, HANDLE hThread, ND_REGS *r, ND_CTX *ctx)
{
    ZeroMemory(ctx, sizeof(*ctx));
    ZeroMemory(r, sizeof(*r));
#ifdef _M_AMD64
    if (p->Wow64)
    {
        if (!pWow64GetThreadContext)
            return FALSE;
        ctx->X86.ContextFlags = ND_CTX32_FULL;
        if (!pWow64GetThreadContext(hThread, &ctx->X86))
            return FALSE;
        r->Is32 = TRUE;
        r->Ip = ctx->X86.Eip; r->Sp = ctx->X86.Esp; r->Fp = ctx->X86.Ebp;
        r->Ax = ctx->X86.Eax; r->Cx = ctx->X86.Ecx; r->Dx = ctx->X86.Edx;
        r->Flags = ctx->X86.EFlags;
        return TRUE;
    }
    ctx->Native.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx->Native))
        return FALSE;
    r->Ip = ctx->Native.Rip; r->Sp = ctx->Native.Rsp; r->Fp = ctx->Native.Rbp;
    r->Ax = ctx->Native.Rax; r->Cx = ctx->Native.Rcx; r->Dx = ctx->Native.Rdx;
    r->R8 = ctx->Native.R8; r->R9 = ctx->Native.R9;
    r->Flags = ctx->Native.EFlags;
    return TRUE;
#elif defined(_M_IX86)
    ctx->Native.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx->Native))
        return FALSE;
    r->Is32 = TRUE;
    r->Ip = ctx->Native.Eip; r->Sp = ctx->Native.Esp; r->Fp = ctx->Native.Ebp;
    r->Ax = ctx->Native.Eax; r->Cx = ctx->Native.Ecx; r->Dx = ctx->Native.Edx;
    r->Flags = ctx->Native.EFlags;
    return TRUE;
#else
    return FALSE;
#endif
}

static BOOL SetRegsIpFlags(ND_PROC *p, HANDLE hThread, ND_CTX *ctx, ULONG64 ip, DWORD flags)
{
#ifdef _M_AMD64
    if (p->Wow64)
    {
        if (!pWow64SetThreadContext)
            return FALSE;
        ctx->X86.Eip = (DWORD)ip;
        ctx->X86.EFlags = flags;
        return pWow64SetThreadContext(hThread, &ctx->X86);
    }
    ctx->Native.Rip = ip;
    ctx->Native.EFlags = flags;
    return SetThreadContext(hThread, &ctx->Native);
#elif defined(_M_IX86)
    ctx->Native.Eip = (DWORD)ip;
    ctx->Native.EFlags = flags;
    return SetThreadContext(hThread, &ctx->Native);
#else
    return FALSE;
#endif
}

static void MachineFor(ND_PROC *p, DWORD *machine)
{
#if defined(_M_AMD64)
    *machine = p->Wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_IX86)
    *machine = IMAGE_FILE_MACHINE_I386;
#elif defined(_M_ARM64)
    *machine = IMAGE_FILE_MACHINE_ARM64;
#else
    *machine = IMAGE_FILE_MACHINE_ARMNT;
#endif
    (void)p;
}

/* Walk a thread's stack with dbghelp (frame pointers on x86, unwind data on x64: both work without symbols).
 * Appends one line per frame to out; fills first[] with the first few return addresses when asked. */
static int WalkStack(ND_PROC *p, HANDLE hThread, WBUF *out, const WCHAR *indent, ULONG64 *first, int nfirst)
{
    ND_REGS r;
    ND_CTX ctx;
    STACKFRAME64 sf;
    DWORD machine;
    int n = 0, same = 0;
    ULONG64 lastPc = 0;

    if (!p->SymInit || !GetRegs(p, hThread, &r, &ctx))
    {
        if (out)
            WbPrintf(out, L"%s(no thread context)\r\n", indent);
        return 0;
    }
    ZeroMemory(&sf, sizeof(sf));
    sf.AddrPC.Offset = r.Ip;     sf.AddrPC.Mode = AddrModeFlat;
    sf.AddrFrame.Offset = r.Fp;  sf.AddrFrame.Mode = AddrModeFlat;
    sf.AddrStack.Offset = r.Sp;  sf.AddrStack.Mode = AddrModeFlat;
    MachineFor(p, &machine);

    while (n < STACK_MAX_FRAMES &&
           StackWalk64(machine, p->hProcess, hThread, &sf, &ctx, NULL,
                       SymFunctionTableAccess64, SymGetModuleBase64, NULL))
    {
        WCHAR where[MAX_PATH + 40];
        if (!sf.AddrPC.Offset)
            break;
        if (sf.AddrPC.Offset == lastPc)
        {
            if (++same > 3)
                break;
        }
        else
            same = 0;
        lastPc = sf.AddrPC.Offset;
        WhereIs(p, sf.AddrPC.Offset, where, _countof(where));
        if (out)
            WbPrintf(out, L"%s#%02d  %s\r\n", indent, n, where);
        if (first && n < nfirst)
            first[n] = sf.AddrPC.Offset;
        n++;
    }
    if (!n && out)
    {
        WCHAR where[MAX_PATH + 40];
        WhereIs(p, r.Ip, where, _countof(where));
        WbPrintf(out, L"%s#00  %s  (stack walk gave nothing)\r\n", indent, where);
    }
    return n;
}

static void DumpRegs(ND_PROC *p, HANDLE hThread, WBUF *out)
{
    ND_REGS r;
    ND_CTX ctx;
    if (!GetRegs(p, hThread, &r, &ctx))
        return;
    if (r.Is32)
    {
#ifdef _M_IX86
        WbPrintf(out, L"  eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx\r\n  esi=%08lx edi=%08lx ebp=%08lx esp=%08lx eip=%08lx\r\n",
                 ctx.Native.Eax, ctx.Native.Ebx, ctx.Native.Ecx, ctx.Native.Edx,
                 ctx.Native.Esi, ctx.Native.Edi, ctx.Native.Ebp, ctx.Native.Esp, ctx.Native.Eip);
#else
        WbPrintf(out, L"  eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx\r\n  esi=%08lx edi=%08lx ebp=%08lx esp=%08lx eip=%08lx\r\n",
                 ctx.X86.Eax, ctx.X86.Ebx, ctx.X86.Ecx, ctx.X86.Edx,
                 ctx.X86.Esi, ctx.X86.Edi, ctx.X86.Ebp, ctx.X86.Esp, ctx.X86.Eip);
#endif
    }
#ifdef _M_AMD64
    else
    {
        WbPrintf(out, L"  rax=%016I64x rbx=%016I64x rcx=%016I64x rdx=%016I64x\r\n"
                      L"  rsi=%016I64x rdi=%016I64x rbp=%016I64x rsp=%016I64x\r\n"
                      L"  r8 =%016I64x r9 =%016I64x r10=%016I64x r11=%016I64x\r\n"
                      L"  r12=%016I64x r13=%016I64x r14=%016I64x r15=%016I64x rip=%016I64x\r\n",
                 ctx.Native.Rax, ctx.Native.Rbx, ctx.Native.Rcx, ctx.Native.Rdx,
                 ctx.Native.Rsi, ctx.Native.Rdi, ctx.Native.Rbp, ctx.Native.Rsp,
                 ctx.Native.R8, ctx.Native.R9, ctx.Native.R10, ctx.Native.R11,
                 ctx.Native.R12, ctx.Native.R13, ctx.Native.R14, ctx.Native.R15, ctx.Native.Rip);
    }
#endif
}

/* ---- modules ---- */

static void FixDosPath(WCHAR *path)
{
    if (!wcsncmp(path, L"\\\\?\\UNC\\", 8))
    {
        /* \\?\UNC\server\share -> \\server\share */
        memmove(path + 2, path + 8, (wcslen(path + 8) + 1) * sizeof(WCHAR));
        path[0] = L'\\';
        path[1] = L'\\';
    }
    else if (!wcsncmp(path, L"\\\\?\\", 4))
        memmove(path, path + 4, (wcslen(path + 4) + 1) * sizeof(WCHAR));
}

static BOOL PathOfFileHandle(HANDLE hFile, WCHAR *out, DWORD cch)
{
    DWORD n;
    if (!hFile || hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    n = GetFinalPathNameByHandleW(hFile, out, cch, VOLUME_NAME_DOS);
    if (!n || n >= cch)
        return FALSE;
    FixDosPath(out);
    return TRUE;
}

static DWORD ImageSizeInTarget(ND_PROC *p, ULONG64 base)
{
    IMAGE_DOS_HEADER dos;
    DWORD sig = 0, size = 0;
    if (!ReadMem(p, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    if (!ReadMem(p, base + dos.e_lfanew, &sig, 4) || sig != IMAGE_NT_SIGNATURE)
        return 0;
    /* SizeOfImage is at the same offset (56) of the optional header in PE32 and PE32+ */
    if (!ReadMem(p, base + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 56, &size, 4))
        return 0;
    return size;
}

static ND_MODULE *ModAdd(ND_PROC *p, ULONG64 base)
{
    if (p->nMods >= p->capMods)
    {
        int ncap = p->capMods ? p->capMods * 2 : 64;
        ND_MODULE *n;
        if (ncap > ND_MAX_MODS)
            ncap = ND_MAX_MODS;
        if (p->nMods >= ncap)
            return NULL;
        if (p->Mods)
            n = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p->Mods, ncap * sizeof(ND_MODULE));
        else
            n = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ncap * sizeof(ND_MODULE));
        if (!n)
            return NULL;
        p->Mods = n;
        p->capMods = ncap;
    }
    p->Mods[p->nMods].Base = base;
    return &p->Mods[p->nMods++];
}

static ND_MODULE *ModByBase(ND_PROC *p, ULONG64 base)
{
    int i;
    for (i = 0; i < p->nMods; i++)
        if (p->Mods[i].Base == base)
            return &p->Mods[i];
    return NULL;
}

/* ---- breakpoints (the documented debugger mechanism: int3 at an exported function) ---- */

static void BpArm(ND_PROC *p, ULONG64 modBase, const WCHAR *path, const char *exportName, BYTE kind)
{
    WORD machine = 0;
    DWORD rva = 0;
    ND_BP *bp;
    BYTE cc = 0xCC;
    SIZE_T done = 0;

    if (p->nBps >= ND_MAX_BPS || !PeMachine(path, &machine) || !PeFindExportRva(path, exportName, &rva))
        return;
    /* a 32-bit program on a 64-bit system: only the 32-bit modules are watched (the 64-bit layer has its own registers) */
    if (p->Wow64 && machine != IMAGE_FILE_MACHINE_I386)
        return;
    bp = &p->Bps[p->nBps];
    bp->Addr = modBase + rva;
    bp->Kind = kind;
    bp->Is32 = (machine == IMAGE_FILE_MACHINE_I386);
    if (!ReadMem(p, bp->Addr, &bp->Orig, 1))
        return;
    if (!WriteProcessMemory(p->hProcess, (LPVOID)(ULONG_PTR)bp->Addr, &cc, 1, &done) || done != 1)
        return;
    FlushInstructionCache(p->hProcess, (LPCVOID)(ULONG_PTR)bp->Addr, 1);
    bp->Armed = 1;
    p->nBps++;
}

static void BpSet(ND_PROC *p, ND_BP *bp, BOOL on)
{
    BYTE b = on ? 0xCC : bp->Orig;
    SIZE_T done = 0;
    WriteProcessMemory(p->hProcess, (LPVOID)(ULONG_PTR)bp->Addr, &b, 1, &done);
    FlushInstructionCache(p->hProcess, (LPCVOID)(ULONG_PTR)bp->Addr, 1);
    bp->Armed = on ? 1 : 0;
}

static void BpRemoveAll(ND_PROC *p)
{
    int i;
    for (i = 0; i < p->nBps; i++)
        if (p->Bps[i].Armed && !p->Exited)
            BpSet(p, &p->Bps[i], FALSE);
}

/* A hard error raised by the target: NtRaiseHardError(Status, NumberOfParameters, UnicodeStringParameterMask,
 * Parameters, ValidResponseOptions, Response). The loader uses it for a missing DLL, a missing function and a bad image. */
static void OnHardError(ND_PROC *p, ND_BP *bp, const ND_REGS *r)
{
    DWORD status = 0, nparams = 0, mask = 0;
    ULONG64 params = 0;
    ULONG64 vals[8];
    ND_LDRERR *e;
    DWORD i;

    if (bp->Is32)
    {
        DWORD a[5] = {0};
        if (!ReadMem(p, r->Sp + 4, a, sizeof(a)))
            return;
        status = a[0]; nparams = a[1]; mask = a[2]; params = a[3];
    }
    else
    {
        status = (DWORD)r->Cx; nparams = (DWORD)r->Dx; mask = (DWORD)r->R8; params = r->R9;
    }
    if (nparams > 8)
        nparams = 8;
    ZeroMemory(vals, sizeof(vals));
    for (i = 0; i < nparams; i++)
    {
        if (bp->Is32)
        {
            DWORD v = 0;
            ReadMem(p, params + i * 4, &v, 4);
            vals[i] = v;
        }
        else
            ReadMem(p, params + i * 8, &vals[i], 8);
    }

    g_Res.nHardErrors++;
    if (g_Res.nLdrErr >= ND_MAX_LDRERR)
        return;
    e = &g_Res.LdrErr[g_Res.nLdrErr];
    ZeroMemory(e, sizeof(*e));
    e->Pid = p->Pid;
    e->Status = status;
    if (nparams > 0)
    {
        if (mask & 1)
            ReadUstr(p, vals[0], bp->Is32, e->Name, _countof(e->Name));
        else
        {
            e->HasOrdinal = TRUE;
            e->Ordinal = (ULONG)vals[0];
        }
    }
    if (nparams > 1 && (mask & 2))
        ReadUstr(p, vals[1], bp->Is32, e->Module, _countof(e->Module));

    /* a duplicate (a 32-bit call travelling through the 64-bit layer) is not recorded twice */
    if (g_Res.nLdrErr > 0)
    {
        ND_LDRERR *prev = &g_Res.LdrErr[g_Res.nLdrErr - 1];
        if (prev->Pid == e->Pid && prev->Status == e->Status && !wcscmp(prev->Name, e->Name) &&
            !wcscmp(prev->Module, e->Module) && prev->Ordinal == e->Ordinal)
            return;
    }
    g_Res.nLdrErr++;
    if (e->HasOrdinal)
        Tl(L"pid %lu: the system reports error %s (0x%08lx): ordinal %lu, in %s", p->Pid,
           StatusName(status), status, e->Ordinal, e->Module);
    else
        Tl(L"pid %lu: the system reports error %s (0x%08lx): %s (%s)", p->Pid,
           StatusName(status), status, e->Name, e->Module);
}

/* returns TRUE if the exception was our breakpoint */
static BOOL HandleBreakpointHit(ND_PROC *p, DWORD tid, ULONG64 addr)
{
    int i;
    for (i = 0; i < p->nBps; i++)
    {
        ND_BP *bp = &p->Bps[i];
        HANDLE hT;
        ND_REGS r;
        ND_CTX ctx;
        if (!bp->Armed || bp->Addr != addr)
            continue;
        hT = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (!hT)
            return TRUE;
        if (GetRegs(p, hT, &r, &ctx))
        {
            if (bp->Kind == ND_BP_HARDERR)
                OnHardError(p, bp, &r);
            else if (bp->Kind == ND_BP_ISDBG)
            {
                p->IsDbgCalls++;
                g_Res.DebuggerQueryCount++;
                g_Res.DebuggerQuery = TRUE;
            }
            /* put the original byte back, run the one instruction, arm the breakpoint again at the single step */
            BpSet(p, bp, FALSE);
            if (SetRegsIpFlags(p, hT, &ctx, addr, r.Flags | 0x100))
            {
                p->StepTid = tid;
                p->StepBp = i;
            }
        }
        CloseHandle(hT);
        return TRUE;
    }
    return FALSE;
}

/* ---- PEB flag: the image's "show loader snaps" global flag ---- */

static void EnableLoaderSnaps(ND_PROC *p)
{
    ND_PBI pbi;
    DWORD flag = 0;
    ULONG_PTR peb32 = 0;
    SIZE_T done;
    ULONG len;

    if (!pNtQueryInformationProcess || g_Opt.NoSnaps)
        return;
    ZeroMemory(&pbi, sizeof(pbi));
    if (pNtQueryInformationProcess(p->hProcess, 0, &pbi, sizeof(pbi), &len) != 0 || !pbi.PebBaseAddress)
        return;
    /* PEB.NtGlobalFlag: offset 0xBC in a 64-bit PEB, 0x68 in a 32-bit one */
#ifdef _M_AMD64
    if (p->Wow64)
    {
        if (pNtQueryInformationProcess(p->hProcess, 26 /* ProcessWow64Information */, &peb32, sizeof(peb32), &len) == 0 && peb32)
        {
            if (ReadMem(p, peb32 + 0x68, &flag, 4))
            {
                flag |= 0x2;
                WriteProcessMemory(p->hProcess, (LPVOID)(ULONG_PTR)(peb32 + 0x68), &flag, 4, &done);
            }
        }
        /* the 64-bit PEB too: the 64-bit layer of the process reads it */
    }
    if (ReadMem(p, (ULONG_PTR)pbi.PebBaseAddress + 0xBC, &flag, 4))
    {
        flag |= 0x2;
        WriteProcessMemory(p->hProcess, (LPVOID)((ULONG_PTR)pbi.PebBaseAddress + 0xBC), &flag, 4, &done);
    }
#else
    (void)peb32;
    if (ReadMem(p, (ULONG_PTR)pbi.PebBaseAddress + 0x68, &flag, 4))
    {
        flag |= 0x2;
        WriteProcessMemory(p->hProcess, (LPVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x68), &flag, 4, &done);
    }
#endif
}

/* ---- debug strings ---- */

static BOOL StartsWithA(const char *s, const char *prefix)
{
    return !strncmp(s, prefix, strlen(prefix));
}

/* One call of a stub shows up as the stub's printed name (DbgPrint) and, for the 'stub' kind, as an exception:
 * the printed name counts the call, the exception only tells the DLL. */
static DWORD g_LastPrintTid;
static char  g_LastPrintFunc[128];

static void StubRecord(ND_PROC *p, DWORD tid, const char *dll, const char *func, BOOL fromException)
{
    int i;
    BOOL sameCall = fromException && tid == g_LastPrintTid && !strcmp(func, g_LastPrintFunc);
    if (!fromException)
    {
        g_LastPrintTid = tid;
        StringCchCopyA(g_LastPrintFunc, sizeof(g_LastPrintFunc), func);
    }
    else
        g_LastPrintFunc[0] = 0;
    for (i = 0; i < g_Res.nStubs; i++)
    {
        if (!_stricmp(g_Res.Stubs[i].Func, func) && (!dll || !dll[0] || !g_Res.Stubs[i].Dll[0] || !_stricmp(g_Res.Stubs[i].Dll, dll)))
        {
            if (dll && dll[0] && !g_Res.Stubs[i].Dll[0])
                StringCchCopyA(g_Res.Stubs[i].Dll, sizeof(g_Res.Stubs[0].Dll), dll);
            if (!sameCall)
                g_Res.Stubs[i].Count++;
            return;
        }
    }
    if (g_Res.nStubs >= ND_MAX_STUBS)
        return;
    ZeroMemory(&g_Res.Stubs[g_Res.nStubs], sizeof(ND_STUB));
    if (dll)
        StringCchCopyA(g_Res.Stubs[g_Res.nStubs].Dll, sizeof(g_Res.Stubs[0].Dll), dll);
    StringCchCopyA(g_Res.Stubs[g_Res.nStubs].Func, sizeof(g_Res.Stubs[0].Func), func);
    g_Res.Stubs[g_Res.nStubs].Count = 1;
    g_Res.nStubs++;
    Tl(L"pid %lu thread %lu: called a function NitroOS does not implement yet: %S!%S",
       p->Pid, tid, dll && dll[0] ? dll : "?", func);
}

/* The DLL of a stub that only printed its name (spec "-stub" entries): the first frame outside ntdll */
static void StubDllFromStack(ND_PROC *p, DWORD tid, char *dll, size_t cch)
{
    ULONG64 frames[6] = {0};
    HANDLE hT = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    int i, n;
    dll[0] = 0;
    if (!hT)
        return;
    n = WalkStack(p, hT, NULL, L"", frames, 6);
    CloseHandle(hT);
    for (i = 0; i < n && i < 6; i++)
    {
        int m;
        for (m = 0; m < p->nMods; m++)
        {
            ND_MODULE *mod = &p->Mods[m];
            if (frames[i] >= mod->Base && frames[i] < mod->Base + (mod->Size ? mod->Size : 0x1000))
            {
                const WCHAR *name = wcsrchr(mod->Path, L'\\');
                name = name ? name + 1 : mod->Path;
                if (_wcsicmp(name, L"ntdll.dll"))
                {
                    StringCchPrintfA(dll, cch, "%S", name);
                    return;
                }
                break;
            }
        }
    }
}

static void OnDebugText(ND_PROC *p, DWORD tid, char *text)
{
    size_t len = strlen(text);
    WCHAR w[200];

    while (len && (text[len - 1] == '\n' || text[len - 1] == '\r'))
        text[--len] = 0;
    if (!len)
        return;
    /* the "0320:" thread-id fragments the debug printer writes before a line are not text */
    if (len == 5 && text[4] == ':' && isxdigit((unsigned char)text[0]) && isxdigit((unsigned char)text[3]))
        return;

    /* Debug builds put "[pid,tid] " and "(file.c:line) " before the text */
    if (text[0] == '[' && strstr(text, "] "))
    {
        char *after = strstr(text, "] ") + 2;
        memmove(text, after, strlen(after) + 1);
        len = strlen(text);
    }
    if (text[0] == '(' && strstr(text, ") "))
    {
        char *after = strstr(text, ") ") + 2;
        memmove(text, after, strlen(after) + 1);
        len = strlen(text);
    }

    if (StartsWithA(text, "WARNING: calling stub "))
    {
        char func[128];
        char dll[64];
        const char *s = text + 22;
        size_t n = 0;
        while (s[n] && s[n] != '(' && n < sizeof(func) - 1)
        {
            func[n] = s[n];
            n++;
        }
        func[n] = 0;
        StubDllFromStack(p, tid, dll, sizeof(dll));
        StubRecord(p, tid, dll, func, FALSE);
        return;
    }

    /* the activation context code of ntdll prints these on every load and every WoW64 transition */
    if (StartsWithA(text, "ActiveSP ") || StartsWithA(text, "Trying to activate") || StartsWithA(text, "sections: ") ||
        StartsWithA(text, "status c0") || strstr(text, "RtlFindActivationContextSectionString") ||
        !strncmp(text, "0000000", 7) || StartsWithA(text, "Image Path:") || StartsWithA(text, "Current Directory:") ||
        StartsWithA(text, "Search Path:"))
    {
        g_Res.nSnapLines++;
        return;
    }

    if (StartsWithA(text, "LDR:") || StartsWithA(text, "NAME - ") || StartsWithA(text, "ORDINAL - ") ||
        strstr(text, "LdrpMapDll") || strstr(text, "LdrGetProcedureAddress"))
    {
        g_Res.nSnapLines++;
        if (StartsWithA(text, "NAME - ") || StartsWithA(text, "ORDINAL - "))
            return;     /* the function names the loader looks up: no use in the timeline */
        if (strstr(text, "ail") || strstr(text, "nable") || strstr(text, "not found") || strstr(text, "NOT") ||
            strstr(text, "xception") || strstr(text, "llegal") || strstr(text, "tatus") || strstr(text, "rror"))
        {
            MultiByteToWideChar(CP_ACP, 0, text, -1, w, _countof(w));
            Tl(L"pid %lu loader: %s", p->Pid, w);
        }
        return;
    }

    g_Res.nDebugStrings++;
    /* lines of the same shape (digits and hex runs masked) are kept three times, then only counted: a 32-bit program
     * on a 64-bit system makes the system print the same few lines thousands of times */
    {
        ULONG64 h = 1469598103934665603ULL;
        size_t i;
        int k;
        for (i = 0; text[i]; i++)
        {
            unsigned char c = (unsigned char)text[i];
            if (isxdigit(c) && (i == 0 || !isalpha((unsigned char)text[i - 1]) || isxdigit((unsigned char)text[i - 1])))
                c = '#';
            if (c == '#' && i && text[i - 1] == '#')
                continue;
            h = (h ^ c) * 1099511628211ULL;
        }
        for (k = 0; k < g_Res.nShapes; k++)
            if (g_Res.Shapes[k].Hash == h)
                break;
        if (k == g_Res.nShapes)
        {
            if (k >= ND_MAX_SHAPES)
                k = ND_MAX_SHAPES - 1;
            else
                g_Res.nShapes++;
            g_Res.Shapes[k].Hash = h;
            g_Res.Shapes[k].Count = 0;
            MultiByteToWideChar(CP_ACP, 0, text, -1, g_Res.Shapes[k].Sample, _countof(g_Res.Shapes[k].Sample));
        }
        if (++g_Res.Shapes[k].Count > 3)
        {
            g_Res.nDebugStringsDropped++;
            return;
        }
    }
    MultiByteToWideChar(CP_ACP, 0, text, -1, w, _countof(w));
    StringCchCopyW(g_Res.LastDebugText, _countof(g_Res.LastDebugText), w);
    Tl(L"pid %lu debug text: %s", p->Pid, w);
}

static void OnOutputDebugString(ND_PROC *p, DWORD tid, const OUTPUT_DEBUG_STRING_INFO *info)
{
    char buf[512];
    SIZE_T cb = info->nDebugStringLength;
    if (!info->lpDebugStringData || !cb)
        return;
    if (info->fUnicode)
    {
        WCHAR wbuf[256];
        SIZE_T got = 0;
        if (cb > sizeof(wbuf) - 2)
            cb = sizeof(wbuf) - 2;
        if (!ReadProcessMemory(p->hProcess, info->lpDebugStringData, wbuf, cb, &got))
            return;
        wbuf[got / 2] = 0;
        WideCharToMultiByte(CP_ACP, 0, wbuf, -1, buf, sizeof(buf), NULL, NULL);
    }
    else
    {
        SIZE_T got = 0;
        if (cb > sizeof(buf) - 1)
            cb = sizeof(buf) - 1;
        if (!ReadProcessMemory(p->hProcess, info->lpDebugStringData, buf, cb, &got))
            return;
        buf[got] = 0;
    }
    OnDebugText(p, tid, buf);
}

/* DbgPrint raises DBG_PRINTEXCEPTION_C: parameter 0 = length, parameter 1 = the text */
static void OnPrintException(ND_PROC *p, DWORD tid, const EXCEPTION_RECORD *rec, BOOL wide)
{
    char buf[512];
    SIZE_T cb;
    SIZE_T got = 0;
    if (rec->NumberParameters < 2)
        return;
    cb = (SIZE_T)rec->ExceptionInformation[0];
    if (wide)
    {
        WCHAR wbuf[256];
        /* a wide print exception counts characters */
        cb = cb * 2;
        if (cb > sizeof(wbuf) - 2)
            cb = sizeof(wbuf) - 2;
        if (!ReadProcessMemory(p->hProcess, (LPCVOID)rec->ExceptionInformation[1], wbuf, cb, &got))
            return;
        wbuf[got / 2] = 0;
        WideCharToMultiByte(CP_ACP, 0, wbuf, -1, buf, sizeof(buf), NULL, NULL);
    }
    else
    {
        if (cb > sizeof(buf) - 1)
            cb = sizeof(buf) - 1;
        if (!ReadProcessMemory(p->hProcess, (LPCVOID)rec->ExceptionInformation[1], buf, cb, &got))
            return;
        buf[got] = 0;
    }
    OnDebugText(p, tid, buf);
}

/* ---- minidump ---- */

static void WriteDump(ND_PROC *p, DWORD tid, const EXCEPTION_RECORD *rec, ND_CRASH *cr)
{
    WCHAR tmp[MAX_PATH], file[MAX_PATH];
    HANDLE hFile, hT;
    MINIDUMP_EXCEPTION_INFORMATION mei;
    EXCEPTION_POINTERS ep;
    EXCEPTION_RECORD er = *rec;
    ND_REGS r;
    ND_CTX ctx;
    BOOL ok;

    if (g_Opt.NoDump || g_Res.nDumps >= ND_MAX_CRASH)
        return;
    /* a WoW64 target would need the 32-bit dump format of the dumper: not supported from a 64-bit tracer */
#ifdef _M_AMD64
    if (p->Wow64)
    {
        WbPrintf(&cr->Detail, L"  (no minidump: a 32-bit program seen from the 64-bit tool; the stack above is what is recorded)\r\n");
        return;
    }
#endif
    hT = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hT)
        return;
    if (!GetRegs(p, hT, &r, &ctx))
    {
        CloseHandle(hT);
        return;
    }
    GetTempPathW(_countof(tmp), tmp);
    StringCchPrintfW(file, _countof(file), L"%snitrodiag-%lu-%lu.dmp", tmp, p->Pid, GetTickCount());
    hFile = CreateFileW(file, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hT);
        return;
    }
    ZeroMemory(&ep, sizeof(ep));
    ep.ExceptionRecord = &er;
    ep.ContextRecord = &ctx.Native;
    mei.ThreadId = tid;
    mei.ExceptionPointers = &ep;
    mei.ClientPointers = FALSE;
    ok = MiniDumpWriteDump(p->hProcess, p->Pid, hFile, MiniDumpNormal, &mei, NULL, NULL);
    if (!ok)
        WbPrintf(&cr->Detail, L"  (minidump failed: error %lu)\r\n", GetLastError());
    CloseHandle(hFile);
    CloseHandle(hT);
    if (ok)
    {
        const WCHAR *nm = wcsrchr(file, L'\\') + 1;
        StringCchPrintfW(cr->DumpName, _countof(cr->DumpName), L"crash-%lu-%lu.dmp", p->Pid, tid);
        StringCchCopyW(g_Res.DumpFiles[g_Res.nDumps++], MAX_PATH, file);
        (void)nm;
        WbPrintf(&cr->Detail, L"  minidump: %s (in the zip)\r\n", cr->DumpName);
    }
    else
        DeleteFileW(file);
}

/* ---- the crash ---- */

static void OnCrash(ND_PROC *p, DWORD tid, const EXCEPTION_RECORD *rec)
{
    ND_CRASH *cr;
    HANDLE hT;
    WCHAR where[MAX_PATH + 40];

    if (g_Res.nCrash >= ND_MAX_CRASH)
        return;
    cr = &g_Res.Crash[g_Res.nCrash++];
    ZeroMemory(cr, sizeof(*cr));
    cr->Pid = p->Pid;
    cr->Tid = tid;
    cr->Code = rec->ExceptionCode;
    cr->Addr = (ULONG64)(ULONG_PTR)rec->ExceptionAddress;
    cr->NumInfo = rec->NumberParameters;
    cr->Info0 = rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0;
    cr->Info1 = rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0;
    WhereIs(p, cr->Addr, where, _countof(where));
    StringCchCopyW(cr->Where, _countof(cr->Where), where);

    Tl(L"pid %lu thread %lu: UNHANDLED EXCEPTION %s (0x%08lx) at %s", p->Pid, tid,
       ExceptionName(rec->ExceptionCode), rec->ExceptionCode, where);

    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2)
    {
        WbPrintf(&cr->Detail, L"  access violation %s address 0x%I64x\r\n",
                 rec->ExceptionInformation[0] == 0 ? L"reading" : (rec->ExceptionInformation[0] == 1 ? L"writing" : L"executing"),
                 (ULONG64)rec->ExceptionInformation[1]);
    }
    else if (rec->ExceptionCode == ND_EXCEPTION_CPP)
        WbPrintf(&cr->Detail, L"  a C++ exception was thrown and nothing caught it\r\n");

    hT = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (hT)
    {
        DumpRegs(p, hT, &cr->Detail);
        WbPrintf(&cr->Detail, L"  stack:\r\n");
        WalkStack(p, hT, &cr->Detail, L"    ", NULL, 0);
        CloseHandle(hT);
    }
    WriteDump(p, tid, rec, cr);
}

/* ---- snapshot of the processes that are still running ---- */

static void Snapshot(void)
{
    int i;
    for (i = 0; i < g_nProcs; i++)
    {
        ND_PROC *p = &g_Procs[i];
        HANDLE snap;
        THREADENTRY32 te;
        int m;

        if (p->Exited)
            continue;
        WbPrintf(&g_Res.Snapshot, L"Process %lu  %s  (still running after %lu s)\r\n", p->Pid, p->Image,
                 (ElapsedMs() + 500) / 1000);
        WbPrintf(&g_Res.Snapshot, L"  modules (%d):\r\n", p->nMods);
        for (m = 0; m < p->nMods; m++)
            WbPrintf(&g_Res.Snapshot, L"    0x%I64x  %s\r\n", p->Mods[m].Base, p->Mods[m].Path);

        snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE)
            continue;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te))
        {
            do
            {
                HANDLE hT;
                if (te.th32OwnerProcessID != p->Pid)
                    continue;
                hT = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (!hT)
                    continue;
                WbPrintf(&g_Res.Snapshot, L"  thread %lu:\r\n", te.th32ThreadID);
                if (SuspendThread(hT) != (DWORD)-1)
                {
                    WalkStack(p, hT, &g_Res.Snapshot, L"    ", NULL, 0);
                    ResumeThread(hT);
                }
                else
                    WbPrintf(&g_Res.Snapshot, L"    (could not suspend)\r\n");
                CloseHandle(hT);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
}

/* ---- events ---- */

static void ProcInitSymbols(ND_PROC *p)
{
    if (!p->SymInit)
    {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS);
        p->SymInit = SymInitialize(p->hProcess, NULL, FALSE);
    }
}

static void OnCreateProcess(const DEBUG_EVENT *de)
{
    const CREATE_PROCESS_DEBUG_INFO *ci = &de->u.CreateProcessInfo;
    ND_PROC *p = ProcFind(de->dwProcessId);
    ND_MODULE *m;
    BOOL w = FALSE;

    if (!p)
        p = ProcNew(de->dwProcessId);
    if (!p)
    {
        if (ci->hFile)
            CloseHandle(ci->hFile);
        return;
    }
    p->hProcess = ci->hProcess;
    p->IsRoot = (p->Pid == g_Res.RootPid);
    p->ImageBase = (ULONG64)(ULONG_PTR)ci->lpBaseOfImage;
    p->nThreads = 1;
    if (pIsWow64Process && pIsWow64Process(p->hProcess, &w))
        p->Wow64 = w;
    if (!PathOfFileHandle(ci->hFile, p->Image, _countof(p->Image)))
        StringCchCopyW(p->Image, _countof(p->Image), L"(unknown image)");
    if (ci->hFile)
        CloseHandle(ci->hFile);
    g_Res.nProcsStarted++;

    ProcInitSymbols(p);
    m = ModAdd(p, p->ImageBase);
    if (m)
    {
        m->Size = ImageSizeInTarget(p, p->ImageBase);
        StringCchCopyW(m->Path, _countof(m->Path), p->Image);
        FileVersionOf(p->Image, m->Version, _countof(m->Version));
        if (p->SymInit)
            SymLoadModuleExW(p->hProcess, NULL, m->Path, NULL, m->Base, m->Size, NULL, 0);
    }
    EnableLoaderSnaps(p);
    Tl(L"pid %lu started: %s (%s)%s", p->Pid, p->Image, p->Wow64 ? L"32-bit program on a 64-bit system" :
#ifdef _M_AMD64
       L"64-bit program",
#else
       L"32-bit program",
#endif
       p->IsRoot ? L"" : L"  [child process]");
}

static void OnLoadDll(const DEBUG_EVENT *de)
{
    const LOAD_DLL_DEBUG_INFO *li = &de->u.LoadDll;
    ND_PROC *p = ProcFind(de->dwProcessId);
    ND_MODULE *m;
    const WCHAR *name;

    if (!p)
    {
        if (li->hFile)
            CloseHandle(li->hFile);
        return;
    }
    m = ModAdd(p, (ULONG64)(ULONG_PTR)li->lpBaseOfDll);
    if (!m)
    {
        if (li->hFile)
            CloseHandle(li->hFile);
        return;
    }
    if (!PathOfFileHandle(li->hFile, m->Path, _countof(m->Path)))
        StringCchCopyW(m->Path, _countof(m->Path), L"(unknown)");
    if (li->hFile)
        CloseHandle(li->hFile);
    m->Size = ImageSizeInTarget(p, m->Base);
    FileVersionOf(m->Path, m->Version, _countof(m->Version));
    if (p->SymInit)
        SymLoadModuleExW(p->hProcess, NULL, m->Path, NULL, m->Base, m->Size, NULL, 0);
    StringCchCopyW(g_Res.LastLoadedModule, _countof(g_Res.LastLoadedModule), m->Path);
    p->LastDllInit = p->nMods - 1;
    Tl(L"pid %lu loaded %s  version %s  size 0x%lx  at 0x%I64x", p->Pid, m->Path,
       m->Version[0] ? m->Version : L"-", m->Size, m->Base);

    name = wcsrchr(m->Path, L'\\');
    name = name ? name + 1 : m->Path;
    if (!_wcsicmp(name, L"ntdll.dll"))
        BpArm(p, m->Base, m->Path, "NtRaiseHardError", ND_BP_HARDERR);
    else if (!_wcsicmp(name, L"kernel32.dll") || !_wcsicmp(name, L"kernelbase.dll"))
        BpArm(p, m->Base, m->Path, "IsDebuggerPresent", ND_BP_ISDBG);
}

static void OnUnloadDll(const DEBUG_EVENT *de)
{
    ND_PROC *p = ProcFind(de->dwProcessId);
    ND_MODULE *m;
    if (!p)
        return;
    m = ModByBase(p, (ULONG64)(ULONG_PTR)de->u.UnloadDll.lpBaseOfDll);
    if (m)
    {
        Tl(L"pid %lu unloaded %s", p->Pid, m->Path);
        if (p->SymInit)
            SymUnloadModule64(p->hProcess, m->Base);
        /* keep the entry for the module list, but mark it */
        m->Version[0] = m->Version[0];
    }
}

static DWORD OnException(const DEBUG_EVENT *de)
{
    const EXCEPTION_RECORD *rec = &de->u.Exception.ExceptionRecord;
    ND_PROC *p = ProcFind(de->dwProcessId);
    DWORD code = rec->ExceptionCode;

    if (!p)
        return DBG_EXCEPTION_NOT_HANDLED;

    if (code == EXCEPTION_BREAKPOINT || code == ND_EXCEPTION_WX86_BREAKPOINT)
    {
        if (HandleBreakpointHit(p, de->dwThreadId, (ULONG64)(ULONG_PTR)rec->ExceptionAddress))
            return DBG_CONTINUE;
        /* the loader's own breakpoints (the first one of the process; a 32-bit program on a 64-bit system has a second one
         * in its 32-bit ntdll): any breakpoint inside ntdll.dll */
        {
            WCHAR where[MAX_PATH + 40];
            WhereIs(p, (ULONG64)(ULONG_PTR)rec->ExceptionAddress, where, _countof(where));
            if (!p->SawInitialBp || !_wcsnicmp(where, L"ntdll.dll+", 10))
            {
                p->SawInitialBp = TRUE;
                if (g_Opt.Raw)
                    Tl(L"pid %lu: loader breakpoint at %s", p->Pid, where);
                return DBG_CONTINUE;
            }
        }
        /* a breakpoint the program raised itself: it is not ours to handle */
    }
    else if (code == EXCEPTION_SINGLE_STEP || code == ND_EXCEPTION_WX86_SINGLE_STEP)
    {
        if (p->StepTid == de->dwThreadId)
        {
            p->StepTid = 0;
            if (p->StepBp >= 0 && p->StepBp < p->nBps)
                BpSet(p, &p->Bps[p->StepBp], TRUE);
            return DBG_CONTINUE;
        }
    }
    else if (code == ND_DBG_PRINTEXCEPTION_C || code == ND_DBG_PRINTEXCEPTION_WIDE_C)
    {
        OnPrintException(p, de->dwThreadId, rec, code == ND_DBG_PRINTEXCEPTION_WIDE_C);
        return DBG_CONTINUE;
    }
    else if (code == ND_EXCEPTION_WINE_STUB && rec->NumberParameters >= 2)
    {
        char dll[64], func[128];
        ReadStrA(p, rec->ExceptionInformation[0], dll, sizeof(dll));
        ReadStrA(p, rec->ExceptionInformation[1], func, sizeof(func));
        if (de->u.Exception.dwFirstChance)
            StubRecord(p, de->dwThreadId, dll, func, TRUE);
        else
        {
            /* the program does not handle the stub's exception: it ends here */
            OnCrash(p, de->dwThreadId, rec);
        }
        return DBG_EXCEPTION_NOT_HANDLED;
    }
    else if (code == 0x406D1388)
        return DBG_EXCEPTION_NOT_HANDLED;   /* a thread name for the debugger */

    if (code == 0x20474343 || code == ND_EXCEPTION_CPP)
        g_Res.CppThrown = TRUE;
    if (de->u.Exception.dwFirstChance)
    {
        p->nFirstChance++;
        g_Res.nFirstChance++;
        if (g_Res.nFirstChance <= FIRSTCHANCE_MAX_LOG)
        {
            WCHAR where[MAX_PATH + 40];
            WhereIs(p, (ULONG64)(ULONG_PTR)rec->ExceptionAddress, where, _countof(where));
            Tl(L"pid %lu thread %lu: first-chance exception %s (0x%08lx) at %s", p->Pid, de->dwThreadId,
               ExceptionName(code), code, where);
        }
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    OnCrash(p, de->dwThreadId, rec);
    return DBG_EXCEPTION_NOT_HANDLED;
}

static int AliveCount(void)
{
    int i, n = 0;
    for (i = 0; i < g_nProcs; i++)
        if (!g_Procs[i].Exited)
            n++;
    return n;
}

static void Detach(void)
{
    int i;
    for (i = 0; i < g_nProcs; i++)
    {
        ND_PROC *p = &g_Procs[i];
        if (p->Exited)
            continue;
        BpRemoveAll(p);
        DebugActiveProcessStop(p->Pid);
    }
}

int TraceRun(void)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DEBUG_EVENT de;
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    HMODULE hK = GetModuleHandleW(L"kernel32.dll");
    BOOL started = FALSE;
    DWORD timeoutMs;
    BOOL snapshotDone = FALSE;
    int failures = 0;

    pNtQueryInformationProcess = (PFN_NTQIP)GetProcAddress(hNt, "NtQueryInformationProcess");
    pWow64GetThreadContext = (PFN_W64GTC)GetProcAddress(hK, "Wow64GetThreadContext");
    pWow64SetThreadContext = (PFN_W64STC)GetProcAddress(hK, "Wow64SetThreadContext");
    pIsWow64Process = (PFN_ISW64)GetProcAddress(hK, "IsWow64Process");

    GetSystemTimeAsFileTime(&g_Res.StartTime);
    g_Res.StartTick = GetTickCount();
    g_Res.TimeoutSec = g_Opt.TimeoutSec;

    if (g_Opt.AttachPid)
    {
        g_Res.RootPid = g_Opt.AttachPid;
        g_Res.Attached = TRUE;
        if (!DebugActiveProcess(g_Opt.AttachPid))
        {
            g_Res.CreateFailed = TRUE;
            g_Res.CreateError = GetLastError();
            return 1;
        }
        DebugSetProcessKillOnExit(FALSE);
        /* an attach is a look at a running process: look for a few seconds when no time was given */
        if (!g_Opt.TimeoutSec)
            g_Opt.TimeoutSec = 3;
        g_Res.TimeoutSec = g_Opt.TimeoutSec;
        started = TRUE;
    }
    else
    {
        WCHAR *cmd = _wcsdup(g_Opt.CmdLine);
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_DEFAULT_ERROR_MODE,
                            NULL, g_Opt.WorkDir[0] ? g_Opt.WorkDir : NULL, &si, &pi))
        {
            g_Res.CreateFailed = TRUE;
            g_Res.CreateError = GetLastError();
            free(cmd);
            return 1;
        }
        free(cmd);
        g_Res.RootPid = pi.dwProcessId;
        DebugSetProcessKillOnExit(FALSE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        started = TRUE;
    }

    timeoutMs = g_Opt.TimeoutSec * 1000;
    while (started)
    {
        DWORD status = DBG_CONTINUE;
        BOOL stop = FALSE;

        if (!PumpStatusWindow() || g_StopRequested)
        {
            g_Res.StoppedByUser = TRUE;
            stop = TRUE;
        }
        else if (timeoutMs && ElapsedMs() >= timeoutMs && AliveCount())
            stop = TRUE;
        if (stop)
        {
            if (AliveCount())
            {
                g_Res.StillRunning = TRUE;
                Tl(L"stopping the observation: the program is still running");
                Snapshot();
                snapshotDone = TRUE;
            }
            Detach();
            break;
        }

        if (!WaitForDebugEvent(&de, 100))
        {
            DWORD err = GetLastError();
            if (err == ERROR_SEM_TIMEOUT || err == WAIT_TIMEOUT)
            {
                failures = 0;
                continue;
            }
            if (++failures > 20)
                break;
            continue;
        }
        failures = 0;

        switch (de.dwDebugEventCode)
        {
            case CREATE_PROCESS_DEBUG_EVENT:
                OnCreateProcess(&de);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
            {
                ND_PROC *p = ProcFind(de.dwProcessId);
                if (p)
                    p->nThreads++;
                if (g_Opt.Raw)
                    Tl(L"pid %lu: thread %lu created", de.dwProcessId, de.dwThreadId);
                break;
            }
            case EXIT_THREAD_DEBUG_EVENT:
                if (g_Opt.Raw)
                    Tl(L"pid %lu: thread %lu exited with code 0x%lx", de.dwProcessId, de.dwThreadId, de.u.ExitThread.dwExitCode);
                break;
            case LOAD_DLL_DEBUG_EVENT:
                OnLoadDll(&de);
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                OnUnloadDll(&de);
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
            {
                ND_PROC *p = ProcFind(de.dwProcessId);
                if (p)
                    OnOutputDebugString(p, de.dwThreadId, &de.u.DebugString);
                break;
            }
            case EXCEPTION_DEBUG_EVENT:
                status = OnException(&de);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
            {
                ND_PROC *p = ProcFind(de.dwProcessId);
                if (p)
                {
                    p->Exited = TRUE;
                    p->ExitCode = de.u.ExitProcess.dwExitCode;
                    p->EndTick = GetTickCount();
                    Tl(L"pid %lu exited with code 0x%08lx (%ld) after %lu ms", p->Pid, p->ExitCode,
                       (LONG)p->ExitCode, p->EndTick - p->StartTick);
                    if (p->SymInit)
                    {
                        SymCleanup(p->hProcess);
                        p->SymInit = FALSE;
                    }
                }
                break;
            }
            case RIP_EVENT:
                Tl(L"pid %lu: system debugging error %lu", de.dwProcessId, de.u.RipInfo.dwError);
                break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status);
        if (g_nProcs && !AliveCount())
            break;
    }
    (void)snapshotDone;
    if (g_Res.Timeline.len > TL_MAX_CHARS)
        WbPrintf(&g_Res.Extras, L"The timeline was cut at %d KB: %lu more lines were dropped.\r\n", TL_MAX_CHARS / 512, g_SeenTimelineBytes);
    return 0;
}
