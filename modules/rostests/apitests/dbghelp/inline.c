/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     dbghelp: the inline frame functions, resolved by name
 *
 * Programs (the 64-bit debuggers of the Windows SDK among them) import these by name from dbghelp.dll and do
 * not start without them.  The rows after the exports are what Windows Server 2022 (dbghelp 10.0.20348)
 * returns for a function that has only an export symbol, which is all this test can count on.
 */

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#include "wine/test.h"

typedef DWORD (WINAPI *PFN_ADDRINC)(HANDLE, DWORD64);
typedef DWORD (WINAPI *PFN_COMPARE)(HANDLE, DWORD64, DWORD, DWORD64, DWORD64, DWORD64);
typedef BOOL (WINAPI *PFN_QUERY)(HANDLE, DWORD64, DWORD, DWORD64, DWORD64, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *PFN_FROMCTX)(HANDLE, DWORD64, ULONG, PDWORD64, PSYMBOL_INFO);
typedef BOOL (WINAPI *PFN_FROMCTXW)(HANDLE, DWORD64, ULONG, PDWORD64, PSYMBOL_INFOW);
typedef BOOL (WINAPI *PFN_LINECTX)(HANDLE, DWORD64, ULONG, DWORD64, PDWORD, PIMAGEHLP_LINE64);
typedef BOOL (WINAPI *PFN_SCOPECTX)(HANDLE, ULONG64, ULONG);
typedef BOOL (WINAPI *PFN_WALKEX)(DWORD, HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, DWORD);

static const char *Names[] =
{
    "SymAddrIncludeInlineTrace", "SymCompareInlineTrace", "SymFromInlineContext", "SymFromInlineContextW",
    "SymGetLineFromInlineContext", "SymGetLineFromInlineContextW", "SymQueryInlineTrace",
    "SymSetScopeFromInlineContext", "StackWalkEx",
};

START_TEST(inline)
{
    HMODULE Dbghelp = LoadLibraryA("dbghelp.dll");
    HANDLE Process = GetCurrentProcess();
    PFN_ADDRINC AddrInclude;
    PFN_COMPARE Compare;
    PFN_QUERY Query;
    PFN_FROMCTX FromContext;
    PFN_FROMCTXW FromContextW;
    PFN_LINECTX LineContext;
    PFN_SCOPECTX ScopeContext;
    DWORD64 Address, Disp = 0, Disp2 = 0;
    ULONG Contexts[] = { 0, INLINE_FRAME_CONTEXT_IGNORE, 0x80000000, 0x40000003, 0x20000000 };
    UCHAR Buffer[sizeof(SYMBOL_INFO) + 256], Buffer2[sizeof(SYMBOL_INFO) + 256];
    PSYMBOL_INFO Info = (PSYMBOL_INFO)Buffer, Info2 = (PSYMBOL_INFO)Buffer2;
    DWORD Context, Index, i, Displacement;
    IMAGEHLP_LINE64 Line;
    BOOL Ret, Found;

    ok(Dbghelp != NULL, "dbghelp.dll not loaded: %lu\n", GetLastError());
    if (!Dbghelp)
        return;
    for (i = 0; i < RTL_NUMBER_OF(Names); i++)
        ok(GetProcAddress(Dbghelp, Names[i]) != NULL, "%s is not exported\n", Names[i]);

    AddrInclude = (PFN_ADDRINC)GetProcAddress(Dbghelp, "SymAddrIncludeInlineTrace");
    Compare = (PFN_COMPARE)GetProcAddress(Dbghelp, "SymCompareInlineTrace");
    Query = (PFN_QUERY)GetProcAddress(Dbghelp, "SymQueryInlineTrace");
    FromContext = (PFN_FROMCTX)GetProcAddress(Dbghelp, "SymFromInlineContext");
    FromContextW = (PFN_FROMCTXW)GetProcAddress(Dbghelp, "SymFromInlineContextW");
    LineContext = (PFN_LINECTX)GetProcAddress(Dbghelp, "SymGetLineFromInlineContext");
    ScopeContext = (PFN_SCOPECTX)GetProcAddress(Dbghelp, "SymSetScopeFromInlineContext");
    if (!AddrInclude || !Compare || !Query || !FromContext || !FromContextW || !LineContext || !ScopeContext)
        return;

    ok(SymInitialize(Process, NULL, TRUE), "SymInitialize failed %lu\n", GetLastError());
    Address = (DWORD64)(ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW");

    SetLastError(0xdeadbeef);
    ok(AddrInclude(Process, Address) == 0, "SymAddrIncludeInlineTrace of an exported function is not 0\n");
    ok(AddrInclude(Process, 0x10) == 0, "SymAddrIncludeInlineTrace of an address in no module is not 0\n");

    Context = 0x12345678;
    Index = 0x12345678;
    SetLastError(0xdeadbeef);
    Ret = Query(Process, Address, 0, Address, Address, &Context, &Index);
    ok(!Ret, "SymQueryInlineTrace succeeded for a function without inline information\n");
    ok(GetLastError() == 0xdeadbeef, "SymQueryInlineTrace set the error %lu\n", GetLastError());
    ok(Context == INLINE_FRAME_CONTEXT_IGNORE && Index == 0, "SymQueryInlineTrace gave context 0x%08lx index %lu\n", Context, Index);

    ok(Compare(Process, Address, 0, Address, Address, Address) == SYM_INLINE_COMP_ERROR, "SymCompareInlineTrace is not SYM_INLINE_COMP_ERROR\n");

    /* An export symbol (in this build, whatever symbol the address has) comes back unchanged for every context value. */
    memset(Buffer, 0, sizeof(Buffer));
    Info->SizeOfStruct = sizeof(*Info);
    Info->MaxNameLen = 200;
    Found = SymFromAddr(Process, Address, &Disp, Info);
    if (!Found)
    {
        skip("no symbol for CreateFileW (%lu)\n", GetLastError());
    }
    else
    {
        for (i = 0; i < RTL_NUMBER_OF(Contexts); i++)
        {
            memset(Buffer2, 0, sizeof(Buffer2));
            Info2->SizeOfStruct = sizeof(*Info2);
            Info2->MaxNameLen = 200;
            Disp2 = 0xee;
            SetLastError(0xdeadbeef);
            Ret = FromContext(Process, Address, Contexts[i], &Disp2, Info2);
            ok(Ret, "SymFromInlineContext(0x%08lx) failed %lu\n", Contexts[i], GetLastError());
            if (Ret)
            {
                ok(!strcmp(Info->Name, Info2->Name), "SymFromInlineContext(0x%08lx): \"%s\", SymFromAddr \"%s\"\n",
                   Contexts[i], Info2->Name, Info->Name);
                ok(Disp == Disp2, "SymFromInlineContext(0x%08lx): displacement %I64u, SymFromAddr %I64u\n", Contexts[i], Disp2, Disp);
            }
        }
        {
            UCHAR WBuffer[sizeof(SYMBOL_INFOW) + 256 * sizeof(WCHAR)];
            PSYMBOL_INFOW InfoW = (PSYMBOL_INFOW)WBuffer;

            memset(WBuffer, 0, sizeof(WBuffer));
            InfoW->SizeOfStruct = sizeof(*InfoW);
            InfoW->MaxNameLen = 200;
            ok(FromContextW(Process, Address, INLINE_FRAME_CONTEXT_IGNORE, NULL, InfoW), "SymFromInlineContextW failed %lu\n", GetLastError());
            ok(InfoW->NameLen != 0 && InfoW->Name[0] == L'C', "SymFromInlineContextW name \"%ls\"\n", InfoW->Name);
        }
    }

    /* No line information: the error is ERROR_INVALID_ADDRESS, also for a structure that is too small. */
    memset(&Line, 0, sizeof(Line));
    Line.SizeOfStruct = sizeof(Line);
    Displacement = 0;
    SetLastError(0xdeadbeef);
    Ret = LineContext(Process, Address, INLINE_FRAME_CONTEXT_IGNORE, 0, &Displacement, &Line);
    if (!Ret)
        ok(GetLastError() == ERROR_INVALID_ADDRESS, "SymGetLineFromInlineContext error %lu\n", GetLastError());
    Line.SizeOfStruct = 4;
    SetLastError(0xdeadbeef);
    ok(!LineContext(Process, Address, INLINE_FRAME_CONTEXT_IGNORE, 0, &Displacement, &Line), "A line was found with SizeOfStruct 4\n");
    ok(GetLastError() == ERROR_INVALID_ADDRESS, "SymGetLineFromInlineContext (small structure) error %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    ok(!ScopeContext(Process, Address, INLINE_FRAME_CONTEXT_IGNORE), "SymSetScopeFromInlineContext succeeded\n");
    ok(GetLastError() == ERROR_NOT_SUPPORTED, "SymSetScopeFromInlineContext error %lu\n", GetLastError());

    /* StackWalkEx: accepts the flags and the structure size as given, and returns the first frame like StackWalk64. */
    {
        PFN_WALKEX WalkEx = (PFN_WALKEX)GetProcAddress(Dbghelp, "StackWalkEx");
        struct
        {
            ADDRESS64 AddrPC, AddrReturn, AddrFrame, AddrStack, AddrBStore;
            PVOID FuncTableEntry;
            DWORD64 Params[4];
            BOOL Far, Virtual;
            DWORD64 Reserved[3];
            KDHELP64 KdHelp;
            DWORD StackFrameSize, InlineFrameContext;
        } Frame;
        CONTEXT Ctx;
        DWORD Machine;

        if (WalkEx)
        {
            memset(&Ctx, 0, sizeof(Ctx));
            RtlCaptureContext(&Ctx);
            memset(&Frame, 0, sizeof(Frame));
#ifdef _WIN64
            Machine = IMAGE_FILE_MACHINE_AMD64;
            Frame.AddrPC.Offset = Ctx.Rip;
            Frame.AddrFrame.Offset = Ctx.Rbp;
            Frame.AddrStack.Offset = Ctx.Rsp;
#else
            Machine = IMAGE_FILE_MACHINE_I386;
            Frame.AddrPC.Offset = Ctx.Eip;
            Frame.AddrFrame.Offset = Ctx.Ebp;
            Frame.AddrStack.Offset = Ctx.Esp;
#endif
            Frame.AddrPC.Mode = Frame.AddrFrame.Mode = Frame.AddrStack.Mode = AddrModeFlat;
            Frame.StackFrameSize = sizeof(Frame);
            Frame.InlineFrameContext = INLINE_FRAME_CONTEXT_IGNORE;
            ok(WalkEx(Machine, Process, GetCurrentThread(), &Frame, &Ctx, NULL, NULL, NULL, NULL, 0),
               "StackWalkEx failed %lu\n", GetLastError());
            ok(Frame.AddrPC.Offset != 0, "StackWalkEx returned no program counter\n");
        }
    }
    SymCleanup(Process);
}
