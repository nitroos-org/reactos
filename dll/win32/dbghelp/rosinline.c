/*
 * PROJECT:     ReactOS dbghelp
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The inline frame API (SymQueryInlineTrace and family, StackWalkEx)
 *
 * The exports and the way the *InlineContext functions fall back to the plain address functions
 * follow Wine's dlls/dbghelp (symbol.c, dbghelp.c, stack.c; (C) Eric Pouech, Jacek Caban and others,
 * LGPL).  Wine's versions look inline sites up in symbol tables that carry them (symt_find_inlined_site,
 * symt_find_lowest_inlined, ...); this module's tables have no inline sites, so the lookup is
 * always "none" and the functions reduce to what Wine does when it finds no site.  What they return
 * in that case was measured with the same calls on Windows Server 2022 (dbghelp 10.0.20348) for a
 * function that has only an export symbol:
 *   SymAddrIncludeInlineTrace   0, no error
 *   SymQueryInlineTrace         FALSE, no error, *CurContext = INLINE_FRAME_CONTEXT_IGNORE, *CurFrameIndex = 0
 *   SymFromInlineContext(W)     as SymFromAddr(W) for every context value, valid or not
 *   SymGetLineFromInlineContext(W)  as SymGetLineFromAddr64 / W64; FALSE with ERROR_INVALID_ADDRESS
 *                               when there is no line (also for a SizeOfStruct that is too small)
 *   SymSetScopeFromInlineContext FALSE, ERROR_NOT_SUPPORTED
 *   SymCompareInlineTrace       SYM_INLINE_COMP_ERROR (0), no error
 *   StackWalkEx                 the StackWalk64 result; flags and StackFrameSize are not checked
 * Not done: inline sites read from PDB/DWARF, the SYM_STKWALK_* flags, and the encoding of
 * InlineFrameContext (opaque to callers; here INLINE_FRAME_CONTEXT_INIT, or IGNORE when it came in as IGNORE).
 */

#include "dbghelp_private.h"

#include <wine/debug.h>
WINE_DEFAULT_DEBUG_CHANNEL(dbghelp);

/******************************************************************
 *		SymAddrIncludeInlineTrace (DBGHELP.@)
 *
 * The number of nested inline sites at addr: none are known.
 */
DWORD WINAPI SymAddrIncludeInlineTrace(HANDLE hProcess, DWORD64 addr)
{
    TRACE("(%p, %s)\n", hProcess, wine_dbgstr_longlong(addr));
    return 0;
}

/******************************************************************
 *		SymCompareInlineTrace (DBGHELP.@)
 */
DWORD WINAPI SymCompareInlineTrace(HANDLE hProcess, DWORD64 addr1, DWORD ctx1, DWORD64 retaddr1, DWORD64 addr2, DWORD64 ctx2)
{
    FIXME("(%p, %s, 0x%x, %s, %s, %s): no inline sites\n", hProcess, wine_dbgstr_longlong(addr1), ctx1,
          wine_dbgstr_longlong(retaddr1), wine_dbgstr_longlong(addr2), wine_dbgstr_longlong(ctx2));
    return 0; /* SYM_INLINE_COMP_ERROR */
}

/******************************************************************
 *		SymQueryInlineTrace (DBGHELP.@)
 */
BOOL WINAPI SymQueryInlineTrace(HANDLE hProcess, DWORD64 StartAddress, DWORD StartContext,
                                DWORD64 StartRetAddress, DWORD64 CurAddress,
                                LPDWORD CurContext, LPDWORD CurFrameIndex)
{
    TRACE("(%p, %s, 0x%x, %s, %s, %p, %p)\n", hProcess, wine_dbgstr_longlong(StartAddress), StartContext,
          wine_dbgstr_longlong(StartRetAddress), wine_dbgstr_longlong(CurAddress), CurContext, CurFrameIndex);

    if (CurContext) *CurContext = INLINE_FRAME_CONTEXT_IGNORE;
    if (CurFrameIndex) *CurFrameIndex = 0;
    return FALSE;
}

/******************************************************************
 *		SymFromInlineContext (DBGHELP.@)
 */
BOOL WINAPI SymFromInlineContext(HANDLE hProcess, DWORD64 addr, ULONG inline_ctx, PDWORD64 disp, PSYMBOL_INFO si)
{
    TRACE("(%p, %s, 0x%x, %p, %p)\n", hProcess, wine_dbgstr_longlong(addr), inline_ctx, disp, si);
    return SymFromAddr(hProcess, addr, disp, si);
}

/******************************************************************
 *		SymFromInlineContextW (DBGHELP.@)
 */
BOOL WINAPI SymFromInlineContextW(HANDLE hProcess, DWORD64 addr, ULONG inline_ctx, PDWORD64 disp, PSYMBOL_INFOW si)
{
    TRACE("(%p, %s, 0x%x, %p, %p)\n", hProcess, wine_dbgstr_longlong(addr), inline_ctx, disp, si);
    return SymFromAddrW(hProcess, addr, disp, si);
}

/******************************************************************
 *		SymGetLineFromInlineContext (DBGHELP.@)
 */
BOOL WINAPI SymGetLineFromInlineContext(HANDLE hProcess, DWORD64 addr, ULONG inline_ctx, DWORD64 mod_addr,
                                        PDWORD disp, PIMAGEHLP_LINE64 line)
{
    BOOL ret;

    TRACE("(%p, %s, 0x%x, %s, %p, %p)\n", hProcess, wine_dbgstr_longlong(addr), inline_ctx,
          wine_dbgstr_longlong(mod_addr), disp, line);

    SetLastError(0);
    ret = SymGetLineFromAddr64(hProcess, addr, disp, line);
    if (!ret && !GetLastError()) SetLastError(ERROR_INVALID_ADDRESS);
    return ret;
}

/******************************************************************
 *		SymGetLineFromInlineContextW (DBGHELP.@)
 */
BOOL WINAPI SymGetLineFromInlineContextW(HANDLE hProcess, DWORD64 addr, ULONG inline_ctx, DWORD64 mod_addr,
                                         PDWORD disp, PIMAGEHLP_LINEW64 line)
{
    BOOL ret;

    TRACE("(%p, %s, 0x%x, %s, %p, %p)\n", hProcess, wine_dbgstr_longlong(addr), inline_ctx,
          wine_dbgstr_longlong(mod_addr), disp, line);

    SetLastError(0);
    ret = SymGetLineFromAddrW64(hProcess, addr, disp, line);
    if (!ret && !GetLastError()) SetLastError(ERROR_INVALID_ADDRESS);
    return ret;
}

/******************************************************************
 *		SymSetScopeFromInlineContext (DBGHELP.@)
 */
BOOL WINAPI SymSetScopeFromInlineContext(HANDLE hProcess, ULONG64 addr, ULONG inline_ctx)
{
    TRACE("(%p, %s, 0x%x)\n", hProcess, wine_dbgstr_longlong(addr), inline_ctx);
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

/******************************************************************
 *		StackWalkEx (DBGHELP.@)
 *
 * StackFrameSize and flags are not checked (as on Windows); the SYM_STKWALK_* flags are not honoured.
 */
BOOL WINAPI StackWalkEx(DWORD MachineType, HANDLE hProcess, HANDLE hThread, LPSTACKFRAME_EX frame, PVOID ctx,
                        PREAD_PROCESS_MEMORY_ROUTINE64 f_read_mem,
                        PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
                        PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
                        PTRANSLATE_ADDRESS_ROUTINE64 f_xlat_adr, DWORD flags)
{
    TRACE("(%d, %p, %p, %p, %p, %p, %p, %p, %p, 0x%x)\n", MachineType, hProcess, hThread, frame, ctx,
          f_read_mem, FunctionTableAccessRoutine, GetModuleBaseRoutine, f_xlat_adr, flags);

    if (flags) FIXME("SYM_STKWALK flags 0x%x are not honoured\n", flags);

    /* STACKFRAME_EX starts with the members of STACKFRAME64 */
    if (!StackWalk64(MachineType, hProcess, hThread, (LPSTACKFRAME64)frame, ctx, f_read_mem,
                     FunctionTableAccessRoutine, GetModuleBaseRoutine, f_xlat_adr))
        return FALSE;

    if (frame->StackFrameSize >= sizeof(*frame) && frame->InlineFrameContext != INLINE_FRAME_CONTEXT_IGNORE)
        frame->InlineFrameContext = INLINE_FRAME_CONTEXT_INIT; /* no inline frames */
    return TRUE;
}
