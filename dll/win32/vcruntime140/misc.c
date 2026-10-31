/*
 * Copyright 2015 Martin Storsjo
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "windows.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(vcruntime);

int* CDECL __processing_throw(void);

/*********************************************************************
 *              __telemetry_main_invoke_trigger
 */
void CDECL __telemetry_main_invoke_trigger(HINSTANCE hinst)
{
    FIXME("(%p)\n", hinst);
}

/*********************************************************************
 *              __telemetry_main_return_trigger
 */
void CDECL __telemetry_main_return_trigger(HINSTANCE hinst)
{
    FIXME("(%p)\n", hinst);
}

/*********************************************************************
 *              __vcrtInitializeCriticalSectionEx
 */
BOOL CDECL __vcrt_InitializeCriticalSectionEx(
        CRITICAL_SECTION *cs, DWORD spin_count, DWORD flags)
{
    TRACE("(%p %lx %lx)\n", cs, spin_count, flags);
    return InitializeCriticalSectionEx(cs, spin_count, flags);
}

int __cdecl __uncaught_exceptions(void)
{
    return *__processing_throw();
}

/* The C++ exceptions of the Microsoft compiler, and the codes of the common language runtime */
#define EH_EXCEPTION_NUMBER     0xE06D7363
#define CLR_EXCEPTION_CODE      0xE0434352
#define CLR_EXCEPTION_CODE_V4   0xE0434F4D

void CDECL terminate(void);

/*********************************************************************
 *              __FrameUnwindFilter
 *
 * The filter of the handlers that run while a C++ exception unwinds a frame. A C++ exception that comes out
 * of a destructor during the unwind ends the process (the exception record and context are kept for the
 * debugger in the thread data of Windows), the managed exceptions only reduce the count of the exceptions that
 * are being thrown; nothing is ever handled: the search goes on.
 */
int CDECL __FrameUnwindFilter(EXCEPTION_POINTERS *ptrs)
{
    TRACE("(%p)\n", ptrs);

    switch (ptrs->ExceptionRecord->ExceptionCode)
    {
    case EH_EXCEPTION_NUMBER:
        terminate();
        break;
    case CLR_EXCEPTION_CODE:
    case CLR_EXCEPTION_CODE_V4:
    {
        int *processing = __processing_throw();

        if (*processing > 0)
            (*processing)--;
        break;
    }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#ifdef _WIN64
/*********************************************************************
 *              __C_specific_handler_noexcept
 *
 * The language handler of the frames of noexcept functions: __C_specific_handler, and a C++ exception that
 * goes on to the next frame instead of being handled there ends the process: it cannot leave the function.
 */
EXCEPTION_DISPOSITION CDECL __C_specific_handler_noexcept(EXCEPTION_RECORD *rec, ULONG64 frame,
        CONTEXT *context, DISPATCHER_CONTEXT *dispatch)
{
    EXCEPTION_DISPOSITION ret = __C_specific_handler(rec, (void *)(ULONG_PTR)frame, context, dispatch);

    TRACE("(%p %I64x %p %p) -> %d\n", rec, frame, context, dispatch, ret);

    if (!(rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND))
        && rec->ExceptionCode == EH_EXCEPTION_NUMBER && ret == ExceptionContinueSearch)
        terminate();
    return ret;
}
#endif

/*********************************************************************
 *              __vcrt_GetModuleFileNameW
 */
DWORD CDECL __vcrt_GetModuleFileNameW(HMODULE module, WCHAR *filename, DWORD size)
{
    TRACE("(%p %p %lu)\n", module, filename, size);
    return GetModuleFileNameW(module, filename, size);
}

/*********************************************************************
 *              __vcrt_GetModuleHandleW
 */
HMODULE CDECL __vcrt_GetModuleHandleW(const WCHAR *name)
{
    TRACE("(%s)\n", debugstr_w(name));
    return GetModuleHandleW(name);
}

/*********************************************************************
 *              __vcrt_LoadLibraryExW
 */
HMODULE CDECL __vcrt_LoadLibraryExW(const WCHAR *name, HANDLE file, DWORD flags)
{
    TRACE("(%s %p %#lx)\n", debugstr_w(name), file, flags);
    return LoadLibraryExW(name, file, flags);
}
