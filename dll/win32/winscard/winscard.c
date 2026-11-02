/*
 * Copyright 2007 Mounir IDRASSI  (mounir.idrassi@idrix.fr, for IDRIX)
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

#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "wine/debug.h"
#include "winscard.h"
#include "winternl.h"

#ifndef SCARD_AUTOALLOCATE
#define SCARD_AUTOALLOCATE ((DWORD)-1)
#endif

WINE_DEFAULT_DEBUG_CHANNEL(winscard);

static HANDLE g_startedEvent = NULL;

const SCARD_IO_REQUEST g_rgSCardT0Pci = { SCARD_PROTOCOL_T0, 8 };
const SCARD_IO_REQUEST g_rgSCardT1Pci = { SCARD_PROTOCOL_T1, 8 };
const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, 8 };


BOOL WINAPI DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    TRACE("%p,%x,%p\n", hinstDLL, fdwReason, lpvReserved);

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            /* FIXME: for now, we act as if the pcsc daemon is always started */
            g_startedEvent = CreateEventA(NULL,TRUE,TRUE,NULL);
            break;
        case DLL_PROCESS_DETACH:
            if (lpvReserved) break;
            CloseHandle(g_startedEvent);
            break;
    }

    return TRUE;
}

/* There is no Smart Card service (SCardSvr) and no reader. Every call answers the
 * way winscard.dll does on Windows when the service is not running (measured on
 * Windows 10 22H2): no context can be established, the context and card handles
 * are invalid, and the reader lists are empty and successful. */
LONG scard_empty_multistring(BOOL wide, void *buf, DWORD *len)
{
    SIZE_T size = wide ? sizeof(WCHAR) : sizeof(CHAR);

    if (!len) return SCARD_E_INVALID_PARAMETER;
    if (!buf)
    {
        *len = 1;
        return SCARD_S_SUCCESS;
    }
    if (*len == SCARD_AUTOALLOCATE)
    {
        void *mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);

        if (!mem) return SCARD_E_NO_MEMORY;
        *(void **)buf = mem;
        *len = 1;
        return SCARD_S_SUCCESS;
    }
    if (*len < 1)
    {
        *len = 1;
        return SCARD_E_INSUFFICIENT_BUFFER;
    }
    memset(buf, 0, size);
    *len = 1;
    return SCARD_S_SUCCESS;
}

LONG scard_no_context(void)
{
    return ERROR_INVALID_HANDLE;
}

HANDLE WINAPI SCardAccessStartedEvent(void)
{
    return g_startedEvent;
}

LONG WINAPI SCardAddReaderToGroupA(SCARDCONTEXT context, LPCSTR reader, LPCSTR group)
{
    LONG retval;
    UNICODE_STRING readerW, groupW;

    if(reader) RtlCreateUnicodeStringFromAsciiz(&readerW,reader);
    else readerW.Buffer = NULL;
    if(group) RtlCreateUnicodeStringFromAsciiz(&groupW,group);
    else groupW.Buffer = NULL;

    retval = SCardAddReaderToGroupW(context, readerW.Buffer, groupW.Buffer);

    RtlFreeUnicodeString(&readerW);
    RtlFreeUnicodeString(&groupW);

    return retval;
}

LONG WINAPI SCardAddReaderToGroupW(SCARDCONTEXT context, LPCWSTR reader, LPCWSTR group)
{
    FIXME("%x %s %s\n", (unsigned int) context, debugstr_w(reader), debugstr_w(group));
    return SCARD_S_SUCCESS;
}

LONG WINAPI SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1,
    LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
    TRACE("(%x,%p,%p,%p)\n", dwScope, pvReserved1, pvReserved2, phContext);
    if (!phContext) return SCARD_E_INVALID_PARAMETER;
    if (dwScope > SCARD_SCOPE_SYSTEM) return SCARD_E_INVALID_VALUE;
    /* No SCardSvr: the Resource Manager is not available */
    return SCARD_E_NO_SERVICE;
}

LONG WINAPI SCardIsValidContext(SCARDCONTEXT context)
{
    TRACE("(%lx)\n", context);
    return scard_no_context();
}

LONG WINAPI SCardListCardsA(SCARDCONTEXT hContext, LPCBYTE pbAtr, LPCGUID rgguidInterfaces, DWORD cguidInterfaceCount, LPSTR mszCards, LPDWORD pcchCards)
{
    FIXME(": stub\n");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return SCARD_F_INTERNAL_ERROR;
}

LONG WINAPI SCardReleaseContext(SCARDCONTEXT context)
{
    TRACE("(%lx)\n", context);
    return scard_no_context();
}

LONG WINAPI SCardStatusA(SCARDHANDLE context, LPSTR szReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
    FIXME("(%lx) stub\n", context);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return SCARD_F_INTERNAL_ERROR;
}

LONG WINAPI SCardStatusW(SCARDHANDLE context, LPWSTR szReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState,LPDWORD pdwProtocol,LPBYTE pbAtr,LPDWORD pcbArtLen)
{
    FIXME("(%lx) stub\n", context);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return SCARD_F_INTERNAL_ERROR;
}

void WINAPI SCardReleaseStartedEvent(void)
{
    FIXME("stub\n");
}

LONG WINAPI SCardListReadersA(SCARDCONTEXT context, const CHAR *groups, CHAR *readers, DWORD *buflen)
{
    TRACE("(%lx, %s, %p, %p)\n", context, debugstr_a(groups), readers, buflen);
    return scard_empty_multistring(FALSE, readers, buflen);
}

LONG WINAPI SCardListReadersW(SCARDCONTEXT context, const WCHAR *groups, WCHAR *readers, DWORD *buflen)
{
    TRACE("(%lx, %s, %p, %p)\n", context, debugstr_w(groups), readers, buflen);
    return scard_empty_multistring(TRUE, readers, buflen);
}

LONG WINAPI SCardCancel(SCARDCONTEXT context)
{
    TRACE("(%lx)\n", context);
    return scard_no_context();
}
