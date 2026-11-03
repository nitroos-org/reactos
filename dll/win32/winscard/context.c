/*
 * PROJECT:     ReactOS SmartCard API
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Resource manager contexts, with and without SCardSvr
 *
 * SCardSvr stopped (the Windows 10 default when no reader is attached; measured on 22H2): no context can
 * be established (SCARD_E_NO_SERVICE), every context argument is an invalid handle (ERROR_INVALID_HANDLE),
 * SCardAccessStartedEvent returns NULL, the reader lists are empty and successful.
 *
 * SCardSvr running (its ServiceMain, CalaisMain, signals the started event): contexts are kept in this
 * process, there are no readers. The answers of this mode are the documented ones and are NOT measured on
 * Windows (starting the service on the oracle is a state change). A reader stack (USB CCID) would replace
 * the in-process context table with the resource manager's RPC interface.
 */

#include "precomp.h"

#include <winreg.h>
#include <wchar.h>

WINE_DEFAULT_DEBUG_CHANNEL(winscard);

#define MAX_CONTEXTS    128
#define PNP_READER_NAME L"\\\\?PnP?\\Notification"

static CRITICAL_SECTION g_cs;
static BOOL g_cs_init;
static HANDLE g_started_event;
static LONG g_started_refs;
static DWORD g_seq;

static struct
{
    SCARDCONTEXT handle;
    HANDLE cancel;
} g_ctx[MAX_CONTEXTS];

void scard_init(void)
{
    InitializeCriticalSection(&g_cs);
    g_cs_init = TRUE;
}

void scard_exit(BOOL process_terminating)
{
    DWORD i;

    if (!g_cs_init) return;
    if (!process_terminating)
    {
        for (i = 0; i < MAX_CONTEXTS; i++)
            if (g_ctx[i].handle) CloseHandle(g_ctx[i].cancel);
        if (g_started_event) CloseHandle(g_started_event);
    }
    DeleteCriticalSection(&g_cs);
}

/* The service signals this event while it runs (see base/services/scardsvr) */
static BOOL service_running(void)
{
    HANDLE ev = OpenEventW(SYNCHRONIZE, FALSE, SCARD_STARTED_EVENT_NAME);
    BOOL running;

    if (!ev) return FALSE;
    running = WaitForSingleObject(ev, 0) == WAIT_OBJECT_0;
    CloseHandle(ev);
    return running;
}

HANDLE WINAPI SCardAccessStartedEvent(void)
{
    HANDLE ret;

    TRACE("()\n");
    EnterCriticalSection(&g_cs);
    if (!g_started_event)
        g_started_event = OpenEventW(SYNCHRONIZE, FALSE, SCARD_STARTED_EVENT_NAME);
    ret = g_started_event;
    if (ret) g_started_refs++;
    LeaveCriticalSection(&g_cs);
    return ret; /* NULL while SCardSvr is not running, as on Windows */
}

void WINAPI SCardReleaseStartedEvent(void)
{
    TRACE("()\n");
    EnterCriticalSection(&g_cs);
    if (g_started_refs > 0 && --g_started_refs == 0 && g_started_event)
    {
        CloseHandle(g_started_event);
        g_started_event = NULL;
    }
    LeaveCriticalSection(&g_cs);
}

static HANDLE find_context(SCARDCONTEXT h)
{
    HANDLE cancel = NULL;
    DWORD idx = (DWORD)(h & 0xFF);

    if (!h) return NULL;
    EnterCriticalSection(&g_cs);
    if (idx < MAX_CONTEXTS && g_ctx[idx].handle == h) cancel = g_ctx[idx].cancel;
    LeaveCriticalSection(&g_cs);
    return cancel;
}

/* The error for a context argument that is not one of ours */
static LONG bad_context(void)
{
    return service_running() ? SCARD_E_INVALID_HANDLE : scard_no_context();
}

LONG WINAPI SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
    DWORD i;
    LONG ret = SCARD_E_NO_MEMORY;

    TRACE("(%lx, %p, %p, %p)\n", dwScope, pvReserved1, pvReserved2, phContext);
    if (!phContext) return SCARD_E_INVALID_PARAMETER;
    if (dwScope > SCARD_SCOPE_SYSTEM) return SCARD_E_INVALID_VALUE;
    if (!service_running()) return SCARD_E_NO_SERVICE;

    EnterCriticalSection(&g_cs);
    for (i = 0; i < MAX_CONTEXTS; i++)
    {
        if (g_ctx[i].handle) continue;
        g_ctx[i].cancel = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!g_ctx[i].cancel) break;
        g_ctx[i].handle = (SCARDCONTEXT)(0x5C000000 + (++g_seq & 0xFFFF) * 0x100 + i);
        *phContext = g_ctx[i].handle;
        ret = SCARD_S_SUCCESS;
        break;
    }
    LeaveCriticalSection(&g_cs);
    return ret;
}

LONG WINAPI SCardIsValidContext(SCARDCONTEXT hContext)
{
    TRACE("(%lx)\n", hContext);
    return find_context(hContext) ? SCARD_S_SUCCESS : bad_context();
}

LONG WINAPI SCardReleaseContext(SCARDCONTEXT hContext)
{
    DWORD idx = (DWORD)(hContext & 0xFF);
    HANDLE cancel = NULL;

    TRACE("(%lx)\n", hContext);
    if (!hContext) return bad_context();
    EnterCriticalSection(&g_cs);
    if (idx < MAX_CONTEXTS && g_ctx[idx].handle == hContext)
    {
        cancel = g_ctx[idx].cancel;
        g_ctx[idx].handle = 0;
        g_ctx[idx].cancel = NULL;
    }
    LeaveCriticalSection(&g_cs);
    if (!cancel) return bad_context();
    CloseHandle(cancel);
    return SCARD_S_SUCCESS;
}

LONG WINAPI SCardCancel(SCARDCONTEXT hContext)
{
    HANDLE cancel = find_context(hContext);

    TRACE("(%lx)\n", hContext);
    if (!cancel) return bad_context();
    SetEvent(cancel);
    return SCARD_S_SUCCESS;
}

/* The reader lists. With a context of the running service there is no reader; the groups are the default ones */
LONG WINAPI SCardListReadersW(SCARDCONTEXT hContext, LPCWSTR mszGroups, LPWSTR mszReaders, LPDWORD pcchReaders)
{
    TRACE("(%lx, %s, %p, %p)\n", hContext, debugstr_w(mszGroups), mszReaders, pcchReaders);
    if (find_context(hContext))
        return pcchReaders ? SCARD_E_NO_READERS_AVAILABLE : SCARD_E_INVALID_PARAMETER;
    return scard_empty_multistring(TRUE, mszReaders, pcchReaders);
}

LONG WINAPI SCardListReadersA(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders)
{
    TRACE("(%lx, %s, %p, %p)\n", hContext, debugstr_a(mszGroups), mszReaders, pcchReaders);
    if (find_context(hContext))
        return pcchReaders ? SCARD_E_NO_READERS_AVAILABLE : SCARD_E_INVALID_PARAMETER;
    return scard_empty_multistring(FALSE, mszReaders, pcchReaders);
}

static const WCHAR default_groups[] =
    L"SCard$AllReaders\0SCard$DefaultReaders\0SCard$LocalReaders\0SCard$SystemReaders\0";

LONG WINAPI SCardListReaderGroupsW(SCARDCONTEXT hContext, LPWSTR mszGroups, LPDWORD pcchGroups)
{
    TRACE("(%lx, %p, %p)\n", hContext, mszGroups, pcchGroups);
    if (find_context(hContext))
        return scard_return_multistring(TRUE, default_groups, ARRAY_SIZE(default_groups), mszGroups, pcchGroups);
    return scard_empty_multistring(TRUE, mszGroups, pcchGroups);
}

LONG WINAPI SCardListReaderGroupsA(SCARDCONTEXT hContext, LPSTR mszGroups, LPDWORD pcchGroups)
{
    TRACE("(%lx, %p, %p)\n", hContext, mszGroups, pcchGroups);
    if (find_context(hContext))
        return scard_return_multistring(FALSE, default_groups, ARRAY_SIZE(default_groups), mszGroups, pcchGroups);
    return scard_empty_multistring(FALSE, mszGroups, pcchGroups);
}

/* Waits like the resource manager with nothing to report: until the timeout or SCardCancel */
static LONG wait_no_change(HANDLE cancel, DWORD timeout)
{
    DWORD w = WaitForSingleObject(cancel, timeout);

    return w == WAIT_OBJECT_0 ? SCARD_E_CANCELLED : SCARD_E_TIMEOUT;
}

LONG WINAPI SCardGetStatusChangeW(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATEW rgReaderStates, DWORD cReaders)
{
    HANDLE cancel = find_context(hContext);
    DWORD i;
    BOOL unknown = FALSE, pnp_wait = FALSE;

    TRACE("(%lx, %lu, %p, %lu)\n", hContext, dwTimeout, rgReaderStates, cReaders);
    if (!cancel) return bad_context();
    if (cReaders && !rgReaderStates) return SCARD_E_INVALID_PARAMETER;
    for (i = 0; i < cReaders; i++)
    {
        if (!rgReaderStates[i].szReader) return SCARD_E_INVALID_VALUE;
        if (!wcscmp(rgReaderStates[i].szReader, PNP_READER_NAME))
        {
            /* the first call reports at once, later ones wait for a reader to arrive */
            if (rgReaderStates[i].dwCurrentState == SCARD_STATE_UNAWARE)
                rgReaderStates[i].dwEventState = SCARD_STATE_CHANGED;
            else
            {
                rgReaderStates[i].dwEventState = rgReaderStates[i].dwCurrentState & ~SCARD_STATE_CHANGED;
                pnp_wait = TRUE;
            }
        }
        else
        {
            rgReaderStates[i].dwEventState = SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED | SCARD_STATE_IGNORE;
            unknown = TRUE;
        }
    }
    if (unknown) return SCARD_E_UNKNOWN_READER;
    if (cReaders && !pnp_wait) return SCARD_S_SUCCESS;
    return wait_no_change(cancel, dwTimeout);
}

LONG WINAPI SCardGetStatusChangeA(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATEA rgReaderStates, DWORD cReaders)
{
    HANDLE cancel = find_context(hContext);
    DWORD i;
    BOOL unknown = FALSE, pnp_wait = FALSE;

    TRACE("(%lx, %lu, %p, %lu)\n", hContext, dwTimeout, rgReaderStates, cReaders);
    if (!cancel) return bad_context();
    if (cReaders && !rgReaderStates) return SCARD_E_INVALID_PARAMETER;
    for (i = 0; i < cReaders; i++)
    {
        if (!rgReaderStates[i].szReader) return SCARD_E_INVALID_VALUE;
        if (!strcmp(rgReaderStates[i].szReader, "\\\\?PnP?\\Notification"))
        {
            if (rgReaderStates[i].dwCurrentState == SCARD_STATE_UNAWARE)
                rgReaderStates[i].dwEventState = SCARD_STATE_CHANGED;
            else
            {
                rgReaderStates[i].dwEventState = rgReaderStates[i].dwCurrentState & ~SCARD_STATE_CHANGED;
                pnp_wait = TRUE;
            }
        }
        else
        {
            rgReaderStates[i].dwEventState = SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED | SCARD_STATE_IGNORE;
            unknown = TRUE;
        }
    }
    if (unknown) return SCARD_E_UNKNOWN_READER;
    if (cReaders && !pnp_wait) return SCARD_S_SUCCESS;
    return wait_no_change(cancel, dwTimeout);
}

LONG WINAPI SCardConnectW(SCARDCONTEXT hContext, LPCWSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                          LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
    TRACE("(%lx, %s, %lx, %lx, %p, %p)\n", hContext, debugstr_w(szReader), dwShareMode, dwPreferredProtocols,
          phCard, pdwActiveProtocol);
    if (!find_context(hContext)) return bad_context();
    if (!szReader || !phCard || !pdwActiveProtocol) return SCARD_E_INVALID_PARAMETER;
    return SCARD_E_UNKNOWN_READER;
}

LONG WINAPI SCardConnectA(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                          LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol)
{
    TRACE("(%lx, %s, %lx, %lx, %p, %p)\n", hContext, debugstr_a(szReader), dwShareMode, dwPreferredProtocols,
          phCard, pdwActiveProtocol);
    if (!find_context(hContext)) return bad_context();
    if (!szReader || !phCard || !pdwActiveProtocol) return SCARD_E_INVALID_PARAMETER;
    return SCARD_E_UNKNOWN_READER;
}
