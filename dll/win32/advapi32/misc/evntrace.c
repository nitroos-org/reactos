/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     advapi32.dll Event tracing stubs
 * COPYRIGHT:   Copyright 2017 Mark Jansen (mark.jansen@reactos.org)
 *              Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <advapi32.h>
#include <wmistr.h>
#include <evntrace.h>

WINE_DEFAULT_DEBUG_CHANNEL(advapi);


TRACEHANDLE
WINAPI
OpenTraceA(IN PEVENT_TRACE_LOGFILEA Logfile)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_PROCESSTRACE_HANDLE;
}

TRACEHANDLE
WINAPI
OpenTraceW(IN PEVENT_TRACE_LOGFILEW Logfile)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_PROCESSTRACE_HANDLE;
}

/* OpenTrace never returns a valid handle, so there is nothing to close */
ULONG
WINAPI
CloseTrace(IN TRACEHANDLE TraceHandle)
{
    return ERROR_INVALID_HANDLE;
}

ULONG
WINAPI
ProcessTrace(IN PTRACEHANDLE HandleArray,
             IN ULONG HandleCount,
             IN LPFILETIME StartTime,
             IN LPFILETIME EndTime)
{
    UNIMPLEMENTED;
    return ERROR_NOACCESS;
}


/*
 * ReactOS has no event tracing sessions. Windows 7 and Windows 10 (measured) refuse a null handle or provider
 * and a control code past capture-state with ERROR_INVALID_PARAMETER and report a session that does not exist
 * with ERROR_WMI_INSTANCE_NOT_FOUND; here no session exists, so every other request ends that way.
 */
ULONG
WINAPI
EnableTraceEx2(
    IN TRACEHANDLE TraceHandle,
    IN LPCGUID ProviderId,
    IN ULONG ControlCode,
    IN UCHAR Level,
    IN ULONGLONG MatchAnyKeyword,
    IN ULONGLONG MatchAllKeyword,
    IN ULONG Timeout,
    IN PENABLE_TRACE_PARAMETERS EnableParameters OPTIONAL)
{
    ULONG Status;

    TRACE("(%I64x, %p, %lu, %u)\n", TraceHandle, ProviderId, ControlCode, Level);

    if (!TraceHandle || !ProviderId || ControlCode > EVENT_CONTROL_CODE_CAPTURE_STATE)
        Status = ERROR_INVALID_PARAMETER;
    else
        Status = ERROR_WMI_INSTANCE_NOT_FOUND;

    /* Windows sets the last error as well (measured) */
    SetLastError(Status);
    return Status;
}

/*
 * No provider registry is kept by this implementation: nothing registered
 * with RegisterTraceGuids is tracked, so the list of providers is empty and
 * no provider GUID is known. The parameter rows follow the measurements of
 * Windows Server 2022: a class beyond TraceGuidQueryProcess, a missing
 * ReturnLength and (for TraceGuidQueryInfo) an input buffer shorter than a
 * GUID are invalid parameters; an unknown provider is ERROR_WMI_GUID_NOT_FOUND.
 */
ULONG
WINAPI
EnumerateTraceGuidsEx(
    IN TRACE_QUERY_INFO_CLASS TraceQueryInfoClass,
    IN PVOID InBuffer OPTIONAL,
    IN ULONG InBufferSize,
    OUT PVOID OutBuffer OPTIONAL,
    IN ULONG OutBufferSize,
    OUT PULONG ReturnLength)
{
    if (ReturnLength == NULL)
        return ERROR_INVALID_PARAMETER;

    switch ((ULONG)TraceQueryInfoClass)
    {
        case TraceGuidQueryList:
        case TraceGuidQueryProcess:
            *ReturnLength = 0;
            return ERROR_SUCCESS;

        case TraceGuidQueryInfo:
            if (InBuffer == NULL || InBufferSize < sizeof(GUID))
                return ERROR_INVALID_PARAMETER;
            *ReturnLength = 0;
            return ERROR_WMI_GUID_NOT_FOUND;

        default:
            return ERROR_INVALID_PARAMETER;
    }
}
