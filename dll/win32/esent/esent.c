/*
 * PROJECT:     ReactOS esent.dll (stub module)
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     The few esent exports that return a real error instead of the generic stub result
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * There is no ESE engine here: no instance, no session and no database can exist. These are the
 * Unicode entry points that msedge.dll (WebView2 runtime) delay-loads. A caller that checks the
 * JET_err result sees a plain failure, and nothing traps in the delay-load failure hook.
 */

#include <stdarg.h>
#include <windef.h>
#include <winbase.h>

#define JET_errInvalidSesid         (-1104)
#define JET_errFeatureNotAvailable  (-1210)

/* JET_ERR JetDetachDatabase2W(JET_SESID sesid, JET_PCWSTR szDatabaseName, JET_GRBIT grbit) */
LONG WINAPI JetDetachDatabase2W(ULONG_PTR sesid, PCWSTR szDatabaseName, ULONG grbit)
{
    /* no session can have been created */
    return JET_errInvalidSesid;
}

/* JET_ERR JetGetSystemParameterW(JET_INSTANCE instance, JET_SESID sesid, ULONG paramid,
                                  JET_API_PTR *plParam, JET_PWSTR szParam, ULONG cbMax) */
LONG WINAPI JetGetSystemParameterW(ULONG_PTR instance, ULONG_PTR sesid, ULONG paramid,
                                   ULONG_PTR *plParam, PWSTR szParam, ULONG cbMax)
{
    return JET_errFeatureNotAvailable;
}
