/*
 * PROJECT:     ReactOS system setup
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registration of the 32-bit COM servers of SysWOW64, shared by Setup's second stage and by
 *              "featmgr /enable wow64" (the 32-bit side added after the installation)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#pragma once

/* One entry per DLL is read from the sections [Wow64RegisterCore] and [Wow64RegisterExtra] of syssetup.inf; the 32-bit
 * regsvr32 of SysWOW64 runs over each of them (so the keys land in the 32-bit registry view). Core: a DLL that still fails
 * after the second pass makes the function return its error; extra: logged only. */

typedef struct _WOW64REG_CALLBACKS
{
    /* a line of text for the log (may be NULL) */
    VOID (*Log)(PVOID Context, PCWSTR Message);
    /* Done of Total DLLs of the first pass are finished; Dll is the one that is about to be registered (may be NULL) */
    VOID (*Progress)(PVOID Context, PCWSTR Dll, ULONG Done, ULONG Total);
    PVOID Context;
} WOW64REG_CALLBACKS, *PWOW64REG_CALLBACKS;

/* Inf: syssetup.inf (open). Returns ERROR_SUCCESS, or the first error of a core DLL. */
DWORD
Wow64RegisterDlls(
    _In_ HINF Inf,
    _In_opt_ const WOW64REG_CALLBACKS *Callbacks);
