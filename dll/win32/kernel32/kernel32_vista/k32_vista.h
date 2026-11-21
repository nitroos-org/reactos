
#pragma once

/* PSDK/NDK Headers */
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>

/* Redefine NTDDI_VERSION to 2K3 SP1 to get correct NDK definitions */
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WS03SP1

#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/kefuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>

/* CSRSS Headers */
#include <win/base.h>

/* Internal Kernel32 Header */
#include "../include/kernel32.h"

LCID
BasepSpecialNeutralLcidToSpecific(
    _In_ LCID Lcid);

/* The locale Windows picks for a neutral LCID (0 if it is not neutral) */
LCID
BasepNeutralLcidToSpecific(
    _In_ LCID Lcid);

/* The locale name a script-tagged alias stands for ("zh-Hant-TW" is "zh-TW"), or NULL */
PCWSTR
BasepLocaleNameAlias(
    _In_ PCWSTR Name);

#define MAX_PROCESS_UI_LANGUAGES 5

ULONG
BasepGetProcessUILanguageIds(
    _Out_writes_(MAX_PROCESS_UI_LANGUAGES) LANGID *Ids);

/* Whether CompareStringEx and FindNLSStringEx take a locale name: NULL, "", the system default, a name with a locale
   and every well-formed tag (Windows takes those, too) */
BOOL
BasepIsLocaleNameAccepted(
    _In_opt_ LPCWSTR name);
