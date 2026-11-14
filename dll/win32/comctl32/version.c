/*
 * PROJECT:     ReactOS Common Controls
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DllGetVersion of the two images of comctl32 (v5 and v6)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * ReactOS ships the common controls twice: the v5 image (system32\comctl32.dll and the 5.82 side-by-side
 * assembly, 5.82) and the v6 image (the 6.0 side-by-side assembly that a manifest with
 * Microsoft.Windows.Common-Controls 6.0.0.0 activates), built from the same sources with
 * COMCTL32_V6_IMAGE defined for the second one. Each image reports its own version.
 */

#include "precomp.h"

#include <shlwapi.h>

WINE_DEFAULT_DEBUG_CHANNEL(commctrl);

/*
 * The v5 numbers are the ones DllGetVersion always returned (they are not those of a
 * real 5.82 DLL); the v6 numbers are the ones of Windows 10 for the v6 assembly: 6.16.10586.
 */
#ifdef COMCTL32_V6_IMAGE
#define DLLVER_MAJOR    6
#define DLLVER_MINOR    16
#define DLLVER_BUILD    10586
#define DLLVER_PLATFORM DLLVER_PLATFORM_NT
#else
#define DLLVER_MAJOR    COMCTL32_VERSION
#define DLLVER_MINOR    COMCTL32_VERSION_MINOR
#define DLLVER_BUILD    2919
#define DLLVER_PLATFORM 6304
#endif

/***********************************************************************
 * DllGetVersion [COMCTL32.@]
 *
 * Retrieves version information of this image of COMCTL32.DLL.
 *
 * PARAMS
 *     pdvi [O] pointer to version information structure.
 *
 * RETURNS
 *     Success: S_OK
 *     Failure: E_INVALIDARG
 */
HRESULT WINAPI DllGetVersion(DLLVERSIONINFO *pdvi)
{
    if (pdvi->cbSize != sizeof(DLLVERSIONINFO))
    {
        WARN("wrong DLLVERSIONINFO size from app\n");
        return E_INVALIDARG;
    }

    pdvi->dwMajorVersion = DLLVER_MAJOR;
    pdvi->dwMinorVersion = DLLVER_MINOR;
    pdvi->dwBuildNumber = DLLVER_BUILD;
    pdvi->dwPlatformID = DLLVER_PLATFORM;

    TRACE("%u.%u.%u.%u\n", pdvi->dwMajorVersion, pdvi->dwMinorVersion,
          pdvi->dwBuildNumber, pdvi->dwPlatformID);

    return S_OK;
}
