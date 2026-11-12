/*
 * PROJECT:     ReactOS Color Management (mscms.dll)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows Color System default-profile queries (Wcs*)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Written from the public documentation of the icm.h API and from answers measured on Windows 10 22H2
 * (build 19045, a machine without a display association list): see
 * modules/rostests/apitests/mscms/WcsDefault.c for the measured values. WINESYNC: Wine's mscms (up to
 * master) only has FIXME stubs that return FALSE for these functions, so there is nothing to sync.
 *
 * The state of the association store is "nothing associated", which is what a stock Windows install
 * answers: an application that asks for the default profile of a device is told that there is none
 * (ERROR_FILE_NOT_FOUND) and falls back to sRGB itself. Nothing here raises an exception.
 */

#include "config.h"
#include "wine/debug.h"

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "wingdi.h"
#include "winuser.h"
#include "icm.h"

#include "mscms_priv.h"

WINE_DEFAULT_DEBUG_CHANNEL(mscms);

static BOOL valid_scope( WCS_PROFILE_MANAGEMENT_SCOPE scope )
{
    return scope == WCS_PROFILE_MANAGEMENT_SCOPE_SYSTEM_WIDE || scope == WCS_PROFILE_MANAGEMENT_SCOPE_CURRENT_USER;
}

/* Windows ships a default colour appearance model next to the profiles; the name is only answered when the file is there. */
static const WCHAR default_camp[] = {'D','6','5','.','c','a','m','p',0};

/* Returns 0 and the profile name, or the error to report. */
static DWORD default_profile( WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR device, COLORPROFILETYPE type,
                              COLORPROFILESUBTYPE subtype, const WCHAR **name )
{
    WCHAR path[MAX_PATH];
    DWORD len = sizeof(path);

    *name = NULL;
    if (!valid_scope( scope ) || (DWORD)type > CPT_GMMP || (DWORD)subtype > CPST_EXTENDED_DISPLAY_COLOR_MODE)
        return ERROR_INVALID_PARAMETER;

    /* no display or printer has an association: nothing is registered for any device */
    if (device) return ERROR_FILE_NOT_FOUND;

    /* system defaults: working spaces were never associated, the others are not valid without a device */
    if (subtype >= CPST_RGB_WORKING_SPACE) return ERROR_FILE_NOT_FOUND;
    if (type == CPT_CAMP && subtype == CPST_NONE)
    {
        if (!GetColorDirectoryW( NULL, path, &len ) || len + (lstrlenW( default_camp ) + 2) * sizeof(WCHAR) > sizeof(path))
            return ERROR_FILE_NOT_FOUND;
        lstrcatW( path, L"\\" );
        lstrcatW( path, default_camp );
        if (GetFileAttributesW( path ) == INVALID_FILE_ATTRIBUTES) return ERROR_FILE_NOT_FOUND;
        *name = default_camp;
        return 0;
    }
    return ERROR_INVALID_PARAMETER;
}

/******************************************************************************
 * WcsGetDefaultColorProfileSize     [MSCMS.@]
 *
 * Size in bytes, terminating null included, of the name of the default profile.
 */
BOOL WINAPI WcsGetDefaultColorProfileSize( WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR device, COLORPROFILETYPE type,
                                           COLORPROFILESUBTYPE subtype, DWORD profile_id, PDWORD size )
{
    const WCHAR *name;
    DWORD err;

    TRACE( "%d, %s, %d, %d, %lu, %p\n", scope, debugstr_w(device), type, subtype, profile_id, size );

    if (!size)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    if ((err = default_profile( scope, device, type, subtype, &name )))
    {
        SetLastError( err );
        return FALSE;
    }
    *size = (lstrlenW( name ) + 1) * sizeof(WCHAR);
    return TRUE;
}

/******************************************************************************
 * WcsGetDefaultColorProfile         [MSCMS.@]
 *
 * Name of the default profile; size is the size of the buffer in bytes.
 */
BOOL WINAPI WcsGetDefaultColorProfile( WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR device, COLORPROFILETYPE type,
                                       COLORPROFILESUBTYPE subtype, DWORD profile_id, DWORD size, LPWSTR buffer )
{
    const WCHAR *name;
    DWORD err;

    TRACE( "%d, %s, %d, %d, %lu, %lu, %p\n", scope, debugstr_w(device), type, subtype, profile_id, size, buffer );

    if (!buffer)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    if ((err = default_profile( scope, device, type, subtype, &name )))
    {
        SetLastError( err );
        return FALSE;
    }
    if (size < (lstrlenW( name ) + 1) * sizeof(WCHAR))
    {
        SetLastError( ERROR_INSUFFICIENT_BUFFER );
        return FALSE;
    }
    lstrcpyW( buffer, name );
    return TRUE;
}

/******************************************************************************
 * WcsGetDefaultRenderingIntent      [MSCMS.@]
 */
BOOL WINAPI WcsGetDefaultRenderingIntent( WCS_PROFILE_MANAGEMENT_SCOPE scope, PDWORD intent )
{
    TRACE( "%d %p\n", scope, intent );

    if (!intent || !valid_scope( scope ))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    *intent = INTENT_PERCEPTUAL;
    return TRUE;
}

/******************************************************************************
 * WcsGetUsePerUserProfiles          [MSCMS.@]
 */
BOOL WINAPI WcsGetUsePerUserProfiles( const WCHAR *device, DWORD class, BOOL *use_per_user )
{
    TRACE( "%s %s %p\n", debugstr_w(device), dbgstr_tag(class), use_per_user );

    if (!device || !use_per_user)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    *use_per_user = FALSE;
    return TRUE;
}

/******************************************************************************
 * WcsGetCalibrationManagementState  [MSCMS.@]
 */
BOOL WINAPI WcsGetCalibrationManagementState( BOOL *enabled )
{
    TRACE( "%p\n", enabled );

    if (!enabled)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    *enabled = FALSE;
    return TRUE;
}

/******************************************************************************
 * WcsEnumColorProfilesSize          [MSCMS.@]
 *
 * Size in bytes of the list of profile names that match the record.
 */
BOOL WINAPI WcsEnumColorProfilesSize( WCS_PROFILE_MANAGEMENT_SCOPE scope, ENUMTYPEW *record, DWORD *size )
{
    DWORD needed = 0;

    TRACE( "%d %p %p\n", scope, record, size );

    if (!record || !size || !valid_scope( scope ))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    SetLastError( 0 );
    if (!EnumColorProfilesW( NULL, record, NULL, &needed, NULL ))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;
    }
    *size = needed;
    return TRUE;
}

/******************************************************************************
 * WcsEnumColorProfiles              [MSCMS.@]
 */
BOOL WINAPI WcsEnumColorProfiles( WCS_PROFILE_MANAGEMENT_SCOPE scope, ENUMTYPEW *record, BYTE *buffer, DWORD size,
                                  DWORD *count )
{
    TRACE( "%d %p %p %lu %p\n", scope, record, buffer, size, count );

    if (!record || !buffer || !valid_scope( scope ))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    return EnumColorProfilesW( NULL, record, buffer, &size, count );
}

/* Write side of the Wcs API (association lists, defaults, calibration): the association store is not there, so
 * these report that instead of raising the unimplemented-function exception into the caller. */
#define WCS_NOT_IMPLEMENTED( name, args ) \
    BOOL WINAPI name args { FIXME( #name ": not implemented\n" ); SetLastError( ERROR_CALL_NOT_IMPLEMENTED ); return FALSE; }

WCS_NOT_IMPLEMENTED( WcsAssociateColorProfileWithDevice, (WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR profile, PCWSTR device) )
WCS_NOT_IMPLEMENTED( WcsDisassociateColorProfileFromDevice, (WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR profile, PCWSTR device) )
WCS_NOT_IMPLEMENTED( WcsSetDefaultColorProfile, (WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR device, COLORPROFILETYPE type,
                                                  COLORPROFILESUBTYPE subtype, DWORD id, PCWSTR profile) )
WCS_NOT_IMPLEMENTED( WcsSetDefaultRenderingIntent, (WCS_PROFILE_MANAGEMENT_SCOPE scope, DWORD intent) )
WCS_NOT_IMPLEMENTED( WcsSetUsePerUserProfiles, (PCWSTR device, DWORD class, BOOL use_per_user) )
WCS_NOT_IMPLEMENTED( WcsSetCalibrationManagementState, (BOOL enabled) )
WCS_NOT_IMPLEMENTED( WcsGpCanInstallOrUninstallProfiles, (BOOL *can) )

HPROFILE WINAPI WcsCreateIccProfile( HPROFILE profile, DWORD options )
{
    FIXME( "%p, %#x: not implemented\n", profile, options );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return NULL;
}
