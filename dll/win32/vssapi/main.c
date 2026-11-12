/*
 * Copyright 2014 Hans Leidekker for CodeWeavers
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

#ifndef __REACTOS__
#include "config.h"
#endif
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "vss.h"
#include "vswriter.h"
#include "vsbackup.h"
#include "wine/asm.h"
#include "wine/debug.h"

#ifdef __REACTOS__
#ifdef _MSC_VER
#define __thiscall __stdcall
#endif
#endif

WINE_DEFAULT_DEBUG_CHANNEL( vssapi );

struct CVssWriter
{
    void **vtable;
};

/******************************************************************
 *  ??0CVssWriter@@QAE@XZ (VSSAPI.@)
 */
struct CVssWriter * __thiscall VSSAPI_CVssWriter_default_ctor( struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
    writer->vtable = NULL;
    return writer;
}
DEFINE_THISCALL_WRAPPER( VSSAPI_CVssWriter_default_ctor, 4 )

/******************************************************************
 *  ??1CVssWriter@@UAE@XZ (VSSAPI.@)
 */
void __thiscall VSSAPI_CVssWriter_dtor( struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
}
DEFINE_THISCALL_WRAPPER( VSSAPI_CVssWriter_dtor, 4 )

/******************************************************************
 *  ?Initialize@CVssWriter@@QAGJU_GUID@@PBGW4VSS_USAGE_TYPE@@W4VSS_SOURCE_TYPE@@W4_VSS_APPLICATION_LEVEL@@KW4VSS_ALTERNATE_WRITER_STATE@@_N@Z
 */
HRESULT __thiscall VSSAPI_CVssWriter_Initialize( struct CVssWriter *writer, VSS_ID id,
    LPCWSTR name, VSS_USAGE_TYPE usage_type, VSS_SOURCE_TYPE source_type,
    VSS_APPLICATION_LEVEL level, DWORD timeout, VSS_ALTERNATE_WRITER_STATE alt_writer_state,
    BOOL throttle, LPCWSTR instance )
{
    FIXME( "%p, %s, %s, %u, %u, %u, %u, %u, %d, %s\n", writer, debugstr_guid(&id),
           debugstr_w(name), usage_type, source_type, level, timeout, alt_writer_state,
           throttle, debugstr_w(instance) );
    return S_OK;
}
DEFINE_THISCALL_WRAPPER( VSSAPI_CVssWriter_Initialize, 52 )

/******************************************************************
 *  ?Subscribe@CVssWriter@@QAGJK@Z
 */
HRESULT __thiscall VSSAPI_CVssWriter_Subscribe( struct CVssWriter *writer, DWORD flags )
{
    FIXME( "%p, %x\n", writer, flags );
    return S_OK;
}
DEFINE_THISCALL_WRAPPER( VSSAPI_CVssWriter_Subscribe, 8 )

/******************************************************************
 *  ?Unsubscribe@CVssWriter@@QAGJXZ
 */
HRESULT __thiscall VSSAPI_CVssWriter_Unsubscribe( struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
    return S_OK;
}
DEFINE_THISCALL_WRAPPER( VSSAPI_CVssWriter_Unsubscribe, 4 )

#ifdef _WIN64
/* The members of CVssWriter that the writers of 64-bit programs import. Like the 32-bit ones above they
 * do nothing: there is no Volume Shadow Copy service to subscribe to, so the writer is never called. The
 * virtual members are the base class defaults of the real class, which return TRUE. */

/******************************************************************
 *  ?SetWriterFailure@CVssWriter@@IEAAJJ@Z
 */
HRESULT VSSAPI_CVssWriter_SetWriterFailure( struct CVssWriter *writer, HRESULT failure )
{
    FIXME( "%p, %#x\n", writer, failure );
    return S_OK;
}

/******************************************************************
 *  ?IsPathAffected@CVssWriter@@IEBA_NPEBG@Z
 */
BOOL VSSAPI_CVssWriter_IsPathAffected( const struct CVssWriter *writer, LPCWSTR path )
{
    FIXME( "%p, %s\n", writer, debugstr_w(path) );
    return FALSE;
}

/******************************************************************
 *  ?GetCurrentSnapshotSetId@CVssWriter@@IEBA?AU_GUID@@XZ
 */
VSS_ID *VSSAPI_CVssWriter_GetCurrentSnapshotSetId( const struct CVssWriter *writer, VSS_ID *id )
{
    FIXME( "%p\n", writer );
    memset( id, 0, sizeof(*id) );
    return id;
}

/******************************************************************
 *  ?GetBackupType@CVssWriter@@IEBA?AW4_VSS_BACKUP_TYPE@@XZ
 */
VSS_BACKUP_TYPE VSSAPI_CVssWriter_GetBackupType( const struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
    return VSS_BT_UNDEFINED;
}

/******************************************************************
 *  ?AreComponentsSelected@CVssWriter@@IEBA_NXZ
 */
BOOL VSSAPI_CVssWriter_AreComponentsSelected( const struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
    return FALSE;
}

/******************************************************************
 *  ?OnVSSShutdown@CVssWriter@@UEAA_NXZ
 */
BOOL VSSAPI_CVssWriter_OnVSSShutdown( struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
    return TRUE;
}

/******************************************************************
 *  ?OnVSSApplicationStartup@CVssWriter@@UEAA_NXZ
 */
BOOL VSSAPI_CVssWriter_OnVSSApplicationStartup( struct CVssWriter *writer )
{
    FIXME( "%p\n", writer );
    return TRUE;
}

/******************************************************************
 *  ?OnBackOffIOOnVolume@CVssWriter@@UEAA_NPEAGU_GUID@@1@Z
 */
BOOL VSSAPI_CVssWriter_OnBackOffIOOnVolume( struct CVssWriter *writer, WCHAR *volume, const VSS_ID *snapshot_id, const VSS_ID *provider_id )
{
    FIXME( "%p, %p, %p, %p\n", writer, volume, snapshot_id, provider_id );
    return TRUE;
}

/******************************************************************
 *  ?OnContinueIOOnVolume@CVssWriter@@UEAA_NPEAGU_GUID@@1@Z
 */
BOOL VSSAPI_CVssWriter_OnContinueIOOnVolume( struct CVssWriter *writer, WCHAR *volume, const VSS_ID *snapshot_id, const VSS_ID *provider_id )
{
    FIXME( "%p, %p, %p, %p\n", writer, volume, snapshot_id, provider_id );
    return TRUE;
}
#endif

HRESULT WINAPI CreateVssBackupComponentsInternal(IVssBackupComponents **backup)
{
    FIXME("%p\n", backup);
    return E_NOTIMPL;
}

/******************************************************************
 *  ?CreateVssBackupComponents@@YGJPAPAVIVssBackupComponents@@@Z
 */
HRESULT WINAPI VSSAPI_CreateVssBackupComponents( IVssBackupComponents **backup )
{
    FIXME( "%p\n", backup );

    return CreateVssBackupComponentsInternal(backup);
}
