/*
 * Implementation of the Microsoft Installer (msi.dll)
 *
 * Copyright 2005 Aric Stewart for CodeWeavers
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

/*
 * Actions dealing with files:
 *
 * InstallFiles
 * DuplicateFiles
 * MoveFiles
 * PatchFiles
 * RemoveDuplicateFiles
 * RemoveFiles
 */

#include <stdarg.h>

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "fdi.h"
#include "msi.h"
#include "msidefs.h"
#include "msipriv.h"
#include "winuser.h"
#include "winreg.h"
#include "shlwapi.h"
#include "patchapi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(msi);

BOOL msi_get_temp_file_name( MSIPACKAGE *package, const WCHAR *tmp_path, const WCHAR *prefix, WCHAR *tmp_filename )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = GetTempFileNameW( tmp_path, prefix, 0, tmp_filename );
    msi_revert_fs_redirection( package );
    return ret;
}

HANDLE msi_create_file( MSIPACKAGE *package, const WCHAR *filename, DWORD access, DWORD sharing, DWORD creation,
                        DWORD flags )
{
    HANDLE handle;
    msi_disable_fs_redirection( package );
    handle = CreateFileW( filename, access, sharing, NULL, creation, flags, NULL );
    msi_revert_fs_redirection( package );
    return handle;
}

BOOL msi_copy_file( MSIPACKAGE *package, const WCHAR *src, const WCHAR *dst, BOOL fail_if_exists )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = CopyFileW( src, dst, fail_if_exists );
    msi_revert_fs_redirection( package );
    return ret;
}

BOOL msi_delete_file( MSIPACKAGE *package, const WCHAR *filename )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = DeleteFileW( filename );
    msi_revert_fs_redirection( package );
    return ret;
}

/* Undo log for a failed install: what the install script created, replaced or moved.
   Entries are appended as the install script does the work and replayed in reverse order
   when the install fails or is cancelled (msi_rollback_finish).  The standard actions with an
   inverse are rolled back by the ROLLBACK script, this covers what has none (InstallFiles,
   CreateFolders, MoveFiles, PatchFiles) and what the script cannot know: the registry keys
   WriteRegistryValues created and the values it overwrote. */
enum rollback_type
{
    ROLLBACK_FILE_CREATED,
    ROLLBACK_FILE_REPLACED,
    ROLLBACK_DIR_CREATED,
    ROLLBACK_FILE_MOVED,    /* path = source, backup = destination */
    ROLLBACK_KEY_CREATED,   /* root, path = subkey, view */
    ROLLBACK_VALUE_SET      /* root, path = subkey, view, name, previous value */
};

struct rollback_entry
{
    struct list entry;
    enum rollback_type type;
    WCHAR *path;
    WCHAR *backup;
    HKEY root;
    REGSAM view;
    WCHAR *name;
    DWORD reg_type;
    BYTE *data;
    DWORD data_size;
    BOOL had_value;
};

/* A crash in the middle of an install leaves the backup copies next to the files.  Every
   backup is noted in this key (value = backup path, data = "<pid>|<original>") until it is
   restored or dropped; the next install deletes the ones whose process is gone. */
static const WCHAR rollback_journal[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\RosPendingBackups";

static void journal_add( const WCHAR *backup, const WCHAR *orig )
{
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }, key;
    WCHAR *data;
    DWORD len;
    int i;

    len = wcslen( orig ) + 16;
    if (!(data = malloc( len * sizeof(WCHAR) ))) return;
    swprintf( data, len, L"%lu|%s", GetCurrentProcessId(), orig );
    for (i = 0; i < 2; i++)
    {
        if (RegCreateKeyExW( roots[i], rollback_journal, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY,
                             NULL, &key, NULL )) continue;
        RegSetValueExW( key, backup, 0, REG_SZ, (BYTE *)data, (wcslen( data ) + 1) * sizeof(WCHAR) );
        RegCloseKey( key );
        break;
    }
    free( data );
}

static void journal_remove( const WCHAR *backup )
{
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }, key;
    int i;

    for (i = 0; i < 2; i++)
    {
        if (RegOpenKeyExW( roots[i], rollback_journal, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key )) continue;
        RegDeleteValueW( key, backup );
        RegCloseKey( key );
    }
}

static BOOL is_process_running( DWORD pid )
{
    HANDLE process;
    BOOL ret;

    if (!pid) return FALSE;
    if (pid == GetCurrentProcessId()) return TRUE;
    if (!(process = OpenProcess( SYNCHRONIZE, FALSE, pid ))) return GetLastError() == ERROR_ACCESS_DENIED;
    ret = WaitForSingleObject( process, 0 ) == WAIT_TIMEOUT;
    CloseHandle( process );
    return ret;
}

/* "rbfXXXX.tmp", what msi_get_temp_file_name( ..., L"rbf", ... ) makes */
static BOOL is_backup_name( const WCHAR *path )
{
    const WCHAR *name = wcsrchr( path, '\\' );
    size_t len;

    name = name ? name + 1 : path;
    len = wcslen( name );
    return len > 7 && len <= 12 && !wcsnicmp( name, L"rbf", 3 ) && !wcsicmp( name + len - 4, L".tmp" );
}

/* Install start: delete the backups a crashed install left behind. */
void msi_rollback_cleanup_stale( MSIPACKAGE *package )
{
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }, key;
    WCHAR *name, *data;
    DWORD index, name_len, data_len, type;
    int i;

    if (!(name = malloc( 32768 * sizeof(WCHAR) ))) return;
    if (!(data = malloc( 32768 * sizeof(WCHAR) )))
    {
        free( name );
        return;
    }
    for (i = 0; i < 2; i++)
    {
        if (RegOpenKeyExW( roots[i], rollback_journal, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, &key ))
            continue;
        index = 0;
        for (;;)
        {
            LONG res;

            name_len = 32768;
            data_len = 32767 * sizeof(WCHAR);
            res = RegEnumValueW( key, index, name, &name_len, NULL, &type, (BYTE *)data, &data_len );
            if (res == ERROR_NO_MORE_ITEMS) break;
            if (res) { index++; continue; }
            data[data_len / sizeof(WCHAR)] = 0;
            if (type == REG_SZ && is_process_running( wcstoul( data, NULL, 10 ) ))
            {
                index++;
                continue;
            }
            if (is_backup_name( name ))
            {
                DWORD attrs = msi_get_file_attributes( package, name );
                if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                {
                    TRACE("deleting stale backup %s\n", debugstr_w(name));
                    msi_set_file_attributes( package, name, FILE_ATTRIBUTE_NORMAL );
                    msi_delete_file( package, name );
                }
            }
            RegDeleteValueW( key, name ); /* the next value is at the same index now */
        }
        RegCloseKey( key );
    }
    free( name );
    free( data );
}

static BOOL rollback_is_recording( MSIPACKAGE *package )
{
    return package->script == SCRIPT_INSTALL && !package->need_rollback &&
           !msi_get_property_int( package->db, L"RollbackDisabled", 0 );
}

static struct rollback_entry *rollback_add( MSIPACKAGE *package, enum rollback_type type, const WCHAR *path, WCHAR *backup )
{
    struct rollback_entry *e;

    if (!(e = calloc( 1, sizeof(*e) ))) return NULL;
    e->type = type;
    e->path = wcsdup( path );
    e->backup = backup;
    if (!e->path)
    {
        free( e );
        return NULL;
    }
    list_add_tail( &package->rollback_files, &e->entry );
    return e;
}

/* Call before a file of the install script is written: remember it as created, or keep a
   copy of the file that is about to be replaced. */
void msi_rollback_record_file( MSIPACKAGE *package, const WCHAR *path )
{
    WCHAR *dir, *p, *backup;
    DWORD attrs;

    if (!rollback_is_recording( package )) return;

    attrs = msi_get_file_attributes( package, path );
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        rollback_add( package, ROLLBACK_FILE_CREATED, path, NULL );
        return;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) return;

    if (!(dir = wcsdup( path ))) return;
    if ((p = wcsrchr( dir, '\\' ))) *p = 0;
    if ((backup = malloc( (wcslen( dir ) + 16) * sizeof(WCHAR) )))
    {
        if (msi_get_temp_file_name( package, dir, L"rbf", backup ) &&
            msi_copy_file( package, path, backup, FALSE ))
        {
            TRACE("backed up %s to %s\n", debugstr_w(path), debugstr_w(backup));
            journal_add( backup, path );
            if (rollback_add( package, ROLLBACK_FILE_REPLACED, path, backup )) backup = NULL;
            else
            {
                journal_remove( backup );
                msi_delete_file( package, backup );
            }
        }
        else
        {
            WARN("no backup of %s (%lu)\n", debugstr_w(path), GetLastError());
            if (backup[0]) msi_delete_file( package, backup );
        }
        free( backup );
    }
    free( dir );
}

/* A file was moved from source to dest (call after the move, and after msi_rollback_record_file
   for dest): the undo moves it back. */
void msi_rollback_record_move( MSIPACKAGE *package, const WCHAR *source, const WCHAR *dest )
{
    WCHAR *copy;

    if (!rollback_is_recording( package )) return;
    if (!(copy = wcsdup( dest ))) return;
    if (!rollback_add( package, ROLLBACK_FILE_MOVED, source, copy )) free( copy );
}

/* Call right after RegCreateKeyEx created the key (REG_CREATED_NEW_KEY). */
void msi_rollback_record_key( MSIPACKAGE *package, HKEY root, const WCHAR *path, REGSAM view )
{
    struct rollback_entry *e;

    if (!rollback_is_recording( package )) return;
    if ((e = rollback_add( package, ROLLBACK_KEY_CREATED, path, NULL )))
    {
        e->root = root;
        e->view = view;
    }
}

/* Call before a registry value is written: old is the value that was there (NULL: none). */
void msi_rollback_record_value( MSIPACKAGE *package, HKEY root, const WCHAR *path, REGSAM view,
                                const WCHAR *name, const BYTE *old, DWORD old_size, DWORD old_type )
{
    struct rollback_entry *e;

    if (!rollback_is_recording( package )) return;
    if (!(e = rollback_add( package, ROLLBACK_VALUE_SET, path, NULL ))) return;
    e->root = root;
    e->view = view;
    e->name = name ? wcsdup( name ) : NULL;
    if (old)
    {
        e->had_value = TRUE;
        e->reg_type = old_type;
        e->data_size = old_size;
        e->data = malloc( old_size ? old_size : 1 );
        if (e->data) memcpy( e->data, old, old_size );
        else e->had_value = FALSE;
    }
}

static BOOL create_directory( MSIPACKAGE *package, const WCHAR *path )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = CreateDirectoryW( path, NULL );
    msi_revert_fs_redirection( package );
    if (ret && rollback_is_recording( package )) rollback_add( package, ROLLBACK_DIR_CREATED, path, NULL );
    return ret;
}

static void rollback_undo_key( const struct rollback_entry *e )
{
    DWORD subkeys, values;
    HKEY key;

    if (RegOpenKeyExW( e->root, e->path, 0, KEY_QUERY_VALUE | e->view, &key )) return;
    if (RegQueryInfoKeyW( key, NULL, NULL, NULL, &subkeys, NULL, NULL, &values, NULL, NULL, NULL, NULL ))
        subkeys = values = 1;
    RegCloseKey( key );
    /* only an empty key goes: something else may live in it now */
    if (!subkeys && !values)
    {
        TRACE("rollback: removing key %s\n", debugstr_w(e->path));
        RegDeleteKeyExW( e->root, e->path, e->view, 0 );
    }
}

static void rollback_undo_value( const struct rollback_entry *e )
{
    HKEY key;

    if (e->had_value)
    {
        /* the undo of WriteRegistryValues deleted it, and the key with it when it was empty */
        if (RegCreateKeyExW( e->root, e->path, 0, NULL, 0, KEY_SET_VALUE | e->view, NULL, &key, NULL )) return;
        TRACE("rollback: restoring value %s of %s\n", debugstr_w(e->name), debugstr_w(e->path));
        RegSetValueExW( key, e->name, 0, e->reg_type, e->data, e->data_size );
    }
    else
    {
        if (RegOpenKeyExW( e->root, e->path, 0, KEY_SET_VALUE | e->view, &key )) return;
        TRACE("rollback: deleting value %s of %s\n", debugstr_w(e->name), debugstr_w(e->path));
        RegDeleteValueW( key, e->name );
    }
    RegCloseKey( key );
}

/* The install is over: undo the log (failed or cancelled install) or drop the backups (success). */
void msi_rollback_finish( MSIPACKAGE *package, BOOL undo )
{
    struct list *item, *cursor;

    /* newest first: files before the directories they were created in */
    for (item = list_tail( &package->rollback_files ); item; item = cursor)
    {
        struct rollback_entry *e = LIST_ENTRY( item, struct rollback_entry, entry );

        cursor = list_prev( &package->rollback_files, item );
        list_remove( &e->entry );

        switch (e->type)
        {
        case ROLLBACK_FILE_CREATED:
            if (undo)
            {
                TRACE("rollback: deleting %s\n", debugstr_w(e->path));
                msi_set_file_attributes( package, e->path, FILE_ATTRIBUTE_NORMAL );
                if (!msi_delete_file( package, e->path ) && GetLastError() != ERROR_FILE_NOT_FOUND)
                    WARN("failed to delete %s (%lu)\n", debugstr_w(e->path), GetLastError());
            }
            break;
        case ROLLBACK_FILE_REPLACED:
            if (undo)
            {
                TRACE("rollback: restoring %s\n", debugstr_w(e->path));
                msi_set_file_attributes( package, e->path, FILE_ATTRIBUTE_NORMAL );
                if (!msi_move_file( package, e->backup, e->path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED ))
                    WARN("failed to restore %s (%lu)\n", debugstr_w(e->path), GetLastError());
            }
            else
            {
                msi_set_file_attributes( package, e->backup, FILE_ATTRIBUTE_NORMAL );
                msi_delete_file( package, e->backup );
            }
            journal_remove( e->backup );
            break;
        case ROLLBACK_DIR_CREATED:
            if (undo)
            {
                TRACE("rollback: removing directory %s\n", debugstr_w(e->path));
                msi_remove_directory( package, e->path ); /* fails if something else lives there */
            }
            break;
        case ROLLBACK_FILE_MOVED:
            if (undo && msi_get_file_attributes( package, e->path ) == INVALID_FILE_ATTRIBUTES &&
                msi_get_file_attributes( package, e->backup ) != INVALID_FILE_ATTRIBUTES)
            {
                TRACE("rollback: moving %s back to %s\n", debugstr_w(e->backup), debugstr_w(e->path));
                if (!msi_move_file( package, e->backup, e->path, MOVEFILE_COPY_ALLOWED ))
                    WARN("failed to move %s back (%lu)\n", debugstr_w(e->backup), GetLastError());
            }
            break;
        case ROLLBACK_KEY_CREATED:
            if (undo) rollback_undo_key( e );
            break;
        case ROLLBACK_VALUE_SET:
            if (undo) rollback_undo_value( e );
            break;
        }
        free( e->path );
        free( e->backup );
        free( e->name );
        free( e->data );
        free( e );
    }
}

BOOL msi_remove_directory( MSIPACKAGE *package, const WCHAR *path )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = RemoveDirectoryW( path );
    msi_revert_fs_redirection( package );
    return ret;
}

BOOL msi_set_file_attributes( MSIPACKAGE *package, const WCHAR *filename, DWORD attrs )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = SetFileAttributesW( filename, attrs );
    msi_revert_fs_redirection( package );
    return ret;
}

DWORD msi_get_file_attributes( MSIPACKAGE *package, const WCHAR *path )
{
    DWORD attrs;
    msi_disable_fs_redirection( package );
    attrs = GetFileAttributesW( path );
    msi_revert_fs_redirection( package );
    return attrs;
}

HANDLE msi_find_first_file( MSIPACKAGE *package, const WCHAR *filename, WIN32_FIND_DATAW *data )
{
    HANDLE handle;
    msi_disable_fs_redirection( package );
    handle = FindFirstFileW( filename, data );
    msi_revert_fs_redirection( package );
    return handle;
}

BOOL msi_find_next_file( MSIPACKAGE *package, HANDLE handle, WIN32_FIND_DATAW *data )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = FindNextFileW( handle, data );
    msi_revert_fs_redirection( package );
    return ret;
}

BOOL msi_move_file( MSIPACKAGE *package, const WCHAR *from, const WCHAR *to, DWORD flags )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = MoveFileExW( from, to, flags );
    msi_revert_fs_redirection( package );
    return ret;
}

static BOOL apply_filepatch( MSIPACKAGE *package, const WCHAR *patch, const WCHAR *old, const WCHAR *new )
{
    BOOL ret;
    msi_disable_fs_redirection( package );
    ret = ApplyPatchToFileW( patch, old, new, 0 );
    msi_revert_fs_redirection( package );
    return ret;
}

DWORD msi_get_file_version_info( MSIPACKAGE *package, const WCHAR *path, DWORD buflen, BYTE *buffer )
{
    DWORD size, handle;
    msi_disable_fs_redirection( package );
    if (buffer) size = GetFileVersionInfoW( path, 0, buflen, buffer );
    else size = GetFileVersionInfoSizeW( path, &handle );
    msi_revert_fs_redirection( package );
    return size;
}

VS_FIXEDFILEINFO *msi_get_disk_file_version( MSIPACKAGE *package, const WCHAR *filename )
{
    VS_FIXEDFILEINFO *ptr, *ret;
    DWORD version_size;
    UINT size;
    void *version;

    if (!(version_size = msi_get_file_version_info( package, filename, 0, NULL ))) return NULL;
    if (!(version = malloc( version_size ))) return NULL;

    msi_get_file_version_info( package, filename, version_size, version );

    if (!VerQueryValueW( version, L"\\", (void **)&ptr, &size ))
    {
        free( version );
        return NULL;
    }

    if (!(ret = malloc( size )))
    {
        free( version );
        return NULL;
    }

    memcpy( ret, ptr, size );
    free( version );
    return ret;
}

DWORD msi_get_disk_file_size( MSIPACKAGE *package, const WCHAR *filename )
{
    DWORD size;
    HANDLE file;
    file = msi_create_file( package, filename, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, 0 );
    if (file == INVALID_HANDLE_VALUE) return INVALID_FILE_SIZE;
    size = GetFileSize( file, NULL );
    CloseHandle( file );
    return size;
}

/* Recursively create all directories in the path. */
BOOL msi_create_full_path( MSIPACKAGE *package, const WCHAR *path )
{
    BOOL ret = TRUE;
    WCHAR *new_path;
    int len;

    if (!(new_path = malloc( (wcslen( path ) + 1) * sizeof(WCHAR) ))) return FALSE;
    lstrcpyW( new_path, path );

    while ((len = lstrlenW( new_path )) && new_path[len - 1] == '\\')
    new_path[len - 1] = 0;

    while (!create_directory( package, new_path ))
    {
        WCHAR *slash;
        DWORD last_error = GetLastError();
        if (last_error == ERROR_ALREADY_EXISTS) break;
        if (last_error != ERROR_PATH_NOT_FOUND)
        {
            ret = FALSE;
            break;
        }
        if (!(slash = wcsrchr( new_path, '\\' )))
        {
            ret = FALSE;
            break;
        }
        len = slash - new_path;
        new_path[len] = 0;
        if (!msi_create_full_path( package, new_path ))
        {
            ret = FALSE;
            break;
        }
        new_path[len] = '\\';
    }
    free( new_path );
    return ret;
}

static void file_update_ui( MSIPACKAGE *package, MSIFILE *f, const WCHAR *action )
{
    MSIRECORD *uirow;

    uirow = MSI_CreateRecord( 9 );
    MSI_RecordSetStringW( uirow, 1, f->FileName );
    MSI_RecordSetStringW( uirow, 9, f->Component->Directory );
    MSI_RecordSetInteger( uirow, 6, f->FileSize );
    MSI_ProcessMessage(package, INSTALLMESSAGE_ACTIONDATA, uirow);
    msiobj_release( &uirow->hdr );
    msi_ui_progress( package, 2, f->FileSize, 0, 0 );
}

static BOOL is_registered_patch_media( MSIPACKAGE *package, UINT disk_id )
{
    MSIPATCHINFO *patch;

    LIST_FOR_EACH_ENTRY( patch, &package->patches, MSIPATCHINFO, entry )
    {
        if (patch->disk_id == disk_id && patch->registered) return TRUE;
    }
    return FALSE;
}

static BOOL is_obsoleted_by_patch( MSIPACKAGE *package, MSIFILE *file )
{
    if (!list_empty( &package->patches ) && file->disk_id < MSI_INITIAL_MEDIA_TRANSFORM_DISKID)
    {
        if (!msi_get_property_int( package->db, L"Installed", 0 )) return FALSE;
        return TRUE;
    }
    if (is_registered_patch_media( package, file->disk_id )) return TRUE;
    return FALSE;
}

static BOOL file_hash_matches( MSIPACKAGE *package, MSIFILE *file )
{
    UINT r;
    MSIFILEHASHINFO hash;

    hash.dwFileHashInfoSize = sizeof(hash);
    r = msi_get_filehash( package, file->TargetPath, &hash );
    if (r != ERROR_SUCCESS)
        return FALSE;

    return !memcmp( &hash, &file->hash, sizeof(hash) );
}

static msi_file_state calculate_install_state( MSIPACKAGE *package, MSIFILE *file )
{
    MSICOMPONENT *comp = file->Component;
    VS_FIXEDFILEINFO *file_version;
    WCHAR *font_version;
    msi_file_state state;
    DWORD size;

    comp->Action = msi_get_component_action( package, comp );
    if (!comp->Enabled || comp->Action != INSTALLSTATE_LOCAL)
    {
        TRACE("skipping %s (not scheduled for install)\n", debugstr_w(file->File));
        return msifs_skipped;
    }
    if (is_obsoleted_by_patch( package, file ))
    {
        TRACE("skipping %s (obsoleted by patch)\n", debugstr_w(file->File));
        return msifs_skipped;
    }
    if (msi_get_file_attributes( package, file->TargetPath ) == INVALID_FILE_ATTRIBUTES)
    {
        TRACE("installing %s (missing)\n", debugstr_w(file->File));
        return msifs_missing;
    }
    if (file->Version)
    {
        if ((file_version = msi_get_disk_file_version( package, file->TargetPath )))
        {
            if (msi_compare_file_versions( file_version, file->Version ) < 0)
            {
                TRACE("overwriting %s (new version %s old version %u.%u.%u.%u)\n",
                      debugstr_w(file->File), debugstr_w(file->Version),
                      HIWORD(file_version->dwFileVersionMS), LOWORD(file_version->dwFileVersionMS),
                      HIWORD(file_version->dwFileVersionLS), LOWORD(file_version->dwFileVersionLS));
                state = msifs_overwrite;
            }
            else
            {
                TRACE("keeping %s (new version %s old version %u.%u.%u.%u)\n",
                      debugstr_w(file->File), debugstr_w(file->Version),
                      HIWORD(file_version->dwFileVersionMS), LOWORD(file_version->dwFileVersionMS),
                      HIWORD(file_version->dwFileVersionLS), LOWORD(file_version->dwFileVersionLS));
                state = msifs_present;
            }
            free( file_version );
            return state;
        }
        else if ((font_version = msi_get_font_file_version( package, file->TargetPath )))
        {
            if (msi_compare_font_versions( font_version, file->Version ) < 0)
            {
                TRACE("overwriting %s (new version %s old version %s)\n",
                      debugstr_w(file->File), debugstr_w(file->Version), debugstr_w(font_version));
                state = msifs_overwrite;
            }
            else
            {
                TRACE("keeping %s (new version %s old version %s)\n",
                      debugstr_w(file->File), debugstr_w(file->Version), debugstr_w(font_version));
                state = msifs_present;
            }
            free( font_version );
            return state;
        }
    }
    if ((size = msi_get_disk_file_size( package, file->TargetPath )) != file->FileSize)
    {
        TRACE("overwriting %s (old size %lu new size %d)\n", debugstr_w(file->File), size, file->FileSize);
        return msifs_overwrite;
    }
    if (file->hash.dwFileHashInfoSize)
    {
        if (file_hash_matches( package, file ))
        {
            TRACE("keeping %s (hash match)\n", debugstr_w(file->File));
            return msifs_hashmatch;
        }
        else
        {
            TRACE("overwriting %s (hash mismatch)\n", debugstr_w(file->File));
            return msifs_overwrite;
        }
    }
    /* assume present */
    TRACE("keeping %s\n", debugstr_w(file->File));
    return msifs_present;
}

static void schedule_install_files(MSIPACKAGE *package)
{
    MSIFILE *file;

    LIST_FOR_EACH_ENTRY(file, &package->files, MSIFILE, entry)
    {
        MSICOMPONENT *comp = file->Component;

        file->state = calculate_install_state( package, file );
        if (file->state == msifs_overwrite && (comp->Attributes & msidbComponentAttributesNeverOverwrite))
        {
            TRACE("not overwriting %s\n", debugstr_w(file->TargetPath));
            file->state = msifs_skipped;
        }
    }
}

static UINT copy_file_attributes( MSIPACKAGE *package, MSIFILE *file, WCHAR *source )
{
    BOOL ret;

    ret = msi_copy_file( package, source, file->TargetPath, FALSE );
    if (!ret)
        return GetLastError();

    msi_set_file_attributes( package, file->TargetPath, FILE_ATTRIBUTE_NORMAL );
    return ERROR_SUCCESS;
}

static UINT copy_install_file(MSIPACKAGE *package, MSIFILE *file, LPWSTR source)
{
    UINT gle;

    TRACE("Copying %s to %s\n", debugstr_w(source), debugstr_w(file->TargetPath));

    gle = copy_file_attributes( package, file, source );
    if (gle == ERROR_SUCCESS)
        return gle;

    if (gle == ERROR_ALREADY_EXISTS && file->state == msifs_overwrite)
    {
        TRACE("overwriting existing file\n");
        return ERROR_SUCCESS;
    }
    else if (gle == ERROR_ACCESS_DENIED)
    {
        msi_set_file_attributes( package, file->TargetPath, FILE_ATTRIBUTE_NORMAL );

        gle = copy_file_attributes( package, file, source );
        TRACE("Overwriting existing file: %d\n", gle);
    }
    if (gle == ERROR_SHARING_VIOLATION || gle == ERROR_USER_MAPPED_FILE)
    {
        WCHAR *tmpfileW, *pathW, *p;
        DWORD len;

        TRACE("file in use, scheduling rename operation\n");

        if (!(pathW = wcsdup( file->TargetPath ))) return ERROR_OUTOFMEMORY;
        if ((p = wcsrchr(pathW, '\\'))) *p = 0;
        len = lstrlenW( pathW ) + 16;
        if (!(tmpfileW = malloc(len * sizeof(WCHAR))))
        {
            free( pathW );
            return ERROR_OUTOFMEMORY;
        }
        if (!GetTempFileNameW( pathW, L"msi", 0, tmpfileW )) tmpfileW[0] = 0;
        free( pathW );

        if (msi_copy_file( package, source, tmpfileW, FALSE ) &&
            msi_move_file( package, file->TargetPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT ) &&
            msi_move_file( package, tmpfileW, file->TargetPath, MOVEFILE_DELAY_UNTIL_REBOOT ))
        {
            package->need_reboot_at_end = 1;
            gle = ERROR_SUCCESS;
        }
        else
        {
            gle = GetLastError();
            WARN("failed to schedule rename operation: %d)\n", gle);
            DeleteFileW( tmpfileW );
        }
        free(tmpfileW);
    }

    return gle;
}

static UINT create_folder( MSIPACKAGE *package, const WCHAR *dir )
{
    MSIFOLDER *folder;
    const WCHAR *install_path;

    install_path = msi_get_target_folder( package, dir );
    if (!install_path) return ERROR_FUNCTION_FAILED;

    folder = msi_get_loaded_folder( package, dir );
    if (folder->State == FOLDER_STATE_UNINITIALIZED)
    {
        msi_create_full_path( package, install_path );
        folder->State = FOLDER_STATE_CREATED;
    }
    return ERROR_SUCCESS;
}

static MSIFILE *find_file( MSIPACKAGE *package, UINT disk_id, const WCHAR *filename )
{
    MSIFILE *file;

    LIST_FOR_EACH_ENTRY( file, &package->files, MSIFILE, entry )
    {
        if (file->disk_id == disk_id &&
            file->state != msifs_installed &&
            !wcsicmp( filename, file->File )) return file;
    }
    return NULL;
}

static BOOL installfiles_cb(MSIPACKAGE *package, LPCWSTR filename, DWORD action,
                            LPWSTR *path, DWORD *attrs, PVOID user)
{
    MSIFILE *file = *(MSIFILE **)user;

    if (action == MSICABEXTRACT_BEGINEXTRACT)
    {
        if (!(file = find_file( package, file->disk_id, filename )))
        {
            TRACE("unknown file in cabinet (%s)\n", debugstr_w(filename));
            return FALSE;
        }
        if (file->state != msifs_missing && file->state != msifs_overwrite)
            return FALSE;

        /* Report progress as each file of a (possibly huge) cabinet is extracted,
         * not only before the cabinet is opened, so the bar advances meanwhile. */
        if (!file->ui_reported)
        {
            file_update_ui( package, file, L"InstallFiles" );
            file->ui_reported = TRUE;
        }

        if (!msi_is_global_assembly( file->Component ))
        {
            create_folder( package, file->Component->Directory );
        }
        *path = wcsdup( file->TargetPath );
        msi_rollback_record_file( package, file->TargetPath );
        *attrs = file->Attributes;
        *(MSIFILE **)user = file;
    }
    else if (action == MSICABEXTRACT_FILEEXTRACTED)
    {
        if (!msi_is_global_assembly( file->Component )) file->state = msifs_installed;
    }

    return TRUE;
}

WCHAR *msi_resolve_file_source( MSIPACKAGE *package, MSIFILE *file )
{
    WCHAR *p, *path;

    TRACE("Working to resolve source of file %s\n", debugstr_w(file->File));

    if (file->IsCompressed) return NULL;

    p = msi_resolve_source_folder( package, file->Component->Directory, NULL );
    path = msi_build_directory_name( 2, p, file->ShortName );

    if (file->LongName && msi_get_file_attributes( package, path ) == INVALID_FILE_ATTRIBUTES)
    {
        free( path );
        path = msi_build_directory_name( 2, p, file->LongName );
    }
    free( p );
    TRACE("file %s source resolves to %s\n", debugstr_w(file->File), debugstr_w(path));
    return path;
}

/*
 * ACTION_InstallFiles()
 *
 * For efficiency, this is done in two passes:
 * 1) Correct all the TargetPaths and determine what files are to be installed.
 * 2) Extract Cabinets and copy files.
 */
UINT ACTION_InstallFiles(MSIPACKAGE *package)
{
    MSIMEDIAINFO *mi;
    UINT rc = ERROR_SUCCESS;
    MSIFILE *file;

    msi_set_sourcedir_props(package, FALSE);

    if (package->script == SCRIPT_NONE)
        return msi_schedule_action(package, SCRIPT_INSTALL, L"InstallFiles");

    schedule_install_files(package);
    mi = calloc(1, sizeof(MSIMEDIAINFO));

    LIST_FOR_EACH_ENTRY( file, &package->files, MSIFILE, entry ) file->ui_reported = FALSE;

    LIST_FOR_EACH_ENTRY( file, &package->files, MSIFILE, entry )
    {
        BOOL is_global_assembly = msi_is_global_assembly( file->Component );

        if (!file->ui_reported) file_update_ui( package, file, L"InstallFiles" );
        file->ui_reported = TRUE;

        rc = msi_load_media_info( package, file->Sequence, mi );
        if (rc != ERROR_SUCCESS)
        {
            ERR("Unable to load media info for %s (%u)\n", debugstr_w(file->File), rc);
            rc = ERROR_FUNCTION_FAILED;
            goto done;
        }

        if (file->state != msifs_hashmatch &&
            file->state != msifs_skipped &&
            (file->state != msifs_present || !msi_get_property_int( package->db, L"Installed", 0 )) &&
            (rc = ready_media( package, file->IsCompressed, mi )))
        {
            ERR("Failed to ready media for %s\n", debugstr_w(file->File));
            goto done;
        }

        if (file->state != msifs_missing && !mi->is_continuous && file->state != msifs_overwrite)
            continue;

        if (file->Sequence > mi->last_sequence || mi->is_continuous ||
            (file->IsCompressed && !mi->is_extracted))
        {
            MSICABDATA data;
            MSIFILE *cursor = file;

            data.mi = mi;
            data.package = package;
            data.cb = installfiles_cb;
            data.user = &cursor;

            if (file->IsCompressed && !msi_cabextract(package, mi, &data))
            {
                ERR("Failed to extract cabinet: %s\n", debugstr_w(mi->cabinet));
                rc = ERROR_INSTALL_FAILURE;
                goto done;
            }
        }

        if (!file->IsCompressed)
        {
            WCHAR *source = msi_resolve_file_source(package, file);

            TRACE("copying %s to %s\n", debugstr_w(source), debugstr_w(file->TargetPath));

            if (!is_global_assembly)
            {
                create_folder(package, file->Component->Directory);
            }
            if (!is_global_assembly) msi_rollback_record_file( package, file->TargetPath );
            rc = copy_install_file(package, file, source);
            if (rc != ERROR_SUCCESS)
            {
                ERR("Failed to copy %s to %s (%u)\n", debugstr_w(source), debugstr_w(file->TargetPath), rc);
                rc = ERROR_INSTALL_FAILURE;
                free(source);
                goto done;
            }
            if (!is_global_assembly) file->state = msifs_installed;
            free(source);
        }
        else if (!is_global_assembly && file->state != msifs_installed &&
                 !(file->Attributes & msidbFileAttributesPatchAdded))
        {
            ERR("compressed file wasn't installed (%s)\n", debugstr_w(file->File));
            rc = ERROR_INSTALL_FAILURE;
            goto done;
        }
    }

done:
    msi_free_media_info(mi);
    return rc;
}

static MSIFILEPATCH *find_filepatch( MSIPACKAGE *package, UINT disk_id, const WCHAR *key )
{
    MSIFILEPATCH *patch;

    LIST_FOR_EACH_ENTRY( patch, &package->filepatches, MSIFILEPATCH, entry )
    {
        if (!patch->extracted && patch->disk_id == disk_id && !wcscmp( key, patch->File->File ))
            return patch;
    }
    return NULL;
}

static BOOL patchfiles_cb(MSIPACKAGE *package, LPCWSTR file, DWORD action,
                          LPWSTR *path, DWORD *attrs, PVOID user)
{
    MSIFILEPATCH *patch = *(MSIFILEPATCH **)user;

    if (action == MSICABEXTRACT_BEGINEXTRACT)
    {
        MSICOMPONENT *comp;

        if (is_registered_patch_media( package, patch->disk_id ) ||
            !(patch = find_filepatch( package, patch->disk_id, file ))) return FALSE;

        comp = patch->File->Component;
        comp->Action = msi_get_component_action( package, comp );
        if (!comp->Enabled || comp->Action != INSTALLSTATE_LOCAL)
        {
            TRACE("file %s component %s not installed or disabled\n",
                  debugstr_w(patch->File->File), debugstr_w(comp->Component));
            return FALSE;
        }

        patch->path = msi_create_temp_file( package->db );
        *path = wcsdup( patch->path );
        *attrs = patch->File->Attributes;
        *(MSIFILEPATCH **)user = patch;
    }
    else if (action == MSICABEXTRACT_FILEEXTRACTED)
    {
        patch->extracted = TRUE;
    }

    return TRUE;
}

static UINT patch_file( MSIPACKAGE *package, MSIFILEPATCH *patch )
{
    UINT r = ERROR_SUCCESS;
    WCHAR *tmpfile = msi_create_temp_file( package->db );

    if (!tmpfile) return ERROR_INSTALL_FAILURE;
    if (apply_filepatch( package, patch->path, patch->File->TargetPath, tmpfile ))
    {
        msi_rollback_record_file( package, patch->File->TargetPath );
        msi_delete_file( package, patch->File->TargetPath );
        msi_move_file( package, tmpfile, patch->File->TargetPath, 0 );
    }
    else
    {
        WARN( "failed to patch %s: %#lx\n", debugstr_w(patch->File->TargetPath), GetLastError() );
        r = ERROR_INSTALL_FAILURE;
    }
    DeleteFileW( patch->path );
    DeleteFileW( tmpfile );
    free( tmpfile );
    return r;
}

UINT msi_patch_assembly( MSIPACKAGE *package, MSIASSEMBLY *assembly, MSIFILEPATCH *patch )
{
    UINT r = ERROR_FUNCTION_FAILED;
    IAssemblyName *name;
    IAssemblyEnum *iter;

    if (!(iter = msi_create_assembly_enum( package, assembly->display_name )))
        return ERROR_FUNCTION_FAILED;

    while ((IAssemblyEnum_GetNextAssembly( iter, NULL, &name, 0 ) == S_OK))
    {
        WCHAR *displayname, *path;
        DWORD len = 0;
        HRESULT hr;

        hr = IAssemblyName_GetDisplayName( name, NULL, &len, 0 );
        if (hr != E_NOT_SUFFICIENT_BUFFER || !(displayname = malloc( len * sizeof(WCHAR) )))
            break;

        hr = IAssemblyName_GetDisplayName( name, displayname, &len, 0 );
        if (FAILED( hr ))
        {
            free( displayname );
            break;
        }

        if ((path = msi_get_assembly_path( package, displayname )))
        {
            if (!msi_copy_file( package, path, patch->File->TargetPath, FALSE ))
            {
                ERR( "failed to copy file %s -> %s (%lu)\n", debugstr_w(path),
                     debugstr_w(patch->File->TargetPath), GetLastError() );
                free( path );
                free( displayname );
                IAssemblyName_Release( name );
                break;
            }
            r = patch_file( package, patch );
            free( path );
        }

        free( displayname );
        IAssemblyName_Release( name );
        if (r == ERROR_SUCCESS) break;
    }

    IAssemblyEnum_Release( iter );
    return r;
}

UINT ACTION_PatchFiles( MSIPACKAGE *package )
{
    MSIFILEPATCH *patch;
    MSIMEDIAINFO *mi;
    UINT rc = ERROR_SUCCESS;

    TRACE("%p\n", package);

    if (package->script == SCRIPT_NONE)
        return msi_schedule_action(package, SCRIPT_INSTALL, L"PatchFiles");

    mi = calloc( 1, sizeof(MSIMEDIAINFO) );

    TRACE("extracting files\n");

    LIST_FOR_EACH_ENTRY( patch, &package->filepatches, MSIFILEPATCH, entry )
    {
        MSIFILE *file = patch->File;
        MSICOMPONENT *comp = file->Component;

        rc = msi_load_media_info( package, patch->Sequence, mi );
        if (rc != ERROR_SUCCESS)
        {
            ERR("Unable to load media info for %s (%u)\n", debugstr_w(file->File), rc);
            rc = ERROR_FUNCTION_FAILED;
            goto done;
        }
        comp->Action = msi_get_component_action( package, comp );
        if (!comp->Enabled || comp->Action != INSTALLSTATE_LOCAL) continue;

        if (!patch->extracted)
        {
            MSICABDATA data;
            MSIFILEPATCH *cursor = patch;

            rc = ready_media( package, TRUE, mi );
            if (rc != ERROR_SUCCESS)
            {
                ERR("Failed to ready media for %s\n", debugstr_w(file->File));
                goto done;
            }
            data.mi      = mi;
            data.package = package;
            data.cb      = patchfiles_cb;
            data.user    = &cursor;

            if (!msi_cabextract( package, mi, &data ))
            {
                ERR("Failed to extract cabinet: %s\n", debugstr_w(mi->cabinet));
                rc = ERROR_INSTALL_FAILURE;
                goto done;
            }
        }
    }

    TRACE("applying patches\n");

    LIST_FOR_EACH_ENTRY( patch, &package->filepatches, MSIFILEPATCH, entry )
    {
        MSICOMPONENT *comp = patch->File->Component;

        if (msi_is_global_assembly( comp ) || !patch->path) continue;

        rc = patch_file( package, patch );
        if (rc && !(patch->Attributes & msidbPatchAttributesNonVital))
        {
            ERR("Failed to apply patch to file: %s\n", debugstr_w(patch->File->File));
            break;
        }
    }

done:
    msi_free_media_info(mi);
    return rc;
}

#define is_dot_dir(x) ((x[0] == '.') && ((x[1] == 0) || ((x[1] == '.') && (x[2] == 0))))

struct file_list
{
    struct list entry;
    LPWSTR sourcename;
    LPWSTR destname;
    LPWSTR source;
    LPWSTR dest;
};

static BOOL move_file( MSIPACKAGE *package, const WCHAR *source, const WCHAR *dest, int options )
{
    BOOL ret;

    if (msi_get_file_attributes( package, source ) == FILE_ATTRIBUTE_DIRECTORY ||
        msi_get_file_attributes( package, dest ) == FILE_ATTRIBUTE_DIRECTORY)
    {
        WARN("Source or dest is directory, not moving\n");
        return FALSE;
    }

    if (options == msidbMoveFileOptionsMove)
    {
        TRACE("moving %s -> %s\n", debugstr_w(source), debugstr_w(dest));
        msi_rollback_record_file( package, dest );
        ret = msi_move_file( package, source, dest, MOVEFILE_REPLACE_EXISTING );
        if (!ret)
        {
            WARN( "msi_move_file failed: %lu\n", GetLastError() );
            return FALSE;
        }
        msi_rollback_record_move( package, source, dest );
    }
    else
    {
        TRACE("copying %s -> %s\n", debugstr_w(source), debugstr_w(dest));
        msi_rollback_record_file( package, dest );
        ret = msi_copy_file( package, source, dest, FALSE );
        if (!ret)
        {
            WARN( "copy_file failed: %lu\n", GetLastError() );
            return FALSE;
        }
    }

    return TRUE;
}

static WCHAR *wildcard_to_file( const WCHAR *wildcard, const WCHAR *filename )
{
    const WCHAR *ptr;
    WCHAR *path;
    DWORD dirlen, pathlen;

    ptr = wcsrchr(wildcard, '\\');
    dirlen = ptr - wildcard + 1;

    pathlen = dirlen + lstrlenW(filename) + 1;
    if (!(path = malloc(pathlen * sizeof(WCHAR)))) return NULL;

    lstrcpynW(path, wildcard, dirlen + 1);
    lstrcatW(path, filename);

    return path;
}

static void free_file_entry(struct file_list *file)
{
    free(file->source);
    free(file->dest);
    free(file);
}

static void free_list(struct file_list *list)
{
    while (!list_empty(&list->entry))
    {
        struct file_list *file = LIST_ENTRY(list_head(&list->entry), struct file_list, entry);

        list_remove(&file->entry);
        free_file_entry(file);
    }
}

static BOOL add_wildcard( struct file_list *files, const WCHAR *source, WCHAR *dest )
{
    struct file_list *new, *file;
    WCHAR *ptr, *filename;
    DWORD size;

    new = calloc(1, sizeof(*new));
    if (!new)
        return FALSE;

    new->source = wcsdup(source);
    ptr = wcsrchr(dest, '\\') + 1;
    filename = wcsrchr(new->source, '\\') + 1;

    new->sourcename = filename;

    if (*ptr)
        new->destname = ptr;
    else
        new->destname = new->sourcename;

    size = (ptr - dest) + lstrlenW(filename) + 1;
    new->dest = malloc(size * sizeof(WCHAR));
    if (!new->dest)
    {
        free_file_entry(new);
        return FALSE;
    }

    lstrcpynW(new->dest, dest, ptr - dest + 1);
    lstrcatW(new->dest, filename);

    if (list_empty(&files->entry))
    {
        list_add_head(&files->entry, &new->entry);
        return TRUE;
    }

    LIST_FOR_EACH_ENTRY(file, &files->entry, struct file_list, entry)
    {
        if (wcscmp( source, file->source ) < 0)
        {
            list_add_before(&file->entry, &new->entry);
            return TRUE;
        }
    }

    list_add_after(&file->entry, &new->entry);
    return TRUE;
}

static BOOL move_files_wildcard( MSIPACKAGE *package, const WCHAR *source, WCHAR *dest, int options )
{
    WIN32_FIND_DATAW wfd;
    HANDLE hfile;
    LPWSTR path;
    BOOL res;
    struct file_list files, *file;
    DWORD size;

    hfile = msi_find_first_file( package, source, &wfd );
    if (hfile == INVALID_HANDLE_VALUE) return FALSE;

    list_init(&files.entry);

    for (res = TRUE; res; res = msi_find_next_file( package, hfile, &wfd ))
    {
        if (is_dot_dir(wfd.cFileName)) continue;

        path = wildcard_to_file( source, wfd.cFileName );
        if (!path)
        {
            res = FALSE;
            goto done;
        }

        add_wildcard(&files, path, dest);
        free(path);
    }

    /* no files match the wildcard */
    if (list_empty(&files.entry))
        goto done;

    /* only the first wildcard match gets renamed to dest */
    file = LIST_ENTRY(list_head(&files.entry), struct file_list, entry);
    size = (wcsrchr(file->dest, '\\') - file->dest) + lstrlenW(file->destname) + 2;
    file->dest = realloc(file->dest, size * sizeof(WCHAR));
    if (!file->dest)
    {
        res = FALSE;
        goto done;
    }

    /* file->dest may be shorter after the reallocation, so add a NULL
     * terminator.  This is needed for the call to wcsrchr, as there will no
     * longer be a NULL terminator within the bounds of the allocation in this case.
     */
    file->dest[size - 1] = '\0';
    lstrcpyW(wcsrchr(file->dest, '\\') + 1, file->destname);

    while (!list_empty(&files.entry))
    {
        file = LIST_ENTRY(list_head(&files.entry), struct file_list, entry);

        move_file( package, file->source, file->dest, options );

        list_remove(&file->entry);
        free_file_entry(file);
    }

    res = TRUE;

done:
    free_list(&files);
    FindClose(hfile);
    return res;
}

void msi_reduce_to_long_filename( WCHAR *filename )
{
    WCHAR *p = wcschr( filename, '|' );
    if (p) memmove( filename, p + 1, (lstrlenW( p + 1 ) + 1) * sizeof(WCHAR) );
}

static UINT ITERATE_MoveFiles( MSIRECORD *rec, LPVOID param )
{
    MSIPACKAGE *package = param;
    MSIRECORD *uirow;
    MSICOMPONENT *comp;
    LPCWSTR sourcename, component;
    LPWSTR sourcedir, destname = NULL, destdir = NULL, source = NULL, dest = NULL;
    int options;
    DWORD size;
    BOOL wildcards;

    component = MSI_RecordGetString(rec, 2);
    comp = msi_get_loaded_component(package, component);
    if (!comp)
        return ERROR_SUCCESS;

    comp->Action = msi_get_component_action( package, comp );
    if (comp->Action != INSTALLSTATE_LOCAL)
    {
        TRACE("component not scheduled for installation %s\n", debugstr_w(component));
        return ERROR_SUCCESS;
    }

    sourcename = MSI_RecordGetString(rec, 3);
    options = MSI_RecordGetInteger(rec, 7);

    sourcedir = msi_dup_property(package->db, MSI_RecordGetString(rec, 5));
    if (!sourcedir)
        goto done;

    destdir = msi_dup_property(package->db, MSI_RecordGetString(rec, 6));
    if (!destdir)
        goto done;

    if (!sourcename)
    {
        if (msi_get_file_attributes( package, sourcedir ) == INVALID_FILE_ATTRIBUTES)
            goto done;

        source = wcsdup(sourcedir);
        if (!source)
            goto done;
    }
    else
    {
        size = lstrlenW(sourcedir) + lstrlenW(sourcename) + 2;
        source = malloc(size * sizeof(WCHAR));
        if (!source)
            goto done;

        lstrcpyW(source, sourcedir);
        if (source[lstrlenW(source) - 1] != '\\')
            lstrcatW(source, L"\\");
        lstrcatW(source, sourcename);
    }

    wildcards = wcschr(source, '*') || wcschr(source, '?');

    if (MSI_RecordIsNull(rec, 4))
    {
        if (!wildcards)
        {
            WCHAR *p;
            if (sourcename)
                destname = wcsdup(sourcename);
            else if ((p = wcsrchr(sourcedir, '\\')))
                destname = wcsdup(p + 1);
            else
                destname = wcsdup(sourcedir);
            if (!destname)
                goto done;
        }
    }
    else
    {
        destname = wcsdup(MSI_RecordGetString(rec, 4));
        if (destname) msi_reduce_to_long_filename(destname);
    }

    size = 0;
    if (destname)
        size = lstrlenW(destname);

    size += lstrlenW(destdir) + 2;
    dest = malloc(size * sizeof(WCHAR));
    if (!dest)
        goto done;

    lstrcpyW(dest, destdir);
    if (dest[lstrlenW(dest) - 1] != '\\')
        lstrcatW(dest, L"\\");

    if (destname)
        lstrcatW(dest, destname);

    if (msi_get_file_attributes( package, destdir ) == INVALID_FILE_ATTRIBUTES)
    {
        if (!msi_create_full_path( package, destdir ))
        {
            WARN( "failed to create directory %lu\n", GetLastError() );
            goto done;
        }
    }

    if (!wildcards)
        move_file( package, source, dest, options );
    else
        move_files_wildcard( package, source, dest, options );

done:
    uirow = MSI_CreateRecord( 9 );
    MSI_RecordSetStringW( uirow, 1, MSI_RecordGetString(rec, 1) );
    MSI_RecordSetInteger( uirow, 6, 1 ); /* FIXME */
    MSI_RecordSetStringW( uirow, 9, destdir );
    MSI_ProcessMessage(package, INSTALLMESSAGE_ACTIONDATA, uirow);
    msiobj_release( &uirow->hdr );

    free(sourcedir);
    free(destdir);
    free(destname);
    free(source);
    free(dest);

    return ERROR_SUCCESS;
}

UINT ACTION_MoveFiles( MSIPACKAGE *package )
{
    MSIQUERY *view;
    UINT rc;

    if (package->script == SCRIPT_NONE)
        return msi_schedule_action(package, SCRIPT_INSTALL, L"MoveFiles");

    rc = MSI_DatabaseOpenViewW(package->db, L"SELECT * FROM `MoveFile`", &view);
    if (rc != ERROR_SUCCESS)
        return ERROR_SUCCESS;

    rc = MSI_IterateRecords(view, NULL, ITERATE_MoveFiles, package);
    msiobj_release(&view->hdr);
    return rc;
}

static WCHAR *get_duplicate_filename( MSIPACKAGE *package, MSIRECORD *row, const WCHAR *file_key, const WCHAR *src )
{
    DWORD len;
    WCHAR *dst_name, *dst_path, *dst;

    if (MSI_RecordIsNull( row, 4 ))
    {
        len = lstrlenW( src ) + 1;
        if (!(dst_name = malloc( len * sizeof(WCHAR)))) return NULL;
        lstrcpyW( dst_name, wcsrchr( src, '\\' ) + 1 );
    }
    else
    {
        MSI_RecordGetStringW( row, 4, NULL, &len );
        if (!(dst_name = malloc( ++len * sizeof(WCHAR) ))) return NULL;
        MSI_RecordGetStringW( row, 4, dst_name, &len );
        msi_reduce_to_long_filename( dst_name );
    }

    if (MSI_RecordIsNull( row, 5 ))
    {
        WCHAR *p;
        dst_path = wcsdup( src );
        p = wcsrchr( dst_path, '\\' );
        if (p) *p = 0;
    }
    else
    {
        const WCHAR *dst_key = MSI_RecordGetString( row, 5 );

        dst_path = wcsdup( msi_get_target_folder( package, dst_key ) );
        if (!dst_path)
        {
            /* try a property */
            dst_path = msi_dup_property( package->db, dst_key );
            if (!dst_path)
            {
                FIXME("Unable to get destination folder, try AppSearch properties\n");
                free( dst_name );
                return NULL;
            }
        }
    }

    dst = msi_build_directory_name( 2, dst_path, dst_name );
    msi_create_full_path( package, dst_path );

    free( dst_name );
    free( dst_path );
    return dst;
}

static UINT ITERATE_DuplicateFiles(MSIRECORD *row, LPVOID param)
{
    MSIPACKAGE *package = param;
    LPWSTR dest;
    LPCWSTR file_key, component;
    MSICOMPONENT *comp;
    MSIRECORD *uirow;
    MSIFILE *file;

    component = MSI_RecordGetString(row,2);
    comp = msi_get_loaded_component(package, component);
    if (!comp)
        return ERROR_SUCCESS;

    comp->Action = msi_get_component_action( package, comp );
    if (comp->Action != INSTALLSTATE_LOCAL)
    {
        TRACE("component not scheduled for installation %s\n", debugstr_w(component));
        return ERROR_SUCCESS;
    }

    file_key = MSI_RecordGetString(row,3);
    if (!file_key)
    {
        ERR("Unable to get file key\n");
        return ERROR_FUNCTION_FAILED;
    }

    file = msi_get_loaded_file( package, file_key );
    if (!file)
    {
        ERR("Original file unknown %s\n", debugstr_w(file_key));
        return ERROR_SUCCESS;
    }

    dest = get_duplicate_filename( package, row, file_key, file->TargetPath );
    if (!dest)
    {
        WARN("Unable to get duplicate filename\n");
        return ERROR_SUCCESS;
    }

    TRACE("Duplicating file %s to %s\n", debugstr_w(file->TargetPath), debugstr_w(dest));
    if (!msi_copy_file( package, file->TargetPath, dest, TRUE ))
    {
        WARN( "failed to copy file %s -> %s (%lu)\n",
              debugstr_w(file->TargetPath), debugstr_w(dest), GetLastError() );
    }
    FIXME("We should track these duplicate files as well\n");

    uirow = MSI_CreateRecord( 9 );
    MSI_RecordSetStringW( uirow, 1, MSI_RecordGetString( row, 1 ) );
    MSI_RecordSetInteger( uirow, 6, file->FileSize );
    MSI_RecordSetStringW( uirow, 9, MSI_RecordGetString( row, 5 ) );
    MSI_ProcessMessage(package, INSTALLMESSAGE_ACTIONDATA, uirow);
    msiobj_release( &uirow->hdr );

    free(dest);
    return ERROR_SUCCESS;
}

UINT ACTION_DuplicateFiles(MSIPACKAGE *package)
{
    MSIQUERY *view;
    UINT rc;

    if (package->script == SCRIPT_NONE)
        return msi_schedule_action(package, SCRIPT_INSTALL, L"DuplicateFiles");

    rc = MSI_DatabaseOpenViewW(package->db, L"SELECT * FROM `DuplicateFile`", &view);
    if (rc != ERROR_SUCCESS)
        return ERROR_SUCCESS;

    rc = MSI_IterateRecords(view, NULL, ITERATE_DuplicateFiles, package);
    msiobj_release(&view->hdr);
    return rc;
}

static UINT ITERATE_RemoveDuplicateFiles( MSIRECORD *row, LPVOID param )
{
    MSIPACKAGE *package = param;
    LPWSTR dest;
    LPCWSTR file_key, component;
    MSICOMPONENT *comp;
    MSIRECORD *uirow;
    MSIFILE *file;

    component = MSI_RecordGetString( row, 2 );
    comp = msi_get_loaded_component( package, component );
    if (!comp)
        return ERROR_SUCCESS;

    comp->Action = msi_get_component_action( package, comp );
    if (comp->Action != INSTALLSTATE_ABSENT)
    {
        TRACE("component not scheduled for removal %s\n", debugstr_w(component));
        return ERROR_SUCCESS;
    }

    file_key = MSI_RecordGetString( row, 3 );
    if (!file_key)
    {
        ERR("Unable to get file key\n");
        return ERROR_FUNCTION_FAILED;
    }

    file = msi_get_loaded_file( package, file_key );
    if (!file)
    {
        ERR("Original file unknown %s\n", debugstr_w(file_key));
        return ERROR_SUCCESS;
    }

    dest = get_duplicate_filename( package, row, file_key, file->TargetPath );
    if (!dest)
    {
        WARN("Unable to get duplicate filename\n");
        return ERROR_SUCCESS;
    }

    TRACE("Removing duplicate %s of %s\n", debugstr_w(dest), debugstr_w(file->TargetPath));
    if (!msi_delete_file( package, dest ))
    {
        WARN( "failed to delete duplicate file %s (%lu)\n", debugstr_w(dest), GetLastError() );
    }

    uirow = MSI_CreateRecord( 9 );
    MSI_RecordSetStringW( uirow, 1, MSI_RecordGetString( row, 1 ) );
    MSI_RecordSetStringW( uirow, 9, MSI_RecordGetString( row, 5 ) );
    MSI_ProcessMessage(package, INSTALLMESSAGE_ACTIONDATA, uirow);
    msiobj_release( &uirow->hdr );

    free(dest);
    return ERROR_SUCCESS;
}

UINT ACTION_RemoveDuplicateFiles( MSIPACKAGE *package )
{
    MSIQUERY *view;
    UINT rc;

    if (package->script == SCRIPT_NONE)
        return msi_schedule_action(package, SCRIPT_INSTALL, L"RemoveDuplicateFiles");

    rc = MSI_DatabaseOpenViewW( package->db, L"SELECT * FROM `DuplicateFile`", &view );
    if (rc != ERROR_SUCCESS)
        return ERROR_SUCCESS;

    rc = MSI_IterateRecords( view, NULL, ITERATE_RemoveDuplicateFiles, package );
    msiobj_release( &view->hdr );
    return rc;
}

static BOOL verify_comp_for_removal(MSICOMPONENT *comp, UINT install_mode)
{
    /* special case */
    if (comp->Action != INSTALLSTATE_SOURCE &&
        comp->Attributes & msidbComponentAttributesSourceOnly &&
        (install_mode == msidbRemoveFileInstallModeOnRemove ||
         install_mode == msidbRemoveFileInstallModeOnBoth)) return TRUE;

    switch (comp->Action)
    {
    case INSTALLSTATE_LOCAL:
    case INSTALLSTATE_SOURCE:
        if (install_mode == msidbRemoveFileInstallModeOnInstall ||
            install_mode == msidbRemoveFileInstallModeOnBoth) return TRUE;
        break;
    case INSTALLSTATE_ABSENT:
        if (install_mode == msidbRemoveFileInstallModeOnRemove ||
            install_mode == msidbRemoveFileInstallModeOnBoth) return TRUE;
        break;
    default: break;
    }
    return FALSE;
}

static UINT ITERATE_RemoveFiles(MSIRECORD *row, LPVOID param)
{
    MSIPACKAGE *package = param;
    MSICOMPONENT *comp;
    MSIRECORD *uirow;
    LPCWSTR component, dirprop;
    UINT install_mode;
    LPWSTR dir = NULL, path = NULL, filename = NULL;
    DWORD size;
    UINT ret = ERROR_SUCCESS;

    component = MSI_RecordGetString(row, 2);
    dirprop = MSI_RecordGetString(row, 4);
    install_mode = MSI_RecordGetInteger(row, 5);

    comp = msi_get_loaded_component(package, component);
    if (!comp)
        return ERROR_SUCCESS;

    comp->Action = msi_get_component_action( package, comp );
    if (!verify_comp_for_removal(comp, install_mode))
    {
        TRACE("Skipping removal due to install mode\n");
        return ERROR_SUCCESS;
    }
    if (comp->assembly && !comp->assembly->application)
    {
        return ERROR_SUCCESS;
    }
    if (comp->Attributes & msidbComponentAttributesPermanent)
    {
        TRACE("permanent component, not removing file\n");
        return ERROR_SUCCESS;
    }

    dir = msi_dup_property(package->db, dirprop);
    if (!dir)
    {
        WARN("directory property has no value\n");
        return ERROR_SUCCESS;
    }
    size = 0;
    if ((filename = wcsdup( MSI_RecordGetString(row, 3) )))
    {
        msi_reduce_to_long_filename( filename );
        size = lstrlenW( filename );
    }
    size += lstrlenW(dir) + 2;
    path = malloc(size * sizeof(WCHAR));
    if (!path)
    {
        ret = ERROR_OUTOFMEMORY;
        goto done;
    }

    if (filename)
    {
        lstrcpyW(path, dir);
        PathAddBackslashW(path);
        lstrcatW(path, filename);

        TRACE("Deleting misc file: %s\n", debugstr_w(path));
        msi_delete_file( package, path );
    }
    else
    {
        TRACE("Removing misc directory: %s\n", debugstr_w(dir));
        msi_remove_directory( package, dir );
    }

done:
    uirow = MSI_CreateRecord( 9 );
    MSI_RecordSetStringW( uirow, 1, MSI_RecordGetString(row, 1) );
    MSI_RecordSetStringW( uirow, 9, dir );
    MSI_ProcessMessage(package, INSTALLMESSAGE_ACTIONDATA, uirow);
    msiobj_release( &uirow->hdr );

    free(filename);
    free(path);
    free(dir);
    return ret;
}

static void remove_folder( MSIFOLDER *folder )
{
    FolderList *fl;

    LIST_FOR_EACH_ENTRY( fl, &folder->children, FolderList, entry )
    {
        remove_folder( fl->folder );
    }
    if (!folder->persistent && folder->State != FOLDER_STATE_REMOVED)
    {
        if (RemoveDirectoryW( folder->ResolvedTarget )) folder->State = FOLDER_STATE_REMOVED;
    }
}

/* Directories that belong to the system or to the user, never to a product. The Directory table
 * names them as the parents of the product's own directories (usually with DefaultDir "."). */
static const WCHAR * const system_folder_names[] =
{
    L"TARGETDIR", L"ROOTDRIVE", L"AdminToolsFolder", L"AppDataFolder", L"CommonAppDataFolder",
    L"CommonFilesFolder", L"CommonFiles64Folder", L"DesktopFolder", L"FavoritesFolder", L"FontsFolder",
    L"LocalAppDataFolder", L"MyPicturesFolder", L"NetHoodFolder", L"PersonalFolder", L"PrintHoodFolder",
    L"ProgramFilesFolder", L"ProgramFiles64Folder", L"ProgramMenuFolder", L"RecentFolder", L"SendToFolder",
    L"StartMenuFolder", L"StartupFolder", L"System16Folder", L"SystemFolder", L"System64Folder",
    L"TempFolder", L"TemplateFolder", L"WindowsFolder", L"WindowsVolume",
};

static BOOL same_folder_path( const WCHAR *a, const WCHAR *b )
{
    size_t la = lstrlenW( a ), lb = lstrlenW( b );

    while (la && a[la - 1] == '\\') la--;
    while (lb && b[lb - 1] == '\\') lb--;
    return la == lb && !_wcsnicmp( a, b, la );
}

/* a folder the removal of empty directories must never touch */
static BOOL is_protected_folder( MSIPACKAGE *package, MSIFOLDER *folder )
{
    UINT i;

    if (!folder->Parent || !folder->Parent[0]) return TRUE;                  /* root of the tree */
    if (!folder->TargetDefault || !folder->TargetDefault[0]) return TRUE;    /* same path as its parent */
    if (!folder->ResolvedTarget || lstrlenW( folder->ResolvedTarget ) <= 3) return TRUE; /* drive root */
    if (folder->persistent) return TRUE;                                     /* CreateFolder, RemoveFolders owns it */

    for (i = 0; i < ARRAY_SIZE(system_folder_names); i++)
    {
        WCHAR *path;
        BOOL same;

        if (!wcsicmp( folder->Directory, system_folder_names[i] )) return TRUE;
        /* TARGETDIR is the root of the tree, but for an installed product it is resolved to the
           InstallLocation, which is the product's own directory (INSTALLLOCATION): it must not
           protect that one. The drive root check above covers the real root. */
        if (!wcsicmp( system_folder_names[i], L"TARGETDIR" ) || !wcsicmp( system_folder_names[i], L"ROOTDRIVE" )) continue;
        if (!(path = msi_dup_property( package->db, system_folder_names[i] ))) continue;
        same = same_folder_path( path, folder->ResolvedTarget );
        free( path );
        if (same) return TRUE;
    }
    return FALSE;
}

/* a folder that a component that stays installed, or is being installed, lives in. A component
 * that gets no action and was never installed (it belongs to a feature that was not installed,
 * e.g. ADDLOCAL named other features) does not keep its directory. */
static BOOL is_folder_in_use( MSIPACKAGE *package, MSIFOLDER *folder )
{
    MSICOMPONENT *comp;

    LIST_FOR_EACH_ENTRY( comp, &package->components, MSICOMPONENT, entry )
    {
        if (!comp->Directory || wcscmp( comp->Directory, folder->Directory )) continue;

        switch (msi_get_component_action( package, comp ))
        {
        case INSTALLSTATE_ABSENT:
            break;
        case INSTALLSTATE_LOCAL:
        case INSTALLSTATE_SOURCE:
            return TRUE;
        default:
            if (comp->Installed == INSTALLSTATE_LOCAL || comp->Installed == INSTALLSTATE_SOURCE) return TRUE;
            break;
        }
    }
    return FALSE;
}

/* "path" is a directory strictly below "base" */
static BOOL is_below_folder( const WCHAR *path, const WCHAR *base )
{
    size_t len = lstrlenW( base );

    while (len && base[len - 1] == '\\') len--;
    return len && !_wcsnicmp( path, base, len ) && path[len] == '\\';
}

/* Windows removes the directories a product used when they are empty afterwards: the directory
 * itself and the chain of parent directories of the Directory table up to, but not including, a
 * system folder. RemoveDirectory fails on one that still has content, which ends the walk. */
void msi_remove_empty_folders( MSIPACKAGE *package, MSIFOLDER *folder, BOOL include_self )
{
    MSIFOLDER *next;

    while (folder)
    {
        if (!include_self)
        {
            if (!folder->Parent || !(next = msi_get_loaded_folder( package, folder->Parent )) || next == folder) return;
            if (!folder->ResolvedTarget || !next->ResolvedTarget) return;
            if (!is_below_folder( folder->ResolvedTarget, next->ResolvedTarget )) return;
            folder = next;
        }
        include_self = FALSE;

        if (is_protected_folder( package, folder ) || is_folder_in_use( package, folder )) return;
        if (folder->State != FOLDER_STATE_REMOVED)
        {
            if (!msi_remove_directory( package, folder->ResolvedTarget )) return;
            folder->State = FOLDER_STATE_REMOVED;
        }
    }
}

UINT ACTION_RemoveFiles( MSIPACKAGE *package )
{
    MSIQUERY *view;
    MSICOMPONENT *comp;
    MSIFILE *file;
    UINT r;

    if (package->script == SCRIPT_NONE)
        return msi_schedule_action(package, SCRIPT_INSTALL, L"RemoveFiles");

    r = MSI_DatabaseOpenViewW(package->db, L"SELECT * FROM `RemoveFile`", &view);
    if (r == ERROR_SUCCESS)
    {
        r = MSI_IterateRecords(view, NULL, ITERATE_RemoveFiles, package);
        msiobj_release(&view->hdr);
        if (r != ERROR_SUCCESS)
            return r;
    }

    LIST_FOR_EACH_ENTRY( file, &package->files, MSIFILE, entry )
    {
        MSIRECORD *uirow;
        VS_FIXEDFILEINFO *ver;

        comp = file->Component;
        file_update_ui( package, file, L"RemoveFiles" );

        comp->Action = msi_get_component_action( package, comp );
        if (comp->Action != INSTALLSTATE_ABSENT || comp->Installed == INSTALLSTATE_SOURCE)
            continue;

        if (comp->assembly && !comp->assembly->application)
            continue;

        if (comp->Attributes & msidbComponentAttributesPermanent)
        {
            TRACE("permanent component, not removing file\n");
            continue;
        }

        if (file->Version)
        {
            ver = msi_get_disk_file_version( package, file->TargetPath );
            if (ver && msi_compare_file_versions( ver, file->Version ) > 0)
            {
                TRACE("newer version detected, not removing file\n");
                free( ver );
                continue;
            }
            free( ver );
        }

        if (file->state == msifs_installed)
            WARN("removing installed file %s\n", debugstr_w(file->TargetPath));

        TRACE("removing %s\n", debugstr_w(file->File) );

        msi_set_file_attributes( package, file->TargetPath, FILE_ATTRIBUTE_NORMAL );
        if (!msi_delete_file( package, file->TargetPath ))
        {
            WARN( "failed to delete %s (%lu)\n",  debugstr_w(file->TargetPath), GetLastError() );
        }
        file->state = msifs_missing;

        uirow = MSI_CreateRecord( 9 );
        MSI_RecordSetStringW( uirow, 1, file->FileName );
        MSI_RecordSetStringW( uirow, 9, comp->Directory );
        MSI_ProcessMessage(package, INSTALLMESSAGE_ACTIONDATA, uirow);
        msiobj_release( &uirow->hdr );
    }

    LIST_FOR_EACH_ENTRY( comp, &package->components, MSICOMPONENT, entry )
    {
        comp->Action = msi_get_component_action( package, comp );
        if (comp->Action != INSTALLSTATE_ABSENT) continue;

        if (comp->Attributes & msidbComponentAttributesPermanent)
        {
            TRACE("permanent component, not removing directory\n");
            continue;
        }
        if (comp->assembly && !comp->assembly->application)
            msi_uninstall_assembly( package, comp );
        else
        {
            MSIFOLDER *folder = msi_get_loaded_folder( package, comp->Directory );
            if (folder)
            {
                remove_folder( folder );
                msi_remove_empty_folders( package, folder, FALSE );
            }
        }
    }
    return ERROR_SUCCESS;
}
