/*
 * Copyright 2010 Louis Lenders
 * Copyright 2012 Hans Leidekker for CodeWeavers
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

#define COBJMACROS

#include <stdio.h>
#include <stdlib.h>
#include "windows.h"
#include "ocidl.h"
#include "initguid.h"
#include "objidl.h"
#include "wbemcli.h"
#include "wmic.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wmic);

/* Aliases. "brief" is the property list of "list brief" (all properties when NULL). "fullskip" names a
 * property that "list" and "list full" leave out; Windows' PAGEFILE alias does that with Caption. */
static const struct
{
    const WCHAR *alias;
    const WCHAR *class;
    const WCHAR *brief;
    const WCHAR *fullskip;
}
alias_map[] =
{
    { L"bios", L"Win32_BIOS", NULL, NULL },
    { L"computersystem", L"Win32_ComputerSystem", NULL, NULL },
    { L"cpu", L"Win32_Processor", L"Caption,DeviceID,Manufacturer,MaxClockSpeed,Name,SocketDesignation", NULL },
    { L"LogicalDisk", L"Win32_LogicalDisk", NULL, NULL },
    { L"nic", L"Win32_NetworkAdapter", NULL, NULL },
    { L"os", L"Win32_OperatingSystem", NULL, NULL },
    { L"pagefile", L"Win32_PageFileUsage", L"Caption,Name,PeakUsage", L"Caption" },
    { L"process", L"Win32_Process", NULL, NULL },
};

enum format { FORMAT_TABLE, FORMAT_LIST, FORMAT_CSV };

static const WCHAR *find_alias( const WCHAR *alias, int *index )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(alias_map); i++)
    {
        if (!_wcsicmp( alias, alias_map[i].alias ))
        {
            *index = i;
            return alias_map[i].class;
        }
    }
    return NULL;
}

static WCHAR *strdupW( const WCHAR *src )
{
    WCHAR *dst;
    if (!src) return NULL;
    if (!(dst = HeapAlloc( GetProcessHeap(), 0, (lstrlenW( src ) + 1) * sizeof(WCHAR) ))) return NULL;
    lstrcpyW( dst, src );
    return dst;
}

/* output: the console as text, a file as UTF-16 (with a byte order mark when it is empty), a pipe in the OEM code page */

static void write_out( HANDLE handle, const WCHAR *str, int len )
{
    static int started;
    DWORD count, mode, type = GetFileType( handle );
    char *buf;
    int n;

    if (!len) return;
    if (GetConsoleMode( handle, &mode ))
    {
        WriteConsoleW( handle, str, len, &count, NULL );
        return;
    }
    if (type == FILE_TYPE_DISK)
    {
        if (!started && SetFilePointer( handle, 0, NULL, FILE_CURRENT ) == 0)
        {
            static const WCHAR bom = 0xfeff;
            WriteFile( handle, &bom, sizeof(bom), &count, NULL );
        }
        started = 1;
        WriteFile( handle, str, len * sizeof(WCHAR), &count, NULL );
        return;
    }
    n = WideCharToMultiByte( CP_OEMCP, 0, str, len, NULL, 0, NULL, NULL );
    if (n > 0 && (buf = HeapAlloc( GetProcessHeap(), 0, n )))
    {
        WideCharToMultiByte( CP_OEMCP, 0, str, len, buf, n, NULL, NULL );
        WriteFile( handle, buf, n, &count, NULL );
        HeapFree( GetProcessHeap(), 0, buf );
    }
}

static void output_text( const WCHAR *str )
{
    write_out( GetStdHandle(STD_OUTPUT_HANDLE), str, lstrlenW( str ) );
}

static void output_error_text( const WCHAR *str )
{
    write_out( GetStdHandle(STD_ERROR_HANDLE), str, lstrlenW( str ) );
}

static int output_error( int msg )
{
    WCHAR buffer[8192];

    LoadStringW( GetModuleHandleW(NULL), msg, buffer, ARRAY_SIZE(buffer) );
    output_error_text( buffer );
    return 1;
}

/* values */

static WCHAR *array_to_string( SAFEARRAY *sa )
{
    VARTYPE vt;
    LONG lo, hi, i;
    WCHAR *ret, *p;
    SIZE_T size;

    if (SafeArrayGetDim( sa ) != 1 || FAILED(SafeArrayGetVartype( sa, &vt ))) return strdupW( L"" );
    SafeArrayGetLBound( sa, 1, &lo );
    SafeArrayGetUBound( sa, 1, &hi );
    size = 4;
    for (i = lo; i <= hi; i++) size += 32;
    if (vt == VT_BSTR)
    {
        size = 4;
        for (i = lo; i <= hi; i++)
        {
            BSTR b = NULL;
            if (SUCCEEDED(SafeArrayGetElement( sa, &i, &b )) && b) size += SysStringLen( b ) + 4;
            SysFreeString( b );
        }
    }
    if (!(ret = HeapAlloc( GetProcessHeap(), 0, size * sizeof(WCHAR) ))) return NULL;
    p = ret;
    *p++ = '{';
    for (i = lo; i <= hi; i++)
    {
        if (i > lo) *p++ = ',';
        if (vt == VT_BSTR)
        {
            BSTR b = NULL;
            *p++ = '"';
            if (SUCCEEDED(SafeArrayGetElement( sa, &i, &b )) && b)
            {
                lstrcpyW( p, b );
                p += lstrlenW( p );
            }
            SysFreeString( b );
            *p++ = '"';
        }
        else
        {
            LONGLONG n = 0;
            switch (vt)
            {
            case VT_I1: case VT_UI1: { BYTE v = 0; SafeArrayGetElement( sa, &i, &v ); n = v; break; }
            case VT_I2: { SHORT v = 0; SafeArrayGetElement( sa, &i, &v ); n = v; break; }
            case VT_UI2: { USHORT v = 0; SafeArrayGetElement( sa, &i, &v ); n = v; break; }
            case VT_I4: { LONG v = 0; SafeArrayGetElement( sa, &i, &v ); n = v; break; }
            case VT_UI4: { ULONG v = 0; SafeArrayGetElement( sa, &i, &v ); n = v; break; }
            default: break;
            }
            p += _snwprintf( p, 32, L"%I64d", n );
        }
    }
    *p++ = '}';
    *p = 0;
    return ret;
}

static WCHAR *value_to_string( VARIANT *v )
{
    VARIANT str;
    WCHAR *ret;

    if (V_VT(v) & VT_ARRAY)
        return (V_VT(v) & VT_BYREF) ? strdupW( L"" ) : array_to_string( V_ARRAY(v) );
    switch (V_VT(v))
    {
    case VT_NULL:
    case VT_EMPTY:
        return strdupW( L"" );
    case VT_BOOL:
        return strdupW( V_BOOL(v) ? L"TRUE" : L"FALSE" );
    }
    VariantInit( &str );
    if (FAILED(VariantChangeType( &str, v, 0, VT_BSTR )) || !V_BSTR(&str)) return strdupW( L"" );
    ret = strdupW( V_BSTR(&str) );
    VariantClear( &str );
    return ret;
}

/* the query result: column names and a grid of strings */

struct result
{
    WCHAR **cols;
    unsigned int ncols;
    WCHAR ***rows;
    unsigned int nrows, rowmax;
};

static int cmp_name( const void *a, const void *b )
{
    return _wcsicmp( *(WCHAR * const *)a, *(WCHAR * const *)b );
}

/* the non-system properties of an object, in alphabetical order as wmic lists them */
static BOOL get_names( IWbemClassObject *obj, WCHAR ***names, unsigned int *count )
{
    SAFEARRAY *sa;
    LONG i, last = -1;
    WCHAR **list;

    *names = NULL;
    *count = 0;
    if (IWbemClassObject_GetNames( obj, NULL, WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY, NULL, &sa ) != S_OK)
        return FALSE;
    SafeArrayGetUBound( sa, 1, &last );
    if (!(list = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, (last + 2) * sizeof(*list) )))
    {
        SafeArrayDestroy( sa );
        return FALSE;
    }
    for (i = 0; i <= last; i++)
    {
        BSTR str = NULL;
        if (SafeArrayGetElement( sa, &i, &str ) == S_OK && str) list[(*count)++] = strdupW( str );
        SysFreeString( str );
    }
    SafeArrayDestroy( sa );
    qsort( list, *count, sizeof(*list), cmp_name );
    *names = list;
    return TRUE;
}

static WCHAR *find_name( WCHAR **names, unsigned int count, const WCHAR *name )
{
    unsigned int i;
    for (i = 0; i < count; i++) if (!_wcsicmp( names[i], name )) return names[i];
    return NULL;
}

/* "a,b c" into a sorted, duplicate-free list of canonical property names; FALSE when one does not exist */
static BOOL resolve_props( const WCHAR *spec, BOOL strict, WCHAR **names, unsigned int ncount, const WCHAR *skip,
                           struct result *res )
{
    unsigned int i;
    WCHAR *copy, *tok, *end;

    if (!(res->cols = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, (ncount + 1) * sizeof(*res->cols) )))
        return FALSE;
    if (!spec)
    {
        for (i = 0; i < ncount; i++)
            if (!skip || _wcsicmp( names[i], skip )) res->cols[res->ncols++] = names[i];
        return TRUE;
    }
    if (!(copy = strdupW( spec ))) return FALSE;
    for (tok = copy; *tok; tok = end)
    {
        WCHAR *name;
        unsigned int k;

        while (*tok == ',' || *tok == ' ') tok++;
        for (end = tok; *end && *end != ',' && *end != ' '; end++) ;
        if (end == tok) break;
        if (*end) *end++ = 0;
        name = find_name( names, ncount, tok );
        if (!name && !strict) continue;   /* the alias lists a property this class lacks */
        if (!name) { HeapFree( GetProcessHeap(), 0, copy ); return FALSE; }
        for (k = 0; k < res->ncols; k++) if (res->cols[k] == name) break;
        if (k == res->ncols) res->cols[res->ncols++] = name;
    }
    HeapFree( GetProcessHeap(), 0, copy );
    qsort( res->cols, res->ncols, sizeof(*res->cols), cmp_name );
    return TRUE;
}

static int add_row( IWbemClassObject *obj, struct result *res )
{
    WCHAR **row;
    unsigned int i;

    if (res->nrows == res->rowmax)
    {
        unsigned int max = res->rowmax ? res->rowmax * 2 : 16;
        WCHAR ***rows = res->rows ? HeapReAlloc( GetProcessHeap(), 0, res->rows, max * sizeof(*rows) )
                                  : HeapAlloc( GetProcessHeap(), 0, max * sizeof(*rows) );
        if (!rows) return 0;
        res->rows = rows;
        res->rowmax = max;
    }
    if (!(row = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, (res->ncols + 1) * sizeof(*row) ))) return 0;
    for (i = 0; i < res->ncols; i++)
    {
        VARIANT v;

        VariantInit( &v );
        if (IWbemClassObject_Get( obj, res->cols[i], 0, &v, NULL, NULL ) == WBEM_S_NO_ERROR)
        {
            row[i] = value_to_string( &v );
            VariantClear( &v );
        }
        if (!row[i]) row[i] = strdupW( L"" );
    }
    res->rows[res->nrows++] = row;
    return 1;
}

/* output */

static void print_table( const struct result *res )
{
    unsigned int c, r, *width;
    WCHAR *line;
    size_t total = 0;

    if (!(width = HeapAlloc( GetProcessHeap(), 0, max( res->ncols, 1 ) * sizeof(*width) ))) return;
    for (c = 0; c < res->ncols; c++)
    {
        width[c] = lstrlenW( res->cols[c] );
        for (r = 0; r < res->nrows; r++) width[c] = max( width[c], (unsigned int)lstrlenW( res->rows[r][c] ) );
        width[c] += 2;
        total += width[c];
    }
    if (!(line = HeapAlloc( GetProcessHeap(), 0, (total + 3) * sizeof(WCHAR) ))) goto done;
    for (r = 0; r <= res->nrows; r++)
    {
        WCHAR *p = line;
        for (c = 0; c < res->ncols; c++)
        {
            const WCHAR *s = r ? res->rows[r - 1][c] : res->cols[c];
            unsigned int len = lstrlenW( s );
            memcpy( p, s, len * sizeof(WCHAR) );
            for (p += len; len < width[c]; len++) *p++ = ' ';
        }
        *p++ = '\r';
        *p++ = '\n';
        write_out( GetStdHandle(STD_OUTPUT_HANDLE), line, p - line );
    }
    HeapFree( GetProcessHeap(), 0, line );
done:
    HeapFree( GetProcessHeap(), 0, width );
}

static void print_list( const struct result *res )
{
    unsigned int c, r;

    output_text( L"\r\n\r\n" );
    for (r = 0; r < res->nrows; r++)
    {
        for (c = 0; c < res->ncols; c++)
        {
            output_text( res->cols[c] );
            output_text( L"=" );
            output_text( res->rows[r][c] );
            output_text( L"\r\n" );
        }
        output_text( L"\r\n\r\n" );
    }
}

static void print_csv( const struct result *res )
{
    unsigned int c, r;
    WCHAR node[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAY_SIZE(node);

    if (!GetComputerNameW( node, &size )) node[0] = 0;
    output_text( L"\r\nNode" );
    for (c = 0; c < res->ncols; c++)
    {
        output_text( L"," );
        output_text( res->cols[c] );
    }
    for (r = 0; r < res->nrows; r++)
    {
        output_text( L"\r\n" );
        output_text( node );
        for (c = 0; c < res->ncols; c++)
        {
            output_text( L"," );
            output_text( res->rows[r][c] );
        }
    }
}

static void free_result( struct result *res )
{
    unsigned int r, c;

    for (r = 0; r < res->nrows; r++)
    {
        for (c = 0; c < res->ncols; c++) HeapFree( GetProcessHeap(), 0, res->rows[r][c] );
        HeapFree( GetProcessHeap(), 0, res->rows[r] );
    }
    HeapFree( GetProcessHeap(), 0, res->rows );
    HeapFree( GetProcessHeap(), 0, res->cols );
}

/* SELECT * FROM class and print the properties named in props (NULL: all except skip) */
static int query_class( const WCHAR *class, const WCHAR *props, BOOL strict, const WCHAR *skip, enum format format )
{
    HRESULT hr;
    IWbemLocator *locator = NULL;
    IWbemServices *services = NULL;
    IEnumWbemClassObject *result = NULL;
    LONG flags = WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY;
    BSTR path = NULL, wql = NULL, query = NULL;
    IWbemClassObject *obj;
    WCHAR **names = NULL;
    unsigned int nnames = 0, i;
    struct result res = { 0 };
    ULONG count;
    int ret = -1;
    BOOL have_cols = FALSE;

    WINE_TRACE("%s, %s\n", debugstr_w(class), debugstr_w(props));

    CoInitialize( NULL );
    CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                          RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );

    hr = CoCreateInstance( &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator,
                           (void **)&locator );
    if (hr != S_OK) goto done;

    if (!(path = SysAllocString( L"ROOT\\CIMV2" ))) goto done;
    hr = IWbemLocator_ConnectServer( locator, path, NULL, NULL, NULL, 0, NULL, NULL, &services );
    if (hr != S_OK) goto done;

    if (!(query = SysAllocStringLen( NULL, lstrlenW( class ) + 14 ))) goto done;
    lstrcpyW( query, L"SELECT * FROM " );
    lstrcatW( query, class );

    if (!(wql = SysAllocString( L"WQL" ))) goto done;
    hr = IWbemServices_ExecQuery( services, wql, query, flags, NULL, &result );
    if (hr != S_OK) goto done;

    for (;;)
    {
        IEnumWbemClassObject_Next( result, WBEM_INFINITE, 1, &obj, &count );
        if (!count) break;

        if (!have_cols)
        {
            if (!get_names( obj, &names, &nnames ) || !resolve_props( props, strict, names, nnames, skip, &res ))
            {
                IWbemClassObject_Release( obj );
                output_error( STRING_INVALID_QUERY );
                goto done;
            }
            have_cols = TRUE;
        }
        add_row( obj, &res );
        IWbemClassObject_Release( obj );
    }
    if (!res.nrows)
    {
        output_error_text( L"No Instance(s) Available.\r\n" );
        ret = 0;
        goto done;
    }
    switch (format)
    {
    case FORMAT_LIST: print_list( &res ); break;
    case FORMAT_CSV: print_csv( &res ); break;
    default: print_table( &res ); break;
    }
    ret = 0;

done:
    free_result( &res );
    if (names)
    {
        for (i = 0; i < nnames; i++) HeapFree( GetProcessHeap(), 0, names[i] );
        HeapFree( GetProcessHeap(), 0, names );
    }
    if (result) IEnumWbemClassObject_Release( result );
    if (services) IWbemServices_Release( services );
    if (locator) IWbemLocator_Release( locator );
    SysFreeString( path );
    SysFreeString( query );
    SysFreeString( wql );
    CoUninitialize();
    return ret;
}

int wmain(int argc, WCHAR *argv[])
{
    const WCHAR *class, *props = NULL, *skip = NULL, *verb;
    WCHAR *proplist = NULL, **words;
    enum format format = FORMAT_TABLE;
    BOOL brief = FALSE, list = FALSE, explicit_format = FALSE;
    int i, first, nwords = 0, ai = -1, ret;
    SIZE_T len;

    if (!(words = HeapAlloc( GetProcessHeap(), 0, (argc + 1) * sizeof(*words) ))) return 1;

    /* the words of the command, and the switches; a switch may also follow the verb */
    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '/')
        {
            if (!_wcsnicmp( argv[i], L"/format:", 8 ) || !_wcsnicmp( argv[i], L"/value", 6 ))
            {
                const WCHAR *f = (argv[i][1] == 'v' || argv[i][1] == 'V') ? L"list" : argv[i] + 8;

                explicit_format = TRUE;
                if (!_wcsicmp( f, L"list" ) || !_wcsicmp( f, L"value" )) format = FORMAT_LIST;
                else if (!_wcsicmp( f, L"csv" )) format = FORMAT_CSV;
                else if (!_wcsicmp( f, L"table" )) format = FORMAT_TABLE;
                else WINE_FIXME( "format %s not supported\n", debugstr_w(f) );
            }
            else WINE_FIXME( "command line switch %s not supported\n", debugstr_w(argv[i]) );
            continue;
        }
        words[nwords++] = argv[i];
    }

    i = 0;
    if (i >= nwords)
        goto not_supported;

    if (!_wcsicmp( words[i], L"quit" ) || !_wcsicmp( words[i], L"exit" ))
        return 0;

    if (!_wcsicmp( words[i], L"class" ) || !_wcsicmp( words[i], L"context" ))
    {
        WINE_FIXME( "command %s not supported\n", debugstr_w(words[i]) );
        goto not_supported;
    }

    if (!_wcsicmp( words[i], L"path" ))
    {
        if (++i >= nwords)
        {
            output_error( STRING_INVALID_PATH );
            return 1;
        }
        class = words[i];
    }
    else
    {
        class = find_alias( words[i], &ai );
        if (!class)
        {
            output_error( STRING_ALIAS_NOT_FOUND );
            return 1;
        }
    }

    /* no verb: a table of all the properties */
    if (++i < nwords)
    {
        verb = words[i++];
        if (!_wcsicmp( verb, L"get" ))
        {
            if (i >= nwords) goto not_supported;
            first = i;
            for (len = 1; i < nwords; i++) len += lstrlenW( words[i] ) + 1;
            if (!(proplist = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) ))) return 1;
            proplist[0] = 0;
            for (i = first; i < nwords; i++)
            {
                if (proplist[0]) lstrcatW( proplist, L"," );
                lstrcatW( proplist, words[i] );
            }
        }
        else if (!_wcsicmp( verb, L"list" ))
        {
            list = TRUE;
            /* a bare LIST shows what LIST FULL does (checked against Windows 10: it lists all but Caption) */
            if (i < nwords)
            {
                if (!_wcsicmp( words[i], L"brief" )) brief = TRUE;
                else if (!_wcsicmp( words[i], L"full" )) brief = FALSE;
                else goto not_supported;
                i++;
            }
            if (i < nwords) goto not_supported;
            if (!brief && !explicit_format) format = FORMAT_LIST;
        }
        else goto not_supported;
    }

    if (ai >= 0 && list)
    {
        if (brief) props = alias_map[ai].brief;
        else skip = alias_map[ai].fullskip;
    }
    if (proplist) props = proplist;
    ret = query_class( class, props, proplist != NULL, skip, format );
    HeapFree( GetProcessHeap(), 0, proplist );
    HeapFree( GetProcessHeap(), 0, words );
    return ret;

not_supported:
    HeapFree( GetProcessHeap(), 0, words );
    return output_error( STRING_CMDLINE_NOT_SUPPORTED );
}
