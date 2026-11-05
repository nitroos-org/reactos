/*
 * Performance Data Helper (pdh.dll)
 *
 * Copyright 2007 Andrey Turkin
 * Copyright 2007 Hans Leidekker
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

#include <stdarg.h>
#include <stdlib.h>
#include <math.h>

#include "windef.h"
#include "winbase.h"

#include "pdh.h"
#include "pdhmsg.h"
#include "winperf.h"
#ifdef __REACTOS__
#include <wchar.h>
#include <winnls.h>
#endif

#include "wine/debug.h"
#include "wine/list.h"

#include "perfdata.h"

WINE_DEFAULT_DEBUG_CHANNEL(pdh);

static CRITICAL_SECTION pdh_handle_cs;
static CRITICAL_SECTION_DEBUG pdh_handle_cs_debug =
{
    0, 0, &pdh_handle_cs,
    { &pdh_handle_cs_debug.ProcessLocksList,
      &pdh_handle_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": pdh_handle_cs") }
};
static CRITICAL_SECTION pdh_handle_cs = { &pdh_handle_cs_debug, -1, 0, 0, 0, 0 };

static inline WCHAR *pdh_strdup_aw( const char *src )
{
    int len;
    WCHAR *dst;

    if (!src) return NULL;
    len = MultiByteToWideChar( CP_ACP, 0, src, -1, NULL, 0 );
    if ((dst = malloc( len * sizeof(WCHAR) ))) MultiByteToWideChar( CP_ACP, 0, src, -1, dst, len );
    return dst;
}

struct sample
{
    LONGLONG    first;      /* counter value */
    LONGLONG    second;     /* time stamp, or the denominator of a fraction */
    FILETIME    stamp;      /* local time of the sample */
    PDH_STATUS  status;     /* PDH_CSTATUS_* of the sample */
};

struct item
{
    WCHAR          *name;       /* instance name as the counter set lists it ("name#1") */
    struct sample   cur;
    struct sample   prev;
    BOOL            has_prev;   /* prev is valid: this instance was present in the previous collection */
};

struct counter
{
    DWORD           magic;                          /* signature */
    struct list     entry;                          /* list entry */
    WCHAR          *path;                           /* identifier */
    DWORD           type;                           /* counter type */
    DWORD           status;                         /* update status */
    LONG            scale;                          /* scale factor */
    LONG            defaultscale;                   /* default scale factor */
    DWORD_PTR       user;                           /* user data */
    DWORD_PTR       queryuser;                      /* query user data */
    LONGLONG        base;                           /* samples per second */
    FILETIME        stamp;                          /* time stamp */
    const struct perf_object_def  *object;          /* counter set */
    const struct perf_counter_def *def;             /* counter */
    WCHAR          *instance;                       /* instance name, NULL for single instance sets */
    DWORD           instance_index;                 /* "#n" of the instance name */
    struct sample   cur;                            /* newest sample */
    struct sample   prev;                           /* the one before, valid once collects >= 2 */
    DWORD           collects;                       /* number of collections since the counter was added */
    BOOL            multi;                          /* the instance is a wildcard pattern: one item per matching instance */
    WCHAR          *pattern;                        /* the pattern, as written between the parentheses */
    struct item    *items;                          /* items of a wildcard counter */
    DWORD           nitems;
};

#define PDH_MAGIC_COUNTER   0x50444831 /* 'PDH1' */

static struct counter *create_counter( void )
{
    struct counter *counter;

    if ((counter = calloc( 1, sizeof(struct counter) )))
    {
        counter->magic = PDH_MAGIC_COUNTER;
        return counter;
    }
    return NULL;
}

static void free_items( struct counter *counter )
{
    DWORD i;

    for (i = 0; i < counter->nitems; i++) free( counter->items[i].name );
    free( counter->items );
    counter->items = NULL;
    counter->nitems = 0;
}

static void destroy_counter( struct counter *counter )
{
    free_items( counter );
    free( counter->pattern );
    /* Ensure compiler doesn't optimize out the assignment with 0. */
    SecureZeroMemory( &counter->magic, sizeof( counter->magic ) );
    free( counter->path );
    free( counter->instance );
    free( counter );
}

#define PDH_MAGIC_QUERY     0x50444830 /* 'PDH0' */

struct query
{
    DWORD       magic;      /* signature */
    DWORD_PTR   user;       /* user data */
    HANDLE      thread;     /* collect thread */
    DWORD       interval;   /* collect interval */
    HANDLE      wait;       /* wait event */
    HANDLE      stop;       /* stop event */
    struct list counters;   /* counter list */
};

static struct query *create_query( void )
{
    struct query *query;

    if ((query = calloc( 1, sizeof(struct query) )))
    {
        query->magic = PDH_MAGIC_QUERY;
        list_init( &query->counters );
        return query;
    }
    return NULL;
}

static void destroy_query( struct query *query )
{
    /* Ensure compiler doesn't optimize out the assignment with 0. */
    SecureZeroMemory( &query->magic, sizeof( query->magic ) );
    free( query );
}

static BOOL is_local_machine( const WCHAR *name, DWORD len )
{
    WCHAR buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD buflen = ARRAY_SIZE(buf);

    if (!GetComputerNameW( buf, &buflen )) return FALSE;
    return len == buflen && !wcsnicmp( name, buf, buflen );
}

/* "\\HOST" or "HOST": is that this computer? PDH knows no other spelling ("localhost" and "." fail) */
static BOOL is_local_name( const WCHAR *machine )
{
    if (machine[0] == '\\') machine++;
    if (machine[0] == '\\') machine++;
    return is_local_machine( machine, lstrlenW( machine ) );
}

static WCHAR *dup_range( const WCHAR *s, size_t n )
{
    WCHAR *r = malloc( (n + 1) * sizeof(WCHAR) );
    if (r)
    {
        memcpy( r, s, n * sizeof(WCHAR) );
        r[n] = 0;
    }
    return r;
}

struct path_elements
{
    WCHAR *machine;     /* with the leading backslashes, or NULL */
    WCHAR *object;
    WCHAR *inst_raw;    /* text between the parentheses as given, or NULL */
    WCHAR *instance;    /* instance name without parent and "#n", or NULL */
    WCHAR *parent;
    DWORD  index;       /* "#n", 0 if none, ~0 if no instance */
    WCHAR *counter;
};

static void free_path( struct path_elements *pe )
{
    free( pe->machine );
    free( pe->object );
    free( pe->inst_raw );
    free( pe->instance );
    free( pe->parent );
    free( pe->counter );
    memset( pe, 0, sizeof(*pe) );
}

/* \[\\machine]\object[(instance)]\counter */
static PDH_STATUS parse_path( const WCHAR *path, struct path_elements *pe )
{
    const WCHAR *p = path, *end;

    memset( pe, 0, sizeof(*pe) );
    pe->index = ~0u;
    if (!path || *p != '\\') return PDH_INVALID_PATH;

    if (p[1] == '\\')
    {
        const WCHAR *e = wcschr( p + 2, '\\' );
        if (!e || e == p + 2) return PDH_INVALID_PATH;
        if (!(pe->machine = dup_range( p, e - p ))) goto nomem;
        p = e;
    }
    p++;
    for (end = p; *end && *end != '(' && *end != '\\'; end++) ;
    if (end == p) goto invalid;
    if (!(pe->object = dup_range( p, end - p ))) goto nomem;
    p = end;

    if (*p == '(')
    {
        const WCHAR *q, *close = NULL;
        WCHAR *inst, *slash, *hash;

        for (q = p + 1; *q; q++) if (q[0] == ')' && q[1] == '\\') close = q;
        if (!close) goto invalid;
        if (!(pe->inst_raw = dup_range( p + 1, close - p - 1 ))) goto nomem;
        if (!(inst = wcsdup( pe->inst_raw ))) goto nomem;
        if ((slash = wcschr( inst, '/' )))
        {
            *slash = 0;
            pe->parent = wcsdup( inst );
            memmove( inst, slash + 1, (lstrlenW( slash + 1 ) + 1) * sizeof(WCHAR) );
        }
        pe->index = 0;
        if ((hash = wcsrchr( inst, '#' )) && hash > inst && hash[-1] != ' ' && hash[1])
        {
            WCHAR *d;
            for (d = hash + 1; *d >= '0' && *d <= '9'; d++) ;
            if (!*d)
            {
                pe->index = wcstoul( hash + 1, NULL, 10 );
                *hash = 0;
            }
        }
        pe->instance = inst;
        p = close + 1;
    }
    if (*p != '\\') goto invalid;
    if (!(pe->counter = wcsdup( p + 1 ))) goto nomem;
    return ERROR_SUCCESS;

invalid:
    free_path( pe );
    return PDH_INVALID_PATH;
nomem:
    free_path( pe );
    return PDH_MEMORY_ALLOCATION_FAILURE;
}

static BOOL has_wildcard( const WCHAR *s )
{
    return s && (wcschr( s, '*' ) || wcschr( s, '?' ));
}

static BOOL wild_match( const WCHAR *pat, const WCHAR *str )
{
    for (; *pat; pat++, str++)
    {
        if (*pat == '*')
        {
            while (pat[1] == '*') pat++;
            if (!pat[1]) return TRUE;
            for (; *str; str++) if (wild_match( pat + 1, str )) return TRUE;
            return FALSE;
        }
        if (!*str) return FALSE;
        if (*pat != '?' && towlower( *pat ) != towlower( *str )) return FALSE;
    }
    return !*str;
}

static BOOL instance_exists( const struct perf_object_def *obj, const struct path_elements *pe )
{
    WCHAR **names, key[300];
    DWORD count, i;
    BOOL found = FALSE;

    if (perf_get_instances( obj, &names, &count )) return FALSE;
    key[0] = 0;
    if (pe->parent)   /* "process/thread": the instance name of a thread has its process in front */
    {
        lstrcpynW( key, pe->parent, ARRAY_SIZE(key) - 32 );
        lstrcatW( key, L"/" );
    }
    lstrcpynW( key + lstrlenW( key ), pe->instance, ARRAY_SIZE(key) - 16 - lstrlenW( key ) );
    if (pe->index && pe->index != ~0u)
    {
        WCHAR num[16];
        swprintf( num, ARRAY_SIZE(num), L"#%u", pe->index );
        lstrcatW( key, num );
    }
    for (i = 0; i < count && !found; i++) found = !wcsicmp( names[i], key );
    perf_free_instances( names, count );
    return found;
}

/* Checks a counter path against the counter sets. With add set, a missing instance is fine
 * (it may appear later) and wildcards are kept for the counter to resolve, as PdhAddCounter does. */
static PDH_STATUS check_path( const WCHAR *path, BOOL add, struct path_elements *pe,
                              const struct perf_object_def **pobj, const struct perf_counter_def **pdef )
{
    const struct perf_object_def *obj = NULL;
    const struct perf_counter_def *def = NULL;
    PDH_STATUS ret;

    if ((ret = parse_path( path, pe )))
        return ret == PDH_INVALID_PATH ? PDH_CSTATUS_BAD_COUNTERNAME : ret;
    if (pe->machine && !is_local_name( pe->machine )) return PDH_CSTATUS_NO_MACHINE;

    if (!wcscmp( pe->object, L"*" ) && !add)
    {
        DWORD i;
        for (i = 0; i < perf_object_count(); i++)
            if (has_wildcard( pe->counter ) || perf_find_counter( perf_object( i ), pe->counter )) return ERROR_SUCCESS;
        return PDH_CSTATUS_NO_COUNTER;
    }
    if (!(obj = perf_find_object( pe->object ))) return PDH_CSTATUS_NO_OBJECT;
    if (!has_wildcard( pe->counter ) || add)
    {
        if (!(def = perf_find_counter( obj, pe->counter ))) return PDH_CSTATUS_NO_COUNTER;
    }

    if (obj->kind == INST_NONE)
    {
        if (pe->instance) return add ? PDH_CSTATUS_BAD_COUNTERNAME : PDH_CSTATUS_NO_INSTANCE;
    }
    else
    {
        if (!pe->instance) return add ? PDH_CSTATUS_BAD_COUNTERNAME : PDH_CSTATUS_NO_INSTANCE;
        if (!add && !has_wildcard( pe->instance ) && !instance_exists( obj, pe )) return PDH_CSTATUS_NO_INSTANCE;
    }
    if (pobj) *pobj = obj;
    if (pdef) *pdef = def;
    return ERROR_SUCCESS;
}

/* a paging file name is \??\C:\pagefile.sys: its question marks are part of the name */
static BOOL is_pattern( const struct perf_object_def *obj, const WCHAR *s )
{
    return s && (wcschr( s, '*' ) || (obj->kind != INST_PAGE && wcschr( s, '?' )));
}

static void stamp_now( FILETIME *stamp )
{
    SYSTEMTIME time;

    GetLocalTime( &time );
    SystemTimeToFileTime( &time, stamp );
}

/* Windows hands the items out ordered by name, compared by code unit: "Idle" before "csrss", "0" before "_Total" */
static int __cdecl cmp_item( const void *a, const void *b )
{
    return wcscmp( ((const struct item *)a)->name, ((const struct item *)b)->name );
}

/* One item per instance that matches the pattern, taken from the instances present now. An instance that was
 * present at the previous collection keeps that sample, so that rates can be calculated for it. */
static void sample_multi( struct counter *counter )
{
    struct item *old = counter->items, *items = NULL;
    DWORD nold = counter->nitems, n = 0, count = 0, i, k;
    WCHAR **names = NULL;
    FILETIME stamp;

    counter->items = NULL;
    counter->nitems = 0;
    stamp_now( &stamp );
    if (!perf_get_instances( counter->object, &names, &count ) && count && (items = calloc( count, sizeof(*items) )))
    {
        for (i = 0; i < count; i++)
        {
            struct item *it = &items[n];

            if (!wild_match( counter->pattern, names[i] )) continue;
            if (!(it->name = wcsdup( names[i] ))) continue;
            it->cur.status = perf_fetch( counter->object, counter->def, names[i], 0, &it->cur.first, &it->cur.second );
            it->cur.stamp = stamp;
            for (k = 0; k < nold; k++)
            {
                if (!wcsicmp( old[k].name, it->name ))
                {
                    if (counter->collects >= 2)
                    {
                        it->prev = old[k].cur;
                        it->has_prev = TRUE;
                    }
                    break;
                }
            }
            n++;
        }
    }
    if (names) perf_free_instances( names, count );
    if (n > 1) qsort( items, n, sizeof(*items), cmp_item );   /* by name, as Windows does */
    for (i = 0; i < nold; i++) free( old[i].name );
    free( old );
    counter->items = items;
    counter->nitems = n;
}

static void sample_counter( struct counter *counter, struct sample *sample )
{
    if (counter->multi)
    {
        sample_multi( counter );
        sample->first = sample->second = 0;
        sample->status = ERROR_SUCCESS;
    }
    else if (!counter->object)  /* a counter of another machine */
    {
        sample->first = sample->second = 0;
        sample->status = PDH_CSTATUS_NO_MACHINE;
    }
    else sample->status = perf_fetch( counter->object, counter->def, counter->instance, counter->instance_index,
                                      &sample->first, &sample->second );
    stamp_now( &sample->stamp );
}

/***********************************************************************
 *              PdhAddCounterA   (PDH.@)
 */
PDH_STATUS WINAPI PdhAddCounterA( PDH_HQUERY query, LPCSTR path,
                                  DWORD_PTR userdata, PDH_HCOUNTER *counter )
{
    PDH_STATUS ret;
    WCHAR *pathW;

    TRACE("%p %s %Ix %p\n", query, debugstr_a(path), userdata, counter);

    if (!path) return PDH_INVALID_ARGUMENT;

    if (!(pathW = pdh_strdup_aw( path )))
        return PDH_MEMORY_ALLOCATION_FAILURE;

    ret = PdhAddCounterW( query, pathW, userdata, counter );

    free( pathW );
    return ret;
}

/***********************************************************************
 *              PdhAddCounterW   (PDH.@)
 */
static PDH_STATUS add_counter( PDH_HQUERY hquery, LPCWSTR path, DWORD_PTR userdata, PDH_HCOUNTER *hcounter,
                               BOOL english )
{
    struct query *query = hquery;
    struct counter *counter;
    struct path_elements pe;
    const struct perf_object_def *obj = NULL;
    const struct perf_counter_def *def = NULL;
    PDH_STATUS ret;

    if (!path  || !hcounter) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!query || query->magic != PDH_MAGIC_QUERY)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    *hcounter = NULL;
    ret = check_path( path, TRUE, &pe, &obj, &def );
    /* PdhAddCounter accepts a counter of another machine (it never gets data), PdhAddEnglishCounter does not */
    if (ret && !(ret == PDH_CSTATUS_NO_MACHINE && !english))
    {
        free_path( &pe );
        LeaveCriticalSection( &pdh_handle_cs );
        return ret;
    }

    if (!(counter = create_counter()))
    {
        free_path( &pe );
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    counter->path           = wcsdup( path );
    counter->base           = PERF_TIME_BASE;
    counter->queryuser      = query->user;
    counter->user           = userdata;
    if (def)
    {
        counter->type           = def->type;
        counter->defaultscale   = def->defscale;
        counter->object         = obj;
        counter->def            = def;
        if (pe.instance && pe.parent)
        {
            counter->instance = malloc( (lstrlenW( pe.parent ) + lstrlenW( pe.instance ) + 2) * sizeof(WCHAR) );
            if (counter->instance)
            {
                lstrcpyW( counter->instance, pe.parent );
                lstrcatW( counter->instance, L"/" );
                lstrcatW( counter->instance, pe.instance );
            }
        }
        else counter->instance  = pe.instance ? wcsdup( pe.instance ) : NULL;
        counter->instance_index = pe.index == ~0u ? 0 : pe.index;
        if (obj->kind != INST_NONE && is_pattern( obj, pe.inst_raw ))
        {
            counter->multi   = TRUE;
            counter->pattern = wcsdup( pe.inst_raw );
        }
    }
    free_path( &pe );

    perf_next_generation();
    sample_counter( counter, &counter->cur );
    counter->stamp  = counter->cur.stamp;
    counter->status = counter->cur.status;

    list_add_tail( &query->counters, &counter->entry );
    *hcounter = counter;

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

PDH_STATUS WINAPI PdhAddCounterW( PDH_HQUERY hquery, LPCWSTR path,
                                  DWORD_PTR userdata, PDH_HCOUNTER *hcounter )
{
    TRACE("%p %s %Ix %p\n", hquery, debugstr_w(path), userdata, hcounter);
    return add_counter( hquery, path, userdata, hcounter, FALSE );
}

/***********************************************************************
 *              PdhAddEnglishCounterA   (PDH.@)
 */
PDH_STATUS WINAPI PdhAddEnglishCounterA( PDH_HQUERY query, LPCSTR path,
                                         DWORD_PTR userdata, PDH_HCOUNTER *counter )
{
    TRACE("%p %s %Ix %p\n", query, debugstr_a(path), userdata, counter);

    if (!counter) return PDH_INVALID_ARGUMENT;
    if (!query) return PDH_INVALID_HANDLE;
    {
        PDH_STATUS ret;
        WCHAR *pathW;

        if (!path) return PDH_INVALID_ARGUMENT;
        if (!(pathW = pdh_strdup_aw( path ))) return PDH_MEMORY_ALLOCATION_FAILURE;
        ret = PdhAddEnglishCounterW( query, pathW, userdata, counter );
        free( pathW );
        return ret;
    }
}

/***********************************************************************
 *              PdhAddEnglishCounterW   (PDH.@)
 */
PDH_STATUS WINAPI PdhAddEnglishCounterW( PDH_HQUERY query, LPCWSTR path,
                                         DWORD_PTR userdata, PDH_HCOUNTER *counter )
{
    TRACE("%p %s %Ix %p\n", query, debugstr_w(path), userdata, counter);

    if (!counter) return PDH_INVALID_ARGUMENT;
    if (!query) return PDH_INVALID_HANDLE;
    return add_counter( query, path, userdata, counter, TRUE );
}

/* caller must hold counter lock */

#define PDH_PRECISION_100NS_TIMER 0x20570500
#define PDH_QUEUELEN_100NS        0x00550500   /* PERF_COUNTER_100NS_QUEUELEN_TYPE */

static PDH_STATUS calc_value( DWORD type, const struct sample *cur, const struct sample *prev, DWORD format, double *out )
{
    double dt, d1;
    DWORD timer;

    *out = 0.0;
    switch (type)
    {
    case PERF_COUNTER_RAWCOUNT:
    case PERF_COUNTER_LARGE_RAWCOUNT:
        *out = (double)cur->first;
        return ERROR_SUCCESS;

    case PERF_RAW_FRACTION:
        if (cur->second <= 0) return PDH_CALC_NEGATIVE_DENOMINATOR;
        *out = 100.0 * (double)cur->first / (double)cur->second;
        break;

    case PERF_ELAPSED_TIME:
        *out = (double)(cur->second - cur->first) / PERF_TIME_BASE;
        if (*out < 0.0) *out = 0.0;
        return ERROR_SUCCESS;

    case PERF_COUNTER_COUNTER:
    case PERF_COUNTER_BULK_COUNT:
    case PERF_100NSEC_TIMER:
    case PERF_100NSEC_TIMER_INV:
    case PDH_PRECISION_100NS_TIMER:
    case PDH_QUEUELEN_100NS:
    case PERF_AVERAGE_TIMER:
    case PERF_AVERAGE_BULK:
        timer = type != PERF_COUNTER_COUNTER && type != PERF_COUNTER_BULK_COUNT;
        if (!prev) return PDH_INVALID_DATA;
        dt = (double)(cur->second - prev->second);
        d1 = (double)(cur->first - prev->first);
        if (dt <= 0.0) return PDH_CALC_NEGATIVE_DENOMINATOR;
        if (d1 < 0.0) return PDH_CALC_NEGATIVE_VALUE;
        if (!timer) *out = d1 * PERF_TIME_BASE / dt;
        else if (type == PDH_QUEUELEN_100NS) *out = d1 / dt;                    /* time integral over time */
        else if (type == PERF_AVERAGE_TIMER) *out = d1 / PERF_TIME_BASE / dt;           /* seconds per operation */
        else if (type == PERF_AVERAGE_BULK) *out = d1 / dt;                             /* amount per operation */
        else if (type == PERF_100NSEC_TIMER_INV) *out = 100.0 * (1.0 - d1 / dt);
        else *out = 100.0 * d1 / dt;
        if (*out < 0.0) *out = 0.0;
        break;

    default:
        FIXME("unhandled counter type %#lx\n", type);
        return PDH_INVALID_DATA;
    }
    if ((type & PERF_DISPLAY_PERCENT) && !(format & PDH_FMT_NOCAP100) && *out > 100.0) *out = 100.0;
    return ERROR_SUCCESS;
}

static PDH_STATUS format_value( struct counter *counter, DWORD format, const struct sample *cur,
                                const struct sample *prev, PDH_FMT_COUNTERVALUE *value )
{
    PDH_STATUS ret;
    double d;

    memset( value, 0, sizeof(*value) );
    if ((ret = cur->status))
    {
        value->CStatus = ret;
        return PDH_INVALID_DATA;
    }
    if ((ret = calc_value( counter->type, cur, prev, format, &d )))
    {
        value->CStatus = PDH_CSTATUS_INVALID_DATA;
        return ret;
    }
    if (format & PDH_FMT_1000) d *= 1000;
    if (!(format & PDH_FMT_NOSCALE) && counter->scale) d *= pow( 10, counter->scale );

    if (format & PDH_FMT_LONG) value->longValue = (LONG)d;
    else if (format & PDH_FMT_LARGE) value->largeValue = (LONGLONG)d;
    else if (format & PDH_FMT_DOUBLE) value->doubleValue = d;
    else
    {
        WARN("unknown format %lx\n", format);
        value->CStatus = PDH_CSTATUS_INVALID_DATA;
        return PDH_INVALID_ARGUMENT;
    }
    value->CStatus = PDH_CSTATUS_VALID_DATA;
    return ERROR_SUCCESS;
}

static void raw_to_sample( const PDH_RAW_COUNTER *raw, struct sample *sample )
{
    sample->first  = raw->FirstValue;
    sample->second = raw->SecondValue;
    sample->stamp  = raw->TimeStamp;
    sample->status = raw->CStatus;
}

/***********************************************************************
 *              PdhCalculateCounterFromRawValue   (PDH.@)
 */
PDH_STATUS WINAPI PdhCalculateCounterFromRawValue( PDH_HCOUNTER handle, DWORD format,
                                                   PPDH_RAW_COUNTER raw1, PPDH_RAW_COUNTER raw2,
                                                   PPDH_FMT_COUNTERVALUE value )
{
    PDH_STATUS ret;
    struct counter *counter = handle;
    struct sample cur, prev;

    TRACE("%p 0x%08lx %p %p %p\n", handle, format, raw1, raw2, value);

    if (!value || !raw1) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    raw_to_sample( raw1, &cur );
    if (raw2) raw_to_sample( raw2, &prev );
    ret = format_value( counter, format, &cur, raw2 ? &prev : NULL, value );

    LeaveCriticalSection( &pdh_handle_cs );
    return ret;
}

/***********************************************************************
 *              PdhFormatFromRawValue   (PDH.@)
 *
 * Calculates the value of a counter from two raw samples (raw1 is the newer one) without a query.
 * The .NET performance counter classes use it for every value they return.
 */
#ifndef PERF_OBJ_TIME_TIMER
#define PERF_OBJ_TIME_TIMER           0x20610500
#endif
#ifndef PERF_PRECISION_SYSTEM_TIMER
#define PERF_PRECISION_SYSTEM_TIMER   0x20470500
#endif
#ifndef PERF_PRECISION_100NS_TIMER
#define PERF_PRECISION_100NS_TIMER    0x20570500
#endif
#ifndef PERF_PRECISION_OBJECT_TIMER
#define PERF_PRECISION_OBJECT_TIMER   0x20670500
#endif
#ifndef PERF_LARGE_RAW_FRACTION
#define PERF_LARGE_RAW_FRACTION       0x20020500
#endif

static LONG to_long( double d )
{
    return (d >= 2147483648.0 || d <= -2147483649.0) ? (LONG)0x80000000 : (LONG)d;
}

static LONGLONG to_large( double d )
{
    return (d >= 9223372036854775808.0 || d <= -9223372036854777856.0) ? (LONGLONG)0x8000000000000000ULL : (LONGLONG)d;
}

PDH_STATUS WINAPI PdhFormatFromRawValue( DWORD type, DWORD format, LONGLONG *timebase, PPDH_RAW_COUNTER raw1,
                                         PPDH_RAW_COUNTER raw2, PPDH_FMT_COUNTERVALUE value )
{
    LONGLONG tb = timebase ? *timebase : 0;
    DWORD kind = format & (PDH_FMT_LONG | PDH_FMT_DOUBLE | PDH_FMT_LARGE);
    double d = 0.0, dt = 0.0, d1 = 0.0, first;
    BOOL cap = TRUE;
    PDH_STATUS ret = ERROR_SUCCESS;

    TRACE("%#lx %#lx %p %p %p %p\n", type, format, timebase, raw1, raw2, value);

    if (!value || !raw1) return PDH_INVALID_ARGUMENT;
    memset( value, 0, sizeof(*value) );
    if (kind != PDH_FMT_LONG && kind != PDH_FMT_DOUBLE && kind != PDH_FMT_LARGE) return PDH_INVALID_ARGUMENT;

    first = (double)raw1->FirstValue;
    switch (type)
    {
    case PERF_COUNTER_RAWCOUNT:
    case PERF_COUNTER_RAWCOUNT_HEX:
        d = (double)(DWORD)raw1->FirstValue;
        cap = FALSE;
        break;

    case PERF_COUNTER_LARGE_RAWCOUNT:
    case PERF_COUNTER_LARGE_RAWCOUNT_HEX:
        d = first;
        cap = FALSE;
        break;

    case PERF_RAW_FRACTION:
    case PERF_LARGE_RAW_FRACTION:
    {
        double num = type == PERF_RAW_FRACTION ? (double)(DWORD)raw1->FirstValue : first;
        double den = type == PERF_RAW_FRACTION ? (double)(DWORD)raw1->SecondValue : (double)raw1->SecondValue;
        d = den != 0.0 ? 100.0 * num / den : 0.0;
        break;
    }

    case PERF_COUNTER_COUNTER:
    case PERF_COUNTER_BULK_COUNT:
    case PERF_COUNTER_TIMER:
    case PERF_COUNTER_TIMER_INV:
    case PERF_100NSEC_TIMER:
    case PERF_100NSEC_TIMER_INV:
    case PERF_OBJ_TIME_TIMER:
    case PERF_SAMPLE_FRACTION:
    case PERF_PRECISION_SYSTEM_TIMER:
    case PERF_PRECISION_100NS_TIMER:
    case PERF_PRECISION_OBJECT_TIMER:
    case PERF_AVERAGE_TIMER:
    case PERF_AVERAGE_BULK:
    case PDH_QUEUELEN_100NS:
        if (!raw2)
        {
            value->CStatus = PDH_CSTATUS_INVALID_DATA;
            return PDH_CSTATUS_INVALID_DATA;
        }
        d1 = (double)(raw1->FirstValue - raw2->FirstValue);
        dt = (double)(raw1->SecondValue - raw2->SecondValue);
        if (dt < 0.0) ret = PDH_CALC_NEGATIVE_DENOMINATOR;
        else if (d1 < 0.0) ret = PDH_CALC_NEGATIVE_VALUE;
        else if (dt > 0.0)
        {
            switch (type)
            {
            case PERF_COUNTER_COUNTER:
            case PERF_COUNTER_BULK_COUNT:
                d = tb > 0 ? d1 / (dt / (double)tb) : 0.0;
                break;
            case PERF_AVERAGE_TIMER:
                d = tb > 0 ? d1 / (double)tb / dt : 0.0;
                break;
            case PERF_COUNTER_TIMER_INV:
            case PERF_100NSEC_TIMER_INV:
                d = 100.0 * (1.0 - d1 / dt);
                if (d < 0.0) ret = PDH_CALC_NEGATIVE_DENOMINATOR;
                break;
            case PERF_AVERAGE_BULK:
            case PDH_QUEUELEN_100NS:
                d = d1 / dt;
                break;
            default:
                d = 100.0 * d1 / dt;
                break;
            }
        }
        if (ret)
        {
            value->CStatus = ret;
            return ret;
        }
        break;

    case PERF_ELAPSED_TIME:
        d = tb > 0 ? (double)(raw1->SecondValue - raw1->FirstValue) / (double)tb : 0.0;
        if (d < 0.0) d = 0.0;
        cap = FALSE;
        break;

    default:
        FIXME("unhandled counter type %#lx\n", type);
        return PDH_FUNCTION_NOT_FOUND;
    }

    if (cap && (type & PERF_DISPLAY_PERCENT) && !(format & PDH_FMT_NOCAP100) && d > 100.0) d = 100.0;
    if (format & PDH_FMT_1000) d *= 1000;

    if (kind == PDH_FMT_LONG) value->longValue = to_long( d );
    else if (kind == PDH_FMT_LARGE) value->largeValue = to_large( d );
    else value->doubleValue = d;
    value->CStatus = PDH_CSTATUS_VALID_DATA;
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhCloseQuery   (PDH.@)
 */
PDH_STATUS WINAPI PdhCloseQuery( PDH_HQUERY handle )
{
    struct query *query = handle;
    struct list *item, *next;

    TRACE("%p\n", handle);

    EnterCriticalSection( &pdh_handle_cs );
    if (!query || query->magic != PDH_MAGIC_QUERY)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    if (query->thread)
    {
        HANDLE thread = query->thread;
        SetEvent( query->stop );
        LeaveCriticalSection( &pdh_handle_cs );

        WaitForSingleObject( thread, INFINITE );

        EnterCriticalSection( &pdh_handle_cs );
        if (query->magic != PDH_MAGIC_QUERY)
        {
            LeaveCriticalSection( &pdh_handle_cs );
            return ERROR_SUCCESS;
        }
        CloseHandle( query->stop );
        CloseHandle( query->thread );
        query->thread = NULL;
    }

    LIST_FOR_EACH_SAFE( item, next, &query->counters )
    {
        struct counter *counter = LIST_ENTRY( item, struct counter, entry );

        list_remove( &counter->entry );
        destroy_counter( counter );
    }

    destroy_query( query );

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/* caller must hold query lock */
static void collect_query_data( struct query *query )
{
    struct list *item;

    perf_next_generation();
    LIST_FOR_EACH( item, &query->counters )
    {
        struct counter *counter = LIST_ENTRY( item, struct counter, entry );

        if (counter->collects) counter->prev = counter->cur;
        counter->collects++;
        sample_counter( counter, &counter->cur );
        counter->stamp  = counter->cur.stamp;
        counter->status = counter->cur.status;
    }
}

/***********************************************************************
 *              PdhCollectQueryData   (PDH.@)
 */
PDH_STATUS WINAPI PdhCollectQueryData( PDH_HQUERY handle )
{
    struct query *query = handle;

    TRACE("%p\n", handle);

    EnterCriticalSection( &pdh_handle_cs );
    if (!query || query->magic != PDH_MAGIC_QUERY)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    if (list_empty( &query->counters ))
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_NO_DATA;
    }

    collect_query_data( query );

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

static DWORD CALLBACK collect_query_thread( void *arg )
{
    struct query *query = arg;
    DWORD interval = query->interval;
    HANDLE stop = query->stop;

    for (;;)
    {
        if (WaitForSingleObject( stop, interval ) != WAIT_TIMEOUT) ExitThread( 0 );

        EnterCriticalSection( &pdh_handle_cs );
        if (query->magic != PDH_MAGIC_QUERY)
        {
            LeaveCriticalSection( &pdh_handle_cs );
            ExitThread( PDH_INVALID_HANDLE );
        }

        collect_query_data( query );

        if (!SetEvent( query->wait ))
        {
            LeaveCriticalSection( &pdh_handle_cs );
            ExitThread( 0 );
        }
        LeaveCriticalSection( &pdh_handle_cs );
    }
}

/***********************************************************************
 *              PdhCollectQueryDataEx   (PDH.@)
 */
PDH_STATUS WINAPI PdhCollectQueryDataEx( PDH_HQUERY handle, DWORD interval, HANDLE event )
{
    PDH_STATUS ret;
    struct query *query = handle;

    TRACE("%p %ld %p\n", handle, interval, event);

    EnterCriticalSection( &pdh_handle_cs );
    if (!query || query->magic != PDH_MAGIC_QUERY)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    if (list_empty( &query->counters ))
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_NO_DATA;
    }
    if (query->thread)
    {
        HANDLE thread = query->thread;
        SetEvent( query->stop );
        LeaveCriticalSection( &pdh_handle_cs );

        WaitForSingleObject( thread, INFINITE );

        EnterCriticalSection( &pdh_handle_cs );
        if (query->magic != PDH_MAGIC_QUERY)
        {
            LeaveCriticalSection( &pdh_handle_cs );
            return PDH_INVALID_HANDLE;
        }
        CloseHandle( query->thread );
        query->thread = NULL;
    }
    else if (!(query->stop = CreateEventW( NULL, FALSE, FALSE, NULL )))
    {
        ret = GetLastError();
        LeaveCriticalSection( &pdh_handle_cs );
        return ret;
    }
    query->wait = event;
    query->interval = interval * 1000;
    if (!(query->thread = CreateThread( NULL, 0, collect_query_thread, query, 0, NULL )))
    {
        ret = GetLastError();
        CloseHandle( query->stop );

        LeaveCriticalSection( &pdh_handle_cs );
        return ret;
    }

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhCollectQueryDataWithTime   (PDH.@)
 */
PDH_STATUS WINAPI PdhCollectQueryDataWithTime( PDH_HQUERY handle, LONGLONG *timestamp )
{
    struct query *query = handle;
    struct counter *counter;
    struct list *item;

    TRACE("%p %p\n", handle, timestamp);

    if (!timestamp) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!query || query->magic != PDH_MAGIC_QUERY)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    if (list_empty( &query->counters ))
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_NO_DATA;
    }

    collect_query_data( query );

    item = list_head( &query->counters );
    counter = LIST_ENTRY( item, struct counter, entry );

    *timestamp = ((LONGLONG)counter->stamp.dwHighDateTime << 32) | counter->stamp.dwLowDateTime;

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/* The elements of the path of a counter as PdhGetCounterInfo reports them. */
struct info_strings
{
    WCHAR *full, *machine, *object, *instance, *parent, *counter;
    const WCHAR *explain;
    DWORD index;
};

static void free_info_strings( struct info_strings *is )
{
    free( is->full );
    free( is->machine );
    free( is->object );
    free( is->instance );
    free( is->parent );
    free( is->counter );
    memset( is, 0, sizeof(*is) );
}

/* The names the way the counter set spells them, not as the path was typed. */
static BOOL make_info_strings( const struct counter *counter, BOOL text, struct info_strings *is )
{
    struct path_elements pe;
    WCHAR host[MAX_COMPUTERNAME_LENGTH + 3];
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    BOOL has_instance;

    memset( is, 0, sizeof(*is) );
    if (parse_path( counter->path, &pe )) return FALSE;

    is->full = wcsdup( counter->path );
    if (pe.machine) is->machine = wcsdup( pe.machine );
    else
    {
        host[0] = host[1] = '\\';
        if (!GetComputerNameW( host + 2, &len )) host[2] = 0;
        is->machine = wcsdup( host );
    }
    is->object = counter->object ? wcsdup( counter->object->name ) : wcsdup( pe.object );
    if (pe.inst_raw)
    {
        is->instance = wcsdup( pe.instance );
        if (pe.parent) is->parent = wcsdup( pe.parent );
        is->index = pe.index == ~0u ? 0 : pe.index;
    }
    is->counter = counter->def ? wcsdup( counter->def->name ) : wcsdup( pe.counter );
    if (text && counter->def) is->explain = counter->def->help;
    has_instance = pe.inst_raw != NULL;
    free_path( &pe );
    if (!is->full || !is->machine || !is->object || !is->counter || (has_instance && !is->instance))
    {
        free_info_strings( is );
        return FALSE;
    }
    return TRUE;
}

static DWORD info_string_bytes( const WCHAR *str, BOOL ansi )
{
    DWORD n = ansi ? WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL ) : (lstrlenW( str ) + 1) * sizeof(WCHAR);
    return (n + 3) & ~3;   /* every string starts on a DWORD */
}

/* Fills a PDH_COUNTER_INFO_A or _W: the record, then the strings from its DataBuffer on. */
static PDH_STATUS counter_info( PDH_HCOUNTER handle, BOOLEAN text, LPDWORD size, void *buffer, BOOL ansi )
{
    struct counter *counter = handle;
    struct info_strings is;
    const WCHAR *list[7];
    DWORD need, offs[7], i;
    const DWORD base = ansi ? FIELD_OFFSET(PDH_COUNTER_INFO_A, DataBuffer) : FIELD_OFFSET(PDH_COUNTER_INFO_W, DataBuffer);
    PDH_STATUS ret = ERROR_SUCCESS;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    if (!size)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_ARGUMENT;
    }
    if (!make_info_strings( counter, text, &is ))
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }

    list[0] = is.full; list[1] = is.machine; list[2] = is.object; list[3] = is.instance;
    list[4] = is.parent; list[5] = is.counter; list[6] = is.explain;
    need = base;
    for (i = 0; i < 7; i++)
    {
        offs[i] = need;
        if (list[i]) need += info_string_bytes( list[i], ansi );
    }
    need += 4;

    if (!buffer || *size < need)
    {
        *size = need;
        ret = PDH_MORE_DATA;
    }
    else
    {
        char *buf = buffer;
        char *str[7];
        DWORD type = counter->type, cversion = counter->object && counter->object->cversion ? counter->object->cversion : 0x10001;

        memset( buf, 0, need );
        for (i = 0; i < 7; i++)
        {
            str[i] = list[i] ? buf + offs[i] : NULL;
            if (!list[i]) continue;
            if (ansi) WideCharToMultiByte( CP_ACP, 0, list[i], -1, str[i], need - offs[i], NULL, NULL );
            else lstrcpyW( (WCHAR *)str[i], list[i] );
        }
        if (ansi)
        {
            PDH_COUNTER_INFO_A *info = buffer;

            info->dwLength = need;
            info->dwType = type;
            info->CVersion = cversion;
            info->CStatus = counter->status;
            info->lScale = counter->scale;
            info->lDefaultScale = counter->defaultscale;
            info->dwUserData = counter->user;
            info->dwQueryUserData = counter->queryuser;
            info->szFullPath = str[0];
            info->szMachineName = str[1];
            info->szObjectName = str[2];
            info->szInstanceName = str[3];
            info->szParentInstance = str[4];
            info->dwInstanceIndex = is.index;
            info->szCounterName = str[5];
            info->szExplainText = str[6];
        }
        else
        {
            PDH_COUNTER_INFO_W *info = buffer;

            info->dwLength = need;
            info->dwType = type;
            info->CVersion = cversion;
            info->CStatus = counter->status;
            info->lScale = counter->scale;
            info->lDefaultScale = counter->defaultscale;
            info->dwUserData = counter->user;
            info->dwQueryUserData = counter->queryuser;
            info->szFullPath = (WCHAR *)str[0];
            info->szMachineName = (WCHAR *)str[1];
            info->szObjectName = (WCHAR *)str[2];
            info->szInstanceName = (WCHAR *)str[3];
            info->szParentInstance = (WCHAR *)str[4];
            info->dwInstanceIndex = is.index;
            info->szCounterName = (WCHAR *)str[5];
            info->szExplainText = (WCHAR *)str[6];
        }
        *size = need;
    }
    free_info_strings( &is );
    LeaveCriticalSection( &pdh_handle_cs );
    return ret;
}

/***********************************************************************
 *              PdhGetCounterInfoA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetCounterInfoA( PDH_HCOUNTER handle, BOOLEAN text, LPDWORD size, PPDH_COUNTER_INFO_A info )
{
    TRACE("%p %d %p %p\n", handle, text, size, info);
    return counter_info( handle, text, size, info, TRUE );
}

/***********************************************************************
 *              PdhGetCounterInfoW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetCounterInfoW( PDH_HCOUNTER handle, BOOLEAN text, LPDWORD size, PPDH_COUNTER_INFO_W info )
{
    TRACE("%p %d %p %p\n", handle, text, size, info);
    return counter_info( handle, text, size, info, FALSE );
}

/***********************************************************************
 *              PdhGetCounterTimeBase   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetCounterTimeBase( PDH_HCOUNTER handle, LONGLONG *base )
{
    struct counter *counter = handle;

    TRACE("%p %p\n", handle, base);

    if (!base) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    *base = counter->base;

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhGetDllVersion   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDllVersion( LPDWORD version )
{
    if (!version)
        return PDH_INVALID_ARGUMENT;

    *version = PDH_VERSION;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhGetFormattedCounterValue   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetFormattedCounterValue( PDH_HCOUNTER handle, DWORD format,
                                               LPDWORD type, PPDH_FMT_COUNTERVALUE value )
{
    PDH_STATUS ret;
    struct counter *counter = handle;

    TRACE("%p %lx %p %p\n", handle, format, type, value);

    if (!value) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    /* rates and timers need two collections; the sample from PdhAddCounterW does not count */
    if (counter->multi && counter->nitems)   /* a wildcard counter answers with its first instance */
        ret = format_value( counter, format, &counter->items[0].cur, counter->items[0].has_prev ? &counter->items[0].prev : NULL, value );
    else
        ret = format_value( counter, format, &counter->cur, counter->collects >= 2 ? &counter->prev : NULL, value );
    if (!ret && type) *type = counter->type;

    LeaveCriticalSection( &pdh_handle_cs );
    return ret;
}

/***********************************************************************
 *              PdhGetRawCounterValue   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetRawCounterValue( PDH_HCOUNTER handle, LPDWORD type,
                                         PPDH_RAW_COUNTER value )
{
    struct counter *counter = handle;

    TRACE("%p %p %p\n", handle, type, value);

    if (!value) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    {
        const struct sample *cur = counter->multi && counter->nitems ? &counter->items[0].cur : &counter->cur;

        value->CStatus                  = cur->status;
        value->TimeStamp.dwLowDateTime  = cur->stamp.dwLowDateTime;
        value->TimeStamp.dwHighDateTime = cur->stamp.dwHighDateTime;
        value->FirstValue               = cur->first;
        value->SecondValue              = cur->second;
    }
    value->MultiCount               = 1;

    if (type) *type = counter->type;

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhLookupPerfIndexByNameA   (PDH.@)
 */
PDH_STATUS WINAPI PdhLookupPerfIndexByNameA( LPCSTR machine, LPCSTR name, LPDWORD index )
{
    PDH_STATUS ret;
    WCHAR *machineW = NULL;
    WCHAR *nameW;

    TRACE("%s %s %p\n", debugstr_a(machine), debugstr_a(name), index);

    if (!name) return PDH_INVALID_ARGUMENT;

    if (machine && !(machineW = pdh_strdup_aw( machine ))) return PDH_MEMORY_ALLOCATION_FAILURE;

    if (!(nameW = pdh_strdup_aw( name )))
        return PDH_MEMORY_ALLOCATION_FAILURE;

    ret = PdhLookupPerfIndexByNameW( machineW, nameW, index );

    free( nameW );
    free( machineW );
    return ret;
}

/***********************************************************************
 *              PdhLookupPerfIndexByNameW   (PDH.@)
 */
PDH_STATUS WINAPI PdhLookupPerfIndexByNameW( LPCWSTR machine, LPCWSTR name, LPDWORD index )
{
    TRACE("%s %s %p\n", debugstr_w(machine), debugstr_w(name), index);

    if (!name || !index) return PDH_INVALID_ARGUMENT;

    if (machine && !is_local_name( machine ))
    {
        FIXME("remote machine not supported\n");
        return PDH_CSTATUS_NO_MACHINE;
    }
    if (perf_index_by_name( name, index )) return ERROR_SUCCESS;
    return PDH_STRING_NOT_FOUND;
}

/***********************************************************************
 *              PdhLookupPerfNameByIndexA   (PDH.@)
 */
PDH_STATUS WINAPI PdhLookupPerfNameByIndexA( LPCSTR machine, DWORD index, LPSTR buffer, LPDWORD size )
{
    PDH_STATUS ret;
    WCHAR *machineW = NULL;
    WCHAR bufferW[PDH_MAX_COUNTER_NAME];
    DWORD sizeW = ARRAY_SIZE(bufferW);

    TRACE("%s %ld %p %p\n", debugstr_a(machine), index, buffer, size);

    if (!buffer || !size) return PDH_INVALID_ARGUMENT;

    if (machine && !(machineW = pdh_strdup_aw( machine ))) return PDH_MEMORY_ALLOCATION_FAILURE;

    if (!(ret = PdhLookupPerfNameByIndexW( machineW, index, bufferW, &sizeW )))
    {
        int required = WideCharToMultiByte( CP_ACP, 0, bufferW, -1, NULL, 0, NULL, NULL );

        if (*size < required) ret = PDH_MORE_DATA;
        else WideCharToMultiByte( CP_ACP, 0, bufferW, -1, buffer, required, NULL, NULL );
        *size = required;
    }
    free( machineW );
    return ret;
}

/***********************************************************************
 *              PdhLookupPerfNameByIndexW   (PDH.@)
 */
PDH_STATUS WINAPI PdhLookupPerfNameByIndexW( LPCWSTR machine, DWORD index, LPWSTR buffer, LPDWORD size )
{
    PDH_STATUS ret;
    const WCHAR *name;
    unsigned int required;

    TRACE("%s %ld %p %p\n", debugstr_w(machine), index, buffer, size);

    if (machine && !is_local_name( machine ))
    {
        FIXME("remote machine not supported\n");
        return PDH_CSTATUS_NO_MACHINE;
    }

    if (!buffer || !size) return PDH_INVALID_ARGUMENT;
    if (!index) return ERROR_SUCCESS;

    if (!perf_name_by_index( index, &name )) return PDH_INVALID_ARGUMENT;

    required = lstrlenW( name ) + 1;
    if (*size < required) ret = PDH_MORE_DATA;
    else
    {
        lstrcpyW( buffer, name );
        ret = ERROR_SUCCESS;
    }
    *size = required;
    return ret;
}

/***********************************************************************
 *              PdhOpenQueryA   (PDH.@)
 */
PDH_STATUS WINAPI PdhOpenQueryA( LPCSTR source, DWORD_PTR userdata, PDH_HQUERY *query )
{
    PDH_STATUS ret;
    WCHAR *sourceW = NULL;

    TRACE("%s %Ix %p\n", debugstr_a(source), userdata, query);

    if (source && !(sourceW = pdh_strdup_aw( source ))) return PDH_MEMORY_ALLOCATION_FAILURE;

    ret = PdhOpenQueryW( sourceW, userdata, query );
    free( sourceW );

    return ret;
}

/***********************************************************************
 *              PdhOpenQueryW   (PDH.@)
 */
PDH_STATUS WINAPI PdhOpenQueryW( LPCWSTR source, DWORD_PTR userdata, PDH_HQUERY *handle )
{
    struct query *query;

    TRACE("%s %Ix %p\n", debugstr_w(source), userdata, handle);

    if (!handle) return PDH_INVALID_ARGUMENT;

    if (source)
    {
        FIXME("log file data source not supported\n");
        return PDH_INVALID_ARGUMENT;
    }
    if ((query = create_query()))
    {
        query->user = userdata;
        *handle = query;

        return ERROR_SUCCESS;
    }
    return PDH_MEMORY_ALLOCATION_FAILURE;
}

/***********************************************************************
 *              PdhRemoveCounter   (PDH.@)
 */
PDH_STATUS WINAPI PdhRemoveCounter( PDH_HCOUNTER handle )
{
    struct counter *counter = handle;

    TRACE("%p\n", handle);

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }

    list_remove( &counter->entry );
    destroy_counter( counter );

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhSetCounterScaleFactor   (PDH.@)
 */
PDH_STATUS WINAPI PdhSetCounterScaleFactor( PDH_HCOUNTER handle, LONG factor )
{
    struct counter *counter = handle;

    TRACE("%p\n", handle);

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    if (factor < PDH_MIN_SCALE || factor > PDH_MAX_SCALE)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_ARGUMENT;
    }

    counter->scale = factor;

    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhValidatePathA   (PDH.@)
 */
PDH_STATUS WINAPI PdhValidatePathA( LPCSTR path )
{
    PDH_STATUS ret;
    WCHAR *pathW;

    TRACE("%s\n", debugstr_a(path));

    if (!path) return PDH_INVALID_ARGUMENT;
    if (!(pathW = pdh_strdup_aw( path ))) return PDH_MEMORY_ALLOCATION_FAILURE;

    ret = PdhValidatePathW( pathW );

    free( pathW );
    return ret;
}

/***********************************************************************
 *              PdhValidatePathW   (PDH.@)
 */
PDH_STATUS WINAPI PdhValidatePathW( LPCWSTR path )
{
    struct path_elements pe;
    PDH_STATUS ret;

    TRACE("%s\n", debugstr_w(path));

    if (!path || !*path) return PDH_INVALID_ARGUMENT;

    ret = check_path( path, FALSE, &pe, NULL, NULL );
    free_path( &pe );
    return ret;
}

/***********************************************************************
 *              PdhVbAddCounter   (PDH.@)
 */
PDH_STATUS WINAPI PdhVbAddCounter( PDH_HQUERY query, LPCSTR path, PDH_HCOUNTER *counter )
{
    FIXME("%p, %s, %p: stub!\n", query, debugstr_a(path), counter);

    if (!path) return PDH_INVALID_ARGUMENT;

    return PDH_NOT_IMPLEMENTED;
}

/***********************************************************************
 *              PdhVbGetDoubleCounterValue   (PDH.@)
 */
double WINAPI PdhVbGetDoubleCounterValue( PDH_HCOUNTER handle, PDH_STATUS *counter_status )
{
    PDH_FMT_COUNTERVALUE value;
    PDH_STATUS status;

    TRACE( "%p %p\n", handle, counter_status );

    memset( &value, 0, sizeof(value) );
    status = PdhGetFormattedCounterValue( handle, PDH_FMT_DOUBLE, NULL, &value );

    if (counter_status) *counter_status = status;
    return value.doubleValue;
}

/***********************************************************************
 *              PdhValidatePathExA   (PDH.@)
 */
PDH_STATUS WINAPI PdhValidatePathExA( PDH_HLOG source, LPCSTR path )
{
    TRACE("%p %s\n", source, debugstr_a(path));

    if (source)
    {
        FIXME("log file data source not supported\n");
        return ERROR_SUCCESS;
    }
    return PdhValidatePathA( path );
}

/***********************************************************************
 *              PdhValidatePathExW   (PDH.@)
 */
PDH_STATUS WINAPI PdhValidatePathExW( PDH_HLOG source, LPCWSTR path )
{
    TRACE("%p %s\n", source, debugstr_w(path));

    if (source)
    {
        FIXME("log file data source not supported\n");
        return ERROR_SUCCESS;
    }
    return PdhValidatePathW( path );
}

/***********************************************************************
 *              PdhMakeCounterPathA   (PDH.@)
 */
PDH_STATUS WINAPI PdhMakeCounterPathA( PDH_COUNTER_PATH_ELEMENTS_A *e, LPSTR buffer,
                                       LPDWORD buflen, DWORD flags )
{
    PDH_STATUS ret = PDH_MEMORY_ALLOCATION_FAILURE;
    PDH_COUNTER_PATH_ELEMENTS_W eW;
    WCHAR *bufferW;
    DWORD buflenW;

    TRACE("%p %p %p 0x%08lx\n", e, buffer, buflen, flags);

    if (!e || !buflen) return PDH_INVALID_ARGUMENT;

    memset( &eW, 0, sizeof(eW) );
    if (e->szMachineName    && !(eW.szMachineName    = pdh_strdup_aw( e->szMachineName ))) goto done;
    if (e->szObjectName     && !(eW.szObjectName     = pdh_strdup_aw( e->szObjectName ))) goto done;
    if (e->szInstanceName   && !(eW.szInstanceName   = pdh_strdup_aw( e->szInstanceName ))) goto done;
    if (e->szParentInstance && !(eW.szParentInstance = pdh_strdup_aw( e->szParentInstance ))) goto done;
    if (e->szCounterName    && !(eW.szCounterName    = pdh_strdup_aw( e->szCounterName ))) goto done;
    eW.dwInstanceIndex = e->dwInstanceIndex;

    buflenW = 0;
    ret = PdhMakeCounterPathW( &eW, NULL, &buflenW, flags );
    if (ret == PDH_MORE_DATA)
    {
        if ((bufferW = malloc( buflenW * sizeof(WCHAR) )))
        {
            if (!(ret = PdhMakeCounterPathW( &eW, bufferW, &buflenW, flags )))
            {
                int len = WideCharToMultiByte(CP_ACP, 0, bufferW, -1, NULL, 0, NULL, NULL);
                if (*buflen >= len) WideCharToMultiByte(CP_ACP, 0, bufferW, -1, buffer, *buflen, NULL, NULL);
                else ret = PDH_MORE_DATA;
                *buflen = len;
            }
            free( bufferW );
        }
        else
            ret = PDH_MEMORY_ALLOCATION_FAILURE;
    }

done:
    free( eW.szMachineName );
    free( eW.szObjectName );
    free( eW.szInstanceName );
    free( eW.szParentInstance );
    free( eW.szCounterName );
    return ret;
}

/***********************************************************************
 *              PdhMakeCounterPathW   (PDH.@)
 */
PDH_STATUS WINAPI PdhMakeCounterPathW( PDH_COUNTER_PATH_ELEMENTS_W *e, LPWSTR buffer,
                                       LPDWORD buflen, DWORD flags )
{
    WCHAR instance[16], *path, *p;
    PDH_STATUS ret = ERROR_SUCCESS;
    BOOL machine_prefix = FALSE, index = FALSE;
    size_t len;

    TRACE("%p %p %p 0x%08lx\n", e, buffer, buflen, flags);

    if (flags) FIXME("unimplemented flags 0x%08lx\n", flags);

    if (!e || !e->szCounterName || !e->szObjectName || !buflen)
        return PDH_INVALID_ARGUMENT;

    /* the length first: the elements are of any size */
    len = 1 + lstrlenW( e->szObjectName ) + 1 + lstrlenW( e->szCounterName ) + 1;
    if (e->szMachineName)
    {
        machine_prefix = e->szMachineName[0] != '\\' || e->szMachineName[1] != '\\';
        len += (machine_prefix ? 2 : 0) + lstrlenW( e->szMachineName );
    }
    if (e->szInstanceName)
    {
        len += 2 + lstrlenW( e->szInstanceName );
        if (e->szParentInstance) len += 1 + lstrlenW( e->szParentInstance );
        if ((index = e->dwInstanceIndex && e->dwInstanceIndex != ~0u))
        {
            swprintf( instance, ARRAY_SIZE(instance), L"#%u", e->dwInstanceIndex );
            len += lstrlenW( instance );
        }
    }

    if (!(path = malloc( len * sizeof(WCHAR) ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    p = path;
    if (e->szMachineName)
    {
        if (machine_prefix) { *p++ = '\\'; *p++ = '\\'; }
        lstrcpyW( p, e->szMachineName );
        p += lstrlenW( p );
    }
    *p++ = '\\';
    lstrcpyW( p, e->szObjectName );
    p += lstrlenW( p );
    if (e->szInstanceName)
    {
        *p++ = '(';
        if (e->szParentInstance)
        {
            lstrcpyW( p, e->szParentInstance );
            p += lstrlenW( p );
            *p++ = '/';
        }
        lstrcpyW( p, e->szInstanceName );
        p += lstrlenW( p );
        if (index)
        {
            lstrcpyW( p, instance );
            p += lstrlenW( p );
        }
        *p++ = ')';
    }
    *p++ = '\\';
    lstrcpyW( p, e->szCounterName );

    if (buffer && *buflen >= len) lstrcpyW( buffer, path );
    else
    {
        ret = PDH_MORE_DATA;
        if (buffer && *buflen)  /* Windows fills what fits */
        {
            memcpy( buffer, path, (*buflen - 1) * sizeof(WCHAR) );
            buffer[*buflen - 1] = 0;
        }
    }
    *buflen = len;
    free( path );
    return ret;
}

/***********************************************************************
 *              PdhSetDefaultRealTimeDataSource   (PDH.@)
 */
PDH_STATUS WINAPI PdhSetDefaultRealTimeDataSource( DWORD source )
{
    FIXME("%lu\n", source);
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhGetLogFileTypeA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetLogFileTypeA(const char *log, DWORD *type)
{
    FIXME("%s, %p: stub\n", debugstr_a(log), type);
    return PDH_NOT_IMPLEMENTED;
}

/***********************************************************************
 *              PdhGetLogFileTypeW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetLogFileTypeW(const WCHAR *log, DWORD *type)
{
    FIXME("%s, %p: stub\n", debugstr_w(log), type);
    return PDH_NOT_IMPLEMENTED;
}

/***********************************************************************
 *              PdhConnectMachineA   (PDH.@)
 */
PDH_STATUS WINAPI PdhConnectMachineA(const char *name)
{
    PDH_STATUS ret;
    WCHAR *nameW = NULL;

    TRACE("%s\n", debugstr_a(name));
    if (name && !(nameW = pdh_strdup_aw( name ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    ret = PdhConnectMachineW( nameW );
    free( nameW );
    return ret;
}

/* ---- counter set enumeration and wildcard expansion ---- */

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#define PDH_NOEXPANDCOUNTERS_FLAG   0x00000001
#define PDH_NOEXPANDINSTANCES_FLAG  0x00000002
#define PDH_DETAIL_MASK             0x0000ffff

struct strlist
{
    WCHAR *s;
    DWORD  len, cap;
    BOOL   fail;
};

/* appends n characters of str and a terminating null */
static void sl_add( struct strlist *l, const WCHAR *str, size_t n )
{
    if (l->fail) return;
    if (l->len + n + 3 > l->cap)
    {
        DWORD cap = max( l->cap * 2, (DWORD)(l->len + n + 64) );
        WCHAR *p = realloc( l->s, cap * sizeof(WCHAR) );
        if (!p)
        {
            l->fail = TRUE;
            return;
        }
        l->s = p;
        l->cap = cap;
    }
    memcpy( l->s + l->len, str, n * sizeof(WCHAR) );
    l->len += n;
    l->s[l->len++] = 0;
}

static void sl_add_str( struct strlist *l, const WCHAR *str )
{
    sl_add( l, str, lstrlenW( str ) );
}

/* terminates the list; an empty list is two nulls */
static BOOL sl_finish( struct strlist *l )
{
    if (l->fail) return FALSE;
    if (!l->s && !(l->s = malloc( 4 * sizeof(WCHAR) ))) return FALSE;
    l->s[l->len++] = 0;
    if (l->len < 2) l->s[l->len++] = 0;
    return TRUE;
}

static PDH_STATUS return_list( const WCHAR *list, DWORD len, WCHAR *buf, DWORD *size )
{
    if (!buf || *size < len)
    {
        *size = len;
        return PDH_MORE_DATA;
    }
    memcpy( buf, list, len * sizeof(WCHAR) );
    *size = len;
    return ERROR_SUCCESS;
}

/* only the live system is a data source; log files are not supported */
static PDH_STATUS check_source_name( const WCHAR *source )
{
    if (!source) return ERROR_SUCCESS;
    if (GetFileAttributesW( source ) == INVALID_FILE_ATTRIBUTES)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? PDH_FILE_NOT_FOUND : PDH_LOG_FILE_OPEN_ERROR;
    FIXME("log file data source not supported\n");
    return PDH_NOT_IMPLEMENTED;
}

static PDH_STATUS check_machine_name( const WCHAR *machine )
{
    if (machine && *machine && !is_local_name( machine ))
    {
        FIXME("remote machine %s not supported\n", debugstr_w(machine));
        return PDH_CSTATUS_NO_MACHINE;
    }
    return ERROR_SUCCESS;
}

static PDH_STATUS local_machine_prefix( WCHAR *buf, DWORD size )
{
    DWORD len = size - 2;

    buf[0] = buf[1] = '\\';
    if (!GetComputerNameW( buf + 2, &len )) return PDH_CSTATUS_NO_MACHINE;
    return ERROR_SUCCESS;
}

static PDH_STATUS enum_objects( const WCHAR *source, const WCHAR *machine, WCHAR *buf, DWORD *size )
{
    struct strlist list = {0};
    PDH_STATUS ret;
    DWORD i;

    if (!size) return PDH_INVALID_ARGUMENT;
    if ((ret = check_source_name( source ))) return ret;
    if ((ret = check_machine_name( machine ))) return ret;

    for (i = 0; i < perf_object_count(); i++) sl_add_str( &list, perf_object( i )->name );
    if (!sl_finish( &list ))
    {
        free( list.s );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    ret = return_list( list.s, list.len, buf, size );
    free( list.s );
    return ret;
}

/***********************************************************************
 *              PdhEnumObjectsW   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectsW( LPCWSTR source, LPCWSTR machine, LPWSTR buf, LPDWORD size, DWORD detail, BOOL refresh )
{
    TRACE("%s %s %p %p %ld %d\n", debugstr_w(source), debugstr_w(machine), buf, size, detail, refresh);
    return enum_objects( source, machine, buf, size );
}

/***********************************************************************
 *              PdhEnumObjectsHW   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectsHW( PDH_HLOG source, LPCWSTR machine, LPWSTR buf, LPDWORD size, DWORD detail, BOOL refresh )
{
    TRACE("%p %s %p %p %ld %d\n", source, debugstr_w(machine), buf, size, detail, refresh);
    if (source) return PDH_INVALID_HANDLE;
    return enum_objects( NULL, machine, buf, size );
}

/* converts a multi-sz list of length wlen to the ANSI buffer */
static PDH_STATUS list_to_ansi( const WCHAR *w, DWORD wlen, char *buf, DWORD *size )
{
    int need = WideCharToMultiByte( CP_ACP, 0, w, wlen, NULL, 0, NULL, NULL );

    if (!buf || *size < need)
    {
        *size = need;
        return PDH_MORE_DATA;
    }
    WideCharToMultiByte( CP_ACP, 0, w, wlen, buf, *size, NULL, NULL );
    *size = need;
    return ERROR_SUCCESS;
}

static PDH_STATUS enum_objects_a( PDH_HLOG hsource, LPCSTR source, LPCSTR machine, LPSTR buf, LPDWORD size )
{
    WCHAR *sourceW = NULL, *machineW = NULL, *bufW;
    DWORD lenW = 0;
    PDH_STATUS ret;

    if (!size) return PDH_INVALID_ARGUMENT;
    if (source && !(sourceW = pdh_strdup_aw( source ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    if (machine && !(machineW = pdh_strdup_aw( machine )))
    {
        free( sourceW );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    ret = hsource ? PdhEnumObjectsHW( hsource, machineW, NULL, &lenW, 0, FALSE )
                  : PdhEnumObjectsW( sourceW, machineW, NULL, &lenW, 0, FALSE );
    if (ret == PDH_MORE_DATA)
    {
        if ((bufW = malloc( lenW * sizeof(WCHAR) )))
        {
            ret = PdhEnumObjectsW( sourceW, machineW, bufW, &lenW, 0, FALSE );
            if (!ret) ret = list_to_ansi( bufW, lenW, buf, size );
            free( bufW );
        }
        else ret = PDH_MEMORY_ALLOCATION_FAILURE;
    }
    free( sourceW );
    free( machineW );
    return ret;
}

/***********************************************************************
 *              PdhEnumObjectsA   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectsA( LPCSTR source, LPCSTR machine, LPSTR buf, LPDWORD size, DWORD detail, BOOL refresh )
{
    TRACE("%s %s %p %p %ld %d\n", debugstr_a(source), debugstr_a(machine), buf, size, detail, refresh);
    return enum_objects_a( NULL, source, machine, buf, size );
}

/***********************************************************************
 *              PdhEnumObjectsHA   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectsHA( PDH_HLOG source, LPCSTR machine, LPSTR buf, LPDWORD size, DWORD detail, BOOL refresh )
{
    TRACE("%p %s %p %p %ld %d\n", source, debugstr_a(machine), buf, size, detail, refresh);
    if (source) return PDH_INVALID_HANDLE;
    return enum_objects_a( NULL, NULL, machine, buf, size );
}

static PDH_STATUS enum_machines( const WCHAR *source, WCHAR *buf, DWORD *size )
{
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 3];
    struct strlist list = {0};
    PDH_STATUS ret;

    if (!size) return PDH_INVALID_ARGUMENT;
    if ((ret = check_source_name( source ))) return ret;
    if ((ret = local_machine_prefix( name, ARRAY_SIZE(name) ))) return ret;

    sl_add_str( &list, name );
    if (!sl_finish( &list ))
    {
        free( list.s );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    ret = return_list( list.s, list.len, buf, size );
    free( list.s );
    return ret;
}

/***********************************************************************
 *              PdhEnumMachinesW   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumMachinesW( LPCWSTR source, LPWSTR buf, LPDWORD size )
{
    TRACE("%s %p %p\n", debugstr_w(source), buf, size);
    return enum_machines( source, buf, size );
}

/***********************************************************************
 *              PdhEnumMachinesHW   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumMachinesHW( PDH_HLOG source, LPWSTR buf, LPDWORD size )
{
    TRACE("%p %p %p\n", source, buf, size);
    if (source) return PDH_INVALID_HANDLE;
    return enum_machines( NULL, buf, size );
}

static PDH_STATUS enum_machines_a( LPSTR buf, LPDWORD size )
{
    WCHAR *bufW;
    DWORD lenW = 0;
    PDH_STATUS ret;

    if (!size) return PDH_INVALID_ARGUMENT;
    ret = enum_machines( NULL, NULL, &lenW );
    if (ret == PDH_MORE_DATA)
    {
        if ((bufW = malloc( lenW * sizeof(WCHAR) )))
        {
            ret = enum_machines( NULL, bufW, &lenW );
            if (!ret) ret = list_to_ansi( bufW, lenW, buf, size );
            free( bufW );
        }
        else ret = PDH_MEMORY_ALLOCATION_FAILURE;
    }
    return ret;
}

/***********************************************************************
 *              PdhEnumMachinesA   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumMachinesA( LPCSTR source, LPSTR buf, LPDWORD size )
{
    TRACE("%s %p %p\n", debugstr_a(source), buf, size);
    if (source)
    {
        WCHAR *sourceW = pdh_strdup_aw( source );
        PDH_STATUS ret = sourceW ? check_source_name( sourceW ) : PDH_MEMORY_ALLOCATION_FAILURE;
        free( sourceW );
        if (ret) return ret;
    }
    return enum_machines_a( buf, size );
}

/***********************************************************************
 *              PdhEnumMachinesHA   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumMachinesHA( PDH_HLOG source, LPSTR buf, LPDWORD size )
{
    TRACE("%p %p %p\n", source, buf, size);
    if (source) return PDH_INVALID_HANDLE;
    return enum_machines_a( buf, size );
}

static PDH_STATUS enum_object_items( const WCHAR *source, const WCHAR *machine, const WCHAR *objname,
                                     WCHAR *counters, DWORD *clen, WCHAR *instances, DWORD *ilen,
                                     DWORD detail, DWORD flags )
{
    const struct perf_object_def *obj;
    struct strlist clist = {0}, ilist = {0};
    WCHAR **names;
    DWORD i, count;
    PDH_STATUS ret;

    if (!objname || !clen || !ilen) return PDH_INVALID_ARGUMENT;
    if ((ret = check_source_name( source ))) return ret;
    if ((ret = check_machine_name( machine ))) return ret;
    if (!(obj = perf_find_object( objname ))) return PDH_CSTATUS_NO_OBJECT;

    for (i = 0; i < obj->count; i++)
        if (obj->counters[i].detail <= (detail & PDH_DETAIL_MASK)) sl_add_str( &clist, obj->counters[i].name );
    if (!sl_finish( &clist ))
    {
        free( clist.s );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }

    if (obj->kind != INST_NONE)
    {
        if ((ret = perf_get_instances( obj, &names, &count )))
        {
            free( clist.s );
            return ret;
        }
        for (i = 0; i < count; i++) sl_add_str( &ilist, names[i] );
        perf_free_instances( names, count );
        if (!sl_finish( &ilist ))
        {
            free( clist.s );
            free( ilist.s );
            return PDH_MEMORY_ALLOCATION_FAILURE;
        }
    }

    /* both lists are reported together; a set without instances has no instance list */
    if (!counters || *clen < clist.len || (ilist.len && (!instances || *ilen < ilist.len)))
    {
        *clen = clist.len;
        *ilen = ilist.len;
        ret = PDH_MORE_DATA;
    }
    else
    {
        memcpy( counters, clist.s, clist.len * sizeof(WCHAR) );
        *clen = clist.len;
        if (ilist.len) memcpy( instances, ilist.s, ilist.len * sizeof(WCHAR) );
        *ilen = ilist.len;
        ret = ERROR_SUCCESS;
    }
    free( clist.s );
    free( ilist.s );
    return ret;
}

/***********************************************************************
 *              PdhEnumObjectItemsW   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectItemsW(LPCWSTR szDataSource, LPCWSTR szMachineName, LPCWSTR szObjectName,
                                      LPWSTR mszCounterList, LPDWORD pcchCounterListLength, LPWSTR mszInstanceList,
                                      LPDWORD pcchInstanceListLength, DWORD dwDetailLevel, DWORD dwFlags)
{
    TRACE("%s, %s, %s, %p, %p, %p, %p, %ld, 0x%lx\n", debugstr_w(szDataSource), debugstr_w(szMachineName),
          debugstr_w(szObjectName), mszCounterList, pcchCounterListLength, mszInstanceList,
          pcchInstanceListLength, dwDetailLevel, dwFlags);

    return enum_object_items( szDataSource, szMachineName, szObjectName, mszCounterList, pcchCounterListLength,
                              mszInstanceList, pcchInstanceListLength, dwDetailLevel, dwFlags );
}

/***********************************************************************
 *              PdhEnumObjectItemsHW   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectItemsHW(PDH_HLOG hDataSource, LPCWSTR szMachineName, LPCWSTR szObjectName,
                                       LPWSTR mszCounterList, LPDWORD pcchCounterListLength, LPWSTR mszInstanceList,
                                       LPDWORD pcchInstanceListLength, DWORD dwDetailLevel, DWORD dwFlags)
{
    TRACE("%p, %s, %s, %p, %p, %p, %p, %ld, 0x%lx\n", hDataSource, debugstr_w(szMachineName),
          debugstr_w(szObjectName), mszCounterList, pcchCounterListLength, mszInstanceList,
          pcchInstanceListLength, dwDetailLevel, dwFlags);

    if (hDataSource) return PDH_INVALID_HANDLE;
    return enum_object_items( NULL, szMachineName, szObjectName, mszCounterList, pcchCounterListLength,
                              mszInstanceList, pcchInstanceListLength, dwDetailLevel, dwFlags );
}

static PDH_STATUS enum_object_items_a( PDH_HLOG hsource, LPCSTR source, LPCSTR machine, LPCSTR object,
                                       LPSTR counters, LPDWORD clen, LPSTR instances, LPDWORD ilen,
                                       DWORD detail, DWORD flags )
{
    WCHAR *sourceW = NULL, *machineW = NULL, *objectW = NULL, *cbuf = NULL, *ibuf = NULL;
    DWORD clenW = 0, ilenW = 0;
    PDH_STATUS ret = PDH_MEMORY_ALLOCATION_FAILURE;

    if (!object || !clen || !ilen) return PDH_INVALID_ARGUMENT;
    if (source && !(sourceW = pdh_strdup_aw( source ))) goto done;
    if (machine && !(machineW = pdh_strdup_aw( machine ))) goto done;
    if (!(objectW = pdh_strdup_aw( object ))) goto done;

    ret = hsource ? PdhEnumObjectItemsHW( hsource, machineW, objectW, NULL, &clenW, NULL, &ilenW, detail, flags )
                  : PdhEnumObjectItemsW( sourceW, machineW, objectW, NULL, &clenW, NULL, &ilenW, detail, flags );
    if (ret != PDH_MORE_DATA) goto done;

    if (!(cbuf = malloc( clenW * sizeof(WCHAR) )) || (ilenW && !(ibuf = malloc( ilenW * sizeof(WCHAR) ))))
    {
        ret = PDH_MEMORY_ALLOCATION_FAILURE;
        goto done;
    }
    ret = PdhEnumObjectItemsW( sourceW, machineW, objectW, cbuf, &clenW, ibuf, &ilenW, detail, flags );
    if (ret) goto done;

    {
        int cneed = WideCharToMultiByte( CP_ACP, 0, cbuf, clenW, NULL, 0, NULL, NULL );
        int ineed = ilenW ? WideCharToMultiByte( CP_ACP, 0, ibuf, ilenW, NULL, 0, NULL, NULL ) : 0;

        if (!counters || *clen < cneed || (ineed && (!instances || *ilen < ineed)))
        {
            *clen = cneed;
            *ilen = ineed;
            ret = PDH_MORE_DATA;
            goto done;
        }
        WideCharToMultiByte( CP_ACP, 0, cbuf, clenW, counters, *clen, NULL, NULL );
        if (ineed) WideCharToMultiByte( CP_ACP, 0, ibuf, ilenW, instances, *ilen, NULL, NULL );
        *clen = cneed;
        *ilen = ineed;
    }

done:
    free( sourceW );
    free( machineW );
    free( objectW );
    free( cbuf );
    free( ibuf );
    return ret;
}

/***********************************************************************
 *              PdhEnumObjectItemsA   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectItemsA(LPCSTR szDataSource, LPCSTR szMachineName, LPCSTR szObjectName,
                                      LPSTR mszCounterList, LPDWORD pcchCounterListLength, LPSTR mszInstanceList,
                                      LPDWORD pcchInstanceListLength, DWORD dwDetailLevel, DWORD dwFlags)
{
    TRACE("%s, %s, %s, %p, %p, %p, %p, %ld, 0x%lx\n", debugstr_a(szDataSource), debugstr_a(szMachineName),
          debugstr_a(szObjectName), mszCounterList, pcchCounterListLength, mszInstanceList,
          pcchInstanceListLength, dwDetailLevel, dwFlags);

    return enum_object_items_a( NULL, szDataSource, szMachineName, szObjectName, mszCounterList,
                                pcchCounterListLength, mszInstanceList, pcchInstanceListLength,
                                dwDetailLevel, dwFlags );
}

/***********************************************************************
 *              PdhEnumObjectItemsHA   (PDH.@)
 */
PDH_STATUS WINAPI PdhEnumObjectItemsHA(PDH_HLOG hDataSource, LPCSTR szMachineName, LPCSTR szObjectName,
                                       LPSTR mszCounterList, LPDWORD pcchCounterListLength, LPSTR mszInstanceList,
                                       LPDWORD pcchInstanceListLength, DWORD dwDetailLevel, DWORD dwFlags)
{
    TRACE("%p, %s, %s, %p, %p, %p, %p, %ld, 0x%lx\n", hDataSource, debugstr_a(szMachineName),
          debugstr_a(szObjectName), mszCounterList, pcchCounterListLength, mszInstanceList,
          pcchInstanceListLength, dwDetailLevel, dwFlags);

    if (hDataSource) return PDH_INVALID_HANDLE;
    return enum_object_items_a( NULL, NULL, szMachineName, szObjectName, mszCounterList,
                                pcchCounterListLength, mszInstanceList, pcchInstanceListLength,
                                dwDetailLevel, dwFlags );
}

static void add_expanded_path( struct strlist *l, const WCHAR *machine, const WCHAR *object,
                               const WCHAR *instance, const WCHAR *counter )
{
    DWORD len = lstrlenW( machine ) + lstrlenW( object ) + (instance ? lstrlenW( instance ) + 2 : 0) +
                lstrlenW( counter ) + 3;
    WCHAR *path = malloc( len * sizeof(WCHAR) );

    if (!path)
    {
        l->fail = TRUE;
        return;
    }
    lstrcpyW( path, machine );
    lstrcatW( path, L"\\" );
    lstrcatW( path, object );
    if (instance)
    {
        lstrcatW( path, L"(" );
        lstrcatW( path, instance );
        lstrcatW( path, L")" );
    }
    lstrcatW( path, L"\\" );
    lstrcatW( path, counter );
    sl_add_str( l, path );
    free( path );
}

/* Expands the instance and counter wildcards of a path to the list of matching paths. A name that has no
 * wildcard is kept as given; expanded names have the spelling of the counter set. */
static PDH_STATUS expand_path( const WCHAR *source, const WCHAR *path, DWORD flags, WCHAR *buf, DWORD *size )
{
    struct path_elements pe;
    struct strlist list = {0};
    WCHAR machine[MAX_COMPUTERNAME_LENGTH + 3];
    DWORD o, first_obj, last_obj, inst_count = 0;
    WCHAR **inst_names = NULL;
    BOOL all_objects, matched = FALSE, instance_wild_missed = FALSE;
    PDH_STATUS ret;

    if (!path || !size) return PDH_INVALID_ARGUMENT;
    if ((ret = check_source_name( source ))) return ret;
    if ((ret = parse_path( path, &pe ))) return ret;
    if (pe.machine && !is_local_name( pe.machine ))
    {
        free_path( &pe );
        return PDH_CSTATUS_NO_MACHINE;
    }
    if ((ret = local_machine_prefix( machine, ARRAY_SIZE(machine) )))
    {
        free_path( &pe );
        return ret;
    }

    all_objects = !wcscmp( pe.object, L"*" );
    first_obj = 0;
    last_obj = perf_object_count();
    if (!all_objects)
    {
        const struct perf_object_def *obj = perf_find_object( pe.object );
        if (!obj)
        {
            free_path( &pe );
            return PDH_CSTATUS_NO_OBJECT;
        }
        for (o = 0; o < perf_object_count(); o++) if (perf_object( o ) == obj) break;
        first_obj = o;
        last_obj = o + 1;
    }

    for (o = first_obj; o < last_obj; o++)
    {
        const struct perf_object_def *obj = perf_object( o );
        DWORD i, c;
        const WCHAR *single_instance[1] = { NULL };
        BOOL expand_inst, expand_ctr = has_wildcard( pe.counter ) && !(flags & PDH_NOEXPANDCOUNTERS_FLAG);
        const struct perf_counter_def *def = NULL;

        if (obj->kind == INST_NONE ? pe.instance != NULL : pe.instance == NULL)
        {
            if (all_objects) continue;
            ret = PDH_INVALID_PATH;
            goto fail;
        }
        if (!expand_ctr && !(def = perf_find_counter( obj, pe.counter )))
        {
            if (all_objects) continue;
            ret = PDH_CSTATUS_NO_COUNTER;
            goto fail;
        }

        expand_inst = obj->kind != INST_NONE && has_wildcard( pe.inst_raw ) && !(flags & PDH_NOEXPANDINSTANCES_FLAG);
        if (expand_inst)
        {
            if ((ret = perf_get_instances( obj, &inst_names, &inst_count ))) goto fail;
        }

        for (i = 0; i < (expand_inst ? inst_count : 1); i++)
        {
            const WCHAR *inst = single_instance[0];

            if (expand_inst)
            {
                if (!wild_match( pe.inst_raw, inst_names[i] )) continue;
                inst = inst_names[i];
            }
            else if (obj->kind != INST_NONE) inst = pe.inst_raw;

            if (expand_ctr)
            {
                for (c = 0; c < obj->count; c++)
                {
                    if (!wild_match( pe.counter, obj->counters[c].name )) continue;
                    add_expanded_path( &list, machine, obj->name, inst, obj->counters[c].name );
                    matched = TRUE;
                }
            }
            else
            {
                add_expanded_path( &list, machine, all_objects ? obj->name : pe.object, inst, all_objects ? def->name : pe.counter );
                matched = TRUE;
            }
        }
        if (expand_inst && !matched) instance_wild_missed = TRUE;
        perf_free_instances( inst_names, inst_count );
        inst_names = NULL;
        inst_count = 0;
    }

    free_path( &pe );
    if (!matched)
    {
        free( list.s );
        return instance_wild_missed ? PDH_CSTATUS_NO_INSTANCE : PDH_CSTATUS_NO_COUNTER;
    }
    if (!sl_finish( &list ))
    {
        free( list.s );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    ret = return_list( list.s, list.len, buf, size );
    free( list.s );
    return ret;

fail:
    perf_free_instances( inst_names, inst_count );
    free_path( &pe );
    free( list.s );
    return ret;
}

/***********************************************************************
 *              PdhExpandWildCardPathW   (PDH.@)
 */
PDH_STATUS WINAPI PdhExpandWildCardPathW( LPCWSTR szDataSource, LPCWSTR szWildCardPath, LPWSTR mszExpandedPathList, LPDWORD pcchPathListLength, DWORD dwFlags )
{
    TRACE("%s, %s, %p, %p, 0x%lx\n", debugstr_w(szDataSource), debugstr_w(szWildCardPath), mszExpandedPathList, pcchPathListLength, dwFlags);
    return expand_path( szDataSource, szWildCardPath, dwFlags, mszExpandedPathList, pcchPathListLength );
}

/***********************************************************************
 *              PdhExpandWildCardPathHW   (PDH.@)
 */
PDH_STATUS WINAPI PdhExpandWildCardPathHW( PDH_HLOG hDataSource, LPCWSTR szWildCardPath, LPWSTR mszExpandedPathList, LPDWORD pcchPathListLength, DWORD dwFlags )
{
    TRACE("%p, %s, %p, %p, 0x%lx\n", hDataSource, debugstr_w(szWildCardPath), mszExpandedPathList, pcchPathListLength, dwFlags);
    if (hDataSource) return PDH_INVALID_HANDLE;
    return expand_path( NULL, szWildCardPath, dwFlags, mszExpandedPathList, pcchPathListLength );
}

static PDH_STATUS expand_path_a( PDH_HLOG hsource, LPCSTR source, LPCSTR path, LPSTR buf, LPDWORD size, DWORD flags )
{
    WCHAR *sourceW = NULL, *pathW, *bufW;
    DWORD lenW = 0;
    PDH_STATUS ret;

    if (!path || !size) return PDH_INVALID_ARGUMENT;
    if (source && !(sourceW = pdh_strdup_aw( source ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    if (!(pathW = pdh_strdup_aw( path )))
    {
        free( sourceW );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    ret = hsource ? PdhExpandWildCardPathHW( hsource, pathW, NULL, &lenW, flags )
                  : PdhExpandWildCardPathW( sourceW, pathW, NULL, &lenW, flags );
    if (ret == PDH_MORE_DATA)
    {
        if ((bufW = malloc( lenW * sizeof(WCHAR) )))
        {
            ret = PdhExpandWildCardPathW( sourceW, pathW, bufW, &lenW, flags );
            if (!ret) ret = list_to_ansi( bufW, lenW, buf, size );
            free( bufW );
        }
        else ret = PDH_MEMORY_ALLOCATION_FAILURE;
    }
    free( sourceW );
    free( pathW );
    return ret;
}

/***********************************************************************
 *              PdhExpandWildCardPathA   (PDH.@)
 */
PDH_STATUS WINAPI PdhExpandWildCardPathA( LPCSTR szDataSource, LPCSTR szWildCardPath, LPSTR mszExpandedPathList, LPDWORD pcchPathListLength, DWORD dwFlags )
{
    TRACE("%s, %s, %p, %p, 0x%lx\n", debugstr_a(szDataSource), debugstr_a(szWildCardPath), mszExpandedPathList, pcchPathListLength, dwFlags);
    return expand_path_a( NULL, szDataSource, szWildCardPath, mszExpandedPathList, pcchPathListLength, dwFlags );
}

/***********************************************************************
 *              PdhExpandWildCardPathHA   (PDH.@)
 */
PDH_STATUS WINAPI PdhExpandWildCardPathHA( PDH_HLOG hDataSource, LPCSTR szWildCardPath, LPSTR mszExpandedPathList, LPDWORD pcchPathListLength, DWORD dwFlags )
{
    TRACE("%p, %s, %p, %p, 0x%lx\n", hDataSource, debugstr_a(szWildCardPath), mszExpandedPathList, pcchPathListLength, dwFlags);
    if (hDataSource) return PDH_INVALID_HANDLE;
    return expand_path_a( NULL, NULL, szWildCardPath, mszExpandedPathList, pcchPathListLength, dwFlags );
}

/***********************************************************************
 *              PdhExpandCounterPathA   (PDH.@)
 */
PDH_STATUS WINAPI PdhExpandCounterPathA( LPCSTR szWildCardPath, LPSTR mszExpandedPathList, LPDWORD pcchPathListLength )
{
    TRACE("%s, %p, %p\n", debugstr_a(szWildCardPath), mszExpandedPathList, pcchPathListLength);
    return PdhExpandWildCardPathA(NULL, szWildCardPath, mszExpandedPathList, pcchPathListLength, 0);
}

/***********************************************************************
 *              PdhExpandCounterPathW   (PDH.@)
 */
PDH_STATUS WINAPI PdhExpandCounterPathW( LPCWSTR szWildCardPath, LPWSTR mszExpandedPathList, LPDWORD pcchPathListLength )
{
    TRACE("%s, %p, %p\n", debugstr_w(szWildCardPath), mszExpandedPathList, pcchPathListLength);
    return PdhExpandWildCardPathW(NULL, szWildCardPath, mszExpandedPathList, pcchPathListLength, 0);
}

/***********************************************************************
 *              PdhParseCounterPathW   (PDH.@)
 */
PDH_STATUS WINAPI PdhParseCounterPathW( LPCWSTR path, PDH_COUNTER_PATH_ELEMENTS_W *buffer, LPDWORD size, DWORD flags )
{
    WCHAR machine[MAX_COMPUTERNAME_LENGTH + 3];
    struct path_elements pe;
    const WCHAR *m;
    DWORD required;
    WCHAR *p;
    PDH_STATUS ret;

    TRACE("%s %p %p 0x%lx\n", debugstr_w(path), buffer, size, flags);

    if (!path || !*path || !size) return PDH_INVALID_ARGUMENT;
    if ((ret = parse_path( path, &pe ))) return ret;

    if (pe.machine) m = pe.machine;
    else if (!(ret = local_machine_prefix( machine, ARRAY_SIZE(machine) ))) m = machine;
    else
    {
        free_path( &pe );
        return ret;
    }

    required = sizeof(*buffer) + (lstrlenW( m ) + 1 + lstrlenW( pe.object ) + 1 + lstrlenW( pe.counter ) + 1) * sizeof(WCHAR);
    if (pe.instance) required += (lstrlenW( pe.instance ) + 1) * sizeof(WCHAR);
    if (pe.parent) required += (lstrlenW( pe.parent ) + 1) * sizeof(WCHAR);

    if (!buffer || *size < required)
    {
        *size = required;
        free_path( &pe );
        return PDH_MORE_DATA;
    }

    p = (WCHAR *)(buffer + 1);
    buffer->szMachineName = p;
    lstrcpyW( p, m );
    p += lstrlenW( p ) + 1;
    buffer->szObjectName = p;
    lstrcpyW( p, pe.object );
    p += lstrlenW( p ) + 1;
    buffer->szInstanceName = NULL;
    buffer->szParentInstance = NULL;
    if (pe.instance)
    {
        buffer->szInstanceName = p;
        lstrcpyW( p, pe.instance );
        p += lstrlenW( p ) + 1;
    }
    if (pe.parent)
    {
        buffer->szParentInstance = p;
        lstrcpyW( p, pe.parent );
        p += lstrlenW( p ) + 1;
    }
    buffer->dwInstanceIndex = pe.index;
    buffer->szCounterName = p;
    lstrcpyW( p, pe.counter );

    *size = required;
    free_path( &pe );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhParseCounterPathA   (PDH.@)
 */
PDH_STATUS WINAPI PdhParseCounterPathA( LPCSTR path, PDH_COUNTER_PATH_ELEMENTS_A *buffer, LPDWORD size, DWORD flags )
{
    PDH_COUNTER_PATH_ELEMENTS_W *elw;
    DWORD sizeW = 0, need;
    WCHAR *pathW;
    PDH_STATUS ret;
    const WCHAR *strw[5];
    char **dst[5];
    int len[5], i;
    char *p;

    TRACE("%s %p %p 0x%lx\n", debugstr_a(path), buffer, size, flags);

    if (!path || !*path || !size) return PDH_INVALID_ARGUMENT;
    if (!(pathW = pdh_strdup_aw( path ))) return PDH_MEMORY_ALLOCATION_FAILURE;

    ret = PdhParseCounterPathW( pathW, NULL, &sizeW, flags );
    if (ret != PDH_MORE_DATA || !(elw = malloc( sizeW )))
    {
        free( pathW );
        return ret == PDH_MORE_DATA ? PDH_MEMORY_ALLOCATION_FAILURE : ret;
    }
    if ((ret = PdhParseCounterPathW( pathW, elw, &sizeW, flags )))
    {
        free( elw );
        free( pathW );
        return ret;
    }

    strw[0] = elw->szMachineName;  strw[1] = elw->szObjectName;  strw[2] = elw->szInstanceName;
    strw[3] = elw->szParentInstance;  strw[4] = elw->szCounterName;
    need = sizeof(*buffer);
    for (i = 0; i < 5; i++)
    {
        len[i] = strw[i] ? WideCharToMultiByte( CP_ACP, 0, strw[i], -1, NULL, 0, NULL, NULL ) : 0;
        need += len[i];
    }
    if (!buffer || *size < need)
    {
        *size = need;
        ret = PDH_MORE_DATA;
    }
    else
    {
        dst[0] = &buffer->szMachineName;  dst[1] = &buffer->szObjectName;  dst[2] = &buffer->szInstanceName;
        dst[3] = &buffer->szParentInstance;  dst[4] = &buffer->szCounterName;
        p = (char *)(buffer + 1);
        for (i = 0; i < 5; i++)
        {
            *dst[i] = NULL;
            if (!strw[i]) continue;
            *dst[i] = p;
            WideCharToMultiByte( CP_ACP, 0, strw[i], -1, p, len[i], NULL, NULL );
            p += len[i];
        }
        buffer->dwInstanceIndex = elw->dwInstanceIndex;
        *size = need;
    }
    free( elw );
    free( pathW );
    return ret;
}

/***********************************************************************
 *              PdhBindInputDataSourceW   (PDH.@)
 */
PDH_STATUS WINAPI PdhBindInputDataSourceW(PDH_HLOG *source, const WCHAR *filenamelist)
{
    PDH_STATUS ret;

    TRACE("%p %s\n", source, debugstr_w(filenamelist));

    if (!source) return PDH_INVALID_ARGUMENT;
    *source = NULL;
    if (!filenamelist) return ERROR_SUCCESS;   /* the real time data source is the null handle */
    if ((ret = check_source_name( filenamelist ))) return ret;
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhBindInputDataSourceA   (PDH.@)
 */
PDH_STATUS WINAPI PdhBindInputDataSourceA(PDH_HLOG *source, const char *filenamelist)
{
    PDH_STATUS ret;
    WCHAR *listW = NULL;

    TRACE("%p %s\n", source, debugstr_a(filenamelist));

    if (filenamelist && !(listW = pdh_strdup_aw( filenamelist ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    ret = PdhBindInputDataSourceW( source, listW );
    free( listW );
    return ret;
}

/***********************************************************************
 *              PdhCloseLog   (PDH.@)
 */
PDH_STATUS WINAPI PdhCloseLog( PDH_HLOG log, DWORD flags )
{
    TRACE("%p 0x%lx\n", log, flags);
    return log ? PDH_INVALID_HANDLE : ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhOpenQueryH   (PDH.@)
 */
PDH_STATUS WINAPI PdhOpenQueryH( PDH_HLOG source, DWORD_PTR userdata, PDH_HQUERY *query )
{
    TRACE("%p %Ix %p\n", source, userdata, query);
    if (!query) return PDH_INVALID_ARGUMENT;
    if (source) return PDH_INVALID_HANDLE;
    return PdhOpenQueryW( NULL, userdata, query );
}

/* ---- counter arrays, defaults, translation ---- */

/* The item list of a counter for the array functions: a wildcard counter has its items, any other counter one item
 * named after its instance. Returns the number of items. The caller holds pdh_handle_cs. */
static DWORD counter_items( struct counter *counter, struct item *single, const WCHAR **single_name )
{
    if (counter->multi) return counter->nitems;
    memset( single, 0, sizeof(*single) );
    single->cur = counter->cur;
    if (counter->collects >= 2)
    {
        single->prev = counter->prev;
        single->has_prev = TRUE;
    }
    *single_name = counter->instance ? counter->instance : L"";
    single->name = (WCHAR *)*single_name;
    return 1;
}

static const struct item *item_at( struct counter *counter, const struct item *single, DWORD i )
{
    return counter->multi ? &counter->items[i] : single;
}

static PDH_STATUS formatted_array( PDH_HCOUNTER handle, DWORD format, DWORD *size, DWORD *count, void *buffer, BOOL ansi )
{
    struct counter *counter = handle;
    struct item single;
    const WCHAR *single_name = NULL;
    DWORD n, i, need, strbytes = 0;
    PDH_STATUS ret = ERROR_SUCCESS;
    const DWORD item_size = ansi ? sizeof(PDH_FMT_COUNTERVALUE_ITEM_A) : sizeof(PDH_FMT_COUNTERVALUE_ITEM_W);

    if (!size || !count) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    n = counter_items( counter, &single, &single_name );
    for (i = 0; i < n; i++)
    {
        const WCHAR *name = item_at( counter, &single, i )->name;
        strbytes += ansi ? WideCharToMultiByte( CP_ACP, 0, name, -1, NULL, 0, NULL, NULL ) : (lstrlenW( name ) + 1) * sizeof(WCHAR);
    }
    need = n * item_size + strbytes;
    if (*size < need || !buffer)
    {
        *size = need;
        *count = n;
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_MORE_DATA;
    }
    {
        char *str = (char *)buffer + n * item_size;

        for (i = 0; i < n; i++)
        {
            const struct item *it = item_at( counter, &single, i );
            PDH_FMT_COUNTERVALUE *value;
            PDH_STATUS st;

            if (ansi)
            {
                PDH_FMT_COUNTERVALUE_ITEM_A *out = (PDH_FMT_COUNTERVALUE_ITEM_A *)buffer + i;
                int len = WideCharToMultiByte( CP_ACP, 0, it->name, -1, str, strbytes, NULL, NULL );
                out->szName = str;
                str += len;
                value = &out->FmtValue;
            }
            else
            {
                PDH_FMT_COUNTERVALUE_ITEM_W *out = (PDH_FMT_COUNTERVALUE_ITEM_W *)buffer + i;
                DWORD len = (lstrlenW( it->name ) + 1) * sizeof(WCHAR);
                memcpy( str, it->name, len );
                out->szName = (WCHAR *)str;
                str += len;
                value = &out->FmtValue;
            }
            st = format_value( counter, format, &it->cur, it->has_prev ? &it->prev : NULL, value );
            if (st && !ret) ret = ERROR_SUCCESS;   /* a failed item reports its own CStatus */
        }
    }
    *size = need;
    *count = n;
    LeaveCriticalSection( &pdh_handle_cs );
    return ret;
}

/***********************************************************************
 *              PdhGetFormattedCounterArrayW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetFormattedCounterArrayW( PDH_HCOUNTER handle, DWORD format, LPDWORD size, LPDWORD count,
                                                PPDH_FMT_COUNTERVALUE_ITEM_W buffer )
{
    TRACE("%p %lx %p %p %p\n", handle, format, size, count, buffer);
    return formatted_array( handle, format, size, count, buffer, FALSE );
}

/***********************************************************************
 *              PdhGetFormattedCounterArrayA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetFormattedCounterArrayA( PDH_HCOUNTER handle, DWORD format, LPDWORD size, LPDWORD count,
                                                PPDH_FMT_COUNTERVALUE_ITEM_A buffer )
{
    TRACE("%p %lx %p %p %p\n", handle, format, size, count, buffer);
    return formatted_array( handle, format, size, count, buffer, TRUE );
}

static PDH_STATUS raw_array( PDH_HCOUNTER handle, DWORD *size, DWORD *count, void *buffer, BOOL ansi )
{
    struct counter *counter = handle;
    struct item single;
    const WCHAR *single_name = NULL;
    DWORD n, i, need, strbytes = 0;
    const DWORD item_size = ansi ? sizeof(PDH_RAW_COUNTER_ITEM_A) : sizeof(PDH_RAW_COUNTER_ITEM_W);

    if (!size || !count) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    n = counter_items( counter, &single, &single_name );
    for (i = 0; i < n; i++)
    {
        const WCHAR *name = item_at( counter, &single, i )->name;
        strbytes += ansi ? WideCharToMultiByte( CP_ACP, 0, name, -1, NULL, 0, NULL, NULL ) : (lstrlenW( name ) + 1) * sizeof(WCHAR);
    }
    need = n * item_size + strbytes;
    if (*size < need || !buffer)
    {
        *size = need;
        *count = n;
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_MORE_DATA;
    }
    {
        char *str = (char *)buffer + n * item_size;

        for (i = 0; i < n; i++)
        {
            const struct item *it = item_at( counter, &single, i );
            PDH_RAW_COUNTER *raw;

            if (ansi)
            {
                PDH_RAW_COUNTER_ITEM_A *out = (PDH_RAW_COUNTER_ITEM_A *)buffer + i;
                int len = WideCharToMultiByte( CP_ACP, 0, it->name, -1, str, strbytes, NULL, NULL );
                out->szName = str;
                str += len;
                raw = &out->RawValue;
            }
            else
            {
                PDH_RAW_COUNTER_ITEM_W *out = (PDH_RAW_COUNTER_ITEM_W *)buffer + i;
                DWORD len = (lstrlenW( it->name ) + 1) * sizeof(WCHAR);
                memcpy( str, it->name, len );
                out->szName = (WCHAR *)str;
                str += len;
                raw = &out->RawValue;
            }
            raw->CStatus     = it->cur.status;
            raw->TimeStamp   = it->cur.stamp;
            raw->FirstValue  = it->cur.first;
            raw->SecondValue = it->cur.second;
            raw->MultiCount  = 1;
        }
    }
    *size = need;
    *count = n;
    LeaveCriticalSection( &pdh_handle_cs );
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhGetRawCounterArrayW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetRawCounterArrayW( PDH_HCOUNTER handle, LPDWORD size, LPDWORD count, PPDH_RAW_COUNTER_ITEM_W buffer )
{
    TRACE("%p %p %p %p\n", handle, size, count, buffer);
    return raw_array( handle, size, count, buffer, FALSE );
}

/***********************************************************************
 *              PdhGetRawCounterArrayA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetRawCounterArrayA( PDH_HCOUNTER handle, LPDWORD size, LPDWORD count, PPDH_RAW_COUNTER_ITEM_A buffer )
{
    TRACE("%p %p %p %p\n", handle, size, count, buffer);
    return raw_array( handle, size, count, buffer, TRUE );
}

/***********************************************************************
 *              PdhIsRealTimeQuery   (PDH.@)
 */
BOOL WINAPI PdhIsRealTimeQuery( PDH_HQUERY handle )
{
    struct query *query = handle;
    BOOL ret = FALSE;

    TRACE("%p\n", handle);

    EnterCriticalSection( &pdh_handle_cs );
    if (query && query->magic == PDH_MAGIC_QUERY) ret = TRUE;   /* the live system is the only data source */
    LeaveCriticalSection( &pdh_handle_cs );
    return ret;
}

/***********************************************************************
 *              PdhConnectMachineW   (PDH.@)
 */
PDH_STATUS WINAPI PdhConnectMachineW( LPCWSTR name )
{
    TRACE("%s\n", debugstr_w(name));
    if (!name || !*name) return ERROR_SUCCESS;
    return is_local_name( name ) ? ERROR_SUCCESS : PDH_CSTATUS_NO_MACHINE;
}

/* the default counter of each set, as the performance counter registry names it */
static const WCHAR *default_counter_name( const struct perf_object_def *obj )
{
    return obj->default_counter;
}

static PDH_STATUS return_string( const WCHAR *str, WCHAR *buf, DWORD *size )
{
    DWORD need = lstrlenW( str ) + 1;

    if (!buf || *size < need)
    {
        *size = need;
        return PDH_MORE_DATA;
    }
    memcpy( buf, str, need * sizeof(WCHAR) );
    *size = need;
    return ERROR_SUCCESS;
}

static PDH_STATUS return_string_a( const WCHAR *str, char *buf, DWORD *size )
{
    int need = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );

    if (!buf || *size < need)
    {
        *size = need;
        return PDH_MORE_DATA;
    }
    WideCharToMultiByte( CP_ACP, 0, str, -1, buf, need, NULL, NULL );
    *size = need;
    return ERROR_SUCCESS;
}

static PDH_STATUS default_object( const WCHAR *source, const WCHAR *machine, WCHAR *buf, DWORD *size )
{
    PDH_STATUS ret;

    if (!size || (machine && !*machine)) return PDH_INVALID_ARGUMENT;
    /* the data source is not looked at: a file that does not exist is accepted, as on Windows */
    if ((ret = check_machine_name( machine ))) return ret;
    return return_string( L"Processor", buf, size );
}

static PDH_STATUS default_counter( const WCHAR *source, const WCHAR *machine, const WCHAR *object, WCHAR *buf, DWORD *size )
{
    const struct perf_object_def *obj;
    PDH_STATUS ret;

    if (!object || !size || (machine && !*machine)) return PDH_INVALID_ARGUMENT;
    if ((ret = check_machine_name( machine ))) return ret;
    if (!(obj = perf_find_object( object ))) return PDH_CSTATUS_NO_OBJECT;
    return return_string( default_counter_name( obj ), buf, size );
}

/***********************************************************************
 *              PdhGetDefaultPerfObjectW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfObjectW( LPCWSTR source, LPCWSTR machine, LPWSTR buf, LPDWORD size )
{
    TRACE("%s %s %p %p\n", debugstr_w(source), debugstr_w(machine), buf, size);
    return default_object( source, machine, buf, size );
}

/***********************************************************************
 *              PdhGetDefaultPerfObjectHW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfObjectHW( PDH_HLOG source, LPCWSTR machine, LPWSTR buf, LPDWORD size )
{
    TRACE("%p %s %p %p\n", source, debugstr_w(machine), buf, size);
    if (source) return PDH_INVALID_HANDLE;
    return default_object( NULL, machine, buf, size );
}

static PDH_STATUS default_object_a( PDH_HLOG hsource, LPCSTR machine, LPSTR buf, LPDWORD size )
{
    WCHAR *machineW = NULL;
    PDH_STATUS ret;

    if (!size || (machine && !*machine)) return PDH_INVALID_ARGUMENT;
    if (hsource) return PDH_INVALID_HANDLE;
    if (machine && !(machineW = pdh_strdup_aw( machine ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    if (!(ret = check_machine_name( machineW ))) ret = return_string_a( L"Processor", buf, size );
    free( machineW );
    return ret;
}

/***********************************************************************
 *              PdhGetDefaultPerfObjectA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfObjectA( LPCSTR source, LPCSTR machine, LPSTR buf, LPDWORD size )
{
    TRACE("%s %s %p %p\n", debugstr_a(source), debugstr_a(machine), buf, size);
    return default_object_a( NULL, machine, buf, size );
}

/***********************************************************************
 *              PdhGetDefaultPerfObjectHA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfObjectHA( PDH_HLOG source, LPCSTR machine, LPSTR buf, LPDWORD size )
{
    TRACE("%p %s %p %p\n", source, debugstr_a(machine), buf, size);
    return default_object_a( source, machine, buf, size );
}

/***********************************************************************
 *              PdhGetDefaultPerfCounterW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfCounterW( LPCWSTR source, LPCWSTR machine, LPCWSTR object, LPWSTR buf, LPDWORD size )
{
    TRACE("%s %s %s %p %p\n", debugstr_w(source), debugstr_w(machine), debugstr_w(object), buf, size);
    return default_counter( source, machine, object, buf, size );
}

/***********************************************************************
 *              PdhGetDefaultPerfCounterHW   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfCounterHW( PDH_HLOG source, LPCWSTR machine, LPCWSTR object, LPWSTR buf, LPDWORD size )
{
    TRACE("%p %s %s %p %p\n", source, debugstr_w(machine), debugstr_w(object), buf, size);
    if (source) return PDH_INVALID_HANDLE;
    return default_counter( NULL, machine, object, buf, size );
}

static PDH_STATUS default_counter_a( PDH_HLOG hsource, LPCSTR machine, LPCSTR object, LPSTR buf, LPDWORD size )
{
    WCHAR *machineW = NULL, *objectW = NULL;
    const struct perf_object_def *obj;
    PDH_STATUS ret;

    if (!object || !size || (machine && !*machine)) return PDH_INVALID_ARGUMENT;
    if (hsource) return PDH_INVALID_HANDLE;
    if (machine && !(machineW = pdh_strdup_aw( machine ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    if (!(objectW = pdh_strdup_aw( object ))) ret = PDH_MEMORY_ALLOCATION_FAILURE;
    else if ((ret = check_machine_name( machineW ))) ;
    else if (!(obj = perf_find_object( objectW ))) ret = PDH_CSTATUS_NO_OBJECT;
    else ret = return_string_a( default_counter_name( obj ), buf, size );
    free( machineW );
    free( objectW );
    return ret;
}

/***********************************************************************
 *              PdhGetDefaultPerfCounterA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfCounterA( LPCSTR source, LPCSTR machine, LPCSTR object, LPSTR buf, LPDWORD size )
{
    TRACE("%s %s %s %p %p\n", debugstr_a(source), debugstr_a(machine), debugstr_a(object), buf, size);
    return default_counter_a( NULL, machine, object, buf, size );
}

/***********************************************************************
 *              PdhGetDefaultPerfCounterHA   (PDH.@)
 */
PDH_STATUS WINAPI PdhGetDefaultPerfCounterHA( PDH_HLOG source, LPCSTR machine, LPCSTR object, LPSTR buf, LPDWORD size )
{
    TRACE("%p %s %s %p %p\n", source, debugstr_a(machine), debugstr_a(object), buf, size);
    return default_counter_a( source, machine, object, buf, size );
}

/***********************************************************************
 *              PdhTranslate009CounterW   (PDH.@)
 *              PdhTranslateLocaleCounterW   (PDH.@)
 *
 * Only the English counter names exist, so a valid path translates to itself.
 */
static PDH_STATUS translate_counter( const WCHAR *path, WCHAR *buf, DWORD *size )
{
    struct path_elements pe;
    PDH_STATUS ret;

    if (!path || !size) return PDH_INVALID_ARGUMENT;
    ret = check_path( path, TRUE, &pe, NULL, NULL );
    free_path( &pe );
    if (ret) return ret;
    return return_string( path, buf, size );
}

PDH_STATUS WINAPI PdhTranslate009CounterW( LPCWSTR path, LPWSTR buf, LPDWORD size )
{
    TRACE("%s %p %p\n", debugstr_w(path), buf, size);
    return translate_counter( path, buf, size );
}

PDH_STATUS WINAPI PdhTranslateLocaleCounterW( LPCWSTR path, LPWSTR buf, LPDWORD size )
{
    TRACE("%s %p %p\n", debugstr_w(path), buf, size);
    return translate_counter( path, buf, size );
}

static PDH_STATUS translate_counter_a( const char *path, char *buf, DWORD *size )
{
    WCHAR *pathW, *out;
    DWORD len = PDH_MAX_COUNTER_PATH;
    PDH_STATUS ret;

    if (!path || !size) return PDH_INVALID_ARGUMENT;
    if (!(pathW = pdh_strdup_aw( path ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    if (!(out = malloc( len * sizeof(WCHAR) )))
    {
        free( pathW );
        return PDH_MEMORY_ALLOCATION_FAILURE;
    }
    if (!(ret = translate_counter( pathW, out, &len ))) ret = return_string_a( out, buf, size );
    free( pathW );
    free( out );
    return ret;
}

PDH_STATUS WINAPI PdhTranslate009CounterA( LPCSTR path, LPSTR buf, LPDWORD size )
{
    TRACE("%s %p %p\n", debugstr_a(path), buf, size);
    return translate_counter_a( path, buf, size );
}

PDH_STATUS WINAPI PdhTranslateLocaleCounterA( LPCSTR path, LPSTR buf, LPDWORD size )
{
    TRACE("%s %p %p\n", debugstr_a(path), buf, size);
    return translate_counter_a( path, buf, size );
}

/***********************************************************************
 *              PdhParseInstanceNameW   (PDH.@)
 */
PDH_STATUS WINAPI PdhParseInstanceNameW( LPCWSTR instance, LPWSTR name, LPDWORD name_len, LPWSTR parent,
                                         LPDWORD parent_len, LPDWORD index )
{
    const WCHAR *slash, *start;
    WCHAR tmp[PDH_MAX_INSTANCE_NAME];
    DWORD idx = 0, n, plen;
    const WCHAR *hash;

    TRACE("%s %p %p %p %p %p\n", debugstr_w(instance), name, name_len, parent, parent_len, index);

    if (!instance || !name_len || !parent_len || !index) return PDH_INVALID_ARGUMENT;

    if ((slash = wcschr( instance, '/' )))
    {
        plen = slash - instance;
        start = slash + 1;
    }
    else
    {
        plen = 0;
        start = instance;
    }
    lstrcpynW( tmp, start, ARRAY_SIZE(tmp) );
    if ((hash = wcsrchr( tmp, '#' )) && hash > tmp && hash[1])
    {
        const WCHAR *d;
        for (d = hash + 1; *d >= '0' && *d <= '9'; d++) ;
        if (!*d)
        {
            idx = wcstoul( hash + 1, NULL, 10 );
            tmp[hash - tmp] = 0;
        }
    }
    n = lstrlenW( tmp ) + 1;
    if (!name || !parent || *name_len < n || *parent_len < plen + 1)
    {
        *name_len = n;
        *parent_len = plen + 1;
        return PDH_MORE_DATA;
    }
    memcpy( name, tmp, n * sizeof(WCHAR) );
    *name_len = n;
    memcpy( parent, instance, plen * sizeof(WCHAR) );
    parent[plen] = 0;
    *parent_len = plen + 1;
    *index = idx;
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhParseInstanceNameA   (PDH.@)
 */
PDH_STATUS WINAPI PdhParseInstanceNameA( LPCSTR instance, LPSTR name, LPDWORD name_len, LPSTR parent,
                                         LPDWORD parent_len, LPDWORD index )
{
    WCHAR *instW, nameW[PDH_MAX_INSTANCE_NAME], parentW[PDH_MAX_INSTANCE_NAME];
    DWORD nl = ARRAY_SIZE(nameW), pl = ARRAY_SIZE(parentW);
    PDH_STATUS ret;

    TRACE("%s %p %p %p %p %p\n", debugstr_a(instance), name, name_len, parent, parent_len, index);

    if (!instance || !name_len || !parent_len || !index) return PDH_INVALID_ARGUMENT;
    if (!(instW = pdh_strdup_aw( instance ))) return PDH_MEMORY_ALLOCATION_FAILURE;
    ret = PdhParseInstanceNameW( instW, nameW, &nl, parentW, &pl, index );
    free( instW );
    if (ret) return ret;
    {
        int n = WideCharToMultiByte( CP_ACP, 0, nameW, -1, NULL, 0, NULL, NULL );
        int p = WideCharToMultiByte( CP_ACP, 0, parentW, -1, NULL, 0, NULL, NULL );

        if (!name || !parent || *name_len < n || *parent_len < p)
        {
            *name_len = n;
            *parent_len = p;
            return PDH_MORE_DATA;
        }
        WideCharToMultiByte( CP_ACP, 0, nameW, -1, name, n, NULL, NULL );
        WideCharToMultiByte( CP_ACP, 0, parentW, -1, parent, p, NULL, NULL );
        *name_len = n;
        *parent_len = p;
    }
    return ERROR_SUCCESS;
}

/***********************************************************************
 *              PdhComputeCounterStatistics   (PDH.@)
 */
PDH_STATUS WINAPI PdhComputeCounterStatistics( PDH_HCOUNTER handle, DWORD format, DWORD first, DWORD count,
                                               PPDH_RAW_COUNTER raw, PPDH_STATISTICS stat )
{
    struct counter *counter = handle;
    PDH_STATUS ret = ERROR_SUCCESS;
    PDH_FMT_COUNTERVALUE value;
    double sum = 0.0, min = 0.0, max = 0.0, v;
    DWORD i, valid = 0;
    struct sample cur, prev;

    TRACE("%p %lx %lu %lu %p %p\n", handle, format, first, count, raw, stat);

    if (!raw || !stat || !count) return PDH_INVALID_ARGUMENT;

    EnterCriticalSection( &pdh_handle_cs );
    if (!counter || counter->magic != PDH_MAGIC_COUNTER)
    {
        LeaveCriticalSection( &pdh_handle_cs );
        return PDH_INVALID_HANDLE;
    }
    memset( stat, 0, sizeof(*stat) );
    stat->dwFormat = format;
    /* the values come from consecutive pairs of the array: entry i against entry i-1 */
    for (i = first + 1; i < first + count; i++)
    {
        raw_to_sample( &raw[i], &cur );
        raw_to_sample( &raw[i - 1], &prev );
        if (format_value( counter, PDH_FMT_DOUBLE | (format & ~(PDH_FMT_LONG | PDH_FMT_LARGE | PDH_FMT_DOUBLE)), &cur, &prev,
                          &value )) continue;
        v = value.doubleValue;
        if (!valid || v < min) min = v;
        if (!valid || v > max) max = v;
        sum += v;
        valid++;
    }
    if (!valid && count == 1)
    {
        raw_to_sample( &raw[first], &cur );
        if (!format_value( counter, PDH_FMT_DOUBLE | (format & ~(PDH_FMT_LONG | PDH_FMT_LARGE | PDH_FMT_DOUBLE)), &cur, NULL, &value ))
        {
            min = max = sum = value.doubleValue;
            valid = 1;
        }
    }
    if (!valid)
    {
        ret = PDH_INVALID_DATA;
    }
    else
    {
        PDH_FMT_COUNTERVALUE *dst[3] = { &stat->min, &stat->max, &stat->mean };
        double val[3] = { min, max, sum / valid };

        stat->count = valid;
        for (i = 0; i < 3; i++)
        {
            dst[i]->CStatus = PDH_CSTATUS_VALID_DATA;
            if (format & PDH_FMT_LONG) dst[i]->longValue = to_long( val[i] );
            else if (format & PDH_FMT_LARGE) dst[i]->largeValue = to_large( val[i] );
            else dst[i]->doubleValue = val[i];
        }
    }
    LeaveCriticalSection( &pdh_handle_cs );
    return ret;
}
