/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The bounds-checking (_s) string and character functions that ntdll exports on NT6+
 * COPYRIGHT:   Copyright 2000 Alexandre Julliard
 *              Copyright 2000 Jon Griffiths
 *              Copyright 2003 Thomas Mertes
 *              Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * After dlls/ntdll/string.c, wcstring.c, printf.c and misc.c of Wine. Like ntdll on Windows, these functions
 * return the error and never call an invalid-parameter handler.
 */

#include <ntdll.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>

#define NDEBUG
#include <debug.h>

#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif
#ifndef STRUNCATE
#define STRUNCATE 80
#endif

#define C1_UPPER 0x0001
#define C1_LOWER 0x0002
#define C1_DIGIT 0x0004
#define C1_SPACE 0x0008
#define C1_PUNCT 0x0010
#define C1_CNTRL 0x0020
#define C1_BLANK 0x0040
#define C1_XDIGIT 0x0080
#define C1_ALPHA 0x0100

errno_t __cdecl _ui64toa_s(unsigned __int64 value, char *str, size_t size, int radix);
errno_t __cdecl _ui64tow_s(unsigned __int64 value, wchar_t *str, size_t size, int radix);

typedef unsigned long __msvcrt_ulong;
typedef long __msvcrt_long;

/* NT6 string functions, with the argument checks of the Windows ntdll (UCRT algorithms, no invalid-parameter handler) */

errno_t
__cdecl
strcat_s(
    _Inout_updates_z_(size) char *dst,
    _In_ size_t size,
    _In_z_ const char *src)
{
    char *d;
    const char *s;
    size_t available;

    if (!dst || !size) return EINVAL;
    if (!src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    available = size;
    while (available > 0 && *d != 0)
    {
        d++;
        available--;
    }
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }

    s = src;
    while ((*d++ = *s++) != 0 && --available > 0)
        ;
    if (available == 0)
    {
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

errno_t
__cdecl
strncat_s(
    _Inout_updates_z_(size) char *dst,
    _In_ size_t size,
    _In_reads_or_z_(count) const char *src,
    _In_ size_t count)
{
    char *d;
    const char *s;
    size_t available, remaining;

    if (count == 0 && !dst && size == 0) return 0;
    if (!dst || !size) return EINVAL;
    if (count != 0 && !src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    available = size;
    remaining = count;
    while (available > 0 && *d != 0)
    {
        d++;
        available--;
    }
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }

    s = src;
    if (count == _TRUNCATE)
    {
        while ((*d++ = *s++) != 0 && --available > 0)
            ;
    }
    else
    {
        while (remaining > 0 && (*d++ = *s++) != 0 && --available > 0)
            remaining--;
        if (remaining == 0)
            *d = 0;
    }

    if (available == 0)
    {
        if (count == _TRUNCATE)
        {
            dst[size - 1] = 0;
            return STRUNCATE;
        }
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

errno_t
__cdecl
strncpy_s(
    _Out_writes_z_(size) char *dst,
    _In_ size_t size,
    _In_reads_or_z_(count) const char *src,
    _In_ size_t count)
{
    char *d;
    const char *s;
    size_t available, remaining;

    if (count == 0 && !dst && size == 0) return 0;
    if (!dst || !size) return EINVAL;
    if (count == 0)
    {
        *dst = 0;
        return 0;
    }
    if (!src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    s = src;
    available = size;
    remaining = count;
    if (count == _TRUNCATE)
    {
        while ((*d++ = *s++) != 0 && --available > 0)
            ;
    }
    else
    {
        while ((*d++ = *s++) != 0 && --available > 0 && --remaining > 0)
            ;
        if (remaining == 0)
            *d = 0;
    }

    if (available == 0)
    {
        if (count == _TRUNCATE)
        {
            dst[size - 1] = 0;
            return STRUNCATE;
        }
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

errno_t
__cdecl
_strset_s(
    _Inout_updates_z_(size) char *dst,
    _In_ size_t size,
    _In_ int value)
{
    char *d = dst;
    size_t available = size;

    if (!dst || !size) return EINVAL;
    while (*d != 0 && --available > 0)
        *d++ = (char)value;
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }
    return 0;
}

errno_t
__cdecl
_strnset_s(
    _Inout_updates_z_(size) char *dst,
    _In_ size_t size,
    _In_ int value,
    _In_ size_t count)
{
    char *d = dst;
    size_t available = size;
    size_t remaining = count;

    if (count == 0 && !dst && size == 0) return 0;
    if (!dst || !size) return EINVAL;
    while (*d != 0 && remaining > 0 && --available > 0)
    {
        *d++ = (char)value;
        remaining--;
    }
    if (remaining == 0)
    {
        while (*d != 0 && --available > 0)
            d++;
    }
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }
    return 0;
}

errno_t
__cdecl
_strlwr_s(
    _Inout_updates_z_(size) char *str,
    _In_ size_t size)
{
    if (!str || !size) return EINVAL;
    if (strnlen(str, size) == size)
    {
        *str = 0;
        return EINVAL;
    }
    _strlwr(str);
    return 0;
}

errno_t
__cdecl
_strupr_s(
    _Inout_updates_z_(size) char *str,
    _In_ size_t size)
{
    if (!str || !size) return EINVAL;
    if (strnlen(str, size) == size)
    {
        *str = 0;
        return EINVAL;
    }
    _strupr(str);
    return 0;
}

errno_t
__cdecl
_wcsset_s(
    _Inout_updates_z_(size) WCHAR *dst,
    _In_ size_t size,
    _In_ wchar_t value)
{
    WCHAR *d = dst;
    size_t available = size;

    if (!dst || !size) return EINVAL;
    while (*d != 0 && --available > 0)
        *d++ = (WCHAR)value;
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }
    return 0;
}

errno_t
__cdecl
_wcsnset_s(
    _Inout_updates_z_(size) WCHAR *dst,
    _In_ size_t size,
    _In_ wchar_t value,
    _In_ size_t count)
{
    WCHAR *d = dst;
    size_t available = size;
    size_t remaining = count;

    if (count == 0 && !dst && size == 0) return 0;
    if (!dst || !size) return EINVAL;
    while (*d != 0 && remaining > 0 && --available > 0)
    {
        *d++ = (WCHAR)value;
        remaining--;
    }
    if (remaining == 0)
    {
        while (*d != 0 && --available > 0)
            d++;
    }
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }
    return 0;
}

errno_t
__cdecl
_wcslwr_s(
    _Inout_updates_z_(size) WCHAR *str,
    _In_ size_t size)
{
    if (!str || !size) return EINVAL;
    if (wcsnlen(str, size) == size)
    {
        *str = 0;
        return EINVAL;
    }
    _wcslwr(str);
    return 0;
}

errno_t
__cdecl
_wcsupr_s(
    _Inout_updates_z_(size) WCHAR *str,
    _In_ size_t size)
{
    if (!str || !size) return EINVAL;
    if (wcsnlen(str, size) == size)
    {
        *str = 0;
        return EINVAL;
    }
    _wcsupr(str);
    return 0;
}

/*********************************************************************
 *		memcpy_s (MSVCRT.@)
 */
errno_t __cdecl memcpy_s( void *dst, size_t len, const void *src, size_t count )
{
    if (!count) return 0;
    if (!dst) return EINVAL;
    if (!src)
    {
        memset( dst, 0, len );
        return EINVAL;
    }
    if (count > len)
    {
        memset( dst, 0, len );
        return ERANGE;
    }
    memmove( dst, src, count );
    return 0;
}

/*********************************************************************
 *		memmove_s (MSVCRT.@)
 */
errno_t __cdecl memmove_s( void *dst, size_t len, const void *src, size_t count )
{
    if (!count) return 0;
    if (!dst) return EINVAL;
    if (!src) return EINVAL;
    if (count > len) return ERANGE;
    memmove( dst, src, count );
    return 0;
}

/*********************************************************************
 *                  strtok_s   (NTDLL.@)
 */
char * __cdecl strtok_s( char *str, const char *delim, char **ctx )
{
    char *next;

    if (!delim || !ctx) return NULL;
    if (!str)
    {
        str = *ctx;
        if (!str) return NULL;
    }
    while (*str && strchr( delim, *str )) str++;
    if (!*str)
    {
        *ctx = str;
        return NULL;
    }
    next = str + 1;
    while (*next && !strchr( delim, *next )) next++;
    if (*next) *next++ = 0;
    *ctx = next;
    return str;
}

/*********************************************************************
 *      _ultoa_s  (NTDLL.@)
 */
errno_t __cdecl _ultoa_s( __msvcrt_ulong value, char *str, size_t size, int radix )
{
    return _ui64toa_s( value, str, size, radix );
}

/******************************************************************
 *      _splitpath_s   (NTDLL.@)
 */
errno_t __cdecl _splitpath_s( const char *inpath, char *drive, size_t sz_drive,
                              char *dir, size_t sz_dir, char *fname, size_t sz_fname,
                              char *ext, size_t sz_ext )
{
    const char *p, *end;

    if (!inpath || (!drive && sz_drive) ||
        (drive && !sz_drive) ||
        (!dir && sz_dir) ||
        (dir && !sz_dir) ||
        (!fname && sz_fname) ||
        (fname && !sz_fname) ||
        (!ext && sz_ext) ||
        (ext && !sz_ext))
        return EINVAL;

    if (inpath[0] && inpath[1] == ':')
    {
        if (drive)
        {
            if (sz_drive <= 2) goto error;
            drive[0] = inpath[0];
            drive[1] = inpath[1];
            drive[2] = 0;
        }
        inpath += 2;
    }
    else if (drive) drive[0] = '\0';

    /* look for end of directory part */
    end = NULL;
    for (p = inpath; *p; p++) if (*p == '/' || *p == '\\') end = p + 1;

    if (end)  /* got a directory */
    {
        if (dir)
        {
            if (sz_dir <= end - inpath) goto error;
            memcpy( dir, inpath, end - inpath );
            dir[end - inpath] = 0;
        }
        inpath = end;
    }
    else if (dir) dir[0] = 0;

    /* look for extension: what's after the last dot */
    end = NULL;
    for (p = inpath; *p; p++) if (*p == '.') end = p;

    if (!end) end = p; /* there's no extension */

    if (fname)
    {
        if (sz_fname <= end - inpath) goto error;
        memcpy( fname, inpath, end - inpath );
        fname[end - inpath] = 0;
    }
    if (ext)
    {
        if (sz_ext <= strlen(end)) goto error;
        strcpy( ext, end );
    }
    return 0;

error:
    if (drive) drive[0] = 0;
    if (dir) dir[0] = 0;
    if (fname) fname[0]= 0;
    if (ext) ext[0]= 0;
    return ERANGE;
}

/*********************************************************************
 *      _makepath_s   (NTDLL.@)
 */
errno_t __cdecl _makepath_s( char *path, size_t size, const char *drive,
                             const char *directory, const char *filename,
                             const char *extension )
{
    char *p = path;

    if (!path || !size) return EINVAL;

    if (drive && drive[0])
    {
        if (size <= 2) goto range;
        *p++ = drive[0];
        *p++ = ':';
        size -= 2;
    }

    if (directory && directory[0])
    {
        unsigned int len = strlen(directory);
        unsigned int needs_separator = directory[len - 1] != '/' && directory[len - 1] != '\\';
        unsigned int copylen = min(size - 1, len);

        if (size < 2) goto range;
        memmove(p, directory, copylen);
        if (size <= len) goto range;
        p += copylen;
        size -= copylen;
        if (needs_separator)
        {
            if (size < 2) goto range;
            *p++ = '\\';
            size -= 1;
        }
    }

    if (filename && filename[0])
    {
        unsigned int len = strlen(filename);
        unsigned int copylen = min(size - 1, len);

        if (size < 2) goto range;
        memmove(p, filename, copylen);
        if (size <= len) goto range;
        p += len;
        size -= len;
    }

    if (extension && extension[0])
    {
        unsigned int len = strlen(extension);
        unsigned int needs_period = extension[0] != '.';
        unsigned int copylen;

        if (size < 2) goto range;
        if (needs_period)
        {
            *p++ = '.';
            size -= 1;
        }
        copylen = min(size - 1, len);
        memcpy(p, extension, copylen);
        if (size <= len) goto range;
        p += copylen;
    }

    *p = 0;
    return 0;

range:
    path[0] = 0;
    return ERANGE;
}

/*********************************************************************
 *      _ultow_s  (NTDLL.@)
 */
errno_t __cdecl _ultow_s( __msvcrt_ulong value, wchar_t *str, size_t size, int radix )
{
    return _ui64tow_s( value, str, size, radix );
}

/******************************************************************
 *      _wsplitpath_s   (NTDLL.@)
 */
errno_t __cdecl _wsplitpath_s( const wchar_t *inpath, wchar_t *drive, size_t sz_drive,
                               wchar_t *dir, size_t sz_dir, wchar_t *fname, size_t sz_fname,
                               wchar_t *ext, size_t sz_ext )
{
    const wchar_t *p, *end;

    if (!inpath || (!drive && sz_drive) ||
        (drive && !sz_drive) ||
        (!dir && sz_dir) ||
        (dir && !sz_dir) ||
        (!fname && sz_fname) ||
        (fname && !sz_fname) ||
        (!ext && sz_ext) ||
        (ext && !sz_ext))
        return EINVAL;

    if (inpath[0] && inpath[1] == ':')
    {
        if (drive)
        {
            if (sz_drive <= 2) goto error;
            drive[0] = inpath[0];
            drive[1] = inpath[1];
            drive[2] = 0;
        }
        inpath += 2;
    }
    else if (drive) drive[0] = '\0';

    /* look for end of directory part */
    end = NULL;
    for (p = inpath; *p; p++) if (*p == '/' || *p == '\\') end = p + 1;

    if (end)  /* got a directory */
    {
        if (dir)
        {
            if (sz_dir <= end - inpath) goto error;
            memcpy( dir, inpath, (end - inpath) * sizeof(wchar_t) );
            dir[end - inpath] = 0;
        }
        inpath = end;
    }
    else if (dir) dir[0] = 0;

    /* look for extension: what's after the last dot */
    end = NULL;
    for (p = inpath; *p; p++) if (*p == '.') end = p;

    if (!end) end = p; /* there's no extension */

    if (fname)
    {
        if (sz_fname <= end - inpath) goto error;
        memcpy( fname, inpath, (end - inpath) * sizeof(wchar_t) );
        fname[end - inpath] = 0;
    }
    if (ext)
    {
        if (sz_ext <= wcslen(end)) goto error;
        wcscpy( ext, end );
    }
    return 0;

error:
    if (drive) drive[0] = 0;
    if (dir) dir[0] = 0;
    if (fname) fname[0]= 0;
    if (ext) ext[0]= 0;
    return ERANGE;
}

/*********************************************************************
 *      _wmakepath_s   (NTDLL.@)
 */
errno_t __cdecl _wmakepath_s( wchar_t *path, size_t size, const wchar_t *drive,
                              const wchar_t *directory, const wchar_t *filename,
                              const wchar_t *extension )
{
    wchar_t *p = path;

    if (!path || !size) return EINVAL;

    if (drive && drive[0])
    {
        if (size <= 2) goto range;
        *p++ = drive[0];
        *p++ = ':';
        size -= 2;
    }

    if (directory && directory[0])
    {
        unsigned int len = wcslen(directory);
        unsigned int needs_separator = directory[len - 1] != '/' && directory[len - 1] != '\\';
        unsigned int copylen = min(size - 1, len);

        if (size < 2) goto range;
        memmove(p, directory, copylen * sizeof(wchar_t));
        if (size <= len) goto range;
        p += copylen;
        size -= copylen;
        if (needs_separator)
        {
            if (size < 2) goto range;
            *p++ = '\\';
            size -= 1;
        }
    }

    if (filename && filename[0])
    {
        unsigned int len = wcslen(filename);
        unsigned int copylen = min(size - 1, len);

        if (size < 2) goto range;
        memmove(p, filename, copylen * sizeof(wchar_t));
        if (size <= len) goto range;
        p += len;
        size -= len;
    }

    if (extension && extension[0])
    {
        unsigned int len = wcslen(extension);
        unsigned int needs_period = extension[0] != '.';
        unsigned int copylen;

        if (size < 2) goto range;
        if (needs_period)
        {
            *p++ = '.';
            size -= 1;
        }
        copylen = min(size - 1, len);
        memcpy(p, extension, copylen * sizeof(wchar_t));
        if (size <= len) goto range;
        p += copylen;
    }

    *p = 0;
    return 0;

range:
    path[0] = 0;
    return ERANGE;
}

/*********************************************************************
 *                  wcstok_s   (NTDLL.@)
 */
wchar_t * __cdecl wcstok_s( wchar_t *str, const wchar_t *delim, wchar_t **ctx )
{
    wchar_t *next;

    if (!delim || !ctx) return NULL;
    if (!str)
    {
        str = *ctx;
        if (!str) return NULL;
    }
    while (*str && wcschr( delim, *str )) str++;
    if (!*str)
    {
        *ctx = str;
        return NULL;
    }
    next = str + 1;
    while (*next && !wcschr( delim, *next )) next++;
    if (*next) *next++ = 0;
    *ctx = next;
    return str;
}

static inline void swap(char *l, char *r, size_t size)
{
    char tmp;

    while(size--) {
        tmp = *l;
        *l++ = *r;
        *r++ = tmp;
    }
}

static void small_sort(void *base, size_t nmemb, size_t size,
        int (__cdecl *compar)(void *, const void *, const void *), void *context)
{
    size_t e, i;
    char *max, *p;

    for(e=nmemb; e>1; e--) {
        max = base;
        for(i=1; i<e; i++) {
            p = (char*)base + i*size;
            if(compar(context, p, max) > 0)
                max = p;
        }

        if(p != max)
            swap(p, max, size);
    }
}

static void quick_sort(void *base, size_t nmemb, size_t size,
        int (__cdecl *compar)(void *, const void *, const void *), void *context)
{
    size_t stack_lo[8*sizeof(size_t)], stack_hi[8*sizeof(size_t)];
    size_t beg, end, lo, hi, med;
    int stack_pos;

    stack_pos = 0;
    stack_lo[stack_pos] = 0;
    stack_hi[stack_pos] = nmemb-1;

#define X(i) ((char*)base+size*(i))
    while(stack_pos >= 0) {
        beg = stack_lo[stack_pos];
        end = stack_hi[stack_pos--];

        if(end-beg < 8) {
            small_sort(X(beg), end-beg+1, size, compar, context);
            continue;
        }

        lo = beg;
        hi = end;
        med = lo + (hi-lo+1)/2;
        if(compar(context, X(lo), X(med)) > 0)
            swap(X(lo), X(med), size);
        if(compar(context, X(lo), X(hi)) > 0)
            swap(X(lo), X(hi), size);
        if(compar(context, X(med), X(hi)) > 0)
            swap(X(med), X(hi), size);

        lo++;
        hi--;
        while(1) {
            while(lo <= hi) {
                if(lo!=med && compar(context, X(lo), X(med))>0)
                    break;
                lo++;
            }

            while(med != hi) {
                if(compar(context, X(hi), X(med)) <= 0)
                    break;
                hi--;
            }

            if(hi < lo)
                break;

            swap(X(lo), X(hi), size);
            if(hi == med)
                med = lo;
            lo++;
            hi--;
        }

        while(hi > beg) {
            if(hi!=med && compar(context, X(hi), X(med))!=0)
                break;
            hi--;
        }

        if(hi-beg >= end-lo) {
            stack_lo[++stack_pos] = beg;
            stack_hi[stack_pos] = hi;
            stack_lo[++stack_pos] = lo;
            stack_hi[stack_pos] = end;
        }else {
            stack_lo[++stack_pos] = lo;
            stack_hi[stack_pos] = end;
            stack_lo[++stack_pos] = beg;
            stack_hi[stack_pos] = hi;
        }
    }
#undef X
}

/*********************************************************************
 *                  qsort_s   (NTDLL.@)
 */
void __cdecl qsort_s( void *base, size_t nmemb, size_t size,
                      int (__cdecl *compar)(void *, const void *, const void *), void *context )
{
    const size_t total_size = nmemb * size;

    if (!base && nmemb) return;
    if (!size) return;
    if (!compar) return;
    if (total_size / size != nmemb) return;
    if (nmemb < 2) return;
    quick_sort( base, nmemb, size, compar, context );
}

/*********************************************************************
 *                  bsearch_s   (NTDLL.@)
 */
void * __cdecl bsearch_s( const void *key, const void *base, size_t nmemb, size_t size,
                          int (__cdecl *compare)(void *, const void *, const void *), void *ctx )
{
    SSIZE_T min = 0;
    SSIZE_T max = nmemb - 1;

    if (!size) return NULL;
    if (!compare) return NULL;

    while (min <= max)
    {
        SSIZE_T cursor = min + (max - min) / 2;
        int ret = compare(ctx, key,(const char *)base+(cursor*size));
        if (!ret)
            return (char*)base+(cursor*size);
        if (ret < 0)
            max = cursor - 1;
        else
            min = cursor + 1;
    }
    return NULL;
}

/* wide versions of the above, exported under the names without the prefix (libcntpr has its own wcs*_s) */

errno_t
__cdecl
ntdll_wcscat_s(
    _Inout_updates_z_(size) WCHAR *dst,
    _In_ size_t size,
    _In_z_ const WCHAR *src)
{
    WCHAR *d;
    const WCHAR *s;
    size_t available;

    if (!dst || !size) return EINVAL;
    if (!src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    available = size;
    while (available > 0 && *d != 0)
    {
        d++;
        available--;
    }
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }

    s = src;
    while ((*d++ = *s++) != 0 && --available > 0)
        ;
    if (available == 0)
    {
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

errno_t
__cdecl
ntdll_wcsncat_s(
    _Inout_updates_z_(size) WCHAR *dst,
    _In_ size_t size,
    _In_reads_or_z_(count) const WCHAR *src,
    _In_ size_t count)
{
    WCHAR *d;
    const WCHAR *s;
    size_t available, remaining;

    if (count == 0 && !dst && size == 0) return 0;
    if (!dst || !size) return EINVAL;
    if (count != 0 && !src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    available = size;
    remaining = count;
    while (available > 0 && *d != 0)
    {
        d++;
        available--;
    }
    if (available == 0)
    {
        *dst = 0;
        return EINVAL;
    }

    s = src;
    if (count == _TRUNCATE)
    {
        while ((*d++ = *s++) != 0 && --available > 0)
            ;
    }
    else
    {
        while (remaining > 0 && (*d++ = *s++) != 0 && --available > 0)
            remaining--;
        if (remaining == 0)
            *d = 0;
    }

    if (available == 0)
    {
        if (count == _TRUNCATE)
        {
            dst[size - 1] = 0;
            return STRUNCATE;
        }
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

errno_t
__cdecl
ntdll_wcsncpy_s(
    _Out_writes_z_(size) WCHAR *dst,
    _In_ size_t size,
    _In_reads_or_z_(count) const WCHAR *src,
    _In_ size_t count)
{
    WCHAR *d;
    const WCHAR *s;
    size_t available, remaining;

    if (count == 0 && !dst && size == 0) return 0;
    if (!dst || !size) return EINVAL;
    if (count == 0)
    {
        *dst = 0;
        return 0;
    }
    if (!src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    s = src;
    available = size;
    remaining = count;
    if (count == _TRUNCATE)
    {
        while ((*d++ = *s++) != 0 && --available > 0)
            ;
    }
    else
    {
        while ((*d++ = *s++) != 0 && --available > 0 && --remaining > 0)
            ;
        if (remaining == 0)
            *d = 0;
    }

    if (available == 0)
    {
        if (count == _TRUNCATE)
        {
            dst[size - 1] = 0;
            return STRUNCATE;
        }
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

errno_t
__cdecl
ntdll_wcscpy_s(
    _Out_writes_z_(size) WCHAR *dst,
    _In_ size_t size,
    _In_z_ const WCHAR *src)
{
    WCHAR *d;
    const WCHAR *s;
    size_t available;

    if (!dst || !size) return EINVAL;
    if (!src)
    {
        *dst = 0;
        return EINVAL;
    }

    d = dst;
    s = src;
    available = size;
    while ((*d++ = *s++) != 0 && --available > 0)
        ;
    if (available == 0)
    {
        *dst = 0;
        return ERANGE;
    }
    return 0;
}

/* printf family ************************************************************/

/* _vsnprintf and _vsnwprintf are the ones of libcntpr: they return -1 when the output does not fit in the count
   given, and do not terminate a string that exactly fills it */

/*
 * The buffer holds SIZE elements. With COUNT == _TRUNCATE, or COUNT < SIZE, at most that many are written and the
 * string is terminated; an output that does not fit gives -1 and keeps the part that was written. With COUNT >= SIZE
 * an output that does not fit gives -1 and an empty string.
 */
#define VSNPRINTF_S_BODY(Func)                                              \
    size_t limit;                                                           \
    BOOLEAN truncate;                                                       \
    int r;                                                                  \
                                                                            \
    if (count == 0 && !str && size == 0) return 0;                          \
    if (!str || !size || !format) return -1;                                \
    if (count == _TRUNCATE)                                                 \
    {                                                                       \
        limit = size - 1;                                                   \
        truncate = TRUE;                                                    \
    }                                                                       \
    else if (count < size)                                                  \
    {                                                                       \
        limit = count;                                                      \
        truncate = TRUE;                                                    \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        limit = size - 1;                                                   \
        truncate = FALSE;                                                   \
    }                                                                       \
    r = Func(str, limit, format, args);                                     \
    if (r < 0 || (size_t)r > limit)                                         \
    {                                                                       \
        str[limit] = 0;                                                     \
        if (!truncate) str[0] = 0;                                          \
        return -1;                                                          \
    }                                                                       \
    str[r] = 0;                                                             \
    return r;

int
__cdecl
_vsnprintf_s(
    _Out_writes_opt_(size) char *str,
    _In_ size_t size,
    _In_ size_t count,
    _In_z_ const char *format,
    _In_ va_list args)
{
    VSNPRINTF_S_BODY(_vsnprintf)
}

int
__cdecl
_vsnwprintf_s(
    _Out_writes_opt_(size) WCHAR *str,
    _In_ size_t size,
    _In_ size_t count,
    _In_z_ const WCHAR *format,
    _In_ va_list args)
{
    VSNPRINTF_S_BODY(_vsnwprintf)
}

int
__cdecl
_snprintf_s(
    _Out_writes_opt_(size) char *str,
    _In_ size_t size,
    _In_ size_t count,
    _In_z_ const char *format,
    ...)
{
    int ret;
    va_list args;

    va_start(args, format);
    ret = _vsnprintf_s(str, size, count, format, args);
    va_end(args);
    return ret;
}

int
__cdecl
_snwprintf_s(
    _Out_writes_opt_(size) WCHAR *str,
    _In_ size_t size,
    _In_ size_t count,
    _In_z_ const WCHAR *format,
    ...)
{
    int ret;
    va_list args;

    va_start(args, format);
    ret = _vsnwprintf_s(str, size, count, format, args);
    va_end(args);
    return ret;
}

int
__cdecl
vsprintf_s(
    _Out_writes_(size) char *str,
    _In_ size_t size,
    _In_z_ const char *format,
    _In_ va_list args)
{
    return _vsnprintf_s(str, size, size, format, args);
}

int
__cdecl
vswprintf_s(
    _Out_writes_(size) WCHAR *str,
    _In_ size_t size,
    _In_z_ const WCHAR *format,
    _In_ va_list args)
{
    return _vsnwprintf_s(str, size, size, format, args);
}

int
__cdecl
sprintf_s(
    _Out_writes_(size) char *str,
    _In_ size_t size,
    _In_z_ const char *format,
    ...)
{
    int ret;
    va_list args;

    va_start(args, format);
    ret = vsprintf_s(str, size, format, args);
    va_end(args);
    return ret;
}

int
__cdecl
swprintf_s(
    _Out_writes_(size) WCHAR *str,
    _In_ size_t size,
    _In_z_ const WCHAR *format,
    ...)
{
    int ret;
    va_list args;

    va_start(args, format);
    ret = vswprintf_s(str, size, format, args);
    va_end(args);
    return ret;
}
