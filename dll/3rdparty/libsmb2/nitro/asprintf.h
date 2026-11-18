/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     asprintf() for libsmb2 (replaces upstream include/asprintf.h, which carries no licence notice)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef NITRO_LIBSMB2_ASPRINTF_H
#define NITRO_LIBSMB2_ASPRINTF_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* Formats into a new heap buffer; returns the length, or -1 with *strp unchanged. */
static inline int vasprintf(char **strp, const char *fmt, va_list ap)
{
    va_list ap2;
    char *str;
    int len;

    va_copy(ap2, ap);
    len = _vscprintf(fmt, ap2);
    va_end(ap2);
    if (len < 0)
        return -1;
    str = malloc((size_t)len + 1);
    if (str == NULL)
        return -1;
    if (_vsnprintf(str, (size_t)len + 1, fmt, ap) != len)
    {
        free(str);
        return -1;
    }
    str[len] = '\0';
    *strp = str;
    return len;
}

static inline int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vasprintf(strp, fmt, ap);
    va_end(ap);
    return r;
}

#endif /* NITRO_LIBSMB2_ASPRINTF_H */
