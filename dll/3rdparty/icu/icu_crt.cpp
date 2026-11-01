/*
 * PROJECT:     ReactOS system ICU (icu.dll)
 * LICENSE:     MIT (https://spdx.org/licenses/MIT.html)
 * PURPOSE:     C99 snprintf() for ICU
 *
 * The ReactOS (and Windows 7 era) msvcrt.dll has _snprintf and vsnprintf but no snprintf, while the MinGW
 * headers/libraries ICU is built against import "snprintf" from msvcrt.dll, which makes the DLL fail to load.
 * ICU calls snprintf in putil.cpp and number_decimalquantity.cpp; this definition satisfies them locally.
 */

#include <stdarg.h>
#include <stddef.h>

extern "C" int __cdecl _vsnprintf(char *buffer, size_t count, const char *format, va_list argptr);

extern "C" int __cdecl
snprintf(char *buffer, size_t count, const char *format, ...)
{
    va_list args;
    int ret;

    if (count == 0)
        return 0;

    va_start(args, format);
    ret = _vsnprintf(buffer, count, format, args);
    va_end(args);

    /* _vsnprintf does not terminate on truncation */
    buffer[count - 1] = '\0';
    return ret;
}
