/*
 * PROJECT:     ReactOS ucrtbase
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     C99 math functions that need the Windows error conventions
 * COPYRIGHT:   Based on Wine's dlls/msvcrt/math.c (Copyright 2000 Jon Griffiths, 2003 Alexandre Julliard
 *              and others) and musl libc src/math/lround.c, llround.c, llrint.c, nearbyint.c
 */

#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <xmmintrin.h>

double math_error(int type, const char *name, double arg1, double arg2, double retval)
{
    switch (type)
    {
        case _DOMAIN:
            errno = EDOM;
            break;
        case _SING:
        case _OVERFLOW:
            errno = ERANGE;
            break;
        default:
            /* no errno for _UNDERFLOW and the other types */
            break;
    }

    return retval;
}

/* x with the fraction cut off, exact in any rounding mode; musl src/math/trunc.c, truncf.c */
static double trunc_double(double x)
{
    union { double f; uint64_t i; } u = { x };
    int e = (int)(u.i >> 52 & 0x7ff) - 0x3ff + 12;
    uint64_t m;

    if (e >= 52 + 12)
        return x;
    if (e < 12)
        e = 1;
    m = -1ULL >> e;
    if ((u.i & m) == 0)
        return x;
    u.i &= ~m;
    return u.f;
}

static float trunc_float(float x)
{
    union { float f; uint32_t i; } u = { x };
    int e = (int)(u.i >> 23 & 0xff) - 0x7f + 9;
    uint32_t m;

    if (e >= 23 + 9)
        return x;
    if (e < 9)
        e = 1;
    m = -1U >> e;
    if ((u.i & m) == 0)
        return x;
    u.i &= ~m;
    return u.f;
}

/* Round half away from zero: the cut-off fraction is exact, so there is no 0.49999999999999994 case */
static double round_double(double x)
{
    double t = trunc_double(x);

    if (fabs(x - t) >= 0.5)
        t += (x < 0) ? -1.0 : 1.0;
    return t;
}

static float round_float(float x)
{
    float t = trunc_float(x);

    if (fabsf(x - t) >= 0.5f)
        t += (x < 0) ? -1.0f : 1.0f;
    return t;
}

/* The out of range results are an invalid conversion: the flag is raised as well as errno set */
static void raise_invalid(void)
{
    volatile double zero = 0.0, r;

    r = zero / zero;
    (void)r;
}

long __cdecl lround(double x)
{
    double d = round_double(x);
    if (!(d >= -2147483648.0 && d <= 2147483647.0))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (long)d;
}

long __cdecl lroundf(float x)
{
    float f = round_float(x);
    if (!(f >= -2147483648.0f && f < 2147483648.0f))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (long)f;
}

__int64 __cdecl llround(double x)
{
    double d = round_double(x);
    if (!(d >= -9223372036854775808.0 && d < 9223372036854775808.0))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (__int64)d;
}

__int64 __cdecl llroundf(float x)
{
    float f = round_float(x);
    if (!(f >= -9223372036854775808.0f && f < 9223372036854775808.0f))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (__int64)f;
}

#ifdef _M_IX86

/* musl's rint adds and subtracts 2^52, which does not work with the x87 excess precision rules of this build */
double __cdecl rint(double x)
{
#ifdef __GNUC__
    double r;
    __asm__ ("frndint" : "=t"(r) : "0"(x));
    return r;
#else
    __asm
    {
        fld x
        frndint
    }
#endif
}

float __cdecl rintf(float x)
{
#ifdef __GNUC__
    double r;
    __asm__ ("frndint" : "=t"(r) : "0"((double)x));
    return (float)r;
#else
    __asm
    {
        fld x
        frndint
    }
#endif
}

#endif /* _M_IX86 */

long __cdecl lrint(double x)
{
    double d = rint(x);
    if (!(d >= -2147483648.0 && d <= 2147483647.0))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (long)d;
}

long __cdecl lrintf(float x)
{
    float f = rintf(x);
    if (!(f >= -2147483648.0f && f < 2147483648.0f))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (long)f;
}

__int64 __cdecl llrint(double x)
{
    double d = rint(x);
    if (!(d >= -9223372036854775808.0 && d < 9223372036854775808.0))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (__int64)d;
}

__int64 __cdecl llrintf(float x)
{
    float f = rintf(x);
    if (!(f >= -9223372036854775808.0f && f < 9223372036854775808.0f))
    {
        raise_invalid();
        errno = EDOM;
        return 0;
    }
    return (__int64)f;
}

/* nearbyint is rint without the inexact exception: the control word and the status flags are put back, but the
   other exceptions that the rounding raised (a signaling NaN) stay raised. The result is stored before the
   environment is loaded back, because loading it restores the register stack. */
#if defined(_M_IX86) && defined(__GNUC__)
#define NEARBYINT_X87(Type, Load, Store, Value) \
    char env[28]; \
    unsigned short cw, sw; \
    Type r; \
    __asm__ volatile ("fnstenv %0" : "=m"(env)); \
    cw = *(unsigned short *)env | 0x20; \
    __asm__ volatile ("fldcw %2\n\t" Load " %3\n\tfrndint\n\t" Store " %0\n\tfnstsw %1" \
                      : "=m"(r), "=m"(sw) : "m"(cw), "m"(Value) : "memory"); \
    *(unsigned short *)(env + 4) |= sw & 0x1f; \
    __asm__ volatile ("fldenv %0" : : "m"(env) : "memory"); \
    return r
#endif

double __cdecl nearbyint(double x)
{
#if defined(_M_IX86) && defined(__GNUC__)
    NEARBYINT_X87(double, "fldl", "fstpl", x);
#elif defined(_M_IX86) && defined(_MSC_VER)
    unsigned char env[28];
    unsigned short cw, sw;
    double r;

    __asm
    {
        fnstenv [env]
        mov ax, word ptr [env]
        or ax, 20h
        mov cw, ax
        fldcw cw
        fld qword ptr [x]
        frndint
        fstp qword ptr [r]
        fnstsw sw
    }
    *(unsigned short *)(env + 4) |= sw & 0x1f;
    __asm fldenv [env]
    return r;
#elif defined(_M_AMD64) || defined(_M_X64)
    unsigned int csr = _mm_getcsr();
    double r;

    _mm_setcsr(csr | 0x1000);
    r = rint(x);
    _mm_setcsr(csr | (_mm_getcsr() & 0x1f));
    return r;
#else
    return rint(x);
#endif
}

float __cdecl nearbyintf(float x)
{
#if defined(_M_IX86) && defined(__GNUC__)
    NEARBYINT_X87(float, "flds", "fstps", x);
#elif defined(_M_IX86) && defined(_MSC_VER)
    unsigned char env[28];
    unsigned short cw, sw;
    float r;

    __asm
    {
        fnstenv [env]
        mov ax, word ptr [env]
        or ax, 20h
        mov cw, ax
        fldcw cw
        fld dword ptr [x]
        frndint
        fstp dword ptr [r]
        fnstsw sw
    }
    *(unsigned short *)(env + 4) |= sw & 0x1f;
    __asm fldenv [env]
    return r;
#elif defined(_M_AMD64) || defined(_M_X64)
    unsigned int csr = _mm_getcsr();
    float r;

    _mm_setcsr(csr | 0x1000);
    r = rintf(x);
    _mm_setcsr(csr | (_mm_getcsr() & 0x1f));
    return r;
#else
    return rintf(x);
#endif
}

/* The legacy logb of Windows differs from logb at the infinities and, for the float one, at NaN, and it reports
   the pole to the user handler of math errors, which logb does not (measured on Windows 10): the sign of an
   infinity stays and _logbf(NaN) is a domain error */
int __cdecl _invoke_matherr(int type, char *name, double arg1, double arg2, double retval);

double __cdecl _logb(double x)
{
    if (!isfinite(x))
        return x;
    if (x == 0)
    {
        double r = -1 / (x * x);

        if (!_invoke_matherr(_SING, "_logb", x, 0, r))
            errno = ERANGE;
        return r;
    }
    return ilogb(x);
}

#ifndef _M_IX86
float __cdecl _logbf(float x)
{
    if (isnan(x))
    {
        errno = EDOM;
        return x;
    }
    if (isinf(x))
        return x;
    if (x == 0)
    {
        float r = -1 / (x * x);

        if (!_invoke_matherr(_SING, "_logbf", x, 0, r))
            errno = ERANGE;
        return r;
    }
    return ilogbf(x);
}
#endif

/*
 * The _o_ variants: the same results, but they never set errno and never call the handler of math errors
 * (measured on Windows 10). The functions below call the plain ones and put errno back, except for the
 * legacy logb, whose results differ and which would call the handler.
 */
#define O_WRAPPER(Type, Name, Function) \
    Type __cdecl Name(Type x) \
    { \
        int saved = errno; \
        Type r = Function(x); \
        errno = saved; \
        return r; \
    }

O_WRAPPER(double, _o_lgamma, lgamma)
O_WRAPPER(float, _o_lgammaf, lgammaf)
O_WRAPPER(double, _o_lgammal, lgamma)
O_WRAPPER(double, _o_tgamma, tgamma)
O_WRAPPER(float, _o_tgammaf, tgammaf)
O_WRAPPER(double, _o_tgammal, tgamma)
O_WRAPPER(double, _o_logb, logb)
O_WRAPPER(float, _o_logbf, logbf)
O_WRAPPER(double, _o_logbl, logb)

/* The legacy logb keeps the sign of an infinity */
double __cdecl _o__logb(double x)
{
    if (!isfinite(x))
        return x;
    if (x == 0)
        return -1 / (x * x);
    return ilogb(x);
}

#ifndef _M_IX86
float __cdecl _o__logbf(float x)
{
    if (!isfinite(x))
        return x;
    if (x == 0)
        return -1 / (x * x);
    return ilogbf(x);
}
#endif

/* Ordered comparison of two doubles, the helper of isgreater() and the other comparison macros: 0 if either
   is a NaN, else _FP_LT (1), _FP_EQ (2) or _FP_GT (4). _ldpcomp is the same function. */
int __cdecl _dpcomp(double x, double y)
{
    if (isnan(x) || isnan(y))
        return 0;
    if (x == y)
        return 2;
    return x < y ? 1 : 4;
}
