/*
 * PROJECT:     ReactOS ucrtbase
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Floating-point environment (fenv.h) and the x87 and SSE control of the i386 CRT
 * COPYRIGHT:   Based on Wine's dlls/msvcrt/math.c (Copyright 2000 Jon Griffiths, 2003 Alexandre Julliard
 *              and others)
 */

#include <errno.h>
#include <float.h>
#include <fenv.h>
#include <math.h>
#include <stdint.h>

#if defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64)

#include <xmmintrin.h>

#define PF_XMMI64_INSTRUCTIONS_AVAILABLE 10

#ifdef _M_IX86
__declspec(dllimport) int __stdcall IsProcessorFeaturePresent(unsigned long Feature);
#endif

static unsigned int get_mxcsr(void)
{
    unsigned int value;

#ifdef __GNUC__
    __asm__ __volatile__("stmxcsr %0" : "=m"(value));
#else
    value = _mm_getcsr();
#endif
    return value;
}

static void set_mxcsr(unsigned int value)
{
#ifdef __GNUC__
    __asm__ __volatile__("ldmxcsr %0" : : "m"(value));
#else
    _mm_setcsr(value);
#endif
}

/* Reads and updates the control word (the rounding, precision and exception mask bits, in the _control87
   encoding) and the status word (the exception flags, in the _statusfp encoding) of the SSE unit. A null
   pointer leaves the word alone; the status is returned as it was before, and cw_mask and sw_mask select
   the bits of the values that are written. */
static void _setfp_sse(unsigned int *cw, unsigned int cw_mask, unsigned int *sw, unsigned int sw_mask)
{
    unsigned int old_fpword, fpword = get_mxcsr();
    unsigned int flags;

    old_fpword = fpword;

    cw_mask &= _MCW_EM | _MCW_RC | _MCW_DN;
    sw_mask &= _MCW_EM;

    if (sw)
    {
        flags = 0;
        if (fpword & 0x1) flags |= _SW_INVALID;
        if (fpword & 0x2) flags |= _SW_DENORMAL;
        if (fpword & 0x4) flags |= _SW_ZERODIVIDE;
        if (fpword & 0x8) flags |= _SW_OVERFLOW;
        if (fpword & 0x10) flags |= _SW_UNDERFLOW;
        if (fpword & 0x20) flags |= _SW_INEXACT;

        *sw = (flags & ~sw_mask) | (*sw & sw_mask);
        fpword &= ~0x3f;
        if (*sw & _SW_INVALID) fpword |= 0x1;
        if (*sw & _SW_DENORMAL) fpword |= 0x2;
        if (*sw & _SW_ZERODIVIDE) fpword |= 0x4;
        if (*sw & _SW_OVERFLOW) fpword |= 0x8;
        if (*sw & _SW_UNDERFLOW) fpword |= 0x10;
        if (*sw & _SW_INEXACT) fpword |= 0x20;
        *sw = flags;
    }

    if (cw)
    {
        flags = 0;
        if (fpword & 0x80) flags |= _EM_INVALID;
        if (fpword & 0x100) flags |= _EM_DENORMAL;
        if (fpword & 0x200) flags |= _EM_ZERODIVIDE;
        if (fpword & 0x400) flags |= _EM_OVERFLOW;
        if (fpword & 0x800) flags |= _EM_UNDERFLOW;
        if (fpword & 0x1000) flags |= _EM_INEXACT;
        switch (fpword & 0x6000)
        {
            case 0x6000: flags |= _RC_UP | _RC_DOWN; break;
            case 0x4000: flags |= _RC_UP; break;
            case 0x2000: flags |= _RC_DOWN; break;
        }
        switch (fpword & 0x8040)
        {
            case 0x0040: flags |= _DN_FLUSH_OPERANDS_SAVE_RESULTS; break;
            case 0x8000: flags |= _DN_SAVE_OPERANDS_FLUSH_RESULTS; break;
            case 0x8040: flags |= _DN_FLUSH; break;
        }

        *cw = (flags & ~cw_mask) | (*cw & cw_mask);
        fpword &= ~0xffc0;
        if (*cw & _EM_INVALID) fpword |= 0x80;
        if (*cw & _EM_DENORMAL) fpword |= 0x100;
        if (*cw & _EM_ZERODIVIDE) fpword |= 0x200;
        if (*cw & _EM_OVERFLOW) fpword |= 0x400;
        if (*cw & _EM_UNDERFLOW) fpword |= 0x800;
        if (*cw & _EM_INEXACT) fpword |= 0x1000;
        switch (*cw & _MCW_RC)
        {
            case _RC_UP | _RC_DOWN: fpword |= 0x6000; break;
            case _RC_UP: fpword |= 0x4000; break;
            case _RC_DOWN: fpword |= 0x2000; break;
        }
        switch (*cw & _MCW_DN)
        {
            case _DN_FLUSH_OPERANDS_SAVE_RESULTS: fpword |= 0x0040; break;
            case _DN_SAVE_OPERANDS_FLUSH_RESULTS: fpword |= 0x8000; break;
            case _DN_FLUSH: fpword |= 0x8040; break;
        }

        /* the status word is cleared if anything changes */
        if (fpword != old_fpword && !sw)
            fpword &= ~0x3f;
    }

    if (fpword != old_fpword)
        set_mxcsr(fpword);
}

#ifdef _M_IX86

typedef struct _X87_ENV
{
    unsigned short control_word, unused1;
    unsigned short status_word, unused2;
    unsigned short tag_word, unused3;
    unsigned long instruction_pointer;
    unsigned short code_segment, unused4;
    unsigned long operand_addr;
    unsigned short data_segment, unused5;
} X87_ENV;

/* The forms that do not wait: an unmasked exception that is pending must not be raised by reading the words
   that are needed to clear it */
static unsigned short x87_get_cw(void)
{
    unsigned short value;

#ifdef __GNUC__
    __asm__ __volatile__("fnstcw %0" : "=m"(value));
#else
    __asm fnstcw [value];
#endif
    return value;
}

static unsigned short x87_get_sw(void)
{
    unsigned short value;

#ifdef __GNUC__
    __asm__ __volatile__("fnstsw %0" : "=m"(value));
#else
    __asm fnstsw [value];
#endif
    return value;
}

/* Not fldcw: it waits and raises an exception that is pending and unmasked before the new word is in use */
static void x87_set_cw(unsigned short value)
{
    X87_ENV env;

#ifdef __GNUC__
    __asm__ __volatile__("fnstenv %0" : "=m"(env));
    env.control_word = value;
    __asm__ __volatile__("fldenv %0" : : "m"(env) : "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)");
#else
    __asm fnstenv [env];
    env.control_word = value;
    __asm fldenv [env];
#endif
}

static void x87_clear_exceptions(void)
{
#ifdef __GNUC__
    __asm__ __volatile__("fnclex");
#else
    __asm fnclex;
#endif
}

/* The only way to set exception flags is to load an environment image */
static void x87_set_cw_sw(unsigned short cw, unsigned short sw)
{
    X87_ENV env;

#ifdef __GNUC__
    __asm__ __volatile__("fnstenv %0" : "=m"(env));
    env.control_word = cw;
    env.status_word = sw;
    __asm__ __volatile__("fldenv %0" : : "m"(env) : "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)");
#else
    __asm fnstenv [env];
    env.control_word = cw;
    env.status_word = sw;
    __asm fldenv [env];
#endif
}

static int sse2_supported(void)
{
    return IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE);
}

/* The x87 counterpart of _setfp_sse */
static void _setfp(unsigned int *cw, unsigned int cw_mask, unsigned int *sw, unsigned int sw_mask)
{
    unsigned short oldcw = 0, newcw = 0;
    unsigned short oldsw = 0, newsw = 0;
    unsigned int flags;

    cw_mask &= _MCW_EM | _MCW_IC | _MCW_RC | _MCW_PC;
    sw_mask &= _MCW_EM;

    if (sw)
    {
        newsw = x87_get_sw();
        oldsw = newsw;

        flags = 0;
        if (newsw & 0x1) flags |= _SW_INVALID;
        if (newsw & 0x2) flags |= _SW_DENORMAL;
        if (newsw & 0x4) flags |= _SW_ZERODIVIDE;
        if (newsw & 0x8) flags |= _SW_OVERFLOW;
        if (newsw & 0x10) flags |= _SW_UNDERFLOW;
        if (newsw & 0x20) flags |= _SW_INEXACT;

        *sw = (flags & ~sw_mask) | (*sw & sw_mask);
        newsw &= ~0x3f;
        if (*sw & _SW_INVALID) newsw |= 0x1;
        if (*sw & _SW_DENORMAL) newsw |= 0x2;
        if (*sw & _SW_ZERODIVIDE) newsw |= 0x4;
        if (*sw & _SW_OVERFLOW) newsw |= 0x8;
        if (*sw & _SW_UNDERFLOW) newsw |= 0x10;
        if (*sw & _SW_INEXACT) newsw |= 0x20;
        *sw = flags;
    }

    if (cw)
    {
        newcw = x87_get_cw();
        oldcw = newcw;

        flags = 0;
        if (newcw & 0x1) flags |= _EM_INVALID;
        if (newcw & 0x2) flags |= _EM_DENORMAL;
        if (newcw & 0x4) flags |= _EM_ZERODIVIDE;
        if (newcw & 0x8) flags |= _EM_OVERFLOW;
        if (newcw & 0x10) flags |= _EM_UNDERFLOW;
        if (newcw & 0x20) flags |= _EM_INEXACT;
        switch (newcw & 0xc00)
        {
            case 0xc00: flags |= _RC_UP | _RC_DOWN; break;
            case 0x800: flags |= _RC_UP; break;
            case 0x400: flags |= _RC_DOWN; break;
        }
        switch (newcw & 0x300)
        {
            case 0x0: flags |= _PC_24; break;
            case 0x200: flags |= _PC_53; break;
            case 0x300: flags |= _PC_64; break;
        }
        if (newcw & 0x1000) flags |= _IC_AFFINE;

        *cw = (flags & ~cw_mask) | (*cw & cw_mask);
        newcw &= ~0x1f3f;
        if (*cw & _EM_INVALID) newcw |= 0x1;
        if (*cw & _EM_DENORMAL) newcw |= 0x2;
        if (*cw & _EM_ZERODIVIDE) newcw |= 0x4;
        if (*cw & _EM_OVERFLOW) newcw |= 0x8;
        if (*cw & _EM_UNDERFLOW) newcw |= 0x10;
        if (*cw & _EM_INEXACT) newcw |= 0x20;
        switch (*cw & _MCW_RC)
        {
            case _RC_UP | _RC_DOWN: newcw |= 0xc00; break;
            case _RC_UP: newcw |= 0x800; break;
            case _RC_DOWN: newcw |= 0x400; break;
        }
        switch (*cw & _MCW_PC)
        {
            case _PC_64: newcw |= 0x300; break;
            case _PC_53: newcw |= 0x200; break;
            case _PC_24: newcw |= 0x0; break;
        }
        if (*cw & _IC_AFFINE) newcw |= 0x1000;
    }

    if (oldsw != newsw && (newsw & 0x3f))
    {
        /* Flags are set by loading the environment, which needs the control word as well */
        x87_set_cw_sw(cw ? newcw : x87_get_cw(), newsw);
        return;
    }

    if (oldsw != newsw)
        x87_clear_exceptions();
    if (oldcw != newcw)
        x87_set_cw(newcw);
}

void __cdecl _statusfp2(unsigned int *x86_sw, unsigned int *sse2_sw)
{
    if (x86_sw)
        _setfp(NULL, 0, x86_sw, 0);
    if (!sse2_sw)
        return;
    if (sse2_supported())
        _setfp_sse(NULL, 0, sse2_sw, 0);
    else
        *sse2_sw = 0;
}

/* The CRT library of this tree only knows the x87 state on i386, Windows reports and clears both */
unsigned int __cdecl _statusfp(void)
{
    unsigned int x86_sw, sse2_sw;

    _statusfp2(&x86_sw, &sse2_sw);
    /* There is no definition for an ambiguous status, all the bits of both units are returned */
    return x86_sw | sse2_sw;
}

unsigned int __cdecl _clearfp(void)
{
    unsigned int flags = 0;

    _setfp(NULL, 0, &flags, _MCW_EM);
    if (sse2_supported())
    {
        unsigned int sse_sw = 0;

        _setfp_sse(NULL, 0, &sse_sw, _MCW_EM);
        flags |= sse_sw;
    }
    return flags;
}

int __cdecl __control87_2(unsigned int newval, unsigned int mask, unsigned int *x86_cw, unsigned int *sse2_cw)
{
    if (x86_cw)
    {
        *x86_cw = newval;
        _setfp(x86_cw, mask, NULL, 0);
    }

    if (!sse2_cw)
        return 1;

    if (sse2_supported())
    {
        *sse2_cw = newval;
        _setfp_sse(sse2_cw, mask, NULL, 0);
    }
    else
        *sse2_cw = 0;

    return 1;
}

unsigned int __cdecl _control87(unsigned int newval, unsigned int mask)
{
    unsigned int flags = 0, sse2_cw;

    __control87_2(newval, mask, &flags, &sse2_cw);

    if (sse2_supported())
    {
        if ((flags ^ sse2_cw) & (_MCW_EM | _MCW_RC))
            flags |= _EM_AMBIGUOUS;
        flags |= sse2_cw;
    }
    return flags;
}

unsigned int __cdecl _controlfp(unsigned int newval, unsigned int mask)
{
    return _control87(newval, mask & ~_EM_DENORMAL);
}

#else /* _M_IX86 */

#define sse2_supported() 1
#define _setfp _setfp_sse

/* The CRT library of this tree writes the control word back converted, which drops the exception flags: a read
   would clear them, and on Windows it does not */
unsigned int __cdecl _control87(unsigned int newval, unsigned int mask)
{
    unsigned int flags = newval;

    _setfp_sse(&flags, mask, NULL, 0);
    return flags;
}

unsigned int __cdecl _controlfp(unsigned int newval, unsigned int mask)
{
    return _control87(newval, mask & ~_EM_DENORMAL);
}

#endif /* _M_IX86 */

enum fenv_masks
{
    FENV_X_INVALID = 0x00100010,
    FENV_X_DENORMAL = 0x00200020,
    FENV_X_ZERODIVIDE = 0x00080008,
    FENV_X_OVERFLOW = 0x00040004,
    FENV_X_UNDERFLOW = 0x00020002,
    FENV_X_INEXACT = 0x00010001,
    FENV_X_AFFINE = 0x00004000,
    FENV_X_UP = 0x00800200,
    FENV_X_DOWN = 0x00400100,
    FENV_X_24 = 0x00002000,
    FENV_X_53 = 0x00001000,
    FENV_Y_INVALID = 0x10000010,
    FENV_Y_DENORMAL = 0x20000020,
    FENV_Y_ZERODIVIDE = 0x08000008,
    FENV_Y_OVERFLOW = 0x04000004,
    FENV_Y_UNDERFLOW = 0x02000002,
    FENV_Y_INEXACT = 0x01000001,
    FENV_Y_UP = 0x80000200,
    FENV_Y_DOWN = 0x40000100,
    FENV_Y_FLUSH = 0x00000400,
    FENV_Y_FLUSH_SAVE = 0x00000800
};

/* Encodes the x87 and SSE control or status words as Windows stores them in an fenv_t: bits 0 to 15 are
   shared and the high bytes tell the unit, so an environment of one unit decodes on the other */
static unsigned long fenv_encode(unsigned int x, unsigned int y)
{
    unsigned long ret = 0;

#ifdef _M_IX86
    if (x & _EM_INVALID) ret |= FENV_X_INVALID;
    if (x & _EM_DENORMAL) ret |= FENV_X_DENORMAL;
    if (x & _EM_ZERODIVIDE) ret |= FENV_X_ZERODIVIDE;
    if (x & _EM_OVERFLOW) ret |= FENV_X_OVERFLOW;
    if (x & _EM_UNDERFLOW) ret |= FENV_X_UNDERFLOW;
    if (x & _EM_INEXACT) ret |= FENV_X_INEXACT;
    if (x & _IC_AFFINE) ret |= FENV_X_AFFINE;
    if (x & _RC_UP) ret |= FENV_X_UP;
    if (x & _RC_DOWN) ret |= FENV_X_DOWN;
    if (x & _PC_24) ret |= FENV_X_24;
    if (x & _PC_53) ret |= FENV_X_53;
#endif
    x &= ~(_MCW_EM | _MCW_IC | _MCW_RC | _MCW_PC);

    if (y & _EM_INVALID) ret |= FENV_Y_INVALID;
    if (y & _EM_DENORMAL) ret |= FENV_Y_DENORMAL;
    if (y & _EM_ZERODIVIDE) ret |= FENV_Y_ZERODIVIDE;
    if (y & _EM_OVERFLOW) ret |= FENV_Y_OVERFLOW;
    if (y & _EM_UNDERFLOW) ret |= FENV_Y_UNDERFLOW;
    if (y & _EM_INEXACT) ret |= FENV_Y_INEXACT;
    if (y & _RC_UP) ret |= FENV_Y_UP;
    if (y & _RC_DOWN) ret |= FENV_Y_DOWN;
    if (y & _DN_FLUSH) ret |= FENV_Y_FLUSH;
    if (y & _DN_FLUSH_OPERANDS_SAVE_RESULTS) ret |= FENV_Y_FLUSH_SAVE;

    return ret;
}

/* Decodes the words of an fenv_t, returns 0 when the value is not one that fenv_encode makes */
static int fenv_decode(unsigned long enc, unsigned int *x, unsigned int *y)
{
    *x = *y = 0;
    if ((enc & FENV_X_INVALID) == FENV_X_INVALID) *x |= _EM_INVALID;
    if ((enc & FENV_X_DENORMAL) == FENV_X_DENORMAL) *x |= _EM_DENORMAL;
    if ((enc & FENV_X_ZERODIVIDE) == FENV_X_ZERODIVIDE) *x |= _EM_ZERODIVIDE;
    if ((enc & FENV_X_OVERFLOW) == FENV_X_OVERFLOW) *x |= _EM_OVERFLOW;
    if ((enc & FENV_X_UNDERFLOW) == FENV_X_UNDERFLOW) *x |= _EM_UNDERFLOW;
    if ((enc & FENV_X_INEXACT) == FENV_X_INEXACT) *x |= _EM_INEXACT;
    if ((enc & FENV_X_AFFINE) == FENV_X_AFFINE) *x |= _IC_AFFINE;
    if ((enc & FENV_X_UP) == FENV_X_UP) *x |= _RC_UP;
    if ((enc & FENV_X_DOWN) == FENV_X_DOWN) *x |= _RC_DOWN;
    if ((enc & FENV_X_24) == FENV_X_24) *x |= _PC_24;
    if ((enc & FENV_X_53) == FENV_X_53) *x |= _PC_53;

    if ((enc & FENV_Y_INVALID) == FENV_Y_INVALID) *y |= _EM_INVALID;
    if ((enc & FENV_Y_DENORMAL) == FENV_Y_DENORMAL) *y |= _EM_DENORMAL;
    if ((enc & FENV_Y_ZERODIVIDE) == FENV_Y_ZERODIVIDE) *y |= _EM_ZERODIVIDE;
    if ((enc & FENV_Y_OVERFLOW) == FENV_Y_OVERFLOW) *y |= _EM_OVERFLOW;
    if ((enc & FENV_Y_UNDERFLOW) == FENV_Y_UNDERFLOW) *y |= _EM_UNDERFLOW;
    if ((enc & FENV_Y_INEXACT) == FENV_Y_INEXACT) *y |= _EM_INEXACT;
    if ((enc & FENV_Y_UP) == FENV_Y_UP) *y |= _RC_UP;
    if ((enc & FENV_Y_DOWN) == FENV_Y_DOWN) *y |= _RC_DOWN;
    if ((enc & FENV_Y_FLUSH) == FENV_Y_FLUSH) *y |= _DN_FLUSH;
    if ((enc & FENV_Y_FLUSH_SAVE) == FENV_Y_FLUSH_SAVE) *y |= _DN_FLUSH_OPERANDS_SAVE_RESULTS;

    return fenv_encode(*x, *y) == enc;
}

int __cdecl fegetenv(fenv_t *env)
{
#ifdef _M_IX86
    unsigned int x87, sse;

    __control87_2(0, 0, &x87, &sse);
    env->_Fe_ctl = fenv_encode(x87, sse);
    _statusfp2(&x87, &sse);
    env->_Fe_stat = fenv_encode(x87, sse);
#else
    env->_Fe_ctl = fenv_encode(0, _control87(0, 0));
    env->_Fe_stat = fenv_encode(0, _statusfp());
#endif
    return 0;
}

/* Windows applies what it can decode of the environment and reports an environment that is not exactly
   what fegetenv makes with a nonzero return; an environment of zeros is not special, it unmasks everything */
int __cdecl fesetenv(const fenv_t *env)
{
    unsigned int x87_cw, cw, x87_stat, stat;
    int valid;

    valid = fenv_decode(env->_Fe_ctl, &x87_cw, &cw);
    valid &= fenv_decode(env->_Fe_stat, &x87_stat, &stat);
    /* a status holds no more than exception flags, and the precision of the x87 unit is one of three */
    valid &= !((x87_stat | stat) & ~_MCW_EM) && (x87_cw & _MCW_PC) != _MCW_PC;

#ifdef _M_IX86
    _setfp(&x87_cw, ~0, &x87_stat, ~0);
    if (sse2_supported())
        _setfp_sse(&cw, ~0, &stat, ~0);
#else
    _setfp(&cw, ~0, &stat, ~0);
#endif
    return !valid;
}

int __cdecl fetestexcept(int flags)
{
    return _statusfp() & flags;
}

int __cdecl fesetexceptflag(const fexcept_t *status, int excepts)
{
    fenv_t env;

    excepts &= FE_ALL_EXCEPT;
    if (!excepts)
        return 0;

    fegetenv(&env);
    env._Fe_stat &= ~fenv_encode(excepts, excepts);
    env._Fe_stat |= *status & fenv_encode(excepts, excepts);
    return fesetenv(&env);
}

int __cdecl feclearexcept(int flags)
{
    fenv_t env;

    fegetenv(&env);
    flags &= FE_ALL_EXCEPT;
    env._Fe_stat &= ~fenv_encode(flags, flags);
    return fesetenv(&env);
}

int __cdecl fegetexceptflag(fexcept_t *status, int excepts)
{
#ifdef _M_IX86
    unsigned int x87, sse;

    _statusfp2(&x87, &sse);
    *status = fenv_encode(x87 & excepts, sse & excepts);
#else
    *status = fenv_encode(0, _statusfp() & excepts);
#endif
    return 0;
}

/* Windows does not enter the non-stop mode, it fails and changes nothing while any exception is unmasked */
int __cdecl feholdexcept(fenv_t *env)
{
    /* only the units that are present have masks in the environment */
    unsigned long masks = fenv_encode(FE_ALL_EXCEPT, sse2_supported() ? FE_ALL_EXCEPT : 0);

    fegetenv(env);
    if ((env->_Fe_ctl & masks) != masks)
        return 1;
    return feclearexcept(FE_ALL_EXCEPT);
}

int __cdecl fegetround(void)
{
    return _controlfp(0, 0) & _MCW_RC;
}

int __cdecl fesetround(int round_mode)
{
    if (round_mode & ~_MCW_RC)
        return 1;
    _controlfp(round_mode, _MCW_RC);
    return 0;
}

/* The values of FLT_ROUNDS: 0 toward zero, 1 to nearest, 2 upward, 3 downward */
int __cdecl __fpe_flt_rounds(void)
{
    switch (_controlfp(0, 0) & _RC_CHOP)
    {
        case _RC_CHOP: return 0;
        case _RC_NEAR: return 1;
        case _RC_UP: return 2;
        default: return 3;
    }
}

/* _except1: the floating-point exception hook of the math functions (the _FpCode* operations of the x87 and SSE
   math library). fpe holds the exception flags (1 overflow, 2 underflow, 4 divide by zero, 8 invalid, 0x10
   inexact) and cw the control word of the caller (the x87 control word on i386, the MXCSR on amd64). When
   every exception in fpe is masked the flags are set and the result is returned (infinity of the sign of res
   for an overflow, a signed zero for an underflow); otherwise the exception is raised, the highest of
   invalid, overflow, underflow, divide by zero and inexact first. The control word that is left is cw. */
__declspec(dllimport) void __stdcall RaiseException(unsigned long code, unsigned long flags, unsigned long argc,
                                                     const uintptr_t *argv);

double __cdecl _except1(unsigned long fpe, int op, double arg, double res, unsigned long cw, void *unk)
{
    /* the bits of the exception masks of an x87 control word: 1 invalid, 4 divide by zero, 8 overflow,
       0x10 underflow, 0x20 inexact */
    static const struct { unsigned long fpe, mask, code; unsigned int sw; } exc[] =
    {
        { 0x08, 0x01, 0xC0000090 /* STATUS_FLOAT_INVALID_OPERATION */, _SW_INVALID },
        { 0x01, 0x08, 0xC0000091 /* STATUS_FLOAT_OVERFLOW */, _SW_OVERFLOW },
        { 0x02, 0x10, 0xC0000093 /* STATUS_FLOAT_UNDERFLOW */, _SW_UNDERFLOW },
        { 0x04, 0x04, 0xC000008E /* STATUS_FLOAT_DIVIDE_BY_ZERO */, _SW_ZERODIVIDE },
        { 0x10, 0x20, 0xC000008F /* STATUS_FLOAT_INEXACT_RESULT */, _SW_INEXACT },
    };
    unsigned long masks, required = 0, code = 0;
    unsigned int raise = 0, flags, cwmask;
    unsigned short operation;
    uintptr_t argument;
    unsigned int i;

#ifdef _M_IX86
    masks = cw & 0x3f;
#else
    masks = (cw >> 7) & 0x3f;
#endif
    for (i = 0; i < sizeof(exc) / sizeof(exc[0]); i++)
    {
        if (!(fpe & exc[i].fpe))
            continue;
        required |= exc[i].mask;
        raise |= exc[i].sw;
        /* the exception that is raised is the first of the table, inexact only if nothing else is in fpe */
        if (!code)
            code = exc[i].code;
    }
    /* all of them have to be masked, else the exception of the first is raised */
    if ((masks & required) == required)
        code = 0;

    /* the parameter of the exception is the address of the operation code shifted by five */
    operation = (unsigned short)(op << 5);
    argument = (uintptr_t)&operation;
    if (code)
        RaiseException(code, 0, 1, &argument);

    if (fpe & 0x01)
    {
        /* (HUGE_VAL is computed by an operation that overflows, it would set the flags) */
        static const union { unsigned long long bits; double value; } infinity = { 0x7ff0000000000000ULL };

        res = signbit(res) ? -infinity.value : infinity.value;
    }
    else if (fpe & 0x02)
        res = signbit(res) ? -0.0 : 0.0;
#ifdef _M_IX86
    /* the x87 code sets the inexact flag with the overflow and the underflow */
    if (fpe & 0x03)
        raise |= _SW_INEXACT;
#endif

    /* the control word of the caller becomes the control word of the thread */
    flags = 0;
    cwmask = _MCW_EM | _MCW_RC;
#ifdef _M_IX86
    if (cw & 0x01) flags |= _EM_INVALID;
    if (cw & 0x02) flags |= _EM_DENORMAL;
    if (cw & 0x04) flags |= _EM_ZERODIVIDE;
    if (cw & 0x08) flags |= _EM_OVERFLOW;
    if (cw & 0x10) flags |= _EM_UNDERFLOW;
    if (cw & 0x20) flags |= _EM_INEXACT;
    switch (cw & 0xc00)
    {
        case 0xc00: flags |= _RC_UP | _RC_DOWN; break;
        case 0x800: flags |= _RC_UP; break;
        case 0x400: flags |= _RC_DOWN; break;
    }
    switch (cw & 0x300)
    {
        case 0x0: flags |= _PC_24; break;
        case 0x200: flags |= _PC_53; break;
        case 0x300: flags |= _PC_64; break;
    }
    if (cw & 0x1000) flags |= _IC_AFFINE;
    cwmask |= _MCW_PC | _MCW_IC;
#else
    if (cw & 0x80) flags |= _EM_INVALID;
    if (cw & 0x100) flags |= _EM_DENORMAL;
    if (cw & 0x200) flags |= _EM_ZERODIVIDE;
    if (cw & 0x400) flags |= _EM_OVERFLOW;
    if (cw & 0x800) flags |= _EM_UNDERFLOW;
    if (cw & 0x1000) flags |= _EM_INEXACT;
    switch (cw & 0x6000)
    {
        case 0x6000: flags |= _RC_UP | _RC_DOWN; break;
        case 0x4000: flags |= _RC_UP; break;
        case 0x2000: flags |= _RC_DOWN; break;
    }
    switch (cw & 0x8040)
    {
        case 0x0040: flags |= _DN_FLUSH_OPERANDS_SAVE_RESULTS; break;
        case 0x8000: flags |= _DN_SAVE_OPERANDS_FLUSH_RESULTS; break;
        case 0x8040: flags |= _DN_FLUSH; break;
    }
    cwmask |= _MCW_DN;
#endif
    _control87(flags, cwmask);

    /* the flags are set last: a change of the control word clears them */
    if (raise)
    {
        unsigned int sw = 0;

        _setfp(NULL, 0, &sw, 0);
        sw |= raise;
        _setfp(NULL, 0, &sw, _MCW_EM);
    }
    return res;
}

#endif /* x86 */
