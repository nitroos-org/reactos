/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for _dpcomp and _except1 of ucrtbase
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The values were measured on Windows 10 22H2 (x64 and x86). Firefox imports _dpcomp (isgreater() and the
 * other comparison macros call it), LibreOffice imports _except1 on i386.
 */

#include <apitest.h>
#include <float.h>
#include <math.h>
#include <windef.h>
#include <winbase.h>
#include <pseh/pseh2.h>

typedef double (__cdecl *_except1_t)(unsigned long fpe, int op, double arg, double res, unsigned long cw, void *unk);

#ifdef _M_IX86
/* the x87 control word of the caller: all exceptions masked, 53 bit precision */
# define CW_ALL_MASKED      0x27f
# define MASK_OVERFLOW      0x08
# define MASK_INEXACT       0x20
# define CONTROL_ALL_MASKED 0x0009001f
# define SW_OVERFLOW_ONLY   (_SW_OVERFLOW | _SW_INEXACT)
# define SW_UNDERFLOW_ONLY  (_SW_UNDERFLOW | _SW_INEXACT)
#else
/* the MXCSR of the caller: all exceptions masked */
# define CW_ALL_MASKED      0x1f80
# define MASK_OVERFLOW      0x400
# define MASK_INEXACT       0x1000
# define CONTROL_ALL_MASKED 0x0008001f
# define SW_OVERFLOW_ONLY   _SW_OVERFLOW
# define SW_UNDERFLOW_ONLY  _SW_UNDERFLOW
#endif

static void test_dpcomp(void)
{
    HMODULE module = GetModuleHandleA("ucrtbase.dll");
    int (__cdecl *p_ldpcomp)(double, double);
    volatile double zero = 0.0;
    double nan_ = zero / zero, inf = 1.0 / zero;

    ok(_dpcomp(1, 2) == 1, "(1, 2) = %d\n", _dpcomp(1, 2));
    ok(_dpcomp(2, 1) == 4, "(2, 1) = %d\n", _dpcomp(2, 1));
    ok(_dpcomp(2, 2) == 2, "(2, 2) = %d\n", _dpcomp(2, 2));
    ok(_dpcomp(0.0, -0.0) == 2, "(0, -0) = %d\n", _dpcomp(0.0, -0.0));
    ok(_dpcomp(nan_, 1) == 0, "(nan, 1) = %d\n", _dpcomp(nan_, 1));
    ok(_dpcomp(1, nan_) == 0, "(1, nan) = %d\n", _dpcomp(1, nan_));
    ok(_dpcomp(nan_, nan_) == 0, "(nan, nan) = %d\n", _dpcomp(nan_, nan_));
    ok(_dpcomp(inf, inf) == 2, "(inf, inf) = %d\n", _dpcomp(inf, inf));
    ok(_dpcomp(-inf, inf) == 1, "(-inf, inf) = %d\n", _dpcomp(-inf, inf));
    ok(_dpcomp(-inf, -inf) == 2, "(-inf, -inf) = %d\n", _dpcomp(-inf, -inf));
    ok(_dpcomp(inf, 1e308) == 4, "(inf, 1e308) = %d\n", _dpcomp(inf, 1e308));

    /* the macros of <math.h> depend on these values */
    ok(isgreater(2.0, 1.0), "isgreater(2, 1)\n");
    ok(!isgreater(1.0, 2.0), "isgreater(1, 2)\n");
    ok(isless(1.0, 2.0), "isless(1, 2)\n");
    ok(isunordered(nan_, 1.0), "isunordered(nan, 1)\n");
    ok(!isunordered(1.0, 1.0), "isunordered(1, 1)\n");
    ok(islessgreater(1.0, 2.0), "islessgreater(1, 2)\n");
    ok(!islessgreater(2.0, 2.0), "islessgreater(2, 2)\n");

    p_ldpcomp = (void *)GetProcAddress(module, "_ldpcomp");
    ok(p_ldpcomp != NULL, "_ldpcomp is not exported\n");
    if (p_ldpcomp)
        ok(p_ldpcomp(1, 2) == 1 && p_ldpcomp(2, 1) == 4, "_ldpcomp does not compare like _dpcomp\n");
}

static DWORD g_code;
static WORD g_operation;

static int except_filter(EXCEPTION_POINTERS *info)
{
    g_code = info->ExceptionRecord->ExceptionCode;
    if (info->ExceptionRecord->NumberParameters == 1)
        g_operation = *(WORD *)info->ExceptionRecord->ExceptionInformation[0];
    else
        g_operation = 0xffff;
    return EXCEPTION_EXECUTE_HANDLER;
}

/* returns the exception code, 0 if _except1 returned */
static DWORD call_except1(_except1_t p_except1, unsigned long fpe, double res, unsigned long cw, double *ret,
                          unsigned int *status, unsigned int *control)
{
    g_code = 0;
    g_operation = 0;
    _clearfp();
    _SEH2_TRY
    {
        *ret = p_except1(fpe, 1, 2.0, res, cw, NULL);
    }
    _SEH2_EXCEPT(except_filter(_SEH2_GetExceptionInformation()))
    {
    }
    _SEH2_END;
    *status = _statusfp();
    *control = _control87(0, 0);
    return g_code;
}

static void test_except1(void)
{
    static const struct
    {
        unsigned long fpe;
        double res;
        double expect;
        unsigned int status;
        DWORD code;
    } masked[] =
    {
        { 0x01, 1e300, HUGE_VAL, SW_OVERFLOW_ONLY, 0xC0000091 },
        { 0x01, -1e300, -HUGE_VAL, SW_OVERFLOW_ONLY, 0xC0000091 },
        { 0x02, 1.0, 0.0, SW_UNDERFLOW_ONLY, 0xC0000093 },
        { 0x02, -1.0, -0.0, SW_UNDERFLOW_ONLY, 0xC0000093 },
        { 0x04, 1e300, 1e300, _SW_ZERODIVIDE, 0xC000008E },
        { 0x08, 1e300, 1e300, _SW_INVALID, 0xC0000090 },
        { 0x10, 1e300, 1e300, _SW_INEXACT, 0xC000008F },
        { 0x11, 1e300, HUGE_VAL, _SW_OVERFLOW | _SW_INEXACT, 0xC0000091 },
        { 0x12, 1.0, 0.0, _SW_UNDERFLOW | _SW_INEXACT, 0xC0000093 },
        { 0x14, 1e300, 1e300, _SW_ZERODIVIDE | _SW_INEXACT, 0xC000008E },
        { 0x18, 1.0, 1.0, _SW_INVALID | _SW_INEXACT, 0xC0000090 },
    };
    HMODULE module = GetModuleHandleA("ucrtbase.dll");
    _except1_t p_except1 = (void *)GetProcAddress(module, "_except1");
    unsigned int old_control = _control87(0, 0);
    unsigned int status, control;
    double ret;
    DWORD code;
    size_t i;

    ok(p_except1 != NULL, "_except1 is not exported\n");
    if (!p_except1)
        return;

    for (i = 0; i < ARRAYSIZE(masked); i++)
    {
        /* the exceptions are masked: the flags are set, the control word becomes the one of the caller */
        ret = -5.0;
        code = call_except1(p_except1, masked[i].fpe, masked[i].res, CW_ALL_MASKED, &ret, &status, &control);
        ok(code == 0, "%u: exception %lx\n", (unsigned)i, code);
        ok(ret == masked[i].expect && !!signbit(ret) == !!signbit(masked[i].expect),
           "%u: returned %g, expected %g\n", (unsigned)i, ret, masked[i].expect);
        ok(status == masked[i].status, "%u: status %x, expected %x\n", (unsigned)i, status, masked[i].status);
        ok(control == CONTROL_ALL_MASKED, "%u: control word %x, expected %x\n", (unsigned)i, control,
           CONTROL_ALL_MASKED);
        _control87(old_control, _MCW_EM | _MCW_RC);

        /* not masked: the exception is raised, its parameter is the operation shifted by five */
        code = call_except1(p_except1, masked[i].fpe, masked[i].res, 0, &ret, &status, &control);
        ok(code == masked[i].code, "%u: exception %lx, expected %lx\n", (unsigned)i, code, masked[i].code);
        ok(g_operation == (1 << 5), "%u: operation %x\n", (unsigned)i, g_operation);
        _control87(old_control, _MCW_EM | _MCW_RC);
    }

    /* the overflow with the inexact result needs both masks */
    code = call_except1(p_except1, 0x11, 1e300, MASK_OVERFLOW, &ret, &status, &control);
    ok(code == 0xC0000091, "overflow only masked: exception %lx\n", code);
    code = call_except1(p_except1, 0x11, 1e300, MASK_INEXACT, &ret, &status, &control);
    ok(code == 0xC0000091, "inexact only masked: exception %lx\n", code);
    code = call_except1(p_except1, 0x11, 1e300, MASK_OVERFLOW | MASK_INEXACT, &ret, &status, &control);
    ok(code == 0 && ret == HUGE_VAL, "both masked: exception %lx, returned %g\n", code, ret);

    /* invalid is the first one raised when several are reported */
    code = call_except1(p_except1, 0x19, 1e300, 0, &ret, &status, &control);
    ok(code == 0xC0000090, "invalid and overflow: exception %lx\n", code);
    code = call_except1(p_except1, 0x03, 1e300, 0, &ret, &status, &control);
    ok(code == 0xC0000091, "overflow and underflow: exception %lx\n", code);

    _control87(old_control, _MCW_EM | _MCW_RC);
    _clearfp();
}

START_TEST(fpexcept)
{
    test_dpcomp();
    test_except1();
}
