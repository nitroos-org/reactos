/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test delivery of unmasked x87 floating point faults (#MF)
 */

#include "precomp.h"

#if defined(_M_IX86) || defined(_M_AMD64)

static
ULONG
RaiseX87DivideByZero(VOID)
{
    /* Control word with only the divide-by-zero exception unmasked */
    USHORT Unmasked = 0x37B, Saved;
    ULONG Code = 0;

    __asm__ __volatile__("fnstcw %0" : "=m"(Saved));
    __asm__ __volatile__("fldcw %0" : : "m"(Unmasked));

    _SEH2_TRY
    {
        /* fldz; fld1; fdivp (1 / 0); the fault is signalled by the fwait */
        __asm__ __volatile__(".byte 0xd9, 0xee, 0xd9, 0xe8, 0xde, 0xf1, 0x9b" : : : "st", "st(1)");
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Code = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    /* The kernel must have cleared the pending error: this fwait must not fault again */
    _SEH2_TRY
    {
        __asm__ __volatile__("fwait");
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Code = 0xDEAD0000 | (Code & 0xFFFF);
    }
    _SEH2_END;

    __asm__ __volatile__("fnclex; fninit");
    __asm__ __volatile__("fldcw %0" : : "m"(Saved));
    return Code;
}

static
ULONG
RaiseX87StackCheck(VOID)
{
    /* Only invalid operation unmasked: popping an empty stack is a stack fault */
    USHORT Unmasked = 0x37E, Saved;
    ULONG Code = 0;

    __asm__ __volatile__("fnstcw %0" : "=m"(Saved));
    __asm__ __volatile__("fnclex; fldcw %0" : : "m"(Unmasked));

    _SEH2_TRY
    {
        /* fstp st(0) on an empty stack; fwait signals it */
        __asm__ __volatile__(".byte 0xdd, 0xd8, 0x9b");
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Code = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    __asm__ __volatile__("fnclex; fninit");
    __asm__ __volatile__("fldcw %0" : : "m"(Saved));
    return Code;
}

START_TEST(X87Fault)
{
    ULONG Code;

    Code = RaiseX87DivideByZero();
    ok(Code == (ULONG)STATUS_FLOAT_DIVIDE_BY_ZERO, "Got exception %#lx, expected STATUS_FLOAT_DIVIDE_BY_ZERO\n", Code);

    Code = RaiseX87StackCheck();
    ok(Code == (ULONG)STATUS_FLOAT_STACK_CHECK, "Got exception %#lx, expected STATUS_FLOAT_STACK_CHECK\n", Code);
}

#else

START_TEST(X87Fault)
{
    skip("x87 faults are only tested on x86 and amd64\n");
}

#endif
