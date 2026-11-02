/* ReactOS integer exception continuation regression. SPDX-License-Identifier: GPL-2.0-or-later */
#include "precomp.h"

DECLSPEC_ALIGN(16) ULONG ContinueXmm[8] = {0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00,
                                         0x12345678, 0x9abcdef0, 0x13579bdf, 0x2468ace0};
ULONG ContinueResult[18];
#ifdef _M_IX86
void ContinueFault(void);
void ContinueResume(void);
void ContinueSetXmm(void);
static ULONG Calls;
static BOOL KeepExceptionBits;

static LONG NTAPI ContinueHandler(EXCEPTION_POINTERS *Pointers)
{
    CONTEXT *Context = Pointers->ContextRecord;
    if (Pointers->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    ++Calls;
    /* The exception dispatch hands the handler a context that carries CONTEXT_EXCEPTION_REQUEST and
     * CONTEXT_EXCEPTION_REPORTING; code that resumes (the CLR) keeps them, NtContinue ignores them */
    Context->ContextFlags = CONTEXT_FULL | (KeepExceptionBits ? 0xC0000000 : 0);
    Context->Eax = 0x12345601; Context->Ebx = 0x12345602;
    Context->Ecx = 0x12345603; Context->Edx = 0x12345604;
    Context->Esi = 0x12345605; Context->Edi = 0x12345606;
    Context->Ebp = 0x12345607;
    Context->EFlags |= 1;
    Context->Eip = (ULONG_PTR)ContinueResume;
    ContinueSetXmm();
    return EXCEPTION_CONTINUE_EXECUTION;
}
#endif

#ifdef _M_AMD64
CONTEXT NativeContinueContext;
EXCEPTION_RECORD NativeContinueRecord = {0xe1234567};
static ULONG NativeRaiseCalls;
static LONG NTAPI NativeRaiseHandler(EXCEPTION_POINTERS *Pointers)
{
    if (Pointers->ExceptionRecord->ExceptionCode != NativeContinueRecord.ExceptionCode)
        return EXCEPTION_CONTINUE_SEARCH;
    ++NativeRaiseCalls;
    ok(!memcmp(&Pointers->ContextRecord->Xmm6, ContinueXmm, sizeof(ContinueXmm)),
       "partial NtRaiseException delivered stale nonvolatile XMM state\n");
    return EXCEPTION_CONTINUE_EXECUTION;
}
#endif

START_TEST(Wow64Continue)
{
#ifdef _M_IX86
    PVOID Handler;
    ULONG i;
    if (!IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE))
    {
        skip("The XMM preservation fixture requires SSE2\n");
        return;
    }
    Handler = RtlAddVectoredExceptionHandler(1, ContinueHandler);
    ok(Handler != NULL, "handler registration failed\n");
    if (!Handler) return;
    ContinueFault();
    RtlRemoveVectoredExceptionHandler(Handler);
    ok(Calls == 1, "continuation handler calls %lu\n", Calls);
    for (i = 0; i < 7; ++i)
        ok(ContinueResult[i] == 0x12345601 + i, "integer %lu: %lx\n", i, ContinueResult[i]);
    ok(ContinueResult[7] & 1, "carry flag not restored: %lx\n", ContinueResult[7]);
    for (i = 0; i < 8; ++i)
        ok(ContinueResult[8+i] == ContinueXmm[i], "XMM word %lu: %lx expected %lx\n",
           i, ContinueResult[8+i], ContinueXmm[i]);
    ok(ContinueResult[16] == ContinueResult[17], "stack changed: %lx / %lx\n", ContinueResult[16], ContinueResult[17]);

    /* the same resume with the exception state bits left in ContextFlags */
    KeepExceptionBits = TRUE;
    memset(ContinueResult, 0, sizeof(ContinueResult));
    Handler = RtlAddVectoredExceptionHandler(1, ContinueHandler);
    ok(Handler != NULL, "handler registration failed\n");
    if (!Handler) return;
    ContinueFault();
    RtlRemoveVectoredExceptionHandler(Handler);
    ok(Calls == 2, "continuation handler calls %lu\n", Calls);
    for (i = 0; i < 7; ++i)
        ok(ContinueResult[i] == 0x12345601 + i, "exception bits, integer %lu: %lx\n", i, ContinueResult[i]);
#elif defined(_M_AMD64)
    static const ULONG flags[] = {CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
                                  CONTEXT_CONTROL | CONTEXT_SEGMENTS,
                                  CONTEXT_FULL | CONTEXT_SEGMENTS};
    extern void NativeContinuePartial(ULONG Flags, BOOL Raise);
    ULONG i, j, raise;
    PVOID handler;
    NTSTATUS status;
    status = NtContinue(NULL, FALSE);
    ok(status == STATUS_ACCESS_VIOLATION, "invalid context: %lx\n", status);
    status = NtRaiseException(NULL, NULL, TRUE);
    ok(status == STATUS_ACCESS_VIOLATION, "invalid exception context: %lx\n", status);
    handler = RtlAddVectoredExceptionHandler(1, NativeRaiseHandler);
    ok(handler != NULL, "native handler registration\n");
    if (!handler) return;
    for (raise = 0; raise < 2; ++raise)
    for (i = 0; i < _countof(flags); ++i)
    {
        for (j = 0; j < _countof(ContinueXmm); ++j) ContinueXmm[j] ^= 0x01010101 * (i + 1);
        NativeContinuePartial(flags[i], raise);
        ok(ContinueResult[0] == ((flags[i] & (CONTEXT_INTEGER & ~CONTEXT_AMD64)) ? 0x12345678 : 0x87654321),
           "native partial integer %lx: %lx\n", flags[i], ContinueResult[0]);
        for (j = 0; j < _countof(ContinueXmm); ++j)
            ok(ContinueResult[8+j] == ContinueXmm[j], "native flags %lx XMM %lu: %lx expected %lx\n",
               flags[i], j, ContinueResult[8+j], ContinueXmm[j]);
    }
    RtlRemoveVectoredExceptionHandler(handler);
    ok(NativeRaiseCalls == 3, "native raise calls %lu\n", NativeRaiseCalls);

#endif
}

