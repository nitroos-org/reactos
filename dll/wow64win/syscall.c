/* ReactOS WoW64 win32k translation. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"

ULONG_PTR Wow64WinFailure(ULONG Number, NTSTATUS Status)
{
    switch (Number)
    {
#include "failure.inc"
    case W64_NtUserGetMessage: return (ULONG_PTR)-1;
    default: return 0;
    }
}

/* The number of 32-bit argument slots of each win32k service, from the same list that numbers the
 * services (the first one is 0x1000) */
static const UCHAR ServiceSlots[] =
{
#define SVC_(name, count) count,
#undef _WIN64
#include <w32ksvc32.h>
#define _WIN64 1
#undef SVC_
};

/* Large enough for every service (the most is 16) */
#define W32K_MAX_ARGUMENTS 24

static ULONG ServiceArgumentCount(ULONG Number)
{
    ULONG Index = Number - 0x1000;
    return Index < RTL_NUMBER_OF(ServiceSlots) ? min((ULONG)ServiceSlots[Index], W32K_MAX_ARGUMENTS) : 0;
}

static ULONG_PTR Dispatch(ULONG Number, ULONG *a)
{
    switch (Number)
    {
#include "generated.inc"
    default: return Wow64WinUserService(Number,a);
    }
}

NTSTATUS NTAPI Wow64WinSystemService(ULONG Number, ULONG *Arguments)
{
    ULONG_PTR Result;
    DWORD LastError;
    /* The argument list is on the guest stack, where other guest threads can change it. The thunks
     * see only this copy, read once, so a count, length or pointer they checked stays what they use. */
    ULONG a[W32K_MAX_ARGUMENTS] = {0};
    /* win32k writes the native TEB, whereas guest SetLastError reads TEB32. */
    NtCurrentTeb()->LastErrorValue = WOW64_TEB32(NtCurrentTeb())->LastErrorValue;
    _SEH2_TRY
    {
        RtlCopyMemory(a, Arguments, ServiceArgumentCount(Number) * sizeof(ULONG));
        Result = Dispatch(Number,a);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        NtCurrentTeb()->LastErrorValue = RtlNtStatusToDosError(_SEH2_GetExceptionCode());
        Result = Wow64WinFailure(Number,_SEH2_GetExceptionCode());
    }
    _SEH2_END;
    LastError = NtCurrentTeb()->LastErrorValue;
    WOW64_TEB32(NtCurrentTeb())->LastErrorValue = LastError;
    return (ULONG)Result;
}
