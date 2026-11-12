/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for the processor group routines and
 *              KeQueryUnbiasedInterruptTime (single group 0 system)
 */

#include <kmt_test.h>

typedef ULONG (NTAPI *PKE_GET_CURRENT_PROCESSOR_NUMBER_EX)(PPROCESSOR_NUMBER);
typedef USHORT (NTAPI *PKE_QUERY_GROUP_COUNT)(VOID);
typedef KAFFINITY (NTAPI *PKE_QUERY_GROUP_AFFINITY)(USHORT);
typedef KAFFINITY (NTAPI *PKE_SET_SYSTEM_AFFINITY_EX)(KAFFINITY);
typedef VOID (NTAPI *PKE_REVERT_AFFINITY_EX)(KAFFINITY);
typedef VOID (NTAPI *PKE_SET_GROUP_AFFINITY)(PGROUP_AFFINITY, PGROUP_AFFINITY);
typedef VOID (NTAPI *PKE_REVERT_GROUP_AFFINITY)(PGROUP_AFFINITY);
typedef ULONGLONG (NTAPI *PKE_QUERY_UNBIASED)(VOID);

START_TEST(KeProcessorGroups)
{
    PKE_GET_CURRENT_PROCESSOR_NUMBER_EX pGetNumberEx = KmtGetSystemRoutineAddress(L"KeGetCurrentProcessorNumberEx");
    PKE_QUERY_GROUP_COUNT pActiveGroups = KmtGetSystemRoutineAddress(L"KeQueryActiveGroupCount");
    PKE_QUERY_GROUP_COUNT pMaxGroups = KmtGetSystemRoutineAddress(L"KeQueryMaximumGroupCount");
    PKE_QUERY_GROUP_AFFINITY pGroupAffinity = KmtGetSystemRoutineAddress(L"KeQueryGroupAffinity");
    PKE_SET_SYSTEM_AFFINITY_EX pSetEx = KmtGetSystemRoutineAddress(L"KeSetSystemAffinityThreadEx");
    PKE_REVERT_AFFINITY_EX pRevertEx = KmtGetSystemRoutineAddress(L"KeRevertToUserAffinityThreadEx");
    PKE_SET_GROUP_AFFINITY pSetGroup = KmtGetSystemRoutineAddress(L"KeSetSystemGroupAffinityThread");
    PKE_REVERT_GROUP_AFFINITY pRevertGroup = KmtGetSystemRoutineAddress(L"KeRevertToUserGroupAffinityThread");
    PKE_QUERY_UNBIASED pUnbiased = KmtGetSystemRoutineAddress(L"KeQueryUnbiasedInterruptTime");
    PROCESSOR_NUMBER Number;
    GROUP_AFFINITY Group, Previous;
    KAFFINITY Active, Old;
    LARGE_INTEGER Delay;
    ULONGLONG T1, T2;
    ULONG Index;
    KIRQL OldIrql;

    ok(pGetNumberEx && pActiveGroups && pMaxGroups && pGroupAffinity && pSetEx &&
       pRevertEx && pSetGroup && pRevertGroup && pUnbiased,
       "a processor group routine is not exported\n");
    if (!(pGetNumberEx && pActiveGroups && pMaxGroups && pGroupAffinity && pSetEx &&
          pRevertEx && pSetGroup && pRevertGroup && pUnbiased))
        return;

    ok_eq_int(pActiveGroups(), 1);
    ok_eq_int(pMaxGroups(), 1);

    Active = KeQueryActiveProcessors();
    ok_eq_hex(pGroupAffinity(0), Active);
    ok_eq_hex(pGroupAffinity(1), 0);

    /* the processor number of the running processor */
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    RtlFillMemory(&Number, sizeof(Number), 0xFF);
    Index = pGetNumberEx(&Number);
    ok_eq_int(Number.Group, 0);
    ok_eq_int(Number.Number, Index);
    ok_eq_ulong(Index, KeGetCurrentProcessorNumber());
    ok(Index < 64, "processor index %lu\n", Index);
    KeLowerIrql(OldIrql);
    /* a NULL pointer is allowed */
    Index = pGetNumberEx(NULL);
    ok(Index < 64, "processor index %lu\n", Index);

    /* system affinity: restrict to one processor, then revert */
    Old = pSetEx(1);
    ok_eq_hex(Old, 0);
    ok_eq_ulong(KeGetCurrentProcessorNumber(), 0);
    pRevertEx(Old);

    Group.Group = 0;
    Group.Mask = 1;
    Group.Reserved[0] = Group.Reserved[1] = Group.Reserved[2] = 0;
    RtlFillMemory(&Previous, sizeof(Previous), 0xFF);
    pSetGroup(&Group, &Previous);
    ok_eq_int(Previous.Group, 0);
    ok_eq_hex(Previous.Mask, 0);
    ok_eq_ulong(KeGetCurrentProcessorNumber(), 0);
    pRevertGroup(&Previous);

    /* the unbiased interrupt time moves forward */
    T1 = pUnbiased();
    Delay.QuadPart = -10 * 1000 * 50; /* 50 ms */
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    T2 = pUnbiased();
    ok(T2 > T1, "time did not advance: %I64u -> %I64u\n", T1, T2);
    ok(T2 - T1 >= 10 * 1000 * 40 && T2 - T1 < 10 * 1000 * 5000,
       "implausible delta %I64u (100 ns units) for a 50 ms delay\n", T2 - T1);
}
