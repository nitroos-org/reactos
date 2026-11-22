/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite for the ROS-internal commands of KdSystemDebugControl
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include <ndk/kdfuncs.h>

/*
 * The ROS-internal commands (debug builds only) take raw kernel pointers: only a kernel-mode caller may use them, a
 * caller whose previous mode is user mode is refused like any unknown command. The arguments are the ones that do
 * nothing when a kernel-mode caller passes them.
 */
static
NTSTATUS
(NTAPI *pKdSystemDebugControl)(
    _In_ SYSDBG_COMMAND Command,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Inout_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE PreviousMode);

START_TEST(KdSystemDebugControlInternal)
{
    static ULONG_PTR Frames[1];
    const struct
    {
        ULONG Command;
        PVOID Buffer;
        ULONG Length;
    } Internal[] = { { ' soR', NULL, 0 }, { 'CsoR', NULL, 99 }, { 'DsoR', Frames, 0 }, { 'PdbK', Frames, 0 } };
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"KdSystemDebugControl");
    NTSTATUS Status;
    ULONG i;

    pKdSystemDebugControl = MmGetSystemRoutineAddress(&Name);
    if (skip(pKdSystemDebugControl != NULL, "KdSystemDebugControl is not exported\n"))
        return;

    Status = pKdSystemDebugControl((SYSDBG_COMMAND)' soR', NULL, 0, NULL, 0, NULL, KernelMode);
    if (skip(NT_SUCCESS(Status), "The internal commands exist only in debug builds (0x%08lx)\n", Status))
        return;

    for (i = 0; i < RTL_NUMBER_OF(Internal); i++)
    {
        Status = pKdSystemDebugControl((SYSDBG_COMMAND)Internal[i].Command, Internal[i].Buffer, Internal[i].Length,
                                       NULL, 0, NULL, UserMode);
        ok(Status == STATUS_INVALID_INFO_CLASS, "Command 0x%08lx from user mode: Status = 0x%08lx, expected 0x%08lx\n",
           Internal[i].Command, Status, STATUS_INVALID_INFO_CLASS);
    }
}
