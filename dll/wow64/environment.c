/* ReactOS WoW64 process environment. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"

static NTSTATUS SetVariable(PVOID *Environment, PCWSTR Name, PCWSTR Value)
{
    UNICODE_STRING Key, Data;
    RtlInitUnicodeString(&Key, Name);
    RtlInitUnicodeString(&Data, Value);
    return RtlSetEnvironmentVariable(Environment, &Key, &Data);
}

static BOOLEAN GetVariable(PVOID Environment, PCWSTR Name, PWSTR Value, USHORT Capacity)
{
    UNICODE_STRING Key, Data;
    NTSTATUS Status;
    RtlInitUnicodeString(&Key, Name);
    RtlInitEmptyUnicodeString(&Data, Value, Capacity - sizeof(WCHAR));
    Status = RtlQueryEnvironmentVariable_U(Environment, &Key, &Data);
    if (!NT_SUCCESS(Status)) return FALSE;
    Value[Data.Length / sizeof(WCHAR)] = UNICODE_NULL;
    return TRUE;
}

/* The environment a guest process starts with, made from the one it was created with (the creator's, or the block
 * it passed to CreateProcess). Measured on Windows Server 2022 with a 32-bit probe started by 64-bit and by 32-bit
 * parents (inherited environment, CreateEnvironmentBlock, a minimal block, blocks without individual variables):
 *  - nothing is added or removed except these changes, and nothing is made up: a variable that is not in the block
 *    stays absent (a block without ProgramFiles(x86) keeps ProgramFiles as it is; one with only SystemRoot gets no
 *    PROCESSOR_ARCHITECTURE; ProgramW6432 and CommonProgramW6432 come only from the creator's block);
 *  - PROCESSOR_ARCHITECTURE other than x86 becomes x86 and PROCESSOR_ARCHITEW6432 gets the native value;
 *  - ProgramFiles takes the value of ProgramFiles(x86), and CommonProgramFiles that of CommonProgramFiles(x86),
 *    each one only when its (x86) variable is in the block. */
NTSTATUS Wow64CreateEnvironment(PVOID *Environment)
{
    static const struct { PCWSTR Name, Guest; } Map[] = {
        {L"ProgramFiles", L"ProgramFiles(x86)"},
        {L"CommonProgramFiles", L"CommonProgramFiles(x86)"},
    };
    WCHAR Value[MAX_PATH];
    NTSTATUS Status;
    ULONG i;

    /* Work on a private native-addressed copy, then serialize it below 4 GB.
     * This also preserves custom inherited variables and drive directories. */
    Status = RtlCreateEnvironment(TRUE, Environment);
    if (!NT_SUCCESS(Status)) return Status;

    if (GetVariable(*Environment, L"PROCESSOR_ARCHITECTURE", Value, sizeof(Value)) && _wcsicmp(Value, L"x86"))
    {
        Status = SetVariable(Environment, L"PROCESSOR_ARCHITEW6432", Value);
        if (!NT_SUCCESS(Status)) return Status;
        Status = SetVariable(Environment, L"PROCESSOR_ARCHITECTURE", L"x86");
        if (!NT_SUCCESS(Status)) return Status;
    }

    for (i = 0; i < RTL_NUMBER_OF(Map); ++i)
    {
        if (!GetVariable(*Environment, Map[i].Guest, Value, sizeof(Value))) continue;
        Status = SetVariable(Environment, Map[i].Name, Value);
        if (!NT_SUCCESS(Status)) return Status;
    }
    return STATUS_SUCCESS;
}

/* A guest process that starts a native (64-bit) child hands over the environment it inherited. That is
 * the guest's view (PROCESSOR_ARCHITECTURE=x86, ProgramFiles and CommonProgramFiles under "Program Files
 * (x86)"), which the child would take for its own: Click-to-Run, for one, then picks the 32-bit common
 * files folder for a 64-bit installation. Translate the guest's view back to the native one.
 * The *W6432 and (x86) variables stay, as in any native process. */
NTSTATUS Wow64CreateNativeChildEnvironment(PCWSTR Guest, PVOID *Environment)
{
    static const struct { PCWSTR Name, Native; } Map[] = {
        {L"PROCESSOR_ARCHITECTURE", L"PROCESSOR_ARCHITEW6432"},
        {L"ProgramFiles", L"ProgramW6432"},
        {L"CommonProgramFiles", L"CommonProgramW6432"},
    };
    WCHAR Value[MAX_PATH];
    PCWSTR End = Guest;
    PVOID Block;
    SIZE_T Size;
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;

    while (*End) End += wcslen(End) + 1;
    Size = (End + 1 - Guest) * sizeof(WCHAR);
    /* RtlSetEnvironmentVariable grows a block of the process heap */
    Block = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!Block) return STATUS_NO_MEMORY;
    RtlCopyMemory(Block, Guest, Size);

    for (i = 0; i < RTL_NUMBER_OF(Map); ++i)
    {
        UNICODE_STRING Key;
        if (!GetVariable(Block, Map[i].Native, Value, sizeof(Value))) continue;
        Status = SetVariable(&Block, Map[i].Name, Value);
        if (!NT_SUCCESS(Status)) break;
        if (i == 0)
        {
            /* Only the guest's view carries the native architecture under this name */
            RtlInitUnicodeString(&Key, Map[i].Native);
            Status = RtlSetEnvironmentVariable(&Block, &Key, NULL);
            if (!NT_SUCCESS(Status)) break;
        }
    }
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Block);
        return Status;
    }
    *Environment = Block;
    return STATUS_SUCCESS;
}
