/*
 * PROJECT:     ReactOS kernel tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Session images: same address in every session, pages and data of their own in each
 *              (NitroSessions)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

NTKERNELAPI
ULONG
NTAPI
PsGetProcessSessionIdEx(
    _In_ PEPROCESS Process);

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID Base,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size);

typedef NTSTATUS (NTAPI *PLOAD_SESSION_IMAGE)(PUNICODE_STRING, PVOID *, PVOID *);
typedef NTSTATUS (NTAPI *PUNLOAD_SESSION_IMAGE)(PVOID);
typedef LONG (NTAPI *PCOUNTER_ROUTINE)(VOID);
typedef PVOID (NTAPI *PADDRESS_ROUTINE)(VOID);

static PLOAD_SESSION_IMAGE LoadSessionImage;
static PUNLOAD_SESSION_IMAGE UnloadSessionImage;
static UNICODE_STRING NameA = RTL_CONSTANT_STRING(L"\\SystemRoot\\bin\\sesstst_a.sys");
static UNICODE_STRING NameB = RTL_CONSTANT_STRING(L"\\SystemRoot\\bin\\sesstst_b.sys");

/* The page table entry of an address, for the protection bits */
/*
 * The Write bit of a valid PTE is bit 11 on multiprocessor kernels (bit 1 is then Writable) and bit 1
 * otherwise: compare a session image with a global image (this driver) instead of assuming one
 */
#if defined(_M_AMD64)
#define TEST_PTE(Va)    ((volatile ULONG64 *)(0xFFFFF68000000000ULL + (((ULONG_PTR)(Va) >> 9) & 0x7FFFFFFFF8ULL)))
#define PTE_WRITE(Pte)  ((((Pte) >> 1) & 1) && (((Pte) >> 11) & 1))
#define PTE_NX(Pte)     (((Pte) >> 63) & 1)
typedef ULONG64 TEST_PTE_VALUE;
#elif defined(_M_IX86) && !defined(_X86PAE_)
#define TEST_PTE(Va)    ((volatile ULONG *)(0xC0000000UL + (((ULONG_PTR)(Va) >> 10) & ~3UL)))
#define PTE_WRITE(Pte)  ((((Pte) >> 1) & 1) && (((Pte) >> 11) & 1))
#define PTE_NX(Pte)     0
typedef ULONG TEST_PTE_VALUE;
#endif

/* Session image space (the top of session space) */
#if defined(_M_AMD64)
#define IS_SESSION_IMAGE(Va) (((ULONG_PTR)(Va) >= 0xFFFFF97FFF000000ULL) && ((ULONG_PTR)(Va) < 0xFFFFF98000000000ULL))
#else
#define IS_SESSION_IMAGE(Va) (((ULONG_PTR)(Va) >= 0xBF800000UL) && ((ULONG_PTR)(Va) < 0xC0000000UL))
#endif

static
PVOID
FindExport(
    _In_ PVOID Base,
    _In_ PCSTR Name)
{
    PIMAGE_EXPORT_DIRECTORY Exports;
    PULONG Names, Functions;
    PUSHORT Ordinals;
    ULONG Size, i;

    Exports = RtlImageDirectoryEntryToData(Base, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size);
    if (!Exports) return NULL;
    Names = (PULONG)((PUCHAR)Base + Exports->AddressOfNames);
    Functions = (PULONG)((PUCHAR)Base + Exports->AddressOfFunctions);
    Ordinals = (PUSHORT)((PUCHAR)Base + Exports->AddressOfNameOrdinals);
    for (i = 0; i < Exports->NumberOfNames; i++)
    {
        if (!strcmp((PCSTR)Base + Names[i], Name))
            return (PUCHAR)Base + Functions[Ordinals[i]];
    }
    return NULL;
}

/* The csrss of the session (a process that is in it; the session leader smss reports 0), referenced */
static
PEPROCESS
FindMember(
    _In_ ULONG SessionId)
{
    PSYSTEM_PROCESS_INFORMATION Info = NULL, Entry;
    ULONG Size = 512 * 1024, Length, Offset = 0;
    PEPROCESS Process, Found = NULL;
    NTSTATUS Status;

    Info = ExAllocatePoolWithTag(PagedPool, Size, 'iSmK');
    if (!Info) return NULL;
    Status = ZwQuerySystemInformation(SystemProcessInformation, Info, Size, &Length);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Info, 'iSmK');
        return NULL;
    }

    for (;;)
    {
        Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Offset);
        if (Entry->UniqueProcessId &&
            NT_SUCCESS(PsLookupProcessByProcessId(Entry->UniqueProcessId, &Process)))
        {
            if ((PsGetProcessExitStatus(Process) == STATUS_PENDING) &&
                (PsGetProcessSessionIdEx(Process) == SessionId) &&
                !_stricmp(PsGetProcessImageFileName(Process), "csrss.exe"))
            {
                Found = Process;
                break;
            }
            ObDereferenceObject(Process);
        }
        if (!Entry->NextEntryOffset) break;
        Offset += Entry->NextEntryOffset;
    }
    ExFreePoolWithTag(Info, 'iSmK');
    return Found;
}

typedef struct _TEST_IMAGE
{
    PVOID Handle;
    PVOID Base;
} TEST_IMAGE, *PTEST_IMAGE;

static
NTSTATUS
Load(
    _In_ PEPROCESS Member,
    _In_ PUNICODE_STRING Name,
    _Out_ PTEST_IMAGE Image)
{
    KAPC_STATE ApcState;
    NTSTATUS Status;

    Image->Handle = Image->Base = NULL;
    KeStackAttachProcess((PKPROCESS)Member, &ApcState);
    Status = LoadSessionImage(Name, &Image->Handle, &Image->Base);
    KeUnstackDetachProcess(&ApcState);
    return Status;
}

static
NTSTATUS
Unload(
    _In_ PEPROCESS Member,
    _In_ PTEST_IMAGE Image)
{
    KAPC_STATE ApcState;
    NTSTATUS Status;

    KeStackAttachProcess((PKPROCESS)Member, &ApcState);
    Status = UnloadSessionImage(Image->Handle);
    KeUnstackDetachProcess(&ApcState);
    return Status;
}

/* Calls an export of an image in the member's session Times times; returns the last result */
static
LONG
Call(
    _In_ PEPROCESS Member,
    _In_ PVOID Base,
    _In_ PCSTR Export,
    _In_ ULONG Times)
{
    KAPC_STATE ApcState;
    PCOUNTER_ROUTINE Routine;
    LONG Result = -1;

    KeStackAttachProcess((PKPROCESS)Member, &ApcState);
    Routine = FindExport(Base, Export);
    ok(Routine != NULL, "%s not found\n", Export);
    while (Routine && Times--)
        Result = Routine();
    KeUnstackDetachProcess(&ApcState);
    return Result;
}

static
PVOID
CallAddress(
    _In_ PEPROCESS Member,
    _In_ PVOID Base,
    _In_ PCSTR Export)
{
    KAPC_STATE ApcState;
    PADDRESS_ROUTINE Routine;
    PVOID Result = NULL;

    KeStackAttachProcess((PKPROCESS)Member, &ApcState);
    Routine = FindExport(Base, Export);
    ok(Routine != NULL, "%s not found\n", Export);
    if (Routine) Result = Routine();
    KeUnstackDetachProcess(&ApcState);
    return Result;
}

#ifdef PTE_WRITE
/* Code is read-only, the counter writable (and not executable where there is NX) */
static
VOID
CheckProtections(
    _In_ PEPROCESS Member,
    _In_ PVOID Base)
{
    KAPC_STATE ApcState;
    PVOID Code, Data;
    TEST_PTE_VALUE CodePte, DataPte;

    /* This driver's code: a global image */
    trace("global code PTE %I64x\n", (ULONG64)*TEST_PTE((PVOID)FindExport));

    KeStackAttachProcess((PKPROCESS)Member, &ApcState);
    Code = FindExport(Base, "SessTestIncrement");
    Data = ((PADDRESS_ROUTINE)FindExport(Base, "SessTestCounterAddress"))();
    CodePte = *TEST_PTE(Code);
    DataPte = *TEST_PTE(Data);
    KeUnstackDetachProcess(&ApcState);

    trace("session code PTE %I64x, data PTE %I64x\n", (ULONG64)CodePte, (ULONG64)DataPte);
    ok((CodePte & 1) && !((CodePte >> 11) & 1) && !PTE_NX(CodePte), "code PTE %I64x\n", (ULONG64)CodePte);
    ok((DataPte & 1) && PTE_WRITE(DataPte), "data PTE %I64x\n", (ULONG64)DataPte);
#if defined(_M_AMD64)
    ok(PTE_NX(DataPte), "data PTE %I64x is executable\n", (ULONG64)DataPte);
#endif
}
#endif

/* A global load (as a GDI driver, in system space) */
static
NTSTATUS
GlobalLoad(
    _In_ PUNICODE_STRING Name,
    _Out_ PVOID *Section)
{
    SYSTEM_GDI_DRIVER_INFORMATION Info;
    NTSTATUS Status;

    RtlZeroMemory(&Info, sizeof(Info));
    Info.DriverName = *Name;
    Status = ZwSetSystemInformation(SystemLoadGdiDriverInformation, &Info, sizeof(Info));
    *Section = Info.SectionPointer;
    return Status;
}

START_TEST(MmSessionImage)
{
    UNICODE_STRING LoadName = RTL_CONSTANT_STRING(L"NitroMmLoadSessionImageForTest");
    UNICODE_STRING UnloadName = RTL_CONSTANT_STRING(L"NitroMmUnloadSessionImageForTest");
    PEPROCESS Member0, Member1;
    TEST_IMAGE A0, A1, B0, B1, A2;
    PVOID Section, Target, Increment;
    NTSTATUS Status, Result;
    KAPC_STATE ApcState;
    LONG Value;
    PVOID Pointer;

    LoadSessionImage = (PLOAD_SESSION_IMAGE)MmGetSystemRoutineAddress(&LoadName);
    UnloadSessionImage = (PUNLOAD_SESSION_IMAGE)MmGetSystemRoutineAddress(&UnloadName);
    if (!LoadSessionImage || !UnloadSessionImage)
    {
        skip(FALSE, "No session image test hook\n");
        return;
    }

    Member0 = FindMember(0);
    Member1 = FindMember(1);
    ok(Member0 != NULL, "No process in session 0\n");
    if (!Member0) return;

    /* Without NitroSessions there are no session images */
    Status = Load(Member0, &NameA, &A0);
    if (Status == STATUS_NOT_SUPPORTED)
    {
        skip(FALSE, "NitroSessions is not set\n");
        ObDereferenceObject(Member0);
        if (Member1) ObDereferenceObject(Member1);
        return;
    }
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(Member1 != NULL, "No process in session 1: run with NitroSessions 4\n");
    if (!NT_SUCCESS(Status) || !Member1)
        goto Out;
    ok(IS_SESSION_IMAGE(A0.Base), "session image at %p\n", A0.Base);

    /* R3: not from a process that is in no session */
    KeStackAttachProcess((PKPROCESS)PsInitialSystemProcess, &ApcState);
    Status = LoadSessionImage(&NameA, &A2.Handle, &A2.Base);
    KeUnstackDetachProcess(&ApcState);
    ok_eq_hex(Status, STATUS_NO_MEMORY);

    /* Same address in session 1, data of its own (the copy is taken before any call) */
    Status = Load(Member1, &NameA, &A1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto UnloadA0;
    ok_eq_pointer(A1.Base, A0.Base);
    ok_eq_pointer(A1.Handle, A0.Handle);
    Value = Call(Member0, A0.Base, "SessTestIncrement", 3);
    ok_eq_long(Value, 3L);
    Value = Call(Member1, A1.Base, "SessTestIncrement", 5);
    ok_eq_long(Value, 5L);
    Value = Call(Member0, A0.Base, "SessTestGetCounter", 1);
    ok_eq_long(Value, 3L);
    Value = Call(Member1, A1.Base, "SessTestGetCounter", 1);
    ok_eq_long(Value, 5L);
    Pointer = CallAddress(Member0, A0.Base, "SessTestCounterAddress");
    Target = CallAddress(Member1, A1.Base, "SessTestCounterAddress");
    ok_eq_pointer(Pointer, Target);
#ifdef PTE_WRITE
    CheckProtections(Member0, A0.Base);
    CheckProtections(Member1, A1.Base);
#endif

    /* R2: a global image cannot import a session image, nor be loaded under its name */
    Section = NULL;
    Status = GlobalLoad(&NameB, &Section);
    ok_eq_hex(Status, STATUS_INVALID_IMAGE_FORMAT);
    Section = NULL;
    Status = GlobalLoad(&NameA, &Section);
    ok_eq_hex(Status, STATUS_INVALID_IMAGE_FORMAT);

    /* B imports A: it binds to the copy of A in its own session */
    Status = Load(Member1, &NameB, &B1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(IS_SESSION_IMAGE(B1.Base), "session image at %p\n", B1.Base);
        Value = Call(Member1, B1.Base, "SessTestBIncrement", 1);
        ok_eq_long(Value, 6L);
        Value = Call(Member0, A0.Base, "SessTestGetCounter", 1);
        ok_eq_long(Value, 3L);
        Target = CallAddress(Member1, B1.Base, "SessTestBImportTarget");
        KeStackAttachProcess((PKPROCESS)Member1, &ApcState);
        Increment = FindExport(A1.Base, "SessTestIncrement");
        KeUnstackDetachProcess(&ApcState);
        ok_eq_pointer(Target, Increment);

        Status = Load(Member0, &NameB, &B0);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            ok_eq_pointer(B0.Base, B1.Base);
            Value = Call(Member0, B0.Base, "SessTestBIncrement", 1);
            ok_eq_long(Value, 4L);
            Value = Call(Member1, A1.Base, "SessTestGetCounter", 1);
            ok_eq_long(Value, 6L);
            Result = Unload(Member0, &B0);
            ok_eq_hex(Result, STATUS_SUCCESS);
        }
        Result = Unload(Member1, &B1);
        ok_eq_hex(Result, STATUS_SUCCESS);
    }

    /* A second load in a session shares that session's copy */
    Status = Load(Member1, &NameA, &A2);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Value = Call(Member1, A2.Base, "SessTestGetCounter", 1);
        ok_eq_long(Value, 6L);
        Result = Unload(Member1, &A2);
        ok_eq_hex(Result, STATUS_SUCCESS);
    }

    Result = Unload(Member1, &A1);
    ok_eq_hex(Result, STATUS_SUCCESS);
UnloadA0:
    Result = Unload(Member0, &A0);
    ok_eq_hex(Result, STATUS_SUCCESS);

    /* Every load is gone: the next one starts from a fresh copy */
    Status = Load(Member1, &NameA, &A1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Value = Call(Member1, A1.Base, "SessTestGetCounter", 1);
        ok_eq_long(Value, 0L);
        Result = Unload(Member1, &A1);
        ok_eq_hex(Result, STATUS_SUCCESS);
    }

Out:
    ObDereferenceObject(Member0);
    if (Member1) ObDereferenceObject(Member1);
}

/*
 * Hidden: stops the system inside a session image loaded in session 1, so that the debugger's
 * backtrace can be checked for the image and function names
 */
START_TEST(MmSessionImageBugCheck)
{
    UNICODE_STRING LoadName = RTL_CONSTANT_STRING(L"NitroMmLoadSessionImageForTest");
    PEPROCESS Member1;
    TEST_IMAGE A1;
    NTSTATUS Status;

    LoadSessionImage = (PLOAD_SESSION_IMAGE)MmGetSystemRoutineAddress(&LoadName);
    Member1 = FindMember(1);
    if (!LoadSessionImage || !Member1)
    {
        skip(FALSE, "Needs the test hook and session 1\n");
        if (Member1) ObDereferenceObject(Member1);
        return;
    }
    Status = Load(Member1, &NameA, &A1);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
        Call(Member1, A1.Base, "SessTestBugCheck", 1);
    ObDereferenceObject(Member1);
}
