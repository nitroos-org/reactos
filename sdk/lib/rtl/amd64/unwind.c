/*
 * PROJECT:     ReactOS runtime library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Unwinding related functions
 * COPYRIGHT:   Copyright 2010-2025 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#if 0 // These are deprecated / not for x64
#define UWOP_SAVE_XMM 6
#define UWOP_SAVE_XMM_FAR 7
#else
#define UWOP_EPILOG 6
#define UWOP_SPARE_CODE 7
#endif
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10


typedef unsigned char UBYTE;

typedef union _UNWIND_CODE
{
    struct
    {
        UBYTE CodeOffset;
        UBYTE UnwindOp:4;
        UBYTE OpInfo:4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO
{
    UBYTE Version:3;
    UBYTE Flags:5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister:4;
    UBYTE FrameOffset:4;
    UNWIND_CODE UnwindCode[1];
/*    union {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };
    OPTIONAL ULONG ExceptionData[];
*/
} UNWIND_INFO, *PUNWIND_INFO;

/* FUNCTIONS *****************************************************************/

/*! RtlLookupFunctionTable
 * \brief Locates the table of RUNTIME_FUNCTION entries for a code address.
 * \param ControlPc
 *            Address of the code, for which the table should be searched.
 * \param ImageBase
 *            Pointer to a DWORD64 that receives the base address of the
 *            corresponding executable image.
 * \param Length
 *            Pointer to an ULONG that receives the number of table entries
 *            present in the table.
 */
PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionTable(
    IN DWORD64 ControlPc,
    OUT PDWORD64 ImageBase,
    OUT PULONG Length)
{
    PVOID Table, Base;
    ULONG Size;

    /* Find corresponding file header from code address */
    if (!RtlPcToFileHeader((PVOID)ControlPc, &Base))
    {
        /* Nothing found, leave ImageBase untouched */
        return NULL;
    }
    *ImageBase = (DWORD64)Base;

    /* Locate the exception directory */
    Table = RtlImageDirectoryEntryToData(Base,
                                         TRUE,
                                         IMAGE_DIRECTORY_ENTRY_EXCEPTION,
                                         &Size);

    /* Return the size of the table in bytes, as Windows does */
    *Length = Size;

    /* Return the address of the table */
    return Table;
}

PRUNTIME_FUNCTION
NTAPI
RtlpLookupDynamicFunctionEntry(
    _In_ DWORD64 ControlPc,
    _Out_ PDWORD64 ImageBase,
    _In_ PUNWIND_HISTORY_TABLE HistoryTable);

/*! RtlpLookupRawFunctionEntry
 * \brief Locates the RUNTIME_FUNCTION entry whose range contains a code
 *        address, without following an indirect entry.
 * \param StaticOnly
 *            TRUE to search only the function tables of loaded images; the
 *            dynamic function tables are not consulted, so no callback runs.
 */
static
PRUNTIME_FUNCTION
RtlpLookupRawFunctionEntry(
    _In_ DWORD64 ControlPc,
    _Out_ PDWORD64 ImageBase,
    _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable,
    _In_ BOOLEAN StaticOnly)
{
    PRUNTIME_FUNCTION FunctionTable, FunctionEntry;
    ULONG TableLength;
    ULONG IndexLo, IndexHi, IndexMid;

    /* Find the corresponding table */
    FunctionTable = RtlLookupFunctionTable(ControlPc, ImageBase, &TableLength);

    /* If no table is found, try dynamic function tables */
    if (!FunctionTable)
    {
        if (StaticOnly)
        {
            return NULL;
        }

        return RtlpLookupDynamicFunctionEntry(ControlPc, ImageBase, HistoryTable);
    }

    /* The table size is in bytes */
    TableLength /= sizeof(RUNTIME_FUNCTION);

    /* Use relative virtual address */
    ControlPc -= *ImageBase;

    /* Do a binary search */
    IndexLo = 0;
    IndexHi = TableLength;
    while (IndexHi > IndexLo)
    {
        IndexMid = (IndexLo + IndexHi) / 2;
        FunctionEntry = &FunctionTable[IndexMid];

        if (ControlPc < FunctionEntry->BeginAddress)
        {
            /* Continue search in lower half */
            IndexHi = IndexMid;
        }
        else if (ControlPc >= FunctionEntry->EndAddress)
        {
            /* Continue search in upper half */
            IndexLo = IndexMid + 1;
        }
        else
        {
            /* ControlPc is within limits, return entry */
            return FunctionEntry;
        }
    }

    /* Nothing found, return NULL */
    return NULL;
}

/*! RtlpGetIndirectTarget
 * \brief Returns the entry an indirect RUNTIME_FUNCTION entry points to.
 * \return NULL if the target is not a RUNTIME_FUNCTION inside the image
 *         (misaligned, or beyond SizeOfImage); entries of a dynamic function
 *         table, whose base is not an image, are not range checked.
 */
static
PRUNTIME_FUNCTION
RtlpGetIndirectTarget(
    _In_ DWORD64 ImageBase,
    _In_ PRUNTIME_FUNCTION FunctionEntry)
{
    ULONG TargetRva = FunctionEntry->UnwindData & ~RUNTIME_FUNCTION_INDIRECT;
    PIMAGE_NT_HEADERS NtHeaders;
    PVOID Base;

    if (TargetRva & (sizeof(ULONG) - 1))
    {
        return NULL;
    }

    if (RtlPcToFileHeader((PVOID)ImageBase, &Base) && ((DWORD64)Base == ImageBase))
    {
        NtHeaders = RtlImageNtHeader(Base);
        if ((NtHeaders == NULL) ||
            ((ULONG64)TargetRva + sizeof(RUNTIME_FUNCTION) >
             NtHeaders->OptionalHeader.SizeOfImage))
        {
            return NULL;
        }
    }

    return RVA(ImageBase, TargetRva);
}

/*! RtlLookupFunctionEntry
 * \brief Locates the RUNTIME_FUNCTION entry corresponding to a code address.
 * \remark An entry whose UnwindData has RUNTIME_FUNCTION_INDIRECT set
 *         describes a part of a function that lies outside the function's
 *         range (MSVC and PGO builds separate cold code from the body like
 *         this); its UnwindData is the RVA of the function's own entry, plus
 *         one. Like Windows, return the function's entry for such a part.
 * \ref https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtllookupfunctionentry
 * \todo Implement HistoryTable
 */
PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionEntry(
    IN DWORD64 ControlPc,
    OUT PDWORD64 ImageBase,
    OUT PUNWIND_HISTORY_TABLE HistoryTable)
{
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG Links;

    FunctionEntry = RtlpLookupRawFunctionEntry(ControlPc, ImageBase, HistoryTable, FALSE);

    for (Links = 0;
         (FunctionEntry != NULL) &&
         (FunctionEntry->UnwindData & RUNTIME_FUNCTION_INDIRECT);
         Links++)
    {
        /* Indirect entries point to the function's entry, not to another
           indirect entry; do not loop on broken data */
        if (Links >= 8)
        {
            return NULL;
        }

        FunctionEntry = RtlpGetIndirectTarget(*ImageBase, FunctionEntry);
    }

    return FunctionEntry;
}

static
__inline
ULONG
UnwindOpSlots(
    _In_ UNWIND_CODE UnwindCode)
{
    static const UCHAR UnwindOpExtraSlotTable[] =
    {
        0, // UWOP_PUSH_NONVOL
        1, // UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
        0, // UWOP_ALLOC_SMALL
        0, // UWOP_SET_FPREG
        1, // UWOP_SAVE_NONVOL
        2, // UWOP_SAVE_NONVOL_FAR
        1, // UWOP_EPILOG // previously UWOP_SAVE_XMM
        2, // UWOP_SPARE_CODE // previously UWOP_SAVE_XMM_FAR
        1, // UWOP_SAVE_XMM128
        2, // UWOP_SAVE_XMM128_FAR
        0, // UWOP_PUSH_MACHFRAME
        2, // UWOP_SET_FPREG_LARGE
    };

    if ((UnwindCode.UnwindOp == UWOP_ALLOC_LARGE) &&
        (UnwindCode.OpInfo != 0))
    {
        return 3;
    }
    else
    {
        return UnwindOpExtraSlotTable[UnwindCode.UnwindOp] + 1;
    }
}

static
__inline
void
SetReg(
    _Inout_ PCONTEXT Context,
    _In_ BYTE Reg,
    _In_ DWORD64 Value)
{
    ((DWORD64*)(&Context->Rax))[Reg] = Value;
}

static
__inline
void
SetRegFromStackValue(
    _Inout_ PCONTEXT Context,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
    _In_ BYTE Reg,
    _In_ PDWORD64 ValuePointer)
{
    SetReg(Context, Reg, *ValuePointer);
    if (ContextPointers != NULL)
    {
        ContextPointers->IntegerContext[Reg] = ValuePointer;
    }
}

static
__inline
DWORD64
GetReg(
    _In_ PCONTEXT Context,
    _In_ BYTE Reg)
{
    return ((DWORD64*)(&Context->Rax))[Reg];
}

static
__inline
void
PopReg(
    _Inout_ PCONTEXT Context,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
    _In_ BYTE Reg)
{
    SetRegFromStackValue(Context, ContextPointers, Reg, (PDWORD64)Context->Rsp);
    Context->Rsp += sizeof(DWORD64);
}

static
__inline
void
SetXmmReg(
    _Inout_ PCONTEXT Context,
    _In_ BYTE Reg,
    _In_ M128A Value)
{
    ((M128A*)(&Context->Xmm0))[Reg] = Value;
}

static
__inline
void
SetXmmRegFromStackValue(
    _Out_ PCONTEXT Context,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
    _In_ BYTE Reg,
    _In_ M128A *ValuePointer)
{
    SetXmmReg(Context, Reg, *ValuePointer);
    if (ContextPointers != NULL)
    {
        ContextPointers->FloatingContext[Reg] = ValuePointer;
    }
}

static
__inline
M128A
GetXmmReg(PCONTEXT Context, BYTE Reg)
{
    return ((M128A*)(&Context->Xmm0))[Reg];
}

/* Checks for a jmp that can end an epilog: a direct jmp out of the function,
   or a jmp through [rip + disp32] as calls through an import table compile to.
   CodeEntry is the entry whose range holds the code, which differs from
   FunctionEntry in a part of the function that has an indirect entry */
static
__inline
BOOLEAN
RtlpIsEpilogJump(
    _In_ BYTE *InstrPtr,
    _In_ ULONG64 ImageBase,
    _In_ PRUNTIME_FUNCTION FunctionEntry,
    _In_ PRUNTIME_FUNCTION PrimaryEntry,
    _In_ PRUNTIME_FUNCTION CodeEntry,
    _Out_ PBOOLEAN IsDirect)
{
    ULONG64 TargetRva;
    ULONG Prefix = 0;

    if ((InstrPtr[0] == 0xE9) || (InstrPtr[0] == 0xEB))
    {
        *IsDirect = TRUE;
        if (InstrPtr[0] == 0xE9)
            TargetRva = (ULONG64)InstrPtr + 5 + (LONG64)*(LONG UNALIGNED*)(InstrPtr + 1);
        else
            TargetRva = (ULONG64)InstrPtr + 2 + (LONG64)(CHAR)InstrPtr[1];
        TargetRva -= ImageBase;

        return !(((TargetRva >= FunctionEntry->BeginAddress) && (TargetRva < FunctionEntry->EndAddress)) ||
                 ((TargetRva >= PrimaryEntry->BeginAddress) && (TargetRva < PrimaryEntry->EndAddress)) ||
                 ((TargetRva >= CodeEntry->BeginAddress) && (TargetRva < CodeEntry->EndAddress)));
    }

    /* Other indirect forms are also switch table jumps of a function body */
    *IsDirect = FALSE;
    if ((InstrPtr[0] & 0xF0) == 0x40)
        Prefix = 1;

    return (InstrPtr[Prefix] == 0xFF) && (InstrPtr[Prefix + 1] == 0x25);
}

/*! RtlpTryToUnwindEpilog
 * \brief Helper function that tries to unwind epilog instructions.
 * \return TRUE if we have been in an epilog and it could be unwound.
 *         FALSE if the instructions were not allowed for an epilog.
 * \ref
 *  https://docs.microsoft.com/en-us/cpp/build/unwind-procedure
 *  https://docs.microsoft.com/en-us/cpp/build/prolog-and-epilog
 */
/*
 * Whether the instruction that ends at ControlPc is a call, so that ControlPc
 * is a return address. The common encodings only; a false match keeps the
 * caller in its body, which is what the unwind through the prolog assumes.
 */
static
BOOLEAN
RtlpFollowsCall(
    _In_ ULONG64 ControlPc,
    _In_ ULONG64 FunctionStart)
{
    const BYTE *Pc = (const BYTE*)ControlPc;
    ULONG64 Room = ControlPc - FunctionStart;
    ULONG Length, Need;
    BYTE ModRm, Mod, Rm;

    /* call rel32 */
    if ((Room >= 5) && (Pc[-5] == 0xE8))
        return TRUE;

    /* call r/m64 (FF /2), also with a REX prefix: try each instruction length
       and check that the ModRM byte implies it */
    for (Length = 2; (Length <= 7) && (Length <= Room); Length++)
    {
        if (Pc[-(LONG)Length] != 0xFF)
            continue;
        ModRm = Pc[-(LONG)Length + 1];
        if (((ModRm >> 3) & 7) != 2)
            continue;
        Mod = ModRm >> 6;
        Rm = ModRm & 7;
        if (Mod == 3)
        {
            if (Length == 2) return TRUE;
            continue;
        }

        /* Opcode, ModRM, a SIB byte for rm 4, then the displacement */
        Need = 2 + (Rm == 4);
        if (Mod == 1)
            Need += 1;
        else if ((Mod == 2) || ((Mod == 0) && (Rm == 5)))
            Need += 4;
        else if ((Mod == 0) && (Rm == 4) && ((Pc[-(LONG)Length + 2] & 7) == 5))
            Need += 4;
        if (Need == Length)
            return TRUE;
    }

    return FALSE;
}

/*
 * Whether a direct jmp stays in the frame of the function that executes it
 * rather than being a tail call: it goes into the middle of a function (GCC
 * jumps to labels inside cold parts, and from cold parts back into the body)
 * or to the start of a fragment (GCC's cold parts and chained fragments have
 * function entries without a prolog of their own). A jump to the start of a
 * function with a prolog, or to code without an entry, is taken for a tail
 * call, as Windows does. This looks up the target's function entry.
 */
static
BOOLEAN
RtlpJumpsToFragment(
    _In_ BYTE *InstrPtr)
{
    PRUNTIME_FUNCTION TargetEntry;
    PUNWIND_INFO TargetInfo;
    ULONG64 Target, TargetBase;

    if (InstrPtr[0] == 0xE9)
        Target = (ULONG64)InstrPtr + 5 + (LONG64)*(LONG UNALIGNED*)(InstrPtr + 1);
    else
        Target = (ULONG64)InstrPtr + 2 + (LONG64)(CHAR)InstrPtr[1];

    TargetEntry = RtlLookupFunctionEntry(Target, &TargetBase, NULL);
    if (TargetEntry == NULL)
        return FALSE;
    if (Target - TargetBase != TargetEntry->BeginAddress)
        return TRUE;

    /* An entry whose unwind data points to another entry describes a fragment */
    if (TargetEntry->UnwindData & RUNTIME_FUNCTION_INDIRECT)
        return TRUE;

    TargetInfo = RVA(TargetBase, TargetEntry->UnwindData);
    if (TargetInfo->Flags & UNW_FLAG_CHAININFO)
        return TRUE;
    return (TargetInfo->SizeOfProlog == 0) && (TargetInfo->CountOfCodes > 0);
}

static
__inline
BOOLEAN
RtlpTryToUnwindEpilog(
    _Inout_ PCONTEXT Context,
    _In_ ULONG64 ControlPc,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers,
    _In_ ULONG64 ImageBase,
    _In_ PRUNTIME_FUNCTION FunctionEntry,
    _In_ PRUNTIME_FUNCTION CodeEntry)
{
    CONTEXT LocalContext;
    BYTE *InstrPtr;
    DWORD Instr;
    BYTE Reg, Mod, Sib;
    ULONG64 EndAddress;
    PRUNTIME_FUNCTION PrimaryEntry;
    PUNWIND_INFO UnwindInfo;
    ULONG i, Links, Length, PushCount = 0, PopCount = 0;
    BOOLEAN HasAllocation = FALSE, StackAdjusted = FALSE, IsDirect;

    /* Count the prolog's pushes and allocations along the chained unwind info */
    PrimaryEntry = FunctionEntry;
    UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);
    for (Links = 0; ; Links++)
    {
        for (i = 0; i < UnwindInfo->CountOfCodes; i += UnwindOpSlots(UnwindInfo->UnwindCode[i]))
        {
            switch (UnwindInfo->UnwindCode[i].UnwindOp)
            {
                case UWOP_PUSH_NONVOL:
                    PushCount++;
                    break;
                case UWOP_ALLOC_LARGE:
                case UWOP_ALLOC_SMALL:
                case UWOP_SET_FPREG:
                    HasAllocation = TRUE;
                    break;
                default:
                    break;
            }
        }

        if (!(UnwindInfo->Flags & UNW_FLAG_CHAININFO))
            break;

        if (Links >= 32)
            return FALSE;

        PrimaryEntry = (PRUNTIME_FUNCTION)&UnwindInfo->UnwindCode[(UnwindInfo->CountOfCodes + 1) & ~1];
        UnwindInfo = RVA(ImageBase, PrimaryEntry->UnwindData);
    }

    /* Make a local copy of the context */
    LocalContext = *Context;

    InstrPtr = (BYTE*)ControlPc;

    /* Check if first instruction of epilog is "add rsp, x" */
    Instr = *(DWORD UNALIGNED*)InstrPtr;
    if ( (Instr & 0x00fffdff) == 0x00c48148 )
    {
        if ( (Instr & 0x0000ff00) == 0x8300 )
        {
            /* This is "add rsp, 0x??" */
            LocalContext.Rsp += Instr >> 24;
            InstrPtr += 4;
        }
        else
        {
            /* This is "add rsp, 0x???????? */
            LocalContext.Rsp += *(DWORD UNALIGNED*)(InstrPtr + 3);
            InstrPtr += 7;
        }
        StackAdjusted = TRUE;
    }
    /* Check if first instruction of epilog is "lea rsp, [reg + disp]" */
    else if ( (Instr & 0x38fffe) == 0x208d48 )
    {
        /* Get the register, REX.B extends it */
        Reg = ((Instr >> 16) & 0x7) + (Instr & 1) * 8;
        Mod = (Instr >> 22) & 0x3;
        Length = 3;

        /* A base of rsp or r12 needs a SIB byte, which must not have an index */
        if ((Reg & 7) == 4)
        {
            Sib = InstrPtr[3];
            if (((Sib >> 3) & 7) != 4)
                return FALSE;
            Reg = (Sib & 7) + (Instr & 1) * 8;
            Length = 4;
        }

        /* Without displacement, a base of rbp or r13 means rip-relative or no base */
        if ((Mod == 3) || ((Mod == 0) && ((Reg & 7) == 5)))
            return FALSE;

        LocalContext.Rsp = GetReg(&LocalContext, Reg);

        if (Mod == 1)
        {
            /* 1 byte displacement */
            LocalContext.Rsp += (LONG)(CHAR)InstrPtr[Length];
            Length += 1;
        }
        else if (Mod == 2)
        {
            /* 4 bytes displacement */
            LocalContext.Rsp += *(LONG UNALIGNED*)(InstrPtr + Length);
            Length += 4;
        }

        InstrPtr += Length;
        StackAdjusted = TRUE;
    }

    /* Loop the pops up to the ret or jmp; code can follow an epilog */
    EndAddress = CodeEntry->EndAddress + ImageBase;
    while ((DWORD64)InstrPtr < EndAddress)
    {
        Instr = *(DWORD UNALIGNED*)InstrPtr;

        /* "ret" or "rep ret" */
        if (((Instr & 0xff) == 0xc3) || ((Instr & 0xffff) == 0xc3f3))
            break;

        /* Check for a simple pop */
        if ( (Instr & 0xf8) == 0x58 )
        {
            /* Opcode pops a basic register from stack */
            Reg = Instr & 0x7;
            PopReg(&LocalContext, ContextPointers, Reg);
            InstrPtr++;
            PopCount++;
            continue;
        }

        /* Check for REX + pop */
        if ( (Instr & 0xf8fb) == 0x5841 )
        {
            /* Opcode is pop r8 .. r15 */
            Reg = ((Instr >> 8) & 0x7) + 8;
            PopReg(&LocalContext, ContextPointers, Reg);
            InstrPtr += 2;
            PopCount++;
            continue;
        }

        /* A tail call. GCC also jumps from the body to a cold part outside
           the function, with the whole frame in place */
        if (RtlpIsEpilogJump(InstrPtr, ImageBase, FunctionEntry, PrimaryEntry, CodeEntry, &IsDirect))
        {
            if (IsDirect && (PopCount == 0) && RtlpJumpsToFragment(InstrPtr))
                return FALSE;
            break;
        }

        /* Opcode not allowed for Epilog */
        return FALSE;
    }

    /* Check if we are at the ret or jmp instruction */
    if ((DWORD64)InstrPtr >= EndAddress)
    {
        /* If we went past the end of the function, something is broken! */
        ASSERT((DWORD64)InstrPtr <= EndAddress);
        return FALSE;
    }

    /* An epilog is finished from its first instruction, except when a call
       ends right before it: then ControlPc is a return address in a caller
       whose compiler did not separate the call from the epilog (GCC), and the
       caller is still in its body, with its handler */
    if (!(HasAllocation && !StackAdjusted) && (PopCount >= PushCount) &&
        RtlpFollowsCall(ControlPc, ImageBase + CodeEntry->BeginAddress))
        return FALSE;

    /* Unwind is finished, pop new Rip from Stack */
    LocalContext.Rip = *(DWORD64*)LocalContext.Rsp;
    LocalContext.Rsp += sizeof(DWORD64);

    *Context = LocalContext;
    return TRUE;
}

/*!

    \ref https://docs.microsoft.com/en-us/cpp/build/unwind-data-definitions-in-c
*/
static
ULONG64
GetEstablisherFrame(
    _In_ PCONTEXT Context,
    _In_ PUNWIND_INFO UnwindInfo,
    _In_ ULONG_PTR CodeOffset)
{
    ULONG i;

    /* Check if we have a frame register */
    if (UnwindInfo->FrameRegister == 0)
    {
        /* No frame register means we use Rsp */
        return Context->Rsp;
    }

    if ((CodeOffset >= UnwindInfo->SizeOfProlog) ||
        ((UnwindInfo->Flags & UNW_FLAG_CHAININFO) != 0))
    {
        return GetReg(Context, UnwindInfo->FrameRegister) -
               UnwindInfo->FrameOffset * 16;
    }

    /* Loop all unwind ops */
    for (i = 0;
         i < UnwindInfo->CountOfCodes;
         i += UnwindOpSlots(UnwindInfo->UnwindCode[i]))
    {
        /* Skip codes past our code offset */
        if (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset)
        {
            continue;
        }

        /* Check for SET_FPREG */
        if (UnwindInfo->UnwindCode[i].UnwindOp == UWOP_SET_FPREG)
        {
            return GetReg(Context, UnwindInfo->FrameRegister) -
                       UnwindInfo->FrameOffset * 16;
        }
    }

    return Context->Rsp;
}

PEXCEPTION_ROUTINE
NTAPI
RtlVirtualUnwind(
    _In_ ULONG HandlerType,
    _In_ ULONG64 ImageBase,
    _In_ ULONG64 ControlPc,
    _In_ PRUNTIME_FUNCTION FunctionEntry,
    _Inout_ PCONTEXT Context,
    _Outptr_ PVOID *HandlerData,
    _Out_ PULONG64 EstablisherFrame,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
{
    PUNWIND_INFO UnwindInfo;
    ULONG_PTR ControlRva, CodeOffset;
    ULONG i, Offset;
    UNWIND_CODE UnwindCode;
    BYTE Reg;
    PULONG LanguageHandler;
    BOOLEAN InProlog;
    ULONG64 FrameBase, CodeBase;
    PRUNTIME_FUNCTION CodeEntry;

    /* Get relative virtual address */
    ControlRva = ControlPc - ImageBase;

    /* Do not leave the outputs unset when there is nothing to unwind */
    *HandlerData = NULL;
    *EstablisherFrame = Context->Rsp;

    /* An indirect entry stands for the entry it points to */
    for (i = 0; FunctionEntry->UnwindData & RUNTIME_FUNCTION_INDIRECT; i++)
    {
        if (i >= 8)
        {
            return NULL;
        }

        FunctionEntry = RtlpGetIndirectTarget(ImageBase, FunctionEntry);
        if (FunctionEntry == NULL)
        {
            return NULL;
        }
    }

    /* Find the entry whose range holds the code. ControlPc can lie outside
       the function's range: in a part of the function separated from its
       body, which has an indirect entry pointing to the function's entry.
       That code is in the body (past the prolog), as on Windows. Such a part
       is in the table of an image: do not search the dynamic function
       tables, whose callbacks would run for every address outside the
       function (Windows does not run them). Code that no entry holds is
       unwound as code past the prolog, without looking at its bytes for an
       epilog. */
    if ((ControlRva >= FunctionEntry->BeginAddress) &&
        (ControlRva < FunctionEntry->EndAddress))
    {
        CodeEntry = FunctionEntry;
    }
    else
    {
        CodeEntry = RtlpLookupRawFunctionEntry(ControlPc, &CodeBase, NULL, TRUE);
        if ((CodeEntry != NULL) && (CodeBase != ImageBase))
        {
            CodeEntry = NULL;
        }
    }

    /* Get a pointer to the unwind info */
    UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);

    /* Calculate relative offset to function start; code outside the
       function's range counts as past the prolog */
    if (CodeEntry == FunctionEntry)
    {
        CodeOffset = ControlRva - FunctionEntry->BeginAddress;
    }
    else
    {
        CodeOffset = MAXULONG_PTR;
    }

    /* A function's handler does not cover its prolog; the prolog of a
       chained fragment's function has run */
    InProlog = (CodeOffset < UnwindInfo->SizeOfProlog) &&
               !(UnwindInfo->Flags & UNW_FLAG_CHAININFO);

    *EstablisherFrame = GetEstablisherFrame(Context, UnwindInfo, CodeOffset);

    /* Check if we are in the function epilog and try to finish it */
    if ((CodeEntry != NULL) &&
        (((CodeOffset >= UnwindInfo->SizeOfProlog) && (UnwindInfo->CountOfCodes > 0)) ||
         ((CodeOffset >= UnwindInfo->SizeOfProlog) && (UnwindInfo->Flags & UNW_FLAG_CHAININFO))))
    {
        if (RtlpTryToUnwindEpilog(Context, ControlPc, ContextPointers, ImageBase, FunctionEntry, CodeEntry))
        {
            /* There's no exception routine */
            return NULL;
        }
    }

    /* Registers saved with mov lie relative to the stack pointer after the
       fixed allocation; once a frame register is set, the frame register is
       what that stack pointer is derived from */
    FrameBase = *EstablisherFrame;

    /* Skip all Ops with an offset greater than the current Offset */
    i = 0;
    while ((i < UnwindInfo->CountOfCodes) &&
           (UnwindInfo->UnwindCode[i].CodeOffset > CodeOffset))
    {
        i += UnwindOpSlots(UnwindInfo->UnwindCode[i]);
    }

RepeatChainedInfo:

    /* Process the remaining unwind ops */
    while (i < UnwindInfo->CountOfCodes)
    {
        UnwindCode = UnwindInfo->UnwindCode[i];
        switch (UnwindCode.UnwindOp)
        {
            case UWOP_PUSH_NONVOL:
                Reg = UnwindCode.OpInfo;
                PopReg(Context, ContextPointers, Reg);
                i++;
                break;

            case UWOP_ALLOC_LARGE:
                if (UnwindCode.OpInfo)
                {
                    Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i+1]);
                    Context->Rsp += Offset;
                    i += 3;
                }
                else
                {
                    Offset = UnwindInfo->UnwindCode[i+1].FrameOffset;
                    Context->Rsp += Offset * 8;
                    i += 2;
                }
                break;

            case UWOP_ALLOC_SMALL:
                Context->Rsp += (UnwindCode.OpInfo + 1) * 8;
                i++;
                break;

            case UWOP_SET_FPREG:
                Reg = UnwindInfo->FrameRegister;
                Context->Rsp = GetReg(Context, Reg) - UnwindInfo->FrameOffset * 16;
                i++;
                break;

            case UWOP_SAVE_NONVOL:
                Reg = UnwindCode.OpInfo;
                Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
                /* The slot stores offset / 8; adding it to a DWORD64* scales it back to bytes.
                 * See https://github.com/dotnet/runtime/blob/421be955e4b70cddf583b10f5ad99814b713fb87/src/coreclr/unwinder/amd64/unwinder.cpp#L831 */
                SetRegFromStackValue(Context, ContextPointers, Reg, (DWORD64*)FrameBase + Offset);
                i += 2;
                break;

            case UWOP_SAVE_NONVOL_FAR:
                Reg = UnwindCode.OpInfo;
                Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i + 1]);
                SetRegFromStackValue(Context, ContextPointers, Reg, (PDWORD64)(FrameBase + Offset));
                i += 3;
                break;

            case UWOP_EPILOG:
                i += 2;
                break;

            case UWOP_SPARE_CODE:
                ASSERT(FALSE);
                i += 3;
                break;

            case UWOP_SAVE_XMM128:
                Reg = UnwindCode.OpInfo;
                Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
                /* The slot stores offset / 16; adding it to an M128A* scales it back to bytes.
                 * See https://github.com/dotnet/runtime/blob/421be955e4b70cddf583b10f5ad99814b713fb87/src/coreclr/unwinder/amd64/unwinder.cpp#L890 */
                SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A*)FrameBase + Offset);
                i += 2;
                break;

            case UWOP_SAVE_XMM128_FAR:
                Reg = UnwindCode.OpInfo;
                Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i + 1]);
                SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A*)(FrameBase + Offset));
                i += 3;
                break;

            case UWOP_PUSH_MACHFRAME:
                /* OpInfo is 1, when an error code was pushed, otherwise 0. */
                Context->Rsp += UnwindCode.OpInfo * sizeof(DWORD64);

                /* Now pop the MACHINE_FRAME (RIP/RSP only. And yes, "magic numbers", deal with it) */
                Context->Rip = *(PDWORD64)(Context->Rsp + 0x00);
                Context->Rsp = *(PDWORD64)(Context->Rsp + 0x18);
                ASSERT((i + 1) == UnwindInfo->CountOfCodes);
                goto Exit;
        }
    }

    /* Check for chained info */
    if (UnwindInfo->Flags & UNW_FLAG_CHAININFO)
    {
        /* See https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160#chained-unwind-info-structures */
        FunctionEntry = (PRUNTIME_FUNCTION)&(UnwindInfo->UnwindCode[(UnwindInfo->CountOfCodes + 1) & ~1]);
        UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);
        i = 0;
        goto RepeatChainedInfo;
    }

    /* Unwind is finished, pop new Rip from Stack */
    if (Context->Rsp != 0)
    {
        Context->Rip = *(DWORD64*)Context->Rsp;
        Context->Rsp += sizeof(DWORD64);
    }

Exit:

    /* Check if we have a handler and return it */
    if (!InProlog &&
        (UnwindInfo->Flags & (HandlerType & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))))
    {
        /* After a chain the handler follows the primary unwind info */
        LanguageHandler = ALIGN_UP_POINTER_BY(&UnwindInfo->UnwindCode[UnwindInfo->CountOfCodes], sizeof(ULONG));
        *HandlerData = (LanguageHandler + 1);
        return RVA(ImageBase, *LanguageHandler);
    }

    return NULL;
}

static __inline
BOOL
RtlpIsStackPointerValid(
    _In_ ULONG64 StackPointer,
    _In_ ULONG64 LowLimit,
    _In_ ULONG64 HighLimit)
{
    return (StackPointer >= LowLimit) &&
           (StackPointer < HighLimit) &&
           ((StackPointer & 7) == 0);
}

EXCEPTION_DISPOSITION
RtlpExecuteHandlerForUnwindHandler(
    _Inout_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PVOID EstablisherFrame,
    _Inout_ PCONTEXT ContextRecord,
    _In_ PDISPATCHER_CONTEXT DispatcherContext)
{
    /* Get a pointer to the register home space for RtlpExecuteHandlerForUnwind */
    PULONG64 HomeSpace = (PULONG64)EstablisherFrame + 6;

    /* Get the ExceptionFlags value, which was saved in the home space */
    ULONG ExceptionFlags = (ULONG)HomeSpace[0];

    /* Get the DispatcherContext, which was saved in the home space */
    PDISPATCHER_CONTEXT PreviousDispatcherContext = (PDISPATCHER_CONTEXT)HomeSpace[3];

    /* Check if the original call to RtlpExecuteHandlerForUnwind was an unwind */
    if (IS_UNWINDING(ExceptionFlags))
    {
        /* Check if the current call to this function is due to unwinding */
        if (IS_UNWINDING(ExceptionRecord->ExceptionFlags))
        {
            /* We are unwinding over the call to a termination handler. This
               could be due to an exception or longjmp. We need to make sure
               to not run this termination handler again. To achieve that,
               we copy the contents of the original dispatcher context back
               over the current dispatcher context and return
               ExceptionCollidedUnwind. RtlUnwindInternal will take the
               original context, and continue unwing there. */
            *DispatcherContext = *PreviousDispatcherContext;
            return ExceptionCollidedUnwind;
        }
    }

    // TODO: properly handle nested exceptions

    return ExceptionContinueSearch;
}


/*!
    \remark The implementation is based on the description in this blog: http://www.nynaeve.net/?p=106

        Differences to the desciption:
        - Instead of using 2 pointers to the unwind context and previous context,
          that are being swapped and the context copied, the unwind context is
          kept in the local context and copied back into the context passed in
          by the caller.

    \see http://www.nynaeve.net/?p=106
*/
BOOLEAN
NTAPI
RtlpUnwindInternal(
    _In_opt_ PVOID TargetFrame,
    _In_opt_ PVOID TargetIp,
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PVOID ReturnValue,
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _UNWIND_HISTORY_TABLE *HistoryTable,
    _In_ ULONG HandlerType)
{
    DISPATCHER_CONTEXT DispatcherContext;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    EXCEPTION_DISPOSITION Disposition;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG_PTR StackLow, StackHigh;
    ULONG64 ImageBase, EstablisherFrame;
    CONTEXT UnwindContext;

    /* Get the current stack limits */
    RtlpGetStackLimits(&StackLow, &StackHigh);

    /* If we have a target frame, then this is our high limit */
    if (TargetFrame != NULL)
    {
        StackHigh = (ULONG64)TargetFrame + 1;
    }

    /* Copy the context */
    UnwindContext = *ContextRecord;
    /* The extended state (CONTEXT_XSTATE, 0x40) stays with the context of the exception: a copy has no
       CONTEXT_EX behind it */
    UnwindContext.ContextFlags &= ~0x40;

    /* Set up the constant fields of the dispatcher context */
    DispatcherContext.ContextRecord =
        (HandlerType == UNW_FLAG_UHANDLER) ? ContextRecord : &UnwindContext;
    DispatcherContext.HistoryTable = HistoryTable;
    DispatcherContext.TargetIp = (ULONG64)TargetIp;

    /* Start looping */
    while (TRUE)
    {
        if (!RtlpIsStackPointerValid(UnwindContext.Rsp, StackLow, StackHigh))
        {
            return FALSE;
        }

        /* Lookup the FunctionEntry for the current RIP */
        FunctionEntry = RtlLookupFunctionEntry(UnwindContext.Rip, &ImageBase, NULL);
        if (FunctionEntry == NULL)
        {
            /* No function entry, so this must be a leaf function. Pop the return address from the stack.
               Note: this can happen after the first frame as the result of an exception */
            UnwindContext.Rip = *(DWORD64*)UnwindContext.Rsp;
            UnwindContext.Rsp += sizeof(DWORD64);

            if (HandlerType == UNW_FLAG_UHANDLER)
            {
                /* Copy the context back for the next iteration */
                *ContextRecord = UnwindContext;
            }
            continue;
        }

        /* Save Rip before the virtual unwind */
        DispatcherContext.ControlPc = UnwindContext.Rip;

        /* Do a virtual unwind to get the next frame */
        ExceptionRoutine = RtlVirtualUnwind(HandlerType,
                                            ImageBase,
                                            UnwindContext.Rip,
                                            FunctionEntry,
                                            &UnwindContext,
                                            &DispatcherContext.HandlerData,
                                            &EstablisherFrame,
                                            NULL);

        /* Check, if we are still within the stack boundaries */
        if ((EstablisherFrame < StackLow) ||
            (EstablisherFrame >= StackHigh) ||
            (EstablisherFrame & 7))
        {
            /// TODO: Handle DPC stack

            /* If we are handling an exception, we are done here. */
            if (HandlerType == UNW_FLAG_EHANDLER)
            {
                ExceptionRecord->ExceptionFlags |= EXCEPTION_STACK_INVALID;
                return FALSE;
            }

            __debugbreak();
            RtlRaiseStatus(STATUS_BAD_STACK);
        }

        /* Check if we have an exception routine */
        if (ExceptionRoutine != NULL)
        {
            /* Log the exception if it's enabled */
            RtlpCheckLogException(ExceptionRecord,
                                  &UnwindContext,
                                  &DispatcherContext,
                                  sizeof(DispatcherContext));

            /* Set up the variable fields of the dispatcher context */
            DispatcherContext.ImageBase = ImageBase;
            DispatcherContext.FunctionEntry = FunctionEntry;
            DispatcherContext.LanguageHandler = ExceptionRoutine;
            DispatcherContext.EstablisherFrame = EstablisherFrame;
            DispatcherContext.ScopeIndex = 0;

            /* Store the return value in the unwind context */
            UnwindContext.Rax = (ULONG64)ReturnValue;

             /* Loop all nested handlers */
            do
            {
                /* Check if this is the target frame. This is also needed
                   after a collided unwind, which continues in the frame
                   of the previous unwind. */
                if (EstablisherFrame == (ULONG64)TargetFrame)
                {
                    /* Set flag to inform the language handler */
                    ExceptionRecord->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
                }

                /* Call the language specific handler */
                Disposition = RtlpExecuteHandlerForUnwind(ExceptionRecord,
                                                          (PVOID)EstablisherFrame,
                                                          ContextRecord,
                                                          &DispatcherContext);

                /* Clear exception flags for the next iteration */
                ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND |
                                                     EXCEPTION_COLLIDED_UNWIND);

                /* Check if we do exception handling */
                if (HandlerType == UNW_FLAG_EHANDLER)
                {
                    if (Disposition == ExceptionContinueExecution)
                    {
                        /* Check if it was non-continuable */
                        if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE)
                        {
                            __debugbreak();
                            RtlRaiseStatus(EXCEPTION_NONCONTINUABLE_EXCEPTION);
                        }

                        /* Execution continues */
                        return TRUE;
                    }
                    else if (Disposition == ExceptionNestedException)
                    {
                        /// TODO
                        __debugbreak();
                    }
                }

                if (Disposition == ExceptionCollidedUnwind)
                {
                    /* We collided with another unwind, so we need to continue
                       "after" the handler, skipping the termination handler
                       that resulted in this unwind. The installed handler has
                       already copied the original dispatcher context, we now
                       need to copy back the original context. */
                    UnwindContext = *ContextRecord = *DispatcherContext.ContextRecord;

                    /* The original context was from "before" the unwind, so we
                       need to do an additional virtual unwind to restore the
                       unwind contxt. */
                    RtlVirtualUnwind(HandlerType,
                                     DispatcherContext.ImageBase,
                                     UnwindContext.Rip,
                                     DispatcherContext.FunctionEntry,
                                     &UnwindContext,
                                     &DispatcherContext.HandlerData,
                                     &EstablisherFrame,
                                     NULL);

                    /* Restore the context pointer, which the handler replaced
                       with the one of the previous unwind, and the
                       establisher frame. */
                    DispatcherContext.ContextRecord =
                        (HandlerType == UNW_FLAG_UHANDLER) ? ContextRecord : &UnwindContext;
                    EstablisherFrame = DispatcherContext.EstablisherFrame;

                    /* Set the exception flags to indicate that we collided
                       with an unwind and continue the handler loop, which
                       will run any additional handlers from the previous
                       unwind. */
                    ExceptionRecord->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
                    continue;
                }

                /* This must be ExceptionContinueSearch now */
                else if (Disposition != ExceptionContinueSearch)
                {
                    __debugbreak();
                    RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
                }
            } while (ExceptionRecord->ExceptionFlags & EXCEPTION_COLLIDED_UNWIND);
        }

        /* Check, if we have left our stack (8.) */
        if ((EstablisherFrame < StackLow) ||
            (EstablisherFrame > StackHigh) ||
            (EstablisherFrame & 7))
        {
            /// TODO: Check for DPC stack
            __debugbreak();

            if (UnwindContext.Rip == ContextRecord->Rip)
            {
                RtlRaiseStatus(STATUS_BAD_FUNCTION_TABLE);
            }
            else
            {
                ZwRaiseException(ExceptionRecord, ContextRecord, FALSE);
            }
        }

        if (EstablisherFrame == (ULONG64)TargetFrame)
        {
            break;
        }

        if (HandlerType == UNW_FLAG_UHANDLER)
        {
            /* We have successfully unwound a frame. Copy the unwind context back. */
            *ContextRecord = UnwindContext;
        }
    }

    if (ExceptionRecord->ExceptionCode != STATUS_UNWIND_CONSOLIDATE)
    {
        ContextRecord->Rip = (ULONG64)TargetIp;
    }

    /* Set the return value */
    ContextRecord->Rax = (ULONG64)ReturnValue;

    /* Restore the context */
    RtlRestoreContext(ContextRecord, ExceptionRecord);

    /* Should never get here! */
    ASSERT(FALSE);
    return FALSE;
}

VOID
NTAPI
RtlUnwindEx(
    _In_opt_ PVOID TargetFrame,
    _In_opt_ PVOID TargetIp,
    _In_opt_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PVOID ReturnValue,
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _UNWIND_HISTORY_TABLE *HistoryTable)
{
    EXCEPTION_RECORD LocalExceptionRecord;

    /* Capture the current context */
    RtlCaptureContext(ContextRecord);

    /* Check if we have an exception record */
    if (ExceptionRecord == NULL)
    {
        /* No exception record was passed, so set up a local one */
        LocalExceptionRecord.ExceptionCode = STATUS_UNWIND;
        LocalExceptionRecord.ExceptionAddress = (PVOID)ContextRecord->Rip;
        LocalExceptionRecord.ExceptionRecord = NULL;
        LocalExceptionRecord.NumberParameters = 0;
        ExceptionRecord = &LocalExceptionRecord;
    }

    /* Set unwind flags */
    ExceptionRecord->ExceptionFlags = EXCEPTION_UNWINDING;
    if (TargetFrame == NULL)
    {
        ExceptionRecord->ExceptionFlags |= EXCEPTION_EXIT_UNWIND;
    }

    /* Call the internal function */
    RtlpUnwindInternal(TargetFrame,
                       TargetIp,
                       ExceptionRecord,
                       ReturnValue,
                       ContextRecord,
                       HistoryTable,
                       UNW_FLAG_UHANDLER);
}

VOID
NTAPI
RtlUnwind(
    _In_opt_ PVOID TargetFrame,
    _In_opt_ PVOID TargetIp,
    _In_opt_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PVOID ReturnValue)
{
    CONTEXT Context;

    RtlUnwindEx(TargetFrame,
                TargetIp,
                ExceptionRecord,
                ReturnValue,
                &Context,
                NULL);
}

ULONG
NTAPI
RtlWalkFrameChain(OUT PVOID *Callers,
                  IN ULONG Count,
                  IN ULONG Flags)
{
    CONTEXT Context;
    ULONG64 ControlPc, ImageBase, EstablisherFrame;
    ULONG64 StackLow, StackHigh;
    PVOID HandlerData;
    ULONG i, FramesToSkip;
    PRUNTIME_FUNCTION FunctionEntry;
    MODE CurrentMode = RtlpGetMode();

    DPRINT("Enter RtlWalkFrameChain\n");

    /* The upper bits in Flags define how many frames to skip */
    FramesToSkip = Flags >> 8;

    /* Capture the current Context */
    RtlCaptureContext(&Context);
    ControlPc = Context.Rip;

    /* Get the stack limits */
    RtlpGetStackLimits(&StackLow, &StackHigh);

    _SEH2_TRY
    {
        /* Loop the frames */
        for (i = 0; i < FramesToSkip + Count; i++)
        {
            /* Lookup the FunctionEntry for the current ControlPc */
            FunctionEntry = RtlLookupFunctionEntry(ControlPc, &ImageBase, NULL);

            /* Is this a leaf function? */
            if (!FunctionEntry)
            {
                Context.Rip = *(DWORD64*)Context.Rsp;
                Context.Rsp += sizeof(DWORD64);
                DPRINT("leaf funtion, new Rip = %p, new Rsp = %p\n", (PVOID)Context.Rip, (PVOID)Context.Rsp);
            }
            else
            {
                RtlVirtualUnwind(UNW_FLAG_NHANDLER,
                                 ImageBase,
                                 ControlPc,
                                 FunctionEntry,
                                 &Context,
                                 &HandlerData,
                                 &EstablisherFrame,
                                 NULL);
                DPRINT("normal funtion, new Rip = %p, new Rsp = %p\n", (PVOID)Context.Rip, (PVOID)Context.Rsp);
            }

            /* Check if we are in kernel mode */
            if (CurrentMode == KernelMode)
            {
                /* Check if we left the kernel range */
                if (Context.Rip < 0xFFFF800000000000ULL)
                {
                    /* Bail out, unless user mode was requested */
                    if ((Flags & 1) == 0)
                    {
                        break;
                    }

                    /* We are in user mode now, get UM stack bounds */
                    CurrentMode = UserMode;
                    StackLow = (ULONG64)NtCurrentTeb()->NtTib.StackLimit;
                    StackHigh = (ULONG64)NtCurrentTeb()->NtTib.StackBase;
                }
            }

            /* Check (again) if we are in user mode now */
            if (CurrentMode == UserMode)
            {
                /* Check if we left the user range */
                if ((Context.Rip < 0x10000) ||
                    (Context.Rip > 0x000007FFFFFEFFFFULL))
                {
                    break;
                }
            }

            /* Check, if we have left our stack */
            if ((Context.Rsp <= StackLow) || (Context.Rsp >= StackHigh))
            {
                break;
            }

            /* Continue with new Rip */
            ControlPc = Context.Rip;

            /* Save value, if we are past the frames to skip */
            if (i >= FramesToSkip)
            {
                Callers[i - FramesToSkip] = (PVOID)ControlPc;
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("Exception while getting callers!\n");
        i = 0;
    }
    _SEH2_END;

    DPRINT("RtlWalkFrameChain returns %ld\n", i);
    return i;
}

/*! RtlGetCallersAddress
 * \ref http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/RtlGetCallersAddress.html
 */
#undef RtlGetCallersAddress
VOID
NTAPI
RtlGetCallersAddress(
    OUT PVOID *CallersAddress,
    OUT PVOID *CallersCaller )
{
    PVOID Callers[4];
    ULONG Number;

    /* Get callers:
     * RtlWalkFrameChain -> RtlGetCallersAddress -> x -> y */
    Number = RtlWalkFrameChain(Callers, 4, 0);

    *CallersAddress = (Number >= 3) ? Callers[2] : NULL;
    *CallersCaller = (Number == 4) ? Callers[3] : NULL;

    return;
}

static
VOID
RtlpCaptureNonVolatileContextPointers(
    _Out_ PKNONVOLATILE_CONTEXT_POINTERS NonvolatileContextPointers,
    _In_ ULONG64 TargetFrame)
{
    CONTEXT Context;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 ImageBase;
    PVOID HandlerData;
    ULONG64 EstablisherFrame;

    /* Zero out the nonvolatile context pointers */
    RtlZeroMemory(NonvolatileContextPointers, sizeof(*NonvolatileContextPointers));

    /* Capture the current context */
    RtlCaptureContext(&Context);

    do
    {
        /* Make sure nothing fishy is going on. Currently this is for kernel mode only. */
        ASSERT((LONG64)Context.Rip < 0);
        ASSERT((LONG64)Context.Rsp < 0);

        /* Look up the function entry */
        FunctionEntry = RtlLookupFunctionEntry(Context.Rip, &ImageBase, NULL);
        if (FunctionEntry != NULL)
        {
            /* Do a virtual unwind to the caller and capture saved non-volatiles */
            RtlVirtualUnwind(UNW_FLAG_EHANDLER,
                             ImageBase,
                             Context.Rip,
                             FunctionEntry,
                             &Context,
                             &HandlerData,
                             &EstablisherFrame,
                             NonvolatileContextPointers);

            ASSERT(EstablisherFrame != 0);
        }
        else
        {
            Context.Rip = *(PULONG64)Context.Rsp;
            Context.Rsp += 8;
        }

        /* Continue until we reach user mode */
    } while ((LONG64)Context.Rip < 0);

    /* If the caller did the right thing, we should get past the target frame */
    ASSERT(EstablisherFrame >= TargetFrame);
}

VOID
RtlGetUnwindContext(
    _Out_ PCONTEXT Context,
    _In_ DWORD64 TargetFrame)
{
    KNONVOLATILE_CONTEXT_POINTERS ContextPointers;
    ULONG ContextFlags = Context->ContextFlags & ~CONTEXT_AMD64;

    /* Capture pointers to the non-volatiles up to the target frame */
    RtlpCaptureNonVolatileContextPointers(&ContextPointers, TargetFrame);

    /* Copy the nonvolatiles from the captured locations */
    if (ContextFlags & CONTEXT_INTEGER)
    {
        Context->Rbx = *ContextPointers.Rbx;
        Context->Rsi = *ContextPointers.Rsi;
        Context->Rdi = *ContextPointers.Rdi;
        Context->R12 = *ContextPointers.R12;
        Context->R13 = *ContextPointers.R13;
        Context->R14 = *ContextPointers.R14;
        Context->R15 = *ContextPointers.R15;
    }
    if (ContextFlags & CONTEXT_FLOATING_POINT)
    {
        Context->Xmm6 = *ContextPointers.Xmm6;
        Context->Xmm7 = *ContextPointers.Xmm7;
        Context->Xmm8 = *ContextPointers.Xmm8;
        Context->Xmm9 = *ContextPointers.Xmm9;
        Context->Xmm10 = *ContextPointers.Xmm10;
        Context->Xmm11 = *ContextPointers.Xmm11;
        Context->Xmm12 = *ContextPointers.Xmm12;
        Context->Xmm13 = *ContextPointers.Xmm13;
        Context->Xmm14 = *ContextPointers.Xmm14;
        Context->Xmm15 = *ContextPointers.Xmm15;
    }
}

VOID
RtlSetUnwindContext(
    _In_ PCONTEXT Context,
    _In_ DWORD64 TargetFrame)
{
    KNONVOLATILE_CONTEXT_POINTERS ContextPointers;
    ULONG ContextFlags = Context->ContextFlags & ~CONTEXT_AMD64;

    /* Capture pointers to the non-volatiles up to the target frame */
    RtlpCaptureNonVolatileContextPointers(&ContextPointers, TargetFrame);

    /* Copy the nonvolatiles to the captured locations */
    if (ContextFlags & CONTEXT_INTEGER)
    {
        *ContextPointers.Rbx = Context->Rbx;
        *ContextPointers.Rsi = Context->Rsi;
        *ContextPointers.Rdi = Context->Rdi;
        *ContextPointers.R12 = Context->R12;
        *ContextPointers.R13 = Context->R13;
        *ContextPointers.R14 = Context->R14;
        *ContextPointers.R15 = Context->R15;
    }
    if (ContextFlags & CONTEXT_FLOATING_POINT)
    {
        *ContextPointers.Xmm6 = Context->Xmm6;
        *ContextPointers.Xmm7 = Context->Xmm7;
        *ContextPointers.Xmm8 = Context->Xmm8;
        *ContextPointers.Xmm9 = Context->Xmm9;
        *ContextPointers.Xmm10 = Context->Xmm10;
        *ContextPointers.Xmm11 = Context->Xmm11;
        *ContextPointers.Xmm12 = Context->Xmm12;
        *ContextPointers.Xmm13 = Context->Xmm13;
        *ContextPointers.Xmm14 = Context->Xmm14;
        *ContextPointers.Xmm15 = Context->Xmm15;
    }
}

VOID
RtlpRestoreContextInternal(
    _In_ PCONTEXT ContextRecord);

PVOID
RtlpCallConsolidateCallback(
    _In_ PCONTEXT ContextRecord,
    _In_ PVOID (*Callback)(PEXCEPTION_RECORD),
    _In_ PEXCEPTION_RECORD ExceptionRecord);

VOID
RtlRestoreContext(
    _In_ PCONTEXT ContextRecord,
    _In_ PEXCEPTION_RECORD ExceptionRecord)
{
    if (ExceptionRecord != NULL)
    {
        if ((ExceptionRecord->ExceptionCode == STATUS_UNWIND_CONSOLIDATE) &&
            (ExceptionRecord->NumberParameters >= 1))
        {
            PVOID (*Consolidate)(EXCEPTION_RECORD*) = (PVOID)ExceptionRecord->ExceptionInformation[0];

            /* Call the callback on a frame that unwinds to the target context,
               so that an exception or unwind started by the callback (a C++
               rethrow from a catch block) does not walk the unwound frames */
            ContextRecord->Rip = (ULONG64)RtlpCallConsolidateCallback(ContextRecord,
                                                                      Consolidate,
                                                                      ExceptionRecord);
        }
        else if ((ExceptionRecord->ExceptionCode == STATUS_LONGJUMP) &&
                 (ExceptionRecord->NumberParameters >= 1))
        {
            _JUMP_BUFFER* JumpBuffer = (_JUMP_BUFFER*)ExceptionRecord->ExceptionInformation[0];
            ContextRecord->Rbx = JumpBuffer->Rbx;
            ContextRecord->Rsp = JumpBuffer->Rsp;
            ContextRecord->Rbp = JumpBuffer->Rbp;
            ContextRecord->Rsi = JumpBuffer->Rsi;
            ContextRecord->Rdi = JumpBuffer->Rdi;
            ContextRecord->R12 = JumpBuffer->R12;
            ContextRecord->R13 = JumpBuffer->R13;
            ContextRecord->R14 = JumpBuffer->R14;
            ContextRecord->R15 = JumpBuffer->R15;
            ContextRecord->Rip = JumpBuffer->Rip;
            ContextRecord->MxCsr = JumpBuffer->MxCsr;
            ContextRecord->FltSave.MxCsr = JumpBuffer->MxCsr;
            ContextRecord->FltSave.ControlWord = JumpBuffer->FpCsr;
            ContextRecord->Xmm6 = *(M128A*)&JumpBuffer->Xmm6;
            ContextRecord->Xmm7 = *(M128A*)&JumpBuffer->Xmm7;
            ContextRecord->Xmm8 = *(M128A*)&JumpBuffer->Xmm8;
            ContextRecord->Xmm9 = *(M128A*)&JumpBuffer->Xmm9;
            ContextRecord->Xmm10 = *(M128A*)&JumpBuffer->Xmm10;
            ContextRecord->Xmm11 = *(M128A*)&JumpBuffer->Xmm11;
            ContextRecord->Xmm12 = *(M128A*)&JumpBuffer->Xmm12;
            ContextRecord->Xmm13 = *(M128A*)&JumpBuffer->Xmm13;
            ContextRecord->Xmm14 = *(M128A*)&JumpBuffer->Xmm14;
            ContextRecord->Xmm15 = *(M128A*)&JumpBuffer->Xmm15;
        }
    }

    /* A user mode context that is not a complete CONTROL, INTEGER and FLOATING_POINT one, or that carries
       extended state (the one of an exception, for instance), goes through NtContinue: it restores the
       groups the context names and no other, and loads that state too. Without CONTEXT_CONTROL it returns
       here, as RtlRestoreContext does on Windows. The common complete context stays in user mode. */
    if (RtlpGetMode() == UserMode &&
        (((ContextRecord->ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE) ||
         ((ContextRecord->ContextFlags & CONTEXT_FULL) != CONTEXT_FULL)))
    {
        ZwContinue(ContextRecord, FALSE);
        if ((ContextRecord->ContextFlags & CONTEXT_CONTROL) != CONTEXT_CONTROL)
            return;
    }

    RtlpRestoreContextInternal(ContextRecord);
}
