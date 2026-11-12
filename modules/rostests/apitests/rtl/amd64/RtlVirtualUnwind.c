/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Test for x64 RtlVirtualUnwind
 * COPYRIGHT:   Copyright 2026 Jiahe Wang <wjhwjhn@gmail.com>
 */

#include <rtltests.h>

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG          6
#define UWOP_SPARE_CODE      7
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME  10

/* OpInfo register encoding.  Matches the order of integer registers
 * starting at CONTEXT.Rax, which is what GetReg/SetReg in unwind.c index. */
enum
{
    REG_RAX = 0, REG_RCX, REG_RDX, REG_RBX,
    REG_RSP,     REG_RBP, REG_RSI, REG_RDI,
    REG_R8,      REG_R9,  REG_R10, REG_R11,
    REG_R12,     REG_R13, REG_R14, REG_R15,
};

/* UNWIND_INFO and UNWIND_CODE are not exposed by any public PSDK header
 * (they live as private definitions inside sdk/lib/rtl/amd64/unwind.c),
 * so we mirror them locally for the test. */
typedef union _TEST_UNWIND_CODE
{
    struct
    {
        UCHAR CodeOffset;
        UCHAR UnwindOp:4;
        UCHAR OpInfo:4;
    };
    USHORT FrameOffset;
} TEST_UNWIND_CODE;

typedef struct _TEST_UNWIND_INFO
{
    UCHAR Version:3;
    UCHAR Flags:5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister:4;
    UCHAR FrameOffset:4;
    TEST_UNWIND_CODE UnwindCode[32];
} TEST_UNWIND_INFO;

/* The fake image is split into 0x1000-byte regions so the unwinder sees
 * a Code range that doesn't overlap with the unwind data we author. */
typedef struct _IMAGE_STRUCT
{
    UCHAR Header[0x1000];
    UCHAR Code[0x1000];
    UCHAR Data[0x1000];
    UCHAR Unwind[0x1000];
} IMAGE_STRUCT;

#define PARENT_OFFSET  0x100  /* Offset of the parent unwind info inside Unwind[]. */

#define INIT_RAX  0xDEADBEEFDEADBEEFULL

static DECLSPEC_ALIGN(16) IMAGE_STRUCT g_Image;

/* Most tests rely on the unwinder's tail step:
 *   Context->Rip = *(DWORD64*)Context->Rsp; Context->Rsp += 8;
 * They stage the expected Rip QWORD at g_StackBuffer[Rsp/8], matching
 * the QWORD pointed to by the pre-tail-step Rsp. */
static DECLSPEC_ALIGN(16) DWORD64 g_StackBuffer[0x80];

static TEST_UNWIND_INFO *
ResetUnwindInfo(UCHAR Version, UCHAR SizeOfProlog, UCHAR CountOfCodes)
{
    TEST_UNWIND_INFO *Info = (TEST_UNWIND_INFO *)g_Image.Unwind;
    RtlZeroMemory(Info, sizeof(*Info));
    Info->Version = Version;
    Info->SizeOfProlog = SizeOfProlog;
    Info->CountOfCodes = CountOfCodes;
    return Info;
}

static VOID
SetCode(TEST_UNWIND_INFO *Info, ULONG Index,
        UCHAR CodeOffset, UCHAR UnwindOp, UCHAR OpInfo)
{
    Info->UnwindCode[Index].CodeOffset = CodeOffset;
    Info->UnwindCode[Index].UnwindOp = UnwindOp;
    Info->UnwindCode[Index].OpInfo = OpInfo;
}

static VOID
InitContext(PCONTEXT Context, ULONG_PTR Rsp)
{
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Rsp = Rsp;
    Context->Rax = INIT_RAX;
}

static ULONG_PTR
DoUnwind(PCONTEXT Context, ULONG CodeOffset,
         PKNONVOLATILE_CONTEXT_POINTERS Pointers)
{
    RUNTIME_FUNCTION Func =
    {
        FIELD_OFFSET(IMAGE_STRUCT, Code),
        FIELD_OFFSET(IMAGE_STRUCT, Data),
        FIELD_OFFSET(IMAGE_STRUCT, Unwind)
    };
    PVOID HandlerData = NULL;
    ULONG_PTR EstablisherFrame = 0;

    RtlVirtualUnwind(UNW_FLAG_NHANDLER,
                     (ULONG_PTR)&g_Image,
                     (ULONG_PTR)g_Image.Code + CodeOffset,
                     &Func,
                     Context,
                     &HandlerData,
                     &EstablisherFrame,
                     Pointers);
    return EstablisherFrame;
}

static ULONG_PTR
RunUnwind(PCONTEXT Context, ULONG_PTR Rsp, ULONG CodeOffset,
          PKNONVOLATILE_CONTEXT_POINTERS Pointers)
{
    InitContext(Context, Rsp);
    return DoUnwind(Context, CodeOffset, Pointers);
}

static VOID Test_PushNonvol(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0] = 0x1111111122222222ULL;
    g_StackBuffer[1] = 0xDEADC0DEDEADC0DEULL;

    Info = ResetUnwindInfo(1, 1, 1);
    SetCode(Info, 0, 1, UWOP_PUSH_NONVOL, REG_RBP);

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 1, NULL), Stack);
    ok_eq_hex64(Ctx.Rbp, 0x1111111122222222ULL);
    ok_eq_hex64(Ctx.Rip, 0xDEADC0DEDEADC0DEULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 16);
}

static VOID Test_AllocSmall(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[8] = 0xFEEDFACEFEEDFACEULL;

    /* sub rsp, 0x40 -> OpInfo = (0x40/8) - 1 = 7 */
    Info = ResetUnwindInfo(1, 4, 1);
    SetCode(Info, 0, 4, UWOP_ALLOC_SMALL, 7);

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 4, NULL), Stack);
    ok_eq_hex64(Ctx.Rip, 0xFEEDFACEFEEDFACEULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x40 + 8);
}

static VOID Test_AllocLargeScaled(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0x100 / 8] = 0x12345678ABCDEF00ULL;

    /* sub rsp, 0x100 with ALLOC_LARGE OpInfo=0: next slot * 8 */
    Info = ResetUnwindInfo(1, 7, 2);
    SetCode(Info, 0, 7, UWOP_ALLOC_LARGE, 0);
    Info->UnwindCode[1].FrameOffset = 0x100 / 8;

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 7, NULL), Stack);
    ok_eq_hex64(Ctx.Rip, 0x12345678ABCDEF00ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x100 + 8);
}

static VOID Test_AllocLargeUnscaled(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;
    ULONG Size = 0x300;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[Size / 8] = 0xAA55AA55AA55AA55ULL;

    /* sub rsp, Size with ALLOC_LARGE OpInfo=1: next 2 slots = full ULONG */
    Info = ResetUnwindInfo(1, 7, 3);
    SetCode(Info, 0, 7, UWOP_ALLOC_LARGE, 1);
    *(ULONG *)&Info->UnwindCode[1] = Size;

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 7, NULL), Stack);
    ok_eq_hex64(Ctx.Rip, 0xAA55AA55AA55AA55ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + Size + 8);
}

static VOID Test_SetFpReg(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR EstFrame;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;
    ULONG_PTR FrameTop = Stack + 0x100;

    /* lea rbp, [rsp + 0x20]; FrameOffset (in 16-byte units) = 2 */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0x100 / 8] = 0x9999AAAA9999AAAAULL;

    Info = ResetUnwindInfo(1, 4, 1);
    Info->FrameRegister = REG_RBP;
    Info->FrameOffset = 2;
    SetCode(Info, 0, 4, UWOP_SET_FPREG, 0);

    InitContext(&Ctx, Stack);
    Ctx.Rbp = FrameTop + 0x20;
    EstFrame = DoUnwind(&Ctx, 4, NULL);

    ok_eq_hex64(EstFrame, FrameTop);
    ok_eq_hex64(Ctx.Rip, 0x9999AAAA9999AAAAULL);
    ok_eq_hex64(Ctx.Rsp, FrameTop + 8);
}

static VOID Test_SaveNonvol(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0x80 / 8] = 0x4242424242424242ULL;
    g_StackBuffer[0]        = 0xDEADC0DEDEADC0DEULL;

    /* mov [rsp + 0x80], rsi; FrameOffset (in 8-byte units) = 0x10 */
    Info = ResetUnwindInfo(1, 8, 2);
    SetCode(Info, 0, 8, UWOP_SAVE_NONVOL, REG_RSI);
    Info->UnwindCode[1].FrameOffset = 0x10;

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 8, NULL), Stack);
    ok_eq_hex64(Ctx.Rsi, 0x4242424242424242ULL);
    ok_eq_hex64(Ctx.Rip, 0xDEADC0DEDEADC0DEULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 8);
}

static VOID Test_SaveXmm128(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;
    M128A Expected;

    Expected.Low  = 0x0011223344556677ULL;
    Expected.High = 0x8899AABBCCDDEEFFULL;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    *(M128A *)&g_StackBuffer[0x40 / 8] = Expected;

    /* movaps [rsp + 0x40], xmm7; FrameOffset (in 16-byte units) = 4 */
    Info = ResetUnwindInfo(1, 9, 2);
    SetCode(Info, 0, 9, UWOP_SAVE_XMM128, 7 /* XMM7 */);
    Info->UnwindCode[1].FrameOffset = 4;

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 9, NULL), Stack);
    ok_eq_xmm(Ctx.Xmm7, Expected);
}

static VOID Test_PushMachframe(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* MACHINE_FRAME layout: [Rip][Cs][EFlags][Rsp][Ss], OpInfo=1 means an
     * error code was pushed (one extra QWORD before the frame). */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[1] = 0xCAFEBABE00000000ULL; /* Rip */
    g_StackBuffer[4] = Stack + 0x100;         /* Rsp */

    Info = ResetUnwindInfo(1, 1, 1);
    SetCode(Info, 0, 1, UWOP_PUSH_MACHFRAME, 1);

    RunUnwind(&Ctx, Stack, 1, NULL);
    ok_eq_hex64(Ctx.Rip, 0xCAFEBABE00000000ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x100);
}

static VOID Test_TypicalProlog(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* Equivalent to:
     *      push rbp        ; CodeOffset 1
     *      push rbx        ; CodeOffset 2
     *      push rsi        ; CodeOffset 3
     *      sub  rsp, 0x40  ; CodeOffset 7  (4-byte instruction)
     */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0x40 / 8] = 0x1111111111111111ULL; /* saved RSI */
    g_StackBuffer[0x48 / 8] = 0x2222222222222222ULL; /* saved RBX */
    g_StackBuffer[0x50 / 8] = 0x3333333333333333ULL; /* saved RBP */
    g_StackBuffer[0x58 / 8] = 0x4444444444444444ULL; /* return Rip */

    Info = ResetUnwindInfo(1, 7, 4);
    SetCode(Info, 0, 7, UWOP_ALLOC_SMALL, 7);
    SetCode(Info, 1, 3, UWOP_PUSH_NONVOL, REG_RSI);
    SetCode(Info, 2, 2, UWOP_PUSH_NONVOL, REG_RBX);
    SetCode(Info, 3, 1, UWOP_PUSH_NONVOL, REG_RBP);

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 7, NULL), Stack);
    ok_eq_hex64(Ctx.Rsi, 0x1111111111111111ULL);
    ok_eq_hex64(Ctx.Rbx, 0x2222222222222222ULL);
    ok_eq_hex64(Ctx.Rbp, 0x3333333333333333ULL);
    ok_eq_hex64(Ctx.Rip, 0x4444444444444444ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x60);
    ok_eq_hex64(Ctx.Rax, INIT_RAX);
}

static VOID Test_PartialProlog(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* Same prolog but ControlPc is between push rbx and sub rsp.
     * Only push rbp / push rbx have executed, so sub rsp must NOT undo. */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0] = 0x2222222222222222ULL;
    g_StackBuffer[1] = 0x3333333333333333ULL;
    g_StackBuffer[2] = 0x4444444444444444ULL;

    Info = ResetUnwindInfo(1, 7, 4);
    SetCode(Info, 0, 7, UWOP_ALLOC_SMALL, 7);
    SetCode(Info, 1, 3, UWOP_PUSH_NONVOL, REG_RSI);
    SetCode(Info, 2, 2, UWOP_PUSH_NONVOL, REG_RBX);
    SetCode(Info, 3, 1, UWOP_PUSH_NONVOL, REG_RBP);

    ok_eq_hex64(RunUnwind(&Ctx, Stack, 2, NULL), Stack);
    ok_eq_hex64(Ctx.Rbx, 0x2222222222222222ULL);
    ok_eq_hex64(Ctx.Rbp, 0x3333333333333333ULL);
    ok_eq_hex64(Ctx.Rip, 0x4444444444444444ULL);
    ok_eq_hex64(Ctx.Rsi, 0); /* push rsi not yet executed */
    ok_eq_hex64(Ctx.Rsp, Stack + 0x18);
}

static VOID Test_ContextPointers(VOID)
{
    CONTEXT Ctx;
    KNONVOLATILE_CONTEXT_POINTERS Ptrs;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    RtlZeroMemory(&Ptrs, sizeof(Ptrs));
    g_StackBuffer[0] = 0xAABBCCDDAABBCCDDULL;

    Info = ResetUnwindInfo(1, 1, 1);
    SetCode(Info, 0, 1, UWOP_PUSH_NONVOL, REG_RBX);

    RunUnwind(&Ctx, Stack, 1, &Ptrs);
    ok_eq_pointer(Ptrs.Rbx, &g_StackBuffer[0]);
    ok_eq_hex64(Ctx.Rbx, 0xAABBCCDDAABBCCDDULL);
}

static VOID Test_ChainedInfo(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Child, *Parent;
    PRUNTIME_FUNCTION ParentFunc;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* Child runs PUSH_NONVOL(RBX), then chains to a parent that runs
     * PUSH_NONVOL(RBP).  Final tail step pops Rip. */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0] = 0xAA00AA00AA00AA00ULL; /* saved RBX */
    g_StackBuffer[1] = 0xBB00BB00BB00BB00ULL; /* saved RBP */
    g_StackBuffer[2] = 0xCC00CC00CC00CC00ULL; /* return Rip */

    Child = ResetUnwindInfo(1, 1, 1);
    Child->Flags = UNW_FLAG_CHAININFO;
    SetCode(Child, 0, 1, UWOP_PUSH_NONVOL, REG_RBX);

    /* Parent's RUNTIME_FUNCTION sits right after the rounded-up child
     * UnwindCode array, at &UnwindCode[(CountOfCodes + 1) & ~1]. */
    ParentFunc = (PRUNTIME_FUNCTION)&Child->UnwindCode[2];
    ParentFunc->BeginAddress = FIELD_OFFSET(IMAGE_STRUCT, Code);
    ParentFunc->EndAddress   = FIELD_OFFSET(IMAGE_STRUCT, Data);
    ParentFunc->UnwindData   = FIELD_OFFSET(IMAGE_STRUCT, Unwind) + PARENT_OFFSET;

    Parent = (TEST_UNWIND_INFO *)(g_Image.Unwind + PARENT_OFFSET);
    RtlZeroMemory(Parent, sizeof(*Parent));
    Parent->Version = 1;
    Parent->SizeOfProlog = 1;
    Parent->CountOfCodes = 1;
    SetCode(Parent, 0, 1, UWOP_PUSH_NONVOL, REG_RBP);

    RunUnwind(&Ctx, Stack, 1, NULL);
    ok_eq_hex64(Ctx.Rbx, 0xAA00AA00AA00AA00ULL);
    ok_eq_hex64(Ctx.Rbp, 0xBB00BB00BB00BB00ULL);
    ok_eq_hex64(Ctx.Rip, 0xCC00CC00CC00CC00ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x18);
}

static VOID Test_SaveNonvolFar(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* Expected at unscaled byte offset 8, decoy at the buggy
     * (DWORD64*)Rsp + 8 == Rsp + 64 location. */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[1] = 0xAAAAAAAABBBBBBBBULL; /* byte offset 8 */
    g_StackBuffer[8] = 0xCCCCCCCCDDDDDDDDULL; /* byte offset 64 */

    Info = ResetUnwindInfo(2, 0, 3);
    SetCode(Info, 0, 0, UWOP_SAVE_NONVOL_FAR, REG_RBX);
    *(ULONG *)&Info->UnwindCode[1] = 8;

    RunUnwind(&Ctx, Stack, 0, NULL);
    ok_eq_hex64(Ctx.Rbx, 0xAAAAAAAABBBBBBBBULL);
    ok(Ctx.Rbx != 0xCCCCCCCCDDDDDDDDULL,
       "Rbx looks scaled-by-8: %I64x\n", Ctx.Rbx);
    /* If the unwinder mis-advances i, trailing zero slots decode as
     * UWOP_PUSH_NONVOL(RAX) and shift Rsp / clobber Rax. */
    ok_eq_hex64(Ctx.Rax, INIT_RAX);
    ok_eq_hex64(Ctx.Rsp, Stack + 8);
}

static VOID Test_SaveXmm128Far(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;
    M128A Expected, Decoy;

    Expected.Low  = 0x1111111122222222ULL;
    Expected.High = 0x3333333344444444ULL;
    Decoy.Low     = 0x5555555566666666ULL;
    Decoy.High    = 0x7777777788888888ULL;

    /* Expected at unscaled byte offset 16, decoy at the buggy
     * (M128A*)Rsp + 16 == Rsp + 256 location. */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    *(M128A *)&g_StackBuffer[16 / 8]  = Expected;
    *(M128A *)&g_StackBuffer[256 / 8] = Decoy;

    Info = ResetUnwindInfo(2, 0, 3);
    SetCode(Info, 0, 0, UWOP_SAVE_XMM128_FAR, 6 /* XMM6 */);
    *(ULONG *)&Info->UnwindCode[1] = 16;

    RunUnwind(&Ctx, Stack, 0, NULL);
    ok_eq_xmm(Ctx.Xmm6, Expected);
    ok(Ctx.Xmm6.Low != Decoy.Low,
       "Xmm6 looks scaled-by-16: %I64x\n", Ctx.Xmm6.Low);
    ok_eq_hex64(Ctx.Rax, INIT_RAX);
    ok_eq_hex64(Ctx.Rsp, Stack + 8);
}

static VOID Test_Epilog(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* UWOP_EPILOG consumes 2 slots.  If the unwinder advances by only 1,
     * the trailing zero slot is misread as UWOP_PUSH_NONVOL(RAX) and the
     * subsequent PUSH_NONVOL(RDI) sees a shifted Rsp. */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0] = 0xAAAAAAAAAAAAAAAAULL;
    g_StackBuffer[1] = 0xBBBBBBBBBBBBBBBBULL;

    Info = ResetUnwindInfo(2, 0, 3);
    SetCode(Info, 0, 0, UWOP_EPILOG, 0);
    Info->UnwindCode[1].FrameOffset = 0;
    SetCode(Info, 2, 0, UWOP_PUSH_NONVOL, REG_RDI);

    RunUnwind(&Ctx, Stack, 0, NULL);
    ok_eq_hex64(Ctx.Rdi, 0xAAAAAAAAAAAAAAAAULL);
    ok_eq_hex64(Ctx.Rax, INIT_RAX);
}

static VOID Test_SpareCode(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Info;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    /* Same idea as Test_Epilog, but UWOP_SPARE_CODE consumes 3 slots.
     * The unwinder used to assert on this code in debug builds, which
     * stopped the test in the debugger; the handler below stays in case
     * an unwinder raises an exception for it. */
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0] = 0xAAAAAAAAAAAAAAAAULL;
    g_StackBuffer[1] = 0xBBBBBBBBBBBBBBBBULL;

    Info = ResetUnwindInfo(2, 0, 4);
    SetCode(Info, 0, 0, UWOP_SPARE_CODE, 0);
    Info->UnwindCode[1].FrameOffset = 0;
    Info->UnwindCode[2].FrameOffset = 0;
    SetCode(Info, 3, 0, UWOP_PUSH_NONVOL, REG_RDI);

    _SEH2_TRY
    {
        RunUnwind(&Ctx, Stack, 0, NULL);
        ok_eq_hex64(Ctx.Rdi, 0xAAAAAAAAAAAAAAAAULL);
        ok_eq_hex64(Ctx.Rax, INIT_RAX);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        skip("UWOP_SPARE_CODE triggered exception 0x%08lx\n",
             _SEH2_GetExceptionCode());
    }
    _SEH2_END;
}

/* push rbx; push rsi; sub rsp, 0x28; nops; add rsp, 0x28; pop rsi; pop rbx at 0x16 */
static const UCHAR g_EpilogFunction[] =
{
    0x53, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x48, 0x83, 0xC4, 0x28, 0x5E, 0x5B,
};

#define EPILOG_START   0x10
#define EPILOG_POP     0x14
#define EPILOG_END     0x16
#define EPILOG_HANDLER 0x0F00

static TEST_UNWIND_INFO *
SetupEpilogFunction(const UCHAR *End, ULONG EndLength, ULONG Flags)
{
    TEST_UNWIND_INFO *Info;

    RtlFillMemory(g_Image.Code, sizeof(g_Image.Code), 0xCC);
    RtlCopyMemory(g_Image.Code, g_EpilogFunction, sizeof(g_EpilogFunction));
    RtlCopyMemory(g_Image.Code + EPILOG_END, End, EndLength);

    Info = ResetUnwindInfo(1, 6, 3);
    Info->Flags = Flags;
    SetCode(Info, 0, 6, UWOP_ALLOC_SMALL, (0x28 / 8) - 1);
    SetCode(Info, 1, 2, UWOP_PUSH_NONVOL, REG_RSI);
    SetCode(Info, 2, 1, UWOP_PUSH_NONVOL, REG_RBX);
    *(ULONG *)&Info->UnwindCode[4] = FIELD_OFFSET(IMAGE_STRUCT, Code) + EPILOG_HANDLER;
    return Info;
}

static PVOID
UnwindEpilogFunction(PCONTEXT Context, ULONG_PTR Rsp, ULONG FunctionEnd,
                     ULONG UnwindOffset, ULONG CodeOffset)
{
    RUNTIME_FUNCTION Func =
    {
        FIELD_OFFSET(IMAGE_STRUCT, Code),
        FIELD_OFFSET(IMAGE_STRUCT, Code) + FunctionEnd,
        FIELD_OFFSET(IMAGE_STRUCT, Unwind) + UnwindOffset
    };
    PVOID HandlerData = NULL;
    ULONG_PTR EstablisherFrame = 0;

    InitContext(Context, Rsp);
    return RtlVirtualUnwind(UNW_FLAG_EHANDLER,
                            (ULONG_PTR)&g_Image,
                            (ULONG_PTR)g_Image.Code + CodeOffset,
                            &Func,
                            Context,
                            &HandlerData,
                            &EstablisherFrame,
                            NULL);
}

/* The body's frame: 0x28 bytes, saved RSI, saved RBX, return address */
static VOID
SetupEpilogStack(VOID)
{
    RtlZeroMemory(g_StackBuffer, sizeof(g_StackBuffer));
    g_StackBuffer[0x28 / 8] = 0x5151515151515151ULL;
    g_StackBuffer[0x30 / 8] = 0xB0B0B0B0B0B0B0B0ULL;
    g_StackBuffer[0x38 / 8] = 0x1234567812345678ULL;
    /* What an unwind through the prolog reads when the stack was already released */
    g_StackBuffer[0x60 / 8] = 0xBAD0BAD0BAD0BAD0ULL;
}

static VOID
CheckEpilogUnwind(ULONG FunctionEnd, const char *Name, BOOLEAN EndsInJump)
{
    CONTEXT Ctx;
    PVOID Handler;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;

    SetupEpilogStack();

    /* At the start of the epilog: the epilog is simulated, there is no handler */
    Handler = UnwindEpilogFunction(&Ctx, Stack, FunctionEnd, 0, EPILOG_START);
    ok(Handler == NULL, "%s: handler %p at the epilog start\n", Name, Handler);
    ok_eq_hex64(Ctx.Rsi, 0x5151515151515151ULL);
    ok_eq_hex64(Ctx.Rbx, 0xB0B0B0B0B0B0B0B0ULL);
    ok_eq_hex64(Ctx.Rip, 0x1234567812345678ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x40);

    /* After the stack release: the rest of the epilog is simulated */
    Handler = UnwindEpilogFunction(&Ctx, Stack + 0x28, FunctionEnd, 0, EPILOG_POP);
    ok(Handler == NULL, "%s: handler %p in the epilog\n", Name, Handler);
    ok_eq_hex64(Ctx.Rsi, 0x5151515151515151ULL);
    ok_eq_hex64(Ctx.Rbx, 0xB0B0B0B0B0B0B0B0ULL);
    ok_eq_hex64(Ctx.Rip, 0x1234567812345678ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x40);

    if (EndsInJump)
    {
        /* A direct jmp to code that is not a function fragment ends the
           epilog even with the frame still there, as on Windows */
        Handler = UnwindEpilogFunction(&Ctx, Stack, FunctionEnd, 0, EPILOG_END);
        ok(Handler == NULL, "%s: handler %p at the jmp\n", Name, Handler);
        ok_eq_hex64(Ctx.Rip, *(ULONG64 *)Stack);
        ok_eq_hex64(Ctx.Rsp, Stack + 8);
        return;
    }

    /* At the instruction that leaves the function */
    Handler = UnwindEpilogFunction(&Ctx, Stack + 0x38, FunctionEnd, 0, EPILOG_END);
    ok(Handler == NULL, "%s: handler %p at the end of the epilog\n", Name, Handler);
    ok_eq_hex64(Ctx.Rsi, 0);
    ok_eq_hex64(Ctx.Rip, 0x1234567812345678ULL);
    ok_eq_hex64(Ctx.Rsp, Stack + 0x40);
}

static VOID Test_EpilogRet(VOID)
{
    static const UCHAR Ret[] = { 0xC3 };
    static const UCHAR RepRet[] = { 0xF3, 0xC3 };

    SetupEpilogFunction(Ret, sizeof(Ret), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + sizeof(Ret), "ret", FALSE);

    /* More code of the function follows the epilog */
    SetupEpilogFunction(Ret, sizeof(Ret), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + 0x20, "ret, code follows", FALSE);

    SetupEpilogFunction(RepRet, sizeof(RepRet), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + sizeof(RepRet), "rep ret", FALSE);
}

static VOID Test_EpilogTailCall(VOID)
{
    CONTEXT Ctx;
    PVOID Handler;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;
    UCHAR Jmp[5] = { 0xE9 };
    static const UCHAR JmpShort[] = { 0xEB, 0x40 };
    static const UCHAR JmpRip[] = { 0xFF, 0x25, 0x00, 0x01, 0x00, 0x00 };
    static const UCHAR RexJmpRip[] = { 0x48, 0xFF, 0x25, 0x00, 0x01, 0x00, 0x00 };
    static const UCHAR JmpReg[] = { 0xFF, 0xE0 };
    static const UCHAR JmpMem[] = { 0xFF, 0x20 };

    /* jmp to a function at 0x800 */
    *(LONG *)&Jmp[1] = 0x800 - (EPILOG_END + 5);
    SetupEpilogFunction(Jmp, sizeof(Jmp), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + sizeof(Jmp), "jmp rel32", TRUE);

    SetupEpilogFunction(JmpShort, sizeof(JmpShort), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + sizeof(JmpShort), "jmp rel8", TRUE);

    SetupEpilogFunction(JmpRip, sizeof(JmpRip), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + sizeof(JmpRip), "jmp [rip+disp32]", FALSE);

    SetupEpilogFunction(RexJmpRip, sizeof(RexJmpRip), UNW_FLAG_EHANDLER);
    CheckEpilogUnwind(EPILOG_END + sizeof(RexJmpRip), "rex jmp [rip+disp32]", FALSE);

    /* A jmp back into the function is a branch in the body, not an epilog */
    *(LONG *)&Jmp[1] = 0x06 - (EPILOG_END + 5);
    SetupEpilogFunction(Jmp, sizeof(Jmp), 0);
    SetupEpilogStack();
    UnwindEpilogFunction(&Ctx, Stack + 0x28, EPILOG_END + sizeof(Jmp), 0, EPILOG_POP);
    ok_eq_hex64(Ctx.Rip, 0xBAD0BAD0BAD0BAD0ULL);

    /* jmp through a register is not an allowed epilog end */
    SetupEpilogFunction(JmpReg, sizeof(JmpReg), UNW_FLAG_EHANDLER);
    SetupEpilogStack();
    Handler = UnwindEpilogFunction(&Ctx, Stack + 0x28, EPILOG_END + sizeof(JmpReg), 0, EPILOG_POP);
    ok(Handler != NULL, "jmp reg: no handler\n");
    ok_eq_hex64(Ctx.Rip, 0xBAD0BAD0BAD0BAD0ULL);

    /* Neither is a jmp through a register's memory, the form of a switch table */
    SetupEpilogFunction(JmpMem, sizeof(JmpMem), UNW_FLAG_EHANDLER);
    SetupEpilogStack();
    Handler = UnwindEpilogFunction(&Ctx, Stack + 0x28, EPILOG_END + sizeof(JmpMem), 0, EPILOG_POP);
    ok(Handler != NULL, "jmp [reg]: no handler\n");
    ok_eq_hex64(Ctx.Rip, 0xBAD0BAD0BAD0BAD0ULL);
}

static VOID Test_EpilogChained(VOID)
{
    CONTEXT Ctx;
    TEST_UNWIND_INFO *Fragment;
    PRUNTIME_FUNCTION PrimaryFunc;
    ULONG_PTR Stack = (ULONG_PTR)g_StackBuffer;
    static const UCHAR Ret[] = { 0xC3 };
    static const UCHAR FragmentCode[] = { 0x48, 0x83, 0xC4, 0x28, 0x5E, 0x5B, 0xC3 };

    /* The primary function, and at 0x100 a fragment of it that is its epilog */
    SetupEpilogFunction(Ret, sizeof(Ret), 0);
    RtlCopyMemory(g_Image.Code + 0x100, FragmentCode, sizeof(FragmentCode));

    Fragment = (TEST_UNWIND_INFO *)(g_Image.Unwind + 0x200);
    RtlZeroMemory(Fragment, sizeof(*Fragment));
    Fragment->Version = 1;
    Fragment->Flags = UNW_FLAG_CHAININFO;
    PrimaryFunc = (PRUNTIME_FUNCTION)&Fragment->UnwindCode[0];
    PrimaryFunc->BeginAddress = FIELD_OFFSET(IMAGE_STRUCT, Code);
    PrimaryFunc->EndAddress = FIELD_OFFSET(IMAGE_STRUCT, Code) + EPILOG_END + sizeof(Ret);
    PrimaryFunc->UnwindData = FIELD_OFFSET(IMAGE_STRUCT, Unwind);

    {
        RUNTIME_FUNCTION Func =
        {
            FIELD_OFFSET(IMAGE_STRUCT, Code) + 0x100,
            FIELD_OFFSET(IMAGE_STRUCT, Code) + 0x100 + sizeof(FragmentCode),
            FIELD_OFFSET(IMAGE_STRUCT, Unwind) + 0x200
        };
        PVOID HandlerData = NULL;
        ULONG_PTR EstablisherFrame = 0;

        SetupEpilogStack();
        InitContext(&Ctx, Stack + 0x28);
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, (ULONG_PTR)&g_Image,
                         (ULONG_PTR)g_Image.Code + 0x104, &Func, &Ctx,
                         &HandlerData, &EstablisherFrame, NULL);
        ok_eq_hex64(Ctx.Rsi, 0x5151515151515151ULL);
        ok_eq_hex64(Ctx.Rbx, 0xB0B0B0B0B0B0B0B0ULL);
        ok_eq_hex64(Ctx.Rip, 0x1234567812345678ULL);
        ok_eq_hex64(Ctx.Rsp, Stack + 0x40);

        /* At the fragment's first instruction the whole frame is still there */
        InitContext(&Ctx, Stack);
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, (ULONG_PTR)&g_Image,
                         (ULONG_PTR)g_Image.Code + 0x100, &Func, &Ctx,
                         &HandlerData, &EstablisherFrame, NULL);
        ok_eq_hex64(Ctx.Rbx, 0xB0B0B0B0B0B0B0B0ULL);
        ok_eq_hex64(Ctx.Rip, 0x1234567812345678ULL);
        ok_eq_hex64(Ctx.Rsp, Stack + 0x40);
    }
}

START_TEST(RtlVirtualUnwind)
{
    RtlpInitialize();
    Test_PushNonvol();
    Test_AllocSmall();
    Test_AllocLargeScaled();
    Test_AllocLargeUnscaled();
    Test_SetFpReg();
    Test_SaveNonvol();
    Test_SaveXmm128();
    Test_PushMachframe();
    Test_TypicalProlog();
    Test_PartialProlog();
    Test_ContextPointers();
    Test_ChainedInfo();
    Test_SaveNonvolFar();
    Test_SaveXmm128Far();
    Test_Epilog();
    Test_SpareCode();
    Test_EpilogRet();
    Test_EpilogTailCall();
    Test_EpilogChained();
}
