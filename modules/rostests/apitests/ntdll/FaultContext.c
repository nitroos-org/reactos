/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Hardware faults on many threads at once: the exception record and the context are exact
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Runtimes that turn hardware faults into language exceptions (the CLR's NullReferenceException and
   DivideByZeroException, the JVM's implicit null checks) decide from the exception record and the context
   whether a fault is one of theirs: the code, the access type and address (ExceptionInformation[0] and [1]), the
   exception address and the registers at the fault. A wrong address makes the CLR raise AccessViolationException
   and the JVM report a crash. Here several threads fault in a loop, near address 0 (no allocation there), on a
   no-access page and by dividing by zero, each with known values in the nonvolatile registers. A vectored
   handler checks every record and context exactly and continues after the faulting instruction, as the runtimes
   do; the registers are checked again after the continue. Meanwhile other threads commit, touch and release
   memory (page faults at other addresses on every processor) and start threads, and one thread suspends the
   faulting threads and reads, and in the last run also writes back, their context, as a garbage collector
   does. The amd64 kernel used to read CR2 again after the page fault handler, which could wait: the access
   violation then named the address of another thread's page fault. */

ULONG_PTR __cdecl FaultContextRun(ULONG_PTR Address, ULONG_PTR Seed, ULONG_PTR Mode);
extern UCHAR FaultContextLiveStart[], FaultContextFaultIp[], FaultContextFaultResume[];
extern UCHAR FaultContextDivideIp[], FaultContextDivideResume[], FaultContextLiveEnd[];

#define RUN_MS          3000
#define MAX_FAULTERS    32
#define MAX_NOISE       16
#define MAX_REPORTS     4

#ifdef _M_AMD64
#define CTX_PC(c)       ((c)->Rip)
#else
#define CTX_PC(c)       ((c)->Eip)
#endif

#ifndef CONTEXT_EXCEPTION_REQUEST
#define CONTEXT_EXCEPTION_REQUEST 0x40000000
#endif

static PUCHAR NoAccessPage;
static volatile LONG Stop, Reports;
static volatile LONG Faults, Divides, BadRecord, BadContext, BadResume, Suspends, BadSuspend;
static HANDLE Faulters[MAX_FAULTERS];
static ULONG FaulterCount;
static CHAR ReportText[MAX_REPORTS][200];

static VOID Report(volatile LONG *Counter, PCSTR Format, ...)
{
    LONG Index;
    va_list Args;

    InterlockedIncrement(Counter);
    Index = InterlockedIncrement(&Reports) - 1;
    if (Index >= MAX_REPORTS)
        return;
    va_start(Args, Format);
    _vsnprintf(ReportText[Index], sizeof(ReportText[Index]) - 1, Format, Args);
    va_end(Args);
}

/* The registers loaded from the seed (in rdx/edx) at the fault; returns a mask of those that differ */
static ULONG CheckRegisters(PCONTEXT Context)
{
    ULONG Mask = 0;
#ifdef _M_AMD64
    ULONG64 Seed = Context->Rdx;

    if (Context->Rbx != (Seed ^ 0x1111111111111111ULL)) Mask |= 1;
    if (Context->Rbp != (Seed ^ 0x2222222222222222ULL)) Mask |= 2;
    if (Context->Rsi != (Seed ^ 0x3333333333333333ULL)) Mask |= 4;
    if (Context->Rdi != (Seed ^ 0x4444444444444444ULL)) Mask |= 8;
    if (Context->R12 != (Seed ^ 0x5555555555555555ULL)) Mask |= 16;
    if (Context->R13 != (Seed ^ 0x6666666666666666ULL)) Mask |= 32;
    if (Context->R15 != (Seed ^ 0x7777777777777777ULL)) Mask |= 64;
    if (Context->R14 != Context->Rsp) Mask |= 128;
    if (((Context->ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) && (Context->Xmm6.Low != Seed))
        Mask |= 256;
#else
    ULONG Seed = Context->Edx;

    if (Context->Ebx != (Seed ^ 0x11111111)) Mask |= 1;
    if (Context->Ebp != (Seed ^ 0x22222222)) Mask |= 2;
    if (Context->Esi != (Seed ^ 0x33333333)) Mask |= 4;
    if (Context->Edi != (Seed ^ 0x44444444)) Mask |= 8;
#endif
    return Mask;
}

static LONG CALLBACK FaultHandler(PEXCEPTION_POINTERS Pointers)
{
    PEXCEPTION_RECORD Record = Pointers->ExceptionRecord;
    PCONTEXT Context = Pointers->ContextRecord;
    ULONG_PTR Pc = CTX_PC(Context), Address, Value;
    ULONG Mask;

    if (Pc == (ULONG_PTR)FaultContextFaultIp)
    {
#ifdef _M_AMD64
        Address = Context->Rcx;
        Value = Context->Rax;
#else
        Address = Context->Ecx;
        Value = Context->Eax;
#endif
        InterlockedIncrement(&Faults);
        if ((Record->ExceptionCode != STATUS_ACCESS_VIOLATION) || (Record->ExceptionFlags != 0) ||
            (Record->ExceptionRecord != NULL) || (Record->ExceptionAddress != (PVOID)Pc) ||
            (Record->NumberParameters != 2) || (Record->ExceptionInformation[0] != 0) ||
            (Record->ExceptionInformation[1] != Address) || (Value != Address))
        {
            Report(&BadRecord, "read fault: code %lx flags %lx params %lu [0] %Ix [1] %p (expected %p) address %p pc %p",
                   Record->ExceptionCode, Record->ExceptionFlags, Record->NumberParameters,
                   Record->ExceptionInformation[0], (PVOID)Record->ExceptionInformation[1], (PVOID)Address,
                   Record->ExceptionAddress, (PVOID)Pc);
        }
        else if ((Mask = CheckRegisters(Context)) != 0)
        {
            Report(&BadContext, "read fault: registers %lx differ in the context", Mask);
        }
        CTX_PC(Context) = (ULONG_PTR)FaultContextFaultResume;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (Pc == (ULONG_PTR)FaultContextDivideIp)
    {
        InterlockedIncrement(&Divides);
        if ((Record->ExceptionCode != STATUS_INTEGER_DIVIDE_BY_ZERO) || (Record->ExceptionFlags != 0) ||
            (Record->ExceptionRecord != NULL) || (Record->ExceptionAddress != (PVOID)Pc))
        {
            Report(&BadRecord, "divide: code %lx flags %lx address %p pc %p",
                   Record->ExceptionCode, Record->ExceptionFlags, Record->ExceptionAddress, (PVOID)Pc);
        }
        else if ((Mask = CheckRegisters(Context)) != 0)
        {
            Report(&BadContext, "divide: registers %lx differ in the context", Mask);
        }
        CTX_PC(Context) = (ULONG_PTR)FaultContextDivideResume;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI FaultThread(PVOID Parameter)
{
    ULONG_PTR Id = (ULONG_PTR)Parameter, Round = 0, Seed, Mask;

    while (!Stop)
    {
        Seed = (Id << 24) ^ (Round * 0x9E3779B1u) ^ ((ULONG_PTR)GetTickCount() << 4);
        switch (Round % 4)
        {
            case 0:
            case 1:
                /* Like a field of a null object: no allocation in the first 64 KB */
                Mask = FaultContextRun(0x10 + 8 * ((Round >> 2) & 0x1ff), Seed, 0);
                break;
            case 2:
                Mask = FaultContextRun((ULONG_PTR)NoAccessPage + 16 * (Round & 0xff), Seed, 0);
                break;
            default:
                Mask = FaultContextRun(0, Seed, 1);
                break;
        }
        if (Mask)
            Report(&BadResume, "registers %Ix differ after the continue (fault kind %Iu)", Mask, Round % 4);
        Round++;
    }
    return 0;
}

static DWORD WINAPI NoiseThread(PVOID Parameter)
{
    while (!Stop)
    {
        volatile UCHAR *Memory = VirtualAlloc(NULL, 64 * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ULONG i;

        if (!Memory)
            continue;
        for (i = 0; i < 64; i++)
            Memory[i * PAGE_SIZE] = 1;
        VirtualFree((PVOID)Memory, 0, MEM_RELEASE);
    }
    return 0;
}

static DWORD WINAPI EmptyThread(PVOID Parameter)
{
    return 0;
}

static DWORD WINAPI ChurnThread(PVOID Parameter)
{
    while (!Stop)
    {
        HANDLE Thread = CreateThread(NULL, 0, EmptyThread, NULL, 0, NULL);
        if (Thread)
        {
            WaitForSingleObject(Thread, INFINITE);
            CloseHandle(Thread);
        }
    }
    return 0;
}

static DWORD WINAPI SuspendThreadProc(PVOID Parameter)
{
    BOOL WriteBack = (Parameter != NULL);
    ULONG Round = 0;
    CONTEXT Context;
    ULONG_PTR Pc;
    HANDLE Thread;

    while (!Stop)
    {
        Thread = Faulters[(Round++ * 7) % FaulterCount];
        if (SuspendThread(Thread) == (DWORD)-1)
            continue;
        RtlZeroMemory(&Context, sizeof(Context));
        Context.ContextFlags = CONTEXT_FULL | CONTEXT_EXCEPTION_REQUEST;
        if (GetThreadContext(Thread, &Context))
        {
            InterlockedIncrement(&Suspends);
            Pc = CTX_PC(&Context);
            /* Between loading the values and checking them (the faulting instructions are checked by the handler) */
            if ((Pc > (ULONG_PTR)FaultContextLiveStart) && (Pc < (ULONG_PTR)FaultContextLiveEnd) &&
                (Pc != (ULONG_PTR)FaultContextFaultIp) && (Pc != (ULONG_PTR)FaultContextDivideIp) &&
                CheckRegisters(&Context))
            {
                Report(&BadSuspend, "suspended at %p: registers %lx differ", (PVOID)Pc, CheckRegisters(&Context));
            }
            if (WriteBack)
            {
                Context.ContextFlags = CONTEXT_FULL;
                SetThreadContext(Thread, &Context);
            }
        }
        ResumeThread(Thread);
        if ((Round & 15) == 0)
            Sleep(0);
    }
    return 0;
}

static VOID RunThreads(PCSTR Name, BOOL Noise, ULONG SuspendMode)
{
    HANDLE Threads[MAX_FAULTERS + MAX_NOISE + 2];
    ULONG Count = 0, NoiseCount, i, Processors;
    SYSTEM_INFO SystemInfo;
    DWORD Wait;
    LONG Shown;

    GetSystemInfo(&SystemInfo);
    Processors = SystemInfo.dwNumberOfProcessors;
    FaulterCount = min(max(2 * Processors, 4), MAX_FAULTERS);
    NoiseCount = Noise ? min(max(Processors, 2), MAX_NOISE) : 0;
    Stop = Reports = 0;
    Faults = Divides = BadRecord = BadContext = BadResume = Suspends = BadSuspend = 0;

    for (i = 0; i < FaulterCount; i++)
    {
        Faulters[i] = Threads[Count] = CreateThread(NULL, 0, FaultThread, (PVOID)(ULONG_PTR)i, 0, NULL);
        ok(Threads[Count] != NULL, "%s: CreateThread failed: %lu\n", Name, GetLastError());
        if (!Threads[Count])
            break;
        Count++;
    }
    FaulterCount = Count;
    for (i = 0; i < NoiseCount && FaulterCount; i++)
    {
        Threads[Count] = CreateThread(NULL, 0, NoiseThread, NULL, 0, NULL);
        if (Threads[Count])
            Count++;
    }
    if (Noise && FaulterCount)
    {
        Threads[Count] = CreateThread(NULL, 0, ChurnThread, NULL, 0, NULL);
        if (Threads[Count])
            Count++;
    }
    if (SuspendMode && FaulterCount)
    {
        Threads[Count] = CreateThread(NULL, 0, SuspendThreadProc, (PVOID)(ULONG_PTR)(SuspendMode > 1), 0, NULL);
        if (Threads[Count])
            Count++;
    }

    Sleep(RUN_MS);

    /* The suspender competes for the processors with the faulting threads.
       Where every exception goes to the kernel debugger first (checked
       builds), it may not get a thread in the time above: give it more, up to
       three times as long, to check at least a few suspended threads. */
    for (i = 0; SuspendMode && (Suspends < 10) && (i < 3 * RUN_MS / 100); i++)
        Sleep(100);
    Stop = 1;
    Wait = WaitForMultipleObjects(Count, Threads, TRUE, 60000);
    ok(Wait == WAIT_OBJECT_0, "%s: the threads did not stop: %lu\n", Name, Wait);
    for (i = 0; i < Count; i++)
        CloseHandle(Threads[i]);

    Shown = min(Reports, MAX_REPORTS);
    for (i = 0; i < (ULONG)Shown; i++)
        trace("%s: %s\n", Name, ReportText[i]);
    trace("%s: %lu faulting threads, %lu noise threads, %ld read faults, %ld divides, %ld suspensions\n",
          Name, FaulterCount, NoiseCount, Faults, Divides, Suspends);
    ok(Faults > 0 && Divides > 0, "%s: no faults (%ld, %ld)\n", Name, Faults, Divides);
    ok(BadRecord == 0, "%s: %ld of %ld exception records were wrong\n", Name, BadRecord, Faults + Divides);
    ok(BadContext == 0, "%s: %ld contexts at the fault were wrong\n", Name, BadContext);
    ok(BadResume == 0, "%s: %ld continues lost registers\n", Name, BadResume);
    if (SuspendMode)
    {
        ok(Suspends > 0, "%s: no thread was suspended\n", Name);
        ok(BadSuspend == 0, "%s: %ld contexts of suspended threads were wrong\n", Name, BadSuspend);
    }
}

START_TEST(FaultContext)
{
    PVOID Handler;

    NoAccessPage = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    ok(NoAccessPage != NULL, "VirtualAlloc failed: %lu\n", GetLastError());
    if (!NoAccessPage)
        return;

    Handler = AddVectoredExceptionHandler(TRUE, FaultHandler);
    ok(Handler != NULL, "AddVectoredExceptionHandler failed\n");
    if (!Handler)
        return;

    RunThreads("faults", FALSE, 0);
    RunThreads("faults+paging", TRUE, 0);
    RunThreads("faults+paging+suspend", TRUE, 2);

    RemoveVectoredExceptionHandler(Handler);
    VirtualFree(NoAccessPage, 0, MEM_RELEASE);
}
