/* SPDX-License-Identifier: GPL-2.0-or-later
 * The 32-bit context of a WoW64 thread as a debugger reads it.
 * 64-bit: the main thread of a suspended WoW64 child has its start context before it
 * runs (RtlUserThreadStart-style: the image entry in EAX, the PEB32 in EBX, the top of
 * the 32-bit stack), which can be changed, and keeps a readable context while the
 * native loader initializes the process.
 * 32-bit under WoW64: a thread running 64-bit code it entered with a far transfer has a
 * readable context (exception active), and that code finds the TEB in R12, the CPU area
 * in R13 and the native stack in R14.
 * The expected values are what Windows 10 reports. */
#include "precomp.h"
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <reactos/wow64.h>

#ifndef CONTEXT_EXCEPTION_REQUEST
#define CONTEXT_EXCEPTION_ACTIVE    0x08000000
#define CONTEXT_SERVICE_ACTIVE      0x10000000
#define CONTEXT_EXCEPTION_REQUEST   0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000
#endif

#ifdef _WIN64
static void TestSuspendedMain(void)
{
    char Path[MAX_PATH], Command[] = "cmd.exe /c exit 7";
    STARTUPINFOA Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Child;
    THREAD_BASIC_INFORMATION Basic;
    WOW64_CONTEXT Context;
    ULONG_PTR Peb32 = 0;
    ULONG ImageBase = 0, HeaderOffset = 0, EntryRva = 0, Samples = 0, Retries = 0, Failures = 0, i;
    ULONG_PTR NativeStackBase = 0, CpuArea = 0;
    TEB32 Teb32;
    SIZE_T Read;
    DWORD ExitCode = 0, Error;
    BOOL Ok;

    if (!GetSystemWow64DirectoryA(Path, sizeof(Path) - 16))
    {
        skip("no SysWOW64\n");
        return;
    }
    strcat(Path, "\\cmd.exe");
    if (!CreateProcessA(Path, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Child))
    {
        skip("cannot start %s: %lu\n", Path, GetLastError());
        return;
    }
    if (!NT_SUCCESS(NtQueryInformationProcess(Child.hProcess, ProcessWow64Information, &Peb32, sizeof(Peb32), NULL)) ||
        !Peb32)
    {
        skip("%s is not a WoW64 child\n", Path);
        TerminateProcess(Child.hProcess, 0);
        goto Done;
    }
    ReadProcessMemory(Child.hProcess, (PUCHAR)Peb32 + 8, &ImageBase, sizeof(ImageBase), &Read);
    ReadProcessMemory(Child.hProcess, (PUCHAR)(ULONG_PTR)ImageBase + 0x3c, &HeaderOffset, sizeof(HeaderOffset), &Read);
    ReadProcessMemory(Child.hProcess, (PUCHAR)(ULONG_PTR)ImageBase + HeaderOffset + 0x28, &EntryRva, sizeof(EntryRva), &Read);

    /* The start context, before the thread ever ran */
    memset(&Context, 0x55, sizeof(Context));
    Context.ContextFlags = WOW64_CONTEXT_ALL;
    Ok = Wow64GetThreadContext(Child.hThread, &Context);
    ok(Ok, "Wow64GetThreadContext on the suspended main thread: %lu\n", GetLastError());
    ok(Context.ContextFlags == WOW64_CONTEXT_ALL, "flags %#lx\n", Context.ContextFlags);
    ok(Context.Eax == ImageBase + EntryRva, "eax %08lx, entry %08lx\n", Context.Eax, ImageBase + EntryRva);
    ok(Context.Ebx == (ULONG)Peb32, "ebx %08lx, PEB32 %08lx\n", Context.Ebx, (ULONG)Peb32);
    ok(!Context.Ecx && !Context.Edx && !Context.Esi && !Context.Edi && !Context.Ebp,
       "ecx %08lx edx %08lx esi %08lx edi %08lx ebp %08lx\n",
       Context.Ecx, Context.Edx, Context.Esi, Context.Edi, Context.Ebp);
    ok((Context.EFlags & ~2) == 0x200, "eflags %08lx\n", Context.EFlags);
    ok(Context.SegCs == 0x23 && Context.SegSs == 0x2b && Context.SegDs == 0x2b && Context.SegEs == 0x2b &&
       Context.SegFs == 0x53 && Context.SegGs == 0x2b, "cs %04lx ss %04lx ds %04lx es %04lx fs %04lx gs %04lx\n",
       Context.SegCs, Context.SegSs, Context.SegDs, Context.SegEs, Context.SegFs, Context.SegGs);
    ok((WORD)Context.FloatSave.ControlWord == 0x27f, "control word %08lx\n", Context.FloatSave.ControlWord);
    ok(*(WORD *)Context.ExtendedRegisters == 0x27f, "SSE control word %04x\n", *(WORD *)Context.ExtendedRegisters);
    ok(*(DWORD *)(Context.ExtendedRegisters + 24) == 0x1f80, "mxcsr %08lx\n", *(DWORD *)(Context.ExtendedRegisters + 24));

    /* Its stack is the guest stack the TEB32 names; the CPU area tops the native stack */
    if (NT_SUCCESS(NtQueryInformationThread(Child.hThread, ThreadBasicInformation, &Basic, sizeof(Basic), NULL)))
    {
        memset(&Teb32, 0, sizeof(Teb32));
        ReadProcessMemory(Child.hProcess, WOW64_TEB32(Basic.TebBaseAddress), &Teb32, sizeof(Teb32), &Read);
        ok(Teb32.NtTib.StackBase && ((Context.Esp + 0xfff) & ~0xfff) == Teb32.NtTib.StackBase,
           "esp %08lx, guest stack base %08lx\n", Context.Esp, Teb32.NtTib.StackBase);
        ReadProcessMemory(Child.hProcess, &((PTEB)Basic.TebBaseAddress)->NtTib.StackBase, &NativeStackBase,
                          sizeof(NativeStackBase), &Read);
        ReadProcessMemory(Child.hProcess, &((PTEB)Basic.TebBaseAddress)->TlsSlots[WOW64_TLS_CPU], &CpuArea,
                          sizeof(CpuArea), &Read);
        ok(CpuArea && CpuArea == NativeStackBase, "CPU area %p, native stack base %p\n",
           (PVOID)CpuArea, (PVOID)NativeStackBase);
    }

    /* A change shows in the next read */
    Context.Ecx = 0x12345678;
    ok(Wow64SetThreadContext(Child.hThread, &Context), "Wow64SetThreadContext: %lu\n", GetLastError());
    memset(&Context, 0x55, sizeof(Context));
    Context.ContextFlags = WOW64_CONTEXT_ALL;
    ok(Wow64GetThreadContext(Child.hThread, &Context), "Wow64GetThreadContext: %lu\n", GetLastError());
    ok(Context.Ecx == 0x12345678, "ecx %08lx\n", Context.Ecx);
    Context.Ecx = 0;
    ok(Wow64SetThreadContext(Child.hThread, &Context), "Wow64SetThreadContext: %lu\n", GetLastError());

    /* While the process initializes, in either mode, the context stays readable. A sample
     * taken during a mode transition asks the caller to retry. */
    for (i = 0; i < 2000 && WaitForSingleObject(Child.hProcess, 0) == WAIT_TIMEOUT; ++i)
    {
        ResumeThread(Child.hThread);
        if (i & 1) Sleep(0);
        SuspendThread(Child.hThread);
        memset(&Context, 0x55, sizeof(Context));
        Context.ContextFlags = WOW64_CONTEXT_ALL | CONTEXT_EXCEPTION_REQUEST;
        if (Wow64GetThreadContext(Child.hThread, &Context))
        {
            ++Samples;
            ok(Context.SegCs == 0x23 && Context.SegDs == 0x2b && Context.SegGs == 0x2b,
               "sample %lu: cs %04lx ds %04lx gs %04lx\n", i, Context.SegCs, Context.SegDs, Context.SegGs);
            ok(Context.ContextFlags & CONTEXT_EXCEPTION_REPORTING, "sample %lu: flags %#lx\n", i, Context.ContextFlags);
            continue;
        }
        Error = GetLastError();
        if (Error == ERROR_RETRY) ++Retries;
        /* A thread that is ending (STATUS_THREAD_IS_TERMINATING) */
        else if (Error != ERROR_ACCESS_DENIED && ++Failures <= 5)
            ok(0, "sample %lu: Wow64GetThreadContext failed: %lu\n", i, Error);
    }
    ok(Samples > 0, "no context read while the child started (retries %lu)\n", Retries);
    trace("%lu samples, %lu retries, %lu failures\n", Samples, Retries, Failures);

    /* The staged start runs the image */
    ResumeThread(Child.hThread);
    ok(WaitForSingleObject(Child.hProcess, 60000) == WAIT_OBJECT_0, "the child did not end\n");
    GetExitCodeProcess(Child.hProcess, &ExitCode);
    ok(ExitCode == 7, "exit code %lu\n", ExitCode);
Done:
    CloseHandle(Child.hThread);
    CloseHandle(Child.hProcess);
}
#else
/* A far call into 64-bit code at Code + sizeof(FarCall) */
static const BYTE FarCall[] =
{
    0x58,                         /* pop eax */
    0x0e,                         /* push cs */
    0x50,                         /* push eax */
    0x6a, 0x33,                   /* push 0x33 */
    0xe8, 0, 0, 0, 0,             /* call 1f */
    0x83, 0x04, 0x24, 0x05,       /* 1: add dword ptr [esp], 5 */
    0xcb,                         /* retf */
};
/* mov rax, Registers; mov [rax], r12; mov [rax + 8], r13; mov [rax + 16], r14;
 * 1: cmp dword ptr [rax + 24], 0; jne 1b; retf */
static BYTE Body64[] =
{
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
    0x4c, 0x89, 0x20,
    0x4c, 0x89, 0x68, 0x08,
    0x4c, 0x89, 0x70, 0x10,
    0x83, 0x78, 0x18, 0x00,
    0x75, 0xfa,
    0xcb,
};
static volatile ULONG64 Registers[4];
static BYTE *Code;

static DWORD WINAPI Spin64(PVOID Parameter)
{
    ((void (*)(void))Code)();
    return 0;
}

static void TestFarTransfer(void)
{
    PUCHAR Teb64 = (PUCHAR)NtCurrentTeb() - 0x2000;
    ULONG64 StackBase, StackLimit, CpuArea;
    CONTEXT Context;
    HANDLE Thread;
    BOOL IsWow64 = FALSE;
    ULONG i;

    if (!IsWow64Process(GetCurrentProcess(), &IsWow64) || !IsWow64)
    {
        skip("not running under WoW64\n");
        return;
    }
    Code = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!Code)
    {
        skip("no code page\n");
        return;
    }
    *(ULONG64 *)(Body64 + 2) = (ULONG_PTR)Registers;
    memcpy(Code, FarCall, sizeof(FarCall));
    memcpy(Code + sizeof(FarCall), Body64, sizeof(Body64));

    /* The registers 64-bit code finds */
    Registers[3] = 0;
    ((void (*)(void))Code)();
    StackBase = *(ULONG64 *)(Teb64 + 0x08);
    StackLimit = *(ULONG64 *)(Teb64 + 0x10);
    /* The 64-bit TEB's TlsSlots are at 0x1480 */
    CpuArea = *(ULONG64 *)(Teb64 + 0x1480 + WOW64_TLS_CPU * sizeof(ULONG64));
    ok(Registers[0] == (ULONG_PTR)Teb64, "r12 %08lx%08lx, TEB %p\n",
       (ULONG)(Registers[0] >> 32), (ULONG)Registers[0], Teb64);
    ok(Registers[1] >= CpuArea && Registers[1] <= (CpuArea | 0xfff), "r13 %08lx%08lx, CPU area %08lx\n",
       (ULONG)(Registers[1] >> 32), (ULONG)Registers[1], (ULONG)CpuArea);
    ok(Registers[2] >= StackLimit && Registers[2] <= StackBase, "r14 %08lx%08lx, native stack %08lx-%08lx\n",
       (ULONG)(Registers[2] >> 32), (ULONG)Registers[2], (ULONG)StackLimit, (ULONG)StackBase);

    /* A thread that stays in 64-bit code */
    Registers[0] = 0;
    Registers[3] = 1;
    Thread = CreateThread(NULL, 0, Spin64, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread: %lu\n", GetLastError());
    if (!Thread) return;
    for (i = 0; i < 500 && !Registers[0]; ++i) Sleep(10);
    ok(Registers[0] != 0, "the thread did not reach 64-bit code\n");
    for (i = 0; i < 3; ++i)
    {
        SuspendThread(Thread);
        memset(&Context, 0x55, sizeof(Context));
        Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_EXCEPTION_REQUEST;
        ok(GetThreadContext(Thread, &Context), "GetThreadContext in 64-bit code: %lu\n", GetLastError());
        ok(Context.ContextFlags == (CONTEXT_CONTROL | CONTEXT_EXCEPTION_REQUEST | CONTEXT_EXCEPTION_REPORTING |
                                    CONTEXT_EXCEPTION_ACTIVE), "flags %#lx\n", Context.ContextFlags);
        ok(Context.SegCs == 0x23, "cs %04lx\n", Context.SegCs);
        ResumeThread(Thread);
        Sleep(10);
    }
    Registers[3] = 0;
    ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "the thread did not end\n");
    CloseHandle(Thread);
}
#endif

START_TEST(Wow64StartContext)
{
#ifdef _WIN64
    TestSuspendedMain();
#else
    TestFarTransfer();
#endif
}
