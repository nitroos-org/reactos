/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The floating-point state of a 32-bit process across WoW64 system calls
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#if defined(__GNUC__) && defined(_M_IX86)

/*
 * The 32-bit ABI treats every XMM register as clobbered by a call, but a thread that is
 * suspended inside a system call, or interrupted by an APC, shows its debugger and the
 * APC the registers it had at the call. The layer keeps them through a service it
 * translates and through one it answers itself, and returns a context read of a blocked
 * thread the live registers.
 *
 * xmm_call(fn, in, out, fcw_mxcsr_in, fcw_mxcsr_out, nargs, args): loads XMM0-XMM7 from
 * in[128], the x87 control word and MXCSR from fcw_mxcsr_in, calls the stdcall function fn
 * with nargs arguments, and stores XMM0-XMM7, the control word and MXCSR.
 */
__asm__(
".text\n.globl _xmm_call\n_xmm_call:\n"
"  push %ebp\n  mov %esp,%ebp\n  push %ebx\n  push %esi\n  sub $8,%esp\n"
"  mov 20(%ebp),%eax\n"
"  fldcw (%eax)\n  ldmxcsr 4(%eax)\n"
"  mov 12(%ebp),%eax\n"
"  movdqu 0(%eax),%xmm0\n  movdqu 16(%eax),%xmm1\n  movdqu 32(%eax),%xmm2\n  movdqu 48(%eax),%xmm3\n"
"  movdqu 64(%eax),%xmm4\n  movdqu 80(%eax),%xmm5\n  movdqu 96(%eax),%xmm6\n  movdqu 112(%eax),%xmm7\n"
"  mov 28(%ebp),%ecx\n  mov 32(%ebp),%esi\n"
"1:\n  test %ecx,%ecx\n  jz 2f\n  dec %ecx\n  push (%esi,%ecx,4)\n  jmp 1b\n"
"2:\n  call *8(%ebp)\n"
"  mov 16(%ebp),%ecx\n"
"  movdqu %xmm0,0(%ecx)\n  movdqu %xmm1,16(%ecx)\n  movdqu %xmm2,32(%ecx)\n  movdqu %xmm3,48(%ecx)\n"
"  movdqu %xmm4,64(%ecx)\n  movdqu %xmm5,80(%ecx)\n  movdqu %xmm6,96(%ecx)\n  movdqu %xmm7,112(%ecx)\n"
"  mov 24(%ebp),%ecx\n  fnstcw (%ecx)\n  stmxcsr 4(%ecx)\n"
"  lea -8(%ebp),%esp\n  pop %esi\n  pop %ebx\n  pop %ebp\n  ret\n");
extern ULONG xmm_call(void *fn, void *in, void *out, ULONG *ctl_in, ULONG *ctl_out, int nargs, const ULONG *args);

typedef struct { UCHAR Xmm[128]; } XMMS;

static void FillPattern(UCHAR *p, UCHAR seed)
{
    int i;
    for (i = 0; i < 128; i++) p[i] = (UCHAR)(seed + i * 7);
}

static void RestoreControl(void)
{
    ULONG d[2] = { 0x27f, 0x1f80 };
    __asm__ __volatile__("fldcw %0\n\tldmxcsr %1" : : "m"(d[0]), "m"(d[1]));
}

static void TestPreserved(PCSTR Name, void *Fn, int Count, const ULONG *Args)
{
    UCHAR In[128] __attribute__((aligned(16))), Out[128] __attribute__((aligned(16)));
    ULONG ControlIn[2] = { 0x23f, 0x1fa0 }, ControlOut[2] = { 0, 0 };
    int Try, Reg;

    for (Try = 0; Try < 3; Try++)
    {
        FillPattern(In, (UCHAR)(0x11 * (Try + 1)));
        memset(Out, 0, sizeof(Out));
        xmm_call(Fn, In, Out, ControlIn, ControlOut, Count, Args);
        for (Reg = 0; Reg < 8; Reg++)
            ok(memcmp(In + Reg * 16, Out + Reg * 16, 16) == 0, "%s: XMM%d changed (try %d)\n", Name, Reg, Try);
        ok((ControlOut[0] & 0xff3f) == (0x23f & 0xff3f), "%s: x87 control word %04lx\n", Name, ControlOut[0]);
        ok((ControlOut[1] & 0xffff) == 0x1fa0, "%s: MXCSR %08lx\n", Name, ControlOut[1]);
    }
    RestoreControl();
}

static HANDLE g_Event, g_Ready;
static volatile LONG g_Done;
static UCHAR g_In[128] __attribute__((aligned(16))), g_Out[128] __attribute__((aligned(16)));
static void *g_Fn;
static int g_Count;
static ULONG g_Args[6];

static DWORD WINAPI BlockedThread(LPVOID Param)
{
    ULONG Control[2] = { 0x27f, 0x1f80 }, ControlOut[2];
    UNREFERENCED_PARAMETER(Param);
    SetEvent(g_Ready);
    xmm_call(g_Fn, g_In, g_Out, Control, ControlOut, g_Count, g_Args);
    g_Done = 1;
    return 0;
}

static void TestBlocked(PCSTR Name, void *Fn, int Count, const ULONG *Args)
{
    UCHAR Pattern[128], Pattern2[128];
    CONTEXT Context;
    HANDLE Thread;
    int i;

    FillPattern(g_In, 0x31);
    memcpy(Pattern, g_In, 128);
    FillPattern(Pattern2, 0x77);
    memset(g_Out, 0, sizeof(g_Out));
    g_Done = 0;
    g_Fn = Fn;
    g_Count = Count;
    memcpy(g_Args, Args, sizeof(ULONG) * Count);
    ResetEvent(g_Event);
    ResetEvent(g_Ready);
    Thread = CreateThread(NULL, 0, BlockedThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread) return;
    WaitForSingleObject(g_Ready, 5000);
    Sleep(300);
    ok(g_Done == 0, "%s: the thread did not block\n", Name);
    SuspendThread(Thread);

    memset(&Context, 0, sizeof(Context));
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS;
    ok(GetThreadContext(Thread, &Context), "%s: GetThreadContext failed: %lu\n", Name, GetLastError());
    ok(memcmp(Context.ExtendedRegisters + 160, Pattern, 128) == 0, "%s: the XMM registers of the blocked thread are not its own\n", Name);

    for (i = 0; i < 128; i++) Context.ExtendedRegisters[160 + i] = Pattern2[i];
    ok(SetThreadContext(Thread, &Context), "%s: SetThreadContext failed: %lu\n", Name, GetLastError());
    memset(&Context, 0, sizeof(Context));
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_EXTENDED_REGISTERS;
    GetThreadContext(Thread, &Context);
    ok(memcmp(Context.ExtendedRegisters + 160, Pattern2, 128) == 0, "%s: the XMM registers set are not read back\n", Name);

    ResumeThread(Thread);
    SetEvent(g_Event);
    WaitForSingleObject(Thread, 10000);
    ok(g_Done == 1, "%s: the thread did not finish\n", Name);
    ok(memcmp(g_Out, Pattern2, 128) == 0, "%s: the XMM registers set are not seen after the service returned\n", Name);
    CloseHandle(Thread);
}

static volatile LONG g_ApcRan;
static VOID CALLBACK ApcRoutine(ULONG_PTR Param)
{
    UNREFERENCED_PARAMETER(Param);
    g_ApcRan++;
}

static DWORD WINAPI ApcThread(LPVOID Param)
{
    ULONG Control[2] = { 0x27f, 0x1f80 }, ControlOut[2];
    ULONG Args[3];
    UNREFERENCED_PARAMETER(Param);
    Args[0] = (ULONG)(ULONG_PTR)g_Event;
    Args[1] = TRUE;     /* alertable */
    Args[2] = 0;        /* infinite */
    SetEvent(g_Ready);
    xmm_call(g_Fn, g_In, g_Out, Control, ControlOut, 3, Args);
    g_Done = 1;
    return 0;
}

static void TestApc(void *Wait)
{
    UCHAR Pattern[128];
    HANDLE Thread;

    FillPattern(g_In, 0x55);
    memcpy(Pattern, g_In, 128);
    memset(g_Out, 0, sizeof(g_Out));
    g_Fn = Wait;
    g_Done = 0;
    g_ApcRan = 0;
    ResetEvent(g_Event);
    ResetEvent(g_Ready);
    Thread = CreateThread(NULL, 0, ApcThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread) return;
    WaitForSingleObject(g_Ready, 5000);
    Sleep(200);
    QueueUserAPC(ApcRoutine, Thread, 0);
    Sleep(200);
    ok(g_ApcRan == 1, "the APC ran %ld times\n", g_ApcRan);
    SetEvent(g_Event);
    WaitForSingleObject(Thread, 10000);
    ok(g_Done == 1, "the thread did not finish\n");
    ok(memcmp(g_Out, Pattern, 128) == 0, "the XMM registers changed across a service interrupted by a user APC\n");
    CloseHandle(Thread);
}

#endif /* __GNUC__ && _M_IX86 */

START_TEST(Wow64FloatState)
{
#if defined(__GNUC__) && defined(_M_IX86)
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    NTSTATUS (NTAPI *pNtQuerySystemTime)(PLARGE_INTEGER) = (PVOID)GetProcAddress(Ntdll, "NtQuerySystemTime");
    NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER) = (PVOID)GetProcAddress(Ntdll, "NtWaitForSingleObject");
    NTSTATUS (NTAPI *pNtWaitForMultipleObjects)(ULONG, const HANDLE *, ULONG, BOOLEAN, PLARGE_INTEGER) =
        (PVOID)GetProcAddress(Ntdll, "NtWaitForMultipleObjects");
    NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG) =
        (PVOID)GetProcAddress(Ntdll, "NtQueryInformationProcess");
    BOOL (WINAPI *pIsWow64Process)(HANDLE, PBOOL) = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    HANDLE Signaled;
    LARGE_INTEGER Time, Zero = {{0, 0}};
    ULONG Args[5];
    HANDLE Handles[1];
    UCHAR Buffer[64];
    BOOL Wow64 = FALSE;

    if (!pIsWow64Process || !pIsWow64Process(GetCurrentProcess(), &Wow64) || !Wow64)
    {
        skip("Not a WoW64 process\n");
        return;
    }
    if (!pNtQuerySystemTime || !pNtWaitForSingleObject || !pNtWaitForMultipleObjects || !pNtQueryInformationProcess)
    {
        skip("Missing ntdll exports\n");
        return;
    }

    g_Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    Signaled = CreateEventW(NULL, TRUE, TRUE, NULL);

    /* a translated service, a service the layer answers itself, and one with a pointer to translate */
    Args[0] = (ULONG)(ULONG_PTR)&Time;
    TestPreserved("NtQuerySystemTime", pNtQuerySystemTime, 1, Args);
    Args[0] = (ULONG)(ULONG_PTR)Signaled; Args[1] = FALSE; Args[2] = (ULONG)(ULONG_PTR)&Zero;
    TestPreserved("NtWaitForSingleObject", pNtWaitForSingleObject, 3, Args);
    Args[0] = (ULONG)(ULONG_PTR)GetCurrentProcess(); Args[1] = 0; Args[2] = (ULONG)(ULONG_PTR)Buffer; Args[3] = 24; Args[4] = 0;
    TestPreserved("NtQueryInformationProcess", pNtQueryInformationProcess, 5, Args);

    /* a thread inside a service, plain and not */
    Args[0] = (ULONG)(ULONG_PTR)g_Event; Args[1] = FALSE; Args[2] = 0;
    TestBlocked("NtWaitForSingleObject (blocked)", pNtWaitForSingleObject, 3, Args);
    Handles[0] = g_Event;
    Args[0] = 1; Args[1] = (ULONG)(ULONG_PTR)Handles; Args[2] = 1 /* WaitAny */; Args[3] = FALSE; Args[4] = 0;
    TestBlocked("NtWaitForMultipleObjects (blocked)", pNtWaitForMultipleObjects, 5, Args);

    TestApc(pNtWaitForSingleObject);

    CloseHandle(Signaled);
    CloseHandle(g_Ready);
    CloseHandle(g_Event);
#else
    skip("The test is for 32-bit code built with GCC\n");
#endif
}
