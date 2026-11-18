/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Read the context, floating point registers included, of a thread that is in the GDI system calls
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#if defined(_M_AMD64) && defined(__GNUC__)

/*
 * A crash handler, a debugger and a runtime that preempts its threads read the context of a thread that is running,
 * including xmm6 to xmm15, which a system call saves for the caller. The kernel finds where it saved them by unwinding
 * the kernel stack of the thread. The GDI system calls NtGdiRectVisible, NtGdiTransformPoints, NtGdiGetBoundsRect,
 * NtGdiSetBoundsRect, NtGdiSetDIBitsToDeviceInternal and NtGdiStretchDIBitsInternal had a frame register that is set
 * before the rest of the frame is allocated and saved xmm registers relative to the stack pointer after it; the
 * unwinder takes the frame register as the base of the saved xmm registers (as Windows does) and read them from an
 * address 8 bytes off 16 byte alignment: a general protection fault in the kernel (bugcheck 0x1E, exception code
 * 0xC0000001) for a thread that was in one of them when it was stopped. win32k is now built so that it saves no xmm
 * register in such a frame (ros_no_nonvolatile_xmm).
 *
 * The worker puts a pattern in xmm6 to xmm13 and calls those system calls in a loop; the xmm registers are callee saved,
 * so the pattern is still the worker's value wherever it is stopped. Any context that is read from it must carry the
 * pattern.
 */

#define ROUNDS      3000
#define NUM_XMM     8

static volatile LONG g_Stop;
static volatile LONG g_Calls;

static const ULONG64 g_Pattern[NUM_XMM][2] =
{
    { 0x1111111111111111ULL, 0xA1A1A1A1A1A1A1A1ULL },
    { 0x2222222222222222ULL, 0xA2A2A2A2A2A2A2A2ULL },
    { 0x3333333333333333ULL, 0xA3A3A3A3A3A3A3A3ULL },
    { 0x4444444444444444ULL, 0xA4A4A4A4A4A4A4A4ULL },
    { 0x5555555555555555ULL, 0xA5A5A5A5A5A5A5A5ULL },
    { 0x6666666666666666ULL, 0xA6A6A6A6A6A6A6A6ULL },
    { 0x7777777777777777ULL, 0xA7A7A7A7A7A7A7A7ULL },
    { 0x8888888888888888ULL, 0xA8A8A8A8A8A8A8A8ULL },
};

static
DWORD
WINAPI
GdiWorker(
    _In_ PVOID Param)
{
    HDC hdcScreen, hdc;
    HBITMAP hbm;
    RECT rc = { 0, 0, 10, 10 };
    POINT pt[4] = { { 1, 1 }, { 5, 5 }, { 9, 9 }, { 3, 7 } };
    ULONG Bits[8 * 8] = { 0 };
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), 8, -8, 1, 32, BI_RGB } };

    hdcScreen = GetDC(NULL);
    hdc = CreateCompatibleDC(hdcScreen);
    hbm = CreateCompatibleBitmap(hdcScreen, 64, 64);
    if (hdc && hbm)
    {
        SelectObject(hdc, hbm);

        __asm__ volatile(
            "movups   (%0), %%xmm6\n\t"
            "movups 16(%0), %%xmm7\n\t"
            "movups 32(%0), %%xmm8\n\t"
            "movups 48(%0), %%xmm9\n\t"
            "movups 64(%0), %%xmm10\n\t"
            "movups 80(%0), %%xmm11\n\t"
            "movups 96(%0), %%xmm12\n\t"
            "movups 112(%0), %%xmm13\n\t"
            :
            : "r"(g_Pattern)
            : "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13");

        while (!g_Stop)
        {
            RectVisible(hdc, &rc);
            GetBoundsRect(hdc, &rc, 0);
            SetBoundsRect(hdc, NULL, DCB_RESET);
            LPtoDP(hdc, pt, 4);
            SetDIBitsToDevice(hdc, 0, 0, 8, 8, 0, 0, 0, 8, Bits, &bmi, DIB_RGB_COLORS);
            StretchDIBits(hdc, 0, 0, 16, 16, 0, 0, 8, 8, Bits, &bmi, DIB_RGB_COLORS, SRCCOPY);
            InterlockedIncrement(&g_Calls);
        }
    }

    if (hbm) DeleteObject(hbm);
    if (hdc) DeleteDC(hdc);
    ReleaseDC(NULL, hdcScreen);
    return 0;
}

/* The except blocks of the same system calls: a user pointer that ProbeForRead/ProbeForWrite rejects raises in the
   kernel, the system call catches it and fails; the kernel unwinds through the system call's frame to get there */
static
VOID
TestBadPointers(VOID)
{
    static const ULONG_PTR Bad[] = { 0x10, 0x7, (ULONG_PTR)0xFFFF800000000000ULL, (ULONG_PTR)0xFFFFF78000000000ULL };
    HDC hdc = CreateCompatibleDC(NULL);
    ULONG i;
    BOOL Result;
    UINT Bounds;

    ok(hdc != NULL, "CreateCompatibleDC failed, error %lu\n", GetLastError());
    if (!hdc)
        return;

    /* The return values are not checked (Windows' are not measured here): the calls must come back, and the DC
       must still work */
    for (i = 0; i < RTL_NUMBER_OF(Bad); i++)
    {
        Result = RectVisible(hdc, (const RECT *)Bad[i]);
        trace("RectVisible(%p) = %d\n", (PVOID)Bad[i], Result);
        Result = LPtoDP(hdc, (LPPOINT)Bad[i], 1);
        trace("LPtoDP(%p) = %d\n", (PVOID)Bad[i], Result);
        Bounds = GetBoundsRect(hdc, (LPRECT)Bad[i], 0);
        trace("GetBoundsRect(%p) = %u\n", (PVOID)Bad[i], Bounds);
        Bounds = SetBoundsRect(hdc, (const RECT *)Bad[i], DCB_ACCUMULATE);
        trace("SetBoundsRect(%p) = %u\n", (PVOID)Bad[i], Bounds);
    }

    {
        RECT rc = { 0, 0, 0, 0 };
        POINT pt = { 3, 4 };
        Bounds = GetBoundsRect(hdc, &rc, 0);
        ok(Bounds != 0, "GetBoundsRect after the bad pointers failed\n");
        ok(LPtoDP(hdc, &pt, 1) && pt.x == 3 && pt.y == 4, "LPtoDP after the bad pointers: %ld,%ld\n", pt.x, pt.y);
    }

    DeleteDC(hdc);
}

START_TEST(ThreadContextGdi)
{
    HANDLE hThread;
    PCONTEXT pContext;
    PVOID pBuffer;
    ULONG i, j, Failed = 0, Wrong = 0, Done = 0;
    PM128A pXmm;

    TestBadPointers();

    /* CONTEXT needs 16 byte alignment for the floating point state */
    pBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    pContext = pBuffer;
    ok(pContext != NULL, "VirtualAlloc failed, error %lu\n", GetLastError());
    if (!pContext)
        return;

    hThread = CreateThread(NULL, 0, GdiWorker, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed, error %lu\n", GetLastError());
    if (!hThread)
    {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        return;
    }

    /* Let the worker get into its loop */
    Sleep(100);

    for (i = 0; i < ROUNDS; i++)
    {
        if (SuspendThread(hThread) == (DWORD)-1)
        {
            Failed++;
            continue;
        }

        RtlZeroMemory(pContext, sizeof(*pContext));
        pContext->ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
        if (!GetThreadContext(hThread, pContext))
        {
            Failed++;
        }
        else
        {
            Done++;
            pXmm = &pContext->Xmm6;
            for (j = 0; j < NUM_XMM; j++)
            {
                if (pXmm[j].Low != g_Pattern[j][0] || (ULONGLONG)pXmm[j].High != g_Pattern[j][1])
                {
                    Wrong++;
                    break;
                }
            }
        }

        ResumeThread(hThread);
    }

    InterlockedExchange(&g_Stop, 1);
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFree(pBuffer, 0, MEM_RELEASE);

    ok(g_Calls > 0, "The worker made no GDI call\n");
    ok(Failed == 0, "%lu of %u requests failed\n", Failed, ROUNDS);
    ok(Done > 0, "No context was read\n");
    ok(Wrong == 0, "%lu of %lu contexts carry other xmm6 to xmm13 than the thread's\n", Wrong, Done);
}

#else

START_TEST(ThreadContextGdi)
{
    skip("Needs amd64 and GCC\n");
}

#endif
