/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for CreateDispatcherQueueController and Windows.System.DispatcherQueue (CoreMessaging.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The documented contract (dispatcherqueue.h, Windows.System.DispatcherQueue*): a controller owns a
 * queue bound to one thread, either the calling thread (which must pump window messages) or a dedicated
 * thread with a message loop of its own, optionally in a COM apartment. Work items run in priority order
 * (High, Normal, Low; first in first out within a priority) when that thread dispatches messages.
 * ShutdownQueueAsync raises ShutdownStarting (with a deferral) and ShutdownCompleted on the queue thread;
 * after that the queue accepts no work. Measured on Windows 10 22H2 (x64 and x86): a wrong dwSize or thread
 * type gives E_INVALIDARG and leaves the output alone, and RoGetActivationFactory needs COM initialized
 * (CO_E_NOTINITIALIZED). The rest is the documented behaviour; the trace lines record details.
 *
 * Measured on Windows 10 22H2 (2026-11-05, x64 and x86), besides that: TryEnqueue with a NULL callback is E_POINTER and
 * with a priority other than the three values E_INVALIDARG (result FALSE); a second controller for a thread is
 * RPC_E_WRONG_THREAD; the second ShutdownQueueAsync is E_UNEXPECTED; work queued before the end of a shutdown,
 * also after ShutdownQueueAsync returned, runs before ShutdownCompleted; changing the Interval of a running timer
 * does not re-arm it; GetDeferral needs COM on the thread (CO_E_NOTINITIALIZED); a timer goes on ticking, and
 * IsRunning stays TRUE, after its queue was shut down or its thread ended, and Start then returns S_OK; and a
 * TryEnqueue after the queue thread ended returns TRUE and holds the handler. The last two are not copied:
 * checks of them are made only for this implementation (IsOurs), which stops timers with their queue and refuses
 * work for a queue without a thread. A timer Start with an Interval of INT64_MAX ends the process on Windows.
 *
 * Tests that run threads against each other (DispatcherQueueThreads) and the messages another process can
 * post to a queue's window (DispatcherQueueForge, which exercises this implementation's window and is skipped
 * where there is no such window) are in the same file.
 */

#define COBJMACROS
#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <objbase.h>
#include <initguid.h>
#include <winstring.h>
#include <roapi.h>
#include "cmabi.h"

static PFN_CREATE_DQC pCreate;
static HRESULT (WINAPI *pRoGetActivationFactory)(HSTRING, REFIID, void **);
static HRESULT (WINAPI *pWindowsCreateString)(LPCWSTR, UINT32, HSTRING *);
static HRESULT (WINAPI *pWindowsDeleteString)(HSTRING);
static LPCWSTR (WINAPI *pWindowsGetStringRawBuffer)(HSTRING, UINT32 *);
static HRESULT (WINAPI *pRoInitialize)(int);
static void (WINAPI *pRoUninitialize)(void);
static HRESULT (WINAPI *pCoGetApartmentType)(int *, int *);

/* ---- handlers ---- */

typedef struct
{
    CmHandler Iface;
    LONG Ref;
    int Tag;
    HRESULT Result;
    CmQueue *Queue;          /* what is checked inside */
    CmQueue *Requeue;        /* enqueue a follow-up item */
    HANDLE Event;
    DWORD ThreadId;
    int AptType, AptQual;
    HRESULT AptHr;
    CmBool HasAccess;
    BOOL SameForThread;
    HANDLE Thread;
    void (*Hook)(void *);    /* called while the item runs */
    void *HookArg;
} TestHandler;

static int g_Order[32];
static LONG g_OrderCount;
static MSG g_CurrentMsg;
static BOOL g_InDispatch;
static MSG g_RunMsg;

static HRESULT STDMETHODCALLTYPE H_QueryInterface(CmHandler *This, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_CmHandler) || IsEqualGUID(iid, &IID_CmAgileObject))
    {
        *out = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    trace("DispatcherQueueHandler asked for %s\n", wine_dbgstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE H_AddRef(CmHandler *This) { return InterlockedIncrement(&((TestHandler *)This)->Ref); }
static ULONG STDMETHODCALLTYPE H_Release(CmHandler *This) { return InterlockedDecrement(&((TestHandler *)This)->Ref); }

static CmQueueStatics *g_QueueStatics;

static HRESULT STDMETHODCALLTYPE H_Invoke(CmHandler *This)
{
    TestHandler *H = (TestHandler *)This;
    LONG n = InterlockedIncrement(&g_OrderCount);

    if (n <= 32)
        g_Order[n - 1] = H->Tag;
    if (g_InDispatch)
        g_RunMsg = g_CurrentMsg;
    H->ThreadId = GetCurrentThreadId();
    if (pCoGetApartmentType)
        H->AptHr = pCoGetApartmentType(&H->AptType, &H->AptQual);
    if (H->Queue)
    {
        CmQueue2 *Q2 = NULL;
        if (SUCCEEDED(H->Queue->lpVtbl->QueryInterface(H->Queue, &IID_CmQueue2, (void **)&Q2)) && Q2)
        {
            Q2->lpVtbl->get_HasThreadAccess(Q2, &H->HasAccess);
            Q2->lpVtbl->Release(Q2);
        }
        if (g_QueueStatics)
        {
            CmQueue *Cur = NULL;
            if (SUCCEEDED(g_QueueStatics->lpVtbl->GetForCurrentThread(g_QueueStatics, &Cur)) && Cur)
            {
                IUnknown *U1 = NULL, *U2 = NULL;
                Cur->lpVtbl->QueryInterface(Cur, &IID_IUnknown, (void **)&U1);
                H->Queue->lpVtbl->QueryInterface(H->Queue, &IID_IUnknown, (void **)&U2);
                H->SameForThread = U1 && U1 == U2;
                if (U1) IUnknown_Release(U1);
                if (U2) IUnknown_Release(U2);
                Cur->lpVtbl->Release(Cur);
            }
        }
        H->Thread = OpenThread(SYNCHRONIZE, FALSE, GetCurrentThreadId());
    }
    if (H->Requeue)
    {
        static TestHandler Follow;
        CmBool r = 0;
        extern const struct CmHandlerVtbl g_HVtbl;
        Follow.Iface.lpVtbl = &g_HVtbl;
        Follow.Tag = 99;
        H->Requeue->lpVtbl->TryEnqueue(H->Requeue, &Follow.Iface, &r);
    }
    if (H->Hook)
        H->Hook(H->HookArg);
    if (H->Event)
        SetEvent(H->Event);
    return H->Result;
}

const struct CmHandlerVtbl g_HVtbl = { H_QueryInterface, H_AddRef, H_Release, H_Invoke };

static void InitHandler(TestHandler *H, int Tag)
{
    memset(H, 0, sizeof(*H));
    H->Iface.lpVtbl = &g_HVtbl;
    H->Ref = 1;
    H->Tag = Tag;
}

typedef struct
{
    CmTypedHandler Iface;
    LONG Ref;
    LONG Calls;
    DWORD ThreadId;
    LONG Order;
    DWORD Ticks[8];
    BOOL TakeDeferral;
    HRESULT DeferralHr;
    BOOL SenderIsQueue;
    BOOL ArgsNull;
    void *Expect;
    HANDLE Event;                /* set by every call */
    BOOL KeepDeferral;           /* take a deferral and keep it, with the arguments */
    CmDeferral *Deferral;
    CmShutdownArgs *KeptArgs;
    CmDeferral *Late;
    HRESULT LateHr;
} TypedHandler;

static LONG g_EventSeq;

static HRESULT STDMETHODCALLTYPE T_QueryInterface(CmTypedHandler *This, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_CmAgileObject) || IsEqualGUID(iid, &IID_CmQueueObjHandler)
        || IsEqualGUID(iid, &IID_CmQueueArgsHandler) || IsEqualGUID(iid, &IID_CmTimerHandler))
    {
        *out = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    trace("TypedEventHandler asked for %s\n", wine_dbgstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE T_AddRef(CmTypedHandler *This) { return InterlockedIncrement(&((TypedHandler *)This)->Ref); }
static ULONG STDMETHODCALLTYPE T_Release(CmTypedHandler *This) { return InterlockedDecrement(&((TypedHandler *)This)->Ref); }
static HRESULT STDMETHODCALLTYPE T_Invoke(CmTypedHandler *This, IInspectable *Sender, IInspectable *Args)
{
    TypedHandler *T = (TypedHandler *)This;

    if (T->Calls < 8)
        T->Ticks[T->Calls] = GetTickCount();
    InterlockedIncrement(&T->Calls);
    T->ThreadId = GetCurrentThreadId();
    T->Order = InterlockedIncrement(&g_EventSeq);
    T->ArgsNull = (Args == NULL);
    if (T->Expect && Sender)
    {
        IUnknown *U1 = NULL, *U2 = NULL;
        IInspectable_QueryInterface(Sender, &IID_IUnknown, (void **)&U1);
        IUnknown_QueryInterface((IUnknown *)T->Expect, &IID_IUnknown, (void **)&U2);
        T->SenderIsQueue = U1 && U1 == U2;
        if (U1) IUnknown_Release(U1);
        if (U2) IUnknown_Release(U2);
    }
    if (T->KeepDeferral && Args)
    {
        T->DeferralHr = IInspectable_QueryInterface(Args, &IID_CmShutdownArgs, (void **)&T->KeptArgs);
        if (SUCCEEDED(T->DeferralHr) && T->KeptArgs)
            T->DeferralHr = T->KeptArgs->lpVtbl->GetDeferral(T->KeptArgs, &T->Deferral);
    }
    if (T->TakeDeferral && Args)
    {
        CmShutdownArgs *A = NULL;
        CmDeferral *D = NULL;
        T->DeferralHr = IInspectable_QueryInterface(Args, &IID_CmShutdownArgs, (void **)&A);
        if (SUCCEEDED(T->DeferralHr) && A)
        {
            T->DeferralHr = A->lpVtbl->GetDeferral(A, &D);
            if (SUCCEEDED(T->DeferralHr) && D)
            {
                T->DeferralHr = D->lpVtbl->Complete(D);
                D->lpVtbl->Release(D);
            }
            A->lpVtbl->Release(A);
        }
    }
    if (T->Event)
        SetEvent(T->Event);
    return S_OK;
}
static const struct CmTypedHandlerVtbl g_TVtbl = { T_QueryInterface, T_AddRef, T_Release, T_Invoke };

static void InitTyped(TypedHandler *T)
{
    memset(T, 0, sizeof(*T));
    T->Iface.lpVtbl = &g_TVtbl;
    T->Ref = 1;
}

typedef struct
{
    CmActionHandler Iface;
    LONG Ref;
    LONG Calls;
    int Status;
    DWORD ThreadId;
    HANDLE Event;
} ActionHandler;

static HRESULT STDMETHODCALLTYPE A_QueryInterface(CmActionHandler *This, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_CmActionHandler) || IsEqualGUID(iid, &IID_CmAgileObject))
    {
        *out = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    trace("AsyncActionCompletedHandler asked for %s\n", wine_dbgstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE A_AddRef(CmActionHandler *This) { return InterlockedIncrement(&((ActionHandler *)This)->Ref); }
static ULONG STDMETHODCALLTYPE A_Release(CmActionHandler *This) { return InterlockedDecrement(&((ActionHandler *)This)->Ref); }
static HRESULT STDMETHODCALLTYPE A_Invoke(CmActionHandler *This, CmAsyncAction *Action, int Status)
{
    ActionHandler *A = (ActionHandler *)This;
    InterlockedIncrement(&A->Calls);
    A->Status = Status;
    A->ThreadId = GetCurrentThreadId();
    if (A->Event)
        SetEvent(A->Event);
    return S_OK;
}
static const struct CmActionHandlerVtbl g_AVtbl = { A_QueryInterface, A_AddRef, A_Release, A_Invoke };

/* ---- helpers ---- */

static CmOptions Opts(DWORD Size, int Thread, int Apt)
{
    CmOptions o;
    o.dwSize = Size;
    o.threadType = Thread;
    o.apartmentType = Apt;
    return o;
}

/* dispatch messages of this thread for up to Ms milliseconds, or until *Until is reached */
static void Pump(DWORD Ms, volatile LONG *Count, LONG Until)
{
    DWORD End = GetTickCount() + Ms;
    MSG msg;

    for (;;)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            g_CurrentMsg = msg;
            g_InDispatch = TRUE;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            g_InDispatch = FALSE;
        }
        if (Count && *Count >= Until)
            return;
        if ((LONG)(GetTickCount() - End) >= 0)
            return;
        MsgWaitForMultipleObjects(0, NULL, FALSE, 10, QS_ALLINPUT);
    }
}

static BOOL SameObject(void *A, void *B)
{
    IUnknown *U1 = NULL, *U2 = NULL;
    BOOL Same;

    if (!A || !B)
        return A == B;
    IUnknown_QueryInterface((IUnknown *)A, &IID_IUnknown, (void **)&U1);
    IUnknown_QueryInterface((IUnknown *)B, &IID_IUnknown, (void **)&U2);
    Same = U1 && U1 == U2;
    if (U1) IUnknown_Release(U1);
    if (U2) IUnknown_Release(U2);
    return Same;
}

static void ClassName(void *Obj, WCHAR *Buf, int Cch)
{
    HSTRING Name = NULL;
    Buf[0] = 0;
    if (SUCCEEDED(IInspectable_GetRuntimeClassName((IInspectable *)Obj, &Name)) && Name)
    {
        lstrcpynW(Buf, pWindowsGetStringRawBuffer(Name, NULL), Cch);
        pWindowsDeleteString(Name);
    }
}

/* Behaviour that Windows does not have and ReactOS chose is checked only where this implementation runs: it is
 * recognised by the class of its queue windows, which exist once a queue has been made */
static BOOL g_Ours;
static BOOL IsOurs(void)
{
    if (!g_Ours)
        g_Ours = FindWindowExW(HWND_MESSAGE, NULL, L"ReactOS.DispatcherQueue", NULL) != NULL;
    return g_Ours;
}

static CmQueue *ForCurrentThread(void)
{
    CmQueue *Q = (CmQueue *)(ULONG_PTR)0x1234;
    HRESULT hr;

    if (!g_QueueStatics)
        return NULL;
    hr = g_QueueStatics->lpVtbl->GetForCurrentThread(g_QueueStatics, &Q);
    ok(hr == S_OK, "GetForCurrentThread returned %08lx\n", hr);
    if (hr != S_OK)
        return NULL;
    return Q;
}

static void DescribeMsg(const char *What, const MSG *m)
{
    WCHAR Cls[64] = L"";
    if (m->hwnd)
        GetClassNameW(m->hwnd, Cls, 64);
    trace("%s: hwnd %p class '%ls' message %#x wParam %Ix lParam %Ix, message-only parent %d\n", What, m->hwnd, Cls,
          m->message, m->wParam, m->lParam, m->hwnd ? (GetAncestor(m->hwnd, GA_PARENT) == GetAncestor(FindWindowExW(HWND_MESSAGE, NULL, NULL, NULL), GA_PARENT)) : -1);
}

/* ---- tests ---- */

static DWORD WINAPI ArgsThread(void *Param)
{
    CmController *C;
    CmQueue *Q;
    HRESULT hr;

    C = (CmController *)(ULONG_PTR)0x1234;
    hr = pCreate(Opts(0, 2, 0), &C);
    ok(hr == E_INVALIDARG, "dwSize 0: %08lx\n", hr);
    ok(C == (CmController *)(ULONG_PTR)0x1234, "dwSize 0: the output was changed to %p\n", C);
    trace("dwSize 0: hr %08lx out %p\n", hr, C);
    if (SUCCEEDED(hr) && C) C->lpVtbl->Release(C);

    C = (CmController *)(ULONG_PTR)0x1234;
    hr = pCreate(Opts(sizeof(CmOptions) + 4, 2, 0), &C);
    ok(hr == E_INVALIDARG, "dwSize 16: %08lx\n", hr);
    ok(C == (CmController *)(ULONG_PTR)0x1234, "dwSize 16: the output was changed to %p\n", C);
    trace("dwSize 16: hr %08lx out %p\n", hr, C);
    if (SUCCEEDED(hr) && C) C->lpVtbl->Release(C);

    C = (CmController *)(ULONG_PTR)0x1234;
    hr = pCreate(Opts(sizeof(CmOptions), 0, 0), &C);
    ok(hr == E_INVALIDARG, "thread type 0: %08lx\n", hr);
    ok(C == (CmController *)(ULONG_PTR)0x1234, "thread type 0: the output was changed to %p\n", C);
    trace("thread type 0: hr %08lx out %p\n", hr, C);
    if (SUCCEEDED(hr) && C) C->lpVtbl->Release(C);

    C = (CmController *)(ULONG_PTR)0x1234;
    hr = pCreate(Opts(sizeof(CmOptions), 3, 0), &C);
    ok(hr == E_INVALIDARG, "thread type 3: %08lx\n", hr);
    ok(C == (CmController *)(ULONG_PTR)0x1234, "thread type 3: the output was changed to %p\n", C);
    trace("thread type 3: hr %08lx out %p\n", hr, C);
    if (SUCCEEDED(hr) && C) C->lpVtbl->Release(C);

    /* Windows 10 22H2 ends the process for an unknown apartment type (measured), so that and a NULL controller
     * pointer are not tried; every apartment option for the current thread is in MatrixThread */

    /* nothing above made a queue for this thread */
    Q = ForCurrentThread();
    ok(Q == NULL, "a failed call left queue %p on the thread\n", Q);
    if (Q) Q->lpVtbl->Release(Q);

    return 0;
}

static void RunOnThread(LPTHREAD_START_ROUTINE Fn, void *Param)
{
    HANDLE Th = CreateThread(NULL, 0, Fn, Param, 0, NULL);
    DWORD w = WaitForSingleObject(Th, 30000);
    ok(w == WAIT_OBJECT_0, "test thread did not finish (%lu)\n", w);
    if (w != WAIT_OBJECT_0)
        TerminateThread(Th, 1);
    CloseHandle(Th);
}

static DWORD WINAPI CurrentThread(void *Param)
{
    CmController *C = NULL, *C2 = NULL;
    CmQueue *Q = NULL, *Cur;
    CmQueue2 *Q2 = NULL;
    TestHandler H[6];
    TypedHandler Start, Done;
    CmToken TokS = { 0 }, TokD = { 0 }, TokX = { 0 };
    CmAsyncAction *Act = NULL;
    CmAsyncInfo *Info = NULL;
    CmBool r;
    WCHAR Name[128];
    HRESULT hr;
    int i, Status = -1, t = -1, q = -1;

    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &C);
    ok(hr == S_OK, "CreateDispatcherQueueController(current) returned %08lx\n", hr);
    if (hr != S_OK || !C)
        return 0;
    if (pCoGetApartmentType)
    {
        hr = pCoGetApartmentType(&t, &q);
        trace("current thread, no COM: apartment hr %08lx type %d qualifier %d\n", hr, t, q);
    }
    ClassName(C, Name, 128);
    ok(!wcscmp(Name, L"Windows.System.DispatcherQueueController"), "controller class '%ls'\n", Name);
    CoInitializeEx(NULL, COINIT_MULTITHREADED); /* GetDeferral needs it on Windows */

    hr = C->lpVtbl->get_DispatcherQueue(C, &Q);
    ok(hr == S_OK && Q, "get_DispatcherQueue returned %08lx %p\n", hr, Q);
    if (!Q)
    {
        C->lpVtbl->Release(C);
        return 0;
    }
    ClassName(Q, Name, 128);
    ok(!wcscmp(Name, L"Windows.System.DispatcherQueue"), "queue class '%ls'\n", Name);
    Cur = NULL;
    hr = C->lpVtbl->get_DispatcherQueue(C, &Cur);
    ok(hr == S_OK && SameObject(Cur, Q), "a second get_DispatcherQueue gives another object\n");
    if (Cur) Cur->lpVtbl->Release(Cur);
    Cur = ForCurrentThread();
    ok(SameObject(Cur, Q), "GetForCurrentThread gives %p, not the queue %p\n", Cur, Q);
    if (Cur) Cur->lpVtbl->Release(Cur);
    hr = Q->lpVtbl->QueryInterface(Q, &IID_CmQueue2, (void **)&Q2);
    ok(hr == S_OK, "QueryInterface(IDispatcherQueue2) returned %08lx\n", hr);
    if (Q2)
    {
        r = 0xcc;
        hr = Q2->lpVtbl->get_HasThreadAccess(Q2, &r);
        ok(hr == S_OK && r == 1, "HasThreadAccess %08lx %u\n", hr, r);
        Q2->lpVtbl->Release(Q2);
    }

    /* one queue per thread */
    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &C2);
    trace("second controller on the thread: hr %08lx\n", hr);
    ok(hr == RPC_E_WRONG_THREAD, "a second controller on the same thread: %08lx\n", hr);
    if (SUCCEEDED(hr) && C2) C2->lpVtbl->Release(C2);

    /* Release returns the count after the release */
    {
        ULONG a = Q->lpVtbl->AddRef(Q), b = Q->lpVtbl->Release(Q);
        ok(b + 1 == a, "AddRef returned %lu, then Release %lu\n", a, b);
    }

    /* priorities; nothing runs before the thread dispatches messages */
    g_OrderCount = 0;
    for (i = 0; i < 6; i++)
        InitHandler(&H[i], i + 1);
    hr = Q->lpVtbl->TryEnqueueWithPriority(Q, CmPriorityLow, &H[0].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue(low) %08lx %u\n", hr, r);
    hr = Q->lpVtbl->TryEnqueueWithPriority(Q, CmPriorityNormal, &H[1].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue(normal) %08lx %u\n", hr, r);
    hr = Q->lpVtbl->TryEnqueue(Q, &H[2].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue %08lx %u\n", hr, r);
    hr = Q->lpVtbl->TryEnqueueWithPriority(Q, CmPriorityHigh, &H[3].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue(high) %08lx %u\n", hr, r);
    r = 1;
    hr = Q->lpVtbl->TryEnqueueWithPriority(Q, 5, &H[4].Iface, &r);
    ok(hr == E_INVALIDARG && r == 0, "TryEnqueue(priority 5): %08lx %u\n", hr, r);
    ok(H[0].Ref > 1, "the queue holds no reference to the handler (%ld)\n", H[0].Ref);
    hr = Q->lpVtbl->TryEnqueue(Q, NULL, &r);
    ok(hr == E_POINTER, "TryEnqueue(NULL) returned %08lx\n", hr);
    Sleep(50);
    ok(g_OrderCount == 0, "%ld items ran before the thread dispatched messages\n", g_OrderCount);
    Pump(2000, &g_OrderCount, 4);
    ok(g_OrderCount == 4, "%ld items ran\n", g_OrderCount);
    trace("order: %d %d %d %d\n", g_Order[0], g_Order[1], g_Order[2], g_Order[3]);
    ok(g_Order[0] == 4, "first ran %d\n", g_Order[0]);
    ok(g_Order[g_OrderCount - 1] == 1, "last ran %d\n", g_Order[g_OrderCount - 1]);
    DescribeMsg("work item delivered by", &g_RunMsg);
    for (i = 0; i < 4; i++)
        ok(H[i].ThreadId == GetCurrentThreadId(), "item %d ran on thread %lx\n", i + 1, H[i].ThreadId);
    Pump(100, NULL, 0);
    ok(H[0].Ref == 1, "the queue still holds the handler (%ld)\n", H[0].Ref);
    ok(H[4].Ref == 1, "the queue holds a handler it refused (%ld)\n", H[4].Ref);

    /* a failing item does not stop the queue (how Windows treats a failing item was not measured) */
    if (IsOurs())
    {
        g_OrderCount = 0;
        InitHandler(&H[4], 5);
        H[4].Result = E_FAIL;
        InitHandler(&H[3], 4);
        Q->lpVtbl->TryEnqueue(Q, &H[4].Iface, &r);
        Q->lpVtbl->TryEnqueue(Q, &H[3].Iface, &r);
        Pump(2000, &g_OrderCount, 2);
        ok(g_OrderCount == 2, "an item that returned a failure stopped the queue (%ld items ran)\n", g_OrderCount);
    }

    /* an item can enqueue another; it runs later, in the same dispatch or the next */
    g_OrderCount = 0;
    InitHandler(&H[5], 50);
    H[5].Requeue = Q;
    hr = Q->lpVtbl->TryEnqueue(Q, &H[5].Iface, &r);
    Pump(1000, &g_OrderCount, 2);
    ok(g_OrderCount == 2 && g_Order[0] == 50 && g_Order[1] == 99, "follow-up: %ld items, %d %d\n", g_OrderCount, g_Order[0], g_Order[1]);

    /* timers */
    {
        CmTimer *Tm = NULL;
        TypedHandler Tick;
        CmTimeSpan Iv = { -1 };
        CmBool Running = 0xcc, Repeating = 0xcc;
        DWORD StartTick, Elapsed;

        hr = Q->lpVtbl->CreateTimer(Q, &Tm);
        ok(hr == S_OK && Tm, "CreateTimer %08lx\n", hr);
        if (Tm)
        {
            ClassName(Tm, Name, 128);
            ok(!wcscmp(Name, L"Windows.System.DispatcherQueueTimer"), "timer class '%ls'\n", Name);
            Tm->lpVtbl->get_Interval(Tm, &Iv);
            Tm->lpVtbl->get_IsRunning(Tm, &Running);
            Tm->lpVtbl->get_IsRepeating(Tm, &Repeating);
            trace("new timer: interval %I64d running %u repeating %u\n", Iv.Duration, Running, Repeating);
            ok(Iv.Duration == 0 && Running == 0 && Repeating == 1, "new timer: %I64d %u %u\n", Iv.Duration, Running, Repeating);
            InitTyped(&Tick);
            Tick.Expect = Tm;
            hr = Tm->lpVtbl->add_Tick(Tm, &Tick.Iface, &TokX);
            ok(hr == S_OK, "add_Tick %08lx\n", hr);
            Iv.Duration = 1000000; /* 100 ms */
            Tm->lpVtbl->put_Interval(Tm, Iv);
            StartTick = GetTickCount();
            hr = Tm->lpVtbl->Start(Tm);
            ok(hr == S_OK, "Start %08lx\n", hr);
            Tm->lpVtbl->get_IsRunning(Tm, &Running);
            ok(Running == 1, "running %u after Start\n", Running);
            Pump(560, NULL, 0);
            Elapsed = GetTickCount() - StartTick;
            trace("repeating 100 ms timer: %ld ticks in %lu ms, at +%lu +%lu +%lu +%lu +%lu ms\n", Tick.Calls, Elapsed,
                  Tick.Ticks[0] - StartTick, Tick.Ticks[1] - StartTick, Tick.Ticks[2] - StartTick, Tick.Ticks[3] - StartTick,
                  Tick.Ticks[4] - StartTick);
            /* a timer never ticks faster than its interval; a loaded machine can make it late, not early */
            ok(Tick.Calls >= 2 && (DWORD)Tick.Calls <= Elapsed / 100 + 1, "%ld ticks in %lu ms\n", Tick.Calls, Elapsed);
            ok(Tick.SenderIsQueue, "the sender of Tick is not the timer\n");
            ok(Tick.ThreadId == GetCurrentThreadId(), "Tick ran on thread %lx\n", Tick.ThreadId);
            hr = Tm->lpVtbl->Stop(Tm);
            ok(hr == S_OK, "Stop %08lx\n", hr);
            Tm->lpVtbl->get_IsRunning(Tm, &Running);
            ok(Running == 0, "running %u after Stop\n", Running);
            Tick.Calls = 0;
            Pump(300, NULL, 0);
            ok(Tick.Calls == 0, "%ld ticks after Stop\n", Tick.Calls);
            Tm->lpVtbl->put_IsRepeating(Tm, 0);
            Tm->lpVtbl->Start(Tm);
            Pump(3000, &Tick.Calls, 1);
            Pump(300, NULL, 0); /* a one-shot timer does not tick twice */
            Tm->lpVtbl->get_IsRunning(Tm, &Running);
            ok(Tick.Calls == 1, "one-shot timer: %ld ticks\n", Tick.Calls);
            trace("one-shot timer: running %u after its tick\n", Running);
            /* an interval too large for a window timer is clamped, it does not wrap around to a short one */
            Tm->lpVtbl->put_IsRepeating(Tm, 1);
            Iv.Duration = (INT64)(~0ULL >> 1);
            hr = Tm->lpVtbl->put_Interval(Tm, Iv);
            trace("interval of INT64_MAX: put_Interval %08lx\n", hr);
            ok(hr == S_OK, "put_Interval(INT64_MAX) %08lx\n", hr);
            if (hr == S_OK && IsOurs()) /* Windows ends the process in Start */
            {
                hr = Tm->lpVtbl->Start(Tm);
                trace("interval of INT64_MAX: Start %08lx\n", hr);
                if (hr == S_OK)
                {
                    Tick.Calls = 0;
                    Pump(300, NULL, 0);
                    ok(Tick.Calls == 0, "a timer with the largest interval ticked %ld times\n", Tick.Calls);
                    Tm->lpVtbl->Stop(Tm);
                }
            }
            hr = Tm->lpVtbl->remove_Tick(Tm, TokX);
            ok(hr == S_OK, "remove_Tick %08lx\n", hr);
            Tm->lpVtbl->Release(Tm);
            Pump(50, NULL, 0);
        }
    }

    /* shutdown */
    InitTyped(&Start);
    InitTyped(&Done);
    Start.TakeDeferral = TRUE;
    Start.Expect = Q;
    Done.Expect = Q;
    g_EventSeq = 0;
    hr = Q->lpVtbl->add_ShutdownStarting(Q, &Start.Iface, &TokS);
    ok(hr == S_OK, "add_ShutdownStarting %08lx\n", hr);
    hr = Q->lpVtbl->add_ShutdownCompleted(Q, &Done.Iface, &TokD);
    ok(hr == S_OK, "add_ShutdownCompleted %08lx\n", hr);
    trace("tokens %I64x %I64x\n", TokS.Value, TokD.Value);
    InitHandler(&H[0], 7);
    g_OrderCount = 0;
    hr = Q->lpVtbl->TryEnqueue(Q, &H[0].Iface, &r);
    hr = C->lpVtbl->ShutdownQueueAsync(C, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync %08lx\n", hr);
    if (Act)
    {
        ActionHandler AH = { { &g_AVtbl }, 1 };

        ClassName(Act, Name, 128);
        trace("shutdown action class '%ls'\n", Name);
        hr = Act->lpVtbl->QueryInterface(Act, &IID_CmAsyncInfo, (void **)&Info);
        ok(hr == S_OK, "QueryInterface(IAsyncInfo) %08lx\n", hr);
        if (Info)
            Info->lpVtbl->get_Status(Info, &Status);
        trace("right after ShutdownQueueAsync: status %d, starting %ld, completed %ld, item ran %ld\n", Status,
              Start.Calls, Done.Calls, g_OrderCount);
        hr = Act->lpVtbl->put_Completed(Act, &AH.Iface);
        ok(hr == S_OK, "put_Completed %08lx\n", hr);
        hr = Q->lpVtbl->TryEnqueue(Q, &H[1].Iface, &r);
        trace("TryEnqueue while shutting down: %08lx %u\n", hr, r);
        Pump(2000, &AH.Calls, 1);
        ok(AH.Calls == 1 && AH.Status == CmAsyncCompleted, "completed handler: %ld calls, status %d\n", AH.Calls, AH.Status);
        ok(Start.Calls == 1 && Done.Calls == 1, "events: starting %ld, completed %ld\n", Start.Calls, Done.Calls);
        ok(Start.Order == 1 && Done.Order == 2, "event order %ld %ld\n", Start.Order, Done.Order);
        ok(Start.ThreadId == GetCurrentThreadId() && Done.ThreadId == GetCurrentThreadId(), "events ran on %lx %lx\n",
           Start.ThreadId, Done.ThreadId);
        ok(Start.SenderIsQueue && Done.SenderIsQueue, "the sender of the events is not the queue\n");
        ok(Start.DeferralHr == S_OK, "deferral %08lx\n", Start.DeferralHr);
        trace("completed args NULL %d; item queued before shutdown ran %ld; completion ran on %s thread\n", Done.ArgsNull,
              g_OrderCount, AH.ThreadId == GetCurrentThreadId() ? "the queue" : "another");
        if (Info)
        {
            Info->lpVtbl->get_Status(Info, &Status);
            ok(Status == CmAsyncCompleted, "status %d\n", Status);
            hr = Act->lpVtbl->GetResults(Act);
            ok(hr == S_OK, "GetResults %08lx\n", hr);
            Info->lpVtbl->Release(Info);
        }
        r = 0xcc;
        hr = Q->lpVtbl->TryEnqueue(Q, &H[2].Iface, &r);
        ok(hr == S_OK && r == 0, "TryEnqueue after shutdown %08lx %u\n", hr, r);
        Cur = ForCurrentThread();
        trace("GetForCurrentThread after shutdown: %p (queue %p)\n", Cur, Q);
        if (Cur) Cur->lpVtbl->Release(Cur);
        Act->lpVtbl->Release(Act);
        Act = NULL;
        hr = C->lpVtbl->ShutdownQueueAsync(C, &Act);
        ok(hr == E_UNEXPECTED, "second ShutdownQueueAsync: %08lx\n", hr);
        if (SUCCEEDED(hr) && Act) Act->lpVtbl->Release(Act);
    }
    Q->lpVtbl->remove_ShutdownStarting(Q, TokS);
    Q->lpVtbl->remove_ShutdownCompleted(Q, TokD);
    Q->lpVtbl->Release(Q);
    C->lpVtbl->Release(C);
    Pump(50, NULL, 0);

    /* after shutdown and release, a new controller can be made on the thread */
    C = NULL;
    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &C);
    trace("controller after shutdown: %08lx\n", hr);
    if (SUCCEEDED(hr) && C) C->lpVtbl->Release(C);
    return 0;
}

static void TestDedicated(int Apt, BOOL Statics)
{
    CmController *C = NULL;
    CmQueue *Q = NULL, *Cur;
    CmQueue2 *Q2 = NULL;
    TestHandler H;
    CmAsyncAction *Act = NULL;
    ActionHandler AH = { { &g_AVtbl }, 1 };
    CmBool r = 0xcc;
    HRESULT hr;
    DWORD w;

    if (Statics)
    {
        CmControllerStatics *S = NULL;
        HSTRING Cls = NULL;
        pWindowsCreateString(L"Windows.System.DispatcherQueueController", 40, &Cls);
        hr = pRoGetActivationFactory(Cls, &IID_CmControllerStatics, (void **)&S);
        ok(hr == S_OK, "RoGetActivationFactory(DispatcherQueueController) %08lx\n", hr);
        pWindowsDeleteString(Cls);
        if (!S)
            return;
        hr = S->lpVtbl->CreateOnDedicatedThread(S, &C);
        ok(hr == S_OK, "CreateOnDedicatedThread %08lx\n", hr);
        S->lpVtbl->Release(S);
    }
    else
    {
        hr = pCreate(Opts(sizeof(CmOptions), 1, Apt), &C);
        ok(hr == S_OK, "CreateDispatcherQueueController(dedicated, %d) %08lx\n", Apt, hr);
    }
    if (!C)
        return;
    hr = C->lpVtbl->get_DispatcherQueue(C, &Q);
    ok(hr == S_OK && Q, "get_DispatcherQueue %08lx\n", hr);
    if (!Q)
    {
        C->lpVtbl->Release(C);
        return;
    }
    Cur = ForCurrentThread();
    ok(Cur == NULL, "the calling thread has queue %p\n", Cur);
    if (Cur) Cur->lpVtbl->Release(Cur);
    if (SUCCEEDED(Q->lpVtbl->QueryInterface(Q, &IID_CmQueue2, (void **)&Q2)) && Q2)
    {
        Q2->lpVtbl->get_HasThreadAccess(Q2, &r);
        ok(r == 0, "HasThreadAccess %u from another thread\n", r);
        Q2->lpVtbl->Release(Q2);
    }

    InitHandler(&H, 1);
    H.Queue = Q;
    H.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    hr = Q->lpVtbl->TryEnqueue(Q, &H.Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue %08lx %u\n", hr, r);
    w = WaitForSingleObject(H.Event, 5000);
    ok(w == WAIT_OBJECT_0, "the item did not run (%lu)\n", w);
    ok(H.ThreadId && H.ThreadId != GetCurrentThreadId(), "the item ran on thread %lx\n", H.ThreadId);
    ok(H.HasAccess == 1, "HasThreadAccess %u on the queue thread\n", H.HasAccess);
    ok(H.SameForThread, "GetForCurrentThread on the queue thread is not the queue\n");
    trace("dedicated apartment option %d%s: item apartment hr %08lx type %d qualifier %d\n", Apt, Statics ? " (statics)" : "",
          H.AptHr, H.AptType, H.AptQual);
    if (!Statics && Apt == 0)
        ok(H.AptHr == CO_E_NOTINITIALIZED || (H.AptHr == S_OK && H.AptQual == 1 /* implicit MTA */),
           "COM_NONE: apartment %08lx %d %d\n", H.AptHr, H.AptType, H.AptQual);
    if (!Statics && Apt == 1)
        ok(H.AptHr == S_OK, "COM_ASTA: apartment %08lx %d %d\n", H.AptHr, H.AptType, H.AptQual);
    if (!Statics && Apt == 2) /* APTTYPE_STA, or APTTYPE_MAINSTA for the first STA of the process */
        ok(H.AptHr == S_OK && (H.AptType == 0 || H.AptType == 3), "COM_STA: apartment %08lx %d %d\n", H.AptHr, H.AptType, H.AptQual);

    hr = C->lpVtbl->ShutdownQueueAsync(C, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync %08lx\n", hr);
    if (Act)
    {
        AH.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
        hr = Act->lpVtbl->put_Completed(Act, &AH.Iface);
        ok(hr == S_OK, "put_Completed %08lx\n", hr);
        w = WaitForSingleObject(AH.Event, 5000);
        ok(w == WAIT_OBJECT_0 && AH.Status == CmAsyncCompleted, "shutdown did not complete (%lu, %d)\n", w, AH.Status);
        trace("dedicated shutdown completion ran on the %s thread\n",
              AH.ThreadId == H.ThreadId ? "queue" : AH.ThreadId == GetCurrentThreadId() ? "calling" : "another");
        CloseHandle(AH.Event);
        Act->lpVtbl->Release(Act);
    }
    if (H.Thread)
    {
        w = WaitForSingleObject(H.Thread, 3000);
        trace("dedicated queue thread %s after shutdown (%lu)\n", w == WAIT_OBJECT_0 ? "exited" : "still runs", w);
        ok(w == WAIT_OBJECT_0, "the dedicated thread did not exit after shutdown (%lu)\n", w);
        CloseHandle(H.Thread);
    }
    r = 0xcc;
    hr = Q->lpVtbl->TryEnqueue(Q, &H.Iface, &r);
    ok(hr == S_OK && r == 0, "TryEnqueue after shutdown %08lx %u\n", hr, r);
    Q->lpVtbl->Release(Q);
    C->lpVtbl->Release(C);
    CloseHandle(H.Event);
}

static DWORD WINAPI FactoryThread(void *Param)
{
    HSTRING Cls = NULL;
    IInspectable *Obj = NULL;
    IUnknown *F = NULL;
    HRESULT hr, FactoryHr;
    HKEY Key;
    WCHAR Buf[MAX_PATH];
    DWORD Size, Type, Val;
    static const WCHAR *Classes[] = { L"Windows.System.DispatcherQueue", L"Windows.System.DispatcherQueueController",
                                      L"Windows.System.DispatcherQueueTimer", L"Windows.System.DispatcherQueueShutdownStartingEventArgs" };
    int i;
    HRESULT (WINAPI *pDllGet)(HSTRING, IUnknown **) =
        (void *)GetProcAddress(GetModuleHandleW(L"CoreMessaging.dll"), "DllGetActivationFactory");

    for (i = 0; i < 4; i++)
    {
        WCHAR Path[200];
        wsprintfW(Path, L"SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\%s", Classes[i]);
        if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &Key))
        {
            Size = sizeof(Buf); Buf[0] = 0;
            RegQueryValueExW(Key, L"DllPath", NULL, &Type, (BYTE *)Buf, &Size);
            trace("%ls: DllPath '%ls' type %lu\n", Classes[i], Buf, Type);
            Size = sizeof(Val); Val = 0xcc;
            if (!RegQueryValueExW(Key, L"ActivationType", NULL, NULL, (BYTE *)&Val, &Size)) trace("  ActivationType %lu\n", Val);
            Size = sizeof(Val); Val = 0xcc;
            if (!RegQueryValueExW(Key, L"Threading", NULL, NULL, (BYTE *)&Val, &Size)) trace("  Threading %lu\n", Val);
            Size = sizeof(Val); Val = 0xcc;
            if (!RegQueryValueExW(Key, L"TrustLevel", NULL, NULL, (BYTE *)&Val, &Size)) trace("  TrustLevel %lu\n", Val);
            RegCloseKey(Key);
        }
        else
            trace("%ls: not registered\n", Classes[i]);
        pWindowsCreateString(Classes[i], lstrlenW(Classes[i]), &Cls);
        F = NULL;
        hr = pRoGetActivationFactory(Cls, &IID_CmActivationFactory, (void **)&F);
        FactoryHr = hr;
        trace("%ls: RoGetActivationFactory(IActivationFactory) %08lx\n", Classes[i], hr);
        if (F)
        {
            IUnknown *Probe = NULL;
            HRESULT h1 = IUnknown_QueryInterface(F, &IID_CmControllerStatics, (void **)&Probe);
            if (Probe) IUnknown_Release(Probe), Probe = NULL;
            {
                HRESULT h2 = IUnknown_QueryInterface(F, &IID_CmQueueStatics, (void **)&Probe);
                if (Probe) IUnknown_Release(Probe);
                trace("  factory: controller statics %08lx, queue statics %08lx\n", h1, h2);
            }
            /* ActivateInstance: these classes have no default constructor */
            Obj = NULL;
            hr = ((HRESULT (STDMETHODCALLTYPE *)(IUnknown *, IInspectable **))(((void **)*(void ***)F)[6]))(F, &Obj);
            trace("  ActivateInstance %08lx %p\n", hr, Obj);
            ok(FAILED(hr), "%ls: ActivateInstance returned %08lx\n", Classes[i], hr);
            if (SUCCEEDED(hr) && Obj) IInspectable_Release(Obj);
            IUnknown_Release(F);
        }
        if (i <= 1)
            ok(SUCCEEDED(FactoryHr), "%ls: no activation factory (%08lx)\n", Classes[i], FactoryHr);
        if (pDllGet)
        {
            F = NULL;
            hr = pDllGet(Cls, &F);
            trace("%ls: CoreMessaging!DllGetActivationFactory %08lx\n", Classes[i], hr);
            if (F) IUnknown_Release(F);
        }
        pWindowsDeleteString(Cls);
    }
    return 0;
}

/* ---- threads against each other ---- */

static BOOL WaitCount(volatile LONG *Count, LONG Until, DWORD Ms)
{
    DWORD End = GetTickCount() + Ms;

    while (*Count < Until)
    {
        if ((LONG)(GetTickCount() - End) >= 0)
            return FALSE;
        Sleep(10);
    }
    return TRUE;
}

typedef struct
{
    HANDLE Ready;       /* the queue exists */
    HANDLE Go;          /* dispatch messages now */
    HANDLE Stop;        /* end the thread */
    HANDLE Thread;
    CmController *C;
    CmQueue *Q;
    DWORD ThreadId;
} PumpCtx;

/* a thread with a queue of its own (for the current thread) and a message loop that the test starts and stops */
static DWORD WINAPI PumpThread(void *Param)
{
    PumpCtx *P = Param;
    HRESULT hr;
    MSG msg;

    P->ThreadId = GetCurrentThreadId();
    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &P->C);
    ok(hr == S_OK, "CreateDispatcherQueueController(current) returned %08lx\n", hr);
    if (hr == S_OK && P->C)
        P->C->lpVtbl->get_DispatcherQueue(P->C, &P->Q);
    SetEvent(P->Ready);
    WaitForSingleObject(P->Go, 20000);
    for (;;)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (WaitForSingleObject(P->Stop, 0) == WAIT_OBJECT_0)
            break;
        MsgWaitForMultipleObjects(1, &P->Stop, FALSE, 1000, QS_ALLINPUT);
    }
    return 0;
}

static BOOL StartPump(PumpCtx *P)
{
    DWORD w;

    memset(P, 0, sizeof(*P));
    P->Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    P->Go = CreateEventW(NULL, TRUE, FALSE, NULL);
    P->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    P->Thread = CreateThread(NULL, 0, PumpThread, P, 0, NULL);
    w = WaitForSingleObject(P->Ready, 10000);
    ok(w == WAIT_OBJECT_0 && P->Q, "the queue thread did not start (%lu)\n", w);
    IsOurs();
    return w == WAIT_OBJECT_0 && P->Q;
}

static void StopPump(PumpCtx *P)
{
    DWORD w;

    SetEvent(P->Go);
    SetEvent(P->Stop);
    w = WaitForSingleObject(P->Thread, 10000);
    ok(w == WAIT_OBJECT_0, "the queue thread did not end (%lu)\n", w);
    if (P->Q) P->Q->lpVtbl->Release(P->Q);
    if (P->C) P->C->lpVtbl->Release(P->C);
    CloseHandle(P->Thread);
    CloseHandle(P->Ready);
    CloseHandle(P->Go);
    CloseHandle(P->Stop);
}

/* TryEnqueue, timers and ShutdownQueueAsync called from a thread other than the queue's */
static void TestCrossThread(void)
{
    PumpCtx P;
    TestHandler H[3];
    TypedHandler Tick, Tick2, Start, Done;
    ActionHandler AH = { { &g_AVtbl }, 1 };
    CmTimer *Tm = NULL, *Tm2 = NULL;
    CmTimeSpan Iv;
    CmToken Tok;
    CmQueue2 *Q2 = NULL;
    CmAsyncAction *Act = NULL;
    CmBool r = 0xcc, Running;
    HRESULT hr;
    LONG n;
    DWORD w, t0;

    if (!StartPump(&P))
    {
        StopPump(&P);
        return;
    }

    /* items from another thread run on the queue thread, in priority order, once it dispatches */
    g_OrderCount = 0;
    for (n = 0; n < 3; n++)
        InitHandler(&H[n], n + 1);
    hr = P.Q->lpVtbl->TryEnqueueWithPriority(P.Q, CmPriorityLow, &H[0].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue(low) from another thread %08lx %u\n", hr, r);
    hr = P.Q->lpVtbl->TryEnqueueWithPriority(P.Q, CmPriorityNormal, &H[1].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue(normal) from another thread %08lx %u\n", hr, r);
    hr = P.Q->lpVtbl->TryEnqueueWithPriority(P.Q, CmPriorityHigh, &H[2].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue(high) from another thread %08lx %u\n", hr, r);
    if (SUCCEEDED(P.Q->lpVtbl->QueryInterface(P.Q, &IID_CmQueue2, (void **)&Q2)) && Q2)
    {
        r = 0xcc;
        Q2->lpVtbl->get_HasThreadAccess(Q2, &r);
        ok(r == 0, "HasThreadAccess %u from another thread\n", r);
        Q2->lpVtbl->Release(Q2);
    }
    Sleep(50);
    ok(g_OrderCount == 0, "%ld items ran before the queue thread dispatched messages\n", g_OrderCount);
    SetEvent(P.Go);
    ok(WaitCount(&g_OrderCount, 3, 10000), "%ld of 3 items ran\n", g_OrderCount);
    trace("cross-thread order: %d %d %d\n", g_Order[0], g_Order[1], g_Order[2]);
    ok(g_Order[0] == 3 && g_Order[1] == 2 && g_Order[2] == 1, "order %d %d %d\n", g_Order[0], g_Order[1], g_Order[2]);
    for (n = 0; n < 3; n++)
        ok(H[n].ThreadId == P.ThreadId, "item %ld ran on thread %lx, not the queue thread %lx\n", n + 1, H[n].ThreadId, P.ThreadId);
    Sleep(50);
    ok(H[0].Ref == 1 && H[1].Ref == 1 && H[2].Ref == 1, "the queue still holds the handlers (%ld %ld %ld)\n", H[0].Ref, H[1].Ref, H[2].Ref);

    /* a timer that another thread starts and stops ticks on the queue thread */
    hr = P.Q->lpVtbl->CreateTimer(P.Q, &Tm);
    ok(hr == S_OK && Tm, "CreateTimer from another thread %08lx\n", hr);
    if (!Tm)
        goto done;
    InitTyped(&Tick);
    Tm->lpVtbl->add_Tick(Tm, &Tick.Iface, &Tok);
    Iv.Duration = 500000; /* 50 ms */
    hr = Tm->lpVtbl->put_Interval(Tm, Iv);
    ok(hr == S_OK, "put_Interval from another thread %08lx\n", hr);
    hr = Tm->lpVtbl->Start(Tm);
    ok(hr == S_OK, "Start from another thread %08lx\n", hr);
    Running = 0xcc;
    Tm->lpVtbl->get_IsRunning(Tm, &Running);
    ok(Running == 1, "IsRunning %u right after Start\n", Running);
    ok(WaitCount(&Tick.Calls, 3, 10000), "%ld ticks after a Start from another thread\n", Tick.Calls);
    ok(Tick.ThreadId == P.ThreadId, "Tick ran on thread %lx, not the queue thread %lx\n", Tick.ThreadId, P.ThreadId);
    hr = Tm->lpVtbl->Stop(Tm);
    ok(hr == S_OK, "Stop from another thread %08lx\n", hr);
    Running = 0xcc;
    Tm->lpVtbl->get_IsRunning(Tm, &Running);
    ok(Running == 0, "IsRunning %u right after Stop\n", Running);
    Sleep(300); /* a tick may have been on its way */
    n = Tick.Calls;
    Sleep(400);
    ok(Tick.Calls == n, "the timer ticked %ld times after Stop\n", Tick.Calls - n);

    /* a Start and a Stop in a row leave it stopped, and it does not show as running in between or after */
    Tm->lpVtbl->Start(Tm);
    Tm->lpVtbl->Stop(Tm);
    Running = 0xcc;
    Tm->lpVtbl->get_IsRunning(Tm, &Running);
    ok(Running == 0, "IsRunning %u after Start and Stop\n", Running);
    Sleep(300);
    n = Tick.Calls;
    Sleep(300);
    ok(Tick.Calls == n, "the timer ticked %ld times after Start and Stop\n", Tick.Calls - n);
    Tm->lpVtbl->get_IsRunning(Tm, &Running);
    ok(Running == 0, "IsRunning %u after Start and Stop settled\n", Running);

    /* a running timer whose interval changes */
    Iv.Duration = 600000000; /* 60 s */
    Tm->lpVtbl->put_Interval(Tm, Iv);
    Tm->lpVtbl->Start(Tm);
    Sleep(150);
    n = Tick.Calls;
    Iv.Duration = 500000;
    hr = Tm->lpVtbl->put_Interval(Tm, Iv);
    t0 = GetTickCount();
    WaitCount(&Tick.Calls, n + 1, 1000);
    trace("interval changed from 60 s to 50 ms on a running timer: put_Interval %08lx, %ld ticks in %lu ms\n", hr,
          Tick.Calls - n, GetTickCount() - t0);
    /* measured on Windows: the new interval is for the next Start (no tick in 3 s) */
    ok(Tick.Calls == n, "the interval of a running timer was applied at once (%ld ticks)\n", Tick.Calls - n);
    Tm->lpVtbl->Stop(Tm);

    /* shutdown from another thread, with a timer started right before it */
    hr = P.Q->lpVtbl->CreateTimer(P.Q, &Tm2);
    ok(hr == S_OK && Tm2, "CreateTimer %08lx\n", hr);
    InitTyped(&Tick2);
    InitTyped(&Start);
    InitTyped(&Done);
    Done.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Start.Expect = P.Q;
    Done.Expect = P.Q;
    g_EventSeq = 0;
    P.Q->lpVtbl->add_ShutdownStarting(P.Q, &Start.Iface, &Tok);
    P.Q->lpVtbl->add_ShutdownCompleted(P.Q, &Done.Iface, &Tok);
    if (Tm2)
    {
        Tm2->lpVtbl->add_Tick(Tm2, &Tick2.Iface, &Tok);
        Tm2->lpVtbl->put_Interval(Tm2, Iv);
        Tm2->lpVtbl->Start(Tm2);
    }
    hr = P.C->lpVtbl->ShutdownQueueAsync(P.C, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync from another thread %08lx\n", hr);
    if (Act)
    {
        hr = Act->lpVtbl->put_Completed(Act, &AH.Iface);
        ok(hr == S_OK, "put_Completed %08lx\n", hr);
    }
    w = WaitForSingleObject(Done.Event, 10000);
    ok(w == WAIT_OBJECT_0, "ShutdownCompleted did not come (%lu)\n", w);
    ok(Start.Calls == 1 && Done.Calls == 1, "events: starting %ld, completed %ld\n", Start.Calls, Done.Calls);
    ok(Start.ThreadId == P.ThreadId && Done.ThreadId == P.ThreadId, "events ran on %lx %lx, not the queue thread %lx\n",
       Start.ThreadId, Done.ThreadId, P.ThreadId);
    ok(Start.Order == 1 && Done.Order == 2, "event order %ld %ld\n", Start.Order, Done.Order);
    Sleep(100);
    if (Act)
    {
        trace("shutdown asked for from another thread: completed handler %ld calls, status %d, on %s thread\n", AH.Calls,
              AH.Status, AH.ThreadId == P.ThreadId ? "the queue" : "another");
        ok(AH.Calls == 1 && AH.Status == CmAsyncCompleted, "completed handler: %ld calls, status %d\n", AH.Calls, AH.Status);
        Act->lpVtbl->Release(Act);
    }
    if (Tm2)
    {
        /* Windows (measured) leaves such a timer running and ticking; here it ends with its queue */
        Running = 0xcc;
        Tm2->lpVtbl->get_IsRunning(Tm2, &Running);
        trace("a timer started right before the shutdown: running %u after it\n", Running);
        if (IsOurs())
            ok(Running == 0, "a timer started right before the shutdown is running after it (%u)\n", Running);
        n = Tick2.Calls;
        Sleep(300);
        trace("  %ld ticks in the 300 ms after the shutdown\n", Tick2.Calls - n);
        if (IsOurs())
            ok(Tick2.Calls == n, "a timer ticked %ld times after the shutdown\n", Tick2.Calls - n);
        Tm2->lpVtbl->Stop(Tm2);
        n = Tick2.Calls;
        hr = Tm2->lpVtbl->Start(Tm2);
        ok(hr == S_OK, "Start after the shutdown: %08lx\n", hr);
        Running = 0xcc;
        Tm2->lpVtbl->get_IsRunning(Tm2, &Running);
        trace("Start after the shutdown: %08lx, running %u\n", hr, Running);
        Sleep(200);
        if (IsOurs())
        {
            Tm2->lpVtbl->get_IsRunning(Tm2, &Running);
            ok(Running == 0, "a timer started after the shutdown is running (%u)\n", Running);
            ok(Tick2.Calls == n, "a timer started after the shutdown ticked\n");
        }
        Tm2->lpVtbl->Stop(Tm2);
        Tm2->lpVtbl->Release(Tm2);
    }
    r = 0xcc;
    InitHandler(&H[0], 9);
    hr = P.Q->lpVtbl->TryEnqueue(P.Q, &H[0].Iface, &r);
    ok(hr == S_OK && r == 0, "TryEnqueue from another thread after the shutdown %08lx %u\n", hr, r);
    ok(H[0].Ref == 1, "a refused handler is held (%ld)\n", H[0].Ref);
    Act = NULL;
    hr = P.C->lpVtbl->ShutdownQueueAsync(P.C, &Act);
    ok(hr == E_UNEXPECTED, "second ShutdownQueueAsync %08lx\n", hr);
    if (SUCCEEDED(hr) && Act) Act->lpVtbl->Release(Act);
    CloseHandle(Done.Event);

done:
    if (Tm)
        Tm->lpVtbl->Release(Tm);
    StopPump(&P);
}

/* items that were queued before ShutdownQueueAsync, and an item that arrives right after it */
static void TestShutdownWithWork(void)
{
    PumpCtx P;
    TestHandler H[4];
    TypedHandler Start, Done;
    CmAsyncAction *Act = NULL;
    CmToken Tok;
    CmBool r;
    HRESULT hr;
    DWORD w;
    int i;

    if (!StartPump(&P))
    {
        StopPump(&P);
        return;
    }
    InitTyped(&Start);
    InitTyped(&Done);
    Done.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    P.Q->lpVtbl->add_ShutdownStarting(P.Q, &Start.Iface, &Tok);
    P.Q->lpVtbl->add_ShutdownCompleted(P.Q, &Done.Iface, &Tok);
    g_OrderCount = 0;
    for (i = 0; i < 4; i++)
        InitHandler(&H[i], i + 1);
    for (i = 0; i < 3; i++)
    {
        hr = P.Q->lpVtbl->TryEnqueue(P.Q, &H[i].Iface, &r);
        ok(hr == S_OK && r == 1, "TryEnqueue %08lx %u\n", hr, r);
    }
    hr = P.C->lpVtbl->ShutdownQueueAsync(P.C, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync %08lx\n", hr);
    r = 0xcc;
    hr = P.Q->lpVtbl->TryEnqueue(P.Q, &H[3].Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue right after ShutdownQueueAsync: %08lx %u\n", hr, r);
    SetEvent(P.Go);
    w = WaitForSingleObject(Done.Event, 10000);
    ok(w == WAIT_OBJECT_0, "ShutdownCompleted did not come (%lu)\n", w);
    trace("work queued before ShutdownQueueAsync ran: %d %d %d; queued right after: %d (completed %ld)\n",
          H[0].ThreadId != 0, H[1].ThreadId != 0, H[2].ThreadId != 0, H[3].ThreadId != 0, Done.Calls);
    ok(H[0].ThreadId && H[1].ThreadId && H[2].ThreadId, "work queued before the shutdown was dropped (%lx %lx %lx)\n",
       H[0].ThreadId, H[1].ThreadId, H[2].ThreadId);
    ok(H[3].ThreadId, "work queued right after ShutdownQueueAsync was dropped\n");
    Sleep(100);
    for (i = 0; i < 4; i++)
        ok(H[i].Ref == 1, "handler %d is still held (%ld)\n", i, H[i].Ref);
    if (Act) Act->lpVtbl->Release(Act);
    CloseHandle(Done.Event);
    StopPump(&P);
}

static DWORD WINAPI CompleteThread(void *Param)
{
    CmDeferral *D = Param;
    HRESULT hr;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    hr = D->lpVtbl->Complete(D);
    ok(hr == S_OK, "Complete from another thread %08lx\n", hr);
    return 0;
}

/* a deferral held after the handler returned, completed on another thread */
static DWORD WINAPI DeferralOffThread(void *Param)
{
    CmController *C = NULL;
    CmQueue *Q = NULL;
    TypedHandler Start, Done;
    TestHandler Y;
    CmAsyncAction *Act = NULL;
    CmToken Tok;
    CmBool r;
    HRESULT hr;

    CoInitializeEx(NULL, COINIT_MULTITHREADED); /* GetDeferral needs it on Windows */
    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &C);
    ok(hr == S_OK, "CreateDispatcherQueueController(current) returned %08lx\n", hr);
    if (hr != S_OK || !C)
        return 0;
    C->lpVtbl->get_DispatcherQueue(C, &Q);
    InitTyped(&Start);
    InitTyped(&Done);
    Start.KeepDeferral = TRUE;
    Q->lpVtbl->add_ShutdownStarting(Q, &Start.Iface, &Tok);
    Q->lpVtbl->add_ShutdownCompleted(Q, &Done.Iface, &Tok);
    hr = C->lpVtbl->ShutdownQueueAsync(C, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync %08lx\n", hr);
    Pump(5000, &Start.Calls, 1);
    ok(Start.Calls == 1 && Start.Deferral, "ShutdownStarting: %ld calls, deferral %p (%08lx)\n", Start.Calls, Start.Deferral, Start.DeferralHr);
    if (Start.Calls == 1 && Start.Deferral)
    {
        /* work that arrives while the deferral is out: whether it runs is recorded, not asserted */
        InitHandler(&Y, 5);
        r = 0xcc;
        hr = Q->lpVtbl->TryEnqueue(Q, &Y.Iface, &r);
        Pump(300, NULL, 0);
        trace("TryEnqueue with a deferral outstanding: %08lx %u, item ran %d\n", hr, r, Y.ThreadId != 0);
        ok(Done.Calls == 0, "ShutdownCompleted came while a deferral was outstanding\n");
        RunOnThread(CompleteThread, Start.Deferral);
        Pump(5000, &Done.Calls, 1);
        ok(Done.Calls == 1, "ShutdownCompleted did not come after the deferral completed on another thread\n");
        ok(Done.ThreadId == GetCurrentThreadId(), "ShutdownCompleted ran on thread %lx\n", Done.ThreadId);
    }
    if (Start.Deferral) Start.Deferral->lpVtbl->Release(Start.Deferral);
    if (Start.KeptArgs) Start.KeptArgs->lpVtbl->Release(Start.KeptArgs);
    if (Act) Act->lpVtbl->Release(Act);
    Q->lpVtbl->Release(Q);
    C->lpVtbl->Release(C);
    Pump(50, NULL, 0);
    return 0;
}

static void LateHook(void *Arg)
{
    TypedHandler *S = Arg;

    /* the last deferral completes: the end of the shutdown is posted to the window, and not dispatched until this
     * item returns. Then another deferral is asked for. */
    S->Deferral->lpVtbl->Complete(S->Deferral);
    S->LateHr = S->KeptArgs->lpVtbl->GetDeferral(S->KeptArgs, &S->Late);
}

/* a deferral asked for after the last one completed, before the shutdown moved on */
static DWORD WINAPI DeferralLate(void *Param)
{
    CmController *C = NULL;
    CmQueue *Q = NULL;
    TypedHandler Start, Done;
    TestHandler X;
    CmAsyncAction *Act = NULL;
    CmAsyncInfo *Info = NULL;
    CmToken Tok;
    CmBool r;
    HRESULT hr;
    int Status = -1;

    CoInitializeEx(NULL, COINIT_MULTITHREADED); /* GetDeferral needs it on Windows */
    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &C);
    ok(hr == S_OK, "CreateDispatcherQueueController(current) returned %08lx\n", hr);
    if (hr != S_OK || !C)
        return 0;
    C->lpVtbl->get_DispatcherQueue(C, &Q);
    InitTyped(&Start);
    InitTyped(&Done);
    Start.KeepDeferral = TRUE;
    Q->lpVtbl->add_ShutdownStarting(Q, &Start.Iface, &Tok);
    Q->lpVtbl->add_ShutdownCompleted(Q, &Done.Iface, &Tok);
    hr = C->lpVtbl->ShutdownQueueAsync(C, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync %08lx\n", hr);
    Pump(5000, &Start.Calls, 1);
    ok(Start.Calls == 1 && Start.Deferral, "ShutdownStarting: %ld calls, deferral %p\n", Start.Calls, Start.Deferral);
    if (Start.Calls == 1 && Start.Deferral && Start.KeptArgs)
    {
        InitHandler(&X, 1);
        X.Hook = LateHook;
        X.HookArg = &Start;
        r = 0xcc;
        hr = Q->lpVtbl->TryEnqueue(Q, &X.Iface, &r);
        Pump(500, NULL, 0);
        trace("late deferral: item ran %d, GetDeferral %08lx, ShutdownCompleted calls %ld\n", X.ThreadId != 0, Start.LateHr, Done.Calls);
        if (SUCCEEDED(Start.LateHr) && Start.Late)
        {
            if (!Done.Calls)
            {
                Start.Late->lpVtbl->Complete(Start.Late);
                Pump(5000, &Done.Calls, 1);
            }
            Start.Late->lpVtbl->Release(Start.Late);
        }
        else
            Pump(5000, &Done.Calls, 1);
        ok(Done.Calls == 1, "ShutdownCompleted %ld times, the shutdown did not complete\n", Done.Calls);
    }
    if (Act)
    {
        Act->lpVtbl->QueryInterface(Act, &IID_CmAsyncInfo, (void **)&Info);
        if (Info)
        {
            Info->lpVtbl->get_Status(Info, &Status);
            ok(Status == CmAsyncCompleted, "shutdown action status %d\n", Status);
            Info->lpVtbl->Release(Info);
        }
        Act->lpVtbl->Release(Act);
    }
    if (Start.Deferral) Start.Deferral->lpVtbl->Release(Start.Deferral);
    if (Start.KeptArgs) Start.KeptArgs->lpVtbl->Release(Start.KeptArgs);
    Q->lpVtbl->Release(Q);
    C->lpVtbl->Release(C);
    Pump(50, NULL, 0);
    return 0;
}

typedef struct
{
    CmController *C;
    CmQueue *Q;
    CmTimer *Tm;
    TestHandler Pending;
} ExitCtx;

/* a thread that makes a queue and ends without shutting it down */
static DWORD WINAPI ExitingThread(void *Param)
{
    ExitCtx *E = Param;
    HRESULT hr;
    CmBool r;
    CmTimeSpan Iv = { 10000000 };

    hr = pCreate(Opts(sizeof(CmOptions), 2, 0), &E->C);
    ok(hr == S_OK, "CreateDispatcherQueueController(current) returned %08lx\n", hr);
    if (hr != S_OK || !E->C)
        return 0;
    E->C->lpVtbl->get_DispatcherQueue(E->C, &E->Q);
    InitHandler(&E->Pending, 1);
    hr = E->Q->lpVtbl->TryEnqueue(E->Q, &E->Pending.Iface, &r); /* never dispatched */
    ok(hr == S_OK && r == 1, "TryEnqueue %08lx %u\n", hr, r);
    if (SUCCEEDED(E->Q->lpVtbl->CreateTimer(E->Q, &E->Tm)) && E->Tm)
    {
        E->Tm->lpVtbl->put_Interval(E->Tm, Iv);
        E->Tm->lpVtbl->Start(E->Tm);
    }
    return 0;
}

static void TestThreadExit(void)
{
    ExitCtx E;
    TestHandler H;
    CmAsyncAction *Act = NULL;
    CmAsyncInfo *Info = NULL;
    CmBool r, Running;
    HANDLE Th;
    HRESULT hr;
    DWORD w;
    int Status = -1;

    memset(&E, 0, sizeof(E));
    Th = CreateThread(NULL, 0, ExitingThread, &E, 0, NULL);
    w = WaitForSingleObject(Th, 10000);
    ok(w == WAIT_OBJECT_0, "the thread did not end (%lu)\n", w);
    CloseHandle(Th);
    if (!E.Q)
        return;
    Sleep(100);

    InitHandler(&H, 2);
    r = 0xcc;
    hr = E.Q->lpVtbl->TryEnqueue(E.Q, &H.Iface, &r);
    trace("TryEnqueue after the queue thread ended: %08lx %u, handler refs %ld\n", hr, r, H.Ref);
    ok(hr == S_OK, "TryEnqueue after the queue thread ended %08lx %u\n", hr, r);
    if (r == 0)
        ok(H.Ref == 1, "a refused handler is held (%ld)\n", H.Ref);
    trace("item queued before the thread ended: refs %ld, ran %d\n", E.Pending.Ref, E.Pending.ThreadId != 0);
    ok(E.Pending.ThreadId == 0, "the item ran\n");
    /* Windows (measured) accepts the item, holds it for ever and returns TRUE; this implementation refuses work
     * for a queue without a thread and lets go of what was queued */
    if (IsOurs())
    {
        ok(r == 0, "TryEnqueue after the queue thread ended returned %u\n", r);
        ok(E.Pending.Ref == 1, "an item that can never run is still held (%ld)\n", E.Pending.Ref);
    }

    if (E.Tm)
    {
        Running = 0xcc;
        E.Tm->lpVtbl->get_IsRunning(E.Tm, &Running);
        trace("timer of the ended thread: running %u\n", Running);
        if (IsOurs())
            ok(Running == 0, "a timer of an ended thread is running (%u)\n", Running);
        hr = E.Tm->lpVtbl->Start(E.Tm);
        ok(hr == S_OK, "Start from another thread, queue thread ended: %08lx\n", hr);
        Running = 0xcc;
        E.Tm->lpVtbl->get_IsRunning(E.Tm, &Running);
        trace("Start from another thread, queue thread ended: %08lx, running %u\n", hr, Running);
        if (IsOurs())
            ok(Running == 0, "a timer of an ended thread was started (%u)\n", Running);
        hr = E.Tm->lpVtbl->Stop(E.Tm);
        trace("Stop: %08lx\n", hr);
        E.Tm->lpVtbl->Release(E.Tm);
    }
    hr = E.C->lpVtbl->ShutdownQueueAsync(E.C, &Act);
    ok(hr == S_OK, "ShutdownQueueAsync after the queue thread ended: %08lx\n", hr);
    /* Windows (measured) leaves that action started for ever; here it is complete */
    if (SUCCEEDED(hr) && Act)
    {
        if (SUCCEEDED(Act->lpVtbl->QueryInterface(Act, &IID_CmAsyncInfo, (void **)&Info)) && Info)
        {
            Info->lpVtbl->get_Status(Info, &Status);
            trace("  action status %d\n", Status);
            Info->lpVtbl->Release(Info);
        }
        Act->lpVtbl->Release(Act);
    }
    E.Q->lpVtbl->Release(E.Q);
    E.C->lpVtbl->Release(E.C);
}

/* ---- thread type x apartment option x apartment of the calling thread ---- */

/* Measured on Windows 10 22H2 (2026-11-12, x64 and x86), each cell on a fresh thread: DQTYPE_THREAD_CURRENT with
 * COM_NONE, COM_ASTA and COM_STA all return S_OK on a thread in no apartment, in an STA and in the MTA (the first
 * version of this file had E_INVALIDARG for ASTA and STA); the calling thread keeps the apartment it had; a second
 * controller for the thread is RPC_E_WRONG_THREAD. DQTYPE_THREAD_DEDICATED with ASTA or STA is S_OK from all three,
 * and with COM_NONE it ends the process, so that cell runs only on this implementation. Not measured: whether the
 * queue of a current thread outside the requested apartment dispatches (the probe's handler was not agile:
 * TryEnqueue is RO_E_MUST_BE_AGILE then), so that is only traced where the apartment does not match. */
#define CELL(Type, Apt, Caller) ((void *)(ULONG_PTR)(((Type) << 8) | ((Apt) << 4) | (Caller)))

static DWORD WINAPI MatrixThread(void *Param)
{
    static const char *const AptNames[] = { "COM_NONE", "COM_ASTA", "COM_STA" };
    static const char *const CallerNames[] = { "no apartment", "STA", "MTA" };
    int Type = ((ULONG_PTR)Param >> 8) & 0xf, Apt = ((ULONG_PTR)Param >> 4) & 0xf, Caller = (ULONG_PTR)Param & 0xf;
    int T0 = -1, Q0 = -1, T1 = -1, Q1 = -1;
    HRESULT hr, hr0 = E_NOTIMPL, hr1 = E_NOTIMPL;
    CmController *C = (CmController *)(ULONG_PTR)0x1234, *C2 = (CmController *)(ULONG_PTR)0x1234;
    CmQueue *Q = NULL, *Cur;
    CmAsyncAction *Act = NULL;
    TestHandler H;
    CmBool r = 0;
    LONG Before;
    char Cell[96];

    wsprintfA(Cell, "%s, %s, caller in %s", Type == 2 ? "current thread" : "dedicated thread", AptNames[Apt], CallerNames[Caller]);
    if (Caller == 1)
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    else if (Caller == 2)
        CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (pCoGetApartmentType)
        hr0 = pCoGetApartmentType(&T0, &Q0);

    hr = pCreate(Opts(sizeof(CmOptions), Type, Apt), &C);
    ok(hr == S_OK, "%s: CreateDispatcherQueueController returned %08lx\n", Cell, hr);
    if (hr != S_OK || !C || C == (CmController *)(ULONG_PTR)0x1234)
        return 0;

    if (pCoGetApartmentType)
        hr1 = pCoGetApartmentType(&T1, &Q1);
    ok(hr0 == hr1 && T0 == T1 && Q0 == Q1, "%s: the apartment of the caller changed from %08lx %d %d to %08lx %d %d\n", Cell,
       hr0, T0, Q0, hr1, T1, Q1);

    hr = C->lpVtbl->get_DispatcherQueue(C, &Q);
    ok(hr == S_OK && Q, "%s: get_DispatcherQueue returned %08lx\n", Cell, hr);
    if (!Q)
    {
        C->lpVtbl->Release(C);
        return 0;
    }
    Cur = ForCurrentThread();
    if (Type == 2)
    {
        ok(SameObject(Cur, Q), "%s: GetForCurrentThread gives %p, not the queue %p\n", Cell, Cur, Q);
        hr = pCreate(Opts(sizeof(CmOptions), Type, Apt), &C2);
        ok(hr == RPC_E_WRONG_THREAD, "%s: a second controller returned %08lx\n", Cell, hr);
        if (hr == S_OK && C2 != (CmController *)(ULONG_PTR)0x1234)
            C2->lpVtbl->Release(C2);

        InitHandler(&H, 1);
        Before = g_OrderCount;
        hr = Q->lpVtbl->TryEnqueue(Q, &H.Iface, &r);
        ok(hr == S_OK && r == 1, "%s: TryEnqueue returned %08lx %u\n", Cell, hr, r);
        Pump(2000, &g_OrderCount, Before + 1);
        if (g_OrderCount > Before)
            ok(H.ThreadId == GetCurrentThreadId(), "%s: the item ran on thread %lx\n", Cell, H.ThreadId);
        else if ((Apt == 0) || (Apt == 1 && Caller == 1) || (Apt == 2 && Caller == 1))
            ok(0, "%s: the item did not run\n", Cell);
        else
            trace("%s: the item did not run\n", Cell);
    }
    else
        ok(Cur == NULL, "%s: the calling thread has queue %p\n", Cell, Cur);
    if (Cur) Cur->lpVtbl->Release(Cur);

    hr = C->lpVtbl->ShutdownQueueAsync(C, &Act);
    ok(hr == S_OK, "%s: ShutdownQueueAsync returned %08lx\n", Cell, hr);
    if (Type == 2)
        Pump(300, NULL, 0);
    if (Act) Act->lpVtbl->Release(Act);
    Q->lpVtbl->Release(Q);
    C->lpVtbl->Release(C);
    return 0;
}

static void TestMatrix(void)
{
    int Type, Apt, Caller;

    for (Type = 2; Type >= 1; Type--)
        for (Apt = 0; Apt <= 2; Apt++)
            for (Caller = 0; Caller <= 2; Caller++)
            {
                if (Type == 1 && Apt == 0 && !IsOurs()) /* ends the process on Windows */
                    continue;
                RunOnThread(MatrixThread, CELL(Type, Apt, Caller));
            }
}

START_TEST(DispatcherQueueThreads)
{
    HMODULE Mod = LoadLibraryW(L"CoreMessaging.dll");

    ok(Mod != NULL, "CoreMessaging.dll does not load (%lu)\n", GetLastError());
    if (!Mod)
        return;
    pCreate = (PFN_CREATE_DQC)GetProcAddress(Mod, "CreateDispatcherQueueController");
    ok(pCreate != NULL, "CreateDispatcherQueueController is not exported\n");
    if (!pCreate)
        return;

    TestCrossThread();
    TestShutdownWithWork();
    RunOnThread(DeferralOffThread, NULL);
    RunOnThread(DeferralLate, NULL);
    TestThreadExit();
}

/* ---- messages from another process ---- */

static const WCHAR g_WindowClass[] = L"ReactOS.DispatcherQueue";

static int FindOwnWindows(HWND *List, int Max)
{
    HWND h = NULL;
    int n = 0;

    while (n < Max && (h = FindWindowExW(HWND_MESSAGE, h, g_WindowClass, NULL)))
    {
        DWORD Pid = 0;
        GetWindowThreadProcessId(h, &Pid);
        if (Pid == GetCurrentProcessId())
            List[n++] = h;
    }
    return n;
}

/* this program in another process: <exe> DispatcherQueueForge <mode> <hwnd>... */
static void RunForger(const WCHAR *Mode, HWND *List, int Count)
{
    WCHAR Path[MAX_PATH], Cmd[MAX_PATH + 200];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD Code = 0xcc, w;
    int i, len;

    GetModuleFileNameW(NULL, Path, MAX_PATH);
    len = wsprintfW(Cmd, L"\"%s\" DispatcherQueueForge %s", Path, Mode);
    for (i = 0; i < Count; i++)
        len += wsprintfW(Cmd + len, L" %I64x", (UINT64)(ULONG_PTR)List[i]);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        skip("cannot start the second process (%lu)\n", GetLastError());
        return;
    }
    w = WaitForSingleObject(pi.hProcess, 30000);
    ok(w == WAIT_OBJECT_0, "the second process did not end (%lu)\n", w);
    if (w != WAIT_OBJECT_0)
        TerminateProcess(pi.hProcess, 1);
    GetExitCodeProcess(pi.hProcess, &Code);
    ok(Code == 0, "the second process ended with %lx\n", Code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

/* what a program could post or send to a queue window of somebody else */
static void ForgeFrom(char **argv, int argc)
{
    BOOL Running = !strcmp(argv[2], "run");
    int i;

    for (i = 3; i < argc; i++)
    {
        HWND h = (HWND)(ULONG_PTR)_strtoui64(argv[i], NULL, 16);
        DWORD_PTR Res;

        if (!IsWindow(h))
            continue;
        PostMessageW(h, WM_USER + 4, 1, (LPARAM)(ULONG_PTR)0x41414141);
        PostMessageW(h, WM_USER + 4, 0, (LPARAM)-1);
        PostMessageW(h, WM_USER + 4, 1, 0);
        PostMessageW(h, WM_USER + 3, 0, 0);
        PostMessageW(h, WM_USER + 2, 0, 0);
        if (Running)
        {
            PostMessageW(h, WM_USER + 1, 0, 0);
            PostMessageW(h, WM_CLOSE, 0, 0);
            PostMessageW(h, WM_QUIT, 0, 0);
            SendMessageTimeoutW(h, WM_USER + 2, 0, 0, SMTO_ABORTIFHUNG, 3000, &Res);
            SendMessageTimeoutW(h, WM_USER + 3, 0, 0, SMTO_ABORTIFHUNG, 3000, &Res);
            SendMessageTimeoutW(h, WM_USER + 4, 1, (LPARAM)(ULONG_PTR)0x41414141, SMTO_ABORTIFHUNG, 3000, &Res);
        }
    }
}

static void TestForged(void)
{
    HMODULE Mod = LoadLibraryW(L"CoreMessaging.dll");
    PumpCtx P;
    CmController *D = NULL;
    CmQueue *DQ = NULL;
    CmTimer *Tm = NULL;
    TypedHandler StartC, StartD, Tick, Hold, Done;
    TestHandler H, A, B;
    CmAsyncAction *Act = NULL;
    CmToken Tok;
    CmTimeSpan Iv = { 500000 };
    CmBool r;
    HWND Wnd[8], DedicatedWnd = NULL;
    HRESULT hr;
    DWORD w;
    int n, k;

    if (!Mod || !(pCreate = (PFN_CREATE_DQC)GetProcAddress(Mod, "CreateDispatcherQueueController")))
    {
        skip("no CoreMessaging.dll\n");
        return;
    }
    if (!StartPump(&P))
    {
        StopPump(&P);
        return;
    }
    SetEvent(P.Go);
    hr = pCreate(Opts(sizeof(CmOptions), 1, 0), &D);
    ok(hr == S_OK, "CreateDispatcherQueueController(dedicated) returned %08lx\n", hr);
    if (hr != S_OK || !D)
    {
        StopPump(&P);
        return;
    }
    D->lpVtbl->get_DispatcherQueue(D, &DQ);
    /* the window of a dedicated queue is made on its thread: it is there once an item has run */
    InitHandler(&H, 1);
    H.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    DQ->lpVtbl->TryEnqueue(DQ, &H.Iface, &r);
    WaitForSingleObject(H.Event, 5000);
    n = FindOwnWindows(Wnd, 8);
    if (n < 2)
    {
        skip("this is not the ReactOS CoreMessaging: no queue windows of class %ls (%d found)\n", g_WindowClass, n);
        goto out;
    }
    trace("%d queue windows\n", n);
    for (k = 0; k < n; k++)
        if (GetWindowThreadProcessId(Wnd[k], NULL) != P.ThreadId)
            DedicatedWnd = Wnd[k];
    InitTyped(&StartC);
    InitTyped(&StartD);
    P.Q->lpVtbl->add_ShutdownStarting(P.Q, &StartC.Iface, &Tok);
    DQ->lpVtbl->add_ShutdownStarting(DQ, &StartD.Iface, &Tok);

    /* running queues: nothing happens, and the processes survive */
    RunForger(L"run", Wnd, n);
    Sleep(200);
    ok(StartC.Calls == 0 && StartD.Calls == 0, "a posted message shut a queue down (%ld, %ld)\n", StartC.Calls, StartD.Calls);
    for (k = 0; k < n; k++)
        ok(IsWindow(Wnd[k]), "queue window %d was destroyed by another process\n", k);

    /* both queues still work: items, and a timer */
    g_OrderCount = 0;
    InitHandler(&A, 1);
    InitHandler(&B, 2);
    r = 0;
    hr = P.Q->lpVtbl->TryEnqueue(P.Q, &A.Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue on the queue of the thread %08lx %u\n", hr, r);
    r = 0;
    hr = DQ->lpVtbl->TryEnqueue(DQ, &B.Iface, &r);
    ok(hr == S_OK && r == 1, "TryEnqueue on the dedicated queue %08lx %u\n", hr, r);
    ok(WaitCount(&g_OrderCount, 2, 10000), "after the posts, %ld of 2 items ran\n", g_OrderCount);
    ok(A.ThreadId == P.ThreadId, "item ran on thread %lx\n", A.ThreadId);
    ok(B.ThreadId && B.ThreadId != P.ThreadId, "item ran on thread %lx\n", B.ThreadId);
    InitTyped(&Tick);
    if (SUCCEEDED(P.Q->lpVtbl->CreateTimer(P.Q, &Tm)) && Tm)
    {
        Tm->lpVtbl->add_Tick(Tm, &Tick.Iface, &Tok);
        Tm->lpVtbl->put_Interval(Tm, Iv);
        Tm->lpVtbl->Start(Tm);
        ok(WaitCount(&Tick.Calls, 2, 10000), "after the posts, %ld timer ticks\n", Tick.Calls);
        Tm->lpVtbl->Stop(Tm);
        Tm->lpVtbl->Release(Tm);
    }

    /* a shutdown under way, held open by a deferral: a posted finish or shutdown does not end it */
    InitTyped(&Hold);
    InitTyped(&Done);
    Hold.KeepDeferral = TRUE;
    Hold.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    DQ->lpVtbl->add_ShutdownStarting(DQ, &Hold.Iface, &Tok);
    DQ->lpVtbl->add_ShutdownCompleted(DQ, &Done.Iface, &Tok);
    hr = D->lpVtbl->ShutdownQueueAsync(D, &Act);
    ok(hr == S_OK && Act, "ShutdownQueueAsync %08lx\n", hr);
    w = WaitForSingleObject(Hold.Event, 10000);
    ok(w == WAIT_OBJECT_0 && Hold.Deferral, "ShutdownStarting did not come (%lu)\n", w);
    if (DedicatedWnd)
    {
        RunForger(L"shut", &DedicatedWnd, 1);
        Sleep(300);
        ok(Done.Calls == 0, "a posted message finished a shutdown that a deferral holds open (%ld)\n", Done.Calls);
        ok(IsWindow(DedicatedWnd), "the queue window of a shutdown under way was destroyed\n");
    }
    if (Hold.Deferral)
    {
        Hold.Deferral->lpVtbl->Complete(Hold.Deferral);
        Hold.Deferral->lpVtbl->Release(Hold.Deferral);
    }
    if (Hold.KeptArgs) Hold.KeptArgs->lpVtbl->Release(Hold.KeptArgs);
    ok(WaitCount(&Done.Calls, 1, 10000), "the shutdown did not complete once the deferral did\n");
    if (Act) Act->lpVtbl->Release(Act);
    CloseHandle(Hold.Event);
out:
    CloseHandle(H.Event);
    DQ->lpVtbl->Release(DQ);
    D->lpVtbl->Release(D);
    StopPump(&P);
}

START_TEST(DispatcherQueueForge)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 4)
        ForgeFrom(argv, argc); /* the other process */
    else
        TestForged();
}

START_TEST(DispatcherQueue)
{
    HMODULE Mod = LoadLibraryW(L"CoreMessaging.dll");
    HMODULE Combase = LoadLibraryW(L"combase.dll");
    HMODULE Ole32 = GetModuleHandleW(L"ole32.dll");
    HSTRING Cls = NULL;
    HRESULT hr;

    ok(Mod != NULL, "CoreMessaging.dll does not load (%lu)\n", GetLastError());
    if (!Mod || !Combase)
        return;
    pCreate = (PFN_CREATE_DQC)GetProcAddress(Mod, "CreateDispatcherQueueController");
    ok(pCreate != NULL, "CreateDispatcherQueueController is not exported\n");
    ok(GetProcAddress(Mod, "DllGetActivationFactory") != NULL, "DllGetActivationFactory is not exported\n");
    ok(GetProcAddress(Mod, "DllCanUnloadNow") != NULL, "DllCanUnloadNow is not exported\n");
    pRoGetActivationFactory = (void *)GetProcAddress(Combase, "RoGetActivationFactory");
    pWindowsCreateString = (void *)GetProcAddress(Combase, "WindowsCreateString");
    pWindowsDeleteString = (void *)GetProcAddress(Combase, "WindowsDeleteString");
    pWindowsGetStringRawBuffer = (void *)GetProcAddress(Combase, "WindowsGetStringRawBuffer");
    pRoInitialize = (void *)GetProcAddress(Combase, "RoInitialize");
    pRoUninitialize = (void *)GetProcAddress(Combase, "RoUninitialize");
    pCoGetApartmentType = (void *)GetProcAddress(Combase, "CoGetApartmentType");
    if (!pCoGetApartmentType && Ole32)
        pCoGetApartmentType = (void *)GetProcAddress(Ole32, "CoGetApartmentType");
    if (!pCreate || !pRoGetActivationFactory)
        return;

    /* the statics work from any thread and need no Windows Runtime initialization of their own */
    pWindowsCreateString(L"Windows.System.DispatcherQueue", 30, &Cls);
    hr = pRoGetActivationFactory(Cls, &IID_CmQueueStatics, (void **)&g_QueueStatics);
    trace("RoGetActivationFactory(DispatcherQueue) without RoInitialize: %08lx\n", hr);
    if (FAILED(hr))
    {
        pRoInitialize(1);
        hr = pRoGetActivationFactory(Cls, &IID_CmQueueStatics, (void **)&g_QueueStatics);
    }
    ok(hr == S_OK, "RoGetActivationFactory(DispatcherQueue) %08lx\n", hr);
    pWindowsDeleteString(Cls);

    RunOnThread(ArgsThread, NULL);
    RunOnThread(CurrentThread, NULL);
    TestMatrix();
    if (IsOurs()) /* ends the process on Windows */
        TestDedicated(0, FALSE);
    TestDedicated(1, FALSE);
    TestDedicated(2, FALSE);
    TestDedicated(0, TRUE);
    RunOnThread(FactoryThread, NULL);

    if (g_QueueStatics)
        g_QueueStatics->lpVtbl->Release(g_QueueStatics);
}
