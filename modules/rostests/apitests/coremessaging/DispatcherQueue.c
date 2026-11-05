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

    /* Windows 10 22H2 ends the process for an unknown apartment type (measured), so that, a NULL controller
     * pointer and a COM apartment for the current thread (neither measured) are not tried */

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
    ok(FAILED(hr), "a second controller on the same thread: %08lx\n", hr);
    if (SUCCEEDED(hr) && C2) C2->lpVtbl->Release(C2);

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
    H[4].Result = E_FAIL; /* a failing item does not stop the queue */
    hr = Q->lpVtbl->TryEnqueueWithPriority(Q, 5, &H[4].Iface, &r);
    trace("TryEnqueue(priority 5): %08lx %u\n", hr, r);
    ok(H[0].Ref > 1, "the queue holds no reference to the handler (%ld)\n", H[0].Ref);
    hr = Q->lpVtbl->TryEnqueue(Q, NULL, &r);
    trace("TryEnqueue(NULL): %08lx\n", hr);
    ok(FAILED(hr), "TryEnqueue(NULL) returned %08lx\n", hr);
    Sleep(50);
    ok(g_OrderCount == 0, "%ld items ran before the thread dispatched messages\n", g_OrderCount);
    Pump(2000, &g_OrderCount, 5);
    ok(g_OrderCount == 5, "%ld items ran\n", g_OrderCount);
    trace("order: %d %d %d %d %d\n", g_Order[0], g_Order[1], g_Order[2], g_Order[3], g_Order[4]);
    ok(g_Order[0] == 4, "first ran %d\n", g_Order[0]);
    ok(g_Order[g_OrderCount - 1] == 1, "last ran %d\n", g_Order[g_OrderCount - 1]);
    DescribeMsg("work item delivered by", &g_RunMsg);
    for (i = 0; i < 5; i++)
        ok(H[i].ThreadId == GetCurrentThreadId(), "item %d ran on thread %lx\n", i + 1, H[i].ThreadId);
    Pump(100, NULL, 0);
    ok(H[0].Ref == 1, "the queue still holds the handler (%ld)\n", H[0].Ref);

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
        DWORD StartTick;

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
            trace("repeating 100 ms timer: %ld ticks in 560 ms, at +%lu +%lu +%lu +%lu +%lu ms\n", Tick.Calls,
                  Tick.Ticks[0] - StartTick, Tick.Ticks[1] - StartTick, Tick.Ticks[2] - StartTick, Tick.Ticks[3] - StartTick,
                  Tick.Ticks[4] - StartTick);
            ok(Tick.Calls >= 3 && Tick.Calls <= 6, "%ld ticks\n", Tick.Calls);
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
            Pump(450, NULL, 0);
            Tm->lpVtbl->get_IsRunning(Tm, &Running);
            ok(Tick.Calls == 1, "one-shot timer: %ld ticks\n", Tick.Calls);
            trace("one-shot timer: running %u after its tick\n", Running);
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
        trace("second ShutdownQueueAsync: %08lx\n", hr);
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
    TestDedicated(0, FALSE);
    TestDedicated(1, FALSE);
    TestDedicated(2, FALSE);
    TestDedicated(0, TRUE);
    RunOnThread(FactoryThread, NULL);

    if (g_QueueStatics)
        g_QueueStatics->lpVtbl->Release(g_QueueStatics);
}
