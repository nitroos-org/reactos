/*
 * PROJECT:     ReactOS CoreMessaging
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateDispatcherQueueController and the Windows.System.DispatcherQueue classes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A dispatcher queue runs work items on one thread, in priority order, when that thread dispatches window
 * messages. This follows the documented contract (dispatcherqueue.h, Windows.System.DispatcherQueue*); the
 * argument checks of CreateDispatcherQueueController were measured on Windows 10 22H2 with coremessaging_apitest
 * (E_INVALIDARG, output left alone). Windows ends the process for an unknown apartment type, and for a
 * dedicated thread with DQTAT_COM_NONE (measured 2026-11-12); this returns E_INVALIDARG for the first and accepts the
 * second (the Windows.System statics make such a queue). For DQTYPE_THREAD_CURRENT every apartment option (NONE, ASTA,
 * STA) succeeds on a thread in no apartment, an STA or the MTA (measured, x64 and x86); the caller's apartment is left
 * as it was. Each queue has a message-only
 * window on its thread: work items, timers and the shutdown sequence arrive there as messages, so they run
 * in whatever message loop the thread has (the caller's for DQTYPE_THREAD_CURRENT, our own for
 * DQTYPE_THREAD_DEDICATED). Microsoft Word loads this DLL for its composition (WinComp) renderer.
 *
 * Also measured on Windows 10 22H2 with coremessaging_apitest: a NULL callback is E_POINTER, a priority other than
 * the three values E_INVALIDARG; the second ShutdownQueueAsync is E_UNEXPECTED; work queued before the shutdown ends
 * runs before ShutdownCompleted; a running timer keeps its interval until the next Start. Where this differs on
 * purpose: timers end with their queue, and a queue whose thread ended refuses work (Windows keeps both going).
 *
 * The window of a queue can be posted to by any process of the user, so the window messages carry no data and act
 * only on state kept in the queue under its lock: a Start or Stop another thread asked for is in a list, a shutdown
 * must have been requested, a finish must have been posted by the queue. A thread that ends without a shutdown
 * takes its window with it; other threads notice that (the thread's handle) and the queue lets go of its work.
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "winerror.h"
#include "objbase.h"
#include "initguid.h"
#include "inspectable.h"
#include "activation.h"
#include "winstring.h"
#include "dispatcherqueue.h"
#include "dqabi.h"
#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(coremessaging);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define WM_DQ_WORK      (WM_USER + 1)
#define WM_DQ_SHUTDOWN  (WM_USER + 2)
#define WM_DQ_FINISH    (WM_USER + 3)
#define WM_DQ_TIMER     (WM_USER + 4)

#define DQ_DRAIN_LIMIT  10000   /* work items run at the end of a shutdown */

static HINSTANCE dq_instance;
static DWORD dq_tls = TLS_OUT_OF_INDEXES;
static ATOM dq_class;
static LONG dq_next_timer_id = 0x100;
static const WCHAR dq_class_name[] = L"ReactOS.DispatcherQueue";

static const WCHAR name_queue[] = L"Windows.System.DispatcherQueue";
static const WCHAR name_controller[] = L"Windows.System.DispatcherQueueController";
static const WCHAR name_timer[] = L"Windows.System.DispatcherQueueTimer";
static const WCHAR name_args[] = L"Windows.System.DispatcherQueueShutdownStartingEventArgs";
static const WCHAR name_deferral[] = L"Windows.Foundation.Deferral";
static const WCHAR name_action[] = L"Windows.Foundation.IAsyncAction";

enum queue_state { QUEUE_RUNNING, QUEUE_SHUTTING_DOWN, QUEUE_SHUT_DOWN };

struct handler_entry
{
    struct list entry;
    INT64 token;
    IDqTypedHandler *handler;
};

struct work_item
{
    struct list entry;
    IDqHandler *handler;
};

struct async_action;
struct timer;

/* a Start or Stop another thread asked for; the queue thread applies it when WM_DQ_TIMER arrives. The window
 * message carries nothing: the requests are only taken from this list, which only this DLL can add to. */
struct timer_req
{
    struct list entry;
    struct timer *timer;      /* holds a reference */
    BOOL start;
};

struct queue
{
    IDqQueue IDqQueue_iface;
    IDqQueue2 IDqQueue2_iface;
    LONG ref;
    CRITICAL_SECTION cs;
    DWORD thread_id;
    HWND hwnd;
    BOOL dedicated;
    enum queue_state state;
    struct list items[3];     /* high, normal, low */
    struct list starting;     /* handler_entry */
    struct list completed;
    struct list timers;       /* running timers, each holds a reference */
    struct list timer_reqs;   /* timer_req, from other threads */
    INT64 next_token;
    LONG deferrals;
    BOOL finish_pending;      /* a WM_DQ_FINISH was posted and not handled yet */
    BOOL quit;                /* dedicated thread: the message loop has been told to end */
    BOOL window_ref;          /* the window holds a reference */
    BOOL tls_ref;             /* the thread's TLS slot holds a reference */
    HANDLE thread;            /* the queue thread, to notice that it ended without a shutdown */
    struct async_action *shutdown;
};

struct timer
{
    IDqTimer IDqTimer_iface;
    LONG ref;
    struct queue *queue;
    struct list entry;        /* in queue->timers while running */
    UINT_PTR id;
    INT64 interval;
    BOOL repeating;
    BOOL running;             /* as the caller sees it */
    BOOL listed;              /* window timer set, in queue->timers */
    struct list ticks;
};

struct controller
{
    IDqController IDqController_iface;
    LONG ref;
    struct queue *queue;
};

struct async_action
{
    IDqAsyncAction IDqAsyncAction_iface;
    IDqAsyncInfo IDqAsyncInfo_iface;
    LONG ref;
    CRITICAL_SECTION cs;
    DqAsyncStatus status;
    BOOL closed;
    IDqActionHandler *handler;
    BOOL handler_set;
};

struct shutdown_args
{
    IDqShutdownArgs IDqShutdownArgs_iface;
    LONG ref;
    struct queue *queue;
};

struct deferral
{
    IDqDeferral IDqDeferral_iface;
    IDqClosable IDqClosable_iface;
    LONG ref;
    struct queue *queue;      /* NULL once completed */
};

static HRESULT inspectable_iids(ULONG *count, IID **iids, const IID *const *list, ULONG n)
{
    ULONG i;

    if (!count || !iids)
        return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(n * sizeof(IID))))
        return E_OUTOFMEMORY;
    for (i = 0; i < n; i++)
        (*iids)[i] = *list[i];
    *count = n;
    return S_OK;
}

static HRESULT class_name(HSTRING *out, const WCHAR *name)
{
    if (!out)
        return E_POINTER;
    return WindowsCreateString(name, lstrlenW(name), out);
}

static HRESULT add_handler(CRITICAL_SECTION *cs, struct list *list, INT64 *next, IDqTypedHandler *handler, DqToken *token)
{
    struct handler_entry *e;

    if (!handler || !token)
        return E_INVALIDARG;
    if (!(e = HeapAlloc(GetProcessHeap(), 0, sizeof(*e))))
        return E_OUTOFMEMORY;
    IUnknown_AddRef((IUnknown *)handler);
    e->handler = handler;
    EnterCriticalSection(cs);
    e->token = ++*next;
    list_add_tail(list, &e->entry);
    LeaveCriticalSection(cs);
    token->value = e->token;
    return S_OK;
}

static HRESULT remove_handler(CRITICAL_SECTION *cs, struct list *list, DqToken token)
{
    struct handler_entry *e, *found = NULL;

    EnterCriticalSection(cs);
    LIST_FOR_EACH_ENTRY(e, list, struct handler_entry, entry)
    {
        if (e->token == token.value)
        {
            list_remove(&e->entry);
            found = e;
            break;
        }
    }
    LeaveCriticalSection(cs);
    if (found)
    {
        IUnknown_Release((IUnknown *)found->handler);
        HeapFree(GetProcessHeap(), 0, found);
    }
    /* an unknown token is not an error */
    return S_OK;
}

static void free_handlers(struct list *list)
{
    struct handler_entry *e, *next;

    LIST_FOR_EACH_ENTRY_SAFE(e, next, list, struct handler_entry, entry)
    {
        list_remove(&e->entry);
        IUnknown_Release((IUnknown *)e->handler);
        HeapFree(GetProcessHeap(), 0, e);
    }
}

/* the handlers are called outside the lock, on a snapshot of the list */
static void raise_event(CRITICAL_SECTION *cs, struct list *list, IInspectable *sender, IInspectable *args)
{
    IDqTypedHandler **snap;
    struct handler_entry *e;
    UINT n = 0, i;

    EnterCriticalSection(cs);
    snap = HeapAlloc(GetProcessHeap(), 0, max(list_count(list), 1) * sizeof(*snap));
    if (snap)
    {
        LIST_FOR_EACH_ENTRY(e, list, struct handler_entry, entry)
        {
            IUnknown_AddRef((IUnknown *)e->handler);
            snap[n++] = e->handler;
        }
    }
    LeaveCriticalSection(cs);
    if (!snap)
        return;
    for (i = 0; i < n; i++)
    {
        HRESULT hr = snap[i]->lpVtbl->Invoke(snap[i], sender, args);
        if (FAILED(hr))
            WARN("event handler %p returned %#lx\n", snap[i], hr);
        IUnknown_Release((IUnknown *)snap[i]);
    }
    HeapFree(GetProcessHeap(), 0, snap);
}

/* ---- IAsyncAction ---- */

static inline struct async_action *impl_from_IDqAsyncAction(IDqAsyncAction *iface)
{
    return CONTAINING_RECORD(iface, struct async_action, IDqAsyncAction_iface);
}
static inline struct async_action *impl_from_IDqAsyncInfo(IDqAsyncInfo *iface)
{
    return CONTAINING_RECORD(iface, struct async_action, IDqAsyncInfo_iface);
}

static HRESULT STDMETHODCALLTYPE action_QueryInterface(IDqAsyncAction *iface, REFIID iid, void **out)
{
    struct async_action *action = impl_from_IDqAsyncAction(iface);

    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IDqAsyncAction)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
        *out = &action->IDqAsyncAction_iface;
    else if (IsEqualGUID(iid, &IID_IDqAsyncInfo))
        *out = &action->IDqAsyncInfo_iface;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE action_AddRef(IDqAsyncAction *iface)
{
    return InterlockedIncrement(&impl_from_IDqAsyncAction(iface)->ref);
}

static ULONG STDMETHODCALLTYPE action_Release(IDqAsyncAction *iface)
{
    struct async_action *action = impl_from_IDqAsyncAction(iface);
    ULONG ref = InterlockedDecrement(&action->ref);

    if (!ref)
    {
        if (action->handler)
            IUnknown_Release((IUnknown *)action->handler);
        DeleteCriticalSection(&action->cs);
        HeapFree(GetProcessHeap(), 0, action);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE action_GetIids(IDqAsyncAction *iface, ULONG *count, IID **iids)
{
    static const IID *const list[] = { &IID_IDqAsyncAction, &IID_IDqAsyncInfo };
    return inspectable_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE action_GetRuntimeClassName(IDqAsyncAction *iface, HSTRING *name)
{
    return class_name(name, name_action);
}

static HRESULT STDMETHODCALLTYPE action_GetTrustLevel(IDqAsyncAction *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE action_put_Completed(IDqAsyncAction *iface, IDqActionHandler *handler)
{
    struct async_action *action = impl_from_IDqAsyncAction(iface);
    DqAsyncStatus status;

    if (!handler)
        return E_INVALIDARG;
    EnterCriticalSection(&action->cs);
    if (action->closed)
    {
        LeaveCriticalSection(&action->cs);
        return E_ILLEGAL_METHOD_CALL;
    }
    if (action->handler_set)
    {
        LeaveCriticalSection(&action->cs);
        return E_ILLEGAL_DELEGATE_ASSIGNMENT;
    }
    action->handler_set = TRUE;
    status = action->status;
    if (status == DqAsyncStarted)
    {
        IUnknown_AddRef((IUnknown *)handler);
        action->handler = handler;
    }
    LeaveCriticalSection(&action->cs);
    /* set after completion: called at once, on this thread */
    if (status != DqAsyncStarted)
        handler->lpVtbl->Invoke(handler, iface, status);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE action_get_Completed(IDqAsyncAction *iface, IDqActionHandler **handler)
{
    struct async_action *action = impl_from_IDqAsyncAction(iface);

    if (!handler)
        return E_POINTER;
    EnterCriticalSection(&action->cs);
    *handler = action->handler;
    if (*handler)
        IUnknown_AddRef((IUnknown *)*handler);
    LeaveCriticalSection(&action->cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE action_GetResults(IDqAsyncAction *iface)
{
    struct async_action *action = impl_from_IDqAsyncAction(iface);
    HRESULT hr;

    EnterCriticalSection(&action->cs);
    if (action->closed)
        hr = E_ILLEGAL_METHOD_CALL;
    else if (action->status == DqAsyncCompleted)
        hr = S_OK;
    else if (action->status == DqAsyncCanceled)
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
    else
        hr = E_ILLEGAL_METHOD_CALL;
    LeaveCriticalSection(&action->cs);
    return hr;
}

static const IDqAsyncActionVtbl action_vtbl =
{
    action_QueryInterface, action_AddRef, action_Release,
    action_GetIids, action_GetRuntimeClassName, action_GetTrustLevel,
    action_put_Completed, action_get_Completed, action_GetResults,
};

#define INFO_FORWARD(iface) (&impl_from_IDqAsyncInfo(iface)->IDqAsyncAction_iface)
static HRESULT STDMETHODCALLTYPE info_QueryInterface(IDqAsyncInfo *iface, REFIID iid, void **out)
{ return action_QueryInterface(INFO_FORWARD(iface), iid, out); }
static ULONG STDMETHODCALLTYPE info_AddRef(IDqAsyncInfo *iface) { return action_AddRef(INFO_FORWARD(iface)); }
static ULONG STDMETHODCALLTYPE info_Release(IDqAsyncInfo *iface) { return action_Release(INFO_FORWARD(iface)); }
static HRESULT STDMETHODCALLTYPE info_GetIids(IDqAsyncInfo *iface, ULONG *count, IID **iids)
{ return action_GetIids(INFO_FORWARD(iface), count, iids); }
static HRESULT STDMETHODCALLTYPE info_GetRuntimeClassName(IDqAsyncInfo *iface, HSTRING *name)
{ return action_GetRuntimeClassName(INFO_FORWARD(iface), name); }
static HRESULT STDMETHODCALLTYPE info_GetTrustLevel(IDqAsyncInfo *iface, TrustLevel *level)
{ return action_GetTrustLevel(INFO_FORWARD(iface), level); }

static HRESULT STDMETHODCALLTYPE info_get_Id(IDqAsyncInfo *iface, UINT32 *id)
{
    if (!id)
        return E_POINTER;
    *id = 1;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE info_get_Status(IDqAsyncInfo *iface, DqAsyncStatus *status)
{
    struct async_action *action = impl_from_IDqAsyncInfo(iface);
    HRESULT hr = S_OK;

    if (!status)
        return E_POINTER;
    EnterCriticalSection(&action->cs);
    if (action->closed)
        hr = E_ILLEGAL_METHOD_CALL;
    else
        *status = action->status;
    LeaveCriticalSection(&action->cs);
    return hr;
}

static HRESULT STDMETHODCALLTYPE info_get_ErrorCode(IDqAsyncInfo *iface, HRESULT *code)
{
    struct async_action *action = impl_from_IDqAsyncInfo(iface);

    if (!code)
        return E_POINTER;
    EnterCriticalSection(&action->cs);
    *code = action->status == DqAsyncCanceled ? HRESULT_FROM_WIN32(ERROR_CANCELLED) : S_OK;
    LeaveCriticalSection(&action->cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE info_Cancel(IDqAsyncInfo *iface)
{
    /* the shutdown of a queue cannot be cancelled once requested */
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE info_Close(IDqAsyncInfo *iface)
{
    struct async_action *action = impl_from_IDqAsyncInfo(iface);
    HRESULT hr = S_OK;

    EnterCriticalSection(&action->cs);
    if (action->status == DqAsyncStarted)
        hr = E_ILLEGAL_STATE_CHANGE;
    else
        action->closed = TRUE;
    LeaveCriticalSection(&action->cs);
    return hr;
}

static const IDqAsyncInfoVtbl info_vtbl =
{
    info_QueryInterface, info_AddRef, info_Release,
    info_GetIids, info_GetRuntimeClassName, info_GetTrustLevel,
    info_get_Id, info_get_Status, info_get_ErrorCode, info_Cancel, info_Close,
};

static struct async_action *action_create(void)
{
    struct async_action *action;

    if (!(action = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*action))))
        return NULL;
    action->IDqAsyncAction_iface.lpVtbl = &action_vtbl;
    action->IDqAsyncInfo_iface.lpVtbl = &info_vtbl;
    action->ref = 1;
    action->status = DqAsyncStarted;
    InitializeCriticalSection(&action->cs);
    return action;
}

static void action_complete(struct async_action *action)
{
    IDqActionHandler *handler;

    EnterCriticalSection(&action->cs);
    if (action->status != DqAsyncStarted)
    {
        LeaveCriticalSection(&action->cs);
        return;
    }
    action->status = DqAsyncCompleted;
    handler = action->handler;
    action->handler = NULL;
    LeaveCriticalSection(&action->cs);
    if (handler)
    {
        handler->lpVtbl->Invoke(handler, &action->IDqAsyncAction_iface, DqAsyncCompleted);
        IUnknown_Release((IUnknown *)handler);
    }
}

/* ---- queue ---- */

static inline struct queue *impl_from_IDqQueue(IDqQueue *iface)
{
    return CONTAINING_RECORD(iface, struct queue, IDqQueue_iface);
}
static inline struct queue *impl_from_IDqQueue2(IDqQueue2 *iface)
{
    return CONTAINING_RECORD(iface, struct queue, IDqQueue2_iface);
}

static void queue_addref(struct queue *queue)
{
    InterlockedIncrement(&queue->ref);
}

static ULONG queue_release(struct queue *queue)
{
    ULONG ref = InterlockedDecrement(&queue->ref);

    if (!ref)
    {
        struct work_item *item, *next;
        int i;

        TRACE("destroying queue %p\n", queue);
        for (i = 0; i < 3; i++)
        {
            LIST_FOR_EACH_ENTRY_SAFE(item, next, &queue->items[i], struct work_item, entry)
            {
                list_remove(&item->entry);
                IUnknown_Release((IUnknown *)item->handler);
                HeapFree(GetProcessHeap(), 0, item);
            }
        }
        free_handlers(&queue->starting);
        free_handlers(&queue->completed);
        if (queue->shutdown)
            action_Release(&queue->shutdown->IDqAsyncAction_iface);
        if (queue->thread)
            CloseHandle(queue->thread);
        DeleteCriticalSection(&queue->cs);
        HeapFree(GetProcessHeap(), 0, queue);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE queue_QueryInterface(IDqQueue *iface, REFIID iid, void **out)
{
    struct queue *queue = impl_from_IDqQueue(iface);

    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IDqQueue)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
        *out = &queue->IDqQueue_iface;
    else if (IsEqualGUID(iid, &IID_IDqQueue2))
        *out = &queue->IDqQueue2_iface;
    else
    {
        TRACE("unsupported interface %s\n", debugstr_guid(iid));
        *out = NULL;
        return E_NOINTERFACE;
    }
    queue_addref(queue);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE queue_AddRef(IDqQueue *iface)
{
    return InterlockedIncrement(&impl_from_IDqQueue(iface)->ref);
}

static ULONG STDMETHODCALLTYPE queue_Release(IDqQueue *iface)
{
    return queue_release(impl_from_IDqQueue(iface));
}

static HRESULT STDMETHODCALLTYPE queue_GetIids(IDqQueue *iface, ULONG *count, IID **iids)
{
    static const IID *const list[] = { &IID_IDqQueue, &IID_IDqQueue2 };
    return inspectable_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE queue_GetRuntimeClassName(IDqQueue *iface, HSTRING *name)
{
    return class_name(name, name_queue);
}

static HRESULT STDMETHODCALLTYPE queue_GetTrustLevel(IDqQueue *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT timer_create(struct queue *queue, IDqTimer **out);

static HRESULT STDMETHODCALLTYPE queue_CreateTimer(IDqQueue *iface, IDqTimer **timer)
{
    if (!timer)
        return E_POINTER;
    return timer_create(impl_from_IDqQueue(iface), timer);
}

static ULONG STDMETHODCALLTYPE timer_Release(IDqTimer *iface);

/* The queue has no window any more, because it was destroyed on the thread or because the thread ended
 * without a shutdown: pending work is dropped, running timers stop, a shutdown that was asked for completes,
 * and the references the window and the thread's TLS slot held go. Safe to call more than once. */
static void queue_detach(struct queue *queue)
{
    struct work_item *item, *next_item;
    struct timer_req *req, *next_req;
    struct timer *timer, *next_timer;
    struct list items, reqs, timers;
    struct async_action *action;
    BOOL drop_window, drop_tls;
    int i;

    queue_addref(queue);
    list_init(&items);
    list_init(&reqs);
    list_init(&timers);
    EnterCriticalSection(&queue->cs);
    queue->state = QUEUE_SHUT_DOWN;
    queue->hwnd = NULL;
    queue->finish_pending = FALSE;
    for (i = 0; i < 3; i++)
        list_move_tail(&items, &queue->items[i]);
    list_move_tail(&reqs, &queue->timer_reqs);
    list_move_tail(&timers, &queue->timers);
    LIST_FOR_EACH_ENTRY(req, &reqs, struct timer_req, entry)
        req->timer->running = FALSE;
    LIST_FOR_EACH_ENTRY(timer, &timers, struct timer, entry)
    {
        timer->running = FALSE;
        timer->listed = FALSE;
    }
    action = queue->shutdown;
    if (action)
        action_AddRef(&action->IDqAsyncAction_iface);
    drop_window = queue->window_ref;
    drop_tls = queue->tls_ref;
    queue->window_ref = queue->tls_ref = FALSE;
    LeaveCriticalSection(&queue->cs);

    LIST_FOR_EACH_ENTRY_SAFE(item, next_item, &items, struct work_item, entry)
    {
        list_remove(&item->entry);
        IUnknown_Release((IUnknown *)item->handler);
        HeapFree(GetProcessHeap(), 0, item);
    }
    LIST_FOR_EACH_ENTRY_SAFE(req, next_req, &reqs, struct timer_req, entry)
    {
        list_remove(&req->entry);
        timer_Release(&req->timer->IDqTimer_iface);
        HeapFree(GetProcessHeap(), 0, req);
    }
    LIST_FOR_EACH_ENTRY_SAFE(timer, next_timer, &timers, struct timer, entry)
    {
        list_remove(&timer->entry);
        timer_Release(&timer->IDqTimer_iface); /* the list's */
    }
    if (action)
    {
        action_complete(action);
        action_Release(&action->IDqAsyncAction_iface);
    }
    if (drop_tls)
    {
        if (queue->thread_id == GetCurrentThreadId() && dq_tls != TLS_OUT_OF_INDEXES && TlsGetValue(dq_tls) == queue)
            TlsSetValue(dq_tls, NULL);
        queue_release(queue);
    }
    if (drop_window)
        queue_release(queue);
    queue_release(queue);
}

/* the reference of the thread's TLS slot goes: the thread has no queue any more */
static void queue_drop_tls(struct queue *queue)
{
    BOOL had;

    EnterCriticalSection(&queue->cs);
    had = queue->tls_ref;
    queue->tls_ref = FALSE;
    LeaveCriticalSection(&queue->cs);
    if (!had)
        return;
    if (queue->thread_id == GetCurrentThreadId() && dq_tls != TLS_OUT_OF_INDEXES && TlsGetValue(dq_tls) == queue)
        TlsSetValue(dq_tls, NULL);
    queue_release(queue);
}

/* called from other threads: a thread that ended took its windows with it, and may not have told us */
static void queue_check_thread(struct queue *queue)
{
    if (queue->hwnd && queue->thread && queue->thread_id != GetCurrentThreadId()
        && WaitForSingleObject(queue->thread, 0) == WAIT_OBJECT_0)
        queue_detach(queue);
}

static int priority_slot(INT32 priority)
{
    if (priority > DqPriorityNormal)
        return 0;
    if (priority < DqPriorityNormal)
        return 2;
    return 1;
}

static HRESULT STDMETHODCALLTYPE queue_TryEnqueueWithPriority(IDqQueue *iface, INT32 priority, IDqHandler *callback,
                                                              DqBool *result)
{
    struct queue *queue = impl_from_IDqQueue(iface);
    struct work_item *item;
    HWND hwnd;

    TRACE("queue %p, priority %d, callback %p\n", queue, priority, callback);

    /* measured on Windows 10 22H2: a NULL callback is E_POINTER; a priority that is not one of the three
     * DispatcherQueuePriority values is E_INVALIDARG and the result is FALSE */
    if (!callback || !result)
        return E_POINTER;
    if (priority != DqPriorityLow && priority != DqPriorityNormal && priority != DqPriorityHigh)
    {
        *result = FALSE;
        return E_INVALIDARG;
    }
    if (!(item = HeapAlloc(GetProcessHeap(), 0, sizeof(*item))))
        return E_OUTOFMEMORY;
    item->handler = callback;
    queue_check_thread(queue);
    EnterCriticalSection(&queue->cs);
    if (queue->state == QUEUE_SHUT_DOWN || !queue->hwnd)
    {
        LeaveCriticalSection(&queue->cs);
        HeapFree(GetProcessHeap(), 0, item);
        *result = FALSE;
        return S_OK;
    }
    IUnknown_AddRef((IUnknown *)callback);
    list_add_tail(&queue->items[priority_slot(priority)], &item->entry);
    hwnd = queue->hwnd;
    LeaveCriticalSection(&queue->cs);
    if (!PostMessageW(hwnd, WM_DQ_WORK, 0, 0))
    {
        WARN("PostMessage failed, error %lu\n", GetLastError());
        /* the thread may be gone: then the item was dropped */
        queue_check_thread(queue);
        EnterCriticalSection(&queue->cs);
        *result = queue->state != QUEUE_SHUT_DOWN;
        LeaveCriticalSection(&queue->cs);
        return S_OK;
    }
    *result = TRUE;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE queue_TryEnqueue(IDqQueue *iface, IDqHandler *callback, DqBool *result)
{
    return queue_TryEnqueueWithPriority(iface, DqPriorityNormal, callback, result);
}

static HRESULT STDMETHODCALLTYPE queue_add_ShutdownStarting(IDqQueue *iface, IDqTypedHandler *handler, DqToken *token)
{
    struct queue *queue = impl_from_IDqQueue(iface);
    return add_handler(&queue->cs, &queue->starting, &queue->next_token, handler, token);
}

static HRESULT STDMETHODCALLTYPE queue_remove_ShutdownStarting(IDqQueue *iface, DqToken token)
{
    struct queue *queue = impl_from_IDqQueue(iface);
    return remove_handler(&queue->cs, &queue->starting, token);
}

static HRESULT STDMETHODCALLTYPE queue_add_ShutdownCompleted(IDqQueue *iface, IDqTypedHandler *handler, DqToken *token)
{
    struct queue *queue = impl_from_IDqQueue(iface);
    return add_handler(&queue->cs, &queue->completed, &queue->next_token, handler, token);
}

static HRESULT STDMETHODCALLTYPE queue_remove_ShutdownCompleted(IDqQueue *iface, DqToken token)
{
    struct queue *queue = impl_from_IDqQueue(iface);
    return remove_handler(&queue->cs, &queue->completed, token);
}

static const IDqQueueVtbl queue_vtbl =
{
    queue_QueryInterface, queue_AddRef, queue_Release,
    queue_GetIids, queue_GetRuntimeClassName, queue_GetTrustLevel,
    queue_CreateTimer, queue_TryEnqueue, queue_TryEnqueueWithPriority,
    queue_add_ShutdownStarting, queue_remove_ShutdownStarting,
    queue_add_ShutdownCompleted, queue_remove_ShutdownCompleted,
};

#define QUEUE2_FORWARD(iface) (&impl_from_IDqQueue2(iface)->IDqQueue_iface)
static HRESULT STDMETHODCALLTYPE queue2_QueryInterface(IDqQueue2 *iface, REFIID iid, void **out)
{ return queue_QueryInterface(QUEUE2_FORWARD(iface), iid, out); }
static ULONG STDMETHODCALLTYPE queue2_AddRef(IDqQueue2 *iface) { return queue_AddRef(QUEUE2_FORWARD(iface)); }
static ULONG STDMETHODCALLTYPE queue2_Release(IDqQueue2 *iface) { return queue_Release(QUEUE2_FORWARD(iface)); }
static HRESULT STDMETHODCALLTYPE queue2_GetIids(IDqQueue2 *iface, ULONG *count, IID **iids)
{ return queue_GetIids(QUEUE2_FORWARD(iface), count, iids); }
static HRESULT STDMETHODCALLTYPE queue2_GetRuntimeClassName(IDqQueue2 *iface, HSTRING *name)
{ return queue_GetRuntimeClassName(QUEUE2_FORWARD(iface), name); }
static HRESULT STDMETHODCALLTYPE queue2_GetTrustLevel(IDqQueue2 *iface, TrustLevel *level)
{ return queue_GetTrustLevel(QUEUE2_FORWARD(iface), level); }

static HRESULT STDMETHODCALLTYPE queue2_get_HasThreadAccess(IDqQueue2 *iface, DqBool *value)
{
    struct queue *queue = impl_from_IDqQueue2(iface);

    if (!value)
        return E_POINTER;
    *value = queue->thread_id == GetCurrentThreadId();
    return S_OK;
}

static const IDqQueue2Vtbl queue2_vtbl =
{
    queue2_QueryInterface, queue2_AddRef, queue2_Release,
    queue2_GetIids, queue2_GetRuntimeClassName, queue2_GetTrustLevel,
    queue2_get_HasThreadAccess,
};

/* the next work item, highest priority first; the lock is held */
static struct work_item *queue_pop_item(struct queue *queue)
{
    struct list *head;
    int i;

    for (i = 0; i < 3; i++)
    {
        if ((head = list_head(&queue->items[i])))
        {
            struct work_item *item = LIST_ENTRY(head, struct work_item, entry);
            list_remove(&item->entry);
            return item;
        }
    }
    return NULL;
}

static void run_item(struct work_item *item)
{
    HRESULT hr = item->handler->lpVtbl->Invoke(item->handler);

    if (FAILED(hr))
        WARN("work item %p returned %#lx\n", item->handler, hr);
    IUnknown_Release((IUnknown *)item->handler);
    HeapFree(GetProcessHeap(), 0, item);
}

/* runs one work item, the highest priority first; if more are left they get a message of their own, so input
 * and paint messages interleave with the work */
static void queue_run_items(struct queue *queue)
{
    struct work_item *item = NULL;
    int i;

    EnterCriticalSection(&queue->cs);
    if (queue->state != QUEUE_SHUT_DOWN)
        item = queue_pop_item(queue);
    LeaveCriticalSection(&queue->cs);
    if (item)
        run_item(item);
    EnterCriticalSection(&queue->cs);
    for (i = 0; i < 3; i++)
    {
        if (!list_empty(&queue->items[i]) && queue->state != QUEUE_SHUT_DOWN && queue->hwnd)
        {
            PostMessageW(queue->hwnd, WM_DQ_WORK, 0, 0);
            break;
        }
    }
    LeaveCriticalSection(&queue->cs);
}

static void timer_stop_on_thread(struct timer *timer);

/* the last step of a shutdown, on the queue thread: no work any more, ShutdownCompleted, the action completes.
 * It acts only when the queue itself is shutting down and no deferral is outstanding, whoever asked. */
static void queue_finish_shutdown(struct queue *queue)
{
    struct work_item *item, *next_item;
    struct timer *timer, *next_timer;
    struct list items;
    struct async_action *action;
    int i;

    list_init(&items);
    queue_addref(queue);
    /* Windows 10 22H2 runs the work that is queued when the shutdown ends, including an item that was queued
     * after ShutdownQueueAsync returned, before ShutdownCompleted; the limit keeps an item that queues itself
     * again from holding the shutdown for ever */
    for (i = 0;; i++)
    {
        EnterCriticalSection(&queue->cs);
        if (queue->state != QUEUE_SHUTTING_DOWN || queue->deferrals)
        {
            LeaveCriticalSection(&queue->cs);
            queue_release(queue);
            return;
        }
        item = i < DQ_DRAIN_LIMIT ? queue_pop_item(queue) : NULL;
        if (!item)
            break; /* the lock stays held: state and queue change together */
        LeaveCriticalSection(&queue->cs);
        run_item(item);
    }
    TRACE("queue %p shut down\n", queue);
    queue->state = QUEUE_SHUT_DOWN;
    queue->finish_pending = FALSE;
    for (i = 0; i < 3; i++)
        list_move_tail(&items, &queue->items[i]);
    action = queue->shutdown;
    if (action)
        action_AddRef(&action->IDqAsyncAction_iface);
    LeaveCriticalSection(&queue->cs);

    LIST_FOR_EACH_ENTRY_SAFE(item, next_item, &items, struct work_item, entry) /* only past the limit */
    {
        list_remove(&item->entry);
        IUnknown_Release((IUnknown *)item->handler);
        HeapFree(GetProcessHeap(), 0, item);
    }
    LIST_FOR_EACH_ENTRY_SAFE(timer, next_timer, &queue->timers, struct timer, entry)
        timer_stop_on_thread(timer);

    raise_event(&queue->cs, &queue->completed, (IInspectable *)&queue->IDqQueue_iface, NULL);

    queue_drop_tls(queue);
    if (action)
    {
        action_complete(action);
        action_Release(&action->IDqAsyncAction_iface);
    }
    if (queue->dedicated)
    {
        EnterCriticalSection(&queue->cs);
        queue->quit = TRUE;
        LeaveCriticalSection(&queue->cs);
        PostQuitMessage(0);
    }
    else if (queue->hwnd)
        DestroyWindow(queue->hwnd);
    queue_release(queue);
}

static HRESULT args_create(struct queue *queue, IInspectable **out);

static void queue_start_shutdown(struct queue *queue)
{
    IInspectable *args = NULL;
    BOOL finish;

    /* only a shutdown that ShutdownQueueAsync (or the last release of a dedicated queue's controller) asked for */
    EnterCriticalSection(&queue->cs);
    if (queue->state != QUEUE_RUNNING || !queue->shutdown)
    {
        LeaveCriticalSection(&queue->cs);
        return;
    }
    queue->state = QUEUE_SHUTTING_DOWN;
    queue->deferrals++; /* held while the handlers run */
    LeaveCriticalSection(&queue->cs);

    if (SUCCEEDED(args_create(queue, &args)))
    {
        raise_event(&queue->cs, &queue->starting, (IInspectable *)&queue->IDqQueue_iface, args);
        IInspectable_Release(args);
    }

    EnterCriticalSection(&queue->cs);
    finish = !--queue->deferrals;
    LeaveCriticalSection(&queue->cs);
    /* work items keep running while a deferral is outstanding; the last deferral finishes the shutdown */
    if (finish)
        queue_finish_shutdown(queue);
}

static void queue_deferral_done(struct queue *queue)
{
    HWND hwnd = NULL;

    EnterCriticalSection(&queue->cs);
    if (!--queue->deferrals && queue->state == QUEUE_SHUTTING_DOWN && !queue->finish_pending && queue->hwnd)
    {
        queue->finish_pending = TRUE;
        hwnd = queue->hwnd;
    }
    LeaveCriticalSection(&queue->cs);
    if (hwnd)
        PostMessageW(hwnd, WM_DQ_FINISH, 0, 0);
}

static void timer_tick(struct queue *queue, UINT_PTR id);
static void timer_apply(struct timer *timer, BOOL start, BOOL requested);

/* on the queue thread: the Start and Stop calls other threads made, in order */
static void queue_run_timer_reqs(struct queue *queue)
{
    struct timer_req *req;
    struct list *head;

    for (;;)
    {
        req = NULL;
        EnterCriticalSection(&queue->cs);
        if ((head = list_head(&queue->timer_reqs)))
        {
            req = LIST_ENTRY(head, struct timer_req, entry);
            list_remove(&req->entry);
        }
        LeaveCriticalSection(&queue->cs);
        if (!req)
            break;
        timer_apply(req->timer, req->start, TRUE); /* releases the request's reference */
        HeapFree(GetProcessHeap(), 0, req);
    }
}

static LRESULT CALLBACK queue_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    struct queue *queue = (struct queue *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    BOOL run;

    if (!queue)
        return DefWindowProcW(hwnd, msg, wparam, lparam);

    /* Any process of the user can post to this window. The messages carry no data, and each of them acts only
     * on state this DLL set: pending work, a requested shutdown, a posted finish, queued timer requests. We
     * never send them, so one that arrives sent is not ours. */
    if (msg >= WM_DQ_WORK && msg <= WM_DQ_TIMER && InSendMessage())
        return 0;

    switch (msg)
    {
    case WM_DQ_WORK:
        queue_run_items(queue);
        return 0;
    case WM_DQ_SHUTDOWN:
        queue_start_shutdown(queue);
        return 0;
    case WM_DQ_FINISH:
        EnterCriticalSection(&queue->cs);
        run = queue->finish_pending;
        queue->finish_pending = FALSE;
        LeaveCriticalSection(&queue->cs);
        /* a deferral taken after the last one completed keeps the shutdown open; its Complete posts again */
        if (run)
            queue_finish_shutdown(queue);
        return 0;
    case WM_DQ_TIMER:
        queue_run_timer_reqs(queue);
        return 0;
    case WM_TIMER:
        timer_tick(queue, wparam);
        return 0;
    case WM_CLOSE:
        return 0; /* the window ends with the queue, not because another process asks */
    case WM_NCDESTROY:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        queue_detach(queue);
        break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL register_class(void)
{
    WNDCLASSW wc;

    if (dq_class)
        return TRUE;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = queue_wndproc;
    wc.hInstance = dq_instance;
    wc.lpszClassName = dq_class_name;
    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        return FALSE;
    dq_class = 1;
    return TRUE;
}

/* on the queue thread: the window, and the queue as the thread's queue */
static HRESULT queue_attach(struct queue *queue)
{
    if (!register_class())
        return HRESULT_FROM_WIN32(GetLastError());
    queue->thread_id = GetCurrentThreadId();
    /* a handle to this thread, which tells other threads that it ended */
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &queue->thread, SYNCHRONIZE, FALSE, 0))
        queue->thread = NULL;
    queue->hwnd = CreateWindowExW(0, dq_class_name, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, dq_instance, NULL);
    if (!queue->hwnd)
        return HRESULT_FROM_WIN32(GetLastError());
    queue_addref(queue); /* the window's */
    queue->window_ref = TRUE;
    SetWindowLongPtrW(queue->hwnd, GWLP_USERDATA, (LONG_PTR)queue);
    queue_addref(queue); /* the thread's */
    queue->tls_ref = TRUE;
    TlsSetValue(dq_tls, queue);
    return S_OK;
}

static struct queue *queue_create(BOOL dedicated)
{
    struct queue *queue;
    int i;

    if (!(queue = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*queue))))
        return NULL;
    queue->IDqQueue_iface.lpVtbl = &queue_vtbl;
    queue->IDqQueue2_iface.lpVtbl = &queue2_vtbl;
    queue->ref = 1;
    queue->dedicated = dedicated;
    queue->state = QUEUE_RUNNING;
    InitializeCriticalSection(&queue->cs);
    for (i = 0; i < 3; i++)
        list_init(&queue->items[i]);
    list_init(&queue->starting);
    list_init(&queue->completed);
    list_init(&queue->timers);
    list_init(&queue->timer_reqs);
    return queue;
}

static HRESULT queue_request_shutdown(struct queue *queue, IDqAsyncAction **out)
{
    struct async_action *action;
    BOOL post = FALSE, done = FALSE;
    HWND hwnd = NULL;

    queue_check_thread(queue);
    EnterCriticalSection(&queue->cs);
    if (queue->shutdown)
    {
        /* measured on Windows 10 22H2: the second ShutdownQueueAsync fails with E_UNEXPECTED, also after the
         * first one completed */
        LeaveCriticalSection(&queue->cs);
        if (out)
            *out = NULL;
        return E_UNEXPECTED;
    }
    if (!(action = action_create()))
    {
        LeaveCriticalSection(&queue->cs);
        return E_OUTOFMEMORY;
    }
    queue->shutdown = action;
    hwnd = queue->hwnd;
    if (queue->state == QUEUE_SHUT_DOWN || !hwnd)
        done = TRUE; /* the thread ended without a shutdown: nothing is left to shut down, so it is complete
                      * (Windows leaves the action started for ever) */
    else
        post = TRUE;
    action_AddRef(&action->IDqAsyncAction_iface);
    LeaveCriticalSection(&queue->cs);
    if (done)
        action_complete(action);
    else if (post && !PostMessageW(hwnd, WM_DQ_SHUTDOWN, 0, 0))
    {
        WARN("PostMessage failed, error %lu\n", GetLastError());
        queue_check_thread(queue); /* completes the action when the thread is gone */
    }
    if (out)
        *out = &action->IDqAsyncAction_iface;
    else
        action_Release(&action->IDqAsyncAction_iface);
    return S_OK;
}

/* ---- shutdown event args and deferral ---- */

static inline struct deferral *impl_from_IDqDeferral(IDqDeferral *iface)
{
    return CONTAINING_RECORD(iface, struct deferral, IDqDeferral_iface);
}
static inline struct deferral *impl_from_IDqClosable(IDqClosable *iface)
{
    return CONTAINING_RECORD(iface, struct deferral, IDqClosable_iface);
}

static HRESULT STDMETHODCALLTYPE deferral_QueryInterface(IDqDeferral *iface, REFIID iid, void **out)
{
    struct deferral *deferral = impl_from_IDqDeferral(iface);

    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IDqDeferral)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
        *out = &deferral->IDqDeferral_iface;
    else if (IsEqualGUID(iid, &IID_IDqClosable))
        *out = &deferral->IDqClosable_iface;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG STDMETHODCALLTYPE deferral_AddRef(IDqDeferral *iface)
{
    return InterlockedIncrement(&impl_from_IDqDeferral(iface)->ref);
}

static HRESULT STDMETHODCALLTYPE deferral_Complete(IDqDeferral *iface)
{
    struct deferral *deferral = impl_from_IDqDeferral(iface);
    struct queue *queue = InterlockedExchangePointer((void **)&deferral->queue, NULL);

    if (queue)
    {
        queue_deferral_done(queue);
        queue_release(queue);
    }
    return S_OK;
}

static ULONG STDMETHODCALLTYPE deferral_Release(IDqDeferral *iface)
{
    struct deferral *deferral = impl_from_IDqDeferral(iface);
    ULONG ref = InterlockedDecrement(&deferral->ref);

    if (!ref)
    {
        /* a deferral released without Complete completes */
        deferral_Complete(iface);
        HeapFree(GetProcessHeap(), 0, deferral);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE deferral_GetIids(IDqDeferral *iface, ULONG *count, IID **iids)
{
    static const IID *const list[] = { &IID_IDqDeferral, &IID_IDqClosable };
    return inspectable_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE deferral_GetRuntimeClassName(IDqDeferral *iface, HSTRING *name)
{
    return class_name(name, name_deferral);
}

static HRESULT STDMETHODCALLTYPE deferral_GetTrustLevel(IDqDeferral *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static const IDqDeferralVtbl deferral_vtbl =
{
    deferral_QueryInterface, deferral_AddRef, deferral_Release,
    deferral_GetIids, deferral_GetRuntimeClassName, deferral_GetTrustLevel,
    deferral_Complete,
};

#define CLOSABLE_FORWARD(iface) (&impl_from_IDqClosable(iface)->IDqDeferral_iface)
static HRESULT STDMETHODCALLTYPE closable_QueryInterface(IDqClosable *iface, REFIID iid, void **out)
{ return deferral_QueryInterface(CLOSABLE_FORWARD(iface), iid, out); }
static ULONG STDMETHODCALLTYPE closable_AddRef(IDqClosable *iface) { return deferral_AddRef(CLOSABLE_FORWARD(iface)); }
static ULONG STDMETHODCALLTYPE closable_Release(IDqClosable *iface) { return deferral_Release(CLOSABLE_FORWARD(iface)); }
static HRESULT STDMETHODCALLTYPE closable_GetIids(IDqClosable *iface, ULONG *count, IID **iids)
{ return deferral_GetIids(CLOSABLE_FORWARD(iface), count, iids); }
static HRESULT STDMETHODCALLTYPE closable_GetRuntimeClassName(IDqClosable *iface, HSTRING *name)
{ return deferral_GetRuntimeClassName(CLOSABLE_FORWARD(iface), name); }
static HRESULT STDMETHODCALLTYPE closable_GetTrustLevel(IDqClosable *iface, TrustLevel *level)
{ return deferral_GetTrustLevel(CLOSABLE_FORWARD(iface), level); }
static HRESULT STDMETHODCALLTYPE closable_Close(IDqClosable *iface)
{ return deferral_Complete(CLOSABLE_FORWARD(iface)); }

static const IDqClosableVtbl closable_vtbl =
{
    closable_QueryInterface, closable_AddRef, closable_Release,
    closable_GetIids, closable_GetRuntimeClassName, closable_GetTrustLevel,
    closable_Close,
};

static inline struct shutdown_args *impl_from_IDqShutdownArgs(IDqShutdownArgs *iface)
{
    return CONTAINING_RECORD(iface, struct shutdown_args, IDqShutdownArgs_iface);
}

static HRESULT STDMETHODCALLTYPE args_QueryInterface(IDqShutdownArgs *iface, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IDqShutdownArgs)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
    {
        *out = iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE args_AddRef(IDqShutdownArgs *iface)
{
    return InterlockedIncrement(&impl_from_IDqShutdownArgs(iface)->ref);
}

static ULONG STDMETHODCALLTYPE args_Release(IDqShutdownArgs *iface)
{
    struct shutdown_args *args = impl_from_IDqShutdownArgs(iface);
    ULONG ref = InterlockedDecrement(&args->ref);

    if (!ref)
    {
        queue_release(args->queue);
        HeapFree(GetProcessHeap(), 0, args);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE args_GetIids(IDqShutdownArgs *iface, ULONG *count, IID **iids)
{
    static const IID *const list[] = { &IID_IDqShutdownArgs };
    return inspectable_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE args_GetRuntimeClassName(IDqShutdownArgs *iface, HSTRING *name)
{
    return class_name(name, name_args);
}

static HRESULT STDMETHODCALLTYPE args_GetTrustLevel(IDqShutdownArgs *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE args_GetDeferral(IDqShutdownArgs *iface, IDqDeferral **out)
{
    struct shutdown_args *args = impl_from_IDqShutdownArgs(iface);
    struct deferral *deferral;

    if (!out)
        return E_POINTER;
    if (!(deferral = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*deferral))))
        return E_OUTOFMEMORY;
    deferral->IDqDeferral_iface.lpVtbl = &deferral_vtbl;
    deferral->IDqClosable_iface.lpVtbl = &closable_vtbl;
    deferral->ref = 1;
    /* after the shutdown is over there is nothing left to hold open */
    EnterCriticalSection(&args->queue->cs);
    if (args->queue->state != QUEUE_SHUT_DOWN)
    {
        args->queue->deferrals++;
        deferral->queue = args->queue;
        queue_addref(args->queue);
    }
    LeaveCriticalSection(&args->queue->cs);
    *out = &deferral->IDqDeferral_iface;
    return S_OK;
}

static const IDqShutdownArgsVtbl args_vtbl =
{
    args_QueryInterface, args_AddRef, args_Release,
    args_GetIids, args_GetRuntimeClassName, args_GetTrustLevel,
    args_GetDeferral,
};

static HRESULT args_create(struct queue *queue, IInspectable **out)
{
    struct shutdown_args *args;

    if (!(args = HeapAlloc(GetProcessHeap(), 0, sizeof(*args))))
        return E_OUTOFMEMORY;
    args->IDqShutdownArgs_iface.lpVtbl = &args_vtbl;
    args->ref = 1;
    args->queue = queue;
    queue_addref(queue);
    *out = (IInspectable *)&args->IDqShutdownArgs_iface;
    return S_OK;
}

/* ---- timer ---- */

static inline struct timer *impl_from_IDqTimer(IDqTimer *iface)
{
    return CONTAINING_RECORD(iface, struct timer, IDqTimer_iface);
}

static HRESULT STDMETHODCALLTYPE timer_QueryInterface(IDqTimer *iface, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IDqTimer)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
    {
        *out = iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE timer_AddRef(IDqTimer *iface)
{
    return InterlockedIncrement(&impl_from_IDqTimer(iface)->ref);
}

static ULONG STDMETHODCALLTYPE timer_Release(IDqTimer *iface)
{
    struct timer *timer = impl_from_IDqTimer(iface);
    ULONG ref = InterlockedDecrement(&timer->ref);

    if (!ref)
    {
        free_handlers(&timer->ticks);
        queue_release(timer->queue);
        HeapFree(GetProcessHeap(), 0, timer);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE timer_GetIids(IDqTimer *iface, ULONG *count, IID **iids)
{
    static const IID *const list[] = { &IID_IDqTimer };
    return inspectable_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE timer_GetRuntimeClassName(IDqTimer *iface, HSTRING *name)
{
    return class_name(name, name_timer);
}

static HRESULT STDMETHODCALLTYPE timer_GetTrustLevel(IDqTimer *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE timer_get_Interval(IDqTimer *iface, DqTimeSpan *value)
{
    struct timer *timer = impl_from_IDqTimer(iface);

    if (!value)
        return E_POINTER;
    EnterCriticalSection(&timer->queue->cs);
    value->Duration = timer->interval;
    LeaveCriticalSection(&timer->queue->cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE timer_put_Interval(IDqTimer *iface, DqTimeSpan value)
{
    struct timer *timer = impl_from_IDqTimer(iface);

    if (value.Duration < 0)
        return E_INVALIDARG;
    /* measured on Windows 10 22H2: the interval of a running timer changes only for the next Start (no tick
     * came within 3 s of 60 s -> 50 ms) */
    EnterCriticalSection(&timer->queue->cs);
    timer->interval = value.Duration;
    LeaveCriticalSection(&timer->queue->cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE timer_get_IsRunning(IDqTimer *iface, DqBool *value)
{
    struct timer *timer = impl_from_IDqTimer(iface);

    if (!value)
        return E_POINTER;
    EnterCriticalSection(&timer->queue->cs);
    *value = timer->running;
    LeaveCriticalSection(&timer->queue->cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE timer_get_IsRepeating(IDqTimer *iface, DqBool *value)
{
    struct timer *timer = impl_from_IDqTimer(iface);

    if (!value)
        return E_POINTER;
    EnterCriticalSection(&timer->queue->cs);
    *value = timer->repeating;
    LeaveCriticalSection(&timer->queue->cs);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE timer_put_IsRepeating(IDqTimer *iface, DqBool value)
{
    struct timer *timer = impl_from_IDqTimer(iface);

    EnterCriticalSection(&timer->queue->cs);
    timer->repeating = !!value;
    LeaveCriticalSection(&timer->queue->cs);
    return S_OK;
}

static void timer_stop_on_thread(struct timer *timer)
{
    BOOL listed;

    EnterCriticalSection(&timer->queue->cs);
    timer->running = FALSE;
    listed = timer->listed;
    if (listed)
    {
        timer->listed = FALSE;
        list_remove(&timer->entry);
    }
    LeaveCriticalSection(&timer->queue->cs);
    if (listed)
    {
        KillTimer(timer->queue->hwnd, timer->id);
        timer_Release(&timer->IDqTimer_iface); /* the list's */
    }
}

/* the window timer period in milliseconds for a TimeSpan in 100 ns units, rounded up */
static UINT interval_ms(INT64 interval)
{
    INT64 ms = interval / 10000 + (interval % 10000 != 0);

    return (UINT)min(ms, (INT64)USER_TIMER_MAXIMUM);
}

/* on the queue thread: (re)start or stop the window timer. A request from another thread already set
 * running when it was made; it is the request's reference that is released here */
static void timer_apply(struct timer *timer, BOOL start, BOOL requested)
{
    struct queue *queue = timer->queue;
    UINT ms;

    if (start && queue->state != QUEUE_SHUT_DOWN)
    {
        EnterCriticalSection(&queue->cs);
        ms = interval_ms(timer->interval);
        if (!requested)
            timer->running = TRUE;
        if (!timer->listed)
        {
            timer_AddRef(&timer->IDqTimer_iface); /* the list's */
            timer->listed = TRUE;
            list_add_tail(&queue->timers, &timer->entry);
        }
        LeaveCriticalSection(&queue->cs);
        if (!SetTimer(queue->hwnd, timer->id, ms, NULL))
        {
            WARN("SetTimer failed, error %lu\n", GetLastError());
            timer_stop_on_thread(timer);
        }
    }
    else
        timer_stop_on_thread(timer); /* also a start that came after the queue was shut down */
    timer_Release(&timer->IDqTimer_iface); /* the request's */
}

static HRESULT timer_request(struct timer *timer, BOOL start)
{
    struct queue *queue = timer->queue;
    struct timer_req *req;
    HWND hwnd;

    if (queue->thread_id == GetCurrentThreadId())
    {
        /* Windows 10 22H2 returns S_OK for a Start on a queue that was shut down (and the timer goes on ticking);
         * here the timer ends with its queue, so it does not run */
        if (queue->state == QUEUE_SHUT_DOWN)
            return S_OK;
        timer_AddRef(&timer->IDqTimer_iface);
        timer_apply(timer, start, FALSE);
        return S_OK;
    }
    /* SetTimer works only on the thread of the window: queue the request for it. The caller sees the new
     * state right away. */
    queue_check_thread(queue);
    if (!(req = HeapAlloc(GetProcessHeap(), 0, sizeof(*req))))
        return E_OUTOFMEMORY;
    EnterCriticalSection(&queue->cs);
    if (queue->state == QUEUE_SHUT_DOWN || !queue->hwnd)
    {
        LeaveCriticalSection(&queue->cs);
        HeapFree(GetProcessHeap(), 0, req);
        return S_OK;
    }
    timer_AddRef(&timer->IDqTimer_iface);
    req->timer = timer;
    req->start = start;
    list_add_tail(&queue->timer_reqs, &req->entry);
    timer->running = start;
    hwnd = queue->hwnd;
    LeaveCriticalSection(&queue->cs);
    if (!PostMessageW(hwnd, WM_DQ_TIMER, 0, 0))
    {
        DWORD error = GetLastError();
        struct timer_req *e;
        BOOL found = FALSE;

        queue_check_thread(queue); /* drops the request when the thread is gone */
        EnterCriticalSection(&queue->cs);
        LIST_FOR_EACH_ENTRY(e, &queue->timer_reqs, struct timer_req, entry)
        {
            if (e == req)
            {
                list_remove(&req->entry);
                timer->running = timer->listed;
                found = TRUE;
                break;
            }
        }
        LeaveCriticalSection(&queue->cs);
        if (found)
        {
            timer_Release(&timer->IDqTimer_iface);
            HeapFree(GetProcessHeap(), 0, req);
            return HRESULT_FROM_WIN32(error);
        }
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE timer_Start(IDqTimer *iface)
{
    return timer_request(impl_from_IDqTimer(iface), TRUE);
}

static HRESULT STDMETHODCALLTYPE timer_Stop(IDqTimer *iface)
{
    return timer_request(impl_from_IDqTimer(iface), FALSE);
}

static HRESULT STDMETHODCALLTYPE timer_add_Tick(IDqTimer *iface, IDqTypedHandler *handler, DqToken *token)
{
    struct timer *timer = impl_from_IDqTimer(iface);
    return add_handler(&timer->queue->cs, &timer->ticks, &timer->queue->next_token, handler, token);
}

static HRESULT STDMETHODCALLTYPE timer_remove_Tick(IDqTimer *iface, DqToken token)
{
    struct timer *timer = impl_from_IDqTimer(iface);
    return remove_handler(&timer->queue->cs, &timer->ticks, token);
}

static const IDqTimerVtbl timer_vtbl =
{
    timer_QueryInterface, timer_AddRef, timer_Release,
    timer_GetIids, timer_GetRuntimeClassName, timer_GetTrustLevel,
    timer_get_Interval, timer_put_Interval, timer_get_IsRunning,
    timer_get_IsRepeating, timer_put_IsRepeating, timer_Start, timer_Stop,
    timer_add_Tick, timer_remove_Tick,
};

static void timer_tick(struct queue *queue, UINT_PTR id)
{
    struct timer *timer, *found = NULL;

    EnterCriticalSection(&queue->cs);
    LIST_FOR_EACH_ENTRY(timer, &queue->timers, struct timer, entry)
    {
        if (timer->id == id)
        {
            found = timer;
            timer_AddRef(&found->IDqTimer_iface);
            break;
        }
    }
    LeaveCriticalSection(&queue->cs);
    if (!found)
    {
        KillTimer(queue->hwnd, id);
        return;
    }
    if (!found->repeating)
        timer_stop_on_thread(found);
    raise_event(&queue->cs, &found->ticks, (IInspectable *)&found->IDqTimer_iface, NULL);
    timer_Release(&found->IDqTimer_iface);
}

static HRESULT timer_create(struct queue *queue, IDqTimer **out)
{
    struct timer *timer;

    if (!(timer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*timer))))
        return E_OUTOFMEMORY;
    timer->IDqTimer_iface.lpVtbl = &timer_vtbl;
    timer->ref = 1;
    timer->queue = queue;
    queue_addref(queue);
    timer->id = (UINT_PTR)InterlockedIncrement(&dq_next_timer_id);
    timer->repeating = TRUE;
    list_init(&timer->ticks);
    list_init(&timer->entry);
    *out = &timer->IDqTimer_iface;
    return S_OK;
}

/* ---- controller ---- */

static inline struct controller *impl_from_IDqController(IDqController *iface)
{
    return CONTAINING_RECORD(iface, struct controller, IDqController_iface);
}

static HRESULT STDMETHODCALLTYPE controller_QueryInterface(IDqController *iface, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IDqController)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
    {
        *out = iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }
    TRACE("unsupported interface %s\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE controller_AddRef(IDqController *iface)
{
    return InterlockedIncrement(&impl_from_IDqController(iface)->ref);
}

static ULONG STDMETHODCALLTYPE controller_Release(IDqController *iface)
{
    struct controller *controller = impl_from_IDqController(iface);
    ULONG ref = InterlockedDecrement(&controller->ref);

    if (!ref)
    {
        /* nobody can shut a dedicated thread down any more: do it now */
        if (controller->queue->dedicated)
            queue_request_shutdown(controller->queue, NULL);
        queue_release(controller->queue);
        HeapFree(GetProcessHeap(), 0, controller);
    }
    return ref;
}

static HRESULT STDMETHODCALLTYPE controller_GetIids(IDqController *iface, ULONG *count, IID **iids)
{
    static const IID *const list[] = { &IID_IDqController };
    return inspectable_iids(count, iids, list, ARRAY_SIZE(list));
}

static HRESULT STDMETHODCALLTYPE controller_GetRuntimeClassName(IDqController *iface, HSTRING *name)
{
    return class_name(name, name_controller);
}

static HRESULT STDMETHODCALLTYPE controller_GetTrustLevel(IDqController *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE controller_get_DispatcherQueue(IDqController *iface, IDqQueue **queue)
{
    struct controller *controller = impl_from_IDqController(iface);

    if (!queue)
        return E_POINTER;
    queue_addref(controller->queue);
    *queue = &controller->queue->IDqQueue_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE controller_ShutdownQueueAsync(IDqController *iface, IDqAsyncAction **action)
{
    struct controller *controller = impl_from_IDqController(iface);

    TRACE("controller %p, queue %p\n", controller, controller->queue);
    if (!action)
        return E_POINTER;
    return queue_request_shutdown(controller->queue, action);
}

static const IDqControllerVtbl controller_vtbl =
{
    controller_QueryInterface, controller_AddRef, controller_Release,
    controller_GetIids, controller_GetRuntimeClassName, controller_GetTrustLevel,
    controller_get_DispatcherQueue, controller_ShutdownQueueAsync,
};

static HRESULT controller_create(struct queue *queue, IDqController **out)
{
    struct controller *controller;

    if (!(controller = HeapAlloc(GetProcessHeap(), 0, sizeof(*controller))))
        return E_OUTOFMEMORY;
    controller->IDqController_iface.lpVtbl = &controller_vtbl;
    controller->ref = 1;
    controller->queue = queue;
    queue_addref(queue);
    *out = &controller->IDqController_iface;
    return S_OK;
}

/* ---- the dedicated thread ---- */

struct thread_start
{
    struct queue *queue;
    DISPATCHERQUEUE_THREAD_APARTMENTTYPE apartment;
    HANDLE ready;
    HRESULT hr;
};

static DWORD WINAPI dedicated_thread(void *param)
{
    struct thread_start *start = param;
    struct queue *queue = start->queue;
    HRESULT com = E_FAIL, hr = S_OK;
    HMODULE self = NULL;
    MSG msg;
    int ret;

    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)dedicated_thread, &self);
    queue_addref(queue);
    if (start->apartment == DQTAT_COM_STA || start->apartment == DQTAT_COM_ASTA)
    {
        if (start->apartment == DQTAT_COM_ASTA)
            FIXME("application STA: a single-threaded apartment is used\n");
        com = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(com))
        {
            ERR("CoInitializeEx failed, %#lx\n", com);
            hr = com;
        }
    }
    if (SUCCEEDED(hr))
        hr = queue_attach(queue);
    start->hr = hr;
    SetEvent(start->ready); /* start is gone after this */
    if (SUCCEEDED(hr))
    {
        for (;;)
        {
            ret = GetMessageW(&msg, NULL, 0, 0);
            if (ret > 0)
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
                continue;
            }
            if (ret < 0)
                break;
            /* WM_QUIT: ours, or one that another process posted to the window, which does not end the queue */
            EnterCriticalSection(&queue->cs);
            ret = queue->quit;
            LeaveCriticalSection(&queue->cs);
            if (ret)
                break;
        }
        if (queue->hwnd)
            DestroyWindow(queue->hwnd);
        queue_detach(queue); /* if the loop ended some other way */
    }
    queue_drop_tls(queue);
    queue_release(queue);
    if (SUCCEEDED(com))
        CoUninitialize();
    TRACE("dedicated thread of queue %p exits\n", queue);
    if (self)
        FreeLibraryAndExitThread(self, 0);
    return 0;
}

HRESULT WINAPI CreateDispatcherQueueController(DispatcherQueueOptions options, PDISPATCHERQUEUECONTROLLER *out)
{
    struct queue *queue;
    HRESULT hr;

    TRACE("size %lu, thread type %d, apartment %d, out %p\n", options.dwSize, options.threadType, options.apartmentType, out);

    /* Windows leaves *out alone when it fails */
    if (!out)
        return E_POINTER;
    if (options.dwSize != sizeof(options)
        || (options.threadType != DQTYPE_THREAD_DEDICATED && options.threadType != DQTYPE_THREAD_CURRENT)
        || (options.apartmentType != DQTAT_COM_NONE && options.apartmentType != DQTAT_COM_ASTA
            && options.apartmentType != DQTAT_COM_STA))
        return E_INVALIDARG;
    if (dq_tls == TLS_OUT_OF_INDEXES)
        return E_OUTOFMEMORY;

    if (options.threadType == DQTYPE_THREAD_CURRENT)
    {
        /* any apartment option is accepted, whatever apartment the thread is in (measured on Windows 10 22H2, all nine
         * combinations): the option is not acted on for the calling thread, which keeps the apartment it had (none
         * stays none) */
        if (TlsGetValue(dq_tls))
            return RPC_E_WRONG_THREAD;
        if (!(queue = queue_create(FALSE)))
            return E_OUTOFMEMORY;
        if (FAILED(hr = queue_attach(queue)))
        {
            queue_release(queue);
            return hr;
        }
    }
    else
    {
        struct thread_start start;
        HANDLE thread;

        if (!(queue = queue_create(TRUE)))
            return E_OUTOFMEMORY;
        start.queue = queue;
        start.apartment = options.apartmentType;
        start.hr = E_FAIL;
        start.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!start.ready || !(thread = CreateThread(NULL, 0, dedicated_thread, &start, 0, NULL)))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            if (start.ready)
                CloseHandle(start.ready);
            queue_release(queue);
            return hr;
        }
        WaitForSingleObject(start.ready, INFINITE);
        CloseHandle(start.ready);
        CloseHandle(thread);
        if (FAILED(hr = start.hr))
        {
            queue_release(queue);
            return hr;
        }
    }

    hr = controller_create(queue, (IDqController **)out);
    queue_release(queue);
    return hr;
}

/* ---- activation factories ---- */

struct factory
{
    IActivationFactory IActivationFactory_iface;
    IInspectable statics_iface; /* IDqControllerStatics or IDqQueueStatics */
    const WCHAR *name;
    const IID *statics_iid;
};

static inline struct factory *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct factory, IActivationFactory_iface);
}
static inline struct factory *impl_from_statics(void *iface)
{
    return CONTAINING_RECORD(iface, struct factory, statics_iface);
}

static HRESULT STDMETHODCALLTYPE factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct factory *factory = impl_from_IActivationFactory(iface);

    if (!out)
        return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) || IsEqualGUID(iid, &IID_IActivationFactory)
        || IsEqualGUID(iid, &IID_IDqAgileObject))
        *out = &factory->IActivationFactory_iface;
    else if (IsEqualGUID(iid, factory->statics_iid))
        *out = &factory->statics_iface;
    else
    {
        TRACE("%s: unsupported interface %s\n", debugstr_w(factory->name), debugstr_guid(iid));
        *out = NULL;
        return E_NOINTERFACE;
    }
    return S_OK; /* static objects */
}

static ULONG STDMETHODCALLTYPE factory_AddRef(IActivationFactory *iface) { return 2; }
static ULONG STDMETHODCALLTYPE factory_Release(IActivationFactory *iface) { return 1; }

static HRESULT STDMETHODCALLTYPE factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    struct factory *factory = impl_from_IActivationFactory(iface);
    const IID *list[2];
    list[0] = &IID_IActivationFactory;
    list[1] = factory->statics_iid;
    return inspectable_iids(count, iids, list, 2);
}

static HRESULT STDMETHODCALLTYPE factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    return class_name(name, impl_from_IActivationFactory(iface)->name);
}

static HRESULT STDMETHODCALLTYPE factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    if (instance)
        *instance = NULL;
    /* neither class has a default constructor */
    return E_NOTIMPL;
}

static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface, factory_AddRef, factory_Release,
    factory_GetIids, factory_GetRuntimeClassName, factory_GetTrustLevel,
    factory_ActivateInstance,
};

#define STATICS_FORWARD(iface) (&impl_from_statics(iface)->IActivationFactory_iface)
static HRESULT STDMETHODCALLTYPE statics_QueryInterface(void *iface, REFIID iid, void **out)
{ return factory_QueryInterface(STATICS_FORWARD(iface), iid, out); }
static ULONG STDMETHODCALLTYPE statics_AddRef(void *iface) { return 2; }
static ULONG STDMETHODCALLTYPE statics_Release(void *iface) { return 1; }
static HRESULT STDMETHODCALLTYPE statics_GetIids(void *iface, ULONG *count, IID **iids)
{ return factory_GetIids(STATICS_FORWARD(iface), count, iids); }
static HRESULT STDMETHODCALLTYPE statics_GetRuntimeClassName(void *iface, HSTRING *name)
{ return factory_GetRuntimeClassName(STATICS_FORWARD(iface), name); }
static HRESULT STDMETHODCALLTYPE statics_GetTrustLevel(void *iface, TrustLevel *level)
{ return factory_GetTrustLevel(STATICS_FORWARD(iface), level); }

static HRESULT STDMETHODCALLTYPE controller_statics_CreateOnDedicatedThread(IDqControllerStatics *iface, IDqController **result)
{
    DispatcherQueueOptions options;

    if (!result)
        return E_POINTER;
    options.dwSize = sizeof(options);
    options.threadType = DQTYPE_THREAD_DEDICATED;
    options.apartmentType = DQTAT_COM_NONE;
    return CreateDispatcherQueueController(options, (PDISPATCHERQUEUECONTROLLER *)result);
}

static HRESULT STDMETHODCALLTYPE queue_statics_GetForCurrentThread(IDqQueueStatics *iface, IDqQueue **result)
{
    struct queue *queue;

    if (!result)
        return E_POINTER;
    queue = dq_tls != TLS_OUT_OF_INDEXES ? TlsGetValue(dq_tls) : NULL;
    if (queue)
    {
        queue_addref(queue);
        *result = &queue->IDqQueue_iface;
    }
    else
        *result = NULL;
    return S_OK;
}

static const IDqControllerStaticsVtbl controller_statics_vtbl =
{
    (void *)statics_QueryInterface, (void *)statics_AddRef, (void *)statics_Release,
    (void *)statics_GetIids, (void *)statics_GetRuntimeClassName, (void *)statics_GetTrustLevel,
    controller_statics_CreateOnDedicatedThread,
};

static const IDqQueueStaticsVtbl queue_statics_vtbl =
{
    (void *)statics_QueryInterface, (void *)statics_AddRef, (void *)statics_Release,
    (void *)statics_GetIids, (void *)statics_GetRuntimeClassName, (void *)statics_GetTrustLevel,
    queue_statics_GetForCurrentThread,
};

static struct factory controller_factory =
{
    { (IActivationFactoryVtbl *)&factory_vtbl }, { (IInspectableVtbl *)&controller_statics_vtbl }, name_controller,
    &IID_IDqControllerStatics
};
static struct factory queue_factory =
{
    { (IActivationFactoryVtbl *)&factory_vtbl }, { (IInspectableVtbl *)&queue_statics_vtbl }, name_queue, &IID_IDqQueueStatics
};

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **out)
{
    LPCWSTR name = WindowsGetStringRawBuffer(classid, NULL);

    TRACE("%s, %p\n", debugstr_w(name), out);

    if (!out)
        return E_POINTER;
    *out = NULL;
    if (name && !wcscmp(name, name_controller))
        *out = &controller_factory.IActivationFactory_iface;
    else if (name && !wcscmp(name, name_queue))
        *out = &queue_factory.IActivationFactory_iface;
    else
        return CLASS_E_CLASSNOTAVAILABLE;
    return S_OK;
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    /* queues and their windows hold code from this DLL */
    return S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        dq_instance = instance;
        DisableThreadLibraryCalls(instance);
        dq_tls = TlsAlloc();
        break;
    case DLL_PROCESS_DETACH:
        if (reserved)
            break;
        if (dq_tls != TLS_OUT_OF_INDEXES)
            TlsFree(dq_tls);
        if (dq_class)
            UnregisterClassW(dq_class_name, dq_instance);
        break;
    }
    return TRUE;
}
