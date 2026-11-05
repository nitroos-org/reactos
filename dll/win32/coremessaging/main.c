/*
 * PROJECT:     ReactOS CoreMessaging
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateDispatcherQueueController and the Windows.System.DispatcherQueue classes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A dispatcher queue runs work items on one thread, in priority order, when that thread dispatches window
 * messages. This follows the documented contract (dispatcherqueue.h, Windows.System.DispatcherQueue*); the
 * argument checks of CreateDispatcherQueueController were measured on Windows 10 22H2 with coremessaging_apitest
 * (E_INVALIDARG, output left alone). Windows ends the process for an unknown apartment type; this returns
 * E_INVALIDARG instead. Each queue has a message-only
 * window on its thread: work items, timers and the shutdown sequence arrive there as messages, so they run
 * in whatever message loop the thread has (the caller's for DQTYPE_THREAD_CURRENT, our own for
 * DQTYPE_THREAD_DEDICATED). Microsoft Word loads this DLL for its composition (WinComp) renderer.
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
    INT64 next_token;
    LONG deferrals;
    BOOL finish_pending;
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

static void queue_release(struct queue *queue)
{
    if (!InterlockedDecrement(&queue->ref))
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
        DeleteCriticalSection(&queue->cs);
        HeapFree(GetProcessHeap(), 0, queue);
    }
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
    struct queue *queue = impl_from_IDqQueue(iface);
    ULONG ref = queue->ref - 1;

    queue_release(queue);
    return ref;
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
    BOOL post = FALSE;

    TRACE("queue %p, priority %d, callback %p\n", queue, priority, callback);

    if (!callback)
        return E_INVALIDARG;
    if (!result)
        return E_POINTER;
    if (!(item = HeapAlloc(GetProcessHeap(), 0, sizeof(*item))))
        return E_OUTOFMEMORY;
    item->handler = callback;
    EnterCriticalSection(&queue->cs);
    if (queue->state == QUEUE_SHUT_DOWN)
    {
        LeaveCriticalSection(&queue->cs);
        HeapFree(GetProcessHeap(), 0, item);
        *result = FALSE;
        return S_OK;
    }
    IUnknown_AddRef((IUnknown *)callback);
    list_add_tail(&queue->items[priority_slot(priority)], &item->entry);
    post = TRUE;
    LeaveCriticalSection(&queue->cs);
    if (post && !PostMessageW(queue->hwnd, WM_DQ_WORK, 0, 0))
        WARN("PostMessage failed, error %lu\n", GetLastError());
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

/* runs the work items present now, highest priority first; items added meanwhile get a message of their own */
static void queue_run_items(struct queue *queue)
{
    struct work_item *item;
    struct list *head;
    int i;

    for (;;)
    {
        item = NULL;
        EnterCriticalSection(&queue->cs);
        if (queue->state != QUEUE_SHUT_DOWN)
        {
            for (i = 0; i < 3 && !item; i++)
            {
                if ((head = list_head(&queue->items[i])))
                {
                    item = LIST_ENTRY(head, struct work_item, entry);
                    list_remove(&item->entry);
                }
            }
        }
        LeaveCriticalSection(&queue->cs);
        if (!item)
            break;
        {
            HRESULT hr = item->handler->lpVtbl->Invoke(item->handler);
            if (FAILED(hr))
                WARN("work item %p returned %#lx\n", item->handler, hr);
        }
        IUnknown_Release((IUnknown *)item->handler);
        HeapFree(GetProcessHeap(), 0, item);
        /* one item per message, so input and paint messages interleave with the work */
        break;
    }
    EnterCriticalSection(&queue->cs);
    for (i = 0; i < 3; i++)
    {
        if (!list_empty(&queue->items[i]) && queue->state != QUEUE_SHUT_DOWN)
        {
            PostMessageW(queue->hwnd, WM_DQ_WORK, 0, 0);
            break;
        }
    }
    LeaveCriticalSection(&queue->cs);
}

static void timer_stop_on_thread(struct timer *timer);

/* the last step of a shutdown, on the queue thread: no work any more, ShutdownCompleted, the action completes */
static void queue_finish_shutdown(struct queue *queue)
{
    struct work_item *item, *next_item;
    struct timer *timer, *next_timer;
    struct list items;
    struct async_action *action;
    int i;

    TRACE("queue %p shut down\n", queue);
    queue_addref(queue);
    list_init(&items);
    EnterCriticalSection(&queue->cs);
    queue->state = QUEUE_SHUT_DOWN;
    queue->finish_pending = FALSE;
    for (i = 0; i < 3; i++)
        list_move_tail(&items, &queue->items[i]);
    action = queue->shutdown;
    if (action)
        action_AddRef(&action->IDqAsyncAction_iface);
    LeaveCriticalSection(&queue->cs);

    LIST_FOR_EACH_ENTRY_SAFE(item, next_item, &items, struct work_item, entry)
    {
        list_remove(&item->entry);
        IUnknown_Release((IUnknown *)item->handler);
        HeapFree(GetProcessHeap(), 0, item);
    }
    LIST_FOR_EACH_ENTRY_SAFE(timer, next_timer, &queue->timers, struct timer, entry)
        timer_stop_on_thread(timer);

    raise_event(&queue->cs, &queue->completed, (IInspectable *)&queue->IDqQueue_iface, NULL);

    if (dq_tls != TLS_OUT_OF_INDEXES && TlsGetValue(dq_tls) == queue)
    {
        TlsSetValue(dq_tls, NULL);
        queue_release(queue);
    }
    if (action)
    {
        action_complete(action);
        action_Release(&action->IDqAsyncAction_iface);
    }
    if (queue->dedicated)
        PostQuitMessage(0);
    else
        DestroyWindow(queue->hwnd);
    queue_release(queue);
}

static HRESULT args_create(struct queue *queue, IInspectable **out);

static void queue_start_shutdown(struct queue *queue)
{
    IInspectable *args = NULL;
    BOOL finish;

    EnterCriticalSection(&queue->cs);
    if (queue->state != QUEUE_RUNNING)
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
    BOOL finish;

    EnterCriticalSection(&queue->cs);
    finish = !--queue->deferrals && queue->state == QUEUE_SHUTTING_DOWN && !queue->finish_pending;
    if (finish)
        queue->finish_pending = TRUE;
    LeaveCriticalSection(&queue->cs);
    if (finish)
        PostMessageW(queue->hwnd, WM_DQ_FINISH, 0, 0);
}

static void timer_tick(struct queue *queue, UINT_PTR id);
static void timer_apply(struct timer *timer, BOOL start);

static LRESULT CALLBACK queue_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    struct queue *queue = (struct queue *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    if (!queue)
        return DefWindowProcW(hwnd, msg, wparam, lparam);

    switch (msg)
    {
    case WM_DQ_WORK:
        queue_run_items(queue);
        return 0;
    case WM_DQ_SHUTDOWN:
        queue_start_shutdown(queue);
        return 0;
    case WM_DQ_FINISH:
        if (queue->state == QUEUE_SHUTTING_DOWN && !queue->deferrals)
            queue_finish_shutdown(queue);
        return 0;
    case WM_DQ_TIMER:
        timer_apply((struct timer *)lparam, (BOOL)wparam);
        return 0;
    case WM_TIMER:
        timer_tick(queue, wparam);
        return 0;
    case WM_NCDESTROY:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        queue_release(queue);
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
    queue->hwnd = CreateWindowExW(0, dq_class_name, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, dq_instance, NULL);
    if (!queue->hwnd)
        return HRESULT_FROM_WIN32(GetLastError());
    queue->thread_id = GetCurrentThreadId();
    queue_addref(queue); /* the window's */
    SetWindowLongPtrW(queue->hwnd, GWLP_USERDATA, (LONG_PTR)queue);
    queue_addref(queue); /* the thread's */
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
    return queue;
}

static HRESULT queue_request_shutdown(struct queue *queue, IDqAsyncAction **out)
{
    struct async_action *action;
    BOOL post = FALSE;

    EnterCriticalSection(&queue->cs);
    if (!(action = queue->shutdown))
    {
        if (!(action = action_create()))
        {
            LeaveCriticalSection(&queue->cs);
            return E_OUTOFMEMORY;
        }
        queue->shutdown = action;
        post = TRUE;
    }
    action_AddRef(&action->IDqAsyncAction_iface);
    LeaveCriticalSection(&queue->cs);
    if (post && !PostMessageW(queue->hwnd, WM_DQ_SHUTDOWN, 0, 0))
        WARN("PostMessage failed, error %lu\n", GetLastError());
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
    deferral->queue = args->queue;
    queue_addref(args->queue);
    EnterCriticalSection(&args->queue->cs);
    args->queue->deferrals++;
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

/* on the queue thread: (re)start or stop the window timer */
static void timer_apply(struct timer *timer, BOOL start)
{
    struct queue *queue = timer->queue;
    UINT ms;

    if (start && queue->state != QUEUE_SHUT_DOWN)
    {
        ms = (UINT)min((timer->interval + 9999) / 10000, (INT64)USER_TIMER_MAXIMUM);
        EnterCriticalSection(&queue->cs);
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
    else if (!start)
        timer_stop_on_thread(timer);
    timer_Release(&timer->IDqTimer_iface); /* the request's */
}

static HRESULT timer_request(struct timer *timer, BOOL start)
{
    struct queue *queue = timer->queue;

    if (queue->state == QUEUE_SHUT_DOWN)
        return start ? RPC_E_DISCONNECTED : S_OK;
    timer_AddRef(&timer->IDqTimer_iface);
    if (queue->thread_id == GetCurrentThreadId())
    {
        timer_apply(timer, start);
        return S_OK;
    }
    /* SetTimer works only on the thread of the window; the caller sees the new state right away */
    EnterCriticalSection(&queue->cs);
    timer->running = start;
    LeaveCriticalSection(&queue->cs);
    if (!PostMessageW(queue->hwnd, WM_DQ_TIMER, start, (LPARAM)timer))
    {
        timer_Release(&timer->IDqTimer_iface);
        return HRESULT_FROM_WIN32(GetLastError());
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
    HRESULT com = E_FAIL, hr;
    HMODULE self = NULL;
    MSG msg;

    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)dedicated_thread, &self);
    if (start->apartment == DQTAT_COM_STA || start->apartment == DQTAT_COM_ASTA)
    {
        if (start->apartment == DQTAT_COM_ASTA)
            FIXME("application STA: a single-threaded apartment is used\n");
        com = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    }
    queue_addref(queue);
    hr = queue_attach(queue);
    start->hr = hr;
    SetEvent(start->ready); /* start is gone after this */
    if (SUCCEEDED(hr))
    {
        while (GetMessageW(&msg, NULL, 0, 0) > 0)
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (queue->hwnd)
            DestroyWindow(queue->hwnd);
    }
    if (TlsGetValue(dq_tls) == queue)
    {
        TlsSetValue(dq_tls, NULL);
        queue_release(queue);
    }
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
        if (options.apartmentType != DQTAT_COM_NONE)
            return E_INVALIDARG;
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
