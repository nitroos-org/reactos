/*
 * PROJECT:     ReactOS CoreMessaging
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Binary interface of the Windows.System.DispatcherQueue classes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * From the published Windows Runtime metadata (sdk/include/psdk/windows.system.idl, windows.foundation.idl,
 * asyncinfo.idl): the C binding widl would generate, written out because these IDL files are not compiled
 * to headers in this tree. The IIDs are the ones in those IDL files; no parameterized interface is used.
 */

#pragma once

typedef unsigned char DqBool;
typedef struct { INT64 value; } DqToken;     /* EventRegistrationToken */
typedef struct { INT64 Duration; } DqTimeSpan; /* Windows.Foundation.TimeSpan */

enum { DqPriorityLow = -10, DqPriorityNormal = 0, DqPriorityHigh = 10 };
typedef enum { DqAsyncStarted = 0, DqAsyncCompleted = 1, DqAsyncCanceled = 2, DqAsyncError = 3 } DqAsyncStatus;

#define DQ_UNKNOWN_METHODS(T) \
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(T *This, REFIID iid, void **out); \
    ULONG (STDMETHODCALLTYPE *AddRef)(T *This); \
    ULONG (STDMETHODCALLTYPE *Release)(T *This);
#define DQ_INSPECTABLE_METHODS(T) \
    DQ_UNKNOWN_METHODS(T) \
    HRESULT (STDMETHODCALLTYPE *GetIids)(T *This, ULONG *count, IID **iids); \
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(T *This, HSTRING *name); \
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(T *This, TrustLevel *level);
#define DQ_INTERFACE(name, methods) \
    typedef struct name name; \
    typedef struct name##Vtbl { methods } name##Vtbl; \
    struct name { const name##Vtbl *lpVtbl; };

typedef struct IDqQueue IDqQueue;
typedef struct IDqTimer IDqTimer;
typedef struct IDqController IDqController;
typedef struct IDqAsyncAction IDqAsyncAction;
typedef struct IDqDeferral IDqDeferral;

/* Windows.System.DispatcherQueueHandler */
DQ_INTERFACE(IDqHandler, DQ_UNKNOWN_METHODS(IDqHandler)
    HRESULT (STDMETHODCALLTYPE *Invoke)(IDqHandler *This);)
/* Windows.Foundation.TypedEventHandler<TSender, TResult> */
DQ_INTERFACE(IDqTypedHandler, DQ_UNKNOWN_METHODS(IDqTypedHandler)
    HRESULT (STDMETHODCALLTYPE *Invoke)(IDqTypedHandler *This, IInspectable *sender, IInspectable *args);)
/* Windows.Foundation.AsyncActionCompletedHandler */
DQ_INTERFACE(IDqActionHandler, DQ_UNKNOWN_METHODS(IDqActionHandler)
    HRESULT (STDMETHODCALLTYPE *Invoke)(IDqActionHandler *This, IDqAsyncAction *action, DqAsyncStatus status);)

/* Windows.System.IDispatcherQueue */
typedef struct IDqQueueVtbl
{
    DQ_INSPECTABLE_METHODS(IDqQueue)
    HRESULT (STDMETHODCALLTYPE *CreateTimer)(IDqQueue *This, IDqTimer **timer);
    HRESULT (STDMETHODCALLTYPE *TryEnqueue)(IDqQueue *This, IDqHandler *callback, DqBool *result);
    HRESULT (STDMETHODCALLTYPE *TryEnqueueWithPriority)(IDqQueue *This, INT32 priority, IDqHandler *callback, DqBool *result);
    HRESULT (STDMETHODCALLTYPE *add_ShutdownStarting)(IDqQueue *This, IDqTypedHandler *handler, DqToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_ShutdownStarting)(IDqQueue *This, DqToken token);
    HRESULT (STDMETHODCALLTYPE *add_ShutdownCompleted)(IDqQueue *This, IDqTypedHandler *handler, DqToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_ShutdownCompleted)(IDqQueue *This, DqToken token);
} IDqQueueVtbl;
struct IDqQueue { const IDqQueueVtbl *lpVtbl; };

/* Windows.System.IDispatcherQueue2 */
DQ_INTERFACE(IDqQueue2, DQ_INSPECTABLE_METHODS(IDqQueue2)
    HRESULT (STDMETHODCALLTYPE *get_HasThreadAccess)(IDqQueue2 *This, DqBool *value);)

/* Windows.System.IDispatcherQueueController */
typedef struct IDqControllerVtbl
{
    DQ_INSPECTABLE_METHODS(IDqController)
    HRESULT (STDMETHODCALLTYPE *get_DispatcherQueue)(IDqController *This, IDqQueue **queue);
    HRESULT (STDMETHODCALLTYPE *ShutdownQueueAsync)(IDqController *This, IDqAsyncAction **action);
} IDqControllerVtbl;
struct IDqController { const IDqControllerVtbl *lpVtbl; };

/* Windows.System.IDispatcherQueueControllerStatics, IDispatcherQueueStatics */
DQ_INTERFACE(IDqControllerStatics, DQ_INSPECTABLE_METHODS(IDqControllerStatics)
    HRESULT (STDMETHODCALLTYPE *CreateOnDedicatedThread)(IDqControllerStatics *This, IDqController **result);)
DQ_INTERFACE(IDqQueueStatics, DQ_INSPECTABLE_METHODS(IDqQueueStatics)
    HRESULT (STDMETHODCALLTYPE *GetForCurrentThread)(IDqQueueStatics *This, IDqQueue **result);)

/* Windows.System.IDispatcherQueueTimer */
typedef struct IDqTimerVtbl
{
    DQ_INSPECTABLE_METHODS(IDqTimer)
    HRESULT (STDMETHODCALLTYPE *get_Interval)(IDqTimer *This, DqTimeSpan *value);
    HRESULT (STDMETHODCALLTYPE *put_Interval)(IDqTimer *This, DqTimeSpan value);
    HRESULT (STDMETHODCALLTYPE *get_IsRunning)(IDqTimer *This, DqBool *value);
    HRESULT (STDMETHODCALLTYPE *get_IsRepeating)(IDqTimer *This, DqBool *value);
    HRESULT (STDMETHODCALLTYPE *put_IsRepeating)(IDqTimer *This, DqBool value);
    HRESULT (STDMETHODCALLTYPE *Start)(IDqTimer *This);
    HRESULT (STDMETHODCALLTYPE *Stop)(IDqTimer *This);
    HRESULT (STDMETHODCALLTYPE *add_Tick)(IDqTimer *This, IDqTypedHandler *handler, DqToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_Tick)(IDqTimer *This, DqToken token);
} IDqTimerVtbl;
struct IDqTimer { const IDqTimerVtbl *lpVtbl; };

/* Windows.System.IDispatcherQueueShutdownStartingEventArgs */
DQ_INTERFACE(IDqShutdownArgs, DQ_INSPECTABLE_METHODS(IDqShutdownArgs)
    HRESULT (STDMETHODCALLTYPE *GetDeferral)(IDqShutdownArgs *This, IDqDeferral **result);)

/* Windows.Foundation.IDeferral, IClosable */
typedef struct IDqDeferralVtbl
{
    DQ_INSPECTABLE_METHODS(IDqDeferral)
    HRESULT (STDMETHODCALLTYPE *Complete)(IDqDeferral *This);
} IDqDeferralVtbl;
struct IDqDeferral { const IDqDeferralVtbl *lpVtbl; };
DQ_INTERFACE(IDqClosable, DQ_INSPECTABLE_METHODS(IDqClosable)
    HRESULT (STDMETHODCALLTYPE *Close)(IDqClosable *This);)

/* Windows.Foundation.IAsyncAction, IAsyncInfo */
typedef struct IDqAsyncActionVtbl
{
    DQ_INSPECTABLE_METHODS(IDqAsyncAction)
    HRESULT (STDMETHODCALLTYPE *put_Completed)(IDqAsyncAction *This, IDqActionHandler *handler);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(IDqAsyncAction *This, IDqActionHandler **handler);
    HRESULT (STDMETHODCALLTYPE *GetResults)(IDqAsyncAction *This);
} IDqAsyncActionVtbl;
struct IDqAsyncAction { const IDqAsyncActionVtbl *lpVtbl; };
DQ_INTERFACE(IDqAsyncInfo, DQ_INSPECTABLE_METHODS(IDqAsyncInfo)
    HRESULT (STDMETHODCALLTYPE *get_Id)(IDqAsyncInfo *This, UINT32 *id);
    HRESULT (STDMETHODCALLTYPE *get_Status)(IDqAsyncInfo *This, DqAsyncStatus *status);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(IDqAsyncInfo *This, HRESULT *code);
    HRESULT (STDMETHODCALLTYPE *Cancel)(IDqAsyncInfo *This);
    HRESULT (STDMETHODCALLTYPE *Close)(IDqAsyncInfo *This);)

DEFINE_GUID(IID_IDqQueue,             0x603e88e4, 0xa338, 0x4ffe, 0xa4, 0x57, 0xa5, 0xcf, 0xb9, 0xce, 0xb8, 0x99);
DEFINE_GUID(IID_IDqQueue2,            0xc822c647, 0x30ef, 0x506e, 0xbd, 0x1e, 0xa6, 0x47, 0xae, 0x66, 0x75, 0xff);
DEFINE_GUID(IID_IDqController,        0x22f34e66, 0x50db, 0x4e36, 0xa9, 0x8d, 0x61, 0xc0, 0x1b, 0x38, 0x4d, 0x20);
DEFINE_GUID(IID_IDqControllerStatics, 0x0a6c98e0, 0x5198, 0x49a2, 0xa3, 0x13, 0x3f, 0x70, 0xd1, 0xf1, 0x3c, 0x27);
DEFINE_GUID(IID_IDqQueueStatics,      0xa96d83d7, 0x9371, 0x4517, 0x92, 0x45, 0xd0, 0x82, 0x4a, 0xc1, 0x2c, 0x74);
DEFINE_GUID(IID_IDqTimer,             0x5feabb1d, 0xa31c, 0x4727, 0xb1, 0xac, 0x37, 0x45, 0x46, 0x49, 0xd5, 0x6a);
DEFINE_GUID(IID_IDqShutdownArgs,      0xc4724c4c, 0xff97, 0x40c0, 0xa2, 0x26, 0xcc, 0x0a, 0xaa, 0x54, 0x5e, 0x89);
DEFINE_GUID(IID_IDqDeferral,          0xd6269732, 0x3b7f, 0x46a7, 0xb4, 0x0b, 0x4f, 0xdc, 0xa2, 0xa2, 0xc6, 0x93);
DEFINE_GUID(IID_IDqClosable,          0x30d5a829, 0x7fa4, 0x4026, 0x83, 0xbb, 0xd7, 0x5b, 0xae, 0x4e, 0xa9, 0x9e);
DEFINE_GUID(IID_IDqAsyncAction,       0x5a648006, 0x843a, 0x4da9, 0x86, 0x5b, 0x9d, 0x26, 0xe5, 0xdf, 0xad, 0x7b);
DEFINE_GUID(IID_IDqAsyncInfo,         0x00000036, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
DEFINE_GUID(IID_IDqAgileObject,       0x94ea2b94, 0xe9cc, 0x49e0, 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90);
