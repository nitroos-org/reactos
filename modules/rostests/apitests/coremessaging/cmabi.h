/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Binary interface of the Windows.System.DispatcherQueue classes, for the CoreMessaging tests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * From the published Windows Runtime metadata (sdk/include/psdk/windows.system.idl,
 * windows.foundation.idl, asyncinfo.idl). The IIDs of the parameterized delegates are computed from
 * their type signatures (the documented Windows Runtime algorithm).
 */

#pragma once

#include <inspectable.h>

typedef unsigned char CmBool;
typedef struct { INT64 Value; } CmToken;
typedef struct { INT64 Duration; } CmTimeSpan;

enum { CmPriorityLow = -10, CmPriorityNormal = 0, CmPriorityHigh = 10 };
enum { CmAsyncStarted = 0, CmAsyncCompleted = 1, CmAsyncCanceled = 2, CmAsyncError = 3 };

#define CM_INSPECTABLE(T) \
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(T *This, REFIID iid, void **out); \
    ULONG (STDMETHODCALLTYPE *AddRef)(T *This); \
    ULONG (STDMETHODCALLTYPE *Release)(T *This); \
    HRESULT (STDMETHODCALLTYPE *GetIids)(T *This, ULONG *count, IID **iids); \
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(T *This, HSTRING *name); \
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(T *This, TrustLevel *level);
#define CM_UNKNOWN(T) \
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(T *This, REFIID iid, void **out); \
    ULONG (STDMETHODCALLTYPE *AddRef)(T *This); \
    ULONG (STDMETHODCALLTYPE *Release)(T *This);

typedef struct CmQueue CmQueue;
typedef struct CmQueue2 CmQueue2;
typedef struct CmController CmController;
typedef struct CmControllerStatics CmControllerStatics;
typedef struct CmQueueStatics CmQueueStatics;
typedef struct CmTimer CmTimer;
typedef struct CmShutdownArgs CmShutdownArgs;
typedef struct CmDeferral CmDeferral;
typedef struct CmAsyncAction CmAsyncAction;
typedef struct CmAsyncInfo CmAsyncInfo;
typedef struct CmHandler CmHandler;             /* Windows.System.DispatcherQueueHandler */
typedef struct CmTypedHandler CmTypedHandler;   /* Windows.Foundation.TypedEventHandler<,> */
typedef struct CmActionHandler CmActionHandler; /* Windows.Foundation.AsyncActionCompletedHandler */

struct CmHandlerVtbl { CM_UNKNOWN(CmHandler) HRESULT (STDMETHODCALLTYPE *Invoke)(CmHandler *This); };
struct CmHandler { const struct CmHandlerVtbl *lpVtbl; };
struct CmTypedHandlerVtbl { CM_UNKNOWN(CmTypedHandler) HRESULT (STDMETHODCALLTYPE *Invoke)(CmTypedHandler *This, IInspectable *sender, IInspectable *args); };
struct CmTypedHandler { const struct CmTypedHandlerVtbl *lpVtbl; };
struct CmActionHandlerVtbl { CM_UNKNOWN(CmActionHandler) HRESULT (STDMETHODCALLTYPE *Invoke)(CmActionHandler *This, CmAsyncAction *action, int status); };
struct CmActionHandler { const struct CmActionHandlerVtbl *lpVtbl; };

struct CmQueueVtbl
{
    CM_INSPECTABLE(CmQueue)
    HRESULT (STDMETHODCALLTYPE *CreateTimer)(CmQueue *This, CmTimer **timer);
    HRESULT (STDMETHODCALLTYPE *TryEnqueue)(CmQueue *This, CmHandler *callback, CmBool *result);
    HRESULT (STDMETHODCALLTYPE *TryEnqueueWithPriority)(CmQueue *This, int priority, CmHandler *callback, CmBool *result);
    HRESULT (STDMETHODCALLTYPE *add_ShutdownStarting)(CmQueue *This, CmTypedHandler *handler, CmToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_ShutdownStarting)(CmQueue *This, CmToken token);
    HRESULT (STDMETHODCALLTYPE *add_ShutdownCompleted)(CmQueue *This, CmTypedHandler *handler, CmToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_ShutdownCompleted)(CmQueue *This, CmToken token);
};
struct CmQueue { const struct CmQueueVtbl *lpVtbl; };

struct CmQueue2Vtbl { CM_INSPECTABLE(CmQueue2) HRESULT (STDMETHODCALLTYPE *get_HasThreadAccess)(CmQueue2 *This, CmBool *value); };
struct CmQueue2 { const struct CmQueue2Vtbl *lpVtbl; };

struct CmControllerVtbl
{
    CM_INSPECTABLE(CmController)
    HRESULT (STDMETHODCALLTYPE *get_DispatcherQueue)(CmController *This, CmQueue **queue);
    HRESULT (STDMETHODCALLTYPE *ShutdownQueueAsync)(CmController *This, CmAsyncAction **action);
};
struct CmController { const struct CmControllerVtbl *lpVtbl; };

struct CmControllerStaticsVtbl { CM_INSPECTABLE(CmControllerStatics) HRESULT (STDMETHODCALLTYPE *CreateOnDedicatedThread)(CmControllerStatics *This, CmController **result); };
struct CmControllerStatics { const struct CmControllerStaticsVtbl *lpVtbl; };
struct CmQueueStaticsVtbl { CM_INSPECTABLE(CmQueueStatics) HRESULT (STDMETHODCALLTYPE *GetForCurrentThread)(CmQueueStatics *This, CmQueue **result); };
struct CmQueueStatics { const struct CmQueueStaticsVtbl *lpVtbl; };

struct CmTimerVtbl
{
    CM_INSPECTABLE(CmTimer)
    HRESULT (STDMETHODCALLTYPE *get_Interval)(CmTimer *This, CmTimeSpan *value);
    HRESULT (STDMETHODCALLTYPE *put_Interval)(CmTimer *This, CmTimeSpan value);
    HRESULT (STDMETHODCALLTYPE *get_IsRunning)(CmTimer *This, CmBool *value);
    HRESULT (STDMETHODCALLTYPE *get_IsRepeating)(CmTimer *This, CmBool *value);
    HRESULT (STDMETHODCALLTYPE *put_IsRepeating)(CmTimer *This, CmBool value);
    HRESULT (STDMETHODCALLTYPE *Start)(CmTimer *This);
    HRESULT (STDMETHODCALLTYPE *Stop)(CmTimer *This);
    HRESULT (STDMETHODCALLTYPE *add_Tick)(CmTimer *This, CmTypedHandler *handler, CmToken *token);
    HRESULT (STDMETHODCALLTYPE *remove_Tick)(CmTimer *This, CmToken token);
};
struct CmTimer { const struct CmTimerVtbl *lpVtbl; };

struct CmShutdownArgsVtbl { CM_INSPECTABLE(CmShutdownArgs) HRESULT (STDMETHODCALLTYPE *GetDeferral)(CmShutdownArgs *This, CmDeferral **result); };
struct CmShutdownArgs { const struct CmShutdownArgsVtbl *lpVtbl; };
struct CmDeferralVtbl { CM_INSPECTABLE(CmDeferral) HRESULT (STDMETHODCALLTYPE *Complete)(CmDeferral *This); };
struct CmDeferral { const struct CmDeferralVtbl *lpVtbl; };

struct CmAsyncActionVtbl
{
    CM_INSPECTABLE(CmAsyncAction)
    HRESULT (STDMETHODCALLTYPE *put_Completed)(CmAsyncAction *This, CmActionHandler *handler);
    HRESULT (STDMETHODCALLTYPE *get_Completed)(CmAsyncAction *This, CmActionHandler **handler);
    HRESULT (STDMETHODCALLTYPE *GetResults)(CmAsyncAction *This);
};
struct CmAsyncAction { const struct CmAsyncActionVtbl *lpVtbl; };
struct CmAsyncInfoVtbl
{
    CM_INSPECTABLE(CmAsyncInfo)
    HRESULT (STDMETHODCALLTYPE *get_Id)(CmAsyncInfo *This, UINT32 *id);
    HRESULT (STDMETHODCALLTYPE *get_Status)(CmAsyncInfo *This, int *status);
    HRESULT (STDMETHODCALLTYPE *get_ErrorCode)(CmAsyncInfo *This, HRESULT *code);
    HRESULT (STDMETHODCALLTYPE *Cancel)(CmAsyncInfo *This);
    HRESULT (STDMETHODCALLTYPE *Close)(CmAsyncInfo *This);
};
struct CmAsyncInfo { const struct CmAsyncInfoVtbl *lpVtbl; };

/* dispatcherqueue.h */
typedef struct
{
    DWORD dwSize;
    int threadType;    /* DQTYPE_THREAD_DEDICATED 1, DQTYPE_THREAD_CURRENT 2 */
    int apartmentType; /* DQTAT_COM_NONE 0, DQTAT_COM_ASTA 1, DQTAT_COM_STA 2 */
} CmOptions;
typedef HRESULT (WINAPI *PFN_CREATE_DQC)(CmOptions options, CmController **controller);

DEFINE_GUID(IID_CmQueue,             0x603e88e4, 0xa338, 0x4ffe, 0xa4, 0x57, 0xa5, 0xcf, 0xb9, 0xce, 0xb8, 0x99);
DEFINE_GUID(IID_CmQueue2,            0xc822c647, 0x30ef, 0x506e, 0xbd, 0x1e, 0xa6, 0x47, 0xae, 0x66, 0x75, 0xff);
DEFINE_GUID(IID_CmController,        0x22f34e66, 0x50db, 0x4e36, 0xa9, 0x8d, 0x61, 0xc0, 0x1b, 0x38, 0x4d, 0x20);
DEFINE_GUID(IID_CmControllerStatics, 0x0a6c98e0, 0x5198, 0x49a2, 0xa3, 0x13, 0x3f, 0x70, 0xd1, 0xf1, 0x3c, 0x27);
DEFINE_GUID(IID_CmQueueStatics,      0xa96d83d7, 0x9371, 0x4517, 0x92, 0x45, 0xd0, 0x82, 0x4a, 0xc1, 0x2c, 0x74);
DEFINE_GUID(IID_CmTimer,             0x5feabb1d, 0xa31c, 0x4727, 0xb1, 0xac, 0x37, 0x45, 0x46, 0x49, 0xd5, 0x6a);
DEFINE_GUID(IID_CmShutdownArgs,      0xc4724c4c, 0xff97, 0x40c0, 0xa2, 0x26, 0xcc, 0x0a, 0xaa, 0x54, 0x5e, 0x89);
DEFINE_GUID(IID_CmHandler,           0xdfa2dc9c, 0x1a2d, 0x4917, 0x98, 0xf2, 0x93, 0x9a, 0xf1, 0xd6, 0xe0, 0xc8);
DEFINE_GUID(IID_CmDeferral,          0xd6269732, 0x3b7f, 0x46a7, 0xb4, 0x0b, 0x4f, 0xdc, 0xa2, 0xa2, 0xc6, 0x93);
DEFINE_GUID(IID_CmClosable,          0x30d5a829, 0x7fa4, 0x4026, 0x83, 0xbb, 0xd7, 0x5b, 0xae, 0x4e, 0xa9, 0x9e);
DEFINE_GUID(IID_CmAsyncAction,       0x5a648006, 0x843a, 0x4da9, 0x86, 0x5b, 0x9d, 0x26, 0xe5, 0xdf, 0xad, 0x7b);
DEFINE_GUID(IID_CmAsyncInfo,         0x00000036, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
DEFINE_GUID(IID_CmActionHandler,     0xa4ed5c81, 0x76c9, 0x40bd, 0x8b, 0xe6, 0xb1, 0xd9, 0x0f, 0xb2, 0x0a, 0xe7);
DEFINE_GUID(IID_CmAgileObject,       0x94ea2b94, 0xe9cc, 0x49e0, 0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90);
DEFINE_GUID(IID_CmActivationFactory, 0x00000035, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
/* TypedEventHandler<DispatcherQueue, IInspectable>, <DispatcherQueue, DispatcherQueueShutdownStartingEventArgs>,
 * <DispatcherQueueTimer, IInspectable> */
DEFINE_GUID(IID_CmQueueObjHandler,   0xfe79f855, 0x2f40, 0x5b88, 0xa0, 0xc3, 0x4c, 0x04, 0x2a, 0x05, 0xdd, 0x05);
DEFINE_GUID(IID_CmQueueArgsHandler,  0xb58b5e24, 0xe1c6, 0x528e, 0x9d, 0x99, 0x07, 0xec, 0x88, 0x29, 0xde, 0xa5);
DEFINE_GUID(IID_CmTimerHandler,      0x8b5644c8, 0x8b57, 0x50ce, 0x89, 0x33, 0x7a, 0xb2, 0xcc, 0x5a, 0x14, 0xef);
