/*
 * PROJECT:     ReactOS PSDK
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateDispatcherQueueController (CoreMessaging.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _DISPATCHERQUEUE_H_
#define _DISPATCHERQUEUE_H_

#ifdef __cplusplus
namespace ABI { namespace Windows { namespace System { struct IDispatcherQueueController; } } }
typedef ABI::Windows::System::IDispatcherQueueController *PDISPATCHERQUEUECONTROLLER;
#else
typedef struct __x_ABI_CWindows_CSystem_CIDispatcherQueueController *PDISPATCHERQUEUECONTROLLER;
#endif

typedef enum DISPATCHERQUEUE_THREAD_APARTMENTTYPE
{
    DQTAT_COM_NONE = 0,
    DQTAT_COM_ASTA = 1,
    DQTAT_COM_STA = 2
} DISPATCHERQUEUE_THREAD_APARTMENTTYPE;

typedef enum DISPATCHERQUEUE_THREAD_TYPE
{
    DQTYPE_THREAD_DEDICATED = 1,
    DQTYPE_THREAD_CURRENT = 2
} DISPATCHERQUEUE_THREAD_TYPE;

typedef struct DispatcherQueueOptions
{
    DWORD dwSize;
    DISPATCHERQUEUE_THREAD_TYPE threadType;
    DISPATCHERQUEUE_THREAD_APARTMENTTYPE apartmentType;
} DispatcherQueueOptions;

#ifdef __cplusplus
extern "C"
#endif
HRESULT WINAPI CreateDispatcherQueueController(DispatcherQueueOptions options,
                                               PDISPATCHERQUEUECONTROLLER *dispatcherQueueController);

#endif /* _DISPATCHERQUEUE_H_ */
