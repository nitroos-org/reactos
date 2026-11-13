/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Context.c
* PURPOSE:         Contains context routines
* PROGRAMMERS:     Ged Murphy (gedmurphy@reactos.org)
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/

static
LONG
ContextTypeToIndex(
    _In_ FLT_CONTEXT_TYPE ContextType
)
{
    switch (ContextType)
    {
    case FLT_VOLUME_CONTEXT: return FLTP_CTX_INDEX_VOLUME;
    case FLT_INSTANCE_CONTEXT: return FLTP_CTX_INDEX_INSTANCE;
    case FLT_FILE_CONTEXT: return FLTP_CTX_INDEX_FILE;
    case FLT_STREAM_CONTEXT: return FLTP_CTX_INDEX_STREAM;
    case FLT_STREAMHANDLE_CONTEXT: return FLTP_CTX_INDEX_STREAMHANDLE;
    case FLT_TRANSACTION_CONTEXT: return FLTP_CTX_INDEX_TRANSACTION;
    }

    return -1;
}


/* INTERNAL FUNCTIONS ******************************************************/

NTSTATUS
FltpRegisterContexts(_In_ PFLT_FILTER Filter,
                     _In_ const FLT_CONTEXT_REGISTRATION *Context)
{
    PCFLT_CONTEXT_REGISTRATION ContextPtr;
    LONG Index;

    /* Loop through all entries in the context registration array */
    for (ContextPtr = Context; ContextPtr->ContextType != FLT_CONTEXT_END; ContextPtr++)
    {
        Index = ContextTypeToIndex(ContextPtr->ContextType);
        if (Index < 0 || Filter->ContextDefs[Index].Registered)
            return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;

        /* Size and pooltag are only checked when ContextAllocateCallback is null */
        if (ContextPtr->ContextAllocateCallback == NULL &&
            (ContextPtr->PoolTag == 0 || ContextPtr->Size == 0))
        {
            return STATUS_FLT_INVALID_CONTEXT_REGISTRATION;
        }

        Filter->ContextDefs[Index].Registered = TRUE;
        Filter->ContextDefs[Index].Flags = ContextPtr->Flags;
        Filter->ContextDefs[Index].CleanupCallback = ContextPtr->ContextCleanupCallback;
        Filter->ContextDefs[Index].Size = ContextPtr->Size;
        Filter->ContextDefs[Index].PoolTag = ContextPtr->PoolTag;
        Filter->ContextDefs[Index].AllocateCallback = ContextPtr->ContextAllocateCallback;
        Filter->ContextDefs[Index].FreeCallback = ContextPtr->ContextFreeCallback;
    }

    return STATUS_SUCCESS;
}

VOID
FltpTeardownInstanceContexts(_In_ PFLT_INSTANCE Instance)
{
    UNREFERENCED_PARAMETER(Instance);
}

VOID
FltpTeardownVolumeContexts(_In_ PFLT_VOLUME Volume)
{
    UNREFERENCED_PARAMETER(Volume);
}
