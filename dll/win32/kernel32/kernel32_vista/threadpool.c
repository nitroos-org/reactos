#include "k32_vista.h"

typedef void (CALLBACK *PTP_IO_CALLBACK)(PTP_CALLBACK_INSTANCE,void*,void*,IO_STATUS_BLOCK*,PTP_IO);

extern BOOL WINAPI DECLSPEC_HOTPATCH TpSimpleTryPost( PTP_SIMPLE_CALLBACK callback, PVOID userdata,
                                                           TP_CALLBACK_ENVIRON *environment );

extern NTSTATUS WINAPI TpAllocWork( TP_WORK **out, PTP_WORK_CALLBACK callback, PVOID userdata,
                                    TP_CALLBACK_ENVIRON *environment );
extern NTSTATUS WINAPI TpAllocCleanupGroup(TP_CLEANUP_GROUP** Group);
extern NTSTATUS WINAPI TpAllocWait(TP_WAIT** out, PTP_WAIT_CALLBACK callback, PVOID userdata, TP_CALLBACK_ENVIRON* environment);
extern NTSTATUS WINAPI TpAllocTimer(TP_TIMER** out, PTP_TIMER_CALLBACK callback, PVOID userdata, TP_CALLBACK_ENVIRON* environment);
extern NTSTATUS WINAPI TpAllocPool(TP_POOL** out,PVOID reserved);
extern NTSTATUS WINAPI TpAllocIoCompletion(TP_IO **out, HANDLE file, PTP_IO_CALLBACK callback,
                                     void *userdata, TP_CALLBACK_ENVIRON *environment);

/***********************************************************************
 *           CreateThreadpoolTimer   (kernelbase.@)
 */
PTP_TIMER WINAPI DECLSPEC_HOTPATCH CreateThreadpoolTimer( PTP_TIMER_CALLBACK callback, PVOID userdata,
                                                          TP_CALLBACK_ENVIRON *environment )
{
    TP_TIMER *timer;

    NTSTATUS status = TpAllocTimer( &timer, callback, userdata, environment );
    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    return timer;
}

static void WINAPI tp_io_callback( TP_CALLBACK_INSTANCE *instance, void *userdata, void *cvalue, IO_STATUS_BLOCK *iosb, TP_IO *io )
{
    PTP_WIN32_IO_CALLBACK callback = *(void **)io;
    callback( instance, userdata, cvalue, RtlNtStatusToDosError( iosb->Status ), iosb->Information, io );
}

/***********************************************************************
 *           CreateThreadpoolIo   (kernelbase.@)
 */
PTP_IO WINAPI DECLSPEC_HOTPATCH CreateThreadpoolIo( HANDLE handle, PTP_WIN32_IO_CALLBACK callback,
                                                    PVOID userdata, TP_CALLBACK_ENVIRON *environment )
{
    TP_IO *io;

    NTSTATUS status = TpAllocIoCompletion( &io, handle, tp_io_callback, userdata, environment );
    *(void **)io = callback; /* ntdll leaves us space to store our callback at the beginning of TP_IO struct */
    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    return io;
}

/***********************************************************************
 *           CreateThreadpoolWait   (kernelbase.@)
 */
PTP_WAIT WINAPI DECLSPEC_HOTPATCH CreateThreadpoolWait( PTP_WAIT_CALLBACK callback, PVOID userdata,
                                                       TP_CALLBACK_ENVIRON *environment )
{
    TP_WAIT *wait;

    NTSTATUS status = TpAllocWait( &wait, callback, userdata, environment );
    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    return wait;
}


/***********************************************************************
 *           CreateThreadpoolWork   (kernelbase.@)
 */
PTP_WORK WINAPI DECLSPEC_HOTPATCH CreateThreadpoolWork( PTP_WORK_CALLBACK callback, PVOID userdata,
                                                        TP_CALLBACK_ENVIRON *environment )
{
    TP_WORK *work;

    NTSTATUS status = TpAllocWork( &work, callback, userdata, environment );
    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }
    return work;
}

/***********************************************************************
 *           TrySubmitThreadpoolCallback   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH TrySubmitThreadpoolCallback( PTP_SIMPLE_CALLBACK callback, PVOID userdata,
                                                           TP_CALLBACK_ENVIRON *environment )
{
    NTSTATUS status = TpSimpleTryPost( callback, userdata, environment );
    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }

    return TRUE;
}

/***********************************************************************
 *           CreateThreadpoolCleanupGroup   (kernelbase.@)
 */
PTP_CLEANUP_GROUP WINAPI DECLSPEC_HOTPATCH CreateThreadpoolCleanupGroup(void)
{
    TP_CLEANUP_GROUP *group;
    NTSTATUS status = TpAllocCleanupGroup(&group);

    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return NULL;
    }

    return group;
}

/***********************************************************************
 *           CreateThreadpool   (kernelbase.@)
 */
PTP_POOL WINAPI DECLSPEC_HOTPATCH CreateThreadpool(void *reserved)
{
    TP_POOL *pool = NULL;
    NTSTATUS status = TpAllocPool(&pool, reserved);

    if (!NT_SUCCESS(status))
    {
        SetLastError(RtlNtStatusToDosError(status));
        return NULL;
    }
    return pool;
}

extern VOID WINAPI TpSetWait(TP_WAIT *wait, HANDLE handle, LARGE_INTEGER *timeout);
extern VOID WINAPI TpSetTimer(TP_TIMER *timer, LARGE_INTEGER *timeout, LONG period, LONG window_length);

/*
 * SetThreadpoolWait, but the reserved argument has to be NULL, and the result says that the wait is set.
 * (Windows 8 and later.)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetThreadpoolWaitEx( PTP_WAIT wait, HANDLE handle, PFILETIME timeout, PVOID reserved )
{
    if (reserved)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    TpSetWait( wait, handle, (LARGE_INTEGER *)timeout );
    return TRUE;
}

/*
 * SetThreadpoolTimer with a result. (Windows 8 and later.)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetThreadpoolTimerEx( PTP_TIMER timer, PFILETIME due_time, DWORD period, DWORD window_length )
{
    TpSetTimer( timer, (LARGE_INTEGER *)due_time, period, window_length );
    return TRUE;
}

/***********************************************************************
 *           SetThreadpoolStackInformation   (kernelbase.@)
 *
 * Measured on Windows 10 22H2: any reserve and commit pair is stored as it is (zero, commit above reserve) and read back
 * as it was set; a pool starts with the stack sizes of the process image. A NULL structure is ERROR_INVALID_PARAMETER.
 */
extern NTSTATUS WINAPI TpSetPoolStackInformation( TP_POOL *pool, TP_POOL_STACK_INFORMATION *stack_info );
extern NTSTATUS WINAPI TpQueryPoolStackInformation( TP_POOL *pool, TP_POOL_STACK_INFORMATION *stack_info );

BOOL WINAPI DECLSPEC_HOTPATCH SetThreadpoolStackInformation( PTP_POOL pool, PTP_POOL_STACK_INFORMATION stack_info )
{
    NTSTATUS status = TpSetPoolStackInformation( pool, stack_info );
    if (!NT_SUCCESS(status))
    {
        BaseSetLastNTError(status);
        return FALSE;
    }
    return TRUE;
}

/***********************************************************************
 *           QueryThreadpoolStackInformation   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH QueryThreadpoolStackInformation( PTP_POOL pool, PTP_POOL_STACK_INFORMATION stack_info )
{
    NTSTATUS status = TpQueryPoolStackInformation( pool, stack_info );
    if (!NT_SUCCESS(status))
    {
        BaseSetLastNTError(status);
        return FALSE;
    }
    return TRUE;
}
