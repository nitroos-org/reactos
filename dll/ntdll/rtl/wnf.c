/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows Notification Facility, partial: user-mode change subscriptions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * PARTIAL WNF. The kernel only answers NtQueryWnfStateData (ntoskrnl/ex/wnf.c) and nothing is ever
 * published, so a subscription never sees a change. What Windows 10 22H2 does at subscribe time was
 * measured (x64 and x86 under WOW64): the name is looked up first (a name that is not valid or not
 * known fails with the status of the query, no handle is returned); if the caller's change stamp is
 * older than the stamp the name has, the callback is queued once, to run on a thread pool thread, with
 * the current stamp and data; with the same or a newer stamp nothing is called. A NULL callback is
 * accepted. Unsubscribe was only measured for a live handle (STATUS_SUCCESS); NULL is not measured.
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

/* The state name is passed (and handed to the callback) by value: 8 bytes in both ABIs */
typedef NTSTATUS (NTAPI *PWNF_USER_CALLBACK_RAW)(
    ULONGLONG StateName,
    WNF_CHANGE_STAMP ChangeStamp,
    PWNF_TYPE_ID TypeId,
    PVOID CallbackContext,
    const VOID *Buffer,
    ULONG BufferSize);

typedef struct _WNF_USER_SUBSCRIPTION
{
    LONG RefCount;
    LONG Unsubscribed;
    WNF_STATE_NAME StateName;
    PWNF_USER_CALLBACK_RAW Callback;
    PVOID Context;
    WNF_TYPE_ID TypeId;
    BOOLEAN HasTypeId;
} WNF_USER_SUBSCRIPTION, *PWNF_USER_SUBSCRIPTION;

static
VOID
RtlpWnfReleaseSubscription(
    _In_ PWNF_USER_SUBSCRIPTION Subscription)
{
    if (InterlockedDecrement(&Subscription->RefCount) == 0)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Subscription);
}

static
VOID
NTAPI
RtlpWnfDeliver(
    _In_ PVOID Parameter)
{
    PWNF_USER_SUBSCRIPTION Subscription = Parameter;
    WNF_CHANGE_STAMP ChangeStamp;
    PVOID Buffer = NULL;
    ULONG Size = 0, Capacity = 0;
    NTSTATUS Status;
    ULONG Try;

    if (Subscription->Unsubscribed || Subscription->Callback == NULL)
        goto Done;

    /* Size, then data; the data can only change by being published and nothing publishes, but loop anyway */
    for (Try = 0; Try < 4; Try++)
    {
        Size = Capacity;
        Status = NtQueryWnfStateData(&Subscription->StateName,
                                     Subscription->HasTypeId ? &Subscription->TypeId : NULL,
                                     NULL,
                                     &ChangeStamp,
                                     Buffer,
                                     &Size);
        if (Status != STATUS_BUFFER_TOO_SMALL)
            break;

        if (Buffer != NULL)
            RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Capacity = Size;
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Capacity);
        if (Buffer == NULL)
            goto Done;
    }
    if (!NT_SUCCESS(Status) || Subscription->Unsubscribed)
        goto Done;

    Subscription->Callback(((ULONGLONG)Subscription->StateName.Data[1] << 32) | Subscription->StateName.Data[0],
                           ChangeStamp,
                           Subscription->HasTypeId ? &Subscription->TypeId : NULL,
                           Subscription->Context,
                           Buffer,
                           Size);

Done:
    if (Buffer != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    RtlpWnfReleaseSubscription(Subscription);
}

NTSTATUS
NTAPI
RtlSubscribeWnfStateChangeNotification(
    _Outptr_ PVOID *SubscriptionHandle,
    _In_ ULONGLONG StateName,
    _In_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ PWNF_USER_CALLBACK_RAW Callback,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ ULONG SerializationGroup,
    _In_opt_ ULONG Unknown)
{
    PWNF_USER_SUBSCRIPTION Subscription;
    WNF_STATE_NAME Name;
    WNF_CHANGE_STAMP Current;
    ULONG Size = 0;
    NTSTATUS Status;

    if (SubscriptionHandle == NULL)
        return STATUS_INVALID_PARAMETER;

    Name.Data[0] = (ULONG)StateName;
    Name.Data[1] = (ULONG)(StateName >> 32);

    /* The lookup: a valid name that has data answers STATUS_BUFFER_TOO_SMALL or STATUS_SUCCESS */
    Status = NtQueryWnfStateData(&Name, TypeId, NULL, &Current, NULL, &Size);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL)
        return Status;

    Subscription = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Subscription));
    if (Subscription == NULL)
        return STATUS_NO_MEMORY;

    Subscription->RefCount = 1;
    Subscription->StateName = Name;
    Subscription->Callback = Callback;
    Subscription->Context = CallbackContext;
    if (TypeId != NULL)
    {
        Subscription->TypeId = *TypeId;
        Subscription->HasTypeId = TRUE;
    }

    /* The stamps are compared as a distance, so that a wrapped stamp (0xFFFFFFFF) counts as older */
    if (Callback != NULL && (LONG)(Current - ChangeStamp) > 0)
    {
        InterlockedIncrement(&Subscription->RefCount);
        Status = RtlQueueWorkItem(RtlpWnfDeliver, Subscription, WT_EXECUTEDEFAULT);
        if (!NT_SUCCESS(Status))
            RtlpWnfReleaseSubscription(Subscription);
    }

    *SubscriptionHandle = Subscription;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlUnsubscribeWnfStateChangeNotification(
    _In_ PVOID SubscriptionHandle)
{
    PWNF_USER_SUBSCRIPTION Subscription = SubscriptionHandle;

    if (Subscription == NULL)
        return STATUS_INVALID_PARAMETER;

    InterlockedExchange(&Subscription->Unsubscribed, 1);
    RtlpWnfReleaseSubscription(Subscription);
    return STATUS_SUCCESS;
}
