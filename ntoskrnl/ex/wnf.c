/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows Notification Facility, partial: NtQueryWnfStateData only
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * PARTIAL WNF. There is no state-name store, no publisher and no subscription machinery in the
 * kernel; nothing is ever published. NtQueryWnfStateData answers like Windows 10 22H2 does for the
 * names programs ask about (measured on x64 and x86 under WOW64):
 *  - version field of the decoded name is not 1, or the data scope is not one of 0, 2, 4:
 *    STATUS_INVALID_PARAMETER (checked first, before any parameter is read);
 *  - a name the table below does not hold: STATUS_OBJECT_NAME_NOT_FOUND (Windows has thousands of
 *    well-known names; the one in the table is the only one a program of the corpus queries);
 *  - a name with data: ChangeStamp and BufferSize are written even when the buffer is too small
 *    (STATUS_BUFFER_TOO_SMALL), the data is copied otherwise.
 * A user-mode pointer that cannot be accessed is STATUS_ACCESS_VIOLATION, a non-NULL ExplicitScope
 * is STATUS_INVALID_PARAMETER. Update, delete, create and the subscriptions are not implemented.
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

/* A WNF_STATE_NAME is its 64-bit identity XORed with this key */
#define WNF_NAME_KEY            0x41C64E6DA3BC0074ULL
#define WNF_NAME_VERSION(n)     ((ULONG)((n) & 0xF))
#define WNF_NAME_SCOPE(n)       ((ULONG)(((n) >> 6) & 0xF))

#define WNF_DATA_SCOPE_SYSTEM   0
#define WNF_DATA_SCOPE_USER     2
#define WNF_DATA_SCOPE_PHYSICAL 4

typedef struct _WNF_KNOWN_NAME
{
    ULONGLONG StateName;
    WNF_CHANGE_STAMP ChangeStamp;
    ULONG DataSize;
    UCHAR Data[4];
} WNF_KNOWN_NAME;

static const WNF_KNOWN_NAME WnfKnownNames[] =
{
    /* WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED: 0 = quiet hours (focus assist) off. Thunderbird and
     * Firefox read it as a DWORD at start-up. */
    { 0x0D83063EA3BF1C75ULL, 1, 4, { 0, 0, 0, 0 } },
};

/* FUNCTIONS ****************************************************************/

NTSTATUS
NTAPI
NtQueryWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID *ExplicitScope,
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _Out_writes_bytes_to_opt_(*BufferSize, *BufferSize) PVOID Buffer,
    _Inout_ PULONG BufferSize)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status = STATUS_SUCCESS;
    ULONGLONG Name = 0;
    ULONG Capacity = 0;
    ULONG i;

    PAGED_CODE();

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            ProbeForRead(StateName, sizeof(*StateName), sizeof(UCHAR));
            if (TypeId != NULL)
            {
                /* Windows reads the type id while it validates the call (a volatile read: ProbeForRead on its
                 * own does not touch the memory) */
                volatile const UCHAR *Bytes = (volatile const UCHAR *)TypeId;
                UCHAR Touch;

                ProbeForRead(TypeId, sizeof(*TypeId), sizeof(UCHAR));
                Touch = Bytes[0];
                Touch |= Bytes[sizeof(*TypeId) - 1];
                (void)Touch;
            }
            ProbeForWrite(ChangeStamp, sizeof(*ChangeStamp), sizeof(UCHAR));
            ProbeForWrite(BufferSize, sizeof(*BufferSize), sizeof(UCHAR));
            Capacity = *BufferSize;
            if (Capacity != 0)
                ProbeForWrite(Buffer, Capacity, sizeof(UCHAR));
        }
        else
        {
            Capacity = *BufferSize;
        }
        Name = ((ULONGLONG)StateName->Data[1] << 32) | StateName->Data[0];
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* There are no explicit scopes (session, user or process instance ids) */
    if (ExplicitScope != NULL)
        return STATUS_INVALID_PARAMETER;

    /* Name validation. Version first; only the system, user and physical machine data scopes get as far
     * as a lookup (the session and machine scopes need an instance that nothing can create here). */
    Name ^= WNF_NAME_KEY;
    if (WNF_NAME_VERSION(Name) != 1)
        return STATUS_INVALID_PARAMETER;
    switch (WNF_NAME_SCOPE(Name))
    {
        case WNF_DATA_SCOPE_SYSTEM:
        case WNF_DATA_SCOPE_USER:
        case WNF_DATA_SCOPE_PHYSICAL:
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }
    Name ^= WNF_NAME_KEY;

    for (i = 0; i < RTL_NUMBER_OF(WnfKnownNames); i++)
    {
        const WNF_KNOWN_NAME *Known = &WnfKnownNames[i];

        if (Known->StateName != Name)
            continue;

        _SEH2_TRY
        {
            *ChangeStamp = Known->ChangeStamp;
            *BufferSize = Known->DataSize;
            if (Capacity < Known->DataSize)
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                RtlCopyMemory(Buffer, Known->Data, Known->DataSize);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        return Status;
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* EOF */
