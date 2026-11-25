#pragma once

typedef struct _USER_REFERENCE_ENTRY
{
   SINGLE_LIST_ENTRY Entry;
   PVOID obj;
} USER_REFERENCE_ENTRY, *PUSER_REFERENCE_ENTRY;

extern PUSER_HANDLE_TABLE gHandleTable;
VOID FASTCALL UserReferenceObject(PVOID obj);
PVOID FASTCALL UserReferenceObjectByHandle(HANDLE handle, HANDLE_TYPE type);
BOOL FASTCALL UserDereferenceObject(PVOID obj);
PVOID FASTCALL UserCreateObject(PUSER_HANDLE_TABLE ht, struct _DESKTOP* pDesktop, PTHREADINFO pti, HANDLE* h,HANDLE_TYPE type , ULONG size);
BOOL FASTCALL UserDeleteObject(HANDLE h, HANDLE_TYPE type );
PVOID UserGetObject(PUSER_HANDLE_TABLE ht, HANDLE handle, HANDLE_TYPE type );
PVOID UserGetObjectNoErr(PUSER_HANDLE_TABLE, HANDLE, HANDLE_TYPE);
/* Entries of the user handle table of a session: what the low word of a handle can address (index << 1 from
   FIRST_USER_HANDLE; 32744), as many as one block of the global USER heap holds (the heap takes a block of 0x7F000
   bytes at most: 21162 entries of 24 bytes on amd64, all 32744 of 12 bytes on i386), opened in steps of
   USER_HANDLE_TABLE_STEP. The most one process may hold (USERProcessHandleQuota) is 18000. */
#define USER_HANDLE_TABLE_ADDRESSABLE ((LAST_USER_HANDLE - FIRST_USER_HANDLE + 1) >> 1)
#define USER_HANDLE_TABLE_MAX_BYTES 0x7C000
#define USER_HANDLE_TABLE_MAX_ENTRIES \
    (USER_HANDLE_TABLE_ADDRESSABLE < (USER_HANDLE_TABLE_MAX_BYTES / sizeof(USER_HANDLE_ENTRY)) ? \
     USER_HANDLE_TABLE_ADDRESSABLE : (USER_HANDLE_TABLE_MAX_BYTES / sizeof(USER_HANDLE_ENTRY)))
#define USER_HANDLE_TABLE_STEP 4096
BOOL FASTCALL UserCreateHandleTable(VOID);
BOOL FASTCALL UserObjectInDestroy(HANDLE);
BOOL FASTCALL UserMarkHandleGranted(HANDLE);
PPROCESSINFO FASTCALL UserGetHandleOwner(HANDLE);
void DbgUserDumpHandleTable();
PVOID FASTCALL ValidateHandle(HANDLE handle, HANDLE_TYPE type);
BOOLEAN UserDestroyObjectsForOwner(PUSER_HANDLE_TABLE Table, PVOID Owner);
BOOL FASTCALL UserMarkObjectDestroy(PVOID);
PVOID FASTCALL UserAssignmentLock(PVOID *ppvObj, PVOID pvNew);
PVOID FASTCALL UserAssignmentUnlock(PVOID *ppvObj);

static __inline VOID
UserRefObjectCo(PVOID obj, PUSER_REFERENCE_ENTRY UserReferenceEntry)
{
    PTHREADINFO W32Thread;

    W32Thread = PsGetCurrentThreadWin32Thread();
    ASSERT(W32Thread != NULL);
    ASSERT(UserReferenceEntry != NULL);
    UserReferenceEntry->obj = obj;
    UserReferenceObject(obj);
    PushEntryList(&W32Thread->ReferencesList, &UserReferenceEntry->Entry);
#if DBG
    W32Thread->cRefObjectCo++;
#endif
}

static __inline VOID
UserDerefObjectCo(PVOID obj)
{
    PTHREADINFO W32Thread;
    PSINGLE_LIST_ENTRY ReferenceEntry;
    PUSER_REFERENCE_ENTRY UserReferenceEntry;

    ASSERT(obj != NULL);
    W32Thread = PsGetCurrentThreadWin32Thread();
    ASSERT(W32Thread != NULL);
    ReferenceEntry = PopEntryList(&W32Thread->ReferencesList);
    ASSERT(ReferenceEntry != NULL);
    UserReferenceEntry = CONTAINING_RECORD(ReferenceEntry, USER_REFERENCE_ENTRY, Entry);
    ASSERT(UserReferenceEntry != NULL);

    ASSERT(obj == UserReferenceEntry->obj);
    UserDereferenceObject(obj);
#if DBG
    W32Thread->cRefObjectCo--;
#endif
}

/*
 * A pool block that a kernel frame keeps across callbacks to user mode (a window list walked while each
 * window is sent a message): when the thread ends inside one of the callbacks, the frame never runs again
 * and would never free it. Held blocks are listed in the thread (the entry lives in the frame, as for
 * UserRefObjectCo) and freed by the thread's exit cleanup. UserFreePoolCo frees the block and unlists it.
 * A block of the global USER heap (UserHeapAlloc) is held with the tag USER_HELD_USER_HEAP: the heap is shared
 * by every process and has a fixed size, so a block lost there is lost for everyone.
 */
typedef struct _USER_HELD_POOL_ENTRY
{
   SINGLE_LIST_ENTRY Entry;
   PVOID pv;
   ULONG Tag;
} USER_HELD_POOL_ENTRY, *PUSER_HELD_POOL_ENTRY;

#define USER_HELD_USER_HEAP 0

static __inline VOID
UserFreeHeldBlock(_In_ PVOID pv, _In_ ULONG Tag)
{
    if (Tag == USER_HELD_USER_HEAP)
        UserHeapFree(pv);
    else
        ExFreePoolWithTag(pv, Tag);
}

static __inline VOID
UserHoldPoolCo(_In_ PVOID pv, _In_ ULONG Tag, _Out_ PUSER_HELD_POOL_ENTRY HeldEntry)
{
    PTHREADINFO W32Thread = PsGetCurrentThreadWin32Thread();

    ASSERT(W32Thread != NULL);
    HeldEntry->pv = pv;
    HeldEntry->Tag = Tag;
    PushEntryList(&W32Thread->HeldPoolList, &HeldEntry->Entry);
}

static __inline VOID
UserFreePoolCo(_Inout_ PUSER_HELD_POOL_ENTRY HeldEntry)
{
    PTHREADINFO W32Thread = PsGetCurrentThreadWin32Thread();
    PSINGLE_LIST_ENTRY *ppEntry;

    ASSERT(W32Thread != NULL);
    /* Usually the first entry; unlisted wherever it is */
    for (ppEntry = &W32Thread->HeldPoolList.Next; *ppEntry; ppEntry = &(*ppEntry)->Next)
    {
        if (*ppEntry == &HeldEntry->Entry)
        {
            *ppEntry = HeldEntry->Entry.Next;
            break;
        }
    }
    UserFreeHeldBlock(HeldEntry->pv, HeldEntry->Tag);
}

void FreeProcMarkObject(_In_ PVOID Object);

/* EOF */
