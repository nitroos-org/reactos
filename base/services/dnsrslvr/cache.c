/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        base/services/dnsrslvr/cache.c
 * PURPOSE:     DNS cache functions
 * PROGRAMMER:  Peter Hater
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

static RESOLVER_CACHE DnsCache;
static BOOL DnsCacheInitialized = FALSE;

#define DnsCacheLock()          do { EnterCriticalSection(&DnsCache.Lock); } while (0)
#define DnsCacheUnlock()        do { LeaveCriticalSection(&DnsCache.Lock); } while (0)

VOID
DnsIntCacheInitialize(VOID)
{
    DPRINT("DnsIntCacheInitialize()\n");

    /* Check if we're initialized */
    if (DnsCacheInitialized)
        return;

    /* Initialize the cache lock and namespace list */
    InitializeCriticalSection((LPCRITICAL_SECTION)&DnsCache.Lock);
    InitializeListHead(&DnsCache.RecordList);
    DnsCacheInitialized = TRUE;
}

VOID
DnsIntCacheFree(VOID)
{
    DPRINT("DnsIntCacheFree()\n");

    /* Check if we're initialized */
    if (!DnsCacheInitialized)
        return;

    if (!DnsCache.RecordList.Flink)
        return;

    DnsIntCacheFlush(CACHE_FLUSH_ALL);

    DeleteCriticalSection(&DnsCache.Lock);
    DnsCacheInitialized = FALSE;
}

VOID
DnsIntCacheRemoveEntryItem(PRESOLVER_CACHE_ENTRY CacheEntry)
{
    DPRINT("DnsIntCacheRemoveEntryItem(%p)\n", CacheEntry);

    /* Remove the entry from the list */
    RemoveEntryList(&CacheEntry->CacheLink);

    /* Free record */
    DnsRecordListFree(CacheEntry->Record, DnsFreeRecordList);

    /* Delete us */
    HeapFree(GetProcessHeap(), 0, CacheEntry);
}

DNS_STATUS
DnsIntCacheFlush(
    _In_ ULONG ulFlags)
{
    PLIST_ENTRY Entry, NextEntry;
    PRESOLVER_CACHE_ENTRY CacheEntry;

    DPRINT("DnsIntCacheFlush(%lu)\n", ulFlags);

    /* Lock the cache */
    DnsCacheLock();

    /* Loop every entry */
    Entry = DnsCache.RecordList.Flink;
    while (Entry != &DnsCache.RecordList)
    {
        NextEntry = Entry->Flink;

        /* Get this entry */
        CacheEntry = CONTAINING_RECORD(Entry, RESOLVER_CACHE_ENTRY, CacheLink);

        /* Remove it from list */
        if (((ulFlags & CACHE_FLUSH_HOSTS_FILE_ENTRIES) && (CacheEntry->bHostsFileEntry != FALSE)) ||
            ((ulFlags & CACHE_FLUSH_NON_HOSTS_FILE_ENTRIES) && (CacheEntry->bHostsFileEntry == FALSE)))
            DnsIntCacheRemoveEntryItem(CacheEntry);

        /* Move to the next entry */
        Entry = NextEntry;
    }

    /* Unlock the cache */
    DnsCacheUnlock();

    return ERROR_SUCCESS;
}


DNS_STATUS
DnsIntFlushCacheEntry(
    _In_ LPCWSTR pszName,
    _In_ WORD wType)
{
    PLIST_ENTRY Entry, NextEntry;
    PRESOLVER_CACHE_ENTRY CacheEntry;

    DPRINT("DnsIntFlushCacheEntry(%S %x)\n", pszName, wType);

    /* Lock the cache */
    DnsCacheLock();

    /* Loop every entry */
    Entry = DnsCache.RecordList.Flink;
    while (Entry != &DnsCache.RecordList)
    {
        NextEntry = Entry->Flink;

        /* Get this entry */
        CacheEntry = CONTAINING_RECORD(Entry, RESOLVER_CACHE_ENTRY, CacheLink);

        /* Remove it from the list */
        if ((_wcsicmp(CacheEntry->Record->pName, pszName) == 0) &&
            (CacheEntry->bHostsFileEntry == FALSE))
        {
            if ((wType == DNS_TYPE_ANY) ||
                (CacheEntry->Record->wType == wType))
            {
                DnsIntCacheRemoveEntryItem(CacheEntry);
            }
        }

        /* Move to the next entry */
        Entry = NextEntry;
    }

    /* Unlock the cache */
    DnsCacheUnlock();

    return ERROR_SUCCESS;
}


VOID
DnsIntCacheLock(VOID)
{
    DnsCacheLock();
}

VOID
DnsIntCacheUnlock(VOID)
{
    DnsCacheUnlock();
}

/* Does the hosts file have a row for this name (any type)? */
BOOL
DnsIntCacheHasHostsName(
    _In_ LPCWSTR Name)
{
    BOOL Ret = FALSE;
    PRESOLVER_CACHE_ENTRY CacheEntry;
    PLIST_ENTRY NextEntry;

    DnsCacheLock();

    for (NextEntry = DnsCache.RecordList.Flink;
         NextEntry != &DnsCache.RecordList;
         NextEntry = NextEntry->Flink)
    {
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, CacheLink);

        if (CacheEntry->bHostsFileEntry &&
            CacheEntry->Record->wType != DNS_TYPE_PTR &&
            _wcsicmp(CacheEntry->Record->pName, Name) == 0)
        {
            Ret = TRUE;
            break;
        }
    }

    DnsCacheUnlock();

    return Ret;
}

/*
 * The names of the PTR records made from the hosts file end with the root label's dot, the names a reverse query
 * is made with may or may not: the one dot is not part of the comparison for the reverse names.
 */
static
BOOL
NamesMatch(
    PDNS_RECORDW Record,
    LPCWSTR Name)
{
    size_t Len1, Len2;

    if (_wcsicmp(Record->pName, Name) == 0)
        return TRUE;
    if (Record->wType != DNS_TYPE_PTR)
        return FALSE;

    Len1 = wcslen(Record->pName);
    Len2 = wcslen(Name);
    if (Len1 > 1 && Record->pName[Len1 - 1] == L'.')
        Len1--;
    if (Len2 > 1 && Name[Len2 - 1] == L'.')
        Len2--;
    return Len1 == Len2 && _wcsnicmp(Record->pName, Name, Len1) == 0;
}


DNS_STATUS
DnsIntCacheGetEntryByName(
    LPCWSTR Name,
    WORD wType,
    DWORD dwFlags,
    PDNS_RECORDW *Record)
{
    DNS_STATUS Status = DNS_INFO_NO_RECORDS;
    PRESOLVER_CACHE_ENTRY CacheEntry;
    PLIST_ENTRY NextEntry;
    PDNS_RECORDW *Tail, Copy;

    DPRINT("DnsIntCacheGetEntryByName(%S %hu 0x%lx %p)\n",
           Name, wType, dwFlags, Record);

    /* Assume failure */
    *Record = NULL;

    /* Lock the cache */
    DnsCacheLock();

    /*
     * The rows of the hosts file come first (they shadow a DNS name) and every row of the name and type
     * is returned, in the order of the file.
     */
    Tail = Record;
    for (NextEntry = DnsCache.RecordList.Flink;
         NextEntry != &DnsCache.RecordList;
         NextEntry = NextEntry->Flink)
    {
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, CacheLink);

        if (CacheEntry->bHostsFileEntry &&
            NamesMatch(CacheEntry->Record, Name) &&
            (wType == DNS_TYPE_ANY || CacheEntry->Record->wType == wType))
        {
            Copy = DnsRecordSetCopyEx(CacheEntry->Record, DnsCharSetUnicode, DnsCharSetUnicode);
            if (Copy == NULL)
                continue;

            *Tail = Copy;
            while (Copy->pNext != NULL)
                Copy = Copy->pNext;
            Tail = &Copy->pNext;
            Status = ERROR_SUCCESS;

            /* a reverse name gets its first row only, as before */
            if (CacheEntry->Record->wType == DNS_TYPE_PTR)
                break;
        }
    }

    if (Status == ERROR_SUCCESS)
    {
        DnsCacheUnlock();
        return Status;
    }

    /* Match the Id with all the entries in the List */
    NextEntry = DnsCache.RecordList.Flink;
    while (NextEntry != &DnsCache.RecordList)
    {
        /* Get the Current Entry */
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, CacheLink);

        /* Check if this is the Catalog Entry ID we want */
        if (NamesMatch(CacheEntry->Record, Name) &&
            (wType == DNS_TYPE_ANY || CacheEntry->Record->wType == wType))
        {
            /* Copy the entry and return it */
            *Record = DnsRecordSetCopyEx(CacheEntry->Record, DnsCharSetUnicode, DnsCharSetUnicode);
            Status = ERROR_SUCCESS;
            break;
        }

        NextEntry = NextEntry->Flink;
    }

    /* Release the cache */
    DnsCacheUnlock();

    return Status;
}

BOOL
DnsIntCacheRemoveEntryByName(LPCWSTR Name)
{
    BOOL Ret = FALSE;
    PRESOLVER_CACHE_ENTRY CacheEntry;
    PLIST_ENTRY NextEntry;

    DPRINT("DnsIntCacheRemoveEntryByName(%S)\n", Name);

    /* Lock the cache */
    DnsCacheLock();

    /* Match the Id with all the entries in the List */
    NextEntry = DnsCache.RecordList.Flink;
    while (NextEntry != &DnsCache.RecordList)
    {
        /* Get the Current Entry */
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, CacheLink);

        /* Check if this is the Catalog Entry ID we want */
        if (_wcsicmp(CacheEntry->Record->pName, Name) == 0)
        {
            /* Remove the entry */
            DnsIntCacheRemoveEntryItem(CacheEntry);
            Ret = TRUE;
            break;
        }

        NextEntry = NextEntry->Flink;
    }

    /* Release the cache */
    DnsCacheUnlock();

    /* Return */
    return Ret;
}

VOID
DnsIntCacheAddEntry(
    _In_ PDNS_RECORDW Record,
    _In_ BOOL bHostsFileEntry)
{
    PRESOLVER_CACHE_ENTRY Entry;

    DPRINT("DnsIntCacheAddEntry(%p %u)\n",
           Record, bHostsFileEntry);

    DPRINT("Name: %S\n", Record->pName);
    DPRINT("TTL: %lu\n", Record->dwTtl);

    /* Lock the cache */
    DnsCacheLock();

    /* Match the Id with all the entries in the List */
    Entry = (PRESOLVER_CACHE_ENTRY)HeapAlloc(GetProcessHeap(), 0, sizeof(*Entry));
    if (!Entry)
    {
        DnsCacheUnlock();
        return;
    }

    Entry->bHostsFileEntry = bHostsFileEntry;
    Entry->Record = DnsRecordSetCopyEx(Record, DnsCharSetUnicode, DnsCharSetUnicode);
    if (!Entry->Record)
    {
        /* An entry without a record would crash the next lookup that walks the list */
        HeapFree(GetProcessHeap(), 0, Entry);
        DnsCacheUnlock();
        return;
    }

    /* Insert it to our List */
    InsertTailList(&DnsCache.RecordList, &Entry->CacheLink);

    /* Release the cache */
    DnsCacheUnlock();
}

DNS_STATUS
DnsIntCacheGetEntries(
    _Out_ DNS_CACHE_ENTRY **ppCacheEntries)
{
    PRESOLVER_CACHE_ENTRY CacheEntry;
    PLIST_ENTRY NextEntry;
    PDNS_CACHE_ENTRY pLastEntry = NULL, pNewEntry;

    /* Lock the cache */
    DnsCacheLock();

    *ppCacheEntries = NULL;

    NextEntry = DnsCache.RecordList.Flink;
    while (NextEntry != &DnsCache.RecordList)
    {
        /* Get the Current Entry */
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, CacheLink);

        DPRINT("1 %S %lu\n", CacheEntry->Record->pName, CacheEntry->Record->wType);
        if (CacheEntry->Record->pNext)
        {
            DPRINT("2 %S %lu\n", CacheEntry->Record->pNext->pName, CacheEntry->Record->pNext->wType);
        }

        pNewEntry = midl_user_allocate(sizeof(DNS_CACHE_ENTRY));
        if (pNewEntry == NULL)
        {
            DnsCacheUnlock();
            return ERROR_OUTOFMEMORY;
        }

        pNewEntry->pszName = midl_user_allocate((wcslen(CacheEntry->Record->pName) + 1) * sizeof(WCHAR));
        if (pNewEntry->pszName == NULL)
        {
            midl_user_free(pNewEntry);
            DnsCacheUnlock();
            return ERROR_OUTOFMEMORY;
        }

        wcscpy(pNewEntry->pszName, CacheEntry->Record->pName);
        pNewEntry->wType1 = CacheEntry->Record->wType;
        pNewEntry->wType2 = 0;
        pNewEntry->wFlags = 0;

        if (pLastEntry == NULL)
            *ppCacheEntries = pNewEntry;
        else
            pLastEntry->pNext = pNewEntry;
        pLastEntry = pNewEntry;

        NextEntry = NextEntry->Flink;
    }

    /* Release the cache */
    DnsCacheUnlock();

    return ERROR_SUCCESS;
}
