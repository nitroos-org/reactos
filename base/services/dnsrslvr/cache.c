/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS system libraries
 * FILE:        base/services/dnsrslvr/cache.c
 * PURPOSE:     DNS cache functions
 * PROGRAMMER:  Peter Hater
 *
 * The cache keeps the answers of the DNS servers for the time their records say (at most MaxCacheTtl), the
 * negative answers (name does not exist, no record of the type) for MaxNegativeCacheTtl, and the rows of the hosts
 * file until the file changes. The entries are found through a hash table of the name. The answers of the DNS
 * servers are bounded in number: the least recently used entry goes when the bound is reached. Expired entries are
 * dropped when a lookup finds them and by a sweep of the whole cache that an add or a lookup does at most once a
 * minute (there is no timer).
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

#define CACHE_BUCKET_COUNT      8192                /* a power of two */
#define CACHE_MAX_ENTRIES       8192                /* the answers of DNS servers, positive and negative */
#define CACHE_SWEEP_INTERVAL    60000               /* ms */
#define DEFAULT_MAX_CACHE_TTL   86400               /* s */
#define DEFAULT_MAX_NEG_TTL     900                 /* s */

static RESOLVER_CACHE DnsCache;
static BOOL DnsCacheInitialized = FALSE;
static volatile LONG MaxCacheTtl = DEFAULT_MAX_CACHE_TTL;
static volatile LONG MaxNegativeCacheTtl = DEFAULT_MAX_NEG_TTL;
static ULONGLONG LastSweep;

#define DnsCacheLock()          do { EnterCriticalSection(&DnsCache.Lock); } while (0)
#define DnsCacheUnlock()        do { LeaveCriticalSection(&DnsCache.Lock); } while (0)

/*
 * The clock of the cache: milliseconds of the performance counter, 64 bits wide (it does not wrap, as GetTickCount does
 * after 49 days). GetTickCount64 would do as well but is not in every version of kernel32 this service is built for.
 */
static
ULONGLONG
CacheNow(VOID)
{
    static LONGLONG Frequency;
    LARGE_INTEGER Counter;

    if (Frequency == 0)
    {
        LARGE_INTEGER Freq;

        if (!QueryPerformanceFrequency(&Freq) || Freq.QuadPart <= 0)
            Freq.QuadPart = 1000;
        Frequency = Freq.QuadPart;
    }
    if (!QueryPerformanceCounter(&Counter))
        return GetTickCount();

    return (ULONGLONG)(Counter.QuadPart / Frequency) * 1000 +
           (ULONGLONG)(Counter.QuadPart % Frequency) * 1000 / (ULONGLONG)Frequency;
}

static
DWORD
ReadParameter(
    _In_ HKEY hKey,
    _In_ PCWSTR Name,
    _In_ DWORD Default)
{
    DWORD Value, Size = sizeof(Value), Type;

    if (RegQueryValueExW(hKey, Name, NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD && Size == sizeof(Value))
        return Value;
    return Default;
}

/* MaxCacheTtl and MaxNegativeCacheTtl (seconds) of the Dnscache parameters; 0 for the second one turns the
   negative cache off */
VOID
DnsIntCacheReadParameters(VOID)
{
    HKEY hKey;
    DWORD Ttl = DEFAULT_MAX_CACHE_TTL, NegTtl = DEFAULT_MAX_NEG_TTL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
                      0,
                      KEY_QUERY_VALUE,
                      &hKey) == ERROR_SUCCESS)
    {
        Ttl = ReadParameter(hKey, L"MaxCacheTtl", DEFAULT_MAX_CACHE_TTL);
        NegTtl = ReadParameter(hKey, L"MaxNegativeCacheTtl", DEFAULT_MAX_NEG_TTL);
        RegCloseKey(hKey);
    }

    /* the cache clock counts milliseconds in 64 bits: a value above a year is "as long as there is" */
    InterlockedExchange(&MaxCacheTtl, (LONG)min(Ttl, 0x7fffffffu));
    InterlockedExchange(&MaxNegativeCacheTtl, (LONG)min(NegTtl, 0x7fffffffu));
}

/* The hash of a name: letters without case, the dot of the root label (after another character) left out */
static
ULONG
NameHash(
    _In_ LPCWSTR Name)
{
    ULONG Hash = 2166136261u;
    size_t Len = wcslen(Name), i;

    if (Len > 1 && Name[Len - 1] == L'.')
        Len--;
    for (i = 0; i < Len; i++)
    {
        WCHAR c = Name[i];

        if (c >= L'A' && c <= L'Z')
            c += L'a' - L'A';
        Hash = (Hash ^ c) * 16777619u;
    }
    return Hash;
}

#define BucketOf(Hash)  (&DnsCache.Buckets[(Hash) & (CACHE_BUCKET_COUNT - 1)])

/*
 * The names of the PTR records made from the hosts file end with the root label's dot, the names a reverse query
 * is made with may or may not: the one dot is not part of the comparison for the reverse names.
 */
static
BOOL
NamesMatch(
    PRESOLVER_CACHE_ENTRY Entry,
    LPCWSTR Name)
{
    size_t Len1, Len2;

    if (_wcsicmp(Entry->Name, Name) == 0)
        return TRUE;
    if (Entry->Type != DNS_TYPE_PTR)
        return FALSE;

    Len1 = wcslen(Entry->Name);
    Len2 = wcslen(Name);
    if (Len1 > 1 && Entry->Name[Len1 - 1] == L'.')
        Len1--;
    if (Len2 > 1 && Name[Len2 - 1] == L'.')
        Len2--;
    return Len1 == Len2 && _wcsnicmp(Entry->Name, Name, Len1) == 0;
}

static
BOOL
IsExpired(
    _In_ PRESOLVER_CACHE_ENTRY Entry,
    _In_ ULONGLONG Now)
{
    return Entry->ExpiresAt != 0 && Entry->ExpiresAt <= Now;
}

/* The seconds left of the entry (1 at least: it is not expired) */
static
DWORD
SecondsLeft(
    _In_ PRESOLVER_CACHE_ENTRY Entry,
    _In_ ULONGLONG Now)
{
    ULONGLONG Left = (Entry->ExpiresAt - Now + 999) / 1000;

    if (Left > 0x7fffffff)
        Left = 0x7fffffff;
    return (DWORD)Left;
}

VOID
DnsIntCacheInitialize(VOID)
{
    ULONG i;

    DPRINT("DnsIntCacheInitialize()\n");

    /* Check if we're initialized */
    if (DnsCacheInitialized)
        return;

    /* Initialize the cache lock and the lists */
    InitializeCriticalSection((LPCRITICAL_SECTION)&DnsCache.Lock);
    InitializeListHead(&DnsCache.RecordList);
    InitializeListHead(&DnsCache.LruList);
    DnsCache.EntryCount = 0;
    DnsCache.Buckets = HeapAlloc(GetProcessHeap(), 0, CACHE_BUCKET_COUNT * sizeof(LIST_ENTRY));
    if (DnsCache.Buckets)
    {
        for (i = 0; i < CACHE_BUCKET_COUNT; i++)
            InitializeListHead(&DnsCache.Buckets[i]);
    }
    LastSweep = CacheNow();
    DnsIntCacheReadParameters();
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
    if (DnsCache.Buckets)
        HeapFree(GetProcessHeap(), 0, DnsCache.Buckets);
    DnsCache.Buckets = NULL;
    DnsCacheInitialized = FALSE;
}

VOID
DnsIntCacheRemoveEntryItem(PRESOLVER_CACHE_ENTRY CacheEntry)
{
    DPRINT("DnsIntCacheRemoveEntryItem(%p)\n", CacheEntry);

    /* Remove the entry from the lists */
    RemoveEntryList(&CacheEntry->CacheLink);
    RemoveEntryList(&CacheEntry->HashLink);
    if (!CacheEntry->bHostsFileEntry)
    {
        RemoveEntryList(&CacheEntry->LruLink);
        DnsCache.EntryCount--;
    }

    /* Free record */
    if (CacheEntry->Record)
        DnsRecordListFree(CacheEntry->Record, DnsFreeRecordList);
    if (CacheEntry->NegName)
        HeapFree(GetProcessHeap(), 0, CacheEntry->NegName);

    /* Delete us */
    HeapFree(GetProcessHeap(), 0, CacheEntry);
}

/* Drops every expired entry (the lock is held) */
static
VOID
SweepExpired(
    _In_ ULONGLONG Now)
{
    PLIST_ENTRY Entry, NextEntry;
    PRESOLVER_CACHE_ENTRY CacheEntry;

    LastSweep = Now;
    for (Entry = DnsCache.LruList.Flink; Entry != &DnsCache.LruList; Entry = NextEntry)
    {
        NextEntry = Entry->Flink;
        CacheEntry = CONTAINING_RECORD(Entry, RESOLVER_CACHE_ENTRY, LruLink);
        if (IsExpired(CacheEntry, Now))
            DnsIntCacheRemoveEntryItem(CacheEntry);
    }
}

/* A cheap check of every use of the cache (the lock is held): the sweep is done once in CACHE_SWEEP_INTERVAL */
static
VOID
SweepIfDue(
    _In_ ULONGLONG Now)
{
    if (Now - LastSweep >= CACHE_SWEEP_INTERVAL)
        SweepExpired(Now);
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
    PLIST_ENTRY Entry, NextEntry, Bucket;
    PRESOLVER_CACHE_ENTRY CacheEntry;

    DPRINT("DnsIntFlushCacheEntry(%S %x)\n", pszName, wType);

    /* Lock the cache */
    DnsCacheLock();

    if (DnsCache.Buckets)
    {
        /* Every match of the name (and the type) goes, the rows of the hosts file stay */
        Bucket = BucketOf(NameHash(pszName));
        for (Entry = Bucket->Flink; Entry != Bucket; Entry = NextEntry)
        {
            NextEntry = Entry->Flink;
            CacheEntry = CONTAINING_RECORD(Entry, RESOLVER_CACHE_ENTRY, HashLink);

            if (!CacheEntry->bHostsFileEntry &&
                NamesMatch(CacheEntry, pszName) &&
                (wType == DNS_TYPE_ANY || CacheEntry->Type == wType))
            {
                DnsIntCacheRemoveEntryItem(CacheEntry);
            }
        }
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
    PLIST_ENTRY NextEntry, Bucket;

    DnsCacheLock();

    if (DnsCache.Buckets)
    {
        Bucket = BucketOf(NameHash(Name));
        for (NextEntry = Bucket->Flink; NextEntry != Bucket; NextEntry = NextEntry->Flink)
        {
            CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, HashLink);

            if (CacheEntry->bHostsFileEntry &&
                CacheEntry->Type != DNS_TYPE_PTR &&
                _wcsicmp(CacheEntry->Name, Name) == 0)
            {
                Ret = TRUE;
                break;
            }
        }
    }

    DnsCacheUnlock();

    return Ret;
}

/* Sets the TTL of every record of the list */
static
VOID
SetTtl(
    _In_ PDNS_RECORDW List,
    _In_ DWORD Ttl)
{
    for (; List; List = List->pNext)
        List->dwTtl = Ttl;
}

/*
 * The records of the name and type: the rows of the hosts file first (every row of the name and type, in the
 * order of the file), else the answer of a DNS server with the time that is left of it, else a negative answer
 * (its status). DNSRSLVR_CACHE_MISS when there is nothing.
 */
DNS_STATUS
DnsIntCacheGetEntryByName(
    LPCWSTR Name,
    WORD wType,
    DWORD dwFlags,
    PDNS_RECORDW *Record)
{
    DNS_STATUS Status = DNSRSLVR_CACHE_MISS;
    PRESOLVER_CACHE_ENTRY CacheEntry, Negative = NULL, Found = NULL;
    PLIST_ENTRY NextEntry, Bucket, Following;
    PDNS_RECORDW *Tail, Copy;
    ULONGLONG Now;
    BOOL bNoSearch = (dwFlags & (DNS_QUERY_NO_RECURSION | DNS_QUERY_TREAT_AS_FQDN)) != 0;

    DPRINT("DnsIntCacheGetEntryByName(%S %hu 0x%lx %p)\n",
           Name, wType, dwFlags, Record);

    /* Assume failure */
    *Record = NULL;

    /* Lock the cache */
    DnsCacheLock();

    if (!DnsCache.Buckets)
    {
        DnsCacheUnlock();
        return Status;
    }

    Now = CacheNow();
    SweepIfDue(Now);
    Bucket = BucketOf(NameHash(Name));

    /*
     * The rows of the hosts file come first (they shadow a DNS name) and every row of the name and type
     * is returned, in the order of the file.
     */
    Tail = Record;
    for (NextEntry = Bucket->Flink; NextEntry != Bucket; NextEntry = NextEntry->Flink)
    {
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, HashLink);

        if (CacheEntry->bHostsFileEntry &&
            NamesMatch(CacheEntry, Name) &&
            (wType == DNS_TYPE_ANY || CacheEntry->Type == wType))
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
            if (CacheEntry->Type == DNS_TYPE_PTR)
                break;
        }
    }

    if (Status == ERROR_SUCCESS)
    {
        DnsCacheUnlock();
        return Status;
    }

    /* The answers of the DNS servers, unless the caller asked for a fresh one */
    if (dwFlags & DNS_QUERY_BYPASS_CACHE)
    {
        DnsCacheUnlock();
        return Status;
    }

    for (NextEntry = Bucket->Flink; NextEntry != Bucket; NextEntry = Following)
    {
        Following = NextEntry->Flink;
        CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, HashLink);

        if (CacheEntry->bHostsFileEntry || !NamesMatch(CacheEntry, Name))
            continue;

        if (IsExpired(CacheEntry, Now))
        {
            DnsIntCacheRemoveEntryItem(CacheEntry);
            continue;
        }

        if (CacheEntry->Record)
        {
            if (wType == DNS_TYPE_ANY || CacheEntry->Type == wType)
            {
                Found = CacheEntry;
                break;
            }
        }
        else if (Negative == NULL && CacheEntry->bNoSearch == bNoSearch &&
                 (CacheEntry->NegStatus == DNS_ERROR_RCODE_NAME_ERROR ||
                  wType == CacheEntry->Type))
        {
            /* a name that does not exist has no record of any type */
            Negative = CacheEntry;
        }
    }

    if (Found == NULL)
        Found = Negative;

    if (Found != NULL)
    {
        /* used now: the last to go */
        RemoveEntryList(&Found->LruLink);
        InsertTailList(&DnsCache.LruList, &Found->LruLink);

        if (Found->Record == NULL)
        {
            Status = Found->NegStatus;
        }
        else
        {
            /* Copy the entry and return it, with the time that is left of it */
            *Record = DnsRecordSetCopyEx(Found->Record, DnsCharSetUnicode, DnsCharSetUnicode);
            if (*Record != NULL)
            {
                SetTtl(*Record, SecondsLeft(Found, Now));
                Status = ERROR_SUCCESS;
            }
        }
    }

    /* Release the cache */
    DnsCacheUnlock();

    return Status;
}

/*
 * Adds an entry (the lock is held). Record is the answer (copied), or NULL for a negative one of Name, Type and
 * NegStatus. A hosts entry never expires and is not counted; the other entries replace the entry of their name
 * and type, and the oldest unused one goes when there are too many.
 */
static
VOID
AddEntry(
    _In_opt_ PDNS_RECORDW Record,
    _In_ BOOL bHostsFileEntry,
    _In_ LPCWSTR Name,
    _In_ WORD Type,
    _In_ DNS_STATUS NegStatus,
    _In_ BOOL bNoSearch,
    _In_ DWORD Ttl)
{
    PRESOLVER_CACHE_ENTRY Entry, Old;
    PLIST_ENTRY Next, Following, Bucket;
    ULONGLONG Now = CacheNow();

    if (!DnsCache.Buckets)
        return;

    Entry = (PRESOLVER_CACHE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Entry));
    if (!Entry)
        return;

    Entry->bHostsFileEntry = bHostsFileEntry;
    if (Record)
    {
        Entry->Record = DnsRecordSetCopyEx(Record, DnsCharSetUnicode, DnsCharSetUnicode);
        if (!Entry->Record)
        {
            /* An entry without a record would crash the next lookup that walks the list */
            HeapFree(GetProcessHeap(), 0, Entry);
            return;
        }
        Entry->Name = Entry->Record->pName;
        Entry->Type = Entry->Record->wType;
    }
    else
    {
        Entry->NegName = HeapAlloc(GetProcessHeap(), 0, (wcslen(Name) + 1) * sizeof(WCHAR));
        if (!Entry->NegName)
        {
            HeapFree(GetProcessHeap(), 0, Entry);
            return;
        }
        wcscpy(Entry->NegName, Name);
        Entry->Name = Entry->NegName;
        Entry->Type = Type;
        Entry->NegStatus = NegStatus;
        Entry->bNoSearch = bNoSearch;
    }
    Entry->Hash = NameHash(Entry->Name);
    Bucket = BucketOf(Entry->Hash);

    if (!bHostsFileEntry)
    {
        Entry->ExpiresAt = Now + (ULONGLONG)Ttl * 1000;

        /*
         * One entry per name and type: a newer answer replaces the older one; a positive answer of a name also
         * ends the entries saying that the name does not exist (and such an entry ends the answers of the name).
         * "No record of the type" stays for the other types: an A answer says nothing about AAAA.
         */
        for (Next = Bucket->Flink; Next != Bucket; Next = Following)
        {
            Following = Next->Flink;
            Old = CONTAINING_RECORD(Next, RESOLVER_CACHE_ENTRY, HashLink);

            if (Old->bHostsFileEntry || !NamesMatch(Old, Entry->Name))
                continue;
            if (Old->Type == Entry->Type ||
                (Record && !Old->Record && Old->NegStatus == DNS_ERROR_RCODE_NAME_ERROR) ||
                (!Record && NegStatus == DNS_ERROR_RCODE_NAME_ERROR && Old->Record))
                DnsIntCacheRemoveEntryItem(Old);
        }

        /* Make room: the entries that are over their time go first, then the least recently used */
        while (DnsCache.EntryCount >= CACHE_MAX_ENTRIES && !IsListEmpty(&DnsCache.LruList))
        {
            if (Now - LastSweep >= 1000)
                SweepExpired(Now);
            if (DnsCache.EntryCount < CACHE_MAX_ENTRIES)
                break;
            Old = CONTAINING_RECORD(DnsCache.LruList.Flink, RESOLVER_CACHE_ENTRY, LruLink);
            DnsIntCacheRemoveEntryItem(Old);
        }

        InsertTailList(&DnsCache.LruList, &Entry->LruLink);
        DnsCache.EntryCount++;
    }
    else
    {
        Entry->ExpiresAt = 0;
    }

    /* Insert it to our Lists */
    InsertTailList(&DnsCache.RecordList, &Entry->CacheLink);
    InsertTailList(Bucket, &Entry->HashLink);
}

VOID
DnsIntCacheAddEntry(
    _In_ PDNS_RECORDW Record,
    _In_ BOOL bHostsFileEntry)
{
    DPRINT("DnsIntCacheAddEntry(%p %u)\n",
           Record, bHostsFileEntry);

    DPRINT("Name: %S\n", Record->pName);
    DPRINT("TTL: %lu\n", Record->dwTtl);

    /* Lock the cache */
    DnsCacheLock();

    AddEntry(Record, bHostsFileEntry, Record->pName, Record->wType, ERROR_SUCCESS, FALSE, Record->dwTtl);

    /* Release the cache */
    DnsCacheUnlock();
}

/*
 * The answer of a DNS server: kept for the time of its shortest record (at most MaxCacheTtl); an answer
 * with a TTL of 0 is not kept.
 */
VOID
DnsIntCacheAddResult(
    _In_ PDNS_RECORDW Records)
{
    PDNS_RECORDW Record;
    DWORD Ttl, Max;

    if (Records == NULL)
        return;

    Ttl = Records->dwTtl;
    for (Record = Records->pNext; Record; Record = Record->pNext)
    {
        if (Record->dwTtl < Ttl)
            Ttl = Record->dwTtl;
    }
    Max = (DWORD)MaxCacheTtl;
    if (Ttl > Max)
        Ttl = Max;
    if (Ttl == 0)
        return;

    DnsCacheLock();
    SweepIfDue(CacheNow());
    AddEntry(Records, FALSE, Records->pName, Records->wType, ERROR_SUCCESS, FALSE, Ttl);
    DnsCacheUnlock();
}

/* A negative answer of a DNS server: the name does not exist (DNS_ERROR_RCODE_NAME_ERROR) or has no
   record of the type (DNS_INFO_NO_RECORDS), kept for MaxNegativeCacheTtl */
VOID
DnsIntCacheAddNegative(
    _In_ LPCWSTR Name,
    _In_ WORD wType,
    _In_ DNS_STATUS Status,
    _In_ BOOL bNoSearch)
{
    DWORD Ttl = (DWORD)MaxNegativeCacheTtl;

    if (Ttl == 0)
        return;
    if (Status != DNS_ERROR_RCODE_NAME_ERROR && Status != DNS_INFO_NO_RECORDS)
        return;

    DnsCacheLock();
    SweepIfDue(CacheNow());
    AddEntry(NULL, FALSE, Name, wType, Status, bNoSearch, Ttl);
    DnsCacheUnlock();
}

/*
 * The list of ipconfig /displaydns goes over the RPC as a linked list, which the marshalling of the RPC does not
 * take beyond a few thousand elements (the call fails): the list is cut at this many entries.
 */
#define CACHE_LIST_MAX      2800

/* Adds the entry to the list (pHead, pLast) of the RPC; ERROR_OUTOFMEMORY when it cannot */
static
DNS_STATUS
ListEntry(
    _In_ PRESOLVER_CACHE_ENTRY CacheEntry,
    _Inout_ DNS_CACHE_ENTRY **ppHead,
    _Inout_ PDNS_CACHE_ENTRY *ppLast)
{
    PDNS_CACHE_ENTRY pNewEntry;

    pNewEntry = midl_user_allocate(sizeof(DNS_CACHE_ENTRY));
    if (pNewEntry == NULL)
        return ERROR_OUTOFMEMORY;

    pNewEntry->pszName = midl_user_allocate((wcslen(CacheEntry->Name) + 1) * sizeof(WCHAR));
    if (pNewEntry->pszName == NULL)
    {
        midl_user_free(pNewEntry);
        return ERROR_OUTOFMEMORY;
    }

    wcscpy(pNewEntry->pszName, CacheEntry->Name);
    /* a name that does not exist is listed for any type, as Windows does (ipconfig /displaydns asks for it
       by that type and gets the answer of the negative entry) */
    pNewEntry->wType1 = (!CacheEntry->Record && CacheEntry->NegStatus == DNS_ERROR_RCODE_NAME_ERROR) ?
                        DNS_TYPE_ANY : CacheEntry->Type;
    pNewEntry->wType2 = 0;
    pNewEntry->wFlags = 0;

    if (*ppLast == NULL)
        *ppHead = pNewEntry;
    else
        (*ppLast)->pNext = pNewEntry;
    *ppLast = pNewEntry;
    return ERROR_SUCCESS;
}

DNS_STATUS
DnsIntCacheGetEntries(
    _Out_ DNS_CACHE_ENTRY **ppCacheEntries)
{
    PRESOLVER_CACHE_ENTRY CacheEntry;
    PLIST_ENTRY NextEntry, Chain, Other;
    PDNS_CACHE_ENTRY pLastEntry = NULL;
    DNS_STATUS Status = ERROR_SUCCESS;
    ULONG Count = 0, Pass, Skip;

    /* Lock the cache */
    DnsCacheLock();

    *ppCacheEntries = NULL;

    /* The entries that are over their time are not listed (they go now) */
    SweepExpired(CacheNow());

    /* When the list is cut, the newest answers are the ones listed (the name just asked for is there) */
    Skip = (DnsCache.EntryCount > CACHE_LIST_MAX) ? DnsCache.EntryCount - CACHE_LIST_MAX : 0;

    /* The answers of the DNS servers first, then the rows of the hosts file */
    for (Pass = 0; Pass < 2 && Status == ERROR_SUCCESS; Pass++)
    {
        for (NextEntry = DnsCache.RecordList.Flink;
             NextEntry != &DnsCache.RecordList && Count < CACHE_LIST_MAX;
             NextEntry = NextEntry->Flink)
        {
            /* Get the Current Entry */
            CacheEntry = CONTAINING_RECORD(NextEntry, RESOLVER_CACHE_ENTRY, CacheLink);

            if (CacheEntry->bHostsFileEntry != (Pass == 1))
                continue;
            if (Pass == 0 && Skip > 0)
            {
                Skip--;
                continue;
            }

            DPRINT("1 %S %lu\n", CacheEntry->Name, CacheEntry->Type);

            /* a name that does not exist is listed once (it may be there for asking with and without the search list) */
            if (!CacheEntry->Record && CacheEntry->NegStatus == DNS_ERROR_RCODE_NAME_ERROR)
            {
                BOOL bListed = FALSE;

                Chain = BucketOf(CacheEntry->Hash);
                for (Other = Chain->Flink; Other != &CacheEntry->HashLink && Other != Chain; Other = Other->Flink)
                {
                    PRESOLVER_CACHE_ENTRY Earlier = CONTAINING_RECORD(Other, RESOLVER_CACHE_ENTRY, HashLink);

                    if (!Earlier->Record && Earlier->NegStatus == DNS_ERROR_RCODE_NAME_ERROR &&
                        _wcsicmp(Earlier->Name, CacheEntry->Name) == 0)
                    {
                        bListed = TRUE;
                        break;
                    }
                }
                if (bListed)
                    continue;
            }

            Status = ListEntry(CacheEntry, ppCacheEntries, &pLastEntry);
            if (Status != ERROR_SUCCESS)
                break;
            Count++;
        }
    }

    /* Release the cache */
    DnsCacheUnlock();

    return Status;
}
