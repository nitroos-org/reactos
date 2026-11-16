#ifndef _DNSRSLVR_PCH_
#define _DNSRSLVR_PCH_

#include <stdarg.h>
#include <stdio.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winreg.h>
#include <winsvc.h>
#include <windns.h>
#include <windns_undoc.h>

#define NTOS_MODE_USER
#include <ndk/rtlfuncs.h>
#include <ndk/obfuncs.h>

#include <dnsrslvr_s.h>

#include <strsafe.h>

/*
 * An entry of the cache: the records of one answer (the name and the type of the first one are its key), or, with no
 * records, a negative answer (the name does not exist, or has no record of the type). The entries of the hosts file
 * never expire and are not counted against the size of the cache.
 */
typedef struct _RESOLVER_CACHE_ENTRY
{
    LIST_ENTRY CacheLink;       /* every entry, oldest first */
    LIST_ENTRY HashLink;        /* the entries of one bucket, oldest first */
    LIST_ENTRY LruLink;         /* the entries of the answers of DNS servers, least recently used first */
    BOOL bHostsFileEntry;
    PDNS_RECORDW Record;        /* NULL for a negative entry */
    PWSTR NegName;              /* the name of a negative entry (owned) */
    PCWSTR Name;                /* the name of the entry (of the record, or NegName) */
    WORD Type;
    BOOL bNoSearch;             /* negative entries: asked without the search list */
    DNS_STATUS NegStatus;       /* negative entries: DNS_ERROR_RCODE_NAME_ERROR or DNS_INFO_NO_RECORDS */
    ULONGLONG ExpiresAt;        /* in milliseconds of the cache clock, 0 = never */
    ULONG Hash;
} RESOLVER_CACHE_ENTRY, *PRESOLVER_CACHE_ENTRY;

typedef struct _RESOLVER_CACHE
{
    LIST_ENTRY RecordList;
    LIST_ENTRY LruList;
    PLIST_ENTRY Buckets;
    ULONG EntryCount;           /* the entries of the LruList */
    CRITICAL_SECTION Lock;
} RESOLVER_CACHE, *PRESOLVER_CACHE;

/* The answer of DnsIntCacheGetEntryByName when nothing is cached for the name and type */
#define DNSRSLVR_CACHE_MISS     ERROR_NOT_FOUND


/* cache.c */

VOID DnsIntCacheInitialize(VOID);
VOID DnsIntCacheRemoveEntryItem(PRESOLVER_CACHE_ENTRY CacheEntry);
VOID DnsIntCacheFree(VOID);

#define CACHE_FLUSH_HOSTS_FILE_ENTRIES     0x00000001
#define CACHE_FLUSH_NON_HOSTS_FILE_ENTRIES 0x00000002
#define CACHE_FLUSH_ALL                    0x00000003

DNS_STATUS
DnsIntCacheFlush(
    _In_ ULONG ulFlags);

DNS_STATUS
DnsIntFlushCacheEntry(
    _In_ LPCWSTR pszName,
    _In_ WORD wType);

VOID
DnsIntCacheLock(VOID);

VOID
DnsIntCacheUnlock(VOID);

BOOL
DnsIntCacheHasHostsName(
    _In_ LPCWSTR Name);

DNS_STATUS
DnsIntCacheGetEntryByName(
    LPCWSTR Name,
    WORD wType,
    DWORD dwFlags,
    PDNS_RECORDW *Record);

VOID
DnsIntCacheAddEntry(
    _In_ PDNS_RECORDW Record,
    _In_ BOOL bHostsFileEntry);

VOID
DnsIntCacheAddResult(
    _In_ PDNS_RECORDW Records);

VOID
DnsIntCacheAddNegative(
    _In_ LPCWSTR Name,
    _In_ WORD wType,
    _In_ DNS_STATUS Status,
    _In_ BOOL bNoSearch);

VOID
DnsIntCacheReadParameters(VOID);

BOOL
DnsIntCacheRemoveEntryByName(
    _In_ LPCWSTR Name);

DNS_STATUS
DnsIntCacheGetEntries(
    _Out_ DNS_CACHE_ENTRY **ppCacheEntries);


/* hostsfile.c */

BOOL
ReadHostsFile(VOID);

VOID
HostsFileInitialize(VOID);

VOID
HostsFileReloadIfChanged(VOID);

#endif /* _DNSRSLVR_PCH_ */
