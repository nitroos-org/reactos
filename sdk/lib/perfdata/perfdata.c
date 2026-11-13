/*
 * Built-in performance counter sets and their providers.
 *
 * Shared by pdh.dll (the PDH counter API) and advapi32.dll (HKEY_PERFORMANCE_DATA).
 * The counter sets are the ones that Windows publishes for the system objects
 * (Memory, Processor, System, PhysicalDisk, Network Interface, Process); their
 * names, name indices and counter types follow Windows. Values come from
 * NtQuerySystemInformation, the disk class driver and the IP helper.
 *
 * This file is linked into advapi32, so it must not use the C runtime DLL:
 * memory comes from the process heap, and only the string and sort helpers that
 * ntdll exports are used.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define WIN32_NO_STATUS /* the NDK headers bring in the NTSTATUS values */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winnls.h"
#include "winioctl.h"
#include "ntddstor.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "iphlpapi.h"
#include "iptypes.h"

#include "pdh.h"
#include "pdhmsg.h"
#include <ndk/umtypes.h>
#include <ndk/extypes.h>
#include "winperf.h"

#include "perfdata.h"

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif


/* process heap wrappers: no CRT */

static void *perf_alloc( SIZE_T size )
{
    return HeapAlloc( GetProcessHeap(), 0, size ? size : 1 );
}

static void *perf_calloc( SIZE_T count, SIZE_T size )
{
    if (size && count > (~(SIZE_T)0) / size) return NULL;
    return HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, (count && size) ? count * size : 1 );
}

static void *perf_realloc( void *ptr, SIZE_T size )
{
    if (!ptr) return perf_alloc( size );
    return HeapReAlloc( GetProcessHeap(), 0, ptr, size ? size : 1 );
}

static void perf_free( void *ptr )
{
    if (ptr) HeapFree( GetProcessHeap(), 0, ptr );
}

static WCHAR *perf_wcsdup( const WCHAR *str )
{
    SIZE_T len = lstrlenW( str ) + 1;
    WCHAR *ret = perf_alloc( len * sizeof(WCHAR) );
    if (ret) memcpy( ret, str, len * sizeof(WCHAR) );
    return ret;
}

#define malloc  perf_alloc
#define calloc  perf_calloc
#define realloc perf_realloc
#define free    perf_free
#define wcsdup  perf_wcsdup
#define wcsicmp _wcsicmp
#define wcsnicmp _wcsnicmp

#include "perfdata_tables.h"

static CRITICAL_SECTION perf_cs;
static CRITICAL_SECTION_DEBUG perf_cs_debug =
{
    0, 0, &perf_cs,
    { &perf_cs_debug.ProcessLocksList, &perf_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": perf_cs") }
};
static CRITICAL_SECTION perf_cs = { &perf_cs_debug, -1, 0, 0, 0, 0 };

/* Layouts of the NtQuerySystemInformation records (the public header only has opaque ones). */

struct pdh_spi
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG Spare3Count;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG Cc[29];
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
    ULONGLONG Tail[8];  /* newer systems append more; the buffer is larger than the record we use */
};

struct pdh_cpu
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
};

struct pdh_vm_counters
{
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
};

struct pdh_process
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    struct pdh_vm_counters vm;
};

#define PDH_SYSINFO_TIMEOFDAY     3
#define PDH_SYSINFO_PERFORMANCE   2
#define PDH_SYSINFO_PROCESS       5
#define PDH_SYSINFO_PAGEFILE      18
#define PDH_SYSINFO_CPU_PERF      8
#define PDH_SYSINFO_INTERRUPT     23
#define PDH_CPU_RECORD_MIN        44
#define PDH_CPU_RECORD_MAX        48

LONG NTAPI NtQuerySystemInformation( ULONG, PVOID, ULONG, PULONG );

static LONG query_sysinfo( ULONG class, void *buf, ULONG size, ULONG *ret )
{
    return NtQuerySystemInformation( class, buf, size, ret );
}

/* ---- snapshots ----
 * A snapshot of each data source is taken once per collection ("generation"), so that all the
 * counters of one PdhCollectQueryData see the same numbers. */

static DWORD cur_gen = 1;

static struct { DWORD gen; BOOL ok; struct pdh_spi spi; } snap_spi;
static struct { DWORD gen; DWORD count; struct pdh_cpu *cpu; } snap_cpu;

/* the record of IOCTL_DISK_PERFORMANCE */
struct pdh_disk_perf
{
    LARGE_INTEGER BytesRead;
    LARGE_INTEGER BytesWritten;
    LARGE_INTEGER ReadTime;
    LARGE_INTEGER WriteTime;
    LARGE_INTEGER IdleTime;
    ULONG ReadCount;
    ULONG WriteCount;
    ULONG QueueDepth;
    ULONG SplitCount;
    LARGE_INTEGER QueryTime;
    ULONG StorageDeviceNumber;
    WCHAR StorageManagerName[8];
};

struct disk_info
{
    WCHAR name[64];
    struct pdh_disk_perf perf;
    BOOL have_perf;
};
static struct { DWORD gen; DWORD count; struct disk_info *disk; } snap_disk;

/* one record of SystemInterruptInformation */
struct pdh_int
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
};
static struct { DWORD gen; DWORD count; struct pdh_int *cpu; } snap_int;

struct ldisk_info
{
    WCHAR name[64];
    struct pdh_disk_perf perf;
    BOOL have_perf;
    ULONGLONG total_mb, free_mb;
    BOOL have_space;
};
static struct { DWORD gen; DWORD count; struct ldisk_info *disk; } snap_ldisk;

struct thread_ref
{
    WCHAR *name;
    const SYSTEM_THREAD_INFORMATION *thread;
};
static struct { DWORD gen; DWORD count; struct thread_ref *thr; } snap_thread;

struct net_info
{
    WCHAR name[128];
    MIB_IFROW row;
};
static struct { DWORD gen; DWORD count; struct net_info *net; } snap_net;

/* one entry of SystemPageFileInformation; the sizes are in pages */
struct pdh_pagefile
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } FileName;
};

struct page_info
{
    WCHAR name[260];
    ULONG total, inuse, peak;
};
static struct { DWORD gen; DWORD count; struct page_info *page; } snap_page;

static struct
{
    DWORD gen;
    DWORD count, threads, ready;
    BYTE *buf;
    ULONG buf_len;
    struct pdh_process **proc;
    WCHAR **name;
} snap_proc;

LONGLONG perf_now(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime( &ft );
    return ((LONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

void perf_next_generation(void)
{
    EnterCriticalSection( &perf_cs );
    cur_gen++;
    LeaveCriticalSection( &perf_cs );
}

static void free_snap_thread(void);

static void free_snap_proc(void)
{
    free_snap_thread();   /* its entries point into the process snapshot */
    DWORD i;
    for (i = 0; i < snap_proc.count; i++) free( snap_proc.name[i] );
    free( snap_proc.name );
    free( snap_proc.proc );
    free( snap_proc.buf );
    memset( &snap_proc, 0, sizeof(snap_proc) );
}

static BOOL ensure_spi( BOOL force )
{
    ULONG len;

    if (!force && snap_spi.gen == cur_gen) return snap_spi.ok;
    memset( &snap_spi.spi, 0, sizeof(snap_spi.spi) );
    snap_spi.ok = query_sysinfo( PDH_SYSINFO_PERFORMANCE, &snap_spi.spi, sizeof(snap_spi.spi), &len ) >= 0;
    snap_spi.gen = cur_gen;
    return snap_spi.ok;
}

static DWORD cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo( &si );
    return si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
}

static BOOL ensure_cpu( BOOL force )
{
    DWORD n, i, stride;
    ULONG len = 0;
    BYTE *raw;

    if (!force && snap_cpu.gen == cur_gen) return snap_cpu.cpu != NULL;
    free( snap_cpu.cpu );
    snap_cpu.cpu = NULL;
    snap_cpu.count = 0;
    snap_cpu.gen = cur_gen;
    n = cpu_count();
    if (!(snap_cpu.cpu = calloc( n, sizeof(*snap_cpu.cpu) ))) return FALSE;

    /* The records are 48 bytes on Windows and on a 64-bit kernel (a WoW64 client gets them
     * unchanged), but 44 on a 32-bit ReactOS kernel, where GCC aligns the 64-bit fields of
     * the structure to 4: this code's own struct has that size when it is built for i386.
     * Ask with room for the larger record and take the stride from the returned length. */
    if (!(raw = calloc( n, PDH_CPU_RECORD_MAX ))) goto fail;
    if (query_sysinfo( PDH_SYSINFO_CPU_PERF, raw, n * PDH_CPU_RECORD_MAX, &len ) < 0 || !len)
    {
        free( raw );
        goto fail;
    }
    stride = len / n;
    if (stride < PDH_CPU_RECORD_MIN || stride > PDH_CPU_RECORD_MAX) stride = PDH_CPU_RECORD_MAX;
    for (i = 0; i < n; i++)
    {
        const BYTE *r = raw + i * stride;
        memcpy( &snap_cpu.cpu[i].IdleTime, r, 8 );
        memcpy( &snap_cpu.cpu[i].KernelTime, r + 8, 8 );
        memcpy( &snap_cpu.cpu[i].UserTime, r + 16, 8 );
        memcpy( &snap_cpu.cpu[i].DpcTime, r + 24, 8 );
        memcpy( &snap_cpu.cpu[i].InterruptTime, r + 32, 8 );
        memcpy( &snap_cpu.cpu[i].InterruptCount, r + 40, 4 );
    }
    free( raw );
    snap_cpu.count = n;
    return TRUE;

fail:
    free( snap_cpu.cpu );
    snap_cpu.cpu = NULL;
    return FALSE;
}

static BOOL ensure_int( BOOL force )
{
    DWORD n = cpu_count();
    ULONG len = 0;

    if (!force && snap_int.gen == cur_gen) return snap_int.cpu != NULL;
    free( snap_int.cpu );
    snap_int.cpu = NULL;
    snap_int.count = 0;
    snap_int.gen = cur_gen;
    if (!(snap_int.cpu = calloc( n, sizeof(*snap_int.cpu) ))) return FALSE;
    if (query_sysinfo( PDH_SYSINFO_INTERRUPT, snap_int.cpu, n * sizeof(*snap_int.cpu), &len ) < 0)
    {
        free( snap_int.cpu );
        snap_int.cpu = NULL;
        return FALSE;
    }
    snap_int.count = n;
    return TRUE;
}

static void append_letter( WCHAR *name, DWORD size, WCHAR letter )
{
    DWORD len = lstrlenW( name );
    if (len + 4 >= size) return;
    name[len++] = ' ';
    name[len++] = letter;
    name[len++] = ':';
    name[len] = 0;
}

static BOOL ensure_disk( BOOL force )
{
    DWORD i, n, letter_disk[26];
    struct disk_info *disks;
    WCHAR path[32];
    HANDLE h;

    if (!force && snap_disk.gen == cur_gen) return TRUE;
    free( snap_disk.disk );
    snap_disk.disk = NULL;
    snap_disk.count = 0;
    snap_disk.gen = cur_gen;

    for (i = 0; i < 26; i++)
    {
        STORAGE_DEVICE_NUMBER num;
        DWORD ret;

        letter_disk[i] = ~0u;
        lstrcpyW( path, L"A:\\" );
        path[0] = 'A' + i;
        if (GetDriveTypeW( path ) != DRIVE_FIXED) continue;
        lstrcpyW( path, L"\\\\.\\A:" );
        path[4] = 'A' + i;
        h = CreateFileW( path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
        if (h == INVALID_HANDLE_VALUE) continue;
        if (DeviceIoControl( h, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &num, sizeof(num), &ret, NULL ) &&
            num.DeviceType == FILE_DEVICE_DISK)
            letter_disk[i] = num.DeviceNumber;
        CloseHandle( h );
    }

    if (!(disks = calloc( 16, sizeof(*disks) ))) return FALSE;
    for (n = 0, i = 0; i < 16; i++)
    {
        DWORD ret, l;

        _snwprintf( path, ARRAY_SIZE(path), L"\\\\.\\PhysicalDrive%u", i );
        h = CreateFileW( path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
        if (h == INVALID_HANDLE_VALUE) continue;
        _snwprintf( disks[n].name, ARRAY_SIZE(disks[n].name), L"%u", i );
        for (l = 0; l < 26; l++) if (letter_disk[l] == i) append_letter( disks[n].name, ARRAY_SIZE(disks[n].name), 'A' + l );
        disks[n].have_perf = DeviceIoControl( h, IOCTL_DISK_PERFORMANCE, NULL, 0, &disks[n].perf,
                                              sizeof(disks[n].perf), &ret, NULL );
        CloseHandle( h );
        n++;
    }
    snap_disk.disk = disks;
    snap_disk.count = n;
    return TRUE;
}

static void ldisk_fill( struct ldisk_info *d, const WCHAR *devpath, const WCHAR *root )
{
    HANDLE h;
    DWORD ret;
    ULARGE_INTEGER avail, total, free_bytes;

    h = CreateFileW( devpath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
    if (h != INVALID_HANDLE_VALUE)
    {
        d->have_perf = DeviceIoControl( h, IOCTL_DISK_PERFORMANCE, NULL, 0, &d->perf, sizeof(d->perf), &ret, NULL );
        CloseHandle( h );
    }
    if (GetDiskFreeSpaceExW( root, &avail, &total, &free_bytes ))
    {
        d->total_mb = total.QuadPart >> 20;
        d->free_mb = free_bytes.QuadPart >> 20;
        d->have_space = TRUE;
    }
}

typedef BOOL (WINAPI *GetVolumePathNamesForNameW_t)( LPCWSTR, LPWSTR, DWORD, PDWORD );

/* The fixed volumes: a letter ("C:") or, for a volume without a letter, the name of its device ("HarddiskVolume1") */
static BOOL ensure_ldisk( BOOL force )
{
    struct ldisk_info *disks;
    DWORD n = 0, i, max_disks = 64;
    GetVolumePathNamesForNameW_t pGetPaths;
    WCHAR vol[MAX_PATH], path[MAX_PATH], letter_vol[26][64];
    HANDLE find;

    if (!force && snap_ldisk.gen == cur_gen) return TRUE;
    free( snap_ldisk.disk );
    snap_ldisk.disk = NULL;
    snap_ldisk.count = 0;
    snap_ldisk.gen = cur_gen;
    if (!(disks = calloc( max_disks, sizeof(*disks) ))) return FALSE;

    pGetPaths = (GetVolumePathNamesForNameW_t)GetProcAddress( GetModuleHandleW( L"kernel32.dll" ), "GetVolumePathNamesForNameW" );

    /* the volumes that have a drive letter are listed by it, however the volume list reports them */
    for (i = 0; i < 26; i++)
    {
        lstrcpyW( path, L"A:\\" );
        path[0] = 'A' + i;
        letter_vol[i][0] = 0;
        if (GetDriveTypeW( path ) == DRIVE_FIXED) GetVolumeNameForVolumeMountPointW( path, letter_vol[i], ARRAY_SIZE(letter_vol[i]) );
    }
    if ((find = FindFirstVolumeW( vol, ARRAY_SIZE(vol) )) != INVALID_HANDLE_VALUE)
    {
        do
        {
            WCHAR names[MAX_PATH * 2], dev[MAX_PATH], *p;
            DWORD len = 0;
            size_t vl = lstrlenW( vol );

            if (n >= max_disks || vl < 6 || GetDriveTypeW( vol ) != DRIVE_FIXED) continue;
            for (i = 0; i < 26; i++) if (letter_vol[i][0] && !wcsicmp( letter_vol[i], vol )) break;
            if (i < 26) continue;
            names[0] = 0;
            if (pGetPaths && pGetPaths( vol, names, ARRAY_SIZE(names), &len ) && names[0]) continue;  /* mounted: listed by its path */
            if (vol[vl - 1] != '\\') continue;
            vol[vl - 1] = 0;   /* \\?\Volume{guid} */
            if (QueryDosDeviceW( vol + 4, dev, ARRAY_SIZE(dev) ) && (p = wcsrchr( dev, '\\' )) && p[1])
            {
                lstrcpynW( disks[n].name, p + 1, ARRAY_SIZE(disks[n].name) );
                vol[vl - 1] = '\\';
                lstrcpyW( path, vol );
                vol[vl - 1] = 0;
                ldisk_fill( &disks[n], vol, path );
                n++;
            }
        } while (FindNextVolumeW( find, vol, ARRAY_SIZE(vol) ));
        FindVolumeClose( find );
    }

    for (i = 0; i < 26 && n < max_disks; i++)
    {
        lstrcpyW( path, L"A:\\" );
        path[0] = 'A' + i;
        if (GetDriveTypeW( path ) != DRIVE_FIXED) continue;
        lstrcpyW( vol, L"\\\\.\\A:" );
        vol[4] = 'A' + i;
        _snwprintf( disks[n].name, ARRAY_SIZE(disks[n].name), L"%c:", 'A' + i );
        ldisk_fill( &disks[n], vol, path );
        n++;
    }
    snap_ldisk.disk = disks;
    snap_ldisk.count = n;
    return TRUE;
}

typedef DWORD (WINAPI *GetIfTable_t)( PMIB_IFTABLE, PULONG, BOOL );
typedef ULONG (WINAPI *GetAdaptersAddresses_t)( ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG );

/* The adapters with their descriptions: GetIfTable's bDescr is the adapter's GUID here, not a description. */
static PIP_ADAPTER_ADDRESSES get_adapter_addresses( HMODULE iphlpapi )
{
    GetAdaptersAddresses_t pGetAdaptersAddresses;
    PIP_ADAPTER_ADDRESSES aa;
    ULONG size = 0, ret;
    ULONG flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    int tries;

    if (!(pGetAdaptersAddresses = (GetAdaptersAddresses_t)GetProcAddress( iphlpapi, "GetAdaptersAddresses" ))) return NULL;
    for (tries = 0; tries < 3; tries++)
    {
        ret = pGetAdaptersAddresses( AF_UNSPEC, flags, NULL, NULL, &size );
        if (ret != ERROR_BUFFER_OVERFLOW || !size) return NULL;
        if (!(aa = malloc( size ))) return NULL;
        ret = pGetAdaptersAddresses( AF_UNSPEC, flags, NULL, aa, &size );
        if (ret == ERROR_SUCCESS) return aa;
        free( aa );
        if (ret != ERROR_BUFFER_OVERFLOW) break;
    }
    return NULL;
}

static const WCHAR *adapter_description( PIP_ADAPTER_ADDRESSES aa, DWORD index )
{
    for (; aa; aa = aa->Next)
        if (aa->IfIndex == index && aa->Description && aa->Description[0]) return aa->Description;
    return NULL;
}

static void sanitize_adapter_name( WCHAR *s )
{
    for (; *s; s++)
    {
        if (*s == '(') *s = '[';
        else if (*s == ')') *s = ']';
        else if (*s == '#' || *s == '/' || *s == '\\') *s = '_';
    }
}

static BOOL ensure_net( BOOL force )
{
    static HMODULE iphlpapi;
    GetIfTable_t pGetIfTable;
    MIB_IFTABLE *table = NULL;
    PIP_ADAPTER_ADDRESSES addresses;
    ULONG size = 0;
    DWORD i, n, ret;

    if (!force && snap_net.gen == cur_gen) return TRUE;
    free( snap_net.net );
    snap_net.net = NULL;
    snap_net.count = 0;
    snap_net.gen = cur_gen;

    if (!iphlpapi && !(iphlpapi = LoadLibraryW( L"iphlpapi.dll" ))) return FALSE;
    if (!(pGetIfTable = (GetIfTable_t)GetProcAddress( iphlpapi, "GetIfTable" ))) return FALSE;

    ret = pGetIfTable( NULL, &size, FALSE );
    if (ret != ERROR_INSUFFICIENT_BUFFER || !size) return FALSE;
    if (!(table = malloc( size ))) return FALSE;
    if (pGetIfTable( table, &size, FALSE ) != NO_ERROR)
    {
        free( table );
        return FALSE;
    }
    if (!(snap_net.net = calloc( table->dwNumEntries + 1, sizeof(*snap_net.net) )))
    {
        free( table );
        return FALSE;
    }
    addresses = get_adapter_addresses( iphlpapi );
    for (n = 0, i = 0; i < table->dwNumEntries; i++)
    {
        MIB_IFROW *row = &table->table[i];
        DWORD len, j;

        if (row->dwType == MIB_IF_TYPE_LOOPBACK) continue;
        const WCHAR *descr = adapter_description( addresses, row->dwIndex );

        if (descr)
        {
            lstrcpynW( snap_net.net[n].name, descr, ARRAY_SIZE(snap_net.net[n].name) );
            len = lstrlenW( snap_net.net[n].name );
        }
        else
        {
            len = row->dwDescrLen;
            if (len && row->bDescr[len - 1] == 0) len--;
            if (len >= ARRAY_SIZE(snap_net.net[n].name)) len = ARRAY_SIZE(snap_net.net[n].name) - 1;
            len = MultiByteToWideChar( CP_ACP, 0, (const char *)row->bDescr, len, snap_net.net[n].name,
                                       ARRAY_SIZE(snap_net.net[n].name) - 1 );
            snap_net.net[n].name[len] = 0;
        }
        if (!len)
        {
            WCHAR num[16];
            _snwprintf( num, ARRAY_SIZE(num), L"%lu", row->dwIndex );
            lstrcpyW( snap_net.net[n].name, L"Interface " );
            lstrcatW( snap_net.net[n].name, num );
        }
        sanitize_adapter_name( snap_net.net[n].name );
        for (j = 0; j < n; j++)  /* make duplicate names unique, as Windows does */
        {
            if (!wcsicmp( snap_net.net[j].name, snap_net.net[n].name ))
            {
                DWORD k = 2;
                WCHAR base[128];
                lstrcpynW( base, snap_net.net[n].name, ARRAY_SIZE(base) - 16 );
                do
                {
                    WCHAR num[16];
                    _snwprintf( num, ARRAY_SIZE(num), L" _%u", k++ );
                    lstrcpyW( snap_net.net[n].name, base );
                    lstrcatW( snap_net.net[n].name, num );
                }
                while (!wcsicmp( snap_net.net[j].name, snap_net.net[n].name ));
                break;
            }
        }
        snap_net.net[n].row = *row;
        n++;
    }
    snap_net.count = n;
    free( addresses );
    free( table );
    return TRUE;
}

#define PDH_THREAD_STATE_READY          1
#define PDH_THREAD_STATE_DEFERREDREADY  7

/* threads that are ready to run but not running: the value of System\Processor Queue Length.
 * The SYSTEM_THREAD_INFORMATION entries follow the SYSTEM_PROCESS_INFORMATION record. */
static DWORD count_ready_threads( const struct pdh_process *p, const BYTE *buf, ULONG len )
{
    const SYSTEM_PROCESS_INFORMATION *spi = (const SYSTEM_PROCESS_INFORMATION *)p;
    const SYSTEM_THREAD_INFORMATION *thr = (const SYSTEM_THREAD_INFORMATION *)(spi + 1);
    DWORD i, ready = 0;

    for (i = 0; i < spi->NumberOfThreads; i++, thr++)
    {
        if ((const BYTE *)(thr + 1) > buf + len) break;
        if (thr->ThreadState == PDH_THREAD_STATE_READY || thr->ThreadState == PDH_THREAD_STATE_DEFERREDREADY) ready++;
    }
    return ready;
}

static BOOL ensure_proc( BOOL force )
{
    ULONG size = 0x20000, ret;
    LONG status;
    BYTE *buf = NULL;
    struct pdh_process *p;
    DWORD n = 0, i;

    if (!force && snap_proc.gen == cur_gen) return snap_proc.buf != NULL;
    free_snap_proc();
    snap_proc.gen = cur_gen;

    for (;;)
    {
        free( buf );
        if (!(buf = malloc( size ))) return FALSE;
        status = query_sysinfo( PDH_SYSINFO_PROCESS, buf, size, &ret );
        if (status != (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) break;
        size = max( ret, size ) + 0x10000;
    }
    if (status < 0)
    {
        free( buf );
        return FALSE;
    }

    for (p = (struct pdh_process *)buf;; p = (struct pdh_process *)((BYTE *)p + p->NextEntryOffset))
    {
        n++;
        snap_proc.threads += p->NumberOfThreads;
        snap_proc.ready += count_ready_threads( p, buf, ret );
        if (!p->NextEntryOffset) break;
    }
    snap_proc.buf = buf;
    snap_proc.buf_len = ret;
    snap_proc.count = n;
    snap_proc.proc = calloc( n, sizeof(*snap_proc.proc) );
    snap_proc.name = calloc( n, sizeof(*snap_proc.name) );
    if (!snap_proc.proc || !snap_proc.name)
    {
        free_snap_proc();
        return FALSE;
    }
    for (i = 0, p = (struct pdh_process *)buf; i < n; i++, p = (struct pdh_process *)((BYTE *)p + p->NextEntryOffset))
    {
        WCHAR name[260];
        DWORD len, j, dup;

        snap_proc.proc[i] = p;
        if (!p->UniqueProcessId) lstrcpyW( name, L"Idle" );
        else if (p->UniqueProcessId == (HANDLE)4) lstrcpyW( name, L"System" );
        else if (p->ImageName.Buffer && p->ImageName.Length)
        {
            len = min( p->ImageName.Length / sizeof(WCHAR), ARRAY_SIZE(name) - 16 );
            memcpy( name, p->ImageName.Buffer, len * sizeof(WCHAR) );
            name[len] = 0;
            if (len > 4 && !wcsicmp( name + len - 4, L".exe" )) name[len - 4] = 0;
        }
        else lstrcpyW( name, L"Unknown" );
        sanitize_adapter_name( name );  /* same character replacements */

        for (dup = 0, j = 0; j < i; j++)  /* count earlier processes of the same name */
        {
            WCHAR *o = snap_proc.name[j];
            size_t l = lstrlenW( name );
            if (!wcsnicmp( o, name, l ) && (!o[l] || (o[l] == '#' && !wcschr( o + l + 1, '#' )))) dup++;
        }
        if (dup)
        {
            WCHAR num[16];
            _snwprintf( num, ARRAY_SIZE(num), L"#%u", dup );
            lstrcatW( name, num );
        }
        snap_proc.name[i] = wcsdup( name );
    }
    return TRUE;
}

static void free_snap_thread(void)
{
    DWORD i;
    for (i = 0; i < snap_thread.count; i++) free( snap_thread.thr[i].name );
    free( snap_thread.thr );
    memset( &snap_thread, 0, sizeof(snap_thread) );
}

/* every thread of the process snapshot, named "<process instance>/<number of the thread in its process>" */
static BOOL ensure_thread( BOOL force )
{
    DWORD i, j, n = 0;

    if (!force && snap_thread.gen == cur_gen) return snap_thread.thr != NULL || !snap_thread.count;
    free_snap_thread();
    snap_thread.gen = cur_gen;
    if (!ensure_proc( force )) return FALSE;

    for (i = 0; i < snap_proc.count; i++) n += snap_proc.proc[i]->NumberOfThreads;
    if (!n) return TRUE;
    if (!(snap_thread.thr = calloc( n, sizeof(*snap_thread.thr) ))) return FALSE;
    for (i = 0; i < snap_proc.count; i++)
    {
        const SYSTEM_PROCESS_INFORMATION *spi = (const SYSTEM_PROCESS_INFORMATION *)snap_proc.proc[i];
        const SYSTEM_THREAD_INFORMATION *thr = (const SYSTEM_THREAD_INFORMATION *)(spi + 1);

        for (j = 0; j < spi->NumberOfThreads && snap_thread.count < n; j++, thr++)
        {
            WCHAR name[320];

            if ((const BYTE *)(thr + 1) > snap_proc.buf + snap_proc.buf_len) break;
            _snwprintf( name, ARRAY_SIZE(name), L"%s/%u", snap_proc.name[i], j );
            name[ARRAY_SIZE(name) - 1] = 0;
            snap_thread.thr[snap_thread.count].thread = thr;
            if (!(snap_thread.thr[snap_thread.count].name = wcsdup( name ))) continue;
            snap_thread.count++;
        }
    }
    return TRUE;
}

static BOOL ensure_page( BOOL force )
{
    ULONG size = 0x1000, ret = 0, n = 0;
    LONG status;
    BYTE *buf = NULL;
    const struct pdh_pagefile *pf;

    if (!force && snap_page.gen == cur_gen) return TRUE;
    free( snap_page.page );
    snap_page.page = NULL;
    snap_page.count = 0;
    snap_page.gen = cur_gen;

    for (;;)
    {
        free( buf );
        if (!(buf = malloc( size ))) return FALSE;
        status = query_sysinfo( PDH_SYSINFO_PAGEFILE, buf, size, &ret );
        if (status != (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) break;
        size = max( ret, size ) + 0x1000;
    }
    if (status < 0 || !ret)   /* no paging file: success and no entry, as on Windows */
    {
        free( buf );
        return status >= 0;
    }

    for (pf = (const struct pdh_pagefile *)buf; ; pf = (const struct pdh_pagefile *)((const BYTE *)pf + pf->NextEntryOffset))
    {
        if ((const BYTE *)(pf + 1) > buf + ret) break;
        n++;
        if (!pf->NextEntryOffset) break;
    }
    if (n && (snap_page.page = calloc( n, sizeof(*snap_page.page) )))
    {
        for (pf = (const struct pdh_pagefile *)buf; snap_page.count < n; pf = (const struct pdh_pagefile *)((const BYTE *)pf + pf->NextEntryOffset))
        {
            struct page_info *pi = &snap_page.page[snap_page.count++];
            DWORD len = min( pf->FileName.Length / sizeof(WCHAR), ARRAY_SIZE(pi->name) - 1 );

            if (pf->FileName.Buffer) memcpy( pi->name, pf->FileName.Buffer, len * sizeof(WCHAR) );
            pi->name[len] = 0;
            pi->total = pf->TotalSize;
            pi->inuse = pf->TotalInUse;
            pi->peak = pf->PeakUsage;
            if (!pf->NextEntryOffset) break;
        }
    }
    free( buf );
    return TRUE;
}

/* % Usage and % Usage Peak are raw fractions of the size of the paging file; _Total adds them up. */
static void fetch_page( DWORD id, const WCHAR *inst, LONGLONG *first, LONGLONG *second, LONG *status )
{
    DWORD i;
    BOOL total = !wcsicmp( inst, L"_Total" ), found = FALSE;

    *first = *second = 0;
    if (!ensure_page( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    for (i = 0; i < snap_page.count; i++)
    {
        const struct page_info *pi = &snap_page.page[i];

        if (!total && wcsicmp( pi->name, inst )) continue;
        found = TRUE;
        *first += (id == CID_PAGINGFILE_USAGE) ? pi->inuse : pi->peak;
        *second += pi->total;
    }
    if (!found && !total) *status = PDH_CSTATUS_NO_INSTANCE;
    else if (!found) *second = 0;
}

/* ---- name tables ---- */

static const struct perf_object_def *sorted_objects[ARRAY_SIZE(objects)];
static BOOL sorted_init;

static int __cdecl cmp_object( const void *a, const void *b )
{
    return wcsicmp( (*(const struct perf_object_def * const *)a)->name, (*(const struct perf_object_def * const *)b)->name );
}

DWORD perf_object_count(void)
{
    return ARRAY_SIZE(objects);
}

const struct perf_object_def *perf_object( DWORD i )
{
    if (!sorted_init)
    {
        DWORD k;
        for (k = 0; k < ARRAY_SIZE(objects); k++) sorted_objects[k] = &objects[k];
        qsort( sorted_objects, ARRAY_SIZE(objects), sizeof(sorted_objects[0]), cmp_object );
        sorted_init = TRUE;
    }
    return i < ARRAY_SIZE(objects) ? sorted_objects[i] : NULL;
}

const struct perf_object_def *perf_find_object( const WCHAR *name )
{
    DWORD i;
    for (i = 0; i < ARRAY_SIZE(objects); i++)
        if (!wcsicmp( objects[i].name, name )) return &objects[i];
    return NULL;
}

const struct perf_counter_def *perf_find_counter( const struct perf_object_def *obj, const WCHAR *name )
{
    DWORD i;
    for (i = 0; i < obj->count; i++)
        if (!wcsicmp( obj->counters[i].name, name )) return &obj->counters[i];
    return NULL;
}

/* The name table: the Perflib\009 Counter value (index, name pairs), else the built-in schema */

static WCHAR *names_data;
static WCHAR **names_str;   /* parallel arrays: index and name of each entry */
static DWORD *names_idx;
static DWORD names_count;
static BOOL names_loaded;

static void add_name( DWORD index, const WCHAR *name )
{
    DWORD *ni;
    WCHAR **ns;

    if (!(ni = realloc( names_idx, (names_count + 1) * sizeof(*ni) ))) return;
    names_idx = ni;
    if (!(ns = realloc( names_str, (names_count + 1) * sizeof(*ns) ))) return;
    names_str = ns;
    names_idx[names_count] = index;
    names_str[names_count] = (WCHAR *)name;
    names_count++;
}

static void load_names(void)
{
    HKEY key;
    DWORD type, size = 0, i;
    WCHAR *p;

    if (names_loaded) return;
    names_loaded = TRUE;

    if (!RegOpenKeyExW( HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009", 0,
                        KEY_QUERY_VALUE, &key ))
    {
        if (!RegQueryValueExW( key, L"Counter", NULL, &type, NULL, &size ) && type == REG_MULTI_SZ && size >= sizeof(WCHAR) &&
            (names_data = malloc( size + 2 * sizeof(WCHAR) )))
        {
            if (!RegQueryValueExW( key, L"Counter", NULL, &type, (BYTE *)names_data, &size ))
            {
                names_data[size / sizeof(WCHAR)] = 0;
                names_data[size / sizeof(WCHAR) + 1] = 0;
                for (p = names_data; *p;)
                {
                    WCHAR *idx = p, *name = p + lstrlenW( p ) + 1;
                    if (!*name) break;
                    add_name( wcstoul( idx, NULL, 10 ), name );
                    p = name + lstrlenW( name ) + 1;
                }
            }
            else
            {
                free( names_data );
                names_data = NULL;
            }
        }
        RegCloseKey( key );
    }
    if (names_count) return;

    /* no registry data: serve the names of the built-in schema */
    for (i = 0; i < ARRAY_SIZE(objects); i++)
    {
        DWORD k;
        add_name( objects[i].index, objects[i].name );
        for (k = 0; k < objects[i].count; k++) add_name( objects[i].counters[k].index, objects[i].counters[k].name );
    }
}

/* an installed name table can be older than this library: the objects and counters it serves are always found */
static BOOL builtin_name_by_index( DWORD index, const WCHAR **name )
{
    DWORD i, k;

    for (i = 0; i < ARRAY_SIZE(objects); i++)
    {
        if (objects[i].index == index) { *name = objects[i].name; return TRUE; }
        for (k = 0; k < objects[i].count; k++)
            if (objects[i].counters[k].index == index) { *name = objects[i].counters[k].name; return TRUE; }
    }
    return FALSE;
}

static BOOL builtin_index_by_name( const WCHAR *name, DWORD *index )
{
    DWORD i, k;

    for (i = 0; i < ARRAY_SIZE(objects); i++)
    {
        if (!wcsicmp( objects[i].name, name )) { *index = objects[i].index; return TRUE; }
        for (k = 0; k < objects[i].count; k++)
            if (!wcsicmp( objects[i].counters[k].name, name )) { *index = objects[i].counters[k].index; return TRUE; }
    }
    return FALSE;
}

BOOL perf_name_by_index( DWORD index, const WCHAR **name )
{
    DWORD i;
    BOOL found = FALSE;

    EnterCriticalSection( &perf_cs );
    load_names();
    for (i = 0; i < names_count; i++)
    {
        if (names_idx[i] == index)
        {
            *name = names_str[i];
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection( &perf_cs );
    return found || builtin_name_by_index( index, name );
}

BOOL perf_index_by_name( const WCHAR *name, DWORD *index )
{
    DWORD i;
    BOOL found = FALSE;

    EnterCriticalSection( &perf_cs );
    load_names();
    for (i = 0; i < names_count; i++)
    {
        if (!wcsicmp( names_str[i], name ))
        {
            *index = names_idx[i];
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection( &perf_cs );
    return found || builtin_index_by_name( name, index );
}

/* ---- instances ---- */

LONG perf_get_instances( const struct perf_object_def *obj, WCHAR ***names, DWORD *count )
{
    WCHAR **list = NULL;
    DWORD i, n = 0;
    LONG ret = ERROR_SUCCESS;

    *names = NULL;
    *count = 0;
    if (obj->kind == INST_NONE) return ERROR_SUCCESS;

    EnterCriticalSection( &perf_cs );
    switch (obj->kind)
    {
    case INST_CPU:
        n = cpu_count() + 1;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i + 1 < n; i++)
        {
            WCHAR buf[16];
            _snwprintf( buf, ARRAY_SIZE(buf), L"%u", i );
            list[i] = wcsdup( buf );
        }
        list[n - 1] = wcsdup( L"_Total" );
        break;

    case INST_DISK:
        ensure_disk( TRUE );
        n = snap_disk.count + 1;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i + 1 < n; i++) list[i] = wcsdup( snap_disk.disk[i].name );
        list[n - 1] = wcsdup( L"_Total" );
        break;

    case INST_NET:
        ensure_net( TRUE );
        n = snap_net.count;
        if (!n) break;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i < n; i++) list[i] = wcsdup( snap_net.net[i].name );
        break;

    case INST_PROC:
        if (!ensure_proc( TRUE )) { ret = PDH_CSTATUS_NO_INSTANCE; break; }
        n = snap_proc.count + 1;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i + 1 < n; i++) list[i] = wcsdup( snap_proc.name[i] );
        list[n - 1] = wcsdup( L"_Total" );
        break;

    case INST_PAGE:
        ensure_page( TRUE );
        n = snap_page.count + 1;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i + 1 < n; i++) list[i] = wcsdup( snap_page.page[i].name );
        list[n - 1] = wcsdup( L"_Total" );
        break;

    case INST_CPUINFO:
        n = cpu_count() + 2;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i + 2 < n; i++)
        {
            WCHAR buf[24];
            _snwprintf( buf, ARRAY_SIZE(buf), L"0,%u", i );
            list[i] = wcsdup( buf );
        }
        list[n - 2] = wcsdup( L"0,_Total" );
        list[n - 1] = wcsdup( L"_Total" );
        break;

    case INST_LDISK:
        ensure_ldisk( TRUE );
        n = snap_ldisk.count + 1;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i + 1 < n; i++) list[i] = wcsdup( snap_ldisk.disk[i].name );
        list[n - 1] = wcsdup( L"_Total" );
        break;

    case INST_THREAD:
        if (!ensure_thread( TRUE )) { ret = PDH_CSTATUS_NO_INSTANCE; break; }
        n = snap_thread.count;
        if (!n) break;
        if (!(list = calloc( n, sizeof(*list) ))) { ret = PDH_MEMORY_ALLOCATION_FAILURE; break; }
        for (i = 0; i < n; i++) list[i] = wcsdup( snap_thread.thr[i].name );
        break;

    default:
        break;
    }
    LeaveCriticalSection( &perf_cs );

    if (ret) { free( list ); return ret; }
    *names = list;
    *count = n;
    return ERROR_SUCCESS;
}

void perf_free_instances( WCHAR **names, DWORD count )
{
    DWORD i;
    for (i = 0; i < count; i++) free( names[i] );
    free( names );
}

/* ---- counter values ---- */

#define TIME_NOW(v) ((v)->second = perf_now())

static void fetch_memory( DWORD id, LONGLONG *first, LONGLONG *second, BOOL *ok )
{
    static DWORD page_size;
    const struct pdh_spi *s;
    LONGLONG pages;

    if (!page_size)
    {
        SYSTEM_INFO si;
        GetSystemInfo( &si );
        page_size = si.dwPageSize;
    }
    if (!(*ok = ensure_spi( FALSE ))) return;
    s = &snap_spi.spi;
    *second = 0;

    switch (id)
    {
    case CID_MEMORY_PAGE_FAULTS_SEC:        *first = s->PageFaultCount; break;
    case CID_MEMORY_TRANSITION_FAULTS_SEC:  *first = s->TransitionCount; break;
    case CID_MEMORY_CACHE_FAULTS_SEC:       *first = s->CacheTransitionCount; break;
    case CID_MEMORY_DEMAND_ZERO_FAULTS_SEC: *first = s->DemandZeroCount; break;
    case CID_MEMORY_PAGES_SEC:              *first = (LONGLONG)s->PageReadCount + s->DirtyPagesWriteCount + s->MappedPagesWriteCount; break;
    case CID_MEMORY_PAGES_INPUT_SEC:        *first = s->PageReadCount; break;
    case CID_MEMORY_PAGE_READS_SEC:         *first = s->PageReadIoCount; break;
    case CID_MEMORY_PAGES_OUTPUT_SEC:       *first = (LONGLONG)s->DirtyPagesWriteCount + s->MappedPagesWriteCount; break;
    case CID_MEMORY_PAGE_WRITES_SEC:        *first = (LONGLONG)s->DirtyWriteIoCount + s->MappedWriteIoCount; break;
    case CID_MEMORY_AVAILABLE_BYTES:        *first = (LONGLONG)s->AvailablePages * page_size; return;
    case CID_MEMORY_AVAILABLE_KBYTES:       *first = (LONGLONG)s->AvailablePages * page_size / 1024; return;
    case CID_MEMORY_AVAILABLE_MBYTES:       *first = (LONGLONG)s->AvailablePages * page_size / (1024 * 1024); return;
    case CID_MEMORY_COMMITTED_BYTES:        *first = (LONGLONG)s->CommittedPages * page_size; return;
    case CID_MEMORY_COMMIT_LIMIT:           *first = (LONGLONG)s->CommitLimit * page_size; return;
    case CID_MEMORY_POOL_PAGED_BYTES:       *first = (LONGLONG)s->PagedPoolPages * page_size; return;
    case CID_MEMORY_POOL_NONPAGED_BYTES:    *first = (LONGLONG)s->NonPagedPoolPages * page_size; return;
    case CID_MEMORY_COMMITTED_BYTES_IN_USE:
        pages = s->CommittedPages;
        *first = pages;
        *second = s->CommitLimit;
        return;
    default:
        *ok = FALSE;
        return;
    }
    *second = perf_now();
}

/* the time the system started, in FILETIME units; now is the current FILETIME */
static LONGLONG perf_boot_time( LONGLONG now )
{
    struct
    {
        LARGE_INTEGER BootTime;
        LARGE_INTEGER CurrentTime;
        LARGE_INTEGER TimeZoneBias;
        ULONG TimeZoneId;
        ULONG Reserved;
        ULONGLONG BootTimeBias;
        ULONGLONG SleepTimeBias;
    } tod;
    ULONG len;

    memset( &tod, 0, sizeof(tod) );
    if (query_sysinfo( PDH_SYSINFO_TIMEOFDAY, &tod, sizeof(tod), &len ) >= 0 && tod.BootTime.QuadPart > 0 &&
        tod.BootTime.QuadPart <= now)
        return tod.BootTime.QuadPart;
    return now - (LONGLONG)GetTickCount() * 10000;
}

static void fetch_system( DWORD id, LONGLONG *first, LONGLONG *second, BOOL *ok )
{
    const struct pdh_spi *s;

    *second = 0;
    switch (id)
    {
    case CID_SYSTEM_SYSTEM_UP_TIME:
        *second = perf_now();
        *first = perf_boot_time( *second );
        *ok = TRUE;
        return;
    case CID_SYSTEM_PROCESSES:
        if (!(*ok = ensure_proc( FALSE ))) return;
        *first = snap_proc.count;
        return;
    case CID_SYSTEM_THREADS:
        if (!(*ok = ensure_proc( FALSE ))) return;
        *first = snap_proc.threads;
        return;
    case CID_SYSTEM_PROCESSOR_QUEUE_LENGTH:
        if (!(*ok = ensure_proc( FALSE ))) return;
        *first = snap_proc.ready;
        return;
    }

    if (!(*ok = ensure_spi( FALSE ))) return;
    s = &snap_spi.spi;
    switch (id)
    {
    case CID_SYSTEM_FILE_READ_OPERATIONS_SEC:    *first = s->IoReadOperationCount; break;
    case CID_SYSTEM_FILE_WRITE_OPERATIONS_SEC:   *first = s->IoWriteOperationCount; break;
    case CID_SYSTEM_FILE_CONTROL_OPERATIONS_SEC: *first = s->IoOtherOperationCount; break;
    case CID_SYSTEM_FILE_DATA_OPERATIONS_SEC:    *first = (LONGLONG)s->IoReadOperationCount + s->IoWriteOperationCount; break;
    case CID_SYSTEM_FILE_READ_BYTES_SEC:         *first = s->IoReadTransferCount.QuadPart; break;
    case CID_SYSTEM_FILE_WRITE_BYTES_SEC:        *first = s->IoWriteTransferCount.QuadPart; break;
    case CID_SYSTEM_FILE_CONTROL_BYTES_SEC:      *first = s->IoOtherTransferCount.QuadPart; break;
    case CID_SYSTEM_CONTEXT_SWITCHES_SEC:        *first = s->ContextSwitches; break;
    case CID_SYSTEM_SYSTEM_CALLS_SEC:            *first = s->SystemCalls; break;
    default: *ok = FALSE; return;
    }
    *second = perf_now();
}

static LONGLONG cpu_value( DWORD id, const struct pdh_cpu *c, DWORD index )
{
    LONGLONG priv;

    if (id == CID_PROCESSOR_DPCS_QUEUED_SEC) return index < snap_int.count ? snap_int.cpu[index].DpcCount : 0;
    if (id == CID_PROCESSOR_DPC_RATE) return index < snap_int.count ? snap_int.cpu[index].DpcRate : 0;

    switch (id)
    {
    case CID_PROCESSOR_PROCESSOR_TIME:
    case CID_PROCESSOR_IDLE_TIME:         return c->IdleTime.QuadPart;
    case CID_PROCESSOR_USER_TIME:         return c->UserTime.QuadPart;
    case CID_PROCESSOR_PRIVILEGED_TIME:
        priv = c->KernelTime.QuadPart - c->IdleTime.QuadPart;
        return priv > 0 ? priv : 0;
    case CID_PROCESSOR_DPC_TIME:          return c->DpcTime.QuadPart;
    case CID_PROCESSOR_INTERRUPT_TIME:    return c->InterruptTime.QuadPart;
    case CID_PROCESSOR_INTERRUPTS_SEC:    return c->InterruptCount;
    }
    return 0;
}

/* the counters that are counts, not times: the total adds them up instead of averaging */
static BOOL cpu_is_count( DWORD id )
{
    return id == CID_PROCESSOR_INTERRUPTS_SEC || id == CID_PROCESSOR_DPCS_QUEUED_SEC || id == CID_PROCESSOR_DPC_RATE;
}

/* % Processor Utility: busy time (kernel without idle, plus user) times 100 over the time of the processor, both
 * cumulative; the ratio of the differences is the percentage. */
static void cpu_utility( const struct pdh_cpu *c, LONGLONG *busy, LONGLONG *total )
{
    LONGLONG all = c->KernelTime.QuadPart + c->UserTime.QuadPart;
    LONGLONG b = all - c->IdleTime.QuadPart;

    *busy = (b > 0 ? b : 0) * 100;
    *total = all;
}

/* inst is "n" (Processor) or "group,n" (Processor Information); "_Total" and "group,_Total" are the sum */
static void fetch_cpu( DWORD id, const WCHAR *inst, BOOL info, LONGLONG *first, LONGLONG *second, LONG *status )
{
    DWORD i;
    BOOL utility = id == CID_PROCINFO_PROCESSOR_UTILITY;
    const WCHAR *name = inst;

    if (!ensure_cpu( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    ensure_int( FALSE );
    if (info && !wcsicmp( inst, L"_Total" )) name = inst;
    else if (info)
    {
        const WCHAR *comma = wcschr( inst, ',' );
        if (!comma || wcsncmp( inst, L"0", comma - inst ) || comma - inst != 1) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
        name = comma + 1;
    }
    if (!wcsicmp( name, L"_Total" ))
    {
        LONGLONG sum = 0, b = 0, t = 0;
        for (i = 0; i < snap_cpu.count; i++)
        {
            LONGLONG b1, t1;
            if (utility) { cpu_utility( &snap_cpu.cpu[i], &b1, &t1 ); b += b1; t += t1; }
            else sum += cpu_value( id, &snap_cpu.cpu[i], i );
        }
        if (utility) { *first = b; *second = t; return; }
        /* the time counters of the total are the average over the processors */
        *first = cpu_is_count( id ) ? sum : sum / (LONGLONG)snap_cpu.count;
    }
    else
    {
        WCHAR *end;
        i = wcstoul( name, &end, 10 );
        if (!*name || *end || i >= snap_cpu.count) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
        if (utility) { cpu_utility( &snap_cpu.cpu[i], first, second ); return; }
        *first = cpu_value( id, &snap_cpu.cpu[i], i );
    }
    *second = id == CID_PROCESSOR_DPC_RATE || id == CID_PROCINFO_DPC_RATE ? 0 : perf_now();
}

/* the Processor counter that a Processor Information counter reads */
static DWORD info_to_cpu_id( DWORD id )
{
    switch (id)
    {
    case CID_PROCINFO_PROCESSOR_TIME:    return CID_PROCESSOR_PROCESSOR_TIME;
    case CID_PROCINFO_USER_TIME:         return CID_PROCESSOR_USER_TIME;
    case CID_PROCINFO_PRIVILEGED_TIME:   return CID_PROCESSOR_PRIVILEGED_TIME;
    case CID_PROCINFO_INTERRUPTS_SEC:    return CID_PROCESSOR_INTERRUPTS_SEC;
    case CID_PROCINFO_DPC_TIME:          return CID_PROCESSOR_DPC_TIME;
    case CID_PROCINFO_INTERRUPT_TIME:    return CID_PROCESSOR_INTERRUPT_TIME;
    case CID_PROCINFO_DPCS_QUEUED_SEC:   return CID_PROCESSOR_DPCS_QUEUED_SEC;
    case CID_PROCINFO_DPC_RATE:          return CID_PROCESSOR_DPC_RATE;
    case CID_PROCINFO_IDLE_TIME:         return CID_PROCESSOR_IDLE_TIME;
    }
    return id;
}

/* The value of a disk counter in first and second, from the record of the disk performance IOCTL. The ids are
 * those of PhysicalDisk; the LogicalDisk counters are mapped to them. */
static void disk_pair( DWORD id, const struct pdh_disk_perf *p, LONGLONG *first, LONGLONG *second )
{
    LONGLONG ops = (LONGLONG)p->ReadCount + p->WriteCount;

    *second = perf_now();
    switch (id)
    {
    case CID_PHYSICALDISK_CURRENT_DISK_QUEUE_LENGTH: *first = p->QueueDepth; *second = 0; break;
    case CID_PHYSICALDISK_DISK_TIME:                 *first = p->ReadTime.QuadPart + p->WriteTime.QuadPart; break;
    case CID_PHYSICALDISK_DISK_READ_TIME:            *first = p->ReadTime.QuadPart; break;
    case CID_PHYSICALDISK_DISK_WRITE_TIME:           *first = p->WriteTime.QuadPart; break;
    case CID_PHYSICALDISK_IDLE_TIME:                 *first = p->IdleTime.QuadPart; break;
    case CID_PHYSICALDISK_DISK_TRANSFERS_SEC:        *first = ops; break;
    case CID_PHYSICALDISK_DISK_READS_SEC:            *first = p->ReadCount; break;
    case CID_PHYSICALDISK_DISK_WRITES_SEC:           *first = p->WriteCount; break;
    case CID_PHYSICALDISK_DISK_BYTES_SEC:            *first = p->BytesRead.QuadPart + p->BytesWritten.QuadPart; break;
    case CID_PHYSICALDISK_DISK_READ_BYTES_SEC:       *first = p->BytesRead.QuadPart; break;
    case CID_PHYSICALDISK_DISK_WRITE_BYTES_SEC:      *first = p->BytesWritten.QuadPart; break;
    /* queue lengths: the summed request latency over the time that passed (the sample time is the time base) */
    case CID_PHYSICALDISK_AVG_DISK_QUEUE_LENGTH:       *first = p->ReadTime.QuadPart + p->WriteTime.QuadPart; break;
    case CID_PHYSICALDISK_AVG_DISK_READ_QUEUE_LENGTH:  *first = p->ReadTime.QuadPart; break;
    case CID_PHYSICALDISK_AVG_DISK_WRITE_QUEUE_LENGTH: *first = p->WriteTime.QuadPart; break;
    /* averages: the sum over the number of operations */
    case CID_PHYSICALDISK_AVG_DISK_SEC_TRANSFER:       *first = p->ReadTime.QuadPart + p->WriteTime.QuadPart; *second = ops; break;
    case CID_PHYSICALDISK_AVG_DISK_SEC_READ:           *first = p->ReadTime.QuadPart; *second = p->ReadCount; break;
    case CID_PHYSICALDISK_AVG_DISK_SEC_WRITE:          *first = p->WriteTime.QuadPart; *second = p->WriteCount; break;
    case CID_PHYSICALDISK_AVG_DISK_BYTES_TRANSFER:     *first = p->BytesRead.QuadPart + p->BytesWritten.QuadPart; *second = ops; break;
    case CID_PHYSICALDISK_AVG_DISK_BYTES_READ:         *first = p->BytesRead.QuadPart; *second = p->ReadCount; break;
    case CID_PHYSICALDISK_AVG_DISK_BYTES_WRITE:        *first = p->BytesWritten.QuadPart; *second = p->WriteCount; break;
    case CID_PHYSICALDISK_SPLIT_IO_SEC:                *first = p->SplitCount; break;
    default: *first = 0; *second = 0; break;
    }
}

static void disk_add( DWORD id, const struct pdh_disk_perf *p, BOOL have_perf, LONGLONG *first, LONGLONG *second, BOOL *any )
{
    LONGLONG f = 0, s = 0;

    if (have_perf) disk_pair( id, p, &f, &s );
    else s = id == CID_PHYSICALDISK_CURRENT_DISK_QUEUE_LENGTH ? 0 : perf_now();
    *first += f;
    if (!*any) *second = s;
    else if (id >= CID_PHYSICALDISK_AVG_DISK_SEC_TRANSFER && id <= CID_PHYSICALDISK_AVG_DISK_BYTES_WRITE) *second += s;
    *any = TRUE;
}

static void fetch_disk( DWORD id, const WCHAR *inst, LONGLONG *first, LONGLONG *second, LONG *status )
{
    DWORD i;
    BOOL any = FALSE;

    *first = *second = 0;
    if (!ensure_disk( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    if (!wcsicmp( inst, L"_Total" ))
    {
        for (i = 0; i < snap_disk.count; i++) disk_add( id, &snap_disk.disk[i].perf, snap_disk.disk[i].have_perf, first, second, &any );
    }
    else
    {
        for (i = 0; i < snap_disk.count; i++) if (!wcsicmp( snap_disk.disk[i].name, inst )) break;
        if (i == snap_disk.count) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
        disk_add( id, &snap_disk.disk[i].perf, snap_disk.disk[i].have_perf, first, second, &any );
    }
    if (!any) *second = id == CID_PHYSICALDISK_CURRENT_DISK_QUEUE_LENGTH ? 0 : perf_now();
}

/* the PhysicalDisk counter that a LogicalDisk counter reads from the same record */
static DWORD ldisk_to_disk_id( DWORD id )
{
    switch (id)
    {
    case CID_LOGICALDISK_CURRENT_DISK_QUEUE_LENGTH:    return CID_PHYSICALDISK_CURRENT_DISK_QUEUE_LENGTH;
    case CID_LOGICALDISK_DISK_TIME:                    return CID_PHYSICALDISK_DISK_TIME;
    case CID_LOGICALDISK_AVG_DISK_QUEUE_LENGTH:        return CID_PHYSICALDISK_AVG_DISK_QUEUE_LENGTH;
    case CID_LOGICALDISK_DISK_READ_TIME:               return CID_PHYSICALDISK_DISK_READ_TIME;
    case CID_LOGICALDISK_AVG_DISK_READ_QUEUE_LENGTH:   return CID_PHYSICALDISK_AVG_DISK_READ_QUEUE_LENGTH;
    case CID_LOGICALDISK_DISK_WRITE_TIME:              return CID_PHYSICALDISK_DISK_WRITE_TIME;
    case CID_LOGICALDISK_AVG_DISK_WRITE_QUEUE_LENGTH:  return CID_PHYSICALDISK_AVG_DISK_WRITE_QUEUE_LENGTH;
    case CID_LOGICALDISK_AVG_DISK_SEC_TRANSFER:        return CID_PHYSICALDISK_AVG_DISK_SEC_TRANSFER;
    case CID_LOGICALDISK_AVG_DISK_SEC_READ:            return CID_PHYSICALDISK_AVG_DISK_SEC_READ;
    case CID_LOGICALDISK_AVG_DISK_SEC_WRITE:           return CID_PHYSICALDISK_AVG_DISK_SEC_WRITE;
    case CID_LOGICALDISK_DISK_TRANSFERS_SEC:           return CID_PHYSICALDISK_DISK_TRANSFERS_SEC;
    case CID_LOGICALDISK_DISK_READS_SEC:               return CID_PHYSICALDISK_DISK_READS_SEC;
    case CID_LOGICALDISK_DISK_WRITES_SEC:              return CID_PHYSICALDISK_DISK_WRITES_SEC;
    case CID_LOGICALDISK_DISK_BYTES_SEC:               return CID_PHYSICALDISK_DISK_BYTES_SEC;
    case CID_LOGICALDISK_DISK_READ_BYTES_SEC:          return CID_PHYSICALDISK_DISK_READ_BYTES_SEC;
    case CID_LOGICALDISK_DISK_WRITE_BYTES_SEC:         return CID_PHYSICALDISK_DISK_WRITE_BYTES_SEC;
    case CID_LOGICALDISK_AVG_DISK_BYTES_TRANSFER:      return CID_PHYSICALDISK_AVG_DISK_BYTES_TRANSFER;
    case CID_LOGICALDISK_AVG_DISK_BYTES_READ:          return CID_PHYSICALDISK_AVG_DISK_BYTES_READ;
    case CID_LOGICALDISK_AVG_DISK_BYTES_WRITE:         return CID_PHYSICALDISK_AVG_DISK_BYTES_WRITE;
    case CID_LOGICALDISK_IDLE_TIME:                    return CID_PHYSICALDISK_IDLE_TIME;
    case CID_LOGICALDISK_SPLIT_IO_SEC:                 return CID_PHYSICALDISK_SPLIT_IO_SEC;
    }
    return ~0u;
}

static void fetch_ldisk( DWORD id, const WCHAR *inst, LONGLONG *first, LONGLONG *second, LONG *status )
{
    DWORD i, did = ldisk_to_disk_id( id );
    BOOL any = FALSE, total = !wcsicmp( inst, L"_Total" );

    *first = *second = 0;
    if (!ensure_ldisk( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    for (i = 0; i < snap_ldisk.count; i++)
    {
        const struct ldisk_info *d = &snap_ldisk.disk[i];

        if (!total && wcsicmp( d->name, inst )) continue;
        if (did == ~0u)   /* % Free Space: free megabytes over the total; Free Megabytes */
        {
            *first += d->free_mb;
            if (id == CID_LOGICALDISK_FREE_SPACE) *second += d->total_mb;
        }
        else disk_add( did, &d->perf, d->have_perf, first, second, &any );
        any = TRUE;
        if (!total) break;
    }
    if (!any && !total) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
    if (did == ~0u) { if (id == CID_LOGICALDISK_FREE_MEGABYTES) *second = 0; }
    else if (!any) *second = did == CID_PHYSICALDISK_CURRENT_DISK_QUEUE_LENGTH ? 0 : perf_now();
}

static void fetch_thread( DWORD id, const WCHAR *inst, LONGLONG *first, LONGLONG *second, LONG *status )
{
    DWORD i;
    const SYSTEM_THREAD_INFORMATION *t;

    *first = *second = 0;
    if (!ensure_thread( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    for (i = 0; i < snap_thread.count; i++) if (!wcsicmp( snap_thread.thr[i].name, inst )) break;
    if (i == snap_thread.count) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
    t = snap_thread.thr[i].thread;

    *second = perf_now();
    switch (id)
    {
    case CID_THREAD_CONTEXT_SWITCHES_SEC: *first = t->ContextSwitches; break;
    case CID_THREAD_PROCESSOR_TIME:       *first = t->UserTime.QuadPart + t->KernelTime.QuadPart; break;
    case CID_THREAD_USER_TIME:            *first = t->UserTime.QuadPart; break;
    case CID_THREAD_PRIVILEGED_TIME:      *first = t->KernelTime.QuadPart; break;
    case CID_THREAD_ELAPSED_TIME:         *first = t->CreateTime.QuadPart; break;
    case CID_THREAD_PRIORITY_CURRENT:     *first = t->Priority; *second = 0; break;
    case CID_THREAD_PRIORITY_BASE:        *first = t->BasePriority; *second = 0; break;
    case CID_THREAD_THREAD_STATE:         *first = t->ThreadState; *second = 0; break;
    case CID_THREAD_THREAD_WAIT_REASON:   *first = t->WaitReason; *second = 0; break;
    case CID_THREAD_ID_PROCESS:           *first = (LONGLONG)(ULONG_PTR)t->ClientId.UniqueProcess; *second = 0; break;
    case CID_THREAD_ID_THREAD:            *first = (LONGLONG)(ULONG_PTR)t->ClientId.UniqueThread; *second = 0; break;
    default: *status = PDH_CSTATUS_INVALID_DATA; break;
    }
}

static void fetch_net( DWORD id, const WCHAR *inst, LONGLONG *first, LONGLONG *second, LONG *status )
{
    const MIB_IFROW *r;
    DWORD i;

    if (!ensure_net( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    for (i = 0; i < snap_net.count; i++) if (!wcsicmp( snap_net.net[i].name, inst )) break;
    if (i == snap_net.count) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
    r = &snap_net.net[i].row;

    *second = 0;
    switch (id)
    {
    case CID_NETWORK_INTERFACE_BYTES_TOTAL_SEC:       *first = (LONGLONG)r->dwInOctets + r->dwOutOctets; break;
    case CID_NETWORK_INTERFACE_BYTES_RECEIVED_SEC:    *first = r->dwInOctets; break;
    case CID_NETWORK_INTERFACE_BYTES_SENT_SEC:        *first = r->dwOutOctets; break;
    case CID_NETWORK_INTERFACE_PACKETS_SEC:           *first = (LONGLONG)r->dwInUcastPkts + r->dwInNUcastPkts + r->dwOutUcastPkts + r->dwOutNUcastPkts; break;
    case CID_NETWORK_INTERFACE_PACKETS_RECEIVED_SEC:  *first = (LONGLONG)r->dwInUcastPkts + r->dwInNUcastPkts; break;
    case CID_NETWORK_INTERFACE_PACKETS_SENT_SEC:      *first = (LONGLONG)r->dwOutUcastPkts + r->dwOutNUcastPkts; break;
    case CID_NETWORK_INTERFACE_CURRENT_BANDWIDTH:     *first = r->dwSpeed; return;
    case CID_NETWORK_INTERFACE_PACKETS_RECEIVED_ERRORS: *first = r->dwInErrors; return;
    case CID_NETWORK_INTERFACE_PACKETS_OUTBOUND_ERRORS: *first = r->dwOutErrors; return;
    default: *status = PDH_CSTATUS_INVALID_DATA; return;
    }
    *second = perf_now();
}

static LONGLONG proc_value( DWORD id, const struct pdh_process *p )
{
    switch (id)
    {
    case CID_PROCESS_PROCESSOR_TIME:     return p->UserTime.QuadPart + p->KernelTime.QuadPart;
    case CID_PROCESS_USER_TIME:          return p->UserTime.QuadPart;
    case CID_PROCESS_PRIVILEGED_TIME:    return p->KernelTime.QuadPart;
    case CID_PROCESS_VIRTUAL_BYTES:      return p->vm.VirtualSize;
    case CID_PROCESS_PAGE_FAULTS_SEC:    return p->vm.PageFaultCount;
    case CID_PROCESS_WORKING_SET:        return p->vm.WorkingSetSize;
    case CID_PROCESS_PRIVATE_BYTES:      return p->vm.PrivateUsage;
    case CID_PROCESS_PAGE_FILE_BYTES:    return p->vm.PagefileUsage;
    case CID_PROCESS_THREAD_COUNT:       return p->NumberOfThreads;
    case CID_PROCESS_HANDLE_COUNT:       return p->HandleCount;
    case CID_PROCESS_ID_PROCESS:         return (LONGLONG)(ULONG_PTR)p->UniqueProcessId;
    case CID_PROCESS_CREATING_PROCESS_ID: return (LONGLONG)(ULONG_PTR)p->InheritedFromUniqueProcessId;
    case CID_PROCESS_ELAPSED_TIME:       return p->CreateTime.QuadPart;
    }
    return 0;
}

static void fetch_proc( DWORD id, const WCHAR *inst, LONGLONG *first, LONGLONG *second, LONG *status )
{
    DWORD i;

    if (!ensure_proc( FALSE )) { *status = PDH_CSTATUS_INVALID_DATA; return; }
    if (!wcsicmp( inst, L"_Total" ))
    {
        LONGLONG sum = 0;
        if (id != CID_PROCESS_ID_PROCESS && id != CID_PROCESS_CREATING_PROCESS_ID && id != CID_PROCESS_ELAPSED_TIME)
            for (i = 0; i < snap_proc.count; i++) sum += proc_value( id, snap_proc.proc[i] );
        *first = sum;
    }
    else
    {
        for (i = 0; i < snap_proc.count; i++) if (!wcsicmp( snap_proc.name[i], inst )) break;
        if (i == snap_proc.count) { *status = PDH_CSTATUS_NO_INSTANCE; return; }
        *first = proc_value( id, snap_proc.proc[i] );
    }
    switch (id)
    {
    case CID_PROCESS_VIRTUAL_BYTES: case CID_PROCESS_WORKING_SET: case CID_PROCESS_PRIVATE_BYTES:
    case CID_PROCESS_PAGE_FILE_BYTES: case CID_PROCESS_THREAD_COUNT: case CID_PROCESS_HANDLE_COUNT:
    case CID_PROCESS_ID_PROCESS: case CID_PROCESS_CREATING_PROCESS_ID:
        *second = 0;
        break;
    default:
        *second = perf_now();
    }
}

LONG perf_fetch( const struct perf_object_def *obj, const struct perf_counter_def *ctr, const WCHAR *inst,
                       DWORD instance_index, LONGLONG *first, LONGLONG *second )
{
    LONG status = ERROR_SUCCESS;
    WCHAR key[300];
    BOOL ok = TRUE;

    *first = *second = 0;
    if (obj->kind != INST_NONE)
    {
        /* a paging file is named \??\C:\pagefile.sys: its question marks are part of the name */
        if (!inst || wcschr( inst, '*' ) || (obj->kind != INST_PAGE && wcschr( inst, '?' ))) return PDH_CSTATUS_NO_INSTANCE;
        lstrcpynW( key, inst, ARRAY_SIZE(key) - 16 );
        if (instance_index && instance_index != ~0u)
        {
            WCHAR num[16];
            _snwprintf( num, ARRAY_SIZE(num), L"#%u", instance_index );
            lstrcatW( key, num );
        }
    }

    EnterCriticalSection( &perf_cs );
    switch (obj->kind)
    {
    case INST_NONE:
        if (obj == perf_find_object( L"Memory" )) fetch_memory( ctr->id, first, second, &ok );
        else fetch_system( ctr->id, first, second, &ok );
        if (!ok) status = PDH_CSTATUS_INVALID_DATA;
        break;
    case INST_CPU:  fetch_cpu( ctr->id, key, FALSE, first, second, &status ); break;
    case INST_CPUINFO: fetch_cpu( info_to_cpu_id( ctr->id ), key, TRUE, first, second, &status ); break;
    case INST_LDISK: fetch_ldisk( ctr->id, key, first, second, &status ); break;
    case INST_THREAD: fetch_thread( ctr->id, key, first, second, &status ); break;
    case INST_DISK: fetch_disk( ctr->id, key, first, second, &status ); break;
    case INST_NET:  fetch_net( ctr->id, key, first, second, &status ); break;
    case INST_PROC: fetch_proc( ctr->id, key, first, second, &status ); break;
    case INST_PAGE: fetch_page( ctr->id, key, first, second, &status ); break;
    }
    LeaveCriticalSection( &perf_cs );
    return status;
}

/* ---- built-in name and help tables (REG_MULTI_SZ layout: index, text, index, text ... ) ---- */

struct name_entry
{
    DWORD        index;
    const WCHAR *text;
    WCHAR       *owned;   /* text built here, freed after the table is made */
};

static void add_entry( struct name_entry *list, DWORD *count, DWORD index, const WCHAR *text, WCHAR *owned )
{
    DWORD i;

    for (i = 0; i < *count; i++)
    {
        if (list[i].index == index)
        {
            perf_free( owned );
            return;
        }
    }
    list[*count].index = index;
    list[*count].text = text;
    list[*count].owned = owned;
    (*count)++;
}

WCHAR *perf_builtin_names( BOOL help, DWORD *bytes )
{
    struct name_entry *list, tmp;
    DWORD i, k, n = 0, total = 0, max = 0;
    WCHAR *out, *p;

    *bytes = 0;
    for (i = 0; i < ARRAY_SIZE(objects); i++) max += 1 + objects[i].count;
    max += 2;   /* the end marker entries */
    if (!(list = perf_calloc( max, sizeof(*list) ))) return NULL;

    for (i = 0; i < ARRAY_SIZE(objects); i++)
    {
        const struct perf_object_def *obj = &objects[i];

        if (!help) add_entry( list, &n, obj->index, obj->name, NULL );
        else add_entry( list, &n, obj->index + 1, obj->help, NULL );
        for (k = 0; k < obj->count; k++)
        {
            const struct perf_counter_def *ctr = &obj->counters[k];

            /* a name index shared by several objects has the text of the first object that uses it */
            add_entry( list, &n, help ? ctr->index + 1 : ctr->index, help ? ctr->help : ctr->name, NULL );
        }
    }

    /* the tables are terminated by an "End Marker" entry (counter 1846, help 1847), and the counter
       table starts with the pair 1, <index of the end marker help> */
    if (!help)
    {
        add_entry( list, &n, 1, L"1847", NULL );
        add_entry( list, &n, 1846, L"End Marker", NULL );
    }
    else
        add_entry( list, &n, 1847, L"End Marker", NULL );

    for (i = 1; i < n; i++)  /* ascending by index, as Windows lists them */
    {
        tmp = list[i];
        for (k = i; k > 0 && list[k - 1].index > tmp.index; k--) list[k] = list[k - 1];
        list[k] = tmp;
    }

    for (i = 0; i < n; i++)
    {
        WCHAR num[16];
        _snwprintf( num, ARRAY_SIZE(num), L"%lu", list[i].index );
        num[ARRAY_SIZE(num) - 1] = 0;
        total += lstrlenW( num ) + 1 + lstrlenW( list[i].text ) + 1;
    }
    total += 2;   /* the empty string that ends the list, and one more for readers that expect two */

    if ((out = perf_alloc( total * sizeof(WCHAR) )))
    {
        for (p = out, i = 0; i < n; i++)
        {
            WCHAR num[16];
            _snwprintf( num, ARRAY_SIZE(num), L"%lu", list[i].index );
            num[ARRAY_SIZE(num) - 1] = 0;
            lstrcpyW( p, num );
            p += lstrlenW( p ) + 1;
            lstrcpyW( p, list[i].text );
            p += lstrlenW( p ) + 1;
        }
        *p++ = 0;
        *p = 0;
        *bytes = total * sizeof(WCHAR);
    }
    for (i = 0; i < n; i++) perf_free( list[i].owned );
    perf_free( list );
    return out;
}

void perf_free_buffer( void *ptr )
{
    perf_free( ptr );
}
