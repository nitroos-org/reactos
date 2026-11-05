/*
 * Built-in performance counter sets (shared by pdh.dll and advapi32.dll).
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

#ifndef __PERFDATA_H
#define __PERFDATA_H

enum inst_kind
{
    INST_NONE,   /* single instance object (Memory, System) */
    INST_CPU,    /* "0".."n-1", "_Total" */
    INST_DISK,   /* "<number> <letters>", "_Total" */
    INST_NET,    /* adapter description */
    INST_PROC,   /* image name, "name#n" for duplicates, "_Total" */
    INST_PAGE,   /* paging file name as the kernel has it (\??\C:\pagefile.sys), "_Total" */
    INST_LDISK,  /* "<letter>:" or "HarddiskVolume<n>" for a volume without a letter, "_Total" */
    INST_THREAD, /* "<process instance>/<thread number>" */
    INST_CPUINFO /* "<group>,<processor>", "<group>,_Total", "_Total" */
};

struct perf_counter_def
{
    DWORD        index;    /* name index in Perflib\009 */
    const WCHAR *name;
    DWORD        type;     /* PERF_* counter type */
    LONG         defscale;
    DWORD        detail;   /* PERF_DETAIL_* */
    DWORD        id;       /* provider-private id */
    const WCHAR *help;     /* explain text of the counter in this object */
};

struct perf_object_def
{
    DWORD                          index;
    const WCHAR                   *name;
    enum inst_kind                 kind;
    const struct perf_counter_def *counters;
    DWORD                          count;
    const WCHAR                   *default_counter;   /* name of the default counter */
    DWORD                          cversion;          /* CVersion that PdhGetCounterInfo reports, 0 for the usual one */
    const WCHAR                   *help;              /* explain text of the object */
};

#define PERF_TIME_BASE 10000000   /* all raw time bases are 100 ns units */

LONGLONG perf_now(void);
void perf_next_generation(void);

DWORD perf_object_count(void);
const struct perf_object_def *perf_object( DWORD i );   /* sorted by name */
const struct perf_object_def *perf_find_object( const WCHAR *name );
const struct perf_counter_def *perf_find_counter( const struct perf_object_def *obj, const WCHAR *name );

BOOL perf_name_by_index( DWORD index, const WCHAR **name );
BOOL perf_index_by_name( const WCHAR *name, DWORD *index );

LONG perf_get_instances( const struct perf_object_def *obj, WCHAR ***names, DWORD *count );
void perf_free_instances( WCHAR **names, DWORD count );

LONG perf_fetch( const struct perf_object_def *obj, const struct perf_counter_def *ctr, const WCHAR *inst,
                       DWORD instance_index, LONGLONG *first, LONGLONG *second );

/* the name (help = FALSE) or help (help = TRUE) table of the built-in schema as REG_MULTI_SZ data; *bytes is its size.
 * Release with perf_free_buffer. */
WCHAR *perf_builtin_names( BOOL help, DWORD *bytes );
void perf_free_buffer( void *ptr );

#endif
