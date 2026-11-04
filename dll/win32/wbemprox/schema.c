/*
 * PROJECT:     ReactOS WMI provider (wbemprox)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Namespaces, class hierarchy and property order of the Windows schema
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The provider keeps one table per class. This file adds what WMI clients expect
 * around those tables: the namespaces (root, root\cimv2, root\default,
 * root\Interop, root\Interop\ms_409, root\StandardCimv2) with their __NAMESPACE instances, the
 * superclass of every class (__SUPERCLASS, __DERIVATION, deep enumeration of a
 * base class), the abstract CIM base classes as tables without rows, the
 * property order Windows reports, and the read/write/key qualifiers.
 */

#define COBJMACROS

#include <stdarg.h>
#include <wchar.h>

#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "oleauto.h"
#include "wbemcli.h"

#include "wine/debug.h"
#include "wbemprox_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(wbemprox);

#define SCHEMA_NS_ROOT    (1 << WBEMPROX_NAMESPACE_ROOT)
#define SCHEMA_NS_CIMV2   ((1 << WBEMPROX_NAMESPACE_CIMV2) | (1 << WBEMPROX_NAMESPACE_DEFAULT))
#define SCHEMA_NS_INTEROP (1 << WBEMPROX_NAMESPACE_INTEROP)
#define SCHEMA_NS_SCV2    (1 << WBEMPROX_NAMESPACE_STANDARDCIMV2)
#define SCHEMA_NS_ALL     ((1 << WBEMPROX_NAMESPACE_LAST) - 1)

#ifndef WBEM_FLAG_SHALLOW
#define WBEM_FLAG_SHALLOW 1
#endif

/* depth limit for every walk up the superclass chain */
#define MAX_DERIVATION 32

struct schema_class
{
    const WCHAR *name;
    const WCHAR *superclass;
    UINT ns_mask;
    const struct column *columns;       /* abstract classes: the table columns */
    UINT num_cols;
    const WCHAR *const *order;          /* the properties in the order Windows reports them */
    UINT num_order;
    const WCHAR *const *writable;       /* properties without the read-only flag */
    UINT num_writable;
    BOOL abstract;                      /* no provider: a table without rows */
};

#include "schema_scv2.h"
#include "schema_data.h"

static const struct
{
    const WCHAR *path;      /* relative to root */
    const WCHAR *full;      /* as __NAMESPACE / __PATH report it */
    enum wbm_namespace parent;
    const WCHAR *name;      /* Name of the __NAMESPACE instance in the parent */
}
namespaces[WBEMPROX_NAMESPACE_LAST] =
{
    { L"", L"ROOT", WBEMPROX_NAMESPACE_LAST, NULL },
    { L"CIMV2", L"ROOT\\CIMV2", WBEMPROX_NAMESPACE_ROOT, L"CIMV2" },
    { L"DEFAULT", L"ROOT\\DEFAULT", WBEMPROX_NAMESPACE_ROOT, L"DEFAULT" },
    { L"Interop", L"ROOT\\Interop", WBEMPROX_NAMESPACE_ROOT, L"Interop" },
    { L"Interop\\ms_409", L"ROOT\\Interop\\ms_409", WBEMPROX_NAMESPACE_INTEROP, L"ms_409" },
    { L"StandardCimv2", L"ROOT\\StandardCimv2", WBEMPROX_NAMESPACE_ROOT, L"StandardCimv2" },
};

BOOL parse_namespace( const WCHAR *path, enum wbm_namespace *ns )
{
    UINT i, len;

    if (!path || !path[0])
    {
        *ns = WBEMPROX_NAMESPACE_ROOT;
        return TRUE;
    }
    len = lstrlenW( path );
    for (i = 1; i < WBEMPROX_NAMESPACE_LAST; i++)
    {
        const WCHAR *p = path, *q = namespaces[i].path;

        if ((UINT)lstrlenW( q ) != len) continue;
        for (; *p; p++, q++)
        {
            WCHAR a = (*p == '/') ? '\\' : towlower( *p ), b = towlower( *q );
            if (a != b) break;
        }
        if (*p) continue;
        *ns = i;
        return TRUE;
    }
    return FALSE;
}

const WCHAR *get_namespace_path( enum wbm_namespace ns )
{
    if (ns >= WBEMPROX_NAMESPACE_LAST) ns = WBEMPROX_NAMESPACE_CIMV2;
    return namespaces[ns].full;
}

/* __NAMESPACE: the child namespaces of the namespace the query runs in */

static const struct column col_namespace[] =
{
    { L"Name", CIM_STRING|COL_FLAG_KEY },
};

struct record_namespace
{
    const WCHAR *name;
};

/* One table per namespace: the rows never change, and a view keeps the table of its own namespace, so
 * queries in different namespaces cannot disturb each other. ns_tables[WBEMPROX_NAMESPACE_ROOT] is the
 * one in the table list. */
static struct record_namespace ns_rows[WBEMPROX_NAMESPACE_LAST][WBEMPROX_NAMESPACE_LAST];
static struct table ns_tables[WBEMPROX_NAMESPACE_LAST];

BOOL is_namespace_table( const struct table *table )
{
    return table >= &ns_tables[0] && table < &ns_tables[WBEMPROX_NAMESPACE_LAST];
}

static void init_namespace_tables( void )
{
    UINT ns, i, row;

    for (ns = 0; ns < WBEMPROX_NAMESPACE_LAST; ns++)
    {
        for (i = 0, row = 0; i < WBEMPROX_NAMESPACE_LAST; i++)
            if (namespaces[i].parent == ns) ns_rows[ns][row++].name = namespaces[i].name;
        ns_tables[ns].name = L"__NAMESPACE";
        ns_tables[ns].num_cols = ARRAY_SIZE(col_namespace);
        ns_tables[ns].columns = col_namespace;
        ns_tables[ns].data = (BYTE *)ns_rows[ns];
        ns_tables[ns].num_rows = row;
        ns_tables[ns].num_rows_allocated = WBEMPROX_NAMESPACE_LAST;
    }
}

/* the class list */

static struct table abstract_tables[ARRAY_SIZE(schema_classes)];
static BOOL has_subclasses[ARRAY_SIZE(schema_classes)];

void init_schema_tables( struct list *list )
{
    UINT i;

    for (i = 0; i < ARRAY_SIZE(schema_classes); i++)
    {
        if (!schema_classes[i].abstract) continue;
        abstract_tables[i].name = schema_classes[i].name;
        abstract_tables[i].num_cols = schema_classes[i].num_cols;
        abstract_tables[i].columns = schema_classes[i].columns;
        list_add_tail( list, &abstract_tables[i].entry );
    }
    init_namespace_tables();
    list_add_tail( list, &ns_tables[WBEMPROX_NAMESPACE_ROOT].entry );
    init_scv2_tables( list );

    /* leaf classes are the common case of a SELECT: know them without walking the table list */
    for (i = 0; i < ARRAY_SIZE(schema_classes); i++)
    {
        UINT j;
        for (j = 0; j < ARRAY_SIZE(schema_classes) && !has_subclasses[i]; j++)
            if (schema_classes[j].superclass && !wcsicmp( schema_classes[j].superclass, schema_classes[i].name ))
                has_subclasses[i] = TRUE;
    }
}

static const struct schema_class *find_schema_class( const WCHAR *name )
{
    UINT i;
    if (!name) return NULL;
    for (i = 0; i < ARRAY_SIZE(schema_classes); i++)
        if (!wcsicmp( schema_classes[i].name, name )) return &schema_classes[i];
    return NULL;
}

/* a few classes have another superclass in root\StandardCimv2 than in root\cimv2 (the tables are shared) */
static const struct
{
    const WCHAR *name;
    const WCHAR *superclass;
}
scv2_superclasses[] =
{
    { L"CIM_ManagedSystemElement", L"CIM_ManagedElement" },
    { L"CIM_LogicalDevice", L"CIM_EnabledLogicalElement" },
};

const WCHAR *get_superclass_ns( const WCHAR *name, enum wbm_namespace ns )
{
    const struct schema_class *class;
    UINT i;

    if (ns == WBEMPROX_NAMESPACE_STANDARDCIMV2)
        for (i = 0; i < ARRAY_SIZE(scv2_superclasses); i++)
            if (name && !wcsicmp( scv2_superclasses[i].name, name )) return scv2_superclasses[i].superclass;
    class = find_schema_class( name );
    return class ? class->superclass : NULL;
}

const WCHAR *get_superclass( const WCHAR *name )
{
    return get_superclass_ns( name, WBEMPROX_NAMESPACE_CIMV2 );
}

/* is name a (direct or indirect) subclass of ancestor */
BOOL is_subclass_ns( const WCHAR *name, const WCHAR *ancestor, enum wbm_namespace ns )
{
    const WCHAR *super = name;
    UINT depth = 0;

    while ((super = get_superclass_ns( super, ns )) && depth++ < MAX_DERIVATION)
        if (!wcsicmp( super, ancestor )) return TRUE;
    return FALSE;
}

BOOL is_subclass( const WCHAR *name, const WCHAR *ancestor )
{
    return is_subclass_ns( name, ancestor, WBEMPROX_NAMESPACE_CIMV2 );
}

/* internal tables of this provider (__ASSOCIATORS, __PARAMETERS, __QUALIFIERS and the method signatures) */
static BOOL is_internal_table( const WCHAR *name )
{
    return name[0] == '_' && name[1] == '_' && !find_schema_class( name );
}

BOOL is_table_visible( const WCHAR *name, enum wbm_namespace ns )
{
    const struct schema_class *class = find_schema_class( name );

    if (class) return (class->ns_mask & (1 << ns)) != 0;
    if (is_internal_table( name )) return TRUE; /* the provider queries them itself, from any namespace */
    return (SCHEMA_NS_CIMV2 & (1 << ns)) != 0;
}

/* __DERIVATION: the superclasses, nearest first */
SAFEARRAY *get_derivation( const WCHAR *name, enum wbm_namespace ns )
{
    const WCHAR *chain[MAX_DERIVATION], *super = name;
    SAFEARRAY *sa;
    LONG i, count = 0;

    while (count < MAX_DERIVATION && (super = get_superclass_ns( super, ns ))) chain[count++] = super;
    if (!(sa = SafeArrayCreateVector( VT_BSTR, 0, count ))) return NULL;
    for (i = 0; i < count; i++)
    {
        BSTR str = SysAllocString( chain[i] );
        if (!str || SafeArrayPutElement( sa, &i, str ) != S_OK)
        {
            SysFreeString( str );
            SafeArrayDestroy( sa );
            return NULL;
        }
        SysFreeString( str );
    }
    return sa;
}

/* the column indices of a table in the order Windows reports the properties; the columns the
 * Windows class does not have follow in table order */
void get_column_order( const struct table *table, UINT *idx )
{
    const struct schema_class *class = find_schema_class( table->name );
    UINT i, j, count = 0;
    BOOL *used;

    if (!class || !class->order || !(used = heap_alloc_zero( table->num_cols * sizeof(*used) )))
    {
        for (i = 0; i < table->num_cols; i++) idx[i] = i;
        return;
    }
    for (i = 0; i < class->num_order; i++)
    {
        for (j = 0; j < table->num_cols; j++)
        {
            if (used[j] || wcsicmp( table->columns[j].name, class->order[i] )) continue;
            used[j] = TRUE;
            idx[count++] = j;
            break;
        }
    }
    for (j = 0; j < table->num_cols; j++) if (!used[j]) idx[count++] = j;
    heap_free( used );
}

/* qualifiers the provider derives from the schema: read/write/key for properties, Static and Implemented
 * for methods. Returns the count; names[i]/values[i] are filled up to max. */
static const struct
{
    const WCHAR *class;
    const WCHAR *method;
}
static_methods[] =
{
    { L"Win32_Process", L"Create" },
    { L"Win32_Service", L"Create" },
    { L"MSFT_NetIPAddress", L"Create" },
};

/* methods that run on the class, not on an instance of it: the Static ones, and the registry and security
 * providers, whose classes have no instances of their own */
BOOL is_class_method( const WCHAR *classname, const WCHAR *method )
{
    UINT i;

    if (!wcsicmp( classname, L"StdRegProv" ) || !wcsicmp( classname, L"__SystemSecurity" )) return TRUE;
    for (i = 0; i < ARRAY_SIZE(static_methods); i++)
        if (!wcsicmp( static_methods[i].class, classname ) && !wcsicmp( static_methods[i].method, method ))
            return TRUE;
    return FALSE;
}

UINT get_synth_qualifiers( const WCHAR *classname, const WCHAR *member, BOOL method, const WCHAR **names,
                           VARIANT *values, UINT max )
{
    const struct schema_class *class = find_schema_class( classname );
    struct table *table;
    UINT i, count = 0, column;
    BOOL known = FALSE, writable = FALSE, key = FALSE;

#define ADD_BOOL(n) do { if (count < max) { names[count] = (n); V_VT( &values[count] ) = VT_BOOL; \
                         V_BOOL( &values[count] ) = VARIANT_TRUE; } count++; } while (0)
#define ADD_INT(n, v) do { if (count < max) { names[count] = (n); V_VT( &values[count] ) = VT_I4; \
                           V_I4( &values[count] ) = (v); } count++; } while (0)

    if (!classname || !member) return 0;

    if (method)
    {
        if (!(table = grab_table( classname ))) return 0;
        if (get_column_index( table, member, &column ) == S_OK && is_method( table, column ))
        {
            ADD_BOOL( L"Implemented" );
            for (i = 0; i < ARRAY_SIZE(static_methods); i++)
                if (!wcsicmp( static_methods[i].class, table->name ) && !wcsicmp( static_methods[i].method, member ))
                    ADD_BOOL( L"Static" );
        }
        release_table( table );
        return count;
    }

    /* parameters of a method signature (__CLASS_METHOD_IN / _OUT) */
    {
        int dir;
        UINT id;
        if (get_param_info( classname, member, &dir, &id ))
        {
            ADD_INT( L"ID", id );
            ADD_BOOL( dir >= 0 ? L"In" : L"Out" );
            return count;
        }
    }

    if (!(table = grab_table( classname ))) return 0;
    if (get_column_index( table, member, &column ) == S_OK && !is_method( table, column ))
    {
        key = (table->columns[column].type & COL_FLAG_KEY) != 0;
        if (class)
        {
            for (i = 0; i < class->num_order; i++)
                if (!wcsicmp( class->order[i], member )) known = TRUE;
            for (i = 0; i < class->num_writable; i++)
                if (!wcsicmp( class->writable[i], member )) writable = TRUE;
        }
    }
    release_table( table );
    if (key) ADD_BOOL( L"key" );
    if (known) ADD_BOOL( L"read" );
    if (writable) ADD_BOOL( L"write" );
    return count;
#undef ADD_BOOL
#undef ADD_INT
}

/* class objects */

/* a class object over a view that is never executed: the properties exist and are NULL, and the
 * provider does not run (no process list, no file system walk for a class definition) */
HRESULT create_class_view_object( enum wbm_namespace ns, const WCHAR *name, IWbemClassObject **obj )
{
    IEnumWbemClassObject *iter;
    struct query *query;
    HRESULT hr;

    *obj = NULL;
    if (!(query = create_query())) return E_OUTOFMEMORY;
    if ((hr = create_view( VIEW_TYPE_SELECT, NULL, NULL, name, NULL, NULL, &query->view )) != S_OK) goto done;
    query->view->ns = ns;
    if (!query->view->table_count || !is_table_visible( query->view->table[0]->name, ns ))
    {
        hr = WBEM_E_NOT_FOUND;
        goto done;
    }
    if ((hr = EnumWbemClassObject_create( query, (void **)&iter )) != S_OK) goto done;
    hr = create_class_object( query->view->table[0]->name, iter, 0, NULL, obj );
    IEnumWbemClassObject_Release( iter );
done:
    release_query( query );
    return hr;
}

/* IWbemServices::CreateClassEnum */
HRESULT create_class_enum( enum wbm_namespace ns, const WCHAR *superclass, LONG flags, IEnumWbemClassObject **ret )
{
    IWbemClassObject **objs = NULL;
    const WCHAR **names = NULL;
    struct table *table;
    UINT count = 0, size = 0, i, done = 0;
    BOOL shallow = (flags & WBEM_FLAG_SHALLOW) != 0;
    HRESULT hr = S_OK;

    *ret = NULL;
    if (superclass && !superclass[0]) superclass = NULL;
    if (superclass)
    {
        if (!(table = grab_table( superclass ))) return WBEM_E_INVALID_CLASS;
        if (!is_table_visible( table->name, ns ) || is_internal_table( table->name ))
        {
            release_table( table );
            return WBEM_E_INVALID_CLASS;
        }
        release_table( table );
    }

    lock_tables();
    LIST_FOR_EACH_ENTRY( table, table_list, struct table, entry )
    {
        const WCHAR *super;

        if (is_internal_table( table->name ) || !is_table_visible( table->name, ns )) continue;
        super = get_superclass_ns( table->name, ns );
        if (superclass)
        {
            if (shallow ? (!super || wcsicmp( super, superclass )) : !is_subclass_ns( table->name, superclass, ns )) continue;
        }
        else if (shallow && super) continue;

        if (count == size)
        {
            const WCHAR **tmp;
            size = size ? size * 2 : 64;
            if (!(tmp = heap_realloc( names, size * sizeof(*names) )))
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            names = tmp;
        }
        names[count++] = table->name; /* builtin and abstract tables are never freed */
    }
    unlock_tables();

    if (hr == S_OK && count && !(objs = heap_alloc_zero( count * sizeof(*objs) ))) hr = E_OUTOFMEMORY;
    for (i = 0; hr == S_OK && i < count; i++)
    {
        if (create_class_view_object( ns, names[i], &objs[done] ) == S_OK) done++;
    }
    if (hr == S_OK) hr = EnumWbemClassObjectArray_create( objs, done, ret );
    if (hr != S_OK) for (i = 0; i < done; i++) IWbemClassObject_Release( objs[i] );
    heap_free( objs );
    heap_free( names );
    return hr;
}

/* can a class have subclasses at all */
static BOOL class_has_subclasses( const WCHAR *name )
{
    const struct schema_class *class = find_schema_class( name );
    UINT i;

    if (class) return has_subclasses[class - schema_classes];
    /* not in the schema: a subclass could still name it as its superclass */
    for (i = 0; i < ARRAY_SIZE(schema_classes); i++)
        if (schema_classes[i].superclass && !wcsicmp( schema_classes[i].superclass, name )) return TRUE;
    return FALSE;
}

/* a SELECT over a class sees the class and, as WMI does, the instances of every subclass */
HRESULT resolve_view_namespace( struct view *view, enum wbm_namespace ns )
{
    struct table *base, *table;
    HRESULT hr = S_OK;

    view->ns = ns;
    if (view->type != VIEW_TYPE_SELECT || !view->table_count) return S_OK;
    base = view->table[0];
    if (!is_table_visible( base->name, ns ))
    {
        /* as on Windows, a class the namespace does not have is an error, not an empty result */
        release_table( base );
        view->table[0] = NULL;
        view->table_count = 0;
        return WBEM_E_INVALID_CLASS;
    }
    if (is_namespace_table( base ))
    {
        if (base != &ns_tables[ns])
        {
            release_table( base );
            view->table[0] = addref_table( &ns_tables[ns] );
        }
        return S_OK;
    }
    if (!class_has_subclasses( base->name )) return S_OK;

    lock_tables();
    LIST_FOR_EACH_ENTRY( table, table_list, struct table, entry )
    {
        struct table **tmp;

        if (table == base || !is_table_visible( table->name, ns ) || !is_subclass_ns( table->name, base->name, ns )) continue;
        if (!(tmp = heap_realloc( view->table, (view->table_count + 1) * sizeof(*tmp) )))
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        view->table = tmp;
        view->table[view->table_count++] = addref_table( table );
    }
    unlock_tables();
    return hr;
}
