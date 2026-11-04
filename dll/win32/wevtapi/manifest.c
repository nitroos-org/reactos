/*
 * The metadata of a publisher that an event manifest describes: the WEVT_TEMPLATE resource of its resource
 * file, which the message compiler makes, read for its levels, tasks, opcodes, keywords, channels, events
 * and the templates of their data. Everything in the resource is untrusted (a program installs it), and
 * every offset and count is checked against the size of the resource.
 *
 * Copyright 2026 the reactos-nitro authors
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

#include "wevtapi_private.h"

#define SIG(a, b, c, d) ((DWORD)(a) | ((DWORD)(b) << 8) | ((DWORD)(c) << 16) | ((DWORD)(d) << 24))

#define MAX_PROVIDERS   256
#define MAX_ENTRIES     65536
#define MAX_NAME_CHARS  4096

struct blob
{
    const BYTE *data;
    DWORD size;
};

static BOOL get_u32(const struct blob *b, DWORD offset, DWORD *value)
{
    if (offset > b->size || b->size - offset < 4) return FALSE;
    memcpy(value, b->data + offset, 4);
    return TRUE;
}

static BOOL get_u64(const struct blob *b, DWORD offset, ULONGLONG *value)
{
    if (offset > b->size || b->size - offset < 8) return FALSE;
    memcpy(value, b->data + offset, 8);
    return TRUE;
}

/* A name: a size that counts itself, then the characters and a terminator */
static WCHAR *get_name(const struct blob *b, DWORD offset)
{
    DWORD size, chars;
    WCHAR *name;

    if (!get_u32(b, offset, &size) || size < 6 || size > b->size - offset) return NULL;
    chars = (size - 4) / sizeof(WCHAR);
    if (chars > MAX_NAME_CHARS) return NULL;
    if (!(name = calloc(chars + 1, sizeof(WCHAR)))) return NULL;
    memcpy(name, b->data + offset + 4, chars * sizeof(WCHAR));
    return name;
}

/* A section: its offset, if it has the signature and the entries of it fit into the resource */
static BOOL check_section(const struct blob *b, DWORD offset, DWORD sig, DWORD header, DWORD entry, DWORD *count)
{
    DWORD s, size;

    if (!get_u32(b, offset, &s) || s != sig || !get_u32(b, offset + 4, &size) || !get_u32(b, offset + 8, count)) return FALSE;
    if (size > b->size - offset || size < header || *count > MAX_ENTRIES) return FALSE;
    return (ULONGLONG)*count * entry <= size - header;
}

struct manifest *manifest_ref(struct manifest *m)
{
    if (m) InterlockedIncrement(&m->refs);
    return m;
}

void manifest_free(struct manifest *m)
{
    DWORD i, j;

    if (!m || InterlockedDecrement(&m->refs)) return;
    for (i = 0; i < m->level_count; i++) free(m->levels[i].name);
    for (i = 0; i < m->opcode_count; i++) free(m->opcodes[i].name);
    for (i = 0; i < m->task_count; i++) free(m->tasks[i].named.name);
    for (i = 0; i < m->keyword_count; i++) free(m->keywords[i].name);
    for (i = 0; i < m->channel_count; i++) free(m->channels[i].name);
    for (i = 0; i < m->template_count; i++)
    {
        for (j = 0; j < m->templates[i].field_count; j++) free(m->templates[i].fields[j].name);
        free(m->templates[i].fields);
    }
    free(m->levels);
    free(m->opcodes);
    free(m->tasks);
    free(m->keywords);
    free(m->channels);
    free(m->events);
    free(m->templates);
    free(m);
}

static BOOL read_simple(const struct blob *b, DWORD offset, DWORD sig, DWORD entry_size, DWORD value_off, DWORD msg_off,
                        DWORD name_off, struct man_named **items, DWORD *count)
{
    DWORD i, n;

    if (!check_section(b, offset, sig, 12, entry_size, &n)) return FALSE;
    if (!n) return TRUE;
    if (!(*items = calloc(n, sizeof(**items)))) return FALSE;
    for (i = 0; i < n; i++)
    {
        DWORD e = offset + 12 + i * entry_size, v, name;
        struct man_named *item = &(*items)[i];

        *count = i + 1;
        get_u32(b, e + value_off, &v);
        item->value = v;
        get_u32(b, e + msg_off, &item->message);
        if (get_u32(b, e + name_off, &name)) item->name = get_name(b, name);
    }
    return TRUE;
}

static BOOL read_keywords(const struct blob *b, DWORD offset, struct manifest *m)
{
    DWORD i, n;

    if (!check_section(b, offset, SIG('K','E','Y','W'), 12, 16, &n)) return FALSE;
    if (!n) return TRUE;
    if (!(m->keywords = calloc(n, sizeof(*m->keywords)))) return FALSE;
    for (i = 0; i < n; i++)
    {
        DWORD e = offset + 12 + i * 16, name;
        struct man_named *item = &m->keywords[i];

        m->keyword_count = i + 1;
        get_u64(b, e, &item->value);
        get_u32(b, e + 8, &item->message);
        if (get_u32(b, e + 12, &name)) item->name = get_name(b, name);
    }
    return TRUE;
}

static BOOL read_tasks(const struct blob *b, DWORD offset, struct manifest *m)
{
    DWORD i, n;

    if (!check_section(b, offset, SIG('T','A','S','K'), 12, 28, &n)) return FALSE;
    if (!n) return TRUE;
    if (!(m->tasks = calloc(n, sizeof(*m->tasks)))) return FALSE;
    for (i = 0; i < n; i++)
    {
        DWORD e = offset + 12 + i * 28, v, name;
        struct man_task *item = &m->tasks[i];

        m->task_count = i + 1;
        get_u32(b, e, &v);
        item->named.value = v;
        get_u32(b, e + 4, &item->named.message);
        if (e + 24 <= b->size) memcpy(&item->guid, b->data + e + 8, sizeof(item->guid));
        if (get_u32(b, e + 24, &name)) item->named.name = get_name(b, name);
    }
    return TRUE;
}

static BOOL read_channels(const struct blob *b, DWORD offset, struct manifest *m)
{
    DWORD i, n;

    if (!check_section(b, offset, SIG('C','H','A','N'), 12, 16, &n)) return FALSE;
    if (!n) return TRUE;
    if (!(m->channels = calloc(n, sizeof(*m->channels)))) return FALSE;
    for (i = 0; i < n; i++)
    {
        DWORD e = offset + 12 + i * 16, name;
        struct man_channel *item = &m->channels[i];

        m->channel_count = i + 1;
        get_u32(b, e, &item->id);
        get_u32(b, e + 8, &item->flags);
        get_u32(b, e + 12, &item->message);
        if (get_u32(b, e + 4, &name)) item->name = get_name(b, name);
    }
    return TRUE;
}

static BOOL read_events(const struct blob *b, DWORD offset, struct manifest *m)
{
    DWORD i, n;

    if (!check_section(b, offset, SIG('E','V','N','T'), 16, 48, &n)) return FALSE;
    if (!n) return TRUE;
    if (!(m->events = calloc(n, sizeof(*m->events)))) return FALSE;
    for (i = 0; i < n; i++)
    {
        DWORD e = offset + 16 + i * 48;
        const BYTE *p = b->data + e;
        struct man_event *ev = &m->events[i];

        if (e > b->size || b->size - e < 48) break;
        ev->id = p[0] | (p[1] << 8);
        ev->version = p[2];
        ev->channel = p[3];
        ev->level = p[4];
        ev->opcode = p[5];
        ev->task = p[6] | (p[7] << 8);
        memcpy(&ev->keywords, p + 8, 8);
        memcpy(&ev->message, p + 16, 4);
        memcpy(&ev->template_offset, p + 20, 4);
        m->event_count = i + 1;
    }
    return TRUE;
}

static BOOL read_templates(const struct blob *b, DWORD offset, struct manifest *m)
{
    DWORD n, i, pos;

    if (!check_section(b, offset, SIG('T','T','B','L'), 12, 0, &n)) return FALSE;
    if (!n) return TRUE;
    if (!(m->templates = calloc(n, sizeof(*m->templates)))) return FALSE;
    pos = offset + 12;
    for (i = 0; i < n; i++)
    {
        DWORD sig, size, fields, names, items, j;
        struct man_template *t = &m->templates[i];

        if (!get_u32(b, pos, &sig) || sig != SIG('T','E','M','P') || !get_u32(b, pos + 4, &size) || size < 40 ||
            size > b->size - pos || !get_u32(b, pos + 8, &fields) || !get_u32(b, pos + 12, &names) ||
            !get_u32(b, pos + 16, &items))
            break;
        (void)names;
        t->offset = pos;
        m->template_count = i + 1;
        if (fields > 1024 || (ULONGLONG)fields * 20 > b->size || items > b->size || b->size - items < fields * 20) goto next;
        if (fields && !(t->fields = calloc(fields, sizeof(*t->fields)))) return FALSE;
        for (j = 0; j < fields; j++)
        {
            DWORD e = items + j * 20, name;

            t->field_count = j + 1;
            t->fields[j].in_type = b->data[e + 4];
            t->fields[j].out_type = b->data[e + 5];
            if (get_u32(b, e + 16, &name)) t->fields[j].name = get_name(b, name);
        }
    next:
        pos += size;
    }
    return TRUE;
}

DWORD manifest_open(const WCHAR *file, const GUID *guid, struct manifest **ret)
{
    struct manifest *m;
    struct blob b;
    HMODULE module;
    HRSRC res;
    HGLOBAL mem;
    DWORD i, sig, size, providers, version, provider = 0, descriptors, error = ERROR_SUCCESS;
    BOOL found = FALSE;

    *ret = NULL;
    if (!file || !file[0]) return ERROR_FILE_NOT_FOUND;
    if (!(module = LoadLibraryExW(file, NULL, LOAD_LIBRARY_AS_DATAFILE))) return GetLastError();
    if (!(res = FindResourceW(module, MAKEINTRESOURCEW(1), L"WEVT_TEMPLATE")) || !(mem = LoadResource(module, res)))
    {
        error = ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND;
        goto done;
    }
    b.size = SizeofResource(module, res);
    b.data = LockResource(mem);
    if (!b.data || b.size < 16 || !get_u32(&b, 0, &sig) || sig != SIG('C','R','I','M') || !get_u32(&b, 4, &size) ||
        size > b.size || !get_u32(&b, 8, &version) || !get_u32(&b, 12, &providers) || providers > MAX_PROVIDERS)
    {
        error = ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND;
        goto done;
    }
    b.size = size;
    for (i = 0; i < providers; i++)
    {
        DWORD e = 16 + i * 20;

        if (e > b.size || b.size - e < 20) break;
        if (guid && memcmp(b.data + e, guid, sizeof(*guid))) continue;
        get_u32(&b, e + 16, &provider);
        found = TRUE;
        break;
    }
    if (!found || !get_u32(&b, provider, &sig) || sig != SIG('W','E','V','T') || !get_u32(&b, provider + 4, &size) ||
        !get_u32(&b, provider + 12, &descriptors) || descriptors > 64)
    {
        error = ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND;
        goto done;
    }
    if (!(m = calloc(1, sizeof(*m)))) { error = ERROR_OUTOFMEMORY; goto done; }
    m->refs = 1;
    get_u32(&b, provider + 8, &m->message);
    if (guid) m->guid = *guid;
    else memcpy(&m->guid, b.data + 16, sizeof(m->guid));
    /* the sections that the descriptors point to are in no fixed order */
    for (i = 0; i < descriptors; i++)
    {
        DWORD off, s;
        BOOL ok = TRUE;

        if (!get_u32(&b, provider + 20 + i * 8, &off) || !get_u32(&b, off, &s)) continue;
        switch (s)
        {
        case SIG('C','H','A','N'): ok = read_channels(&b, off, m); break;
        case SIG('E','V','N','T'): ok = read_events(&b, off, m); break;
        case SIG('K','E','Y','W'): ok = read_keywords(&b, off, m); break;
        case SIG('L','E','V','L'): ok = read_simple(&b, off, s, 12, 0, 4, 8, &m->levels, &m->level_count); break;
        case SIG('O','P','C','O'): ok = read_simple(&b, off, s, 12, 0, 4, 8, &m->opcodes, &m->opcode_count); break;
        case SIG('T','A','S','K'): ok = read_tasks(&b, off, m); break;
        case SIG('T','T','B','L'): ok = read_templates(&b, off, m); break;
        default: break;
        }
        (void)ok;
    }
    *ret = m;

done:
    FreeLibrary(module);
    return error;
}

static const WCHAR *const in_types[] =
{
    NULL, L"win:UnicodeString", L"win:AnsiString", L"win:Int8", L"win:UInt8", L"win:Int16", L"win:UInt16", L"win:Int32",
    L"win:UInt32", L"win:Int64", L"win:UInt64", L"win:Float", L"win:Double", L"win:Boolean", L"win:Binary", L"win:GUID",
    L"win:Pointer", L"win:FILETIME", L"win:SYSTEMTIME", L"win:SID", L"win:HexInt32", L"win:HexInt64",
};

static const WCHAR *const out_types[] =
{
    NULL, L"xs:string", L"xs:dateTime", L"xs:byte", L"xs:unsignedByte", L"xs:short", L"xs:unsignedShort", L"xs:int",
    L"xs:unsignedInt", L"xs:long", L"xs:unsignedLong", L"xs:float", L"xs:double", L"xs:boolean", L"xs:GUID",
    L"xs:hexBinary", L"win:HexInt8", L"win:HexInt16", L"win:HexInt32", L"win:HexInt64", L"win:PID", L"win:TID",
    L"win:Port", L"win:IPv4", L"win:IPv6", L"win:SocketAddress", L"win:CIMDateTime", L"win:ETWTimestamp", L"win:XML",
    L"win:ErrorCode", L"win:Win32Error", L"win:NTSTATUS", L"win:HResult",
};

const WCHAR *manifest_in_type_name(BYTE type)
{
    return type < ARRAY_SIZE(in_types) && in_types[type] ? in_types[type] : L"win:UnicodeString";
}

const WCHAR *manifest_out_type_name(BYTE type)
{
    return type < ARRAY_SIZE(out_types) ? out_types[type] : NULL;
}

/* The template of an event as Windows writes it: a data element for each value, with the types by name */
WCHAR *manifest_template_xml(const struct manifest *m, DWORD template_offset)
{
    static const WCHAR head[] = L"<template xmlns=\"http://schemas.microsoft.com/win/2004/08/events\">\r\n";
    static const WCHAR tail[] = L"</template>\r\n";
    const struct man_template *t = NULL;
    SIZE_T cap, len = 0;
    WCHAR *xml;
    DWORD i;

    for (i = 0; i < m->template_count; i++)
        if (m->templates[i].offset == template_offset) { t = &m->templates[i]; break; }
    /* a template with no data is a template still */
    if (!t) return NULL;

    cap = ARRAY_SIZE(head) + ARRAY_SIZE(tail) + 8;
    for (i = 0; i < t->field_count; i++) cap += wcslen(t->fields[i].name ? t->fields[i].name : L"") * 6 + 160;
    if (!(xml = malloc(cap * sizeof(WCHAR)))) return NULL;
    len = _snwprintf(xml, cap, L"%ls", head);
    for (i = 0; i < t->field_count; i++)
    {
        const struct man_field *f = &t->fields[i];
        const WCHAR *out = manifest_out_type_name(f->out_type);
        const WCHAR *p;

        len += _snwprintf(xml + len, cap - len, L"  <data name=\"");
        for (p = f->name ? f->name : L""; *p; p++)
        {
            if (*p == '&') len += _snwprintf(xml + len, cap - len, L"&amp;");
            else if (*p == '<') len += _snwprintf(xml + len, cap - len, L"&lt;");
            else if (*p == '>') len += _snwprintf(xml + len, cap - len, L"&gt;");
            else if (*p == '"') len += _snwprintf(xml + len, cap - len, L"&quot;");
            else xml[len++] = *p;
        }
        len += _snwprintf(xml + len, cap - len, L"\" inType=\"%ls\"", manifest_in_type_name(f->in_type));
        if (out) len += _snwprintf(xml + len, cap - len, L" outType=\"%ls\"", out);
        len += _snwprintf(xml + len, cap - len, L"/>\r\n");
    }
    len += _snwprintf(xml + len, cap - len, L"%ls", tail);
    return xml;
}
