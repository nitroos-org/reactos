/*
 * Writes .evtx files: the events that EvtExportLog and EvtClearLog (with a backup) put into a file. The
 * XML of an event is stored as binary XML with the names inline and the values as text, which is a form
 * that every reader of .evtx files has to take, so there are no templates and no string table.
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

#define FILE_HEADER_SIZE   4096
#define CHUNK_SIZE         65536
#define CHUNK_HEADER_SIZE  512
#define MAX_NAME_CHARS     255
#define MAX_DEPTH          64

struct evtx_writer
{
    HANDLE file;
    WCHAR *path;
    BYTE *chunk;
    DWORD free_offset;              /* in the chunk that is being filled */
    DWORD chunk_count;              /* chunks that were written, and the one being filled if it has records */
    BOOL chunk_used;
    ULONGLONG first_record, last_record;    /* of the chunk being filled */
    ULONGLONG file_first_record, file_last_record;
    DWORD last_offset;
    BOOL any;
};

static DWORD crc_table[256];
static BOOL crc_ready;

static DWORD crc32(const BYTE *data, SIZE_T len, DWORD crc)
{
    if (!crc_ready)
    {
        DWORD i, j, c;

        for (i = 0; i < 256; i++)
        {
            for (c = i, j = 0; j < 8; j++) c = (c & 1) ? 0xedb88320 ^ (c >> 1) : c >> 1;
            crc_table[i] = c;
        }
        crc_ready = TRUE;
    }
    crc = ~crc;
    while (len--) crc = crc_table[(crc ^ *data++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static void put16(BYTE *p, WORD v) { p[0] = v; p[1] = v >> 8; }
static void put32(BYTE *p, DWORD v) { put16(p, v); put16(p + 2, v >> 16); }
static void put64(BYTE *p, ULONGLONG v) { put32(p, (DWORD)v); put32(p + 4, (DWORD)(v >> 32)); }

/* The binary XML of one record is built here: BYTES at a position of the chunk that is known beforehand */
struct bin
{
    BYTE *buf;
    DWORD len, cap;
    DWORD base;                     /* the offset in the chunk of the first byte */
    BOOL fail;
};

static BYTE *bin_room(struct bin *b, DWORD n)
{
    BYTE *p;

    if (b->fail || n > b->cap - b->len) { b->fail = TRUE; return NULL; }
    p = b->buf + b->len;
    b->len += n;
    return p;
}

static void bin_u8(struct bin *b, BYTE v) { BYTE *p = bin_room(b, 1); if (p) *p = v; }
static void bin_u16(struct bin *b, WORD v) { BYTE *p = bin_room(b, 2); if (p) put16(p, v); }
static void bin_u32(struct bin *b, DWORD v) { BYTE *p = bin_room(b, 4); if (p) put32(p, v); }

/* a name: the offset of it, which is the position right behind, and the name itself */
static void bin_name(struct bin *b, const WCHAR *name, DWORD n)
{
    DWORD i;
    WORD hash = 0;
    BYTE *p;

    if (!n || n > MAX_NAME_CHARS) { b->fail = TRUE; return; }
    bin_u32(b, b->base + b->len + 4);
    bin_u32(b, 0);
    for (i = 0; i < n; i++) hash = hash * 65599 + name[i];
    bin_u16(b, hash);
    bin_u16(b, n);
    if (!(p = bin_room(b, (n + 1) * 2))) return;
    for (i = 0; i < n; i++) put16(p + i * 2, name[i]);
    put16(p + n * 2, 0);
}

static void bin_text(struct bin *b, const WCHAR *text, DWORD n)
{
    DWORD i;
    BYTE *p;

    if (n > 0xffff) { b->fail = TRUE; return; }
    bin_u8(b, 0x05);
    bin_u8(b, 0x01);
    bin_u16(b, n);
    if (!(p = bin_room(b, n * 2))) return;
    for (i = 0; i < n; i++) put16(p + i * 2, text[i]);
}

/* The text with its entities replaced, as a heap string */
static WCHAR *decode(const WCHAR *s, DWORD n, DWORD *out_len)
{
    WCHAR *out = malloc((n + 1) * sizeof(WCHAR));
    DWORD i = 0, o = 0;

    if (!out) return NULL;
    while (i < n)
    {
        if (s[i] == '&')
        {
            static const struct { const WCHAR *name; WCHAR ch; } ents[] =
                { { L"amp;", '&' }, { L"lt;", '<' }, { L"gt;", '>' }, { L"quot;", '"' }, { L"apos;", '\'' } };
            DWORD k;

            for (k = 0; k < ARRAY_SIZE(ents); k++)
            {
                DWORD l = wcslen(ents[k].name);

                if (i + 1 + l <= n && !wcsncmp(s + i + 1, ents[k].name, l)) { out[o++] = ents[k].ch; i += 1 + l; break; }
            }
            if (k < ARRAY_SIZE(ents)) continue;
            if (i + 2 < n && s[i + 1] == '#')
            {
                ULONG v = 0;
                DWORD j = i + 2;
                BOOL hex = s[j] == 'x';

                if (hex) j++;
                for (; j < n && s[j] != ';'; j++)
                {
                    WCHAR c = s[j];
                    DWORD d = c >= '0' && c <= '9' ? c - '0' : hex && c >= 'a' && c <= 'f' ? c - 'a' + 10 : hex && c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;

                    if (d >= (hex ? 16 : 10)) break;
                    v = v * (hex ? 16 : 10) + d;
                    if (v > 0xffff) break;
                }
                if (j < n && s[j] == ';' && v) { out[o++] = (WCHAR)v; i = j + 1; continue; }
            }
        }
        out[o++] = s[i++];
    }
    out[o] = 0;
    *out_len = o;
    return out;
}

static BOOL is_space(WCHAR c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static BOOL name_char(WCHAR c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':';
}

/* One element, which p points at the "<" of; the tokens go into b, and p is left behind the element */
static BOOL convert_element(struct bin *b, const WCHAR **p, DWORD depth)
{
    const WCHAR *s = *p, *name;
    struct { const WCHAR *name, *value; DWORD name_len, value_len; } attrs[16];
    DWORD name_len, count = 0, i, size_at, start, list_at, list_start;
    BOOL empty = FALSE;

    if (depth > MAX_DEPTH || *s != '<') return FALSE;
    s++;
    name = s;
    while (name_char(*s)) s++;
    name_len = s - name;
    if (!name_len) return FALSE;
    for (;;)
    {
        WCHAR quote;
        const WCHAR *v;

        while (is_space(*s)) s++;
        if (*s == '/' && s[1] == '>') { empty = TRUE; s += 2; break; }
        if (*s == '>') { s++; break; }
        if (count == ARRAY_SIZE(attrs) || !name_char(*s)) return FALSE;
        attrs[count].name = s;
        while (name_char(*s)) s++;
        attrs[count].name_len = s - attrs[count].name;
        while (is_space(*s)) s++;
        if (*s++ != '=') return FALSE;
        while (is_space(*s)) s++;
        quote = *s++;
        if (quote != '\'' && quote != '"') return FALSE;
        v = s;
        while (*s && *s != quote) s++;
        if (!*s) return FALSE;
        attrs[count].value = v;
        attrs[count].value_len = s - v;
        s++;
        count++;
    }

    bin_u8(b, count ? 0x41 : 0x01);
    bin_u16(b, 0xffff);
    size_at = b->len;
    bin_u32(b, 0);
    start = b->len;
    bin_name(b, name, name_len);
    if (count)
    {
        list_at = b->len;
        bin_u32(b, 0);
        list_start = b->len;
        for (i = 0; i < count; i++)
        {
            DWORD n;
            WCHAR *v = decode(attrs[i].value, attrs[i].value_len, &n);

            if (!v) return FALSE;
            bin_u8(b, i + 1 < count ? 0x46 : 0x06);
            bin_name(b, attrs[i].name, attrs[i].name_len);
            if (n) bin_text(b, v, n);
            else bin_text(b, L"", 0);
            free(v);
        }
        if (!b->fail) put32(b->buf + list_at, b->len - list_start);
    }
    if (empty)
    {
        bin_u8(b, 0x03);
        if (!b->fail) put32(b->buf + size_at, b->len - start);
        *p = s;
        return !b->fail;
    }
    bin_u8(b, 0x02);
    for (;;)
    {
        if (!*s) return FALSE;
        if (*s == '<' && s[1] == '/')
        {
            const WCHAR *e = s + 2;

            if (wcsncmp(e, name, name_len) || e[name_len] != '>') return FALSE;
            s = e + name_len + 1;
            break;
        }
        if (*s == '<')
        {
            if (!convert_element(b, &s, depth + 1)) return FALSE;
        }
        else
        {
            const WCHAR *t = s;
            DWORD n;
            WCHAR *v;

            while (*s && *s != '<') s++;
            if (!(v = decode(t, s - t, &n))) return FALSE;
            if (n) bin_text(b, v, n);
            free(v);
        }
    }
    bin_u8(b, 0x04);
    if (!b->fail) put32(b->buf + size_at, b->len - start);
    *p = s;
    return !b->fail;
}

/* The chunk header and checksums, and the chunk to the file */
static DWORD flush_chunk(struct evtx_writer *w)
{
    BYTE *c = w->chunk;
    DWORD crc, written;
    LARGE_INTEGER pos;

    if (!w->chunk_used) return ERROR_SUCCESS;
    memcpy(c, "ElfChnk\0", 8);
    put64(c + 8, w->first_record);
    put64(c + 16, w->last_record);
    put64(c + 24, w->first_record);
    put64(c + 32, w->last_record);
    put32(c + 40, 128);
    put32(c + 44, w->last_offset);
    put32(c + 48, w->free_offset);
    put32(c + 52, crc32(c + CHUNK_HEADER_SIZE, w->free_offset - CHUNK_HEADER_SIZE, 0));
    crc = crc32(c, 120, 0);
    put32(c + 124, crc32(c + 128, CHUNK_HEADER_SIZE - 128, crc));
    pos.QuadPart = FILE_HEADER_SIZE + (LONGLONG)w->chunk_count * CHUNK_SIZE;
    if (!SetFilePointerEx(w->file, pos, NULL, FILE_BEGIN) || !WriteFile(w->file, c, CHUNK_SIZE, &written, NULL) || written != CHUNK_SIZE)
        return GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    w->chunk_count++;
    w->chunk_used = FALSE;
    memset(c, 0, CHUNK_SIZE);
    w->free_offset = CHUNK_HEADER_SIZE;
    return ERROR_SUCCESS;
}

DWORD evtx_create(const WCHAR *path, BOOL overwrite, struct evtx_writer **ret)
{
    struct evtx_writer *w;
    DWORD error = ERROR_SUCCESS;

    *ret = NULL;
    if (!(w = calloc(1, sizeof(*w)))) return ERROR_OUTOFMEMORY;
    if (!(w->chunk = calloc(1, CHUNK_SIZE)) || !(w->path = _wcsdup(path))) { error = ERROR_OUTOFMEMORY; goto fail; }
    w->free_offset = CHUNK_HEADER_SIZE;
    w->file = CreateFileW(path, GENERIC_WRITE, 0, NULL, overwrite ? CREATE_ALWAYS : CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (w->file == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        if (error == ERROR_FILE_EXISTS) error = ERROR_ALREADY_EXISTS;
        goto fail;
    }
    *ret = w;
    return ERROR_SUCCESS;

fail:
    free(w->chunk);
    free(w->path);
    free(w);
    return error;
}

/* The next record of the file: the XML of an event, its number and when it happened (FILETIME units) */
DWORD evtx_add_xml(struct evtx_writer *w, ULONGLONG record_id, ULONGLONG time, const WCHAR *xml)
{
    struct bin b;
    const WCHAR *p = xml;
    DWORD tries, error;

    for (tries = 0; tries < 2; tries++)
    {
        BYTE *record;
        DWORD size;

        memset(&b, 0, sizeof(b));
        b.cap = CHUNK_SIZE - CHUNK_HEADER_SIZE - 28;
        b.buf = malloc(b.cap);
        if (!b.buf) return ERROR_OUTOFMEMORY;
        b.base = w->free_offset + 24;
        p = xml;
        while (is_space(*p)) p++;
        bin_u8(&b, 0x0f);
        bin_u8(&b, 0x01);
        bin_u8(&b, 0x01);
        bin_u8(&b, 0x00);
        if (!convert_element(&b, &p, 0))
        {
            free(b.buf);
            /* an event that is not XML of the shape that this library writes, or does not fit into a chunk */
            return b.fail ? ERROR_INSUFFICIENT_BUFFER : ERROR_EVT_MALFORMED_XML_TEXT;
        }
        bin_u8(&b, 0x00);
        size = 24 + b.len + 4;
        if (size <= CHUNK_SIZE - w->free_offset)
        {
            record = w->chunk + w->free_offset;
            put32(record, 0x2a2a);
            put32(record + 4, size);
            put64(record + 8, record_id);
            put64(record + 16, time);
            memcpy(record + 24, b.buf, b.len);
            put32(record + size - 4, size);
            free(b.buf);
            if (!w->chunk_used) { w->first_record = record_id; w->chunk_used = TRUE; }
            w->last_record = record_id;
            w->last_offset = w->free_offset;
            w->free_offset += size;
            if (!w->any) w->file_first_record = record_id;
            w->file_last_record = record_id;
            w->any = TRUE;
            return ERROR_SUCCESS;
        }
        free(b.buf);
        /* the chunk is full: the record goes to the next one, where its names are at other offsets */
        if ((error = flush_chunk(w))) return error;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

DWORD evtx_finish(struct evtx_writer *w, BOOL keep)
{
    BYTE header[FILE_HEADER_SIZE];
    LARGE_INTEGER pos = { 0 };
    DWORD error = ERROR_SUCCESS, written;

    if (keep) error = flush_chunk(w);
    if (keep && !error)
    {
        memset(header, 0, sizeof(header));
        memcpy(header, "ElfFile\0", 8);
        put64(header + 8, 0);
        put64(header + 16, w->chunk_count ? w->chunk_count - 1 : 0);
        put64(header + 24, w->any ? w->file_last_record + 1 : 1);
        put32(header + 32, 128);
        put16(header + 36, 1);
        put16(header + 38, 3);
        put16(header + 40, FILE_HEADER_SIZE);
        put16(header + 42, w->chunk_count);
        put32(header + 124, crc32(header, 120, 0));
        if (!SetFilePointerEx(w->file, pos, NULL, FILE_BEGIN) || !WriteFile(w->file, header, sizeof(header), &written, NULL) || written != sizeof(header))
            error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    }
    CloseHandle(w->file);
    if (!keep || error) DeleteFileW(w->path);
    free(w->chunk);
    free(w->path);
    free(w);
    return error;
}
