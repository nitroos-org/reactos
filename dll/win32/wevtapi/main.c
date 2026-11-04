/*
 * Copyright 2012 Austin English
 * Copyright 2012 André Hentschel
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
#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(wevtapi);

/*
 * There is no event log service of the Vista kind behind this library. What it knows about are
 * the .evtx files that a query names (evtx.c reads them) and the classic logs that the registry lists under the EventLog key: it offers
 * them as channels, reads their records through the classic eventlog API (see classic.c), and
 * lets the sources that those logs register stand for publishers. The handles, the arguments and
 * the channel names are checked the way Windows checks them. A call that would need what is not
 * here (a server on another machine, a subscription, the log information of an .evtx file, the
 * export or the clearing of a log) fails, after those checks, with the error of an RPC server that cannot be reached or
 * with the error for a request that is not supported.
 */

enum object_type
{
    OBJECT_SESSION = 1,
    OBJECT_CHANNEL_ENUM,
    OBJECT_CHANNEL_CONFIG,
    OBJECT_RENDER_CONTEXT,
    OBJECT_BOOKMARK,
    OBJECT_PUBLISHER_ENUM,
    OBJECT_QUERY,
    OBJECT_EVENT,
    OBJECT_LOG,
    OBJECT_PUBLISHER,
    OBJECT_ARRAY,
    OBJECT_EVENT_ENUM,
    OBJECT_EVENT_META,
};

/* what an array handle stands for */
enum array_kind
{
    ARRAY_CHANNELS,                 /* the logs that a publisher writes to */
    ARRAY_EMPTY,                    /* levels, tasks, opcodes and keywords, which a classic source has none of */
    ARRAY_MANIFEST,                 /* levels, tasks, opcodes or keywords of a manifest publisher, as the MAN_ kind says */
};

/* what an event metadata handle, and the enumeration of them, stand for: an event of a manifest */
struct event_meta
{
    struct manifest *manifest;
    DWORD index;                    /* the event, or the next one for an enumeration */
};

struct event_data
{
    EVENTLOGRECORD *rec;            /* an event of a classic log, or */
    struct evtx_event *evtx;        /* an event of an .evtx file */
    WCHAR *channel;
};

struct render_context
{
    DWORD flags;
    DWORD count;
    int *indexes;
};

struct publisher_enum
{
    WCHAR **names;
    DWORD count;
};

struct array_data
{
    enum array_kind kind;
    WCHAR **items;
    DWORD count;
    struct manifest *manifest;      /* of a manifest publisher: where the elements are */
    DWORD man_kind;
};

struct bookmark_entry
{
    WCHAR *channel;
    ULONGLONG record_id;
    BOOL has_record_id;
    BOOL is_current;
    BOOL has_is_current;
};

struct object
{
    struct list entry;
    enum object_type type;
    BOOL remote;                    /* session: the server is another machine */
    DWORD index;                    /* channel enumeration: the next key */
    WCHAR *name;                    /* channel configuration: the channel */
    struct bookmark_entry *marks;   /* bookmark */
    DWORD mark_count;
    WCHAR *direction;               /* bookmark: the Direction attribute of the list, if it has one */
    void *data;                     /* query, event, render context, publisher, publisher enumeration, array */
    struct subscription *sub;       /* query: the subscription that it is */
};

/* A subscription: a query that goes on, and a thread that looks for what the logs get */
struct subscription
{
    CRITICAL_SECTION cs;
    HANDLE signal;                  /* of the caller, set when events can be read (pull) */
    EVT_SUBSCRIBE_CALLBACK callback;
    void *context;
    HANDLE stop, thread;
    DWORD thread_id;
    BOOL cancelled;
};

static CRITICAL_SECTION object_cs;
static CRITICAL_SECTION_DEBUG object_cs_debug =
{
    0, 0, &object_cs,
    { &object_cs_debug.ProcessLocksList, &object_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": object_cs") }
};
static CRITICAL_SECTION object_cs = { &object_cs_debug, -1, 0, 0, 0, 0 };

static struct list object_list = LIST_INIT(object_list);

static const WCHAR eventlog_key[] = L"System\\CurrentControlSet\\Services\\EventLog";

/* Windows leaves no error behind from a call that works, and a caller may look at the last error whatever the result was */
static BOOL succeed(void)
{
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static BOOL fail(DWORD error)
{
    SetLastError(error);
    return FALSE;
}

static struct object *find_object(EVT_HANDLE handle, enum object_type type)
{
    struct object *object;

    LIST_FOR_EACH_ENTRY(object, &object_list, struct object, entry)
        if ((EVT_HANDLE)object == handle)
            return (type == 0 || object->type == type) ? object : NULL;
    return NULL;
}

static EVT_HANDLE new_object(enum object_type type, BOOL remote, const WCHAR *name)
{
    struct object *object = calloc(1, sizeof(*object));

    if (!object)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    object->type = type;
    object->remote = remote;
    if (name && !(object->name = _wcsdup(name)))
    {
        free(object);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    EnterCriticalSection(&object_cs);
    list_add_head(&object_list, &object->entry);
    LeaveCriticalSection(&object_cs);
    SetLastError(ERROR_SUCCESS);
    return (EVT_HANDLE)object;
}

static void free_marks(struct bookmark_entry *marks, DWORD count);

static void free_subscription(struct subscription *sub)
{
    /* the thread that looks for events ends first; a callback that closes its own subscription cannot wait for itself */
    SetEvent(sub->stop);
    if (sub->thread)
    {
        if (GetCurrentThreadId() != sub->thread_id) WaitForSingleObject(sub->thread, INFINITE);
        CloseHandle(sub->thread);
    }
    CloseHandle(sub->stop);
    DeleteCriticalSection(&sub->cs);
    free(sub);
}

static void free_object(struct object *object)
{
    switch (object->type)
    {
    case OBJECT_QUERY:
        if (object->sub) free_subscription(object->sub);
        classic_query_free(object->data);
        break;
    case OBJECT_EVENT:
    {
        struct event_data *event = object->data;

        if (event) { free(event->rec); evtx_event_free(event->evtx); free(event->channel); free(event); }
        break;
    }
    case OBJECT_RENDER_CONTEXT:
    {
        struct render_context *context = object->data;

        if (context) { free(context->indexes); free(context); }
        break;
    }
    case OBJECT_PUBLISHER:
        classic_pub_free(object->data);
        break;
    case OBJECT_CHANNEL_ENUM:
    case OBJECT_PUBLISHER_ENUM:
    {
        struct publisher_enum *list = object->data;

        if (list) { classic_names_free(list->names, list->count); free(list); }
        break;
    }
    case OBJECT_ARRAY:
    {
        struct array_data *array = object->data;

        if (array) { if (array->items) classic_names_free(array->items, array->count); manifest_free(array->manifest); free(array); }
        break;
    }
    case OBJECT_EVENT_ENUM:
    case OBJECT_EVENT_META:
    {
        struct event_meta *meta = object->data;

        if (meta) { manifest_free(meta->manifest); free(meta); }
        break;
    }
    default:
        break;
    }
    free_marks(object->marks, object->mark_count);
    free(object->direction);
    free(object->name);
    free(object);
}

/* A handle that is NULL or a session. Sets the last error and returns FALSE for anything else. */
static BOOL get_session(EVT_HANDLE session, BOOL *remote)
{
    struct object *object;
    BOOL ret = TRUE;

    *remote = FALSE;
    if (!session) return TRUE;

    EnterCriticalSection(&object_cs);
    object = find_object(session, OBJECT_SESSION);
    if (object) *remote = object->remote;
    else ret = FALSE;
    LeaveCriticalSection(&object_cs);

    if (!ret) SetLastError(ERROR_INVALID_HANDLE);
    return ret;
}

static BOOL is_local_server(const WCHAR *server)
{
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAY_SIZE(name);

    if (!server || !server[0] || !wcscmp(server, L".") || !_wcsicmp(server, L"localhost")) return TRUE;
    return GetComputerNameW(name, &size) && !_wcsicmp(server, name);
}

static BOOL no_service(void)
{
    return fail(RPC_S_SERVER_UNAVAILABLE);
}

static BOOL is_bad_channel_char(WCHAR c)
{
    return c < ' ' || c == '<' || c == '>' || c == '"' || c == '&' || c == '|';
}

/* ERROR_SUCCESS when the classic log exists, else the error Windows gives for the name */
static DWORD check_channel(const WCHAR *name)
{
    HKEY root, key;
    const WCHAR *p;
    LSTATUS status;

    if (!name || !name[0]) return ERROR_EVT_INVALID_CHANNEL_PATH;
    for (p = name; *p; p++)
        if (is_bad_channel_char(*p)) return ERROR_EVT_INVALID_CHANNEL_PATH;
    if (wcschr(name, '\\')) return ERROR_EVT_CHANNEL_NOT_FOUND;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, eventlog_key, 0, KEY_READ, &root)) return classic_registered_channel(name) ? ERROR_SUCCESS : ERROR_EVT_CHANNEL_NOT_FOUND;
    status = RegOpenKeyExW(root, name, 0, KEY_READ, &key);
    if (!status) RegCloseKey(key);
    RegCloseKey(root);
    return status && !classic_registered_channel(name) ? ERROR_EVT_CHANNEL_NOT_FOUND : ERROR_SUCCESS;
}

/* A reader for the small subset of XML that structured queries and bookmarks use */

#define XML_MAX_NAME  64
#define XML_MAX_ATTRS 16
#define XML_MAX_DEPTH 32

struct xml_attr
{
    WCHAR name[XML_MAX_NAME];
    WCHAR *value;
};

struct xml_tag
{
    WCHAR name[XML_MAX_NAME];
    struct xml_attr attrs[XML_MAX_ATTRS];
    DWORD attr_count;
    BOOL closing;
    BOOL empty;
    BOOL junk;      /* there was text other than white space before the tag */
};

enum { XML_ERROR = -1, XML_END = 0, XML_TAG = 1 };

static void free_tag(struct xml_tag *tag)
{
    DWORD i;

    for (i = 0; i < tag->attr_count; i++)
        free(tag->attrs[i].value);
    tag->attr_count = 0;
}

static BOOL is_xml_space(WCHAR c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static BOOL is_name_char(WCHAR c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':';
}

static BOOL read_name(const WCHAR **p, WCHAR *name)
{
    DWORD len = 0;

    while (is_name_char(**p))
    {
        if (len + 1 >= XML_MAX_NAME) return FALSE;
        name[len++] = *(*p)++;
    }
    name[len] = 0;
    return len != 0;
}

/* Writes the character of a numeric reference as UTF-16. Returns the number of characters, or 0 for a number that is no character. */
static int encode_char(ULONG ch, WCHAR *out)
{
    if (!ch || ch > 0x10ffff || (ch >= 0xd800 && ch <= 0xdfff) || ch == 0xfffe || ch == 0xffff || (ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r'))
        return 0;
    if (ch < 0x10000)
    {
        out[0] = ch;
        return 1;
    }
    ch -= 0x10000;
    out[0] = 0xd800 | (ch >> 10);
    out[1] = 0xdc00 | (ch & 0x3ff);
    return 2;
}

/* The text of an attribute value with its references resolved, or NULL for text that is not valid */
static WCHAR *decode_value(const WCHAR *start, const WCHAR *end)
{
    WCHAR *value = calloc(end - start + 1, sizeof(WCHAR)), *out = value;

    if (!value) return NULL;
    while (start < end)
    {
        if (*start != '&')
        {
            *out++ = *start++;
            continue;
        }
        if (end - start >= 4 && !wcsncmp(start, L"&lt;", 4)) { *out++ = '<'; start += 4; }
        else if (end - start >= 4 && !wcsncmp(start, L"&gt;", 4)) { *out++ = '>'; start += 4; }
        else if (end - start >= 5 && !wcsncmp(start, L"&amp;", 5)) { *out++ = '&'; start += 5; }
        else if (end - start >= 6 && !wcsncmp(start, L"&quot;", 6)) { *out++ = '"'; start += 6; }
        else if (end - start >= 6 && !wcsncmp(start, L"&apos;", 6)) { *out++ = '\''; start += 6; }
        else if (end - start >= 4 && start[1] == '#')
        {
            const WCHAR *p = start + 2;
            ULONG ch = 0, base = 10;
            int len;

            if (*p == 'x') { base = 16; p++; }
            if (p >= end || *p == ';') goto error;
            for (; p < end && *p != ';'; p++)
            {
                ULONG digit = *p >= '0' && *p <= '9' ? *p - '0' : base == 16 && *p >= 'a' && *p <= 'f' ? *p - 'a' + 10 :
                              base == 16 && *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : 16;
                if (digit >= base || ch > 0x10ffff) goto error;
                ch = ch * base + digit;
            }
            if (p >= end || !(len = encode_char(ch, out))) goto error;
            out += len;
            start = p + 1;
        }
        else goto error;
    }
    *out = 0;
    return value;

error:
    free(value);
    return NULL;
}

/* Reads the next tag, skipping text, comments and processing instructions. Text that is not white space is noted in the tag. */
static int next_tag(const WCHAR **text, struct xml_tag *tag)
{
    const WCHAR *p = *text, *end;
    BOOL junk = FALSE;

    memset(tag, 0, sizeof(*tag));
    for (;;)
    {
        while (*p && *p != '<')
        {
            if (*p == '&')
            {
                /* a reference in text must be one that is known */
                WCHAR *value;

                for (end = p; *end && *end != ';' && *end != '<' && end - p <= 12; end++) {}
                if (*end != ';' || !(value = decode_value(p, end + 1))) return XML_ERROR;
                free(value);
                junk = TRUE;
                p = end + 1;
                continue;
            }
            if (!is_xml_space(*p)) junk = TRUE;
            p++;
        }
        if (!*p)
        {
            *text = p;
            tag->junk = junk;
            return XML_END;
        }
        if (!wcsncmp(p, L"<!--", 4))
        {
            if (!(end = wcsstr(p + 4, L"-->"))) return XML_ERROR;
            p = end + 3;
        }
        else if (!wcsncmp(p, L"<?", 2))
        {
            if (!(end = wcsstr(p + 2, L"?>"))) return XML_ERROR;
            p = end + 2;
        }
        else if (!wcsncmp(p, L"<![CDATA[", 9))
        {
            if (!(end = wcsstr(p + 9, L"]]>"))) return XML_ERROR;
            junk = TRUE;
            p = end + 3;
        }
        else break;
    }
    tag->junk = junk;

    p++;
    if (*p == '/')
    {
        p++;
        tag->closing = TRUE;
    }
    if (!read_name(&p, tag->name)) return XML_ERROR;
    if (!is_xml_space(*p) && *p != '>' && *p != '/') return XML_ERROR;

    for (;;)
    {
        struct xml_attr *attr;
        WCHAR quote;

        while (is_xml_space(*p)) p++;
        if (*p == '>')
        {
            p++;
            break;
        }
        if (*p == '/' && !tag->closing)
        {
            if (p[1] != '>') goto error;
            p += 2;
            tag->empty = TRUE;
            break;
        }
        if (tag->closing || tag->attr_count == XML_MAX_ATTRS) goto error;

        attr = &tag->attrs[tag->attr_count];
        if (!read_name(&p, attr->name)) goto error;
        while (is_xml_space(*p)) p++;
        if (*p++ != '=') goto error;
        while (is_xml_space(*p)) p++;
        quote = *p++;
        if (quote != '"' && quote != '\'') goto error;
        for (end = p; *end && *end != quote && *end != '<'; end++) {}
        if (*end != quote) goto error;
        if (!(attr->value = decode_value(p, end))) goto error;
        tag->attr_count++;
        p = end + 1;
        /* the next attribute, or the end of the tag, follows after white space */
        if (!is_xml_space(*p) && *p != '>' && *p != '/') goto error;
    }

    *text = p;
    return XML_TAG;

error:
    free_tag(tag);
    return XML_ERROR;
}

static const WCHAR *find_attr(const struct xml_tag *tag, const WCHAR *name)
{
    DWORD i;

    for (i = 0; i < tag->attr_count; i++)
        if (!wcscmp(tag->attrs[i].name, name)) return tag->attrs[i].value;
    return NULL;
}

static BOOL has_duplicate_attr(const struct xml_tag *tag)
{
    DWORD i, j;

    for (i = 0; i < tag->attr_count; i++)
        for (j = i + 1; j < tag->attr_count; j++)
            if (!wcscmp(tag->attrs[i].name, tag->attrs[j].name)) return TRUE;
    return FALSE;
}

/* A structured query is XML whose first element is QueryList, after any declaration or comment */
static BOOL is_query_list(const WCHAR *query)
{
    struct xml_tag tag;
    const WCHAR *p = query;
    BOOL ret;
    int status;

    if (!query) return FALSE;
    status = next_tag(&p, &tag);
    ret = status == XML_TAG && !tag.closing && !wcscmp(tag.name, L"QueryList");
    if (status == XML_TAG) free_tag(&tag);
    return ret;
}

/* A path of a selection is a file when it is written as a URI of one, and a channel otherwise, whatever the query was opened for */
static BOOL is_file_uri(const WCHAR *path)
{
    return !_wcsnicmp(path, L"file://", 7);
}

static DWORD check_path(const WCHAR *path)
{
    if (!is_file_uri(path)) return check_channel(path);
    path += 7;
    if (!path[0]) return ERROR_EVT_INVALID_CHANNEL_PATH;
    return GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
}

/* The paths that a structured query selects. ERROR_SUCCESS when the query is well formed and all of them exist. */
static DWORD check_query_list(const WCHAR *query)
{
    WCHAR open[XML_MAX_DEPTH][XML_MAX_NAME];
    WCHAR *query_path = NULL;
    const WCHAR *p = query;
    struct xml_tag tag;
    DWORD depth = 0, error = ERROR_SUCCESS;
    BOOL found = FALSE, root = FALSE, select = FALSE;
    int ret;

    while (!error && (ret = next_tag(&p, &tag)) == XML_TAG)
    {
        const WCHAR *path;

        /* text belongs inside the element of a query, not around the document */
        if ((tag.junk && !depth) || has_duplicate_attr(&tag)) error = ERROR_EVT_MALFORMED_XML_TEXT;
        else if (tag.closing)
        {
            if (!depth || wcscmp(open[--depth], tag.name)) error = ERROR_EVT_MALFORMED_XML_TEXT;
            else if (!wcscmp(tag.name, L"Query"))
            {
                free(query_path);
                query_path = NULL;
            }
        }
        else
        {
            if (!depth && root) error = ERROR_EVT_MALFORMED_XML_TEXT;
            else if (!root && wcscmp(tag.name, L"QueryList")) error = ERROR_EVT_INVALID_QUERY;
            root = TRUE;

            path = find_attr(&tag, L"Path");
            if (!error && !wcscmp(tag.name, L"Query"))
            {
                /* the path of a query is the default of its selections, and is looked at when one uses it */
                free(query_path);
                query_path = path ? _wcsdup(path) : NULL;
            }
            else if (!error && (!wcscmp(tag.name, L"Select") || !wcscmp(tag.name, L"Suppress")))
            {
                if (!wcscmp(tag.name, L"Select")) select = TRUE;
                if (!path) path = query_path;
                /* a selection with no path of its own and no default of its query selects nothing */
                if (!path && !wcscmp(tag.name, L"Select")) error = ERROR_EVT_INVALID_QUERY;
                if (path)
                {
                    error = check_path(path);
                    if (error == ERROR_EVT_INVALID_CHANNEL_PATH) error = ERROR_EVT_INVALID_QUERY;
                    found = found || !error;
                }
            }
            if (!error && !tag.empty)
            {
                if (depth == XML_MAX_DEPTH) error = ERROR_EVT_MALFORMED_XML_TEXT;
                else memcpy(open[depth++], tag.name, sizeof(tag.name));
            }
        }
        free_tag(&tag);
    }
    free(query_path);
    if (ret == XML_ERROR) error = ERROR_EVT_MALFORMED_XML_TEXT;
    if (!error && ret == XML_END && tag.junk && !depth) error = ERROR_EVT_MALFORMED_XML_TEXT;
    if (error) return error;
    if (depth || !root) return ERROR_EVT_MALFORMED_XML_TEXT;
    if (!select) return ERROR_INVALID_PARAMETER;
    return found ? ERROR_SUCCESS : ERROR_EVT_INVALID_QUERY;
}

/* The checks of a query, a subscription or an export up to the point where the service is needed */
static DWORD check_query(const WCHAR *path, const WCHAR *query, BOOL file)
{
    /* a structured query names its channels or files itself, and the path is not looked at, but for one that says it is a file and is empty */
    if (is_query_list(query))
    {
        if (file && path && !path[0]) return ERROR_INVALID_PARAMETER;
        return check_query_list(query);
    }

    if (file)
    {
        if (!path || !path[0]) return ERROR_EVT_INVALID_CHANNEL_PATH;
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return GetLastError();
        return ERROR_SUCCESS;
    }

    if (!path || !path[0]) return ERROR_EVT_INVALID_CHANNEL_PATH;

    if (check_channel(path)) return check_channel(path);
    if (query && !query[0]) return ERROR_EVT_INVALID_QUERY;
    return ERROR_SUCCESS;
}

EVT_HANDLE WINAPI EvtOpenSession(EVT_LOGIN_CLASS login_class, void *login, DWORD timeout, DWORD flags)
{
    EVT_RPC_LOGIN *rpc = login;

    FIXME("(%u %p %lu %lu) semi-stub\n", login_class, login, timeout, flags);

    if (login_class != EvtRpcLogin || !login || flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (rpc->Flags > EvtRpcLoginAuthNTLM)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    return new_object(OBJECT_SESSION, !is_local_server(rpc->Server), NULL);
}

BOOL WINAPI EvtClose(EVT_HANDLE handle)
{
    struct object *object;

    TRACE("(%p)\n", handle);

    EnterCriticalSection(&object_cs);
    object = find_object(handle, 0);
    if (object) list_remove(&object->entry);
    LeaveCriticalSection(&object_cs);

    if (!object) return fail(ERROR_INVALID_HANDLE);
    free_object(object);
    return succeed();
}

BOOL WINAPI EvtCancel(EVT_HANDLE handle)
{
    struct object *object;
    DWORD error = ERROR_SUCCESS;

    TRACE("(%p)\n", handle);

    /* the handles that can be cancelled are queries and subscriptions: a wait of a subscription ends with an error */
    if (!handle) return succeed();
    EnterCriticalSection(&object_cs);
    object = find_object(handle, 0);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if (object->type != OBJECT_QUERY) error = ERROR_NOT_SUPPORTED;
    else if (object->sub) object->sub->cancelled = TRUE;
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

DWORD WINAPI EvtGetExtendedStatus(DWORD size, WCHAR *buffer, DWORD *used)
{
    TRACE("(%lu %p %p)\n", size, buffer, used);

    if (!used) return ERROR_INVALID_PARAMETER;
    *used = 0;
    return ERROR_SUCCESS;
}

/* The channels as they are when the enumeration opens: the classic logs and those that installed manifests register */
static EVT_HANDLE new_channel_enum(void)
{
    struct publisher_enum *list = calloc(1, sizeof(*list));
    EVT_HANDLE handle;

    if (!list)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    list->count = classic_channel_list(&list->names);
    if (!(handle = new_object(OBJECT_CHANNEL_ENUM, FALSE, NULL)))
    {
        classic_names_free(list->names, list->count);
        free(list);
        return NULL;
    }
    ((struct object *)handle)->data = list;
    return handle;
}

EVT_HANDLE WINAPI EvtOpenChannelEnum(EVT_HANDLE session, DWORD flags)
{
    BOOL remote;

    TRACE("(%p %lu)\n", session, flags);

    if (flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!get_session(session, &remote)) return NULL;
    if (remote)
    {
        no_service();
        return NULL;
    }
    return new_channel_enum();
}

BOOL WINAPI EvtNextChannelPath(EVT_HANDLE channel_enum, DWORD buffer_len, WCHAR *buffer, DWORD *used)
{
    struct object *object;
    struct publisher_enum *list;
    DWORD len;
    BOOL ret = FALSE;

    TRACE("(%p %lu %p %p)\n", channel_enum, buffer_len, buffer, used);

    EnterCriticalSection(&object_cs);
    object = find_object(channel_enum, OBJECT_CHANNEL_ENUM);
    if (!object) SetLastError(ERROR_INVALID_HANDLE);
    else if (!used || (buffer_len && !buffer)) SetLastError(ERROR_INVALID_PARAMETER);
    else if (!(list = object->data) || object->index >= list->count) SetLastError(ERROR_NO_MORE_ITEMS);
    else
    {
        len = lstrlenW(list->names[object->index]) + 1;
        *used = len;
        if (buffer_len < len) SetLastError(ERROR_INSUFFICIENT_BUFFER);
        else
        {
            memcpy(buffer, list->names[object->index], len * sizeof(WCHAR));
            object->index++;
            ret = TRUE;
        }
    }
    LeaveCriticalSection(&object_cs);
    if (ret) SetLastError(ERROR_SUCCESS);
    return ret;
}

EVT_HANDLE WINAPI EvtOpenChannelConfig(EVT_HANDLE session, const WCHAR *path, DWORD flags)
{
    DWORD error;
    BOOL remote;

    TRACE("(%p %s %lu)\n", session, debugstr_w(path), flags);

    if (flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!get_session(session, &remote)) return NULL;
    if (!path)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (remote)
    {
        no_service();
        return NULL;
    }
    if ((error = check_channel(path)))
    {
        SetLastError(error);
        return NULL;
    }
    return new_object(OBJECT_CHANNEL_CONFIG, FALSE, path);
}

BOOL WINAPI EvtGetChannelConfigProperty(EVT_HANDLE config, EVT_CHANNEL_CONFIG_PROPERTY_ID id, DWORD flags,
                                        DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct object *object;
    DWORD error;

    TRACE("(%p %i %lu %lu %p %p)\n", config, id, flags, size, buffer, used);

    EnterCriticalSection(&object_cs);
    object = find_object(config, OBJECT_CHANNEL_CONFIG);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if ((int)id < 0 || id >= EvtChannelConfigPropertyIdEND || flags || !used) error = ERROR_INVALID_PARAMETER;
    else error = classic_channel_property(object->name, id, size, buffer, used);
    LeaveCriticalSection(&object_cs);

    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtSetChannelConfigProperty(EVT_HANDLE config, EVT_CHANNEL_CONFIG_PROPERTY_ID id, DWORD flags,
                                        PEVT_VARIANT value)
{
    BOOL found;

    FIXME("(%p %i %lu %p) semi-stub\n", config, id, flags, value);

    EnterCriticalSection(&object_cs);
    found = find_object(config, OBJECT_CHANNEL_CONFIG) != NULL;
    LeaveCriticalSection(&object_cs);

    if (!found) return fail(ERROR_INVALID_HANDLE);
    if ((int)id < 0 || id >= EvtChannelConfigPropertyIdEND || flags || !value) return fail(ERROR_INVALID_PARAMETER);

    /* the registry that backs the channels is not changed through this interface */
    return fail(ERROR_NOT_SUPPORTED);
}

BOOL WINAPI EvtSaveChannelConfig(EVT_HANDLE config, DWORD flags)
{
    BOOL found;

    FIXME("(%p %#lx) semi-stub\n", config, flags);

    EnterCriticalSection(&object_cs);
    found = find_object(config, OBJECT_CHANNEL_CONFIG) != NULL;
    LeaveCriticalSection(&object_cs);

    if (!found) return fail(ERROR_INVALID_HANDLE);
    if (flags) return fail(ERROR_INVALID_PARAMETER);

    /* nothing can have been changed, so there is nothing to save */
    return succeed();
}

/* The selections of a query: those of a structured query, or the one that the path and the query make */
static void free_selects(struct classic_select *selects, DWORD count)
{
    DWORD i;

    for (i = 0; i < count; i++)
    {
        free(selects[i].channel);
        free(selects[i].xpath);
    }
    free(selects);
}

static BOOL add_select(struct classic_select **selects, DWORD *count, const WCHAR *channel, const WCHAR *xpath, DWORD group, BOOL suppress, BOOL file)
{
    struct classic_select *p = realloc(*selects, (*count + 1) * sizeof(*p)), *sel;

    if (!p) return FALSE;
    *selects = p;
    sel = &p[*count];
    memset(sel, 0, sizeof(*sel));
    sel->group = group;
    sel->suppress = suppress;
    sel->file = file;
    if (!(sel->channel = _wcsdup(channel))) return FALSE;
    if (xpath && !(sel->xpath = _wcsdup(xpath))) { free(sel->channel); return FALSE; }
    (*count)++;
    return TRUE;
}

static DWORD build_selects(const WCHAR *path, const WCHAR *query, BOOL file, struct classic_select **selects, DWORD *count)
{
    struct xml_tag tag;
    const WCHAR *p = query;
    WCHAR *query_path = NULL;
    DWORD group = 0;
    DWORD error = ERROR_SUCCESS;

    *selects = NULL;
    *count = 0;
    if (!is_query_list(query))
    {
        if (!add_select(selects, count, path, query, 0, FALSE, file)) error = ERROR_OUTOFMEMORY;
        goto done;
    }

    while (!error && next_tag(&p, &tag) == XML_TAG)
    {
        if (tag.closing)
        {
            if (!wcscmp(tag.name, L"Query"))
            {
                free(query_path);
                query_path = NULL;
            }
        }
        else if (!wcscmp(tag.name, L"Query"))
        {
            const WCHAR *value = find_attr(&tag, L"Path");

            group++;
            free(query_path);
            query_path = value ? _wcsdup(value) : NULL;
        }
        else if (!tag.empty && (!wcscmp(tag.name, L"Select") || !wcscmp(tag.name, L"Suppress")))
        {
            const WCHAR *value = find_attr(&tag, L"Path"), *end = wcschr(p, '<');
            WCHAR *xpath = end ? decode_value(p, end) : NULL;
            BOOL suppress = !wcscmp(tag.name, L"Suppress");

            if (!xpath) error = ERROR_EVT_MALFORMED_XML_TEXT;
            else if (!value) value = query_path;
            if (!error && value && !add_select(selects, count, is_file_uri(value) ? value + 7 : value, xpath, group, suppress,
                                               is_file_uri(value)))
                error = ERROR_OUTOFMEMORY;
            free(xpath);
        }
        free_tag(&tag);
    }
    free(query_path);

done:
    if (error) free_selects(*selects, *count);
    if (error) { *selects = NULL; *count = 0; }
    return error;
}

EVT_HANDLE WINAPI EvtQuery(EVT_HANDLE session, const WCHAR *path, const WCHAR *query, DWORD flags)
{
    struct classic_select *selects;
    struct classic_query *result;
    struct object *object;
    EVT_HANDLE handle;
    DWORD error, count;
    BOOL remote;

    TRACE("(%p %s %s %#lx)\n", session, debugstr_w(path), debugstr_w(query), flags);

    if ((flags & 3) != EvtQueryChannelPath && (flags & 3) != EvtQueryFilePath)
        goto invalid;
    if ((flags & (EvtQueryForwardDirection | EvtQueryReverseDirection)) == (EvtQueryForwardDirection | EvtQueryReverseDirection))
        goto invalid;
    if (flags & ~(0x3 | EvtQueryForwardDirection | EvtQueryReverseDirection | EvtQueryTolerateQueryErrors))
        goto invalid;

    if (!get_session(session, &remote)) return NULL;
    if (remote)
    {
        no_service();
        return NULL;
    }
    if ((error = check_query(path, query, (flags & 3) == EvtQueryFilePath)))
    {
        SetLastError(error);
        return NULL;
    }
    if ((error = build_selects(path, query, (flags & 3) == EvtQueryFilePath, &selects, &count)))
    {
        SetLastError(error);
        return NULL;
    }
    error = classic_query_open(selects, count, (flags & EvtQueryReverseDirection) != 0, &result);
    free_selects(selects, count);
    if (error)
    {
        SetLastError(error);
        return NULL;
    }
    if (!(handle = new_object(OBJECT_QUERY, FALSE, NULL)))
    {
        classic_query_free(result);
        return NULL;
    }
    object = (struct object *)handle;
    object->data = result;
    return handle;

invalid:
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
}

static EVT_HANDLE new_event(EVENTLOGRECORD *rec, struct evtx_event *evtx, const WCHAR *channel)
{
    struct event_data *event = calloc(1, sizeof(*event));
    EVT_HANDLE handle;

    if (!event) return NULL;
    if (!(event->channel = _wcsdup(channel)) || !(handle = new_object(OBJECT_EVENT, FALSE, NULL)))
    {
        free(event->channel);
        free(event);
        return NULL;
    }
    /* the handle owns the record from here */
    event->rec = rec;
    event->evtx = evtx;
    ((struct object *)handle)->data = event;
    return handle;
}

/* Hands out what a subscription has, and waits for more up to the timeout */
static DWORD subscription_next(struct subscription *sub, struct classic_query *query, DWORD size, EVT_HANDLE *array,
                               DWORD timeout, DWORD *ret_count)
{
    DWORD n = 0, error = ERROR_SUCCESS, start = GetTickCount();

    if (sub->callback) return ERROR_INVALID_OPERATION;
    for (;;)
    {
        EnterCriticalSection(&sub->cs);
        if (sub->cancelled)
        {
            sub->cancelled = FALSE;
            LeaveCriticalSection(&sub->cs);
            return ERROR_OPERATION_ABORTED;
        }
        classic_query_poll(query);
        while (n < size)
        {
            const WCHAR *channel;
            struct qevent qe;

            if (!classic_query_next(query, &qe, &channel, &error)) break;
            if (!(array[n] = new_event(qe.rec, qe.evtx, channel)))
            {
                free(qe.rec);
                evtx_event_free(qe.evtx);
                error = ERROR_OUTOFMEMORY;
                break;
            }
            n++;
        }
        LeaveCriticalSection(&sub->cs);
        if (n)
        {
            *ret_count = n;
            return ERROR_SUCCESS;
        }
        if (error == ERROR_OUTOFMEMORY) return error;
        /* the signal of the caller stays up only while there is something to read */
        if (!timeout) return ERROR_NO_MORE_ITEMS;
        if (timeout != INFINITE && GetTickCount() - start >= timeout) return ERROR_TIMEOUT;
        Sleep(50);
    }
}

static DWORD WINAPI subscription_thread(void *param)
{
    struct subscription *sub = param;
    struct classic_query *query = NULL;
    EVT_HANDLE handle = NULL;

    for (;;)
    {
        struct object *object;
        BOOL pending;

        if (WaitForSingleObject(sub->stop, 250) != WAIT_TIMEOUT) break;
        /* the query of the subscription is found through its handle, which the thread was given */
        EnterCriticalSection(&object_cs);
        handle = NULL;
        LIST_FOR_EACH_ENTRY(object, &object_list, struct object, entry)
            if (object->sub == sub) { handle = (EVT_HANDLE)object; query = object->data; break; }
        LeaveCriticalSection(&object_cs);
        if (!handle) continue;

        EnterCriticalSection(&sub->cs);
        pending = classic_query_poll(query);
        if (pending && sub->callback)
        {
            for (;;)
            {
                const WCHAR *channel;
                struct qevent qe;
                DWORD error;
                EVT_HANDLE event;

                if (!classic_query_next(query, &qe, &channel, &error)) break;
                if (!(event = new_event(qe.rec, qe.evtx, channel)))
                {
                    free(qe.rec);
                    evtx_event_free(qe.evtx);
                    break;
                }
                LeaveCriticalSection(&sub->cs);
                sub->callback(EvtSubscribeActionDeliver, sub->context, event);
                EvtClose(event);
                if (WaitForSingleObject(sub->stop, 0) == WAIT_OBJECT_0) return 0;
                EnterCriticalSection(&sub->cs);
            }
        }
        LeaveCriticalSection(&sub->cs);
        if (pending && sub->signal) SetEvent(sub->signal);
    }
    return 0;
}

BOOL WINAPI EvtNext(EVT_HANDLE result_set, DWORD size, EVT_HANDLE *array, DWORD timeout, DWORD flags, DWORD *ret_count)
{
    struct object *object;
    DWORD n = 0, error = ERROR_SUCCESS;

    TRACE("(%p %lu %p %lu %#lx %p)\n", result_set, size, array, timeout, flags, ret_count);

    EnterCriticalSection(&object_cs);
    object = find_object(result_set, OBJECT_QUERY);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if (!array || !ret_count || flags) error = ERROR_INVALID_PARAMETER;
    /* room for no event is room for the end of the results, as far as Windows goes */
    else if (!size) error = ERROR_NO_MORE_ITEMS;
    else if (object->sub)
    {
        struct subscription *sub = object->sub;
        struct classic_query *query = object->data;

        /* the wait must not hold the handles of everyone else */
        LeaveCriticalSection(&object_cs);
        error = subscription_next(sub, query, size, array, timeout, ret_count);
        return error ? fail(error) : succeed();
    }
    else if (object->index)
    {
        /* an error of a damaged file that came behind events that were handed over */
        error = object->index;
        object->index = 0;
    }
    else
    {
        while (n < size)
        {
            const WCHAR *channel;
            struct qevent qe;

            if (!classic_query_next(object->data, &qe, &channel, &error)) break;
            if (!(array[n] = new_event(qe.rec, qe.evtx, channel)))
            {
                free(qe.rec);
                evtx_event_free(qe.evtx);
                error = ERROR_OUTOFMEMORY;
                break;
            }
            n++;
            error = ERROR_SUCCESS;
        }
        /* what was read is handed over, and the end or the error shows with the next call */
        if (n && error != ERROR_SUCCESS && error != ERROR_NO_MORE_ITEMS && error != ERROR_OUTOFMEMORY) object->index = error;
        if (n) error = ERROR_SUCCESS;
        else if (!error) error = ERROR_NO_MORE_ITEMS;
        if (n) *ret_count = n;
    }
    LeaveCriticalSection(&object_cs);

    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtSeek(EVT_HANDLE result_set, LONGLONG position, EVT_HANDLE bookmark, DWORD timeout, DWORD flags)
{
    struct object *object;
    DWORD error, origin = flags & EvtSeekOriginMask;

    TRACE("(%p %s %p %lu %#lx)\n", result_set, wine_dbgstr_longlong(position), bookmark, timeout, flags);

    /* the origin is checked before the handle */
    if (origin < EvtSeekRelativeToFirst || origin > EvtSeekRelativeToBookmark || (flags & ~(EvtSeekOriginMask | EvtSeekStrict)))
        return fail(ERROR_INVALID_PARAMETER);

    EnterCriticalSection(&object_cs);
    object = find_object(result_set, OBJECT_QUERY);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if (object->sub) error = ERROR_INVALID_PARAMETER;
    else if (origin == EvtSeekRelativeToBookmark)
    {
        struct object *mark = bookmark ? find_object(bookmark, OBJECT_BOOKMARK) : NULL;
        DWORD i;

        if (!bookmark) error = ERROR_INVALID_PARAMETER;
        else if (!mark) error = ERROR_INVALID_HANDLE;
        else
        {
            error = ERROR_EVT_QUERY_RESULT_INVALID_POSITION;
            for (i = 0; i < mark->mark_count; i++)
                if (mark->marks[i].has_record_id)
                {
                    error = classic_query_seek(object->data, origin, position, mark->marks[i].channel[0] ? mark->marks[i].channel : NULL,
                                               mark->marks[i].record_id);
                    break;
                }
        }
    }
    else if (bookmark) error = ERROR_INVALID_PARAMETER;
    else error = classic_query_seek(object->data, origin, position, NULL, 0);
    LeaveCriticalSection(&object_cs);

    return error ? fail(error) : succeed();
}

EVT_HANDLE WINAPI EvtSubscribe(EVT_HANDLE session, HANDLE signal_event, const WCHAR *path, const WCHAR *query,
                               EVT_HANDLE bookmark, void *context, EVT_SUBSCRIBE_CALLBACK callback, DWORD flags)
{
    DWORD error, count, mark_count = 0, origin = flags & EvtSubscribeOriginMask;
    struct classic_select *selects;
    struct classic_mark *marks = NULL;
    struct classic_query *result;
    struct subscription *sub;
    struct object *object;
    EVT_HANDLE handle;
    BOOL remote, found;

    TRACE("(%p %p %s %s %p %p %p %#lx)\n", session, signal_event, debugstr_w(path), debugstr_w(query),
          bookmark, context, callback, flags);

    if (!origin || (!signal_event && !callback) || (signal_event && callback) ||
        (flags & ~(EvtSubscribeOriginMask | EvtSubscribeTolerateQueryErrors | EvtSubscribeStrict)))
        goto invalid;
    if ((origin == EvtSubscribeStartAfterBookmark) != (bookmark != NULL))
        goto invalid;

    if (!get_session(session, &remote)) return NULL;
    if (bookmark)
    {
        DWORD i;

        EnterCriticalSection(&object_cs);
        object = find_object(bookmark, OBJECT_BOOKMARK);
        found = object != NULL;
        if (found && object->mark_count && (marks = calloc(object->mark_count, sizeof(*marks))))
        {
            /* the channels and numbers are copied, as the bookmark may be closed while the subscription goes on */
            for (i = 0; i < object->mark_count; i++)
                if (object->marks[i].has_record_id && object->marks[i].channel[0] && (marks[mark_count].channel = _wcsdup(object->marks[i].channel)))
                    marks[mark_count++].record_id = object->marks[i].record_id;
        }
        LeaveCriticalSection(&object_cs);
        if (!found)
        {
            SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
    }
    if (remote)
    {
        no_service();
        error = ERROR_SUCCESS;
        goto fail_marks;
    }
    if ((error = check_query(path, query, FALSE))) goto fail_marks;
    if ((error = build_selects(path, query, FALSE, &selects, &count))) goto fail_marks;
    error = classic_query_open(selects, count, FALSE, &result);
    free_selects(selects, count);
    if (error) goto fail_marks;
    if ((error = classic_query_follow(result, origin == EvtSubscribeStartAtOldestRecord ? CLASSIC_FOLLOW_OLDEST :
                                      origin == EvtSubscribeStartAfterBookmark ? CLASSIC_FOLLOW_BOOKMARK : CLASSIC_FOLLOW_FUTURE,
                                      marks, mark_count)))
    {
        classic_query_free(result);
        goto fail_marks;
    }
    while (mark_count) free((WCHAR *)marks[--mark_count].channel);
    free(marks);
    marks = NULL;

    if (!(sub = calloc(1, sizeof(*sub))))
    {
        classic_query_free(result);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    InitializeCriticalSection(&sub->cs);
    sub->signal = signal_event;
    sub->callback = callback;
    sub->context = context;
    sub->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!sub->stop || !(handle = new_object(OBJECT_QUERY, FALSE, NULL)))
    {
        if (sub->stop) CloseHandle(sub->stop);
        DeleteCriticalSection(&sub->cs);
        free(sub);
        classic_query_free(result);
        return NULL;
    }
    object = (struct object *)handle;
    object->data = result;
    object->sub = sub;
    if (!(sub->thread = CreateThread(NULL, 0, subscription_thread, sub, 0, &sub->thread_id)))
    {
        error = GetLastError();
        EnterCriticalSection(&object_cs);
        list_remove(&object->entry);
        LeaveCriticalSection(&object_cs);
        free_object(object);
        SetLastError(error);
        return NULL;
    }
    return handle;

fail_marks:
    while (mark_count) free((WCHAR *)marks[--mark_count].channel);
    free(marks);
    if (error) SetLastError(error);
    return NULL;

invalid:
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
}

EVT_HANDLE WINAPI EvtOpenLog(EVT_HANDLE session, const WCHAR *path, DWORD flags)
{
    DWORD error;
    BOOL remote;
    EVT_HANDLE handle;

    TRACE("(%p %s %#lx)\n", session, debugstr_w(path), flags);

    if ((flags != EvtOpenChannelPath && flags != EvtOpenFilePath) || !path)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!get_session(session, &remote)) return NULL;
    if (remote)
    {
        no_service();
        return NULL;
    }
    if (flags == EvtOpenFilePath)
        error = check_query(path, NULL, TRUE);
    else
        error = check_channel(path);
    if (error)
    {
        SetLastError(error);
        return NULL;
    }
    handle = new_object(OBJECT_LOG, FALSE, path);
    /* the log of a file: what it is asked for is the file's */
    if (handle && flags == EvtOpenFilePath) ((struct object *)handle)->index = 1;
    return handle;
}

BOOL WINAPI EvtGetLogInfo(EVT_HANDLE log, EVT_LOG_PROPERTY_ID id, DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct object *object;
    DWORD error;

    TRACE("(%p %i %lu %p %p)\n", log, id, size, buffer, used);

    EnterCriticalSection(&object_cs);
    object = find_object(log, OBJECT_LOG);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if ((int)id < 0 || id >= EvtLogPropertyIdEND || !used) error = ERROR_INVALID_PARAMETER;
    else if (object->index) error = classic_file_log_property(object->name, id, size, buffer, used);
    else error = classic_log_property(object->name, id, size, buffer, used);
    LeaveCriticalSection(&object_cs);

    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtGetQueryInfo(EVT_HANDLE query, EVT_QUERY_PROPERTY_ID id, DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct object *object;
    DWORD error;

    TRACE("(%p %i %lu %p %p)\n", query, id, size, buffer, used);

    EnterCriticalSection(&object_cs);
    object = find_object(query, OBJECT_QUERY);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if (!used || (id != EvtQueryNames && id != EvtQueryStatuses)) error = ERROR_INVALID_PARAMETER;
    else if (id == EvtQueryNames) error = classic_query_names(object->data, size, buffer, used);
    else error = classic_query_statuses(object->data, size, buffer, used);
    LeaveCriticalSection(&object_cs);

    return error ? fail(error) : succeed();
}

/* The events that the selection gives, into a new .evtx file */
static DWORD export_events(const WCHAR *path, const WCHAR *query, BOOL file_path, const WCHAR *file, BOOL overwrite, BOOL tolerate)
{
    struct classic_select *selects;
    struct classic_query *result;
    struct evtx_writer *writer;
    ULONGLONG number = 0;
    DWORD error, count, e;

    if ((error = build_selects(path, query, file_path, &selects, &count))) return error;
    error = classic_query_open(selects, count, FALSE, &result);
    free_selects(selects, count);
    if (error) return error;
    if ((error = evtx_create(file, overwrite, &writer)))
    {
        classic_query_free(result);
        return error;
    }
    for (;;)
    {
        const WCHAR *channel;
        struct qevent qe;
        struct classic_event event;
        WCHAR *xml;

        if (!classic_query_next(result, &qe, &channel, &e))
        {
            if (e == ERROR_NO_MORE_ITEMS) break;
            if (e == ERROR_OUTOFMEMORY || !tolerate) { error = e; break; }
            continue;
        }
        if (qe.evtx ? !classic_event_from_evtx(&event, qe.evtx) : !classic_event_init(&event, qe.rec, channel))
            error = ERROR_OUTOFMEMORY;
        else
        {
            if (!(xml = classic_render_xml(&event, NULL))) error = ERROR_OUTOFMEMORY;
            else
            {
                error = evtx_add_xml(writer, ++number, event.time, xml);
                free(xml);
            }
            classic_event_free(&event);
        }
        free(qe.rec);
        evtx_event_free(qe.evtx);
        if (error) break;
    }
    classic_query_free(result);
    e = evtx_finish(writer, !error);
    return error ? error : e;
}

BOOL WINAPI EvtExportLog(EVT_HANDLE session, const WCHAR *path, const WCHAR *query, const WCHAR *file, DWORD flags)
{
    DWORD error;
    BOOL remote;

    TRACE("(%p %s %s %s %#lx)\n", session, debugstr_w(path), debugstr_w(query), debugstr_w(file), flags);

    if ((flags & 3) != EvtExportLogChannelPath && (flags & 3) != EvtExportLogFilePath)
        return fail(ERROR_INVALID_PARAMETER);
    if (flags & ~(0x3 | EvtExportLogTolerateQueryErrors | EvtExportLogOverwrite))
        return fail(ERROR_INVALID_PARAMETER);
    if (!get_session(session, &remote)) return FALSE;
    if (remote) return no_service();
    if ((error = check_query(path, query, (flags & 3) == EvtExportLogFilePath))) return fail(error);
    if (!file) return fail(ERROR_INVALID_PARAMETER);
    error = export_events(path, query, (flags & 3) == EvtExportLogFilePath, file, (flags & EvtExportLogOverwrite) != 0,
                          (flags & EvtExportLogTolerateQueryErrors) != 0);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtClearLog(EVT_HANDLE session, const WCHAR *path, const WCHAR *file, DWORD flags)
{
    DWORD error;
    HANDLE log;
    BOOL remote, ret;

    TRACE("(%p %s %s %#lx)\n", session, debugstr_w(path), debugstr_w(file), flags);

    if (flags) return fail(ERROR_INVALID_PARAMETER);
    if (!get_session(session, &remote)) return FALSE;
    if (remote) return no_service();
    if ((error = check_channel(path))) return fail(error);
    /* the log is copied to an .evtx file before it is cleared, and a copy that cannot be made keeps the log as it is */
    if (file && (error = export_events(path, NULL, FALSE, file, FALSE, FALSE))) return fail(error);
    /* a channel that only a manifest registers has no records to clear */
    if (!(log = OpenEventLogW(NULL, path)))
    {
        if ((error = GetLastError()) && classic_registered_channel(path)) return succeed();
        return fail(error);
    }
    ret = ClearEventLogW(log, NULL);
    error = ret ? ERROR_SUCCESS : GetLastError();
    CloseEventLog(log);
    return error ? fail(error) : succeed();
}

EVT_HANDLE WINAPI EvtCreateRenderContext(DWORD count, const WCHAR **paths, DWORD flags)
{
    struct render_context *context;
    EVT_HANDLE handle;
    DWORD i;

    TRACE("(%lu %p %#lx)\n", count, paths, flags);

    if (flags == EvtRenderContextValues)
    {
        if (!count || !paths) goto invalid;
        for (i = 0; i < count; i++)
            if (!paths[i] || !paths[i][0]) goto invalid;
    }
    else if (flags == EvtRenderContextSystem || flags == EvtRenderContextUser)
    {
        if (count || paths) goto invalid;
    }
    else goto invalid;

    if (!(context = calloc(1, sizeof(*context)))) goto nomem;
    context->flags = flags;
    context->count = count;
    if (count)
    {
        if (!(context->indexes = calloc(count, sizeof(*context->indexes)))) { free(context); goto nomem; }
        for (i = 0; i < count; i++) context->indexes[i] = classic_value_index(paths[i]);
    }
    if (!(handle = new_object(OBJECT_RENDER_CONTEXT, FALSE, NULL)))
    {
        free(context->indexes);
        free(context);
        return NULL;
    }
    ((struct object *)handle)->data = context;
    return handle;

invalid:
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;

nomem:
    SetLastError(ERROR_OUTOFMEMORY);
    return NULL;
}

/* A bookmark list in the format that Windows writes: Bookmark elements with up to three attributes */

enum { BOOKMARK_OK, BOOKMARK_MALFORMED, BOOKMARK_INVALID };

/* The digits at the start of a record number; no digit makes zero, and a number that is too large is the largest one */
static ULONGLONG parse_record_id(const WCHAR *text)
{
    ULONGLONG number = 0;

    for (; *text >= '0' && *text <= '9'; text++)
    {
        if (number > (MAXLONGLONG - (*text - '0')) / 10) return MAXLONGLONG;
        number = number * 10 + (*text - '0');
    }
    return number;
}

static BOOL is_channel_text(const WCHAR *name)
{
    for (; *name; name++)
        if (is_bad_channel_char(*name) || *name == '\'') return FALSE;
    return TRUE;
}

static void free_marks(struct bookmark_entry *marks, DWORD count)
{
    DWORD i;

    for (i = 0; i < count; i++)
        free(marks[i].channel);
    free(marks);
}

static int parse_bookmark_list(const WCHAR *xml, struct bookmark_entry **marks, DWORD *count, WCHAR **direction)
{
    struct bookmark_entry *list = NULL, *entry;
    const WCHAR *p = xml, *value;
    struct xml_tag tag;
    BOOL root = FALSE, closed = FALSE;
    DWORD n = 0, i;
    int ret, result = BOOKMARK_MALFORMED;

    *marks = NULL;
    *count = 0;
    *direction = NULL;

    while ((ret = next_tag(&p, &tag)) == XML_TAG)
    {
        int status = BOOKMARK_INVALID;

        if (tag.junk) { free_tag(&tag); result = BOOKMARK_MALFORMED; goto done; }
        if (closed || has_duplicate_attr(&tag)) goto invalid;

        if (!root)
        {
            if (tag.closing || wcscmp(tag.name, L"BookmarkList")) goto invalid;
            for (i = 0; i < tag.attr_count; i++)
                if (wcscmp(tag.attrs[i].name, L"Direction")) goto invalid;
            if ((value = find_attr(&tag, L"Direction")) && !(*direction = _wcsdup(value))) goto invalid;
            root = TRUE;
            closed = tag.empty;
        }
        else if (tag.closing)
        {
            if (wcscmp(tag.name, L"BookmarkList")) goto invalid;
            closed = TRUE;
        }
        else if (!wcscmp(tag.name, L"Bookmark") && tag.empty)
        {
            if (!(entry = realloc(list, (n + 1) * sizeof(*list)))) goto invalid;
            list = entry;
            entry = &list[n++];
            memset(entry, 0, sizeof(*entry));

            value = find_attr(&tag, L"Channel");
            if (value && !is_channel_text(value)) goto invalid;
            if (!(entry->channel = _wcsdup(value ? value : L""))) goto invalid;
            if ((value = find_attr(&tag, L"RecordId")))
            {
                entry->record_id = parse_record_id(value);
                entry->has_record_id = TRUE;
            }
            if ((value = find_attr(&tag, L"IsCurrent")))
            {
                if (wcscmp(value, L"true") && wcscmp(value, L"false")) goto invalid;
                entry->is_current = !wcscmp(value, L"true");
                entry->has_is_current = TRUE;
            }
        }
        else goto invalid;

        free_tag(&tag);
        continue;

    invalid:
        free_tag(&tag);
        result = status;
        goto done;
    }
    /* text without a list at all, text that is cut off or text that is not XML */
    if (ret == XML_END && root && closed && !tag.junk) result = BOOKMARK_OK;

done:
    if (result != BOOKMARK_OK)
    {
        free_marks(list, n);
        free(*direction);
        *direction = NULL;
        return result;
    }
    *marks = list;
    *count = n;
    return BOOKMARK_OK;
}

EVT_HANDLE WINAPI EvtCreateBookmark(const WCHAR *bookmark_xml)
{
    struct bookmark_entry *marks = NULL;
    WCHAR *direction = NULL;
    DWORD count = 0;
    struct object *object;
    EVT_HANDLE handle;
    int result;

    TRACE("(%s)\n", debugstr_w(bookmark_xml));

    if (bookmark_xml && (result = parse_bookmark_list(bookmark_xml, &marks, &count, &direction)))
    {
        SetLastError(result == BOOKMARK_MALFORMED ? ERROR_EVT_MALFORMED_XML_TEXT : ERROR_INVALID_PARAMETER);
        return NULL;
    }

    if (!(handle = new_object(OBJECT_BOOKMARK, FALSE, NULL)))
    {
        free_marks(marks, count);
        free(direction);
        return NULL;
    }
    object = (struct object *)handle;
    object->marks = marks;
    object->mark_count = count;
    object->direction = direction;
    return handle;
}

struct builder
{
    WCHAR *buf;   /* NULL to only measure */
    SIZE_T len;
};

static void add_text(struct builder *b, const WCHAR *text)
{
    SIZE_T len = lstrlenW(text);

    if (b->buf) memcpy(b->buf + b->len, text, len * sizeof(WCHAR));
    b->len += len;
}

/* The text of an attribute value, with the characters that XML reserves written as references */
static void add_escaped(struct builder *b, const WCHAR *text)
{
    for (; *text; text++)
    {
        switch (*text)
        {
        case '&': add_text(b, L"&amp;"); break;
        case '<': add_text(b, L"&lt;"); break;
        case '>': add_text(b, L"&gt;"); break;
        case '\'': add_text(b, L"&apos;"); break;
        case '"': add_text(b, L"&quot;"); break;
        default:
            if (b->buf) b->buf[b->len] = *text;
            b->len++;
        }
    }
}

static void add_number(struct builder *b, ULONGLONG value)
{
    WCHAR digits[24], *p = digits + ARRAY_SIZE(digits) - 1;

    *p = 0;
    do *--p = '0' + (value % 10); while ((value /= 10));
    add_text(b, p);
}

/* The XML that Windows renders for a bookmark. Returns its length in characters. */
static SIZE_T render_bookmark(const struct object *bookmark, WCHAR *out)
{
    struct builder b = { out, 0 };
    DWORD i;

    add_text(&b, L"<BookmarkList");
    if (bookmark->direction)
    {
        add_text(&b, L" Direction='");
        add_escaped(&b, bookmark->direction);
        add_text(&b, L"'");
    }
    add_text(&b, L">\r\n");
    for (i = 0; i < bookmark->mark_count; i++)
    {
        const struct bookmark_entry *entry = &bookmark->marks[i];

        add_text(&b, L"  <Bookmark Channel='");
        add_escaped(&b, entry->channel);
        add_text(&b, L"'");
        if (entry->has_record_id)
        {
            add_text(&b, L" RecordId='");
            add_number(&b, entry->record_id);
            add_text(&b, L"'");
        }
        if (entry->has_is_current)
            add_text(&b, entry->is_current ? L" IsCurrent='true'" : L" IsCurrent='false'");
        add_text(&b, L"/>\r\n");
    }
    add_text(&b, L"</BookmarkList>");
    if (out) out[b.len] = 0;
    return b.len;
}

/* The event that a handle names, as the library sees it. The caller holds the lock and frees what is in it. */
static BOOL get_event(EVT_HANDLE handle, struct classic_event *event)
{
    struct object *object = find_object(handle, OBJECT_EVENT);
    struct event_data *data;

    if (!object) return FALSE;
    data = object->data;
    if (data->evtx) return classic_event_from_evtx(event, data->evtx);
    return classic_event_init(event, data->rec, data->channel);
}

BOOL WINAPI EvtRender(EVT_HANDLE context, EVT_HANDLE fragment, DWORD flags, DWORD buffer_size, void *buffer,
                      DWORD *buffer_used, DWORD *property_count)
{
    struct object *object;
    DWORD needed, error = ERROR_SUCCESS, dummy;

    TRACE("(%p %p %#lx %lu %p %p %p)\n", context, fragment, flags, buffer_size, buffer, buffer_used, property_count);

    if (!property_count) property_count = &dummy;

    EnterCriticalSection(&object_cs);
    if (flags > EvtRenderBookmark || !buffer_used || (buffer_size && !buffer)) error = ERROR_INVALID_PARAMETER;
    else if (flags == EvtRenderEventValues && !context) error = ERROR_INVALID_PARAMETER;
    else if (flags == EvtRenderBookmark && context) error = ERROR_INVALID_PARAMETER;
    else if (flags == EvtRenderBookmark)
    {
        if (!(object = find_object(fragment, OBJECT_BOOKMARK))) error = ERROR_INVALID_HANDLE;
        else
        {
            SIZE_T length = render_bookmark(object, NULL);

            if (length >= MAXDWORD / sizeof(WCHAR)) error = ERROR_NOT_ENOUGH_MEMORY;
            else
            {
                needed = (length + 1) * sizeof(WCHAR);
                *buffer_used = needed;
                *property_count = 0;
                if (buffer_size < needed) error = ERROR_INSUFFICIENT_BUFFER;
                else render_bookmark(object, buffer);
            }
        }
    }
    else
    {
        struct classic_event event;

        /* the other fragments are events, and only an event is rendered as values or as XML */
        if (!get_event(fragment, &event))
            error = find_object(fragment, OBJECT_EVENT) ? ERROR_INVALID_DATA : ERROR_INVALID_HANDLE;
        else
        {
            if (flags == EvtRenderEventXml)
            {
                WCHAR *xml = classic_render_xml(&event, NULL);

                if (!xml) error = ERROR_OUTOFMEMORY;
                else
                {
                    needed = (lstrlenW(xml) + 1) * sizeof(WCHAR);
                    *buffer_used = needed;
                    *property_count = 0;
                    if (buffer_size < needed) error = ERROR_INSUFFICIENT_BUFFER;
                    else memcpy(buffer, xml, needed);
                    free(xml);
                }
            }
            else
            {
                struct object *ctx = find_object(context, OBJECT_RENDER_CONTEXT);

                if (!ctx) error = ERROR_INVALID_HANDLE;
                else
                {
                    struct render_context *rc = ctx->data;

                    error = classic_render_values(rc->flags, (const DWORD *)rc->indexes, rc->count, &event, buffer_size,
                                                  buffer, buffer_used, property_count);
                }
            }
            classic_event_free(&event);
        }
    }
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtUpdateBookmark(EVT_HANDLE bookmark, EVT_HANDLE event)
{
    struct object *object;
    struct classic_event ev;
    DWORD i, error = ERROR_SUCCESS;

    TRACE("(%p %p)\n", bookmark, event);

    EnterCriticalSection(&object_cs);
    if (!(object = find_object(bookmark, OBJECT_BOOKMARK)) || !get_event(event, &ev)) error = ERROR_INVALID_HANDLE;
    else
    {
        struct bookmark_entry *entry = NULL;

        /* a bookmark has one place in each log, and the one that was set last is the current one */
        for (i = 0; i < object->mark_count; i++)
            if (!_wcsicmp(object->marks[i].channel, ev.channel)) entry = &object->marks[i];
        if (!entry)
        {
            struct bookmark_entry *marks = realloc(object->marks, (object->mark_count + 1) * sizeof(*marks));
            WCHAR *channel = _wcsdup(ev.channel);

            if (!marks || !channel)
            {
                free(channel);
                if (marks) object->marks = marks;
                error = ERROR_OUTOFMEMORY;
            }
            else
            {
                object->marks = marks;
                entry = &marks[object->mark_count++];
                memset(entry, 0, sizeof(*entry));
                entry->channel = channel;
            }
        }
        if (entry)
        {
            for (i = 0; i < object->mark_count; i++)
            {
                object->marks[i].is_current = FALSE;
                object->marks[i].has_is_current = TRUE;
            }
            entry->record_id = ev.record_id;
            entry->has_record_id = TRUE;
            entry->is_current = TRUE;
        }
        classic_event_free(&ev);
    }
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

EVT_HANDLE WINAPI EvtOpenPublisherEnum(EVT_HANDLE session, DWORD flags)
{
    struct publisher_enum *list;
    EVT_HANDLE handle;
    BOOL remote;

    TRACE("(%p %#lx)\n", session, flags);

    if (flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!get_session(session, &remote)) return NULL;
    if (remote)
    {
        no_service();
        return NULL;
    }
    if (!(list = calloc(1, sizeof(*list))))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    /* the sources that the logs register, as they are when the enumeration opens */
    list->count = classic_pub_list(&list->names);
    if (!(handle = new_object(OBJECT_PUBLISHER_ENUM, FALSE, NULL)))
    {
        classic_names_free(list->names, list->count);
        free(list);
        return NULL;
    }
    ((struct object *)handle)->data = list;
    return handle;
}

BOOL WINAPI EvtNextPublisherId(EVT_HANDLE publisher_enum, DWORD buffer_len, WCHAR *buffer, DWORD *used)
{
    struct object *object;
    struct publisher_enum *list;
    DWORD len, error = ERROR_SUCCESS;

    TRACE("(%p %lu %p %p)\n", publisher_enum, buffer_len, buffer, used);

    EnterCriticalSection(&object_cs);
    if (!(object = find_object(publisher_enum, OBJECT_PUBLISHER_ENUM))) error = ERROR_INVALID_HANDLE;
    else if (!used || (buffer_len && !buffer)) error = ERROR_INVALID_PARAMETER;
    else
    {
        list = object->data;
        if (object->index >= list->count) error = ERROR_NO_MORE_ITEMS;
        else
        {
            len = lstrlenW(list->names[object->index]) + 1;
            *used = len;
            if (buffer_len < len) error = ERROR_INSUFFICIENT_BUFFER;
            else
            {
                memcpy(buffer, list->names[object->index], len * sizeof(WCHAR));
                object->index++;
            }
        }
    }
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

EVT_HANDLE WINAPI EvtOpenPublisherMetadata(EVT_HANDLE session, const WCHAR *publisher, const WCHAR *log_file,
                                           LCID locale, DWORD flags)
{
    struct classic_pub *pub;
    EVT_HANDLE handle;
    BOOL remote;

    TRACE("(%p %s %s %#lx %#lx)\n", session, debugstr_w(publisher), debugstr_w(log_file), locale, flags);

    if (flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!get_session(session, &remote)) return NULL;
    if (remote)
    {
        no_service();
        return NULL;
    }
    if (log_file)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    /* no name is the publisher of the standard messages, which is what the text of a level or a task comes from */
    pub = publisher ? classic_pub_open(publisher) : classic_pub_default();
    if (!pub)
    {
        /* a publisher that no log registers has no manifest, and Windows reports that as a missing file */
        SetLastError(publisher ? ERROR_FILE_NOT_FOUND : ERROR_OUTOFMEMORY);
        return NULL;
    }
    if (!(handle = new_object(OBJECT_PUBLISHER, FALSE, NULL)))
    {
        classic_pub_free(pub);
        return NULL;
    }
    ((struct object *)handle)->data = pub;
    return handle;
}

/* A handle for an array of a publisher: its channel references, or its levels, tasks, opcodes and keywords */
static EVT_HANDLE new_array(enum array_kind kind, const struct classic_pub *pub, DWORD man_kind)
{
    struct array_data *array = calloc(1, sizeof(*array));
    EVT_HANDLE handle;
    DWORD i;

    if (!array) return NULL;
    array->kind = kind;
    if (kind == ARRAY_MANIFEST)
    {
        array->manifest = manifest_ref(pub->manifest);
        array->man_kind = man_kind;
        array->count = classic_manifest_array_size(array->manifest, man_kind);
    }
    if (kind == ARRAY_CHANNELS)
    {
        array->manifest = manifest_ref(pub->manifest);
        if (!(array->items = calloc(pub->log_count ? pub->log_count : 1, sizeof(*array->items)))) { manifest_free(array->manifest); free(array); return NULL; }
        for (i = 0; i < pub->log_count; i++)
        {
            if (!(array->items[i] = _wcsdup(pub->logs[i]))) break;
            array->count++;
        }
        if (array->count != pub->log_count)
        {
            classic_names_free(array->items, array->count);
            manifest_free(array->manifest);
            free(array);
            return NULL;
        }
    }
    if (!(handle = new_object(OBJECT_ARRAY, FALSE, NULL)))
    {
        if (array->items) classic_names_free(array->items, array->count);
        manifest_free(array->manifest);
        free(array);
        return NULL;
    }
    ((struct object *)handle)->data = array;
    return handle;
}

BOOL WINAPI EvtGetPublisherMetadataProperty(EVT_HANDLE metadata, EVT_PUBLISHER_METADATA_PROPERTY_ID id, DWORD flags, DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct object *object;
    DWORD error = ERROR_SUCCESS;

    TRACE("(%p %u %#lx %lu %p %p)\n", metadata, id, flags, size, buffer, used);

    EnterCriticalSection(&object_cs);
    if (!(object = find_object(metadata, OBJECT_PUBLISHER))) error = ERROR_INVALID_HANDLE;
    else if ((int)id < 0 || id >= EvtPublisherMetadataPropertyIdEND || flags || !used) error = ERROR_INVALID_PARAMETER;
    else if (id == EvtPublisherMetadataChannelReferences || id == EvtPublisherMetadataLevels ||
             id == EvtPublisherMetadataTasks || id == EvtPublisherMetadataOpcodes || id == EvtPublisherMetadataKeywords)
    {
        *used = sizeof(EVT_VARIANT);
        if (size < sizeof(EVT_VARIANT) || !buffer) error = ERROR_INSUFFICIENT_BUFFER;
        else
        {
            struct classic_pub *pub = object->data;
            BOOL manifest = pub->manifest && id != EvtPublisherMetadataChannelReferences;
            EVT_HANDLE array = new_array(id == EvtPublisherMetadataChannelReferences ? ARRAY_CHANNELS : manifest ? ARRAY_MANIFEST : ARRAY_EMPTY,
                                         pub, id == EvtPublisherMetadataLevels ? MAN_LEVELS : id == EvtPublisherMetadataTasks ? MAN_TASKS :
                                         id == EvtPublisherMetadataOpcodes ? MAN_OPCODES : MAN_KEYWORDS);

            if (!array) error = ERROR_OUTOFMEMORY;
            else
            {
                buffer->UInt64Val = 0;
                buffer->EvtHandleVal = array;
                buffer->Type = EvtVarTypeEvtHandle;
            }
        }
    }
    else error = classic_pub_property(object->data, id, size, buffer, used);
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtFormatMessage(EVT_HANDLE metadata, EVT_HANDLE event, DWORD message_id, DWORD count, PEVT_VARIANT values,
                             DWORD flags, DWORD size, WCHAR *buffer, DWORD *used)
{
    struct object *object;
    struct classic_event ev;
    WCHAR *text = NULL;
    DWORD length = 0, error = ERROR_SUCCESS;
    BOOL have_event = FALSE;

    TRACE("(%p %p %lu %lu %p %#lx %lu %p %p)\n", metadata, event, message_id, count, values, flags, size, buffer, used);

    EnterCriticalSection(&object_cs);
    object = metadata ? find_object(metadata, OBJECT_PUBLISHER) : NULL;
    if (flags < EvtFormatMessageEvent || flags > EvtFormatMessageXml || !used || (size && !buffer) || (count && !values))
        error = ERROR_INVALID_PARAMETER;
    else if (event && !(have_event = get_event(event, &ev))) error = ERROR_INVALID_HANDLE;
    else if (!object && !(flags == EvtFormatMessageXml && !metadata)) error = ERROR_INVALID_HANDLE;
    else if (!object)
    {
        /* with no publisher, the XML of an event has nothing but the event in it */
        if (!(text = classic_render_xml(&ev, NULL))) error = ERROR_OUTOFMEMORY;
        else length = lstrlenW(text) + 1;
    }
    else error = classic_format(object->data, have_event ? &ev : NULL, message_id, flags, count, values, &text, &length);

    if (!error)
    {
        *used = length;
        if (size < length) error = ERROR_INSUFFICIENT_BUFFER;
        else memcpy(buffer, text, length * sizeof(WCHAR));
    }
    free(text);
    if (have_event) classic_event_free(&ev);
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtGetEventInfo(EVT_HANDLE event, EVT_EVENT_PROPERTY_ID id, DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct classic_event ev;
    DWORD error;

    TRACE("(%p %u %lu %p %p)\n", event, id, size, buffer, used);

    EnterCriticalSection(&object_cs);
    if (!get_event(event, &ev)) error = ERROR_INVALID_HANDLE;
    else
    {
        if ((int)id < 0 || id >= EvtEventPropertyIdEND || !used) error = ERROR_INVALID_PARAMETER;
        else error = classic_event_info(&ev, id, size, buffer, used);
        classic_event_free(&ev);
    }
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtGetEventMetadataProperty(EVT_HANDLE metadata, EVT_EVENT_METADATA_PROPERTY_ID id, DWORD flags, DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct object *object;
    DWORD error;

    TRACE("(%p %u %#lx %lu %p %p)\n", metadata, id, flags, size, buffer, used);

    EnterCriticalSection(&object_cs);
    if (!(object = find_object(metadata, OBJECT_EVENT_META))) error = ERROR_INVALID_HANDLE;
    else if ((int)id < 0 || id >= EvtEventMetadataPropertyIdEND || flags || !used) error = ERROR_INVALID_PARAMETER;
    else
    {
        struct event_meta *meta = object->data;

        error = classic_manifest_event_property(meta->manifest, meta->index, id, size, buffer, used);
    }
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

EVT_HANDLE WINAPI EvtOpenEventMetadataEnum(EVT_HANDLE metadata, DWORD flags)
{
    struct object *object;
    struct event_meta *meta;
    EVT_HANDLE handle = NULL;
    DWORD error = ERROR_SUCCESS;

    TRACE("(%p %#lx)\n", metadata, flags);

    EnterCriticalSection(&object_cs);
    object = find_object(metadata, OBJECT_PUBLISHER);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if (flags) error = ERROR_INVALID_PARAMETER;
    else if (!(meta = calloc(1, sizeof(*meta)))) error = ERROR_OUTOFMEMORY;
    else
    {
        /* the sources of the classic logs define no events: their enumeration ends at once */
        meta->manifest = manifest_ref(((struct classic_pub *)object->data)->manifest);
        if (!(handle = new_object(OBJECT_EVENT_ENUM, FALSE, NULL)))
        {
            manifest_free(meta->manifest);
            free(meta);
        }
        else ((struct object *)handle)->data = meta;
    }
    LeaveCriticalSection(&object_cs);
    if (error) SetLastError(error);
    return handle;
}

EVT_HANDLE WINAPI EvtNextEventMetadata(EVT_HANDLE metadata_enum, DWORD flags)
{
    struct object *object;
    struct event_meta *list, *meta;
    EVT_HANDLE handle = NULL;
    DWORD error = ERROR_SUCCESS;

    TRACE("(%p %#lx)\n", metadata_enum, flags);

    EnterCriticalSection(&object_cs);
    object = find_object(metadata_enum, OBJECT_EVENT_ENUM);
    if (!object) error = ERROR_INVALID_HANDLE;
    else if (flags) error = ERROR_INVALID_PARAMETER;
    else
    {
        list = object->data;
        if (!list->manifest || list->index >= list->manifest->event_count) error = ERROR_NO_MORE_ITEMS;
        else if (!(meta = calloc(1, sizeof(*meta)))) error = ERROR_OUTOFMEMORY;
        else
        {
            meta->manifest = manifest_ref(list->manifest);
            meta->index = list->index;
            if (!(handle = new_object(OBJECT_EVENT_META, FALSE, NULL)))
            {
                manifest_free(meta->manifest);
                free(meta);
            }
            else
            {
                ((struct object *)handle)->data = meta;
                list->index++;
            }
        }
    }
    LeaveCriticalSection(&object_cs);
    if (error) SetLastError(error);
    return handle;
}

BOOL WINAPI EvtGetObjectArraySize(HANDLE array, DWORD *size)
{
    struct object *object;
    DWORD error = ERROR_SUCCESS;

    TRACE("(%p %p)\n", array, size);

    EnterCriticalSection(&object_cs);
    if (!(object = find_object(array, OBJECT_ARRAY))) error = ERROR_INVALID_HANDLE;
    else if (!size) error = ERROR_INVALID_PARAMETER;
    else *size = ((struct array_data *)object->data)->count;
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtGetObjectArrayProperty(HANDLE array, DWORD id, DWORD index, DWORD flags, DWORD size, PEVT_VARIANT buffer, DWORD *used)
{
    struct object *object;
    struct array_data *data;
    DWORD error = ERROR_SUCCESS;

    TRACE("(%p %lu %lu %#lx %lu %p %p)\n", array, id, index, flags, size, buffer, used);

    EnterCriticalSection(&object_cs);
    if (!(object = find_object(array, OBJECT_ARRAY))) error = ERROR_INVALID_HANDLE;
    else if (flags || !used) error = ERROR_INVALID_PARAMETER;
    else
    {
        data = object->data;
        if (data->kind == ARRAY_MANIFEST) error = classic_manifest_array_property(data->manifest, data->man_kind, index, id, size, buffer, used);
        else if (data->kind != ARRAY_CHANNELS || id < EvtPublisherMetadataChannelReferencePath || id > EvtPublisherMetadataChannelReferenceMessageID)
            error = ERROR_INVALID_PARAMETER;
        else if (index >= data->count) error = ERROR_NO_MORE_ITEMS;
        else if (data->manifest) error = classic_manifest_channel_property(data->manifest, data->items[index], index, id, size, buffer, used);
        else error = classic_array_property(data->items[index], index, id, size, buffer, used);
    }
    LeaveCriticalSection(&object_cs);
    return error ? fail(error) : succeed();
}

BOOL WINAPI EvtSetObjectArrayProperty(HANDLE array, DWORD id, DWORD index, DWORD flags, PEVT_VARIANT value)
{
    FIXME("(%p %lu %lu %#lx %p) semi-stub\n", array, id, index, flags, value);
    return fail(ERROR_INVALID_HANDLE);
}

BOOL WINAPI EvtArchiveExportedLog(EVT_HANDLE session, const WCHAR *path, LCID locale, DWORD flags)
{
    BOOL remote;

    TRACE("(%p %s %#lx %#lx)\n", session, debugstr_w(path), locale, flags);

    if (flags || !path) return fail(ERROR_INVALID_PARAMETER);
    if (!get_session(session, &remote)) return FALSE;
    if (remote) return no_service();
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return FALSE;
    /* the archive is a folder of metadata files in a format that this library does not write */
    return fail(ERROR_NOT_SUPPORTED);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(instance);
        break;
    case DLL_PROCESS_DETACH:
        if (!reserved)
        {
            struct object *object, *next;

            LIST_FOR_EACH_ENTRY_SAFE(object, next, &object_list, struct object, entry)
            {
                list_remove(&object->entry);
                free_object(object);
            }
            DeleteCriticalSection(&object_cs);
        }
        break;
    }
    return TRUE;
}
