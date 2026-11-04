/*
 * Classic event log backend of wevtapi: the records of the logs that the eventlog service keeps
 * (Application, System, Security and the logs that others register), seen as events.
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

#ifndef __WEVTAPI_PRIVATE_H
#define __WEVTAPI_PRIVATE_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winerror.h"
#include "winevt.h"

/* The ways that a name or a value in a record's text can be limited */
#define EVT_MAX_XPATH_LEN   (64 * 1024)
#define EVT_MAX_XPATH_DEPTH 64

/* xpath.c: the subset of XPath 1.0 that event queries use, over the XML of one event */

struct xpath;
struct xnode;

/* NULL when the text is not an expression of the subset */
struct xpath *xpath_compile(const WCHAR *text);
void xpath_free(struct xpath *path);
/* TRUE when the expression selects at least one node of the document, or is true */
BOOL xpath_match(const struct xpath *path, struct xnode *document);

/* The document of an event as xml_render_event writes it. NULL for text that is not that XML. */
struct xnode *xml_parse_event(const WCHAR *xml);
void xml_free(struct xnode *document);

/* The document of an event as xml_render_event writes it. The text of the node that a path of names names
   (Event/System/Provider/@Name), or NULL. An element with no text gives an empty string. */
const WCHAR *xml_value(struct xnode *document, const WCHAR *path);

/* evtx.c: the events of an .evtx file, read-only. Everything in the file is untrusted. */

struct evtx_file;

/* One value of the data of an event (EventData or UserData), as the file holds it */
struct evtx_value
{
    DWORD type;                     /* EvtVarType of the value */
    DWORD size;                     /* bytes */
    DWORD offset;                   /* in the blob of the event */
};

struct evtx_event
{
    WCHAR *xml;
    WCHAR *path;                    /* of the file */
    ULONGLONG record_id;
    ULONGLONG time;                 /* FILETIME units */
    ULONGLONG keywords;
    WCHAR *provider, *channel, *computer;
    WCHAR **strings;                /* the values of the data as text */
    GUID provider_guid, activity, related_activity;
    BOOL has_provider_guid, has_activity, has_related_activity, has_qualifiers;
    WORD id, qualifiers, task;
    BYTE level, opcode, version;
    DWORD process_id, thread_id;
    PSID sid;
    struct evtx_value *values;
    DWORD value_count;
    BYTE *blob;
    DWORD blob_len;
};

DWORD evtx_open(const WCHAR *path, BOOL reverse, struct evtx_file **file);
void evtx_close(struct evtx_file *file);
/* Starts again; the direction of the reading is the one that evtx_open was given */
void evtx_rewind(struct evtx_file *file);
/* ERROR_SUCCESS with an event, ERROR_NO_MORE_ITEMS at the end, ERROR_EVENTLOG_FILE_CORRUPT for something that is
   wrong in the file, after which the next call reads on with what can still be read. */
DWORD evtx_next(struct evtx_file *file, struct evtx_event **event);
void evtx_event_free(struct evtx_event *event);

/* evtxw.c: .evtx files that are written. Each XML of an event becomes the next record of the file. */

struct evtx_writer;

/* ERROR_ALREADY_EXISTS for a file that is there, unless it is to be overwritten */
DWORD evtx_create(const WCHAR *path, BOOL overwrite, struct evtx_writer **writer);
DWORD evtx_add_xml(struct evtx_writer *writer, ULONGLONG record_id, ULONGLONG time, const WCHAR *xml);
/* Ends the file; a file that is not kept is deleted. Returns the error of writing the end. */
DWORD evtx_finish(struct evtx_writer *writer, BOOL keep);

/* classic.c: records, sources and the text of messages */

/* The fields of one record of a classic log, seen as the system section of an event */
struct classic_event
{
    const EVENTLOGRECORD *rec;
    const WCHAR *channel;
    const WCHAR *source;
    const WCHAR *computer;
    WORD id;
    WORD qualifiers;
    BYTE level;
    WORD task;
    ULONGLONG keywords;
    ULONGLONG time;                 /* FILETIME units */
    ULONGLONG record_id;
    DWORD string_count;
    const WCHAR **strings;          /* allocated, the strings are in the record */
    const BYTE *data;
    DWORD data_len;
    PSID sid;
    const struct evtx_event *evtx;  /* for an event of an .evtx file, which has the fields above set and no rec */
};

BOOL classic_event_init(struct classic_event *event, const EVENTLOGRECORD *rec, const WCHAR *channel);
/* The view of an event of an .evtx file. The event must outlive the view. */
BOOL classic_event_from_evtx(struct classic_event *event, const struct evtx_event *evtx);
void classic_event_free(struct classic_event *event);

/* A source (publisher) of the classic logs, with the files that hold its message texts */
struct classic_pub
{
    WCHAR *name;
    WCHAR *event_file;              /* the raw values of the registry, which may name environment variables */
    WCHAR *category_file;
    WCHAR *parameter_file;
    WCHAR **logs;                   /* the logs that register it */
    DWORD log_count;
    WCHAR *resource_file;           /* of a manifest publisher: the raw value, with the metadata resource in it */
    GUID guid;
    BOOL has_guid;
    struct manifest *manifest;      /* read when the publisher is opened, NULL for a classic source */
};

struct classic_pub *classic_pub_open(const WCHAR *name);
struct classic_pub *classic_pub_default(void);
void classic_pub_free(struct classic_pub *pub);
/* The names of all sources of all logs, without duplicates. Returns the count, and NULL in *names for none. */
DWORD classic_pub_list(WCHAR ***names);
/* The names of the sources that one log registers. */
DWORD classic_pub_list_for_log(const WCHAR *log, WCHAR ***names);
void classic_names_free(WCHAR **names, DWORD count);
/* The names of the channels: the classic logs, and the channels that an installed manifest registers */
DWORD classic_channel_list(WCHAR ***names);
/* Whether an installed manifest registers the channel (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels) */
BOOL classic_registered_channel(const WCHAR *name);
/* A copy of the raw value with its environment variables expanded, or NULL */
WCHAR *classic_expand(const WCHAR *value);

/* The system section as the variants of EvtRender. Returns ERROR_SUCCESS or the error to report. */
DWORD classic_render_values(DWORD context_flags, const DWORD *indexes, DWORD index_count, const struct classic_event *event,
                            DWORD size, void *buffer, DWORD *used, DWORD *count);
/* The index of the system value that a path such as Event/System/EventID names, or -1 */
int classic_value_index(const WCHAR *path);

/* The XML of the event, as a heap string. rendering is the text of a RenderingInfo element to add, or NULL. */
WCHAR *classic_render_xml(const struct classic_event *event, const WCHAR *rendering);

/* EvtFormatMessage for the classic logs. Returns the text in *text (heap) and ERROR_SUCCESS, or the error to report. */
DWORD classic_format(const struct classic_pub *pub, const struct classic_event *event, DWORD message_id, DWORD flags,
                     DWORD value_count, const EVT_VARIANT *values, WCHAR **text, DWORD *length);

/* The properties of publishers, of the elements of their arrays, and of events */
DWORD classic_pub_property(const struct classic_pub *pub, DWORD id, DWORD size, void *buffer, DWORD *used);
DWORD classic_array_property(const WCHAR *item, DWORD index, DWORD id, DWORD size, void *buffer, DWORD *used);
/* The kinds of arrays of a manifest publisher */
#define MAN_LEVELS   1
#define MAN_TASKS    2
#define MAN_OPCODES  3
#define MAN_KEYWORDS 4
DWORD classic_manifest_array_size(const struct manifest *m, DWORD kind);
DWORD classic_manifest_array_property(const struct manifest *m, DWORD kind, DWORD index, DWORD id, DWORD size, void *buffer, DWORD *used);
DWORD classic_manifest_channel_property(const struct manifest *m, const WCHAR *name, DWORD index, DWORD id, DWORD size, void *buffer, DWORD *used);
DWORD classic_manifest_event_property(const struct manifest *m, DWORD index, DWORD id, DWORD size, void *buffer, DWORD *used);
DWORD classic_event_info(const struct classic_event *event, DWORD id, DWORD size, void *buffer, DWORD *used);

/* The properties of the channels and logs that the registry describes */
DWORD classic_channel_property(const WCHAR *channel, DWORD id, DWORD size, void *buffer, DWORD *used);
DWORD classic_log_property(const WCHAR *channel, DWORD id, DWORD size, void *buffer, DWORD *used);
DWORD classic_file_log_property(const WCHAR *path, DWORD id, DWORD size, void *buffer, DWORD *used);

/* A reader of the records of one or more logs, with the filters of a query */
struct classic_query;

struct classic_select
{
    WCHAR *channel;
    WCHAR *xpath;                   /* NULL for every event */
    BOOL file;                      /* the channel is the path of an .evtx file */
    DWORD group;                    /* the query that it belongs to */
    BOOL suppress;
};

/* What a query hands over: a record of a classic log, or an event of an .evtx file */
struct qevent
{
    EVENTLOGRECORD *rec;
    struct evtx_event *evtx;
};

DWORD classic_query_open(const struct classic_select *selects, DWORD count, BOOL reverse, struct classic_query **query);
void classic_query_free(struct classic_query *query);
/* The next event, in the order of the time that events were generated at. FALSE for the end or for an error,
   which is set; after the error of a file that is damaged the next call goes on. */
BOOL classic_query_next(struct classic_query *query, struct qevent *event, const WCHAR **channel, DWORD *error);
DWORD classic_query_names(const struct classic_query *query, DWORD size, void *buffer, DWORD *used);
DWORD classic_query_statuses(const struct classic_query *query, DWORD size, void *buffer, DWORD *used);
/* Starts again from the first event, and skips the given number of events */
DWORD classic_query_rewind(struct classic_query *query, ULONGLONG skip);
/* Moves to a position: origin is 1 (from the first event), 2 (last), 3 (current) or 4 (the event of a bookmark) */
DWORD classic_query_seek(struct classic_query *query, DWORD origin, LONGLONG position, const WCHAR *mark_channel,
                         ULONGLONG mark_record);

/* Subscriptions: a query that reads what the logs get later */
#define CLASSIC_FOLLOW_FUTURE   1
#define CLASSIC_FOLLOW_OLDEST   2
#define CLASSIC_FOLLOW_BOOKMARK 3
struct classic_mark
{
    const WCHAR *channel;
    ULONGLONG record_id;
};
DWORD classic_query_follow(struct classic_query *query, DWORD origin, const struct classic_mark *marks, DWORD mark_count);
BOOL classic_query_poll(struct classic_query *query);

/* manifest.c: the metadata of a publisher that an event manifest describes (the WEVT_TEMPLATE resource) */

struct man_named
{
    ULONGLONG value;
    DWORD message;                  /* of the message file, 0xffffffff for none */
    WCHAR *name;
};

struct man_task
{
    struct man_named named;
    GUID guid;
};

struct man_channel
{
    DWORD id, flags, message;
    WCHAR *name;
};

struct man_event
{
    WORD id, task;
    BYTE version, channel, level, opcode;
    ULONGLONG keywords;
    DWORD message;
    DWORD template_offset;          /* in the resource; 0xffffffff for an event with no data */
};

struct man_field
{
    WCHAR *name;
    BYTE in_type, out_type;
};

struct man_template
{
    DWORD offset;
    DWORD field_count;
    struct man_field *fields;
};

struct manifest
{
    LONG refs;
    GUID guid;
    DWORD message;
    struct man_named *levels, *opcodes, *keywords;
    struct man_task *tasks;
    struct man_channel *channels;
    struct man_event *events;
    struct man_template *templates;
    DWORD level_count, opcode_count, keyword_count, task_count, channel_count, event_count, template_count;
};

DWORD manifest_open(const WCHAR *file, const GUID *guid, struct manifest **man);
struct manifest *manifest_ref(struct manifest *man);
/* Gives up a reference; the last one frees the manifest */
void manifest_free(struct manifest *man);
/* The template of an event as XML text (heap), or NULL for an event that has no data */
WCHAR *manifest_template_xml(const struct manifest *man, DWORD template_offset);
const WCHAR *manifest_in_type_name(BYTE type);
const WCHAR *manifest_out_type_name(BYTE type);

#endif
