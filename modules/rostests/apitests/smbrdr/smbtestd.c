/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     smbtestd: TEST engine for the SMB mini-redirector (mrxsmb.sys), serving its
 *              upcalls with libsmb2.dll. Test code, not the product engine service.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * smbtestd [-U [DOMAIN\]USER] [-P PASSWORD] [-v 2.1|3.0|3.1.1] [-o LOGFILE] [-m SEED]
 *   Starts the mrxsmb service, attaches to \Device\NitroSmbEngine and answers its requests
 *   (see sdk/include/reactos/drivers/smbrdr/smbupcall.h) until the driver detaches it or the
 *   process is killed. One libsmb2 context per CONNECT, single-threaded: requests are served
 *   one at a time.
 *   -U/-P  explicit credentials for every connection (password also from SMBTESTD_PASSWORD);
 *          without them: single sign-on as the user whose token comes with CONNECT
 *          (impersonated around credential acquisition, as the engine service would)
 *   -m     hostile mode: corrupts one field of about every third reply (sizes, offsets, ids,
 *          statuses, directory chains) from a seeded generator, to test the driver's checks
 * It checks every request from the driver as well (it does not trust the sizes either).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstatus.h>

#ifndef ALIGN_UP_BY
#define ALIGN_UP_BY(x, a) (((ULONG_PTR)(x) + (a) - 1) & ~((ULONG_PTR)(a) - 1))
#endif
#define SMB2_HDR_SIZE 64

/* smb2.h has its own copies of these two (same values) */
#undef FILE_DEVICE_CD_ROM
#undef FILE_DEVICE_DISK
#include <smb2.h>
#include <libsmb2.h>
#include <libsmb2-raw.h>
#include <libsmb2-nitro.h>

#include <drivers/smbrdr/smbupcall.h>
#include "sysopen.h"

#ifndef FILE_DEVICE_NETWORK_REDIRECTOR
#define FILE_DEVICE_NETWORK_REDIRECTOR 0x00000028
#endif

#define MAX_CONNECTIONS 64
#define MAX_FILES 1024

typedef struct
{
    ULONGLONG Id;
    struct smb2_context *Smb2;
} CONNECTION;

typedef struct
{
    ULONGLONG Id;
    ULONGLONG ConnectionId;
    smb2_file_id FileId;
} OPEN_FILE;

static CONNECTION Connections[MAX_CONNECTIONS];
static OPEN_FILE Files[MAX_FILES];
static ULONGLONG NextId = 0x1000;
static struct
{
    const char *user, *password;
    enum smb2_negotiate_version version;
    unsigned seed;
    BOOL hostile;
} opt = { NULL, NULL, SMB2_VERSION_ANY, 0, FALSE };
static FILE *logf;
static UCHAR *ReplyBuffer, *RequestBuffer;

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    SYSTEMTIME st;

    if (!logf)
        return;
    GetSystemTime(&st);
    fprintf(logf, "%02u:%02u:%02u.%03u ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_start(ap, fmt);
    vfprintf(logf, fmt, ap);
    va_end(ap);
    fputc('\n', logf);
    fflush(logf);
}

/*
 * Synchronous wrapper around libsmb2's raw async commands. The reply structure (and a
 * directory reply's data, which points into the receive buffer) is only valid during
 * the callback: copy what is needed there.
 */
enum cb_kind { CB_NONE, CB_CREATE, CB_READ, CB_WRITE, CB_QUERY_INFO, CB_QUERY_DIR };

struct sync_cb
{
    int done;
    uint32_t status;
    enum cb_kind kind;
    int have;                           /* a reply of the kind was copied */
    struct smb2_create_reply create;
    uint32_t count;                     /* READ data length, WRITE count, QUERY_DIR bytes copied */
    void *info;                         /* QUERY_INFO output, owned by us (smb2_free_data) */
    uint32_t info_length;
    UCHAR *dst;                         /* QUERY_DIR destination */
    uint32_t max;
};

static void cb_init(struct sync_cb *cb, enum cb_kind kind, UCHAR *dst, uint32_t max)
{
    memset(cb, 0, sizeof(*cb));
    cb->kind = kind;
    cb->dst = dst;
    cb->max = max;
}

static void raw_cb(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    struct sync_cb *cb = private_data;

    (void)smb2;
    cb->done = 1;
    cb->status = (uint32_t)status;
    if (command_data == NULL || (status != 0 && (uint32_t)status != (uint32_t)STATUS_BUFFER_OVERFLOW))
        return;
    switch (cb->kind)
    {
        case CB_CREATE:
            memcpy(&cb->create, command_data, sizeof(cb->create));
            cb->create.create_context = NULL;
            cb->have = 1;
            break;
        case CB_READ:
            cb->count = ((struct smb2_read_reply *)command_data)->data_length;
            cb->have = 1;
            break;
        case CB_WRITE:
            cb->count = ((struct smb2_write_reply *)command_data)->count;
            cb->have = 1;
            break;
        case CB_QUERY_INFO:
            cb->info = ((struct smb2_query_info_reply *)command_data)->output_buffer;
            cb->info_length = ((struct smb2_query_info_reply *)command_data)->output_buffer_length;
            cb->have = 1;
            break;
        case CB_QUERY_DIR:
        {
            struct smb2_query_directory_reply *qr = command_data;

            if (qr->output_buffer_length <= cb->max && (qr->output_buffer || !qr->output_buffer_length))
            {
                if (qr->output_buffer_length)
                    memcpy(cb->dst, qr->output_buffer, qr->output_buffer_length);
                cb->count = qr->output_buffer_length;
                cb->have = 1;
            }
            break;
        }
        default:
            break;
    }
}

static int wait_reply(struct smb2_context *smb2, struct sync_cb *cb)
{
    while (!cb->done)
    {
        WSAPOLLFD pfd;

        pfd.fd = smb2_get_fd(smb2);
        pfd.events = (SHORT)smb2_which_events(smb2);
        pfd.revents = 0;
        if (WSAPoll(&pfd, 1, 1000) < 0)
            return -1;
        if (smb2_service(smb2, pfd.revents) < 0)
            return -1;
    }
    return 0;
}

/* NT status of a raw command; a dead connection is STATUS_CONNECTION_DISCONNECTED */
static NTSTATUS run_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu, struct sync_cb *cb)
{
    if (pdu == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    smb2_queue_pdu(smb2, pdu);
    if (wait_reply(smb2, cb) < 0)
        return STATUS_CONNECTION_DISCONNECTED;
    return (NTSTATUS)cb->status;
}

static CONNECTION *find_connection(ULONGLONG id)
{
    int i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
        if (Connections[i].Id == id && id != 0)
            return &Connections[i];
    return NULL;
}

static OPEN_FILE *find_file(ULONGLONG conn, ULONGLONG id)
{
    int i;

    for (i = 0; i < MAX_FILES; i++)
        if (Files[i].Id == id && id != 0 && Files[i].ConnectionId == conn)
            return &Files[i];
    return NULL;
}

/* UTF-16 (from a checked request) to a malloc'ed UTF-8 string, '\' kept */
static char *utf16_to_utf8(const WCHAR *s, ULONG bytes)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, s, bytes / 2, NULL, 0, NULL, NULL);
    char *out = malloc(n + 1);

    if (!out)
        return NULL;
    WideCharToMultiByte(CP_UTF8, 0, s, bytes / 2, out, n, NULL, NULL);
    out[n] = 0;
    return out;
}

static ULONG utf8_to_utf16(const char *s, WCHAR *out, ULONG max_chars)
{
    int n;

    if (!s)
        return 0;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, out, max_chars);
    return n > 0 ? (ULONG)(n - 1) : 0;
}

/* A string of a request, checked against the message */
static const WCHAR *req_string(const SMBUP_HEADER *h, ULONG fixed_end, const SMBUP_STRING *s, ULONG *bytes)
{
    *bytes = 0;
    if (s->Length == 0)
        return L"";
    if (!SMBUP_RANGE_VALID(s->Offset, s->Length, fixed_end, h->TotalSize, 2) || s->Length > SMBUP_MAX_NAME_BYTES)
        return NULL;
    *bytes = s->Length;
    return (const WCHAR *)((const UCHAR *)h + s->Offset);
}

/* Reply construction */
static ULONG reply_begin(const SMBUP_HEADER *req, ULONG fixed)
{
    SMBUP_HEADER *r = (SMBUP_HEADER *)ReplyBuffer;

    memset(ReplyBuffer, 0, sizeof(SMBUP_HEADER) + fixed);
    r->Magic = SMBUP_MAGIC;
    r->Version = SMBUP_VERSION;
    r->Opcode = req->Opcode;
    r->HeaderSize = sizeof(SMBUP_HEADER);
    r->RequestId = req->RequestId;
    r->TotalSize = sizeof(SMBUP_HEADER) + fixed;
    return r->TotalSize;
}

static SMBUP_DATA_REPLY *data_reply(void)
{
    return (SMBUP_DATA_REPLY *)(ReplyBuffer + sizeof(SMBUP_HEADER));
}

static LONGLONG tv_to_win(struct smb2_timeval *tv)
{
    return (LONGLONG)smb2_timeval_to_win(tv);
}

/* NT time of a set request to libsmb2's timeval: 0 (keep) and -1 (stop updating) as libsmb2 encodes them */
static void win_to_tv(LONGLONG t, struct smb2_timeval *tv)
{
    if (t == 0)
    {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    else if (t < 0)
    {
        tv->tv_sec = (time_t)0xffffffff;
        tv->tv_usec = (long)0xffffffff;
    }
    else
        smb2_win_to_timeval((uint64_t)t, tv);
}

/* Operations ****************************************************************/

static NTSTATUS do_connect(const SMBUP_HEADER *h, ULONG *win32)
{
    const SMBUP_CONNECT_REQUEST *r = (const void *)(h + 1);
    ULONG fixed_end = sizeof(*h) + sizeof(*r), sb, shb;
    const WCHAR *ws = req_string(h, fixed_end, &r->Server, &sb);
    const WCHAR *wsh = req_string(h, fixed_end, &r->Share, &shb);
    SMBUP_CONNECT_REPLY *rep = (SMBUP_CONNECT_REPLY *)(ReplyBuffer + sizeof(SMBUP_HEADER));
    HANDLE token = (HANDLE)(ULONG_PTR)r->TokenHandle;
    struct smb2_context *smb2 = NULL;
    char *server = NULL, *share = NULL;
    NTSTATUS st = STATUS_SUCCESS;
    int i, rc;

    *win32 = 0;
    if (!ws || !wsh || sb == 0 || shb == 0)
    {
        st = STATUS_INVALID_PARAMETER;
        goto out;
    }
    server = utf16_to_utf8(ws, sb);
    share = utf16_to_utf8(wsh, shb);
    if (server)
    {
        /* \\2001-db8--1.ipv6-literal.net\share: the address, for libsmb2, as [2001:db8::1] */
        size_t n = strlen(server);
        const char *suffix = ".ipv6-literal.net";

        if (n > strlen(suffix) && !_stricmp(server + n - strlen(suffix), suffix))
        {
            char *lit = malloc(n + 3);
            size_t i, k = 0;

            if (lit)
            {
                lit[k++] = '[';
                for (i = 0; i < n - strlen(suffix); i++)
                    lit[k++] = server[i] == '-' ? ':' : server[i] == 's' ? '%' : server[i];
                lit[k++] = ']';
                lit[k] = 0;
                free(server);
                server = lit;
            }
        }
    }
    for (i = 0; i < MAX_CONNECTIONS && Connections[i].Id; i++);
    if (!server || !share || i == MAX_CONNECTIONS || !(smb2 = smb2_init_context()))
    {
        st = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    smb2_set_version(smb2, opt.version);
    smb2_set_timeout(smb2, 30);
    if (opt.user)
    {
        char domain[256] = "", user[256];
        const char *bs = strchr(opt.user, '\\');

        if (bs)
        {
            _snprintf(domain, sizeof(domain) - 1, "%.*s", (int)(bs - opt.user), opt.user);
            _snprintf(user, sizeof(user) - 1, "%s", bs + 1);
        }
        else
            _snprintf(user, sizeof(user) - 1, "%s", opt.user);
        user[sizeof(user) - 1] = 0;
        rc = NitroSmb2SetCredentials(smb2, user, domain[0] ? domain : NULL, opt.password, NULL);
    }
    else
    {
        /* Single sign-on as the user of the token the driver handed us */
        if (!token || !SetThreadToken(NULL, token))
        {
            st = STATUS_NO_TOKEN;
            goto out;
        }
        rc = NitroSmb2SetCredentials(smb2, NULL, NULL, NULL, NULL);
        RevertToSelf();
    }
    if (rc < 0)
    {
        *win32 = NitroSmb2ErrorToWin32(smb2, rc);
        st = STATUS_LOGON_FAILURE;
        goto out;
    }

    rc = smb2_connect_share(smb2, server, share, NULL);
    if (rc < 0)
    {
        *win32 = NitroSmb2ErrorToWin32(smb2, rc);
        st = smb2_get_nterror(smb2) ? (NTSTATUS)smb2_get_nterror(smb2) : STATUS_BAD_NETWORK_PATH;
        if (NT_SUCCESS(st))
            st = STATUS_BAD_NETWORK_PATH;
        logmsg("connect %s\\%s failed rc=%d win32=%lu nt=%08lx (%s)", server, share, rc, *win32, st, smb2_get_error(smb2));
        goto out;
    }

    Connections[i].Id = ++NextId;
    Connections[i].Smb2 = smb2;
    smb2 = NULL;
    rep->ConnectionId = Connections[i].Id;
    rep->MaxReadSize = min(smb2_get_max_read_size(Connections[i].Smb2), SMBUP_MAX_IO);
    rep->MaxWriteSize = min(smb2_get_max_write_size(Connections[i].Smb2), SMBUP_MAX_IO);
    rep->ShareType = 1;
    logmsg("connect %s\\%s logon %08lx%08lx -> conn %I64x (dialect %x)", server, share,
           h->LogonIdHigh, h->LogonIdLow, rep->ConnectionId, smb2_get_dialect(Connections[i].Smb2));

out:
    if (token)
        CloseHandle(token);
    if (smb2)
        smb2_destroy_context(smb2);
    free(server);
    free(share);
    return st;
}

static NTSTATUS do_disconnect(const SMBUP_HEADER *h)
{
    const SMBUP_DISCONNECT_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    int i;

    if (!c)
        return STATUS_INVALID_HANDLE;
    for (i = 0; i < MAX_FILES; i++)
        if (Files[i].ConnectionId == c->Id)
            memset(&Files[i], 0, sizeof(Files[i]));
    smb2_disconnect_share(c->Smb2);
    smb2_destroy_context(c->Smb2);
    logmsg("disconnect conn %I64x", c->Id);
    memset(c, 0, sizeof(*c));
    return STATUS_SUCCESS;
}

static NTSTATUS do_create(const SMBUP_HEADER *h)
{
    const SMBUP_CREATE_REQUEST *r = (const void *)(h + 1);
    SMBUP_CREATE_REPLY *rep = (SMBUP_CREATE_REPLY *)(ReplyBuffer + sizeof(SMBUP_HEADER));
    CONNECTION *c = find_connection(r->ConnectionId);
    struct smb2_create_request req;
    struct smb2_create_reply *cr;
    struct sync_cb cb;
    ULONG pb;
    const WCHAR *wp = req_string(h, sizeof(*h) + sizeof(*r), &r->Path, &pb);
    char *path;
    NTSTATUS st;
    int i;

    if (!c)
        return STATUS_CONNECTION_DISCONNECTED;
    if (!wp)
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < MAX_FILES && Files[i].Id; i++);
    if (i == MAX_FILES || !(path = utf16_to_utf8(wp, pb)))
        return STATUS_INSUFFICIENT_RESOURCES;

    memset(&req, 0, sizeof(req));
    req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
    req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
    req.desired_access = r->DesiredAccess;
    req.file_attributes = r->FileAttributes;
    req.share_access = r->ShareAccess;
    req.create_disposition = r->CreateDisposition;
    req.create_options = r->CreateOptions;
    req.name = path;

    cb_init(&cb, CB_CREATE, NULL, 0);
    st = run_pdu(c->Smb2, smb2_cmd_create_async(c->Smb2, &req, raw_cb, &cb), &cb);
    logmsg("create conn %I64x \"%s\" access %08lx disp %lu opts %08lx -> %08lx", c->Id, path,
           r->DesiredAccess, r->CreateDisposition, r->CreateOptions, st);
    free(path);
    if (!NT_SUCCESS(st))
        return st;
    if (!cb.have)
        return STATUS_INVALID_NETWORK_RESPONSE;
    cr = &cb.create;

    Files[i].Id = ++NextId;
    Files[i].ConnectionId = c->Id;
    memcpy(Files[i].FileId, cr->file_id, SMB2_FD_SIZE);
    rep->FileId = Files[i].Id;
    rep->CreateAction = cr->create_action;
    rep->Attributes.CreationTime = cr->creation_time;
    rep->Attributes.LastAccessTime = cr->last_access_time;
    rep->Attributes.LastWriteTime = cr->last_write_time;
    rep->Attributes.ChangeTime = cr->change_time;
    rep->Attributes.AllocationSize = cr->allocation_size;
    rep->Attributes.EndOfFile = cr->end_of_file;
    rep->Attributes.FileAttributes = cr->file_attributes;
    return STATUS_SUCCESS;
}

static NTSTATUS do_close(const SMBUP_HEADER *h, BOOL flush)
{
    const SMBUP_HANDLE_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    struct sync_cb cb;
    NTSTATUS st;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    cb_init(&cb, CB_NONE, NULL, 0);
    if (flush)
    {
        struct smb2_flush_request req;

        memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);
        return run_pdu(c->Smb2, smb2_cmd_flush_async(c->Smb2, &req, raw_cb, &cb), &cb);
    }
    else
    {
        struct smb2_close_request req;

        memset(&req, 0, sizeof(req));
        memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);
        st = run_pdu(c->Smb2, smb2_cmd_close_async(c->Smb2, &req, raw_cb, &cb), &cb);
        memset(f, 0, sizeof(*f));
        return st;
    }
}

static NTSTATUS do_read(const SMBUP_HEADER *h, ULONG *total)
{
    const SMBUP_IO_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    SMBUP_DATA_REPLY *dr = data_reply();
    ULONG off = ALIGN_UP_BY(sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY), 8);
    struct smb2_read_request req;
    struct sync_cb cb;
    NTSTATUS st;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    if (r->Length > SMBUP_MAX_IO || r->Offset < 0)
        return STATUS_INVALID_PARAMETER;

    memset(&req, 0, sizeof(req));
    req.length = r->Length;
    req.offset = r->Offset;
    req.buf = ReplyBuffer + off;
    memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);
    cb_init(&cb, CB_READ, NULL, 0);
    st = run_pdu(c->Smb2, smb2_cmd_read_async(c->Smb2, &req, raw_cb, &cb), &cb);
    if (!NT_SUCCESS(st))
        return st;
    if (!cb.have || cb.count > r->Length)
        return STATUS_INVALID_NETWORK_RESPONSE;
    dr->Length = cb.count;
    dr->DataOffset = off;
    *total = off + cb.count;
    return STATUS_SUCCESS;
}

static NTSTATUS do_write(const SMBUP_HEADER *h)
{
    const SMBUP_IO_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    struct smb2_write_request req;
    struct sync_cb cb;
    NTSTATUS st;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    if (r->Length > SMBUP_MAX_IO || r->Offset < 0 ||
        !SMBUP_RANGE_VALID(r->DataOffset, r->Length, sizeof(*h) + sizeof(*r), h->TotalSize, 1))
        return STATUS_INVALID_PARAMETER;

    memset(&req, 0, sizeof(req));
    req.length = r->Length;
    req.offset = r->Offset;
    req.buf = (const uint8_t *)h + r->DataOffset;
    memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);
    cb_init(&cb, CB_WRITE, NULL, 0);
    st = run_pdu(c->Smb2, smb2_cmd_write_async(c->Smb2, &req, 0, raw_cb, &cb), &cb);
    if (!NT_SUCCESS(st))
        return st;
    if (!cb.have)
        return STATUS_INVALID_NETWORK_RESPONSE;
    data_reply()->Length = min(cb.count, r->Length);
    return STATUS_SUCCESS;
}

/* QUERY_INFO / QUERY_VOLUME: libsmb2 decodes the classes it knows; re-encode them in
 * the NT layout. Classes it does not decode come raw (passthrough). */
static NTSTATUS do_query(const SMBUP_HEADER *h, BOOL volume, ULONG *total)
{
    const SMBUP_QUERY_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    SMBUP_DATA_REPLY *dr = data_reply();
    ULONG off = ALIGN_UP_BY(sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY), 8), len = 0;
    UCHAR *out = ReplyBuffer + off;
    struct smb2_query_info_request req;
    struct smb2_query_info_reply qrs, *qr;
    struct sync_cb cb;
    NTSTATUS st;
    BOOL raw;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    if (r->OutputLength > SMBUP_MAX_INFO)
        return STATUS_INVALID_PARAMETER;

    memset(&req, 0, sizeof(req));
    req.info_type = volume ? SMB2_0_INFO_FILESYSTEM : SMB2_0_INFO_FILE;
    req.file_info_class = (uint8_t)r->InformationClass;
    req.output_buffer_length = max(r->OutputLength, 64);
    memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);

    cb_init(&cb, CB_QUERY_INFO, NULL, 0);
    smb2_set_passthrough(c->Smb2, 1);
    st = run_pdu(c->Smb2, smb2_cmd_query_info_async(c->Smb2, &req, raw_cb, &cb), &cb);
    smb2_set_passthrough(c->Smb2, 0);
    if (!NT_SUCCESS(st))
        return st;
    if (!cb.have || !cb.info)
        return STATUS_INVALID_NETWORK_RESPONSE;
    qrs.output_buffer = cb.info;
    qrs.output_buffer_length = cb.info_length;
    qr = &qrs;

    raw = FALSE;
    if (!volume)
    {
        switch (r->InformationClass)
        {
            case 4: /* FileBasicInformation */
            {
                struct smb2_file_basic_info *i = qr->output_buffer;
                FILE_BASIC_INFORMATION *o = (void *)out;

                memset(o, 0, sizeof(*o));
                o->CreationTime.QuadPart = i->creation_time_raw;
                o->LastAccessTime.QuadPart = i->last_access_time_raw;
                o->LastWriteTime.QuadPart = i->last_write_time_raw;
                o->ChangeTime.QuadPart = i->change_time_raw;
                o->FileAttributes = i->file_attributes;
                len = sizeof(*o);
                break;
            }
            case 5: /* FileStandardInformation */
            {
                struct smb2_file_standard_info *i = qr->output_buffer;
                FILE_STANDARD_INFORMATION *o = (void *)out;

                memset(o, 0, sizeof(*o));
                o->AllocationSize.QuadPart = i->allocation_size;
                o->EndOfFile.QuadPart = i->end_of_file;
                o->NumberOfLinks = i->number_of_links;
                o->DeletePending = i->delete_pending;
                o->Directory = i->directory;
                len = sizeof(*o);
                break;
            }
            case 34: /* FileNetworkOpenInformation */
            {
                struct smb2_file_network_open_info *i = qr->output_buffer;
                FILE_NETWORK_OPEN_INFORMATION *o = (void *)out;

                memset(o, 0, sizeof(*o));
                o->CreationTime.QuadPart = tv_to_win(&i->creation_time);
                o->LastAccessTime.QuadPart = tv_to_win(&i->last_access_time);
                o->LastWriteTime.QuadPart = tv_to_win(&i->last_write_time);
                o->ChangeTime.QuadPart = tv_to_win(&i->change_time);
                o->AllocationSize.QuadPart = i->allocation_size;
                o->EndOfFile.QuadPart = i->end_of_file;
                o->FileAttributes = i->file_attributes;
                len = sizeof(*o);
                break;
            }
            case 22: /* FileStreamInformation: libsmb2 decodes it into an array */
            {
                struct smb2_file_stream_info *i = qr->output_buffer;
                ULONG pos = 0, prev = MAXULONG;

                for (;;)
                {
                    FILE_STREAM_INFORMATION *o = (void *)(out + pos);
                    ULONG room = (SMBUP_MAX_INFO - pos - FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName)) / 2;

                    if (pos + FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) > r->OutputLength)
                        break;
                    memset(o, 0, sizeof(*o));
                    o->StreamSize.QuadPart = i->stream_size;
                    o->StreamAllocationSize.QuadPart = i->stream_allocation_size;
                    o->StreamNameLength = 2 * utf8_to_utf16(i->stream_name, o->StreamName, room);
                    if (prev != MAXULONG)
                        ((FILE_STREAM_INFORMATION *)(out + prev))->NextEntryOffset = pos - prev;
                    prev = pos;
                    len = pos + FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) + o->StreamNameLength;
                    pos = ALIGN_UP_BY(len, 8);
                    if (!i->next_entry_offset)
                        break;
                    i++;
                }
                break;
            }
            case 35: /* FileAttributeTagInformation */
            {
                struct smb2_file_attribute_tag_info *i = qr->output_buffer;
                FILE_ATTRIBUTE_TAG_INFORMATION *o = (void *)out;

                o->FileAttributes = i->file_attributes;
                o->ReparseTag = i->reparse_tag;
                len = sizeof(*o);
                break;
            }
            default:
                raw = TRUE;
        }
    }
    else
    {
        switch (r->InformationClass)
        {
            case 1: /* FileFsVolumeInformation */
            {
                struct smb2_file_fs_volume_info *i = qr->output_buffer;
                FILE_FS_VOLUME_INFORMATION *o = (void *)out;
                ULONG chars = (SMBUP_MAX_INFO - FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel)) / 2;

                memset(o, 0, sizeof(*o));
                o->VolumeCreationTime.QuadPart = tv_to_win(&i->creation_time);
                o->VolumeSerialNumber = i->volume_serial_number;
                o->SupportsObjects = i->supports_objects;
                o->VolumeLabelLength = 2 * utf8_to_utf16((const char *)i->volume_label, o->VolumeLabel, chars);
                len = FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + o->VolumeLabelLength;
                break;
            }
            case 3: /* FileFsSizeInformation */
            {
                struct smb2_file_fs_size_info *i = qr->output_buffer;
                FILE_FS_SIZE_INFORMATION *o = (void *)out;

                o->TotalAllocationUnits.QuadPart = i->total_allocation_units;
                o->AvailableAllocationUnits.QuadPart = i->available_allocation_units;
                o->SectorsPerAllocationUnit = i->sectors_per_allocation_unit;
                o->BytesPerSector = i->bytes_per_sector;
                len = sizeof(*o);
                break;
            }
            case 5: /* FileFsAttributeInformation */
            {
                struct smb2_file_fs_attribute_info *i = qr->output_buffer;
                FILE_FS_ATTRIBUTE_INFORMATION *o = (void *)out;
                ULONG chars = (SMBUP_MAX_INFO - FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) / 2;

                o->FileSystemAttributes = i->filesystem_attributes;
                o->MaximumComponentNameLength = i->maximum_component_name_length;
                o->FileSystemNameLength = 2 * utf8_to_utf16((const char *)i->filesystem_name, o->FileSystemName, chars);
                len = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + o->FileSystemNameLength;
                break;
            }
            case 7: /* FileFsFullSizeInformation */
            {
                struct smb2_file_fs_full_size_info *i = qr->output_buffer;
                FILE_FS_FULL_SIZE_INFORMATION *o = (void *)out;

                o->TotalAllocationUnits.QuadPart = i->total_allocation_units;
                o->CallerAvailableAllocationUnits.QuadPart = i->caller_available_allocation_units;
                o->ActualAvailableAllocationUnits.QuadPart = i->actual_available_allocation_units;
                o->SectorsPerAllocationUnit = i->sectors_per_allocation_unit;
                o->BytesPerSector = i->bytes_per_sector;
                len = sizeof(*o);
                break;
            }
            default:
                raw = TRUE;
        }
    }

    if (raw)
    {
        len = min(qr->output_buffer_length, r->OutputLength);
        memcpy(out, qr->output_buffer, len);
    }
    smb2_free_data(c->Smb2, qr->output_buffer);

    st = STATUS_SUCCESS;
    if (len > r->OutputLength)
    {
        len = r->OutputLength;
        st = STATUS_BUFFER_OVERFLOW;
    }
    dr->Length = len;
    dr->DataOffset = off;
    *total = off + len;
    return st;
}

static NTSTATUS do_set(const SMBUP_HEADER *h)
{
    const SMBUP_SET_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    struct smb2_set_info_request req;
    struct smb2_file_basic_info basic;
    struct smb2_file_disposition_info disp;
    struct smb2_file_end_of_file_info eof;
    struct sync_cb cb;
    NTSTATUS st;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    if (r->Length > 64 || !SMBUP_RANGE_VALID(r->DataOffset, r->Length, sizeof(*h) + sizeof(*r), h->TotalSize, 1))
        return STATUS_INVALID_PARAMETER;
    memset(&req, 0, sizeof(req));
    req.info_type = SMB2_0_INFO_FILE;
    req.file_info_class = (uint8_t)r->InformationClass;
    memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);

    /* libsmb2 encodes these classes itself (its passthrough mode puts the length and
     * offset of SET_INFO into the data, not into the request) */
    switch (r->InformationClass)
    {
        case 4: /* FileBasicInformation */
        {
            const FILE_BASIC_INFORMATION *in = (const void *)((const UCHAR *)h + r->DataOffset);

            if (r->Length < sizeof(*in))
                return STATUS_INFO_LENGTH_MISMATCH;
            memset(&basic, 0, sizeof(basic));
            win_to_tv(in->CreationTime.QuadPart, &basic.creation_time);
            win_to_tv(in->LastAccessTime.QuadPart, &basic.last_access_time);
            win_to_tv(in->LastWriteTime.QuadPart, &basic.last_write_time);
            win_to_tv(in->ChangeTime.QuadPart, &basic.change_time);
            basic.file_attributes = in->FileAttributes;
            req.input_data = &basic;
            break;
        }
        case 13: /* FileDispositionInformation */
            if (r->Length < 1)
                return STATUS_INFO_LENGTH_MISMATCH;
            disp.delete_pending = *((const UCHAR *)h + r->DataOffset) ? 1 : 0;
            req.input_data = &disp;
            break;
        case 20: /* FileEndOfFileInformation */
            if (r->Length < sizeof(LONGLONG))
                return STATUS_INFO_LENGTH_MISMATCH;
            eof.end_of_file = *(const ULONGLONG UNALIGNED *)((const UCHAR *)h + r->DataOffset);
            req.input_data = &eof;
            break;
        default:
            return STATUS_NOT_SUPPORTED;
    }

    cb_init(&cb, CB_NONE, NULL, 0);
    st = run_pdu(c->Smb2, smb2_cmd_set_info_async(c->Smb2, &req, raw_cb, &cb), &cb);
    logmsg("set info class %lu -> %08lx", r->InformationClass, st);
    return st;
}

static NTSTATUS do_rename(const SMBUP_HEADER *h)
{
    const SMBUP_RENAME_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    struct smb2_set_info_request req;
    struct smb2_file_rename_info rn;
    struct sync_cb cb;
    ULONG nb;
    const WCHAR *wn = req_string(h, sizeof(*h) + sizeof(*r), &r->NewName, &nb);
    char *name;
    NTSTATUS st;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    if (!wn || nb == 0)
        return STATUS_INVALID_PARAMETER;
    if (!(name = utf16_to_utf8(wn, nb)))
        return STATUS_INSUFFICIENT_RESOURCES;

    rn.replace_if_exist = r->ReplaceIfExists ? 1 : 0;
    rn.file_name = (const uint8_t *)name;
    memset(&req, 0, sizeof(req));
    req.info_type = SMB2_0_INFO_FILE;
    req.file_info_class = SMB2_FILE_RENAME_INFORMATION;
    req.input_data = &rn;
    memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);

    cb_init(&cb, CB_NONE, NULL, 0);
    st = run_pdu(c->Smb2, smb2_cmd_set_info_async(c->Smb2, &req, raw_cb, &cb), &cb);
    logmsg("rename -> \"%s\" %08lx", name, st);
    free(name);
    return st;
}

static NTSTATUS do_query_directory(const SMBUP_HEADER *h, ULONG *total)
{
    const SMBUP_DIRECTORY_REQUEST *r = (const void *)(h + 1);
    CONNECTION *c = find_connection(r->ConnectionId);
    OPEN_FILE *f = find_file(r->ConnectionId, r->FileId);
    SMBUP_DATA_REPLY *dr = data_reply();
    ULONG off = ALIGN_UP_BY(sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY), 8), pb;
    const WCHAR *wp = req_string(h, sizeof(*h) + sizeof(*r), &r->Pattern, &pb);
    struct smb2_query_directory_request req;
    struct sync_cb cb;
    char *pattern;
    NTSTATUS st;

    if (!c || !f)
        return STATUS_INVALID_HANDLE;
    if (!wp || r->OutputLength > SMBUP_MAX_INFO || r->InformationClass > 0xFF)
        return STATUS_INVALID_PARAMETER;
    pattern = pb ? utf16_to_utf8(wp, pb) : _strdup("*");
    if (!pattern)
        return STATUS_INSUFFICIENT_RESOURCES;

    memset(&req, 0, sizeof(req));
    req.file_information_class = (uint8_t)r->InformationClass;
    req.flags = (r->Flags & SMBUP_DIR_RESTART_SCANS ? SMB2_RESTART_SCANS : 0) |
                (r->Flags & SMBUP_DIR_RETURN_SINGLE_ENTRY ? SMB2_RETURN_SINGLE_ENTRY : 0) |
                (r->Flags & SMBUP_DIR_INDEX_SPECIFIED ? SMB2_INDEX_SPECIFIED : 0);
    req.file_index = r->FileIndex;
    req.output_buffer_length = r->OutputLength;
    req.name = pattern;
    memcpy(req.file_id, f->FileId, SMB2_FD_SIZE);

    /* The server's entries as they came (copied in the callback): the driver checks the chain */
    cb_init(&cb, CB_QUERY_DIR, ReplyBuffer + off, r->OutputLength);
    smb2_set_passthrough(c->Smb2, 1);
    st = run_pdu(c->Smb2, smb2_cmd_query_directory_async(c->Smb2, &req, raw_cb, &cb), &cb);
    smb2_set_passthrough(c->Smb2, 0);
    free(pattern);
    if (!NT_SUCCESS(st))
        return st;
    if (!cb.have)
        return STATUS_INVALID_NETWORK_RESPONSE;
    dr->Length = cb.count;
    dr->DataOffset = off;
    *total = off + cb.count;
    return STATUS_SUCCESS;
}

static void do_logoff(const SMBUP_HEADER *h)
{
    logmsg("logoff %08lx%08lx (connections stay: test engine)", h->LogonIdHigh, h->LogonIdLow);
}

/* Hostile mode: one corrupted field */
static void corrupt(ULONG *total)
{
    SMBUP_HEADER *r = (SMBUP_HEADER *)ReplyBuffer;
    SMBUP_DATA_REPLY *dr = data_reply();
    int what = rand() % 9;

    switch (what)
    {
        case 0: r->TotalSize += 8; break;
        case 1: r->RequestId ^= 0x40; break;
        case 2: r->Status = STATUS_REPARSE; break;
        case 3: r->Status = STATUS_PENDING; break;
        case 4: dr->Length = 0x7FFFFFF0; break;
        case 5: dr->DataOffset = 4; break;
        case 6: if (*total > sizeof(SMBUP_HEADER) + 16) ReplyBuffer[*total - 1] ^= 0xFF; break;
        case 7: r->Opcode = (USHORT)(r->Opcode % (SmbUpMaximumOpcode - 1) + 1); break;
        case 8: if (*total > 128) memset(ReplyBuffer + 96, 0xFF, 16); break;
    }
    logmsg("hostile: corruption %d", what);
}

/* Checks a request from the driver: the engine does not trust its sizes either */
static BOOL valid_request(const SMBUP_HEADER *h, DWORD got)
{
    ULONG fixed;

    if (got < sizeof(*h) || h->Magic != SMBUP_MAGIC || h->Version != SMBUP_VERSION ||
        h->HeaderSize != sizeof(*h) || h->TotalSize != got || got > SMBUP_MAX_MESSAGE ||
        h->Opcode <= SmbUpInvalid || h->Opcode >= SmbUpMaximumOpcode)
        return FALSE;
    fixed = SMBUP_REQUEST_FIXED_SIZE(h->Opcode);
    return got >= sizeof(*h) + fixed;
}

static BOOL start_driver(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), svc;
    BOOL ok;

    if (!scm)
        return FALSE;
    svc = OpenServiceW(scm, L"mrxsmb", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc)
    {
        CloseServiceHandle(scm);
        return FALSE;
    }
    ok = StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    if (!ok)
        printf("smbtestd: StartService(mrxsmb) failed %lu\n", GetLastError());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

int wmain(int argc, WCHAR **argv)
{
    static char user[256], password[256];
    HANDLE dev;
    SMBUP_ATTACH attach;
    DWORD got, ret;
    ULONG served = 0;
    int i;

    for (i = 1; i < argc; i++)
    {
        if (!wcscmp(argv[i], L"-U") && i + 1 < argc)
        {
            WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, user, sizeof(user), NULL, NULL);
            opt.user = user;
        }
        else if (!wcscmp(argv[i], L"-P") && i + 1 < argc)
        {
            WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, password, sizeof(password), NULL, NULL);
            opt.password = password;
        }
        else if (!wcscmp(argv[i], L"-v") && i + 1 < argc)
        {
            i++;
            opt.version = !wcscmp(argv[i], L"2.1") ? SMB2_VERSION_0210 :
                          !wcscmp(argv[i], L"3.0") ? SMB2_VERSION_0300 :
                          !wcscmp(argv[i], L"3.1.1") ? SMB2_VERSION_0311 : SMB2_VERSION_ANY;
        }
        else if (!wcscmp(argv[i], L"-o") && i + 1 < argc)
            logf = _wfopen(argv[++i], L"a");
        else if (!wcscmp(argv[i], L"-m") && i + 1 < argc)
        {
            opt.hostile = TRUE;
            opt.seed = (unsigned)_wtoi(argv[++i]);
        }
    }
    if (opt.user && !opt.password)
    {
        const char *env = getenv("SMBTESTD_PASSWORD");

        if (env)
        {
            _snprintf(password, sizeof(password) - 1, "%s", env);
            opt.password = password;
        }
    }
    srand(opt.seed);
    {
        WSADATA wsa;

        if (WSAStartup(MAKEWORD(2, 2), &wsa))
            return 9;
    }

    ReplyBuffer = VirtualAlloc(NULL, SMBUP_MAX_MESSAGE, MEM_COMMIT, PAGE_READWRITE);
    RequestBuffer = VirtualAlloc(NULL, SMBUP_MAX_MESSAGE, MEM_COMMIT, PAGE_READWRITE);
    if (!ReplyBuffer || !RequestBuffer)
        return 8;

    if (!start_driver())
        printf("smbtestd: mrxsmb not started (%lu), trying the device anyway\n", GetLastError());

    dev = SmbTestOpenAsSystem(NITRO_SMBRDR_ENGINE_DOS_NAME, GENERIC_READ | GENERIC_WRITE, 0);
    if (dev == INVALID_HANDLE_VALUE)
    {
        printf("smbtestd: open engine device failed %lu\n", GetLastError());
        return 2;
    }
    attach.Magic = SMBUP_MAGIC;
    attach.Version = SMBUP_VERSION;
    attach.Reserved = 0;
    attach.MaxMessageSize = SMBUP_MAX_MESSAGE;
    attach.Reserved2 = 0;
    if (!DeviceIoControl(dev, IOCTL_SMBRDR_ENGINE_ATTACH, &attach, sizeof(attach), NULL, 0, &ret, NULL))
    {
        printf("smbtestd: attach failed %lu\n", GetLastError());
        return 3;
    }
    printf("smbtestd: attached (pid %lu)%s\n", GetCurrentProcessId(), opt.hostile ? " HOSTILE" : "");
    fflush(stdout);
    logmsg("attached pid %lu hostile %d seed %u", GetCurrentProcessId(), opt.hostile, opt.seed);

    for (;;)
    {
        const SMBUP_HEADER *h = (const SMBUP_HEADER *)RequestBuffer;
        SMBUP_HEADER *r = (SMBUP_HEADER *)ReplyBuffer;
        ULONG total, win32 = 0;
        NTSTATUS st;

        if (!DeviceIoControl(dev, IOCTL_SMBRDR_ENGINE_GET, NULL, 0, RequestBuffer, SMBUP_MAX_MESSAGE, &got, NULL))
        {
            printf("smbtestd: GET failed %lu after %lu requests\n", GetLastError(), served);
            logmsg("GET failed %lu", GetLastError());
            break;
        }
        if (!valid_request(h, got))
        {
            logmsg("invalid request from the driver (%lu bytes)", got);
            continue;
        }
        if (h->Flags & SMBUP_FLAG_NOTIFICATION)
        {
            if (h->Opcode == SmbUpLogoff)
                do_logoff(h);
            continue;
        }

        total = reply_begin(h, SMBUP_REPLY_FIXED_SIZE(h->Opcode));
        switch (h->Opcode)
        {
            case SmbUpConnect: st = do_connect(h, &win32); break;
            case SmbUpDisconnect: st = do_disconnect(h); break;
            case SmbUpCreate: st = do_create(h); break;
            case SmbUpClose: st = do_close(h, FALSE); break;
            case SmbUpFlush: st = do_close(h, TRUE); break;
            case SmbUpRead: st = do_read(h, &total); break;
            case SmbUpWrite: st = do_write(h); break;
            case SmbUpQueryInfo: st = do_query(h, FALSE, &total); break;
            case SmbUpQueryVolume: st = do_query(h, TRUE, &total); break;
            case SmbUpSetInfo: st = do_set(h); break;
            case SmbUpRename: st = do_rename(h); break;
            case SmbUpQueryDirectory: st = do_query_directory(h, &total); break;
            default: st = STATUS_NOT_SUPPORTED; break;
        }
        r->Status = st;
        r->Win32Error = win32;
        r->TotalSize = total;
        if (opt.hostile && rand() % 3 == 0)
            corrupt(&total);
        served++;

        if (!DeviceIoControl(dev, IOCTL_SMBRDR_ENGINE_REPLY, ReplyBuffer, total, NULL, 0, &ret, NULL))
            logmsg("REPLY %I64u failed %lu", h->RequestId, GetLastError());
    }

    CloseHandle(dev);
    return 0;
}
