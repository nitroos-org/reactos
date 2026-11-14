/*
 * Associations
 *
 * Copyright 2007 Robert Shearman (for CodeWeavers)
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
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>

#include "rpc.h"
#include "rpcndr.h"

#include "wine/debug.h"

#include "rpc_binding.h"
#include "rpc_assoc.h"
#include "rpc_message.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpc);

static CRITICAL_SECTION assoc_list_cs;
static CRITICAL_SECTION_DEBUG assoc_list_cs_debug =
{
    0, 0, &assoc_list_cs,
    { &assoc_list_cs_debug.ProcessLocksList, &assoc_list_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": assoc_list_cs") }
};
static CRITICAL_SECTION assoc_list_cs = { &assoc_list_cs_debug, -1, 0, 0, 0, 0 };

static struct list client_assoc_list = LIST_INIT(client_assoc_list);
static struct list server_assoc_list = LIST_INIT(server_assoc_list);

static LONG last_assoc_group_id;

typedef struct _RpcContextHandle
{
    struct list entry;
    void *user_context;
    NDR_RUNDOWN rundown_routine;
    void *ctx_guard;
    UUID uuid;
    CRITICAL_SECTION lock;
    unsigned int refs;
} RpcContextHandle;

static void RpcContextHandle_Destroy(RpcContextHandle *context_handle);

static RPC_STATUS RpcAssoc_Alloc(LPCSTR Protseq, LPCSTR NetworkAddr,
                                 LPCSTR Endpoint, LPCWSTR NetworkOptions,
                                 RpcAssoc **assoc_out)
{
    RpcAssoc *assoc;
    assoc = malloc(sizeof(*assoc));
    if (!assoc)
        return RPC_S_OUT_OF_RESOURCES;
    assoc->refs = 1;
    list_init(&assoc->free_connection_pool);
    list_init(&assoc->context_handle_list);
    InitializeCriticalSectionEx(&assoc->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    assoc->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RpcAssoc.cs");
    InitializeCriticalSectionEx(&assoc->group_cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    assoc->group_cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RpcAssoc.group_cs");
    assoc->Protseq = strdup(Protseq);
    assoc->NetworkAddr = strdup(NetworkAddr);
    assoc->Endpoint = strdup(Endpoint);
    assoc->NetworkOptions = wcsdup(NetworkOptions);
    assoc->assoc_group_id = 0;
    assoc->connection_cnt = 0;
    assoc->idle_since = 0;
    assoc->is_client = FALSE;
    UuidCreate(&assoc->http_uuid);
    list_init(&assoc->entry);
    *assoc_out = assoc;
    return RPC_S_OK;
}

static BOOL compare_networkoptions(LPCWSTR opts1, LPCWSTR opts2)
{
    if ((opts1 == NULL) && (opts2 == NULL))
        return TRUE;
    if ((opts1 == NULL) || (opts2 == NULL))
        return FALSE;
    return !wcscmp(opts1, opts2);
}

RPC_STATUS RPCRT4_GetAssociation(LPCSTR Protseq, LPCSTR NetworkAddr,
                                 LPCSTR Endpoint, LPCWSTR NetworkOptions,
                                 RpcAssoc **assoc_out)
{
    RpcAssoc *assoc;
    RPC_STATUS status;

    EnterCriticalSection(&assoc_list_cs);
    LIST_FOR_EACH_ENTRY(assoc, &client_assoc_list, RpcAssoc, entry)
    {
        if (!strcmp(Protseq, assoc->Protseq) &&
            !strcmp(NetworkAddr, assoc->NetworkAddr) &&
            !strcmp(Endpoint, assoc->Endpoint) &&
            compare_networkoptions(NetworkOptions, assoc->NetworkOptions))
        {
            /* an association kept for its idle connections is in use again */
            assoc->idle_since = 0;
            assoc->refs++;
            *assoc_out = assoc;
            LeaveCriticalSection(&assoc_list_cs);
            TRACE("using existing assoc %p\n", assoc);
            return RPC_S_OK;
        }
    }

    status = RpcAssoc_Alloc(Protseq, NetworkAddr, Endpoint, NetworkOptions, &assoc);
    if (status != RPC_S_OK)
    {
        LeaveCriticalSection(&assoc_list_cs);
        return status;
    }
    assoc->is_client = TRUE;
    list_add_head(&client_assoc_list, &assoc->entry);
    *assoc_out = assoc;

    LeaveCriticalSection(&assoc_list_cs);

    TRACE("new assoc %p\n", assoc);

    return RPC_S_OK;
}

RPC_STATUS RpcServerAssoc_GetAssociation(LPCSTR Protseq, LPCSTR NetworkAddr,
                                         LPCSTR Endpoint, LPCWSTR NetworkOptions,
                                         ULONG assoc_gid,
                                         RpcAssoc **assoc_out)
{
    RpcAssoc *assoc;
    RPC_STATUS status;

    EnterCriticalSection(&assoc_list_cs);
    if (assoc_gid)
    {
        LIST_FOR_EACH_ENTRY(assoc, &server_assoc_list, RpcAssoc, entry)
        {
            /* FIXME: NetworkAddr shouldn't be NULL */
            if (assoc->assoc_group_id == assoc_gid &&
                !strcmp(Protseq, assoc->Protseq) &&
                (!NetworkAddr || !assoc->NetworkAddr || !strcmp(NetworkAddr, assoc->NetworkAddr)) &&
                !strcmp(Endpoint, assoc->Endpoint) &&
                ((!assoc->NetworkOptions == !NetworkOptions) &&
                 (!NetworkOptions || !wcscmp(NetworkOptions, assoc->NetworkOptions))))
            {
                assoc->refs++;
                *assoc_out = assoc;
                LeaveCriticalSection(&assoc_list_cs);
                TRACE("using existing assoc %p\n", assoc);
                return RPC_S_OK;
            }
        }
        *assoc_out = NULL;
        LeaveCriticalSection(&assoc_list_cs);
        return RPC_S_NO_CONTEXT_AVAILABLE;
    }

    status = RpcAssoc_Alloc(Protseq, NetworkAddr, Endpoint, NetworkOptions, &assoc);
    if (status != RPC_S_OK)
    {
        LeaveCriticalSection(&assoc_list_cs);
        return status;
    }
    assoc->assoc_group_id = InterlockedIncrement(&last_assoc_group_id);
    list_add_head(&server_assoc_list, &assoc->entry);
    *assoc_out = assoc;

    LeaveCriticalSection(&assoc_list_cs);

    TRACE("new assoc %p\n", assoc);

    return RPC_S_OK;
}

static void RpcAssoc_Destroy(RpcAssoc *assoc)
{
    RpcConnection *Connection, *cursor2;
    RpcContextHandle *context_handle, *context_handle_cursor;

    TRACE("destroying assoc %p\n", assoc);

    LIST_FOR_EACH_ENTRY_SAFE(Connection, cursor2, &assoc->free_connection_pool, RpcConnection, conn_pool_entry)
    {
        list_remove(&Connection->conn_pool_entry);
        RPCRT4_ReleaseConnection(Connection);
    }

    LIST_FOR_EACH_ENTRY_SAFE(context_handle, context_handle_cursor, &assoc->context_handle_list, RpcContextHandle, entry)
        RpcContextHandle_Destroy(context_handle);

    free(assoc->NetworkOptions);
    free(assoc->Endpoint);
    free(assoc->NetworkAddr);
    free(assoc->Protseq);

    assoc->cs.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&assoc->cs);
    assoc->group_cs.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&assoc->group_cs);

    free(assoc);
}

/* The idle connections kept for one server (callers that do not share a connection, another identity each time, do not
 * make the pool grow without limit). */
#define MAX_IDLE_CONNECTIONS 8
/* How long a client association whose last binding handle is gone keeps its idle connections for the next binding
 * handle to the same server, and how often the ones that are due are looked for. */
#define IDLE_ASSOC_LIFETIME_MS 30000
#define IDLE_ASSOC_SWEEP_MS    5000

static HANDLE idle_timer;       /* the sweep, while there is an association to wait for; protected by assoc_list_cs */
static BOOL idle_flushing;      /* protected by assoc_list_cs */

static BOOL assoc_has_idle_connections(RpcAssoc *assoc)
{
    BOOL ret;

    EnterCriticalSection(&assoc->cs);
    ret = !list_empty(&assoc->free_connection_pool);
    LeaveCriticalSection(&assoc->cs);
    return ret;
}

static void CALLBACK idle_sweep(void *param, BOOLEAN timed_out)
{
    struct list dead = LIST_INIT(dead);
    RpcAssoc *assoc, *next;
    BOOL again = FALSE;
    HANDLE timer = NULL;
    DWORD now = GetTickCount();

    EnterCriticalSection(&assoc_list_cs);
    LIST_FOR_EACH_ENTRY_SAFE(assoc, next, &client_assoc_list, RpcAssoc, entry)
    {
        if (assoc->refs || !assoc->idle_since) continue;
        if (idle_flushing || now - assoc->idle_since >= IDLE_ASSOC_LIFETIME_MS)
        {
            list_remove(&assoc->entry);
            list_add_tail(&dead, &assoc->entry);
        }
        else
            again = TRUE;
    }
    /* nothing left to wait for: the sweep ends (a new one starts with the next association that is kept) */
    if (!again)
    {
        timer = idle_timer;
        idle_timer = NULL;
    }
    LeaveCriticalSection(&assoc_list_cs);

    if (timer) DeleteTimerQueueTimer(NULL, timer, NULL);
    LIST_FOR_EACH_ENTRY_SAFE(assoc, next, &dead, RpcAssoc, entry)
        RpcAssoc_Destroy(assoc);
}

/* assoc_list_cs is held */
static void arm_idle_timer(void)
{
    if (idle_timer || idle_flushing) return;
    if (!CreateTimerQueueTimer(&idle_timer, NULL, idle_sweep, NULL, IDLE_ASSOC_SWEEP_MS, IDLE_ASSOC_SWEEP_MS,
                               WT_EXECUTEDEFAULT))
        idle_timer = NULL;
}

/* Closes every connection kept for a binding handle that is not there any more (the library is unloading). */
void RpcAssoc_FlushIdle(void)
{
    HANDLE timer;

    EnterCriticalSection(&assoc_list_cs);
    idle_flushing = TRUE;
    timer = idle_timer;
    idle_timer = NULL;
    LeaveCriticalSection(&assoc_list_cs);

    /* waits for a sweep that is running */
    if (timer) DeleteTimerQueueTimer(NULL, timer, INVALID_HANDLE_VALUE);
    idle_sweep(NULL, FALSE);

    EnterCriticalSection(&assoc_list_cs);
    idle_flushing = FALSE;
    LeaveCriticalSection(&assoc_list_cs);
}

ULONG RpcAssoc_Release(RpcAssoc *assoc)
{
    ULONG refs;
    BOOL kept = FALSE;

    EnterCriticalSection(&assoc_list_cs);
    refs = --assoc->refs;
    if (!refs)
    {
        /* A client association with idle connections stays for a while: the next binding handle to the same
         * server (same endpoint, and the same identity and security, which the connections are matched on) uses
         * them instead of opening and binding a new one. */
        if (assoc->is_client && !idle_flushing && assoc_has_idle_connections(assoc))
        {
            kept = TRUE;
            assoc->idle_since = GetTickCount() | 1;
            arm_idle_timer();
        }
        else
            list_remove(&assoc->entry);
    }
    LeaveCriticalSection(&assoc_list_cs);

    if (!refs && !kept)
        RpcAssoc_Destroy(assoc);

    return refs;
}

#define ROUND_UP(value, alignment) (((value) + ((alignment) - 1)) & ~((alignment)-1))

static RPC_STATUS RpcAssoc_BindConnection(const RpcAssoc *assoc, RpcConnection *conn,
                                          const RPC_SYNTAX_IDENTIFIER *InterfaceId,
                                          const RPC_SYNTAX_IDENTIFIER *TransferSyntax)
{
    RpcPktHdr *hdr;
    RpcPktHdr *response_hdr;
    RPC_MESSAGE msg;
    RPC_STATUS status;
    unsigned char *auth_data = NULL;
    ULONG auth_length;

    TRACE("sending bind request to server\n");

    hdr = RPCRT4_BuildBindHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                 RPC_MAX_PACKET_SIZE, RPC_MAX_PACKET_SIZE,
                                 assoc->assoc_group_id,
                                 InterfaceId, TransferSyntax);

    status = RPCRT4_Send(conn, hdr, NULL, 0);
    free(hdr);
    if (status != RPC_S_OK)
        return status;

    status = RPCRT4_ReceiveWithAuth(conn, &response_hdr, &msg, &auth_data, &auth_length);
    if (status != RPC_S_OK)
    {
        ERR("receive failed with error %ld\n", status);
        return status;
    }

    switch (response_hdr->common.ptype)
    {
    case PKT_BIND_ACK:
    {
        RpcAddressString *server_address = msg.Buffer;
        if ((msg.BufferLength >= FIELD_OFFSET(RpcAddressString, string[0])) ||
            (msg.BufferLength >= ROUND_UP(FIELD_OFFSET(RpcAddressString, string[server_address->length]), 4)))
        {
            unsigned short remaining = msg.BufferLength -
            ROUND_UP(FIELD_OFFSET(RpcAddressString, string[server_address->length]), 4);
            RpcResultList *results = (RpcResultList*)((ULONG_PTR)server_address +
                ROUND_UP(FIELD_OFFSET(RpcAddressString, string[server_address->length]), 4));
            if ((results->num_results == 1) &&
                (remaining >= FIELD_OFFSET(RpcResultList, results[results->num_results])))
            {
                switch (results->results[0].result)
                {
                case RESULT_ACCEPT:
                    /* respond to authorization request */
                    if (auth_length > sizeof(RpcAuthVerifier))
                        status = RPCRT4_ClientConnectionAuth(conn,
                                                             auth_data + sizeof(RpcAuthVerifier),
                                                             auth_length);
                    if (status == RPC_S_OK)
                    {
                        conn->assoc_group_id = response_hdr->bind_ack.assoc_gid;
                        conn->MaxTransmissionSize = response_hdr->bind_ack.max_tsize;
                        conn->ActiveInterface = *InterfaceId;
                    }
                    break;
                case RESULT_PROVIDER_REJECTION:
                    switch (results->results[0].reason)
                    {
                    case REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED:
                        ERR("syntax %s, %d.%d not supported\n",
                            debugstr_guid(&InterfaceId->SyntaxGUID),
                            InterfaceId->SyntaxVersion.MajorVersion,
                            InterfaceId->SyntaxVersion.MinorVersion);
                        status = RPC_S_UNKNOWN_IF;
                        break;
                    case REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED:
                        ERR("transfer syntax not supported\n");
                        status = RPC_S_SERVER_UNAVAILABLE;
                        break;
                    case REASON_NONE:
                    default:
                        status = RPC_S_CALL_FAILED_DNE;
                    }
                    break;
                case RESULT_USER_REJECTION:
                default:
                    ERR("rejection result %d\n", results->results[0].result);
                    status = RPC_S_CALL_FAILED_DNE;
                }
            }
            else
            {
                ERR("incorrect results size\n");
                status = RPC_S_CALL_FAILED_DNE;
            }
        }
        else
        {
            ERR("bind ack packet too small (%d)\n", msg.BufferLength);
            status = RPC_S_PROTOCOL_ERROR;
        }
        break;
    }
    case PKT_BIND_NACK:
        switch (response_hdr->bind_nack.reject_reason)
        {
        case REJECT_LOCAL_LIMIT_EXCEEDED:
        case REJECT_TEMPORARY_CONGESTION:
            ERR("server too busy\n");
            status = RPC_S_SERVER_TOO_BUSY;
            break;
        case REJECT_PROTOCOL_VERSION_NOT_SUPPORTED:
            ERR("protocol version not supported\n");
            status = RPC_S_PROTOCOL_ERROR;
            break;
        case REJECT_UNKNOWN_AUTHN_SERVICE:
            ERR("unknown authentication service\n");
            status = RPC_S_UNKNOWN_AUTHN_SERVICE;
            break;
        case REJECT_INVALID_CHECKSUM:
            ERR("invalid checksum\n");
            status = RPC_S_ACCESS_DENIED;
            break;
        default:
            ERR("rejected bind for reason %d\n", response_hdr->bind_nack.reject_reason);
            status = RPC_S_CALL_FAILED_DNE;
        }
        break;
    default:
        ERR("wrong packet type received %d\n", response_hdr->common.ptype);
        status = RPC_S_PROTOCOL_ERROR;
        break;
    }

    I_RpcFree(msg.Buffer);
    free(response_hdr);
    free(auth_data);
    return status;
}

static RpcConnection *RpcAssoc_GetIdleConnection(RpcAssoc *assoc,
                                                 const RPC_SYNTAX_IDENTIFIER *InterfaceId,
                                                 const RPC_SYNTAX_IDENTIFIER *TransferSyntax, const RpcAuthInfo *AuthInfo,
                                                 const RpcQualityOfService *QOS, LPCWSTR CookieAuth,
                                                 BOOL token_key_valid, const RpcTokenKey *token_key)
{
    RpcConnection *Connection, *next;
    struct list dead = LIST_INIT(dead);
    RpcConnection *found = NULL;

    /* A connection is only reused by a caller that would have got the same one: the same interface, the same
     * security (level, service, credentials, server name, quality of service, HTTP cookie) and the same token
     * (the identity a pipe or a security exchange gives the server), never one that opened it for another. */
    if (!token_key_valid) return NULL;

    EnterCriticalSection(&assoc->cs);
    LIST_FOR_EACH_ENTRY_SAFE(Connection, next, &assoc->free_connection_pool, RpcConnection, conn_pool_entry)
    {
        if (!memcmp(&Connection->ActiveInterface, InterfaceId,
                    sizeof(RPC_SYNTAX_IDENTIFIER)) &&
            RpcAuthInfo_IsEqual(Connection->AuthInfo, AuthInfo) &&
            RpcQualityOfService_IsEqual(Connection->QOS, QOS) &&
            !Connection->CookieAuth == !CookieAuth &&
            (!CookieAuth || !wcscmp(Connection->CookieAuth, CookieAuth)) &&
            Connection->token_key_valid &&
            !memcmp(&Connection->token_key, token_key, sizeof(RpcTokenKey)))
        {
            list_remove(&Connection->conn_pool_entry);
            /* the server may have closed it while it was idle */
            if (Connection->ops->is_idle_alive && !Connection->ops->is_idle_alive(Connection))
            {
                TRACE("pooled connection %p was closed by the server\n", Connection);
                list_add_tail(&dead, &Connection->conn_pool_entry);
                continue;
            }
            found = Connection;
            TRACE("got connection from pool %p\n", Connection);
            break;
        }
    }
    LeaveCriticalSection(&assoc->cs);

    LIST_FOR_EACH_ENTRY_SAFE(Connection, next, &dead, RpcConnection, conn_pool_entry)
    {
        list_remove(&Connection->conn_pool_entry);
        RPCRT4_ReleaseConnection(Connection);
    }
    return found;
}

RPC_STATUS RpcAssoc_GetClientConnection(RpcAssoc *assoc,
                                        const RPC_SYNTAX_IDENTIFIER *InterfaceId,
                                        const RPC_SYNTAX_IDENTIFIER *TransferSyntax, RpcAuthInfo *AuthInfo,
                                        RpcQualityOfService *QOS, LPCWSTR CookieAuth,
                                        RpcConnection **Connection, BOOL *from_cache)
{
    RpcConnection *NewConnection;
    RPC_STATUS status;
    BOOL retried = FALSE, naming_group = FALSE;
    ULONG gid;
    RpcTokenKey token_key;
    BOOL token_key_valid = RPCRT4_GetCallerTokenKey(&token_key);

    *Connection = RpcAssoc_GetIdleConnection(assoc, InterfaceId, TransferSyntax, AuthInfo, QOS, CookieAuth,
                                             token_key_valid, &token_key);
    if (*Connection) {
        TRACE("return idle connection %p for association %p\n", *Connection, assoc);
        if (from_cache) *from_cache = TRUE;
        return RPC_S_OK;
    }

    for (;;)
    {
        /* create a new connection */
        status = RPCRT4_CreateConnection(&NewConnection, FALSE /* is this a server connection? */,
            assoc->Protseq, assoc->NetworkAddr,
            assoc->Endpoint, assoc->NetworkOptions,
            AuthInfo, QOS, CookieAuth);
        if (status != RPC_S_OK)
            return status;

        /* Count the connection before it can fail: releasing it always calls
         * RpcAssoc_ConnectionReleased(), so a failed connection must not leave the count
         * negative (the association group id would then never be reset). */
        NewConnection->assoc = assoc;
        NewConnection->token_key_valid = token_key_valid;
        if (token_key_valid) NewConnection->token_key = token_key;
        InterlockedIncrement(&assoc->connection_cnt);
        status = RPCRT4_OpenClientConnection(NewConnection);
        if (status != RPC_S_OK)
        {
            RPCRT4_ReleaseConnection(NewConnection);
            return status;
        }

        /* Connections bound without a group id each get a group of their own at the server, and a context
         * handle of one group is unknown on a connection of another. So while the group is not known only one
         * bind goes out (with id 0), and its answer names the group for all the others. */
        gid = assoc->assoc_group_id;
        if (!gid)
        {
            EnterCriticalSection(&assoc->group_cs);
            gid = assoc->assoc_group_id;
            if (gid)
                LeaveCriticalSection(&assoc->group_cs);
            else
                naming_group = TRUE;
        }
        status = RpcAssoc_BindConnection(assoc, NewConnection, InterfaceId, TransferSyntax);
        if (naming_group)
        {
            if (status == RPC_S_OK)
            {
                EnterCriticalSection(&assoc->cs);
                if (!assoc->assoc_group_id) assoc->assoc_group_id = NewConnection->assoc_group_id;
                LeaveCriticalSection(&assoc->cs);
            }
            naming_group = FALSE;
            LeaveCriticalSection(&assoc->group_cs);
        }
        if (status == RPC_S_OK)
            break;

        RPCRT4_ReleaseConnection(NewConnection);

        /* The association group id was handed out by an earlier server. If the endpoint now belongs
         * to a different server (a restarted service, or the endpoint name of an exited process
         * reused by a new one, e.g. OLE_<pid>), that server does not know the group and rejects the
         * bind. Forget the group and ask for a new one, once. */
        EnterCriticalSection(&assoc->cs);
        if (status == RPC_S_CALL_FAILED_DNE && !retried && gid)
        {
            TRACE("bind rejected, retrying without association group %#lx\n", gid);
            assoc->assoc_group_id = 0;
            retried = TRUE;
            LeaveCriticalSection(&assoc->cs);
            continue;
        }
        LeaveCriticalSection(&assoc->cs);
        return status;
    }

    TRACE("return new connection %p for association %p\n", NewConnection, assoc);
    *Connection = NewConnection;
    if (from_cache) *from_cache = FALSE;
    return RPC_S_OK;
}

void RpcAssoc_ReleaseIdleConnection(RpcAssoc *assoc, RpcConnection *Connection)
{
    unsigned int idle = 0;
    struct list *entry;

    assert(!Connection->server);
    Connection->async_state = NULL;
    EnterCriticalSection(&assoc->cs);
    if (!assoc->assoc_group_id) assoc->assoc_group_id = Connection->assoc_group_id;
    LIST_FOR_EACH(entry, &assoc->free_connection_pool) idle++;
    if (idle < MAX_IDLE_CONNECTIONS)
    {
        list_add_head(&assoc->free_connection_pool, &Connection->conn_pool_entry);
        Connection = NULL;
    }
    LeaveCriticalSection(&assoc->cs);

    /* enough are kept for this server */
    if (Connection) RPCRT4_ReleaseConnection(Connection);
}

void RpcAssoc_ConnectionReleased(RpcAssoc *assoc)
{
    if (InterlockedDecrement(&assoc->connection_cnt))
        return;

    TRACE("Last %p connection released\n", assoc);
    assoc->assoc_group_id = 0;
}

RPC_STATUS RpcServerAssoc_AllocateContextHandle(RpcAssoc *assoc, void *CtxGuard,
                                                NDR_SCONTEXT *SContext)
{
    RpcContextHandle *context_handle;

    context_handle = calloc(1, sizeof(*context_handle));
    if (!context_handle)
        return RPC_S_OUT_OF_MEMORY;

    context_handle->ctx_guard = CtxGuard;
    InitializeCriticalSectionEx(&context_handle->lock, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    context_handle->lock.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RpcContextHandle.lock");
    context_handle->refs = 1;

    /* lock here to mirror unmarshall, so we don't need to special-case the
     * freeing of a non-marshalled context handle */
    EnterCriticalSection(&context_handle->lock);

    EnterCriticalSection(&assoc->cs);
    list_add_tail(&assoc->context_handle_list, &context_handle->entry);
    LeaveCriticalSection(&assoc->cs);

    *SContext = (NDR_SCONTEXT)context_handle;
    return RPC_S_OK;
}

BOOL RpcContextHandle_IsGuardCorrect(NDR_SCONTEXT SContext, void *CtxGuard)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    return context_handle->ctx_guard == CtxGuard;
}

RPC_STATUS RpcServerAssoc_FindContextHandle(RpcAssoc *assoc, const UUID *uuid,
                                            void *CtxGuard, ULONG Flags, NDR_SCONTEXT *SContext)
{
    RpcContextHandle *context_handle;

    EnterCriticalSection(&assoc->cs);
    LIST_FOR_EACH_ENTRY(context_handle, &assoc->context_handle_list, RpcContextHandle, entry)
    {
        if (RpcContextHandle_IsGuardCorrect((NDR_SCONTEXT)context_handle, CtxGuard) &&
            !memcmp(&context_handle->uuid, uuid, sizeof(*uuid)))
        {
            *SContext = (NDR_SCONTEXT)context_handle;
            if (context_handle->refs++)
            {
                LeaveCriticalSection(&assoc->cs);
                TRACE("found %p\n", context_handle);
                EnterCriticalSection(&context_handle->lock);
                return RPC_S_OK;
            }
        }
    }
    LeaveCriticalSection(&assoc->cs);

    ERR("no context handle found for uuid %s, guard %p\n",
        debugstr_guid(uuid), CtxGuard);
    return ERROR_INVALID_HANDLE;
}

RPC_STATUS RpcServerAssoc_UpdateContextHandle(RpcAssoc *assoc,
                                              NDR_SCONTEXT SContext,
                                              void *CtxGuard,
                                              NDR_RUNDOWN rundown_routine)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    RPC_STATUS status;

    if (!RpcContextHandle_IsGuardCorrect((NDR_SCONTEXT)context_handle, CtxGuard))
        return ERROR_INVALID_HANDLE;

    EnterCriticalSection(&assoc->cs);
    if (UuidIsNil(&context_handle->uuid, &status))
    {
        /* add a ref for the data being valid */
        context_handle->refs++;
        UuidCreate(&context_handle->uuid);
        context_handle->rundown_routine = rundown_routine;
        TRACE("allocated uuid %s for context handle %p\n",
              debugstr_guid(&context_handle->uuid), context_handle);
    }
    LeaveCriticalSection(&assoc->cs);

    return RPC_S_OK;
}

void RpcContextHandle_GetUuid(NDR_SCONTEXT SContext, UUID *uuid)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    *uuid = context_handle->uuid;
}

static void RpcContextHandle_Destroy(RpcContextHandle *context_handle)
{
    TRACE("freeing %p\n", context_handle);

    if (context_handle->user_context && context_handle->rundown_routine)
    {
        TRACE("calling rundown routine %p with user context %p\n",
              context_handle->rundown_routine, context_handle->user_context);
        context_handle->rundown_routine(context_handle->user_context);
    }

    context_handle->lock.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&context_handle->lock);

    free(context_handle);
}

unsigned int RpcServerAssoc_ReleaseContextHandle(RpcAssoc *assoc, NDR_SCONTEXT SContext, BOOL release_lock)
{
    RpcContextHandle *context_handle = (RpcContextHandle *)SContext;
    unsigned int refs;

    if (release_lock)
        LeaveCriticalSection(&context_handle->lock);

    EnterCriticalSection(&assoc->cs);
    refs = --context_handle->refs;
    if (!refs)
        list_remove(&context_handle->entry);
    LeaveCriticalSection(&assoc->cs);

    if (!refs)
        RpcContextHandle_Destroy(context_handle);

    return refs;
}
