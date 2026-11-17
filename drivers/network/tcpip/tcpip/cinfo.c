/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/cinfo.c
 * PURPOSE:     Per-socket connection information.
 * PROGRAMMER:  Jérôme Gardou
 */

#include "ntdef.h"
#include "precomp.h"

typedef struct tcp_keepalive {
  ULONG onoff;
  ULONG keepalivetime;
  ULONG keepaliveinterval;
} TCP_KEEPALIVE;

/*
 * The options are kept in the address file and given to the connection endpoint (the first one associated with
 * the address file, when there is one now). A socket sets them before its connection exists (before connect or
 * listen, or while it is only bound): the endpoint takes them when it is associated (DispTdiAssociateAddress),
 * and a connection a listener accepts takes the listener's (TCPAcceptEventHandler).
 */
TDI_STATUS SetConnectionInfo(TDIObjectID *ID,
                             PADDRESS_FILE AddressFile,
                             PVOID Buffer,
                             UINT BufferSize)
{
    ASSERT(ID->toi_type == INFO_TYPE_CONNECTION);
    switch (ID->toi_id)
    {
        case TCP_SOCKET_NODELAY:
            if (BufferSize < sizeof(BOOLEAN))
                return TDI_INVALID_PARAMETER;
            AddressFile->TcpNoDelay = (*(BOOLEAN*)Buffer != 0);
            AddressFile->TcpOptSet |= TCP_OPT_NODELAY;
            break;

        case TCP_SOCKET_KEEPALIVE:
            if (BufferSize < sizeof(DWORD))
                return TDI_INVALID_PARAMETER;
            AddressFile->TcpKeepAlive = (*(DWORD*)Buffer != 0);
            AddressFile->TcpOptSet |= TCP_OPT_KEEPALIVE;
            break;

        case TCP_SOCKET_KEEPALIVEVALS:
        {
            TCP_KEEPALIVE Set;
            if (BufferSize < sizeof(TCP_KEEPALIVE))
                return TDI_INVALID_PARAMETER;
            Set = *(TCP_KEEPALIVE*)Buffer;
            AddressFile->TcpKeepAlive = (Set.onoff != 0);
            AddressFile->TcpKeepAliveTime = Set.keepalivetime;
            AddressFile->TcpKeepAliveInterval = Set.keepaliveinterval;
            AddressFile->TcpOptSet |= TCP_OPT_KEEPALIVE | TCP_OPT_KEEPALIVEVALS;
            break;
        }
        default:
            DbgPrint("TCPIP: Unknown connection info ID: %u.\n", ID->toi_id);
            return TDI_INVALID_PARAMETER;
    }

    /* A connection exists already: it takes the option now */
    if (AddressFile->Connection)
        TCPApplyAddressFileOptions(AddressFile, AddressFile->Connection);

    return TDI_SUCCESS;
}
