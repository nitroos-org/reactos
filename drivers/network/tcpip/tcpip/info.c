/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/info.c
 * PURPOSE:     TDI query and set information routines
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

#include <debug.h>

/* Make room for Needed more entities. The list holds one entity per address
   file, so it grows with the number of sockets. Called and returns with the
   lock held; the lock is dropped while it allocates */
static
BOOLEAN
GrowEntityList(PKIRQL OldIrql, ULONG Needed)
{
    TDIEntityInfo *NewList, *OldList = NULL;
    PUCHAR NewUsed, OldUsed = NULL;
    ULONG Max;

    while (EntityMax - EntityCount < Needed)
    {
        Max = EntityMax;
        TcpipReleaseSpinLock(&EntityListLock, *OldIrql);

        if (Max > MAXULONG / 2 / sizeof(TDIEntityInfo))
        {
            TcpipAcquireSpinLock(&EntityListLock, OldIrql);
            return FALSE;
        }
        NewList = ExAllocatePoolWithTag(NonPagedPool, 2 * Max * sizeof(TDIEntityInfo), TDI_ENTITY_TAG);
        NewUsed = ExAllocatePoolWithTag(NonPagedPool, 2 * Max + 1, TDI_ENTITY_TAG);
        if (!NewList || !NewUsed)
        {
            if (NewList)
                ExFreePoolWithTag(NewList, TDI_ENTITY_TAG);
            if (NewUsed)
                ExFreePoolWithTag(NewUsed, TDI_ENTITY_TAG);
            TcpipAcquireSpinLock(&EntityListLock, OldIrql);
            return FALSE;
        }

        TcpipAcquireSpinLock(&EntityListLock, OldIrql);
        if (EntityMax == Max)
        {
            RtlCopyMemory(NewList, EntityList, EntityCount * sizeof(TDIEntityInfo));
            OldList = EntityList;
            OldUsed = EntityInstanceUsed;
            EntityList = NewList;
            EntityInstanceUsed = NewUsed;
            EntityMax = 2 * Max;
        }
        else
        {
            /* Another caller grew it meanwhile */
            OldList = NewList;
            OldUsed = NewUsed;
        }
        ExFreePoolWithTag(OldList, TDI_ENTITY_TAG);
        ExFreePoolWithTag(OldUsed, TDI_ENTITY_TAG);
    }

    return TRUE;
}

/* Publish Count entities together: room for all of them is made first, so
   either all appear in one hold of the lock or none does, and nothing fails
   once a reader can see one of them */
NTSTATUS AddEntities(const TDI_ENTITY_ADD *Entries, ULONG Count)
{
    KIRQL OldIrql;
    ULONG i, j, Instance;

    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    if (!GrowEntityList(&OldIrql, Count))
    {
        TcpipReleaseSpinLock(&EntityListLock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (j = 0; j < Count; j++)
    {
        /* The lowest instance number this type does not use yet. Only
           EntityCount entities exist, so it is at most EntityCount */
        RtlZeroMemory(EntityInstanceUsed, EntityCount + 1);
        for (i = 0; i < EntityCount; i++)
        {
            if (EntityList[i].tei_entity == Entries[j].EntityType &&
                EntityList[i].tei_instance <= EntityCount)
            {
                EntityInstanceUsed[EntityList[i].tei_instance] = TRUE;
            }
        }
        for (Instance = 0; EntityInstanceUsed[Instance]; Instance++);

        EntityList[EntityCount].tei_entity = Entries[j].EntityType;
        EntityList[EntityCount].tei_instance = Instance;
        EntityList[EntityCount].context = Entries[j].Context;
        EntityList[EntityCount].flags = Entries[j].Flags;
        EntityCount++;
    }

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    return STATUS_SUCCESS;
}

NTSTATUS AddEntity(ULONG EntityType, PVOID Context, ULONG Flags)
{
    TDI_ENTITY_ADD Entry = { EntityType, Context, Flags };

    return AddEntities(&Entry, 1);
}

VOID RemoveEntityByContext(PVOID Context)
{
   ULONG i;
   KIRQL OldIrql;

   TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

   for (i = 0; i < EntityCount; ) {
	if( EntityList[i].context == Context ) {
	    /* The last entity moves into this slot; check the slot again */
	    EntityList[i] = EntityList[--EntityCount];
	} else {
	    i++;
	}
    }

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);
}

PVOID GetContext(TDIEntityID ID)
{
    UINT i;
    KIRQL OldIrql;
    PVOID Context;

    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    for (i = 0; i < EntityCount; i++)
    {
        if (EntityList[i].tei_entity == ID.tei_entity &&
            EntityList[i].tei_instance == ID.tei_instance)
            break;
    }

    if (i == EntityCount)
    {
        TcpipReleaseSpinLock(&EntityListLock, OldIrql);
        DbgPrint("WARNING: Unable to get context for %d %d\n", ID.tei_entity, ID.tei_instance);
        return NULL;
    }

    Context = EntityList[i].context;

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    return Context;
}

/* The INFO_TYPE_ADDRESS_OBJECT and INFO_TYPE_CONNECTION query/set paths treat
 * the resolved entity context as a PADDRESS_FILE and dereference it. Only the
 * transport entities register an address-file context: TiCreateFileObject()
 * (fileobjs.c) publishes CO_TL_ENTITY for TCP, CL_TL_ENTITY for UDP/RawIP and
 * ER_ENTITY for ICMP, each with an ADDRESS_FILE as its context; interface
 * entities (IF, AT, CL_NL, CO_NL in iinfo.c) publish a PIP_INTERFACE instead. toi_entity
 * is chosen by the caller - unprivileged since the non-admin socket change - so
 * resolving an interface (or network-layer) entity here would make
 * Set/GetAddressFileInfo read and write through a mis-typed pointer (kernel
 * pool corruption). Reject any entity that is not an address-file transport
 * entity. Additionally, take a live reference on the address file while the
 * entity-list lock is held, so a concurrent close cannot free it under the
 * caller; GetContext() alone returns an unreferenced pointer. The caller must
 * DereferenceObject() the returned object. Returns NULL for a wrong-typed,
 * absent, or already-closing entity. */
static
PADDRESS_FILE
ReferenceAddressFileByEntity(TDIEntityID ID)
{
    UINT i;
    KIRQL OldIrql;
    PADDRESS_FILE AddrFile;
    LONG OldRefCount;

    switch (ID.tei_entity)
    {
        case CO_TL_ENTITY:
        case CL_TL_ENTITY:
        case ER_ENTITY:
            break;
        default:
            /* Not an address-file entity (would be a PIP_INTERFACE). */
            return NULL;
    }

    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    for (i = 0; i < EntityCount; i++)
    {
        if (EntityList[i].tei_entity == ID.tei_entity &&
            EntityList[i].tei_instance == ID.tei_instance)
            break;
    }

    if (i == EntityCount)
    {
        TcpipReleaseSpinLock(&EntityListLock, OldIrql);
        return NULL;
    }

    AddrFile = EntityList[i].context;

    /* Reference it unless its last reference has already gone - AddrFileFree()
     * is then about to RemoveEntityByContext() (under EntityListLock) and free
     * it. Holding EntityListLock keeps both the entry and the object alive
     * until that removal, so the RefCount read below is safe. */
    do
    {
        OldRefCount = *((volatile LONG *)&AddrFile->RefCount);
        if (OldRefCount == 0)
        {
            TcpipReleaseSpinLock(&EntityListLock, OldIrql);
            return NULL;
        }
    } while (InterlockedCompareExchange(&AddrFile->RefCount,
                                        OldRefCount + 1,
                                        OldRefCount) != OldRefCount);

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    return AddrFile;
}

/* The TCP and UDP connection tables answer for the address file the entity names. The caller picks the
 * entity, so the address file is referenced (not taken from GetContext) while its row is read: a close
 * cannot free it meanwhile. An entity that is not a transport entity, or whose address file is closing,
 * is refused. */
static
TDI_STATUS
QueryConnectionTableByEntity(
    TDIEntityID ID,
    BOOLEAN Tcp,
    PNDIS_BUFFER Buffer,
    PUINT BufferSize,
    TDI_TCPUDP_CLASS_INFO Class)
{
    PADDRESS_FILE AddrFile;
    TDI_STATUS Status;

    AddrFile = ReferenceAddressFileByEntity(ID);
    if (AddrFile == NULL)
        return TDI_INVALID_PARAMETER;

    if (Tcp)
        Status = InfoTdiQueryGetConnectionTcpTable(AddrFile, Buffer, BufferSize, Class);
    else
        Status = InfoTdiQueryGetConnectionUdpTable(AddrFile, Buffer, BufferSize, Class);

    DereferenceObject(AddrFile);
    return Status;
}

/* The connections in TIME_WAIT, as an array of TCP_TIMEWAIT_ROW. They have no address file, so
 * the per-entity queries cannot return them. As for any table, a caller whose buffer does not hold
 * the whole answer gets the size that does; the table can change between the two calls, and the
 * caller asks again when the sizes differ. */
#define MAX_TIME_WAIT_ROWS (1024 * 1024)

static
TDI_STATUS
InfoTdiQueryGetTimeWaitTable(
    PNDIS_BUFFER Buffer,
    PUINT BufferSize)
{
    PTCP_TIMEWAIT_ROW Rows = NULL;
    ULONG Max = 0, Count;
    TDI_STATUS Status;

    if (Buffer && *BufferSize >= sizeof(TCP_TIMEWAIT_ROW))
    {
        Max = min(*BufferSize / sizeof(TCP_TIMEWAIT_ROW), MAX_TIME_WAIT_ROWS);
        Rows = ExAllocatePoolWithTag(NonPagedPool, Max * sizeof(TCP_TIMEWAIT_ROW), TDI_ENTITY_TAG);
        if (!Rows)
            return TDI_NO_RESOURCES;
    }

    Count = TCPEnumTimeWait(Rows, Max);
    if (Count > MAX_TIME_WAIT_ROWS)
        Count = MAX_TIME_WAIT_ROWS;

    if (Count > Max || Count == 0)
    {
        /* Does not fit (only the size is reported), or nothing to copy */
        Status = InfoCopyOut(NULL, Count * sizeof(TCP_TIMEWAIT_ROW), NULL, BufferSize);
    }
    else
    {
        Status = InfoCopyOut((PCHAR)Rows, Count * sizeof(TCP_TIMEWAIT_ROW), Buffer, BufferSize);
    }

    if (Rows)
        ExFreePoolWithTag(Rows, TDI_ENTITY_TAG);
    return Status;
}

/* The interface of an interface entity (IF, AT, CL_NL, CO_NL), referenced for the caller
 * (IPDereferenceInterface), or NULL. IPDestroyInterface removes the entities under
 * EntityListLock before it drops the interface's own reference, so an interface found
 * here under the lock is alive. */
static
PIP_INTERFACE
ReferenceInterfaceByEntity(TDIEntityID ID)
{
    UINT i;
    KIRQL OldIrql;
    PIP_INTERFACE IF = NULL;

    switch (ID.tei_entity)
    {
        case IF_ENTITY:
        case AT_ENTITY:
        case CL_NL_ENTITY:
        case CO_NL_ENTITY:
            break;
        default:
            return NULL;
    }

    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    for (i = 0; i < EntityCount; i++)
    {
        if (EntityList[i].tei_entity == ID.tei_entity &&
            EntityList[i].tei_instance == ID.tei_instance)
        {
            IF = EntityList[i].context;
            IPReferenceInterface(IF);
            break;
        }
    }

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    if (!IF)
        DbgPrint("WARNING: Unable to get context for %d %d\n", ID.tei_entity, ID.tei_instance);

    return IF;
}

TDI_STATUS InfoCopyOut( PCHAR DataOut, UINT SizeOut,
			PNDIS_BUFFER ClientBuf, PUINT ClientBufSize ) {
    UINT RememberedCBSize = *ClientBufSize;
    *ClientBufSize = SizeOut;

    /* The driver returns success even when it couldn't fit every available
     * byte. */
    if( RememberedCBSize < SizeOut || !ClientBuf )
	return TDI_SUCCESS;
    else {
	CopyBufferToBufferChain( ClientBuf, 0, (PCHAR)DataOut, SizeOut );
	return TDI_SUCCESS;
    }
}

TDI_STATUS InfoTdiQueryEntityType(TDIEntityID ID,
                                  PNDIS_BUFFER Buffer,
				  PUINT BufferSize)
{
    KIRQL OldIrql;
    UINT i, Flags = 0;

    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    for (i = 0; i < EntityCount; i++)
    {
        if (EntityList[i].tei_entity == ID.tei_entity &&
            EntityList[i].tei_instance == ID.tei_instance)
            break;
    }

    if (i == EntityCount)
    {
        TcpipReleaseSpinLock(&EntityListLock, OldIrql);
        return TDI_INVALID_PARAMETER;
    }

    Flags = EntityList[i].flags;

    InfoCopyOut((PCHAR)&Flags,
                sizeof(ULONG),
                Buffer,
                BufferSize);

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    return TDI_SUCCESS;
}

TDI_STATUS InfoTdiQueryListEntities(PNDIS_BUFFER Buffer,
				    PUINT BufferSize)
{
    UINT Count, Size, BufSize = *BufferSize;
    KIRQL OldIrql;

    TI_DbgPrint(DEBUG_INFO,("About to copy %d TDIEntityIDs to user\n",
			   EntityCount));

    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    Size = EntityCount * sizeof(TDIEntityID);
    *BufferSize = Size;

    TI_DbgPrint(DEBUG_INFO,("BufSize: %d, NeededSize: %d\n", BufSize, Size));

    if (BufSize < Size || !Buffer)
    {
	TcpipReleaseSpinLock( &EntityListLock, OldIrql );
	/* The buffer is too small to contain requested data, but we return
         * success anyway, as we did everything we wanted. */
	return TDI_SUCCESS;
    }

    /* Return entity list -- Copy only the TDIEntityID parts. */
    for( Count = 0; Count < EntityCount; Count++ ) {
	CopyBufferToBufferChain(Buffer,
				Count * sizeof(TDIEntityID),
				(PCHAR)&EntityList[Count],
				sizeof(TDIEntityID));
    }

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    return TDI_SUCCESS;
}

TDI_STATUS
InfoTdiQueryGetATInfo(
    TDIEntityID ID,
    PIP_INTERFACE Interface,
    PNDIS_BUFFER Buffer,
    PUINT BufferSize)
{
    ULONG ATInfo[2];
    TDI_STATUS Status;

    TI_DbgPrint(DEBUG_INFO, ("Called.\n"));

    if (!Interface)
        return TDI_INVALID_PARAMETER;

    if (*BufferSize < sizeof(ATInfo))
        return STATUS_BUFFER_TOO_SMALL;

    /* FIXME: I have no idea what the first field should contain... */
    ATInfo[0] = 0;
    ATInfo[1] = Interface->Index;

    Status = InfoCopyOut((PCHAR)ATInfo,
                         sizeof(ATInfo),
                         Buffer,
                         BufferSize);

    TI_DbgPrint(DEBUG_INFO, ("Returning %08x\n", Status));

    return Status;
}

TDI_STATUS InfoTdiQueryInformationEx(
  PTDI_REQUEST Request,
  TDIObjectID *ID,
  PNDIS_BUFFER Buffer,
  PUINT BufferSize,
  PVOID Context)
/*
 * FUNCTION: Returns extended information
 * ARGUMENTS:
 *   Request    = Pointer to TDI request structure for the request
 *   ID         = TDI object ID
 *   Buffer     = Pointer to buffer with data to use
 *   BufferSize = Pointer to buffer with size of Buffer. On return
 *                this is filled with number of bytes returned
 *   Context    = Pointer to context buffer
 * RETURNS:
 *   Status of operation
 */
{
    PIP_INTERFACE IF;
    TDI_STATUS InfoStatus;

    TI_DbgPrint(DEBUG_INFO,
		("InfoEx Req: %x %x %x!%04x:%d\n",
		 ID->toi_class,
		 ID->toi_type,
		 ID->toi_id,
		 ID->toi_entity.tei_entity,
		 ID->toi_entity.tei_instance));

    switch (ID->toi_class)
    {
        case INFO_CLASS_GENERIC:
           switch (ID->toi_id)
           {
              case ENTITY_LIST_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 return InfoTdiQueryListEntities(Buffer, BufferSize);

              case ENTITY_TYPE_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 return InfoTdiQueryEntityType(ID->toi_entity, Buffer, BufferSize);

              default:
                 return TDI_INVALID_REQUEST;
           }

        case INFO_CLASS_PROTOCOL:
           if (ID->toi_type == INFO_TYPE_ADDRESS_OBJECT)
           {
               PADDRESS_FILE AddressFile;
               TDI_STATUS AddrStatus;

               AddressFile = ReferenceAddressFileByEntity(ID->toi_entity);
               if (AddressFile == NULL)
                   return TDI_INVALID_PARAMETER;

               AddrStatus = GetAddressFileInfo(ID, AddressFile, Buffer, BufferSize);
               DereferenceObject(AddressFile);
               return AddrStatus;
           }

           switch (ID->toi_id)
           {
              case IF_MIB_STATS_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 if (ID->toi_entity.tei_entity == IF_ENTITY)
                     if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                     {
                         InfoStatus = InfoTdiQueryGetInterfaceMIB(ID->toi_entity, IF, Buffer, BufferSize);
                         IPDereferenceInterface(IF);
                         return InfoStatus;
                     }
                     else
                         return TDI_INVALID_PARAMETER;
                 else if (ID->toi_entity.tei_entity == CL_NL_ENTITY ||
                          ID->toi_entity.tei_entity == CO_NL_ENTITY)
                     if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                     {
                         InfoStatus = InfoTdiQueryGetIPSnmpInfo(ID->toi_entity, IF, Buffer, BufferSize);
                         IPDereferenceInterface(IF);
                         return InfoStatus;
                     }
                     else
                         return TDI_INVALID_PARAMETER;
                 else if (ID->toi_entity.tei_entity == AT_ENTITY)
                     if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                     {
                         InfoStatus = InfoTdiQueryGetATInfo(ID->toi_entity, IF, Buffer, BufferSize);
                         IPDereferenceInterface(IF);
                         return InfoStatus;
                     }
                     else
                         return TDI_INVALID_PARAMETER;
                 else
                     return TDI_INVALID_PARAMETER;

              case IP_MIB_ADDRTABLE_ENTRY_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 if (ID->toi_entity.tei_entity == CL_NL_ENTITY ||
                     ID->toi_entity.tei_entity == CO_NL_ENTITY)
                    return InfoTdiQueryGetAddrTable(ID->toi_entity, Buffer, BufferSize);
                else if (ID->toi_entity.tei_entity == CO_TL_ENTITY)
                     return QueryConnectionTableByEntity(ID->toi_entity, TRUE, Buffer, BufferSize, TcpUdpClassOwnerPid);
                else if (ID->toi_entity.tei_entity == CL_TL_ENTITY)
                     return QueryConnectionTableByEntity(ID->toi_entity, FALSE, Buffer, BufferSize, TcpUdpClassOwnerPid);
                else
                    return TDI_INVALID_PARAMETER;

              case IP_MIB_ARPTABLE_ENTRY_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 if (ID->toi_entity.tei_entity == AT_ENTITY)
                     if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                     {
                         InfoStatus = InfoTdiQueryGetArptableMIB(ID->toi_entity, IF,
                                                           Buffer, BufferSize);
                         IPDereferenceInterface(IF);
                         return InfoStatus;
                     }
                     else
                         return TDI_INVALID_PARAMETER;
                 else if (ID->toi_entity.tei_entity == CO_NL_ENTITY ||
                          ID->toi_entity.tei_entity == CL_NL_ENTITY)
                     if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                     {
                         InfoStatus = InfoTdiQueryGetRouteTable(IF, Buffer, BufferSize);
                         IPDereferenceInterface(IF);
                         return InfoStatus;
                     }
                     else
                         return TDI_INVALID_PARAMETER;
                 else if (ID->toi_entity.tei_entity == CO_TL_ENTITY)
                     return QueryConnectionTableByEntity(ID->toi_entity, TRUE, Buffer, BufferSize, TcpUdpClassBasic);
                 else if (ID->toi_entity.tei_entity == CL_TL_ENTITY)
                     return QueryConnectionTableByEntity(ID->toi_entity, FALSE, Buffer, BufferSize, TcpUdpClassBasic);
                 else
                     return TDI_INVALID_PARAMETER;

              case IP_SPECIFIC_MODULE_ENTRY_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 if (ID->toi_entity.tei_entity == CO_TL_ENTITY)
                     return QueryConnectionTableByEntity(ID->toi_entity, TRUE, Buffer, BufferSize, TcpUdpClassOwner);
                 else if (ID->toi_entity.tei_entity == CL_TL_ENTITY)
                     return QueryConnectionTableByEntity(ID->toi_entity, FALSE, Buffer, BufferSize, TcpUdpClassOwner);
                 else
                     return TDI_INVALID_PARAMETER;

              case IP_TCP_TIMEWAIT_ENTRY_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER ||
                     ID->toi_entity.tei_entity != CO_TL_ENTITY ||
                     ID->toi_entity.tei_instance != 0)
                     return TDI_INVALID_PARAMETER;

                 return InfoTdiQueryGetTimeWaitTable(Buffer, BufferSize);

#if 0
              case IP_INTFC_INFO_ID:
                 if (ID->toi_type != INFO_TYPE_PROVIDER)
                     return TDI_INVALID_PARAMETER;

                 return InfoTdiQueryGetIFInfo(Context, Buffer, BufferSize);
#endif

              default:
                 return TDI_INVALID_REQUEST;
           }

        default:
           return TDI_INVALID_REQUEST;
    }
}

TDI_STATUS InfoTdiSetInformationEx
(PTDI_REQUEST Request,
 TDIObjectID *ID,
 PVOID Buffer,
 UINT BufferSize)
/*
 * FUNCTION: Sets extended information
 * ARGUMENTS:
 *   Request    = Pointer to TDI request structure for the request
 *   ID         = Pointer to TDI object ID
 *   Buffer     = Pointer to buffer with data to use
 *   BufferSize = Size of Buffer
 * RETURNS:
 *   Status of operation
 */
{
    PIP_INTERFACE IF;
    TDI_STATUS InfoStatus;

    switch (ID->toi_class)
    {
        case INFO_CLASS_PROTOCOL:
        {
            switch (ID->toi_type)
            {
                case INFO_TYPE_ADDRESS_OBJECT:
                {
                    PADDRESS_FILE AddressFile;
                    TDI_STATUS AddrStatus;

                    AddressFile = ReferenceAddressFileByEntity(ID->toi_entity);
                    if (AddressFile == NULL)
                        return TDI_INVALID_PARAMETER;

                    AddrStatus = SetAddressFileInfo(ID, AddressFile, Buffer, BufferSize);
                    DereferenceObject(AddressFile);
                    return AddrStatus;
                }
                case INFO_TYPE_CONNECTION:
                {
                    PADDRESS_FILE AddressFile;
                    TDI_STATUS AddrStatus;

                    AddressFile = ReferenceAddressFileByEntity(ID->toi_entity);
                    if (AddressFile == NULL)
                        return TDI_INVALID_PARAMETER;

                    AddrStatus = SetConnectionInfo(ID, AddressFile->Connection, Buffer, BufferSize);
                    DereferenceObject(AddressFile);
                    return AddrStatus;
                }
                case INFO_TYPE_PROVIDER:
                {
                    switch (ID->toi_id)
                    {
                        case IP_MIB_ARPTABLE_ENTRY_ID:
                            if (ID->toi_type != INFO_TYPE_PROVIDER)
                                return TDI_INVALID_PARAMETER;

                            if (ID->toi_entity.tei_entity == AT_ENTITY)
                                if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                                {
                                    InfoStatus = InfoTdiSetArptableMIB(IF, Buffer,
                                        BufferSize);
                                    IPDereferenceInterface(IF);
                                    return InfoStatus;
                                }
                                else
                                    return TDI_INVALID_PARAMETER;
                            else if (ID->toi_entity.tei_entity == CL_NL_ENTITY
                                || ID->toi_entity.tei_entity == CO_NL_ENTITY)
                                if ((IF = ReferenceInterfaceByEntity(ID->toi_entity)))
                                {
                                    InfoStatus = InfoTdiSetRoute(IF, Buffer, BufferSize);
                                    IPDereferenceInterface(IF);
                                    return InfoStatus;
                                }
                                else
                                    return TDI_INVALID_PARAMETER;
                            else
                                return TDI_INVALID_PARAMETER;

                        default:
                            return TDI_INVALID_REQUEST;
                    }
                }
                default:
                    DbgPrint("TCPIP: IOCTL_TCP_SET_INFORMATION_EX - Unrecognized information type for INFO_CLASS_PROTOCOL: %#x.\n", ID->toi_type);
                    return TDI_INVALID_PARAMETER;
            }
            break;
        }
        default:
            DbgPrint("TCPIP: IOCTL_TCP_SET_INFORMATION_EX - Unrecognized information class %#x.\n", ID->toi_class);
            return TDI_INVALID_REQUEST;
    }
}
