/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/iinfo.c
 * PURPOSE:     Per-interface information.
 * PROGRAMMERS: Art Yerkes
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

#include <ipifcons.h>
#include <igmp.h>

/* See iptypes.h */
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128

TDI_STATUS InfoTdiQueryGetInterfaceMIB(TDIEntityID ID,
				       PIP_INTERFACE Interface,
				       PNDIS_BUFFER Buffer,
				       PUINT BufferSize) {
    TDI_STATUS Status = TDI_INVALID_REQUEST;
    IFEntry* OutData;
    PLAN_ADAPTER IF;
    PCHAR IFDescr;
    ULONG Size;
    ULONG Medium;
    NDIS_STATUS NdisStatus;

    if (!Interface)
        return TDI_INVALID_PARAMETER;

    IF = (PLAN_ADAPTER)Interface->Context;

    TI_DbgPrint(DEBUG_INFO,
		("Getting IFEntry MIB (IF %08x LA %08x) (%04x:%d)\n",
		 Interface, IF, ID.tei_entity, ID.tei_instance));

    OutData = ExAllocatePoolWithTag( NonPagedPool, FIELD_OFFSET(IFEntry, if_descr[MAX_ADAPTER_DESCRIPTION_LENGTH + 1]), OUT_DATA_TAG );

    if( !OutData ) return TDI_NO_RESOURCES; /* Out of memory */

    RtlZeroMemory( OutData, FIELD_OFFSET(IFEntry, if_descr[MAX_ADAPTER_DESCRIPTION_LENGTH + 1]));

    OutData->if_index = Interface->Index;
    /* viz: tcpip keeps those indices */
    OutData->if_type = Interface ==
        Loopback ? MIB_IF_TYPE_LOOPBACK : MIB_IF_TYPE_OTHER;
    OutData->if_mtu = Interface->MTU;
    TI_DbgPrint(DEBUG_INFO,
		("Getting interface speed\n"));
    OutData->if_physaddrlen = Interface->AddressLength;
    OutData->if_adminstatus = MIB_IF_ADMIN_STATUS_UP;
    /* NDIS_HARDWARE_STATUS -> ROUTER_CONNECTION_STATE */
    GetInterfaceConnectionStatus( Interface, &OutData->if_operstatus );

    IFDescr = (PCHAR)&OutData->if_descr[0];

    if( IF ) {
        if (OutData->if_type == MIB_IF_TYPE_OTHER)
        {
            NdisStatus = NDISCall(IF,
                                  NdisRequestQueryInformation,
                                  OID_GEN_PHYSICAL_MEDIUM,
                                  &Medium,
                                  sizeof(ULONG));
            if (NdisStatus == NDIS_STATUS_SUCCESS)
            {
                switch (Medium)
                {
#if 0
                    case NdisPhysicalMediumUnspecified:
#endif
                    case NdisPhysicalMediumWirelessLan:
                        /* Win2003: MIB_IF_TYPE_ETHERNET; Vista+: IF_TYPE_IEEE80211 */
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
                        OutData->if_type = IF_TYPE_IEEE80211;
#else
                        OutData->if_type = MIB_IF_TYPE_ETHERNET;
#endif
                        break;
#if 0
                    case NdisPhysicalMediumCableModem:
                    case NdisPhysicalMediumPhoneLine:
                    case NdisPhysicalMediumPowerLine:
                    case NdisPhysicalMediumDSL:
                    case NdisPhysicalMediumFibreChannel:
                    case NdisPhysicalMedium1394:
                    case NdisPhysicalMediumWirelessWan:
#endif
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
                    /* NDIS 6.0+ (Vista+) */
                    case NdisPhysicalMediumNative802_11:
                        OutData->if_type = IF_TYPE_IEEE80211;
                        break;
#endif
#if 0
                    case NdisPhysicalMediumBluetooth:
                    case NdisPhysicalMediumInfiniband:
                    case NdisPhysicalMediumWiMax:
                    case NdisPhysicalMediumUWB:
#endif
                    case NdisPhysicalMedium802_3:
                        OutData->if_type = MIB_IF_TYPE_ETHERNET;
                        break;

                    case NdisPhysicalMedium802_5:
                        OutData->if_type = MIB_IF_TYPE_TOKENRING;
                        break;
#if 0
                    case NdisPhysicalMediumIrda:
                    case NdisPhysicalMediumWiredWAN:
                    case NdisPhysicalMediumWiredCoWan:
                    case NdisPhysicalMediumOther:
#endif
                }
            }
        }

        if (OutData->if_type == MIB_IF_TYPE_OTHER)
        {
            NdisStatus = NDISCall(IF,
                                  NdisRequestQueryInformation,
                                  OID_GEN_MEDIA_SUPPORTED,
                                  &Medium,
                                  sizeof(ULONG));
            if (NdisStatus == NDIS_STATUS_SUCCESS)
            {
                switch (Medium)
                {
                    case NdisMedium802_3:
                        OutData->if_type = MIB_IF_TYPE_ETHERNET;
                        break;

                    case NdisMedium802_5:
                        OutData->if_type = MIB_IF_TYPE_TOKENRING;
                        break;

                    case NdisMediumFddi:
                        OutData->if_type = MIB_IF_TYPE_FDDI;
                        break;
#if 0
                    case NdisMediumWan,
                    case NdisMediumLocalTalk:
                    case NdisMediumDix:
                    case NdisMediumArcnetRaw:
                    case NdisMediumArcnet878_2:
                    case NdisMediumAtm:
                    case NdisMediumWirelessWan:
                    case NdisMediumIrda:
                    case NdisMediumBpc:
                    case NdisMediumCoWan:
                    case NdisMedium1394:
#endif
                }
            }
        }

        GetInterfaceSpeed( Interface, (PUINT)&OutData->if_speed );
        /* No link, no speed (measured on Windows Server 2022: GetIfEntry dwSpeed is 0 while the cable is out) */
        if (OutData->if_operstatus == MIB_IF_OPER_STATUS_NON_OPERATIONAL)
            OutData->if_speed = 0;
        TI_DbgPrint(DEBUG_INFO,
            ("IF Speed = %d * 100bps\n", OutData->if_speed));
        memcpy(OutData->if_physaddr, Interface->Address, Interface->AddressLength);
        TI_DbgPrint(DEBUG_INFO, ("Got HWAddr\n"));

        memcpy(&OutData->if_inoctets, &Interface->Stats, sizeof(SEND_RECV_STATS));

        NdisStatus = NDISCall(IF,
                              NdisRequestQueryInformation,
                              OID_GEN_XMIT_ERROR,
                              &OutData->if_outerrors,
                              sizeof(ULONG));
        if (NdisStatus != NDIS_STATUS_SUCCESS)
            OutData->if_outerrors = 0;

        TI_DbgPrint(DEBUG_INFO, ("OutErrors = %d\n", OutData->if_outerrors));

        NdisStatus = NDISCall(IF,
                              NdisRequestQueryInformation,
                              OID_GEN_RCV_ERROR,
                              &OutData->if_inerrors,
                              sizeof(ULONG));
        if (NdisStatus != NDIS_STATUS_SUCCESS)
            OutData->if_inerrors = 0;

        TI_DbgPrint(DEBUG_INFO, ("InErrors = %d\n", OutData->if_inerrors));
    }

    GetInterfaceName( Interface, IFDescr, MAX_ADAPTER_DESCRIPTION_LENGTH );

    TI_DbgPrint(DEBUG_INFO, ("Copied in name %s\n", IFDescr));
    OutData->if_descrlen = strlen(IFDescr);
    Size = FIELD_OFFSET(IFEntry, if_descr[OutData->if_descrlen + 1]);

    TI_DbgPrint(DEBUG_INFO, ("Finished IFEntry MIB (%04x:%d) size %d\n",
			    ID.tei_entity, ID.tei_instance, Size));

    Status = InfoCopyOut( (PCHAR)OutData, Size, Buffer, BufferSize );
    ExFreePoolWithTag( OutData, OUT_DATA_TAG );

    TI_DbgPrint(DEBUG_INFO,("Returning %x\n", Status));

    return Status;
}

/* Appends a static row for Addr unless the table has one: a multicast address maps to its link address (01-00-5e and the
   low 23 bits), any other address is a broadcast address (all ones) */
static ULONG ArpAddStatic(PIPARP_ENTRY Table, ULONG Count, ULONG Capacity, ULONG Index, ULONG Addr)
{
    PUCHAR Bytes = (PUCHAR)&Addr;
    PIPARP_ENTRY Entry;
    ULONG i;

    for (i = 0; i < Count; i++)
        if (Table[i].LogAddr == Addr)
            return Count;
    if (Count >= Capacity)
        return Count;

    Entry = &Table[Count];
    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->Index = Index;
    Entry->AddrSize = 6;
    Entry->LogAddr = Addr;
    Entry->Type = ARP_ENTRY_STATIC;
    if (IPV4_IS_MULTICAST(Addr))
    {
        Entry->PhysAddr[0] = 0x01;
        Entry->PhysAddr[1] = 0x00;
        Entry->PhysAddr[2] = 0x5e;
        Entry->PhysAddr[3] = Bytes[1] & 0x7f;
        Entry->PhysAddr[4] = Bytes[2];
        Entry->PhysAddr[5] = Bytes[3];
    }
    else
    {
        RtlFillMemory(Entry->PhysAddr, 6, 0xff);
    }
    return Count + 1;
}

/* The table of an interface: the neighbors, and, once it has an IPv4 address, the static rows Windows lists next to them
   (measured on Windows Server 2022): the subnet broadcast address and 255.255.255.255 with the all-ones link address,
   224.0.0.22 (where the IGMPv3 reports go) and every IPv4 group the interface is a member of. */
TDI_STATUS InfoTdiQueryGetArptableMIB(TDIEntityID ID,
				      PIP_INTERFACE Interface,
				      PNDIS_BUFFER Buffer,
				      PUINT BufferSize) {
    NTSTATUS Status;
    ULONG NumNeighbors = NBCopyNeighbors( Interface, NULL, 0 );
    ULONG Unicast = (Interface->Unicast.Type == IP_ADDRESS_V4) ? Interface->Unicast.Address.IPv4Address : 0;
    ULONG NumGroups = 0, Capacity, Count, i;
    PULONG Groups = NULL;
    PIPARP_ENTRY ArpEntries;

    if (Unicast != 0)
        NumGroups = IGMPCopyGroups(Interface->Index, NULL, 0);

    /* the neighbors, the two broadcast addresses, 224.0.0.22 and the groups */
    if (NumNeighbors > 0x10000 || NumGroups > 0x10000)
        return STATUS_INSUFFICIENT_RESOURCES;
    Capacity = NumNeighbors + (Unicast != 0 ? 3 + NumGroups : 0);

    if (Capacity != 0)
    {
        ULONG Seen;

        ArpEntries = ExAllocatePoolWithTag( NonPagedPool, Capacity * sizeof(IPARP_ENTRY), ARP_ENTRY_TAG );
        if( !ArpEntries ) return STATUS_NO_MEMORY;

        /* The cache can change between the count and the copy: the copy is
           capacity-bounded and the reply is clamped to what was copied */
        Seen = NumNeighbors ? NBCopyNeighbors( Interface, ArpEntries, NumNeighbors ) : 0;
        Count = min(Seen, NumNeighbors);

        if (Unicast != 0 && Interface == Loopback)
        {
            /* the loopback interface has the one row, without a link address (measured) */
            ULONG Before = Count;

            Count = ArpAddStatic(ArpEntries, Count, Capacity, Interface->Index, DH2N(0xE0000016));
            if (Count > Before)
            {
                ArpEntries[Before].AddrSize = 0;
                RtlZeroMemory(ArpEntries[Before].PhysAddr, sizeof(ArpEntries[Before].PhysAddr));
            }
        }
        else if (Unicast != 0)
        {
            if (NumGroups != 0)
                Groups = ExAllocatePoolWithTag( NonPagedPool, NumGroups * sizeof(ULONG), ARP_ENTRY_TAG );
            Seen = Groups ? IGMPCopyGroups(Interface->Index, Groups, NumGroups) : 0;

            if (Interface->Broadcast.Address.IPv4Address != 0)
                Count = ArpAddStatic(ArpEntries, Count, Capacity, Interface->Index, Interface->Broadcast.Address.IPv4Address);
            Count = ArpAddStatic(ArpEntries, Count, Capacity, Interface->Index, 0xFFFFFFFF);
            Count = ArpAddStatic(ArpEntries, Count, Capacity, Interface->Index, DH2N(0xE0000016));
            for (i = 0; i < min(Seen, NumGroups); i++)
                Count = ArpAddStatic(ArpEntries, Count, Capacity, Interface->Index, Groups[i]);
            if (Groups)
                ExFreePoolWithTag( Groups, ARP_ENTRY_TAG );
        }

        Status = InfoCopyOut( (PVOID)ArpEntries, Count * sizeof(IPARP_ENTRY), Buffer, BufferSize );

        ExFreePoolWithTag( ArpEntries, ARP_ENTRY_TAG );
    }
    else
    {
        Status = InfoCopyOut(NULL, 0, NULL, BufferSize);
    }

    return Status;
}

TDI_STATUS InfoTdiSetArptableMIB(PIP_INTERFACE IF, PVOID Buffer, UINT BufferSize)
{
    PIPARP_ENTRY ArpEntry = Buffer;
    IP_ADDRESS Address;
    PNEIGHBOR_CACHE_ENTRY NCE, OldNCE;

    if (!Buffer || BufferSize < sizeof(IPARP_ENTRY))
        return TDI_INVALID_PARAMETER;

    if (ArpEntry->AddrSize > sizeof(ArpEntry->PhysAddr))
        return TDI_INVALID_PARAMETER;

    AddrInitIPv4(&Address, ArpEntry->LogAddr);

    if ((OldNCE = NBLocateNeighbor(&Address, IF)))
        NBRemoveNeighbor(OldNCE);

    NCE = NBAddNeighbor(IF,
                        &Address,
                        ArpEntry->PhysAddr,
                        ArpEntry->AddrSize,
                        NUD_PERMANENT,
                        0);

    if (OldNCE)
    {
        /* The routes through the old entry (a gateway) use the new one */
        if (NCE)
            RouterReplaceRouter(OldNCE, NCE);
        NBDereferenceNeighbor(OldNCE);
    }

    if (!NCE)
        return TDI_INVALID_PARAMETER;

    NBDereferenceNeighbor(NCE);
    return TDI_SUCCESS;
}

/* All three entities appear together or not at all: a query can never see
   an interface whose creation is then undone */
NTSTATUS InsertTDIInterfaceEntity( PIP_INTERFACE Interface ) {
    TDI_ENTITY_ADD Entries[3] = {
        { IF_ENTITY, Interface, IF_MIB },
        { AT_ENTITY, Interface, (Interface != Loopback) ? AT_ARP : AT_NULL },
        /* FIXME: This is probably wrong */
        { CL_NL_ENTITY, Interface, CL_NL_IP },
    };

    return AddEntities(Entries, ARRAYSIZE(Entries));
}

VOID RemoveTDIInterfaceEntity( PIP_INTERFACE Interface ) {
    /* This removes all of them */
    RemoveEntityByContext(Interface);
}
