/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/iphlpapi/address.c
 * PURPOSE:         iphlpapi implementation - Adapter Address APIs
 * PROGRAMMERS:     Jérôme Gardou (jerome.gardou@reactos.org)
 */

#include "iphlpapi_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);
#ifdef GetAdaptersAddressesV2
/* Helper for GetAdaptersAddresses:
 * Retrieves the list of network adapters from tcpip.sys */
static
NTSTATUS
GetInterfacesList(
    _In_ HANDLE TcpFile,
    _Out_ TDIEntityID **EntityList,
    _Out_ ULONG* InterfaceCount)
{

    TCP_REQUEST_QUERY_INFORMATION_EX TcpQueryInfo;
    IO_STATUS_BLOCK StatusBlock;
    NTSTATUS Status;
    ULONG_PTR BufferSize;

    ZeroMemory(&TcpQueryInfo, sizeof(TcpQueryInfo));
    TcpQueryInfo.ID.toi_class = INFO_CLASS_GENERIC;
    TcpQueryInfo.ID.toi_type = INFO_TYPE_PROVIDER;
    TcpQueryInfo.ID.toi_id = ENTITY_LIST_ID;
    TcpQueryInfo.ID.toi_entity.tei_entity = GENERIC_ENTITY;
    TcpQueryInfo.ID.toi_entity.tei_instance = 0;

    Status = NtDeviceIoControlFile(
        TcpFile,
        NULL,
        NULL,
        NULL,
        &StatusBlock,
        IOCTL_TCP_QUERY_INFORMATION_EX,
        &TcpQueryInfo,
        sizeof(TcpQueryInfo),
        NULL,
        0);
    if (Status == STATUS_PENDING)
    {
        /* So we have to wait a bit */
        Status = NtWaitForSingleObject(TcpFile, FALSE, NULL);
        if (NT_SUCCESS(Status))
            Status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
        return Status;

    BufferSize = StatusBlock.Information;
    *EntityList = HeapAlloc(GetProcessHeap(), 0, BufferSize);
    if (!*EntityList)
        return STATUS_NO_MEMORY;

    /* Do the real call */
    Status = NtDeviceIoControlFile(
        TcpFile,
        NULL,
        NULL,
        NULL,
        &StatusBlock,
        IOCTL_TCP_QUERY_INFORMATION_EX,
        &TcpQueryInfo,
        sizeof(TcpQueryInfo),
        *EntityList,
        BufferSize);
    if (Status == STATUS_PENDING)
    {
        /* So we have to wait a bit */
        Status = NtWaitForSingleObject(TcpFile, FALSE, NULL);
        if (NT_SUCCESS(Status))
            Status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        HeapFree(GetProcessHeap(), 0, *EntityList);
        return Status;
    }

    *InterfaceCount = BufferSize / sizeof(TDIEntityID);
    return Status;
}

static
NTSTATUS
GetSnmpInfo(
    _In_ HANDLE TcpFile,
    _In_ TDIEntityID InterfaceID,
    _Out_ IPSNMPInfo* Info)
{
    TCP_REQUEST_QUERY_INFORMATION_EX TcpQueryInfo;
    IO_STATUS_BLOCK StatusBlock;
    NTSTATUS Status;

    ZeroMemory(&TcpQueryInfo, sizeof(TcpQueryInfo));
    TcpQueryInfo.ID.toi_class = INFO_CLASS_PROTOCOL;
    TcpQueryInfo.ID.toi_type = INFO_TYPE_PROVIDER;
    TcpQueryInfo.ID.toi_id = IP_MIB_STATS_ID;
    TcpQueryInfo.ID.toi_entity = InterfaceID;

    Status = NtDeviceIoControlFile(
        TcpFile,
        NULL,
        NULL,
        NULL,
        &StatusBlock,
        IOCTL_TCP_QUERY_INFORMATION_EX,
        &TcpQueryInfo,
        sizeof(TcpQueryInfo),
        Info,
        sizeof(*Info));
    if (Status == STATUS_PENDING)
    {
        /* So we have to wait a bit */
        Status = NtWaitForSingleObject(TcpFile, FALSE, NULL);
        if (NT_SUCCESS(Status))
            Status = StatusBlock.Status;
    }

    return Status;
}

static
NTSTATUS
GetAddrEntries(
    _In_ HANDLE TcpFile,
    _In_ TDIEntityID InterfaceID,
    _Out_ IPAddrEntry* Entries,
    _In_ ULONG NumEntries)
{
    TCP_REQUEST_QUERY_INFORMATION_EX TcpQueryInfo;
    IO_STATUS_BLOCK StatusBlock;
    NTSTATUS Status;

    ZeroMemory(&TcpQueryInfo, sizeof(TcpQueryInfo));
    TcpQueryInfo.ID.toi_class = INFO_CLASS_PROTOCOL;
    TcpQueryInfo.ID.toi_type = INFO_TYPE_PROVIDER;
    TcpQueryInfo.ID.toi_id = IP_MIB_ADDRTABLE_ENTRY_ID;
    TcpQueryInfo.ID.toi_entity = InterfaceID;

    Status = NtDeviceIoControlFile(
        TcpFile,
        NULL,
        NULL,
        NULL,
        &StatusBlock,
        IOCTL_TCP_QUERY_INFORMATION_EX,
        &TcpQueryInfo,
        sizeof(TcpQueryInfo),
        Entries,
        NumEntries * sizeof(Entries[0]));
    if (Status == STATUS_PENDING)
    {
        /* So we have to wait a bit */
        Status = NtWaitForSingleObject(TcpFile, FALSE, NULL);
        if (NT_SUCCESS(Status))
            Status = StatusBlock.Status;
    }

    return Status;
}

/*
 * Fills the IFEntry buffer from tcpip.sys.
 * The buffer size MUST be FIELD_OFFSET(IFEntry, if_descr[MAX_ADAPTER_DESCRIPTION_LENGTH + 1]).
 * See MSDN IFEntry struct definition if you don't believe me. ;-)
 */
static
NTSTATUS
GetInterfaceEntry(
    _In_ HANDLE TcpFile,
    _In_ TDIEntityID InterfaceID,
    _Out_ IFEntry* Entry)
{
    TCP_REQUEST_QUERY_INFORMATION_EX TcpQueryInfo;
    IO_STATUS_BLOCK StatusBlock;
    NTSTATUS Status;

    ZeroMemory(&TcpQueryInfo, sizeof(TcpQueryInfo));
    TcpQueryInfo.ID.toi_class = INFO_CLASS_PROTOCOL;
    TcpQueryInfo.ID.toi_type = INFO_TYPE_PROVIDER;
    TcpQueryInfo.ID.toi_id = IP_MIB_STATS_ID;
    TcpQueryInfo.ID.toi_entity = InterfaceID;

    Status = NtDeviceIoControlFile(
        TcpFile,
        NULL,
        NULL,
        NULL,
        &StatusBlock,
        IOCTL_TCP_QUERY_INFORMATION_EX,
        &TcpQueryInfo,
        sizeof(TcpQueryInfo),
        Entry,
        FIELD_OFFSET(IFEntry, if_descr[MAX_ADAPTER_DESCRIPTION_LENGTH + 1]));
    if (Status == STATUS_PENDING)
    {
        /* So we have to wait a bit */
        Status = NtWaitForSingleObject(TcpFile, FALSE, NULL);
        if (NT_SUCCESS(Status))
            Status = StatusBlock.Status;
    }

    return Status;
}

/* Helpers to get the list of DNS for an interface */
static
VOID
EnumerateServerNameSize(
    _In_ PWCHAR Interface,
    _In_ PWCHAR NameServer,
    _Inout_ PVOID Data)
{
    ULONG* BufferSize = Data;

    /* This is just sizing here */
    UNREFERENCED_PARAMETER(Interface);
    UNREFERENCED_PARAMETER(NameServer);

    *BufferSize += sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS) + sizeof(SOCKADDR);
}

static
VOID
EnumerateServerName(
    _In_ PWCHAR Interface,
    _In_ PWCHAR NameServer,
    _Inout_ PVOID Data)
{
    PIP_ADAPTER_DNS_SERVER_ADDRESS** Ptr = Data;
    PIP_ADAPTER_DNS_SERVER_ADDRESS ServerAddress = **Ptr;
    PCWSTR Terminator;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Interface);

    ServerAddress->Length = sizeof(IP_ADAPTER_DNS_SERVER_ADDRESS);
    ServerAddress->Address.lpSockaddr = (PVOID)(ServerAddress + 1);
    ServerAddress->Address.iSockaddrLength = sizeof(SOCKADDR);

    ServerAddress->Address.lpSockaddr->sa_family = AF_INET;
    ((LPSOCKADDR_IN)ServerAddress->Address.lpSockaddr)->sin_port = 0;

    Status = RtlIpv4StringToAddressW(NameServer, FALSE, &Terminator, 
                                     &((LPSOCKADDR_IN)ServerAddress->Address.lpSockaddr)->sin_addr);
    if (!NT_SUCCESS(Status))
    {
        /* Pass along, name conversion failed */
        ERR("%S is not a valid IP address\n", NameServer);
        return;
    }

    /* Go to next item */
    ServerAddress->Next = (PVOID)(ServerAddress->Address.lpSockaddr + 1);
    *Ptr = &ServerAddress->Next;
}

static
VOID
QueryFlags(
    _In_ PUCHAR Interface,
    _In_ DWORD InterfaceLength,
    _Out_ LPDWORD Flags)
{
    HKEY InterfaceKey;
    CHAR KeyName[256];
    DWORD Type, Size, Data;

    /*
     * Windows 10 22H2 (measured): Ethernet 0x1c5, loopback 0x181 =
     *  0x001 DDNS_ENABLED          every interface registers its address in DNS unless
     *                              RegistrationEnabled is 0 (the loopback has no settings: on)
     *  0x004 DHCP_ENABLED          EnableDHCP
     *  0x040 NETBIOS_OVER_TCPIP    NOT set: this tree has no NetBT, NetBIOS over TCP/IP is not enabled
     *  0x080 IPV4_ENABLED          the stack is IPv4, every interface carries it; .NET
     *                              GetIPv4Properties refuses an interface without this bit
     *  0x100 IPV6_ENABLED          NOT set: there is no IPv6 stack (Ipv6IfIndex is 0). .NET would build
     *                              the IPv6 interface properties for the adapter and callers would try
     *                              IPv6 sockets that cannot work here
     */
    *Flags = IP_ADAPTER_IPV4_ENABLED | IP_ADAPTER_DDNS_ENABLED;

    snprintf(KeyName, 256,
             "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%*s",
             InterfaceLength, Interface);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &InterfaceKey) == ERROR_SUCCESS)
    {
        Size = sizeof(DWORD);
        if (RegQueryValueExA(InterfaceKey, "EnableDHCP", NULL, &Type, (LPBYTE)&Data, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Data == 1)
        {
            *Flags |= IP_ADAPTER_DHCP_ENABLED;
        }

        Size = sizeof(DWORD);
        if (RegQueryValueExA(InterfaceKey, "RegisterAdapterName", NULL, &Type, (LPBYTE)&Data, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Data == 1)
        {
            *Flags |= IP_ADAPTER_REGISTER_ADAPTER_SUFFIX;
        }

        Size = sizeof(DWORD);
        if (RegQueryValueExA(InterfaceKey, "RegistrationEnabled", NULL, &Type, (LPBYTE)&Data, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Data == 0)
        {
            *Flags &= ~IP_ADAPTER_DDNS_ENABLED;
        }

        RegCloseKey(InterfaceKey);
    }

    // FIXME: handle 0x8 -> 0x20
}

static
ULONG
CountPrefixBits(
    _In_ ULONG Netmask)
{
    ULONG i, BitCount = 0;

    for (i = 0; i < sizeof(ULONG) * 8; i++)
    {
        if ((Netmask & (1 << i)) == 0)
            break;
        BitCount++;
    }

    return BitCount;
}

/* The layout Windows 7 returns; the headers of this tree stop before FirstDnsSuffix. */
typedef struct _IP_ADAPTER_ADDRESSES_W7
{
    IP_ADAPTER_ADDRESSES_LH Lh;
    PVOID FirstDnsSuffix;
} IP_ADAPTER_ADDRESSES_W7;

C_ASSERT(FIELD_OFFSET(IP_ADAPTER_ADDRESSES_LH, FirstPrefix) == FIELD_OFFSET(IP_ADAPTER_ADDRESSES, FirstPrefix));

/*
 * V6 is the IPv6 state of the stack: empty while IPv6 is off, and then nothing below differs from a system without
 * IPv6. With IPv6 on, an interface that has it is flagged IP_ADAPTER_IPV6_ENABLED with Ipv6IfIndex (whatever
 * Family asks for, Windows 10 measured), Family AF_INET6 lists only the IPv6 addresses, and AF_UNSPEC lists them
 * before the IPv4 ones.
 */
static
DWORD
GetAdaptersAddressesImpl(
    _In_ ULONG Family,
    _In_ ULONG Flags,
    _In_ PVOID Reserved,
    _Inout_ PIP_ADAPTER_ADDRESSES pAdapterAddresses,
    _Inout_ PULONG pOutBufLen,
    _In_ const IPV6_STATE *V6)
{
    BOOL V6On = (V6->Header != NULL);
    BOOL SkipV4 = FALSE;
    NTSTATUS Status;
    HANDLE TcpFile;
    TDIEntityID* InterfacesList;
    ULONG InterfacesCount;
    ULONG AdaptersCount = 0;
    ULONG i;
    ULONG TotalSize = 0, RemainingSize, BufferSize;
    PULONG AdapterIndexes = NULL;
    ULONG AdapterIndexCount = 0;
    BYTE* Ptr = (BYTE*)pAdapterAddresses;
    DWORD MIN_SIZE = 15 * 1024;
    PIP_ADAPTER_ADDRESSES PreviousAA = NULL;

    TRACE("Family %u, Flags 0x%08x, Reserved %p, pAdapterAddress %p, pOutBufLen %p\n",
          Family, Flags, Reserved, pAdapterAddresses, pOutBufLen);

    if (!pOutBufLen)
        return ERROR_INVALID_PARAMETER;

    // FIXME: the exact needed size should be computed first, BEFORE doing any write to the output buffer.
    // As suggested by MSDN, require a 15 KB buffer, which allows to React properly to length checks.
    if(!Ptr || *pOutBufLen < MIN_SIZE)
    {
        *pOutBufLen = MIN_SIZE;
        return ERROR_BUFFER_OVERFLOW;
    }

    switch(Family)
    {
        case AF_INET:
            break;
        case AF_INET6:
            if (!V6On)
            {
                /* One day maybe... */
                FIXME("IPv6 is not supported in ReactOS!\n");
                /* We got nothing to say in this case */
                return ERROR_NO_DATA;
            }
            /* Only the IPv6 addresses: no IPv4 address, prefix, gateway or name server */
            SkipV4 = TRUE;
            Flags |= GAA_FLAG_SKIP_DNS_SERVER;
            Flags &= ~GAA_FLAG_INCLUDE_GATEWAYS;
            break;
        case AF_UNSPEC:
            if (!V6On)
            {
                WARN("IPv6 addresses ignored, IPv4 only\n");
                Family = AF_INET;
            }
            break;
        default:
            ERR("Invalid family 0x%x\n", Family);
            return ERROR_INVALID_PARAMETER;
            break;
    }

    BufferSize = RemainingSize = *pOutBufLen;
    if (Ptr)
        ZeroMemory(Ptr, RemainingSize);

    /* open the tcpip driver */
    Status = openTcpFile(&TcpFile, FILE_READ_DATA);
    if (!NT_SUCCESS(Status))
    {
        ERR("Could not open handle to tcpip.sys. Status %08x\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    /* Get the interfaces list */
    Status = GetInterfacesList(TcpFile, &InterfacesList, &InterfacesCount);
    if (!NT_SUCCESS(Status))
    {
        ERR("Could not get adapters list. Status %08x\n", Status);
        NtClose(TcpFile);
        return RtlNtStatusToDosError(Status);
    }

    /* The indexes of the adapters, to tell which gateways belong to one */
    AdapterIndexes = HeapAlloc(GetProcessHeap(), 0, (InterfacesCount + 1) * sizeof(ULONG));
    if (!AdapterIndexes)
    {
        Status = STATUS_NO_MEMORY;
        goto Error;
    }

    /* Let's see if we got any adapter. */
    for (i = 0; i < InterfacesCount; i++)
    {
        PIP_ADAPTER_ADDRESSES CurrentAA = (PIP_ADAPTER_ADDRESSES)Ptr;
        ULONG CurrentAASize = 0;
        ULONG FriendlySize = 0, DescriptionSize = 0;
        ULONG DhcpDomainSize = 0, DomainSize = 0;

        if (InterfacesList[i].tei_entity == IF_ENTITY)
        {
            BYTE EntryBuffer[FIELD_OFFSET(IFEntry, if_descr) +
                             RTL_FIELD_SIZE(IFEntry, if_descr[0]) * (MAX_ADAPTER_DESCRIPTION_LENGTH + 1)];
            IFEntry* Entry = (IFEntry*)EntryBuffer;

            /* Remember we got one */
            AdaptersCount++;

            /* Of course we need some space for the base structure. */
            CurrentAASize = sizeof(IP_ADAPTER_ADDRESSES_W7);

            /* Get the entry */
            Status = GetInterfaceEntry(TcpFile, InterfacesList[i], Entry);
            if (!NT_SUCCESS(Status))
                goto Error;

            /* Family IPv6 lists the adapters that have IPv6 (Windows 10 measured) */
            if (SkipV4 && !Ipv6FindInterface(V6, Entry->if_index))
            {
                AdaptersCount--;
                continue;
            }

            AdapterIndexes[AdapterIndexCount++] = Entry->if_index;

            TRACE("Got entity %*s, index %u.\n",
                Entry->if_descrlen, &Entry->if_descr[0], Entry->if_index);

            /* Add the adapter name */
            CurrentAASize += Entry->if_descrlen + sizeof(CHAR);

            /* Add the DNS suffix */
            if (Entry->if_type != IF_TYPE_SOFTWARE_LOOPBACK)
            {
                HKEY InterfaceKey;
                CHAR KeyName[256];
                DWORD ValueType, ValueSize, Data;

                snprintf(KeyName, 256,
                    "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%*s",
                    Entry->if_descrlen, &Entry->if_descr[0]);

                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &InterfaceKey) == ERROR_SUCCESS)
                {
                    ValueSize = sizeof(DWORD);
                    if (RegQueryValueExW(InterfaceKey, L"EnableDHCP", NULL, &ValueType, (LPBYTE)&Data, &ValueSize) == ERROR_SUCCESS &&
                        ValueType == REG_DWORD && Data == 1)
                    {
                        ValueSize = sizeof(DWORD);
                        if (RegQueryValueExW(InterfaceKey, L"DhcpDomain", NULL, &ValueType, NULL, &ValueSize) == ERROR_SUCCESS &&
                            ValueType == REG_SZ)
                        {
                            /* We remove the null char, it will be re-added after */
                            DhcpDomainSize = ValueSize - sizeof(WCHAR);
                            CurrentAASize += DhcpDomainSize;
                        }
                    }
                    else
                    {
                        ValueSize = sizeof(DWORD);
                        if (RegQueryValueExW(InterfaceKey, L"Domain", NULL, &ValueType, NULL, &ValueSize) == ERROR_SUCCESS &&
                            ValueType == REG_SZ)
                        {
                            /* We remove the null char, it will be re-added after */
                            DomainSize = ValueSize - sizeof(WCHAR);
                            CurrentAASize += DomainSize;
                        }
                    }

                    RegCloseKey(InterfaceKey);
                }
            }

            CurrentAASize += sizeof(WCHAR);

            /* Add the description. */
            if (Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK)
            {
                DescriptionSize = mbstowcs(NULL, (PCSTR)&Entry->if_descr[0], Entry->if_descrlen) * sizeof(WCHAR);
                CurrentAASize += DescriptionSize;
            }
            else
            {
                HKEY ConnectionKey;
                CHAR KeyName[256];
                CHAR InstanceID[128];
                DWORD ValueType = 0;
                DWORD ValueSize = 0;

                snprintf(KeyName, 256,
                    "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%*s\\Connection",
                    Entry->if_descrlen, &Entry->if_descr[0]);

                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &ConnectionKey) == ERROR_SUCCESS)
                {
                    ValueSize = 128;
                    RegQueryValueExA(ConnectionKey, "PnpInstanceID", NULL, &ValueType, (LPBYTE)InstanceID, &ValueSize);
                    RegCloseKey(ConnectionKey);
                }

                if (ValueSize != 0)
                {
                    sprintf(KeyName, "SYSTEM\\CurrentControlSet\\Enum\\%s", InstanceID);

                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &ConnectionKey) == ERROR_SUCCESS)
                    {
                        ValueSize = 0;
                        if (RegQueryValueExW(ConnectionKey, L"DeviceDesc", NULL, &ValueType, NULL, &ValueSize) == ERROR_SUCCESS &&
                            ValueType == REG_SZ)
                        {
                            /* We remove the null char, it will be re-added after */
                            DescriptionSize = ValueSize - sizeof(WCHAR);
                            CurrentAASize += DescriptionSize;
                        }

                        RegCloseKey(ConnectionKey);
                    }
                }
            }

            /* We always make sure to have enough room for empty string */
            CurrentAASize += sizeof(WCHAR);

            if (!(Flags & GAA_FLAG_SKIP_FRIENDLY_NAME))
            {
                if (Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK)
                {
                    FriendlySize = mbstowcs(NULL, (PCSTR)&Entry->if_descr[0], Entry->if_descrlen) * sizeof(WCHAR);
                    CurrentAASize += FriendlySize;
                }
                else
                {
                    /* Get the friendly name */
                    HKEY ConnectionKey;
                    CHAR KeyName[256];

                    snprintf(KeyName, 256,
                        "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%*s\\Connection",
                        Entry->if_descrlen, &Entry->if_descr[0]);

                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &ConnectionKey) == ERROR_SUCCESS)
                    {
                        DWORD ValueType;
                        DWORD ValueSize = 0;

                        if (RegQueryValueExW(ConnectionKey, L"Name", NULL, &ValueType, NULL, &ValueSize) == ERROR_SUCCESS &&
                            ValueType == REG_SZ)
                        {
                            /* We remove the null char, it will be re-added after */
                            FriendlySize = ValueSize - sizeof(WCHAR);
                            CurrentAASize += FriendlySize;
                        }

                        RegCloseKey(ConnectionKey);
                    }
                }

                /* We always make sure to have enough room for empty string */
                CurrentAASize += sizeof(WCHAR);
            }

            if (!(Flags & GAA_FLAG_SKIP_DNS_SERVER))
            {
                /* Enumerate the name servers */
                HKEY InterfaceKey;
                CHAR KeyName[256];

                snprintf(KeyName, 256,
                    "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%*s",
                    Entry->if_descrlen, &Entry->if_descr[0]);

                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &InterfaceKey) == ERROR_SUCCESS)
                {
                    EnumNameServers(InterfaceKey, NULL, &CurrentAASize, EnumerateServerNameSize);
                    RegCloseKey(InterfaceKey);
                }
            }

            /* This is part of what we will need */
            TotalSize += CurrentAASize;

            /* Fill in the data */
            if ((CurrentAA) && (RemainingSize >= CurrentAASize))
            {
                /* Only an adapter that was written is linked in */
                if (PreviousAA)
                    PreviousAA->Next = CurrentAA;

                CurrentAA->Length = sizeof(IP_ADAPTER_ADDRESSES_W7);
                CurrentAA->IfIndex = Entry->if_index;
                ((IP_ADAPTER_ADDRESSES_LH*)CurrentAA)->Luid.Value = makeInterfaceLuid(Entry->if_index, Entry->if_type);
                CopyMemory(CurrentAA->PhysicalAddress, Entry->if_physaddr, Entry->if_physaddrlen);
                CurrentAA->PhysicalAddressLength = Entry->if_physaddrlen;
                QueryFlags(&Entry->if_descr[0], Entry->if_descrlen, &CurrentAA->Flags);
                if (V6On && Ipv6FindInterface(V6, Entry->if_index))
                {
                    ULONG Zone;

                    /* Windows 10 (measured): the same for any Family; the zones of an interface are its own
                       index for the interface and link scopes and 1 above them (the site, admin and
                       organization scopes, and the global one), 0 for the unused level 14 */
                    CurrentAA->Flags |= IP_ADAPTER_IPV6_ENABLED;
                    CurrentAA->Ipv6IfIndex = Entry->if_index;
                    for (Zone = 0; Zone < 16; Zone++)
                        ((IP_ADAPTER_ADDRESSES_LH*)CurrentAA)->ZoneIndices[Zone] =
                            (Zone < 4) ? Entry->if_index : (Zone == 14 ? 0 : 1);
                }
                if (Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK)
                {
                    /* Windows 10 (measured): the loopback has no MTU limit (.NET reads -1), 1 Gbit/s */
                    CurrentAA->Mtu = 0xFFFFFFFF;
                    ((IP_ADAPTER_ADDRESSES_LH*)CurrentAA)->TransmitLinkSpeed = 1073741824ULL;
                }
                else
                {
                    CurrentAA->Mtu = Entry->if_mtu;
                    ((IP_ADAPTER_ADDRESSES_LH*)CurrentAA)->TransmitLinkSpeed = Entry->if_speed;
                }
                ((IP_ADAPTER_ADDRESSES_LH*)CurrentAA)->ReceiveLinkSpeed =
                    ((IP_ADAPTER_ADDRESSES_LH*)CurrentAA)->TransmitLinkSpeed;
                CurrentAA->IfType = Entry->if_type;
                if(Entry->if_operstatus >= IF_OPER_STATUS_CONNECTING)
                    CurrentAA->OperStatus = IfOperStatusUp;
                else
                    CurrentAA->OperStatus = IfOperStatusDown;

                /* Next items */
                Ptr = (BYTE*)CurrentAA + sizeof(IP_ADAPTER_ADDRESSES_W7);

                /* Now fill in the name */
                CopyMemory(Ptr, &Entry->if_descr[0], Entry->if_descrlen);
                CurrentAA->AdapterName = (PCHAR)Ptr;
                CurrentAA->AdapterName[Entry->if_descrlen] = '\0';
                /* Next items */
                Ptr = (BYTE*)(CurrentAA->AdapterName + Entry->if_descrlen + 1);

                /* The DNS suffix */
                CurrentAA->DnsSuffix = (PWCHAR)Ptr;

                if (Entry->if_type != IF_TYPE_SOFTWARE_LOOPBACK)
                {
                    HKEY InterfaceKey;
                    CHAR KeyName[256];
                    DWORD ValueType, ValueSize;

                    snprintf(KeyName, 256,
                        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%*s",
                        Entry->if_descrlen, &Entry->if_descr[0]);

                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &InterfaceKey) == ERROR_SUCCESS)
                    {
                        if (DhcpDomainSize != 0)
                        {
                            ValueSize = DhcpDomainSize + sizeof(WCHAR);
                            if (RegQueryValueExW(InterfaceKey, L"DhcpDomain", NULL, &ValueType, (LPBYTE)CurrentAA->DnsSuffix, &ValueSize) == ERROR_SUCCESS &&
                                ValueType == REG_SZ && ValueSize == DhcpDomainSize + sizeof(WCHAR))
                            {
                                /* We're done, next items */
                                Ptr = (BYTE*)(CurrentAA->DnsSuffix + (ValueSize / sizeof(WCHAR)));
                            }
                            else
                            {
                                /* Fail */
                                ERR("DhcpDomain name changed after probe!\n");
                                DhcpDomainSize = 0;
                            }
                        }

                        if (DomainSize != 0)
                        {
                            ValueSize = DomainSize + sizeof(WCHAR);
                            if (RegQueryValueExW(InterfaceKey, L"Domain", NULL, &ValueType, (LPBYTE)CurrentAA->DnsSuffix, &ValueSize) == ERROR_SUCCESS &&
                                ValueType == REG_SZ && ValueSize == DomainSize + sizeof(WCHAR))
                            {
                                /* We're done, next items */
                                Ptr = (BYTE*)(CurrentAA->DnsSuffix + (ValueSize / sizeof(WCHAR)));
                            }
                            else
                            {
                                /* Fail */
                                ERR("Domain name changed after probe!\n");
                                DomainSize = 0;
                            }
                        }

                        RegCloseKey(InterfaceKey);
                    }
                }

                /* In case of failure (or no name) */
                if ((DhcpDomainSize == 0) && (DomainSize == 0))
                {
                    CurrentAA->DnsSuffix[0] = L'\0';
                    /* Next items */
                    Ptr = (BYTE*)(CurrentAA->DnsSuffix + 1);
                }

                /* The description */
                CurrentAA->Description = (PWCHAR)Ptr;

                if (DescriptionSize != 0)
                {
                    if (Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK)
                    {
                        size_t size;
                        size = mbstowcs((PWCHAR)Ptr, (PCSTR)&Entry->if_descr[0], Entry->if_descrlen);
                        CurrentAA->Description = (PWCHAR)Ptr;
                        CurrentAA->Description[size] = '\0';
                        /* Next items */
                        Ptr = (BYTE*)(CurrentAA->Description + size + 1);
                    }
                    else
                    {
                        HKEY ConnectionKey;
                        CHAR KeyName[256];
                        CHAR InstanceID[128];
                        DWORD ValueType = 0;
                        DWORD ValueSize = 0;

                        snprintf(KeyName, 256,
                            "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%*s\\Connection",
                            Entry->if_descrlen, &Entry->if_descr[0]);

                        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &ConnectionKey) == ERROR_SUCCESS)
                        {
                            ValueSize = 128;
                            RegQueryValueExA(ConnectionKey, "PnpInstanceID", NULL, &ValueType, (LPBYTE)InstanceID, &ValueSize);
                            RegCloseKey(ConnectionKey);
                        }

                        if (ValueSize != 0)
                        {
                            sprintf(KeyName, "SYSTEM\\CurrentControlSet\\Enum\\%s", InstanceID);

                            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &ConnectionKey) == ERROR_SUCCESS)
                            {
                                ValueSize = DescriptionSize + sizeof(WCHAR);
                                if (RegQueryValueExW(ConnectionKey, L"DeviceDesc", NULL, &ValueType, (LPBYTE)CurrentAA->Description, &ValueSize) == ERROR_SUCCESS &&
                                    ValueType == REG_SZ && ValueSize == DescriptionSize + sizeof(WCHAR))
                                {
                                    /* We're done, next items */
                                    Ptr = (BYTE*)(CurrentAA->Description + (ValueSize / sizeof(WCHAR)));
                                }
                                else
                                {
                                    /* Fail */
                                    ERR("Description name changed after probe!\n");
                                    DescriptionSize = 0;
                                }

                                RegCloseKey(ConnectionKey);
                            }
                        }
                    }
                }

                /* In case of failure (or no name) */
                if (DescriptionSize == 0)
                {
                    CurrentAA->Description[0] = L'\0';
                    /* Next items */
                    Ptr = (BYTE*)(CurrentAA->Description + 1);
                }

                /* The friendly name */
                if (!(Flags & GAA_FLAG_SKIP_FRIENDLY_NAME))
                {
                    CurrentAA->FriendlyName = (PWCHAR)Ptr;

                    if (FriendlySize != 0)
                    {
                        /* Get the friendly name */
                        if (Entry->if_type == IF_TYPE_SOFTWARE_LOOPBACK)
                        {
                            size_t size;
                            size = mbstowcs(CurrentAA->FriendlyName, (PCSTR)&Entry->if_descr[0], Entry->if_descrlen);
                            CurrentAA->FriendlyName[size] = '\0';
                            /* Next items */
                            Ptr = (BYTE*)(CurrentAA->FriendlyName + size + 1);
                        }
                        else
                        {
                            HKEY ConnectionKey;
                            CHAR KeyName[256];

                            snprintf(KeyName, 256,
                                "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%*s\\Connection",
                                Entry->if_descrlen, &Entry->if_descr[0]);

                            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &ConnectionKey) == ERROR_SUCCESS)
                            {
                                DWORD ValueType;
                                DWORD ValueSize = FriendlySize + sizeof(WCHAR);

                                if (RegQueryValueExW(ConnectionKey, L"Name", NULL, &ValueType, (LPBYTE)CurrentAA->FriendlyName, &ValueSize) == ERROR_SUCCESS &&
                                    ValueType == REG_SZ && ValueSize == FriendlySize + sizeof(WCHAR))
                                {
                                    /* We're done, next items */
                                    Ptr = (BYTE*)(CurrentAA->FriendlyName + (ValueSize / sizeof(WCHAR)));
                                }
                                else
                                {
                                    /* Fail */
                                    ERR("Friendly name changed after probe!\n");
                                    FriendlySize = 0;
                                }

                                RegCloseKey(ConnectionKey);
                            }
                            else
                            {
                                /* Fail */
                                FriendlySize = 0;
                            }
                        }
                    }

                    /* In case of failure (or no name) */
                    if (FriendlySize == 0)
                    {
                        CurrentAA->FriendlyName[0] = L'\0';
                        /* Next items */
                        Ptr = (BYTE*)(CurrentAA->FriendlyName + 1);
                    }
                }

                /* The DNS Servers */
                if (!(Flags & GAA_FLAG_SKIP_DNS_SERVER))
                {
                    /* Enumerate the name servers */
                    HKEY InterfaceKey;
                    CHAR KeyName[256];

                    snprintf(KeyName, 256,
                        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%*s",
                        Entry->if_descrlen, &Entry->if_descr[0]);

                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &InterfaceKey) != ERROR_SUCCESS)
                    {
                        TRACE("Failed opening interface key for interface %*s\n", Entry->if_descrlen, &Entry->if_descr[0]);
                    }
                    else
                    {
                        PIP_ADAPTER_DNS_SERVER_ADDRESS* ServerAddressPtr;

                        CurrentAA->FirstDnsServerAddress = (PIP_ADAPTER_DNS_SERVER_ADDRESS)Ptr;
                        ServerAddressPtr = &CurrentAA->FirstDnsServerAddress;

                        EnumNameServers(InterfaceKey, NULL, &ServerAddressPtr, EnumerateServerName);
                        RegCloseKey(InterfaceKey);

                        /* Set the last entry in the list as having NULL next member */
                        Ptr = (BYTE*)*ServerAddressPtr;
                        *ServerAddressPtr = NULL;
                    }
                }

                /* We're done for this interface */
                PreviousAA = CurrentAA;
                RemainingSize -= CurrentAASize;
            }
        }
    }

    if (AdaptersCount == 0)
    {
        /* Uh? Not even localhost ?! */
        ERR("No Adapters found!\n");
        *pOutBufLen = 0;
        HeapFree(GetProcessHeap(), 0, AdapterIndexes);
        HeapFree(GetProcessHeap(), 0, InterfacesList);
        NtClose(TcpFile);
        return ERROR_NO_DATA;
    }

    /* See if we have anything to add */
    // FIXME: Anycast and multicast
    if ((Flags & (GAA_FLAG_SKIP_UNICAST | GAA_FLAG_INCLUDE_PREFIX)) == GAA_FLAG_SKIP_UNICAST)
        goto Gateways;

    /* Now fill in the addresses */
    for (i = 0; i < InterfacesCount; i++)
    {
        /* Look for network layers */
        if ((InterfacesList[i].tei_entity == CL_NL_ENTITY)
                || (InterfacesList[i].tei_entity == CO_NL_ENTITY))
        {
            IPSNMPInfo SnmpInfo;
            PIP_ADAPTER_ADDRESSES CurrentAA = NULL;
            IPAddrEntry* AddrEntries;
            ULONG j;

            /* Get its SNMP info */
            Status = GetSnmpInfo(TcpFile, InterfacesList[i], &SnmpInfo);
            if (!NT_SUCCESS(Status))
                goto Error;

            if (SnmpInfo.ipsi_numaddr == 0)
                continue;

            /* Allocate the address entry array and get them */
            AddrEntries = HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                SnmpInfo.ipsi_numaddr * sizeof(AddrEntries[0]));
            if (!AddrEntries)
            {
                Status = STATUS_NO_MEMORY;
                goto Error;
            }
            Status = GetAddrEntries(TcpFile, InterfacesList[i], AddrEntries, SnmpInfo.ipsi_numaddr);
            if (!NT_SUCCESS(Status))
            {
                HeapFree(GetProcessHeap(), 0, AddrEntries);
                goto Error;
            }

            for (j = 0; j < SnmpInfo.ipsi_numaddr; j++)
            {
                /* Find the adapters struct for this address. */
                if (pAdapterAddresses)
                {
                    CurrentAA = pAdapterAddresses;
                    while (CurrentAA)
                    {
                        if (CurrentAA->Length && CurrentAA->IfIndex == AddrEntries[j].iae_index)
                            break;

                        CurrentAA = CurrentAA->Next;
                    }

                    /* An adapter that did not fit is not there to link the address to, but the address still needs room */
                    if (!CurrentAA)
                        ERR("Got address for interface %u but no adapter was found for it.\n", AddrEntries[j].iae_index);
                }

                TRACE("address is 0x%08x, mask is 0x%08x\n", AddrEntries[j].iae_addr, AddrEntries[j].iae_mask);

                //FIXME: For now reactos only supports unicast addresses
                if (!(Flags & GAA_FLAG_SKIP_UNICAST) && !SkipV4)
                {
                    ULONG Size = sizeof(IP_ADAPTER_UNICAST_ADDRESS) + sizeof(SOCKADDR);

                    if (CurrentAA && Ptr && (RemainingSize >= Size))
                    {
                        PIP_ADAPTER_UNICAST_ADDRESS UnicastAddress = (PIP_ADAPTER_UNICAST_ADDRESS)Ptr;

                        /* Fill in the structure */
                        UnicastAddress->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
                        UnicastAddress->Next = CurrentAA->FirstUnicastAddress;

                        // FIXME: Put meaningful value here
                        UnicastAddress->Flags = 0;
                        UnicastAddress->PrefixOrigin = IpPrefixOriginOther;
                        UnicastAddress->SuffixOrigin = IpSuffixOriginOther;
                        UnicastAddress->DadState = IpDadStatePreferred;
                        UnicastAddress->ValidLifetime = 0xFFFFFFFF;
                        UnicastAddress->PreferredLifetime = 0xFFFFFFFF;
                        UnicastAddress->OnLinkPrefixLength = (UINT8)CountPrefixBits(AddrEntries[j].iae_mask);

                        /* Set the address */
                        //FIXME: ipv4 only (again...)
                        UnicastAddress->Address.lpSockaddr = (LPSOCKADDR)(UnicastAddress + 1);
                        UnicastAddress->Address.iSockaddrLength = sizeof(SOCKADDR);
                        UnicastAddress->Address.lpSockaddr->sa_family = AF_INET;
                        ((LPSOCKADDR_IN)UnicastAddress->Address.lpSockaddr)->sin_port = 0;
                        ((LPSOCKADDR_IN)UnicastAddress->Address.lpSockaddr)->sin_addr.S_un.S_addr = AddrEntries[j].iae_addr;

                        CurrentAA->FirstUnicastAddress = UnicastAddress;
                        Ptr += Size;
                        RemainingSize -= Size;
                    }

                    TotalSize += Size;
                }

                if ((Flags & GAA_FLAG_INCLUDE_PREFIX) && !SkipV4)
                {
                    ULONG Size = sizeof(IP_ADAPTER_PREFIX) + sizeof(SOCKADDR);

                    if (CurrentAA && Ptr && (RemainingSize >= Size))
                    {
                        PIP_ADAPTER_PREFIX Prefix = (PIP_ADAPTER_PREFIX)Ptr;

                        /* Fill in the structure */
                        Prefix->Length = sizeof(IP_ADAPTER_PREFIX);
                        Prefix->Next = CurrentAA->FirstPrefix;

                        /* Set the address */
                        //FIXME: ipv4 only (again...)
                        Prefix->Address.lpSockaddr = (LPSOCKADDR)(Prefix + 1);
                        Prefix->Address.iSockaddrLength = sizeof(SOCKADDR);
                        Prefix->Address.lpSockaddr->sa_family = AF_INET;
                        ((LPSOCKADDR_IN)Prefix->Address.lpSockaddr)->sin_port = 0;
                        ((LPSOCKADDR_IN)Prefix->Address.lpSockaddr)->sin_addr.S_un.S_addr = AddrEntries[j].iae_addr & AddrEntries[j].iae_mask;

                        /* Compute the prefix size */
                        Prefix->PrefixLength = CountPrefixBits(AddrEntries[j].iae_mask);

                        CurrentAA->FirstPrefix = Prefix;
                        Ptr += Size;
                        RemainingSize -= Size;
                    }

                    TotalSize += Size;
                }
            }

            HeapFree(GetProcessHeap(), 0, AddrEntries);
        }
    }

    /* The IPv6 addresses: first in the list of their adapter (Windows 10 measured), in the order the stack has
       them. This leaves the prefixes, multicast and anycast lists, gateways and name servers of IPv6 out */
    if (V6On && Family != AF_INET && !(Flags & GAA_FLAG_SKIP_UNICAST))
    {
        ULONG AdapterNumber;

        /* Every adapter of the answer counts, also one that did not fit into the caller's buffer: the size
           has to cover the rows of all of them for the second call to succeed */
        for (AdapterNumber = 0; AdapterNumber < AdapterIndexCount; AdapterNumber++)
        {
            const TCP_IPV6_INTERFACE_ROW *Interface = Ipv6FindInterface(V6, AdapterIndexes[AdapterNumber]);
            PIP_ADAPTER_ADDRESSES CurrentAA = NULL, Candidate;
            LONG Row;

            if (!Interface)
                continue;

            for (Candidate = pAdapterAddresses; Candidate; Candidate = Candidate->Next)
            {
                if (Candidate->Length && Candidate->IfIndex == AdapterIndexes[AdapterNumber])
                {
                    CurrentAA = Candidate;
                    break;
                }
            }

            /* prepended, so the last row first */
            for (Row = (LONG)V6->Header->AddressCount - 1; Row >= 0; Row--)
            {
                const TCP_IPV6_ADDRESS_ROW *Address = &V6->Addresses[Row];
                ULONG Size = (sizeof(IP_ADAPTER_UNICAST_ADDRESS) + sizeof(SOCKADDR_IN6) + 7) & ~7UL;

                if (Address->IfIndex != AdapterIndexes[AdapterNumber])
                    continue;

                if (CurrentAA && Ptr && (RemainingSize >= Size))
                {
                    PIP_ADAPTER_UNICAST_ADDRESS UnicastAddress = (PIP_ADAPTER_UNICAST_ADDRESS)Ptr;
                    LPSOCKADDR_IN6 Socket = (LPSOCKADDR_IN6)(UnicastAddress + 1);
                    BOOL LinkLocal = Address->Address[0] == 0xFE && (Address->Address[1] & 0xC0) == 0x80;
                    BOOL Loopback = (CurrentAA->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

                    UnicastAddress->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
                    UnicastAddress->Next = CurrentAA->FirstUnicastAddress;
                    /* DNS eligible: the address of a router advertisement, not the link-local or loopback one */
                    UnicastAddress->Flags = (LinkLocal || Loopback) ? 0 : IP_ADAPTER_ADDRESS_DNS_ELIGIBLE;
                    UnicastAddress->PrefixOrigin = Address->PrefixOrigin;
                    UnicastAddress->SuffixOrigin = Address->SuffixOrigin;
                    UnicastAddress->DadState = Address->DadState;
                    UnicastAddress->ValidLifetime = Address->ValidLifetime;
                    UnicastAddress->PreferredLifetime = Address->PreferredLifetime;
                    UnicastAddress->OnLinkPrefixLength = (UINT8)Address->PrefixLength;

                    UnicastAddress->Address.lpSockaddr = (LPSOCKADDR)Socket;
                    UnicastAddress->Address.iSockaddrLength = sizeof(SOCKADDR_IN6);
                    RtlZeroMemory(Socket, sizeof(*Socket));
                    Socket->sin6_family = AF_INET6;
                    RtlCopyMemory(&Socket->sin6_addr, Address->Address, 16);
                    /* the zone of a link-local address is its interface */
                    if (LinkLocal)
                        Socket->sin6_scope_id = CurrentAA->IfIndex;

                    CurrentAA->FirstUnicastAddress = UnicastAddress;
                    Ptr += Size;
                    RemainingSize -= Size;
                }

                TotalSize += Size;
            }
        }
    }

Gateways:
    /* The gateways of an adapter are the next hops of the default routes of its interface */
    if (Flags & GAA_FLAG_INCLUDE_GATEWAYS)
    {
        RouteTable *Routes = getRouteTable();
        ULONG Route, Index;

        for (Route = 0; Routes && Route < Routes->numRoutes; Route++)
        {
            RouteEntry *Entry = &Routes->routes[Route];
            ULONG Size = sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH) + sizeof(SOCKADDR_IN);
            PIP_ADAPTER_ADDRESSES CurrentAA = NULL;
            PIP_ADAPTER_GATEWAY_ADDRESS_LH Gateway, *Link;
            BOOLEAN Duplicate = FALSE;

            /* Only a default route that leaves through a router is a gateway */
            if (Entry->dest != 0 || Entry->mask != 0 || Entry->gateway == 0)
                continue;

            /* ... of an interface that is an adapter */
            for (Index = 0; Index < AdapterIndexCount && AdapterIndexes[Index] != Entry->ifIndex; Index++)
                ;
            if (Index == AdapterIndexCount)
                continue;

            for (CurrentAA = pAdapterAddresses; CurrentAA; CurrentAA = CurrentAA->Next)
            {
                if (CurrentAA->Length && CurrentAA->IfIndex == Entry->ifIndex)
                    break;
            }

            /* One entry per gateway, even when more than one route leads to it */
            Link = CurrentAA ? &((PIP_ADAPTER_ADDRESSES_LH)CurrentAA)->FirstGatewayAddress : NULL;
            while (Link && *Link)
            {
                if (((LPSOCKADDR_IN)(*Link)->Address.lpSockaddr)->sin_addr.S_un.S_addr == Entry->gateway)
                    Duplicate = TRUE;
                Link = &(*Link)->Next;
            }
            if (Duplicate)
                continue;

            if (CurrentAA && (RemainingSize >= Size))
            {
                Gateway = (PIP_ADAPTER_GATEWAY_ADDRESS_LH)Ptr;

                Gateway->Length = sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH);
                Gateway->Next = NULL;
                Gateway->Address.lpSockaddr = (LPSOCKADDR)(Gateway + 1);
                Gateway->Address.iSockaddrLength = sizeof(SOCKADDR_IN);
                ((LPSOCKADDR_IN)Gateway->Address.lpSockaddr)->sin_family = AF_INET;
                ((LPSOCKADDR_IN)Gateway->Address.lpSockaddr)->sin_port = 0;
                ((LPSOCKADDR_IN)Gateway->Address.lpSockaddr)->sin_addr.S_un.S_addr = Entry->gateway;

                /* In the order of the routes: at the end of the list of the adapter */
                *Link = Gateway;

                Ptr += Size;
                RemainingSize -= Size;
            }

            TotalSize += Size;
        }

        if (Routes)
            HeapFree(GetProcessHeap(), 0, Routes);
    }

    /* We're done */
    HeapFree(GetProcessHeap(), 0, AdapterIndexes);
    HeapFree(GetProcessHeap(), 0, InterfacesList);
    NtClose(TcpFile);
    *pOutBufLen = TotalSize;
    if (TotalSize > BufferSize)
        return ERROR_BUFFER_OVERFLOW;
    TRACE("TotalSize: %x\n", *pOutBufLen);
    return ERROR_SUCCESS;

Error:
    ERR("Failed! Status 0x%08x\n", Status);
    *pOutBufLen = 0;
    HeapFree(GetProcessHeap(), 0, AdapterIndexes);
    HeapFree(GetProcessHeap(), 0, InterfacesList);
    NtClose(TcpFile);
    return RtlNtStatusToDosError(Status);
}

DWORD
WINAPI
DECLSPEC_HOTPATCH
GetAdaptersAddresses(
    _In_ ULONG Family,
    _In_ ULONG Flags,
    _In_ PVOID Reserved,
    _Inout_ PIP_ADAPTER_ADDRESSES pAdapterAddresses,
    _Inout_ PULONG pOutBufLen)
{
    IPV6_STATE V6;
    DWORD Result;

    /* The stack tells whether IPv6 is on; if it is not, or does not say, nothing changes */
    Ipv6GetState(&V6);
    Result = GetAdaptersAddressesImpl(Family, Flags, Reserved, pAdapterAddresses, pOutBufLen, &V6);
    Ipv6FreeState(&V6);
    return Result;
}


DWORD
WINAPI
NhpAllocateAndGetInterfaceInfoFromStack(
    _Inout_ IP_INTERFACE_NAME_INFO **ppTable,
    _Inout_ PDWORD pdwCount,
    _In_ BOOL bOrder,
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags)
{
    NTSTATUS Status;
    HANDLE TcpFile;
    TDIEntityID* InterfacesList;
    ULONG InterfacesCount;
    ULONG AdaptersCount = 0;
    ULONG i, j;
    IP_INTERFACE_NAME_INFO *pTable = NULL;
    UNICODE_STRING UnicodeGuidString;
    ANSI_STRING AnsiGuidString;

    TRACE("ppTable %p, pdwCount %p, bOrder %u, hHeap %p, dwFlags %lu\n",
          ppTable, pdwCount, bOrder, hHeap, dwFlags);

    /* open the tcpip driver */
    Status = openTcpFile(&TcpFile, FILE_READ_DATA);
    if (!NT_SUCCESS(Status))
    {
        ERR("Could not open handle to tcpip.sys. Status %08x\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    /* Get the interfaces list */
    Status = GetInterfacesList(TcpFile, &InterfacesList, &InterfacesCount);
    if (!NT_SUCCESS(Status))
    {
        ERR("Could not get adapters list. Status %08x\n", Status);
        NtClose(TcpFile);
        return RtlNtStatusToDosError(Status);
    }

    for (i = 0; i < InterfacesCount; i++)
    {
        if (InterfacesList[i].tei_entity == IF_ENTITY)
        {
            BYTE EntryBuffer[FIELD_OFFSET(IFEntry, if_descr) +
                             RTL_FIELD_SIZE(IFEntry, if_descr[0]) * (MAX_ADAPTER_DESCRIPTION_LENGTH + 1)];
            IFEntry* Entry = (IFEntry*)EntryBuffer;

            /* Get the entry */
            Status = GetInterfaceEntry(TcpFile, InterfacesList[i], Entry);
            if (!NT_SUCCESS(Status))
                goto Error;

            if (Entry->if_type != IF_TYPE_SOFTWARE_LOOPBACK)
                AdaptersCount++;
        }
    }

    TRACE("InterfacesCount %lu  AdaptersCount %lu\n", InterfacesCount, AdaptersCount);

    pTable = HeapAlloc(hHeap, dwFlags, AdaptersCount * sizeof(IP_INTERFACE_NAME_INFO));
    if (pTable == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto Error;
    }

    for (i = 0, j = 0; i < InterfacesCount; i++)
    {
        if (InterfacesList[i].tei_entity == IF_ENTITY)
        {
            BYTE EntryBuffer[FIELD_OFFSET(IFEntry, if_descr) +
                             RTL_FIELD_SIZE(IFEntry, if_descr[0]) * (MAX_ADAPTER_DESCRIPTION_LENGTH + 1)];
            IFEntry* Entry = (IFEntry*)EntryBuffer;

            /* Get the entry */
            Status = GetInterfaceEntry(TcpFile, InterfacesList[i], Entry);
            if (!NT_SUCCESS(Status))
                goto Error;

            TRACE("Got entity %*s, index %u.\n",
                  Entry->if_descrlen, &Entry->if_descr[0], Entry->if_index);

            if (Entry->if_type != IF_TYPE_SOFTWARE_LOOPBACK)
            {
                pTable[j].Index = Entry->if_index;
                pTable[j].MediaType = Entry->if_type;
                pTable[j].ConnectionType = 1; //IF_CONNECTION_DEDICATED;
                pTable[j].AccessType = 2; //IF_ACCESS_BROADCAST;

                AnsiGuidString.Length = Entry->if_descrlen;
                AnsiGuidString.MaximumLength = Entry->if_descrlen;
                AnsiGuidString.Buffer = (PCHAR)Entry->if_descr;
                Status = RtlAnsiStringToUnicodeString(&UnicodeGuidString,
                                                      &AnsiGuidString, TRUE);
                if (!NT_SUCCESS(Status))
                {
                    ERR("Status %lx\n", Status);
                    goto Error;
                }

                Status = RtlGUIDFromString(&UnicodeGuidString, &pTable[j].DeviceGuid);
                RtlFreeUnicodeString(&UnicodeGuidString);
                if (!NT_SUCCESS(Status))
                {
                    ERR("Status %lx\n", Status);
                    goto Error;
                }

                memset(&pTable[j].InterfaceGuid, 0, sizeof(GUID));

                j++;
            }
        }
    }

    /* We're done */
    HeapFree(GetProcessHeap(), 0, InterfacesList);
    NtClose(TcpFile);
    *ppTable = pTable;
    *pdwCount = AdaptersCount;
    return ERROR_SUCCESS;

Error:
    ERR("Failed! Status 0x%08x\n", Status);
    if (pTable)
        HeapFree(hHeap, 0, pTable);
    *ppTable = NULL;
    *pdwCount = 0;
    HeapFree(GetProcessHeap(), 0, InterfacesList);
    NtClose(TcpFile);
    return RtlNtStatusToDosError(Status);
}

#endif
