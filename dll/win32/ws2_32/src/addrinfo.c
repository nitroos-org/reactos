/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS WinSock 2 API
 * FILE:        dll/win32/ws2_32/src/addrinfo.c
 * PURPOSE:     Protocol-Independent Address Resolution
 * PROGRAMMER:  Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES ******************************************************************/

#include <ws2_32.h>

#include <ws2tcpip.h>

#define NDEBUG
#include <debug.h>

/* DEFINES *******************************************************************/

/*
 * ws2_32 is built with _WIN32_WINNT 0x502, where the Vista+ headers hide the
 * extended address info types. Their layout is the Windows ABI, so declare
 * them here for the Win8-era GetAddrInfoEx family.
 */
#if (_WIN32_WINNT < 0x0600)
typedef struct addrinfoexA
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    void *ai_blob;
    size_t ai_bloblen;
    LPGUID ai_provider;
    struct addrinfoexA *ai_next;
} ADDRINFOEXA, *PADDRINFOEXA;

typedef struct addrinfoexW
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    PWSTR ai_canonname;
    struct sockaddr *ai_addr;
    void *ai_blob;
    size_t ai_bloblen;
    LPGUID ai_provider;
    struct addrinfoexW *ai_next;
} ADDRINFOEXW, *PADDRINFOEXW;

typedef void
(CALLBACK *LPLOOKUPSERVICE_COMPLETION_ROUTINE)(
    _In_ DWORD dwError,
    _In_ DWORD dwBytes,
    _In_ LPWSAOVERLAPPED lpOverlapped);
#endif

#define Swap(a, b, c)       { (c) = (a); (a) = (b); (b) = (c); }
#define FreeAddrInfoW(a)    freeaddrinfo((LPADDRINFO)a)

/* FUNCTIONS *****************************************************************/

/* FIXME: put into dnslib */
VOID
WSAAPI
Dns_Ip4AddressToReverseName_W(IN LPWSTR AddressBuffer,
                              IN IN_ADDR Address)
{
    /* Convert the address into IPv4 format */
    wsprintfW(AddressBuffer, L"%u.%u.%u.%u.in-addr.arpa.",
              Address.S_un.S_un_b.s_b4,
              Address.S_un.S_un_b.s_b3,
              Address.S_un.S_un_b.s_b2,
              Address.S_un.S_un_b.s_b1);
}

VOID
WINAPI
Dns_SplitHostFromDomainNameW(IN LPWSTR DomainName)
{
    PWCHAR Dot;

    /* NI_NOFQDN: keep the host label only */
    Dot = wcschr(DomainName, L'.');
    if (Dot)
        *Dot = UNICODE_NULL;
}

static
INT
WINAPI
ConvertAddrinfoFromUnicodeToAnsi(IN PADDRINFOW Addrinfo)
{
    LPSTR AnsiName;
    LPWSTR *UnicodeName;

    /* Make sure we have a valid pointer */
    if (Addrinfo)
    {
        do
        {
            /* Get the name */
            UnicodeName = &Addrinfo->ai_canonname;

            /* Check if it exists */
            if (*UnicodeName)
            {
                /* Convert it */
                AnsiName = AnsiDupFromUnicode(*UnicodeName);
                if (AnsiName)
                {
                    /* Free the old one */
                    HeapFree(WsSockHeap, 0, *UnicodeName);

                    /* Set the new one */
                    *UnicodeName = (LPWSTR)AnsiName;
                }
                else
                {
                    return GetLastError();
                }
            }
        } while ((Addrinfo = Addrinfo->ai_next));
    }

    /* All done */
    return ERROR_SUCCESS;
}

static
BOOL
WINAPI
ParseV4Address(IN PCWSTR AddressString,
               OUT PDWORD pAddress,
               OUT PBOOL pbTrailingSpace)
{
    CHAR AnsiAddressString[MAX_HOSTNAME_LEN];
    CHAR * cp = AnsiAddressString;
    DWORD val, base;
    unsigned char c;
    DWORD parts[4], *pp = parts;

    if (pbTrailingSpace)
        *pbTrailingSpace = FALSE;

    if (!AddressString)
        return FALSE;
    WideCharToMultiByte(CP_ACP,
                        0,
                        AddressString,
                        -1,
                        AnsiAddressString,
                        sizeof(AnsiAddressString),
                        NULL,
                        0);
    if (!isdigit(*cp)) return FALSE;

again:
    /*
    * Collect number up to ``.''.
    * Values are specified as for C:
    * 0x=hex, 0=octal, other=decimal.
    */
    val = 0; base = 10;
    if (*cp == '0') {
        if (*++cp == 'x' || *cp == 'X')
            base = 16, cp++;
        else
            base = 8;
    }
    while ((c = *cp)) {
        if (isdigit(c)) {
            val = (val * base) + (c - '0');
            cp++;
            continue;
        }
        if (base == 16 && isxdigit(c)) {
            val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
            cp++;
            continue;
        }
        break;
    }
    if (*cp == '.') {
        /*
        * Internet format:
        *    a.b.c.d
        */
        if (pp >= parts + 4) return FALSE;
        *pp++ = val;
        cp++;
        goto again;
    }
    /*
    * Check for trailing characters. Like inet_aton, accept trailing
    * whitespace, and nothing else.
    */
    if (*cp)
    {
        if (!isspace((unsigned char)*cp)) return FALSE;
        while (isspace((unsigned char)*cp)) cp++;
        if (*cp) return FALSE;
        if (pbTrailingSpace) *pbTrailingSpace = TRUE;
    }

    if (pp >= parts + 4) return FALSE;
    *pp++ = val;
    /*
    * Concoct the address according to
    * the number of parts specified.
    */
    if ((DWORD)(pp - parts) != 4) return FALSE;
    if (parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xff || parts[3] > 0xff) return FALSE;
    val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

    if (pAddress)
        *pAddress = htonl(val);

    return TRUE;
}

static
PADDRINFOW
WINAPI
NewAddrInfo(IN INT SocketType,
            IN INT Protocol,
            IN WORD Port,
            IN DWORD Address)
{
    PADDRINFOW AddrInfo;
    PSOCKADDR_IN SockAddress;

    /* Allocate a structure */
    AddrInfo = HeapAlloc(WsSockHeap, 0, sizeof(ADDRINFOW));
    if (!AddrInfo) return NULL;

    /* Allocate a sockaddr */
    SockAddress = HeapAlloc(WsSockHeap, 0, sizeof(SOCKADDR_IN));
    if (!SockAddress)
    {
        /* Free the addrinfo and fail */
        HeapFree(WsSockHeap, 0, AddrInfo);
        return NULL;
    }

    /* Write data for socket address */
    SockAddress->sin_family = AF_INET;
    SockAddress->sin_port = Port;
    SockAddress->sin_addr.s_addr = Address;
    ZeroMemory(SockAddress->sin_zero, sizeof(SockAddress->sin_zero));

    /* Fill out the addrinfo */
    AddrInfo->ai_family = PF_INET;
    AddrInfo->ai_socktype = SocketType;
    AddrInfo->ai_protocol = Protocol;
    AddrInfo->ai_flags = 0;
    AddrInfo->ai_next = 0;
    AddrInfo->ai_canonname = NULL;
    AddrInfo->ai_addrlen = sizeof(SOCKADDR_IN);
    AddrInfo->ai_addr = (PSOCKADDR)SockAddress;

    /* Return it */
    return AddrInfo;
}

/*
 * An IPv6 address in text form: "::1", "fe80::1%4", and both of them in brackets, with or without a
 * port ("[::1]:80", the port is not used). Windows answers it whether or not the machine has IPv6:
 * nothing is looked up. A numeric scope id after '%' is the only zone accepted.
 */
static
BOOL
ParseV6Address(IN PCWSTR AddressString,
               OUT PIN6_ADDR pAddress,
               OUT PULONG pScopeId)
{
    WCHAR Text[64];
    PCWSTR Terminator = NULL;
    PCWSTR Scope, Close;
    SIZE_T Length;
    ULONG Id = 0;

    *pScopeId = 0;
    if (!AddressString || !wcschr(AddressString, L':'))
        return FALSE;

    if (*AddressString == L'[')
    {
        Close = wcschr(AddressString, L']');
        if (!Close)
            return FALSE;

        /* After the bracket: nothing, or a port */
        Scope = Close + 1;
        if (*Scope == L':')
        {
            if (!*++Scope)
                return FALSE;
            for (; *Scope; Scope++)
            {
                if (*Scope < L'0' || *Scope > L'9')
                    return FALSE;
            }
        }
        else if (*Scope)
        {
            return FALSE;
        }

        Length = Close - (AddressString + 1);
        if (!Length || Length >= RTL_NUMBER_OF(Text))
            return FALSE;
        RtlCopyMemory(Text, AddressString + 1, Length * sizeof(WCHAR));
        Text[Length] = UNICODE_NULL;
        AddressString = Text;
    }

    if (!NT_SUCCESS(RtlIpv6StringToAddressW(AddressString, &Terminator, pAddress)) || !Terminator)
        return FALSE;

    if (*Terminator == L'%')
    {
        Scope = Terminator + 1;
        if (!*Scope)
            return FALSE;
        for (; *Scope; Scope++)
        {
            if (*Scope < L'0' || *Scope > L'9')
                return FALSE;
            Id = Id * 10 + (*Scope - L'0');
        }
        *pScopeId = Id;
        return TRUE;
    }

    return *Terminator == UNICODE_NULL;
}

static
BOOLEAN
IsLocalhostName(IN PCWSTR Name)
{
    static const WCHAR Localhost[] = L"localhost";
    SIZE_T Length = RTL_NUMBER_OF(Localhost) - 1;

    if (_wcsnicmp(Name, Localhost, Length) != 0)
        return FALSE;

    /* Optionally followed by the root dot */
    return Name[Length] == UNICODE_NULL ||
           (Name[Length] == L'.' && Name[Length + 1] == UNICODE_NULL);
}

static
PADDRINFOW
WINAPI
NewAddrInfo6(IN INT SocketType,
             IN INT Protocol,
             IN WORD Port,
             IN const IN6_ADDR *Address,
             IN ULONG ScopeId)
{
    PADDRINFOW AddrInfo;
    PSOCKADDR_IN6 SockAddress;

    AddrInfo = HeapAlloc(WsSockHeap, 0, sizeof(ADDRINFOW));
    if (!AddrInfo) return NULL;

    SockAddress = HeapAlloc(WsSockHeap, HEAP_ZERO_MEMORY, sizeof(SOCKADDR_IN6));
    if (!SockAddress)
    {
        HeapFree(WsSockHeap, 0, AddrInfo);
        return NULL;
    }

    SockAddress->sin6_family = AF_INET6;
    SockAddress->sin6_port = Port;
    SockAddress->sin6_addr = *Address;
    SockAddress->sin6_scope_id = ScopeId;

    AddrInfo->ai_family = PF_INET6;
    AddrInfo->ai_socktype = SocketType;
    AddrInfo->ai_protocol = Protocol;
    AddrInfo->ai_flags = 0;
    AddrInfo->ai_next = 0;
    AddrInfo->ai_canonname = NULL;
    AddrInfo->ai_addrlen = sizeof(SOCKADDR_IN6);
    AddrInfo->ai_addr = (PSOCKADDR)SockAddress;

    return AddrInfo;
}

static
INT
WINAPI
CloneAddrInfo(IN WORD Port,
              IN PADDRINFOW ptResult)
{
    PADDRINFOW Next = NULL;
    PADDRINFOW New  = NULL;

    /* Loop the chain */
    for (Next = ptResult; Next;)
    {
        /* Create a new structure */
        New = NewAddrInfo(SOCK_DGRAM,
                          Next->ai_protocol,
                          Port,
                          ((PSOCKADDR_IN)Next->ai_addr)->sin_addr.s_addr);
        if (!New) break;

        /* Link them */
        New->ai_next = Next->ai_next;
        Next->ai_next = New;
        Next = New->ai_next;
    }

    /* Check if we ran out of memory */
    if (Next) return EAI_MEMORY;

    /* Return success */
    return 0;
}

static
INT
WINAPI
QueryDNS(IN LPCSTR NodeName,
         IN INT SocketType,
         IN INT Protocol,
         IN WORD Port,
         OUT CHAR Alias[NI_MAXHOST],
         OUT PADDRINFOW *pptResult)
{
    PADDRINFOW *Next = pptResult;
    PHOSTENT Hostent = NULL;
    PCHAR *Addresses;

    /* Assume nothing found */
    *Next = NULL;
    Alias[0] = '\0';

    /* Get the hostent */
    Hostent = gethostbyname(NodeName);
    if (Hostent)
    {
        /* Check for valid addresses */
        if ((Hostent->h_addrtype == AF_INET) &&
            (Hostent->h_length == sizeof(IN_ADDR)))
        {
            /* Loop every address in it */
            for (Addresses = Hostent->h_addr_list; *Addresses; Addresses++)
            {
                /* Create an addrinfo structure for it*/
                *Next = NewAddrInfo(SocketType,
                                    Protocol,
                                    Port,
                                    ((PIN_ADDR)*Addresses)->s_addr);
                if (!*Next) return EAI_MEMORY;

                /* Move to the next entry */
                Next = &((*Next)->ai_next);
            }
        }

        /* Copy the canonical name */
        strcpy(Alias, Hostent->h_name);

        /* Return success */
        return 0;
    }

    /* Find out what the error was */
    switch (GetLastError())
    {
        /* Convert the Winsock Error to an EAI error */
        case WSAHOST_NOT_FOUND: return EAI_NONAME;
        case WSATRY_AGAIN: return EAI_AGAIN;
        case WSANO_RECOVERY: return EAI_FAIL;
        case WSANO_DATA: return EAI_NODATA;
        default: return EAI_NONAME;
    }
}

/*
 * Reverse lookup of an address that belongs to this machine (loopback, or one of its own addresses):
 * Windows answers with the machine's name without asking DNS. Returns TRUE and fills the name if so.
 */
static
BOOLEAN
LookupLocalNodeByAddr(IN LPWSTR pNodeBuffer,
                      IN DWORD NodeBufferSize,
                      IN BOOLEAN OnlyNodeName,
                      IN PIN_ADDR Ip4Addr,
                      IN BOOLEAN Loopback)
{
    WCHAR Name[256];
    DWORD Size;
    BOOLEAN IsLocal = Loopback;
    CHAR HostName[256];
    PHOSTENT Hostent;
    PCHAR *Addresses;

    if (Ip4Addr->S_un.S_un_b.s_b1 == 127)
        IsLocal = TRUE;

    if (!IsLocal)
    {
        /* One of the addresses our own name resolves to? */
        if (gethostname(HostName, sizeof(HostName)) != NO_ERROR)
            return FALSE;
        Hostent = gethostbyname(HostName);
        if (!Hostent || Hostent->h_addrtype != AF_INET || Hostent->h_length != sizeof(IN_ADDR))
            return FALSE;
        for (Addresses = Hostent->h_addr_list; *Addresses; Addresses++)
        {
            if (((PIN_ADDR)*Addresses)->s_addr == Ip4Addr->s_addr)
            {
                IsLocal = TRUE;
                break;
            }
        }
        if (!IsLocal)
            return FALSE;
    }

    Size = RTL_NUMBER_OF(Name);
    if (!GetComputerNameExW(OnlyNodeName ? ComputerNameDnsHostname : ComputerNameDnsFullyQualified,
                            Name,
                            &Size))
        return FALSE;
    if (wcslen(Name) + 1 > NodeBufferSize)
        return FALSE;
    wcscpy(pNodeBuffer, Name);
    return TRUE;
}

static
INT
WINAPI
LookupNodeByAddr(IN LPWSTR pNodeBuffer,
                 IN DWORD NodeBufferSize,
                 IN BOOLEAN OnlyNodeName,
                 IN PVOID Addr,
                 IN DWORD AddrSize,
                 IN INT AddressFamily)
{
    GUID LookupGuid = SVCID_DNS_TYPE_PTR;
    PIN_ADDR Ip4Addr = Addr;
    WCHAR ReverseBuffer[76];
    WSAQUERYSETW Restrictions;
    LPWSAQUERYSETW Reply;
    DWORD BufferLength;
    INT ErrorCode;
    HANDLE LookupHandle = NULL;
    BOOLEAN Loopback = FALSE;

    /* Validate the address */
    if (!Addr) return WSAEFAULT;

    /* Make sure the family and address size match */
    if (AddressFamily == AF_INET6)
    {
        /* Check the address size for this type */
        if (AddrSize != sizeof(IN6_ADDR)) return WSAEFAULT;
        Ip4Addr = (PIN_ADDR)&((PIN6_ADDR)Addr)->u.Byte[12];
        Loopback = IN6_IS_ADDR_LOOPBACK((PIN6_ADDR)Addr);
    }
    else if (AddressFamily == AF_INET)
    {
        /* Check the address size for this type */
        if (AddrSize != sizeof(IN_ADDR)) return WSAEFAULT;
    }
    else
    {
        /* Address family not supported */
        return WSAEAFNOSUPPORT;
    }

    /* An address of this machine is named by the machine itself */
    if ((Loopback || AddressFamily == AF_INET || IN6_IS_ADDR_V4MAPPED(Addr)) &&
        LookupLocalNodeByAddr(pNodeBuffer, NodeBufferSize, OnlyNodeName, Ip4Addr, Loopback))
    {
        return ERROR_SUCCESS;
    }

    /* Check if this is a mapped V4 IPv6 or pure IPv4 */
    if (((AddressFamily == AF_INET6) && (IN6_IS_ADDR_V4MAPPED(Addr))) ||
        (AddressFamily == AF_INET))
    {
        /* Get the reverse name */
        Dns_Ip4AddressToReverseName_W(ReverseBuffer, *Ip4Addr);
    }
    else
    {
        /* FIXME: reverse names of other IPv6 addresses (ip6.arpa) are not implemented */
        return WSAHOST_NOT_FOUND;
    }

    /* By this point we have the Reverse Name, so prepare for lookup */
    RtlZeroMemory(&Restrictions, sizeof(Restrictions));
    Restrictions.dwSize = sizeof(Restrictions);
    Restrictions.lpszServiceInstanceName = ReverseBuffer;
    Restrictions.lpServiceClassId = &LookupGuid;
    Restrictions.dwNameSpace = NS_DNS;

    /* Now do the lookup */
    ErrorCode = WSALookupServiceBeginW(&Restrictions,
                                       LUP_RETURN_NAME,
                                       &LookupHandle);
    if (ErrorCode != ERROR_SUCCESS)
        ErrorCode = WSAGetLastError();
    if (ErrorCode == ERROR_SUCCESS)
    {
        /* Lookup successful, now get the data: the query set is followed by the strings it points to */
        BufferLength = NI_MAXHOST * sizeof(WCHAR) + sizeof(*Reply) + 256;
        Reply = HeapAlloc(GetProcessHeap(), 0, BufferLength);
        if (!Reply)
        {
            ErrorCode = WSA_NOT_ENOUGH_MEMORY;
            goto Finish;
        }
        ErrorCode = WSALookupServiceNextW(LookupHandle,
                                          0,
                                          &BufferLength,
                                          Reply);
        if (ErrorCode != ERROR_SUCCESS)
            ErrorCode = WSAGetLastError();
        if (ErrorCode == ERROR_SUCCESS)
        {
            /* Now check if we have a name back */
            if (!Reply->lpszServiceInstanceName)
            {
                /* Fail */
                ErrorCode = WSAHOST_NOT_FOUND;
            }
            else
            {
                /* Check if the caller only wants the node name */
                if (OnlyNodeName)
                {
                    /* Split it and get only the partial host name */
                    Dns_SplitHostFromDomainNameW(Reply->lpszServiceInstanceName);
                }

                /* Check the length and see if it's within our limit */
                if (wcslen(Reply->lpszServiceInstanceName) + 1 >
                    NodeBufferSize)
                {
                    /* It's not, so fail */
                    ErrorCode = WSAEFAULT;
                }
                else
                {
                    /* It will fit, let's copy it*/
                    wcscpy(pNodeBuffer, Reply->lpszServiceInstanceName);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, Reply);
    }

Finish:
    /* Normalize the error code of a lookup that found nothing */
    if (ErrorCode == WSASERVICE_NOT_FOUND || ErrorCode == WSANO_DATA)
        ErrorCode = WSAHOST_NOT_FOUND;

    /* Finish the lookup if one was in progress */
    if (LookupHandle) WSALookupServiceEnd(LookupHandle);

    /* Return the error code */
    return ErrorCode;
}

static
INT
WINAPI
GetServiceNameForPort(IN LPWSTR pServiceBuffer,
                      IN DWORD ServiceBufferSize,
                      IN WORD Port,
                      IN DWORD Flags)
{
    struct servent *Service;
    INT Length;

    /* Port is in network byte order. The name of the service, unless the number is asked for or the port has none */
    if (!(Flags & NI_NUMERICSERV))
    {
        Service = getservbyport(Port, (Flags & NI_DGRAM) ? "udp" : "tcp");
        if (Service && Service->s_name)
        {
            Length = MultiByteToWideChar(CP_ACP, 0, Service->s_name, -1, pServiceBuffer, ServiceBufferSize);
            if (Length)
                return ERROR_SUCCESS;
        }
    }

    /* The port number, which has up to 5 digits and the terminator */
    Port = (WORD)((Port >> 8) | ((Port & 0xff) << 8));
    Length = (Port >= 10000) ? 5 : (Port >= 1000) ? 4 : (Port >= 100) ? 3 : (Port >= 10) ? 2 : 1;
    if (ServiceBufferSize < (DWORD)Length + 1)
        return ERROR_INSUFFICIENT_BUFFER;
    _snwprintf(pServiceBuffer, ServiceBufferSize, L"%u", (UINT)Port);
    pServiceBuffer[Length] = UNICODE_NULL;
    return ERROR_SUCCESS;
}

static
INT
WINAPI
LookupAddressForName(IN LPCSTR NodeName,
                     IN INT SocketType,
                     IN INT Protocol,
                     IN WORD Port,
                     IN BOOL bAI_CANONNAME,
                     OUT PADDRINFOW *pptResult)
{
    INT iError = 0;
    INT AliasCount = 0;
    CHAR szFQDN1[NI_MAXHOST] = "";
    CHAR szFQDN2[NI_MAXHOST] = "";
    PCHAR Name = szFQDN1;
    PCHAR Alias = szFQDN2;
    PCHAR Scratch = NULL;

    /* Make a copy of the name */
    strcpy(Name, NodeName);

    /* Loop */
    while (TRUE)
    {
        /* Do a DNS Query for the name */
        iError = QueryDNS(NodeName,
                          SocketType,
                          Protocol,
                          Port,
                          Alias,
                          pptResult);
        if (iError) break;

        /* Exit if we have a result */
        if (*pptResult) break;

        /* Don't loop continuously if this is a DNS misconfiguration */
        if ((!strlen(Alias)) || (!strcmp(Name, Alias)) || (++AliasCount == 16))
        {
            /* Exit the loop with a failure */
            iError = EAI_FAIL;
            break;
        }

        /* Restart loopup if we got a CNAME */
        Swap(Name, Alias, Scratch);
    }

    /* Check if we succeeded and the canonical name is requested */
    if (!iError && bAI_CANONNAME)
    {
        /* Allocate memory for a copy */
        (*pptResult)->ai_canonname = HeapAlloc(WsSockHeap, 0, 512);

        /* Check if we had enough memory */
        if (!(*pptResult)->ai_canonname)
        {
            /* Set failure code */
            iError = EAI_MEMORY;
        }
        else
        {
            /* Convert the alias to UNICODE */
            MultiByteToWideChar(CP_ACP,
                                0,
                                Alias,
                                -1,
                                (*pptResult)->ai_canonname,
                                256);
        }
    }

    /* Return to caller */
    return iError;
}

/* The canonical name of "localhost" is the name of this computer (Windows 10 measured). 0 or an EAI_ error */
static
INT
SetComputerNameCanon(IN PADDRINFOW AddrInfo)
{
    CHAR HostName[256];
    SIZE_T Length;

    if (AddrInfo->ai_canonname)
    {
        HeapFree(WsSockHeap, 0, AddrInfo->ai_canonname);
        AddrInfo->ai_canonname = NULL;
    }
    if (gethostname(HostName, sizeof(HostName)) != 0)
        return 0;

    Length = strlen(HostName) + 1;
    AddrInfo->ai_canonname = HeapAlloc(WsSockHeap, 0, Length * sizeof(WCHAR));
    if (!AddrInfo->ai_canonname)
        return EAI_MEMORY;
    MultiByteToWideChar(CP_ACP, 0, HostName, -1, AddrInfo->ai_canonname, (int)Length);
    return 0;
}

/*
 * @implemented
 */
INT
WSAAPI
GetAddrInfoW(IN PCWSTR pszNodeName,
             IN PCWSTR pszServiceName,
             IN const ADDRINFOW *ptHints,
             OUT PADDRINFOW *pptResult)
{
    INT iError = 0;
    INT iFlags = 0;
    INT iFamily = PF_UNSPEC;
    INT iSocketType = 0;
    INT iProtocol = 0;
    WORD wPort = 0;
    DWORD dwAddress = 0;
    PSERVENT ptService = NULL;
    PCHAR pc = NULL;
    BOOL bClone = FALSE;
    BOOL bNumeric, bNumeric6 = FALSE, bNoNode6 = FALSE, bTrailingSpace = FALSE;
    BOOL bV6On;
    WS_IPV6_INFO V6Info;
    IN6_ADDR Address6;
    ULONG ulScope6 = 0;
    WORD wTcpPort = 0;
    WORD wUdpPort = 0;
    WCHAR CanonicalName[0x42];
    CHAR AnsiServiceName[256];
    CHAR AnsiNodeName[256];
    DPRINT("GetAddrInfoW: %S, %S, %p, %p\n", pszNodeName, pszServiceName, ptHints, pptResult);

    /* Check for WSAStartup */
    if ((iError = WsQuickProlog()) != ERROR_SUCCESS) return iError;

    /* Assume error */
    *pptResult  = NULL;

    /* We must have at least one name to work with */
    if (!(pszNodeName) && !(pszServiceName))
    {
        /* Fail */
        SetLastError(EAI_NONAME);
        return EAI_NONAME;
    }

    /*
     * Whether the stack has IPv6 on (Tcpip\Parameters\Ipv6Enable, off by default). Off, every answer below is
     * the one of a system without IPv6. On, the names that mean this machine (no node, "localhost") answer
     * IPv6 before IPv4 as Windows 10 does, AI_ADDRCONFIG leaves the IPv6 answers out while no non-loopback IPv6
     * address is usable, and the IPv6 family is a family: it finds no IPv4 address (WSAHOST_NOT_FOUND) instead
     * of failing (WSAEAFNOSUPPORT). Host names are still resolved to IPv4 addresses only (no AAAA queries).
     */
    bV6On = WsQueryIpv6((ptHints && (ptHints->ai_flags & AI_ADDRCONFIG)) ? &V6Info : NULL);
    if (!(ptHints && (ptHints->ai_flags & AI_ADDRCONFIG)))
        V6Info.NonLoopback = 0;

    /* Check if we got hints */
    if (ptHints)
    {
        /* Make sure these are empty */
        if ((ptHints->ai_addrlen) ||
            (ptHints->ai_canonname) ||
            (ptHints->ai_addr) ||
            (ptHints->ai_next))
        {
            /* Fail if they aren't */
            SetLastError(EAI_FAIL);
            return EAI_FAIL;
        }

        /* Save the flags and validate them */
        iFlags = ptHints->ai_flags;
        if ((iFlags & AI_CANONNAME) && !pszNodeName)
        {
            SetLastError(EAI_BADFLAGS);
            return EAI_BADFLAGS;
        }

        /* Save family and validate it */
        iFamily = ptHints->ai_family;
        bNumeric6 = (iFamily == PF_UNSPEC || iFamily == PF_INET6) &&
                    ParseV6Address(pszNodeName, &Address6, &ulScope6);

        /*
         * No node name for the IPv6 family: Windows 10 (IPv6 installed, measured) answers the
         * wildcard "::" (AI_PASSIVE) or the loopback "::1". Without an IPv6 transport here the
         * address is only a name; creating an IPv6 socket is what fails, with WSAEAFNOSUPPORT,
         * which is the failure a server with an optional "::" bind skips.
         * AF_UNSPEC keeps its IPv4-only answer: this system has no IPv6 transport to serve it.
         */
        /*
         * The name "localhost" (or "localhost.") for PF_INET6 is answered as the no-node loopback
         * case: Windows 10 (IPv6 installed, measured for "localhost") answers ::1. The match is
         * case-insensitive here; the case, the trailing-dot form and the flag combinations other
         * than the plain query were not measured. AI_NUMERICHOST is not satisfied by a name, so it
         * keeps its previous failure. PF_UNSPEC "localhost" is not changed and stays IPv4 only: a
         * client that connects to the first result would get ::1 first and fail, since there is no
         * IPv6 transport to connect with.
         */
        if (pszNodeName && iFamily == PF_INET6 && !(iFlags & AI_NUMERICHOST) &&
            IsLocalhostName(pszNodeName))
        {
            RtlZeroMemory(&Address6, sizeof(Address6));
            ulScope6 = 0;
            Address6.u.Byte[15] = 1;
            bNumeric6 = TRUE;
            bNoNode6 = TRUE;
        }
        else if (!pszNodeName && iFamily == PF_INET6)
        {
            RtlZeroMemory(&Address6, sizeof(Address6));
            ulScope6 = 0;
            if (!(iFlags & AI_PASSIVE))
                Address6.u.Byte[15] = 1;
            bNumeric6 = TRUE;
            bNoNode6 = TRUE;
        }

        if ((iFamily != PF_UNSPEC) && (iFamily != PF_INET) && !bNumeric6 && !(bV6On && iFamily == PF_INET6))
        {
            SetLastError(EAI_FAMILY);
            return EAI_FAMILY;
        }

        /* Save socket type and validate it */
        iSocketType = ptHints->ai_socktype;
        if ((iSocketType != 0) &&
            (iSocketType != SOCK_STREAM) &&
            (iSocketType != SOCK_DGRAM) &&
            (iSocketType != SOCK_RAW))
        {
            SetLastError(EAI_SOCKTYPE);
            return EAI_SOCKTYPE;
        }

        /* Save the protocol */
        iProtocol = ptHints->ai_protocol;
    }

    /* Check if we have a service name */
    if (pszServiceName)
    {
        /* We need to convert it to ANSI */
        WideCharToMultiByte(CP_ACP,
                            0,
                            pszServiceName,
                            -1,
                            AnsiServiceName,
                            sizeof(AnsiServiceName),
                            NULL,
                            0);

        /* Get the port */
        wPort = (WORD)strtoul(AnsiServiceName, &pc, 10);

        /* Check if the port string is numeric */
        if (*pc == '\0')
        {
            /* Get the port directly */
            wPort = wTcpPort = wUdpPort = htons(wPort);

#if 0
            /* Check if this is both TCP and UDP */
            if (iSocketType == 0)
            {
                /* Set it to TCP for now, but remember to clone */
                bClone = TRUE;
                iSocketType = SOCK_STREAM;
            }
#endif
        }
        else
        {
            wPort = 0;
            /* The port name was a string. Check if this is a UDP socket */
            if ((iSocketType == 0) || (iSocketType == SOCK_DGRAM))
            {
                /* It's UDP, do a getservbyname */
                ptService = getservbyname(AnsiServiceName, "udp");

                /* If we got a servent, return the port from it */
                if (ptService) wPort = wUdpPort = ptService->s_port;
            }

            /* Check if this is a TCP socket */
            if ((iSocketType == 0) || (iSocketType == SOCK_STREAM))
            {
                /* It's TCP, do a getserbyname */
                ptService = getservbyname(AnsiServiceName, "tcp");

                /* Return the port from the servent */
                if (ptService) wPort = wTcpPort = ptService->s_port;
            }

            /* If we got 0, then fail */
            if (wPort == 0)
            {
                SetLastError(EAI_SERVICE);
                return EAI_SERVICE;
            }

            /* Check if this was for both */
            if (iSocketType == 0)
            {
                /* Do the TCP case right now */
                if (wTcpPort && !wUdpPort)
                    iSocketType = SOCK_STREAM;
                if (!wTcpPort && wUdpPort)
                    iSocketType = SOCK_DGRAM;
                //bClone = (wTcpPort && wUdpPort);
            }
        }
    }

    /* An IPv6 address answers with itself, and with the family the caller allowed */
    if (!ptHints)
        bNumeric6 = ParseV6Address(pszNodeName, &Address6, &ulScope6);

    /* Check if this is a valid IPv4 address */
    bNumeric = pszNodeName && !bNumeric6 && ParseV4Address(pszNodeName, &dwAddress, &bTrailingSpace);

    /* An address with trailing whitespace is not strictly numeric */
    if (bNumeric && bTrailingSpace && (iFlags & AI_NUMERICHOST))
        bNumeric = FALSE;

    if (bNumeric6)
    {
        *pptResult = NewAddrInfo6(iSocketType, iProtocol, wPort, &Address6, ulScope6);
        if (!(*pptResult))
        {
            iError = EAI_MEMORY;
        }
        else
        {
            /* An address that was not given by the caller is not numeric host input */
            if (!bNoNode6)
                (*pptResult)->ai_flags |= AI_NUMERICHOST;

            /* The canonical name of an address is its numeric form, as for an IPv4 address */
            if (iFlags & AI_CANONNAME)
            {
                ULONG CanonicalLength = RTL_NUMBER_OF(CanonicalName);

                CanonicalName[0] = UNICODE_NULL;
                /* Windows 10 (measured): with a service the name is "[::1]:80", the port in it */
                RtlIpv6AddressToStringExW(&Address6, ulScope6, bV6On ? wPort : 0, CanonicalName, &CanonicalLength);

                (*pptResult)->ai_canonname = HeapAlloc(WsSockHeap,
                                                       0,
                                                       (wcslen(CanonicalName) + 1) * sizeof(WCHAR));
                if (!(*pptResult)->ai_canonname)
                    iError = EAI_MEMORY;
                else
                    RtlMoveMemory((*pptResult)->ai_canonname,
                                  CanonicalName,
                                  (wcslen(CanonicalName) + 1) * sizeof(WCHAR));
            }
        }
    }
    /* Check if no node was given or if this is is a valid IPv4 address */
    else if ((!pszNodeName) || bNumeric)
    {
        /* Check if we don't have a node name */
        if (!pszNodeName)
        {
            /* Make one up based on the flags */
            dwAddress = htonl((iFlags & AI_PASSIVE) ?
                              INADDR_ANY : INADDR_LOOPBACK);
        }

        /* Create the Addr Info */
        *pptResult = NewAddrInfo(iSocketType, iProtocol, wPort, dwAddress);

        /* If we didn't get one back, assume out of memory */
        if (!(*pptResult)) iError = EAI_MEMORY;

        /* Check if we have success and a nodename */
        if (!iError && pszNodeName)
        {
            /* Set AI_NUMERICHOST since this is a numeric string */
            if (!bTrailingSpace)
                (*pptResult)->ai_flags |= AI_NUMERICHOST;

            /* Check if the canonical name was requested */
            if (iFlags & AI_CANONNAME)
            {
                /* Get the canonical name */
                GetNameInfoW((*pptResult)->ai_addr,
                             (socklen_t)(*pptResult)->ai_addrlen,
                             CanonicalName,
                             0x41,
                             NULL,
                             0,
                             2);

                /* Allocate memory for a copy */
                (*pptResult)->ai_canonname = HeapAlloc(WsSockHeap,
                                                       0,
                                                       (wcslen(CanonicalName) + 1) * sizeof(WCHAR));

                if (!(*pptResult)->ai_canonname)
                {
                    /* No memory for the copy */
                    iError = EAI_MEMORY;
                }
                else
                {
                    /* Duplicate the string */
                    RtlMoveMemory((*pptResult)->ai_canonname,
                                  CanonicalName,
                                  (wcslen(CanonicalName) + 1) * sizeof(WCHAR));
                }
            }
        }
    }
    else if (iFlags & AI_NUMERICHOST)
    {
        /* No name for this request (we have a non-numeric name) */
        iError = EAI_NONAME;
    }
    else
    {
        /* We need to convert it to ANSI */
        WideCharToMultiByte(CP_ACP,
                            0,
                            pszNodeName,
                            -1,
                            AnsiNodeName,
                            sizeof(AnsiNodeName),
                            NULL,
                            0);

        /* Non-numeric name, do DNS lookup. Windows 10 answers "localhost" itself (with or without the root dot)
           and does not look at the hosts file for it; with IPv6 on, so do we */
        if (bV6On && IsLocalhostName(pszNodeName))
        {
            *pptResult = NewAddrInfo(iSocketType, iProtocol, wPort, htonl(INADDR_LOOPBACK));
            iError = *pptResult ? 0 : EAI_MEMORY;
            /* every family: for AF_UNSPEC the ::1 entry takes the name over below, but with AI_ADDRCONFIG
               and no usable IPv6 address nothing is prepended and this entry keeps it */
            if (!iError && (iFlags & AI_CANONNAME))
                iError = SetComputerNameCanon(*pptResult);
        }
        else
        {
            iError = LookupAddressForName(AnsiNodeName,
                                          iSocketType,
                                          iProtocol,
                                          wPort,
                                          (iFlags & AI_CANONNAME),
                                          pptResult);
        }
    }

    if (!iError && bV6On && *pptResult)
    {
        /* The IPv6 family finds IPv6 addresses only: what resolved to IPv4 ones is no answer */
        if (iFamily == PF_INET6 && (*pptResult)->ai_family != PF_INET6)
        {
            FreeAddrInfoW(*pptResult);
            *pptResult = NULL;
            iError = EAI_NONAME;
        }
        /* No IPv6 address that can be used as a source: AI_ADDRCONFIG asks for no IPv6 answer */
        else if (iFamily == PF_INET6 && (iFlags & AI_ADDRCONFIG) && !V6Info.NonLoopback &&
                 (!bNumeric6 || bNoNode6))
        {
            FreeAddrInfoW(*pptResult);
            *pptResult = NULL;
            iError = EAI_NONAME;
        }
        /* This machine, for either family: ::1 (or :: for a server) before the IPv4 answer */
        else if (iFamily == PF_UNSPEC && !bNumeric6 && !bNumeric &&
                 (!pszNodeName || (IsLocalhostName(pszNodeName) && !(iFlags & AI_NUMERICHOST))) &&
                 (*pptResult)->ai_family == PF_INET &&
                 (!(iFlags & AI_ADDRCONFIG) || V6Info.NonLoopback))
        {
            PADDRINFOW Head;

            RtlZeroMemory(&Address6, sizeof(Address6));
            /* the wildcard :: for a server without a node name, the loopback ::1 otherwise */
            if (pszNodeName || !(iFlags & AI_PASSIVE))
                Address6.u.Byte[15] = 1;

            Head = NewAddrInfo6((*pptResult)->ai_socktype, (*pptResult)->ai_protocol, wPort, &Address6, 0);
            if (!Head)
            {
                iError = EAI_MEMORY;
            }
            else
            {
                Head->ai_next = *pptResult;
                *pptResult = Head;

                /* the name of this computer goes with the first entry only */
                if ((iFlags & AI_CANONNAME) && pszNodeName)
                {
                    iError = SetComputerNameCanon(Head);
                    if (!iError && Head->ai_next->ai_canonname)
                    {
                        HeapFree(WsSockHeap, 0, Head->ai_next->ai_canonname);
                        Head->ai_next->ai_canonname = NULL;
                    }
                }
            }
        }
    }

    /* If all was good and the caller requested UDP and TCP */
    if (!iError && bClone)
    {
        /* Process UDP now, we already did TCP */
        iError = CloneAddrInfo(wUdpPort, *pptResult);
    }

    /* If we've hit an error till here */
    if (iError)
    {
        /* Free the address info and return nothing */
        FreeAddrInfoW(*pptResult);
        *pptResult = NULL;
    }

    /* Return to caller */
    SetLastError(iError);
    return iError;
}

#undef freeaddrinfo
/*
 * @implemented
 */
VOID
WINAPI
freeaddrinfo(PADDRINFOA AddrInfo)
{
    PADDRINFOA NextInfo;

    /* Loop the chain of structures */
    for (NextInfo = AddrInfo; NextInfo; NextInfo = AddrInfo)
    {
        /* Check if there is a canonical name */
        if (NextInfo->ai_canonname)
        {
            /* Free it */
            HeapFree(WsSockHeap, 0, NextInfo->ai_canonname);
        }

        /* Check if there is an address */
        if (NextInfo->ai_addr)
        {
            /* Free it */
            HeapFree(WsSockHeap, 0, NextInfo->ai_addr);
        }

        /* Move to the next entry */
        AddrInfo = NextInfo->ai_next;

        /* Free this entry */
        HeapFree(WsSockHeap, 0, NextInfo);
    }
}

#undef getaddrinfo
/*
 * @implemented
 */
INT
WINAPI
getaddrinfo(const char FAR *nodename,
            const char FAR *servname,
            const struct addrinfo FAR *hints,
            struct addrinfo FAR * FAR *res)
{
    INT ErrorCode;
    LPWSTR UnicodeNodeName = NULL;
    LPWSTR UnicodeServName = NULL;
    DPRINT("getaddrinfo: %s, %s, %p, %p\n", nodename, servname, hints, res);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickProlog()) != ERROR_SUCCESS) return ErrorCode;

    /* Convert the node name */
    if (nodename)
    {
        UnicodeNodeName = UnicodeDupFromAnsi(nodename);
        if (!UnicodeNodeName)
        {
            /* Prepare to fail */
            ErrorCode = GetLastError();
            goto Quickie;
        }
    }

    /* Convert the servname too, if we have one */
    if (servname)
    {
        UnicodeServName = UnicodeDupFromAnsi(servname);
        if (!UnicodeServName)
        {
            /* Prepare to fail */
            ErrorCode = GetLastError();
            goto Quickie;
        }
    }

    /* Now call the unicode function */
    ErrorCode = GetAddrInfoW(UnicodeNodeName,
                             UnicodeServName,
                             (PADDRINFOW)hints,
                             (PADDRINFOW*)res);

    /* Convert it to ANSI if we succeeded */
    if (ErrorCode == ERROR_SUCCESS) ConvertAddrinfoFromUnicodeToAnsi((PADDRINFOW)*res);

Quickie:
    /* Check if we have a unicode node name and serv name */
    if (UnicodeNodeName) HeapFree(WsSockHeap, 0, UnicodeNodeName);
    if (UnicodeServName) HeapFree(WsSockHeap, 0, UnicodeServName);

    /* Check if we are in error */
    if (ErrorCode != ERROR_SUCCESS)
    {
        /* Free the structure and return nothing */
        freeaddrinfo(*res);
        *res = NULL;
    }

    /* Set the last error and return */
    SetLastError(ErrorCode);
    return ErrorCode;
}

/*
 * @implemented
 */
INT
WSAAPI
GetNameInfoW(IN CONST SOCKADDR *pSockaddr,
             IN socklen_t SockaddrLength,
             OUT PWCHAR pNodeBuffer,
             IN DWORD NodeBufferSize,
             OUT PWCHAR pServiceBuffer,
             IN DWORD ServiceBufferSize,
             IN INT Flags)
{
    DWORD AddressLength, AddrSize;
    PVOID Addr;
    SOCKADDR_IN6 Address;
    INT ErrorCode = ERROR_SUCCESS;

    DPRINT("GetNameInfoW: %p, %d, %p, %ld, %p, %ld, %d\n",
           pSockaddr,
           SockaddrLength,
           pNodeBuffer,
           NodeBufferSize,
           pServiceBuffer,
           ServiceBufferSize,
           Flags);

    /* Check for valid socket */
    if (!pSockaddr)
        return WSAEFAULT;

    /* Check which family this is */
    if (pSockaddr->sa_family == AF_INET)
    {
        /* IPv4 */
        AddressLength = sizeof(SOCKADDR_IN);
        Addr = &((PSOCKADDR_IN)pSockaddr)->sin_addr;
        AddrSize = sizeof(IN_ADDR);
    }
    else if (pSockaddr->sa_family == AF_INET6)
    {
        /* IPv6 */
        AddressLength = sizeof(SOCKADDR_IN6);
        Addr = &((PSOCKADDR_IN6)pSockaddr)->sin6_addr;
        AddrSize = sizeof(IN6_ADDR);
    }
    else
    {
        /* Unsupported family */
        SetLastError(EAI_FAMILY);
        return EAI_FAMILY;
    }

    /* Check for valid socket address length */
    if ((DWORD)SockaddrLength < AddressLength)
        return WSAEFAULT;

    /* Check if we have a node name */
    if (pNodeBuffer)
    {
        /* Check if only the numeric host is wanted */
        if (!(Flags & NI_NUMERICHOST))
        {
            /* Do the lookup by addr */
            ErrorCode = LookupNodeByAddr(pNodeBuffer,
                                         NodeBufferSize,
                                         Flags & NI_NOFQDN,
                                         Addr,
                                         AddrSize,
                                         pSockaddr->sa_family);
            /* Check if we failed */
            if (ErrorCode != ERROR_SUCCESS)
            {
                /* Fail if the caller REALLY wants the NAME itself? */
                if (Flags & NI_NAMEREQD) goto quickie;
            }
            else
            {
                /* We succeeded, no need to get the numeric address */
                goto SkipNumeric;
            }
        }

        /* Copy the address */
        RtlMoveMemory(&Address, pSockaddr, AddressLength);

        /* Get the numeric address */
        if (pSockaddr->sa_family == AF_INET)
        {
            /* IPv4 */
            ((PSOCKADDR_IN)&Address)->sin_port = 0;
        }
        else if (pSockaddr->sa_family == AF_INET6)
        {
            /* IPv6 */
            ((PSOCKADDR_IN6)&Address)->sin6_port = 0;
        }
        ErrorCode = WSAAddressToStringW((LPSOCKADDR)&Address,
                                        AddressLength,
                                        NULL,
                                        pNodeBuffer,
                                        &NodeBufferSize);
        if (ErrorCode == SOCKET_ERROR)
        {
            /* Get the error code and exit with it */
            ErrorCode = GetLastError();
            goto quickie;
        }
    }

SkipNumeric:
    /* Check if we got a service name */
    if (pServiceBuffer)
    {
        /* Handle this request */
        ErrorCode = GetServiceNameForPort(pServiceBuffer,
                                          ServiceBufferSize,
                                          ((PSOCKADDR_IN)pSockaddr)->sin_port,
                                          Flags);
    }

    /* Set the error and return it (or success) */
quickie:
    SetLastError(ErrorCode);
    return ErrorCode;
}

#undef getnameinfo
/*
 * @implemented
 */
INT
WINAPI
getnameinfo(const struct sockaddr FAR *sa,
            socklen_t salen,
            char FAR *host,
            DWORD hostlen,
            char FAR *serv,
            DWORD servlen,
            INT flags)
{
    INT ErrorCode;
    WCHAR Buffer[256];
    WCHAR ServiceBuffer[17];
    DWORD HostLength = 0, ServLength = 0;
    PWCHAR ServiceString = NULL, HostString = NULL;
    DPRINT("getnameinfo: %p, %p, %p, %lx\n", host, serv, sa, salen);

    /* Check for WSAStartup */
    if ((ErrorCode = WsQuickProlog()) != ERROR_SUCCESS) return ErrorCode;

    /* Check if we have a host pointer */
    if (host)
    {
        /* Setup the data for it */
        HostString = Buffer;
        HostLength = sizeof(Buffer) / sizeof(WCHAR);
    }

    /* Check if we have a service pointer */
    if (serv)
    {
        /* Setup the data for it */
        ServiceString = ServiceBuffer;
        ServLength = sizeof(ServiceBuffer) / sizeof(WCHAR);
    }

    /* Now call the unicode function */
    ErrorCode = GetNameInfoW(sa,
                             salen,
                             HostString,
                             HostLength,
                             ServiceString,
                             ServLength,
                             flags);

    /* Check for success */
    if (ErrorCode == ERROR_SUCCESS)
    {
        /* Check if we had a host pointer */
        if (HostString)
        {
            /* Convert it back to ANSI */
            ErrorCode = WideCharToMultiByte(CP_ACP,
                                            0,
                                            HostString,
                                            -1,
                                            host,
                                            hostlen,
                                            NULL,
                                            NULL);
            if (!ErrorCode)
            {
                ErrorCode = GetLastError();
                goto Quickie;
            }
        }

        /* Check if we have a service pointer */
        if (ServiceString)
        {
            /* Convert it back to ANSI */
            ErrorCode = WideCharToMultiByte(CP_ACP,
                                            0,
                                            ServiceString,
                                            -1,
                                            serv,
                                            servlen,
                                            NULL,
                                            NULL);
            if (!ErrorCode)
            {
                ErrorCode = GetLastError();
                goto Quickie;
            }
        }

        /* Return success */
        return ERROR_SUCCESS;
    }

    /* Set the last error and return */
Quickie:
    SetLastError(ErrorCode);
    return ErrorCode;
}

/*
 * Free an ADDRINFOEXA/W chain built by GetAddrInfoExW. The A and W layouts
 * are identical apart from the ai_canonname pointer type, so one routine
 * serves both.
 */
static
VOID
FreeAddrInfoExChain(IN PADDRINFOEXW pAddrInfoEx)
{
    PADDRINFOEXW Next;

    while (pAddrInfoEx)
    {
        Next = pAddrInfoEx->ai_next;
        if (pAddrInfoEx->ai_canonname)
            HeapFree(WsSockHeap, 0, pAddrInfoEx->ai_canonname);
        if (pAddrInfoEx->ai_addr)
            HeapFree(WsSockHeap, 0, pAddrInfoEx->ai_addr);
        if (pAddrInfoEx->ai_blob)
            HeapFree(WsSockHeap, 0, pAddrInfoEx->ai_blob);
        HeapFree(WsSockHeap, 0, pAddrInfoEx);
        pAddrInfoEx = Next;
    }
}

/*
 * @implemented
 */
VOID
WSAAPI
FreeAddrInfoExW(IN PADDRINFOEXW pAddrInfoEx)
{
    FreeAddrInfoExChain(pAddrInfoEx);
}

/*
 * @implemented
 */
VOID
WSAAPI
FreeAddrInfoEx(IN PADDRINFOEXA pAddrInfoEx)
{
    FreeAddrInfoExChain((PADDRINFOEXW)pAddrInfoEx);
}

/* Convert an ADDRINFOW chain (from GetAddrInfoW) into an ADDRINFOEXW chain */
static
INT
AddrInfoToAddrInfoEx(IN PADDRINFOW pSrc,
                     OUT PADDRINFOEXW *ppResult)
{
    PADDRINFOEXW Head = NULL, *Tail = &Head, Node;

    for (; pSrc; pSrc = pSrc->ai_next)
    {
        Node = HeapAlloc(WsSockHeap, HEAP_ZERO_MEMORY, sizeof(*Node));
        if (!Node)
            goto NoMemory;
        *Tail = Node;
        Tail = &Node->ai_next;

        Node->ai_flags = pSrc->ai_flags;
        Node->ai_family = pSrc->ai_family;
        Node->ai_socktype = pSrc->ai_socktype;
        Node->ai_protocol = pSrc->ai_protocol;
        Node->ai_addrlen = pSrc->ai_addrlen;

        if (pSrc->ai_addr && pSrc->ai_addrlen)
        {
            Node->ai_addr = HeapAlloc(WsSockHeap, 0, pSrc->ai_addrlen);
            if (!Node->ai_addr)
                goto NoMemory;
            RtlCopyMemory(Node->ai_addr, pSrc->ai_addr, pSrc->ai_addrlen);
        }
        if (pSrc->ai_canonname)
        {
            SIZE_T Size = (wcslen(pSrc->ai_canonname) + 1) * sizeof(WCHAR);
            Node->ai_canonname = HeapAlloc(WsSockHeap, 0, Size);
            if (!Node->ai_canonname)
                goto NoMemory;
            RtlCopyMemory(Node->ai_canonname, pSrc->ai_canonname, Size);
        }
    }

    *ppResult = Head;
    return ERROR_SUCCESS;

NoMemory:
    FreeAddrInfoExChain(Head);
    return WSA_NOT_ENOUGH_MEMORY;
}

/*
 * GetAddrInfoExW asynchronous machinery.
 *
 * Windows resolves an OVERLAPPED GetAddrInfoEx lookup on a system worker
 * thread and delivers the completion (completion routine or event) from
 * there, never as an APC to the calling thread (measured on Windows 10: the
 * routine runs on a thread-pool thread even when the caller never waits
 * alertably, and also when it does). .NET issues the call from thread-pool
 * threads that never wait alertably, so an APC delivery never ran.
 *
 * Every pending lookup is a GAIX_REQUEST on a global list, named by a small
 * integer handle (as on Windows). A request is completed exactly once, by
 * whichever of the lookup worker and GetAddrInfoExCancel moves it out of the
 * PENDING state while holding the list lock. The caller's OVERLAPPED and
 * result pointer are only touched by that winner, and never after the
 * completion has been signalled.
 */
#define GAIX_PENDING    0
#define GAIX_DONE       1
#define GAIX_CANCELLED  2

typedef struct _GAIX_REQUEST
{
    LIST_ENTRY Entry;
    ULONG_PTR Id;
    LONG State;
    LPOVERLAPPED Overlapped;
    LPLOOKUPSERVICE_COMPLETION_ROUTINE Routine;
    PADDRINFOEXW *ppResult;
    DWORD NameSpace;
    BOOL HasHints;
    ADDRINFOW Hints;
    PWSTR Name;
    PWSTR Service;
} GAIX_REQUEST, *PGAIX_REQUEST;

static volatile LONG GaixLock;
static volatile LONG GaixNextId;
static LIST_ENTRY GaixPending = {&GaixPending, &GaixPending};

static
VOID
GaixLockAcquire(VOID)
{
    /* Critical sections here are a handful of instructions: a spin lock is enough */
    while (InterlockedCompareExchange(&GaixLock, 1, 0) != 0)
        Sleep(0);
}

static
VOID
GaixLockRelease(VOID)
{
    InterlockedExchange(&GaixLock, 0);
}

/* The DNS lookup proper; also what a synchronous call and the async worker share */
static
INT
GaixResolve(IN PCWSTR pName,
            IN PCWSTR pServiceName,
            IN DWORD dwNameSpace,
            IN const ADDRINFOW *pHints,
            OUT PADDRINFOEXW *ppResult)
{
    ADDRINFOW *pResult = NULL;
    INT Error;

    *ppResult = NULL;

    /* Only the DNS-capable namespaces are served (Windows: WSASERVICE_NOT_FOUND) */
    if (dwNameSpace != NS_ALL && dwNameSpace != NS_DNS)
        return WSASERVICE_NOT_FOUND;

    Error = GetAddrInfoW(pName, pServiceName, pHints, &pResult);
    if (Error == ERROR_SUCCESS)
    {
        Error = AddrInfoToAddrInfoEx(pResult, ppResult);
        if (pResult)
            FreeAddrInfoW(pResult);
    }
    return Error;
}

/* Signal a completed request. The OVERLAPPED may be freed by the callee afterwards */
static
VOID
GaixSignal(IN LPOVERLAPPED Overlapped,
           IN LPLOOKUPSERVICE_COMPLETION_ROUTINE Routine,
           IN INT Error)
{
    Overlapped->Internal = (ULONG_PTR)(LONG)Error;
    Overlapped->InternalHigh = 0;
    if (Routine)
        Routine((DWORD)Error, 0, (LPWSAOVERLAPPED)Overlapped);
    else if (Overlapped->hEvent)
        SetEvent((HANDLE)((ULONG_PTR)Overlapped->hEvent & ~(ULONG_PTR)1));
}

static
VOID
GaixFreeRequest(IN PGAIX_REQUEST Request)
{
    HeapFree(WsSockHeap, 0, Request);
}

/* Worker: resolve, then complete unless the lookup was cancelled meanwhile */
static
DWORD
WINAPI
GaixLookupWorker(IN PVOID Parameter)
{
    PGAIX_REQUEST Request = Parameter;
    PADDRINFOEXW Result;
    LPOVERLAPPED Overlapped;
    LPLOOKUPSERVICE_COMPLETION_ROUTINE Routine;
    PADDRINFOEXW *ppResult;
    INT Error;
    BOOL Won = FALSE;

    Error = GaixResolve(Request->Name,
                        Request->Service,
                        Request->NameSpace,
                        Request->HasHints ? &Request->Hints : NULL,
                        &Result);

    GaixLockAcquire();
    if (Request->State == GAIX_PENDING)
    {
        Request->State = GAIX_DONE;
        RemoveEntryList(&Request->Entry);
        Won = TRUE;
    }
    GaixLockRelease();

    /* Copy what we need: the request is ours alone from here on */
    Overlapped = Request->Overlapped;
    Routine = Request->Routine;
    ppResult = Request->ppResult;
    GaixFreeRequest(Request);

    if (!Won)
    {
        /* Cancelled: the caller was told so; nobody owns this result */
        FreeAddrInfoExChain(Result);
        return 0;
    }

    /* The result must be visible before the completion is */
    *ppResult = Result;
    GaixSignal(Overlapped, Routine, Error);
    return 0;
}

/*
 * @implemented
 *
 * Without an OVERLAPPED the lookup runs on the calling thread (a timeout is
 * rejected with WSAEINVAL, as on Windows). With one, Windows completes
 * inline - returning the real result with nothing signalled and *lpHandle
 * NULL - when the name is NULL or a numeric address, or the call fails
 * validation; otherwise it returns WSA_IO_PENDING with *ppResult NULL,
 * resolves on a worker thread, stores the result, then runs the completion
 * routine on that thread or signals the event. Exactly one of the routine or
 * hEvent must be given. The result code ends up in Overlapped->Internal.
 * The timeout of an overlapped call is accepted and ignored.
 * lpNspId is not validated.
 */
INT
WSAAPI
GetAddrInfoExW(IN PCWSTR pName,
               IN PCWSTR pServiceName,
               IN DWORD dwNameSpace,
               IN LPGUID lpNspId,
               IN const ADDRINFOEXW *hints,
               OUT PADDRINFOEXW *ppResult,
               IN struct timeval *timeout,
               IN LPOVERLAPPED lpOverlapped,
               IN LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
               OUT LPHANDLE lpHandle)
{
    ADDRINFOW Hints, *pHints = NULL;
    PGAIX_REQUEST Request;
    SIZE_T NameSize = 0, ServiceSize = 0;
    INT Error;

    UNREFERENCED_PARAMETER(lpNspId);

    if (lpHandle)
        *lpHandle = NULL;

    if (!ppResult)
    {
        SetLastError(WSAEINVAL);
        return WSAEINVAL;
    }
    *ppResult = NULL;

    if (lpOverlapped)
    {
        /* Windows marks the operation in progress before it validates anything */
        lpOverlapped->Internal = WSAEINPROGRESS;

        /* Exactly one of the routine and the event */
        if (!lpCompletionRoutine == !lpOverlapped->hEvent)
        {
            SetLastError(WSAEINVAL);
            return WSAEINVAL;
        }
    }
    else if (lpCompletionRoutine || timeout)
    {
        SetLastError(WSAEINVAL);
        return WSAEINVAL;
    }

    if (hints)
    {
        RtlZeroMemory(&Hints, sizeof(Hints));
        Hints.ai_flags = hints->ai_flags;
        Hints.ai_family = hints->ai_family;
        Hints.ai_socktype = hints->ai_socktype;
        Hints.ai_protocol = hints->ai_protocol;
        pHints = &Hints;
    }

    if (!lpOverlapped)
    {
        Error = GaixResolve(pName, pServiceName, dwNameSpace, pHints, ppResult);
        SetLastError(Error);
        return Error;
    }

    /* Overlapped. Names that need no network are answered inline, like Windows */
    if (dwNameSpace == NS_ALL || dwNameSpace == NS_DNS)
    {
        ADDRINFOW Numeric;

        if (pHints)
            Numeric = Hints;
        else
            RtlZeroMemory(&Numeric, sizeof(Numeric));
        if (pName)
            Numeric.ai_flags |= AI_NUMERICHOST;

        Error = GaixResolve(pName, pServiceName, dwNameSpace, &Numeric, ppResult);

        /*
         * Success; or a failure that waiting would not change: any error but
         * "host not found" (family, service, flags), or a name the caller
         * said is numeric.
         */
        if (Error == ERROR_SUCCESS ||
            Error != WSAHOST_NOT_FOUND ||
            !pName ||
            (pHints && (pHints->ai_flags & AI_NUMERICHOST)))
        {
            SetLastError(Error);
            return Error;
        }
    }

    /* Hand the lookup to a worker; it needs its own copy of everything */
    if (pName)
        NameSize = (wcslen(pName) + 1) * sizeof(WCHAR);
    if (pServiceName)
        ServiceSize = (wcslen(pServiceName) + 1) * sizeof(WCHAR);

    Request = HeapAlloc(WsSockHeap, HEAP_ZERO_MEMORY, sizeof(*Request) + NameSize + ServiceSize);
    if (!Request)
    {
        SetLastError(WSA_NOT_ENOUGH_MEMORY);
        return WSA_NOT_ENOUGH_MEMORY;
    }
    if (pName)
    {
        Request->Name = (PWSTR)(Request + 1);
        RtlCopyMemory(Request->Name, pName, NameSize);
    }
    if (pServiceName)
    {
        Request->Service = (PWSTR)((PUCHAR)(Request + 1) + NameSize);
        RtlCopyMemory(Request->Service, pServiceName, ServiceSize);
    }
    Request->NameSpace = dwNameSpace;
    Request->HasHints = (pHints != NULL);
    if (pHints)
        Request->Hints = Hints;
    Request->Overlapped = lpOverlapped;
    Request->Routine = lpCompletionRoutine;
    Request->ppResult = ppResult;
    Request->State = GAIX_PENDING;
    do
    {
        Request->Id = (ULONG_PTR)InterlockedIncrement(&GaixNextId);
    } while (!Request->Id);

    /* The OVERLAPPED is the caller's from the moment the worker may run */
    lpOverlapped->Pointer = ppResult;
    if (lpHandle)
        *lpHandle = (HANDLE)Request->Id;

    GaixLockAcquire();
    InsertTailList(&GaixPending, &Request->Entry);
    GaixLockRelease();

    if (!QueueUserWorkItem(GaixLookupWorker, Request, WT_EXECUTELONGFUNCTION))
    {
        GaixLockAcquire();
        RemoveEntryList(&Request->Entry);
        GaixLockRelease();
        GaixFreeRequest(Request);
        if (lpHandle)
            *lpHandle = NULL;
        SetLastError(WSA_NOT_ENOUGH_MEMORY);
        return WSA_NOT_ENOUGH_MEMORY;
    }

    SetLastError(WSA_IO_PENDING);
    return WSA_IO_PENDING;
}

/*
 * @implemented
 *
 * Cancel a pending overlapped lookup: it completes with WSA_E_CANCELLED
 * (result NULL; routine run or event signalled before this returns) and
 * returns 0. A handle that is not pending
 * (never issued, completed, or already cancelled) gives WSA_INVALID_HANDLE
 * without touching the last error (measured on Windows 10).
 */
INT
WSAAPI
GetAddrInfoExCancel(IN LPHANDLE lpHandle)
{
    PGAIX_REQUEST Request = NULL;
    PLIST_ENTRY Entry;
    struct
    {
        LPOVERLAPPED Overlapped;
        LPLOOKUPSERVICE_COMPLETION_ROUTINE Routine;
    } Local = {NULL, NULL};
    ULONG_PTR Id;

    if (!lpHandle || !*lpHandle)
        return WSA_INVALID_HANDLE;
    Id = (ULONG_PTR)*lpHandle;

    GaixLockAcquire();
    for (Entry = GaixPending.Flink; Entry != &GaixPending; Entry = Entry->Flink)
    {
        PGAIX_REQUEST Candidate = CONTAINING_RECORD(Entry, GAIX_REQUEST, Entry);

        if (Candidate->Id == Id && Candidate->State == GAIX_PENDING)
        {
            /* Ours now: the lookup worker will see CANCELLED and drop its result */
            Request = Candidate;
            Request->State = GAIX_CANCELLED;
            RemoveEntryList(&Request->Entry);
            /* Safe to read: the worker frees the request only after it sees the state change under this lock */
            Local.Overlapped = Request->Overlapped;
            Local.Routine = Request->Routine;
            break;
        }
    }
    GaixLockRelease();

    if (!Request)
        return WSA_INVALID_HANDLE;

    /*
     * Windows runs the completion routine of a cancelled lookup right here,
     * on the cancelling thread, before GetAddrInfoExCancel returns (measured:
     * also when cancelled from a thread other than the issuing one).
     */
    GaixSignal(Local.Overlapped, Local.Routine, WSA_E_CANCELLED);
    return ERROR_SUCCESS;
}

/*
 * @implemented
 *
 * Windows returns the lookup's status: WSAEINPROGRESS while pending, 0 or
 * the failure after completion, WSA_E_CANCELLED if cancelled.
 */
INT
WSAAPI
GetAddrInfoExOverlappedResult(IN LPOVERLAPPED lpOverlapped)
{
    return (INT)lpOverlapped->Internal;
}
