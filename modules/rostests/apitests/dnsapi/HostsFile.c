/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Names of the hosts file are answered by DnsQuery, gethostbyname, getaddrinfo and
 *              GetAddrInfoEx (IPv4 and IPv6 rows, several names per line, comments, CRLF and LF,
 *              case, a row that shadows another name, changes picked up without a restart)
 *
 * The test replaces the real hosts file while it runs and puts the original back. That is only done in a
 * throwaway machine: the test does nothing unless the environment variable NITRO_HOSTS_TEST is 1.
 */

/* The Vista+ address info types are hidden from the 0x502 headers this module is built with */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#undef WINVER
#define WINVER 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windns.h>
#include <apitest.h>

typedef INT (WSAAPI *PFN_GetAddrInfoExW)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW *, PADDRINFOEXW *,
                                         struct timeval *, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
typedef VOID (WSAAPI *PFN_FreeAddrInfoExW)(PADDRINFOEXW);

static PFN_GetAddrInfoExW pGetAddrInfoExW;
static PFN_FreeAddrInfoExW pFreeAddrInfoExW;
static char g_HostsPath[MAX_PATH];
static BYTE *g_Saved;
static DWORD g_SavedSize;
static BOOL g_HadFile;
static BOOL g_V6;
static char g_ComputerName[128];

static
BOOL
WriteHosts(const char *Text)
{
    HANDLE File = CreateFileA(g_HostsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Written = 0;
    BOOL Ret;

    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(File, Text, (DWORD)strlen(Text), &Written, NULL) && Written == strlen(Text);
    CloseHandle(File);
    return Ret;
}

static
BOOL
SaveHosts(void)
{
    HANDLE File = CreateFileA(g_HostsPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Read;

    if (File == INVALID_HANDLE_VALUE)
    {
        g_HadFile = FALSE;
        return TRUE;
    }
    g_HadFile = TRUE;
    g_SavedSize = GetFileSize(File, NULL);
    g_Saved = HeapAlloc(GetProcessHeap(), 0, g_SavedSize + 1);
    if (!g_Saved || !ReadFile(File, g_Saved, g_SavedSize, &Read, NULL) || Read != g_SavedSize)
    {
        CloseHandle(File);
        return FALSE;
    }
    CloseHandle(File);
    return TRUE;
}

static
void
RestoreHosts(void)
{
    if (g_HadFile)
    {
        HANDLE File = CreateFileA(g_HostsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD Written;

        if (File != INVALID_HANDLE_VALUE)
        {
            WriteFile(File, g_Saved, g_SavedSize, &Written, NULL);
            CloseHandle(File);
        }
    }
    else
    {
        DeleteFileA(g_HostsPath);
    }
}

static
BOOL
GetHostsPath(void)
{
    char Dir[MAX_PATH];

    if (!GetSystemDirectoryA(Dir, sizeof(Dir)))
        return FALSE;
    snprintf(g_HostsPath, sizeof(g_HostsPath), "%s\\drivers\\etc\\hosts", Dir);
    return TRUE;
}

/* "a.b.c.d" of the n-th A record of the answer, "" when there is none */
static
void
RecordText(PDNS_RECORD Record, int Index, char *Out, size_t OutSize)
{
    Out[0] = 0;
    for (; Record; Record = Record->pNext)
    {
        if (Index-- == 0)
        {
            if (Record->wType == DNS_TYPE_A)
            {
                IN_ADDR In;
                In.s_addr = Record->Data.A.IpAddress;
                snprintf(Out, OutSize, "%s", inet_ntoa(In));
            }
            else if (Record->wType == DNS_TYPE_AAAA)
            {
                WORD *W = (WORD *)&Record->Data.AAAA.Ip6Address;
                snprintf(Out, OutSize, "%x:%x:%x:%x:%x:%x:%x:%x",
                         ntohs(W[0]), ntohs(W[1]), ntohs(W[2]), ntohs(W[3]),
                         ntohs(W[4]), ntohs(W[5]), ntohs(W[6]), ntohs(W[7]));
            }
            return;
        }
    }
}

static
int
RecordCount(PDNS_RECORD Record)
{
    int n = 0;
    for (; Record; Record = Record->pNext)
        n++;
    return n;
}

/* the answer of DnsQuery_A has the expected records in the file's order */
static
void
CheckDnsQuery(const char *Name, WORD Type, int Count, const char *First, const char *Second)
{
    PDNS_RECORD Record = NULL;
    DNS_STATUS Status;
    char Text[64];

    Status = DnsQuery_A(Name, Type, DNS_QUERY_STANDARD | DNS_QUERY_NO_RECURSION, NULL, &Record, NULL);
    ok(Status == ERROR_SUCCESS, "DnsQuery_A(%s, %u): %lu\n", Name, Type, Status);
    ok(RecordCount(Record) == Count, "DnsQuery_A(%s, %u): %d records, expected %d\n", Name, Type, RecordCount(Record), Count);
    RecordText(Record, 0, Text, sizeof(Text));
    ok(strcmp(Text, First) == 0, "DnsQuery_A(%s, %u): first %s, expected %s\n", Name, Type, Text, First);
    if (Second)
    {
        RecordText(Record, 1, Text, sizeof(Text));
        ok(strcmp(Text, Second) == 0, "DnsQuery_A(%s, %u): second %s, expected %s\n", Name, Type, Text, Second);
    }
    if (Record)
        DnsRecordListFree(Record, DnsFreeRecordList);
}

static
void
CheckNoRecord(const char *Name, WORD Type)
{
    PDNS_RECORD Record = NULL;
    DNS_STATUS Status;

    Status = DnsQuery_A(Name, Type, DNS_QUERY_NO_WIRE_QUERY, NULL, &Record, NULL);
    ok(Status != ERROR_SUCCESS && Record == NULL, "DnsQuery_A(%s, %u) no wire: %lu, record %p\n", Name, Type, Status, Record);
    if (Record)
        DnsRecordListFree(Record, DnsFreeRecordList);
}

static
void
CheckHostent(const char *Name, int Count, const char *First, const char *Second)
{
    struct hostent *He = gethostbyname(Name);
    int n = 0;
    char Text[64];

    ok(He != NULL, "gethostbyname(%s) failed: %d\n", Name, WSAGetLastError());
    if (!He)
        return;
    ok(He->h_addrtype == AF_INET && He->h_length == 4, "gethostbyname(%s): type %d length %d\n", Name, He->h_addrtype, He->h_length);
    while (He->h_addr_list[n])
        n++;
    ok(n == Count, "gethostbyname(%s): %d addresses, expected %d\n", Name, n, Count);
    if (n >= 1)
    {
        snprintf(Text, sizeof(Text), "%s", inet_ntoa(*(struct in_addr *)He->h_addr_list[0]));
        ok(strcmp(Text, First) == 0, "gethostbyname(%s): first %s, expected %s\n", Name, Text, First);
    }
    if (n >= 2 && Second)
    {
        snprintf(Text, sizeof(Text), "%s", inet_ntoa(*(struct in_addr *)He->h_addr_list[1]));
        ok(strcmp(Text, Second) == 0, "gethostbyname(%s): second %s, expected %s\n", Name, Text, Second);
    }
}

static
void
AddrText(const struct addrinfo *Ai, char *Out, size_t OutSize)
{
    DWORD Len = (DWORD)OutSize;

    Out[0] = 0;
    if (Ai->ai_family == AF_INET)
    {
        snprintf(Out, OutSize, "%s", inet_ntoa(((struct sockaddr_in *)Ai->ai_addr)->sin_addr));
    }
    else if (Ai->ai_family == AF_INET6)
    {
        const WORD *W = (const WORD *)&((struct sockaddr_in6 *)Ai->ai_addr)->sin6_addr;
        (void)Len;
        snprintf(Out, OutSize, "%x:%x:%x:%x:%x:%x:%x:%x",
                 ntohs(W[0]), ntohs(W[1]), ntohs(W[2]), ntohs(W[3]),
                 ntohs(W[4]), ntohs(W[5]), ntohs(W[6]), ntohs(W[7]));
    }
}

/* does the list have an entry of Family with this text? counts the entries of the family */
static
int
FindInList(const struct addrinfo *List, int Family, const char *Text)
{
    int Count = 0, Found = 0;
    char Buf[64];

    for (; List; List = List->ai_next)
    {
        if (List->ai_family != Family)
            continue;
        Count++;
        AddrText(List, Buf, sizeof(Buf));
        if (Text && strcmp(Buf, Text) == 0)
            Found = 1;
    }
    return Text ? Found : Count;
}

static
void
CheckGai(const char *Name, int Family, int Count4, int Count6, const char *Addr4, const char *Addr6)
{
    struct addrinfo Hints, *List = NULL;
    int Ret;

    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = Family;
    Hints.ai_socktype = SOCK_STREAM;
    Ret = getaddrinfo(Name, "80", &Hints, &List);
    if (Count4 == 0 && Count6 == 0)
    {
        ok(Ret != 0 && List == NULL, "getaddrinfo(%s, family %d): %d, expected a failure\n", Name, Family, Ret);
        if (List)
            freeaddrinfo(List);
        return;
    }
    ok(Ret == 0, "getaddrinfo(%s, family %d): %d (%d)\n", Name, Family, Ret, WSAGetLastError());
    if (Ret != 0)
        return;
    ok(FindInList(List, AF_INET, NULL) == Count4, "getaddrinfo(%s, family %d): %d IPv4 entries, expected %d\n",
       Name, Family, FindInList(List, AF_INET, NULL), Count4);
    ok(FindInList(List, AF_INET6, NULL) == Count6, "getaddrinfo(%s, family %d): %d IPv6 entries, expected %d\n",
       Name, Family, FindInList(List, AF_INET6, NULL), Count6);
    if (Addr4)
        ok(FindInList(List, AF_INET, Addr4), "getaddrinfo(%s, family %d): no %s\n", Name, Family, Addr4);
    if (Addr6)
        ok(FindInList(List, AF_INET6, Addr6), "getaddrinfo(%s, family %d): no %s\n", Name, Family, Addr6);
    freeaddrinfo(List);
}

static
void
CheckGaiEx(const WCHAR *Name, int Count4, int Count6, const char *Addr4, const char *Addr6)
{
    ADDRINFOEXW Hints, *List = NULL;
    ADDRINFOEXW *Ai;
    int Ret, n4 = 0, n6 = 0, Has4 = 0, Has6 = 0;
    char Buf[64];

    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = AF_UNSPEC;
    Hints.ai_socktype = SOCK_STREAM;
    if (!pGetAddrInfoExW)
        return;
    Ret = pGetAddrInfoExW(Name, L"80", NS_DNS, NULL, &Hints, &List, NULL, NULL, NULL, NULL);
    ok(Ret == 0, "GetAddrInfoExW(%ls): %d\n", Name, Ret);
    if (Ret != 0)
        return;
    for (Ai = List; Ai; Ai = Ai->ai_next)
    {
        if (Ai->ai_family == AF_INET)
        {
            n4++;
            snprintf(Buf, sizeof(Buf), "%s", inet_ntoa(((struct sockaddr_in *)Ai->ai_addr)->sin_addr));
            if (Addr4 && strcmp(Buf, Addr4) == 0)
                Has4 = 1;
        }
        else if (Ai->ai_family == AF_INET6)
        {
            const WORD *W = (const WORD *)&((struct sockaddr_in6 *)Ai->ai_addr)->sin6_addr;
            n6++;
            snprintf(Buf, sizeof(Buf), "%x:%x:%x:%x:%x:%x:%x:%x",
                     ntohs(W[0]), ntohs(W[1]), ntohs(W[2]), ntohs(W[3]),
                     ntohs(W[4]), ntohs(W[5]), ntohs(W[6]), ntohs(W[7]));
            if (Addr6 && strcmp(Buf, Addr6) == 0)
                Has6 = 1;
        }
    }
    ok(n4 == Count4, "GetAddrInfoExW(%ls): %d IPv4 entries, expected %d\n", Name, n4, Count4);
    ok(n6 == Count6, "GetAddrInfoExW(%ls): %d IPv6 entries, expected %d\n", Name, n6, Count6);
    if (Addr4)
        ok(Has4, "GetAddrInfoExW(%ls): no %s\n", Name, Addr4);
    if (Addr6)
        ok(Has6, "GetAddrInfoExW(%ls): no %s\n", Name, Addr6);
    pFreeAddrInfoExW(List);
}

/* every row of the table, against the file written by the caller */
static
void
CheckRows(const char *Label)
{
    trace("rows: %s\n", Label);

    /* DnsQuery: IPv4, case, several names per line, a tab, a trailing comment */
    CheckDnsQuery("hx-one", DNS_TYPE_A, 1, "10.77.5.1", NULL);
    CheckDnsQuery("HX-ONE", DNS_TYPE_A, 1, "10.77.5.1", NULL);
    CheckDnsQuery("hx-two.example.test", DNS_TYPE_A, 1, "10.77.5.2", NULL);
    CheckDnsQuery("Hx-Alias-Two", DNS_TYPE_A, 1, "10.77.5.2", NULL);
    CheckDnsQuery("hx-two-b", DNS_TYPE_A, 1, "10.77.5.2", NULL);
    CheckDnsQuery("hx-spaces", DNS_TYPE_A, 1, "10.77.5.11", NULL);
    CheckDnsQuery("hx-last", DNS_TYPE_A, 1, "10.77.5.13", NULL);
    /* two rows of one name: both, in the order of the file */
    CheckDnsQuery("hx-multi", DNS_TYPE_A, 2, "10.77.5.3", "10.77.5.4");
    /* IPv6 rows */
    CheckDnsQuery("hx-six", DNS_TYPE_AAAA, 1, "2001:db8:77:0:0:0:0:1", NULL);
    CheckDnsQuery("HX-V6MULTI-B", DNS_TYPE_AAAA, 1, "fd00:77:0:0:0:0:0:5", NULL);
    CheckDnsQuery("hx-v6multi", DNS_TYPE_AAAA, 1, "fd00:77:0:0:0:0:0:5", NULL);
    /* a name with both: each type its own row */
    CheckDnsQuery("hx-dual", DNS_TYPE_A, 1, "10.77.5.9", NULL);
    CheckDnsQuery("hx-dual", DNS_TYPE_AAAA, 1, "2001:db8:77:0:0:0:0:2", NULL);
    /* the other type of a one-family name: nothing (the name server is not asked) */
    CheckNoRecord("hx-one", DNS_TYPE_AAAA);
    CheckNoRecord("hx-six", DNS_TYPE_A);
    /* a name that is in no row, the comment and the too long line leave nothing */
    CheckNoRecord("hx-comment", DNS_TYPE_A);
    CheckNoRecord("hx-trailing-comment", DNS_TYPE_A);
    CheckNoRecord("hx-longline", DNS_TYPE_A);
    CheckNoRecord("hx-noaddr", DNS_TYPE_A);
    CheckNoRecord("hx-badaddr", DNS_TYPE_A);
    /* the row after the too long line is read */
    CheckDnsQuery("hx-afterlong", DNS_TYPE_A, 1, "10.77.5.14", NULL);
    /* a row that shadows the name of this machine */
    CheckDnsQuery(g_ComputerName, DNS_TYPE_A, 1, "10.77.5.12", NULL);

    /* gethostbyname */
    CheckHostent("hx-one", 1, "10.77.5.1", NULL);
    CheckHostent("HX-Alias-Two", 1, "10.77.5.2", NULL);
    CheckHostent("hx-multi", 2, "10.77.5.3", "10.77.5.4");
    CheckHostent("hx-dual", 1, "10.77.5.9", NULL);
    CheckHostent(g_ComputerName, 1, "10.77.5.12", NULL);

    /* getaddrinfo, AF_INET */
    CheckGai("hx-one", AF_INET, 1, 0, "10.77.5.1", NULL);
    CheckGai("HX-MULTI", AF_INET, 2, 0, "10.77.5.4", NULL);
    CheckGai("hx-dual", AF_INET, 1, 0, "10.77.5.9", NULL);
    CheckGai("hx-six", AF_INET, 0, 0, NULL, NULL);
    /* AF_UNSPEC */
    CheckGai("hx-one", AF_UNSPEC, 1, 0, "10.77.5.1", NULL);
    if (g_V6)
    {
        CheckGai("hx-six", AF_INET6, 0, 1, NULL, "2001:db8:77:0:0:0:0:1");
        CheckGai("hx-v6multi-b", AF_INET6, 0, 1, NULL, "fd00:77:0:0:0:0:0:5");
        CheckGai("hx-dual", AF_INET6, 0, 1, NULL, "2001:db8:77:0:0:0:0:2");
        CheckGai("hx-one", AF_INET6, 0, 0, NULL, NULL);
        CheckGai("hx-six", AF_UNSPEC, 0, 1, NULL, "2001:db8:77:0:0:0:0:1");
        CheckGai("hx-dual", AF_UNSPEC, 1, 1, "10.77.5.9", "2001:db8:77:0:0:0:0:2");
        CheckGaiEx(L"hx-dual", 1, 1, "10.77.5.9", "2001:db8:77:0:0:0:0:2");
        CheckGaiEx(L"HX-ONE", 1, 0, "10.77.5.1", NULL);
        CheckGaiEx(L"hx-six", 0, 1, NULL, "2001:db8:77:0:0:0:0:1");
    }
    else
    {
        CheckGaiEx(L"HX-ONE", 1, 0, "10.77.5.1", NULL);
    }
}

#define BASE_ROWS \
    "# a comment line\n" \
    "\n" \
    "10.77.5.1 hx-one            # trailing comment hx-trailing-comment\n" \
    "10.77.5.2\thx-two.example.test HX-ALIAS-TWO\thx-two-b\n" \
    "10.77.5.3 hx-multi\n" \
    "10.77.5.4 hx-multi\n" \
    "2001:db8:77::1 hx-six\n" \
    "2001:db8:77::2 hx-dual\n" \
    "10.77.5.9 hx-dual\n" \
    "fd00:77::5 hx-v6multi hx-v6multi-b\n" \
    "   10.77.5.11   hx-spaces   \n" \
    "#10.77.5.99 hx-comment\n" \
    "10.77.5.98\n" \
    "999.77.5.97 hx-badaddr\n"

START_TEST(HostsFile)
{
    WSADATA Wsa;
    SOCKET S;
    DWORD Size;
    char *Text, *P;
    char Row[8192];
    PDNS_RECORD Record;

    if (!GetEnvironmentVariableA("NITRO_HOSTS_TEST", Row, sizeof(Row)) || strcmp(Row, "1") != 0)
    {
        skip("NITRO_HOSTS_TEST is not 1: the test replaces the hosts file\n");
        return;
    }

    ok(WSAStartup(MAKEWORD(2, 2), &Wsa) == 0, "WSAStartup\n");
    pGetAddrInfoExW = (PFN_GetAddrInfoExW)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "GetAddrInfoExW");
    pFreeAddrInfoExW = (PFN_FreeAddrInfoExW)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "FreeAddrInfoExW");
    Size = sizeof(g_ComputerName);
    ok(GetComputerNameExA(ComputerNameDnsHostname, g_ComputerName, &Size), "GetComputerNameEx\n");
    ok(GetHostsPath(), "hosts path\n");
    S = socket(AF_INET6, SOCK_STREAM, 0);
    g_V6 = (S != INVALID_SOCKET);
    if (S != INVALID_SOCKET)
        closesocket(S);
    trace("IPv6 sockets: %d\n", g_V6);

    if (!SaveHosts())
    {
        skip("cannot read %s\n", g_HostsPath);
        return;
    }

    /* the long line is a row for hx-longline that is too long for the reader: it must not be taken */
    Text = HeapAlloc(GetProcessHeap(), 0, 8192);
    P = Text;
    P += sprintf(P, "%s", BASE_ROWS);
    P += sprintf(P, "10.77.5.50 ");
    memset(P, 'a', 3000);
    P += 3000;
    P += sprintf(P, " hx-longline\n");
    P += sprintf(P, "10.77.5.14 hx-afterlong\n");
    P += sprintf(P, "10.77.5.12 %s\n", g_ComputerName);
    P += sprintf(P, "10.77.5.13 hx-last");     /* no line end at the end of the file */

    /* LF only */
    ok(WriteHosts(Text), "write hosts (LF)\n");
    CheckRows("LF");

    /* CRLF: the same rows */
    {
        char *Crlf = HeapAlloc(GetProcessHeap(), 0, 16384), *Q = Crlf;

        for (P = Text; *P; P++)
        {
            if (*P == '\n')
                *Q++ = '\r';
            *Q++ = *P;
        }
        *Q = 0;
        ok(WriteHosts(Crlf), "write hosts (CRLF)\n");
        CheckRows("CRLF");
        HeapFree(GetProcessHeap(), 0, Crlf);
    }

    /* an edit is seen by the next query: a new name, then the name removed again */
    CheckNoRecord("hx-late", DNS_TYPE_A);
    sprintf(Row, "%s\n10.77.5.20 hx-late\n", Text);
    ok(WriteHosts(Row), "write hosts (late)\n");
    CheckDnsQuery("hx-late", DNS_TYPE_A, 1, "10.77.5.20", NULL);
    CheckHostent("hx-late", 1, "10.77.5.20", NULL);
    ok(WriteHosts(Text), "write hosts (late removed)\n");
    CheckNoRecord("hx-late", DNS_TYPE_A);

    /* the address of a name changes with the file */
    sprintf(Row, "10.77.5.30 hx-moving\n");
    ok(WriteHosts(Row), "write hosts (moving 1)\n");
    CheckDnsQuery("hx-moving", DNS_TYPE_A, 1, "10.77.5.30", NULL);
    sprintf(Row, "10.77.5.31 hx-moving\n");
    ok(WriteHosts(Row), "write hosts (moving 2)\n");
    CheckDnsQuery("hx-moving", DNS_TYPE_A, 1, "10.77.5.31", NULL);

    /* no file: no rows, no crash */
    DeleteFileA(g_HostsPath);
    CheckNoRecord("hx-moving", DNS_TYPE_A);
    Record = NULL;
    ok(DnsQuery_A("localhost", DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY, NULL, &Record, NULL) != ERROR_SUCCESS || Record != NULL,
       "localhost without a hosts file\n");
    if (Record)
        DnsRecordListFree(Record, DnsFreeRecordList);

    HeapFree(GetProcessHeap(), 0, Text);
    RestoreHosts();
    /* the original rows are back */
    CheckNoRecord("hx-one", DNS_TYPE_A);
    WSACleanup();
}
