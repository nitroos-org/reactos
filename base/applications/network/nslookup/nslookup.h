#ifndef _NSLOOKUP_H
#define _NSLOOKUP_H

#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#define _INC_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#define TypeA       "A"
#define TypeAAAA    "AAAA"
#define TypeBoth    "A+AAAA"
#define TypeAny     "ANY"
#define TypeCNAME   "CNAME"
#define TypeMX      "MX"
#define TypeNS      "NS"
#define TypePTR     "PTR"
#define TypeSOA     "SOA"
#define TypeSRV     "SRV"

#define TYPE_A      0x01
#define TYPE_AAAA   0x1C
#define TYPE_NS     0x02
#define TYPE_CNAME  0x05
#define TYPE_SOA    0x06
#define TYPE_WKS    0x0B
#define TYPE_PTR    0x0C
#define TYPE_MX     0x0F
#define TYPE_ANY    0xFF

#define ClassIN     "IN"
#define ClassAny    "ANY"

#define CLASS_IN    0x01
#define CLASS_ANY   0xFF

#define OPCODE_QUERY    0x00
#define OPCODE_IQUERY   0x01
#define OPCODE_STATUS   0x02

#define OpcodeQuery     "QUERY"
#define OpcodeIQuery    "IQUERY"
#define OpcodeStatus    "STATUS"
#define OpcodeReserved  "RESERVED"

#define RCODE_NOERROR   0x00
#define RCODE_FORMERR   0x01
#define RCODE_FAILURE   0x02
#define RCODE_NXDOMAIN  0x03
#define RCODE_NOTIMP    0x04
#define RCODE_REFUSED   0x05

#define RCodeNOERROR    "NOERROR"
#define RCodeFORMERR    "FORMERR"
#define RCodeFAILURE    "FAILURE"
#define RCodeNXDOMAIN   "NXDOMAIN"
#define RCodeNOTIMP     "NOTIMP"
#define RCodeREFUSED    "REFUSED"
#define RCodeReserved   "RESERVED"

#define DEFAULT_ROOT    "A.ROOT-SERVERS.NET."
#define ARPA_SIG        ".in-addr.arpa"

typedef struct _STATE
{
    BOOL debug;
    BOOL defname;
    BOOL d2;
    BOOL recurse;
    BOOL search;
    BOOL vc;
    BOOL ignoretc;
    BOOL MSxfr;
    CHAR domain[256];
    CHAR srchlist[6][256];
    CHAR root[256];
    DWORD retry;
    DWORD timeout;
    DWORD ixfrver;
    PCHAR type;
    PCHAR Class;
    USHORT port;
    CHAR DefaultServer[256];
    CHAR DefaultServerAddress[64]; /* IPv4 or IPv6 text (an IPv6 one may carry %scope) */
} STATE, *PSTATE;

/* nslookup.c */

extern STATE    State;
extern HANDLE   ProcessHeap;

/* utility.c */

BOOL SendRequest( PCHAR pInBuffer,
                  ULONG InBufferLength,
                  PCHAR pOutBuffer,
                  PULONG pOutBufferLength );

/* Largest name ExtractName writes, including the terminating NUL: every
   caller's output buffer is at least this big. */
#define EXTRACT_NAME_OUT_MAX 255

int     ExtractName( PCHAR pBuffer,
                     ULONG BufferLength,
                     PCHAR pOutput,
                     USHORT Offset,
                     UCHAR Limit );

/* The fixed part of a resource record after its name: type, class, TTL and data
   length, read at *pOffset. TRUE only when that part and the record data both lie
   inside the packet; *pOffset is then moved to the first byte of the data. */
BOOL    ReadRecordHeader( PCHAR pBuffer,
                          ULONG BufferLength,
                          int *pOffset,
                          USHORT *pType,
                          USHORT *pClass,
                          ULONG *pTtl,
                          USHORT *pDataLength );

/* The offset just after the (possibly compressed) name at Offset; -1 when the name runs past the packet.
   Independent of the length ExtractName writes: the wire length of the name. */
int     SkipName( PCHAR pBuffer, ULONG BufferLength, int Offset );

/* Skips the question section of a reply; FALSE when it runs past the packet. */
BOOL    SkipQuestions( PCHAR pBuffer,
                       ULONG BufferLength,
                       USHORT NumQuestions,
                       int *pOffset );

/* The reply is complete enough to read its header (12 bytes). */
#define DNS_HEADER_LENGTH 12
/* Truncation (TC) bit, in the third byte of the header. */
#define DNS_FLAG_TC 0x02

void    ReverseIP( PCHAR pIP, PCHAR pReturn );
BOOL    IsValidIP( PCHAR pInput );
BOOL    IsValidIPv6( PCHAR pInput );
int     ExtractIP( PCHAR pBuffer, PCHAR pOutput, USHORT Offset );
void    PrintD2( PCHAR pBuffer, DWORD BufferLength );
void    PrintDebug( PCHAR pBuffer, DWORD BufferLength );
PCHAR   OpcodeIDtoOpcodeName( UCHAR Opcode );
PCHAR   RCodeIDtoRCodeName( UCHAR RCode );
PCHAR   TypeIDtoTypeName( USHORT TypeID );
USHORT  TypeNametoTypeID( PCHAR TypeName );
PCHAR   ClassIDtoClassName( USHORT ClassID );
USHORT  ClassNametoClassID( PCHAR ClassName );

#endif /* _NSLOOKUP_H */
