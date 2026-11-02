/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         LGPLv2.1+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Tests for ICMP functions
 * PROGRAMMERS:     Tim Crawford
 *                  Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <apitest.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

static
void
test_IcmpCreateFile(void)
{
    HANDLE hIcmp;

    SetLastError(0xDEADBEEF);
    hIcmp = IcmpCreateFile();
    ok(hIcmp != INVALID_HANDLE_VALUE, "IcmpCreateFile failed unexpectedly: %lu\n", GetLastError());

    if (hIcmp != INVALID_HANDLE_VALUE)
        IcmpCloseHandle(hIcmp);
}

static
void
test_Icmp6CreateFile(void)
{
    HANDLE hIcmp;

    SetLastError(0xDEADBEEF);
    hIcmp = Icmp6CreateFile();

    if (GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        /* On Windows Server 2003, the IPv6 protocol must be installed. */
        skip("IPv6 is not available.\n");
        return;
    }

    ok(hIcmp != INVALID_HANDLE_VALUE, "Icmp6CreateFile failed unexpectedly: %lu\n", GetLastError());

    if (hIcmp != INVALID_HANDLE_VALUE)
        IcmpCloseHandle(hIcmp);
}

static
void
test_IcmpCloseHandle(void)
{
    HANDLE hIcmp;
    BOOL bRet;
    DWORD LastError;

    SetLastError(0xDEADBEEF);
    hIcmp = IcmpCreateFile();
    if (hIcmp != INVALID_HANDLE_VALUE)
    {
        bRet = IcmpCloseHandle(hIcmp);
        ok(bRet, "IcmpCloseHandle failed unexpectedly: %lu\n", GetLastError());
    }

    SetLastError(0xDEADBEEF);
    hIcmp = Icmp6CreateFile();
    if (hIcmp != INVALID_HANDLE_VALUE)
    {
        bRet = IcmpCloseHandle(hIcmp);
        ok(bRet, "IcmpCloseHandle failed unexpectedly: %lu\n", GetLastError());
    }

    hIcmp = INVALID_HANDLE_VALUE;
    SetLastError(0xDEADBEEF);
    bRet = IcmpCloseHandle(hIcmp);
    ok(!bRet, "IcmpCloseHandle succeeded unexpectedly\n");
    LastError = GetLastError();
    ok(LastError == ERROR_INVALID_HANDLE || LastError == ERROR_INVALID_PARAMETER,
       "Unexpected last error (0x%lX)\n", LastError);

    hIcmp = NULL;
    SetLastError(0xDEADBEEF);
    bRet = IcmpCloseHandle(hIcmp);
    ok(!bRet, "IcmpCloseHandle succeeded unexpectedly\n");
    LastError = GetLastError();
    ok(LastError == ERROR_INVALID_HANDLE || LastError == ERROR_INVALID_PARAMETER,
       "Unexpected last error (0x%lX)\n", LastError);
}

static
void
test_IcmpSendEcho(void)
{
    HANDLE hIcmp;
    unsigned long ipaddr = INADDR_NONE;
    DWORD bRet = 0, error = 0;
    char SendData[32] = "Data Buffer";
    PVOID ReplyBuffer;
    DWORD ReplySize = 0;

    SetLastError(0xDEADBEEF);
    hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
    {
        skip("IcmpCreateFile failed unexpectedly: %lu\n", GetLastError());
        return;
    }

    ipaddr = 0x08080808; // 8.8.8.8
    ReplyBuffer = malloc(sizeof(ICMP_ECHO_REPLY) + sizeof(SendData));

    ReplySize = sizeof(ICMP_ECHO_REPLY);
    SetLastError(0xDEADBEEF);
    bRet = IcmpSendEcho(hIcmp, ipaddr, SendData, sizeof(SendData),
        NULL, ReplyBuffer, ReplySize, 5000);

    ok(!bRet, "IcmpSendEcho succeeded unexpectedly\n");
    error = GetLastError();
    ok(error == IP_BUF_TOO_SMALL /* Win2003 */ ||
       error == IP_GENERAL_FAILURE /* Win10 */,
       "IcmpSendEcho returned unexpected error: %lu\n", error);

    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
    SetLastError(0xDEADBEEF);
    bRet = IcmpSendEcho(hIcmp, ipaddr, SendData, sizeof(SendData),
        NULL, ReplyBuffer, ReplySize, 5000);

    ok(bRet, "IcmpSendEcho failed unexpectedly: %lu\n", GetLastError());

    free(ReplyBuffer);
    IcmpCloseHandle(hIcmp);
}

/* Is the Administrators group enabled (not deny-only) in the effective token of this thread? */
static
BOOL
AdminsEnabled(PSID AdminsSid)
{
    HANDLE hToken;
    BYTE Buffer[4096];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;
    BOOL Ret = TRUE; /* unknown: assume the worst for the test */

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return Ret;
    if (GetTokenInformation(hToken, TokenGroups, Buffer, sizeof(Buffer), &Length))
    {
        Ret = FALSE;
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if (EqualSid(Groups->Groups[i].Sid, AdminsSid))
            {
                Ret = (Groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
                      !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY);
                break;
            }
        }
    }
    CloseHandle(hToken);
    return Ret;
}

/* Run a standard user's view: impersonate a copy of our token whose Administrators group is
 * deny-only and that has no privileges. If we already run as a standard user, no change is needed. */
static
BOOL
EnterStandardUser(BOOL *Impersonating)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_AND_ATTRIBUTES Admins;
    PSID AdminsSid = NULL;
    HANDLE hToken = NULL, hRestricted = NULL, hImpersonation = NULL;
    BOOL IsAdmin = FALSE, Ret = FALSE;

    *Impersonating = FALSE;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminsSid))
        return FALSE;

    IsAdmin = AdminsEnabled(AdminsSid);
    if (!IsAdmin)
    {
        Ret = TRUE; /* already a standard user */
        goto Quit;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
        goto Quit;
    Admins.Sid = AdminsSid;
    Admins.Attributes = 0;
    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 1, &Admins, 0, NULL, 0, NULL, &hRestricted))
        goto Quit;
    if (!DuplicateTokenEx(hRestricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenImpersonation, &hImpersonation))
        goto Quit;
    if (!SetThreadToken(NULL, hImpersonation))
        goto Quit;
    *Impersonating = TRUE;
    Ret = TRUE;

Quit:
    if (hImpersonation) CloseHandle(hImpersonation);
    if (hRestricted) CloseHandle(hRestricted);
    if (hToken) CloseHandle(hToken);
    FreeSid(AdminsSid);
    return Ret;
}

/* Windows lets a standard user ping: IcmpCreateFile opens \Device\Ip with GENERIC_EXECUTE and the
 * device grants Everyone read, write and execute. */
static
void
test_IcmpStandardUser(void)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID AdminsSid = NULL;
    BOOL Impersonating, IsAdmin = TRUE;
    HANDLE hIcmp;
    char SendData[32] = "standard user";
    UCHAR ReplyBuffer[sizeof(ICMP_ECHO_REPLY) + sizeof(SendData) + 8];
    PICMP_ECHO_REPLY Reply = (PICMP_ECHO_REPLY)ReplyBuffer;
    DWORD Replies;

    if (!EnterStandardUser(&Impersonating))
    {
        skip("Could not create a standard user token: %lu\n", GetLastError());
        return;
    }

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminsSid))
    {
        IsAdmin = AdminsEnabled(AdminsSid);
        FreeSid(AdminsSid);
    }
    ok(!IsAdmin, "The test thread must not act as an administrator\n");

    if (!IsAdmin)
    {
        SetLastError(0xDEADBEEF);
        hIcmp = IcmpCreateFile();
        ok(hIcmp != INVALID_HANDLE_VALUE, "IcmpCreateFile failed for a standard user: %lu\n", GetLastError());
        if (hIcmp != INVALID_HANDLE_VALUE)
        {
            SetLastError(0xDEADBEEF);
            Replies = IcmpSendEcho(hIcmp, htonl(INADDR_LOOPBACK), SendData, sizeof(SendData),
                                   NULL, ReplyBuffer, sizeof(ReplyBuffer), 3000);
            ok(Replies == 1, "IcmpSendEcho returned %lu replies for a standard user (error %lu)\n",
               Replies, GetLastError());
            if (Replies == 1)
                ok(Reply->Status == IP_SUCCESS, "Reply status %lu\n", Reply->Status);
            IcmpCloseHandle(hIcmp);
        }
    }

    if (Impersonating)
        SetThreadToken(NULL, NULL);
}

#define CONCURRENT_DATA_SIZE 16
#define CONCURRENT_REPLIES 4

typedef struct _CONCURRENT_ECHO
{
    char Data[CONCURRENT_DATA_SIZE];
    UCHAR ReplyBuffer[CONCURRENT_REPLIES * (sizeof(ICMP_ECHO_REPLY) + CONCURRENT_DATA_SIZE + 8)];
    DWORD ReplySize;
    DWORD Replies;
    DWORD Error;
    DWORD Start;
    DWORD End;
} CONCURRENT_ECHO, *PCONCURRENT_ECHO;

static
void
SendConcurrentEcho(PCONCURRENT_ECHO Echo)
{
    HANDLE hIcmp;

    Echo->Replies = 0;
    Echo->Error = 0;
    hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
    {
        Echo->Error = GetLastError();
        return;
    }
    SetLastError(0xDEADBEEF);
    Echo->Start = GetTickCount();
    Echo->Replies = IcmpSendEcho(hIcmp, htonl(INADDR_LOOPBACK), Echo->Data, sizeof(Echo->Data),
                                 NULL, Echo->ReplyBuffer, Echo->ReplySize, 3000);
    Echo->End = GetTickCount();
    if (!Echo->Replies)
        Echo->Error = GetLastError();
    IcmpCloseHandle(hIcmp);
}

static
DWORD
WINAPI
ConcurrentEchoThread(LPVOID Parameter)
{
    SendConcurrentEcho(Parameter);
    return 0;
}

static
void
CheckConcurrentReplies(PCONCURRENT_ECHO Echo, const char *Name)
{
    PICMP_ECHO_REPLY Reply = (PICMP_ECHO_REPLY)Echo->ReplyBuffer;
    DWORD i;

    ok(Echo->Replies == 1, "%s: %lu replies, error %lu\n", Name, Echo->Replies, Echo->Error);
    for (i = 0; i < Echo->Replies && i < CONCURRENT_REPLIES; i++)
    {
        ok(Reply[i].Status == IP_SUCCESS, "%s: reply %lu status %lu\n", Name, i, Reply[i].Status);
        ok(Reply[i].Address == htonl(INADDR_LOOPBACK), "%s: reply %lu from 0x%lx\n", Name, i, Reply[i].Address);
        ok(Reply[i].DataSize == CONCURRENT_DATA_SIZE, "%s: reply %lu has %u data bytes\n", Name, i, Reply[i].DataSize);
        if (Reply[i].Data && Reply[i].DataSize == CONCURRENT_DATA_SIZE)
            ok(!memcmp(Reply[i].Data, Echo->Data, CONCURRENT_DATA_SIZE), "%s: reply %lu holds another request's data\n", Name, i);
    }
}

/* Two echo requests outstanding at the same time: each must get only the reply to itself.
 * The first one has room for several replies, so it would also collect the second one's.
 * A round in which the first request returned before the second one was sent proves nothing
 * (a system may return on the first reply) and is reported as skipped. */
static
void
test_IcmpSendEchoConcurrent(void)
{
    static CONCURRENT_ECHO First, Second;
    HANDLE hThread;
    DWORD Round, Wait, Overlapped = 0;

    for (Round = 0; Round < 3; Round++)
    {
        memset(&First, 0, sizeof(First));
        memset(&Second, 0, sizeof(Second));
        memset(First.Data, 'A', sizeof(First.Data));
        memset(Second.Data, 'B', sizeof(Second.Data));
        First.ReplySize = sizeof(First.ReplyBuffer);
        Second.ReplySize = sizeof(ICMP_ECHO_REPLY) + CONCURRENT_DATA_SIZE + 8;

        hThread = CreateThread(NULL, 0, ConcurrentEchoThread, &First, 0, NULL);
        ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!hThread)
            return;
        Sleep(500);
        SendConcurrentEcho(&Second);
        Wait = WaitForSingleObject(hThread, 10000);
        ok(Wait == WAIT_OBJECT_0, "Wait returned %lu\n", Wait);
        CloseHandle(hThread);
        if (Wait != WAIT_OBJECT_0)
            return;

        CheckConcurrentReplies(&First, "First");
        CheckConcurrentReplies(&Second, "Second");
        if ((LONG)(First.Start - Second.Start) <= 0 && (LONG)(Second.Start - First.End) < 0)
            Overlapped++;
    }
    if (!Overlapped)
        skip("The echo requests never overlapped\n");
}

/* IcmpSendEcho2, IcmpSendEcho2Ex and IcmpParseReplies.
 * The functions are looked up at run time so that one binary runs on every system, whatever its headers declare. */
typedef DWORD (WINAPI *PFN_SENDECHO2)(HANDLE, HANDLE, PVOID, PVOID, IPAddr, LPVOID, WORD,
                                      PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_SENDECHO2EX)(HANDLE, HANDLE, PVOID, PVOID, IPAddr, IPAddr, LPVOID, WORD,
                                        PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_PARSEREPLIES)(LPVOID, DWORD);

static PFN_SENDECHO2 pIcmpSendEcho2;
static PFN_SENDECHO2EX pIcmpSendEcho2Ex;
static PFN_PARSEREPLIES pIcmpParseReplies;

#define ECHO2_DATA_SIZE 32
/* What the documentation asks for: a reply, the data, 8 bytes for an ICMP error and an IO_STATUS_BLOCK. */
#define ECHO2_REPLY_SIZE (sizeof(ICMP_ECHO_REPLY) + ECHO2_DATA_SIZE + 8 + 2 * sizeof(PVOID))

static
void
FillEchoData(UCHAR *Data, DWORD Size)
{
    DWORD i;

    for (i = 0; i < Size; i++)
        Data[i] = (UCHAR)('a' + i % 23);
}

/* One reply to a request for ECHO2_DATA_SIZE bytes (or none) sent to the loopback address */
static
void
CheckLoopbackReply(const char *Name, UCHAR *Buffer, DWORD BufferSize, const UCHAR *Data, WORD DataSize)
{
    PICMP_ECHO_REPLY Reply = (PICMP_ECHO_REPLY)Buffer;

    ok(Reply->Status == IP_SUCCESS, "%s: status %lu\n", Name, (DWORD)Reply->Status);
    ok(Reply->Address == htonl(INADDR_LOOPBACK), "%s: from 0x%lx\n", Name, (DWORD)Reply->Address);
    ok(Reply->DataSize == DataSize, "%s: %u data bytes, expected %u\n", Name, Reply->DataSize, DataSize);
    ok(Reply->Reserved == 0, "%s: Reserved is %u\n", Name, Reply->Reserved);
    ok(Reply->RoundTripTime < 5000, "%s: round trip time %lu\n", Name, (DWORD)Reply->RoundTripTime);
    /* A reply always has a Data pointer inside the buffer, also with no data:
     * .NET's Ping copies from it and rejects NULL. */
    ok(Reply->Data != NULL, "%s: Data is NULL\n", Name);
    if (Reply->Data)
    {
        ok((PUCHAR)Reply->Data >= Buffer + sizeof(ICMP_ECHO_REPLY) &&
           (PUCHAR)Reply->Data + Reply->DataSize <= Buffer + BufferSize,
           "%s: Data %p (%u bytes) is outside the %lu byte buffer at %p\n",
           Name, Reply->Data, Reply->DataSize, BufferSize, Buffer);
        if (Reply->DataSize == DataSize && DataSize != 0 &&
            (PUCHAR)Reply->Data >= Buffer && (PUCHAR)Reply->Data + DataSize <= Buffer + BufferSize)
            ok(!memcmp(Reply->Data, Data, DataSize), "%s: the data came back different\n", Name);
    }
    ok(Reply->Options.OptionsSize == 0, "%s: OptionsSize %u\n", Name, Reply->Options.OptionsSize);
    ok(Reply->Options.Ttl != 0, "%s: Ttl is 0\n", Name);
}

static volatile LONG ApcCalls;
static PVOID ApcContextSeen;
static ULONG_PTR ApcStatusSeen;

static
VOID
WINAPI
EchoApc(PVOID Context, PVOID IoStatusBlock, ULONG Reserved)
{
    ApcContextSeen = Context;
    ApcStatusSeen = IoStatusBlock ? *(ULONG_PTR *)IoStatusBlock : (ULONG_PTR)-1;
    InterlockedIncrement(&ApcCalls);
}

static
void
test_IcmpSendEcho2(void)
{
    HANDLE hIcmp, hEvent, hEvent2;
    UCHAR Data[ECHO2_DATA_SIZE];
    static UCHAR Buffer[ECHO2_REPLY_SIZE + 64], Buffer2[ECHO2_REPLY_SIZE + 64];
    static UCHAR BigData[1000], BigBuffer[sizeof(ICMP_ECHO_REPLY) + sizeof(BigData) + 8 + 2 * sizeof(PVOID)];
    IP_OPTION_INFORMATION Options;
    DWORD Ret, Wait, Error, Start, Elapsed;
    IPAddr Loopback = htonl(INADDR_LOOPBACK);
    LONG i;

    if (!pIcmpSendEcho2 || !pIcmpParseReplies)
    {
        skip("IcmpSendEcho2 or IcmpParseReplies is not available\n");
        return;
    }

    hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
    {
        skip("IcmpCreateFile failed unexpectedly: %lu\n", GetLastError());
        return;
    }
    FillEchoData(Data, sizeof(Data));

    /* Synchronous, without options */
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), NULL, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 1, "IcmpSendEcho2 returned %lu, error %lu\n", Ret, GetLastError());
    if (Ret == 1)
        CheckLoopbackReply("sync", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));

    /* One host answers once: with room for many replies the call still returns at the first one,
     * not after the whole timeout (what made Ping.Send and Test-Connection take their full timeout) */
    memset(Buffer, 0xCC, sizeof(Buffer));
    Start = GetTickCount();
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), NULL, Buffer, sizeof(Buffer), 5000);
    Elapsed = GetTickCount() - Start;
    ok(Ret == 1, "IcmpSendEcho2 with a large buffer returned %lu, error %lu\n", Ret, GetLastError());
    ok(Elapsed < 2500, "IcmpSendEcho2 took %lu ms for a reply from the loopback address\n", Elapsed);
    if (Ret == 1)
        CheckLoopbackReply("large", Buffer, sizeof(Buffer), Data, sizeof(Data));

    /* Synchronous, with options: the TTL goes out, DF is allowed */
    memset(&Options, 0, sizeof(Options));
    Options.Ttl = 64;
    Options.Flags = IP_FLAG_DF;
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 1, "IcmpSendEcho2 with options returned %lu, error %lu\n", Ret, GetLastError());
    if (Ret == 1)
        CheckLoopbackReply("options", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));

    /* No data at all: this is what makes .NET's Test-Connection fail on a NULL Data pointer */
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, NULL, 0, &Options, Buffer, sizeof(ICMP_ECHO_REPLY) + 8 + 2 * sizeof(PVOID), 3000);
    ok(Ret == 1, "IcmpSendEcho2 without data returned %lu, error %lu\n", Ret, GetLastError());
    if (Ret == 1)
        CheckLoopbackReply("nodata", Buffer, sizeof(ICMP_ECHO_REPLY) + 8 + 2 * sizeof(PVOID), NULL, 0);

    /* More data than fits in a packet buffer of a few bytes */
    FillEchoData(BigData, sizeof(BigData));
    memset(BigBuffer, 0xCC, sizeof(BigBuffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, BigData, sizeof(BigData), NULL, BigBuffer, sizeof(BigBuffer), 3000);
    ok(Ret == 1, "IcmpSendEcho2 with %u bytes returned %lu, error %lu\n", (unsigned)sizeof(BigData), Ret, GetLastError());
    if (Ret == 1)
        CheckLoopbackReply("big", BigBuffer, sizeof(BigBuffer), BigData, sizeof(BigData));

    /* Buffer sizes: smaller than a reply is a bad parameter, too small for the data a general failure */
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), NULL, Buffer, sizeof(ICMP_ECHO_REPLY) - 1, 3000);
    ok(Ret == 0, "IcmpSendEcho2 with a tiny buffer returned %lu\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "tiny buffer: error %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), NULL, Buffer, sizeof(ICMP_ECHO_REPLY) + 8, 3000);
    ok(Ret == 0, "IcmpSendEcho2 with a small buffer returned %lu\n", Ret);
    ok(GetLastError() == IP_GENERAL_FAILURE, "small buffer: error %lu\n", GetLastError());

    /* Bad arguments */
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), NULL, NULL, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 0, "IcmpSendEcho2 without a buffer returned %lu\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "no buffer: error %lu\n", GetLastError());
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, NULL, NULL, Loopback, Data, sizeof(Data), NULL, Buffer, ECHO2_REPLY_SIZE, 0);
    ok(Ret == 0, "IcmpSendEcho2 with timeout 0 returned %lu\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "timeout 0: error %lu\n", GetLastError());

    /* IcmpParseReplies */
    SetLastError(0xDEADBEEF);
    Ret = pIcmpParseReplies(NULL, 0);
    ok(Ret == 0, "IcmpParseReplies(NULL) returned %lu\n", Ret);
    ok(GetLastError() == ERROR_GEN_FAILURE, "IcmpParseReplies(NULL): error %lu\n", GetLastError());

    /* Event: the call returns 0 with ERROR_IO_PENDING, the event is signalled, IcmpParseReplies counts the reply once */
    hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(hEvent != NULL, "CreateEvent failed: %lu\n", GetLastError());
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, hEvent, NULL, NULL, Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    Error = GetLastError();
    ok(Ret == 0, "IcmpSendEcho2 with an event returned %lu\n", Ret);
    ok(Error == ERROR_IO_PENDING, "event: error %lu\n", Error);
    Wait = WaitForSingleObject(hEvent, 5000);
    ok(Wait == WAIT_OBJECT_0, "the event was not signalled: %lu\n", Wait);
    if (Wait == WAIT_OBJECT_0)
    {
        Ret = pIcmpParseReplies(Buffer, ECHO2_REPLY_SIZE);
        ok(Ret == 1, "IcmpParseReplies returned %lu\n", Ret);
        if (Ret == 1)
            CheckLoopbackReply("event", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));
        SetLastError(0xDEADBEEF);
        Ret = pIcmpParseReplies(Buffer, ECHO2_REPLY_SIZE);
        ok(Ret == 0, "the second IcmpParseReplies returned %lu\n", Ret);
    }

    /* Two requests outstanding on one handle, each with its own event and buffer */
    hEvent2 = CreateEventW(NULL, FALSE, FALSE, NULL);
    memset(Buffer, 0xCC, sizeof(Buffer));
    memset(Buffer2, 0xCC, sizeof(Buffer2));
    Ret = pIcmpSendEcho2(hIcmp, hEvent, NULL, NULL, Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 0 && GetLastError() == ERROR_IO_PENDING, "first request: %lu, error %lu\n", Ret, GetLastError());
    Ret = pIcmpSendEcho2(hIcmp, hEvent2, NULL, NULL, Loopback, Data, sizeof(Data), &Options, Buffer2, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 0 && GetLastError() == ERROR_IO_PENDING, "second request: %lu, error %lu\n", Ret, GetLastError());
    Wait = WaitForSingleObject(hEvent, 5000);
    ok(Wait == WAIT_OBJECT_0, "the first event was not signalled: %lu\n", Wait);
    if (Wait == WAIT_OBJECT_0)
    {
        Ret = pIcmpParseReplies(Buffer, ECHO2_REPLY_SIZE);
        ok(Ret == 1, "first IcmpParseReplies returned %lu\n", Ret);
        if (Ret == 1)
            CheckLoopbackReply("first", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));
    }
    Wait = WaitForSingleObject(hEvent2, 5000);
    ok(Wait == WAIT_OBJECT_0, "the second event was not signalled: %lu\n", Wait);
    if (Wait == WAIT_OBJECT_0)
    {
        Ret = pIcmpParseReplies(Buffer2, ECHO2_REPLY_SIZE);
        ok(Ret == 1, "second IcmpParseReplies returned %lu\n", Ret);
        if (Ret == 1)
            CheckLoopbackReply("second", Buffer2, ECHO2_REPLY_SIZE, Data, sizeof(Data));
    }
    CloseHandle(hEvent2);
    CloseHandle(hEvent);

    /* APC: runs in an alertable wait of the calling thread with the context and the status block */
    ApcCalls = 0;
    ApcContextSeen = NULL;
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2(hIcmp, NULL, (PVOID)EchoApc, (PVOID)(ULONG_PTR)0x1234, Loopback, Data, sizeof(Data), NULL,
                         Buffer, ECHO2_REPLY_SIZE, 3000);
    Error = GetLastError();
    ok(Ret == 0, "IcmpSendEcho2 with an APC returned %lu\n", Ret);
    ok(Error == ERROR_IO_PENDING, "APC: error %lu\n", Error);
    for (i = 0; i < 50 && !ApcCalls; i++)
        SleepEx(100, TRUE);
    ok(ApcCalls == 1, "the APC ran %ld times\n", ApcCalls);
    ok(ApcContextSeen == (PVOID)(ULONG_PTR)0x1234, "the APC got context %p\n", ApcContextSeen);
    ok((NTSTATUS)ApcStatusSeen == 0, "the APC saw status 0x%lx\n", (ULONG)ApcStatusSeen);
    if (ApcCalls == 1)
    {
        Ret = pIcmpParseReplies(Buffer, ECHO2_REPLY_SIZE);
        ok(Ret == 1, "IcmpParseReplies after the APC returned %lu\n", Ret);
        if (Ret == 1)
            CheckLoopbackReply("apc", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));
    }

    IcmpCloseHandle(hIcmp);
}

static
void
test_IcmpSendEcho2Ex(void)
{
    HANDLE hIcmp, hEvent;
    UCHAR Data[ECHO2_DATA_SIZE];
    static UCHAR Buffer[ECHO2_REPLY_SIZE + 64];
    IP_OPTION_INFORMATION Options;
    DWORD Ret, Wait;
    IPAddr Loopback = htonl(INADDR_LOOPBACK);

    if (!pIcmpSendEcho2Ex || !pIcmpParseReplies)
    {
        skip("IcmpSendEcho2Ex is not available\n");
        return;
    }

    hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE)
    {
        skip("IcmpCreateFile failed unexpectedly: %lu\n", GetLastError());
        return;
    }
    FillEchoData(Data, sizeof(Data));
    memset(&Options, 0, sizeof(Options));
    Options.Ttl = 64;

    /* No source address, then the loopback address as the source */
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2Ex(hIcmp, NULL, NULL, NULL, 0, Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 1, "IcmpSendEcho2Ex without a source returned %lu, error %lu\n", Ret, GetLastError());
    if (Ret == 1)
        CheckLoopbackReply("ex-nosource", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));

    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2Ex(hIcmp, NULL, NULL, NULL, Loopback, Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 1, "IcmpSendEcho2Ex from the loopback address returned %lu, error %lu\n", Ret, GetLastError());
    if (Ret == 1)
        CheckLoopbackReply("ex-loopback", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));

    /* With an event */
    hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2Ex(hIcmp, hEvent, NULL, NULL, Loopback, Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 0 && GetLastError() == ERROR_IO_PENDING, "IcmpSendEcho2Ex with an event: %lu, error %lu\n", Ret, GetLastError());
    Wait = WaitForSingleObject(hEvent, 5000);
    ok(Wait == WAIT_OBJECT_0, "the event was not signalled: %lu\n", Wait);
    if (Wait == WAIT_OBJECT_0)
    {
        Ret = pIcmpParseReplies(Buffer, ECHO2_REPLY_SIZE);
        ok(Ret == 1, "IcmpParseReplies returned %lu\n", Ret);
        if (Ret == 1)
            CheckLoopbackReply("ex-event", Buffer, ECHO2_REPLY_SIZE, Data, sizeof(Data));
    }
    CloseHandle(hEvent);

    /* A source address that no interface has: 192.0.2.1 is reserved for documentation */
    memset(Buffer, 0xCC, sizeof(Buffer));
    SetLastError(0xDEADBEEF);
    Ret = pIcmpSendEcho2Ex(hIcmp, NULL, NULL, NULL, inet_addr("192.0.2.1"), Loopback, Data, sizeof(Data), &Options, Buffer, ECHO2_REPLY_SIZE, 3000);
    ok(Ret == 0, "IcmpSendEcho2Ex from a foreign address returned %lu\n", Ret);
    ok(GetLastError() == ERROR_INVALID_NETNAME, "foreign source: error %lu\n", GetLastError());

    IcmpCloseHandle(hIcmp);
}

START_TEST(icmp)
{
    HMODULE hIphlpapi = GetModuleHandleW(L"iphlpapi.dll");

    if (!hIphlpapi)
        hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    pIcmpSendEcho2 = (PFN_SENDECHO2)GetProcAddress(hIphlpapi, "IcmpSendEcho2");
    pIcmpSendEcho2Ex = (PFN_SENDECHO2EX)GetProcAddress(hIphlpapi, "IcmpSendEcho2Ex");
    pIcmpParseReplies = (PFN_PARSEREPLIES)GetProcAddress(hIphlpapi, "IcmpParseReplies");

    test_IcmpCreateFile();
    test_Icmp6CreateFile();
    test_IcmpCloseHandle();
    test_IcmpSendEcho();
    test_IcmpStandardUser();
    test_IcmpSendEchoConcurrent();
    test_IcmpSendEcho2();
    test_IcmpSendEcho2Ex();
}
