/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Review tests of the filter manager: negative cases of the communication port
 *              (sizes, replies that come too late, a client which goes away, a filter which goes
 *              away), who may connect, pre/post pairing of fast I/O, a parked post-operation of
 *              a read the file system pended
 */

#include "precomp.h"
#include <fltuser.h>
#include <lm.h>
#include <stdarg.h>

#define PORT_R      L"\\FltSampleRPort"
#define PORT_A      L"\\FltSampleAPort"

#ifndef STATUS_PORT_DISCONNECTED
#define STATUS_PORT_DISCONNECTED ((NTSTATUS)0xC0000037L)
#endif

typedef struct _BIG_MESSAGE
{
    FILTER_MESSAGE_HEADER Header;
    UCHAR Data[512];

} BIG_MESSAGE;

typedef struct _SEND_THREAD
{
    HANDLE Port;
    ULONG Code;
    ULONG Arg;
    ULONG WaitMs;               /* the driver's FltSendMessage timeout, 0: for ever */
    HRESULT Result;
    DWORD Bytes;
    FLTSAMPLE_ASK_RESULT Ask;

} SEND_THREAD;

/* FilterSendMessage of a NOTIFY / ASK request: the driver sends to the client from inside the call */
static
DWORD
WINAPI
SendThread(PVOID Parameter)
{
    SEND_THREAD *T = Parameter;
    UCHAR Buffer[64];
    PFLTSAMPLE_MSG Message = (PFLTSAMPLE_MSG)Buffer;

    Message->Code = T->Code;
    Message->Arg = T->Arg;
    *(PULONG)Message->Data = T->WaitMs;
    ZeroMemory(&T->Ask, sizeof(T->Ask));
    T->Result = FilterSendMessage(T->Port, Message, FIELD_OFFSET(FLTSAMPLE_MSG, Data) + sizeof(ULONG),
                                  &T->Ask, sizeof(T->Ask), &T->Bytes);
    return 0;
}

static
HANDLE
StartSend(SEND_THREAD *T, HANDLE Port, ULONG Code, ULONG Arg, ULONG WaitMs)
{
    ZeroMemory(T, sizeof(*T));
    T->Port = Port;
    T->Code = Code;
    T->Arg = Arg;
    T->WaitMs = WaitMs;
    T->Result = E_PENDING;
    return CreateThread(NULL, 0, SendThread, T, 0, NULL);
}

static
HANDLE
ConnectPort(PCWSTR Name, HRESULT *Result)
{
    HANDLE Port = INVALID_HANDLE_VALUE;

    *Result = FilterConnectCommunicationPort(Name, 0, NULL, 0, NULL, &Port);
    return SUCCEEDED(*Result) ? Port : INVALID_HANDLE_VALUE;
}

/* Gets one message, waiting up to Ms */
static
HRESULT
GetWithTimeout(HANDLE Port, PFILTER_MESSAGE_HEADER Header, DWORD Size, DWORD Ms)
{
    OVERLAPPED Overlapped = { 0 };
    DWORD Bytes;
    HRESULT hr;

    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hr = FilterGetMessage(Port, Header, Size, &Overlapped);
    if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING))
    {
        if (WaitForSingleObject(Overlapped.hEvent, Ms) != WAIT_OBJECT_0)
        {
            CancelIo(Port);
            WaitForSingleObject(Overlapped.hEvent, 3000);
            CloseHandle(Overlapped.hEvent);
            return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        }
        hr = GetOverlappedResult(Port, &Overlapped, &Bytes, FALSE) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }
    CloseHandle(Overlapped.hEvent);
    return hr;
}

/* Port: buffers too small and too big in both directions, late and unknown replies */
static
void
test_Sizes(void)
{
    SAMPLE R = { { 0 } };
    HANDLE Port, Thread;
    HRESULT hr;
    SEND_THREAD T;
    BIG_MESSAGE Message;
    UCHAR Small[sizeof(FILTER_MESSAGE_HEADER) + 8];
    PUCHAR Big;
    PFILTER_REPLY_HEADER Reply;
    DWORD Bytes;
    UCHAR Echo[16];
    ULONG Size;

    if (!LoadSample(&R, L"FltSampleR", L"381000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    Port = ConnectPort(PORT_R, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    if (Port == INVALID_HANDLE_VALUE)
        goto Quit;

    /* client -> filter: nothing at all, which the filter refuses */
    hr = FilterSendMessage(Port, NULL, 0, NULL, 0, &Bytes);
    ok(FAILED(hr), "An empty message: 0x%lx\n", (ULONG)hr);

    /* client -> filter: 4 MB in, 16 bytes out */
    Size = 4 * 1024 * 1024;
    Big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size + sizeof(FILTER_REPLY_HEADER));
    ok(Big != NULL, "No memory\n");
    if (Big)
    {
        ((PFLTSAMPLE_MSG)Big)->Code = FLTSAMPLE_MSG_PING;
        FillMemory(((PFLTSAMPLE_MSG)Big)->Data, 64, 'p');
        Bytes = 0xFFFF;
        hr = FilterSendMessage(Port, Big, Size, Echo, sizeof(Echo), &Bytes);
        ok(hr == S_OK && Bytes == sizeof(Echo), "4 MB message: 0x%lx, %lu bytes\n", (ULONG)hr, Bytes);

        /* client -> filter: 12 bytes in, 1 MB out: the answer is what the filter says it wrote */
        Bytes = 0xFFFF;
        hr = FilterSendMessage(Port, Big, FIELD_OFFSET(FLTSAMPLE_MSG, Data) + 4, Big, 1024 * 1024, &Bytes);
        ok(hr == S_OK && Bytes == 4, "1 MB out buffer: 0x%lx, %lu bytes\n", (ULONG)hr, Bytes);
    }

    /* filter -> client: a buffer smaller than the header */
    hr = FilterGetMessage(Port, (PFILTER_MESSAGE_HEADER)Small, sizeof(FILTER_MESSAGE_HEADER) - 1, NULL);
    ok(FAILED(hr), "Get with less than a header: 0x%lx\n", (ULONG)hr);

    /* filter -> client: a 60 byte message into a buffer for 8, then one which is big enough */
    Thread = StartSend(&T, Port, FLTSAMPLE_MSG_NOTIFY, 60, 5000);
    hr = GetWithTimeout(Port, (PFILTER_MESSAGE_HEADER)Small, sizeof(Small), 3000);
    ok(FAILED(hr) && hr != HRESULT_FROM_WIN32(WAIT_TIMEOUT), "Get into a too small buffer: 0x%lx\n", (ULONG)hr);
    trace("Get into a too small buffer: 0x%lx\n", (ULONG)hr);
    ZeroMemory(&Message, sizeof(Message));
    hr = GetWithTimeout(Port, &Message.Header, sizeof(Message), 3000);
    ok(hr == S_OK, "Get after a too small buffer: 0x%lx\n", (ULONG)hr);
    ok(WaitForSingleObject(Thread, 6000) == WAIT_OBJECT_0, "The sender didn't return\n");
    CloseHandle(Thread);
    ok(T.Result == S_OK && T.Ask.Status == STATUS_SUCCESS, "Notify: 0x%lx, status 0x%lx\n", (ULONG)T.Result, T.Ask.Status);

    /* filter -> client -> filter: a reply smaller than the header, an unknown id, a reply of 64 KB for 4 bytes */
    Thread = StartSend(&T, Port, FLTSAMPLE_MSG_ASK, 8, 5000);
    ZeroMemory(&Message, sizeof(Message));
    hr = GetWithTimeout(Port, &Message.Header, sizeof(Message), 3000);
    ok(hr == S_OK, "Get of an ask: 0x%lx\n", (ULONG)hr);
    if (Big)
    {
        Reply = (PFILTER_REPLY_HEADER)Big;
        ZeroMemory(Big, 128);
        Reply->MessageId = Message.Header.MessageId;
        hr = FilterReplyMessage(Port, Reply, sizeof(FILTER_REPLY_HEADER) - 1);
        ok(FAILED(hr), "A reply smaller than its header: 0x%lx\n", (ULONG)hr);
        Reply->MessageId = Message.Header.MessageId + 1000;
        hr = FilterReplyMessage(Port, Reply, sizeof(FILTER_REPLY_HEADER) + 4);
        ok(FAILED(hr), "A reply to an unknown message: 0x%lx\n", (ULONG)hr);
        Reply->MessageId = Message.Header.MessageId;
        Reply->Status = STATUS_SUCCESS;
        FillMemory(Reply + 1, 64 * 1024, 0x5A);
        hr = FilterReplyMessage(Port, Reply, sizeof(FILTER_REPLY_HEADER) + 64 * 1024);
        trace("A reply of 64 KB to a 4 byte reply buffer: 0x%lx\n", (ULONG)hr);
    }
    ok(WaitForSingleObject(Thread, 6000) == WAIT_OBJECT_0, "The sender didn't return\n");
    CloseHandle(Thread);
    ok(T.Ask.Status == STATUS_SUCCESS && T.Ask.ReplyLength == 4 && *(PULONG)T.Ask.Reply == 0x5A5A5A5A,
       "Big reply: status 0x%lx, length %lu, value 0x%lx\n", T.Ask.Status, T.Ask.ReplyLength, *(PULONG)T.Ask.Reply);

    /* A reply after the sender gave up */
    Thread = StartSend(&T, Port, FLTSAMPLE_MSG_ASK, 8, 200);
    ZeroMemory(&Message, sizeof(Message));
    hr = GetWithTimeout(Port, &Message.Header, sizeof(Message), 3000);
    ok(hr == S_OK, "Get of an ask: 0x%lx\n", (ULONG)hr);
    ok(WaitForSingleObject(Thread, 6000) == WAIT_OBJECT_0, "The sender didn't return\n");
    CloseHandle(Thread);
    ok(T.Ask.Status == STATUS_TIMEOUT, "Ask nobody answered: status 0x%lx\n", T.Ask.Status);
    if (Big)
    {
        Reply = (PFILTER_REPLY_HEADER)Big;
        ZeroMemory(Big, 64);
        Reply->MessageId = Message.Header.MessageId;
        hr = FilterReplyMessage(Port, Reply, sizeof(FILTER_REPLY_HEADER) + 4);
        ok(FAILED(hr), "A reply after the timeout: 0x%lx\n", (ULONG)hr);
    }

    /* The port still works */
    Bytes = 0;
    hr = FilterSendMessage(Port, &(FLTSAMPLE_MSG){ FLTSAMPLE_MSG_PING, 0, { 'z' } }, FIELD_OFFSET(FLTSAMPLE_MSG, Data) + 1,
                           Echo, sizeof(Echo), &Bytes);
    ok(hr == S_OK && Bytes == 1 && Echo[0] == 'z', "Ping after all that: 0x%lx %lu\n", (ULONG)hr, Bytes);

    if (Big)
        HeapFree(GetProcessHeap(), 0, Big);
    CloseHandle(Port);
Quit:
    UnloadSample(&R, TRUE);
}

typedef struct _UNLOAD_THREAD
{
    PSAMPLE Sample;
    BOOL Result;

} UNLOAD_THREAD;

static
DWORD
WINAPI
UnloadThread(PVOID Parameter)
{
    UNLOAD_THREAD *U = Parameter;

    U->Result = UnloadSample(U->Sample, FALSE);
    return 0;
}

/* The filter unloads while it waits for a reply from a client, and while that client holds the message */
static
void
test_UnloadWhileAsking(void)
{
    SAMPLE R = { { 0 } };
    HANDLE Port, Thread, Unloader;
    HRESULT hr;
    SEND_THREAD T;
    UNLOAD_THREAD U;
    BIG_MESSAGE Message;
    FILTER_REPLY_HEADER Reply[2];
    DWORD Wait, Start;

    if (!LoadSample(&R, L"FltSampleR", L"381000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    Port = ConnectPort(PORT_R, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    if (Port == INVALID_HANDLE_VALUE)
    {
        UnloadSample(&R, TRUE);
        return;
    }

    /* The driver asks and waits for ever */
    Thread = StartSend(&T, Port, FLTSAMPLE_MSG_ASK, 8, 0);
    ZeroMemory(&Message, sizeof(Message));
    hr = GetWithTimeout(Port, &Message.Header, sizeof(Message), 3000);
    ok(hr == S_OK, "Get of an ask: 0x%lx\n", (ULONG)hr);

    /* The filter goes */
    U.Sample = &R;
    U.Result = FALSE;
    Start = GetTickCount();
    Unloader = CreateThread(NULL, 0, UnloadThread, &U, 0, NULL);
    Wait = WaitForSingleObject(Unloader, 20000);
    ok(Wait == WAIT_OBJECT_0, "The unload of a filter with a client holding a message didn't end in 20 s\n");
    trace("Unload with a pending ask took %lu ms, result %d\n", GetTickCount() - Start, U.Result);
    ok(U.Result, "The unload failed\n");
    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "The asking thread didn't return\n");
    ok(T.Ask.Status == STATUS_PORT_DISCONNECTED || FAILED(T.Result),
       "The ask of a filter which went: 0x%lx, status 0x%lx\n", (ULONG)T.Result, T.Ask.Status);

    /* The reply comes after it all */
    ZeroMemory(Reply, sizeof(Reply));
    Reply[0].MessageId = Message.Header.MessageId;
    hr = FilterReplyMessage(Port, Reply, sizeof(Reply));
    ok(FAILED(hr), "A reply to a filter which is gone: 0x%lx\n", (ULONG)hr);

    if (Wait == WAIT_OBJECT_0)
        CloseHandle(Unloader);
    CloseHandle(Thread);
    CloseHandle(Port);
}

/*
 * The child: connects, lets creates of .msg files be asked about, takes one message, says so, and
 * waits to be killed without answering.
 */
static
void
RunChild(void)
{
    HANDLE Port, Ready, Got;
    HRESULT hr;
    BIG_MESSAGE Message;
    FLTSAMPLE_MSG Arm = { FLTSAMPLE_MSG_ARM, 1, { 0 } };
    DWORD Bytes;

    Ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"RvFltChildReady");
    Got = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"RvFltChildGot");
    Port = ConnectPort(PORT_R, &hr);
    if (Port == INVALID_HANDLE_VALUE || !Ready || !Got)
        ExitProcess(2);
    (void)FilterSendMessage(Port, &Arm, FIELD_OFFSET(FLTSAMPLE_MSG, Data), NULL, 0, &Bytes);
    SetEvent(Ready);
    hr = FilterGetMessage(Port, &Message.Header, sizeof(Message), NULL);
    SetEvent(Got);
    Sleep(INFINITE);
}

typedef struct _CREATE_THREAD
{
    WCHAR Path[MAX_PATH];
    DWORD Error;
    DWORD Done;

} CREATE_THREAD;

static
DWORD
WINAPI
CreateThreadProc(PVOID Parameter)
{
    CREATE_THREAD *C = Parameter;
    HANDLE File;

    File = CreateFileW(C->Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    C->Error = File == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    C->Done = GetTickCount();
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    return 0;
}

/* A client process ends while the filter waits for its answer about a create */
static
void
test_ClientExitMidSend(void)
{
    SAMPLE R = { { 0 } };
    HANDLE Ready, Got, Thread, Port;
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Child;
    WCHAR Command[MAX_PATH + 32], Self[MAX_PATH];
    CREATE_THREAD C;
    HRESULT hr;
    DWORD Killed;
    FLTSAMPLE_STATS S;
    FLTSAMPLE_MSG Arm = { FLTSAMPLE_MSG_ARM, 0, { 0 } };
    DWORD Bytes;

    if (!LoadSample(&R, L"FltSampleR", L"381000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    Ready = CreateEventW(NULL, TRUE, FALSE, L"RvFltChildReady");
    Got = CreateEventW(NULL, TRUE, FALSE, L"RvFltChildGot");
    GetModuleFileNameW(NULL, Self, RTL_NUMBER_OF(Self));
    StringCbPrintfW(Command, sizeof(Command), L"\"%ls\" rvchild", Self);
    if (!CreateProcessW(NULL, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Child))
    {
        skip("Can't start the child: %lu\n", GetLastError());
        goto Quit;
    }
    ok(WaitForSingleObject(Ready, 10000) == WAIT_OBJECT_0, "The child didn't connect\n");

    /* A create the client is asked about; the filter waits 5 s at most */
    ZeroMemory(&C, sizeof(C));
    MakeTestFile(L"rvexit.msg", C.Path, RTL_NUMBER_OF(C.Path));
    Thread = CreateThread(NULL, 0, CreateThreadProc, &C, 0, NULL);
    ok(WaitForSingleObject(Got, 10000) == WAIT_OBJECT_0, "The child didn't get the create\n");

    /* The client dies with the question unanswered: the create goes on right away */
    TerminateProcess(Child.hProcess, 1);
    Killed = GetTickCount();
    ok(WaitForSingleObject(Child.hProcess, 10000) == WAIT_OBJECT_0, "The child didn't end\n");
    ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "The create didn't end\n");
    trace("Create ended %ld ms after the client was killed, error %lu\n", (LONG)(C.Done - Killed), C.Error);
    ok((LONG)(C.Done - Killed) < 3000, "The create waited %ld ms after the client was gone\n", (LONG)(C.Done - Killed));
    ok(C.Error == 0, "The create failed: %lu\n", C.Error);
    CloseHandle(Thread);
    CloseHandle(Child.hProcess);
    CloseHandle(Child.hThread);
    DeleteFileW(C.Path);

    /* The connection is free again */
    Port = ConnectPort(PORT_R, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect after the client died: 0x%lx\n", (ULONG)hr);
    if (Port != INVALID_HANDLE_VALUE)
    {
        (void)FilterSendMessage(Port, &Arm, FIELD_OFFSET(FLTSAMPLE_MSG, Data), NULL, 0, &Bytes);
        CloseHandle(Port);
    }
    if (SampleStats(&R, &S))
        ok(S.PortConnects == S.PortDisconnects, "Connects %lu, disconnects %lu\n", S.PortConnects, S.PortDisconnects);

Quit:
    CloseHandle(Ready);
    CloseHandle(Got);
    UnloadSample(&R, TRUE);
}

/* Who may connect: nobody, when the filter gives its port a descriptor with an empty DACL */
static
void
test_PortDenyAll(void)
{
    SAMPLE S = { { 0 } };
    HKEY Key;
    DWORD One = 1;
    HANDLE Port;
    HRESULT hr;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\FltSampleS", 0, NULL, 0,
                        KEY_ALL_ACCESS, NULL, &Key, NULL) != ERROR_SUCCESS)
    {
        skip("Can't create the service key\n");
        return;
    }
    RegSetValueExW(Key, L"RvDenyAllPort", 0, REG_DWORD, (PBYTE)&One, sizeof(One));
    RegCloseKey(Key);

    if (!LoadSample(&S, L"FltSampleS", L"382000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    Port = ConnectPort(L"\\FltSampleSPort", &hr);
    trace("Connect to a port whose DACL is empty: 0x%lx\n", (ULONG)hr);
    ok(Port == INVALID_HANDLE_VALUE && hr == E_ACCESSDENIED,
       "Connected to a port whose descriptor lets nobody in: 0x%lx\n", (ULONG)hr);
    if (Port != INVALID_HANDLE_VALUE)
        CloseHandle(Port);

    UnloadSample(&S, TRUE);
}

/* Who may connect: a plain user, not an administrator */
static
void
test_PortSecurity(void)
{
    static WCHAR UserName[] = L"rvfltuser", Password[] = L"Rv-Flt-9pw!x";
    SAMPLE R = { { 0 } };
    USER_INFO_1 User = { 0 };
    NET_API_STATUS NetStatus = 1;
    NET_API_STATUS (WINAPI *pNetUserAdd)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
    NET_API_STATUS (WINAPI *pNetUserDel)(LPCWSTR, LPCWSTR);
    HANDLE Token = NULL, Port;
    HRESULT hr;

    if (!LoadSample(&R, L"FltSampleR", L"381000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    User.usri1_name = UserName;
    User.usri1_password = Password;
    User.usri1_priv = USER_PRIV_USER;
    User.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    /* netapi32 by name: the test executable doesn't import it */
    {
        HMODULE NetApi = LoadLibraryW(L"netapi32.dll");
        pNetUserAdd = NetApi ? (PVOID)GetProcAddress(NetApi, "NetUserAdd") : NULL;
        pNetUserDel = NetApi ? (PVOID)GetProcAddress(NetApi, "NetUserDel") : NULL;
    }
    if (!pNetUserAdd || !pNetUserDel)
    {
        skip("No netapi32\n");
        UnloadSample(&R, TRUE);
        return;
    }
    NetStatus = pNetUserAdd(NULL, 1, (LPBYTE)&User, NULL);
    trace("NetUserAdd: %lu\n", NetStatus);
    if (!LogonUserW(UserName, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip("LogonUser of a plain user failed: %lu\n", GetLastError());
        goto Quit;
    }
    if (!ImpersonateLoggedOnUser(Token))
    {
        skip("Can't impersonate: %lu\n", GetLastError());
        goto Quit;
    }

    /* Control: the thread's token now is the plain user's, without the administrators group */
    {
        SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
        PSID Admins = NULL;
        BOOL IsAdmin = TRUE;
        WCHAR Name[64];
        DWORD NameLength = RTL_NUMBER_OF(Name);

        if (AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins))
        {
            if (!CheckTokenMembership(NULL, Admins, &IsAdmin))
                IsAdmin = TRUE;
            FreeSid(Admins);
        }
        if (!GetUserNameW(Name, &NameLength))
            Name[0] = 0;
        trace("Impersonating %ls, member of the administrators: %d\n", Name, IsAdmin);
        if (IsAdmin)
        {
            skip("The impersonated plain user still counts as an administrator here, no conclusion\n");
            RevertToSelf();
            goto Quit;
        }
    }

    /*
     * The sample creates its port without a security descriptor; a port's default descriptor on
     * Windows lets SYSTEM and the administrators in (VERIFY ON ORACLE). Either way the descriptor of
     * the port has to be checked on connect.
     */
    Port = ConnectPort(PORT_R, &hr);
    trace("Plain user connect: 0x%lx\n", (ULONG)hr);
    ok(Port == INVALID_HANDLE_VALUE && hr == E_ACCESSDENIED,
       "A plain user connected to the port: 0x%lx\n", (ULONG)hr);
    if (Port != INVALID_HANDLE_VALUE)
        CloseHandle(Port);

    RevertToSelf();

Quit:
    if (Token) CloseHandle(Token);
    if (NetStatus == NERR_Success)
        pNetUserDel(NULL, UserName);
    UnloadSample(&R, TRUE);
}

static
BOOL
WriteTestData(PCWSTR Path, ULONG Size)
{
    HANDLE File;
    PUCHAR Data;
    DWORD Written = 0;
    ULONG i;

    Data = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Data)
        return FALSE;
    for (i = 0; i < Size; i++)
        Data[i] = (UCHAR)(i * 7);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        WriteFile(File, Data, Size, &Written, NULL);
        CloseHandle(File);
    }
    HeapFree(GetProcessHeap(), 0, Data);
    return Written == Size;
}

/* A filter below refuses fast I/O: the filter above, which asked for its post-operation, gets it */
static
void
test_FastIoPairing(void)
{
    SAMPLE A = { { 0 } }, B = { { 0 } };
    FLTSAMPLE_STATS Before, After, SB;
    WCHAR Path[MAX_PATH];
    HANDLE File;
    UCHAR Buffer[512];
    DWORD Read, i;
    ULONG Flags;

    MakeTestFile(L"rvpair.dat", Path, RTL_NUMBER_OF(Path));
    ok(WriteTestData(Path, 65536), "Can't write the test file\n");

    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    if (!LoadSample(&B, L"FltSampleB", L"370000.5", 0xFFFF))
    {
        skip("Can't load the second sample filter\n");
        UnloadSample(&A, TRUE);
        return;
    }
    Flags = FLTSAMPLE_RV_DISALLOW_FASTIO;
    ok(SampleIoctl(&B, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0), "Can't set the flags\n");

    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        /* The first read sets the cache up, the others are candidates for fast I/O */
        ReadFile(File, Buffer, sizeof(Buffer), &Read, NULL);
        Sleep(100);
        SampleStats(&A, &Before);
        for (i = 0; i < 50; i++)
        {
            SetFilePointer(File, (i * 997) % 60000, NULL, FILE_BEGIN);
            ReadFile(File, Buffer, sizeof(Buffer), &Read, NULL);
        }
        Sleep(200);
        SampleStats(&A, &After);
        SampleStats(&B, &SB);
        CloseHandle(File);

        trace("Upper filter: %lu pre-reads, %lu post-reads; lower refused fast I/O %lu times\n",
              After.Pre[IRP_MJ_READ] - Before.Pre[IRP_MJ_READ], After.Post[IRP_MJ_READ] - Before.Post[IRP_MJ_READ],
              SB.RvFastIoDisallowed);
        ok(SB.RvFastIoDisallowed > 0, "No fast I/O was tried, the test says nothing\n");
        ok(After.Pre[IRP_MJ_READ] - Before.Pre[IRP_MJ_READ] == After.Post[IRP_MJ_READ] - Before.Post[IRP_MJ_READ],
           "Pre-reads %lu, post-reads %lu of the filter above the one which refused fast I/O\n",
           After.Pre[IRP_MJ_READ] - Before.Pre[IRP_MJ_READ], After.Post[IRP_MJ_READ] - Before.Post[IRP_MJ_READ]);
    }

    UnloadSample(&B, TRUE);
    UnloadSample(&A, TRUE);
    DeleteFileW(Path);
}

/* A line that survives a wedged guest: appended to C:\\harness\\out\\rvnote.txt and written through */
static
void
Note(const char *Format, ...)
{
    char Line[512];
    va_list Args;
    HANDLE File;
    DWORD Written;

    va_start(Args, Format);
    _vsnprintf(Line, sizeof(Line) - 1, Format, Args);
    Line[sizeof(Line) - 1] = 0;
    va_end(Args);
    printf("%s", Line);
    fflush(stdout);
    File = CreateFileW(L"C:\\harness\\out\\rvnote.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                       FILE_FLAG_WRITE_THROUGH, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        WriteFile(File, Line, (DWORD)strlen(Line), &Written, NULL);
        FlushFileBuffers(File);
        CloseHandle(File);
    }
}

/* Overlapped transfers of 4 KB, each waited for 5 s at most; returns the number which never completed */
static
DWORD
OverlappedPass(HANDLE File, BOOL Write, PUCHAR Buffer, DWORD Stride, PDWORD Pending, PDWORD Done)
{
    OVERLAPPED Overlapped;
    DWORD Bytes, i;
    BOOL Ret;

    *Pending = *Done = 0;
    for (i = 0; i < 16; i++)
    {
        ZeroMemory(&Overlapped, sizeof(Overlapped));
        Overlapped.Offset = i * Stride;
        Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        Ret = Write ? WriteFile(File, Buffer, 4096, NULL, &Overlapped) : ReadFile(File, Buffer, 4096, NULL, &Overlapped);
        if (!Ret && GetLastError() == ERROR_IO_PENDING)
            (*Pending)++;
        if (WaitForSingleObject(Overlapped.hEvent, 5000) != WAIT_OBJECT_0)
            return 1;   /* the event lives on with the transfer */
        if (GetOverlappedResult(File, &Overlapped, &Bytes, FALSE) && Bytes == 4096)
            (*Done)++;
        CloseHandle(Overlapped.hEvent);
    }
    return 0;
}

/* A post-operation parks (MORE_PROCESSING_REQUIRED) an asynchronous read the file system has pended */
static
void
test_ParkPendedRead(void)
{
    SAMPLE A = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File;
    PUCHAR Buffer;
    DWORD Pending, Done, Hung;
    ULONG Flags;

    MakeTestFile(L"rvpark.dat", Path, RTL_NUMBER_OF(Path));
    ok(WriteTestData(Path, 65536 * 2), "Can't write the test file\n");
    Note("rvpark: test file written\n");
    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    Note("rvpark: filter loaded\n");
    Buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE || !Buffer)
        goto Quit;

    Note("rvpark: start, file system %lu\n", CurrentFileSystem());
    /* Control: the filter loaded, nothing parked */
    Hung = OverlappedPass(File, FALSE, Buffer, 4096, &Pending, &Done);
    Note("rvpark control: %lu pending, %lu done, hung %lu\n", Pending, Done, Hung);
    ok(!Hung && Done == 16, "Control pass: hung %lu, done %lu\n", Hung, Done);

    Flags = FLTSAMPLE_RV_PARK_READ_POST;
    ok(SampleIoctl(&A, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0), "Can't set the flags\n");
    Hung = OverlappedPass(File, FALSE, Buffer, 4096, &Pending, &Done);
    SampleStats(&A, &S);
    Note("rvpark parked: %lu pending, %lu done, hung %lu; %lu post-operations parked, %lu finished by the filter\n",
           Pending, Done, Hung, S.RvParked, S.RvParkDone);
    ok(S.RvParked > 0, "No post-operation was parked, the test says nothing\n");
    ok(Hung == 0, "A read whose post-operation was parked and finished never completed\n");
    if (!Hung)
        CloseHandle(File);
Quit:
    Flags = 0;
    SampleIoctl(&A, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0);
    UnloadSample(&A, TRUE);
    Note("rvpark: filter unloaded\n");
}

/* The same with writes which extend the file: FAT pends those when the caller can't wait */
static
void
test_ParkPendedWrite(void)
{
    SAMPLE A = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH], Path2[MAX_PATH];
    HANDLE File;
    PUCHAR Buffer;
    DWORD Pending, Done, Hung;
    ULONG Flags;

    MakeTestFile(L"rvparkw.dat", Path, RTL_NUMBER_OF(Path));
    MakeTestFile(L"rvparkw2.dat", Path2, RTL_NUMBER_OF(Path2));
    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    Buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    if (!Buffer)
        goto Quit;
    FillMemory(Buffer, 4096, 0x33);

    Note("rvparkw: start, file system %lu\n", CurrentFileSystem());
    /* Control: nothing parked */
    File = CreateFileW(Path2, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        goto Quit;
    Hung = OverlappedPass(File, TRUE, Buffer, 65536, &Pending, &Done);
    Note("rvparkw control: %lu pending, %lu done, hung %lu\n", Pending, Done, Hung);
    ok(!Hung && Done == 16, "Control pass: hung %lu, done %lu\n", Hung, Done);
    if (!Hung)
        CloseHandle(File);

    Flags = FLTSAMPLE_RV_PARK_WRITE_POST;
    ok(SampleIoctl(&A, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0), "Can't set the flags\n");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Create failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        goto Quit;
    Hung = OverlappedPass(File, TRUE, Buffer, 65536, &Pending, &Done);
    SampleStats(&A, &S);
    Note("rvparkw parked: %lu pending, %lu done, hung %lu; %lu post-operations parked, %lu finished by the filter\n",
           Pending, Done, Hung, S.RvParked, S.RvParkDone);
    ok(S.RvParked > 0, "No post-operation was parked, the test says nothing\n");
    ok(Hung == 0, "A write whose post-operation was parked and finished never completed\n");
    if (!Hung)
        CloseHandle(File);
Quit:
    Flags = 0;
    SampleIoctl(&A, FLTSAMPLE_IOCTL_RV_FLAGS, &Flags, sizeof(Flags), NULL, 0);
    UnloadSample(&A, TRUE);
    Note("rvparkw: filter unloaded\n");
}

/* The author's .safe mode (FltDoCompletionProcessingWhenSafe) with overlapped non-cached reads the file system pends */
static
void
test_SafePendedRead(void)
{
    SAMPLE A = { { 0 } };
    FLTSAMPLE_STATS S;
    WCHAR Path[MAX_PATH];
    HANDLE File;
    PUCHAR Buffer;
    DWORD Pending, Done, Hung;

    MakeTestFile(L"rvsafe.safe", Path, RTL_NUMBER_OF(Path));
    ok(WriteTestData(Path, 65536 * 2), "Can't write the test file\n");
    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }
    Note("rvsafe: filter loaded\n");
    Buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Open failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE && Buffer)
    {
        Hung = OverlappedPass(File, FALSE, Buffer, 4096, &Pending, &Done);
        SampleStats(&A, &S);
        Note("rvsafe: %lu pending, %lu done, hung %lu; safe posts %lu, deferred to a worker %lu\n",
             Pending, Done, Hung, S.SafePosts, S.SafePostsDeferred);
        ok(Hung == 0, "A read with FltDoCompletionProcessingWhenSafe never completed\n");
        if (!Hung)
            CloseHandle(File);
    }
    UnloadSample(&A, TRUE);
    Note("rvsafe: filter unloaded\n");
}

START_TEST(rvsafe)
{
    Note("rvsafe: suite start\n");
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_SafePendedRead();
}

START_TEST(rvneg)
{
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_Sizes();
    test_UnloadWhileAsking();
    test_ClientExitMidSend();
    test_PortDenyAll();
    test_PortSecurity();
    test_FastIoPairing();
}

/* Separate, because a read that never completes keeps the process from ending */
START_TEST(rvpark)
{
    Note("rvpark: suite start\n");
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_ParkPendedRead();
}

START_TEST(rvparkw)
{
    Note("rvparkw: suite start\n");
    EnsureTestDirectory();
    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    test_ParkPendedWrite();
}

START_TEST(rvchild)
{
    RunChild();
}
