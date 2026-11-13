/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the communication ports: FilterConnectCommunicationPort, FilterSendMessage,
 *              FilterGetMessage, FilterReplyMessage with FltCreateCommunicationPort and FltSendMessage
 */

#include "precomp.h"
#include <fltuser.h>

#define PORT_A L"\\FltSampleAPort"

typedef struct _CLIENT_MESSAGE
{
    FILTER_MESSAGE_HEADER Header;
    UCHAR Data[256];

} CLIENT_MESSAGE;

typedef struct _CLIENT_REPLY
{
    FILTER_REPLY_HEADER Header;
    ULONG Value;

} CLIENT_REPLY;

static
HRESULT
Send(HANDLE Port, ULONG Code, ULONG Arg, PVOID Data, ULONG DataSize, PVOID Out, ULONG OutSize, PULONG Returned)
{
    UCHAR Buffer[512];
    PFLTSAMPLE_MSG Message = (PFLTSAMPLE_MSG)Buffer;
    DWORD Bytes = 0;
    HRESULT hr;

    Message->Code = Code;
    Message->Arg = Arg;
    if (DataSize)
        CopyMemory(Message->Data, Data, DataSize);
    hr = FilterSendMessage(Port, Message, FIELD_OFFSET(FLTSAMPLE_MSG, Data) + DataSize, Out, OutSize, &Bytes);
    if (Returned)
        *Returned = Bytes;
    return hr;
}

static
HANDLE
Connect(PCWSTR Name, HRESULT *Result)
{
    HANDLE Port = INVALID_HANDLE_VALUE;

    *Result = FilterConnectCommunicationPort(Name, 0, NULL, 0, NULL, &Port);
    return SUCCEEDED(*Result) ? Port : INVALID_HANDLE_VALUE;
}

typedef struct _REPLY_THREAD
{
    HANDLE Port;
    volatile LONG Stop;
    volatile LONG Messages;
    volatile LONG Creates;
    volatile ULONG LastKind;
    volatile ULONG64 LastId;
    ULONG AskReply;                 /* what the reply to an ask is */
    BOOL Reply;                     /* answer the asks and the creates */

} REPLY_THREAD;

/* A client that takes the messages of the driver and answers them */
static
DWORD
WINAPI
ReplyThread(PVOID Parameter)
{
    REPLY_THREAD *Client = Parameter;
    CLIENT_MESSAGE Message;
    CLIENT_REPLY Reply;
    HRESULT hr;

    while (!Client->Stop)
    {
        ZeroMemory(&Message, sizeof(Message));
        hr = FilterGetMessage(Client->Port, &Message.Header, sizeof(Message), NULL);
        if (FAILED(hr))
            break;

        Client->LastKind = *(PULONG)Message.Data;
        Client->LastId = Message.Header.MessageId;
        InterlockedIncrement(&Client->Messages);

        if (Message.Header.ReplyLength == 0 || !Client->Reply)
            continue;

        ZeroMemory(&Reply, sizeof(Reply));
        Reply.Header.MessageId = Message.Header.MessageId;
        Reply.Header.Status = STATUS_SUCCESS;
        if (*(PULONG)Message.Data == FLTSAMPLE_KIND_CREATE)
        {
            PWSTR Name = (PWSTR)(Message.Data + sizeof(ULONG));

            InterlockedIncrement(&Client->Creates);
            Reply.Value = wcsstr(Name, L"deny") != NULL;
        }
        else
        {
            Reply.Value = Client->AskReply;
        }
        (void)FilterReplyMessage(Client->Port, &Reply.Header, sizeof(Reply));
    }
    return 0;
}

static
void
test_Connect(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    HANDLE Port, Second, Other;
    HRESULT hr;
    char Context[] = "refuse";
    char Echo[16] = { 0 };
    ULONG Returned;

    Port = Connect(PORT_A, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    if (Port == INVALID_HANDLE_VALUE)
        return;

    /* One connection at most */
    Second = Connect(PORT_A, &hr);
    ok(Second == INVALID_HANDLE_VALUE && FAILED(hr), "A second connection to a port for one: 0x%lx\n", (ULONG)hr);
    if (Second != INVALID_HANDLE_VALUE)
        CloseHandle(Second);

    CloseHandle(Port);

    /* A port which isn't there, and a server which says no */
    Other = Connect(L"\\NoSuchPort", &hr);
    ok(Other == INVALID_HANDLE_VALUE && FAILED(hr), "Connect to a port which doesn't exist: 0x%lx\n", (ULONG)hr);
    Other = INVALID_HANDLE_VALUE;
    hr = FilterConnectCommunicationPort(PORT_A, 0, Context, 6, NULL, &Other);
    ok(FAILED(hr), "The connection the server refused: 0x%lx\n", (ULONG)hr);

    /* Gone from one, there is room for the next */
    Port = Connect(PORT_A, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect after the disconnect failed: 0x%lx\n", (ULONG)hr);
    if (Port == INVALID_HANDLE_VALUE)
        return;

    /* A message and its answer */
    ZeroMemory(Echo, sizeof(Echo));
    hr = Send(Port, FLTSAMPLE_MSG_PING, 0, "hello", 5, Echo, sizeof(Echo), &Returned);
    ok(hr == S_OK, "FilterSendMessage returned 0x%lx\n", (ULONG)hr);
    ok(Returned == 5 && !memcmp(Echo, "hello", 5), "Answer of %lu bytes: %.5s\n", Returned, Echo);

    hr = Send(Port, 99, 0, NULL, 0, NULL, 0, NULL);
    ok(FAILED(hr), "A message the filter doesn't know: 0x%lx\n", (ULONG)hr);

    hr = Send(Port, FLTSAMPLE_MSG_GET_STATS, 0, NULL, 0, &S, sizeof(S), &Returned);
    ok(hr == S_OK && Returned == sizeof(S), "Statistics: 0x%lx, %lu bytes\n", (ULONG)hr, Returned);
    ok(S.PortConnects == 2 && S.PortDisconnects >= 1, "%lu connects, %lu disconnects\n", S.PortConnects, S.PortDisconnects);
    ok(S.PortMessages >= 3, "%lu messages\n", S.PortMessages);

    /* The same through the control device: the count is for the connection as well */
    CloseHandle(Port);
    Sleep(100);
    SampleStats(A, &S);
    ok(S.PortDisconnects == 2, "%lu disconnects after the close\n", S.PortDisconnects);

    /* A closed handle is no port */
    ok(FAILED(FilterSendMessage(Port, "x", 1, NULL, 0, (LPDWORD)&Returned)), "Send on a closed handle\n");
}

static
void
test_ToClient(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    REPLY_THREAD Client = { 0 };
    HANDLE Thread;
    HRESULT hr;
    ULONG Timeout = 100;
    UCHAR Data[8];
    FLTSAMPLE_ASK_RESULT Result;
    ULONG Returned, i;

    Client.Port = Connect(PORT_A, &hr);
    ok(Client.Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    if (Client.Port == INVALID_HANDLE_VALUE)
        return;

    /* Nobody takes the message: the sender gives up when its time is over, and the message is gone */
    CopyMemory(Data, &Timeout, sizeof(Timeout));
    ZeroMemory(&Result, sizeof(Result));
    hr = Send(Client.Port, FLTSAMPLE_MSG_NOTIFY, 8, Data, sizeof(Timeout), &Result, sizeof(Result), &Returned);
    ok(hr == S_OK && Returned == sizeof(Result), "Send: 0x%lx, %lu bytes\n", (ULONG)hr, Returned);
    ok(Result.Status == STATUS_TIMEOUT, "A message nobody takes: 0x%lx\n", Result.Status);

    /* A client waiting for a message gets it, with the header of the filter manager in front of it */
    Client.Reply = TRUE;
    Client.AskReply = 0x1234;
    Thread = CreateThread(NULL, 0, ReplyThread, &Client, 0, NULL);
    Sleep(50);
    Timeout = 5000;
    CopyMemory(Data, &Timeout, sizeof(Timeout));
    ZeroMemory(&Result, sizeof(Result));
    hr = Send(Client.Port, FLTSAMPLE_MSG_NOTIFY, 8, Data, sizeof(Timeout), &Result, sizeof(Result), &Returned);
    ok(hr == S_OK && Result.Status == STATUS_SUCCESS, "A notification: 0x%lx, status 0x%lx\n", (ULONG)hr, Result.Status);
    Sleep(50);
    ok(Client.Messages == 1 && Client.LastKind == FLTSAMPLE_KIND_NOTIFY, "The client got %ld messages, the last of kind %lu\n", Client.Messages, Client.LastKind);

    /* A message the sender waits an answer to */
    ZeroMemory(&Result, sizeof(Result));
    hr = Send(Client.Port, FLTSAMPLE_MSG_ASK, 8, Data, sizeof(Timeout), &Result, sizeof(Result), &Returned);
    ok(hr == S_OK && Result.Status == STATUS_SUCCESS, "A question: 0x%lx, status 0x%lx\n", (ULONG)hr, Result.Status);
    ok(Result.ReplyLength == sizeof(ULONG) && *(PULONG)Result.Reply == 0x1234, "The answer: %lu bytes, 0x%lx\n", Result.ReplyLength, *(PULONG)Result.Reply);

    /* Many, and the ids are not the same */
    {
        ULONG64 Last = Client.LastId;
        for (i = 0; i < 20; i++)
        {
            ZeroMemory(&Result, sizeof(Result));
            hr = Send(Client.Port, FLTSAMPLE_MSG_ASK, 8, Data, sizeof(Timeout), &Result, sizeof(Result), &Returned);
            if (hr != S_OK || Result.Status != STATUS_SUCCESS || *(PULONG)Result.Reply != 0x1234 || Client.LastId == Last)
                break;
            Last = Client.LastId;
        }
        ok(i == 20, "Question %lu failed: 0x%lx, status 0x%lx\n", i, (ULONG)hr, Result.Status);
    }

    /* The client doesn't answer: the sender times out */
    Client.Reply = FALSE;
    Timeout = 150;
    CopyMemory(Data, &Timeout, sizeof(Timeout));
    ZeroMemory(&Result, sizeof(Result));
    hr = Send(Client.Port, FLTSAMPLE_MSG_ASK, 8, Data, sizeof(Timeout), &Result, sizeof(Result), &Returned);
    ok(hr == S_OK && Result.Status == STATUS_TIMEOUT, "A question nobody answers: 0x%lx, status 0x%lx\n", (ULONG)hr, Result.Status);

    SampleStats(A, &S);
    ok(S.PortSent >= 24, "%lu messages sent\n", S.PortSent);

    InterlockedExchange(&Client.Stop, 1);
    CloseHandle(Client.Port);       /* the reader's request fails, it ends */
    WaitForSingleObject(Thread, 5000);
    CloseHandle(Thread);
}

typedef struct _ASK_THREAD
{
    HANDLE Port;
    FLTSAMPLE_ASK_RESULT Result;
    HRESULT Hr;

} ASK_THREAD;

static
DWORD
WINAPI
AskThread(PVOID Parameter)
{
    ASK_THREAD *Ask = Parameter;
    ULONG Forever = 0, Returned;

    ZeroMemory(&Ask->Result, sizeof(Ask->Result));
    Ask->Hr = Send(Ask->Port, FLTSAMPLE_MSG_ASK, 8, &Forever, sizeof(Forever), &Ask->Result, sizeof(Ask->Result), &Returned);
    return 0;
}

static
void
test_Create(PSAMPLE A)
{
    FLTSAMPLE_STATS S;
    REPLY_THREAD Client = { 0 };
    HANDLE Thread, File;
    HRESULT hr;
    WCHAR Path[MAX_PATH];

    Client.Port = Connect(PORT_A, &hr);
    ok(Client.Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    if (Client.Port == INVALID_HANDLE_VALUE)
        return;
    Client.Reply = TRUE;
    Thread = CreateThread(NULL, 0, ReplyThread, &Client, 0, NULL);

    /* The program decides about the creates of .msg files */
    ok(Send(Client.Port, FLTSAMPLE_MSG_ARM, 1, NULL, 0, NULL, 0, NULL) == S_OK, "Arm failed\n");
    SampleIoctl(A, FLTSAMPLE_IOCTL_RESET, NULL, 0, NULL, 0);

    MakeTestFile(L"allowed.msg", Path, RTL_NUMBER_OF(Path));
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "The create the client allowed failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);

    MakeTestFile(L"deny.msg", Path, RTL_NUMBER_OF(Path));
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "The create the client refused: %p, %lu\n", File, GetLastError());

    SampleStats(A, &S);
    ok(S.PortAsked == 2 && S.PortDenied == 1 && S.PortAskFailed == 0, "%lu asked, %lu refused, %lu failed\n", S.PortAsked, S.PortDenied, S.PortAskFailed);
    ok(Client.Creates == 2, "The client was asked about %ld creates\n", Client.Creates);

    /* Nobody to ask: let it through */
    InterlockedExchange(&Client.Stop, 1);
    CloseHandle(Client.Port);
    WaitForSingleObject(Thread, 5000);
    CloseHandle(Thread);
    Sleep(100);

    MakeTestFile(L"deny.msg", Path, RTL_NUMBER_OF(Path));
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "The create with no client to ask failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    DeleteFileW(Path);
    MakeTestFile(L"allowed.msg", Path, RTL_NUMBER_OF(Path));
    DeleteFileW(Path);

    /* A client which goes while the driver waits for its answer */
    {
        ASK_THREAD Ask = { 0 };
        REPLY_THREAD Reader = { 0 };
        HANDLE AskHandle, ReadHandle;

        Ask.Port = Connect(PORT_A, &hr);
        ok(Ask.Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
        if (Ask.Port == INVALID_HANDLE_VALUE)
            return;
        Reader.Port = Ask.Port;
        Reader.Reply = FALSE;
        ReadHandle = CreateThread(NULL, 0, ReplyThread, &Reader, 0, NULL);
        AskHandle = CreateThread(NULL, 0, AskThread, &Ask, 0, NULL);
        Sleep(300);
        ok(Reader.Messages == 1, "The reader got %ld messages\n", Reader.Messages);
        ok(WaitForSingleObject(AskHandle, 100) == WAIT_TIMEOUT, "The question was answered by itself\n");
        InterlockedExchange(&Reader.Stop, 1);
        CloseHandle(Ask.Port);
        ok(WaitForSingleObject(AskHandle, 5000) == WAIT_OBJECT_0, "The question wasn't given up when the client left\n");
        ok(Ask.Result.Status == STATUS_PORT_DISCONNECTED, "A question when the client left: 0x%lx\n", Ask.Result.Status);
        WaitForSingleObject(ReadHandle, 5000);
        CloseHandle(AskHandle);
        CloseHandle(ReadHandle);
    }
}

static
void
test_Overlapped(PSAMPLE A)
{
    CLIENT_MESSAGE Message;
    OVERLAPPED Overlapped = { 0 };
    HANDLE Port;
    HRESULT hr;
    ULONG Timeout = 3000, Returned;
    FLTSAMPLE_ASK_RESULT Result;
    DWORD Bytes;

    Port = Connect(PORT_A, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    if (Port == INVALID_HANDLE_VALUE)
        return;

    /* A request for a message which waits, and gets it */
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ZeroMemory(&Message, sizeof(Message));
    hr = FilterGetMessage(Port, &Message.Header, sizeof(Message), &Overlapped);
    ok(hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING), "FilterGetMessage returned 0x%lx\n", (ULONG)hr);
    ok(WaitForSingleObject(Overlapped.hEvent, 100) == WAIT_TIMEOUT, "The request was done before a message\n");

    ZeroMemory(&Result, sizeof(Result));
    hr = Send(Port, FLTSAMPLE_MSG_NOTIFY, 12, &Timeout, sizeof(Timeout), &Result, sizeof(Result), &Returned);
    ok(hr == S_OK && Result.Status == STATUS_SUCCESS, "Send: 0x%lx, status 0x%lx\n", (ULONG)hr, Result.Status);
    ok(WaitForSingleObject(Overlapped.hEvent, 3000) == WAIT_OBJECT_0, "No message came\n");
    ok(GetOverlappedResult(Port, &Overlapped, &Bytes, FALSE), "GetOverlappedResult failed: %lu\n", GetLastError());
    ok(Bytes == sizeof(FILTER_MESSAGE_HEADER) + 12, "%lu bytes\n", Bytes);
    ok(Message.Header.ReplyLength == 0, "A message for no reply has room for %lu\n", Message.Header.ReplyLength);

    /* A request which is cancelled */
    ResetEvent(Overlapped.hEvent);
    hr = FilterGetMessage(Port, &Message.Header, sizeof(Message), &Overlapped);
    ok(hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING), "FilterGetMessage returned 0x%lx\n", (ULONG)hr);
    CancelIo(Port);
    ok(WaitForSingleObject(Overlapped.hEvent, 3000) == WAIT_OBJECT_0, "The cancelled request didn't end\n");
    ok(!GetOverlappedResult(Port, &Overlapped, &Bytes, FALSE) && GetLastError() == ERROR_OPERATION_ABORTED,
       "Cancelled request: %lu\n", GetLastError());

    /* A request still waiting when the connection ends */
    ResetEvent(Overlapped.hEvent);
    hr = FilterGetMessage(Port, &Message.Header, sizeof(Message), &Overlapped);
    ok(hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING), "FilterGetMessage returned 0x%lx\n", (ULONG)hr);
    CloseHandle(Port);
    ok(WaitForSingleObject(Overlapped.hEvent, 3000) == WAIT_OBJECT_0, "The request didn't end with the connection\n");
    CloseHandle(Overlapped.hEvent);
    Sleep(100);
    (void)A;
}

static
void
test_Unload(void)
{
    SAMPLE A = { { 0 } };
    HANDLE Port;
    HRESULT hr;
    CLIENT_MESSAGE Message;
    OVERLAPPED Overlapped = { 0 };
    DWORD Bytes;

    if (!LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    /* The filter goes with a client connected and a request waiting */
    Port = Connect(PORT_A, &hr);
    ok(Port != INVALID_HANDLE_VALUE, "Connect failed: 0x%lx\n", (ULONG)hr);
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hr = FilterGetMessage(Port, &Message.Header, sizeof(Message), &Overlapped);
    ok(hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING), "FilterGetMessage returned 0x%lx\n", (ULONG)hr);

    UnloadSample(&A, TRUE);
    ok(WaitForSingleObject(Overlapped.hEvent, 3000) == WAIT_OBJECT_0, "The request didn't end with the filter\n");
    ok(!GetOverlappedResult(Port, &Overlapped, &Bytes, FALSE), "The request of a filter which is gone succeeded\n");
    ok(FAILED(FilterSendMessage(Port, "x", 1, NULL, 0, &Bytes)), "A message to a filter which is gone\n");
    CloseHandle(Overlapped.hEvent);
    CloseHandle(Port);

    /* And the name is free again */
    hr = LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF);
    ok(hr, "Load again failed\n");
    if (hr)
    {
        Port = Connect(PORT_A, &hr);
        ok(Port != INVALID_HANDLE_VALUE, "Connect to the filter loaded again failed: 0x%lx\n", (ULONG)hr);
        if (Port != INVALID_HANDLE_VALUE)
            CloseHandle(Port);
        UnloadSample(&A, TRUE);
    }
}

START_TEST(comms)
{
    SAMPLE A = { { 0 } };

    EnsureTestDirectory();
    if (!StartFilterManager() ||
        !LoadSample(&A, L"FltSampleA", L"380000.5", 0xFFFF))
    {
        skip("Can't load the sample filter\n");
        return;
    }

    test_Connect(&A);
    test_ToClient(&A);
    test_Create(&A);
    test_Overlapped(&A);
    UnloadSample(&A, TRUE);

    test_Unload();
}
