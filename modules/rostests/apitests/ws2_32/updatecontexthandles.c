/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Socket handles kept by msafd: connect, ConnectEx and AcceptEx (with the
 *              SO_UPDATE_*_CONTEXT setsockopt) followed by closesocket must not close or leak a
 *              handle that is not the socket's own. Windows keeps no such handles at all.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>

#define ROUNDS 32
#define MARKERS 4

/* msafd.dll's NtClose, wrapped through its import table to see which closes fail (ReactOS only) */
typedef NTSTATUS (NTAPI *PFN_NTCLOSE)(HANDLE);
static PFN_NTCLOSE g_RealNtClose;
static volatile LONG g_Failed, g_NullCloses;
static HANDLE g_FirstFailed[4];
static NTSTATUS g_FirstStatus[4];

static
NTSTATUS
NTAPI
HookNtClose(HANDLE Handle)
{
    NTSTATUS Status = g_RealNtClose(Handle);
    LONG Index;

    if (!NT_SUCCESS(Status) && !Handle)
    {
        /* Closing nothing: harmless, only counted */
        InterlockedIncrement(&g_NullCloses);
    }
    else if (!NT_SUCCESS(Status))
    {
        Index = InterlockedIncrement(&g_Failed) - 1;
        if (Index < 4)
        {
            g_FirstFailed[Index] = Handle;
            g_FirstStatus[Index] = Status;
        }
    }
    return Status;
}

static
BOOL
HookMsafdClose(VOID)
{
    PBYTE Base = (PBYTE)GetModuleHandleW(L"msafd.dll");
    PIMAGE_NT_HEADERS Nt;
    PIMAGE_IMPORT_DESCRIPTOR Import;
    PIMAGE_DATA_DIRECTORY Dir;

    if (!Base)
        return FALSE;
    Nt = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    Dir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!Dir->VirtualAddress)
        return FALSE;
    for (Import = (PIMAGE_IMPORT_DESCRIPTOR)(Base + Dir->VirtualAddress); Import->Name; Import++)
    {
        PIMAGE_THUNK_DATA Names, Funcs;

        if (_stricmp((char *)(Base + Import->Name), "ntdll.dll") != 0 || !Import->OriginalFirstThunk)
            continue;
        Names = (PIMAGE_THUNK_DATA)(Base + Import->OriginalFirstThunk);
        Funcs = (PIMAGE_THUNK_DATA)(Base + Import->FirstThunk);
        for (; Names->u1.AddressOfData; Names++, Funcs++)
        {
            PIMAGE_IMPORT_BY_NAME Name;
            DWORD Old;

            if (IMAGE_SNAP_BY_ORDINAL(Names->u1.Ordinal))
                continue;
            Name = (PIMAGE_IMPORT_BY_NAME)(Base + Names->u1.AddressOfData);
            if (strcmp((char *)Name->Name, "NtClose") != 0)
                continue;
            if (!VirtualProtect(&Funcs->u1.Function, sizeof(Funcs->u1.Function), PAGE_READWRITE, &Old))
                return FALSE;
            g_RealNtClose = (PFN_NTCLOSE)Funcs->u1.Function;
            Funcs->u1.Function = (ULONG_PTR)HookNtClose;
            VirtualProtect(&Funcs->u1.Function, sizeof(Funcs->u1.Function), Old, &Old);
            return TRUE;
        }
    }
    return FALSE;
}

static
DWORD
HandleCount(VOID)
{
    DWORD Count = 0;

    GetProcessHandleCount(GetCurrentProcess(), &Count);
    return Count;
}

static
VOID
CheckClosed(const char *What, LONG FailedBefore)
{
    LONG Failed = g_Failed - FailedBefore;

    ok(Failed == 0, "%s: msafd closed %ld handles that are not valid in this process (first: %p, 0x%lx)\n", What,
       Failed, g_FirstFailed[0], (ULONG)g_FirstStatus[0]);
}

static
SOCKET
Listener(struct sockaddr_in *Address)
{
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int Length = sizeof(*Address);

    if (Socket == INVALID_SOCKET)
        return Socket;
    ZeroMemory(Address, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Socket, (struct sockaddr *)Address, sizeof(*Address)) ||
        listen(Socket, ROUNDS) || getsockname(Socket, (struct sockaddr *)Address, &Length))
    {
        closesocket(Socket);
        return INVALID_SOCKET;
    }
    return Socket;
}

/* connect() on an unbound socket, and a socket that was never connected */
static
BOOL
PlainConnect(SOCKET ListenSocket, const struct sockaddr_in *Server)
{
    SOCKET Client, Accepted, Unbound;
    BOOL Ok = FALSE;

    Unbound = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Unbound != INVALID_SOCKET)
        closesocket(Unbound);
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client == INVALID_SOCKET)
        return FALSE;
    if (connect(Client, (const struct sockaddr *)Server, sizeof(*Server)) == 0)
    {
        Accepted = accept(ListenSocket, NULL, NULL);
        if (Accepted != INVALID_SOCKET)
        {
            closesocket(Accepted);
            Ok = TRUE;
        }
    }
    closesocket(Client);
    return Ok;
}

static
BOOL
ConnectExOnce(LPFN_CONNECTEX pConnectEx, HANDLE Port, SOCKET ListenSocket, const struct sockaddr_in *Server,
              BOOL Update)
{
    SOCKET Client, Accepted;
    struct sockaddr_in Local;
    OVERLAPPED Overlapped;
    LPOVERLAPPED Completed;
    DWORD Bytes;
    ULONG_PTR Key;
    BOOL Ok = FALSE;

    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client == INVALID_SOCKET)
        return FALSE;
    ZeroMemory(&Local, sizeof(Local));
    Local.sin_family = AF_INET;
    Local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Client, (struct sockaddr *)&Local, sizeof(Local)) == SOCKET_ERROR ||
        CreateIoCompletionPort((HANDLE)Client, Port, 1, 0) != Port)
        goto Done;
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    if (!pConnectEx(Client, (const struct sockaddr *)Server, sizeof(*Server), NULL, 0, &Bytes, &Overlapped) &&
        WSAGetLastError() != ERROR_IO_PENDING)
        goto Done;
    if (!GetQueuedCompletionStatus(Port, &Bytes, &Key, &Completed, 10000) || Completed != &Overlapped)
        goto Done;
    if (Update && setsockopt(Client, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR)
        goto Done;
    Accepted = accept(ListenSocket, NULL, NULL);
    if (Accepted != INVALID_SOCKET)
    {
        closesocket(Accepted);
        Ok = TRUE;
    }
Done:
    closesocket(Client);
    return Ok;
}

static
BOOL
AcceptExOnce(LPFN_ACCEPTEX pAcceptEx, SOCKET ListenSocket, const struct sockaddr_in *Server, BOOL Update)
{
    SOCKET Accepted, Client;
    OVERLAPPED Overlapped;
    char Buffer[2 * (sizeof(struct sockaddr_in) + 16)];
    DWORD Bytes;
    BOOL Ok = FALSE;

    Accepted = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Accepted == INVALID_SOCKET)
        return FALSE;
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Overlapped.hEvent)
        goto Done;
    if (!pAcceptEx(ListenSocket, Accepted, Buffer, 0, sizeof(struct sockaddr_in) + 16,
                   sizeof(struct sockaddr_in) + 16, &Bytes, &Overlapped) && WSAGetLastError() != ERROR_IO_PENDING)
        goto Done;
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client != INVALID_SOCKET)
    {
        if (connect(Client, (const struct sockaddr *)Server, sizeof(*Server)) == 0 &&
            WaitForSingleObject(Overlapped.hEvent, 10000) == WAIT_OBJECT_0)
        {
            Ok = !Update || setsockopt(Accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&ListenSocket,
                                       sizeof(ListenSocket)) == 0;
        }
        closesocket(Client);
    }
Done:
    closesocket(Accepted);
    if (Overlapped.hEvent)
        CloseHandle(Overlapped.hEvent);
    return Ok;
}

static
BOOL
MarkersValid(HANDLE *Markers)
{
    DWORD Flags;
    int i;

    for (i = 0; i < MARKERS; i++)
        if (!GetHandleInformation(Markers[i], &Flags))
            return FALSE;
    return TRUE;
}

START_TEST(updatecontexthandles)
{
    WSADATA Data;
    GUID ConnectExGuid = WSAID_CONNECTEX, AcceptExGuid = WSAID_ACCEPTEX;
    LPFN_CONNECTEX pConnectEx = NULL;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    SOCKET ListenSocket;
    struct sockaddr_in Server;
    HANDLE Port, Markers[MARKERS];
    DWORD Bytes, Before, After;
    BOOL Hooked;
    LONG FailedBefore;
    int Round, Pass, i;

    ok_int(WSAStartup(MAKEWORD(2, 2), &Data), 0);

    /* Handles of the process that the sockets must leave alone */
    for (i = 0; i < MARKERS; i++)
        Markers[i] = CreateEventW(NULL, TRUE, FALSE, NULL);

    ListenSocket = Listener(&Server);
    ok(ListenSocket != INVALID_SOCKET, "no listening socket %d\n", WSAGetLastError());
    if (ListenSocket == INVALID_SOCKET)
        goto Cleanup;
    ok_int(WSAIoctl(ListenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &ConnectExGuid, sizeof(ConnectExGuid),
                    &pConnectEx, sizeof(pConnectEx), &Bytes, NULL, NULL), 0);
    ok_int(WSAIoctl(ListenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptExGuid, sizeof(AcceptExGuid),
                    &pAcceptEx, sizeof(pAcceptEx), &Bytes, NULL, NULL), 0);
    Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!pConnectEx || !pAcceptEx || !Port)
    {
        ok(0, "setup failed\n");
        goto Cleanup;
    }

    /* msafd.dll is loaded now (ReactOS only: Windows has no such module and the close checks are skipped) */
    Hooked = HookMsafdClose();
    trace("msafd NtClose hook: %s\n", Hooked ? "installed" : "not available");

    /* Pass 0: no update-context setsockopt. Pass 1: with it. */
    for (Pass = 0; Pass < 2; Pass++)
    {
        BOOL Update = Pass;

        /* Warm up: one-time handles are not a leak */
        ok(PlainConnect(ListenSocket, &Server), "warm-up connect failed\n");
        ok(ConnectExOnce(pConnectEx, Port, ListenSocket, &Server, Update), "warm-up ConnectEx failed\n");
        ok(AcceptExOnce(pAcceptEx, ListenSocket, &Server, Update), "warm-up AcceptEx failed\n");

        /* connect() */
        FailedBefore = g_Failed;
        Before = HandleCount();
        for (Round = 0; Round < ROUNDS; Round++)
            if (!PlainConnect(ListenSocket, &Server))
                break;
        After = HandleCount();
        ok(Round == ROUNDS, "connect %d failed\n", Round);
        ok(MarkersValid(Markers), "connect: a marker handle was closed\n");
        ok(After <= Before + 2, "connect: %lu handles before, %lu after\n", Before, After);
        if (Hooked)
            CheckClosed(Pass ? "connect (pass 1)" : "connect (pass 0)", FailedBefore);

        /* ConnectEx */
        FailedBefore = g_Failed;
        Before = HandleCount();
        for (Round = 0; Round < ROUNDS; Round++)
            if (!ConnectExOnce(pConnectEx, Port, ListenSocket, &Server, Update))
                break;
        After = HandleCount();
        ok(Round == ROUNDS, "ConnectEx %d failed\n", Round);
        ok(MarkersValid(Markers), "ConnectEx (update %d): a marker handle was closed\n", Update);
        ok(After <= Before + 2, "ConnectEx (update %d): %lu handles before, %lu after\n", Update, Before, After);
        if (Hooked)
            CheckClosed(Pass ? "ConnectEx + SO_UPDATE_CONNECT_CONTEXT" : "ConnectEx", FailedBefore);

        /* AcceptEx */
        FailedBefore = g_Failed;
        Before = HandleCount();
        for (Round = 0; Round < ROUNDS; Round++)
            if (!AcceptExOnce(pAcceptEx, ListenSocket, &Server, Update))
                break;
        After = HandleCount();
        ok(Round == ROUNDS, "AcceptEx %d failed\n", Round);
        ok(MarkersValid(Markers), "AcceptEx (update %d): a marker handle was closed\n", Update);
        ok(After <= Before + 2, "AcceptEx (update %d): %lu handles before, %lu after\n", Update, Before, After);
        if (Hooked)
            CheckClosed(Pass ? "AcceptEx + SO_UPDATE_ACCEPT_CONTEXT" : "AcceptEx", FailedBefore);
    }

    if (Hooked)
        trace("msafd closed NULL %ld times\n", g_NullCloses);

Cleanup:
    for (i = 0; i < MARKERS; i++)
        ok(Markers[i] && CloseHandle(Markers[i]), "marker %d was closed behind the test's back\n", i);
    if (Port)
        CloseHandle(Port);
    if (ListenSocket != INVALID_SOCKET)
        closesocket(ListenSocket);
    WSACleanup();
}
