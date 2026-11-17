/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Contract test: a socket's options named by TDI entity id on a control channel
 *              (IOCTL_TCP_SET_INFORMATION_EX, INFO_TYPE_ADDRESS_OBJECT) are the socket's owner's to set.
 *              Another account's process and a restricted token are refused; the owner's own process, another
 *              process of the same user and an administrator are not; setsockopt on the own socket works; the
 *              public tables (entity list, the socket's row) stay readable for everybody.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Two test accounts. The owner child (account A) binds a UDP socket on loopback and publishes its entity instance
 * through a file; the other children (account B; account A; account A with a restricted token) and this process
 * (an administrator) then each set the socket's TTL by entity id to the value the owner already set, so no
 * request changes anything. Children answer through their exit codes.
 */

#include "precomp.h"
#include <ws2tcpip.h>
#include <tdiinfo.h>
#include <lm.h>
#include <strsafe.h>

#define AO_USER_A   L"aoownA"
#define AO_USER_B   L"aoownB"
#define AO_PASS     L"AoOwn-Pass#1x"
#define AO_DIR      L"C:\\aoowntst"
#define AO_TTL      64

/* Exit code of an "other" child: the low byte is the set's answer, the bits above are failures of the rest */
#define AO_SET_SUCCESS      0
#define AO_SET_DENIED       1
#define AO_SET_OTHER        2
#define AO_FAIL_OPEN        0x100
#define AO_FAIL_LIST        0x200
#define AO_FAIL_ROW         0x400
#define AO_FAIL_RESTRICT    0x800

/* The row of an IPv4 UDP socket (IP_MIB_ADDRTABLE_ENTRY_ID of its CL_TL entity): MIB_UDPROW_OWNER_PID */
typedef struct _AO_UDP_ROW
{
    ULONG LocalAddr;
    ULONG LocalPort;
    ULONG OwningPid;
} AO_UDP_ROW;

static
NTSTATUS
AoIoctl(
    _In_ HANDLE File,
    _In_ ULONG Code,
    _In_ PVOID In,
    _In_ ULONG InLen,
    _Out_opt_ PVOID Out,
    _In_ ULONG OutLen,
    _Out_opt_ PULONG_PTR Information)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK Iosb;
    HANDLE Event;

    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return Status;
    Iosb.Status = STATUS_PENDING;
    Iosb.Information = 0;
    Status = NtDeviceIoControlFile(File, Event, NULL, NULL, &Iosb, Code, In, InLen, Out, OutLen);
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(Event, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (Information)
        *Information = Iosb.Information;
    NtClose(Event);
    return Status;
}

static
NTSTATUS
AoOpenTcp(
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING Us;
    OBJECT_ATTRIBUTES Oa;
    IO_STATUS_BLOCK Iosb;

    RtlInitUnicodeString(&Us, L"\\Device\\Tcp");
    InitializeObjectAttributes(&Oa, &Us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(Handle, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &Oa, &Iosb,
                        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
}

static
NTSTATUS
AoQuery(
    _In_ HANDLE Tcp,
    _In_ ULONG Entity,
    _In_ ULONG Instance,
    _In_ ULONG Class,
    _In_ ULONG Id,
    _Out_ PVOID Out,
    _In_ ULONG OutLen,
    _Out_ PULONG_PTR Returned)
{
    TCP_REQUEST_QUERY_INFORMATION_EX Req;

    RtlZeroMemory(&Req, sizeof(Req));
    Req.ID.toi_entity.tei_entity = Entity;
    Req.ID.toi_entity.tei_instance = Instance;
    Req.ID.toi_class = Class;
    Req.ID.toi_type = INFO_TYPE_PROVIDER;
    Req.ID.toi_id = Id;
    return AoIoctl(Tcp, IOCTL_TCP_QUERY_INFORMATION_EX, &Req, sizeof(Req), Out, OutLen, Returned);
}

/* The CL_TL entity whose row has this port (network order) and process: the public tables netstat reads.
   Returns AO_FAIL_LIST, AO_FAIL_ROW (not found) or 0 */
static
ULONG
AoFindEntity(
    _In_ HANDLE Tcp,
    _In_ USHORT Port,
    _In_ ULONG Pid,
    _Out_ PULONG Instance)
{
    TDIEntityID *List;
    ULONG_PTR Returned = 0;
    ULONG Count, i, Result = AO_FAIL_ROW;
    AO_UDP_ROW Row;
    NTSTATUS Status;

    *Instance = MAXULONG;
    List = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4096 * sizeof(TDIEntityID));
    if (!List)
        return AO_FAIL_LIST;

    Status = AoQuery(Tcp, GENERIC_ENTITY, 0, INFO_CLASS_GENERIC, ENTITY_LIST_ID, List,
                     4096 * sizeof(TDIEntityID), &Returned);
    if (!NT_SUCCESS(Status) || Returned == 0 || Returned > 4096 * sizeof(TDIEntityID))
    {
        HeapFree(GetProcessHeap(), 0, List);
        return AO_FAIL_LIST;
    }

    Count = (ULONG)(Returned / sizeof(TDIEntityID));
    for (i = 0; i < Count; i++)
    {
        if (List[i].tei_entity != CL_TL_ENTITY)
            continue;
        RtlZeroMemory(&Row, sizeof(Row));
        Returned = 0;
        Status = AoQuery(Tcp, CL_TL_ENTITY, List[i].tei_instance, INFO_CLASS_PROTOCOL,
                         IP_MIB_ADDRTABLE_ENTRY_ID, &Row, sizeof(Row), &Returned);
        if (!NT_SUCCESS(Status) || Returned < sizeof(Row))
            continue;
        /* (the row's port in network order, as getsockname's; either order is taken) */
        if (((USHORT)Row.LocalPort == Port || (USHORT)Row.LocalPort == ntohs(Port)) && Row.OwningPid == Pid)
        {
            *Instance = List[i].tei_instance;
            Result = 0;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, List);
    return Result;
}

/* A UDP socket's address-object option by entity id, on a control channel */
static
NTSTATUS
AoSetByEntity(
    _In_ HANDLE Tcp,
    _In_ ULONG Instance,
    _In_ ULONG OptionId,
    _In_ ULONG Value)
{
    UCHAR Buffer[FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer) + sizeof(ULONG)];
    PTCP_REQUEST_SET_INFORMATION_EX Req = (PTCP_REQUEST_SET_INFORMATION_EX)Buffer;

    RtlZeroMemory(Buffer, sizeof(Buffer));
    Req->ID.toi_entity.tei_entity = CL_TL_ENTITY;
    Req->ID.toi_entity.tei_instance = Instance;
    Req->ID.toi_class = INFO_CLASS_PROTOCOL;
    Req->ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;
    Req->ID.toi_id = OptionId;
    Req->BufferSize = sizeof(ULONG);
    RtlCopyMemory(Req->Buffer, &Value, sizeof(Value));
    return AoIoctl(Tcp, IOCTL_TCP_SET_INFORMATION_EX, Req, sizeof(Buffer), NULL, 0, NULL);
}

/* This process's handles, from the system handle table (free with HeapFree), or NULL */
static
PSYSTEM_HANDLE_INFORMATION_EX
AoQueryHandles(VOID)
{
    PSYSTEM_HANDLE_INFORMATION_EX Info;
    ULONG Size = 0x10000;
    NTSTATUS Status;

    for (;;)
    {
        Info = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Info)
            return NULL;
        Status = NtQuerySystemInformation(SystemExtendedHandleInformation, Info, Size, NULL);
        if (NT_SUCCESS(Status))
            return Info;
        HeapFree(GetProcessHeap(), 0, Info);
        if (Status != STATUS_INFO_LENGTH_MISMATCH || Size >= 0x4000000)
            return NULL;
        Size *= 2;
    }
}

/* The socket's own address handle: the file handle that binding the socket adds to this process (AFD returns it
 * to the Winsock helper). A request on it is about that socket whatever entity it names, so a set naming an entity
 * that does not exist works there; on a control channel it does not. Returns how many such handles took it */
static
ULONG
AoOwnHandleSet(
    _In_ HANDLE Tcp)
{
    PSYSTEM_HANDLE_INFORMATION_EX Before = NULL, After = NULL;
    ULONG_PTR Self = GetCurrentProcessId(), i, j;
    USHORT FileType = MAXUSHORT;
    struct sockaddr_in A;
    SOCKET S;
    ULONG Taken = 0, Tried = 0;
    NTSTATUS Status;
    BOOL Old;

    S = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(S != INVALID_SOCKET, "own handle: socket failed %d\n", WSAGetLastError());
    if (S == INVALID_SOCKET)
        return 0;

    Before = AoQueryHandles();
    memset(&A, 0, sizeof(A));
    A.sin_family = AF_INET;
    A.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(S, (struct sockaddr *)&A, sizeof(A)) == 0, "own handle: bind failed %d\n", WSAGetLastError());
    After = AoQueryHandles();
    ok(Before && After, "own handle: no handle table\n");
    if (!Before || !After)
        goto Done;

    /* The type of a file handle: the control channel's */
    for (i = 0; i < After->NumberOfHandles; i++)
    {
        if (After->Handles[i].UniqueProcessId == Self && After->Handles[i].HandleValue == (ULONG_PTR)Tcp)
            FileType = After->Handles[i].ObjectTypeIndex;
    }
    ok(FileType != MAXUSHORT, "own handle: the control channel is not in the handle table\n");

    for (i = 0; i < After->NumberOfHandles; i++)
    {
        if (After->Handles[i].UniqueProcessId != Self || After->Handles[i].ObjectTypeIndex != FileType)
            continue;
        for (j = 0, Old = FALSE; j < Before->NumberOfHandles && !Old; j++)
        {
            Old = (Before->Handles[j].UniqueProcessId == Self &&
                   Before->Handles[j].HandleValue == After->Handles[i].HandleValue);
        }
        if (Old)
            continue;
        Tried++;
        Status = AoSetByEntity((HANDLE)After->Handles[i].HandleValue, 0x7ffffff0, AO_OPTION_TTL, AO_TTL);
        trace("own handle %p (access 0x%lx): set naming no entity gave 0x%lx\n",
              (PVOID)After->Handles[i].HandleValue, After->Handles[i].GrantedAccess, Status);
        if (Status == STATUS_SUCCESS)
            Taken++;
    }
    ok(Tried != 0, "own handle: binding added no file handle\n");

    /* The control channel names sockets by entity id only */
    Status = AoSetByEntity(Tcp, 0x7ffffff0, AO_OPTION_TTL, AO_TTL);
    ok(Status == STATUS_INVALID_PARAMETER, "control channel: set naming no entity gave 0x%lx\n", Status);

Done:
    if (Before)
        HeapFree(GetProcessHeap(), 0, Before);
    if (After)
        HeapFree(GetProcessHeap(), 0, After);
    closesocket(S);
    return Taken;
}

static
BOOL
AoFileExists(
    _In_ PCWSTR Name)
{
    WCHAR Path[MAX_PATH];

    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\%ls", AO_DIR, Name);
    return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static
BOOL
AoWriteFile(
    _In_ PCWSTR Name,
    _In_ PCSTR Text)
{
    WCHAR Path[MAX_PATH], Tmp[MAX_PATH];
    HANDLE File;
    DWORD Written = 0;
    BOOL Ok;
    SECURITY_DESCRIPTOR Sd;
    SECURITY_ATTRIBUTES Sa;

    /* Readable by the other account (the writer's default DACL would not be) */
    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&Sd, TRUE, NULL, FALSE);
    Sa.nLength = sizeof(Sa);
    Sa.lpSecurityDescriptor = &Sd;
    Sa.bInheritHandle = FALSE;

    /* Written under another name and renamed, so a reader never sees half of it */
    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\%ls", AO_DIR, Name);
    StringCchPrintfW(Tmp, RTL_NUMBER_OF(Tmp), L"%ls\\%ls.tmp", AO_DIR, Name);
    File = CreateFileW(Tmp, GENERIC_WRITE, 0, &Sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = WriteFile(File, Text, (DWORD)strlen(Text), &Written, NULL);
    CloseHandle(File);
    return Ok && MoveFileExW(Tmp, Path, MOVEFILE_REPLACE_EXISTING);
}

static
BOOL
AoReadFile(
    _In_ PCWSTR Name,
    _Out_writes_(Size) PSTR Text,
    _In_ DWORD Size)
{
    WCHAR Path[MAX_PATH];
    HANDLE File;
    DWORD Read = 0;
    BOOL Ok;

    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\%ls", AO_DIR, Name);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = ReadFile(File, Text, Size - 1, &Read, NULL);
    CloseHandle(File);
    Text[Ok ? Read : 0] = 0;
    return Ok && Read != 0;
}

/* The owner's progress, for the parent's trace when it publishes nothing */
static
DWORD
AoMark(
    _In_ DWORD Step)
{
    CHAR Text[32];

    StringCchPrintfA(Text, sizeof(Text), "step %lu error %lu", Step, GetLastError());
    AoWriteFile(L"owner-step.txt", Text);
    return Step;
}

/* The owner (account A): binds the socket, checks its own options, publishes the entity and keeps the socket
   until the parent is done. Exit 0 or the failing step */
static
DWORD
AoChildOwner(VOID)
{
    WSADATA Wd;
    SOCKET S;
    struct sockaddr_in A;
    int Len = sizeof(A), Value;
    HANDLE Tcp;
    ULONG Instance;
    CHAR Text[96];
    DWORD Waited, Exit = 0;

    AoMark(1);
    if (WSAStartup(MAKEWORD(2, 2), &Wd) != 0)
        return AoMark(10);
    S = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (S == INVALID_SOCKET)
        return AoMark(11);
    memset(&A, 0, sizeof(A));
    A.sin_family = AF_INET;
    A.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(S, (struct sockaddr *)&A, sizeof(A)) != 0 || getsockname(S, (struct sockaddr *)&A, &Len) != 0)
        return AoMark(12);
    AoMark(2);

    /* The own socket's options through Winsock */
    Value = AO_TTL;
    if (setsockopt(S, IPPROTO_IP, IP_TTL, (char *)&Value, sizeof(Value)) != 0)
        return AoMark(13);
    Value = 1;
    if (setsockopt(S, SOL_SOCKET, SO_BROADCAST, (char *)&Value, sizeof(Value)) != 0)
        return AoMark(14);
    AoMark(3);

    if (!NT_SUCCESS(AoOpenTcp(&Tcp)))
        return AoMark(15);
    if (AoFindEntity(Tcp, A.sin_port, GetCurrentProcessId(), &Instance) != 0)
        return AoMark(16);
    /* By entity id from the process that opened it */
    if (!NT_SUCCESS(AoSetByEntity(Tcp, Instance, AO_OPTION_TTL, AO_TTL)))
        return AoMark(17);
    AoMark(4);

    StringCchPrintfA(Text, sizeof(Text), "%lu %u %lu", Instance, (UINT)A.sin_port, GetCurrentProcessId());
    if (!AoWriteFile(L"info.txt", Text))
        return AoMark(18);
    AoMark(5);

    for (Waited = 0; Waited < 300 && !AoFileExists(L"done.txt"); Waited++)
        Sleep(1000);
    if (Waited >= 300)
        Exit = 19;

    /* Still the owner's to set */
    Value = AO_TTL;
    if (!Exit && setsockopt(S, IPPROTO_IP, IP_TTL, (char *)&Value, sizeof(Value)) != 0)
        Exit = 20;

    NtClose(Tcp);
    closesocket(S);
    WSACleanup();
    return Exit;
}

/* Another process: reads the public tables, then sets the owner's TTL by entity id (with a restricted token of its
   own if Restricted). Exit: AO_SET_* | AO_FAIL_* */
static
DWORD
AoChildOther(
    _In_ ULONG Instance,
    _In_ USHORT Port,
    _In_ ULONG Pid,
    _In_ BOOL Restricted)
{
    HANDLE Tcp, Token = NULL, Restrict = NULL, Imp = NULL;
    ULONG Found = MAXULONG, Exit = 0;
    NTSTATUS Status;
    SID_AND_ATTRIBUTES Sids[1];
    BYTE World[SECURITY_MAX_SID_SIZE];
    DWORD Cb = sizeof(World);

    if (!NT_SUCCESS(AoOpenTcp(&Tcp)))
        return AO_FAIL_OPEN | AO_SET_OTHER;

    /* The public tables: the entity list and the socket's row */
    Exit |= AoFindEntity(Tcp, Port, Pid, &Found);
    if (!Exit && Found != Instance)
        Exit |= AO_FAIL_ROW;

    if (Restricted)
    {
        Sids[0].Sid = World;
        Sids[0].Attributes = 0;
        if (!CreateWellKnownSid(WinWorldSid, NULL, World, &Cb) ||
            !OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Token) ||
            !CreateRestrictedToken(Token, 0, 0, NULL, 0, NULL, 1, Sids, &Restrict) ||
            !DuplicateToken(Restrict, SecurityImpersonation, &Imp) ||
            !SetThreadToken(NULL, Imp))
        {
            Exit |= AO_FAIL_RESTRICT;
        }
    }

    Status = AoSetByEntity(Tcp, Instance, AO_OPTION_TTL, AO_TTL);
    if (Status == STATUS_SUCCESS)
        Exit |= AO_SET_SUCCESS;
    else if (Status == STATUS_ACCESS_DENIED)
        Exit |= AO_SET_DENIED;
    else
        Exit |= AO_SET_OTHER;

    if (Restricted)
        RevertToSelf();
    if (Imp)
        CloseHandle(Imp);
    if (Restrict)
        CloseHandle(Restrict);
    if (Token)
        CloseHandle(Token);
    NtClose(Tcp);
    return Exit;
}

static
BOOL
AoAddUser(
    _In_ PCWSTR Name)
{
    USER_INFO_1 Ui;
    DWORD Err = 0;
    NET_API_STATUS Status;

    memset(&Ui, 0, sizeof(Ui));
    Ui.usri1_name = (LPWSTR)Name;
    Ui.usri1_password = (LPWSTR)AO_PASS;
    Ui.usri1_priv = USER_PRIV_USER;
    Ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    NetUserDel(NULL, Name);
    Status = NetUserAdd(NULL, 1, (LPBYTE)&Ui, &Err);
    ok(Status == NERR_Success, "NetUserAdd(%ls) failed: %lu\n", Name, Status);
    return Status == NERR_Success;
}

static
BOOL
AoStartChild(
    _In_ PCWSTR User,
    _In_ PCWSTR Args,
    _Out_ PHANDLE Process)
{
    WCHAR Exe[MAX_PATH], Command[MAX_PATH + 160];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;

    *Process = NULL;
    GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
    StringCchPrintfW(Command, RTL_NUMBER_OF(Command), L"\"%ls\" tcpaoowner child %ls", Exe, Args);
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (!CreateProcessWithLogonW(User, L".", AO_PASS, 0, NULL, Command, 0, NULL, NULL, &Si, &Pi))
    {
        ok(0, "CreateProcessWithLogonW(%ls, %ls) failed: %lu\n", User, Args, GetLastError());
        return FALSE;
    }
    CloseHandle(Pi.hThread);
    *Process = Pi.hProcess;
    return TRUE;
}

static
DWORD
AoWaitChild(
    _In_ HANDLE Process,
    _In_ DWORD Ms)
{
    DWORD Exit = MAXDWORD;

    if (WaitForSingleObject(Process, Ms) != WAIT_OBJECT_0)
    {
        ok(0, "a child did not exit\n");
        TerminateProcess(Process, MAXDWORD);
    }
    else if (!GetExitCodeProcess(Process, &Exit))
    {
        Exit = MAXDWORD;
    }
    CloseHandle(Process);
    return Exit;
}

static
DWORD
AoRunOther(
    _In_ PCWSTR User,
    _In_ ULONG Instance,
    _In_ UINT Port,
    _In_ ULONG Pid,
    _In_ BOOL Restricted)
{
    WCHAR Args[96];
    HANDLE Process;

    StringCchPrintfW(Args, RTL_NUMBER_OF(Args), L"other %lu %u %lu %u", Instance, Port, Pid, Restricted ? 1 : 0);
    if (!AoStartChild(User, Args, &Process))
        return MAXDWORD;
    return AoWaitChild(Process, 120000);
}

static
VOID
AoCleanFiles(VOID)
{
    DeleteFileW(AO_DIR L"\\info.txt");
    DeleteFileW(AO_DIR L"\\info.txt.tmp");
    DeleteFileW(AO_DIR L"\\done.txt");
    DeleteFileW(AO_DIR L"\\done.txt.tmp");
    DeleteFileW(AO_DIR L"\\owner-step.txt");
    DeleteFileW(AO_DIR L"\\owner-step.txt.tmp");
}

START_TEST(tcpaoowner)
{
    BYTE AdminSid[SECURITY_MAX_SID_SIZE];
    DWORD Cb = sizeof(AdminSid), Exit, Waited;
    BOOL Member = FALSE;
    SECURITY_DESCRIPTOR Sd;
    SECURITY_ATTRIBUTES Sa;
    HANDLE Owner = NULL, Tcp;
    CHAR Text[96];
    ULONG Instance = MAXULONG, Pid = 0, Found = MAXULONG;
    UINT Port = 0;
    NTSTATUS Status;
    WSADATA Wd;
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        if (!strcmp(argv[3], "owner"))
            ExitProcess(AoChildOwner());
        if (!strcmp(argv[3], "other") && argc >= 8)
            ExitProcess(AoChildOther(strtoul(argv[4], NULL, 10), (USHORT)strtoul(argv[5], NULL, 10),
                                     strtoul(argv[6], NULL, 10), atoi(argv[7]) != 0));
        ExitProcess(MAXDWORD);
    }

    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminSid, &Cb);
    CheckTokenMembership(NULL, AdminSid, &Member);
    if (!Member)
    {
        skip("Test must run as an Administrator\n");
        return;
    }
    ok(WSAStartup(MAKEWORD(2, 2), &Wd) == 0, "WSAStartup failed\n");

    /* A directory both test accounts may use */
    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&Sd, TRUE, NULL, FALSE);
    Sa.nLength = sizeof(Sa);
    Sa.lpSecurityDescriptor = &Sd;
    Sa.bInheritHandle = FALSE;
    CreateDirectoryW(AO_DIR, &Sa);
    SetFileSecurityW(AO_DIR, DACL_SECURITY_INFORMATION, &Sd);
    AoCleanFiles();

    if (!AoAddUser(AO_USER_A) || !AoAddUser(AO_USER_B))
        goto Cleanup;

    if (!AoStartChild(AO_USER_A, L"owner", &Owner))
        goto Cleanup;
    Text[0] = 0;
    for (Waited = 0; Waited < 180 && !AoReadFile(L"info.txt", Text, sizeof(Text)); Waited++)
    {
        if (WaitForSingleObject(Owner, 1000) == WAIT_OBJECT_0)
            break;
    }
    if (sscanf(Text, "%lu %u %lu", &Instance, &Port, &Pid) != 3)
    {
        if (!AoReadFile(L"owner-step.txt", Text, sizeof(Text)))
            StringCchCopyA(Text, sizeof(Text), "(no step file)");
        ok(0, "the owner child published no socket (after %lu s; %s)\n", Waited, Text);
        AoWriteFile(L"done.txt", "done");
        Exit = AoWaitChild(Owner, 30000);
        ok(Exit == 0, "owner child: step %lu\n", Exit);
        goto Cleanup;
    }
    trace("owner socket: entity instance %lu, port %u, process %lu\n", Instance, ntohs((USHORT)Port), Pid);

    /* Another account: refused, public tables readable */
    Exit = AoRunOther(AO_USER_B, Instance, Port, Pid, FALSE);
    trace("other account: exit 0x%lx\n", Exit);
    ok((Exit & 0xff) == AO_SET_DENIED, "another account set the socket's TTL by entity id (answer %lu, expected %d)\n",
       Exit & 0xff, AO_SET_DENIED);
    ok(Exit != MAXDWORD && (Exit & ~0xff) == 0, "another account: public tables failed (0x%lx)\n", Exit & ~0xff);

    /* The same account, another process: allowed */
    Exit = AoRunOther(AO_USER_A, Instance, Port, Pid, FALSE);
    trace("same account: exit 0x%lx\n", Exit);
    ok(Exit == AO_SET_SUCCESS, "the owner's account in another process: exit 0x%lx, expected 0\n", Exit);

    /* The same account with a restricted token: refused */
    Exit = AoRunOther(AO_USER_A, Instance, Port, Pid, TRUE);
    trace("restricted token: exit 0x%lx\n", Exit);
    ok(Exit != MAXDWORD && !(Exit & AO_FAIL_RESTRICT), "restricted token not set up (0x%lx)\n", Exit);
    ok((Exit & 0xff) == AO_SET_DENIED, "a restricted token set the socket's TTL by entity id (answer %lu, expected %d)\n",
       Exit & 0xff, AO_SET_DENIED);

    /* An administrator: allowed; and the public tables */
    Status = AoOpenTcp(&Tcp);
    ok(Status == STATUS_SUCCESS, "open \\Device\\Tcp: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        ok(AoFindEntity(Tcp, (USHORT)Port, Pid, &Found) == 0 && Found == Instance,
           "administrator: the socket's row was not found (%lu)\n", Found);
        Status = AoSetByEntity(Tcp, Instance, AO_OPTION_TTL, AO_TTL);
        ok(Status == STATUS_SUCCESS, "administrator: set by entity id gave 0x%lx\n", Status);
        /* The Winsock helper's path: the socket's own address handle */
        ok(AoOwnHandleSet(Tcp) == 1, "the socket's own address handle did not take its option request\n");
        NtClose(Tcp);
    }

    AoWriteFile(L"done.txt", "done");
    Exit = AoWaitChild(Owner, 60000);
    ok(Exit == 0, "owner child: failing step %lu (own socket options)\n", Exit);
    Owner = NULL;

Cleanup:
    if (Owner)
    {
        AoWriteFile(L"done.txt", "done");
        AoWaitChild(Owner, 30000);
    }
    AoCleanFiles();
    RemoveDirectoryW(AO_DIR);
    NetUserDel(NULL, AO_USER_A);
    NetUserDel(NULL, AO_USER_B);
    WSACleanup();
}
