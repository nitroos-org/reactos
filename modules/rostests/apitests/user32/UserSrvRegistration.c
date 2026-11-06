/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Only the logon process and the service control manager register with the user server
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * The user server keeps one logon process (winlogon) and one services process (services.exe).
 * Both register at boot, and both run as LocalSystem. A registration from any other process,
 * or one that names a process other than the caller, is refused with STATUS_ACCESS_DENIED, and
 * so is a logon/logoff notification (UserpLogon) that does not come from the registered logon
 * process. Before, the first process to send the request took the slot and any process could send
 * the logon notification.
 *
 * Windows 10 has neither registration in its user server table (the numbering is ReactOS's), so the
 * raw requests are for ReactOS only; this test runs as an administrator, not as LocalSystem.
 */

typedef LONG (NTAPI *PCSRCALL)(PVOID, PVOID, ULONG, ULONG);

typedef struct
{
    CHAR Header[sizeof(PVOID) == 8 ? 40 : 24]; /* PORT_MESSAGE */
    PVOID CaptureData;
    ULONG ApiNumber;
    LONG Status;
    ULONG Reserved;
    union
    {
        struct { BOOL IsLogon; } Logon;
        struct { ULONG_PTR ProcessId; } Services;
        struct { ULONG_PTR ProcessId; BOOL Register; } LogonProcess;
        ULONGLONG Pad[32];
    } Data;
} RAW_USER_MESSAGE;

/* USERSRV_SERVERDLL_INDEX 3; UserpLogon 1026, UserpRegisterServicesProcess 1027, UserpRegisterLogonProcess 1031 */
#define USER_API(n) ((3 << 16) | (n))

#define STATUS_ACCESS_DENIED_       ((LONG)0xC0000022)
#define STATUS_NOT_LOGON_PROCESS_   ((LONG)0xC00000ED)

static PCSRCALL pCsrClientCallServer;
static BOOL (WINAPI *pRegisterServicesProcess)(DWORD);

static LONG CallUser(RAW_USER_MESSAGE *Message, ULONG Api, ULONG Size)
{
    LONG Status = pCsrClientCallServer(Message, NULL, USER_API(Api), Size);
    ok(Status == Message->Status, "returned %08lx, message status %08lx\n", Status, Message->Status);
    return Status;
}

START_TEST(UserSrvRegistration)
{
    RAW_USER_MESSAGE Message;
    ULONG_PTR Self = GetCurrentProcessId();
    LONG Status;
    BOOL Ret;

    pCsrClientCallServer = (PCSRCALL)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrClientCallServer");
    pRegisterServicesProcess = (PVOID)GetProcAddress(GetModuleHandleW(L"user32.dll"), "RegisterServicesProcess");
    if (!is_reactos() || !pCsrClientCallServer || !pRegisterServicesProcess)
    {
        skip("The user server registration requests are numbered for ReactOS\n");
        return;
    }

    /* The exported wrapper: the services slot is not for this process */
    SetLastError(0xdeadbeef);
    Ret = pRegisterServicesProcess(GetCurrentProcessId());
    ok(Ret == FALSE, "RegisterServicesProcess succeeded\n");
    ok(GetLastError() == ERROR_ACCESS_DENIED, "RegisterServicesProcess: error %lu\n", GetLastError());

    /* The raw services registration, for this process and for another one (the parent's id is as good as any) */
    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.Services.ProcessId = Self;
    Status = CallUser(&Message, 1027, sizeof(Message.Data.Services));
    ok(Status == STATUS_ACCESS_DENIED_, "UserpRegisterServicesProcess(self) returned %08lx\n", Status);

    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.Services.ProcessId = 4;
    Status = CallUser(&Message, 1027, sizeof(Message.Data.Services));
    ok(Status == STATUS_ACCESS_DENIED_, "UserpRegisterServicesProcess(4) returned %08lx\n", Status);

    /* The raw logon process registration, sent past win32k */
    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.LogonProcess.ProcessId = Self;
    Message.Data.LogonProcess.Register = TRUE;
    Status = CallUser(&Message, 1031, sizeof(Message.Data.LogonProcess));
    ok(Status == STATUS_ACCESS_DENIED_, "UserpRegisterLogonProcess(self) returned %08lx\n", Status);

    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.LogonProcess.ProcessId = 4;
    Message.Data.LogonProcess.Register = TRUE;
    Status = CallUser(&Message, 1031, sizeof(Message.Data.LogonProcess));
    ok(Status == STATUS_ACCESS_DENIED_, "UserpRegisterLogonProcess(4) returned %08lx\n", Status);

    /* Deregistering is for the logon process only (unchanged) */
    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.LogonProcess.ProcessId = Self;
    Message.Data.LogonProcess.Register = FALSE;
    Status = CallUser(&Message, 1031, sizeof(Message.Data.LogonProcess));
    ok(Status == STATUS_NOT_LOGON_PROCESS_, "UserpRegisterLogonProcess(deregister) returned %08lx\n", Status);

    /* The logon/logoff notification */
    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.Logon.IsLogon = TRUE;
    Status = CallUser(&Message, 1026, sizeof(Message.Data.Logon));
    ok(Status == STATUS_ACCESS_DENIED_, "UserpLogon(on) returned %08lx\n", Status);

    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data.Logon.IsLogon = FALSE;
    Status = CallUser(&Message, 1026, sizeof(Message.Data.Logon));
    ok(Status == STATUS_ACCESS_DENIED_, "UserpLogon(off) returned %08lx\n", Status);

    /* The user server still answers this process: a request any process may send */
    ok(GetDesktopWindow() != NULL, "GetDesktopWindow failed\n");
}
