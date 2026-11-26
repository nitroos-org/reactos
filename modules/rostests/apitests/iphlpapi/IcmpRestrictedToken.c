/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A token whose only restricting SID is the restricted code SID (RC): it opens \Device\Ip and
 *              \Device\Ip6 for read and execute, which is what IcmpCreateFile needs, and nothing wider; the TCP,
 *              UDP and raw IP devices stay closed to it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (measured, the same program on the reference): with such a token \Device\Ip and \Device\Ip6
 * open for 0x1200a9 and for FILE_READ_DATA | SYNCHRONIZE (0x100001) and fail with STATUS_ACCESS_DENIED for
 * 0x1201bf, 0x120116 and 0x1f01ff; \Device\Tcp, \Device\Tcp6, \Device\Udp, \Device\RawIp and \Device\RawIp6 fail
 * for every one of these accesses; IcmpSendEcho to 127.0.0.1 gets its reply.
 */

#include <apitest.h>
#include <ndk/ntndk.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#define STATUS_ACCESS_DENIED_ROW ((NTSTATUS)0xC0000022)

static NTSTATUS OpenDevice(PCWSTR Path, ACCESS_MASK Access)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Handle;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Handle, Access, &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    if (NT_SUCCESS(Status))
        NtClose(Handle);
    return Status;
}

static void CheckRow(PCWSTR Path, ACCESS_MASK Access, BOOLEAN ExpectOpen)
{
    NTSTATUS Status = OpenDevice(Path, Access);

    if (ExpectOpen)
        ok(NT_SUCCESS(Status), "%ls with 0x%lx: 0x%08lx, expected success\n", Path, Access, Status);
    else
        /* \Device\Tcp6 and \Device\RawIp6 do not exist here (STATUS_OBJECT_NAME_NOT_FOUND): nothing to open */
        ok(Status == STATUS_ACCESS_DENIED_ROW || Status == ((NTSTATUS)0xC0000034),
           "%ls with 0x%lx: 0x%08lx, expected access denied\n", Path, Access, Status);
}

START_TEST(IcmpRestrictedToken)
{
    static const PCWSTR Closed[] = { L"\\Device\\Tcp", L"\\Device\\Tcp6", L"\\Device\\Udp", L"\\Device\\RawIp", L"\\Device\\RawIp6" };
    static const ACCESS_MASK Accesses[] = { 0x1200a9, 0x1201bf, 0x100001, 0x120116, 0x1f01ff };
    HANDLE Token, Restricted, Impersonation, Icmp;
    UCHAR SidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD SidLength = sizeof(SidBuffer), Replies;
    SID_AND_ATTRIBUTES Restrict;
    UCHAR Reply[512];
    CHAR Data[8] = "abcdefg";
    ULONG i, j;

    if (!CreateWellKnownSid(WinRestrictedCodeSid, NULL, SidBuffer, &SidLength) ||
        !OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &Token))
    {
        skip("no token: %lu\n", GetLastError());
        return;
    }
    Restrict.Sid = (PSID)SidBuffer;
    Restrict.Attributes = 0;
    if (!CreateRestrictedToken(Token, 0, 0, NULL, 0, NULL, 1, &Restrict, &Restricted) ||
        !DuplicateTokenEx(Restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation))
    {
        skip("CreateRestrictedToken: %lu\n", GetLastError());
        CloseHandle(Token);
        return;
    }
    ok(SetThreadToken(NULL, Impersonation), "SetThreadToken: %lu\n", GetLastError());

    for (j = 0; j < RTL_NUMBER_OF(Accesses); j++)
    {
        CheckRow(L"\\Device\\Ip", Accesses[j], Accesses[j] == 0x1200a9 || Accesses[j] == 0x100001);
        CheckRow(L"\\Device\\Ip6", Accesses[j], Accesses[j] == 0x1200a9 || Accesses[j] == 0x100001);
        for (i = 0; i < RTL_NUMBER_OF(Closed); i++)
            CheckRow(Closed[i], Accesses[j], FALSE);
    }

    Icmp = IcmpCreateFile();
    ok(Icmp != INVALID_HANDLE_VALUE, "IcmpCreateFile: %lu\n", GetLastError());
    if (Icmp != INVALID_HANDLE_VALUE)
    {
        Replies = IcmpSendEcho(Icmp, 0x0100007f, Data, 7, NULL, Reply, sizeof(Reply), 2000);
        ok(Replies == 1, "IcmpSendEcho: %lu replies, error %lu\n", Replies, GetLastError());
        IcmpCloseHandle(Icmp);
    }

    RevertToSelf();
    CloseHandle(Impersonation);
    CloseHandle(Restricted);
    CloseHandle(Token);
}
