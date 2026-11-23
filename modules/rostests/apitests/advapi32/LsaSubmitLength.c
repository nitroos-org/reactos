/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The LSA authentication port takes a submit buffer / authentication information of at most
 *              1 MiB (1048576 bytes) in LsaCallAuthenticationPackage and in LsaLogonUser, and answers
 *              STATUS_INVALID_PARAMETER at once for one byte more, without reading the caller's memory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (build 20348): lengths of 1048576 are accepted (LsaLogonUser: the logon of a user
 * that does not exist is STATUS_NO_SUCH_USER or STATUS_LOGON_FAILURE; LsaCallAuthenticationPackage with a
 * challenge request of an untrusted caller: STATUS_ACCESS_DENIED), 1048577 up to 0x7FFFFFFF and 0xFFFFFFFF are
 * STATUS_INVALID_PARAMETER (0xC000000D) in about no time, with a buffer of that size and with a buffer of 4096 bytes.
 */

#include "precomp.h"
#include <ntsecapi.h>

#define LIMIT 0x100000UL

/* secur32 exports, loaded at run time (advapi32_apitest does not import secur32) */
static NTSTATUS (NTAPI *pLsaConnectUntrusted)(PHANDLE);
static NTSTATUS (NTAPI *pLsaDeregisterLogonProcess)(HANDLE);
static NTSTATUS (NTAPI *pLsaLookupAuthenticationPackage)(HANDLE, PLSA_STRING, PULONG);
static NTSTATUS (NTAPI *pLsaCallAuthenticationPackage)(HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
static NTSTATUS (NTAPI *pLsaLogonUser)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG, PVOID, ULONG, PTOKEN_GROUPS,
                                       PTOKEN_SOURCE, PVOID *, PULONG, PLUID, PHANDLE, PQUOTA_LIMITS, PNTSTATUS);
static NTSTATUS (NTAPI *pLsaFreeReturnBuffer)(PVOID);
#define LsaConnectUntrusted pLsaConnectUntrusted
#define LsaDeregisterLogonProcess pLsaDeregisterLogonProcess
#define LsaLookupAuthenticationPackage pLsaLookupAuthenticationPackage
#define LsaCallAuthenticationPackage pLsaCallAuthenticationPackage
#define LsaLogonUser pLsaLogonUser
#define LsaFreeReturnBuffer pLsaFreeReturnBuffer

static HANDLE Lsa;
static ULONG Package;

static NTSTATUS
Call(PVOID Buffer, ULONG Length)
{
    PVOID Reply = NULL;
    ULONG ReplyLength = 0;
    NTSTATUS ProtocolStatus = 0;
    NTSTATUS Status;

    *(PULONG)Buffer = 3; /* MsV1_0Lm20ChallengeRequest */
    Status = LsaCallAuthenticationPackage(Lsa, Package, Buffer, Length, &Reply, &ReplyLength, &ProtocolStatus);
    if (Reply)
        LsaFreeReturnBuffer(Reply);
    return Status;
}

static NTSTATUS
Logon(PVOID Buffer, ULONG Length)
{
    LSA_STRING Origin;
    TOKEN_SOURCE Source;
    PVOID Profile = NULL;
    ULONG ProfileLength = 0;
    LUID Luid;
    HANDLE Token = NULL;
    QUOTA_LIMITS Quotas;
    NTSTATUS SubStatus = 0;
    NTSTATUS Status;
    MSV1_0_INTERACTIVE_LOGON *Info = Buffer;
    WCHAR *Domain = (WCHAR *)((PBYTE)Buffer + sizeof(*Info)), *User = Domain + 8, *Password = User + 16;

    RtlZeroMemory(Info, sizeof(*Info));
    memcpy(Domain, L"LSALEN", 14);
    memcpy(User, L"lsalenNoUser", 26);
    memcpy(Password, L"x", 2);
    Info->MessageType = MsV1_0InteractiveLogon;
    Info->LogonDomainName.Length = 12; Info->LogonDomainName.MaximumLength = 14;
    Info->LogonDomainName.Buffer = (PWSTR)(ULONG_PTR)((PBYTE)Domain - (PBYTE)Buffer);
    Info->UserName.Length = 24; Info->UserName.MaximumLength = 26;
    Info->UserName.Buffer = (PWSTR)(ULONG_PTR)((PBYTE)User - (PBYTE)Buffer);
    Info->Password.Length = 2; Info->Password.MaximumLength = 2;
    Info->Password.Buffer = (PWSTR)(ULONG_PTR)((PBYTE)Password - (PBYTE)Buffer);

    Origin.Buffer = (PCHAR)"LsaLen";
    Origin.Length = 6;
    Origin.MaximumLength = 7;
    memcpy(Source.SourceName, "LsaLen\0\0", 8);
    AllocateLocallyUniqueId(&Source.SourceIdentifier);
    Status = LsaLogonUser(Lsa, &Origin, Interactive, Package, Buffer, Length, NULL, &Source, &Profile, &ProfileLength,
                          &Luid, &Token, &Quotas, &SubStatus);
    if (Profile)
        LsaFreeReturnBuffer(Profile);
    if (Token)
        CloseHandle(Token);
    return Status;
}

START_TEST(LsaSubmitLength)
{
    static const ULONG Over[] = { LIMIT + 1, LIMIT + 4096, 2 * LIMIT, 16 * LIMIT, 0x7FFFFFFF, 0xFFFFFFFF };
    LSA_STRING Name;
    NTSTATUS Status;
    PVOID Big, Small;
    ULONG i;

    {
        HMODULE hSecur32 = LoadLibraryW(L"secur32.dll");

        if (!hSecur32)
        {
            skip("secur32.dll is not available\n");
            return;
        }
        pLsaConnectUntrusted = (PVOID)GetProcAddress(hSecur32, "LsaConnectUntrusted");
        pLsaDeregisterLogonProcess = (PVOID)GetProcAddress(hSecur32, "LsaDeregisterLogonProcess");
        pLsaLookupAuthenticationPackage = (PVOID)GetProcAddress(hSecur32, "LsaLookupAuthenticationPackage");
        pLsaCallAuthenticationPackage = (PVOID)GetProcAddress(hSecur32, "LsaCallAuthenticationPackage");
        pLsaLogonUser = (PVOID)GetProcAddress(hSecur32, "LsaLogonUser");
        pLsaFreeReturnBuffer = (PVOID)GetProcAddress(hSecur32, "LsaFreeReturnBuffer");
        if (!pLsaConnectUntrusted || !pLsaDeregisterLogonProcess || !pLsaLookupAuthenticationPackage ||
            !pLsaCallAuthenticationPackage || !pLsaLogonUser || !pLsaFreeReturnBuffer)
        {
            skip("secur32.dll lacks an entry point\n");
            return;
        }
    }
    Status = LsaConnectUntrusted(&Lsa);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted 0x%08lx\n", Status);
    if (Status != STATUS_SUCCESS)
        return;
    Name.Buffer = (PCHAR)MSV1_0_PACKAGE_NAME;
    Name.Length = (USHORT)strlen(MSV1_0_PACKAGE_NAME);
    Name.MaximumLength = Name.Length + 1;
    Status = LsaLookupAuthenticationPackage(Lsa, &Name, &Package);
    ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage 0x%08lx\n", Status);

    Big = VirtualAlloc(NULL, 16 * LIMIT, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Small = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(Big && Small, "no memory\n");
    if (Big && Small)
    {
        /* The largest accepted length gets past the check */
        Status = Call(Big, LIMIT);
        ok(Status != STATUS_INVALID_PARAMETER, "LsaCallAuthenticationPackage with %lu bytes: 0x%08lx\n", LIMIT, Status);
        {
            /* the answer for the same logon information at a small length is the answer the largest length gets */
            NTSTATUS Small4k = Logon(Big, 4096);

            Status = Logon(Big, LIMIT);
            ok(Status == Small4k, "LsaLogonUser with %lu bytes: 0x%08lx, with 4096 bytes 0x%08lx\n", LIMIT, Status, Small4k);
        }

        for (i = 0; i < RTL_NUMBER_OF(Over); i++)
        {
            /* a buffer of the stated size where there is one (up to 16 MiB), a small one where there cannot be */
            PVOID Buffer = Over[i] <= 16 * LIMIT ? Big : Small;

            Status = Call(Buffer, Over[i]);
            ok(Status == STATUS_INVALID_PARAMETER, "LsaCallAuthenticationPackage with %lu bytes: 0x%08lx\n", Over[i], Status);
            Status = Logon(Buffer, Over[i]);
            ok(Status == STATUS_INVALID_PARAMETER, "LsaLogonUser with %lu bytes: 0x%08lx\n", Over[i], Status);
        }
    }
    if (Big)
        VirtualFree(Big, 0, MEM_RELEASE);
    if (Small)
        VirtualFree(Small, 0, MEM_RELEASE);
    LsaDeregisterLogonProcess(Lsa);
}
