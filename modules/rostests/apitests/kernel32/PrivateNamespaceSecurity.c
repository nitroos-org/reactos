/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Private namespace with a restrictive security descriptor, as the .NET Framework CLR creates
 *              for its IPC block (Cor_CLR_WRITER): a second process must be able to find and open it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The creator gives the namespace a DACL that allows only DIRECTORY_CREATE_OBJECT to Administrators and the
 * performance groups.  On Windows
 *  - CreatePrivateNamespace for a boundary that exists fails with ERROR_ALREADY_EXISTS (and does not open it),
 *  - OpenPrivateNamespace from another process succeeds with exactly the access the DACL allows.
 * A second managed process failed to start with CLR error 80070005 while one ran, because the namespace was
 * opened with DIRECTORY_ALL_ACCESS.
 */

#include "precomp.h"

typedef HANDLE (WINAPI *PFN_CreateBoundaryDescriptorW)(LPCWSTR, ULONG);
typedef BOOL (WINAPI *PFN_AddSIDToBoundaryDescriptor)(HANDLE *, PSID);
typedef VOID (WINAPI *PFN_DeleteBoundaryDescriptor)(HANDLE);
typedef HANDLE (WINAPI *PFN_CreatePrivateNamespaceW)(LPSECURITY_ATTRIBUTES, LPVOID, LPCWSTR);
typedef HANDLE (WINAPI *PFN_OpenPrivateNamespaceW)(LPVOID, LPCWSTR);
typedef BOOLEAN (WINAPI *PFN_ClosePrivateNamespace)(HANDLE, ULONG);

static PFN_CreateBoundaryDescriptorW pCreateBoundaryDescriptorW;
static PFN_AddSIDToBoundaryDescriptor pAddSIDToBoundaryDescriptor;
static PFN_DeleteBoundaryDescriptor pDeleteBoundaryDescriptor;
static PFN_CreatePrivateNamespaceW pCreatePrivateNamespaceW;
static PFN_OpenPrivateNamespaceW pOpenPrivateNamespaceW;
static PFN_ClosePrivateNamespace pClosePrivateNamespace;

static PSID AdminSid;

static HANDLE MakeBoundary(PCWSTR Name)
{
    HANDLE Boundary = pCreateBoundaryDescriptorW(Name, 0);

    ok(Boundary != NULL, "CreateBoundaryDescriptorW failed: %lu\n", GetLastError());
    if (Boundary)
        ok(pAddSIDToBoundaryDescriptor(&Boundary, AdminSid), "AddSIDToBoundaryDescriptor failed: %lu\n", GetLastError());
    return Boundary;
}

static ACCESS_MASK GrantedAccess(HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status = NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL);

    ok(NT_SUCCESS(Status), "NtQueryObject returned %lx\n", Status);
    return NT_SUCCESS(Status) ? Info.GrantedAccess : 0;
}

/* The second process: what the CLR does when it finds the namespace there */
static void RunChild(PCWSTR Alias, PCWSTR BoundaryName)
{
    HANDLE Boundary = MakeBoundary(BoundaryName), Ns;

    SetLastError(0xdeadbeef);
    Ns = pCreatePrivateNamespaceW(NULL, Boundary, Alias);
    ok(Ns == NULL, "child: creating an existing private namespace succeeded\n");
    ok(GetLastError() == ERROR_ALREADY_EXISTS, "child: create error %lu\n", GetLastError());
    if (Ns)
        pClosePrivateNamespace(Ns, 0);

    SetLastError(0xdeadbeef);
    Ns = pOpenPrivateNamespaceW(Boundary, Alias);
    ok(Ns != NULL, "child: OpenPrivateNamespaceW failed: %lu\n", GetLastError());
    if (Ns)
    {
        ACCESS_MASK Access = GrantedAccess(Ns);

        /* DIRECTORY_CREATE_OBJECT from the DACL, nothing beyond it and no DIRECTORY_QUERY/ALL_ACCESS */
        ok((Access & DIRECTORY_CREATE_OBJECT) != 0, "child: access %lx lacks DIRECTORY_CREATE_OBJECT\n", Access);
        ok((Access & (DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_SUBDIRECTORY)) == 0,
           "child: access %lx has more than the DACL allows\n", Access);
        pClosePrivateNamespace(Ns, 0);
    }
    pDeleteBoundaryDescriptor(Boundary);
}

START_TEST(PrivateNamespaceSecurity)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    WCHAR Alias[64], BoundaryName[64], FileName[MAX_PATH], CommandLine[2 * MAX_PATH + 160];
    UCHAR SdBuffer[sizeof(SECURITY_DESCRIPTOR)], AclBuffer[256];
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)SdBuffer;
    PACL Acl = (PACL)AclBuffer;
    SECURITY_ATTRIBUTES Sa = {sizeof(Sa), Sd, FALSE};
    STARTUPINFOW Si = {sizeof(Si)};
    PROCESS_INFORMATION Pi;
    HANDLE Boundary, Ns, Event;
    DWORD ExitCode;
    NTSTATUS Status;
    char **argv;
    int argc;

    pCreateBoundaryDescriptorW = (PVOID)GetProcAddress(Kernel32, "CreateBoundaryDescriptorW");
    pAddSIDToBoundaryDescriptor = (PVOID)GetProcAddress(Kernel32, "AddSIDToBoundaryDescriptor");
    pDeleteBoundaryDescriptor = (PVOID)GetProcAddress(Kernel32, "DeleteBoundaryDescriptor");
    pCreatePrivateNamespaceW = (PVOID)GetProcAddress(Kernel32, "CreatePrivateNamespaceW");
    pOpenPrivateNamespaceW = (PVOID)GetProcAddress(Kernel32, "OpenPrivateNamespaceW");
    pClosePrivateNamespace = (PVOID)GetProcAddress(Kernel32, "ClosePrivateNamespace");
    if (!pCreateBoundaryDescriptorW || !pAddSIDToBoundaryDescriptor || !pDeleteBoundaryDescriptor ||
        !pCreatePrivateNamespaceW || !pOpenPrivateNamespaceW || !pClosePrivateNamespace)
    {
        skip("Private namespace APIs are not available\n");
        return;
    }

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                         0, 0, 0, 0, 0, 0, &AdminSid);
    ok(NT_SUCCESS(Status), "RtlAllocateAndInitializeSid returned %lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "child"))
    {
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, Alias, _countof(Alias));
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, BoundaryName, _countof(BoundaryName));
        RunChild(Alias, BoundaryName);
        return;
    }

    StringCbPrintfW(Alias, sizeof(Alias), L"PnsSec%lu", GetCurrentProcessId());
    StringCbPrintfW(BoundaryName, sizeof(BoundaryName), L"PnsSecB%lu", GetCurrentProcessId());

    /* DACL: DIRECTORY_CREATE_OBJECT for Administrators only, like the CLR's */
    RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlCreateAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    Status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, DIRECTORY_CREATE_OBJECT, AdminSid);
    ok(NT_SUCCESS(Status), "RtlAddAccessAllowedAce returned %lx\n", Status);
    Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);
    ok(NT_SUCCESS(Status), "RtlSetDaclSecurityDescriptor returned %lx\n", Status);

    Boundary = MakeBoundary(BoundaryName);
    if (!Boundary)
        return;

    SetLastError(0xdeadbeef);
    Ns = pCreatePrivateNamespaceW(&Sa, Boundary, Alias);
    ok(Ns != NULL, "CreatePrivateNamespaceW failed: %lu\n", GetLastError());
    if (!Ns)
    {
        pDeleteBoundaryDescriptor(Boundary);
        return;
    }
    ok(GrantedAccess(Ns) == DIRECTORY_ALL_ACCESS, "creator access %lx\n", GrantedAccess(Ns));

    /* the namespace is usable for the creator */
    {
        WCHAR EventName[128];

        StringCbPrintfW(EventName, sizeof(EventName), L"%ls\\Evt", Alias);
        Event = CreateEventW(NULL, TRUE, FALSE, EventName);
        ok(Event != NULL, "CreateEventW in the namespace failed: %lu\n", GetLastError());
        if (Event)
            CloseHandle(Event);
    }

    /* same process, same boundary: the namespace exists */
    {
        HANDLE Again;

        SetLastError(0xdeadbeef);
        Again = pCreatePrivateNamespaceW(&Sa, Boundary, Alias);
        ok(Again == NULL, "creating the same private namespace twice succeeded\n");
        ok(GetLastError() == ERROR_ALREADY_EXISTS, "second create error %lu\n", GetLastError());
        if (Again)
            pClosePrivateNamespace(Again, 0);
    }

    /* the other process */
    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" PrivateNamespaceSecurity child %ls %ls",
                    FileName, Alias, BoundaryName);
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
    {
        ok(WaitForSingleObject(Pi.hProcess, 30000) == WAIT_OBJECT_0, "the child did not finish\n");
        ExitCode = 0xdeadbeef;
        GetExitCodeProcess(Pi.hProcess, &ExitCode);
        ok(ExitCode == 0, "the child reported failures (exit code %lu)\n", ExitCode);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
    }
    else
    {
        skip("CreateProcessW failed: %lu\n", GetLastError());
    }

    pClosePrivateNamespace(Ns, 0);
    pDeleteBoundaryDescriptor(Boundary);
    RtlFreeSid(AdminSid);
}
