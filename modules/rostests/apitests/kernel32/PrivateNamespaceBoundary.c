/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Private namespaces are isolated by their boundary descriptor
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Microsoft Learn ("Object Namespaces", CreatePrivateNamespaceW, AddIntegrityLabelToBoundaryDescriptor): a namespace
 * is identified by its name and its boundary (the same name with other boundaries is another namespace); it can be
 * created only by a caller within the boundary (every SID; a label not above the caller's level); a boundary must have
 * a SID; a caller outside the boundary may open an existing namespace with what its security descriptor grants.
 * The Low child (a copy of the test's token lowered to Low) checks the last two against a namespace the test made.
 * Rows not measured on Windows (the documentation only): the error codes, and the access a Low opener gets.
 */

#include "precomp.h"
#include <sddl.h>

typedef HANDLE (WINAPI *PFN_CreateBoundaryDescriptorW)(LPCWSTR, ULONG);
typedef BOOL (WINAPI *PFN_AddSIDToBoundaryDescriptor)(HANDLE *, PSID);
typedef BOOL (WINAPI *PFN_AddIntegrityLabelToBoundaryDescriptor)(HANDLE *, PSID);
typedef VOID (WINAPI *PFN_DeleteBoundaryDescriptor)(HANDLE);
typedef HANDLE (WINAPI *PFN_CreatePrivateNamespaceW)(LPSECURITY_ATTRIBUTES, LPVOID, LPCWSTR);
typedef HANDLE (WINAPI *PFN_OpenPrivateNamespaceW)(LPVOID, LPCWSTR);
typedef BOOLEAN (WINAPI *PFN_ClosePrivateNamespace)(HANDLE, ULONG);

static PFN_CreateBoundaryDescriptorW pCreateBoundaryDescriptorW;
static PFN_AddSIDToBoundaryDescriptor pAddSIDToBoundaryDescriptor;
static PFN_AddIntegrityLabelToBoundaryDescriptor pAddIntegrityLabelToBoundaryDescriptor;
static PFN_DeleteBoundaryDescriptor pDeleteBoundaryDescriptor;
static PFN_CreatePrivateNamespaceW pCreatePrivateNamespaceW;
static PFN_OpenPrivateNamespaceW pOpenPrivateNamespaceW;
static PFN_ClosePrivateNamespace pClosePrivateNamespace;

/* A boundary: the name, the SID (an SDDL string, or NULL for none) and the label (an SDDL string, or NULL) */
static HANDLE MakeBoundary(PCWSTR Name, PCWSTR SidString, PCWSTR LabelString)
{
    HANDLE Boundary = pCreateBoundaryDescriptorW(Name, 0);
    PSID Sid;

    ok(Boundary != NULL, "CreateBoundaryDescriptorW failed: %lu\n", GetLastError());
    if (!Boundary)
        return NULL;
    if (SidString && ConvertStringSidToSidW(SidString, &Sid))
    {
        ok(pAddSIDToBoundaryDescriptor(&Boundary, Sid), "AddSIDToBoundaryDescriptor failed: %lu\n", GetLastError());
        LocalFree(Sid);
    }
    if (LabelString && ConvertStringSidToSidW(LabelString, &Sid))
    {
        ok(pAddIntegrityLabelToBoundaryDescriptor(&Boundary, Sid), "AddIntegrityLabel failed: %lu\n", GetLastError());
        LocalFree(Sid);
    }
    return Boundary;
}

static ACCESS_MASK GrantedAccess(HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status = NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL);

    ok(NT_SUCCESS(Status), "NtQueryObject returned %lx\n", Status);
    return NT_SUCCESS(Status) ? Info.GrantedAccess : 0;
}

static DWORD TokenLevel(VOID)
{
    UCHAR Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;
    HANDLE Token;
    DWORD Size, Level = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        if (GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Size))
            Level = *GetSidSubAuthority(Label->Label.Sid, *GetSidSubAuthorityCount(Label->Label.Sid) - 1);
        CloseHandle(Token);
    }
    return Level;
}

/* Tries to create a namespace; returns the error (0 when it was made, then closed) */
static DWORD TryCreate(PCWSTR Name, PCWSTR Sid, PCWSTR Label, PCWSTR Alias)
{
    HANDLE Boundary = MakeBoundary(Name, Sid, Label), Ns;
    DWORD Error;

    if (!Boundary)
        return 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ns = pCreatePrivateNamespaceW(NULL, Boundary, Alias);
    Error = Ns ? 0 : GetLastError();
    if (Ns)
        pClosePrivateNamespace(Ns, 0);
    pDeleteBoundaryDescriptor(Boundary);
    return Error;
}

/* The Low child: argv[3] the boundary name of the namespace the parent holds (Everyone, Medium label) */
static void RunLowChild(PCWSTR Name)
{
    WCHAR Text[MAX_PATH];
    UNICODE_STRING RootName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Boundary, Ns, Event, Directory;
    NTSTATUS Status;
    DWORD Error;

    ok(TokenLevel() == SECURITY_MANDATORY_LOW_RID, "child: level %#lx, not Low\n", TokenLevel());

    /* Not within a boundary with a Medium label, nor with a SID it does not hold */
    Error = TryCreate(L"PnsLowMedium", L"S-1-1-0", L"S-1-16-8192", L"LowA");
    ok(Error == ERROR_ACCESS_DENIED, "child: create with a Medium label: error %lu\n", Error);
    Error = TryCreate(L"PnsLowSid", L"S-1-5-21-1-2-3-4242", L"S-1-16-4096", L"LowB");
    ok(Error == ERROR_ACCESS_DENIED, "child: create with a SID it does not hold: error %lu\n", Error);
    /* Within its own boundary */
    Error = TryCreate(L"PnsLowOwn", L"S-1-1-0", L"S-1-16-4096", L"LowC");
    ok(Error == 0, "child: create with a Low label: error %lu\n", Error);

    /* The parent's namespace (Medium label): opened with what its descriptor and label leave a Low caller */
    Boundary = MakeBoundary(Name, L"S-1-1-0", L"S-1-16-8192");
    SetLastError(0xdeadbeef);
    Ns = pOpenPrivateNamespaceW(Boundary, L"Up");
    ok(Ns != NULL, "child: OpenPrivateNamespaceW failed: %lu\n", GetLastError());
    if (Ns)
    {
        ACCESS_MASK Access = GrantedAccess(Ns);

        ok((Access & (DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY | WRITE_DAC | WRITE_OWNER | DELETE)) == 0,
           "child: access %#lx to a Medium namespace\n", Access);
        /* so it cannot put an object of its own there */
        SetLastError(0xdeadbeef);
        Event = CreateEventW(NULL, TRUE, FALSE, L"Up\\Planted");
        ok(Event == NULL, "child: created an event in the Medium namespace\n");
        ok(GetLastError() == ERROR_ACCESS_DENIED, "child: error %lu\n", GetLastError());
        if (Event)
            CloseHandle(Event);
        /* the parent's object is there, through the alias */
        Event = OpenEventW(SYNCHRONIZE, FALSE, L"Up\\Evt");
        ok(Event != NULL, "child: OpenEventW of the parent's event failed: %lu\n", GetLastError());
        if (Event)
            CloseHandle(Event);
        pClosePrivateNamespace(Ns, 0);
    }
    pDeleteBoundaryDescriptor(Boundary);

    /* Nobody but the kernel makes a namespace directory: no squatting of a boundary's name */
    StringCbPrintfW(Text, sizeof(Text), L"\\PrivateNamespaces\\Squat%lu", GetCurrentProcessId());
    RtlInitUnicodeString(&RootName, Text);
    InitializeObjectAttributes(&Attributes, &RootName, 0, NULL, NULL);
    Status = NtCreateDirectoryObject(&Directory, DIRECTORY_ALL_ACCESS, &Attributes);
    ok(Status == STATUS_ACCESS_DENIED, "child: NtCreateDirectoryObject in the root returned %lx\n", Status);
    if (NT_SUCCESS(Status))
        CloseHandle(Directory);
}

static BOOL StartLowChild(PCWSTR Name, PDWORD ExitCode)
{
    SID_IDENTIFIER_AUTHORITY MandatoryAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    WCHAR FileName[MAX_PATH], CommandLine[2 * MAX_PATH + 100];
    STARTUPINFOW Si = {sizeof(Si)};
    PROCESS_INFORMATION Pi;
    TOKEN_MANDATORY_LABEL Label = {{0}};
    HANDLE Token, LowToken;
    PSID LowSid;
    BOOL Ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
                          &Token))
        return FALSE;
    if (DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &LowToken))
    {
        AllocateAndInitializeSid(&MandatoryAuthority, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &LowSid);
        Label.Label.Attributes = SE_GROUP_INTEGRITY;
        Label.Label.Sid = LowSid;
        if (SetTokenInformation(LowToken, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(LowSid)))
        {
            GetModuleFileNameW(NULL, FileName, _countof(FileName));
            StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" PrivateNamespaceBoundary child %ls", FileName, Name);
            if (CreateProcessAsUserW(LowToken, NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
            {
                ok(WaitForSingleObject(Pi.hProcess, 30000) == WAIT_OBJECT_0, "the child did not finish\n");
                *ExitCode = 0xdeadbeef;
                GetExitCodeProcess(Pi.hProcess, ExitCode);
                CloseHandle(Pi.hThread);
                CloseHandle(Pi.hProcess);
                Ret = TRUE;
            }
            else
            {
                skip("CreateProcessAsUserW failed: %lu\n", GetLastError());
            }
        }
        FreeSid(LowSid);
        CloseHandle(LowToken);
    }
    CloseHandle(Token);
    return Ret;
}

START_TEST(PrivateNamespaceBoundary)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    WCHAR Name[64], Name2[64], Above[32];
    HANDLE B1, B2, BOther, Ns1, Ns2, Ns, Event1, Event;
    DWORD Level, Error, ExitCode;
    char **argv;
    int argc;

    pCreateBoundaryDescriptorW = (PVOID)GetProcAddress(Kernel32, "CreateBoundaryDescriptorW");
    pAddSIDToBoundaryDescriptor = (PVOID)GetProcAddress(Kernel32, "AddSIDToBoundaryDescriptor");
    pAddIntegrityLabelToBoundaryDescriptor = (PVOID)GetProcAddress(Kernel32, "AddIntegrityLabelToBoundaryDescriptor");
    pDeleteBoundaryDescriptor = (PVOID)GetProcAddress(Kernel32, "DeleteBoundaryDescriptor");
    pCreatePrivateNamespaceW = (PVOID)GetProcAddress(Kernel32, "CreatePrivateNamespaceW");
    pOpenPrivateNamespaceW = (PVOID)GetProcAddress(Kernel32, "OpenPrivateNamespaceW");
    pClosePrivateNamespace = (PVOID)GetProcAddress(Kernel32, "ClosePrivateNamespace");
    if (!pCreateBoundaryDescriptorW || !pAddSIDToBoundaryDescriptor || !pAddIntegrityLabelToBoundaryDescriptor ||
        !pDeleteBoundaryDescriptor || !pCreatePrivateNamespaceW || !pOpenPrivateNamespaceW || !pClosePrivateNamespace)
    {
        skip("Private namespace APIs are not available\n");
        return;
    }

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, Name, _countof(Name));
        RunLowChild(Name);
        return;
    }

    Level = TokenLevel();
    ok(Level >= SECURITY_MANDATORY_MEDIUM_RID, "level %#lx: the test needs Medium or above\n", Level);
    StringCbPrintfW(Name, sizeof(Name), L"PnsB%lu", GetCurrentProcessId());
    StringCbPrintfW(Name2, sizeof(Name2), L"PnsC%lu", GetCurrentProcessId());

    /* 1. The same name, other SIDs: two namespaces; their objects are apart */
    B1 = MakeBoundary(Name, L"S-1-1-0", L"S-1-16-8192");
    B2 = MakeBoundary(Name, L"S-1-5-11", NULL);
    Ns1 = pCreatePrivateNamespaceW(NULL, B1, L"One");
    ok(Ns1 != NULL, "create (Everyone, Medium): error %lu\n", GetLastError());
    Ns2 = pCreatePrivateNamespaceW(NULL, B2, L"Two");
    ok(Ns2 != NULL, "create (Authenticated Users), same name: error %lu\n", GetLastError());
    Event1 = CreateEventW(NULL, TRUE, FALSE, L"One\\Evt");
    ok(Event1 != NULL, "CreateEventW in the first namespace: error %lu\n", GetLastError());
    ok(GetLastError() == ERROR_SUCCESS, "the event existed (%lu)\n", GetLastError());
    SetLastError(0xdeadbeef);
    Event = OpenEventW(SYNCHRONIZE, FALSE, L"Two\\Evt");
    ok(Event == NULL, "the event of the first namespace is in the second\n");
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "error %lu\n", GetLastError());
    if (Event)
        CloseHandle(Event);
    /* ... nor in BaseNamedObjects under the alias */
    Event = OpenEventW(SYNCHRONIZE, FALSE, L"Gone\\Evt");
    ok(Event == NULL, "an alias that names no namespace found the event\n");
    if (Event)
        CloseHandle(Event);

    /* 2. The SIDs are a set: the same boundary made in another order is the same namespace */
    {
        HANDLE BSame = pCreateBoundaryDescriptorW(Name, 0);
        PSID Sid;

        ConvertStringSidToSidW(L"S-1-16-8192", &Sid);
        pAddIntegrityLabelToBoundaryDescriptor(&BSame, Sid);
        LocalFree(Sid);
        ConvertStringSidToSidW(L"S-1-1-0", &Sid);
        pAddSIDToBoundaryDescriptor(&BSame, Sid);
        pAddSIDToBoundaryDescriptor(&BSame, Sid);
        LocalFree(Sid);
        SetLastError(0xdeadbeef);
        Ns = pCreatePrivateNamespaceW(NULL, BSame, L"Same");
        ok(Ns == NULL && GetLastError() == ERROR_ALREADY_EXISTS, "the same boundary again: %p, error %lu\n", Ns,
           GetLastError());
        if (Ns)
            pClosePrivateNamespace(Ns, 0);
        Ns = pOpenPrivateNamespaceW(BSame, L"Same");
        ok(Ns != NULL, "open with the same boundary: error %lu\n", GetLastError());
        if (Ns)
        {
            Event = OpenEventW(SYNCHRONIZE, FALSE, L"Same\\Evt");
            ok(Event != NULL, "the event through the second alias: error %lu\n", GetLastError());
            if (Event)
                CloseHandle(Event);
            pClosePrivateNamespace(Ns, 0);
        }
        pDeleteBoundaryDescriptor(BSame);
    }

    /* 3. Another name, the same SIDs: not found */
    BOther = MakeBoundary(Name2, L"S-1-1-0", L"S-1-16-8192");
    SetLastError(0xdeadbeef);
    Ns = pOpenPrivateNamespaceW(BOther, L"Other");
    ok(Ns == NULL, "a boundary with another name opened the namespace\n");
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "error %lu\n", GetLastError());
    if (Ns)
        pClosePrivateNamespace(Ns, 0);
    pDeleteBoundaryDescriptor(BOther);

    /* 4. Creation is for callers within the boundary */
    Error = TryCreate(Name2, L"S-1-5-21-1-2-3-4242", NULL, L"Foreign");
    ok(Error == ERROR_ACCESS_DENIED, "create with a SID the caller does not hold: error %lu\n", Error);
    StringCbPrintfW(Above, sizeof(Above), L"S-1-16-%lu", Level + 0x1000);
    Error = TryCreate(Name2, L"S-1-1-0", Above, L"Above");
    ok(Error == ERROR_ACCESS_DENIED, "create with a label above the caller's level: error %lu\n", Error);
    Error = TryCreate(Name2, NULL, L"S-1-16-8192", L"NoSid");
    ok(Error == ERROR_INVALID_PARAMETER, "create without a SID: error %lu\n", Error);
    Error = TryCreate(Name2, L"S-1-1-0", L"S-1-16-4096", L"Lower");
    ok(Error == 0, "create with a label below the caller's level: error %lu\n", Error);

    /* 4b. A thread impersonating below SecurityImpersonation is not within anyone's boundary: refused, as an
       access check refuses it (Windows not measured: the stricter choice). At SecurityImpersonation it is
       judged by the token it impersonates (here its own) */
    {
        static const SECURITY_IMPERSONATION_LEVEL Levels[] = { SecurityAnonymous, SecurityIdentification, SecurityImpersonation };
        ULONG i;

        for (i = 0; i < _countof(Levels); i++)
        {
            if (!ImpersonateSelf(Levels[i]))
            {
                skip("ImpersonateSelf(%d) failed: %lu\n", Levels[i], GetLastError());
                continue;
            }
            Error = TryCreate(Name2, L"S-1-1-0", NULL, L"Imp");
            RevertToSelf();
            if (Levels[i] < SecurityImpersonation)
                ok(Error == ERROR_BAD_IMPERSONATION_LEVEL, "create impersonating at level %d: error %lu\n", Levels[i], Error);
            else
                ok(Error == 0, "create impersonating at level %d: error %lu\n", Levels[i], Error);
        }
    }

    /* 5. The Low child against the first namespace (held open here) */
    if (StartLowChild(Name, &ExitCode))
        ok(ExitCode == 0, "the child reported %lu failures\n", ExitCode);

    if (Event1)
        CloseHandle(Event1);
    if (Ns2)
        pClosePrivateNamespace(Ns2, 0);
    if (Ns1)
        pClosePrivateNamespace(Ns1, 0);

    /* 6. Gone with its last handle */
    SetLastError(0xdeadbeef);
    Ns = pOpenPrivateNamespaceW(B1, L"Again");
    ok(Ns == NULL, "the namespace outlived its handles\n");
    if (Ns)
        pClosePrivateNamespace(Ns, 0);
    pDeleteBoundaryDescriptor(B2);
    pDeleteBoundaryDescriptor(B1);
}
