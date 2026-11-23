/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A private namespace never exists with another descriptor than its final one
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The name of a namespace follows from its boundary, so anyone can look for it while it is being created.
 * A second thread of the same user spins on OpenPrivateNamespace (MAXIMUM_ALLOWED) for the boundary of the
 * current round while the first creates the namespace, and checks the access of every handle it gets against
 * what the namespace's final descriptor allows that thread. Two cases, each for many rounds:
 *  - DACL: the creator's security attributes allow Everyone only DIRECTORY_QUERY | DIRECTORY_TRAVERSE; the
 *    opener (the same token: owner rights READ_CONTROL | WRITE_DAC) must never get more;
 *  - label: a boundary with a High label, created by a High creator, and an opener impersonating a Medium copy
 *    of the token: the label refuses it every write right whatever the DACL (Everyone GENERIC_ALL) allows.
 * A namespace that was first created with the creator's default descriptor and changed afterwards gave the
 * opener the default DACL's access (all of it, for the creator's own user) in between. The test counts the
 * rounds in which the opener got a handle at all, so a run where it never met the namespace does not pass
 * for the wrong reason.
 *
 * Then the descriptor rows of a create (no race): an owner the creator may assign, one it may not
 * (STATUS_INVALID_OWNER), the creator's label replacing the boundary's, a SACL without a label leaving the
 * boundary's label, a label above the creator refused.
 */

#include "precomp.h"
#include <sddl.h>
#include <aclapi.h>

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

#ifndef PRIVATE_NAMESPACE_FLAG_DESTROY
#define PRIVATE_NAMESPACE_FLAG_DESTROY 0x00000001 /* Microsoft Learn, ClosePrivateNamespace */
#endif

#define DIR_WRITE (DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY | DELETE | WRITE_DAC | WRITE_OWNER)

static HANDLE MakeBoundary(PCWSTR Name, PCWSTR Label)
{
    HANDLE Boundary = pCreateBoundaryDescriptorW(Name, 0);
    PSID Sid;

    if (!Boundary)
        return NULL;
    if (ConvertStringSidToSidW(L"S-1-1-0", &Sid))
    {
        pAddSIDToBoundaryDescriptor(&Boundary, Sid);
        LocalFree(Sid);
    }
    if (Label && ConvertStringSidToSidW(Label, &Sid))
    {
        pAddIntegrityLabelToBoundaryDescriptor(&Boundary, Sid);
        LocalFree(Sid);
    }
    return Boundary;
}

static ACCESS_MASK GrantedAccess(HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;

    if (!NT_SUCCESS(NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL)))
        return 0;
    return Info.GrantedAccess;
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

/* Shared between the creator and the opener */
static HANDLE volatile g_Boundary;
static volatile LONG g_Round = -1, g_Spinning = -1, g_Stop = -1, g_Acked = -1, g_Quit;
static volatile LONG g_Early, g_Opened, g_RoundsOpened, g_FirstBad;
static ACCESS_MASK g_Forbidden;
static HANDLE g_OpenerToken; /* impersonated by the opener, or NULL */

static DWORD WINAPI OpenerThread(PVOID Unused)
{
    LONG Seen = -1;

    if (g_OpenerToken && !SetThreadToken(NULL, g_OpenerToken))
        return 1;
    while (!g_Quit)
    {
        LONG Round = g_Round;
        BOOL OpenedThisRound = FALSE;

        if (Round == Seen)
        {
            YieldProcessor();
            continue;
        }
        Seen = Round;
        InterlockedExchange(&g_Spinning, Round);
        while (g_Stop != Round && !g_Quit)
        {
            HANDLE Ns = pOpenPrivateNamespaceW(g_Boundary, L"HbkRaceOpener");

            if (Ns)
            {
                ACCESS_MASK Access = GrantedAccess(Ns);

                if (Access & g_Forbidden)
                {
                    if (InterlockedIncrement(&g_Early) == 1)
                        InterlockedExchange(&g_FirstBad, (LONG)Access);
                }
                InterlockedIncrement(&g_Opened);
                OpenedThisRound = TRUE;
                pClosePrivateNamespace(Ns, 0);
            }
        }
        if (OpenedThisRound)
            InterlockedIncrement(&g_RoundsOpened);
        InterlockedExchange(&g_Acked, Round);
    }
    RevertToSelf();
    return 0;
}

static void RunRace(PCWSTR Case, PCWSTR Sddl, PCWSTR Label, ULONG Rounds, HANDLE OpenerToken, ACCESS_MASK Forbidden)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    HANDLE Thread;
    ULONG Round, Created = 0, Failed = 0;
    DWORD LastError = 0;
    WCHAR Name[64];

    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL),
       "%ls: SDDL %ls: %lu\n", Case, Sddl, GetLastError());
    g_Round = g_Spinning = g_Stop = g_Acked = -1;
    g_Quit = 0;
    g_Early = g_Opened = g_RoundsOpened = g_FirstBad = 0;
    g_Forbidden = Forbidden;
    g_OpenerToken = OpenerToken;
    Thread = CreateThread(NULL, 0, OpenerThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
        return;

    for (Round = 0; Round < Rounds; Round++)
    {
        HANDLE Boundary, Ns;

        StringCbPrintfW(Name, sizeof(Name), L"HbkRace-%ls-%lu-%lu", Case, GetCurrentProcessId(), Round);
        Boundary = MakeBoundary(Name, Label);
        if (!Boundary)
        {
            Failed++;
            continue;
        }
        g_Boundary = Boundary;
        InterlockedExchange(&g_Round, (LONG)Round);
        while (g_Spinning != (LONG)Round)
            YieldProcessor();

        Ns = pCreatePrivateNamespaceW(&Sa, Boundary, L"HbkRace");
        if (Ns)
            Created++;
        else
        {
            Failed++;
            LastError = GetLastError();
        }
        /* Let the opener meet the finished namespace too, then end the round */
        Sleep(0);
        InterlockedExchange(&g_Stop, (LONG)Round);
        while (g_Acked != (LONG)Round)
            YieldProcessor();
        if (Ns)
            pClosePrivateNamespace(Ns, PRIVATE_NAMESPACE_FLAG_DESTROY);
        pDeleteBoundaryDescriptor(Boundary);
    }
    InterlockedExchange(&g_Quit, 1);
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);
    LocalFree(Sa.lpSecurityDescriptor);

    trace("%ls: %lu rounds, %lu created, %lu failed (last %lu); the opener got %ld handles in %ld rounds, %ld with more "
          "access than the final descriptor allows (first 0x%lx)\n",
          Case, Rounds, Created, Failed, LastError, g_Opened, g_RoundsOpened, g_Early, (ULONG)g_FirstBad);
    ok(Created == Rounds, "%ls: %lu of %lu creates failed (last error %lu)\n", Case, Failed, Rounds, LastError);
    ok(g_Early == 0, "%ls: %ld handles had access 0x%lx (or other access) the final descriptor does not allow\n",
       Case, g_Early, (ULONG)g_FirstBad);
    ok(g_RoundsOpened > 0, "%ls: the opener never got a handle: the race did not run\n", Case);
}

/* The descriptor of a new namespace: its owner and label (Sddl: the creator's security attributes or NULL) */
static DWORD CreateAndRead(PCWSTR Name, PCWSTR BoundaryLabel, PCWSTR Sddl, PWSTR *Result)
{
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    PSECURITY_DESCRIPTOR Sd = NULL;
    HANDLE Boundary, Ns;
    DWORD Error = 0;

    *Result = NULL;
    if (Sddl && !ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL))
        return GetLastError() | 0x80000000;
    Boundary = MakeBoundary(Name, BoundaryLabel);
    SetLastError(0xdeadbeef);
    Ns = pCreatePrivateNamespaceW(Sddl ? &Sa : NULL, Boundary, L"HbkRows");
    if (!Ns)
        Error = GetLastError();
    else
    {
        if (GetSecurityInfo(Ns, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                            NULL, NULL, NULL, NULL, &Sd) == ERROR_SUCCESS)
        {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1,
                                                                 OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                                                                 Result, NULL);
            LocalFree(Sd);
        }
        pClosePrivateNamespace(Ns, PRIVATE_NAMESPACE_FLAG_DESTROY);
    }
    pDeleteBoundaryDescriptor(Boundary);
    if (Sa.lpSecurityDescriptor)
        LocalFree(Sa.lpSecurityDescriptor);
    return Error;
}

static void Rows(DWORD Level)
{
    PWSTR Text;
    DWORD Error;

    /* An owner the creator may assign (its user) */
    {
        HANDLE Token;
        UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
        DWORD Size;
        PWSTR User = NULL;
        WCHAR Sddl[256];

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        {
            if (GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Size))
                ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &User);
            CloseHandle(Token);
        }
        if (User)
        {
            StringCbPrintfW(Sddl, sizeof(Sddl), L"O:%lsD:(A;;GA;;;WD)", User);
            Error = CreateAndRead(L"HbkRowOwn", NULL, Sddl, &Text);
            ok(Error == 0, "own user as owner: error %lu\n", Error);
            if (Text)
            {
                /* SDDL writes a well-known account by its alias (LA for the built-in Administrator) */
                PSECURITY_DESCRIPTOR Sd = NULL;
                PSID Owner = NULL, Expected = ((PTOKEN_USER)Buffer)->User.Sid;
                BOOL Defaulted;

                ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Text, SDDL_REVISION_1, &Sd, NULL) &&
                   GetSecurityDescriptorOwner(Sd, &Owner, &Defaulted) && Owner && EqualSid(Owner, Expected),
                   "own user as owner: %ls\n", Text);
                if (Sd)
                    LocalFree(Sd);
            }
            else
            {
                ok(FALSE, "own user as owner: no descriptor\n");
            }
            if (Text)
                LocalFree(Text);
            LocalFree(User);
        }
    }

    /* An owner it may not assign: LocalService, no SeRestorePrivilege enabled */
    Error = CreateAndRead(L"HbkRowOwnLs", NULL, L"O:LSD:(A;;GA;;;WD)", &Text);
    ok(Error == ERROR_INVALID_OWNER, "LocalService as owner: error %lu, expected ERROR_INVALID_OWNER\n", Error);
    if (Text)
        LocalFree(Text);

    /* The creator's label replaces the boundary's (Low below a Medium boundary label) */
    Error = CreateAndRead(L"HbkRowLow", L"S-1-16-8192", L"D:(A;;GA;;;WD)S:(ML;;NW;;;LW)", &Text);
    ok(Error == 0, "creator's Low label: error %lu\n", Error);
    ok(Text && wcsstr(Text, L"(ML;;NW;;;LW)") && !wcsstr(Text, L";;;ME)"), "creator's Low label: %ls\n",
       Text ? Text : L"(none)");
    if (Text)
        LocalFree(Text);

    /* A SACL without a label leaves the boundary's label */
    Error = CreateAndRead(L"HbkRowNoLabel", L"S-1-16-8192", L"D:(A;;GA;;;WD)S:", &Text);
    ok(Error == 0, "SACL without a label: error %lu\n", Error);
    ok(Text && wcsstr(Text, L"(ML;;NW;;;ME)"), "SACL without a label: %ls\n", Text ? Text : L"(none)");
    if (Text)
        LocalFree(Text);

    /* No security attributes: the boundary's label */
    Error = CreateAndRead(L"HbkRowNone", L"S-1-16-8192", NULL, &Text);
    ok(Error == 0, "no attributes: error %lu\n", Error);
    ok(Text && wcsstr(Text, L"(ML;;NW;;;ME)"), "no attributes: %ls\n", Text ? Text : L"(none)");
    if (Text)
        LocalFree(Text);

    /* A label above the creator's own level */
    if (Level < SECURITY_MANDATORY_SYSTEM_RID)
    {
        Error = CreateAndRead(L"HbkRowAbove", NULL, L"D:(A;;GA;;;WD)S:(ML;;NW;;;SI)", &Text);
        ok(Error != 0, "a System label from a creator at 0x%lx was accepted: %ls\n", Level, Text ? Text : L"(none)");
        trace("System label from 0x%lx: error %lu\n", Level, Error);
        if (Text)
            LocalFree(Text);
    }
}

START_TEST(PrivateNamespaceRace)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    ULONG Rounds = 3000;
    WCHAR Env[16];
    DWORD Level;

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
        skip("private namespace functions not available\n");
        return;
    }
    if (GetEnvironmentVariableW(L"HBK_RACE_ROUNDS", Env, _countof(Env)))
        Rounds = wcstoul(Env, NULL, 10);
    Level = TokenLevel();

    /* The DACL case: the opener is the creator's own token */
    RunRace(L"dacl", L"D:(A;;0x3;;;WD)", NULL, Rounds, NULL, ~(DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL | WRITE_DAC) & ~MAXIMUM_ALLOWED);

    /* The label case: a High boundary label, the opener at Medium */
    if (Level >= SECURITY_MANDATORY_HIGH_RID)
    {
        HANDLE Token = NULL, Medium = NULL;
        TOKEN_MANDATORY_LABEL Label = {{0}};
        PSID MediumSid = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token) &&
            DuplicateTokenEx(Token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &Medium) &&
            ConvertStringSidToSidW(L"S-1-16-8192", &MediumSid))
        {
            Label.Label.Attributes = SE_GROUP_INTEGRITY;
            Label.Label.Sid = MediumSid;
            ok(SetTokenInformation(Medium, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid(MediumSid)),
               "SetTokenInformation failed: %lu\n", GetLastError());
            RunRace(L"label", L"D:(A;;GA;;;WD)", L"S-1-16-12288", Rounds, Medium, DIR_WRITE);
        }
        else
        {
            skip("no Medium copy of the token: %lu\n", GetLastError());
        }
        if (MediumSid)
            LocalFree(MediumSid);
        if (Medium)
            CloseHandle(Medium);
        if (Token)
            CloseHandle(Token);
    }
    else
    {
        skip("the label case needs a High creator (level 0x%lx)\n", Level);
    }

    Rows(Level);
}
