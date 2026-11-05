/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for kernel32 exports of Windows 8 and Windows 10 that were missing: GlobalAddAtomEx,
 *              the synchronization barrier, CheckTokenMembershipEx, CheckTokenCapability, GetAppContainerAce,
 *              AddScopedPolicyIDAce, AddIntegrityLabelToBoundaryDescriptor, the NUMA handle functions, the threadpool
 *              stack information, GetDiskSpaceInformation, the local time conversions,
 *              DnsHostnameToComputerNameExW and the small system queries
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every expected value was measured on Windows 10 22H2 (x64 and x86) with a probe program (evidence of the ticket
 * EXPORTS-kernel32-missing). These are the contracts through which programs import the names (api-ms-win-security-base-l1-2-x,
 * api-ms-win-core-timezone-l1-1-1, api-ms-win-core-file-l1-2-3, ...).
 */

#include "precomp.h"
#include <pseh/pseh2.h>

typedef struct _TEST_BARRIER { DWORD a, b; ULONG_PTR c[2]; DWORD d, e; } TEST_BARRIER;
typedef struct _TEST_DISK_SPACE
{
    ULONGLONG v[11];
    DWORD SectorsPerAllocationUnit;
    DWORD BytesPerSector;
} TEST_DISK_SPACE;
typedef struct _TEST_TP_STACK { SIZE_T Reserve; SIZE_T Commit; } TEST_TP_STACK;

#define SPIN_ONLY 1
#define BLOCK_ONLY 2
#define NO_DELETE 4

static HMODULE g_Kernel32;

static FARPROC
Proc(const char *Name)
{
    return GetProcAddress(g_Kernel32, Name);
}

/* a SID with the authority n and the given subauthorities, in a buffer of 12 + 4 * 8 bytes */
static PSID
MakeSid(PVOID Buffer, UCHAR Authority, UCHAR Count, ...)
{
    PBYTE Bytes = Buffer;
    va_list List;
    UCHAR i;

    RtlZeroMemory(Bytes, 8 + 4 * 8);
    Bytes[0] = 1;
    Bytes[1] = Count;
    Bytes[7] = Authority;
    va_start(List, Count);
    for (i = 0; i < Count; i++)
        *(PDWORD)(Bytes + 8 + 4 * i) = va_arg(List, DWORD);
    va_end(List);
    return Buffer;
}

/* ------------------------------------------------------------------------------------------------ atoms */

static void
test_GlobalAddAtomEx(void)
{
    typedef ATOM (WINAPI *PFN_ExW)(LPCWSTR, DWORD);
    typedef ATOM (WINAPI *PFN_ExA)(LPCSTR, DWORD);
    PFN_ExW pW = (PVOID)Proc("GlobalAddAtomExW");
    PFN_ExA pA = (PVOID)Proc("GlobalAddAtomExA");
    DWORD Flags[] = {1, 0x10, 0xFFFFFFFF, 0x80000000, 3, 4};
    ATOM Atom;
    ULONG i;

    ok(pW && pA, "GlobalAddAtomExA/W are not exported\n");
    if (!pW || !pA)
        return;

    for (i = 0; i < RTL_NUMBER_OF(Flags); i++)
    {
        SetLastError(0xdeadbeef);
        Atom = pW(L"k32exp_atom_badflags", Flags[i]);
        ok(Atom == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "W flags %lx: atom %x, error %lu\n", Flags[i], Atom, GetLastError());
        SetLastError(0xdeadbeef);
        Atom = pA("k32exp_atom_badflags", Flags[i]);
        ok(Atom == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "A flags %lx: atom %x, error %lu\n", Flags[i], Atom, GetLastError());
    }

    /* 0 and 2 (ATOM_FLAG_GLOBAL) are the valid flags. The table can be out of reach of a service session
     * (ERROR_ACCESS_DENIED, which Windows 10 gives in session 0 and session 1 of a hardened machine). */
    for (i = 0; i < 2; i++)
    {
        DWORD Flag = i ? 2 : 0;

        SetLastError(0xdeadbeef);
        Atom = pW(L"k32exp_atom_ok", Flag);
        if (!Atom)
        {
            ok(GetLastError() == ERROR_ACCESS_DENIED, "flags %lx: error %lu\n", Flag, GetLastError());
            continue;
        }
        ok(Atom >= 0xC000, "atom %x\n", Atom);
        ok(GlobalFindAtomW(L"K32EXP_ATOM_OK") == Atom, "case insensitive find\n");
        ok(pA("k32exp_atom_ok", Flag) == Atom, "second add gives the same atom\n");
        ok(GlobalDeleteAtom(Atom) == 0, "delete 1\n");
        ok(GlobalFindAtomW(L"k32exp_atom_ok") == Atom, "reference count 2 -> 1\n");
        ok(GlobalDeleteAtom(Atom) == 0, "delete 2\n");
        ok(GlobalFindAtomW(L"k32exp_atom_ok") == 0, "gone\n");
    }
}

/* ------------------------------------------------------------------------------------------------ barrier */

typedef BOOL (WINAPI *PFN_Init)(TEST_BARRIER *, LONG, LONG);
typedef BOOL (WINAPI *PFN_Enter)(TEST_BARRIER *, DWORD);
typedef BOOL (WINAPI *PFN_Delete)(TEST_BARRIER *);

static PFN_Enter g_Enter;
static TEST_BARRIER g_Barrier;
static volatile LONG g_Results[8];
static DWORD g_Delay[8];

static DWORD WINAPI
BarrierThread(PVOID Param)
{
    ULONG Index = (ULONG)(ULONG_PTR)Param;

    Sleep(g_Delay[Index]);
    g_Results[Index] = g_Enter(&g_Barrier, 0) ? 1 : 0;
    return 0;
}

static void
test_Barrier(void)
{
    PFN_Init pInit = (PVOID)Proc("InitializeSynchronizationBarrier");
    PFN_Delete pDelete = (PVOID)Proc("DeleteSynchronizationBarrier");
    TEST_BARRIER Barrier;
    HANDLE Threads[8];
    LONG Totals[] = {0, -1};
    ULONG i, Round, Count;
    BOOL Result;

    g_Enter = (PVOID)Proc("EnterSynchronizationBarrier");
    ok(pInit && g_Enter && pDelete, "the synchronization barrier is not exported\n");
    if (!pInit || !g_Enter || !pDelete)
        return;

    /* invalid arguments fail without a last error; -1 is the default spin count */
    for (i = 0; i < RTL_NUMBER_OF(Totals); i++)
    {
        SetLastError(0xdeadbeef);
        ok(!pInit(&Barrier, Totals[i], -1) && GetLastError() == 0xdeadbeef, "total %ld: error %lu\n", Totals[i], GetLastError());
    }
    SetLastError(0xdeadbeef);
    ok(!pInit(&Barrier, 2, -2) && GetLastError() == 0xdeadbeef, "spin -2: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pInit(NULL, 1, -1) && GetLastError() == ERROR_INVALID_PARAMETER, "NULL barrier: error %lu\n", GetLastError());
    ok(pInit(&Barrier, 2, -1), "total 2, spin -1\n");
    ok(pInit(&Barrier, 2, 0), "spin 0\n");
    ok(pInit(&Barrier, 2, 100), "spin 100\n");
    ok(pInit(&Barrier, 0x7FFFFFFF, -1), "the largest total\n");

    /* one thread: every enter is the last one, for every valid flag combination */
    for (i = 0; i < 8; i++)
    {
        ok(pInit(&Barrier, 1, -1), "init\n");
        ok(g_Enter(&Barrier, i), "flags %lx: not the last thread\n", i);
        ok(g_Enter(&Barrier, i), "flags %lx: second phase\n", i);
    }

    /* a flag outside of the three raises STATUS_INVALID_PARAMETER */
    {
        static const DWORD Bad[] = {8, 0x10, 0x80000000};

        for (i = 0; i < RTL_NUMBER_OF(Bad); i++)
        {
            NTSTATUS Code = 0;

            ok(pInit(&Barrier, 1, -1), "init\n");
            _SEH2_TRY
            {
                g_Enter(&Barrier, Bad[i]);
            }
            _SEH2_EXCEPT(Code = _SEH2_GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)
            {
            }
            _SEH2_END;
            ok(Code == STATUS_INVALID_PARAMETER, "flags %lx: exception %lx\n", Bad[i], Code);
        }
    }

    /* an uninitialized barrier and a NULL one give FALSE */
    RtlZeroMemory(&Barrier, sizeof(Barrier));
    ok(!g_Enter(&Barrier, 0), "zeroed barrier\n");
    ok(!g_Enter(NULL, 0), "NULL barrier\n");

    /* two threads: the one that arrives last gets TRUE, the other FALSE */
    for (Round = 0; Round < 4; Round++)
    {
        BOOL Main;

        ok(pInit(&g_Barrier, 2, -1), "init\n");
        g_Results[0] = -1;
        g_Delay[0] = (Round & 1) ? 0 : 250;
        Threads[0] = CreateThread(NULL, 0, BarrierThread, (PVOID)0, 0, NULL);
        Sleep((Round & 1) ? 250 : 0);
        Main = g_Enter(&g_Barrier, 0);
        WaitForSingleObject(Threads[0], 10000);
        CloseHandle(Threads[0]);
        if (Round & 1)
            ok(Main && g_Results[0] == 0, "main arrives last: main %d, thread %ld\n", Main, g_Results[0]);
        else
            ok(!Main && g_Results[0] == 1, "thread arrives last: main %d, thread %ld\n", Main, g_Results[0]);
        ok(pDelete(&g_Barrier), "delete\n");
    }

    /* four threads, three phases on one barrier: exactly one TRUE per phase, with spin only and with block only too */
    for (Round = 0; Round < 3; Round++)
    {
        ok(pInit(&g_Barrier, 4, Round == 0 ? 100 : -1), "init\n");
        Count = 0;
        for (i = 1; i < 4; i++)
        {
            g_Delay[i] = i * 20;
            g_Results[i] = -1;
            Threads[i] = CreateThread(NULL, 0, BarrierThread, (PVOID)(ULONG_PTR)i, 0, NULL);
        }
        Result = g_Enter(&g_Barrier, Round == 1 ? BLOCK_ONLY : (Round == 2 ? SPIN_ONLY : 0));
        Count += Result ? 1 : 0;
        WaitForMultipleObjects(3, Threads + 1, TRUE, 10000);
        for (i = 1; i < 4; i++)
        {
            Count += g_Results[i] == 1;
            CloseHandle(Threads[i]);
        }
        ok(Count == 1, "round %lu: %lu threads got TRUE\n", Round, Count);
        ok(pDelete(&g_Barrier), "delete\n");
    }
}

/* ------------------------------------------------------------------------------------------------ tokens and ACLs */

static void
test_TokenFunctions(void)
{
    typedef BOOL (WINAPI *PFN_Ex)(HANDLE, PSID, DWORD, PBOOL);
    typedef BOOL (WINAPI *PFN_Cap)(HANDLE, PSID, PBOOL);
    PFN_Ex pEx = (PVOID)Proc("CheckTokenMembershipEx");
    PFN_Cap pCap = (PVOID)Proc("CheckTokenCapability");
    BYTE World[64], Admin[64], Random[64], Cap[64], Cap2[64], NotCap[64], Package[64];
    HANDLE Primary = NULL, Imp = NULL;
    DWORD Flags[] = {0, 1, 2, 3};
    BOOL Result, Member;
    ULONG i;

    MakeSid(World, 1, 1, 0);
    MakeSid(Admin, 5, 2, 32, 544);
    MakeSid(Random, 5, 4, 21, 1, 2, 3);
    MakeSid(Cap, 15, 2, 3, 1);
    MakeSid(Cap2, 15, 9, 3, 1024, 1, 2, 3, 4, 5, 6, 7);
    MakeSid(NotCap, 5, 1, 18);
    MakeSid(Package, 15, 8, 2, 1, 2, 3, 4, 5, 6, 7);

    ok(pEx && pCap, "CheckTokenMembershipEx/CheckTokenCapability are not exported\n");
    if (!pEx || !pCap)
        return;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Primary), "OpenProcessToken failed: %lu\n", GetLastError());
    ok(DuplicateTokenEx(Primary, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Imp), "DuplicateTokenEx failed: %lu\n", GetLastError());

    for (i = 0; i < RTL_NUMBER_OF(Flags); i++)
    {
        Member = 0x55;
        SetLastError(0xdeadbeef);
        Result = pEx(Imp, World, Flags[i], &Member);
        ok(Result && Member == TRUE && GetLastError() == 0xdeadbeef, "world, flags %lx: %d, member %d, error %lu\n", Flags[i], Result, Member, GetLastError());
    }
    for (i = 0; i < 3; i++)
    {
        static const DWORD Bad[] = {4, 0x10, 0xFFFFFFFF};

        Member = 0x55;
        SetLastError(0xdeadbeef);
        Result = pEx(Imp, World, Bad[i], &Member);
        ok(!Result && GetLastError() == ERROR_INVALID_PARAMETER && Member == FALSE, "flags %lx: %d, error %lu, member %d\n", Bad[i], Result, GetLastError(), Member);
    }
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pEx(Imp, NULL, 0, &Member);
    ok(!Result && GetLastError() == ERROR_INVALID_PARAMETER && Member == 0x55, "NULL SID: %d, error %lu, member %d\n", Result, GetLastError(), Member);
    Member = 0x55;
    Result = pEx(Imp, Random, 0, &Member);
    ok(Result && Member == FALSE, "a SID the token is not a member of: %d, member %d\n", Result, Member);
    Member = 0x55;
    Result = pEx(Imp, Package, 1, &Member);
    ok(Result && Member == FALSE, "a package SID: %d, member %d\n", Result, Member);
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pEx(Primary, World, 0, &Member);
    ok(!Result && GetLastError() == ERROR_NO_IMPERSONATION_TOKEN && Member == FALSE, "primary token: %d, error %lu\n", Result, GetLastError());
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pEx(NULL, World, 0, &Member);
    ok(Result && Member == TRUE, "NULL token: %d, member %d, error %lu\n", Result, Member, GetLastError());
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pEx((HANDLE)(ULONG_PTR)0x12345678, World, 0, &Member);
    ok(!Result && GetLastError() == ERROR_INVALID_HANDLE && Member == FALSE, "bogus token: %d, error %lu\n", Result, GetLastError());
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pEx(INVALID_HANDLE_VALUE, World, 0, &Member);
    ok(!Result && GetLastError() == ERROR_INVALID_HANDLE && Member == FALSE, "-1 token: %d, error %lu\n", Result, GetLastError());
    /* the Administrators group follows the process token (the tests run elevated or not) */
    {
        BOOL Basic = FALSE;

        Member = 0x55;
        ok(pEx(Imp, Admin, 0, &Member), "Administrators\n");
        ok(CheckTokenMembership(Imp, Admin, &Basic) && Basic == Member, "same answer as CheckTokenMembership\n");
    }

    /* capabilities: only capability SIDs (S-1-15-3-...) are accepted; a token that is no AppContainer has all of them */
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pCap(Imp, Cap, &Member);
    ok(Result && Member == TRUE && GetLastError() == 0xdeadbeef, "S-1-15-3-1: %d, has %d, error %lu\n", Result, Member, GetLastError());
    Member = 0x55;
    Result = pCap(Imp, Cap2, &Member);
    ok(Result && Member == TRUE, "S-1-15-3-1024-...: %d, has %d\n", Result, Member);
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pCap(NULL, Cap, &Member);
    ok(Result && Member == TRUE, "NULL token: %d, has %d, error %lu\n", Result, Member, GetLastError());
    {
        PSID Bad[] = {NotCap, World, Package, Random};

        for (i = 0; i < RTL_NUMBER_OF(Bad); i++)
        {
            Member = 0x55;
            SetLastError(0xdeadbeef);
            Result = pCap(Imp, Bad[i], &Member);
            ok(!Result && GetLastError() == ERROR_INVALID_PARAMETER && Member == FALSE, "SID %lu: %d, error %lu, has %d\n", i, Result, GetLastError(), Member);
        }
    }
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pCap(Primary, Cap, &Member);
    ok(!Result && GetLastError() == ERROR_NO_IMPERSONATION_TOKEN && Member == FALSE, "primary token: %d, error %lu, has %d\n", Result, GetLastError(), Member);
    Member = 0x55;
    SetLastError(0xdeadbeef);
    Result = pCap(Imp, NULL, &Member);
    ok(!Result && GetLastError() == ERROR_INVALID_PARAMETER && Member == 0x55, "NULL SID: %d, error %lu, has %d\n", Result, GetLastError(), Member);

    CloseHandle(Imp);
    CloseHandle(Primary);
}

static void
test_Acl(void)
{
    typedef BOOL (WINAPI *PFN_GetAce)(PACL, DWORD, PVOID *, PDWORD);
    typedef BOOL (WINAPI *PFN_Scoped)(PACL, DWORD, DWORD, DWORD, PSID);
    typedef BOOL (WINAPI *PFN_AddIL)(HANDLE *, PSID);
    typedef HANDLE (WINAPI *PFN_CreateBd)(LPCWSTR, ULONG);
    typedef VOID (WINAPI *PFN_DeleteBd)(HANDLE);
    PFN_GetAce pGetAce = (PVOID)Proc("GetAppContainerAce");
    PFN_Scoped pScoped = (PVOID)Proc("AddScopedPolicyIDAce");
    PFN_AddIL pAddIL = (PVOID)Proc("AddIntegrityLabelToBoundaryDescriptor");
    PFN_CreateBd pCreate = (PVOID)Proc("CreateBoundaryDescriptorW");
    PFN_DeleteBd pDeleteBd = (PVOID)Proc("DeleteBoundaryDescriptor");
    PFN_AddIL pAddSid = (PVOID)Proc("AddSIDToBoundaryDescriptor");
    BYTE Buffer[512], World[64], Cap[64], Pkg8[64], Pkg12[64], Policy[64], Policy3[64], Policy0[64], NotPolicy[64], Il[64];
    PACL Acl = (PACL)Buffer;
    PVOID Ace;
    DWORD Index;
    PACE_HEADER Header;
    BOOL Result;
    ULONG i;

    MakeSid(World, 1, 1, 0);
    MakeSid(Cap, 15, 2, 3, 1);
    MakeSid(Pkg8, 15, 8, 2, 1, 2, 3, 4, 5, 6, 7);
    MakeSid(Pkg12, 15, 12, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
    MakeSid(Policy, 17, 1, 1);
    MakeSid(Policy3, 17, 3, 1, 2, 3);
    MakeSid(Policy0, 17, 1, 0);
    MakeSid(NotPolicy, 18, 1, 1);
    MakeSid(Il, 16, 1, 0x1000);

    ok(pGetAce && pScoped && pAddIL && pCreate && pDeleteBd && pAddSid, "ACL functions are not exported\n");
    if (!pGetAce || !pScoped || !pAddIL || !pCreate || !pDeleteBd || !pAddSid)
        return;

    /* GetAppContainerAce: an ACE whose SID has the authority 15 (package, capability and group capability SIDs) */
    InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION);
    Ace = (PVOID)0x11;
    Index = 0x77;
    SetLastError(0xdeadbeef);
    ok(!pGetAce(Acl, 0, &Ace, &Index) && GetLastError() == ERROR_INVALID_PARAMETER && Ace == (PVOID)0x11 && Index == 0x77,
       "empty ACL: error %lu\n", GetLastError());
    ok(AddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, World), "AddAccessAllowedAce\n");
    SetLastError(0xdeadbeef);
    ok(!pGetAce(Acl, 0, &Ace, &Index) && GetLastError() == ERROR_NOT_FOUND && Ace == (PVOID)0x11 && Index == 0x77,
       "ACL without such an ACE: error %lu\n", GetLastError());
    ok(AddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, Cap), "AddAccessAllowedAce cap\n");
    ok(AddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, Pkg12), "AddAccessAllowedAce pkg12\n");
    ok(AddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, Pkg8), "AddAccessAllowedAce pkg8\n");
    {
        static const DWORD Start[] = {0, 1, 2, 3};
        static const DWORD Found[] = {1, 1, 2, 3};

        for (i = 0; i < RTL_NUMBER_OF(Start); i++)
        {
            Ace = NULL;
            Index = 0x77;
            SetLastError(0xdeadbeef);
            Result = pGetAce(Acl, Start[i], &Ace, &Index);
            ok(Result && Index == Found[i] && GetLastError() == 0, "start %lu: %d, index %lu, error %lu\n", Start[i], Result, Index, GetLastError());
            if (Result)
            {
                PVOID Expected;

                GetAce(Acl, Found[i], &Expected);
                ok(Ace == Expected, "start %lu: ACE %p, expected %p\n", Start[i], Ace, Expected);
            }
        }
    }
    for (i = 4; i < 6; i++)
    {
        Index = 0x77;
        SetLastError(0xdeadbeef);
        ok(!pGetAce(Acl, i, &Ace, &Index) && GetLastError() == ERROR_INVALID_PARAMETER && Index == 0x77, "start %lu: error %lu\n", i, GetLastError());
    }
    ok(pGetAce(Acl, 0, &Ace, NULL) && GetLastError() == 0, "the index is optional\n");
    SetLastError(0xdeadbeef);
    ok(!pGetAce(Acl, 0, NULL, &Index) && GetLastError() == ERROR_INVALID_PARAMETER, "NULL ACE pointer: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pGetAce(NULL, 0, &Ace, &Index) && GetLastError() == ERROR_INVALID_PARAMETER, "NULL ACL: error %lu\n", GetLastError());

    /* AddScopedPolicyIDAce */
    InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION_DS);
    SetLastError(0xdeadbeef);
    ok(pScoped(Acl, ACL_REVISION_DS, 0, 0, Policy), "AddScopedPolicyIDAce failed: %lu\n", GetLastError());
    ok(Acl->AceCount == 1, "ACE count %u\n", Acl->AceCount);
    Header = (PACE_HEADER)(Acl + 1);
    ok(Header->AceType == 0x13 && Header->AceFlags == 0 && Header->AceSize == 20, "ACE type %x flags %x size %u\n", Header->AceType, Header->AceFlags, Header->AceSize);
    ok(*(PDWORD)(Header + 1) == 0, "mask %lx\n", *(PDWORD)(Header + 1));
    ok(RtlEqualSid((PSID)((PBYTE)Header + 8), Policy), "the ACE carries the SID\n");
    for (i = 0; i < 5; i++)
    {
        static const DWORD Revs[] = {0, 1, 2, 3, 4};
        static const UCHAR Expected[] = {2, 2, 2, 3, 4};

        InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION);
        ok(pScoped(Acl, Revs[i], 0, 0, Policy), "revision %lu\n", Revs[i]);
        ok(Acl->AclRevision == Expected[i], "revision %lu: ACL revision %u, expected %u\n", Revs[i], Acl->AclRevision, Expected[i]);
    }
    InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION_DS);
    SetLastError(0xdeadbeef);
    ok(!pScoped(Acl, 5, 0, 0, Policy) && GetLastError() == ERROR_REVISION_MISMATCH, "revision 5: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pScoped(Acl, 0xFFFFFFFF, 0, 0, Policy) && GetLastError() == ERROR_REVISION_MISMATCH, "revision -1: error %lu\n", GetLastError());
    for (i = 0; i < 5; i++)
    {
        static const DWORD Good[] = {0, 1, 2, 3, 0x1F};

        InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION_DS);
        ok(pScoped(Acl, ACL_REVISION_DS, Good[i], 0, Policy), "flags %lx\n", Good[i]);
        ok(((PACE_HEADER)(Acl + 1))->AceFlags == Good[i], "flags %lx stored as %x\n", Good[i], ((PACE_HEADER)(Acl + 1))->AceFlags);
    }
    {
        static const DWORD BadFlags[] = {0x80, 0xFF};
        static const DWORD BadMasks[] = {1, 0x12345, 0xFFFFFFFF};

        for (i = 0; i < RTL_NUMBER_OF(BadFlags); i++)
        {
            SetLastError(0xdeadbeef);
            ok(!pScoped(Acl, ACL_REVISION_DS, BadFlags[i], 0, Policy) && GetLastError() == ERROR_INVALID_PARAMETER, "flags %lx: error %lu\n", BadFlags[i], GetLastError());
        }
        for (i = 0; i < RTL_NUMBER_OF(BadMasks); i++)
        {
            SetLastError(0xdeadbeef);
            ok(!pScoped(Acl, ACL_REVISION_DS, 0, BadMasks[i], Policy) && GetLastError() == ERROR_INVALID_PARAMETER, "mask %lx: error %lu\n", BadMasks[i], GetLastError());
        }
    }
    InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION_DS);
    ok(pScoped(Acl, ACL_REVISION_DS, 0, 0, Policy3), "S-1-17-1-2-3\n");
    ok(((PACE_HEADER)(Acl + 1))->AceSize == 28, "AceSize %u\n", ((PACE_HEADER)(Acl + 1))->AceSize);
    ok(pScoped(Acl, ACL_REVISION_DS, 0, 0, Policy0), "S-1-17-0\n");
    ok(Acl->AceCount == 2, "count %u\n", Acl->AceCount);
    SetLastError(0xdeadbeef);
    ok(!pScoped(Acl, ACL_REVISION_DS, 0, 0, World) && GetLastError() == ERROR_INVALID_PARAMETER, "S-1-1-0: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pScoped(Acl, ACL_REVISION_DS, 0, 0, Il) && GetLastError() == ERROR_INVALID_PARAMETER, "S-1-16-4096: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pScoped(Acl, ACL_REVISION_DS, 0, 0, NotPolicy) && GetLastError() == ERROR_INVALID_PARAMETER, "S-1-18-1: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pScoped(Acl, ACL_REVISION_DS, 0, 0, NULL) && GetLastError() == ERROR_INVALID_SID, "NULL SID: error %lu\n", GetLastError());
    {
        BYTE Zero[64] = {0};

        SetLastError(0xdeadbeef);
        ok(!pScoped(Acl, ACL_REVISION_DS, 0, 0, Zero) && GetLastError() == ERROR_INVALID_SID, "invalid SID: error %lu\n", GetLastError());
    }
    SetLastError(0xdeadbeef);
    ok(!pScoped(NULL, ACL_REVISION_DS, 0, 0, Policy) && GetLastError() == ERROR_INVALID_ACL, "NULL ACL: error %lu\n", GetLastError());
    {
        BYTE Small[24];
        PACL SmallAcl = (PACL)Small;

        InitializeAcl(SmallAcl, 16, ACL_REVISION_DS);
        SetLastError(0xdeadbeef);
        ok(!pScoped(SmallAcl, ACL_REVISION_DS, 0, 0, Policy) && GetLastError() == ERROR_ALLOTTED_SPACE_EXCEEDED, "16 byte ACL: error %lu\n", GetLastError());
        InitializeAcl(SmallAcl, 24, ACL_REVISION_DS);
        SetLastError(0xdeadbeef);
        ok(!pScoped(SmallAcl, ACL_REVISION_DS, 0, 0, Policy) && GetLastError() == ERROR_ALLOTTED_SPACE_EXCEEDED && SmallAcl->AceCount == 0,
           "24 byte ACL: error %lu\n", GetLastError());
    }
    InitializeAcl(Acl, sizeof(Buffer), ACL_REVISION_DS);
    for (i = 0; i < 3; i++)
        ok(pScoped(Acl, ACL_REVISION_DS, 0, 0, Policy), "add %lu\n", i);
    ok(Acl->AceCount == 3, "count %u\n", Acl->AceCount);

    /* AddIntegrityLabelToBoundaryDescriptor: any SID with a subauthority is taken, one label per descriptor */
    {
        const struct { UCHAR Authority; UCHAR Count; DWORD Sub; } Ok[] = { {16, 1, 0x1000}, {16, 1, 0x2000}, {16, 1, 0}, {5, 2, 32}, {1, 1, 0}, {15, 2, 2} };
        HANDLE Bd, Bd2;
        BYTE Sid[64];

        for (i = 0; i < RTL_NUMBER_OF(Ok); i++)
        {
            Bd = pCreate(L"k32exp_bd", 0);
            ok(Bd != NULL, "CreateBoundaryDescriptorW failed: %lu\n", GetLastError());
            MakeSid(Sid, Ok[i].Authority, Ok[i].Count, Ok[i].Sub, 544);
            SetLastError(0xdeadbeef);
            ok(pAddIL(&Bd, Sid) && GetLastError() == 0xdeadbeef, "SID %lu: error %lu\n", i, GetLastError());
            SetLastError(0xdeadbeef);
            ok(!pAddIL(&Bd, Il) && GetLastError() == ERROR_OBJECT_ALREADY_EXISTS, "second label: error %lu\n", GetLastError());
            ok(pAddSid(&Bd, World), "ordinary SIDs can still be added\n");
            pDeleteBd(Bd);
        }
        Bd = pCreate(L"k32exp_bd", 0);
        SetLastError(0xdeadbeef);
        ok(!pAddIL(&Bd, MakeSid(Sid, 16, 0)) && GetLastError() == ERROR_INVALID_PARAMETER, "SID without subauthority: error %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        ok(!pAddIL(&Bd, NULL) && GetLastError() == ERROR_INVALID_PARAMETER, "NULL SID: error %lu\n", GetLastError());
        /* a SID added the ordinary way does not stand in for the label, and the label may follow it */
        Bd2 = pCreate(L"k32exp_bd2", 0);
        ok(pAddSid(&Bd2, Il), "an integrity SID as an ordinary SID\n");
        ok(pAddIL(&Bd2, Il), "the label after it\n");
        pDeleteBd(Bd);
        pDeleteBd(Bd2);
    }
}

/* ------------------------------------------------------------------------------------------------ NUMA, threadpool */

static void
test_Numa(void)
{
    typedef BOOL (WINAPI *PFN_Handle)(HANDLE, PUSHORT);
    typedef BOOL (WINAPI *PFN_Prox)(ULONG, PUSHORT);
    typedef BOOL (WINAPI *PFN_Mem)(USHORT, PULONGLONG);
    PFN_Handle pHandle = (PVOID)Proc("GetNumaNodeNumberFromHandle");
    PFN_Prox pProx = (PVOID)Proc("GetNumaProximityNodeEx");
    PFN_Mem pMem = (PVOID)Proc("GetNumaAvailableMemoryNodeEx");
    WCHAR Path[MAX_PATH];
    HANDLE File, Event, Port;
    ULONG Highest = 0;
    USHORT Node;
    ULONGLONG Bytes;
    ULONG i;

    ok(pHandle && pProx && pMem, "the NUMA functions are not exported\n");
    if (!pHandle || !pProx || !pMem)
        return;

    {
        typedef BOOL (WINAPI *PFN_Highest)(PULONG);
        PFN_Highest pHighest = (PVOID)Proc("GetNumaHighestNodeNumber");

        if (pHighest)
            pHighest(&Highest);
    }
    GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path));
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

    Node = 0x55;
    SetLastError(0xdeadbeef);
    ok(pHandle(File, &Node) && Node == 0 && GetLastError() == 0xdeadbeef, "file: node %u, error %lu\n", Node, GetLastError());
    {
        HANDLE Others[] = {Event, Port, GetCurrentProcess(), INVALID_HANDLE_VALUE, NULL, (HANDLE)(ULONG_PTR)0x12344};

        for (i = 0; i < RTL_NUMBER_OF(Others); i++)
        {
            Node = 0x55;
            SetLastError(0xdeadbeef);
            ok(!pHandle(Others[i], &Node) && GetLastError() == ERROR_INVALID_HANDLE && Node == 0x55, "handle %lu: node %u, error %lu\n", i, Node, GetLastError());
        }
    }

    Node = 0x55;
    SetLastError(0xdeadbeef);
    ok(pProx(0, &Node) && Node == 0 && GetLastError() == 0xdeadbeef, "proximity 0: node %u, error %lu\n", Node, GetLastError());
    {
        static const ULONG Ids[] = {1, 2, 5, 0x100, 0xFFFFFFFF};

        for (i = 0; i < RTL_NUMBER_OF(Ids); i++)
        {
            Node = 0x55;
            SetLastError(0xdeadbeef);
            ok(!pProx(Ids[i], &Node) && GetLastError() == ERROR_NOT_FOUND && Node == 0x55, "proximity %lx: node %u, error %lu\n", Ids[i], Node, GetLastError());
        }
    }

    Bytes = 0x55;
    SetLastError(0xdeadbeef);
    ok(pMem(0, &Bytes) && Bytes != 0 && Bytes != 0x55, "node 0: %I64u bytes, error %lu\n", Bytes, GetLastError());
    if (Highest == 0)
    {
        static const USHORT Nodes[] = {1, 2, 255, 0xFFFF};

        for (i = 0; i < RTL_NUMBER_OF(Nodes); i++)
        {
            Bytes = 0x55;
            SetLastError(0xdeadbeef);
            ok(!pMem(Nodes[i], &Bytes) && GetLastError() == ERROR_INVALID_PARAMETER && Bytes == 0x55, "node %u: error %lu\n", Nodes[i], GetLastError());
        }
    }

    CloseHandle(File);
    CloseHandle(Event);
    CloseHandle(Port);
}

static void
test_ThreadpoolStack(void)
{
    typedef BOOL (WINAPI *PFN_StackInfo)(PTP_POOL, TEST_TP_STACK *);
    PFN_StackInfo pQuery = (PVOID)Proc("QueryThreadpoolStackInformation");
    PFN_StackInfo pSet = (PVOID)Proc("SetThreadpoolStackInformation");
    PTP_POOL Pool;
    TEST_TP_STACK Info;
    PIMAGE_NT_HEADERS Headers = RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);
    static const struct { SIZE_T Reserve, Commit; } Sets[] =
    {
        {0x100000, 0x4000}, {0x4000, 0x8000}, {0, 0}, {0x100000, 0}, {0, 0x4000}, {0x123456, 0x1234}, {0x1000, 0x800},
    };
    ULONG i;

    ok(pQuery && pSet, "the threadpool stack functions are not exported\n");
    if (!pQuery || !pSet)
        return;

    Pool = CreateThreadpool(NULL);
    ok(Pool != NULL, "CreateThreadpool failed: %lu\n", GetLastError());
    if (!Pool)
        return;

    /* a pool starts with the stack sizes of the process image */
    RtlFillMemory(&Info, sizeof(Info), 0xCC);
    SetLastError(0xdeadbeef);
    ok(pQuery(Pool, &Info) && GetLastError() == 0xdeadbeef, "query: error %lu\n", GetLastError());
    ok(Info.Reserve == Headers->OptionalHeader.SizeOfStackReserve && Info.Commit == Headers->OptionalHeader.SizeOfStackCommit,
       "default %Ix/%Ix, image %Ix/%Ix\n", Info.Reserve, Info.Commit,
       (SIZE_T)Headers->OptionalHeader.SizeOfStackReserve, (SIZE_T)Headers->OptionalHeader.SizeOfStackCommit);

    /* any pair is stored as it is: nothing is validated */
    for (i = 0; i < RTL_NUMBER_OF(Sets); i++)
    {
        Info.Reserve = Sets[i].Reserve;
        Info.Commit = Sets[i].Commit;
        SetLastError(0xdeadbeef);
        ok(pSet(Pool, &Info) && GetLastError() == 0xdeadbeef, "set %Ix/%Ix: error %lu\n", Sets[i].Reserve, Sets[i].Commit, GetLastError());
        RtlFillMemory(&Info, sizeof(Info), 0xCC);
        ok(pQuery(Pool, &Info), "query\n");
        ok(Info.Reserve == Sets[i].Reserve && Info.Commit == Sets[i].Commit, "set %Ix/%Ix reads %Ix/%Ix\n", Sets[i].Reserve, Sets[i].Commit, Info.Reserve, Info.Commit);
    }

    SetLastError(0xdeadbeef);
    ok(!pSet(Pool, NULL) && GetLastError() == ERROR_INVALID_PARAMETER, "set NULL: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pQuery(Pool, NULL) && GetLastError() == ERROR_INVALID_PARAMETER, "query NULL: error %lu\n", GetLastError());

    /* a second pool starts again with the defaults of the image */
    {
        PTP_POOL Other = CreateThreadpool(NULL);

        RtlFillMemory(&Info, sizeof(Info), 0xCC);
        ok(Other && pQuery(Other, &Info) && Info.Reserve == Headers->OptionalHeader.SizeOfStackReserve, "second pool %Ix\n", Info.Reserve);
        if (Other)
            CloseThreadpool(Other);
    }
    CloseThreadpool(Pool);
}

/* ------------------------------------------------------------------------------------------------ disk space */

static void
test_DiskSpace(void)
{
    typedef HRESULT (WINAPI *PFN_W)(LPCWSTR, TEST_DISK_SPACE *);
    typedef HRESULT (WINAPI *PFN_A)(LPCSTR, TEST_DISK_SPACE *);
    PFN_W pW = (PVOID)Proc("GetDiskSpaceInformationW");
    PFN_A pA = (PVOID)Proc("GetDiskSpaceInformationA");
    WCHAR Windir[MAX_PATH], Root[4], Exe[MAX_PATH];
    TEST_DISK_SPACE Info, Info2;
    DWORD Sectors, Bytes, Free, Total;
    ULARGE_INTEGER Avail, TotalBytes, FreeBytes;
    HRESULT Hr;
    ULONG i;

    ok(pW && pA, "GetDiskSpaceInformationA/W are not exported\n");
    if (!pW || !pA)
        return;

    GetWindowsDirectoryW(Windir, RTL_NUMBER_OF(Windir));
    GetModuleFileNameW(NULL, Exe, RTL_NUMBER_OF(Exe));
    Root[0] = Windir[0];
    Root[1] = L':';
    Root[2] = L'\\';
    Root[3] = 0;

    RtlFillMemory(&Info, sizeof(Info), 0xCC);
    SetLastError(0xdeadbeef);
    Hr = pW(Root, &Info);
    ok(Hr == S_OK && GetLastError() == 0xdeadbeef, "root: %lx, error %lu\n", Hr, GetLastError());
    ok(GetDiskFreeSpaceW(Root, &Sectors, &Bytes, &Free, &Total), "GetDiskFreeSpaceW failed: %lu\n", GetLastError());
    ok(GetDiskFreeSpaceExW(Root, &Avail, &TotalBytes, &FreeBytes), "GetDiskFreeSpaceExW failed: %lu\n", GetLastError());
    ok(Info.SectorsPerAllocationUnit == Sectors && Info.BytesPerSector == Bytes, "geometry %lu/%lu, expected %lu/%lu\n",
       Info.SectorsPerAllocationUnit, Info.BytesPerSector, Sectors, Bytes);
    ok(Info.v[0] == Total && Info.v[3] == Total, "total units %I64u/%I64u, expected %lu\n", Info.v[0], Info.v[3], Total);
    ok(Info.v[1] <= Info.v[0] && Info.v[4] <= Info.v[3], "available %I64u/%I64u\n", Info.v[1], Info.v[4]);
    ok(Info.v[4] * Sectors * Bytes >= Avail.QuadPart - 64 * 1024 * 1024 && Info.v[4] * Sectors * Bytes <= Avail.QuadPart + 64 * 1024 * 1024,
       "caller available %I64u units, GetDiskFreeSpaceExW %I64u bytes\n", Info.v[4], Avail.QuadPart);
    ok(Info.v[2] == 0 && Info.v[5] == 0 && Info.v[8] == 0 && Info.v[10] == 0, "pool and reserve fields %I64u %I64u %I64u %I64u\n", Info.v[2], Info.v[5], Info.v[8], Info.v[10]);
    ok(Info.v[6] + Info.v[7] + Info.v[1] == Info.v[0], "used %I64u + reserved %I64u + available %I64u != total %I64u\n", Info.v[6], Info.v[7], Info.v[1], Info.v[0]);
    ok(Info.v[9] == Info.v[1] - Info.v[0], "available committed %I64u\n", Info.v[9]);

    /* other names for the same volume */
    {
        const WCHAR *Same[] = {Windir, L"\\", L".", NULL};
        WCHAR Drive[3] = {Windir[0], L':', 0};
        WCHAR Prefixed[16];

        StringCchPrintfW(Prefixed, RTL_NUMBER_OF(Prefixed), L"\\\\?\\%c:\\", Windir[0]);
        for (i = 0; i < 6; i++)
        {
            const WCHAR *Path = i < 4 ? Same[i] : (i == 4 ? Prefixed : Drive);

            if (i == 2 || i == 1 || i == 3)
            {
                /* the current directory and "\" are on the volume of the tests; skip when it is another one */
                WCHAR Current[MAX_PATH];

                GetCurrentDirectoryW(RTL_NUMBER_OF(Current), Current);
                if (Current[0] != Windir[0])
                    continue;
            }
            RtlFillMemory(&Info2, sizeof(Info2), 0xCC);
            SetLastError(0xdeadbeef);
            Hr = pW(Path, &Info2);
            ok(Hr == S_OK && GetLastError() == 0xdeadbeef && Info2.v[0] == Info.v[0] && Info2.BytesPerSector == Info.BytesPerSector,
               "path %lu: %lx, error %lu\n", i, Hr, GetLastError());
        }
    }
    RtlFillMemory(&Info2, sizeof(Info2), 0xCC);
    Hr = pA("C:\\", &Info2);
    ok(Hr == S_OK || GetFileAttributesW(L"C:\\") == INVALID_FILE_ATTRIBUTES, "ANSI: %lx\n", Hr);

    /* failures: the result is the NTSTATUS as an HRESULT, the structure is left alone */
    RtlFillMemory(&Info2, sizeof(Info2), 0xCC);
    SetLastError(0xdeadbeef);
    Hr = pW(Exe, &Info2);
    ok(Hr == (HRESULT)0xD0000103 && GetLastError() == ERROR_DIRECTORY && Info2.v[0] == 0xCCCCCCCCCCCCCCCCULL, "a file: %lx, error %lu\n", Hr, GetLastError());
    RtlFillMemory(&Info2, sizeof(Info2), 0xCC);
    SetLastError(0xdeadbeef);
    Hr = pW(L"C:\\k32exp_no_such_directory", &Info2);
    ok(Hr == (HRESULT)0xD0000034 && GetLastError() == ERROR_PATH_NOT_FOUND && Info2.v[0] == 0xCCCCCCCCCCCCCCCCULL, "missing name: %lx, error %lu\n", Hr, GetLastError());
    RtlFillMemory(&Info2, sizeof(Info2), 0xCC);
    SetLastError(0xdeadbeef);
    Hr = pW(L"", &Info2);
    ok(Hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) && GetLastError() == ERROR_PATH_NOT_FOUND, "empty path: %lx, error %lu\n", Hr, GetLastError());
    {
        char Long[600];

        memset(Long, 'a', sizeof(Long) - 1);
        Long[sizeof(Long) - 1] = 0;
        SetLastError(0xdeadbeef);
        Hr = pA(Long, &Info2);
        ok(Hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) && GetLastError() == ERROR_PATH_NOT_FOUND, "599 characters: %lx, error %lu\n", Hr, GetLastError());
    }
    SetLastError(0xdeadbeef);
    Hr = pW(Root, NULL);
    ok(Hr == (HRESULT)0xD000000D && GetLastError() == 0xC000000D, "NULL result: %lx, error %lx\n", Hr, GetLastError());
}

/* ------------------------------------------------------------------------------------------------ time zone conversions */

static BOOL
SameTime(const SYSTEMTIME *a, WORD Y, WORD M, WORD D, WORD H, WORD Min)
{
    return a->wYear == Y && a->wMonth == M && a->wDay == D && a->wHour == H && a->wMinute == Min && a->wSecond == 0 && a->wMilliseconds == 0;
}

static void
test_LocalTime(void)
{
    typedef BOOL (WINAPI *PFN_LF)(const TIME_ZONE_INFORMATION *, const FILETIME *, SYSTEMTIME *);
    typedef BOOL (WINAPI *PFN_LS)(const TIME_ZONE_INFORMATION *, const SYSTEMTIME *, FILETIME *);
    typedef BOOL (WINAPI *PFN_Ex)(const DYNAMIC_TIME_ZONE_INFORMATION *, const SYSTEMTIME *, SYSTEMTIME *);
    PFN_LF pLF = (PVOID)Proc("LocalFileTimeToLocalSystemTime");
    PFN_LS pLS = (PVOID)Proc("LocalSystemTimeToLocalFileTime");
    PFN_Ex pToLocal = (PVOID)Proc("SystemTimeToTzSpecificLocalTimeEx");
    PFN_Ex pToUtc = (PVOID)Proc("TzSpecificLocalTimeToSystemTimeEx");
    TIME_ZONE_INFORMATION Pst;
    DYNAMIC_TIME_ZONE_INFORMATION Dyn, Other;
    SYSTEMTIME St, Out, Bad = {2020, 13, 0, 1, 0, 0, 0, 0};
    FILETIME Ft, Ft2;
    ULONG i;

    ok(pLF && pLS && pToLocal && pToUtc, "the time functions are not exported\n");
    if (!pLF || !pLS || !pToLocal || !pToUtc)
        return;

    RtlZeroMemory(&Pst, sizeof(Pst));
    Pst.Bias = 480;
    Pst.DaylightBias = -60;
    Pst.StandardDate.wMonth = 11;
    Pst.StandardDate.wDay = 1;
    Pst.StandardDate.wHour = 2;
    Pst.DaylightDate.wMonth = 3;
    Pst.DaylightDate.wDay = 2;
    Pst.DaylightDate.wHour = 2;
    RtlZeroMemory(&Dyn, sizeof(Dyn));
    RtlCopyMemory(&Dyn, &Pst, sizeof(Pst));
    wcscpy(Dyn.TimeZoneKeyName, L"Pacific Standard Time");

    /* the zone is ignored by the first two, which are FileTimeToSystemTime and SystemTimeToFileTime */
    St.wYear = 2020; St.wMonth = 7; St.wDayOfWeek = 0; St.wDay = 1; St.wHour = 12; St.wMinute = 0; St.wSecond = 0; St.wMilliseconds = 0;
    ok(SystemTimeToFileTime(&St, &Ft), "SystemTimeToFileTime\n");
    SetLastError(0xdeadbeef);
    ok(pLF(&Pst, &Ft, &Out) && SameTime(&Out, 2020, 7, 1, 12, 0) && Out.wDayOfWeek == 3, "local file time: %d-%d-%d %d:%d\n", Out.wYear, Out.wMonth, Out.wDay, Out.wHour, Out.wMinute);
    ok(GetLastError() == 0xdeadbeef, "error %lu\n", GetLastError());
    ok(pLF(NULL, &Ft, &Out) && SameTime(&Out, 2020, 7, 1, 12, 0), "NULL zone\n");
    ok(pLS(&Pst, &St, &Ft2) && Ft2.dwLowDateTime == Ft.dwLowDateTime && Ft2.dwHighDateTime == Ft.dwHighDateTime, "local system time\n");
    ok(pLS(NULL, &St, &Ft2), "NULL zone\n");
    SetLastError(0xdeadbeef);
    ok(!pLS(&Pst, &Bad, &Ft2) && GetLastError() == ERROR_INVALID_PARAMETER, "invalid time: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    ok(!pLS(NULL, &Bad, &Ft2) && GetLastError() == ERROR_INVALID_PARAMETER, "invalid time, NULL zone: error %lu\n", GetLastError());

    {
        static const struct { WORD Y, M, D, H, Min; WORD LY, LM, LD, LH, LMin; } Cases[] =
        {
            {2020, 7, 1, 12, 0, 2020, 7, 1, 5, 0},      /* daylight time */
            {2020, 1, 15, 12, 0, 2020, 1, 15, 4, 0},    /* standard time */
            {2020, 3, 8, 9, 30, 2020, 3, 8, 1, 30},     /* just before the change */
            {2020, 3, 8, 10, 0, 2020, 3, 8, 3, 0},      /* the change */
            {2020, 11, 1, 8, 59, 2020, 11, 1, 1, 59},   /* the end of daylight time */
            {2020, 11, 1, 9, 30, 2020, 11, 1, 1, 30},
        };

        for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
        {
            St.wYear = Cases[i].Y; St.wMonth = Cases[i].M; St.wDay = Cases[i].D; St.wHour = Cases[i].H; St.wMinute = Cases[i].Min;
            St.wSecond = 0; St.wMilliseconds = 0; St.wDayOfWeek = 0;
            SetLastError(0xdeadbeef);
            RtlFillMemory(&Out, sizeof(Out), 0xCC);
            ok(pToLocal(&Dyn, &St, &Out) && SameTime(&Out, Cases[i].LY, Cases[i].LM, Cases[i].LD, Cases[i].LH, Cases[i].LMin),
               "case %lu: UTC to local: %d-%d-%d %d:%d, error %lu\n", i, Out.wYear, Out.wMonth, Out.wDay, Out.wHour, Out.wMinute, GetLastError());
            /* daylight time marked as not dynamic: the zone as it stands, without the key */
            Other = Dyn;
            Other.TimeZoneKeyName[0] = 0;
            Other.DynamicDaylightTimeDisabled = TRUE;
            RtlFillMemory(&Out, sizeof(Out), 0xCC);
            ok(pToLocal(&Other, &St, &Out) && SameTime(&Out, Cases[i].LY, Cases[i].LM, Cases[i].LD, Cases[i].LH, Cases[i].LMin), "case %lu: not dynamic\n", i);
            /* an empty key name fails when daylight time is dynamic */
            Other.DynamicDaylightTimeDisabled = FALSE;
            SetLastError(0xdeadbeef);
            ok(!pToLocal(&Other, &St, &Out) && GetLastError() == ERROR_FILE_NOT_FOUND, "case %lu: empty key: error %lu\n", i, GetLastError());
            SetLastError(0xdeadbeef);
            ok(!pToUtc(&Other, &St, &Out) && GetLastError() == ERROR_FILE_NOT_FOUND, "case %lu: empty key, to UTC: error %lu\n", i, GetLastError());
            /* the current zone */
            SetLastError(0xdeadbeef);
            ok(pToLocal(NULL, &St, &Out), "case %lu: NULL zone: error %lu\n", i, GetLastError());
            ok(pToUtc(NULL, &St, &Out), "case %lu: NULL zone, to UTC: error %lu\n", i, GetLastError());
        }
    }

    {
        /* the reverse direction, from the same table: local 2020-07-01 12:00 is 19:00 UTC, in January 20:00 */
        St.wYear = 2020; St.wMonth = 7; St.wDay = 1; St.wHour = 12; St.wMinute = 0; St.wSecond = 0; St.wMilliseconds = 0; St.wDayOfWeek = 0;
        ok(pToUtc(&Dyn, &St, &Out) && SameTime(&Out, 2020, 7, 1, 19, 0), "local to UTC (daylight)\n");
        St.wMonth = 1;
        ok(pToUtc(&Dyn, &St, &Out) && SameTime(&Out, 2020, 1, 1, 20, 0), "local to UTC (standard)\n");
        /* 1601: the local time of a UTC time at the start of the epoch is before it, the other way round it works */
        St.wYear = 1601; St.wMonth = 1; St.wDay = 1; St.wHour = 0; St.wMinute = 0;
        SetLastError(0xdeadbeef);
        ok(!pToLocal(&Dyn, &St, &Out) && GetLastError() == ERROR_INVALID_PARAMETER, "1601 to local: error %lu\n", GetLastError());
        ok(pToUtc(&Dyn, &St, &Out) && SameTime(&Out, 1601, 1, 1, 8, 0), "1601 to UTC\n");
        /* an invalid time */
        SetLastError(0xdeadbeef);
        ok(!pToLocal(&Dyn, &Bad, &Out) && GetLastError() == ERROR_INVALID_PARAMETER, "invalid UTC time: error %lu\n", GetLastError());
        SetLastError(0xdeadbeef);
        ok(!pToUtc(&Dyn, &Bad, &Out) && GetLastError() == ERROR_INVALID_PARAMETER, "invalid local time: error %lu\n", GetLastError());
    }
}

/* ------------------------------------------------------------------------------------------------ DnsHostnameToComputerNameExW */

static void
test_DnsHostname(void)
{
    typedef BOOL (WINAPI *PFN_Dns)(LPCWSTR, LPWSTR, LPDWORD);
    PFN_Dns pEx = (PVOID)Proc("DnsHostnameToComputerNameExW");
    PFN_Dns pOld = (PVOID)Proc("DnsHostnameToComputerNameW");
    static const struct { PCWSTR In; PCWSTR Ex; PCWSTR Old; } Cases[] =
    {
        {L"host", L"HOST", L"HOST"},
        {L"HostName.example.com", L"HOSTNAME.EXAMPL", L"HOSTNAME"},
        {L"a.b", L"A.B", L"A"},
        {L"abcdefghijklmnopqrstuvwxyz.example.com", L"ABCDEFGHIJKLMNO", L"ABCDEFGHIJKLMNO"},
        {L"abcdefghijklmno", L"ABCDEFGHIJKLMNO", L"ABCDEFGHIJKLMNO"},
        {L"abcdefghijklmnop", L"ABCDEFGHIJKLMNO", L"ABCDEFGHIJKLMNO"},
        {L"", L"", NULL},
        {L".", L".", NULL},
        {L".x", L".X", NULL},
        {L"x.", L"X.", L"X"},
        {L"host_name", L"HOST_NAME", L"HOST_NAME"},
        {L"my host", L"MY HOST", L"MY HOST"},
        {L"UPPER-lower.9", L"UPPER-LOWER.9", L"UPPER-LOWER"},
        {L"-lead", L"-LEAD", L"-LEAD"},
        {L"a\\b*c,d;e:f", L"A\\B*C,D;E:F", L"A\\B*C,D;E:F"},
        {L"a\x00e9z", L"A\x00c9Z", L"A\x00c9Z"},
    };
    WCHAR Out[64];
    DWORD Size;
    ULONG i, k;

    ok(pEx && pOld, "DnsHostnameToComputerNameExW/W are not exported\n");
    if (!pEx || !pOld)
        return;

    for (k = 0; k < 2; k++)
    {
        PFN_Dns p = k ? pOld : pEx;

        for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
        {
            PCWSTR Expected = k ? Cases[i].Old : Cases[i].Ex;
            BOOL Result;

            Size = 64;
            RtlFillMemory(Out, sizeof(Out), 0xDD);
            SetLastError(0xdeadbeef);
            Result = p(Cases[i].In, Out, &Size);
            if (!Expected)
            {
                ok(!Result && GetLastError() == ERROR_INVALID_COMPUTERNAME, "%s \"%ls\": %d, error %lu\n", k ? "W" : "ExW", Cases[i].In, Result, GetLastError());
                continue;
            }
            ok(Result && wcscmp(Out, Expected) == 0 && Size == wcslen(Expected) && GetLastError() == 0xdeadbeef,
               "%s \"%ls\": %d, \"%ls\", size %lu, error %lu\n", k ? "W" : "ExW", Cases[i].In, Result, Out, Size, GetLastError());
        }

        /* the buffer holds the result and the null; else ERROR_MORE_DATA, the length without the null, buffer untouched */
        Size = 3;
        RtlFillMemory(Out, sizeof(Out), 0xDD);
        SetLastError(0xdeadbeef);
        ok(!p(L"hostname.example.com", Out, &Size) && GetLastError() == ERROR_MORE_DATA && Size == (k ? 8 : 15) && Out[0] == 0xDDDD,
           "buffer of 3: error %lu, size %lu\n", GetLastError(), Size);
        Size = 8;
        SetLastError(0xdeadbeef);
        ok(!p(L"hostname.example.com", Out, &Size) && GetLastError() == ERROR_MORE_DATA && Size == (k ? 8 : 15), "buffer of 8: error %lu, size %lu\n", GetLastError(), Size);
        Size = 0;
        SetLastError(0xdeadbeef);
        ok(!p(L"hostname.example.com", NULL, &Size) && GetLastError() == ERROR_MORE_DATA && Size == (k ? 8 : 15), "no buffer: error %lu, size %lu\n", GetLastError(), Size);
        if (k)
        {
            Size = 9;
            ok(p(L"hostname.example.com", Out, &Size) && wcscmp(Out, L"HOSTNAME") == 0 && Size == 8, "buffer of 9\n");
            SetLastError(0xdeadbeef);
            ok(!p(NULL, Out, &Size) && GetLastError() == ERROR_INVALID_COMPUTERNAME, "NULL name: error %lu\n", GetLastError());
        }
    }
}

/* ------------------------------------------------------------------------------------------------ small queries */

static void
test_Small(void)
{
    typedef BOOL (WINAPI *PFN_Vhd)(PBOOL);
    typedef BOOL (WINAPI *PFN_Mem)(PULONG);
    typedef UINT (WINAPI *PFN_Begin)(UINT);
    typedef UINT (WINAPI *PFN_Caps)(PVOID, UINT);
    typedef DWORD (WINAPI *PFN_Time)(void);
    typedef UINT (WINAPI *PFN_Sys)(PVOID, UINT);
    PFN_Vhd pVhd = (PVOID)Proc("IsNativeVhdBoot");
    PFN_Mem pMem = (PVOID)Proc("GetMemoryErrorHandlingCapabilities");
    PFN_Begin pBegin = (PVOID)Proc("timeBeginPeriod");
    PFN_Begin pEnd = (PVOID)Proc("timeEndPeriod");
    PFN_Caps pCaps = (PVOID)Proc("timeGetDevCaps");
    PFN_Time pTime = (PVOID)Proc("timeGetTime");
    PFN_Sys pSys = (PVOID)Proc("timeGetSystemTime");
    BOOL Native;
    ULONG Capabilities;
    DWORD Caps[4];
    DWORD Mm[4];
    DWORD T0, T1;

    ok(pVhd && pMem, "IsNativeVhdBoot/GetMemoryErrorHandlingCapabilities are not exported\n");
    if (pVhd)
    {
        Native = 0x55;
        ok(pVhd(&Native) && Native == FALSE, "IsNativeVhdBoot: native %d\n", Native);
    }
    if (pMem)
    {
        Capabilities = 0x55;
        SetLastError(0xdeadbeef);
        ok(pMem(&Capabilities) && Capabilities == 0 && GetLastError() == ERROR_NOT_FOUND, "capabilities %lx, error %lu\n", Capabilities, GetLastError());
    }

    ok(pBegin && pEnd && pCaps && pTime && pSys, "the time* names are not exported by kernel32\n");
    if (pBegin && pEnd && pCaps && pTime && pSys)
    {
        ok(pBegin(0) == 97, "timeBeginPeriod(0)\n");
        ok(pBegin(1) == 0, "timeBeginPeriod(1)\n");
        ok(pEnd(1) == 0, "timeEndPeriod(1)\n");
        ok(pEnd(1) == 97, "an unmatched timeEndPeriod\n");
        ok(pCaps(Caps, 8) == 0 && Caps[0] == 1 && Caps[1] == 1000000, "timeGetDevCaps: %lu %lu\n", Caps[0], Caps[1]);
        ok(pCaps(Caps, 4) == 97 && pCaps(Caps, 0) == 97 && pCaps(NULL, 8) == 97, "timeGetDevCaps with a bad size or pointer\n");
        T0 = pTime();
        Sleep(120);
        T1 = pTime();
        ok(T1 - T0 >= 100 && T1 - T0 < 400, "timeGetTime moved by %lu ms in 120 ms\n", T1 - T0);
        RtlFillMemory(Mm, sizeof(Mm), 0xCC);
        ok(pSys(Mm, 12) == 0 && Mm[0] == 1 /* TIME_MS */, "timeGetSystemTime: type %lu\n", Mm[0]);
        ok(pSys(Mm, 4) == 129 && pSys(Mm, 0) == 129, "timeGetSystemTime with a bad size\n");
    }
}

/* the registry names that kernel32 exports on Windows 10 (contract api-ms-win-core-registry) reach advapi32 */
static void
test_RegistryForwards(void)
{
    typedef LONG (WINAPI *PFN_Open)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LONG (WINAPI *PFN_Query)(HKEY, LPCWSTR, PDWORD, PDWORD, PBYTE, PDWORD);
    typedef LONG (WINAPI *PFN_Close)(HKEY);
    PFN_Open pOpen = (PVOID)Proc("RegOpenKeyExW");
    PFN_Query pQuery = (PVOID)Proc("RegQueryValueExW");
    PFN_Close pClose = (PVOID)Proc("RegCloseKey");
    HMODULE Advapi32 = LoadLibraryW(L"advapi32.dll");
    static const char *Names[] =
    {
        "RegCloseKey", "RegCopyTreeW", "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyExA", "RegDeleteKeyExW", "RegDeleteTreeA",
        "RegDeleteTreeW", "RegDeleteValueA", "RegDeleteValueW", "RegEnumKeyExA", "RegEnumKeyExW", "RegEnumValueA", "RegEnumValueW",
        "RegFlushKey", "RegGetKeySecurity", "RegGetValueA", "RegGetValueW", "RegLoadKeyA", "RegLoadKeyW", "RegNotifyChangeKeyValue",
        "RegOpenCurrentUser", "RegOpenKeyExA", "RegOpenKeyExW", "RegOpenUserClassesRoot", "RegQueryInfoKeyA", "RegQueryInfoKeyW",
        "RegQueryValueExA", "RegQueryValueExW", "RegRestoreKeyA", "RegRestoreKeyW", "RegSaveKeyExA", "RegSaveKeyExW", "RegSetKeySecurity",
        "RegSetValueExA", "RegSetValueExW", "RegUnLoadKeyA", "RegUnLoadKeyW", "CreateProcessAsUserA", "CheckTokenMembershipEx",
    };
    ULONG i;
    HKEY Key;
    WCHAR Value[64];
    DWORD Size = sizeof(Value), Type;

    for (i = 0; i < RTL_NUMBER_OF(Names); i++)
    {
        FARPROC Own = Proc(Names[i]);
        FARPROC Target = Advapi32 ? GetProcAddress(Advapi32, Names[i]) : NULL;

        ok(Own != NULL, "kernel32!%s is not exported\n", Names[i]);
        if (Own && Target && is_reactos())
            ok(Own == Target, "kernel32!%s is not advapi32!%s\n", Names[i], Names[i]);
    }

    if (pOpen && pQuery && pClose)
    {
        ok(pOpen(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS, "RegOpenKeyExW\n");
        ok(pQuery(Key, L"ProductName", NULL, &Type, (PBYTE)Value, &Size) == ERROR_SUCCESS && Type == REG_SZ, "RegQueryValueExW\n");
        ok(pClose(Key) == ERROR_SUCCESS, "RegCloseKey\n");
    }
}

START_TEST(Win10Exports)
{
    g_Kernel32 = GetModuleHandleW(L"kernel32.dll");
    LoadLibraryW(L"kernelbase.dll");

    test_GlobalAddAtomEx();
    test_Barrier();
    test_TokenFunctions();
    test_Acl();
    test_Numa();
    test_ThreadpoolStack();
    test_DiskSpace();
    test_LocalTime();
    test_DnsHostname();
    test_Small();
    test_RegistryForwards();
}
