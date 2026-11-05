/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the audit category lookups of advapi32: AuditEnumerateCategories,
 *              AuditEnumerateSubCategories, AuditLookupCategoryName[AW], AuditLookupSubCategoryName[AW],
 *              AuditLookupCategoryIdFromCategoryGuid, AuditLookupCategoryGuidFromCategoryId, AuditFree
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (build 19045, x64 and x86), as an administrator and with a filtered token.
 */

#include "precomp.h"

typedef BOOLEAN (WINAPI *FN_ENUM)(GUID **, ULONG *);
typedef BOOLEAN (WINAPI *FN_ENUMSUB)(const GUID *, BOOLEAN, GUID **, ULONG *);
typedef BOOLEAN (WINAPI *FN_NAMEW)(const GUID *, PWSTR *);
typedef BOOLEAN (WINAPI *FN_NAMEA)(const GUID *, PSTR *);
typedef BOOLEAN (WINAPI *FN_IDFROMGUID)(const GUID *, ULONG *);
typedef BOOLEAN (WINAPI *FN_GUIDFROMID)(ULONG, GUID *);
typedef VOID (WINAPI *FN_FREE)(PVOID);

#define PENDING 0xdeadf00d

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif

static const PCWSTR CategoryNames[9] =
{
    L"System", L"Logon/Logoff", L"Object Access", L"Privilege Use", L"Detailed Tracking",
    L"Policy Change", L"Account Management", L"DS Access", L"Account Logon"
};
static const ULONG SubCounts[9] = { 5, 11, 14, 3, 6, 6, 6, 4, 4 };

static FN_ENUM pEnum;
static FN_ENUMSUB pEnumSub;
static FN_NAMEW pCatW, pSubW;
static FN_NAMEA pCatA, pSubA;
static FN_IDFROMGUID pIdFromGuid;
static FN_GUIDFROMID pGuidFromId;
static FN_FREE pFree;

static void ExpectCategoryGuid(const GUID *Guid, ULONG Index)
{
    ok(Guid->Data1 == 0x69979848 + Index && Guid->Data2 == 0x797A && Guid->Data3 == 0x11D9 &&
       Guid->Data4[0] == 0xBE && Guid->Data4[1] == 0xD3 && Guid->Data4[2] == 0x50 && Guid->Data4[3] == 0x50 &&
       Guid->Data4[4] == 0x54 && Guid->Data4[5] == 0x50 && Guid->Data4[6] == 0x30 && Guid->Data4[7] == 0x30,
       "category %lu: GUID %08lx-%04x-%04x-%02x%02x\n", Index, Guid->Data1, Guid->Data2, Guid->Data3,
       Guid->Data4[0], Guid->Data4[1]);
}

static void ExpectSubGuid(const GUID *Guid, ULONG Number)
{
    ok(Guid->Data1 == 0x0CCE9210 + Number && Guid->Data2 == 0x69AE && Guid->Data3 == 0x11D9 &&
       Guid->Data4[0] == 0xBE && Guid->Data4[1] == 0xD3 && Guid->Data4[7] == 0x30,
       "subcategory %lu: GUID %08lx-%04x-%04x\n", Number, Guid->Data1, Guid->Data2, Guid->Data3);
}

static void TestName(const GUID *Guid, BOOLEAN Sub, PCWSTR Expected)
{
    PWSTR Wide = NULL;
    PSTR Ansi = NULL;
    BOOLEAN Ret;
    char Narrow[128];

    SetLastError(PENDING);
    Ret = (Sub ? pSubW : pCatW)(Guid, &Wide);
    ok(Ret == TRUE && GetLastError() == ERROR_SUCCESS, "W lookup: %d, error %lu\n", Ret, GetLastError());
    ok(Wide && !wcscmp(Wide, Expected), "W name %ls, expected %ls\n", Wide ? Wide : L"(null)", Expected);
    if (Wide)
        pFree(Wide);

    SetLastError(PENDING);
    Ret = (Sub ? pSubA : pCatA)(Guid, &Ansi);
    ok(Ret == TRUE && GetLastError() == ERROR_SUCCESS, "A lookup: %d, error %lu\n", Ret, GetLastError());
    WideCharToMultiByte(CP_ACP, 0, Expected, -1, Narrow, sizeof(Narrow), NULL, NULL);
    ok(Ansi && !strcmp(Ansi, Narrow), "A name %s, expected %s\n", Ansi ? Ansi : "(null)", Narrow);
    if (Ansi)
        pFree(Ansi);
}

static void TestErrors(void)
{
    GUID Bad = { 0x12345678 }, Guid, *Array = NULL, *Cats = NULL;
    PWSTR Wide = NULL;
    PSTR Ansi = NULL;
    ULONG Count = 0xcccc, Id = 0xcccc, CatCount = 0;
    BOOLEAN Ret;
    ULONG Id2;

    /* A GUID that is no category, no subcategory, or the other kind */
    SetLastError(PENDING);
    Ret = pCatW(&Bad, &Wide);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER && Wide == NULL, "unknown category: %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCatA(&Bad, &Ansi);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER && Ansi == NULL, "unknown category A: %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pSubW(&Bad, &Wide);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "unknown subcategory: %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pSubA(&Bad, &Ansi);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "unknown subcategory A: %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pIdFromGuid(&Bad, &Id);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER && Id == 0xcccc, "unknown id: %d, %lu, %lx\n", Ret, GetLastError(), Id);
    SetLastError(PENDING);
    Ret = pEnumSub(&Bad, FALSE, &Array, &Count);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER && Count == 0xcccc && !Array, "unknown category enum: %d, %lu\n", Ret, GetLastError());

    ok(pEnum(&Cats, &CatCount) && CatCount == 9, "no categories\n");
    if (Cats && CatCount == 9)
    {
        Array = NULL;
        Count = 0;
        ok(pEnumSub(&Cats[0], FALSE, &Array, &Count) && Count == 5, "no subcategories\n");
        if (Array && Count == 5)
        {
            SetLastError(PENDING);
            Ret = pCatW(&Array[0], &Wide);
            ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "subcategory as a category: %d, %lu\n", Ret, GetLastError());
            SetLastError(PENDING);
            Ret = pSubW(&Cats[0], &Wide);
            ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "category as a subcategory: %d, %lu\n", Ret, GetLastError());
            SetLastError(PENDING);
            Ret = pIdFromGuid(&Array[0], &Id2);
            ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "subcategory as a category id: %d, %lu\n", Ret, GetLastError());
            pFree(Array);
        }
        pFree(Cats);
    }

    /* Identifiers: 0..8 are the categories, 9 and 10 are not */
    memset(&Guid, 0xcc, sizeof(Guid));
    SetLastError(PENDING);
    Ret = pGuidFromId(9, &Guid);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER && Guid.Data1 == 0xcccccccc, "id 9: %d, %lu\n", Ret, GetLastError());
    Ret = pGuidFromId(10, &Guid);
    ok(Ret == FALSE, "id 10: %d\n", Ret);
    /* Windows 10 answers -1 with a GUID that is in no table */
    SetLastError(PENDING);
    Ret = pGuidFromId(0xffffffff, &Guid);
    ok(Ret == TRUE && GetLastError() == PENDING && Guid.Data1 == 0x69979847, "id -1: %d, %lu, %08lx\n", Ret, GetLastError(), Guid.Data1);

    /* NULL arguments (the W form with a NULL GUID is an RPC error of Windows) */
    SetLastError(PENDING);
    Ret = pEnum(NULL, &Count);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "Enum(NULL, &n): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pEnum(&Cats, NULL);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "Enum(&p, NULL): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCatW(NULL, &Wide);
    ok(Ret == FALSE && GetLastError() == RPC_X_NULL_REF_POINTER, "CatW(NULL): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pCatW(&Bad, NULL);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "CatW(guid, NULL): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pGuidFromId(0, NULL);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "GuidFromId(0, NULL): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pIdFromGuid(NULL, &Id2);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "IdFromGuid(NULL): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pIdFromGuid(&Bad, NULL);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "IdFromGuid(guid, NULL): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pEnumSub(NULL, FALSE, &Array, &Count);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "EnumSub(NULL, FALSE): %d, %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pEnumSub(&Bad, TRUE, NULL, &Count);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_PARAMETER, "EnumSub(guid, TRUE, NULL): %d, %lu\n", Ret, GetLastError());
    pFree(NULL);
}

START_TEST(AuditCategories)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    GUID *Cats = NULL, *Subs = NULL, *All = NULL;
    ULONG CatCount = 0, SubCount, AllCount = 0, i, j, Id, Total = 0;
    BOOLEAN Ret;
    GUID Guid;

    pEnum = (FN_ENUM)GetProcAddress(hAdvapi32, "AuditEnumerateCategories");
    pEnumSub = (FN_ENUMSUB)GetProcAddress(hAdvapi32, "AuditEnumerateSubCategories");
    pCatW = (FN_NAMEW)GetProcAddress(hAdvapi32, "AuditLookupCategoryNameW");
    pCatA = (FN_NAMEA)GetProcAddress(hAdvapi32, "AuditLookupCategoryNameA");
    pSubW = (FN_NAMEW)GetProcAddress(hAdvapi32, "AuditLookupSubCategoryNameW");
    pSubA = (FN_NAMEA)GetProcAddress(hAdvapi32, "AuditLookupSubCategoryNameA");
    pIdFromGuid = (FN_IDFROMGUID)GetProcAddress(hAdvapi32, "AuditLookupCategoryIdFromCategoryGuid");
    pGuidFromId = (FN_GUIDFROMID)GetProcAddress(hAdvapi32, "AuditLookupCategoryGuidFromCategoryId");
    pFree = (FN_FREE)GetProcAddress(hAdvapi32, "AuditFree");

    if (!pEnum && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pEnum && pEnumSub && pCatW && pCatA && pSubW && pSubA && pIdFromGuid && pGuidFromId && pFree,
       "audit lookups are not exported: %p %p %p %p %p %p %p %p %p\n",
       pEnum, pEnumSub, pCatW, pCatA, pSubW, pSubA, pIdFromGuid, pGuidFromId, pFree);
    if (!pEnum || !pEnumSub || !pCatW || !pCatA || !pSubW || !pSubA || !pIdFromGuid || !pGuidFromId || !pFree)
        return;

    SetLastError(PENDING);
    Ret = pEnum(&Cats, &CatCount);
    ok(Ret == TRUE && GetLastError() == ERROR_SUCCESS, "AuditEnumerateCategories: %d, %lu\n", Ret, GetLastError());
    ok(CatCount == 9 && Cats, "%lu categories\n", CatCount);
    if (!Cats || CatCount != 9)
        return;

    SetLastError(PENDING);
    Ret = pEnumSub(NULL, TRUE, &All, &AllCount);
    ok(Ret == TRUE && GetLastError() == ERROR_SUCCESS, "all subcategories: %d, %lu\n", Ret, GetLastError());
    ok(AllCount == 59 && All, "%lu subcategories in all\n", AllCount);

    for (i = 0; i < 9; i++)
    {
        ExpectCategoryGuid(&Cats[i], i);
        TestName(&Cats[i], FALSE, CategoryNames[i]);

        Id = 0xcccc;
        SetLastError(PENDING);
        Ret = pIdFromGuid(&Cats[i], &Id);
        ok(Ret == TRUE && Id == i && GetLastError() == PENDING, "id of category %lu: %d, %lu, error %lu\n", i, Ret, Id, GetLastError());

        memset(&Guid, 0, sizeof(Guid));
        SetLastError(PENDING);
        Ret = pGuidFromId(i, &Guid);
        ok(Ret == TRUE && IsEqualGUID(&Guid, &Cats[i]) && GetLastError() == PENDING, "guid of id %lu: %d, error %lu\n", i, Ret, GetLastError());

        Subs = NULL;
        SubCount = 0xcccc;
        SetLastError(PENDING);
        Ret = pEnumSub(&Cats[i], FALSE, &Subs, &SubCount);
        ok(Ret == TRUE && GetLastError() == ERROR_SUCCESS, "subcategories of %lu: %d, %lu\n", i, Ret, GetLastError());
        ok(SubCount == SubCounts[i], "category %lu has %lu subcategories, expected %lu\n", i, SubCount, SubCounts[i]);
        if (!Subs)
            continue;
        for (j = 0; j < SubCount; j++)
        {
            PWSTR Name = NULL;
            ULONG Number = Subs[j].Data1 - 0x0CCE9210, k, Found = 0;

            ExpectSubGuid(&Subs[j], Number);
            ok(pSubW(&Subs[j], &Name) && Name && Name[0], "no name for subcategory %lu of %lu\n", j, i);
            if (Name)
                pFree(Name);
            for (k = 0; All && k < AllCount; k++)
                Found += IsEqualGUID(&All[k], &Subs[j]);
            ok(Found == 1, "subcategory %lu of %lu is in the full list %lu times\n", j, i, Found);
            Total++;
        }
        pFree(Subs);
    }
    ok(Total == 59, "the categories list %lu subcategories\n", Total);

    for (i = 0; All && i < AllCount; i++)
        ok(All[i].Data1 == 0x0CCE9210 + i, "full list %lu: %08lx\n", i, All[i].Data1);

    /* spot checks of the names, first, last and the ones that are out of the order of the GUIDs */
    if (All && AllCount == 59)
    {
        TestName(&All[0], TRUE, L"Security State Change");
        TestName(&All[5], TRUE, L"Logon");
        TestName(&All[16], TRUE, L"SAM");
        TestName(&All[27], TRUE, L"Process Creation");
        TestName(&All[51], TRUE, L"Network Policy Server");
        TestName(&All[55], TRUE, L"User / Device Claims");
        TestName(&All[58], TRUE, L"Token Right Adjusted Events");
    }

    TestErrors();

    /* the same without the rights of an administrator */
    {
        HANDLE Token, Restricted, Impersonation;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token) &&
            CreateRestrictedToken(Token, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &Restricted) &&
            DuplicateTokenEx(Restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation))
        {
            if (SetThreadToken(NULL, Impersonation))
            {
                GUID *Again = NULL;
                ULONG AgainCount = 0;

                ok(pEnum(&Again, &AgainCount) && AgainCount == 9, "filtered token: %lu categories, error %lu\n", AgainCount, GetLastError());
                if (Again)
                    pFree(Again);
                TestName(&Cats[0], FALSE, L"System");
                SetThreadToken(NULL, NULL);
            }
        }
    }

    if (All)
        pFree(All);
    pFree(Cats);
}
