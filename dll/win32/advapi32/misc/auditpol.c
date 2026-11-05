/*
 * PROJECT:     ReactOS advapi32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Security audit policy category tables: AuditEnumerateCategories, AuditEnumerateSubCategories,
 *              AuditLookupCategoryName[AW], AuditLookupSubCategoryName[AW], AuditLookupCategoryIdFromCategoryGuid,
 *              AuditLookupCategoryGuidFromCategoryId, AuditFree
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * These are lookups in the fixed table of audit categories and subcategories (the GUIDs are documented, the
 * names, their order and the error codes were measured on Windows 10 22H2, build 19045, x64 and x86, as an
 * administrator and with a filtered token: the same). They read nothing from the audit policy and need no
 * privilege. The calls that read or change the policy (AuditQuerySystemPolicy, AuditSetSystemPolicy, the per-user
 * and global SACL calls, AuditQuerySecurity, AuditSetSecurity, AuditComputeEffectivePolicy*) are not here: there is
 * no audit policy store in the local security authority, so they stay absent instead of pretending.
 */

#include <advapi32.h>

#include <ndk/rtlfuncs.h>

WINE_DEFAULT_DEBUG_CHANNEL(advapi);

#define AUDIT_CATEGORY_COUNT    9
#define AUDIT_SUBCATEGORY_COUNT 59

#define AUDIT_CATEGORY_DATA1_BASE    0x69979848UL
#define AUDIT_SUBCATEGORY_DATA1_BASE 0x0CCE9210UL

/* Data2, Data3 and Data4 are the same in every category GUID ({6997984x-797A-11D9-BED3-505054503030}) and in every
 * subcategory GUID ({0CCE92xx-69AE-11D9-BED3-505054503030}). */
static const UCHAR AuditGuidTail[8] = { 0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30 };

static const PCWSTR AuditCategoryNames[AUDIT_CATEGORY_COUNT] =
{
    L"System",
    L"Logon/Logoff",
    L"Object Access",
    L"Privilege Use",
    L"Detailed Tracking",
    L"Policy Change",
    L"Account Management",
    L"DS Access",
    L"Account Logon",
};

static const PCWSTR AuditSubCategoryNames[AUDIT_SUBCATEGORY_COUNT] =
{
    L"Security State Change",   /* 0x00 */
    L"Security System Extension",   /* 0x01 */
    L"System Integrity",   /* 0x02 */
    L"IPsec Driver",   /* 0x03 */
    L"Other System Events",   /* 0x04 */
    L"Logon",   /* 0x05 */
    L"Logoff",   /* 0x06 */
    L"Account Lockout",   /* 0x07 */
    L"IPsec Main Mode",   /* 0x08 */
    L"IPsec Quick Mode",   /* 0x09 */
    L"IPsec Extended Mode",   /* 0x0A */
    L"Special Logon",   /* 0x0B */
    L"Other Logon/Logoff Events",   /* 0x0C */
    L"File System",   /* 0x0D */
    L"Registry",   /* 0x0E */
    L"Kernel Object",   /* 0x0F */
    L"SAM",   /* 0x10 */
    L"Certification Services",   /* 0x11 */
    L"Application Generated",   /* 0x12 */
    L"Handle Manipulation",   /* 0x13 */
    L"File Share",   /* 0x14 */
    L"Filtering Platform Packet Drop",   /* 0x15 */
    L"Filtering Platform Connection",   /* 0x16 */
    L"Other Object Access Events",   /* 0x17 */
    L"Sensitive Privilege Use",   /* 0x18 */
    L"Non Sensitive Privilege Use",   /* 0x19 */
    L"Other Privilege Use Events",   /* 0x1A */
    L"Process Creation",   /* 0x1B */
    L"Process Termination",   /* 0x1C */
    L"DPAPI Activity",   /* 0x1D */
    L"RPC Events",   /* 0x1E */
    L"Audit Policy Change",   /* 0x1F */
    L"Authentication Policy Change",   /* 0x20 */
    L"Authorization Policy Change",   /* 0x21 */
    L"MPSSVC Rule-Level Policy Change",   /* 0x22 */
    L"Filtering Platform Policy Change",   /* 0x23 */
    L"Other Policy Change Events",   /* 0x24 */
    L"User Account Management",   /* 0x25 */
    L"Computer Account Management",   /* 0x26 */
    L"Security Group Management",   /* 0x27 */
    L"Distribution Group Management",   /* 0x28 */
    L"Application Group Management",   /* 0x29 */
    L"Other Account Management Events",   /* 0x2A */
    L"Directory Service Access",   /* 0x2B */
    L"Directory Service Changes",   /* 0x2C */
    L"Directory Service Replication",   /* 0x2D */
    L"Detailed Directory Service Replication",   /* 0x2E */
    L"Credential Validation",   /* 0x2F */
    L"Kerberos Service Ticket Operations",   /* 0x30 */
    L"Other Account Logon Events",   /* 0x31 */
    L"Kerberos Authentication Service",   /* 0x32 */
    L"Network Policy Server",   /* 0x33 */
    L"Detailed File Share",   /* 0x34 */
    L"Removable Storage",   /* 0x35 */
    L"Central Policy Staging",   /* 0x36 */
    L"User / Device Claims",   /* 0x37 */
    L"Plug and Play Events",   /* 0x38 */
    L"Group Membership",   /* 0x39 */
    L"Token Right Adjusted Events",   /* 0x3A */
};

static const UCHAR AuditCategory0Subs[] = { 0, 1, 2, 3, 4 };
static const UCHAR AuditCategory1Subs[] = { 5, 6, 7, 8, 9, 10, 11, 12, 51, 55, 57 };
static const UCHAR AuditCategory2Subs[] = { 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 52, 53, 54 };
static const UCHAR AuditCategory3Subs[] = { 24, 25, 26 };
static const UCHAR AuditCategory4Subs[] = { 27, 28, 29, 30, 56, 58 };
static const UCHAR AuditCategory5Subs[] = { 31, 32, 33, 34, 35, 36 };
static const UCHAR AuditCategory6Subs[] = { 37, 38, 39, 40, 41, 42 };
static const UCHAR AuditCategory7Subs[] = { 43, 44, 45, 46 };
static const UCHAR AuditCategory8Subs[] = { 47, 48, 49, 50 };

static const struct { const UCHAR *Subs; ULONG Count; } AuditCategorySubs[AUDIT_CATEGORY_COUNT] =
{
    { AuditCategory0Subs, 5 },
    { AuditCategory1Subs, 11 },
    { AuditCategory2Subs, 14 },
    { AuditCategory3Subs, 3 },
    { AuditCategory4Subs, 6 },
    { AuditCategory5Subs, 6 },
    { AuditCategory6Subs, 6 },
    { AuditCategory7Subs, 4 },
    { AuditCategory8Subs, 4 },
};

static
VOID
AuditMakeGuid(
    _Out_ GUID *Guid,
    _In_ ULONG Data1,
    _In_ USHORT Data2)
{
    Guid->Data1 = Data1;
    Guid->Data2 = Data2;
    Guid->Data3 = 0x11D9;
    RtlCopyMemory(Guid->Data4, AuditGuidTail, sizeof(AuditGuidTail));
}

/* Index of a category GUID, or -1 */
static
LONG
AuditFindCategory(
    _In_ const GUID *Guid)
{
    GUID Expected;
    ULONG Index = Guid->Data1 - AUDIT_CATEGORY_DATA1_BASE;

    if (Index >= AUDIT_CATEGORY_COUNT)
        return -1;
    AuditMakeGuid(&Expected, Guid->Data1, 0x797A);
    return IsEqualGUID(&Expected, Guid) ? (LONG)Index : -1;
}

/* Index of a subcategory GUID, or -1 */
static
LONG
AuditFindSubCategory(
    _In_ const GUID *Guid)
{
    GUID Expected;
    ULONG Index = Guid->Data1 - AUDIT_SUBCATEGORY_DATA1_BASE;

    if (Index >= AUDIT_SUBCATEGORY_COUNT)
        return -1;
    AuditMakeGuid(&Expected, Guid->Data1, 0x69AE);
    return IsEqualGUID(&Expected, Guid) ? (LONG)Index : -1;
}

/******************************************************************************
 * AuditFree [ADVAPI32.@]
 *
 * Releases the buffers of the Audit* calls; NULL is accepted.
 */
VOID
WINAPI
AuditFree(
    _In_ PVOID Buffer)
{
    if (Buffer)
        HeapFree(GetProcessHeap(), 0, Buffer);
}

/******************************************************************************
 * AuditEnumerateCategories [ADVAPI32.@]
 *
 * The categories in the order of their identifiers. A success sets the last error to 0.
 */
BOOLEAN
WINAPI
AuditEnumerateCategories(
    _Out_ GUID **ppAuditCategoriesArray,
    _Out_ PULONG pdwCountReturned)
{
    GUID *Array;
    ULONG i;

    if (!ppAuditCategoriesArray || !pdwCountReturned)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Array = HeapAlloc(GetProcessHeap(), 0, AUDIT_CATEGORY_COUNT * sizeof(GUID));
    if (!Array)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    for (i = 0; i < AUDIT_CATEGORY_COUNT; i++)
        AuditMakeGuid(&Array[i], AUDIT_CATEGORY_DATA1_BASE + i, 0x797A);

    *ppAuditCategoriesArray = Array;
    *pdwCountReturned = AUDIT_CATEGORY_COUNT;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/******************************************************************************
 * AuditEnumerateSubCategories [ADVAPI32.@]
 *
 * With bRetrieveAllSubCategories the category is ignored (it may be NULL) and all 59 subcategories are returned in
 * the order of their GUIDs; otherwise those of the category, in the order Windows lists them. A success sets the
 * last error to 0, a failure leaves the outputs untouched.
 */
BOOLEAN
WINAPI
AuditEnumerateSubCategories(
    _In_opt_ const GUID *pAuditCategoryGuid,
    _In_ BOOLEAN bRetrieveAllSubCategories,
    _Out_ GUID **ppAuditSubCategoriesArray,
    _Out_ PULONG pdwCountReturned)
{
    GUID *Array;
    LONG Category = -1;
    ULONG i, Count;

    if (!ppAuditSubCategoriesArray || !pdwCountReturned)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (bRetrieveAllSubCategories)
    {
        Count = AUDIT_SUBCATEGORY_COUNT;
    }
    else
    {
        if (!pAuditCategoryGuid || (Category = AuditFindCategory(pAuditCategoryGuid)) < 0)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        Count = AuditCategorySubs[Category].Count;
    }

    Array = HeapAlloc(GetProcessHeap(), 0, Count * sizeof(GUID));
    if (!Array)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    for (i = 0; i < Count; i++)
    {
        ULONG Sub = bRetrieveAllSubCategories ? i : AuditCategorySubs[Category].Subs[i];
        AuditMakeGuid(&Array[i], AUDIT_SUBCATEGORY_DATA1_BASE + Sub, 0x69AE);
    }

    *ppAuditSubCategoriesArray = Array;
    *pdwCountReturned = Count;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static
BOOLEAN
AuditLookupNameW(
    _In_ const GUID *Guid,
    _Out_ PWSTR *ppszName,
    _In_ BOOLEAN SubCategory)
{
    LONG Index;
    PCWSTR Name;
    PWSTR Copy;
    SIZE_T Size;

    /* A NULL GUID is a NULL reference for the RPC stub of Windows */
    if (!Guid)
    {
        SetLastError(RPC_X_NULL_REF_POINTER);
        return FALSE;
    }
    if (!ppszName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Index = SubCategory ? AuditFindSubCategory(Guid) : AuditFindCategory(Guid);
    if (Index < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Name = SubCategory ? AuditSubCategoryNames[Index] : AuditCategoryNames[Index];
    Size = (wcslen(Name) + 1) * sizeof(WCHAR);
    Copy = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Copy)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    RtlCopyMemory(Copy, Name, Size);

    *ppszName = Copy;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static
BOOLEAN
AuditLookupNameA(
    _In_ const GUID *Guid,
    _Out_ PSTR *ppszName,
    _In_ BOOLEAN SubCategory)
{
    PWSTR Wide;
    PSTR Ansi;
    int Size;

    if (Guid && !ppszName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!AuditLookupNameW(Guid, &Wide, SubCategory))
        return FALSE;

    Size = WideCharToMultiByte(CP_ACP, 0, Wide, -1, NULL, 0, NULL, NULL);
    Ansi = Size > 0 ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (!Ansi || !WideCharToMultiByte(CP_ACP, 0, Wide, -1, Ansi, Size, NULL, NULL))
    {
        HeapFree(GetProcessHeap(), 0, Ansi);
        AuditFree(Wide);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    AuditFree(Wide);

    *ppszName = Ansi;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/******************************************************************************
 * AuditLookupCategoryNameW and AuditLookupCategoryNameA [ADVAPI32.@]
 *
 * A GUID that is not a category (a subcategory too) is ERROR_INVALID_PARAMETER; NULL as the GUID is
 * RPC_X_NULL_REF_POINTER (measured for the W form, the A form is assumed to match).
 */
BOOLEAN
WINAPI
AuditLookupCategoryNameW(
    _In_ const GUID *pAuditCategoryGuid,
    _Out_ PWSTR *ppszCategoryName)
{
    return AuditLookupNameW(pAuditCategoryGuid, ppszCategoryName, FALSE);
}

BOOLEAN
WINAPI
AuditLookupCategoryNameA(
    _In_ const GUID *pAuditCategoryGuid,
    _Out_ PSTR *ppszCategoryName)
{
    return AuditLookupNameA(pAuditCategoryGuid, ppszCategoryName, FALSE);
}

/******************************************************************************
 * AuditLookupSubCategoryNameW and AuditLookupSubCategoryNameA [ADVAPI32.@]
 */
BOOLEAN
WINAPI
AuditLookupSubCategoryNameW(
    _In_ const GUID *pAuditSubCategoryGuid,
    _Out_ PWSTR *ppszSubCategoryName)
{
    return AuditLookupNameW(pAuditSubCategoryGuid, ppszSubCategoryName, TRUE);
}

BOOLEAN
WINAPI
AuditLookupSubCategoryNameA(
    _In_ const GUID *pAuditSubCategoryGuid,
    _Out_ PSTR *ppszSubCategoryName)
{
    return AuditLookupNameA(pAuditSubCategoryGuid, ppszSubCategoryName, TRUE);
}

/******************************************************************************
 * AuditLookupCategoryIdFromCategoryGuid [ADVAPI32.@]
 *
 * The identifier is the POLICY_AUDIT_EVENT_TYPE value (0 = System ... 8 = Account Logon). A failure is
 * ERROR_INVALID_PARAMETER and leaves the output untouched; a success leaves the last error as it was.
 */
BOOLEAN
WINAPI
AuditLookupCategoryIdFromCategoryGuid(
    _In_ const GUID *pAuditCategoryGuid,
    _Out_ PULONG pAuditCategoryId)
{
    LONG Index;

    if (!pAuditCategoryGuid || !pAuditCategoryId || (Index = AuditFindCategory(pAuditCategoryGuid)) < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *pAuditCategoryId = Index;
    return TRUE;
}

/******************************************************************************
 * AuditLookupCategoryGuidFromCategoryId [ADVAPI32.@]
 *
 * 0 to 8 give the category GUIDs, anything else above 8 is ERROR_INVALID_PARAMETER. The identifier -1 is
 * an oddity of Windows 10, which answers it with success and the GUID {69979847-797A-11D9-BED3-505054503030}
 * (one before the System category, in no table); it is reproduced because it was measured, no other negative
 * value was.
 */
BOOLEAN
WINAPI
AuditLookupCategoryGuidFromCategoryId(
    _In_ ULONG AuditCategoryId,
    _Out_ GUID *pAuditCategoryGuid)
{
    if (!pAuditCategoryGuid || (AuditCategoryId >= AUDIT_CATEGORY_COUNT && AuditCategoryId != 0xFFFFFFFFUL))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    AuditMakeGuid(pAuditCategoryGuid, AUDIT_CATEGORY_DATA1_BASE + AuditCategoryId, 0x797A);
    return TRUE;
}
