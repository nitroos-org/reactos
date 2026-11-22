/*
 * PROJECT:     NitroOS unit tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The kernel's verdict on a stored key descriptor of a per-user hive (ntoskrnl/config/cmaclsd.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Rows: owner x ACE list (x the key's place) -> keep (0) or the reasons to
 * replace the descriptor. The descriptors are self-relative, as the kernel
 * passes its validated copies.
 */

#include "ntoskrnl.h"
#include <winnls.h>
#include <sddl.h>
#include <stdio.h>
#include "../../../../ntoskrnl/config/cmaclsd.h"

#define OWN     "S-1-5-21-1-2-3-1001"
#define OTHER   "S-1-5-21-1-2-3-1002"
#define LS      "S-1-5-19"
#define NS      "S-1-5-20"
#define PKG     "S-1-15-2-1-2-3-4-5-6-7"
#define AC      "S-1-15-2-1"
#define LPAC    "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"
#define TI      "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
#define RC      "S-1-5-12"

/* The default of HKU\<SID> (cmacl.c CmpAclSdUser) and what a key below inherits from it */
#define ROOT_DACL(Sid) "D:P(A;OICI;KA;;;" Sid ")(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;" RC ")(A;;KR;;;" AC ")(A;;KR;;;" LPAC ")"
#define CHILD_DACL(Sid) "D:AI(A;OICIID;KA;;;" Sid ")(A;OICIID;KA;;;SY)(A;OICIID;KA;;;BA)(A;OICIID;KR;;;" RC ")"

#define ROOT    CMP_ACL_UH_PLACE_ROOT
#define APPC    CMP_ACL_UH_PLACE_APPCONTAINER

#define R_OWNER CMP_ACL_UH_OWNER
#define R_WRITE CMP_ACL_UH_WRITE
#define R_TYPE  CMP_ACL_UH_ACETYPE
#define R_READ  CMP_ACL_UH_READ
#define R_DENY  CMP_ACL_UH_DENY
#define R_LABEL CMP_ACL_UH_LABEL

typedef struct _ROW
{
    PCSTR What;
    PCSTR Own;
    ULONG Place;
    PCSTR Sddl;
    ULONG Expected;
} ROW;

static const ROW Rows[] =
{
    /* The defaults: kept */
    { "default root", OWN, ROOT, "O:BAG:SY" ROOT_DACL(OWN), 0 },
    { "default root, NetworkService", NS, ROOT, "O:BAG:SY" ROOT_DACL(NS), 0 },
    { "default root, LocalService", LS, ROOT, "O:BAG:SY" ROOT_DACL(LS), 0 },
    { "key the user created", OWN, 0, "O:" OWN "G:" OWN CHILD_DACL(OWN), 0 },
    { "key an administrator created in its own hive", OWN, 0, "O:BAG:SY" CHILD_DACL(OWN), 0 },
    { "key SYSTEM created (profile service)", OWN, 0, "O:SYG:SY" CHILD_DACL(OWN), 0 },
    { "key owned by TrustedInstaller", OWN, 0, "O:" TI "G:SY" CHILD_DACL(OWN), 0 },
    { "NetworkService's own key", NS, 0, "O:" NS "G:" NS CHILD_DACL(NS), 0 },
    { "user's restrictive DACL (only itself)", OWN, 0, "O:" OWN "G:" OWN "D:P(A;;KA;;;" OWN ")", 0 },
    { "user's restrictive DACL (itself read only)", OWN, 0, "O:" OWN "G:" OWN "D:P(A;;KR;;;" OWN ")", 0 },
    { "user's restrictive DACL (itself + SYSTEM)", OWN, 0, "O:" OWN "G:" OWN "D:P(A;CI;KA;;;" OWN ")(A;CI;KA;;;SY)", 0 },
    { "CREATOR OWNER inherit-only", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CIIO;KA;;;CO)", 0 },
    { "CREATOR GROUP inherit-only", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CIIO;KA;;;CG)", 0 },
    { "OWNER RIGHTS allow", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KR;;;S-1-3-4)", 0 },
    { "RESTRICTED read", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN), 0 },
    { "an allow with an empty mask", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;0x0;;;WD)", 0 },
    { "audit ACE for Everyone", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(AU;SAFA;KA;;;WD)", 0 },

    /* Planted owner: replaced */
    { "owner: another account", OWN, 0, "O:" OTHER "G:" OTHER CHILD_DACL(OWN), R_OWNER },
    { "owner: Users", OWN, 0, "O:BUG:SY" CHILD_DACL(OWN), R_OWNER },
    { "owner: Everyone", OWN, 0, "O:WDG:SY" CHILD_DACL(OWN), R_OWNER },
    { "owner: LocalService in NetworkService's hive", NS, 0, "O:" LS "G:SY" CHILD_DACL(NS), R_OWNER },
    { "owner: missing", OWN, 0, "G:SY" CHILD_DACL(OWN), R_OWNER },
    { "key another account created (owner, its full control)", OWN, 0,
      "O:" OTHER "G:" OTHER CHILD_DACL(OWN) "(A;OICI;KA;;;" OTHER ")", R_OWNER | R_WRITE },

    /* Planted write grants: replaced */
    { "Everyone full, inheritable (the Run key row)", OWN, 0, "O:BAG:SY" "D:(A;CI;KA;;;WD)", R_WRITE },
    { "Everyone full added to the default", OWN, 0, "O:BAG:SY" CHILD_DACL(OWN) "(A;CI;KA;;;WD)", R_WRITE },
    { "Users set value", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;0x2;;;BU)", R_WRITE },
    { "Authenticated Users create subkey", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;0x4;;;AU)", R_WRITE },
    { "another account create link", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;0x20;;;" OTHER ")", R_WRITE },
    { "another account DELETE", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;SD;;;" OTHER ")", R_WRITE },
    { "another account WRITE_DAC", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;WD;;;" OTHER ")", R_WRITE },
    { "another account WRITE_OWNER", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;WO;;;" OTHER ")", R_WRITE },
    { "Everyone GENERIC_ALL", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;GA;;;WD)", R_WRITE },
    { "Everyone GENERIC_WRITE", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;GW;;;WD)", R_WRITE },
    { "Everyone MAXIMUM_ALLOWED", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;0x2000000;;;WD)", R_WRITE },
    { "RESTRICTED write", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KA;;;" RC ")", R_WRITE },
    { "NetworkService write in a user's hive", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KA;;;NS)", R_WRITE },
    { "Everyone full in NetworkService's Classes", NS, 0, "O:BAG:SY" CHILD_DACL(NS) "(A;CI;KA;;;WD)", R_WRITE },
    { "Everyone full in LocalService's hive", LS, 0, "O:BAG:SY" CHILD_DACL(LS) "(A;CI;KA;;;WD)", R_WRITE },
    { "1500 read grants to other accounts, then Everyone full", OWN, 0, NULL /* built */, R_WRITE | R_READ },

    /* Inheritance flags */
    { "Everyone full, container inherit + inherit only (children only)", OWN, 0,
      "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CIIO;KA;;;WD)", R_WRITE },
    { "Everyone full, no propagate + container inherit", OWN, 0,
      "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CINP;KA;;;WD)", R_WRITE },
    { "Everyone full, container inherit + inherit only + no propagate", OWN, 0,
      "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CIIONP;KA;;;WD)", R_WRITE },
    { "Everyone full, object inherit + inherit only (never on a key)", OWN, 0,
      "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;OIIO;KA;;;WD)", 0 },
    { "Everyone full, inherited copy (ID)", OWN, 0,
      "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CIID;KA;;;WD)", R_WRITE },

    /* Read grants: removed */
    { "Everyone read", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;CI;KR;;;WD)", R_READ },
    { "Users read", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KR;;;BU)", R_READ },
    { "another account query value", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;0x1;;;" OTHER ")", R_READ },
    { "Everyone READ_CONTROL only", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;RC;;;WD)", R_READ },
    { "Everyone GENERIC_READ", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;GR;;;WD)", R_READ },
    { "ALL APPLICATION PACKAGES read below the root", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KR;;;" AC ")", R_READ },
    { "LPAC read below the root", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KR;;;" LPAC ")", R_READ },
    { "the default root's descriptor on another key (AC/LPAC)", OWN, 0, "O:BAG:SY" ROOT_DACL(OWN), R_READ },
    { "ALL APPLICATION PACKAGES read on the root, inheritable", OWN, ROOT,
      "O:BAG:SY" ROOT_DACL(OWN) "(A;CI;KR;;;" AC ")", R_READ },
    { "ALL APPLICATION PACKAGES write on the root", OWN, ROOT, "O:BAG:SY" ROOT_DACL(OWN) "(A;;KA;;;" AC ")", R_WRITE },

    /* AppContainer storage: the package SID only there */
    { "package full control in AppContainer\\Storage", OWN, APPC,
      "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;OICI;KA;;;" PKG ")", 0 },
    { "package full control elsewhere", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;OICI;KA;;;" PKG ")", R_WRITE },
    { "package read elsewhere", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KR;;;" PKG ")", R_READ },
    { "Everyone full in AppContainer\\Storage", OWN, APPC, "O:" OWN "G:SY" CHILD_DACL(OWN) "(A;;KA;;;WD)", R_WRITE },

    /* Deny ACEs */
    { "deny the account itself (a denial of service)", OWN, 0,
      "O:" OWN "G:SY" "D:(D;;KA;;;" OWN ")(A;OICIID;KA;;;" OWN ")(A;OICIID;KA;;;SY)", R_DENY },
    { "deny Everyone set value", OWN, 0, "O:" OWN "G:SY" "D:(D;CI;0x2;;;WD)(A;OICIID;KA;;;" OWN ")", R_DENY },
    { "deny SYSTEM", OWN, 0, "O:" OWN "G:SY" "D:(D;;KA;;;SY)(A;OICIID;KA;;;" OWN ")", R_DENY },
    { "deny Administrators", OWN, 0, "O:" OWN "G:SY" "D:(D;;KA;;;BA)(A;OICIID;KA;;;" OWN ")", R_DENY },
    { "deny OWNER RIGHTS", OWN, 0, "O:" OWN "G:SY" "D:(D;;WD;;;S-1-3-4)(A;OICIID;KA;;;" OWN ")", R_DENY },
    { "deny INTERACTIVE, inherit only to subkeys", OWN, 0, "O:" OWN "G:SY" "D:(D;CIIO;KA;;;IU)(A;OICIID;KA;;;" OWN ")", R_DENY },
    { "deny the account, object inherit only (never on a key)", OWN, 0,
      "O:" OWN "G:SY" "D:(D;OIIO;KA;;;" OWN ")(A;OICIID;KA;;;" OWN ")", 0 },
    { "deny another account (harmless)", OWN, 0, "O:" OWN "G:SY" "D:(D;;KA;;;" OTHER ")(A;OICIID;KA;;;" OWN ")", 0 },
    { "deny with an empty mask", OWN, 0, "O:" OWN "G:SY" "D:(D;;0x0;;;" OWN ")(A;OICIID;KA;;;" OWN ")", 0 },
    { "deny SERVICE in LocalService's hive", LS, 0, "O:" LS "G:SY" "D:(D;;KA;;;SU)(A;OICIID;KA;;;" LS ")", R_DENY },

    /* No DACL */
    { "NULL DACL", OWN, 0, "O:" OWN "G:SY" "D:NO_ACCESS_CONTROL", R_WRITE },
    { "no DACL at all", OWN, 0, "O:" OWN "G:SY", R_WRITE },
    { "empty DACL (nobody: kept)", OWN, 0, "O:" OWN "G:SY" "D:P", 0 },

    /* Mandatory labels */
    { "label Low (AppDataLow)", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(ML;CI;0x1;;;S-1-16-4096)", 0 },
    { "label Untrusted", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(ML;;0x1;;;S-1-16-0)", 0 },
    { "label Medium", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(ML;;0x1;;;S-1-16-8192)", 0 },
    { "label High", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(ML;;0x1;;;S-1-16-12288)", R_LABEL },
    { "label System, inherit only to subkeys", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(ML;CIIO;0x1;;;S-1-16-16384)", R_LABEL },
    { "label High, object inherit only (never on a key)", OWN, 0, "O:" OWN "G:SY" CHILD_DACL(OWN) "S:(ML;OIIO;0x1;;;S-1-16-12288)", 0 },

    /* Combinations */
    { "planted owner + Everyone read + deny the account", OWN, 0,
      "O:" OTHER "G:SY" "D:(D;;KA;;;" OWN ")(A;;KR;;;WD)", R_OWNER | R_DENY | R_READ },
    { "the account's hive name for another SID", OTHER, 0, "O:" OWN "G:" OWN CHILD_DACL(OWN), R_OWNER | R_WRITE },
};

static const GENERIC_MAPPING KeyMapping = { KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS };

/* A DACL of 1500 ACEs for other accounts' read, then Everyone full (the review's "Big" variant) */
static PWSTR BuildBigSddl(void)
{
    static const WCHAR Head[] = L"O:S-1-5-21-1-2-3-1001G:SYD:";
    SIZE_T Chars = wcslen(Head) + 1500 * 48 + 64;
    PWSTR Sddl = HeapAlloc(GetProcessHeap(), 0, Chars * sizeof(WCHAR)), p;
    int Used;
    ULONG i;

    if (!Sddl)
        return NULL;
    wcscpy(Sddl, Head);
    p = Sddl + wcslen(Sddl);
    for (i = 0; i < 1500; i++)
    {
        Used = _snwprintf(p, Chars - (p - Sddl), L"(A;;KR;;;S-1-5-21-9-9-9-%lu)", 2000 + i);
        if (Used <= 0)
        {
            HeapFree(GetProcessHeap(), 0, Sddl);
            return NULL;
        }
        p += Used;
    }
    wcscpy(p, L"(A;CI;KA;;;WD)");
    return Sddl;
}

/* An allow ACE of another type (callback: 0x9; object: 0x5), Everyone, KEY_READ; or a deny object ACE (0x6) */
static PSECURITY_DESCRIPTOR BuildOddAce(UCHAR AceType, PSID Own)
{
    static SID_IDENTIFIER_AUTHORITY World = {SECURITY_WORLD_SID_AUTHORITY};
    UCHAR AclBuffer[256], AceBuffer[96];
    SECURITY_DESCRIPTOR Absolute;
    PACL Acl = (PACL)AclBuffer;
    PACE_HEADER Ace = (PACE_HEADER)AceBuffer;
    PSID Everyone = NULL;
    PSECURITY_DESCRIPTOR Relative = NULL;
    ULONG Length = 0, AceSize;
    PUCHAR p;

    if (!AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone))
        return NULL;
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION_DS);
    AddAccessAllowedAceEx(Acl, ACL_REVISION_DS, CONTAINER_INHERIT_ACE, KEY_ALL_ACCESS, Own);

    /* header, mask, (object: flags), SID, (callback: 4 bytes of data) */
    ZeroMemory(AceBuffer, sizeof(AceBuffer));
    p = AceBuffer + sizeof(ACE_HEADER);
    *(PULONG)p = KEY_READ;
    p += sizeof(ULONG);
    if (AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE || AceType == ACCESS_DENIED_OBJECT_ACE_TYPE)
    {
        *(PULONG)p = 0;     /* no object types */
        p += sizeof(ULONG);
    }
    CopySid(GetLengthSid(Everyone), p, Everyone);
    p += GetLengthSid(Everyone);
    if (AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
        p += 4;
    AceSize = (ULONG)(p - AceBuffer);
    Ace->AceType = AceType;
    Ace->AceFlags = 0;
    Ace->AceSize = (USHORT)AceSize;
    if (!NT_SUCCESS(RtlAddAce(Acl, ACL_REVISION_DS, MAXULONG, Ace, AceSize)))
        goto done;

    InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Absolute, Own, FALSE);
    SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
    MakeSelfRelativeSD(&Absolute, NULL, &Length);
    Relative = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Relative && !MakeSelfRelativeSD(&Absolute, Relative, &Length))
    {
        HeapFree(GetProcessHeap(), 0, Relative);
        Relative = NULL;
    }
done:
    FreeSid(Everyone);
    return Relative;
}

/*
 * The owner's full control, then an ACE of only a header (4 bytes: no room for
 * an access mask) of the given type, the last thing in the ACL
 */
static PSECURITY_DESCRIPTOR BuildShortAce(UCHAR AceType, PSID Own)
{
    UCHAR AclBuffer[128];
    SECURITY_DESCRIPTOR Absolute;
    PACL Acl = (PACL)AclBuffer;
    PACE_HEADER Ace;
    PSECURITY_DESCRIPTOR Relative = NULL;
    ULONG Length = 0, Used;

    ZeroMemory(AclBuffer, sizeof(AclBuffer));
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    AddAccessAllowedAceEx(Acl, ACL_REVISION, CONTAINER_INHERIT_ACE, KEY_ALL_ACCESS, Own);
    Used = sizeof(ACL) + ((PACE_HEADER)(Acl + 1))->AceSize;
    Ace = (PACE_HEADER)(AclBuffer + Used);
    Ace->AceType = AceType;
    Ace->AceFlags = 0;
    Ace->AceSize = sizeof(ACE_HEADER);
    Acl->AceCount++;
    /* The ACL ends right after the short ACE (2 more bytes: the minimum the validation wants after a header) */
    Acl->AclSize = (USHORT)(Used + sizeof(ACE_HEADER) + 2);

    InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Absolute, Own, FALSE);
    SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
    MakeSelfRelativeSD(&Absolute, NULL, &Length);
    Relative = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Relative && !MakeSelfRelativeSD(&Absolute, Relative, &Length))
    {
        HeapFree(GetProcessHeap(), 0, Relative);
        Relative = NULL;
    }
    return Relative;
}

/* A DACL as large as an ACL gets (64 KB): 3 270 read grants of 20 bytes to other SIDs, then Everyone full */
static PSECURITY_DESCRIPTOR BuildFullAcl(PSID Own, PULONG Aces)
{
    static SID_IDENTIFIER_AUTHORITY Null = {SECURITY_NULL_SID_AUTHORITY}, World = {SECURITY_WORLD_SID_AUTHORITY};
    SECURITY_DESCRIPTOR Absolute;
    PSECURITY_DESCRIPTOR Relative = NULL;
    PACL Acl;
    PSID Sid, Everyone = NULL;
    ULONG Length = 0, i;

    *Aces = 0;
    Acl = HeapAlloc(GetProcessHeap(), 0, 0xFFFC);
    if (!Acl || !AllocateAndInitializeSid(&World, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone))
        goto done;
    InitializeAcl(Acl, 0xFFFC, ACL_REVISION);
    for (i = 0; ; i++)
    {
        if (!AllocateAndInitializeSid(&Null, 1, 1000 + i, 0, 0, 0, 0, 0, 0, 0, &Sid))
            break;
        if (!AddAccessAllowedAce(Acl, ACL_REVISION, KEY_READ, Sid))
        {
            FreeSid(Sid);
            break;
        }
        FreeSid(Sid);
    }
    *Aces = i;
    /* Room for the last one: drop grants until it fits */
    while (!AddAccessAllowedAce(Acl, ACL_REVISION, KEY_ALL_ACCESS, Everyone) && Acl->AceCount)
    {
        DeleteAce(Acl, Acl->AceCount - 1);
        (*Aces)--;
    }
    InitializeSecurityDescriptor(&Absolute, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Absolute, Own, FALSE);
    SetSecurityDescriptorDacl(&Absolute, TRUE, Acl, FALSE);
    MakeSelfRelativeSD(&Absolute, NULL, &Length);
    Relative = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Relative && !MakeSelfRelativeSD(&Absolute, Relative, &Length))
    {
        HeapFree(GetProcessHeap(), 0, Relative);
        Relative = NULL;
    }
done:
    if (Everyone)
        FreeSid(Everyone);
    if (Acl)
        HeapFree(GetProcessHeap(), 0, Acl);
    return Relative;
}

static void Judge(PCSTR What, PSECURITY_DESCRIPTOR Sd, PSID Own, ULONG Place, ULONG Expected)
{
    ULONG Verdict, Length;
    PSID Owner = (PSID)1, SdOwner = NULL;
    BOOL Defaulted;
    PVOID Copy;

    ok(IsValidSecurityDescriptor(Sd), "%s: descriptor not valid\n", What);
    Length = GetSecurityDescriptorLength(Sd);
    Copy = HeapAlloc(GetProcessHeap(), 0, Length);
    if (!Copy)
        return;
    CopyMemory(Copy, Sd, Length);

    Verdict = CmpAclUserHiveSdVerdict(Sd, Own, Place, (PGENERIC_MAPPING)&KeyMapping, &Owner);
    ok(Verdict == Expected, "%s: verdict 0x%lx, expected 0x%lx\n", What, Verdict, Expected);

    /* The owner handed back is the descriptor's, and the descriptor is left as it was */
    GetSecurityDescriptorOwner(Sd, &SdOwner, &Defaulted);
    ok(Owner == SdOwner, "%s: owner %p, expected %p\n", What, Owner, SdOwner);
    ok(memcmp(Copy, Sd, Length) == 0, "%s: the descriptor was changed\n", What);

    /* No owner wanted: the same verdict */
    ok(CmpAclUserHiveSdVerdict(Sd, Own, Place, (PGENERIC_MAPPING)&KeyMapping, NULL) == Verdict,
       "%s: verdict differs without the owner\n", What);
    HeapFree(GetProcessHeap(), 0, Copy);
}

START_TEST(UserHiveVerdict)
{
    PSECURITY_DESCRIPTOR Sd;
    PSID Own, Other;
    WCHAR Wide[4096];
    PWSTR Big;
    ULONG i, Length;

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        if (!ConvertStringSidToSidA(Rows[i].Own, &Own))
        {
            ok(0, "%s: bad own SID\n", Rows[i].What);
            continue;
        }
        if (Rows[i].Sddl)
        {
            MultiByteToWideChar(CP_ACP, 0, Rows[i].Sddl, -1, Wide, ARRAYSIZE(Wide));
            Sd = NULL;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Wide, SDDL_REVISION_1, &Sd, &Length))
            {
                ok(0, "%s: SDDL not parsed (%lu): %s\n", Rows[i].What, GetLastError(), Rows[i].Sddl);
                LocalFree(Own);
                continue;
            }
            Judge(Rows[i].What, Sd, Own, Rows[i].Place, Rows[i].Expected);
            LocalFree(Sd);
        }
        else
        {
            Big = BuildBigSddl();
            Sd = NULL;
            ok(Big && ConvertStringSecurityDescriptorToSecurityDescriptorW(Big, SDDL_REVISION_1, &Sd, &Length),
               "%s: not built (%lu)\n", Rows[i].What, GetLastError());
            if (Sd)
            {
                Judge(Rows[i].What, Sd, Own, Rows[i].Place, Rows[i].Expected);
                LocalFree(Sd);
            }
            if (Big)
                HeapFree(GetProcessHeap(), 0, Big);
        }
        LocalFree(Own);
    }

    /* ACE types the kernel never stores on a key */
    ok(ConvertStringSidToSidA(OWN, &Own), "own SID\n");
    ok(ConvertStringSidToSidA(OTHER, &Other), "other SID\n");
    Sd = BuildOddAce(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, Own);
    ok(Sd != NULL, "callback ACE not built\n");
    if (Sd)
    {
        Judge("allow callback ACE for Everyone", Sd, Own, 0, CMP_ACL_UH_ACETYPE);
        HeapFree(GetProcessHeap(), 0, Sd);
    }
    Sd = BuildOddAce(ACCESS_ALLOWED_OBJECT_ACE_TYPE, Own);
    ok(Sd != NULL, "object ACE not built\n");
    if (Sd)
    {
        Judge("allow object ACE for Everyone", Sd, Own, 0, CMP_ACL_UH_ACETYPE);
        HeapFree(GetProcessHeap(), 0, Sd);
    }
    Sd = BuildOddAce(ACCESS_DENIED_OBJECT_ACE_TYPE, Own);
    ok(Sd != NULL, "deny object ACE not built\n");
    if (Sd)
    {
        Judge("deny object ACE (SID not where a plain ACE has it: taken as hurting)", Sd, Own, 0, CMP_ACL_UH_DENY);
        HeapFree(GetProcessHeap(), 0, Sd);
    }

    /* An ACE with no room for its access mask: malformed, its mask is not read past its end */
    Sd = BuildShortAce(ACCESS_DENIED_CALLBACK_ACE_TYPE, Own);
    ok(Sd != NULL, "short ACE not built\n");
    if (Sd)
    {
        Judge("deny callback ACE of 4 bytes (no mask)", Sd, Own, 0, CMP_ACL_UH_ACETYPE);
        HeapFree(GetProcessHeap(), 0, Sd);
    }

    /* The largest ACL: judged in one pass over its ACEs (the last one, Everyone full, is found) */
    {
        ULONG Aces, Start;
        Sd = BuildFullAcl(Own, &Aces);
        ok(Sd != NULL && Aces > 3000, "full ACL not built (%lu ACEs)\n", Aces);
        if (Sd)
        {
            Start = GetTickCount();
            Judge("64 KB DACL: 3 000+ read grants to other SIDs, then Everyone full", Sd, Own, 0,
                  CMP_ACL_UH_READ | CMP_ACL_UH_WRITE);
            trace("64 KB DACL (%lu ACEs): judged 2x in %lu ms\n", Aces + 1, GetTickCount() - Start);
            HeapFree(GetProcessHeap(), 0, Sd);
        }
    }
    LocalFree(Own);
    LocalFree(Other);
}
