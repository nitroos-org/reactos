/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     AccessCheck with malformed DACLs, and with DACLs of thousands of ACEs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * NtAccessCheck captures the descriptor of its caller and validates its ACLs first: a DACL with an ACE
 * of size 0, of a size that is not a multiple of 4, one that runs past AclSize, more ACEs counted than
 * fit, an AclSize below the ACL header or a bad revision (ERROR_INVALID_ACL) never reaches the access check of the kernel.
 * These rows fix the result (the same before and after the kernel's ACE walk became one pass). The large
 * DACL rows check that every ACE of a DACL of about 3 300 ACEs counts, the last one too.
 * The owner of these descriptors (LOCAL SERVICE) is not in the caller's token: no implicit owner rights.
 */

static GENERIC_MAPPING Mapping = {0x1 | READ_CONTROL, 0x2 | WRITE_DAC, 0x4 | SYNCHRONIZE, 0x3F | STANDARD_RIGHTS_REQUIRED};
static SID LocalService = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SERVICE_RID } };
static SID World = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };

static void Check(int Line, HANDLE Token, PACL Acl, DWORD Desired, BOOL ExpectResult, DWORD ExpectError,
                  BOOL ExpectStatus, DWORD ExpectGranted)
{
    SECURITY_DESCRIPTOR Sd;
    BYTE PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted = 0xCCCCCCCC, Error;
    BOOL Status = 0xCC, Result;

    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Sd, &LocalService, FALSE);
    SetSecurityDescriptorGroup(&Sd, &LocalService, FALSE);
    SetSecurityDescriptorDacl(&Sd, TRUE, Acl, FALSE);
    SetLastError(0xDEADBEEF);
    Result = AccessCheck(&Sd, Token, Desired, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status);
    Error = Result ? 0 : GetLastError();
    ok_(__FILE__, Line)(Result == ExpectResult, "0x%lx: AccessCheck returned %d, expected %d (error %lu)\n", Desired, Result, ExpectResult, Error);
    if (!Result)
    {
        ok_(__FILE__, Line)(Error == ExpectError, "0x%lx: error %lu, expected %lu\n", Desired, Error, ExpectError);
        return;
    }
    ok_(__FILE__, Line)(Status == ExpectStatus, "0x%lx: access status %d, expected %d\n", Desired, Status, ExpectStatus);
    ok_(__FILE__, Line)(Granted == ExpectGranted, "0x%lx: granted 0x%lx, expected 0x%lx\n", Desired, Granted, ExpectGranted);
}
#define CHECK_OK(t, a, d, st, g)    Check(__LINE__, t, a, d, TRUE, 0, st, g)
#define CHECK_REFUSED(t, a, d, e)   Check(__LINE__, t, a, d, FALSE, e, FALSE, 0)

static void PutAce(PACL Acl, ULONG Offset, UCHAR Type, USHORT Size, ACCESS_MASK Mask, PSID Sid)
{
    PACCESS_ALLOWED_ACE Ace = (PACCESS_ALLOWED_ACE)((PBYTE)Acl + Offset);

    Ace->Header.AceType = Type;
    Ace->Header.AceFlags = 0;
    Ace->Header.AceSize = Size;
    memcpy(&Ace->Mask, &Mask, sizeof(Mask));
    memcpy((PBYTE)Ace + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart), Sid, GetLengthSid(Sid));
}

static void MakeAcl(PACL Acl, ULONG Bytes, USHORT AclSize, USHORT AceCount, BYTE Revision)
{
    ZeroMemory(Acl, Bytes);
    Acl->AclRevision = Revision;
    Acl->AclSize = AclSize;
    Acl->AceCount = AceCount;
}

static void TestMalformed(HANDLE Token)
{
    BYTE Buffer[512];
    PACL Acl = (PACL)Buffer;
    const USHORT Ace = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + sizeof(World));   /* 20 */

    /* Well formed: Everyone 0x1 */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + Ace, 1, ACL_REVISION);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, &World);
    CHECK_OK(Token, Acl, 0x1, TRUE, 0x1);
    CHECK_OK(Token, Acl, 0x2, FALSE, 0);
    CHECK_OK(Token, Acl, MAXIMUM_ALLOWED, TRUE, 0x1);

    /* An ACE of size 0 */
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 0, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);
    CHECK_REFUSED(Token, Acl, MAXIMUM_ALLOWED, ERROR_INVALID_ACL);

    /* AceSize 22, not a multiple of 4, and the next ACE behind it */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + 22 + Ace, 2, ACL_REVISION);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 22, 0x2, &World);
    PutAce(Acl, sizeof(ACL) + 22, ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);

    /* AceSize 18 */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + Ace, 1, ACL_REVISION);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 18, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);

    /* The ACE runs 4 bytes past AclSize */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + Ace - 4, 1, ACL_REVISION);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);

    /* AceCount 3, one ACE that ends at AclSize */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + Ace, 3, ACL_REVISION);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);

    /* AceCount 3, one ACE and 12 bytes of zeros */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + Ace + 12, 3, ACL_REVISION);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);

    /* AclSize below the ACL header */
    MakeAcl(Acl, sizeof(Buffer), 4, 0, ACL_REVISION);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);

    /* Revision 9 */
    MakeAcl(Acl, sizeof(Buffer), sizeof(ACL) + Ace, 1, 9);
    PutAce(Acl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, Ace, 0x1, &World);
    CHECK_REFUSED(Token, Acl, 0x1, ERROR_INVALID_ACL);
}

/* N ACEs for SIDs nobody has (S-1-9-<i>, 20 bytes each), then the ACE of interest as the last one */
static PACL MakeLargeAcl(ULONG Count, UCHAR LastType, ACCESS_MASK LastMask)
{
    SID Unknown = { SID_REVISION, 1, { {0, 0, 0, 0, 0, 9} }, { 0 } };
    PACL Acl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFFFC);
    ULONG i;

    if (!Acl || !InitializeAcl(Acl, 0xFFFC, ACL_REVISION))
        return NULL;
    for (i = 0; i < Count; i++)
    {
        Unknown.SubAuthority[0] = 1000 + i;
        if (!AddAccessAllowedAce(Acl, ACL_REVISION, 0x3, &Unknown))
            break;
    }
    if (LastType == ACCESS_DENIED_ACE_TYPE)
        AddAccessDeniedAce(Acl, ACL_REVISION, LastMask, &World);
    else
        AddAccessAllowedAce(Acl, ACL_REVISION, LastMask, &World);
    return Acl;
}

static void TestLarge(HANDLE Token)
{
    PACL Acl;

    /* 3 275 ACEs: Everyone 0x1 is the last one */
    Acl = MakeLargeAcl(3274, ACCESS_ALLOWED_ACE_TYPE, 0x1);
    ok(Acl && Acl->AceCount == 3275, "AceCount %u\n", Acl ? Acl->AceCount : 0);
    if (Acl)
    {
        CHECK_OK(Token, Acl, 0x1, TRUE, 0x1);
        CHECK_OK(Token, Acl, 0x2, FALSE, 0);
        CHECK_OK(Token, Acl, MAXIMUM_ALLOWED, TRUE, 0x1);
        HeapFree(GetProcessHeap(), 0, Acl);
    }

    /* The same with Everyone denied 0x1 last, and an allow of 0x3 for Everyone first */
    Acl = MakeLargeAcl(0, ACCESS_ALLOWED_ACE_TYPE, 0x2);
    if (Acl)
    {
        SID Unknown = { SID_REVISION, 1, { {0, 0, 0, 0, 0, 9} }, { 0 } };
        ULONG i;

        for (i = 0; i < 3000; i++)
        {
            Unknown.SubAuthority[0] = 1000 + i;
            AddAccessAllowedAce(Acl, ACL_REVISION, 0x1, &Unknown);
        }
        AddAccessDeniedAce(Acl, ACL_REVISION, 0x1, &World);
        AddAccessAllowedAce(Acl, ACL_REVISION, 0x1, &World);
        CHECK_OK(Token, Acl, 0x2, TRUE, 0x2);
        CHECK_OK(Token, Acl, 0x1, FALSE, 0);
        CHECK_OK(Token, Acl, MAXIMUM_ALLOWED, TRUE, 0x2);
        HeapFree(GetProcessHeap(), 0, Acl);
    }
}

START_TEST(AccessCheckMalformedAcl)
{
    HANDLE Process, Token;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &Process), "OpenProcessToken: %lu\n", GetLastError());
    ok(DuplicateToken(Process, SecurityImpersonation, &Token), "DuplicateToken: %lu\n", GetLastError());
    TestMalformed(Token);
    TestLarge(Token);
    CloseHandle(Token);
    CloseHandle(Process);
}
