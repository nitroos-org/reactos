/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NetLocalGroupAddMembers/DelMembers/SetMembers with member names that do not exist,
 *              members that are one already and non-members
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <lm.h>
#include <pseh/pseh2.h>

/*
 * Measured on Windows 10 22H2, a 64-bit and a 32-bit process alike (level 3, local server):
 * - a member name that does not exist, alone, twice, before or after a name that does exist:
 *   ERROR_NO_SUCH_MEMBER (1387), for Add and for Del;
 * - that error comes before the group is looked at: with a group that does not exist the
 *   list with an unknown name still gives 1387, while only mapped names give NERR_GroupNotFound (2220);
 * - mapped names only: Add of a member that is one already gives ERROR_MEMBER_IN_ALIAS (1378), Del of
 *   a non-member ERROR_MEMBER_NOT_IN_ALIAS (1377), Add to a group that does not exist NERR_GroupNotFound
 *   (2220); ReactOS gave 0 and ERROR_FILE_NOT_FOUND for the first two (harness evidence g5fix-20261106).
 * NetLocalGroupSetMembers is a stub in ReactOS (it returns success without a lookup), so it is not tested.
 * ReactOS: LsaLookupNames returns STATUS_SOME_NOT_MAPPED for a list with some names mapped, and the
 * caller read the domain of the unmapped entry (DomainIndex -1), so the caller faulted.
 */

static const WCHAR Unknown1[] = L"apitest-no-such-member-1";
static const WCHAR Unknown2[] = L"apitest-no-such-member-2";
static const WCHAR AuthUsers[] = L"NT AUTHORITY\\Authenticated Users"; /* a member of Users */
static const WCHAR System[] = L"NT AUTHORITY\\SYSTEM"; /* not a member of Users */
static const WCHAR NoGroup[] = L"apitest-no-such-group";

typedef NET_API_STATUS (WINAPI *MEMBERS_FN)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);

static DWORD Call(MEMBERS_FN Fn, PCWSTR Group, DWORD Count, const WCHAR *Names[], BOOL *Faulted)
{
    LOCALGROUP_MEMBERS_INFO_3 Members[3];
    NET_API_STATUS Status = 0xdeadbeef;
    DWORD i;

    for (i = 0; i < Count; i++)
        Members[i].lgrmi3_domainandname = (LPWSTR)Names[i];

    *Faulted = FALSE;
    _SEH2_TRY
    {
        Status = Fn(NULL, Group, 3, (LPBYTE)Members, Count);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        *Faulted = TRUE;
    }
    _SEH2_END;
    return Status;
}

static void Expect(MEMBERS_FN Fn, PCSTR What, PCWSTR Group, DWORD Count, const WCHAR *Names[], DWORD Expected)
{
    BOOL Faulted;
    DWORD Status = Call(Fn, Group, Count, Names, &Faulted);

    ok(!Faulted, "%s: the call faulted\n", What);
    if (!Faulted)
        ok(Status == Expected, "%s: status %lu, expected %lu\n", What, Status, Expected);
}

START_TEST(NetLocalGroupUnknownMember)
{
    const WCHAR *One[] = { Unknown1 };
    const WCHAR *Two[] = { Unknown1, Unknown2 };
    const WCHAR *MappedUnknown[] = { AuthUsers, Unknown1 };
    const WCHAR *UnknownMapped[] = { Unknown1, AuthUsers };
    const WCHAR *UnknownMappedUnknown[] = { Unknown1, AuthUsers, Unknown2 };
    const WCHAR *SystemUnknown[] = { System, Unknown1 };
    const WCHAR *Member[] = { AuthUsers };
    const WCHAR *NonMember[] = { System };

    /* Add: nothing can be added, every list has a name that does not exist */
    Expect(NetLocalGroupAddMembers, "Add Users, one unknown", L"Users", 1, One, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupAddMembers, "Add Users, two unknown", L"Users", 2, Two, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupAddMembers, "Add Users, mapped + unknown", L"Users", 2, MappedUnknown, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupAddMembers, "Add Users, unknown + mapped", L"Users", 2, UnknownMapped, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupAddMembers, "Add Users, unknown + mapped + unknown", L"Users", 3, UnknownMappedUnknown, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupAddMembers, "Add nogroup, one unknown", NoGroup, 1, One, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupAddMembers, "Add nogroup, mapped + unknown", NoGroup, 2, MappedUnknown, ERROR_NO_SUCH_MEMBER);

    /* Del: SYSTEM is no member of Users, so nothing is removed either */
    Expect(NetLocalGroupDelMembers, "Del Users, one unknown", L"Users", 1, One, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupDelMembers, "Del Users, mapped + unknown", L"Users", 2, SystemUnknown, ERROR_NO_SUCH_MEMBER);
    Expect(NetLocalGroupDelMembers, "Del nogroup, one unknown", NoGroup, 1, One, ERROR_NO_SUCH_MEMBER);

    /* Mapped names only; none of these changes a group */
    Expect(NetLocalGroupAddMembers, "Add Users, a member already", L"Users", 1, Member, ERROR_MEMBER_IN_ALIAS);
    Expect(NetLocalGroupDelMembers, "Del Users, not a member", L"Users", 1, NonMember, ERROR_MEMBER_NOT_IN_ALIAS);
    Expect(NetLocalGroupAddMembers, "Add nogroup, mapped", NoGroup, 1, Member, NERR_GroupNotFound);
}
