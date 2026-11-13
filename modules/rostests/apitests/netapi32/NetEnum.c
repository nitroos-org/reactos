/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for NetUserEnum, NetGroupEnum and NetLocalGroupEnum: all entries
 *              in one buffer, the totals, small preferred lengths and resume handles
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <lm.h>

#define MAX_NAMES 512
#define NUM_TEST_USERS 3

typedef struct _NAMELIST
{
    DWORD Count;
    WCHAR Names[MAX_NAMES][UNLEN + 1];
} NAMELIST, *PNAMELIST;

static const WCHAR *TestUsers[NUM_TEST_USERS] =
{
    L"apitest_enum_a", L"apitest_enum_b", L"apitest_enum_c"
};
static const WCHAR *TestComments[NUM_TEST_USERS] =
{
    L"", L"comment b", L"a longer comment for the third test user, to vary the size of the entries"
};
static const WCHAR *TestFullNames[NUM_TEST_USERS] =
{
    L"Enum Test A", L"", L"Enum Test C With A Longer Full Name"
};
static BOOL FullNamesSet;

/* The name, comment and full name members of the entry i of an array of the level */
static const WCHAR *
UserField(DWORD level, LPBYTE buf, DWORD i, int field)
{
    /* field: 0 name, 1 comment, 2 full name */
    switch (level)
    {
        case 0:
            return field == 0 ? ((PUSER_INFO_0)buf)[i].usri0_name : NULL;
        case 1:
            return field == 0 ? ((PUSER_INFO_1)buf)[i].usri1_name :
                   field == 1 ? ((PUSER_INFO_1)buf)[i].usri1_comment : NULL;
        case 2:
            return field == 0 ? ((PUSER_INFO_2)buf)[i].usri2_name :
                   field == 1 ? ((PUSER_INFO_2)buf)[i].usri2_comment :
                                ((PUSER_INFO_2)buf)[i].usri2_full_name;
        case 3:
            return field == 0 ? ((PUSER_INFO_3)buf)[i].usri3_name :
                   field == 1 ? ((PUSER_INFO_3)buf)[i].usri3_comment :
                                ((PUSER_INFO_3)buf)[i].usri3_full_name;
        case 10:
            return field == 0 ? ((PUSER_INFO_10)buf)[i].usri10_name :
                   field == 1 ? ((PUSER_INFO_10)buf)[i].usri10_comment :
                                ((PUSER_INFO_10)buf)[i].usri10_full_name;
        case 11:
            return field == 0 ? ((PUSER_INFO_11)buf)[i].usri11_name :
                   field == 1 ? ((PUSER_INFO_11)buf)[i].usri11_comment :
                                ((PUSER_INFO_11)buf)[i].usri11_full_name;
        case 20:
            return field == 0 ? ((PUSER_INFO_20)buf)[i].usri20_name :
                   field == 1 ? ((PUSER_INFO_20)buf)[i].usri20_comment :
                                ((PUSER_INFO_20)buf)[i].usri20_full_name;
    }
    return NULL;
}

static BOOL
InBuffer(LPBYTE buf, const void *p)
{
    DWORD size = 0;

    if (NetApiBufferSize(buf, &size) != NERR_Success)
        return FALSE;
    return (const BYTE *)p >= buf && (const BYTE *)p < buf + size;
}

static void
AddName(PNAMELIST list, const WCHAR *name)
{
    ok(name != NULL, "an entry has no name\n");
    if (name == NULL || list->Count >= MAX_NAMES)
        return;
    lstrcpynW(list->Names[list->Count++], name, UNLEN + 1);
}

static BOOL
HasName(const NAMELIST *list, const WCHAR *name, DWORD *times)
{
    DWORD i, n = 0;

    for (i = 0; i < list->Count; i++)
        if (!lstrcmpiW(list->Names[i], name))
            n++;
    if (times)
        *times = n;
    return n != 0;
}

/* Every name of the list exactly once, and the same names as the reference */
static void
CompareLists(const char *what, const NAMELIST *ref, const NAMELIST *got)
{
    DWORD i, n;

    ok(ref->Count == got->Count, "%s: %lu entries, the reference has %lu\n", what, got->Count, ref->Count);
    for (i = 0; i < ref->Count; i++)
    {
        HasName(got, ref->Names[i], &n);
        ok(n == 1, "%s: %ls returned %lu times\n", what, ref->Names[i], n);
    }
    for (i = 0; i < got->Count; i++)
    {
        HasName(ref, got->Names[i], &n);
        ok(n == 1, "%s: %ls is not in the reference\n", what, got->Names[i]);
    }
}

static void
CheckUserFields(DWORD level, LPBYTE buf, DWORD read)
{
    DWORD i, j;
    const WCHAR *s;
    int f;

    for (i = 0; i < read; i++)
    {
        for (f = 0; f < 3; f++)
        {
            s = UserField(level, buf, i, f);
            /* the comment of level 0 and the full name of level 1 do not exist */
            if ((level == 0 && f > 0) || (level == 1 && f == 2))
                continue;
            ok(s != NULL, "level %lu entry %lu has no string %d\n", level, i, f);
            if (s != NULL)
                ok(InBuffer(buf, s), "level %lu entry %lu string %d (%p) is outside of the buffer\n", level, i, f, s);
        }

        /* the test users carry what was set */
        s = UserField(level, buf, i, 0);
        for (j = 0; s != NULL && j < NUM_TEST_USERS; j++)
        {
            if (lstrcmpiW(s, TestUsers[j]))
                continue;
            if (level >= 1 && level != 20 && UserField(level, buf, i, 1) != NULL)
                ok(!lstrcmpW(UserField(level, buf, i, 1), TestComments[j]),
                   "level %lu %ls: comment '%ls'\n", level, s, UserField(level, buf, i, 1));
            if (FullNamesSet && level >= 2 && UserField(level, buf, i, 2) != NULL)
                ok(!lstrcmpW(UserField(level, buf, i, 2), TestFullNames[j]),
                   "level %lu %ls: full name '%ls'\n", level, s, UserField(level, buf, i, 2));
        }
    }
}

static void
CheckUserFlags(DWORD level, LPBYTE buf, DWORD read)
{
    DWORD i, flags = 0;

    for (i = 0; i < read; i++)
    {
        switch (level)
        {
            case 1: flags = ((PUSER_INFO_1)buf)[i].usri1_flags; break;
            case 2: flags = ((PUSER_INFO_2)buf)[i].usri2_flags; break;
            case 3: flags = ((PUSER_INFO_3)buf)[i].usri3_flags; break;
            case 20: flags = ((PUSER_INFO_20)buf)[i].usri20_flags; break;
            default: return;
        }
        ok((flags & UF_NORMAL_ACCOUNT) != 0, "level %lu entry %lu (%ls) flags %08lx\n",
           level, i, UserField(level, buf, i, 0), flags);
    }
}

/* The users: all at once, then in pieces of prefmaxlen */
static void
TestUserEnumLevel(DWORD level, const NAMELIST *ref)
{
    NET_API_STATUS st;
    LPBYTE buf;
    DWORD read, total, resume, calls, i;
    static const DWORD limits[] = { 1, 300, 1000 };
    NAMELIST got;
    char what[64];

    /* MAX_PREFERRED_LENGTH, no resume handle */
    buf = NULL; read = total = 0xdead;
    st = NetUserEnum(NULL, level, 0, &buf, MAX_PREFERRED_LENGTH, &read, &total, NULL);
    ok(st == NERR_Success, "level %lu: NetUserEnum returned %lu\n", level, st);
    ok(read == ref->Count, "level %lu: %lu entries read, %lu expected\n", level, read, ref->Count);
    ok(total == ref->Count, "level %lu: total %lu, %lu expected\n", level, total, ref->Count);
    got.Count = 0;
    if (buf != NULL)
    {
        for (i = 0; i < read; i++)
            AddName(&got, UserField(level, buf, i, 0));
        CheckUserFields(level, buf, read);
        CheckUserFlags(level, buf, read);
        NetApiBufferFree(buf);
    }
    sprintf(what, "level %lu all", level);
    CompareLists(what, ref, &got);

    /* MAX_PREFERRED_LENGTH with a resume handle: no ERROR_MORE_DATA, the handle is reset */
    buf = NULL; read = total = 0xdead; resume = 0;
    st = NetUserEnum(NULL, level, 0, &buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
    ok(st == NERR_Success, "level %lu: NetUserEnum with a resume handle returned %lu\n", level, st);
    ok(read == ref->Count, "level %lu: %lu entries read with a resume handle\n", level, read);
    ok(resume == 0, "level %lu: resume handle %lu after the last entry\n", level, resume);
    if (buf != NULL)
        NetApiBufferFree(buf);

    /* a small preferred length without a resume handle: a first part and ERROR_MORE_DATA */
    buf = NULL; read = total = 0xdead;
    st = NetUserEnum(NULL, level, 0, &buf, 1, &read, &total, NULL);
    ok(st == ERROR_MORE_DATA, "level %lu: NetUserEnum(prefmaxlen 1) returned %lu\n", level, st);
    ok(read >= 1, "level %lu: no entry returned for prefmaxlen 1\n", level);
    ok(total == ref->Count, "level %lu: total %lu with prefmaxlen 1\n", level, total);
    if (buf != NULL)
        NetApiBufferFree(buf);

    /* pieces */
    for (i = 0; i < ARRAYSIZE(limits); i++)
    {
        DWORD prev_total = 0, n;

        got.Count = 0;
        resume = 0;
        calls = 0;
        do
        {
            buf = NULL; read = total = 0xdead;
            st = NetUserEnum(NULL, level, 0, &buf, limits[i], &read, &total, &resume);
            calls++;
            ok(st == NERR_Success || st == ERROR_MORE_DATA,
               "level %lu limit %lu: NetUserEnum returned %lu\n", level, limits[i], st);
            if (st != NERR_Success && st != ERROR_MORE_DATA)
                break;
            ok(read >= 1, "level %lu limit %lu: call %lu returned no entry\n", level, limits[i], calls);
            if (calls > 1)
                ok(total == prev_total, "level %lu limit %lu: total changed from %lu to %lu\n",
                   level, limits[i], prev_total, total);
            prev_total = total;
            if (st == ERROR_MORE_DATA)
                ok(resume != 0, "level %lu limit %lu: ERROR_MORE_DATA with resume handle 0\n", level, limits[i]);
            else
                ok(resume == 0, "level %lu limit %lu: resume handle %lu at the end\n", level, limits[i], resume);
            if (buf != NULL)
            {
                for (n = 0; n < read; n++)
                    AddName(&got, UserField(level, buf, n, 0));
                CheckUserFields(level, buf, read);
                NetApiBufferFree(buf);
            }
        } while (st == ERROR_MORE_DATA && calls <= MAX_NAMES);
        sprintf(what, "level %lu limit %lu", level, limits[i]);
        CompareLists(what, ref, &got);
        if (limits[i] == 1)
            ok(calls == ref->Count, "level %lu limit 1: %lu calls for %lu entries\n", level, calls, ref->Count);
    }
}

static void
TestUserEnum(void)
{
    static const DWORD levels[] = { 0, 1, 2, 3, 10, 11, 20 };
    NET_API_STATUS st;
    LPBYTE buf = NULL;
    DWORD read = 0, total = 0, i, n;
    NAMELIST ref;

    st = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, &buf, MAX_PREFERRED_LENGTH, &read, &total, NULL);
    ok(st == NERR_Success, "NetUserEnum(level 0) returned %lu\n", st);
    ok(read == total, "level 0: %lu entries read of %lu\n", read, total);
    ref.Count = 0;
    for (i = 0; buf != NULL && i < read; i++)
        AddName(&ref, ((PUSER_INFO_0)buf)[i].usri0_name);
    if (buf != NULL)
        NetApiBufferFree(buf);
    trace("%lu users\n", ref.Count);

    for (i = 0; i < NUM_TEST_USERS; i++)
    {
        HasName(&ref, TestUsers[i], &n);
        ok(n == 1, "test user %ls listed %lu times\n", TestUsers[i], n);
    }
    ok(ref.Count >= NUM_TEST_USERS, "only %lu users\n", ref.Count);

    for (i = 0; i < ARRAYSIZE(levels); i++)
        TestUserEnumLevel(levels[i], &ref);
}

/* NetGroupEnum and NetLocalGroupEnum: the same, with the name at the same place for all levels */
static const WCHAR *
GroupName(BOOL local, DWORD level, LPBYTE buf, DWORD i)
{
    if (local)
        return level == 0 ? ((PLOCALGROUP_INFO_0)buf)[i].lgrpi0_name : ((PLOCALGROUP_INFO_1)buf)[i].lgrpi1_name;

    switch (level)
    {
        case 0: return ((PGROUP_INFO_0)buf)[i].grpi0_name;
        case 1: return ((PGROUP_INFO_1)buf)[i].grpi1_name;
        case 2: return ((PGROUP_INFO_2)buf)[i].grpi2_name;
        default: return ((PGROUP_INFO_3)buf)[i].grpi3_name;
    }
}

static NET_API_STATUS
EnumGroups(BOOL local, DWORD level, LPBYTE *buf, DWORD prefmaxlen, LPDWORD read, LPDWORD total, PDWORD_PTR resume)
{
    if (local)
        return NetLocalGroupEnum(NULL, level, buf, prefmaxlen, read, total, resume);
    return NetGroupEnum(NULL, level, buf, prefmaxlen, read, total, resume);
}

static void
TestGroupEnumLevel(BOOL local, DWORD level)
{
    const char *fn = local ? "NetLocalGroupEnum" : "NetGroupEnum";
    NET_API_STATUS st;
    LPBYTE buf = NULL;
    DWORD read = 0, total = 0, i, calls, n;
    DWORD_PTR resume;
    NAMELIST ref, got;
    static const DWORD limits[] = { 1, 200 };
    char what[64];
    const WCHAR *name;

    st = EnumGroups(local, level, &buf, MAX_PREFERRED_LENGTH, &read, &total, NULL);
    if (!local && st != NERR_Success)
    {
        skip("%s level %lu returned %lu\n", fn, level, st);
        return;
    }
    ok(st == NERR_Success, "%s level %lu returned %lu\n", fn, level, st);
    ok(read == total, "%s level %lu: %lu entries read of %lu\n", fn, level, read, total);
    ref.Count = 0;
    for (i = 0; buf != NULL && i < read; i++)
    {
        name = GroupName(local, level, buf, i);
        AddName(&ref, name);
        if (name != NULL)
            ok(InBuffer(buf, name), "%s level %lu: name of entry %lu is outside of the buffer\n", fn, level, i);
    }
    if (buf != NULL)
        NetApiBufferFree(buf);
    ok(ref.Count >= 1, "%s level %lu: no entry\n", fn, level);
    if (local)
    {
        HasName(&ref, L"Administrators", &n);
        ok(n == 1, "Administrators listed %lu times\n", n);
    }

    /* the same with a resume handle */
    buf = NULL; resume = 0;
    st = EnumGroups(local, level, &buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
    ok(st == NERR_Success, "%s level %lu with a resume handle returned %lu\n", fn, level, st);
    ok(read == ref.Count, "%s level %lu: %lu entries with a resume handle, %lu expected\n", fn, level, read, ref.Count);
    ok(resume == 0, "%s level %lu: resume handle %p at the end\n", fn, level, (void *)resume);
    if (buf != NULL)
        NetApiBufferFree(buf);

    for (i = 0; i < ARRAYSIZE(limits); i++)
    {
        got.Count = 0;
        resume = 0;
        calls = 0;
        do
        {
            buf = NULL; read = total = 0xdead;
            st = EnumGroups(local, level, &buf, limits[i], &read, &total, &resume);
            calls++;
            ok(st == NERR_Success || st == ERROR_MORE_DATA, "%s level %lu limit %lu returned %lu\n", fn, level, limits[i], st);
            if (st != NERR_Success && st != ERROR_MORE_DATA)
                break;
            ok(read >= 1, "%s level %lu limit %lu: call %lu returned no entry\n", fn, level, limits[i], calls);
            ok(total == ref.Count, "%s level %lu limit %lu: total %lu, %lu expected\n", fn, level, limits[i], total, ref.Count);
            for (n = 0; buf != NULL && n < read; n++)
                AddName(&got, GroupName(local, level, buf, n));
            if (buf != NULL)
                NetApiBufferFree(buf);
        } while (st == ERROR_MORE_DATA && calls <= MAX_NAMES);
        ok(resume == 0, "%s level %lu limit %lu: resume handle %p at the end\n", fn, level, limits[i], (void *)resume);
        sprintf(what, "%s level %lu limit %lu", fn, level, limits[i]);
        CompareLists(what, &ref, &got);
        if (limits[i] == 1)
            ok(calls == ref.Count, "%s level %lu limit 1: %lu calls for %lu entries\n", fn, level, calls, ref.Count);
    }
}

static BOOL
CreateTestUsers(void)
{
    USER_INFO_1 info;
    USER_INFO_1011 fn;
    NET_API_STATUS st;
    DWORD err, i;

    for (i = 0; i < NUM_TEST_USERS; i++)
        NetUserDel(NULL, (LPWSTR)TestUsers[i]);

    for (i = 0; i < NUM_TEST_USERS; i++)
    {
        ZeroMemory(&info, sizeof(info));
        info.usri1_name = (LPWSTR)TestUsers[i];
        info.usri1_password = (LPWSTR)L"Apitest-Enum-2026!";
        info.usri1_priv = USER_PRIV_USER;
        info.usri1_comment = (LPWSTR)TestComments[i];
        info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
        st = NetUserAdd(NULL, 1, (LPBYTE)&info, &err);
        if (st != NERR_Success)
        {
            skip("NetUserAdd(%ls) returned %lu (needs an elevated administrator)\n", TestUsers[i], st);
            return FALSE;
        }
    }

    FullNamesSet = TRUE;
    for (i = 0; i < NUM_TEST_USERS; i++)
    {
        fn.usri1011_full_name = (LPWSTR)TestFullNames[i];
        st = NetUserSetInfo(NULL, TestUsers[i], 1011, (LPBYTE)&fn, &err);
        if (st != NERR_Success)
            FullNamesSet = FALSE;
    }
    return TRUE;
}

static const WCHAR *TestGroups[2] = { L"apitest_enum_g1", L"apitest_enum_g2" };
static const WCHAR *TestLocalGroups[2] = { L"apitest_enum_lg1", L"apitest_enum_lg2" };

static void
CreateTestGroups(void)
{
    GROUP_INFO_1 gi;
    LOCALGROUP_INFO_1 li;
    DWORD i, err;
    NET_API_STATUS st;

    for (i = 0; i < 2; i++)
    {
        NetGroupDel(NULL, TestGroups[i]);
        NetLocalGroupDel(NULL, TestLocalGroups[i]);

        gi.grpi1_name = (LPWSTR)TestGroups[i];
        gi.grpi1_comment = (LPWSTR)L"enum test group";
        st = NetGroupAdd(NULL, 1, (LPBYTE)&gi, &err);
        if (st != NERR_Success)
            trace("NetGroupAdd(%ls) returned %lu\n", TestGroups[i], st);

        li.lgrpi1_name = (LPWSTR)TestLocalGroups[i];
        li.lgrpi1_comment = (LPWSTR)L"enum test alias";
        st = NetLocalGroupAdd(NULL, 1, (LPBYTE)&li, &err);
        if (st != NERR_Success)
            trace("NetLocalGroupAdd(%ls) returned %lu\n", TestLocalGroups[i], st);
    }
}

static void
DeleteTestGroups(void)
{
    DWORD i;

    for (i = 0; i < 2; i++)
    {
        NetGroupDel(NULL, TestGroups[i]);
        NetLocalGroupDel(NULL, TestLocalGroups[i]);
    }
}

static const WCHAR *
GroupUserName(DWORD level, LPBYTE buf, DWORD i)
{
    return level == 0 ? ((PGROUP_USERS_INFO_0)buf)[i].grui0_name : ((PGROUP_USERS_INFO_1)buf)[i].grui1_name;
}

/* NetGroupGetUsers pages by itself: the members of a group, all at once and in pieces */
static void
TestGroupGetUsers(void)
{
    static const DWORD limits[] = { 1, 60, MAX_PREFERRED_LENGTH };
    NET_API_STATUS st;
    LPBYTE buf;
    DWORD read, total, i, level, n, calls;
    DWORD_PTR resume;
    NAMELIST ref, got;
    char what[64];

    for (i = 0; i < NUM_TEST_USERS; i++)
    {
        st = NetGroupAddUser(NULL, TestGroups[0], TestUsers[i]);
        if (st != NERR_Success)
        {
            skip("NetGroupAddUser(%ls) returned %lu\n", TestUsers[i], st);
            return;
        }
    }

    ref.Count = 0;
    for (i = 0; i < NUM_TEST_USERS; i++)
        AddName(&ref, TestUsers[i]);

    for (level = 0; level <= 1; level++)
    {
        for (i = 0; i < ARRAYSIZE(limits); i++)
        {
            got.Count = 0;
            resume = 0;
            calls = 0;
            do
            {
                buf = NULL; read = total = 0xdead;
                st = NetGroupGetUsers(NULL, TestGroups[0], level, &buf, limits[i], &read, &total, &resume);
                calls++;
                ok(st == NERR_Success || st == ERROR_MORE_DATA,
                   "NetGroupGetUsers level %lu limit %lu returned %lu\n", level, limits[i], st);
                if (st != NERR_Success && st != ERROR_MORE_DATA)
                    break;
                ok(read >= 1, "NetGroupGetUsers level %lu limit %lu: call %lu returned no entry\n", level, limits[i], calls);
                ok(total == NUM_TEST_USERS, "NetGroupGetUsers level %lu limit %lu: total %lu\n", level, limits[i], total);
                for (n = 0; buf != NULL && n < read; n++)
                    AddName(&got, GroupUserName(level, buf, n));
                if (buf != NULL)
                    NetApiBufferFree(buf);
            } while (st == ERROR_MORE_DATA && calls <= MAX_NAMES);
            ok(resume == 0, "NetGroupGetUsers level %lu limit %lu: resume handle %p at the end\n",
               level, limits[i], (void *)resume);
            sprintf(what, "NetGroupGetUsers level %lu limit %lu", level, limits[i]);
            CompareLists(what, &ref, &got);
        }
    }
}

START_TEST(NetEnum)
{
    BOOL users;
    DWORD i;

    users = CreateTestUsers();
    CreateTestGroups();

    if (users)
        TestUserEnum();

    for (i = 0; i < 4; i++)
        TestGroupEnumLevel(FALSE, i);
    for (i = 0; i < 2; i++)
        TestGroupEnumLevel(TRUE, i);

    if (users)
        TestGroupGetUsers();

    DeleteTestGroups();

    for (i = 0; i < NUM_TEST_USERS; i++)
        NetUserDel(NULL, (LPWSTR)TestUsers[i]);
}
