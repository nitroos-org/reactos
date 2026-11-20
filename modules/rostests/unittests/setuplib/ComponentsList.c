/*
 * PROJECT:     ReactOS Setup Library - Unit-tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the pure parts of the optional-components code: the file
 *              pattern match, the profile names, the answer lines and the
 *              resolution of dependencies and conflicts
 */

#include "precomp.h"
#include <components.h>

#define BIT(n)  (1UL << (n))

static void
InitDesc(COMPONENT_DESC *d, ULONG i, PCWSTR id, ULONG profiles, ULONG depends, ULONG conflicts, BOOLEAN applicable)
{
    wcscpy(d[i].Id, id);
    d[i].Profiles = profiles;
    d[i].Depends = depends;
    d[i].Conflicts = conflicts;
    d[i].Applicable = applicable;
}

static void
Test_Glob(void)
{
    static const struct { PCWSTR pat; PCWSTR path; BOOLEAN match; } t[] =
    {
        { L"SysWOW64\\*",            L"SysWOW64\\cmd.exe",                 TRUE },
        { L"SysWOW64\\*",            L"syswow64\\wbem\\mofcomp.exe",       TRUE },   /* any case, '*' crosses '\' */
        { L"SysWOW64\\*",            L"system32\\cmd.exe",                 FALSE },
        { L"SysWOW64\\*",            L"SysWOW64",                          FALSE },
        { L"winsxs\\x86_*",          L"winsxs\\x86_microsoft.windows.common-controls_x\\comctl32.dll", TRUE },
        { L"winsxs\\x86_*",          L"winsxs\\amd64_microsoft.windows.common-controls_x\\comctl32.dll", FALSE },
        { L"system32\\calc.exe",     L"system32\\calc.exe",                TRUE },
        { L"system32\\calc.exe",     L"system32\\calc.exe.mui",            FALSE },
        { L"system32\\calc.exe",     L"SysWOW64\\calc.exe",                FALSE },
        { L"bin\\*",                 L"bin\\a\\b.exe",                     TRUE },
        { L"bin\\*",                 L"bin",                               FALSE },
        { L"Fonts\\Noto?ans*.otf",   L"Fonts\\NotoSansSC-Regular.otf",     TRUE },
        { L"Fonts\\Noto?ans*.otf",   L"Fonts\\NotoSansSC-Regular.ttf",     FALSE },
        { L"*",                      L"",                                  TRUE },
        { L"*",                      L"anything\\at\\all",                 TRUE },
        { L"**x",                    L"abx",                               TRUE },
        { L"a*b*c",                  L"aXXbYYc",                           TRUE },
        { L"a*b*c",                  L"aXXbYY",                            FALSE },
        { L"",                       L"",                                  TRUE },
        { L"",                       L"a",                                 FALSE },
        { L"a",                      L"",                                  FALSE },
        { L"?",                      L"",                                  FALSE },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(t); ++i)
    {
        BOOLEAN res = ComponentGlobMatch(t[i].pat, t[i].path);
        ok(res == t[i].match, "ComponentGlobMatch('%S', '%S') returned %d, expected %d\n", t[i].pat, t[i].path, res, t[i].match);
    }
}

static void
Test_Profiles(void)
{
    ULONG p = 99;

    ok(ComponentParseProfile(L"standard", &p) && p == COMPONENT_PROFILE_STANDARD, "standard\n");
    ok(ComponentParseProfile(L" Minimal ", &p) && p == COMPONENT_PROFILE_MINIMAL, "Minimal\n");
    ok(ComponentParseProfile(L"CORE", &p) && p == COMPONENT_PROFILE_CORE, "CORE\n");
    ok(!ComponentParseProfile(L"", &p), "empty\n");
    ok(ComponentParseProfile(L"core-like", &p) && p == COMPONENT_PROFILE_CORE, "core-like is core\n");
    ok(!ComponentParseProfile(L"core-lik", &p), "core-lik\n");
    ok(!ComponentParseProfile(L"nano", &p), "nano\n");
    ok(!ComponentParseProfile(L"standar", &p), "standar\n");
    ok(!ComponentParseProfile(L"standard x", &p), "standard x\n");
    ok(!wcscmp(ComponentProfileName(COMPONENT_PROFILE_MINIMAL), L"minimal"), "name\n");
    ok(!wcscmp(ComponentProfileName(77), L"standard"), "name of a bad profile\n");
}

static void
Test_Answers(void)
{
    COMPONENT_DESC d[4];
    COMPONENT_CHOICE ex[4];
    ULONG i;
    const ULONG all = BIT(COMPONENT_PROFILE_STANDARD) | BIT(COMPONENT_PROFILE_MINIMAL) | BIT(COMPONENT_PROFILE_CORE);

    InitDesc(d, 0, L"wow64", BIT(COMPONENT_PROFILE_STANDARD), 0, 0, TRUE);
    InitDesc(d, 1, L"gl", all, 0, 0, TRUE);
    InitDesc(d, 2, L"vulkan", BIT(COMPONENT_PROFILE_STANDARD), BIT(1), 0, TRUE);
    InitDesc(d, 3, L"x86only", all, 0, 0, FALSE);
    for (i = 0; i < 4; ++i)
        ex[i] = COMPONENT_UNSET;

    ok(ComponentSetAnswer(4, d, ex, L"wow64", L"no") == COMPONENT_ANSWER_OK && ex[0] == COMPONENT_NO, "wow64 = no\n");
    ok(ComponentSetAnswer(4, d, ex, L"WOW64", L" Yes ") == COMPONENT_ANSWER_OK && ex[0] == COMPONENT_YES, "WOW64 = Yes\n");
    ok(ComponentSetAnswer(4, d, ex, L"gl", L"0") == COMPONENT_ANSWER_OK && ex[1] == COMPONENT_NO, "gl = 0\n");
    ok(ComponentSetAnswer(4, d, ex, L"vulcan", L"no") == COMPONENT_ANSWER_UNKNOWN, "unknown id\n");
    ok(ComponentSetAnswer(4, d, ex, L"", L"no") == COMPONENT_ANSWER_UNKNOWN, "empty id\n");
    ok(ComponentSetAnswer(4, d, ex, L"vulkan", L"maybe") == COMPONENT_ANSWER_BAD && ex[2] == COMPONENT_UNSET, "bad value\n");
    ok(ComponentSetAnswer(4, d, ex, L"vulkan", L"") == COMPONENT_ANSWER_BAD, "empty value\n");
    ok(ComponentSetAnswer(4, d, ex, L"x86only", L"yes") == COMPONENT_ANSWER_NOT_HERE && ex[3] == COMPONENT_UNSET, "other edition\n");
}

static void
Test_Resolve(void)
{
    COMPONENT_DESC d[5];
    COMPONENT_CHOICE ex[5];
    ULONG sel, i;
    const ULONG std = BIT(COMPONENT_PROFILE_STANDARD);
    const ULONG all = BIT(COMPONENT_PROFILE_STANDARD) | BIT(COMPONENT_PROFILE_MINIMAL) | BIT(COMPONENT_PROFILE_CORE);

    /* 0 wow64 (standard) · 1 gl (all) · 2 vulkan (standard, needs gl) · 3 gl-wow64 (standard, needs wow64)
       4 other (standard, conflicts with 0 for the test) */
    InitDesc(d, 0, L"wow64", std, 0, 0, TRUE);
    InitDesc(d, 1, L"gl", all, 0, 0, TRUE);
    InitDesc(d, 2, L"vulkan", std, BIT(1), 0, TRUE);
    InitDesc(d, 3, L"gl-wow64", std, BIT(0), 0, TRUE);
    InitDesc(d, 4, L"other", 0, 0, BIT(0), TRUE);

    /* standard, nothing asked: everything that is on in standard (the default installation) */
    for (i = 0; i < 5; ++i) ex[i] = COMPONENT_UNSET;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == (BIT(0) | BIT(1) | BIT(2) | BIT(3)), "standard: 0x%lx\n", sel);

    /* minimal: only what the profile keeps */
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_MINIMAL, ex);
    ok(sel == BIT(1), "minimal: 0x%lx\n", sel);

    /* core = minimal here */
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_CORE, ex);
    ok(sel == BIT(1), "core: 0x%lx\n", sel);

    /* a bad profile number falls back to standard */
    sel = ComponentsResolve(5, d, 99, ex);
    ok(sel == (BIT(0) | BIT(1) | BIT(2) | BIT(3)), "bad profile: 0x%lx\n", sel);

    /* explicit no on top of standard: wow64 = no takes gl-wow64 with it (its dependency is refused) */
    ex[0] = COMPONENT_NO;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == (BIT(1) | BIT(2)), "wow64 = no: 0x%lx\n", sel);

    /* explicit yes in minimal for a component whose dependency is off only by the profile: the dependency comes along */
    ex[0] = COMPONENT_UNSET;
    ex[3] = COMPONENT_YES;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_MINIMAL, ex);
    ok(sel == (BIT(0) | BIT(1) | BIT(3)), "gl-wow64 = yes in minimal: 0x%lx\n", sel);

    /* explicit yes, but its dependency explicitly no: the "no" wins, the dependent is left out */
    ex[0] = COMPONENT_NO;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_MINIMAL, ex);
    ok(sel == BIT(1), "gl-wow64 = yes, wow64 = no: 0x%lx\n", sel);

    /* a chain: vulkan needs gl; gl = no in standard takes vulkan with it */
    ex[0] = COMPONENT_UNSET; ex[3] = COMPONENT_UNSET; ex[1] = COMPONENT_NO;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == (BIT(0) | BIT(3)), "gl = no: 0x%lx\n", sel);

    /* conflict: "other" (explicit yes) against wow64 (profile): the one that was asked for stays */
    ex[1] = COMPONENT_UNSET; ex[4] = COMPONENT_YES;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(!(sel & BIT(0)) && (sel & BIT(4)), "conflict, other asked for: 0x%lx\n", sel);
    /* its dependent gl-wow64 goes with wow64 */
    ok(!(sel & BIT(3)), "conflict takes the dependent: 0x%lx\n", sel);

    /* conflict, both asked for: the later one in the list is left out */
    ex[0] = COMPONENT_YES; ex[4] = COMPONENT_YES;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok((sel & BIT(0)) && !(sel & BIT(4)), "conflict, both asked for: 0x%lx\n", sel);

    /* a component of another edition is never selected, also not by an explicit yes */
    d[2].Applicable = FALSE;
    ex[0] = ex[1] = ex[3] = ex[4] = COMPONENT_UNSET; ex[2] = COMPONENT_YES;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(!(sel & BIT(2)), "not applicable: 0x%lx\n", sel);
    /* and a dependency that does not exist here takes its dependent out */
    d[2].Applicable = TRUE;
    d[1].Applicable = FALSE;
    ex[2] = COMPONENT_UNSET;
    sel = ComponentsResolve(5, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(!(sel & BIT(1)) && !(sel & BIT(2)), "dependency does not exist here: 0x%lx\n", sel);

    /* nothing is selected twice, an empty list selects nothing */
    ok(ComponentsResolve(0, d, COMPONENT_PROFILE_STANDARD, ex) == 0, "empty list\n");

    /* a dependency cycle ends (a needs b, b needs a, both asked for: both stay) */
    InitDesc(d, 0, L"a", 0, BIT(1), 0, TRUE);
    InitDesc(d, 1, L"b", 0, BIT(0), 0, TRUE);
    ex[0] = ex[1] = COMPONENT_YES;
    sel = ComponentsResolve(2, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == (BIT(0) | BIT(1)), "cycle: 0x%lx\n", sel);
    ex[0] = COMPONENT_NO;
    sel = ComponentsResolve(2, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == 0, "cycle, one refused: 0x%lx\n", sel);
}

static void
Test_Find(void)
{
    COMPONENT_DESC d[2];

    InitDesc(d, 0, L"wow64", 0, 0, 0, TRUE);
    InitDesc(d, 1, L"gl", 0, 0, 0, TRUE);
    ok(ComponentFindIndex(2, d, L"GL") == 1, "GL\n");
    ok(ComponentFindIndex(2, d, L"wow64") == 0, "wow64\n");
    ok(ComponentFindIndex(2, d, L"gl2") == -1, "gl2\n");
    ok(ComponentFindIndex(2, d, L"") == -1, "empty\n");
    ok(ComponentFindIndex(0, d, L"gl") == -1, "empty list\n");
}

/* Patterns that must not reach a file outside their directory, and very long inputs */
static void
Test_GlobBoundaries(void)
{
    static WCHAR LongPath[4096], LongPattern[4096];
    ULONG i;

    ok(!ComponentGlobMatch(L"bin\\*", L"binx\\a.exe"), "bin\\* is not binx\\a.exe\n");
    ok(!ComponentGlobMatch(L"bin\\*", L"system32\\bin\\a.exe"), "bin\\* is anchored at the start\n");
    ok(!ComponentGlobMatch(L"system32\\sol.exe", L"system32\\sol.exe\\x"), "no match past the end\n");
    ok(!ComponentGlobMatch(L"system32\\sol.exe", L"system32\\xsol.exe"), "no match in the middle of a name\n");
    ok(ComponentGlobMatch(L"system32\\?ol.exe", L"system32\\sol.exe"), "? is one character\n");
    ok(!ComponentGlobMatch(L"system32\\?ol.exe", L"system32\\ol.exe"), "? is not nothing\n");
    ok(!ComponentGlobMatch(L"games", L"system32\\games.exe"), "a bare word matches only that whole path\n");
    ok(!ComponentGlobMatch(L"tests", L"bin\\tests"), "a bare word is anchored\n");

    for (i = 0; i < RTL_NUMBER_OF(LongPath) - 1; ++i)
        LongPath[i] = (i % 17 == 16) ? L'\\' : L'a';
    LongPath[RTL_NUMBER_OF(LongPath) - 1] = UNICODE_NULL;
    for (i = 0; i < RTL_NUMBER_OF(LongPattern) - 1; ++i)
        LongPattern[i] = (i % 2) ? L'a' : L'*';
    LongPattern[RTL_NUMBER_OF(LongPattern) - 2] = L'b';
    LongPattern[RTL_NUMBER_OF(LongPattern) - 1] = UNICODE_NULL;
    ok(ComponentGlobMatch(L"*", LongPath), "* matches a very long path\n");
    ok(ComponentGlobMatch(L"a*", LongPath), "a* matches a very long path\n");
    ok(!ComponentGlobMatch(L"a*b", LongPath), "a*b does not match a path without b\n");
    /* many stars (*a*a*...*b) against a long path without a b: must end (no exponential search) and not match */
    ok(!ComponentGlobMatch(LongPattern, LongPath), "many stars against a long path\n");
}

/* The registry lines of left-out components: whole keys, one value, wildcards, other keys untouched */
static void
Test_RegistryOmitted(void)
{
    static COMPONENTS_STATE s;

    RtlZeroMemory(&s, sizeof(s));
    ok(!ComponentsIsRegistryOmitted(&s, L"HKCR", L"rtffile\\shell\\open\\command", L""), "no patterns: nothing is omitted\n");

    s.OmitReg[s.OmitRegCount++] = L"HKCR\\rtffile";
    s.OmitReg[s.OmitRegCount++] = L"HKCR\\rtffile\\*";
    s.OmitReg[s.OmitRegCount++] = L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wordpad.exe*";
    s.OmitReg[s.OmitRegCount++] = L"HKLM\\SOFTWARE\\Classes\\Foo|Bar";
    s.OmitReg[s.OmitRegCount++] = L"HKCR\\*\\OpenWithList\\wordpad.exe";

    ok(ComponentsIsRegistryOmitted(&s, L"HKCR", L"rtffile", NULL), "the key itself\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKCR", L"RTFFILE", L""), "any case\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKCR", L"rtffile\\shell\\open\\command", L""), "a subkey\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKCR", L"rtffile\\DefaultIcon", L"Value"), "a subkey with a value\n");
    ok(!ComponentsIsRegistryOmitted(&s, L"HKCR", L"rtffile2", L""), "a key with the same start is not matched\n");
    ok(!ComponentsIsRegistryOmitted(&s, L"HKLM", L"rtffile", L""), "another root\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wordpad.exe", L"Path"),
       "a key with a space in its path, and a value of it\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKLM", L"SOFTWARE\\Classes\\Foo", L"Bar"), "one value\n");
    ok(!ComponentsIsRegistryOmitted(&s, L"HKLM", L"SOFTWARE\\Classes\\Foo", L"Baz"), "another value of the key\n");
    ok(!ComponentsIsRegistryOmitted(&s, L"HKLM", L"SOFTWARE\\Classes\\Foo", NULL), "the key of a value pattern\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKCR", L"*\\OpenWithList\\wordpad.exe", L""), "the key named *\n");
    ok(ComponentsIsRegistryOmitted(&s, L"HKCR", L"SystemFileAssociations\\text\\OpenWithList\\wordpad.exe", L""), "* is any run\n");
    ok(!ComponentsIsRegistryOmitted(&s, L"HKCR", L"*\\OpenWithList\\notepad.exe", L""), "another program\n");
}

/* The 32-component limit of the masks */
static void
Test_ResolveLimits(void)
{
    COMPONENT_DESC d[COMPONENT_MAX + 4];
    COMPONENT_CHOICE ex[COMPONENT_MAX + 4];
    ULONG i, sel;
    const ULONG std = BIT(COMPONENT_PROFILE_STANDARD);

    for (i = 0; i < RTL_NUMBER_OF(d); ++i)
    {
        InitDesc(d, i, L"c", std, 0, 0, TRUE);
        ex[i] = COMPONENT_UNSET;
    }
    /* component 31 needs 30, which needs 29 ... 0: refusing 0 takes the whole chain, including the top bit */
    for (i = 1; i < COMPONENT_MAX; ++i)
        d[i].Depends = BIT(i - 1);
    sel = ComponentsResolve(COMPONENT_MAX, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == 0xFFFFFFFFUL, "32 components, all on: 0x%lx\n", sel);
    ex[0] = COMPONENT_NO;
    sel = ComponentsResolve(COMPONENT_MAX, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == 0, "32 components, chain broken at the root: 0x%lx\n", sel);
    /* the 32nd component refused alone */
    ex[0] = COMPONENT_UNSET; ex[COMPONENT_MAX - 1] = COMPONENT_NO;
    sel = ComponentsResolve(COMPONENT_MAX, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == 0x7FFFFFFFUL, "32nd component refused: 0x%lx\n", sel);
    /* a list longer than the limit is cut, nothing beyond bit 31 is read or set */
    ex[COMPONENT_MAX - 1] = COMPONENT_UNSET;
    sel = ComponentsResolve(COMPONENT_MAX + 4, d, COMPONENT_PROFILE_STANDARD, ex);
    ok(sel == 0xFFFFFFFFUL, "longer than the limit: 0x%lx\n", sel);
}

START_TEST(ComponentsList)
{
    Test_Glob();
    Test_GlobBoundaries();
    Test_Profiles();
    Test_Answers();
    Test_Resolve();
    Test_ResolveLimits();
    Test_Find();
    Test_RegistryOmitted();
}
