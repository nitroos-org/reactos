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

START_TEST(ComponentsList)
{
    Test_Glob();
    Test_Profiles();
    Test_Answers();
    Test_Resolve();
    Test_Find();
}
