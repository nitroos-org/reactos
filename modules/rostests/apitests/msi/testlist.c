/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_CustomActionDir(void);
extern void func_LaunchPipe(void);
extern void func_MsiPasswordEdit(void);
extern void func_NoImpersonateAction(void);
extern void func_RefusedPackageLog(void);
extern void func_RemoveUnknownProduct(void);
extern void func_Wow64Folders(void);

const struct test winetest_testlist[] =
{
    { "CustomActionDir", func_CustomActionDir },
    { "LaunchPipe", func_LaunchPipe },
    { "MsiPasswordEdit", func_MsiPasswordEdit },
    { "NoImpersonateAction", func_NoImpersonateAction },
    { "RefusedPackageLog", func_RefusedPackageLog },
    { "RemoveUnknownProduct", func_RemoveUnknownProduct },
    { "Wow64Folders", func_Wow64Folders },
    { 0, 0 }
};
