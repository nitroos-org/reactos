/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */


#define STANDALONE
#include <apitest.h>

extern void func_SignatureTimeStamp(void);
extern void func_WTHelperGetFileHash(void);

const struct test winetest_testlist[] =
{
    { "SignatureTimeStamp", func_SignatureTimeStamp },
    { "WTHelperGetFileHash", func_WTHelperGetFileHash },

    { 0, 0 }
};
