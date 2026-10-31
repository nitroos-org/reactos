#define STANDALONE
#include <apitest.h>

extern void func_BCryptDeriveKey(void);
extern void func_BCryptKeyExport(void);

const struct test winetest_testlist[] =
{
    { "BCryptDeriveKey", func_BCryptDeriveKey },
    { "BCryptKeyExport", func_BCryptKeyExport },

    { 0, 0 }
};
