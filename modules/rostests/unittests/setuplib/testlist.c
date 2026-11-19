#define STANDALONE
#include <apitest.h>

extern void func_IsValidInstallDirectory(void);
extern void func_UnattendParse(void);

const struct test winetest_testlist[] =
{
    { "IsValidInstallDirectory", func_IsValidInstallDirectory },
    { "UnattendParse", func_UnattendParse },
    { 0, 0 }
};
