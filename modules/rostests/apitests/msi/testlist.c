#define STANDALONE
#include <apitest.h>

extern void func_RefusedPackageLog(void);
extern void func_Wow64Folders(void);

const struct test winetest_testlist[] =
{
    { "RefusedPackageLog", func_RefusedPackageLog },
    { "Wow64Folders", func_Wow64Folders },
    { 0, 0 }
};
