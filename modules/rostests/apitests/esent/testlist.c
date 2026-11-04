#define STANDALONE
#include <apitest.h>

extern void func_DelayImports(void);

const struct test winetest_testlist[] =
{
    { "DelayImports", func_DelayImports },

    { 0, 0 }
};
