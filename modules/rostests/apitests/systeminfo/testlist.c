#define STANDALONE
#include <apitest.h>

extern void func_systeminfo(void);

const struct test winetest_testlist[] =
{
    { "systeminfo", func_systeminfo },
    { 0, 0 }
};
