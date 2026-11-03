#define STANDALONE
#include <apitest.h>

extern void func_licenses(void);

const struct test winetest_testlist[] =
{
    { "licenses", func_licenses },
    { 0, 0 }
};
