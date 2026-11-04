#define STANDALONE
#include <apitest.h>

extern void func_licenses(void);
extern void func_slc(void);

const struct test winetest_testlist[] =
{
    { "licenses", func_licenses },
    { "slc", func_slc },
    { 0, 0 }
};
