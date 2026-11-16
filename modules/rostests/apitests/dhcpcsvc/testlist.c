
#define STANDALONE
#include <apitest.h>

extern void func_AdapterName(void);

const struct test winetest_testlist[] =
{
    { "AdapterName", func_AdapterName },
    { 0, 0 }
};
