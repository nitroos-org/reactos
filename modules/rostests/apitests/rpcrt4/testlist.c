#define STANDALONE
#include <apitest.h>

extern void func_interface_access(void);

const struct test winetest_testlist[] =
{
    { "interface_access", func_interface_access },
    { 0, 0 }
};
