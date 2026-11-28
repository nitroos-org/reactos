
#define STANDALONE
#include <apitest.h>

extern void func_WtsSessions(void);

const struct test winetest_testlist[] =
{
    { "WtsSessions", func_WtsSessions },
    { 0, 0 }
};
