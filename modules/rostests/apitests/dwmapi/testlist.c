#define STANDALONE
#include <apitest.h>

extern void func_DwmFlush(void);

const struct test winetest_testlist[] =
{
    { "DwmFlush", func_DwmFlush },

    { 0, 0 }
};
