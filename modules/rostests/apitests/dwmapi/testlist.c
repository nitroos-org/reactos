#define STANDALONE
#include <apitest.h>

extern void func_DwmExtendFrame(void);
extern void func_DwmFlush(void);

const struct test winetest_testlist[] =
{
    { "DwmExtendFrame", func_DwmExtendFrame },
    { "DwmFlush", func_DwmFlush },

    { 0, 0 }
};
