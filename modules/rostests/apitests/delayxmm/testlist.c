#define STANDALONE
#include <wine/test.h>

extern void func_delayxmm(void);

const struct test winetest_testlist[] =
{
    { "delayxmm", func_delayxmm },
    { 0, 0 }
};
