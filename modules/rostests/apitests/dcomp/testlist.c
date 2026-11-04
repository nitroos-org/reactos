#define STANDALONE
#include <apitest.h>

extern void func_DCompositionCreateDevice(void);

const struct test winetest_testlist[] =
{
    { "DCompositionCreateDevice", func_DCompositionCreateDevice },

    { 0, 0 }
};
