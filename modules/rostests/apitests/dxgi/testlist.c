#define STANDALONE
#include <apitest.h>

extern void func_CreateSwapChainForComposition(void);
extern void func_EnumWarpAdapter(void);

const struct test winetest_testlist[] =
{
    { "CreateSwapChainForComposition", func_CreateSwapChainForComposition },
    { "EnumWarpAdapter", func_EnumWarpAdapter },

    { 0, 0 }
};
