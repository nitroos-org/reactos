#define STANDALONE
#include <apitest.h>

extern void func_Msvcp140MoneyIds(void);
extern void func_Msvcp140ThrowCppError(void);

const struct test winetest_testlist[] =
{
    { "Msvcp140MoneyIds", func_Msvcp140MoneyIds },

    { "Msvcp140ThrowCppError", func_Msvcp140ThrowCppError },
    { 0, 0 }
};
