
#define STANDALONE
#include <apitest.h>

extern void func_EffectivePowerMode(void);
extern void func_power(void);

const struct test winetest_testlist[] =
{
    { "EffectivePowerMode", func_EffectivePowerMode },
    { "power", func_power },
    { 0, 0 }
};
