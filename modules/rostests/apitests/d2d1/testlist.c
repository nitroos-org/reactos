
#define STANDALONE
#include <wine/test.h>

extern void func_d2d1_present(void);
extern void func_d2d1_effects(void);

const struct test winetest_testlist[] =
{
    { "d2d1_present", func_d2d1_present },
    { "d2d1_effects", func_d2d1_effects },

    { 0, 0 }
};
