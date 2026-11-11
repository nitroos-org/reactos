
#define STANDALONE
#include <wine/test.h>

extern void func_d2d1_present(void);
extern void func_d2d1_effects(void);
extern void func_d2d1_effect_render(void);
extern void func_d2d1_fillbatch(void);

const struct test winetest_testlist[] =
{
    { "d2d1_present", func_d2d1_present },
    { "d2d1_effects", func_d2d1_effects },
    { "d2d1_effect_render", func_d2d1_effect_render },
    { "d2d1_fillbatch", func_d2d1_fillbatch },

    { 0, 0 }
};
