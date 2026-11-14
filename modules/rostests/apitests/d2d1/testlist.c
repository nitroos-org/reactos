
#define STANDALONE
#include <wine/test.h>

extern void func_d2d1_present(void);
extern void func_d2d1_cannotdraw(void);
extern void func_d2d1_combine(void);
extern void func_d2d1_wictarget(void);
extern void func_d2d1_effects(void);
extern void func_d2d1_effect_render(void);
extern void func_d2d1_fillbatch(void);
extern void func_d2d1_shapebatch(void);
extern void func_d2d1_svg(void);
extern void func_d2d1_svgdraw(void);

const struct test winetest_testlist[] =
{
    { "d2d1_present", func_d2d1_present },
    { "d2d1_cannotdraw", func_d2d1_cannotdraw },
    { "d2d1_combine", func_d2d1_combine },
    { "d2d1_wictarget", func_d2d1_wictarget },
    { "d2d1_effects", func_d2d1_effects },
    { "d2d1_effect_render", func_d2d1_effect_render },
    { "d2d1_fillbatch", func_d2d1_fillbatch },
    { "d2d1_shapebatch", func_d2d1_shapebatch },
    { "d2d1_svg", func_d2d1_svg },
    { "d2d1_svgdraw", func_d2d1_svgdraw },

    { 0, 0 }
};
