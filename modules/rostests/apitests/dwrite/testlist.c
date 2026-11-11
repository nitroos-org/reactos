#define STANDALONE
#include <wine/test.h>

extern void func_dwrite_glyph_leak(void);
extern void func_dwrite_cmap_race(void);

const struct test winetest_testlist[] =
{
    { "dwrite_glyph_leak", func_dwrite_glyph_leak },
    { "dwrite_cmap_race", func_dwrite_cmap_race },

    { 0, 0 }
};
