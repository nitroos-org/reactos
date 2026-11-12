#define STANDALONE
#include <wine/test.h>

extern void func_dwrite_glyph_leak(void);
extern void func_dwrite_cmap_race(void);
extern void func_dwrite_fallback_symbols(void);

const struct test winetest_testlist[] =
{
    { "dwrite_glyph_leak", func_dwrite_glyph_leak },
    { "dwrite_cmap_race", func_dwrite_cmap_race },
    { "dwrite_fallback_symbols", func_dwrite_fallback_symbols },

    { 0, 0 }
};
