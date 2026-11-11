#define STANDALONE
#include <wine/test.h>

extern void func_dwrite_glyph_leak(void);

const struct test winetest_testlist[] =
{
    { "dwrite_glyph_leak", func_dwrite_glyph_leak },

    { 0, 0 }
};
