#define STANDALONE
#include <wine/test.h>

extern void func_usp10_nogpos(void);

const struct test winetest_testlist[] =
{
    { "usp10_nogpos", func_usp10_nogpos },

    { 0, 0 }
};
