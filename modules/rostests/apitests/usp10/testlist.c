#define STANDALONE
#include <wine/test.h>

extern void func_usp10_nogpos(void);
extern void func_usp10_surrogate(void);

const struct test winetest_testlist[] =
{
    { "usp10_nogpos", func_usp10_nogpos },
    { "usp10_surrogate", func_usp10_surrogate },

    { 0, 0 }
};
