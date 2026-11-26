
#define STANDALONE
#include <apitest.h>

extern void func_cookie(void);
extern void func_stacktrace(void);

const struct test winetest_testlist[] =
{
    { "cookie",                         func_cookie },
    { "stacktrace",                     func_stacktrace },

    { 0, 0 }
};
