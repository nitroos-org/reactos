#define STANDALONE
#include <apitest.h>

extern void func_HttpServerApi(void);
extern void func_HttpServerFlow(void);

const struct test winetest_testlist[] =
{
    { "HttpServerApi", func_HttpServerApi },
    { "HttpServerFlow", func_HttpServerFlow },

    { 0, 0 }
};
