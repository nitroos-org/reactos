#define STANDALONE
#include <apitest.h>

extern void func_StorportRoutines(void);

const struct test winetest_testlist[] =
{
    { "StorportRoutines", func_StorportRoutines },
};
