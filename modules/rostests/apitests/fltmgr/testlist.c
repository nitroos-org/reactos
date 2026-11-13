#define STANDALONE
#include <apitest.h>

extern void func_instance(void);
extern void func_operation(void);
extern void func_context(void);

const struct test winetest_testlist[] =
{
    { "instance", func_instance },
    { "operation", func_operation },
    { "context", func_context },
    { 0, 0 }
};
