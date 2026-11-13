#define STANDALONE
#include <apitest.h>

extern void func_instance(void);
extern void func_operation(void);
extern void func_context(void);
extern void func_comms(void);

const struct test winetest_testlist[] =
{
    { "instance", func_instance },
    { "operation", func_operation },
    { "context", func_context },
    { "comms", func_comms },
    { 0, 0 }
};
