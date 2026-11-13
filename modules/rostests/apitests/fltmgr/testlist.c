#define STANDALONE
#include <apitest.h>

extern void func_instance(void);
extern void func_operation(void);
extern void func_context(void);
extern void func_comms(void);
extern void func_load(void);
extern void func_bootcheck(void);
extern void func_stress(void);
extern void func_eof(void);
extern void func_reload(void);

const struct test winetest_testlist[] =
{
    { "instance", func_instance },
    { "operation", func_operation },
    { "context", func_context },
    { "comms", func_comms },
    { "load", func_load },
    { "bootcheck", func_bootcheck },
    { "stress", func_stress },
    { "eof", func_eof },
    { "reload", func_reload },
    { 0, 0 }
};
