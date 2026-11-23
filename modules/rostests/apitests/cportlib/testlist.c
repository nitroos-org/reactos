#define STANDALONE
#include <wine/test.h>

extern void func_Uart16550GetByte(void);

const struct test winetest_testlist[] =
{
    { "Uart16550GetByte", func_Uart16550GetByte },
    { 0, 0 }
};
