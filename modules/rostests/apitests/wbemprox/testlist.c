#define STANDALONE
#include <apitest.h>

extern void func_Win32_Process(void);

const struct test winetest_testlist[] =
{
    { "Win32_Process", func_Win32_Process },
    { 0, 0 }
};
