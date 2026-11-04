#define STANDALONE
#include <apitest.h>

extern void func_StandardCimv2(void);
extern void func_Win32_Process(void);

const struct test winetest_testlist[] =
{
    { "StandardCimv2", func_StandardCimv2 },
    { "Win32_Process", func_Win32_Process },
    { 0, 0 }
};
