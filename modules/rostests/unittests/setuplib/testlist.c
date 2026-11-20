#define STANDALONE
#include <apitest.h>

extern void func_GptLayout(void);
extern void func_IsValidInstallDirectory(void);
extern void func_UnattendParse(void);

const struct test winetest_testlist[] =
{
    { "GptLayout", func_GptLayout },
    { "IsValidInstallDirectory", func_IsValidInstallDirectory },
    { "UnattendParse", func_UnattendParse },
    { 0, 0 }
};
