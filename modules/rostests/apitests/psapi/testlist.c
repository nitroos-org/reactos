
#define STANDALONE
#include <wine/test.h>

extern void func_EnumProcessModulesEx(void);
extern void func_ListGrowth(void);
extern void func_QueryWorkingSet(void);
extern void func_GetDeviceDriverFileName(void);
extern void func_GetDeviceDriverBaseName(void);

const struct test winetest_testlist[] =
{
    { "EnumProcessModulesEx",                       func_EnumProcessModulesEx },
    { "ListGrowth",                                 func_ListGrowth },
    { "QueryWorkingSet",                            func_QueryWorkingSet },
    { "GetDeviceDriverFileName",                    func_GetDeviceDriverFileName },
    { "GetDeviceDriverBaseName",                    func_GetDeviceDriverBaseName },

    { 0, 0 }
};

