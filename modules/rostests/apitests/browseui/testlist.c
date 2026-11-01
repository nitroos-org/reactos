
#define STANDALONE
#include <apitest.h>

extern void func_ACListISF(void);
extern void func_BandSite(void);
extern void func_FolderWindowResources(void);
extern void func_IACLCustomMRU(void);
extern void func_IACLHistory(void);
extern void func_IAutoComplete(void);
extern void func_SHEnumClassesOfCategories(void);
extern void func_SHExplorerParseCmdLine(void);

const struct test winetest_testlist[] =
{
    { "ACListISF", func_ACListISF },
    { "BandSite", func_BandSite },
    { "FolderWindowResources", func_FolderWindowResources },
    { "IACLCustomMRU", func_IACLCustomMRU },
    { "IACLHistory", func_IACLHistory },
    { "IAutoComplete", func_IAutoComplete },
    { "SHEnumClassesOfCategories", func_SHEnumClassesOfCategories },
    { "SHExplorerParseCmdLine", func_SHExplorerParseCmdLine },
    { 0, 0 }
};
