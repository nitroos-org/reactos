#define STANDALONE
#include <apitest.h>

extern void func_buttonv6(void);
extern void func_exports(void);
extern void func_ImageListApi(void);
extern void func_ImageListWriteEx(void);
extern void func_listviewv6(void);
extern void func_propsheetv6(void);
extern void func_propsheet_title(void);
extern void func_tabv6(void);
extern void func_treeviewv6(void);
extern void func_toolbarv6(void);
extern void func_tooltipv6(void);
extern void func_version(void);

const struct test winetest_testlist[] =
{
    { "buttonv6", func_buttonv6 },
    { "exports", func_exports },
    { "ImageListApi", func_ImageListApi },
    { "ImageListWriteEx", func_ImageListWriteEx },
    { "listviewv6", func_listviewv6 },
    { "propsheetv6", func_propsheetv6 },
    { "propsheet_title", func_propsheet_title },
    { "tabv6", func_tabv6 },
    { "treeviewv6", func_treeviewv6 },
    { "toolbarv6", func_toolbarv6 },
    { "tooltipv6", func_tooltipv6 },
    { "version", func_version },
    { 0, 0 }
};
