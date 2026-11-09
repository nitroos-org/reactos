/* Automatically generated file; DO NOT EDIT!! */

#define STANDALONE
#include <wine/test.h>

extern void func_apphelp(void);
extern void func_appcache(void);
extern void func_db(void);
extern void func_env(void);
extern void func_layerapi(void);
extern void func_register(void);
extern void func_shimload(void);

const struct test winetest_testlist[] =
{
    { "apphelp", func_apphelp },
    { "appcache", func_appcache },
    { "db", func_db },
    { "env", func_env },
    { "layerapi", func_layerapi },
    { "register", func_register },
    { "shimload", func_shimload },
    { 0, 0 }
};
