
#define STANDALONE
#include <wine/test.h>

extern void func_initializespy(void);
extern void func_ScmCreatedEvent(void);
extern void func_SystemWow64Directory(void);

const struct test winetest_testlist[] =
{
    { "initializespy", func_initializespy },
    { "ScmCreatedEvent", func_ScmCreatedEvent },
    { "SystemWow64Directory", func_SystemWow64Directory },

    { 0, 0 }
};
