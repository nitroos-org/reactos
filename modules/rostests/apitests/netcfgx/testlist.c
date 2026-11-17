#define STANDALONE
#include <apitest.h>

extern void func_Tcpip6Component(void);

const struct test winetest_testlist[] =
{
    { "Tcpip6Component", func_Tcpip6Component },
    { 0, 0 }
};
