#define STANDALONE
#include <apitest.h>

extern void func_DnscacheHandles(void);
extern void func_DnsQuery(void);

const struct test winetest_testlist[] =
{
    { "DnscacheHandles", func_DnscacheHandles },
    { "DnsQuery", func_DnsQuery },
    { 0, 0 }
};
