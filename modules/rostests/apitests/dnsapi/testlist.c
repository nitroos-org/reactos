#define STANDALONE
#include <apitest.h>

extern void func_DnscacheHandles(void);
extern void func_DnsQuery(void);
extern void func_DnsQueryAaaa(void);
extern void func_DnsQueryMany(void);
extern void func_DnsQueryTypes(void);

const struct test winetest_testlist[] =
{
    { "DnscacheHandles", func_DnscacheHandles },
    { "DnsQuery", func_DnsQuery },
    { "DnsQueryAaaa", func_DnsQueryAaaa },
    { "DnsQueryMany", func_DnsQueryMany },
    { "DnsQueryTypes", func_DnsQueryTypes },
    { 0, 0 }
};
