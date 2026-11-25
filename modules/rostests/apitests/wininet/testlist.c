
#define STANDALONE
#include <apitest.h>

extern void func_CookieEx2(void);
extern void func_HttpGzip(void);
extern void func_InternetOpen(void);
extern void func_ProxyBypass(void);

const struct test winetest_testlist[] =
{
    { "CookieEx2", func_CookieEx2 },
    { "HttpGzip", func_HttpGzip },
    { "InternetOpen", func_InternetOpen },
    { "ProxyBypass", func_ProxyBypass },

    { 0, 0 }
};
