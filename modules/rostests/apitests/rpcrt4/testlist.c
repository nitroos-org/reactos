#define STANDALONE
#include <apitest.h>

extern void func_conn_reuse(void);
extern void func_interface_access(void);
extern void func_ntlm_auth(void);

const struct test winetest_testlist[] =
{
    { "conn_reuse", func_conn_reuse },
    { "interface_access", func_interface_access },
    { "ntlm_auth", func_ntlm_auth },
    { 0, 0 }
};
