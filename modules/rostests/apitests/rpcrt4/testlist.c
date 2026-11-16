#define STANDALONE
#include <apitest.h>

extern void func_autolisten(void);
extern void func_conn_reuse(void);
extern void func_generic_handle(void);
extern void func_interface_access(void);
extern void func_ntlm_auth(void);
extern void func_primitive_handle(void);

const struct test winetest_testlist[] =
{
    { "autolisten", func_autolisten },
    { "conn_reuse", func_conn_reuse },
    { "generic_handle", func_generic_handle },
    { "interface_access", func_interface_access },
    { "ntlm_auth", func_ntlm_auth },
    { "primitive_handle", func_primitive_handle },
    { 0, 0 }
};
