
#define STANDALONE
#include <apitest.h>

extern void func_browseui(void);
extern void func_certmgr(void);
extern void func_combase(void);
extern void func_explorerframe(void);
extern void func_ieframe(void);
extern void func_interfaces(void);
extern void func_netcfgx(void);
extern void func_netprofm(void);
extern void func_netshell(void);
extern void func_ole32(void);
extern void func_prnfldr(void);
extern void func_shdocvw(void);
extern void func_shell32(void);
extern void func_windows_storage(void);
extern void func_winrt_composition(void);
extern void func_winrt_packagemanager(void);
extern void func_winrt_profile(void);
extern void func_winrt_ui(void);
extern void func_zipfldr(void);

const struct test winetest_testlist[] =
{
    { "browseui", func_browseui },
    { "certmgr", func_certmgr },
    { "combase", func_combase },
    { "explorerframe", func_explorerframe },
    { "ieframe", func_ieframe },
    { "interfaces", func_interfaces },
    { "netcfgx", func_netcfgx },
    { "netprofm", func_netprofm },
    { "netshell", func_netshell },
    { "ole32", func_ole32 },
    { "prnfldr", func_prnfldr },
    { "shdocvw", func_shdocvw },
    { "shell32", func_shell32 },
    { "windows_storage", func_windows_storage },
    { "winrt_composition", func_winrt_composition },
    { "winrt_packagemanager", func_winrt_packagemanager },
    { "winrt_profile", func_winrt_profile },
    { "winrt_ui", func_winrt_ui },
    { "zipfldr", func_zipfldr },

    { 0, 0 }
};
