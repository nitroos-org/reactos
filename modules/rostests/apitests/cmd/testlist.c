#define STANDALONE
#include <apitest.h>

extern void func_attrib(void);
extern void func_cd(void);
extern void func_color(void);
extern void func_echo(void);
extern void func_echoenc(void);
extern void func_exit(void);
extern void func_exitb(void);
extern void func_fc(void);
extern void func_mklink(void);
extern void func_mkdir(void);
extern void func_pipe(void);
extern void func_ftype(void);
extern void func_pushd(void);
extern void func_ren(void);
extern void func_search(void);
extern void func_start(void);

const struct test winetest_testlist[] =
{
    { "attrib", func_attrib },
    { "cd", func_cd },
    { "color", func_color },
    { "echo", func_echo },
    { "echoenc", func_echoenc },
    { "exit", func_exit },
    { "exitb", func_exitb },
    { "fc", func_fc },
    { "mklink", func_mklink },
    { "mkdir", func_mkdir },
    { "pipe", func_pipe },
    { "ftype", func_ftype },
    { "pushd", func_pushd },
    { "ren", func_ren },
    { "search", func_search },
    { "start", func_start },
    { 0, 0 }
};
