#define STANDALONE
#include <apitest.h>

extern void func_select(void);
extern void func_send(void);
extern void func_sendcancel(void);
extern void func_sendtounbound(void);
extern void func_sendbeforeconnect(void);
extern void func_windowsize(void);
extern void func_nonpagedwindow(void);
extern void func_defensive(void);
extern void func_dgramstub(void);
extern void func_dgramhot(void);
extern void func_dgramclose(void);
extern void func_dgramfail(void);
extern void func_dgramlate(void);
extern void func_tcpnonadmin(void);
extern void func_tcpsetinfoex(void);
extern void func_tcpaccept(void);
extern void func_outputprobe(void);
extern void func_connectoptions(void);
extern void func_acceptstate(void);
extern void func_acceptname(void);

extern void func_g7lockbuffers(void);

extern void func_g7shortaddr(void);

extern void func_g7acceptlistening(void);

extern void func_g7setip(void);

extern void func_g7setinfoex(void);

extern void func_g8ndisstats(void);
extern void func_g8dgramqueue(void);
extern void func_g8dgramcancel(void);
extern void func_g8icmp(void);
extern void func_g8hwquery(void);
extern void func_g8tableinfo(void);

const struct test winetest_testlist[] =
{
    { "select", func_select },
    { "send", func_send },
    { "sendcancel", func_sendcancel },
    { "sendtounbound", func_sendtounbound },
    { "sendbeforeconnect", func_sendbeforeconnect },
    { "windowsize", func_windowsize },
    { "nonpagedwindow", func_nonpagedwindow },
    { "defensive", func_defensive },
    { "dgramstub", func_dgramstub },
    { "dgramhot", func_dgramhot },
    { "dgramclose", func_dgramclose },
    { "dgramfail", func_dgramfail },
    { "dgramlate", func_dgramlate },
    { "tcpnonadmin", func_tcpnonadmin },
    { "tcpsetinfoex", func_tcpsetinfoex },
    { "tcpaccept", func_tcpaccept },
    { "outputprobe", func_outputprobe },
    { "connectoptions", func_connectoptions },
    { "acceptstate", func_acceptstate },
    { "acceptname", func_acceptname },
    { "g7lockbuffers", func_g7lockbuffers },
    { "g7shortaddr", func_g7shortaddr },
    { "g7acceptlistening", func_g7acceptlistening },
    { "g7setip", func_g7setip },
    { "g7setinfoex", func_g7setinfoex },
    { "g8ndisstats", func_g8ndisstats },
    { "g8dgramqueue", func_g8dgramqueue },
    { "g8dgramcancel", func_g8dgramcancel },
    { "g8icmp", func_g8icmp },
    { "g8hwquery", func_g8hwquery },
    { "g8tableinfo", func_g8tableinfo },
    { 0, 0 }
};
