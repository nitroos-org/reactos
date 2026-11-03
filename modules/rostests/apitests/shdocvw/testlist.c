#define STANDALONE
#include <apitest.h>

extern void func_AttachmentExecute(void);
extern void func_DownloadNames(void);
extern void func_FileDownload(void);
extern void func_InternetShortcut(void);
extern void func_MRUList(void);
extern void func_WinList(void);

const struct test winetest_testlist[] =
{
    { "AttachmentExecute", func_AttachmentExecute },
    { "DownloadNames", func_DownloadNames },
    { "FileDownload", func_FileDownload },
    { "InternetShortcut", func_InternetShortcut },
    { "MRUList", func_MRUList },
    { "WinList", func_WinList },
    { 0, 0 }
};
