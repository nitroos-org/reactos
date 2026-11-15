
#define STANDALONE
#include <apitest.h>

extern void func_AppContainerProfile(void);
extern void func_AppContainerRegisterSid(void);
extern void func_DeleteProfile(void);
extern void func_DeriveAppContainerSid(void);
extern void func_GetProfileDirs(void);
extern void func_LegacyProfileJunctions(void);
extern void func_LoadUserProfile(void);
extern void func_NetworkCatalogUpgrade(void);
extern void func_ProfileSecurity(void);
extern void func_ProgramDataSecurity(void);

const struct test winetest_testlist[] =
{
    { "AppContainerProfile", func_AppContainerProfile },
    { "AppContainerRegisterSid", func_AppContainerRegisterSid },
    { "DeleteProfile", func_DeleteProfile },
    { "DeriveAppContainerSid", func_DeriveAppContainerSid },
    { "GetProfileDirs", func_GetProfileDirs },
    { "LegacyProfileJunctions", func_LegacyProfileJunctions },
    { "LoadUserProfile", func_LoadUserProfile },
    { "NetworkCatalogUpgrade", func_NetworkCatalogUpgrade },
    { "ProfileSecurity", func_ProfileSecurity },
    { "ProgramDataSecurity", func_ProgramDataSecurity },
    { 0, 0 }
};
