
#define STANDALONE
#include <apitest.h>

extern void func_CM_Is_Dock_Station_Present(void);
extern void func_CM_Get_DevNode_Property(void);
extern void func_CM_Register_Notification(void);
extern void func_devclass(void);
extern void func_RootBusDisable(void);
extern void func_RootDeviceDisable(void);
extern void func_RootDeviceInstallRestart(void);
extern void func_RootDeviceRemove(void);
extern void func_SetupDiGetActualModelsSection(void);
extern void func_SetupDiGetDeviceProperty(void);
extern void func_SetupDiInstallClassExA(void);
extern void func_SetupInstallServicesFromInfSectionEx(void);
extern void func_CM_MapCrToErr(void);
extern void func_CM_PowerScheme(void);
extern void func_CM_Get_DevNode_Property_Keys(void);
extern void func_CM_Get_Device_Interface_Property(void);
extern void func_CM_Get_Class_Property(void);

const struct test winetest_testlist[] =
{
    { "CM_Is_Dock_Station_Present", func_CM_Is_Dock_Station_Present },
    { "CM_Get_DevNode_Property", func_CM_Get_DevNode_Property },
    { "CM_Register_Notification", func_CM_Register_Notification },
    { "devclass", func_devclass },
    { "RootBusDisable", func_RootBusDisable },
    { "RootDeviceDisable", func_RootDeviceDisable },
    { "RootDeviceInstallRestart", func_RootDeviceInstallRestart },
    { "RootDeviceRemove", func_RootDeviceRemove },
    { "SetupDiGetActualModelsSection", func_SetupDiGetActualModelsSection },
    { "SetupDiGetDeviceProperty", func_SetupDiGetDeviceProperty },
    { "SetupDiInstallClassExA", func_SetupDiInstallClassExA },
    { "SetupInstallServicesFromInfSectionEx", func_SetupInstallServicesFromInfSectionEx },
    { "CM_MapCrToErr", func_CM_MapCrToErr },
    { "CM_PowerScheme", func_CM_PowerScheme },
    { "CM_Get_DevNode_Property_Keys", func_CM_Get_DevNode_Property_Keys },
    { "CM_Get_Device_Interface_Property", func_CM_Get_Device_Interface_Property },
    { "CM_Get_Class_Property", func_CM_Get_Class_Property },
    { 0, 0 }
};
