
list(APPEND SOURCE
    CM_Is_Dock_Station_Present.c
    CM_Get_DevNode_Property.c
    CM_MapCrToErr.c
    CM_PowerScheme.c
    CM_Get_Class_Property.c
    CM_Get_Device_Interface_Property.c
    CM_Get_DevNode_Property_Keys.c
    CM_Register_Notification.c
    CM_Get_Device_Interface_List.c
    RegisterDeviceNotification.c
    devclass.c
    RootBusDisable.c
    RootDeviceDisable.c
    RootDeviceInstallRestart.c
    RootDeviceRemove.c
    SetupDiInstallClassExA.c
    SetupDiGetActualModelsSection.c
    SetupDiGetDeviceProperty.c
    SetupInstallServicesFromInfSectionEx.c
    testlist.c)

include_directories(${REACTOS_SOURCE_DIR}/modules/rostests/drivers/fakemp)
add_executable(setupapi_apitest ${SOURCE})
set_module_type(setupapi_apitest win32cui)
add_importlibs(setupapi_apitest advapi32 netapi32 setupapi shlwapi user32 msvcrt kernel32)
add_dependencies(setupapi_apitest fakemps fakebus)
add_rostests_file(TARGET setupapi_apitest)
