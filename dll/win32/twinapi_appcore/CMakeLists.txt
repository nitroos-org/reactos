spec2def(twinapi.appcore.dll twinapi.appcore.spec)

add_library(twinapi_appcore MODULE
    twinapi.appcore.c
    twinapi.appcore.rc
    ${CMAKE_CURRENT_BINARY_DIR}/twinapi.appcore.def)

set_module_type(twinapi_appcore win32dll ENTRYPOINT 0)
set_target_properties(twinapi_appcore PROPERTIES OUTPUT_NAME "twinapi.appcore")
add_importlibs(twinapi_appcore kernel32 ntdll)
add_cd_file(TARGET twinapi_appcore DESTINATION reactos/system32 FOR all)
