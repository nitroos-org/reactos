spec2def(kernel.appcore.dll kernel.appcore.spec)

add_library(kernel_appcore MODULE
    kernel.appcore.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kernel.appcore.def)

set_module_type(kernel_appcore win32dll ENTRYPOINT 0)
set_target_properties(kernel_appcore PROPERTIES OUTPUT_NAME "kernel.appcore")
add_cd_file(TARGET kernel_appcore DESTINATION reactos/system32 FOR all)
