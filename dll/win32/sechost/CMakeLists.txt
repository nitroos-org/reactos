spec2def(sechost.dll sechost.spec)

add_library(sechost MODULE
    sechost.rc
    ${CMAKE_CURRENT_BINARY_DIR}/sechost.def)

set_module_type(sechost win32dll ENTRYPOINT 0)
set_target_properties(sechost PROPERTIES OUTPUT_NAME "sechost")
add_cd_file(TARGET sechost DESTINATION reactos/system32 FOR all)
