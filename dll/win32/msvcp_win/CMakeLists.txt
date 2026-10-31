spec2def(msvcp_win.dll msvcp_win.spec)

add_library(msvcp_win MODULE
    msvcp_win.rc
    ${CMAKE_CURRENT_BINARY_DIR}/msvcp_win.def)

set_module_type(msvcp_win win32dll ENTRYPOINT 0)
set_target_properties(msvcp_win PROPERTIES OUTPUT_NAME "msvcp_win")
add_cd_file(TARGET msvcp_win DESTINATION reactos/system32 FOR all)
