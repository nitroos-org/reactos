
add_library(fltsample MODULE fltsample.c)
set_module_type(fltsample kernelmodedriver)
target_compile_definitions(fltsample PRIVATE NTDDI_VERSION=NTDDI_WS03SP1)
add_importlibs(fltsample fltmgr ntoskrnl hal)
add_rostests_file(TARGET fltsample)
