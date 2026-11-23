
list(APPEND SOURCE
    lfbmp.c
    lfbmp.h)

add_library(lfbmp MODULE ${SOURCE} lfbmp.rc)
set_module_type(lfbmp kernelmodedriver)
add_importlibs(lfbmp videoprt)
target_link_libraries(lfbmp libcntpr)
add_pch(lfbmp lfbmp.h SOURCE)
add_cd_file(TARGET lfbmp DESTINATION reactos/system32/drivers FOR all)
add_registry_inf(lfbmp_reg.inf)
add_driver_inf(lfbmp lfbmp.inf)
