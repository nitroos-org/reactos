
include_directories(../include)

#
# MupProvider
#
list(APPEND MUPPROVIDER_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    MupProvider_drv.c)

add_library(mupprovider_drv MODULE ${MUPPROVIDER_DRV_SOURCE})
set_module_type(mupprovider_drv kernelmodedriver)
target_link_libraries(mupprovider_drv kmtest_printf ${PSEH_LIB})
add_importlibs(mupprovider_drv ntoskrnl hal)
target_compile_definitions(mupprovider_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET mupprovider_drv)
