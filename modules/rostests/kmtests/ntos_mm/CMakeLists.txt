
include_directories(../include)

#
# NtCreateSection
#
list(APPEND NTCREATESECTION_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    NtCreateSection_drv.c)

add_library(ntcreatesection_drv MODULE ${NTCREATESECTION_DRV_SOURCE})
set_module_type(ntcreatesection_drv kernelmodedriver)
target_link_libraries(ntcreatesection_drv kmtest_printf ${PSEH_LIB})
add_importlibs(ntcreatesection_drv ntoskrnl hal)
target_compile_definitions(ntcreatesection_drv PRIVATE KMT_STANDALONE_DRIVER)
#add_pch(ntcreatesection_drv ../include/kmt_test.h)
add_rostests_file(TARGET ntcreatesection_drv)

#
# MmMapLockedPagesSpecifyCache
#
list(APPEND MMMAPLOCKEDPAGESSPECIFYCACHE_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    MmMapLockedPagesSpecifyCache_drv.c)

add_library(mmmaplockedpagesspecifycache_drv MODULE ${MMMAPLOCKEDPAGESSPECIFYCACHE_DRV_SOURCE})
set_module_type(mmmaplockedpagesspecifycache_drv kernelmodedriver)
target_link_libraries(mmmaplockedpagesspecifycache_drv kmtest_printf ${PSEH_LIB})
add_importlibs(mmmaplockedpagesspecifycache_drv ntoskrnl hal)
target_compile_definitions(mmmaplockedpagesspecifycache_drv PRIVATE KMT_STANDALONE_DRIVER)
#add_pch(mmmaplockedpagesspecifycache_drv ../include/kmt_test.h)
add_rostests_file(TARGET mmmaplockedpagesspecifycache_drv)

#
# MmSpecialPool (user-mode accesses)
#
list(APPEND MMSPECIALPOOL_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    MmSpecialPool_drv.c)

add_library(mmspecialpool_drv MODULE ${MMSPECIALPOOL_DRV_SOURCE})
set_module_type(mmspecialpool_drv kernelmodedriver)
target_link_libraries(mmspecialpool_drv kmtest_printf ${PSEH_LIB})
add_importlibs(mmspecialpool_drv ntoskrnl hal)
target_compile_definitions(mmspecialpool_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET mmspecialpool_drv)

#
# Session images (MmSessionImage): sesstst_a, and sesstst_b which imports it
#
spec2def(sesstst_a.sys sesstst_a.spec ADD_IMPORTLIB)
add_library(sesstst_a MODULE sesstst_a.c ${CMAKE_CURRENT_BINARY_DIR}/sesstst_a.def)
set_module_type(sesstst_a kernelmodedriver)
add_importlibs(sesstst_a ntoskrnl)
add_rostests_file(TARGET sesstst_a)

spec2def(sesstst_b.sys sesstst_b.spec)
add_library(sesstst_b MODULE sesstst_b.c ${CMAKE_CURRENT_BINARY_DIR}/sesstst_b.def)
set_module_type(sesstst_b kernelmodedriver)
add_importlibs(sesstst_b sesstst_a ntoskrnl)
add_rostests_file(TARGET sesstst_b)
