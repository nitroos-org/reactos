include_directories(../include)

#
# PsExitStatus
#
list(APPEND PSEXITSTATUS_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    PsExitStatus_drv.c)

add_library(psexitstatus_drv MODULE ${PSEXITSTATUS_DRV_SOURCE})
set_module_type(psexitstatus_drv kernelmodedriver)
target_link_libraries(psexitstatus_drv kmtest_printf ${PSEH_LIB})
add_importlibs(psexitstatus_drv ntoskrnl hal)
target_compile_definitions(psexitstatus_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET psexitstatus_drv)

# The child process of the test; on a 64-bit system the i386 build of it runs next to kmtest.exe as
# psexitstatus_child32.exe (a WoW64 process)
add_executable(psexitstatus_child PsExitStatus_child.c)
set_module_type(psexitstatus_child win32cui)
add_importlibs(psexitstatus_child msvcrt kernel32)
add_rostests_file(TARGET psexitstatus_child)
