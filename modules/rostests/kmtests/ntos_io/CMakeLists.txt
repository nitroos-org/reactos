
include_directories(../include)

#
# IoCreateFile
#
list(APPEND IOCREATEFILE_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    IoCreateFile_drv.c)

add_library(iocreatefile_drv MODULE ${IOCREATEFILE_DRV_SOURCE})
set_module_type(iocreatefile_drv kernelmodedriver)
target_link_libraries(iocreatefile_drv kmtest_printf ${PSEH_LIB})
add_importlibs(iocreatefile_drv ntoskrnl hal)
target_compile_definitions(iocreatefile_drv PRIVATE KMT_STANDALONE_DRIVER)
#add_pch(iocreatefile_drv ../include/kmt_test.h)
add_rostests_file(TARGET iocreatefile_drv)

#
# IoCreateFileEx
#
list(APPEND IOCREATEFILEEX_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    IoCreateFileEx_drv.c)

add_library(iocreatefileex_drv MODULE ${IOCREATEFILEEX_DRV_SOURCE})
set_module_type(iocreatefileex_drv kernelmodedriver)
target_link_libraries(iocreatefileex_drv kmtest_printf ${PSEH_LIB})
add_importlibs(iocreatefileex_drv ntoskrnl hal)
target_compile_definitions(iocreatefileex_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET iocreatefileex_drv)

#
# IoDeviceObject
#
list(APPEND IODEVICEOBJECT_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    IoDeviceObject_drv.c)

add_library(iodeviceobject_drv MODULE ${IODEVICEOBJECT_DRV_SOURCE})
set_module_type(iodeviceobject_drv kernelmodedriver)
target_link_libraries(iodeviceobject_drv kmtest_printf ${PSEH_LIB})
add_importlibs(iodeviceobject_drv ntoskrnl hal)
target_compile_definitions(iodeviceobject_drv PRIVATE KMT_STANDALONE_DRIVER)
#add_pch(iodeviceobject_drv ../include/kmt_test.h)
add_rostests_file(TARGET iodeviceobject_drv)

#
# IoHelper
#
list(APPEND IOHELPER_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    IoHelper_drv.c)

add_library(iohelper_drv MODULE ${IOHELPER_DRV_SOURCE})
set_module_type(iohelper_drv kernelmodedriver)
target_link_libraries(iohelper_drv kmtest_printf ${PSEH_LIB})
add_importlibs(iohelper_drv ntoskrnl hal)
target_compile_definitions(iohelper_drv PRIVATE KMT_STANDALONE_DRIVER)
#add_pch(iohelper_drv ../include/kmt_test.h)
add_rostests_file(TARGET iohelper_drv)

#
# IoIs32bitProcess
#
list(APPEND IOIS32BITPROCESS_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    IoIs32bitProcess_drv.c)

add_library(iois32bitprocess_drv MODULE ${IOIS32BITPROCESS_DRV_SOURCE})
set_module_type(iois32bitprocess_drv kernelmodedriver)
target_link_libraries(iois32bitprocess_drv kmtest_printf ${PSEH_LIB})
add_importlibs(iois32bitprocess_drv ntoskrnl hal)
target_compile_definitions(iois32bitprocess_drv PRIVATE KMT_STANDALONE_DRIVER)
add_rostests_file(TARGET iois32bitprocess_drv)

# The client kmtest.exe runs as a WoW64 process: the i386 build of it, installed next to the 64-bit
# kmtest.exe as iois32bitprocess_client32.exe
add_executable(iois32bitprocess_client IoIs32bitProcess_client.c)
set_module_type(iois32bitprocess_client win32cui)
add_importlibs(iois32bitprocess_client msvcrt kernel32 ntdll)
target_compile_definitions(iois32bitprocess_client PRIVATE NTDDI_VERSION=NTDDI_WS03SP1)
add_rostests_file(TARGET iois32bitprocess_client)

#
# IoReadWrite
#
list(APPEND IOREADWRITE_DRV_SOURCE
    ../kmtest_drv/kmtest_standalone.c
    IoReadWrite_drv.c)

add_library(ioreadwrite_drv MODULE ${IOREADWRITE_DRV_SOURCE})
set_module_type(ioreadwrite_drv kernelmodedriver)
target_link_libraries(ioreadwrite_drv kmtest_printf ${PSEH_LIB})
add_importlibs(ioreadwrite_drv ntoskrnl hal)
target_compile_definitions(ioreadwrite_drv PRIVATE KMT_STANDALONE_DRIVER)
#add_pch(ioreadwrite_drv ../include/kmt_test.h)
add_rostests_file(TARGET ioreadwrite_drv)
