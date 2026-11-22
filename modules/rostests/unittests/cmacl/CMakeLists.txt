
# ntoskrnl.h here is a user mode stand-in, so that the kernel's verdict on user-hive descriptors compiles into a test
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${REACTOS_SOURCE_DIR}/modules/rostests/apitests/include)

add_executable(cmacl_unittest
    UserHiveVerdict.c
    ${REACTOS_SOURCE_DIR}/ntoskrnl/config/cmaclsd.c
    testlist.c)

set_module_type(cmacl_unittest win32cui)
add_importlibs(cmacl_unittest advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET cmacl_unittest)
