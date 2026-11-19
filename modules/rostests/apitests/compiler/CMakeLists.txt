
if (MSVC OR ARCH STREQUAL "i386")
    #FIXME _setjmp definitions in CRT headers is wrong
    add_subdirectory(ms)
    list(APPEND SOURCE ms_seh.c)
endif()

list(APPEND SOURCE
    floatconv.c
    hresult.c
    hresult_cpp.cpp
    hresult_inline.c
    pseh.c
    pseh_cpp.cpp
    psehtest2.c
    testlist.c)

add_executable(compiler_apitest ${SOURCE})
if (MSVC OR ARCH STREQUAL "i386")
    target_link_libraries(compiler_apitest ms_seh_test)
endif()
target_link_libraries(compiler_apitest wine ${PSEH_LIB})
set_module_type(compiler_apitest win32cui)
# amd64 GCC: the PSEH tests keep doubles in try blocks (see ros_no_nonvolatile_xmm)
ros_no_nonvolatile_xmm(compiler_apitest)
add_importlibs(compiler_apitest msvcrt kernel32 ntdll)
add_rostests_file(TARGET compiler_apitest)
