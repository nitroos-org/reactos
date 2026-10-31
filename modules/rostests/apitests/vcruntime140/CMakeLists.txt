
list(APPEND SOURCE
    vcruntime140.c
    FrameHelpers.c
    testlist.c)

add_executable(vcruntime140_apitest ${SOURCE})
set_module_type(vcruntime140_apitest win32cui)
target_link_libraries(vcruntime140_apitest wine ${PSEH_LIB})
add_importlibs(vcruntime140_apitest version msvcrt kernel32 ntdll)
add_rostests_file(TARGET vcruntime140_apitest)

# The runtime DLLs that this build does not make (dll/win32/CMakeLists.txt)
if(MSVC OR DLL_EXPORT_VERSION LESS 0x600)
    target_compile_definitions(vcruntime140_apitest PRIVATE VCRT_NO_MSVCP140)
endif()
if(MSVC)
    target_compile_definitions(vcruntime140_apitest PRIVATE VCRT_NO_VCRUNTIME140_1)
endif()

# pefixup sets the linker version of the images that GCC makes (the DLLs in dll/win32)
if(NOT MSVC)
    target_compile_definitions(vcruntime140_apitest PRIVATE VCRT_EXPECT_LINKER_MINOR=50)
endif()
