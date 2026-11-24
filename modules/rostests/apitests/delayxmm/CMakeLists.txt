
# Helper DLL: functions with floating point arguments, imported with delay-load by the test program
spec2def(delayxmm_dll.dll delayxmm_dll.spec ADD_IMPORTLIB)
list(APPEND DLL_SRC
    delayxmm_dll.c
    ${CMAKE_CURRENT_BINARY_DIR}/delayxmm_dll_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/delayxmm_dll.def)
add_library(delayxmm_dll MODULE ${DLL_SRC})
set_module_type(delayxmm_dll win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(delayxmm_dll kernel32)
add_dependencies(delayxmm_dll psdk)
add_rostests_file(TARGET delayxmm_dll)

add_executable(delayxmm_apitest delayxmm.c testlist.c)
set_module_type(delayxmm_apitest win32cui)
add_importlibs(delayxmm_apitest msvcrt kernel32)
add_delay_importlibs(delayxmm_apitest delayxmm_dll)
add_rostests_file(TARGET delayxmm_apitest)
