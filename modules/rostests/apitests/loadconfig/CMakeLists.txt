
spec2def(loadconfig_apitest.exe loadconfig_apitest.spec)

list(APPEND SOURCE
    common.c
    cookie.c
    stacktrace.c
    loadconfig.h)

add_executable(loadconfig_apitest ${SOURCE} testlist.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_apitest.def)

set_target_properties(loadconfig_apitest
    PROPERTIES
    ENABLE_EXPORTS TRUE
    DEFINE_SYMBOL "")

target_link_libraries(loadconfig_apitest wine ${PSEH_LIB})
set_module_type(loadconfig_apitest win32cui)
add_importlibs(loadconfig_apitest msvcrt kernel32 ntdll)
#add_pch(loadconfig_apitest loadconfig.h SOURCE)
add_rostests_file(TARGET loadconfig_apitest)

fixup_load_config(loadconfig_apitest)

# Images with a security cookie for the loader to make (cookie.c). One source, four DLLs: 1 is imported statically by
# loadconfig_cookie_exe, 4 by delay load, 2 is found by LoadLibrary and by the forwarder loadconfig_cookief, 3 has no
# entry point
spec2def(loadconfig_cookie1.dll loadconfig_cookie1.spec ADD_IMPORTLIB)
add_library(loadconfig_cookie1 MODULE cookie_dll.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_cookie1.def)
set_target_properties(loadconfig_cookie1 PROPERTIES ENABLE_EXPORTS TRUE DEFINE_SYMBOL "")
set_module_type(loadconfig_cookie1 win32dll ENTRYPOINT DllMain 12)
add_importlibs(loadconfig_cookie1 kernel32)
add_rostests_file(TARGET loadconfig_cookie1)
fixup_load_config(loadconfig_cookie1)

spec2def(loadconfig_cookie2.dll loadconfig_cookie2.spec)
add_library(loadconfig_cookie2 MODULE cookie_dll.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_cookie2.def)
set_target_properties(loadconfig_cookie2 PROPERTIES ENABLE_EXPORTS TRUE DEFINE_SYMBOL "")
set_module_type(loadconfig_cookie2 win32dll ENTRYPOINT DllMain 12)
add_importlibs(loadconfig_cookie2 kernel32)
add_rostests_file(TARGET loadconfig_cookie2)
fixup_load_config(loadconfig_cookie2)

spec2def(loadconfig_cookie3.dll loadconfig_cookie3.spec)
add_library(loadconfig_cookie3 MODULE cookie_dll.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_cookie3.def)
set_target_properties(loadconfig_cookie3 PROPERTIES ENABLE_EXPORTS TRUE DEFINE_SYMBOL "")
set_module_type(loadconfig_cookie3 win32dll ENTRYPOINT 0)
fixup_load_config(loadconfig_cookie3)
add_rostests_file(TARGET loadconfig_cookie3)

spec2def(loadconfig_cookie4.dll loadconfig_cookie4.spec ADD_IMPORTLIB)
add_library(loadconfig_cookie4 MODULE cookie_dll.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_cookie4.def)
set_target_properties(loadconfig_cookie4 PROPERTIES ENABLE_EXPORTS TRUE DEFINE_SYMBOL "")
set_module_type(loadconfig_cookie4 win32dll ENTRYPOINT DllMain 12)
add_importlibs(loadconfig_cookie4 kernel32)
add_rostests_file(TARGET loadconfig_cookie4)
fixup_load_config(loadconfig_cookie4)

spec2def(loadconfig_cookief.dll loadconfig_cookief.spec)
add_library(loadconfig_cookief MODULE cookie_fwd.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_cookief.def)
set_module_type(loadconfig_cookief win32dll ENTRYPOINT 0)
add_rostests_file(TARGET loadconfig_cookief)

spec2def(loadconfig_cookie_exe.exe loadconfig_cookie_exe.spec)
add_executable(loadconfig_cookie_exe cookie_exe.c ${CMAKE_CURRENT_BINARY_DIR}/loadconfig_cookie_exe.def)
set_target_properties(loadconfig_cookie_exe PROPERTIES ENABLE_EXPORTS TRUE DEFINE_SYMBOL "")
set_module_type(loadconfig_cookie_exe win32cui)
add_importlibs(loadconfig_cookie_exe loadconfig_cookie1 msvcrt kernel32)
add_delay_importlibs(loadconfig_cookie_exe loadconfig_cookie4)
add_rostests_file(TARGET loadconfig_cookie_exe)
fixup_load_config(loadconfig_cookie_exe)
