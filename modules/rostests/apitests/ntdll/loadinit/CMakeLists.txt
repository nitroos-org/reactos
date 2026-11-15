
# Helper DLLs of the LdrLoadDllPendingInit test: P imports A then B, B imports C, N imports B; A's DllMain
# reaches B (LoadLibrary, GetProcAddress, or the load of N) while B and C are mapped but not yet initialized

spec2def(ntdll_loadinit_c.dll loadinit_c.spec ADD_IMPORTLIB)
list(APPEND C_SRC
    loadinit_c.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_loadinit_c_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_loadinit_c.def)
add_library(ntdll_loadinit_c MODULE ${C_SRC})
set_module_type(ntdll_loadinit_c win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ntdll_loadinit_c kernel32 ntdll)
add_dependencies(ntdll_loadinit_c psdk)
add_rostests_file(TARGET ntdll_loadinit_c)

spec2def(ntdll_loadinit_b.dll loadinit_b.spec ADD_IMPORTLIB)
list(APPEND B_SRC
    loadinit_b.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_loadinit_b_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_loadinit_b.def)
add_library(ntdll_loadinit_b MODULE ${B_SRC})
set_module_type(ntdll_loadinit_b win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ntdll_loadinit_b ntdll_loadinit_c kernel32 ntdll)
add_dependencies(ntdll_loadinit_b psdk ntdll_loadinit_c)
add_rostests_file(TARGET ntdll_loadinit_b)

spec2def(ntdll_loadinit_a.dll loadinit_a.spec ADD_IMPORTLIB)
list(APPEND A_SRC
    loadinit_a.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_loadinit_a_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/ntdll_loadinit_a.def)
add_library(ntdll_loadinit_a MODULE ${A_SRC})
set_module_type(ntdll_loadinit_a win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ntdll_loadinit_a kernel32 ntdll)
add_dependencies(ntdll_loadinit_a psdk)
add_rostests_file(TARGET ntdll_loadinit_a)

add_library(ntdll_loadinit_n MODULE loadinit_n.c)
set_module_type(ntdll_loadinit_n win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ntdll_loadinit_n ntdll_loadinit_b kernel32 ntdll)
add_dependencies(ntdll_loadinit_n psdk ntdll_loadinit_b)
add_rostests_file(TARGET ntdll_loadinit_n)

add_library(ntdll_loadinit_p MODULE loadinit_p.c)
set_module_type(ntdll_loadinit_p win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ntdll_loadinit_p ntdll_loadinit_a ntdll_loadinit_b kernel32 ntdll)
add_dependencies(ntdll_loadinit_p psdk ntdll_loadinit_a ntdll_loadinit_b)
add_rostests_file(TARGET ntdll_loadinit_p)
