# The dependency: copies of it in several directories show which of them a load used.
spec2def(ll_search_dep.dll ll_search_dep.spec ADD_IMPORTLIB)

list(APPEND DEP_SRC
    dep.c
    ${CMAKE_CURRENT_BINARY_DIR}/ll_search_dep_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/ll_search_dep.def)

add_library(ll_search_dep MODULE ${DEP_SRC})
set_module_type(ll_search_dep win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ll_search_dep kernel32 ntdll)
add_dependencies(ll_search_dep psdk)
add_rostests_file(TARGET ll_search_dep)

# The library that imports it.
spec2def(ll_search_lib.dll ll_search_lib.spec ADD_IMPORTLIB)

list(APPEND LIB_SRC
    lib.c
    ${CMAKE_CURRENT_BINARY_DIR}/ll_search_lib_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/ll_search_lib.def)

add_library(ll_search_lib MODULE ${LIB_SRC})
set_module_type(ll_search_lib win32dll ENTRYPOINT DllMain 12 IMAGEBASE default)
add_importlibs(ll_search_lib ll_search_dep kernel32 ntdll)
add_dependencies(ll_search_lib psdk)
add_rostests_file(TARGET ll_search_lib)
