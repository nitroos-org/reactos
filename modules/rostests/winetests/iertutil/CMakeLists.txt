
add_definitions(-DUSE_WINE_TODOS)
include_directories(BEFORE ${REACTOS_SOURCE_DIR}/sdk/include/wine)

list(APPEND SOURCE
    iertutil.c)

add_executable(iertutil_winetest ${SOURCE})
target_link_libraries(iertutil_winetest uuid winetestlib)
set_module_type(iertutil_winetest win32cui)
add_importlibs(iertutil_winetest combase user32 advapi32 msvcrt kernel32 ntdll)
add_dependencies(iertutil_winetest psdk)
add_rostests_file(TARGET iertutil_winetest)
