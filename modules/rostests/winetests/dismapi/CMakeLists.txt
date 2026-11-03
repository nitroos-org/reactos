add_definitions(-DUSE_WINE_TODOS -D__WINESRC__)

list(APPEND SOURCE
    dismapi.c
    testlist.c)

add_executable(dismapi_winetest ${SOURCE})
set_module_type(dismapi_winetest win32cui)
add_importlibs(dismapi_winetest msvcrt kernel32)
add_rostests_file(TARGET dismapi_winetest)
