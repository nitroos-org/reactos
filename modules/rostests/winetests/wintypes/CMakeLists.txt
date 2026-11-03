
add_definitions(-DUSE_WINE_TODOS -D__WINESRC__)

list(APPEND SOURCE
    wintypes.c
    testlist.c)

add_executable(wintypes_winetest ${SOURCE})
set_module_type(wintypes_winetest win32cui)
add_importlibs(wintypes_winetest combase msvcrt kernel32)
add_rostests_file(TARGET wintypes_winetest)
