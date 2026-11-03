add_definitions(-DUSE_WINE_TODOS -D__WINESRC__)

list(APPEND SOURCE
    rstrtmgr.c
    testlist.c)

add_executable(rstrtmgr_winetest ${SOURCE})
set_module_type(rstrtmgr_winetest win32cui)
add_importlibs(rstrtmgr_winetest rstrtmgr user32 msvcrt kernel32)
add_rostests_file(TARGET rstrtmgr_winetest)
