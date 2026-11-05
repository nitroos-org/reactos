
list(APPEND SOURCE
    advpack.c
    files.c
    install.c
    testlist.c)

spec2def(selfreg.dll selfreg.spec)

add_library(advpack_selfreg MODULE selfreg.c ${CMAKE_CURRENT_BINARY_DIR}/selfreg.def)
set_module_type(advpack_selfreg win32dll IMAGEBASE default)
add_importlibs(advpack_selfreg advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET advpack_selfreg)
set_source_files_properties(advpack.rc PROPERTIES OBJECT_DEPENDS advpack_selfreg)

add_executable(advpack_winetest ${SOURCE} advpack.rc)

target_compile_definitions(advpack_winetest PRIVATE USE_WINE_TODOS)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(advpack_winetest PRIVATE -Wno-format-overflow)
endif()

set_module_type(advpack_winetest win32cui)
add_importlibs(advpack_winetest advpack cabinet advapi32 user32 msvcrt kernel32)
add_rostests_file(TARGET advpack_winetest)
