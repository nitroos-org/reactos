
list(APPEND SOURCE
    Cards.c
    NoService.c
    testlist.c)

add_executable(winscard_apitest ${SOURCE})
target_link_libraries(winscard_apitest wine)
set_module_type(winscard_apitest win32cui)
add_importlibs(winscard_apitest winscard msvcrt kernel32)
add_rostests_file(TARGET winscard_apitest)
