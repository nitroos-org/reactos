
list(APPEND SOURCE
    ../include/msgtrace.c
    button.c
    exports.c
    ImageListWriteEx.c
    imagelist.c
    listview.c
    propsheet.c
    propsheet_title.c
    TabInsertSelection.c
    TreeViewCheckState.c
    testlist.c
    toolbar.c
    tooltip.c
    version.c)

add_executable(comctl32_apitest
    ${SOURCE}
    comctl32_apitest.rc)

target_link_libraries(comctl32_apitest wine uuid)
set_module_type(comctl32_apitest win32cui)
add_importlibs(comctl32_apitest uxtheme comctl32 user32 gdi32 ole32 version msvcrt kernel32 ntdll)
add_rostests_file(TARGET comctl32_apitest)
add_rostests_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/comctl32v5.manifest")
