project(appcompat)

add_definitions(
    -DWINETEST_USE_DBGSTR_LONGLONG
    -DUNICODE
    -D_UNICODE)

list(APPEND SOURCE
    apphelp.c
    appcache.c
    data.c
    db.cpp
    env.c
    layerapi.c
    register.cpp
    shimload.c
    testlist.c
    testdata.rc
    testdb.xml)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/testdb.sdb
                   COMMAND native-xml2sdb -i ${CMAKE_CURRENT_SOURCE_DIR}/testdb.xml -o ${CMAKE_CURRENT_BINARY_DIR}/testdb.sdb
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/testdb.xml native-xml2sdb)

add_rc_deps(testdata.rc ${CMAKE_CURRENT_BINARY_DIR}/testdb.sdb)
add_executable(apphelp_apitest ${SOURCE})
set_module_type(apphelp_apitest win32cui)
target_link_libraries(apphelp_apitest ${PSEH_LIB} cpprt atl_classes)
add_importlibs(apphelp_apitest advapi32 userenv version shlwapi msvcrt kernel32 ntdll)
add_dependencies(apphelp_apitest apphelp_shimload_child)
add_rostests_file(TARGET apphelp_apitest)

# Helper for the shimload test: imports the C runtime and little else, like the programs that matter
add_executable(apphelp_shimload_child shimload_child.c)
set_module_type(apphelp_shimload_child win32cui)
add_importlibs(apphelp_shimload_child msvcrt kernel32)
add_rostests_file(TARGET apphelp_shimload_child)
