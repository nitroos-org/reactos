
include_directories(${REACTOS_SOURCE_DIR}/base/services/dhcpcsvc/include)

add_executable(dhcpcsvc_apitest AdapterName.c testlist.c)
set_module_type(dhcpcsvc_apitest win32cui)
target_link_libraries(dhcpcsvc_apitest ${PSEH_LIB})
add_importlibs(dhcpcsvc_apitest msvcrt kernel32)
add_rostests_file(TARGET dhcpcsvc_apitest)
