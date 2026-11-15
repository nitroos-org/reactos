
add_executable(pathping pathping.c pathping.rc)
set_module_type(pathping win32cui UNICODE)
target_link_libraries(pathping conutils)
add_importlibs(pathping ws2_32 iphlpapi msvcrt kernel32)
add_cd_file(TARGET pathping DESTINATION reactos/system32 FOR all)
