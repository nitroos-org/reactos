
add_executable(mscms_apitest WcsDefault.c testlist.c)
target_link_libraries(mscms_apitest wine)
set_module_type(mscms_apitest win32cui)
add_importlibs(mscms_apitest msvcrt kernel32)
add_rostests_file(TARGET mscms_apitest)
