
add_executable(psapi_apitest EnumProcessModulesEx.c ListGrowth.c psapi.c QueryWorkingSet.c testlist.c)
set_module_type(psapi_apitest win32cui)
target_link_libraries(psapi_apitest ${PSEH_LIB})
add_importlibs(psapi_apitest psapi msvcrt kernel32 ntdll)
add_rostests_file(TARGET psapi_apitest)
