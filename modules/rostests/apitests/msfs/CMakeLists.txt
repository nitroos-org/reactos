
list(APPEND SOURCE
    SetMailslotInformation.c)

add_executable(msfs_apitest ${SOURCE})
set_module_type(msfs_apitest win32cui)
target_link_libraries(msfs_apitest winetestlib)
add_importlibs(msfs_apitest msvcrt kernel32 ntdll)

add_rostests_file(TARGET msfs_apitest)

add_executable(msfs_access_apitest MailslotAccess.c)
set_module_type(msfs_access_apitest win32cui)
target_link_libraries(msfs_access_apitest winetestlib)
add_importlibs(msfs_access_apitest msvcrt advapi32 kernel32)
add_rostests_file(TARGET msfs_access_apitest)
