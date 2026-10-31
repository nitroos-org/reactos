
add_executable(msi_apitest RefusedPackageLog.c Wow64Folders.c testlist.c)
set_module_type(msi_apitest win32cui)
add_importlibs(msi_apitest msi msvcrt kernel32)
add_rostests_file(TARGET msi_apitest)
