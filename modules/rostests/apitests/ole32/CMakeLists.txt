
add_executable(ole32_apitest initializespy.cpp ScmCreatedEvent.c SystemWow64Directory.c testlist.c)
target_link_libraries(ole32_apitest wine uuid cpprt)
set_module_type(ole32_apitest win32cui)
add_importlibs(ole32_apitest user32 gdi32 shell32 ole32 shlwapi advapi32 msvcrt kernel32)
add_rostests_file(TARGET ole32_apitest)
