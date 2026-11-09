add_executable(pagercommit pagercommit.c)
set_module_type(pagercommit win32cui)
add_importlibs(pagercommit advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET pagercommit)
