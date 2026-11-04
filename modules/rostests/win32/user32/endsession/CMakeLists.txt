add_executable(endsession endsession.c)
set_module_type(endsession win32gui)
add_importlibs(endsession user32 msvcrt kernel32)
add_rostests_file(TARGET endsession SUBDIR suppl)
