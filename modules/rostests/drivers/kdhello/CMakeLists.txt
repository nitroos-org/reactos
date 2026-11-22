
# A minimal WDM driver to practise kernel debugging on, and its user-mode trigger
add_library(kdhello MODULE kdhello.c)
set_module_type(kdhello kernelmodedriver)
add_importlibs(kdhello ntoskrnl)
add_rostests_file(TARGET kdhello)

add_executable(kdhellotest kdhellotest.c)
set_module_type(kdhellotest win32cui)
add_importlibs(kdhellotest msvcrt kernel32)
add_rostests_file(TARGET kdhellotest)
