
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(
    -D_WIN32_WINNT=0x602
    -DNTDDI_VERSION=0x06020000) # NTDDI_WIN8, as storport

add_library(storest MODULE storest.c)
set_module_type(storest kernelmodedriver)
add_importlibs(storest storport ntoskrnl hal)
add_rostests_file(TARGET storest)
