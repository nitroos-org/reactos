
add_executable(mountvol mountvol.c mountvol.rc)
set_module_type(mountvol win32cui UNICODE)
target_link_libraries(mountvol conutils)
add_importlibs(mountvol msvcrt kernel32)
add_cd_file(TARGET mountvol DESTINATION reactos/system32 FOR all)
