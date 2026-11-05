
add_executable(sesstest sesstest.c)
set_module_type(sesstest nativecui)
target_link_libraries(sesstest nt)
add_importlibs(sesstest ntdll)
add_rostests_file(TARGET sesstest)
