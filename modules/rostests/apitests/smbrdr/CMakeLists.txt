
# Test engine and mapping tool for the SMB mini-redirector (installed with the tests only)

# libsmb2.dll's public headers key their Windows definitions on _WINDOWS
add_definitions(-D_WINDOWS)
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x601)
include_directories(
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/include
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/include/smb2
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/nitro)

add_executable(smbtestd smbtestd.c)
set_module_type(smbtestd win32cui UNICODE)
add_importlibs(smbtestd libsmb2 advapi32 ws2_32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET smbtestd)

add_executable(smbtool smbtool.c)
set_module_type(smbtool win32cui UNICODE)
add_importlibs(smbtool bcrypt advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET smbtool)

add_executable(smbmap smbmap.c)
set_module_type(smbmap win32cui UNICODE)
add_importlibs(smbmap advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET smbmap)
