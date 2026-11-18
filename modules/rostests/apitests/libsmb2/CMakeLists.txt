# libsmb2.dll's public headers key their Windows definitions on _WINDOWS
add_definitions(-D_WINDOWS)
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x601)
include_directories(
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/include
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/include/smb2
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/nitro)

# smbcli: the test client for the SMB interop matrix (installed with the tests only)
add_executable(smbcli smbcli.c)
set_module_type(smbcli win32cui)
add_importlibs(smbcli libsmb2 bcrypt psapi advapi32 ws2_32 msvcrt kernel32)
add_rostests_file(TARGET smbcli)
