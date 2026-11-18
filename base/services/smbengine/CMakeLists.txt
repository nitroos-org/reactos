# The SMB client engine service: answers the requests of the SMB mini-redirector
# (drivers/filesystems/mrxsmb) with libsmb2.dll. Own process, LocalService, demand start.

# libsmb2.dll's public headers key their Windows definitions on _WINDOWS
add_definitions(-D_WINDOWS)
remove_definitions(-D_WIN32_WINNT=0x502 -DWINVER=0x502)
add_definitions(-D_WIN32_WINNT=0x601 -DWINVER=0x601)

include_directories(
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/include
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/include/smb2
    ${REACTOS_SOURCE_DIR}/dll/3rdparty/libsmb2/nitro)

list(APPEND SOURCE
    smbengine.c
    conn.c
    smbengine.h)

add_executable(smbengine ${SOURCE} smbengine.rc)
set_module_type(smbengine win32cui UNICODE)
add_importlibs(smbengine libsmb2 advapi32 ws2_32 msvcrt kernel32 ntdll)
add_cd_file(TARGET smbengine DESTINATION reactos/system32 FOR all)
add_registry_inf(smbengine_reg.inf)
