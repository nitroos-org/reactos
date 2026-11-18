
spec2def(fwpuclnt.dll fwpuclnt.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    fwpuclnt.c
    ${CMAKE_CURRENT_BINARY_DIR}/fwpuclnt_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/fwpuclnt.def)

add_library(fwpuclnt MODULE ${SOURCE})
set_module_type(fwpuclnt win32dll UNICODE ENTRYPOINT DllMain 12)
add_importlibs(fwpuclnt advapi32 msvcrt kernel32 ntdll)
add_dependencies(fwpuclnt psdk)
add_cd_file(TARGET fwpuclnt DESTINATION reactos/system32 FOR all)
