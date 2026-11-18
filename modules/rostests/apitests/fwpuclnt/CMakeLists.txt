list(APPEND SOURCE
    fwpuclnt.c
    testlist.c)

add_executable(fwpuclnt_apitest ${SOURCE})
set_module_type(fwpuclnt_apitest win32cui)
add_importlibs(fwpuclnt_apitest fwpuclnt advapi32 msvcrt kernel32)
add_dependencies(fwpuclnt_apitest fwpuclnt)
add_rostests_file(TARGET fwpuclnt_apitest)
