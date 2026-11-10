
# Two copies of one DLL: the first above 4 GB on amd64, the second at the address its low 32 bits make
if(ARCH STREQUAL "amd64")
    set(WEVHOOK_BASE1 0x0000000220000000)
    set(WEVHOOK_BASE2 0x0000000020000000)
else()
    set(WEVHOOK_BASE1 0x6A000000)
    set(WEVHOOK_BASE2 0x6B000000)
endif()

foreach(N 1 2)
    spec2def(user32_wevhook${N}.dll wevhook.spec)
    add_library(user32_wevhook${N} MODULE
        wevhook.c
        ${CMAKE_CURRENT_BINARY_DIR}/user32_wevhook${N}_stubs.c
        ${CMAKE_CURRENT_BINARY_DIR}/user32_wevhook${N}.def)
    set_module_type(user32_wevhook${N} win32dll IMAGEBASE ${WEVHOOK_BASE${N}})
    add_importlibs(user32_wevhook${N} user32 msvcrt kernel32)
    add_rostests_file(TARGET user32_wevhook${N})
endforeach()

# The same hook procedure, logging the processes that load the DLL (WinEventInContext)
spec2def(user32_wevhooklog.dll wevhook.spec)
add_library(user32_wevhooklog MODULE
    wevhooklog.c
    ${CMAKE_CURRENT_BINARY_DIR}/user32_wevhooklog_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/user32_wevhooklog.def)
set_module_type(user32_wevhooklog win32dll)
add_importlibs(user32_wevhooklog user32 msvcrt kernel32)
add_rostests_file(TARGET user32_wevhooklog)
