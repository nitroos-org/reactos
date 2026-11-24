
add_definitions(-DUNICODE -D_UNICODE)

if(ARCH STREQUAL "amd64")
    # The entry of the helper saves xmm0-xmm3 for the stubs that do not (dlltool of binutils 2.36)
    add_asm_files(delayimp_asm amd64/delayload_asm.S)
endif()

add_library(delayimp
    delayimp.c
    pfnDliFailureHook2.c
    pfnDliNotifyHook2.c
    ${delayimp_asm}
)
add_dependencies(delayimp psdk)
add_importlibs(delayimp kernel32)
