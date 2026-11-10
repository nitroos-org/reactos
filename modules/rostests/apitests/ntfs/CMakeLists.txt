
list(APPEND SOURCE
    access.c
    attrs.c
    delete.c
    inherit.c
    notify.c
    recreuse.c
    relopen.c
    reparse.c
    special.c
    streams.c
    util.c
    volume.c)

list(APPEND PCH_SKIP_SOURCE
    testlist.c)

add_executable(ntfs_apitest
    ${SOURCE}
    ${PCH_SKIP_SOURCE})

target_link_libraries(ntfs_apitest wine ${PSEH_LIB})
set_module_type(ntfs_apitest win32cui)
add_importlibs(ntfs_apitest advapi32 netapi32 msvcrt kernel32 ntdll)
add_pch(ntfs_apitest precomp.h "${PCH_SKIP_SOURCE}")
add_rostests_file(TARGET ntfs_apitest)
