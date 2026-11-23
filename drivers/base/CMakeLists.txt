
add_subdirectory(beep)
add_subdirectory(bootvid)
add_subdirectory(condrv)

if(_WINKD_)
    add_subdirectory(kdcom)
    if(ARCH STREQUAL "i386" OR ARCH STREQUAL "amd64")
        add_subdirectory(kdgdb)
        add_subdirectory(kdvm)
    endif()
else()
    add_subdirectory(kdrosdbg)
    if(KDKIT)
        # The real transport of the kernel debugging kit, in place of the stub on the media
        add_subdirectory(kdcom)
    endif()
endif()
add_subdirectory(kdstub)

add_subdirectory(null)
