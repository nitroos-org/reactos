
list(APPEND SOURCE
    check/boot.c
    check/charconv.c
    check/check.c
    check/common.c
    check/fat.c
    check/file.c
    check/io.c
    check/lfn.c
    common.c
    extend.c
    fat12.c
    fat16.c
    fat32.c
    vfatlib.c
    vfatlib.h)

# Plain C without system headers (also built by a host test): no precompiled header.
list(APPEND PCH_SKIP_SOURCE
    fatgrow.c)

add_library(vfatlib ${SOURCE} ${PCH_SKIP_SOURCE})
add_dependencies(vfatlib xdk)
add_pch(vfatlib vfatlib.h SOURCE)
