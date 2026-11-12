
# Little CMS 2 (MIT), the copy Wine bundles in libs/lcms2; see README.ReactOS
list(APPEND SOURCE
    src/cmsalpha.c
    src/cmscnvrt.c
    src/cmserr.c
    src/cmsgamma.c
    src/cmsgmt.c
    src/cmshalf.c
    src/cmsintrp.c
    src/cmsio0.c
    src/cmsio1.c
    src/cmslut.c
    src/cmsmtrx.c
    src/cmsnamed.c
    src/cmsopt.c
    src/cmspack.c
    src/cmspcs.c
    src/cmsplugin.c
    src/cmssamp.c
    src/cmstypes.c
    src/cmsvirt.c
    src/cmswtpnt.c
    src/cmsxform.c)

add_library(lcms2 STATIC ${SOURCE})
target_include_directories(lcms2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_dependencies(lcms2 psdk)
