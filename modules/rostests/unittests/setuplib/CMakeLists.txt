
PROJECT(setuplib_unittest)

include_directories(${REACTOS_SOURCE_DIR}/modules/rostests/apitests/include)
if(KDKIT)
    # as the library is built (base/setup/lib)
    add_definitions(-DNITRO_KDKIT)
endif()

list(APPEND SOURCE
    BootEntryIdentity.c
    ComponentsList.c
    FreeLdrIniUpdate.c
    GptLayout.c
    IsValidInstallDirectory.c
    KeylessEntries.c
    UnattendParse.c
    testlist.c
    precomp.h)

add_executable(setuplib_unittest ${SOURCE})
#add_pch(setuplib_unittest precomp.h SOURCE)
# bootsup.c (FreeLdrIniUpdate) brings in the file system code of the library
target_link_libraries(setuplib_unittest setuplib_static ntfslib ext2lib vfatlib btrfslib ${PSEH_LIB})
set_module_type(setuplib_unittest win32cui)
add_importlibs(setuplib_unittest msvcrt kernel32 ntdll)
add_rostests_file(TARGET setuplib_unittest)
