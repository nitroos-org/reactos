
list(APPEND SOURCE
    mrxsmb.c
    upcall.c
    mrxsmb.h)

add_definitions(-DRDBSS_TRACKER)

add_library(mrxsmb MODULE ${SOURCE} mrxsmb.rc)
set_module_type(mrxsmb kernelmodedriver)
target_link_libraries(mrxsmb ntoskrnl_vista rdbsslib rxce copysup memcmp wdmsec ${PSEH_LIB})
add_importlibs(mrxsmb ntoskrnl hal)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    target_compile_options(mrxsmb PRIVATE "-Wno-switch")
endif()

add_cd_file(TARGET mrxsmb DESTINATION reactos/system32/drivers FOR all)
add_registry_inf(mrxsmb_reg.inf)
