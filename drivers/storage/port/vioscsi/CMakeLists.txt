
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(
    -D_WIN32_WINNT=0x602
    -DNTDDI_VERSION=0x06020000) # NTDDI_WIN8, as storport (PORT_CONFIGURATION_INFORMATION depends on it)

list(APPEND SOURCE
    helper.c
    utils.c
    vioscsi.c
    virtio_pci.c)

add_library(vioscsi MODULE ${SOURCE} vioscsi.rc)
target_link_libraries(vioscsi virtio)
set_module_type(vioscsi kernelmodedriver)
add_importlibs(vioscsi storport ntoskrnl hal)

if(NOT MSVC)
    target_compile_options(vioscsi PRIVATE
        -Wno-unused-function
        -Wno-unknown-pragmas
        -Wno-attributes
        -Wno-pointer-sign
        -Wno-old-style-declaration
        -Wno-unused-but-set-variable
        -Wno-unused-variable)
endif()
