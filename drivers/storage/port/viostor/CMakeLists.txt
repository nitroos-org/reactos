
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(
    -D_WIN32_WINNT=0x602
    -DNTDDI_VERSION=0x06020000) # NTDDI_WIN8, as storport (PORT_CONFIGURATION_INFORMATION depends on it)

list(APPEND SOURCE
    virtio_pci.c
    virtio_stor.c
    virtio_stor_hw_helper.c
    virtio_stor_utils.c)

add_library(viostor MODULE ${SOURCE} virtio_stor.rc)
target_link_libraries(viostor virtio)
set_module_type(viostor kernelmodedriver)
add_importlibs(viostor storport ntoskrnl hal)

if(NOT MSVC)
    target_compile_options(viostor PRIVATE
        -Wno-unused-function
        -Wno-unknown-pragmas
        -Wno-attributes
        -Wno-pointer-sign
        -Wno-old-style-declaration
        -Wno-unused-but-set-variable
        -Wno-unused-variable)
endif()

add_cd_file(TARGET viostor DESTINATION reactos/system32/drivers NO_CAB FOR all)
add_registry_inf(viostor_reg.inf)
add_driver_inf(viostor viostor.inf)
