add_definitions(
    -DNDIS50_MINIPORT
    -DNDIS_MINIPORT_DRIVER
    -DNDIS_LEGACY_MINIPORT=1)

list(APPEND SOURCE
    vmxnet3.c
    info.c
    vmxnet3.h)

add_library(vmxnet3 MODULE ${SOURCE} vmxnet3.rc)
add_pch(vmxnet3 vmxnet3.h SOURCE)
set_module_type(vmxnet3 kernelmodedriver)
add_importlibs(vmxnet3 ndis ntoskrnl hal)
add_cd_file(TARGET vmxnet3 DESTINATION reactos/system32/drivers FOR all)
add_driver_inf(vmxnet3 netvmxnet3.inf)
