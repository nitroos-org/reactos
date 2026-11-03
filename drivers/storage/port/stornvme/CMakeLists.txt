
list(APPEND SOURCE
    scsi.c
    stornvme.c)

add_library(stornvme MODULE ${SOURCE} stornvme.rc)
set_module_type(stornvme kernelmodedriver)
add_importlibs(stornvme storport ntoskrnl hal)
add_cd_file(TARGET stornvme DESTINATION reactos/system32/drivers NO_CAB FOR all)
add_registry_inf(stornvme_reg.inf)
add_driver_inf(stornvme stornvme.inf)
