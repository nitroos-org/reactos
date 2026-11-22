
add_library(pvscsi MODULE pvscsi.c pvscsi.rc)
set_module_type(pvscsi kernelmodedriver)
add_importlibs(pvscsi scsiport ntoskrnl hal)
add_cd_file(TARGET pvscsi DESTINATION reactos/system32/drivers NO_CAB FOR all)
add_registry_inf(pvscsi_reg.inf)
