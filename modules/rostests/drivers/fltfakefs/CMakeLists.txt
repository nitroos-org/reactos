
add_library(fltfakefs MODULE fltfakefs.c)
set_module_type(fltfakefs kernelmodedriver)
add_importlibs(fltfakefs ntoskrnl hal)
add_rostests_file(TARGET fltfakefs)
