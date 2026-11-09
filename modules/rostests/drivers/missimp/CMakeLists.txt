
add_library(missimp MODULE missimp.c)
set_module_type(missimp kernelmodedriver)
add_importlibs(missimp ntoskrnl)
add_rostests_file(TARGET missimp)
