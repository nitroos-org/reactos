
add_library(intexstub MODULE intexstub.c)
set_module_type(intexstub kernelmodedriver)
add_importlibs(intexstub ntoskrnl)
add_rostests_file(TARGET intexstub)
add_rostests_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/intexstub.inf)
