
if(_WINKD_)
    set(KDCOM_TARGET kdcom)
    spec2def(kdcom.dll kdcom.spec ADD_IMPORTLIB)
else()
    # The kernel debugging kit: the stub (kdrosdbg) is the kdcom that the default kernel is linked against, this is
    # the real one, put on the media as kdcom.dll in its place
    set(KDCOM_TARGET kdcomkit)
    spec2def(kdcom.dll kdcom.spec)
endif()

list(APPEND SOURCE
    kdcom.c
    kddll.c
    kdserial.c
    kddll.h)

add_library(${KDCOM_TARGET} MODULE
    ${SOURCE}
    kdcom.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kdcom.def)
add_pch(${KDCOM_TARGET} kddll.h SOURCE)

set_module_type(${KDCOM_TARGET} kerneldll ENTRYPOINT 0)
set_subsystem(${KDCOM_TARGET} native)
add_importlibs(${KDCOM_TARGET} ntoskrnl hal)
target_link_libraries(${KDCOM_TARGET} cportlib strtol)
add_dependencies(${KDCOM_TARGET} psdk bugcodes)
if(GDB) ## See PR #5187
    set(KDCOM_NAME_ON_CD kdser.dll)
elseif(_WINKD_)
    set(KDCOM_NAME_ON_CD "$<TARGET_FILE_NAME:kdcom>")
else()
    set(KDCOM_NAME_ON_CD kdcom.dll)
endif()
add_cd_file(TARGET ${KDCOM_TARGET} DESTINATION reactos/system32 NO_CAB NAME_ON_CD ${KDCOM_NAME_ON_CD} FOR all)
