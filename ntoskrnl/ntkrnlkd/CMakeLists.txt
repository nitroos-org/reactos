# The kernel of the kernel debugging kit: the multiprocessor kernel with the Windows KD protocol (_WINKD_) in place
# of the built-in KdTerm text debugging. The same sources as ntkrnlmp, compiled with -D_WINKD_, without the
# sources of the text debugger (ntoskrnl/kd), and importing the transport from kdcom.dll. Boot it with
# /KERNEL=ntkrnlkd.exe /DEBUG /DEBUGPORT=COM1 (see base/setup/lib/bootsup.c).
set(_WINKD_ TRUE)
include(../ntos.cmake)

include_directories(${REACTOS_SOURCE_DIR}/ntoskrnl)
spec2def(ntkrnlkd.exe ../ntoskrnl.spec)

set(NTKRNLKD_SOURCE ${NTKRNLMP_SOURCE})
set(NTKRNLKD_ASM_SOURCE ${NTKRNLMP_ASM_SOURCE})
list(FILTER NTKRNLKD_SOURCE EXCLUDE REGEX "/ntoskrnl/kd/")

if(ARCH STREQUAL "i386")
    list(APPEND NTKRNLKD_SOURCE
        ${REACTOS_SOURCE_DIR}/ntoskrnl/ke/i386/mproc.c)
elseif(ARCH STREQUAL "amd64")
    list(APPEND NTKRNLKD_SOURCE
        ${REACTOS_SOURCE_DIR}/ntoskrnl/ke/amd64/mproc.c)
endif()

list(APPEND NTKRNLKD_PCH_SKIP_SOURCE
    ${REACTOS_SOURCE_DIR}/ntoskrnl/guid.c)

add_asm_files(ntkrnlkd_asm ${NTKRNLKD_ASM_SOURCE})

add_executable(ntkrnlkd
    ${ntkrnlkd_asm}
    ${NTKRNLKD_SOURCE}
    ${NTKRNLKD_PCH_SKIP_SOURCE}
    ${REACTOS_SOURCE_DIR}/ntoskrnl/ntoskrnl.rc
    ${CMAKE_CURRENT_BINARY_DIR}/ntkrnlkd.def)
set_module_type(ntkrnlkd kernel)
add_message_rc_deps(${REACTOS_SOURCE_DIR}/ntoskrnl/ntoskrnl.rc bugcodes)
target_compile_definitions(ntkrnlkd PRIVATE CONFIG_SMP)

if(STACK_PROTECTOR)
    target_link_libraries(ntkrnlkd gcc_ssp_nt)
endif()

# No ROSSYM_LIB: it belongs to KDBG
target_link_libraries(ntkrnlkd ntoskrnl_vista cportlib csq ${PSEH_LIB} arbiter cmlib ntlsalib rtl rtl_vista libcntpr setjmp wdmguid poguid ioevent sdbread_km)
add_importlibs(ntkrnlkd hal kdcom bootvid)
add_pch(ntkrnlkd ${REACTOS_SOURCE_DIR}/ntoskrnl/include/ntoskrnl.h "${NTKRNLKD_PCH_SKIP_SOURCE}")
add_dependencies(ntkrnlkd psdk asm)

# In the cabinet (installed to system32 with the other files), not on the media on its own: nothing in txtsetup.sif
add_cd_file(TARGET ntkrnlkd DESTINATION reactos/system32 FOR all)
