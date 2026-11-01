
add_subdirectory(kernel32_vista)

add_definitions(-D_KERNEL32_)
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/subsys)
set(kernel32_spec kernel32.spec)
if(BUILD_WOW64_ENABLED OR SYSWOW64_GUEST)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/kernel32.spec")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/kernel32.spec" wow64_kernel32_spec)
    foreach(function Wow64GetThreadContext Wow64SetThreadContext)
        string(REPLACE "@ stub -version=0x600+ -arch=i386,arm ${function}" "@ stdcall -version=0x600+ -arch=i386,arm ${function}(ptr ptr)" wow64_kernel32_spec "${wow64_kernel32_spec}")
    endforeach()
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/kernel32-wow64.spec" "${wow64_kernel32_spec}")
    file(RELATIVE_PATH kernel32_spec "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/kernel32-wow64.spec")
endif()
# A name that more than one active spec line exports ends up twice in kernel32.def. Reject it here: the lines that
# spec2def would drop for this DLL_EXPORT_VERSION and architecture (-version=, -arch=, -i386) do not count, so the version
# and architecture variants of one name stay legal.
if(ARCH STREQUAL "amd64")
    set(_kernel32_arch "x86_64")
else()
    set(_kernel32_arch "${ARCH}")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/kernel32.spec")
math(EXPR _kernel32_version "${DLL_EXPORT_VERSION}")
file(STRINGS kernel32.spec _kernel32_spec_lines REGEX "^@ ")
set(_kernel32_seen)
foreach(_line IN LISTS _kernel32_spec_lines)
    if(NOT _line MATCHES "^@ [a-z]+ (-[^ ]+ )*([A-Za-z0-9_@?$]+)([ (]|$)")
        continue()
    endif()
    set(_name ${CMAKE_MATCH_2})
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*-version=(0x[0-9a-fA-F]+)\\+")
        math(EXPR _min "${CMAKE_MATCH_2}")
        set(_max 0xFFF)
    elseif(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*-version=(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+)")
        math(EXPR _min "${CMAKE_MATCH_2}")
        set(_max ${CMAKE_MATCH_3})
    else()
        set(_min 0)
        set(_max 0xFFFFFFFF)
    endif()
    math(EXPR _max "${_max}")
    if(_kernel32_version LESS _min OR _kernel32_version GREATER _max)
        continue()
    endif()
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*-i386( |$)" AND NOT _kernel32_arch STREQUAL "i386")
        continue()
    endif()
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*-arch=([A-Za-z0-9_,!]+)")
        string(REPLACE "," ";" _archs "${CMAKE_MATCH_2}")
        set(_arch_ok FALSE)
        foreach(_a IN LISTS _archs)
            if(_a MATCHES "^!(.+)$")
                if(NOT CMAKE_MATCH_1 STREQUAL _kernel32_arch)
                    set(_arch_ok TRUE)
                endif()
            elseif(_a STREQUAL _kernel32_arch)
                set(_arch_ok TRUE)
            endif()
        endforeach()
        if(NOT _arch_ok)
            continue()
        endif()
    endif()
    list(FIND _kernel32_seen ${_name} _idx)
    if(NOT _idx EQUAL -1)
        message(FATAL_ERROR "kernel32.spec: ${_name} is exported twice at export version ${DLL_EXPORT_VERSION} (${_kernel32_arch}): '${_line}'")
    endif()
    list(APPEND _kernel32_seen ${_name})
endforeach()

spec2def(kernel32.dll ${kernel32_spec} ADD_IMPORTLIB)

# Shared between kernel32 and kernel32_vista
add_library(kernel32_shared
    client/shared_utils.c
    client/file/fileutils.c
)
target_link_libraries(kernel32_shared PRIVATE pseh)
add_dependencies(kernel32_shared psdk)

list(APPEND SOURCE
    winnls/string/idn.c
    winnls/string/IdnToAscii.c
    winnls/string/IdnToUnicode.c
    winnls/string/normalize.c
    winnls/string/normdata.c
    client/actctx.c
    client/appcache.c
    client/atom.c
    client/appmodel.c
    client/acnamedobj.c
    client/capsid.c
    client/atomansi.c
    client/compname.c
    client/debugger.c
    client/dep.c
    client/dosdev.c
    client/dllmain.c
    client/environ.c
    client/except.c
    client/fiber.c
    client/handle.c
    client/heapmem.c
    client/job.c
    client/loader.c
    client/mitigation.c
    client/path.c
    client/pathansi.c
    client/perfcnt.c
    client/power.c
    client/privnamespace.c
    client/proc.c
    client/pseudoconsole.c
    client/procinfo.c
    client/procansi.c
    client/pss.c
    client/resntfy.c
    client/session.c
    client/synch.c
    client/synchansi.c
    client/sysinfo.c
    client/sysinfoansi.c
    client/time.c
    client/timerqueue.c
    client/toolhelp.c
    client/utils.c
    client/thread.c
    client/vdm.c
    client/version.c
    client/versionansi.c
    client/virtmem.c
    client/console/alias.c
    client/console/console.c
    client/console/history.c
    client/console/init.c
    client/console/readwrite.c
    client/file/backup.c
    client/file/cnotify.c
    client/file/copy.c
    client/file/copy2.c
    client/file/copyansi.c
    client/file/create.c
    client/file/delete.c
    client/file/deviceio.c
    client/file/dir.c
    client/file/diransi.c
    client/file/disk.c
    client/file/fileinfo.c
    client/file/fileinfoansi.c
    client/file/filemap.c
    client/file/filename.c
    client/file/find.c
    client/file/hardlink.c
    client/file/iocompl.c
    client/file/lfile.c
    client/file/lock.c
    client/file/mailslot.c
    client/file/move.c
    client/file/moveansi.c
    client/file/mntpoint.c
    client/file/mntpointansi.c
    client/file/npipe.c
    client/file/rw.c
    client/file/tape.c
    client/file/volume.c
    client/file/volume_by_handle.c
    client/file/volumeansi.c
    wine/actctx.c
    wine/comm.c
    wine/lzexpand.c
    wine/muldiv.c
    wine/profile.c
    wine/res.c
    wine/timezone.c
    winnls/string/calendar_data.c
    winnls/string/casemap.c
    winnls/string/collation.c
    winnls/string/digitmap.c
    winnls/string/fold.c
    winnls/string/format_msg.c
    winnls/string/japanese.c
    winnls/string/locale.c
    winnls/string/localeansi.c
    winnls/string/lcformat.c
    winnls/string/lcformatansi.c
    winnls/string/lstring.c
    winnls/string/nls.c
    winnls/string/sortkey.c
    k32.h)

if(MSVC)
    # Disable warning C4146: unary minus operator applied to unsigned type, result still unsigned
    set_source_files_properties(wine/res.c PROPERTIES COMPILE_OPTIONS "/wd4146")

    # Disable warning C4267: 'initializing': conversion from 'size_t' to 'DWORD', possible loss of data
    set_source_files_properties(winnls/string/locale.c PROPERTIES COMPILE_OPTIONS "/wd4267")
else()
    # Disable warning: 'variable' defined but not used
    set_source_files_properties(winnls/string/locale.c PROPERTIES COMPILE_OPTIONS "-Wno-unused-variable")
endif()

if(ARCH STREQUAL "i386")
    list(APPEND ASM_SOURCE
        client/i386/fiber.S
        client/i386/thread.S)
elseif(ARCH STREQUAL "amd64")
    list(APPEND ASM_SOURCE
        client/amd64/fiber.S)
elseif(ARCH STREQUAL "arm")
    list(APPEND ASM_SOURCE
        client/arm/fiber.S
        client/arm/thread.S)
endif()

add_asm_files(kernel32_asm ${ASM_SOURCE})
add_library(kernel32 MODULE
    ${SOURCE}
    ${kernel32_asm}
    kernel32.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kernel32_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/kernel32.def)

set_module_type(kernel32 win32dll ENTRYPOINT DllMain 12)
#############################################
## HACK FOR MSVC COMPILATION WITH win32dll ##
set_subsystem(kernel32 console)
################# END  HACK #################

target_link_libraries(kernel32 psapi_static kernel32_vista_static kernel32_shared wine chkstk ${PSEH_LIB})
add_importlibs(kernel32 ntdll)
add_pch(kernel32 k32.h SOURCE)
add_dependencies(kernel32 psdk errcodes asm)
add_cd_file(TARGET kernel32 DESTINATION reactos/system32 FOR all)
