
# SysWOW64: the i386 user-mode files on an amd64 image.
#
# An amd64 build with SYSWOW64 enabled configures and builds a second, nested
# i386 build of the same source tree (an ExternalProject, like host-tools) in
# "guest" mode. The guest build records every file it would install, and builds
# only the ones listed in boot/bootdata/packages/syswow64.lst. The amd64 build
# then stages these files (sdk/cmake/syswow64_stage.cmake) into reactos.cab and
# the LiveCD/BootCD file lists, under %SystemRoot%\SysWOW64 and the x86
# side-by-side assembly directories.

set(SYSWOW64_LIST ${REACTOS_SOURCE_DIR}/boot/bootdata/packages/syswow64.lst)

# ---------------------------------------------------------------------------
# Guest side (the nested i386 build)
# ---------------------------------------------------------------------------

# Maps an i386 installation directory to its amd64 directory relative to
# %SystemRoot%, or to "" when the directory is never part of SysWOW64.
function(syswow64_map_destination _dest _out)
    if(_dest STREQUAL "reactos/system32" OR _dest STREQUAL "reactos")
        set(${_out} "SysWOW64" PARENT_SCOPE)
    elseif(_dest MATCHES "^reactos/system32/(.+)$")
        set(${_out} "SysWOW64/${CMAKE_MATCH_1}" PARENT_SCOPE)
    elseif(_dest MATCHES "^reactos/(winsxs/(x86_.+|manifests))$")
        set(${_out} "${CMAKE_MATCH_1}" PARENT_SCOPE)
    elseif(_dest STREQUAL "reactos/Microsoft.NET/Framework/v4.0.30319")
        # wminet_utils.dll for 32-bit System.Management (InstallRoot of the Wow6432Node view)
        set(${_out} "Microsoft.NET/Framework/v4.0.30319" PARENT_SCOPE)
    else()
        set(${_out} "" PARENT_SCOPE)
    endif()
endfunction()

function(syswow64_guest_begin)
    if(NOT ARCH STREQUAL "i386")
        message(FATAL_ERROR "SYSWOW64_GUEST requires ARCH=i386")
    endif()
    add_definitions(-DSYSWOW64_GUEST)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${SYSWOW64_LIST}")
    file(STRINGS ${SYSWOW64_LIST} _lines REGEX "^[^#]")
    set(_wanted "")
    foreach(_line ${_lines})
        string(STRIP "${_line}" _line)
        # "@0x600 <file>" is only part of the list at that export level and later
        if(_line MATCHES "^@(0x[0-9A-Fa-f]+)[ \t]+(.+)$")
            if(DLL_EXPORT_VERSION LESS ${CMAKE_MATCH_1})
                continue()
            endif()
            set(_line "${CMAKE_MATCH_2}")
        endif()
        string(TOLOWER "${_line}" _line)
        list(APPEND _wanted "${_line}")
    endforeach()
    set_property(GLOBAL PROPERTY SYSWOW64_WANTED "${_wanted}")
    file(WRITE ${REACTOS_BINARY_DIR}/syswow64-guest.cmake.lst "")
    add_custom_target(syswow64_guest)
endfunction()

# Called by add_cd_file() in the guest build.
function(syswow64_guest_add_cd_file _target _files _dest _name_on_cd _for)
    if(NOT (("all" IN_LIST _for) OR ("bootcd" IN_LIST _for)))
        return()
    endif()
    syswow64_map_destination("${_dest}" _wowdest)
    if(NOT _wowdest)
        return()
    endif()
    get_property(_wanted GLOBAL PROPERTY SYSWOW64_WANTED)

    if(_files)
        set(_items ${_files})
    else()
        set(_items "$<TARGET_FILE:${_target}>")
    endif()
    set(_recorded FALSE)
    foreach(_item ${_items})
        # The name as installed. A target's file name is only known at
        # generation time: derive the expected name to filter here, and record
        # the real one, which the staging step matches against the list again.
        if(_name_on_cd)
            set(_name ${_name_on_cd})
            set(_real_name ${_name_on_cd})
        elseif(_files)
            get_filename_component(_name "${_item}" NAME)
            set(_real_name ${_name})
        else()
            get_target_property(_name ${_target} OUTPUT_NAME)
            if(NOT _name)
                set(_name ${_target})
            endif()
            get_target_property(_suffix ${_target} SUFFIX)
            # An explicitly empty suffix is meaningful (stdole2.tlb).
            if(_suffix STREQUAL "_suffix-NOTFOUND")
                get_target_property(_type ${_target} TYPE)
                if(_type STREQUAL "EXECUTABLE")
                    set(_suffix ".exe")
                else()
                    set(_suffix ".dll")
                endif()
            endif()
            set(_name "${_name}${_suffix}")
            set(_real_name "$<TARGET_FILE_NAME:${_target}>")
        endif()
        string(TOLOWER "${_wowdest}/${_name}" _key)
        if(_key IN_LIST _wanted)
            file(APPEND ${REACTOS_BINARY_DIR}/syswow64-guest.cmake.lst "${_wowdest}|${_real_name}|${_item}\n")
            set(_recorded TRUE)
        endif()
    endforeach()
    if(_recorded AND _target)
        add_dependencies(syswow64_guest ${_target})
    endif()
endfunction()

function(syswow64_guest_end)
    file(GENERATE
         OUTPUT ${REACTOS_BINARY_DIR}/syswow64-guest.$<CONFIG>.lst
         INPUT ${REACTOS_BINARY_DIR}/syswow64-guest.cmake.lst)
endfunction()

# ---------------------------------------------------------------------------
# Host side (the amd64 build)
# ---------------------------------------------------------------------------

function(setup_syswow64)
    include(ExternalProject)

    add_custom_target(syswow64_incremental_test
        COMMAND ${CMAKE_COMMAND}
            -DMODULE=${REACTOS_SOURCE_DIR}/sdk/cmake/syswow64.cmake
            -DSTAGE=${REACTOS_SOURCE_DIR}/sdk/cmake/syswow64_stage.cmake
            -DWORK=${REACTOS_BINARY_DIR}/syswow64-incremental-test
            -P ${REACTOS_SOURCE_DIR}/sdk/cmake/tests/syswow64_incremental.cmake
        VERBATIM)

    if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR "SYSWOW64 is only supported with the GCC toolchain; configure with -DSYSWOW64=OFF")
    endif()

    # RosBE keeps the i386 compilers next to the amd64 ones, outside the PATH
    # of an amd64 shell.
    get_filename_component(_cc_dir ${CMAKE_C_COMPILER} DIRECTORY)
    find_program(SYSWOW64_I386_GCC i686-w64-mingw32-gcc
                 HINTS ${_cc_dir}/../../i386/bin ${_cc_dir})
    if(NOT SYSWOW64_I386_GCC)
        message(FATAL_ERROR "SYSWOW64: i686-w64-mingw32-gcc not found (set SYSWOW64_I386_GCC, or configure with -DSYSWOW64=OFF)")
    endif()
    string(REGEX REPLACE "gcc$" "" _i386_prefix ${SYSWOW64_I386_GCC})
    message("-- SysWOW64: i386 guest build with ${_i386_prefix}gcc")

    set(_args
        -DARCH:STRING=i386
        -DCMAKE_TOOLCHAIN_FILE:FILEPATH=${REACTOS_SOURCE_DIR}/toolchain-gcc.cmake
        -DMINGW_TOOLCHAIN_PREFIX:STRING=${_i386_prefix}
        -DSYSWOW64_GUEST:BOOL=ON
        -DENABLE_ROSTESTS:BOOL=OFF)
    # Settings that change what the user-mode files are or how they are built
    foreach(_var CMAKE_BUILD_TYPE DLL_EXPORT_VERSION ENABLE_CCACHE SEPARATE_DBG NO_ROSSYM
                 OPTIMIZE LTCG DBG KDBG _WINKD_ GDB USE_DUMMY_PSEH STACK_PROTECTOR PCH I18N_LANG VERBUMP_TIER)
        if(DEFINED ${_var})
            list(APPEND _args "-D${_var}=${${_var}}")
        endif()
    endforeach()

    set(_guest_dir ${REACTOS_BINARY_DIR}/syswow64-i386)
    set(_manifest ${_guest_dir}/syswow64-guest.${CMAKE_BUILD_TYPE}.lst)

    ExternalProject_Add(syswow64-i386
        SOURCE_DIR ${REACTOS_SOURCE_DIR}
        PREFIX ${_guest_dir}-ep
        BINARY_DIR ${_guest_dir}
        CMAKE_ARGS ${_args}
        BUILD_COMMAND ${CMAKE_COMMAND} --build ${_guest_dir} --target syswow64_guest
        BUILD_ALWAYS TRUE
        INSTALL_COMMAND ${CMAKE_COMMAND} -E true
        BUILD_BYPRODUCTS ${_manifest}
        EXCLUDE_FROM_ALL TRUE
        USES_TERMINAL_CONFIGURE TRUE
        USES_TERMINAL_BUILD TRUE)

    # The ISO file lists of boot/boot_images.cmake, with the i386 files added
    set(_out ${REACTOS_BINARY_DIR}/syswow64)
    set(_boot ${REACTOS_BINARY_DIR}/boot)
    set(_cfg ${CMAKE_BUILD_TYPE})
    set(SYSWOW64_DFF ${_out}/syswow64.dff PARENT_SCOPE)
    set(SYSWOW64_STAMP ${_out}/syswow64.stamp PARENT_SCOPE)
    set(SYSWOW64_LIVECD_LST ${_out}/livecd.${_cfg}.lst PARENT_SCOPE)
    set(SYSWOW64_BOOTCD_LST ${_out}/bootcd.${_cfg}.lst PARENT_SCOPE)

    # Runs on every build; the outputs only change when a staged file does.
    add_custom_target(syswow64_stage
        COMMAND ${CMAKE_COMMAND}
            -D MANIFEST=${_manifest}
            -D LIST=${SYSWOW64_LIST}
            -D DLL_EXPORT_VERSION=${DLL_EXPORT_VERSION}
            -D BOOTCD_LOOSE=${SYSWOW64_BOOTCD_LOOSE}
            -D OUT=${_out}
            -D LIVECD_IN=${_boot}/livecd.${_cfg}.lst
            -D LIVECD_OUT=${_out}/livecd.${_cfg}.lst
            -D BOOTCD_IN=${_boot}/bootcd.${_cfg}.lst
            -D BOOTCD_OUT=${_out}/bootcd.${_cfg}.lst
            -P ${REACTOS_SOURCE_DIR}/sdk/cmake/syswow64_stage.cmake
        BYPRODUCTS ${_out}/syswow64.dff ${_out}/syswow64.stamp ${_out}/syswow64-livecd.lst
                   ${_out}/livecd.${_cfg}.lst ${_out}/bootcd.${_cfg}.lst
        DEPENDS ${SYSWOW64_LIST} ${REACTOS_SOURCE_DIR}/sdk/cmake/syswow64_stage.cmake
        VERBATIM)
    add_dependencies(syswow64_stage syswow64-i386)
endfunction()
