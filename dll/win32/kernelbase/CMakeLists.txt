
remove_definitions(-D_WIN32_WINNT=0x502 -DWINVER=0x502)

add_definitions(
    -D__WINESRC__
    -D_WINE
    -D_KERNELBASE_)

include_directories(BEFORE ${REACTOS_SOURCE_DIR}/sdk/include/wine)

add_subdirectory(wine)

spec2def(kernelbase_ros.dll kernelbase_ros.spec ADD_IMPORTLIB)

add_library(kernelbase_ros MODULE
    DllMain.c
    appcontainer.c
    synch.c
    time.c
    ${CMAKE_CURRENT_BINARY_DIR}/kernelbase_ros_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/kernelbase_ros.def)

# NtAllocateVirtualMemoryEx, NtMapViewOfSectionEx, NtUnmapViewOfSectionEx and NtCreateLowBoxToken are exported by
# ntdll from 0x600 on only
if(DLL_EXPORT_VERSION GREATER_EQUAL 0x600)
    target_sources(kernelbase_ros PRIVATE memory.c)
    target_compile_definitions(kernelbase_ros PRIVATE KERNELBASE_NT6_NTDLL)
endif()

set_module_type(kernelbase_ros win32dll ENTRYPOINT DllMain 12)
target_link_libraries(kernelbase_ros psapi_static kernelbase_static wine chkstk)
add_importlibs(kernelbase_ros msvcrt advapi32 advapi32_vista kernel32 kernel32_vista ntdll ntdll_vista)
add_dependencies(kernelbase_ros psdk errcodes)
add_cd_file(TARGET kernelbase_ros DESTINATION reactos/system32 FOR all)

# Programs ask for kernelbase.dll by that name (the MSYS2 and Cygwin runtimes load it for the interrupt time functions).
# The module only forwards every export of kernelbase_ros.dll, so that one copy of the code is loaded.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/kernelbase_ros.spec
                                                                  ${CMAKE_CURRENT_SOURCE_DIR}/kernelbase_fwd.lst)
if(ARCH STREQUAL "amd64")
    set(_kernelbase_arch "x86_64")
else()
    set(_kernelbase_arch "${ARCH}")
endif()
file(STRINGS kernelbase_ros.spec _kernelbase_spec REGEX "^@ (stdcall|cdecl|varargs) ")
math(EXPR _kernelbase_version "${DLL_EXPORT_VERSION}")
set(_kernelbase_def "; File generated automatically, do not edit!\n\nNAME kernelbase.dll\n\nEXPORTS\n")
set(_kernelbase_implib_spec "# File generated automatically, do not edit!\n")
foreach(_line IN LISTS _kernelbase_spec)
    set(_min 0)
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*-version=(0x[0-9a-fA-F]+)\\+")
        set(_min ${CMAKE_MATCH_2})
    endif()
    math(EXPR _min "${_min}")
    if(_kernelbase_version LESS _min)
        continue()
    endif()
    # -arch=<list>: a name starting with ! excludes that architecture (spec2def syntax)
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*-arch=([A-Za-z0-9_,!]+)")
        string(REPLACE "," ";" _archs "${CMAKE_MATCH_2}")
        set(_arch_ok FALSE)
        foreach(_a IN LISTS _archs)
            if(_a MATCHES "^!(.+)$")
                if(NOT CMAKE_MATCH_1 STREQUAL _kernelbase_arch)
                    set(_arch_ok TRUE)
                endif()
            elseif(_a STREQUAL _kernelbase_arch)
                set(_arch_ok TRUE)
            endif()
        endforeach()
        if(NOT _arch_ok)
            continue()
        endif()
    endif()
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*([A-Za-z0-9_]+)\\(")
        string(APPEND _kernelbase_def " ${CMAKE_MATCH_2}=kernelbase_ros.${CMAKE_MATCH_2}\n")
        string(APPEND _kernelbase_implib_spec "${_line}\n")
    endif()
endforeach()

# Exports that Windows' kernelbase.dll has but that live in kernel32.dll on ReactOS: forward them to kernel32.
# Every name must be exported by kernel32.spec (checked here), so that no forwarder dangles.
file(STRINGS ${REACTOS_SOURCE_DIR}/dll/win32/kernel32/kernel32.spec _kernel32_spec REGEX "^@ ")
set(_kernel32_names)
foreach(_line IN LISTS _kernel32_spec)
    if(_line MATCHES "^@ [a-z]+ (-[^ ]+ )*([A-Za-z0-9_@]+)([ (]|$)")
        list(APPEND _kernel32_names ${CMAKE_MATCH_2})
        string(APPEND _kernel32_line_${CMAKE_MATCH_2} "${_line}\n")
    endif()
endforeach()
file(STRINGS kernelbase_fwd.lst _kernelbase_fwd REGEX "^@ ")
foreach(_line IN LISTS _kernelbase_fwd)
    if(NOT _line MATCHES "^@ ([A-Za-z0-9_]+)( .*)?$")
        message(FATAL_ERROR "kernelbase_fwd.lst: bad line '${_line}'")
    endif()
    set(_name ${CMAKE_MATCH_1})
    set(_gate "${CMAKE_MATCH_2}")
    list(FIND _kernel32_names ${_name} _idx)
    if(_idx EQUAL -1)
        message(FATAL_ERROR "kernelbase_fwd.lst: ${_name} is not exported by kernel32.spec")
    endif()
    set(_min 0)
    set(_max 0xFFFFFFF)
    if(_gate MATCHES "-version=(0x[0-9a-fA-F]+)\\+")
        set(_min ${CMAKE_MATCH_1})
    elseif(_gate MATCHES "-version=(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+)")
        set(_min ${CMAKE_MATCH_1})
        set(_max ${CMAKE_MATCH_2})
    endif()
    math(EXPR _min "${_min}")
    math(EXPR _max "${_max}")
    if(_kernelbase_version LESS _min OR _kernelbase_version GREATER _max)
        continue()
    endif()
    if(_gate MATCHES "-arch=([A-Za-z0-9_,]+)")
        string(REPLACE "," ";" _archs "${CMAKE_MATCH_1}")
        list(FIND _archs ${_kernelbase_arch} _idx)
        if(_idx EQUAL -1)
            continue()
        endif()
    endif()
    string(FIND "${_kernelbase_def}" " ${_name}=" _idx)
    if(NOT _idx EQUAL -1)
        message(FATAL_ERROR "kernelbase_fwd.lst: ${_name} is already exported through kernelbase_ros")
    endif()
    string(APPEND _kernelbase_def " ${_name}=kernel32.${_name}\n")
    # the import library needs the argument sizes (stdcall decoration on i386), which only the kernel32 spec line has
    # (all of them: the version/arch variants of one name are separate spec lines)
    # (-private would keep them out of the library: kernel32 only hides them from its own import library)
    string(REPLACE " -private" "" _k32lines "${_kernel32_line_${_name}}")
    string(APPEND _kernelbase_implib_spec "${_k32lines}")
endforeach()
file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kernelbase.def CONTENT "${_kernelbase_def}")

# Import library of kernelbase.dll for the modules that import it statically (shlwapi, vbscript). It has exactly the exports of
# kernelbase.def above: both come from the same spec lines, the implib spec just keeps the argument lists. The imports then resolve
# through the forwarders, which load kernelbase_ros.dll (kernelbase.dll itself is not an import of kernel32: that would be a cycle).
file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kernelbase_implib.spec CONTENT "${_kernelbase_implib_spec}")
file(RELATIVE_PATH _kernelbase_implib_spec_rel ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/kernelbase_implib.spec)
generate_import_lib(libkernelbase kernelbase.dll ${_kernelbase_implib_spec_rel} "--version=${DLL_EXPORT_VERSION}" "")

add_library(kernelbase MODULE
    kernelbase.rc
    ${CMAKE_CURRENT_BINARY_DIR}/kernelbase.def)

set_module_type(kernelbase win32dll ENTRYPOINT 0)
add_dependencies(kernelbase psdk kernelbase_ros)
add_cd_file(TARGET kernelbase DESTINATION reactos/system32 FOR all)
