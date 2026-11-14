
# Stages the i386 guest build's SysWOW64 files for the amd64 images.
# Run in script mode by the syswow64_stage target (sdk/cmake/syswow64.cmake):
#   cmake -D MANIFEST=<guest manifest> -D LIST=<syswow64.lst> -D DLL_EXPORT_VERSION=<level> -D OUT=<dir>
#         [-D LIVECD_IN=<lst> -D LIVECD_OUT=<lst>] [-D BOOTCD_IN=<lst> -D BOOTCD_OUT=<lst>]
#         -P syswow64_stage.cmake
#
# Writes:
#  - OUT/syswow64.dff: lines appended to reactos.dff. The cabinet stores files
#    by base name and the amd64 files already use the plain names, so each file
#    is staged as OUT/cab/wow64-<dir id>-<name> and the cabinet INF names its
#    target file explicitly ("<dir id>,<name>").
#  - OUT/syswow64-livecd.lst: "reactos/<dir>/<name>=<path>" lines for the
#    LiveCD tree, and the combined LiveCD/BootCD lists when given.
#  - OUT/syswow64.stamp: touched whenever the cabinet contents change.

cmake_minimum_required(VERSION 3.17)

# Directory ids of the generated part. reactos.dff.in uses 1-81.
set(FIRST_DIR_ID 200)

if(NOT EXISTS "${MANIFEST}")
    message(FATAL_ERROR "SysWOW64: the i386 guest build wrote no manifest (${MANIFEST})")
endif()

function(write_if_different _path _content)
    if(EXISTS "${_path}")
        file(READ "${_path}" _old)
        if(_old STREQUAL _content)
            set(WRITTEN FALSE PARENT_SCOPE)
            return()
        endif()
    endif()
    file(WRITE "${_path}" "${_content}")
    set(WRITTEN TRUE PARENT_SCOPE)
endfunction()

# The wanted files, as "<dir>/<name>" relative to %SystemRoot%, lower case
file(STRINGS "${LIST}" _lines REGEX "^[^#]")
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
    if(_line)
        if(_line IN_LIST _wanted)
            message(FATAL_ERROR "SysWOW64: ${_line} is listed twice in ${LIST}")
        endif()
        list(APPEND _wanted "${_line}")
    endif()
endforeach()

# The guest's candidates: "<dir>|<name>|<path>". A file listed under two
# source directories (notepad.exe is in both the root and system32 on i386)
# is the same build output; the first one wins.
file(STRINGS "${MANIFEST}" _entries)
set(_found "")
set(_dirs "")
foreach(_entry ${_entries})
    string(REPLACE "|" ";" _parts "${_entry}")
    list(GET _parts 0 _dir)
    list(GET _parts 1 _name)
    list(GET _parts 2 _path)
    string(TOLOWER "${_dir}/${_name}" _key)
    if(NOT _key IN_LIST _wanted OR _key IN_LIST _found)
        continue()
    endif()
    if(NOT EXISTS "${_path}")
        message(FATAL_ERROR "SysWOW64: ${_path} was not built")
    endif()
    list(APPEND _found "${_key}")
    set(_dir_of_${_key} "${_dir}")
    set(_name_of_${_key} "${_name}")
    set(_path_of_${_key} "${_path}")
    if(NOT _dir IN_LIST _dirs)
        list(APPEND _dirs "${_dir}")
    endif()
endforeach()

# Every listed file must come out of the build: a component that was renamed
# or removed has to be removed from the list as well.
set(_missing "")
foreach(_key ${_wanted})
    if(NOT _key IN_LIST _found)
        list(APPEND _missing "${_key}")
    endif()
endforeach()
if(_missing)
    string(REPLACE ";" "\n  " _missing "${_missing}")
    message(FATAL_ERROR "SysWOW64: listed in ${LIST} but not produced by the i386 build:\n  ${_missing}")
endif()

list(SORT _dirs)
set(_id ${FIRST_DIR_ID})
set(_dff ".InfBegin\n[Directories]\n")
foreach(_dir ${_dirs})
    set(_id_of_${_dir} ${_id})
    string(REPLACE "/" "\\" _windir "${_dir}")
    string(APPEND _dff "${_id} = ${_windir}\n")
    math(EXPR _id "${_id} + 1")
endforeach()
string(APPEND _dff "\n[SourceFiles]\n.InfEnd\n\n")

file(MAKE_DIRECTORY "${OUT}/cab")
set(_changed FALSE)
set(_staged "")
set(_livecd "")
list(SORT _found)
foreach(_key ${_found})
    set(_dir "${_dir_of_${_key}}")
    set(_name "${_name_of_${_key}}")
    set(_path "${_path_of_${_key}}")
    set(_cabname "wow64-${_id_of_${_dir}}-${_name}")
    set(_dst "${OUT}/cab/${_cabname}")
    list(APPEND _staged "${_cabname}")
    set(_copy TRUE)
    if(EXISTS "${_dst}")
        file(SHA256 "${_path}" _h1)
        file(SHA256 "${_dst}" _h2)
        if(_h1 STREQUAL _h2)
            set(_copy FALSE)
        endif()
    endif()
    if(_copy)
        # the file on disk can be named differently from the name it has on the CD (NAME_ON_CD)
        get_filename_component(_srcname "${_path}" NAME)
        file(COPY "${_path}" DESTINATION "${OUT}/tmp")
        file(RENAME "${OUT}/tmp/${_srcname}" "${_dst}")
        set(_changed TRUE)
    endif()
    string(APPEND _dff "\"${_dst}\" ${_id_of_${_dir}},${_name}\n")
    string(APPEND _livecd "reactos/${_dir}/${_name}=${_path}\n")
endforeach()

# Files staged by an earlier build that are no longer wanted
file(GLOB _old RELATIVE "${OUT}/cab" "${OUT}/cab/*")
foreach(_file ${_old})
    if(NOT _file IN_LIST _staged)
        file(REMOVE "${OUT}/cab/${_file}")
        set(_changed TRUE)
    endif()
endforeach()

write_if_different("${OUT}/syswow64.dff" "${_dff}")
if(WRITTEN)
    set(_changed TRUE)
endif()
write_if_different("${OUT}/syswow64-livecd.lst" "${_livecd}")

# The BootCD installs SysWOW64 from the cab (wow64-* entries of syswow64.dff) like every other
# file of the system, so a loose copy next to it only doubles the size of the ISO (177 MB of 32-bit
# files, 73 MB of them libgallium_wgl.dll). BOOTCD_LOOSE=ON keeps it, for the 32-bit files in the
# BootCD's own live environment; the LiveCD image always has it.
foreach(_cd LIVECD BOOTCD)
    if(DEFINED ${_cd}_IN)
        file(READ "${${_cd}_IN}" _base)
        if(NOT _base MATCHES "\n$")
            string(APPEND _base "\n")
        endif()
        if(_cd STREQUAL "BOOTCD" AND NOT BOOTCD_LOOSE)
            write_if_different("${${_cd}_OUT}" "${_base}")
        else()
            write_if_different("${${_cd}_OUT}" "${_base}${_livecd}")
        endif()
    endif()
endforeach()

if(_changed OR NOT EXISTS "${OUT}/syswow64.stamp")
    file(TOUCH "${OUT}/syswow64.stamp")
endif()

list(LENGTH _found _count)
list(LENGTH _dirs _ndirs)
message("-- SysWOW64: ${_count} files in ${_ndirs} directories")
