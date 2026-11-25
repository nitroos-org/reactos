# NITRO_PDB_PUBLICS: the list of the images of the symbols package, with the 32-bit files of SysWOW64.
# Run with -DHOST_LIST=<file of "image|pdb" lines of this build> -DOUT=<merged list>
#          and, when the 32-bit guest build exists, -DGUEST_LIST=<its "image|pdb" lines> -DGUEST_FILES=<the files it stages>.
# The guest build lists every module it could build; only the ones it staged for SysWOW64 (GUEST_FILES, lines
# "<directory>|<installed name>|<image path>") are part of the installation medium. Images of the medium that are PE files
# but have no PDB are listed in <OUT>.missing, one per line: with every user-mode module selected that file must stay empty.

foreach(_v HOST_LIST OUT)
    if(NOT DEFINED ${_v})
        message(FATAL_ERROR "pdb_merge: ${_v} is not set")
    endif()
endforeach()

file(STRINGS "${HOST_LIST}" _host_lines)
set(_out "")
foreach(_line ${_host_lines})
    if(_line)
        string(APPEND _out "${_line}\n")
    endif()
endforeach()

set(_missing "")
if(DEFINED GUEST_LIST AND DEFINED GUEST_FILES AND EXISTS "${GUEST_LIST}" AND EXISTS "${GUEST_FILES}")
    # image path -> pdb path of the guest build
    file(STRINGS "${GUEST_LIST}" _guest_lines)
    foreach(_line ${_guest_lines})
        if(_line MATCHES "^([^|]+)\\|(.+)$")
            set(_pdb_of_${CMAKE_MATCH_1} "${CMAKE_MATCH_2}")
            set(_have_${CMAKE_MATCH_1} TRUE)
        endif()
    endforeach()
    file(STRINGS "${GUEST_FILES}" _staged)
    foreach(_line ${_staged})
        if(NOT _line MATCHES "^([^|]*)\\|([^|]+)\\|(.+)$")
            continue()
        endif()
        set(_dir "${CMAKE_MATCH_1}")
        set(_name "${CMAKE_MATCH_2}")
        set(_img "${CMAKE_MATCH_3}")
        if(NOT _name MATCHES "\\.(dll|exe|ocx|cpl|drv|sys|ax|acm|scr)$")
            continue()
        endif()
        if(_have_${_img})
            string(APPEND _out "${_img}|${_pdb_of_${_img}}\n")
        else()
            string(APPEND _missing "${_dir}/${_name}\n")
        endif()
    endforeach()
endif()

file(WRITE "${OUT}" "${_out}")
file(WRITE "${OUT}.missing" "${_missing}")
if(_missing)
    string(REGEX REPLACE "\n$" "" _missing_msg "${_missing}")
    string(REPLACE "\n" "; " _missing_msg "${_missing_msg}")
    message(STATUS "pdb_merge: images of the medium without a PDB: ${_missing_msg}")
endif()
