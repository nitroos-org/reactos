# NITRO_PDB_PUBLICS: the symbols package of a build.
# Run with -DMANIFEST=<pdb/MANIFEST.txt> -DLIST=<file of "image|pdb" lines> -DPDB_ROOT=<the pdb directory>
#          -DOUT=<directory for the package> -DNAME=<name of the package> -DEPOCH=<seconds, time of the files in the archives>
#          -DFORMATS=<list of: zip, tar.xz>
#
# Writes <OUT>/<NAME>/ with
#   MANIFEST.txt   the manifest of the build (image, size, time stamp, PDB, GUID, age, hashes, keys)
#   README.txt     what the files are and how a debugger is pointed at them
#   store/         a symbol store (the layout symsrv/dbghelp read from a local directory or a plain HTTP directory):
#                    <pdb name>/<GUID without dashes, upper case><age in hex>/<pdb name>
#                    <image name>/<TimeDateStamp in 8 upper case hex digits><SizeOfImage in lower case hex>/<image name>
#                  images are listed under the name they have after installation (ntkrnlmp.exe is installed as ntoskrnl.exe) and,
#                  when that differs, under the name of the build
# and the archives <OUT>/<NAME>.<format> of that directory. The files of the build itself (the unpacked directory of the PDBs, the
# manifest) stay where they are. Needs CMake 3.17 only (the toolchain's), so files are copied with configure_file.

foreach(_v MANIFEST LIST PDB_ROOT OUT NAME)
    if(NOT DEFINED ${_v})
        message(FATAL_ERROR "pdb_package: ${_v} is not set")
    endif()
endforeach()
if(NOT DEFINED FORMATS)
    set(FORMATS zip tar.xz)
endif()
if(NOT DEFINED EPOCH)
    set(EPOCH 0)
endif()

set(_root "${OUT}/${NAME}")
file(REMOVE_RECURSE "${_root}")
file(MAKE_DIRECTORY "${_root}/store")

# image path of each PDB (the manifest does not carry build paths)
file(STRINGS "${LIST}" _pairs)
set(_pdb_keys "")
set(_img_paths "")
foreach(_pair ${_pairs})
    if(_pair MATCHES "^([^|]+)\\|(.+)$")
        file(RELATIVE_PATH _rel "${PDB_ROOT}" "${CMAKE_MATCH_2}")
        list(APPEND _pdb_keys "${_rel}")
        list(APPEND _img_paths "${CMAKE_MATCH_1}")
    endif()
endforeach()

file(STRINGS "${MANIFEST}" _rows)
set(_n 0)
set(_bytes_pdb 0)
set(_bytes_img 0)
foreach(_row ${_rows})
    if(_row MATCHES "^#" OR _row STREQUAL "")
        continue()
    endif()
    string(REPLACE "\t" ";" _c "${_row}")
    list(LENGTH _c _nc)
    if(NOT _nc EQUAL 13)
        message(FATAL_ERROR "pdb_package: manifest row with ${_nc} columns (13 expected): ${_row}")
    endif()
    list(GET _c 3 _pdbname)
    list(GET _c 6 _pdbkey)
    list(GET _c 8 _psize)
    list(GET _c 10 _pdbrel)
    list(GET _c 11 _install)
    list(GET _c 12 _imgkey)
    list(GET _c 1 _isize)
    list(FIND _pdb_keys "${_pdbrel}" _idx)
    if(_idx LESS 0)
        message(FATAL_ERROR "pdb_package: no image for ${_pdbrel}")
    endif()
    list(GET _img_paths ${_idx} _imgpath)
    configure_file("${PDB_ROOT}/${_pdbrel}" "${_root}/store/${_pdbkey}/${_pdbname}" COPYONLY)
    configure_file("${_imgpath}" "${_root}/store/${_install}/${_imgkey}/${_install}" COPYONLY)
    # a debugger asks for the name the loader gave the module: the kernel booted with /KERNEL=ntkrnlkd.exe lists halmp.dll and
    # kdcomkit.dll, a default boot hal.dll and kdcom.dll, so the image is also stored under the name it has in the build
    list(GET _c 0 _bname)
    if(NOT _bname STREQUAL _install)
        configure_file("${_imgpath}" "${_root}/store/${_bname}/${_imgkey}/${_bname}" COPYONLY)
    endif()
    math(EXPR _n "${_n} + 1")
    math(EXPR _bytes_pdb "${_bytes_pdb} + ${_psize}")
    math(EXPR _bytes_img "${_bytes_img} + ${_isize}")
endforeach()
configure_file("${MANIFEST}" "${_root}/MANIFEST.txt" COPYONLY)

file(WRITE "${_root}/README.txt" "NitroOS symbols: ${NAME}
${_n} images with their PDB files (public symbols: function and variable names, no types, no line numbers).

store/ is a symbol store. Point the debugger at it:
  .sympath srv*C:\\symbols\\${NAME}\\store           (WinDbg, kd, cdb: a local directory)
  .sympath srv*C:\\cache*http://<host>/<directory>   (the same tree served by any plain HTTP server)
  .reload /f
PDB files are found by the GUID and age that the image records, images by TimeDateStamp and SizeOfImage. MANIFEST.txt lists
both for every image, with the SHA-256 of the files. The PDB files of the same build are not mixed with those of another:
a PDB that does not belong to the running image is never used by the debugger.
")

foreach(_fmt ${FORMATS})
    set(_file "${OUT}/${NAME}.${_fmt}")
    file(REMOVE "${_file}")
    # tar: entries in a fixed order, a fixed modification time
    file(GLOB_RECURSE _files RELATIVE "${OUT}" "${_root}/*")
    list(SORT _files)
    if(NOT EPOCH EQUAL 0)
        # the time of the build's source, not of the build (string(TIMESTAMP) honours SOURCE_DATE_EPOCH)
        set(ENV{SOURCE_DATE_EPOCH} "${EPOCH}")
    endif()
    string(TIMESTAMP _mtime "%Y-%m-%d %H:%M:%S UTC" UTC)
    if(_fmt STREQUAL "zip")
        set(_tarargs cf "${_file}" --format=zip "--mtime=${_mtime}")
    elseif(_fmt STREQUAL "tar.xz")
        set(_tarargs cJf "${_file}" --format=gnutar "--mtime=${_mtime}")
    else()
        message(FATAL_ERROR "pdb_package: unknown archive format ${_fmt}")
    endif()
    execute_process(COMMAND "${CMAKE_COMMAND}" -E tar ${_tarargs} -- ${_files}
                    WORKING_DIRECTORY "${OUT}" RESULT_VARIABLE _rc)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "pdb_package: could not write ${_file}")
    endif()
    file(SIZE "${_file}" _asize)
    message(STATUS "pdb_package: ${_file} (${_asize} bytes)")
endforeach()
message(STATUS "pdb_package: ${_n} images, ${_bytes_pdb} bytes of PDB files, ${_bytes_img} bytes of images in ${_root}")
