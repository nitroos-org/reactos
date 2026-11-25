# Exercise sdk/cmake/pdb_merge.cmake: the list of the images of the symbols package with the 32-bit files of SysWOW64.
# Run with -DMERGE=<sdk/cmake/pdb_merge.cmake> -DWORK=<scratch directory>. No compiler is needed.
cmake_minimum_required(VERSION 3.17)
foreach(_arg MERGE WORK)
    if(NOT DEFINED ${_arg})
        message(FATAL_ERROR "${_arg} is required")
    endif()
endforeach()
function(run)
    execute_process(COMMAND ${ARGV} RESULT_VARIABLE _result)
    if(NOT _result EQUAL 0)
        message(FATAL_ERROR "Command failed (${_result}): ${ARGV}")
    endif()
endfunction()
function(expect_file _file _content)
    file(READ "${_file}" _have)
    if(NOT _have STREQUAL _content)
        message(FATAL_ERROR "${_file}: expected\n[${_content}]\ngot\n[${_have}]")
    endif()
endfunction()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
file(WRITE "${WORK}/host.txt" "/b/dll/win32/kernel32/kernel32.dll|/b/pdb/dll/win32/kernel32/kernel32.pdb\n")
# the nested build lists every module it could build, even the ones nobody stages
file(WRITE "${WORK}/guest.txt"
    "/g/dll/win32/kernel32/kernel32.dll|/b/pdb/syswow64/dll/win32/kernel32/kernel32.pdb\n"
    "/g/dll/keyboard/kbdus.dll|/b/pdb/syswow64/dll/keyboard/kbdus.pdb\n"
    "/g/drivers/foo/foo.sys|/b/pdb/syswow64/drivers/foo/foo.pdb\n")
# the staged files: kernel32 and kbdus have a PDB, lonely.dll has none, a .nls file is not an image
file(WRITE "${WORK}/staged.txt"
    "SysWOW64|kernel32.dll|/g/dll/win32/kernel32/kernel32.dll\n"
    "SysWOW64|kbdus.dll|/g/dll/keyboard/kbdus.dll\n"
    "SysWOW64|lonely.dll|/g/dll/lonely/lonely.dll\n"
    "SysWOW64|c_1252.nls|/g/nls/c_1252.nls\n")

run(${CMAKE_COMMAND} -DHOST_LIST=${WORK}/host.txt -DGUEST_LIST=${WORK}/guest.txt -DGUEST_FILES=${WORK}/staged.txt
    -DOUT=${WORK}/all.txt -P ${MERGE})
expect_file("${WORK}/all.txt"
    "/b/dll/win32/kernel32/kernel32.dll|/b/pdb/dll/win32/kernel32/kernel32.pdb\n/g/dll/win32/kernel32/kernel32.dll|/b/pdb/syswow64/dll/win32/kernel32/kernel32.pdb\n/g/dll/keyboard/kbdus.dll|/b/pdb/syswow64/dll/keyboard/kbdus.pdb\n")
expect_file("${WORK}/all.txt.missing" "SysWOW64/lonely.dll\n")

# without a guest build the list is the host's
run(${CMAKE_COMMAND} -DHOST_LIST=${WORK}/host.txt -DOUT=${WORK}/host-only.txt -P ${MERGE})
expect_file("${WORK}/host-only.txt" "/b/dll/win32/kernel32/kernel32.dll|/b/pdb/dll/win32/kernel32/kernel32.pdb\n")
expect_file("${WORK}/host-only.txt.missing" "")
message(STATUS "pdb_merge test passed")
