# Session image budget (i386): the images loaded into session image space (8 MB on i386) must fit in
# 6 MB together, with room for four keyboard layouts. Each image is rounded up to 64 KB.
# Run with -DIMAGES="file1;file2;..." -DLIMIT=<bytes>.

set(_total 0)
foreach(_image ${IMAGES})
    file(READ "${_image}" _hdr LIMIT 1024 HEX)
    # e_lfanew at 0x3C (little endian)
    string(SUBSTRING "${_hdr}" 120 8 _lfanew_hex)
    string(REGEX REPLACE "(..)(..)(..)(..)" "\\4\\3\\2\\1" _lfanew_hex "${_lfanew_hex}")
    math(EXPR _lfanew "0x${_lfanew_hex}")
    # SizeOfImage: optional header (e_lfanew + 24) + 56
    math(EXPR _offset "(${_lfanew} + 80) * 2")
    string(SUBSTRING "${_hdr}" ${_offset} 8 _size_hex)
    string(REGEX REPLACE "(..)(..)(..)(..)" "\\4\\3\\2\\1" _size_hex "${_size_hex}")
    math(EXPR _size "((0x${_size_hex} + 0xFFFF) / 0x10000) * 0x10000")
    math(EXPR _total "${_total} + ${_size}")
endforeach()

# Four keyboard layouts (each under 64 KB)
math(EXPR _total "${_total} + 4 * 0x10000")

if(_total GREATER LIMIT)
    message(FATAL_ERROR "Session images need ${_total} bytes, more than the ${LIMIT} allowed in session image space")
endif()
message(STATUS "Session images: ${_total} of ${LIMIT} bytes")
