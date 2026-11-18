
# Generate threaddll.dll
spec2def(msvcp140_threaddll.dll threaddll.spec)
add_library(msvcp140_threaddll SHARED
    threaddll.c
    msvcp140_threaddll.def
)
set_entrypoint(msvcp140_threaddll DllMain 12)
ros_check_unwind(msvcp140_threaddll)
if(MSVC)
    target_link_libraries(msvcp140_threaddll runtmchk)
endif()
add_importlibs(msvcp140_threaddll ucrtbase kernel32)

# Hacks to make it work with MSVC IDE / MSBUILD
if(MSVC_IDE)
    if(DBG)
        set(THREADDLL_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/Debug)
    else()
        set(THREADDLL_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/Release)
    endif()
    message(STATUS "msvcp140_threaddll.dll output directory: ${THREADDLL_OUTPUT_DIR}")

    set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /I${THREADDLL_OUTPUT_DIR}")
endif()

# Hack to replace the old CRT include directory with the UCRT include directory
get_property(INCLUDE_DIRS DIRECTORY . PROPERTY INCLUDE_DIRECTORIES)
list(REMOVE_ITEM INCLUDE_DIRS "${REACTOS_SOURCE_DIR}/sdk/include/crt")
set_property(DIRECTORY . PROPERTY INCLUDE_DIRECTORIES ${INCLUDE_DIRS})
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/ucrt)

remove_definitions(-D_WIN32_WINNT=0x502 -DWINVER=0x502)
add_definitions(-D_WIN32_WINNT=0x601 -DWINVER=0x601)

# The test redefines types of the UCRT headers (_Mbstatet) under another name: see test_Mbstatet
add_definitions(
    -D_beginthreadex_start_routine_t=_beginthreadex_proc_type
    -DUSE_WINE_TODOS
    -D_USE_MATH_DEFINES
    -DWINETEST_USE_DBGSTR_LONGLONG
    -D_finddata64_t=__finddata64_t
)

list(APPEND SOURCE
    msvcp140.c
    testlist.c
    msvcp140_winetest.rc
)

set_source_files_properties(msvcp140_winetest.rc OBJECT_DEPENDS msvcp140_threaddll)

add_executable(msvcp140_winetest ${SOURCE})
if(NOT MSVC)
    target_compile_options(msvcp140_winetest PRIVATE -Wno-format)
endif()
set_module_type(msvcp140_winetest win32cui)

target_link_libraries(msvcp140_winetest wine oldnames ${PSEH_LIB} chkstk)
if(NOT MSVC)
    # Add this manually here, so it can link to ucrtbase.dll and vcstartup
    target_link_libraries(msvcp140_winetest -lgcc)
endif()

add_importlibs(msvcp140_winetest ucrtbase kernel32 ntdll)
add_dependencies(msvcp140_winetest msvcp140_threaddll)
add_rostests_file(TARGET msvcp140_winetest)
