
# Programs that misbehave on purpose, for the tests of base/applications/nitrodiag (run by nitrodiag_tests.cmd).
add_executable(ndt ndt.c)
set_module_type(ndt win32cui)
target_link_libraries(ndt uuid)
add_importlibs(ndt ole32 shell32 msvcrt kernel32)
add_rostests_file(TARGET ndt)

add_executable(ndt_cpp ndt_cpp.cpp)
set_module_type(ndt_cpp win32cui)
target_link_libraries(ndt_cpp cppstl)
set_target_cpp_properties(ndt_cpp WITH_EXCEPTIONS)
add_importlibs(ndt_cpp msvcrt kernel32)
add_rostests_file(TARGET ndt_cpp)

add_executable(ndt_gui ndt_gui.c)
set_module_type(ndt_gui win32gui UNICODE)
add_importlibs(ndt_gui user32 msvcrt kernel32)
add_rostests_file(TARGET ndt_gui)

# ndt_missing.exe imports NdFuncA and NdFuncB from ndt_full.dll; the tests take the DLL away, or put ndt_short.dll in its place
spec2def(ndt_full.dll ndt_full.spec ADD_IMPORTLIB)
add_library(ndt_full MODULE ndt_full.c ${CMAKE_CURRENT_BINARY_DIR}/ndt_full.def)
set_module_type(ndt_full win32dll)
add_importlibs(ndt_full kernel32)
add_dependencies(ndt_full psdk)
add_rostests_file(TARGET ndt_full)

spec2def(ndt_short.dll ndt_short.spec)
add_library(ndt_short MODULE ndt_short.c ${CMAKE_CURRENT_BINARY_DIR}/ndt_short.def)
set_module_type(ndt_short win32dll)
add_importlibs(ndt_short kernel32)
add_dependencies(ndt_short psdk)
add_rostests_file(TARGET ndt_short)

add_executable(ndt_missing ndt_missing.c)
set_module_type(ndt_missing win32cui)
add_importlibs(ndt_missing ndt_full msvcrt kernel32)
add_dependencies(ndt_missing ndt_full)
add_rostests_file(TARGET ndt_missing)

add_rostests_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/nitrodiag_tests.cmd)
