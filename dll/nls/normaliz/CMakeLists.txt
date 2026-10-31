
spec2def(normaliz.dll normaliz.spec ADD_IMPORTLIB)

# The exports of normaliz.dll are all forwarders, to kernelbase.dll as on Windows.
add_library(normaliz MODULE
    normaliz.rc
    ${CMAKE_CURRENT_BINARY_DIR}/normaliz.def)

set_module_type(normaliz win32dll ENTRYPOINT 0)
add_cd_file(TARGET normaliz DESTINATION reactos/system32 FOR all)
