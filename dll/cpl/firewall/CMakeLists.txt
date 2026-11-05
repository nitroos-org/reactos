spec2def(firewall.cpl firewall.spec)
file(GLOB firewall_rc_deps resources/*.*)
add_rc_deps(firewall.rc ${firewall_rc_deps})

add_library(firewall MODULE
    firewall.c
    firewall.rc
    ${CMAKE_CURRENT_BINARY_DIR}/firewall.def)

set_module_type(firewall cpl UNICODE)
target_link_libraries(firewall fwstore)
add_importlibs(firewall comctl32 comdlg32 shell32 user32 gdi32 advapi32 rpcrt4 msvcrt kernel32 ntdll)
add_cd_file(TARGET firewall DESTINATION reactos/system32 FOR all)
