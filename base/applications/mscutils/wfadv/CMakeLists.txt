
list(APPEND SOURCE
    profile.c
    rules.c
    ruledlg.c
    wfadv.c
    wizard.c
    wfadv.h)

add_rc_deps(wfadv.rc ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dll/cpl/firewall/resources/applet.ico)
add_executable(wfadv ${SOURCE} wfadv.rc)
set_module_type(wfadv win32gui UNICODE)
target_link_libraries(wfadv fwstore)
add_importlibs(wfadv comctl32 comdlg32 shell32 user32 gdi32 advapi32 rpcrt4 msvcrt kernel32 ntdll)
add_cd_file(TARGET wfadv DESTINATION reactos/system32 FOR all)
