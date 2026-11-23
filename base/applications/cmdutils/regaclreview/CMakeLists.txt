
## The message texts of the event source (a string template each)
add_message_headers(ANSI regaclreviewmsg.mc)

add_executable(regaclreview regaclreview.c regaclreview.rc)
set_module_type(regaclreview win32cui UNICODE)
add_dependencies(regaclreview regaclreviewmsg)
add_message_rc_deps(regaclreview.rc regaclreviewmsg)
add_importlibs(regaclreview advapi32 netapi32 msvcrt kernel32)
add_cd_file(TARGET regaclreview DESTINATION reactos/system32 FOR all)
