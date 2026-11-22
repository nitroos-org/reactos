
add_library(iologmsg MODULE iologmsg.rc)
set_module_type(iologmsg module UNICODE)
add_dependencies(iologmsg ntiologc)
add_message_rc_deps(iologmsg.rc ntiologc)
add_cd_file(TARGET iologmsg DESTINATION reactos/system32 FOR all)
