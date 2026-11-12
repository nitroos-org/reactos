
add_definitions(-DUNICODE -D_UNICODE -D_NTOSKRNL_ -D_NTSYSTEM_)

list(APPEND SOURCE
    wdmsec.c)

add_library(wdmsec ${SOURCE})
add_dependencies(wdmsec bugcodes xdk)
