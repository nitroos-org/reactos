list(APPEND SOURCE
    kpush.c
    rule.c
    store.c
    typed.c
    precomp.h
    fwstore.h)

add_library(fwstore STATIC ${SOURCE})
add_dependencies(fwstore xdk)
target_include_directories(fwstore INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
