
# RFC 6724 address selection shared by tcpip.sys and user mode (iphlpapi): base types and memcmp/memcpy/memset only
add_library(addrsel STATIC addrsel.c)
add_dependencies(addrsel xdk psdk)
