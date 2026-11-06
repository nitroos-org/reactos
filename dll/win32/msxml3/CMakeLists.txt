
add_definitions(
    -D__ROS_LONG64__
    -D_WINE
    -DLIBXML_STATIC
    -DCOM_NO_WINDOWS_H)

spec2def(msxml3.dll msxml3.spec ADD_IMPORTLIB NO_PRIVATE_WARNINGS)
add_typelib(msxml3_v1.idl)

list(APPEND SOURCE
    attribute.c
    bsc.c
    cdata.c
    comment.c
    dispex.c
    docfrag.c
    doctype.c
    domdoc.c
    domimpl.c
    element.c
    entity.c
    entityref.c
    httprequest.c
    main.c
    mxnamespace.c
    mxwriter.c
    node.c
    nodelist.c
    nodemap.c
    notation.c
    parseerror.c
    pi.c
    reactos.c
    saxreader.c
    schema.c
    selection.c
    stylesheet.c
    text.c
    xdr.c
    xmldoc.c
    xmlparser.c
    xmlview.c
    xpath.c)

list(APPEND PCH_SKIP_SOURCE
    factory.c
    uuid.c)

# msxml.mc (error message table). add_message_headers() would emit msxml.h (shadows the PSDK msxml.h)
# and a target named msxml, so run the steps here with a private name. ReactOS-only wiring.
utf16le_convert(${CMAKE_CURRENT_SOURCE_DIR}/msxml.mc ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.mc nobom)
macro_mc(-U ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.mc)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.h ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.rc
    COMMAND ${COMMAND_MC}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.mc)
set_source_files_properties(
    ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.h ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.rc
    PROPERTIES GENERATED TRUE)
add_custom_target(msxml3_msg DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.h ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.rc)

list(APPEND msxml3_rc_deps
    ${CMAKE_CURRENT_BINARY_DIR}/msxml3_msg.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/msxml3.manifest
    ${CMAKE_CURRENT_SOURCE_DIR}/msxml3_v1.rgs
    ${CMAKE_CURRENT_SOURCE_DIR}/xmlparser.rgs
    ${CMAKE_CURRENT_BINARY_DIR}/msxml3_v1.tlb)

set_source_files_properties(version.rc PROPERTIES OBJECT_DEPENDS "${msxml3_rc_deps}")

add_library(msxml3 MODULE
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    version.rc
    ${CMAKE_CURRENT_BINARY_DIR}/msxml3_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/msxml3.def)
add_pch(msxml3 precomp.h "${PCH_SKIP_SOURCE}")

add_idl_headers(xmlparser_idlheader xmlparser.idl)
add_idl_headers(saxreader_extensions_idlheader saxreader_extensions.idl)
set_module_type(msxml3 win32dll)
target_link_libraries(msxml3 libxml2 iconv-static uuid wine wine_dll_register zlib)

if(MSVC)
    target_compile_options(msxml3 PRIVATE /FIwine/typeof.h /FImsvc.h)

    # Disable warning C4090: 'function': different 'const' qualifiers
    target_compile_options(msxml3 PRIVATE /wd4090)

    if(ARCH STREQUAL "amd64" OR ARCH STREQUAL "arm64")
        # Disable warning C4267: 'function': conversion from 'size_t' to 'UINT', possible loss of data
        target_compile_options(msxml3 PRIVATE "/wd4267")
    endif()
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    target_compile_options(msxml3 PRIVATE -Wno-incompatible-function-pointer-types)
endif()

add_importlibs(msxml3 libxslt urlmon ws2_32 shlwapi oleaut32 ole32 user32 msvcrt kernel32 ntdll)
add_dependencies(msxml3 xmlparser_idlheader saxreader_extensions_idlheader msxml3_msg stdole2) # msxml3_v1.tlb needs stdole2.tlb
add_cd_file(TARGET msxml3 DESTINATION reactos/system32 FOR all)
set_wine_module_FIXME(msxml3) # CORE-5743: No ARRAY_SIZE and CONST_VTABLE
