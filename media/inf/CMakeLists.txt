
list(APPEND INF_FILES
    audio.inf
    battery.inf
    bda.inf
    bth.inf
    c_image.inf
    display.inf
    fdc.inf
    flpydisk.inf
    hal.inf
    hdc.inf
    input.inf
    keyboard.inf
    ks.inf
    kscaptur.inf
    legcydrv.inf
    machine.inf
    monitor.inf
    msmouse.inf
    ndisuio.inf
    NET_NIC.inf
    nettcpip.inf
    ports.inf
    scsi.inf
    shortcuts.inf
    unknown.inf
    usb.inf
    usbport.inf
    volume.inf
    wdmaudio.inf
    wmiacpi.inf)

list(APPEND UTF8_INF_FILES
    defltwk.inf
    font.inf
    intl.inf
    layout.inf)

# module name is used for a custom target creation, so we can put any unique name here
add_driver_inf(media_inf ${INF_FILES})

foreach(item ${UTF8_INF_FILES})
    add_cd_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/${item}" DESTINATION reactos/inf FOR all)
endforeach(item)

set(SYSSETUP_INF ${CMAKE_CURRENT_SOURCE_DIR}/syssetup.inf)

if(DLL_EXPORT_VERSION GREATER_EQUAL 0x601)
    # The Media Foundation DLLs and explorerframe are only built at this level, and setup shows an
    # error box for every DLL on the registration list that is missing, so they are listed only here.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/syssetup.inf)
    file(READ ${CMAKE_CURRENT_SOURCE_DIR}/syssetup.inf SYSSETUP_CONTENT)
    # file(READ) turns the CRLF line ends into LF; they are restored when the file is written
    string(REPLACE "11,,fontext.dll,1\n" "11,,evr.dll,1\n11,,explorerframe.dll,1\n11,,fontext.dll,1\n" SYSSETUP_CONTENT "${SYSSETUP_CONTENT}")
    string(REPLACE "11,,mlang.dll,1\n" "11,,mf.dll,1\n11,,mfreadwrite.dll,1\n11,,mlang.dll,1\n" SYSSETUP_CONTENT "${SYSSETUP_CONTENT}")
    if(NOT SYSSETUP_CONTENT MATCHES "11,,explorerframe.dll,1" OR NOT SYSSETUP_CONTENT MATCHES "11,,evr.dll,1" OR NOT SYSSETUP_CONTENT MATCHES "11,,mfreadwrite.dll,1")
        message(FATAL_ERROR "syssetup.inf lost the anchors for the Media Foundation DLLs and explorerframe")
    endif()
    set(SYSSETUP_INF ${CMAKE_CURRENT_BINARY_DIR}/syssetup.inf)
    string(REPLACE "\n" "\r\n" SYSSETUP_CONTENT "${SYSSETUP_CONTENT}")
    file(WRITE ${SYSSETUP_INF} "${SYSSETUP_CONTENT}")
endif()

if(DLL_EXPORT_VERSION LESS 0x601)
    # vbscript.dll is only built from 0x601 on and wbemprox.dll from 0x600 on; setup shows an error box
    # for every DLL on the registration list that is missing, so they are not listed below that
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/syssetup.inf)
    file(READ ${CMAKE_CURRENT_SOURCE_DIR}/syssetup.inf SYSSETUP_CONTENT)
    string(REPLACE "11,,vbscript.dll,1\n" "" SYSSETUP_CONTENT "${SYSSETUP_CONTENT}")
    if(DLL_EXPORT_VERSION LESS 0x600)
        string(REPLACE "11,wbem,wbemprox.dll,1\n" "" SYSSETUP_CONTENT "${SYSSETUP_CONTENT}")
    endif()
    set(SYSSETUP_INF ${CMAKE_CURRENT_BINARY_DIR}/syssetup.inf)
    string(REPLACE "\n" "\r\n" SYSSETUP_CONTENT "${SYSSETUP_CONTENT}")
    file(WRITE ${SYSSETUP_INF} "${SYSSETUP_CONTENT}")
endif()

add_cd_file(FILE ${SYSSETUP_INF} DESTINATION reactos/inf FOR all)
