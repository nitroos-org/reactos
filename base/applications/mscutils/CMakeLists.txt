
add_subdirectory(certmgr)
add_subdirectory(devmgmt)
add_subdirectory(diskmgmt)
add_subdirectory(eventvwr)
add_subdirectory(servman)
add_subdirectory(wfadv)

list(APPEND MSC_FILES
    certlm.msc
    certmgr.msc
    compmgmt.msc
    devmgmt.msc
    diskmgmt.msc
    eventvwr.msc
    lusrmgr.msc
    services.msc
    wf.msc)

foreach(item ${MSC_FILES})
    add_cd_file(FILE "${CMAKE_CURRENT_SOURCE_DIR}/${item}" DESTINATION reactos/system32 FOR all)
endforeach(item)
