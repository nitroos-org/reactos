
include_directories(${REACTOS_SOURCE_DIR}/dll/win32/ieframe)

list(APPEND SOURCE
    AttachmentExecute.cpp
    DownloadNames.c
    FileDownload.c
    InternetShortcut.c
    MRUList.cpp
    WinList.cpp
    testlist.c
    ${REACTOS_SOURCE_DIR}/dll/win32/ieframe/download_name.c)

add_executable(shdocvw_apitest ${SOURCE})
set_module_type(shdocvw_apitest win32cui)
target_link_libraries(shdocvw_apitest ${PSEH_LIB} uuid)
add_importlibs(shdocvw_apitest shlwapi shell32 oleaut32 ole32 urlmon user32 advapi32 ws2_32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET shdocvw_apitest)
