
spec2def(wminet_utils.dll wminet_utils.spec)

list(APPEND SOURCE
    wminet_utils.c
    wminet_utils.rc
    ${CMAKE_CURRENT_BINARY_DIR}/wminet_utils.def)

add_library(wminet_utils MODULE ${SOURCE})
set_module_type(wminet_utils win32dll)
target_link_libraries(wminet_utils uuid oldnames)
add_importlibs(wminet_utils ole32 oleaut32 advapi32 msvcrt kernel32 ntdll)
# Where the .NET Framework 4.x puts it: <HKLM\SOFTWARE\Microsoft\.NETFramework\InstallRoot>\v4.0.30319.
# InstallRoot is Framework64 for 64-bit processes when the image has WoW64 (syssetup sets it, see
# SetWow64NetFrameworkInstallRoots), and Framework otherwise (syssetup.inf, and the 32-bit view). The file
# version is 4.0.30319.0, below every .NET Framework 4.x release, so installing the real .NET Framework
# replaces this file.
if(ARCH STREQUAL "amd64" AND BUILD_WOW64_ENABLED)
    add_cd_file(TARGET wminet_utils DESTINATION reactos/Microsoft.NET/Framework64/v4.0.30319 FOR all)
else()
    add_cd_file(TARGET wminet_utils DESTINATION reactos/Microsoft.NET/Framework/v4.0.30319 FOR all)
endif()
