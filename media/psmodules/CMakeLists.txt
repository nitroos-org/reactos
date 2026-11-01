# PowerShell 7 script modules. PowerShell 7 (amd64, installed by featmgr) searches
# %SystemRoot%\system32\WindowsPowerShell\v1.0\Modules, where Windows keeps the modules that ship with the OS.
# Each module folder holds the sources and its Pester tests; only the files PowerShell loads are installed.
if(ARCH STREQUAL "amd64")
    set(_LA_SRC ${CMAKE_CURRENT_SOURCE_DIR}/Microsoft.PowerShell.LocalAccounts)
    set(_LA_DST reactos/system32/WindowsPowerShell/v1.0/Modules/Microsoft.PowerShell.LocalAccounts/1.0.0.0)
    foreach(_la_file
            Microsoft.PowerShell.LocalAccounts.psd1
            Microsoft.PowerShell.LocalAccounts.psm1
            LocalAccounts.Types.psm1
            LocalAccounts.format.ps1xml
            LocalAccountsNative.cs)
        add_cd_file(FILE ${_LA_SRC}/${_la_file} DESTINATION ${_LA_DST} FOR all)
    endforeach()
endif()
