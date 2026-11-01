# PowerShell 7 script modules. PowerShell 7 (amd64, installed by featmgr) searches
# %SystemRoot%\system32\WindowsPowerShell\v1.0\Modules, where Windows keeps the modules that ship with the OS.
# Each module folder holds the sources and its Pester tests; only the files PowerShell loads are installed.
if(ARCH STREQUAL "amd64")
    set(_PSM_DST reactos/system32/WindowsPowerShell/v1.0/Modules)

    set(_LA_SRC ${CMAKE_CURRENT_SOURCE_DIR}/Microsoft.PowerShell.LocalAccounts)
    set(_LA_DST ${_PSM_DST}/Microsoft.PowerShell.LocalAccounts/1.0.0.0)
    foreach(_la_file
            Microsoft.PowerShell.LocalAccounts.psd1
            Microsoft.PowerShell.LocalAccounts.psm1
            LocalAccounts.Types.psm1
            LocalAccounts.format.ps1xml
            LocalAccountsNative.cs)
        add_cd_file(FILE ${_LA_SRC}/${_la_file} DESTINATION ${_LA_DST} FOR all)
    endforeach()

    # NetAdapter, NetTCPIP and DnsClient share one helper (schemas, iphlpapi/dnsapi calls, DNS records): each module
    # folder carries a copy of the three source files and the first module to load compiles them.
    set(_NET_SHARED
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/NitroNetSpec.g.cs
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/NitroNetNative.cs
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/NitroDns.cs)
    foreach(_net_module
            NetAdapter/2.0.0.0:NetAdapter
            NetTCPIP/1.0.0.0:NetTCPIP
            DnsClient/1.0.0.0:DnsClient)
        string(REPLACE ":" ";" _net_parts ${_net_module})
        list(GET _net_parts 0 _net_dir)
        list(GET _net_parts 1 _net_name)
        string(REGEX REPLACE "/.*$" "" _net_src_dir ${_net_dir})
        set(_net_files
            ${_net_name}.psd1
            ${_net_name}.psm1
            ${_net_name}.Types.psm1
            ${_net_name}.format.ps1xml)
        if(_net_name STREQUAL "DnsClient")
            list(APPEND _net_files DnsClient.types.ps1xml)
        endif()
        foreach(_net_file ${_net_files})
            add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/${_net_src_dir}/${_net_file} DESTINATION ${_PSM_DST}/${_net_dir} FOR all)
        endforeach()
        foreach(_net_file ${_NET_SHARED})
            add_cd_file(FILE ${_net_file} DESTINATION ${_PSM_DST}/${_net_dir} FOR all)
        endforeach()
    endforeach()

    # Storage (Get-Volume, Get-Disk, Get-Partition, Get-PhysicalDisk): one native helper in its own namespace, shipped beside the module.
    foreach(_stor_file
            Storage.psd1
            Storage.psm1
            Storage.Types.psm1
            Storage.format.ps1xml
            NitroStorageNative.cs)
        add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/Storage/${_stor_file} DESTINATION ${_PSM_DST}/Storage/2.0.0.0 FOR all)
    endforeach()
endif()
