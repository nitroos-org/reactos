@{
    RootModule            = 'NetTCPIP.psm1'
    NestedModules         = @('NetTCPIP.Types.psm1')
    ModuleVersion         = '1.0.0.0'
    GUID                  = '2d0b6c7f-16a0-4185-843f-ae47b6db4551'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'TCP/IP cmdlets for PowerShell 7 on ReactOS-Nitro: a clean-room script module over iphlpapi with the cmdlet names, parameters and output shapes of the Windows NetTCPIP module (read side: Get-NetIPAddress, Get-NetIPInterface, Get-NetRoute, Get-NetTCPConnection, Get-NetUDPEndpoint, Get-NetIPConfiguration, Test-NetConnection).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FormatsToProcess      = @('NetTCPIP.format.ps1xml')
    FunctionsToExport     = @(
        'Get-NetIPAddress', 'Get-NetIPConfiguration', 'Get-NetIPInterface', 'Get-NetRoute', 'Get-NetTCPConnection',
        'Get-NetUDPEndpoint', 'Test-NetConnection')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @('gip', 'TNC')
}
