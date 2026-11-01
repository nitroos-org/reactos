@{
    RootModule            = 'DnsClient.psm1'
    NestedModules         = @('DnsClient.Types.psm1')
    ModuleVersion         = '1.0.0.0'
    GUID                  = '5696d5ef-fa2d-4997-94f1-0bc13daa2ac5'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'DNS client cmdlets for PowerShell 7 on ReactOS-Nitro: a clean-room script module over dnsapi and iphlpapi with the cmdlet names, parameters and output shapes of the Windows DnsClient module (Resolve-DnsName, Get-DnsClientServerAddress, Set-DnsClientServerAddress).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    TypesToProcess        = @('DnsClient.types.ps1xml')
    FormatsToProcess      = @('DnsClient.format.ps1xml')
    FunctionsToExport     = @('Get-DnsClientServerAddress', 'Resolve-DnsName', 'Set-DnsClientServerAddress')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
}
