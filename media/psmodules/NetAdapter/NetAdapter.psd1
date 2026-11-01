@{
    RootModule            = 'NetAdapter.psm1'
    NestedModules         = @('NetAdapter.Types.psm1')
    ModuleVersion         = '2.0.0.0'
    GUID                  = '1042b422-63a8-4016-a6d6-293e19e8f8a6'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'Network adapter cmdlets for PowerShell 7 on ReactOS-Nitro: a clean-room script module over iphlpapi with the cmdlet names, parameters and output shapes of the Windows NetAdapter module (read side only).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FormatsToProcess      = @('NetAdapter.format.ps1xml')
    FunctionsToExport     = @('Get-NetAdapter', 'Get-NetAdapterStatistics')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
}
