@{
    RootModule            = 'Microsoft.PowerShell.LocalAccounts.psm1'
    NestedModules         = @('LocalAccounts.Types.psm1')
    ModuleVersion         = '1.0.0.0'
    GUID                  = 'c6f1d6f1-5a0e-4b5e-9b0e-7a2f3d8c4e11'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'Local user and group cmdlets for PowerShell 7 on ReactOS-Nitro: a clean-room script module over netapi32 and advapi32 with the cmdlet names, parameters and output types of the Windows Microsoft.PowerShell.LocalAccounts module.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Core')
    FormatsToProcess      = @('LocalAccounts.format.ps1xml')
    FunctionsToExport     = @(
        'Add-LocalGroupMember', 'Disable-LocalUser', 'Enable-LocalUser', 'Get-LocalGroup', 'Get-LocalGroupMember',
        'Get-LocalUser', 'New-LocalGroup', 'New-LocalUser', 'Remove-LocalGroup', 'Remove-LocalGroupMember',
        'Remove-LocalUser', 'Rename-LocalGroup', 'Rename-LocalUser', 'Set-LocalGroup', 'Set-LocalUser')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @(
        'algm', 'dlu', 'elu', 'glg', 'glgm', 'glu', 'nlg', 'nlu', 'rlg', 'rlgm', 'rlu', 'rnlg', 'rnlu', 'slg', 'slu')
}
