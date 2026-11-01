@{
    RootModule            = 'Storage.psm1'
    NestedModules         = @('Storage.Types.psm1')
    ModuleVersion         = '2.0.0.0'
    GUID                  = '6866615e-38d3-4dc6-b235-76a6fa5e2159'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'Storage cmdlets for PowerShell 7 on ReactOS-Nitro: a clean-room script module over the kernel32 volume calls and the disk IOCTLs with the cmdlet names, parameters and output shapes of the Windows Storage module (Get-Volume, Get-Disk, Get-Partition, Get-PhysicalDisk, Set-Volume -NewFileSystemLabel).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FormatsToProcess      = @('Storage.format.ps1xml')
    FunctionsToExport     = @('Get-Disk', 'Get-Partition', 'Get-PhysicalDisk', 'Get-Volume', 'Set-Volume')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
}
