@{
    RootModule            = 'NitroDiag.psm1'
    ModuleVersion         = '1.0.0.0'
    GUID                  = '5d0c1c0e-3b7a-4c58-8f2e-7a1f43c9b6e2'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'Start-NitroDiag: runs a program under nitrodiag.exe (the compatibility log tool) and returns the path of the report.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @('Start-NitroDiag')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
}
