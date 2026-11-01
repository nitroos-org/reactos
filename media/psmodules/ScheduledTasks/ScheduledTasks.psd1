@{
    RootModule            = 'ScheduledTasks.psm1'
    NestedModules         = @('ScheduledTasks.Types.psm1')
    ModuleVersion         = '1.0.0.0'
    GUID                  = '0b1f6c5e-7a3d-4e29-9d41-6b8a52c3f7d0'
    Author                = 'ReactOS-Nitro'
    CompanyName           = 'ReactOS-Nitro'
    Copyright             = 'ReactOS-Nitro contributors. GNU GPL v2 or later.'
    Description           = 'ScheduledTasks cmdlets for PowerShell 7 on ReactOS-Nitro: a clean-room script module over the Schedule.Service COM object with the cmdlet names, parameters and output shapes of the Windows ScheduledTasks module.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FormatsToProcess      = @('ScheduledTasks.format.ps1xml')
    FunctionsToExport     = @('Disable-ScheduledTask', 'Enable-ScheduledTask', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo', 'New-ScheduledTask',
                              'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'New-ScheduledTaskTrigger',
                              'Register-ScheduledTask', 'Start-ScheduledTask', 'Stop-ScheduledTask', 'Unregister-ScheduledTask')
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
}
