# Defines the enum types of the ScheduledTasks module (RunLevel, LogonType, MultipleInstances, Compatibility,
# ProcessTokenSidType, State) in the namespace the Windows module uses for them, once per process. They are built with
# System.Reflection.Emit, so no C# is compiled. Kept in a nested module so the types exist before the main module binds them.
$ns = 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask'
$defs = [ordered]@{
    StateEnum               = [ordered]@{ Unknown = 0; Disabled = 1; Queued = 2; Ready = 3; Running = 4 }
    RunLevelEnum            = [ordered]@{ Limited = 0; Highest = 1 }
    LogonTypeEnum           = [ordered]@{ None = 0; Password = 1; S4U = 2; Interactive = 3; Group = 4; ServiceAccount = 5; InteractiveOrPassword = 6 }
    MultipleInstancesEnum   = [ordered]@{ Parallel = 0; Queue = 1; IgnoreNew = 2 }
    CompatibilityEnum       = [ordered]@{ At = 0; V1 = 1; Vista = 2; Win7 = 3; Win8 = 4 }
    ProcessTokenSidTypeEnum = [ordered]@{ None = 0; Unrestricted = 1; Default = 2 }
}
$module = $null
foreach ($name in $defs.Keys) {
    if ("$ns.$name" -as [type]) { continue }
    if ($null -eq $module) {
        $asm = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly([System.Reflection.AssemblyName]::new('Nitro.ScheduledTasks.GeneratedTypes'), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $module = $asm.DefineDynamicModule('Nitro.ScheduledTasks.GeneratedTypes')
    }
    $eb = $module.DefineEnum("$ns.$name", [System.Reflection.TypeAttributes]::Public, [int])
    foreach ($member in $defs[$name].Keys) { $null = $eb.DefineLiteral($member, [int]$defs[$name][$member]) }
    $null = $eb.CreateType()
}
