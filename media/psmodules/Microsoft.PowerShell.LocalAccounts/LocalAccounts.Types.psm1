# Compiles the object model and the netapi32 helper (LocalAccountsNative.cs) once per process.
# Kept in its own nested module so the types exist before the main module's parameter types are bound.
if (-not ('Microsoft.PowerShell.Commands.LocalAccountsNative' -as [type])) {
    $source = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'LocalAccountsNative.cs'))
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}
