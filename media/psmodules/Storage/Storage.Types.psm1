# Compiles the Storage helper (native calls, object builder, query filter) once per process.
# Kept in a nested module so the types exist before the main module binds them. The types live in Nitro.Storage, apart from
# the Nitro.Net helper of the network modules.
if (-not ('Nitro.Storage.Native' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'NitroStorageNative.cs') -ErrorAction Stop
}
