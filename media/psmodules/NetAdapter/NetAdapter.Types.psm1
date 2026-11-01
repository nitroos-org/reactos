# Compiles the shared network helper (schemas, native calls, DNS records) once per process.
# Kept in a nested module so the types exist before the main module binds its parameter types. NetAdapter, NetTCPIP and
# DnsClient each carry the same three source files; whichever module loads first compiles them.
if (-not ('Nitro.Net.Native' -as [type])) {
    $sources = foreach ($f in 'NitroNetSpec.g.cs', 'NitroNetNative.cs', 'NitroDns.cs') { Join-Path $PSScriptRoot $f }
    Add-Type -Path $sources -ErrorAction Stop
}
