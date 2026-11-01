# Storage for ReactOS-Nitro: a clean-room PowerShell 7 script module (read side, plus Set-Volume -NewFileSystemLabel). Same module, cmdlet and parameter names and the
# same object shape as the Windows Storage module: the output objects carry the
# Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_* type names and the properties in the order
# Windows reports them. The data comes from kernel32 and the disk IOCTLs through Nitro.Storage.Native (NitroStorageNative.cs).

Set-StrictMode -Version 2.0

function Write-StorageErrors {
    param([System.Management.Automation.PSCmdlet]$Cmdlet, $Errors)
    foreach ($e in $Errors) { $Cmdlet.WriteError($e) }
}

# -AsJob is accepted for parameter parity only; it is not implemented (nothing here is remote or slow).
function Test-StorageAsJob {
    param([System.Management.Automation.PSCmdlet]$Cmdlet, [bool]$AsJob)
    if ($AsJob) {
        $e = [System.Management.Automation.ErrorRecord]::new([System.NotSupportedException]::new('The -AsJob parameter is not supported by this implementation.'), 'AsJobNotSupported', 'NotImplemented', $null)
        $Cmdlet.WriteError($e)
    }
    $AsJob
}

function Get-Volume {
    [CmdletBinding(DefaultParameterSetName = 'ByDriveLetter')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Volume')]
    param(
        [Parameter(ParameterSetName = 'ById', ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')][ValidateNotNull()][string[]]$ObjectId,

        [Parameter(ParameterSetName = 'ByUniqueId', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$UniqueId,

        [Parameter(ParameterSetName = 'ByPaths', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$Path,

        [Parameter(ParameterSetName = 'ByLabel', ValueFromPipelineByPropertyName = $true)]
        [Alias('FriendlyName')][ValidateNotNull()][string[]]$FileSystemLabel,

        [Parameter(ParameterSetName = 'ByDriveLetter', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][char[]]$DriveLetter,

        [Parameter(ParameterSetName = 'ByPartition', ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_Partition')][ValidateNotNull()][object]$Partition,

        [Parameter(ParameterSetName = 'ByFilePath', ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')][ValidateNotNullOrEmpty()][string]$FilePath,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-StorageAsJob $PSCmdlet $AsJob) { return }
        $q = [Nitro.Storage.Query]::new()
        $items = [Nitro.Storage.Native]::Volumes()
        if ($PSBoundParameters.ContainsKey('ObjectId')) { $q.Add('ObjectId', $ObjectId, $false) }
        if ($PSBoundParameters.ContainsKey('UniqueId')) { $q.Add('UniqueId', $UniqueId, $false) }
        if ($PSBoundParameters.ContainsKey('Path')) { $q.Add('Path', $Path, $false) }
        if ($PSBoundParameters.ContainsKey('FileSystemLabel')) { $q.Add('FileSystemLabel', $FileSystemLabel, $true) }
        if ($PSBoundParameters.ContainsKey('DriveLetter')) { $q.Add('DriveLetter', $DriveLetter, $false) }
        if ($PSBoundParameters.ContainsKey('FilePath')) {
            $vol = [Nitro.Storage.Native]::VolumeOfFile($FilePath)
            $items = $items.Where({ $_['Path'] -eq $vol })
        }
        if ($PSBoundParameters.ContainsKey('Partition')) {
            $paths = @($Partition.AccessPaths)
            $items = $items.Where({ $paths -contains $_['Path'] })
        }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $found = $q.Run($items, 'MSFT_Volume', $true, $errors)
        foreach ($d in $found) { [Nitro.Storage.Builder]::Create('MSFT_Volume', $d) }
        Write-StorageErrors $PSCmdlet $errors
    }
}

function Get-Disk {
    [CmdletBinding(DefaultParameterSetName = 'ByNumber')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Disk')]
    param(
        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Alias('Id')][ValidateNotNull()][string[]]$UniqueId,

        [Parameter(ParameterSetName = 'ByName')]
        [ValidateNotNull()][string[]]$FriendlyName,

        [Parameter(ParameterSetName = 'ByName')]
        [ValidateNotNull()][string[]]$SerialNumber,

        [Parameter(ParameterSetName = 'ByPath', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$Path,

        [Parameter(ParameterSetName = 'ByNumber', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('DeviceId')][ValidateNotNull()][uint32[]]$Number,

        [Parameter(ParameterSetName = 'ByPartition', ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_Partition')][ValidateNotNull()][object]$Partition,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-StorageAsJob $PSCmdlet $AsJob) { return }
        $q = [Nitro.Storage.Query]::new()
        if ($PSBoundParameters.ContainsKey('UniqueId')) { $q.Add('UniqueId', $UniqueId, $false) }
        if ($PSBoundParameters.ContainsKey('FriendlyName')) { $q.Add('FriendlyName', $FriendlyName, $true) }
        if ($PSBoundParameters.ContainsKey('SerialNumber')) { $q.Add('SerialNumber', $SerialNumber, $true) }
        if ($PSBoundParameters.ContainsKey('Path')) { $q.Add('Path', $Path, $false) }
        if ($PSBoundParameters.ContainsKey('Number')) { $q.Add('Number', $Number, $false) }
        if ($PSBoundParameters.ContainsKey('Partition')) { $q.Add('Number', @([uint32]$Partition.DiskNumber), $false) }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $found = $q.Run([Nitro.Storage.Native]::Disks(), 'MSFT_Disk', ($PSCmdlet.ParameterSetName -ne 'ByPartition'), $errors)
        foreach ($d in $found) { [Nitro.Storage.Builder]::Create('MSFT_Disk', $d) }
        Write-StorageErrors $PSCmdlet $errors
    }
}

function Get-Partition {
    [CmdletBinding(DefaultParameterSetName = 'ByUniqueId')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_Partition')]
    param(
        [Parameter(ParameterSetName = 'ByUniqueId', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$UniqueId,

        [Parameter(ParameterSetName = 'ById', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('DiskPath')][ValidateNotNull()][string[]]$DiskId,

        [Parameter(ParameterSetName = 'ById', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][uint64[]]$Offset,

        [Parameter(ParameterSetName = 'ByNumber', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][uint32[]]$DiskNumber,

        [Parameter(ParameterSetName = 'ByNumber', Position = 1)]
        [Alias('Number')][ValidateNotNull()][uint32[]]$PartitionNumber,

        [Parameter(ParameterSetName = 'ByDriveLetter', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][char[]]$DriveLetter,

        [Parameter(ParameterSetName = 'ByDisk', ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_Disk')][ValidateNotNull()][object]$Disk,

        [Parameter(ParameterSetName = 'ByVolume', ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_Volume')][ValidateNotNull()][object]$Volume,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-StorageAsJob $PSCmdlet $AsJob) { return }
        $q = [Nitro.Storage.Query]::new()
        $items = [Nitro.Storage.Native]::Partitions()
        if ($PSBoundParameters.ContainsKey('UniqueId')) { $q.Add('UniqueId', $UniqueId, $false) }
        if ($PSBoundParameters.ContainsKey('DiskId')) { $q.Add('DiskId', $DiskId, $false) }
        if ($PSBoundParameters.ContainsKey('Offset')) { $q.Add('Offset', $Offset, $false) }
        if ($PSBoundParameters.ContainsKey('DiskNumber')) { $q.Add('DiskNumber', $DiskNumber, $false) }
        if ($PSBoundParameters.ContainsKey('PartitionNumber')) { $q.Add('PartitionNumber', $PartitionNumber, $false) }
        if ($PSBoundParameters.ContainsKey('DriveLetter')) { $q.Add('DriveLetter', $DriveLetter, $false) }
        if ($PSBoundParameters.ContainsKey('Disk')) { $q.Add('DiskNumber', @([uint32]$Disk.Number), $false) }
        if ($PSBoundParameters.ContainsKey('Volume')) {
            $vp = $Volume.Path
            $items = $items.Where({ $_['AccessPaths'] -and ($_['AccessPaths'] -contains $vp) })
        }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $report = $PSCmdlet.ParameterSetName -notin 'ByDisk', 'ByVolume'
        $found = $q.Run($items, 'MSFT_Partition', $report, $errors)
        foreach ($d in $found) { [Nitro.Storage.Builder]::Create('MSFT_Partition', $d) }
        Write-StorageErrors $PSCmdlet $errors
    }
}

function Get-PhysicalDisk {
    [CmdletBinding(DefaultParameterSetName = 'ByUniqueId')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/Microsoft/Windows/Storage/MSFT_PhysicalDisk')]
    param(
        [Parameter(ParameterSetName = 'ByUniqueId', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')][ValidateNotNullOrEmpty()][string]$UniqueId,

        [Parameter(ParameterSetName = 'ByObjectId', ValueFromPipeline = $true)]
        [Alias('PhysicalDiskObjectId')][ValidateNotNullOrEmpty()][string]$ObjectId,

        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [ValidateNotNullOrEmpty()][string]$DeviceNumber,

        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()][string]$FriendlyName,

        [Parameter(ParameterSetName = 'ByName', Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()][string]$SerialNumber,

        [Parameter(ParameterSetName = 'ByInputObject', Mandatory = $true, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_PhysicalDisk')][ValidateNotNullOrEmpty()][object]$InputObject,

        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Parameter(ParameterSetName = 'ByObjectId')]
        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [Parameter(ParameterSetName = 'ByName')]
        [ValidateSet('Unknown', 'AutoSelect', 'ManualSelect', 'HotSpare', 'Retired', 'Journal')][string]$Usage,

        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Parameter(ParameterSetName = 'ByObjectId')]
        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [Parameter(ParameterSetName = 'ByName')]
        [string]$Description,

        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Parameter(ParameterSetName = 'ByObjectId')]
        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [Parameter(ParameterSetName = 'ByName')]
        [string]$Manufacturer,

        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Parameter(ParameterSetName = 'ByObjectId')]
        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [Parameter(ParameterSetName = 'ByName')]
        [string]$Model,

        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Parameter(ParameterSetName = 'ByObjectId')]
        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [Parameter(ParameterSetName = 'ByName')]
        [bool]$CanPool,

        [Parameter(ParameterSetName = 'ByUniqueId')]
        [Parameter(ParameterSetName = 'ByObjectId')]
        [Parameter(ParameterSetName = 'ByDeviceNumber')]
        [Parameter(ParameterSetName = 'ByName')]
        [ValidateSet('Healthy', 'Warning', 'Unhealthy', 'Unknown')][string]$HealthStatus,

        [Alias('Session')][object]$CimSession
    )
    process {
        $q = [Nitro.Storage.Query]::new()
        if ($PSBoundParameters.ContainsKey('UniqueId')) { $q.Add('UniqueId', $UniqueId, $false) }
        if ($PSBoundParameters.ContainsKey('ObjectId')) { $q.Add('ObjectId', $ObjectId, $false) }
        if ($PSBoundParameters.ContainsKey('DeviceNumber')) { $q.Add('DeviceId', $DeviceNumber, $false) }
        if ($PSBoundParameters.ContainsKey('FriendlyName')) { $q.Add('FriendlyName', $FriendlyName, $true) }
        if ($PSBoundParameters.ContainsKey('SerialNumber')) { $q.Add('SerialNumber', $SerialNumber, $true) }
        if ($PSBoundParameters.ContainsKey('InputObject')) { $q.Add('UniqueId', $InputObject.UniqueId, $false) }
        if ($PSBoundParameters.ContainsKey('Usage')) {
            $q.Add('Usage', @{ Unknown = 'Unknown'; AutoSelect = 'Auto-Select'; ManualSelect = 'Manual-Select'; HotSpare = 'Hot Spare'; Retired = 'Retired'; Journal = 'Journal' }[$Usage], $false)
        }
        if ($PSBoundParameters.ContainsKey('Description')) { $q.Add('Description', $Description, $false) }
        if ($PSBoundParameters.ContainsKey('Manufacturer')) { $q.Add('Manufacturer', $Manufacturer, $false) }
        if ($PSBoundParameters.ContainsKey('Model')) { $q.Add('Model', $Model, $false) }
        if ($PSBoundParameters.ContainsKey('CanPool')) { $q.Add('CanPool', $CanPool, $false) }
        if ($PSBoundParameters.ContainsKey('HealthStatus')) { $q.Add('HealthStatus', $HealthStatus, $false) }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $found = $q.Run([Nitro.Storage.Native]::PhysicalDisks(), 'MSFT_PhysicalDisk', $false, $errors)
        foreach ($d in $found) { [Nitro.Storage.Builder]::Create('MSFT_PhysicalDisk', $d) }
    }
}


# Set-Volume: -NewFileSystemLabel through SetVolumeLabel (the volume is found as Get-Volume finds it; a not-found value is the same
# CmdletizationQuery_NotFound error). Windows returns nothing. -DedupMode is not available: this system has no deduplication.
function Set-Volume {
    [CmdletBinding(DefaultParameterSetName = 'ByDriveLetterSetLabel')]
    param(
        [Parameter(ParameterSetName = 'ByObjectSetDedup', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = 'ByObjectSetLabel', Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()][ValidateNotNull()][object[]]$InputObject,

        [Parameter(ParameterSetName = 'ByDriveLetterSetLabel')]
        [Parameter(ParameterSetName = 'ByLabelSetLabel')]
        [Parameter(ParameterSetName = 'ByPathSetLabel')]
        [Parameter(ParameterSetName = 'ByUniqueIdSetLabel')]
        [Parameter(ParameterSetName = 'ByObjectSetLabel')]
        [Alias('NewFriendlyName')][string]$NewFileSystemLabel,

        [Parameter(ParameterSetName = 'ByUniqueIdSetDedup', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = 'ByUniqueIdSetLabel', Mandatory = $true, ValueFromPipeline = $true)]
        [string]$UniqueId,

        [Parameter(ParameterSetName = 'ByPathSetDedup', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = 'ByPathSetLabel', Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Path,

        [Parameter(ParameterSetName = 'ByLabelSetDedup', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = 'ByLabelSetLabel', Mandatory = $true, ValueFromPipeline = $true)]
        [Alias('FriendlyName')][string]$FileSystemLabel,

        [Parameter(ParameterSetName = 'ByDriveLetterSetDedup', Mandatory = $true, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = 'ByDriveLetterSetLabel', Mandatory = $true, ValueFromPipeline = $true)]
        [char]$DriveLetter,

        [Parameter(ParameterSetName = 'ByDriveLetterSetDedup')]
        [Parameter(ParameterSetName = 'ByLabelSetDedup')]
        [Parameter(ParameterSetName = 'ByPathSetDedup')]
        [Parameter(ParameterSetName = 'ByUniqueIdSetDedup')]
        [Parameter(ParameterSetName = 'ByObjectSetDedup')]
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.SetVolume.DedupMode]$DedupMode,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-StorageAsJob $PSCmdlet $AsJob) { return }
        $set = $PSCmdlet.ParameterSetName
        $all = [Nitro.Storage.Native]::Volumes()
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $targets = @()
        if ($set -like 'ByObject*') {
            foreach ($o in $InputObject) {
                $hit = @($all | Where-Object { $_['UniqueId'] -eq [string]$o.UniqueId -or $_['Path'] -eq [string]$o.Path })
                if ($hit.Count -eq 0) { $errors.Add([Nitro.Storage.Errors]::NotFoundValue('MSFT_Volume', 'UniqueId', [string]$o.UniqueId, [string]$o.UniqueId)) }
                $targets += $hit
            }
        } else {
            $q = [Nitro.Storage.Query]::new()
            if ($set -like 'ByDriveLetter*') { $q.Add('DriveLetter', @($DriveLetter), $false) }
            elseif ($set -like 'ByLabel*') { $q.Add('FileSystemLabel', @($FileSystemLabel), $true) }
            elseif ($set -like 'ByPath*') { $q.Add('Path', @($Path), $false) }
            elseif ($set -like 'ByUniqueId*') { $q.Add('UniqueId', @($UniqueId), $false) }
            $targets = @($q.Run($all, 'MSFT_Volume', $true, $errors))
        }
        Write-StorageErrors $PSCmdlet $errors
        if ($set -like '*SetDedup') {
            if ($PSBoundParameters.ContainsKey('DedupMode') -and $targets.Count -gt 0) {
                $e = [System.Management.Automation.ErrorRecord]::new([System.NotSupportedException]::new('Data deduplication is not available on this system.'), 'DedupNotSupported', 'NotImplemented', $DedupMode)
                $PSCmdlet.WriteError($e)
            }
            return
        }
        if (-not $PSBoundParameters.ContainsKey('NewFileSystemLabel')) { return }
        foreach ($v in $targets) {
            $rc = [Nitro.Storage.Native]::SetLabel([string]$v['Path'], $v['DriveLetter'], $NewFileSystemLabel)
            if ($rc -ne 0) {
                $msg = [System.ComponentModel.Win32Exception]::new($rc).Message
                $ex = try { [Microsoft.Management.Infrastructure.CimException]::new($msg) } catch { [System.InvalidOperationException]::new($msg) }
                $cat = switch ($rc) { 5 { 'PermissionDenied' } 2 { 'ObjectNotFound' } 3 { 'ObjectNotFound' } 87 { 'InvalidArgument' } 123 { 'InvalidArgument' } default { 'NotSpecified' } }
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new($ex, "Windows System Error $rc", $cat, 'MSFT_Volume'))
            }
        }
    }
}

Export-ModuleMember -Function 'Get-Disk', 'Get-Partition', 'Get-PhysicalDisk', 'Get-Volume', 'Set-Volume'
