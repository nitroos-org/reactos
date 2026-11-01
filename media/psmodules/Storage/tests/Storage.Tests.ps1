# Pester 4 tests of the Storage module (Get-Volume, Get-Disk, Get-Partition, Get-PhysicalDisk).
# Run in the nitro guest against the installed module (loaded BY NAME) and, read-only, on the Windows oracle against the real
# module (set STOR_ORACLE=1): the expectations are the measured Windows shapes, so a pass on both is the parity check.
# Rows that only make sense on one system are skipped on the other.
$script:Oracle = [bool]$env:STOR_ORACLE
Import-Module Storage -Force -ErrorAction Stop

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class StorTestK32 {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetDiskFreeSpaceExW(string dir, out ulong avail, out ulong total, out ulong free);
}
'@

$P = 'Microsoft.Management.Infrastructure.CimInstance'
$NS = "$P#ROOT/Microsoft/Windows/Storage"
$hidden = @('CimClass', 'CimInstanceProperties', 'CimSystemProperties')
$pt = 'ObjectId', 'PassThroughClass', 'PassThroughIds', 'PassThroughNamespace', 'PassThroughServer', 'UniqueId'
$script:Shape = @{
    Volume = @{
        Cls = 'MSFT_Volume'
        Chain = @("$NS/MSFT_Volume", "$NS/MSFT_StorageObject", "$P#MSFT_Volume", "$P#MSFT_StorageObject", $P, 'System.Object')
        Props = @('OperationalStatus', 'HealthStatus', 'DriveType', 'FileSystemType', 'DedupMode') + $pt + @('AllocationUnitSize', 'DriveLetter', 'FileSystem', 'FileSystemLabel', 'Path', 'Size', 'SizeRemaining', 'PSComputerName')
        Types = @{ AllocationUnitSize = 'System.UInt32'; DriveLetter = 'System.Char'; Size = 'System.UInt64'; SizeRemaining = 'System.UInt64'
                   OperationalStatus = 'System.String'; HealthStatus = 'System.String'; DriveType = 'System.String'; FileSystemType = 'System.String'; DedupMode = 'System.String'
                   FileSystem = 'System.String'; FileSystemLabel = 'System.String'; Path = 'System.String'; UniqueId = 'System.String'; ObjectId = 'System.String' }
        Table = @('DriveLetter', 'FriendlyName', 'FileSystemType', 'DriveType', 'HealthStatus', 'OperationalStatus', 'SizeRemaining', 'Size')
    }
    Disk = @{
        Cls = 'MSFT_Disk'
        Chain = @("$NS/MSFT_Disk", "$NS/MSFT_StorageObject", "$P#MSFT_Disk", "$P#MSFT_StorageObject", $P, 'System.Object')
        Props = @('DiskNumber', 'PartitionStyle', 'ProvisioningType', 'OperationalStatus', 'HealthStatus', 'BusType', 'UniqueIdFormat', 'OfflineReason') + $pt + @(
            'AdapterSerialNumber', 'AllocatedSize', 'BootFromDisk', 'FirmwareVersion', 'FriendlyName', 'Guid', 'IsBoot', 'IsClustered', 'IsHighlyAvailable', 'IsOffline', 'IsReadOnly',
            'IsScaleOut', 'IsSystem', 'LargestFreeExtent', 'Location', 'LogicalSectorSize', 'Manufacturer', 'Model', 'Number', 'NumberOfPartitions', 'Path', 'PhysicalSectorSize',
            'SerialNumber', 'Signature', 'Size', 'PSComputerName')
        Types = @{ DiskNumber = 'System.UInt32'; Number = 'System.UInt32'; LogicalSectorSize = 'System.UInt32'; PhysicalSectorSize = 'System.UInt32'; NumberOfPartitions = 'System.UInt32'
                   Signature = 'System.UInt32'; AllocatedSize = 'System.UInt64'; LargestFreeExtent = 'System.UInt64'; Size = 'System.UInt64'
                   BootFromDisk = 'System.Boolean'; IsBoot = 'System.Boolean'; IsClustered = 'System.Boolean'; IsHighlyAvailable = 'System.Boolean'; IsOffline = 'System.Boolean'
                   IsReadOnly = 'System.Boolean'; IsScaleOut = 'System.Boolean'; IsSystem = 'System.Boolean'
                   PartitionStyle = 'System.String'; ProvisioningType = 'System.String'; OperationalStatus = 'System.String'; HealthStatus = 'System.String'; BusType = 'System.String'
                   UniqueIdFormat = 'System.String'; FriendlyName = 'System.String'; Path = 'System.String'; UniqueId = 'System.String' }
        Table = @('Number', 'Friendly', 'Name', 'Serial', 'Number', 'HealthStatus', 'OperationalStatus', 'Total', 'Size', 'Partition')
    }
    Partition = @{
        Cls = 'MSFT_Partition'
        Chain = @("$NS/MSFT_Partition", "$NS/MSFT_StorageObject", "$P#MSFT_Partition", "$P#MSFT_StorageObject", $P, 'System.Object')
        Props = @('OperationalStatus', 'Type', 'DiskPath') + $pt + @('AccessPaths', 'DiskId', 'DiskNumber', 'DriveLetter', 'GptType', 'Guid', 'IsActive', 'IsBoot', 'IsDAX', 'IsHidden',
            'IsOffline', 'IsReadOnly', 'IsShadowCopy', 'IsSystem', 'MbrType', 'NoDefaultDriveLetter', 'Offset', 'PartitionNumber', 'Size', 'TransitionState', 'PSComputerName')
        Types = @{ AccessPaths = 'System.String[]'; DiskNumber = 'System.UInt32'; PartitionNumber = 'System.UInt32'; DriveLetter = 'System.Char'; Offset = 'System.UInt64'; Size = 'System.UInt64'
                   MbrType = 'System.UInt16'; TransitionState = 'System.UInt16'; IsActive = 'System.Boolean'; IsBoot = 'System.Boolean'; IsHidden = 'System.Boolean'; IsOffline = 'System.Boolean'
                   IsSystem = 'System.Boolean'; OperationalStatus = 'System.String'; Type = 'System.String'; DiskPath = 'System.String'; DiskId = 'System.String'; UniqueId = 'System.String' }
        Table = @('PartitionNumber', 'DriveLetter', 'Offset', 'Size', 'Type')
    }
    PhysicalDisk = @{
        Cls = 'MSFT_PhysicalDisk'
        Chain = @("$P#root/microsoft/windows/storage/MSFT_PhysicalDisk", "$NS/MSFT_StorageFaultDomain", "$NS/MSFT_StorageObject", "$P#MSFT_PhysicalDisk", "$P#MSFT_StorageFaultDomain", "$P#MSFT_StorageObject", $P, 'System.Object')
        Props = @('ClassName', 'Usage', 'OperationalStatus', 'UniqueIdFormat', 'HealthStatus', 'BusType', 'CannotPoolReason', 'SupportedUsages', 'MediaType', 'SpindleSpeed') + $pt + @(
            'Description', 'FriendlyName', 'Manufacturer', 'Model', 'OperationalDetails', 'PhysicalLocation', 'SerialNumber', 'AdapterSerialNumber', 'AllocatedSize', 'CanPool', 'DeviceId',
            'EnclosureNumber', 'FirmwareVersion', 'IsIndicationEnabled', 'IsPartial', 'LogicalSectorSize', 'OtherCannotPoolReasonDescription', 'PartNumber', 'PhysicalSectorSize', 'Size',
            'SlotNumber', 'SoftwareVersion', 'StoragePoolUniqueId', 'VirtualDiskFootprint', 'PSComputerName')
        Types = @{ ClassName = 'System.String'; Usage = 'System.String'; OperationalStatus = 'System.String'; HealthStatus = 'System.String'; BusType = 'System.String'; MediaType = 'System.String'
                   SupportedUsages = 'System.Object[]'; SpindleSpeed = 'System.UInt32'; AllocatedSize = 'System.UInt64'; LogicalSectorSize = 'System.UInt64'; PhysicalSectorSize = 'System.UInt64'
                   Size = 'System.UInt64'; VirtualDiskFootprint = 'System.UInt64'; CanPool = 'System.Boolean'; IsPartial = 'System.Boolean'; DeviceId = 'System.String'; UniqueId = 'System.String' }
        Table = @('Number', 'FriendlyName', 'SerialNumber', 'MediaType', 'CanPool', 'OperationalStatus', 'HealthStatus', 'Usage', 'Size')
    }
}

function MemberNames($o) { @($o.psobject.Properties.Name | Where-Object { $_ -notin $hidden }) }
# the error records a command writes (binding errors included), whatever the caller's $ErrorActionPreference
function Err([scriptblock]$sb) {
    $ErrorActionPreference = 'Continue'
    try { @(& $sb 2>&1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) } catch { @($_) }
}
function Ok([scriptblock]$sb) { @(& $sb 2>$null) }
function HeaderTokens($o) {
    $lines = @(($o | Format-Table | Out-String -Width 250) -split "`r?`n" | Where-Object { $_.Trim() })
    @($lines | Where-Object { $_ -notmatch '^\s*DiskPath:' } | Select-Object -First 1 | ForEach-Object { $_.Trim() -split '\s+' })
}

$script:V = Get-Volume -DriveLetter C
$script:CPart = Get-Partition -DriveLetter C
$script:D = Get-Disk -Number $script:CPart.DiskNumber
$script:PD = @(Get-PhysicalDisk)

Describe 'module surface' {
    It 'imports without output or errors' {
        $out = @(Import-Module Storage -Force -ErrorAction Stop *>&1)
        $out.Count | Should -Be 0
    }
    It 'is Storage 2.0.0.0' {
        (Get-Module Storage).Version.ToString() | Should -Be '2.0.0.0'
    }
    It 'exports <Name> from Storage' -TestCases @(@{ Name = 'Get-Volume' }, @{ Name = 'Get-Disk' }, @{ Name = 'Get-Partition' }, @{ Name = 'Get-PhysicalDisk' }) {
        param($Name)
        (Get-Command $Name).Source | Should -Be 'Storage'
    }
    It 'has the default parameter set <Set> on <Name>' -TestCases @(
        @{ Name = 'Get-Volume'; Set = 'ByDriveLetter' }, @{ Name = 'Get-Disk'; Set = 'ByNumber' },
        @{ Name = 'Get-Partition'; Set = 'ByUniqueId' }, @{ Name = 'Get-PhysicalDisk'; Set = 'ByUniqueId' }) {
        param($Name, $Set)
        (Get-Command $Name).DefaultParameterSet | Should -Be $Set
    }
    It '<Name> has parameter -<Param> of type <Type> (position <Pos>)' -TestCases @(
        @{ Name = 'Get-Volume'; Param = 'DriveLetter'; Type = 'System.Char[]'; Pos = 0 },
        @{ Name = 'Get-Volume'; Param = 'FileSystemLabel'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Volume'; Param = 'Path'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Volume'; Param = 'UniqueId'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Volume'; Param = 'FilePath'; Type = 'System.String'; Pos = -2147483648 },
        @{ Name = 'Get-Disk'; Param = 'Number'; Type = 'System.UInt32[]'; Pos = 0 },
        @{ Name = 'Get-Disk'; Param = 'FriendlyName'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Disk'; Param = 'SerialNumber'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Disk'; Param = 'Path'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Partition'; Param = 'DiskNumber'; Type = 'System.UInt32[]'; Pos = 0 },
        @{ Name = 'Get-Partition'; Param = 'PartitionNumber'; Type = 'System.UInt32[]'; Pos = 1 },
        @{ Name = 'Get-Partition'; Param = 'DriveLetter'; Type = 'System.Char[]'; Pos = -2147483648 },
        @{ Name = 'Get-Partition'; Param = 'DiskId'; Type = 'System.String[]'; Pos = -2147483648 },
        @{ Name = 'Get-Partition'; Param = 'Offset'; Type = 'System.UInt64[]'; Pos = -2147483648 },
        @{ Name = 'Get-PhysicalDisk'; Param = 'FriendlyName'; Type = 'System.String'; Pos = 0 },
        @{ Name = 'Get-PhysicalDisk'; Param = 'SerialNumber'; Type = 'System.String'; Pos = 1 },
        @{ Name = 'Get-PhysicalDisk'; Param = 'DeviceNumber'; Type = 'System.String'; Pos = -2147483648 },
        @{ Name = 'Get-PhysicalDisk'; Param = 'UniqueId'; Type = 'System.String'; Pos = -2147483648 }) {
        param($Name, $Param, $Type, $Pos)
        $p = (Get-Command $Name).Parameters[$Param]
        $p | Should -Not -BeNullOrEmpty
        $p.ParameterType.FullName | Should -Be $Type
        ($p.ParameterSets.Values | ForEach-Object { $_.Position } | Sort-Object | Select-Object -Last 1) | Should -Be $Pos
    }
    It '<Name> -<Param> has the alias <Alias>' -TestCases @(
        @{ Name = 'Get-Volume'; Param = 'FileSystemLabel'; Alias = 'FriendlyName' }, @{ Name = 'Get-Volume'; Param = 'ObjectId'; Alias = 'Id' },
        @{ Name = 'Get-Volume'; Param = 'FilePath'; Alias = 'FullName' }, @{ Name = 'Get-Disk'; Param = 'Number'; Alias = 'DeviceId' },
        @{ Name = 'Get-Disk'; Param = 'UniqueId'; Alias = 'Id' }, @{ Name = 'Get-Partition'; Param = 'PartitionNumber'; Alias = 'Number' },
        @{ Name = 'Get-Partition'; Param = 'DiskId'; Alias = 'DiskPath' }, @{ Name = 'Get-PhysicalDisk'; Param = 'UniqueId'; Alias = 'Id' }) {
        param($Name, $Param, $Alias)
        (Get-Command $Name).Parameters[$Param].Aliases | Should -Contain $Alias
    }
    It 'has no HelpUri (the Windows functions have none)' {
        (Get-Command Get-Volume, Get-Disk, Get-Partition, Get-PhysicalDisk | Where-Object { $_.HelpUri }).Count | Should -Be 0
    }
}

foreach ($k in 'Volume', 'Disk', 'Partition', 'PhysicalDisk') {
    $sh = $script:Shape[$k]
    $obj = switch ($k) { 'Volume' { $script:V } 'Disk' { $script:D } 'Partition' { $script:CPart } 'PhysicalDisk' { $script:PD[0] } }
    Describe "MSFT_$k object shape" {
        It 'is a single object' {
            @($obj).Count | Should -Be 1
        }
        It 'has the Windows type-name chain' {
            ($obj.psobject.TypeNames -join '|') | Should -Be ($sh.Chain -join '|')
        }
        It 'has the Windows properties in the Windows order' {
            $names = MemberNames $obj
            ($names -join ',') | Should -Be ($sh.Props -join ',')
        }
        It 'has the Windows value type for <Name>' -TestCases @($sh.Types.GetEnumerator() | ForEach-Object { @{ Name = $_.Key; Type = $_.Value; Obj = $obj } }) {
            param($Name, $Type, $Obj)
            $v = $Obj.$Name
            if ($null -ne $v) { $t = $v.GetType().FullName; $t | Should -Be $Type }
        }
        It 'ToString names the class and the start of the ObjectId' {
            $obj.ToString() | Should -Match "^MSFT_$k \(ObjectId = `"\{1\}"
        }
        It 'default table columns are the Windows ones' {
            $tok = HeaderTokens $obj
            ($tok -join ' ') | Should -Be ($sh.Table -join ' ')
        }
    }
}

Describe 'Get-Volume values' {
    $v = $script:V
    $avail = 0; $total = 0; $free = 0
    [void][StorTestK32]::GetDiskFreeSpaceExW('C:\', [ref]$avail, [ref]$total, [ref]$free)
    It 'C: is NTFS, fixed and healthy' {
        $v.FileSystem | Should -Be 'NTFS'
        $v.FileSystemType | Should -Be 'NTFS'
        $v.DriveType | Should -Be 'Fixed'
        $v.HealthStatus | Should -Be 'Healthy'
        $v.OperationalStatus | Should -Be 'OK'
        $v.DedupMode | Should -Be 'NotAvailable'
        $v.DriveLetter | Should -Be ([char]'C')
    }
    It 'Size matches GetDiskFreeSpaceEx' {
        $v.Size | Should -Be $total
    }
    It 'SizeRemaining is close to GetDiskFreeSpaceEx (64 MB of churn allowed)' {
        [math]::Abs([int64]$v.SizeRemaining - [int64]$free) | Should -BeLessThan 67108864
    }
    It 'has a volume GUID path as Path and UniqueId' {
        $v.Path | Should -Match '^\\\\\?\\Volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\$'
        $v.UniqueId | Should -Be $v.Path
    }
    It 'has an ObjectId of the Windows form' {
        $v.ObjectId | Should -Match '^\{1\}\\\\[^\\]+\\root/Microsoft/Windows/Storage/Providers_v2\\WSP_Volume\.ObjectId="\{[0-9a-f-]{36}\}:VO:\\\\\?\\Volume\{[0-9a-f-]{36}\}\\"$'
    }
    It 'has a plausible allocation unit size' {
        $v.AllocationUnitSize | Should -BeIn 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
    }
    It 'lists every volume once and C: among them' {
        $all = @(Get-Volume)
        $all.Count | Should -BeGreaterThan 0
        @($all | Where-Object { $_.DriveLetter -eq 'C' }).Count | Should -Be 1
        (@($all.UniqueId | Select-Object -Unique)).Count | Should -Be $all.Count
    }
}

Describe 'Get-Disk, Get-Partition and Get-PhysicalDisk values' {
    $d = $script:D; $parts = @(Get-Partition -DiskNumber $script:D.Number); $pd = $script:PD
    It 'the disk has plausible values' {
        $d.Size | Should -BeGreaterThan 0
        $d.PartitionStyle | Should -BeIn 'RAW', 'MBR', 'GPT'
        $d.HealthStatus | Should -Be 'Healthy'
        $d.OperationalStatus | Should -Be 'Online'
        $d.BusType | Should -BeIn 'Unknown', 'SCSI', 'ATAPI', 'ATA', '1394', 'SSA', 'Fibre Channel', 'USB', 'RAID', 'iSCSI', 'SAS', 'SATA', 'SD', 'MMC', 'Virtual', 'File Backed Virtual', 'Spaces', 'NVMe', 'SCM', 'UFS'
        $d.DiskNumber | Should -Be $d.Number
        $d.LogicalSectorSize | Should -BeIn 512, 4096
        $d.IsBoot | Should -BeTrue
        $d.IsSystem | Should -BeTrue
        $d.Path | Should -Match '^\\\\\?\\'
    }
    It 'NumberOfPartitions equals the partitions found' {
        $d.NumberOfPartitions | Should -Be $parts.Count
    }
    It 'the partitions fit in the disk, do not overlap and are numbered from 1' {
        $sorted = @($parts | Sort-Object Offset)
        for ($i = 1; $i -lt $sorted.Count; $i++) { ($sorted[$i - 1].Offset + $sorted[$i - 1].Size) | Should -BeLessOrEqual $sorted[$i].Offset }
        ($sorted | Select-Object -Last 1 | ForEach-Object { $_.Offset + $_.Size }) | Should -BeLessOrEqual $d.Size
        ($parts.PartitionNumber | Sort-Object)[0] | Should -Be 1
        @($parts.PartitionNumber | Select-Object -Unique).Count | Should -Be $parts.Count
    }
    It 'the C: partition has the drive letter, the access paths and fits the volume' {
        $c = $script:CPart
        $c.DriveLetter | Should -Be ([char]'C')
        $c.AccessPaths | Should -Contain 'C:\'
        $c.AccessPaths | Should -Contain $script:V.Path
        $c.Size | Should -BeGreaterOrEqual $script:V.Size
        $c.IsBoot | Should -BeTrue
        $c.OperationalStatus | Should -Be 'Online'
        $c.DiskId | Should -Be $d.Path
        $c.DiskPath | Should -Be $d.Path
    }
    It 'partitions without a volume letter have the NUL drive letter' {
        foreach ($p in ($parts | Where-Object { $_.AccessPaths -notcontains 'C:\' -and $_.AccessPaths.Count -le 1 })) { [int]$p.DriveLetter | Should -Be 0 }
    }
    It 'the physical disk agrees with the disk' {
        $pd.Count | Should -BeGreaterThan 0
        $pd[0].Size | Should -Be $d.Size
        $pd[0].FriendlyName | Should -Be $d.FriendlyName
        $pd[0].DeviceId | Should -Be ([string]$d.Number)
        $pd[0].HealthStatus | Should -Be 'Healthy'
        $pd[0].OperationalStatus | Should -Be 'OK'
        $pd[0].ClassName | Should -Be 'MSFT_PhysicalDisk'
        ($pd[0].SupportedUsages -join ',') | Should -Be 'Auto-Select,Manual-Select,Hot Spare,Retired,Journal'
        $pd[0].MediaType | Should -BeIn 'Unspecified', 'HDD', 'SSD', 'SCM'
    }
}

Describe 'size column of the default views' {
    It 'formats <Bytes> as <Text> in the <Kind> table' -TestCases @(
        foreach ($b in @(@(0, '0 B'), @(1, '1 B'), @(1023, '1023 B'), @(1024, '1 KB'), @(1536, '1.5 KB'), @(1048575, '1024 KB'), @(1048576, '1 MB'),
                         @(68448940032, '63.75 GB'), @(1099511627776, '1 TB'), @(1125899906842624, '1 PB'))) { @{ Bytes = $b[0]; Text = $b[1]; Kind = 'Partition' } }
    ) {
        param($Bytes, $Text, $Kind)
        $o = [pscustomobject]@{ PartitionNumber = [uint32]1; DriveLetter = [char]'C'; Offset = [uint64]5; Size = [uint64]$Bytes; Type = 'Basic'; DiskPath = 'dp' }
        $o.PSObject.TypeNames.Insert(0, "$P#MSFT_Partition")
        $lines = @(($o | Format-Table | Out-String -Width 200) -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch 'DiskPath:' })
        $lines[-1].TrimEnd() | Should -Match ([regex]::Escape("$Text Basic") + '$')
    }
}

Describe 'filters' {
    $label = $script:V.FileSystemLabel
    It '-DriveLetter C, c and positional C find the C: volume' {
        (Get-Volume -DriveLetter C).DriveLetter | Should -Be ([char]'C')
        (Get-Volume -DriveLetter c).UniqueId | Should -Be $script:V.UniqueId
        (Get-Volume C).UniqueId | Should -Be $script:V.UniqueId
    }
    It '-FileSystemLabel and its alias -FriendlyName find the volume (case-insensitive, wildcards)' {
        if (-not $label) { Set-ItResult -Skipped -Because 'C: has no label'; return }
        (Get-Volume -FileSystemLabel $label).UniqueId | Should -Be $script:V.UniqueId
        (Get-Volume -FriendlyName $label.ToUpper()).UniqueId | Should -Be $script:V.UniqueId
        (Get-Volume -FileSystemLabel ($label.Substring(0, 1) + '*')).UniqueId | Should -Contain $script:V.UniqueId
    }
    It '-Path, -UniqueId and -FilePath find the volume' {
        (Get-Volume -Path $script:V.Path).UniqueId | Should -Be $script:V.UniqueId
        (Get-Volume -UniqueId $script:V.UniqueId).UniqueId | Should -Be $script:V.UniqueId
        (Get-Volume -FilePath 'C:\Windows').UniqueId | Should -Be $script:V.UniqueId
    }
    It 'Get-Volume -DriveLetter C,Z returns C: and one error' {
        $e = Err { Get-Volume -DriveLetter C, Z }
        $e.Count | Should -Be 1
        @(Ok { Get-Volume -DriveLetter C, Z }).Count | Should -Be 1
    }
    It 'Get-Disk -Number, positional, -DeviceId, -UniqueId, -Path, -FriendlyName find the disk' {
        $d = $script:D
        (Get-Disk -Number $d.Number).UniqueId | Should -Be $d.UniqueId
        (Get-Disk $d.Number).UniqueId | Should -Be $d.UniqueId
        (Get-Disk -DeviceId $d.Number).UniqueId | Should -Be $d.UniqueId
        (Get-Disk -UniqueId $d.UniqueId).Number | Should -Be $d.Number
        (Get-Disk -Path $d.Path).Number | Should -Be $d.Number
        if ($d.FriendlyName) { (Get-Disk -FriendlyName ($d.FriendlyName.Substring(0, 3) + '*')).Number | Should -Contain $d.Number }
    }
    It 'Get-Partition by disk number, partition number, positional and alias' {
        $c = $script:CPart
        (Get-Partition -DiskNumber $c.DiskNumber -PartitionNumber $c.PartitionNumber).Offset | Should -Be $c.Offset
        (Get-Partition $c.DiskNumber $c.PartitionNumber).Offset | Should -Be $c.Offset
        (Get-Partition -DiskNumber $c.DiskNumber -Number $c.PartitionNumber).Offset | Should -Be $c.Offset
        (Get-Partition -PartitionNumber $c.PartitionNumber | Where-Object { $_.DiskNumber -eq $c.DiskNumber }).Offset | Should -Be $c.Offset
    }
    It 'Get-Partition by drive letter, disk id, disk id + offset, unique id' {
        $c = $script:CPart
        (Get-Partition -DriveLetter C).Offset | Should -Be $c.Offset
        (Get-Partition -DiskId $c.DiskId | Where-Object PartitionNumber -eq $c.PartitionNumber).Offset | Should -Be $c.Offset
        (Get-Partition -DiskId $c.DiskId -Offset $c.Offset).PartitionNumber | Should -Be $c.PartitionNumber
        (Get-Partition -UniqueId $c.UniqueId).Offset | Should -Be $c.Offset
    }
    It 'Get-PhysicalDisk by device number, unique id, friendly name' {
        $p = $script:PD[0]
        (Get-PhysicalDisk -DeviceNumber $p.DeviceId).UniqueId | Should -Be $p.UniqueId
        (Get-PhysicalDisk -UniqueId $p.UniqueId).DeviceId | Should -Be $p.DeviceId
        if ($p.FriendlyName) { (Get-PhysicalDisk -FriendlyName ($p.FriendlyName.Substring(0, 3) + '*')).DeviceId | Should -Contain $p.DeviceId }
        @(Get-PhysicalDisk -HealthStatus Healthy).Count | Should -BeGreaterThan 0
        @(Get-PhysicalDisk -CanPool $true).Count | Should -Be 0
        @(Get-PhysicalDisk -Usage Retired).Count | Should -Be 0
    }
    It 'Get-PhysicalDisk with no match writes no error' {
        (Err { Get-PhysicalDisk -DeviceNumber 99 }).Count | Should -Be 0
        (Err { Get-PhysicalDisk -FriendlyName nosuch }).Count | Should -Be 0
    }
}

Describe 'pipelines' {
    It 'Get-Disk | Get-Partition lists the partitions of the disk' {
        $a = @(Get-Disk -Number $script:D.Number | Get-Partition)
        $a.Count | Should -Be $script:D.NumberOfPartitions
    }
    It 'Get-Partition -DriveLetter C | Get-Volume gives the C: volume' {
        (Get-Partition -DriveLetter C | Get-Volume).UniqueId | Should -Be $script:V.UniqueId
    }
    It 'Get-Volume -DriveLetter C | Get-Partition gives the C: partition' {
        (Get-Volume -DriveLetter C | Get-Partition).Offset | Should -Be $script:CPart.Offset
    }
    It 'Get-Partition -DriveLetter C | Get-Disk gives the disk' {
        (Get-Partition -DriveLetter C | Get-Disk).Number | Should -Be $script:D.Number
    }
    It 'Get-Disk | Get-Partition | Get-Volume gives the volumes of the disk, C: among them' {
        @(Get-Disk -Number $script:D.Number | Get-Partition | Get-Volume | Where-Object { $_.DriveLetter -eq 'C' }).Count | Should -Be 1
    }
    It 'Get-Disk | Get-PhysicalDisk gives the physical disk' {
        (Get-Disk -Number $script:D.Number | Get-PhysicalDisk).DeviceId | Should -Be ([string]$script:D.Number)
    }
}

Describe 'errors' {
    It '<Cmd> -> <Id> / <Cat> / target <TType> <Target>' -TestCases @(
        @{ Cmd = 'Get-Volume -DriveLetter Z'; Id = 'CmdletizationQuery_NotFound_DriveLetter,Get-Volume'; Cat = 'ObjectNotFound'; TType = 'System.Char'; Target = 'Z'; Msg = "No MSFT_Volume objects found with property 'DriveLetter' equal to 'Z'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Volume -FileSystemLabel nosuch'; Id = 'CmdletizationQuery_NotFound_FileSystemLabel,Get-Volume'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Volume objects found with property 'FileSystemLabel' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Volume -UniqueId nosuch'; Id = 'CmdletizationQuery_NotFound_UniqueId,Get-Volume'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Volume objects found with property 'UniqueId' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Volume -Path C:\'; Id = 'CmdletizationQuery_NotFound_Path,Get-Volume'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'C:\'; Msg = "No MSFT_Volume objects found with property 'Path' equal to 'C:\'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Disk -Number 99'; Id = 'CmdletizationQuery_NotFound_Number,Get-Disk'; Cat = 'ObjectNotFound'; TType = 'System.UInt32'; Target = '99'; Msg = "No MSFT_Disk objects found with property 'Number' equal to '99'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Disk -FriendlyName nosuch'; Id = 'CmdletizationQuery_NotFound_FriendlyName,Get-Disk'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Disk objects found with property 'FriendlyName' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Disk -SerialNumber nosuch'; Id = 'CmdletizationQuery_NotFound_SerialNumber,Get-Disk'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Disk objects found with property 'SerialNumber' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Disk -UniqueId nosuch'; Id = 'CmdletizationQuery_NotFound_UniqueId,Get-Disk'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Disk objects found with property 'UniqueId' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Disk -Path nosuch'; Id = 'CmdletizationQuery_NotFound_Path,Get-Disk'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Disk objects found with property 'Path' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Partition -DiskNumber 99'; Id = 'CmdletizationQuery_NotFound_DiskNumber,Get-Partition'; Cat = 'ObjectNotFound'; TType = 'System.UInt32'; Target = '99'; Msg = "No MSFT_Partition objects found with property 'DiskNumber' equal to '99'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Partition -DriveLetter Z'; Id = 'CmdletizationQuery_NotFound_DriveLetter,Get-Partition'; Cat = 'ObjectNotFound'; TType = 'System.Char'; Target = 'Z'; Msg = "No MSFT_Partition objects found with property 'DriveLetter' equal to 'Z'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Partition -DiskId nosuch'; Id = 'CmdletizationQuery_NotFound_DiskId,Get-Partition'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Partition objects found with property 'DiskId' equal to 'nosuch'.  Verify the value of the property and retry." },
        @{ Cmd = 'Get-Partition -UniqueId nosuch'; Id = 'CmdletizationQuery_NotFound_UniqueId,Get-Partition'; Cat = 'ObjectNotFound'; TType = 'System.String'; Target = 'nosuch'; Msg = "No MSFT_Partition objects found with property 'UniqueId' equal to 'nosuch'.  Verify the value of the property and retry." }
    ) {
        param($Cmd, $Id, $Cat, $TType, $Target, $Msg)
        $e = @(Err ([scriptblock]::Create($Cmd)))
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be $Id
        $e[0].CategoryInfo.Category | Should -Be $Cat
        $e[0].CategoryInfo.Reason | Should -Be 'CimJobException'
        $e[0].Exception.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.Cim.CimJobException'
        $e[0].CategoryInfo.Activity | Should -Be ($Cmd -split ' ')[0]
        $e[0].TargetObject.GetType().FullName | Should -Be $TType
        [string]$e[0].TargetObject | Should -Be $Target
        $e[0].Exception.Message | Should -Be $Msg
    }
    It 'two properties with no match give the CIM query error' {
        $e = @(Err { Get-Partition -DiskNumber 0 -PartitionNumber 99 })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound,Get-Partition'
        $e[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $e[0].TargetObject | Should -Be 'MSFT_Partition'
        $e[0].Exception.Message | Should -Be 'No matching MSFT_Partition objects found by CIM query for instances of the ROOT/Microsoft/Windows/Storage/MSFT_Partition class on the  CIM server: SELECT * FROM MSFT_Partition  WHERE ((DiskNumber = 0)) AND ((PartitionNumber = 99)). Verify query parameters and retry.'
    }
    It 'Get-Disk -Number 0,99 returns disk 0 and an error for 99' {
        @(Ok { Get-Disk -Number 0, 99 }).Count | Should -Be 1
        $e = @(Err { Get-Disk -Number 0, 99 })
        $e.Count | Should -Be 1
        [string]$e[0].TargetObject | Should -Be '99'
    }
    It 'null and unconvertible arguments are binding errors' {
        (Err { Get-Volume -DriveLetter $null })[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentValidationError,Get-Volume'
        (Err { Get-Volume -DriveLetter $null })[0].CategoryInfo.Category | Should -Be 'InvalidData'
        (Err { Get-Disk -Number -1 })[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentTransformationError,Get-Disk'
        (Err { Get-Disk -Number abc })[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentTransformationError,Get-Disk'
    }
    It "-DriveLetter 'C:' is C plus an error for ':'" {
        $e = @(Err { Get-Volume -DriveLetter 'C:' })
        $e.Count | Should -Be 1
        [string]$e[0].TargetObject | Should -Be ':'
    }
}

# ======================================================================================== Set-Volume
# Surface and binding-error rows are read-only and also run on the Windows oracle against the real module (STOR_ORACLE=1).
# The round trip changes the label of C: through every selector, checks it with Get-Volume AND `vol`, and restores it; it is
# skipped on the oracle and when STOR_NOROUNDTRIP=1.
$script:SkipVolRt = $script:Oracle -or ($env:STOR_NOROUNDTRIP -eq '1')
function SvSet($param, $set) { (Get-Command Set-Volume).Parameters[$param].ParameterSets[$set] }

Describe 'Set-Volume surface (Windows parameter model)' {
    It 'is a Storage function with the default set ByDriveLetterSetLabel and no ShouldProcess' {
        (Get-Command Set-Volume).Source | Should -Be 'Storage'
        (Get-Command Set-Volume).DefaultParameterSet | Should -Be 'ByDriveLetterSetLabel'
        (Get-Command Set-Volume).Parameters.Keys | Should -Not -Contain 'WhatIf'
        (Get-Command Set-Volume).Parameters.Keys | Should -Not -Contain 'PassThru'
    }
    It 'has the ten Windows parameter sets' {
        @((Get-Command Set-Volume).ParameterSets.Name | Sort-Object) | Should -Be @(
            'ByDriveLetterSetDedup', 'ByDriveLetterSetLabel', 'ByLabelSetDedup', 'ByLabelSetLabel', 'ByObjectSetDedup', 'ByObjectSetLabel',
            'ByPathSetDedup', 'ByPathSetLabel', 'ByUniqueIdSetDedup', 'ByUniqueIdSetLabel')
    }
    It 'selectors are mandatory and take the pipeline: <Param>' -TestCases @(
        @{ Param = 'DriveLetter'; Set = 'ByDriveLetterSetLabel'; Type = 'System.Char' }, @{ Param = 'FileSystemLabel'; Set = 'ByLabelSetLabel'; Type = 'System.String' },
        @{ Param = 'Path'; Set = 'ByPathSetLabel'; Type = 'System.String' }, @{ Param = 'UniqueId'; Set = 'ByUniqueIdSetLabel'; Type = 'System.String' },
        @{ Param = 'InputObject'; Set = 'ByObjectSetLabel'; Type = 'System.Object[]' }) {
        param($Param, $Set, $Type)
        (SvSet $Param $Set).IsMandatory | Should -BeTrue
        (SvSet $Param $Set).ValueFromPipeline | Should -BeTrue
        (Get-Command Set-Volume).Parameters[$Param].ParameterType.FullName | Should -BeIn @($Type, 'Microsoft.Management.Infrastructure.CimInstance[]')
    }
    It 'NewFileSystemLabel is a string with the alias NewFriendlyName in the label sets only' {
        $p = (Get-Command Set-Volume).Parameters['NewFileSystemLabel']
        $p.ParameterType.FullName | Should -Be 'System.String'
        $p.Aliases | Should -Contain 'NewFriendlyName'
        $p.ParameterSets.Keys | Should -Not -Contain 'ByDriveLetterSetDedup'
        $p.ParameterSets.Keys | Should -Contain 'ByObjectSetLabel'
        (Get-Command Set-Volume).Parameters['FileSystemLabel'].Aliases | Should -Contain 'FriendlyName'
    }
    It 'DedupMode is the SetVolume enum Disabled/GeneralPurpose/HyperV/Backup/NotAvailable (uint)' {
        $t = (Get-Command Set-Volume).Parameters['DedupMode'].ParameterType
        $t.FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.SetVolume.DedupMode'
        [enum]::GetUnderlyingType($t).FullName | Should -Be 'System.UInt32'
        @([enum]::GetNames($t)) | Should -Be @('Disabled', 'GeneralPurpose', 'HyperV', 'Backup', 'NotAvailable')
        [int][enum]::Parse($t, 'NotAvailable') | Should -Be 4
    }
    It 'no arguments, or only a label, is a missing-mandatory-parameter error for DriveLetter' {
        foreach ($sb in { Set-Volume }, { Set-Volume -NewFileSystemLabel x }) {
            $e = @(Err $sb)
            $e[0].FullyQualifiedErrorId | Should -Be 'MissingMandatoryParameter,Set-Volume'
            $e[0].Exception.Message | Should -Match 'missing mandatory parameters: DriveLetter'
        }
    }
    It 'two selectors are an ambiguous parameter set' {
        $e = @(Err { Set-Volume -DriveLetter C -Path 'C:\' -NewFileSystemLabel x })
        $e[0].FullyQualifiedErrorId | Should -Be 'AmbiguousParameterSet,Set-Volume'
        [string]$e[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
    }
}

Describe 'Set-Volume round trip on C: (Get-Volume and vol agree)' {
    BeforeAll {
        if (-not $script:SkipVolRt) {
            $script:origLabel = [string](Get-Volume -DriveLetter C).FileSystemLabel
            $script:vol = { ((& cmd.exe /c vol C:) -join "`n") }
        }
    }
    AfterAll { if (-not $script:SkipVolRt) { Set-Volume -DriveLetter C -NewFileSystemLabel $script:origLabel } }
    It 'sets the label by drive letter and returns nothing' -Skip:$script:SkipVolRt {
        $o = @(Set-Volume -DriveLetter C -NewFileSystemLabel 'NITRO1')
        $o.Count | Should -Be 0
        (Get-Volume -DriveLetter C).FileSystemLabel | Should -Be 'NITRO1'
        (& $script:vol) | Should -Match 'Volume in drive C is NITRO1'
    }
    It 'finds the volume by label (wildcards), by path, by UniqueId and by pipeline object' -Skip:$script:SkipVolRt {
        Set-Volume -FileSystemLabel 'NITRO*' -NewFileSystemLabel 'NITRO2'
        (& $script:vol) | Should -Match 'Volume in drive C is NITRO2'
        $v = Get-Volume -DriveLetter C
        Set-Volume -Path $v.Path -NewFileSystemLabel 'NITRO3'
        (& $script:vol) | Should -Match 'Volume in drive C is NITRO3'
        Set-Volume -UniqueId $v.UniqueId -NewFileSystemLabel 'NITRO4'
        (Get-Volume -DriveLetter C).FileSystemLabel | Should -Be 'NITRO4'
        Get-Volume -DriveLetter C | Set-Volume -NewFileSystemLabel 'NITRO5'
        (& $script:vol) | Should -Match 'Volume in drive C is NITRO5'
        Set-Volume -DriveLetter c -NewFriendlyName 'NITRO6'
        (Get-Volume -DriveLetter C).FileSystemLabel | Should -Be 'NITRO6'
    }
    It 'takes a label with a space and an empty label clears it' -Skip:$script:SkipVolRt {
        Set-Volume -DriveLetter C -NewFileSystemLabel 'My Disk'
        (Get-Volume -DriveLetter C).FileSystemLabel | Should -Be 'My Disk'
        (& $script:vol) | Should -Match 'Volume in drive C is My Disk'
        Set-Volume -DriveLetter C -NewFileSystemLabel ''
        [string](Get-Volume -DriveLetter C).FileSystemLabel | Should -Be ''
        (& $script:vol) | Should -Match 'Volume in drive C has no label'
    }
    It 'a too long label is a Windows System Error and changes nothing' -Skip:$script:SkipVolRt {
        Set-Volume -DriveLetter C -NewFileSystemLabel 'KEEP'
        $e = @(Err { Set-Volume -DriveLetter C -NewFileSystemLabel ('x' * 40) })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Match '^Windows System Error \d+,Set-Volume$'
        (Get-Volume -DriveLetter C).FileSystemLabel | Should -Be 'KEEP'
    }
    It 'an unknown drive letter is CmdletizationQuery_NotFound_DriveLetter; a CD-ROM without media is a device error' -Skip:$script:SkipVolRt {
        $e = @(Err { Set-Volume -DriveLetter Z -NewFileSystemLabel x })
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_DriveLetter,Set-Volume'
        [string]$e[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $e[0].Exception.Message | Should -Be "No MSFT_Volume objects found with property 'DriveLetter' equal to 'Z'.  Verify the value of the property and retry."
        $cd = @(Get-Volume | Where-Object { [string]$_.DriveType -eq 'CD-ROM' -and $_.DriveLetter })
        if ($cd.Count) {
            $e = @(Err { Set-Volume -DriveLetter $cd[0].DriveLetter -NewFileSystemLabel x })
            $e[0].FullyQualifiedErrorId | Should -Match '^Windows System Error \d+,Set-Volume$'
        }
    }
    It '-DedupMode is refused: this system has no deduplication' -Skip:$script:SkipVolRt {
        $e = @(Err { Set-Volume -DriveLetter C -DedupMode Disabled })
        $e[0].FullyQualifiedErrorId | Should -Be 'DedupNotSupported,Set-Volume'
    }
}
