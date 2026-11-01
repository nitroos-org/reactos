# Pester (4.x/5.x compatible) tests for the Microsoft.PowerShell.LocalAccounts script module of ReactOS-Nitro.
# Expected shapes were measured on a Windows 10 22H2 reference machine (PowerShell 7.4.22, the Windows module).
# Read-only tests run anywhere; the create/rename/remove round trip changes accounts and only runs when
# LACC_ROUNDTRIP=1 (the nitro guest runner sets it; never set it on a reference machine).
#   LACC_MODULE  path of the module folder to import (default: the module found on PSModulePath)

# Written for Pester 4.10 (what the PowerShell repo pins): imports and tables are plain script-level code.
$target = if ($env:LACC_MODULE) { $env:LACC_MODULE } else { 'Microsoft.PowerShell.LocalAccounts' }
Import-Module $target -Force
$skipRoundTrip = ($env:LACC_ROUNDTRIP -ne '1')

$userProps  = 'AccountExpires','Description','Enabled','FullName','PasswordChangeableDate','PasswordExpires','UserMayChangePassword','PasswordRequired','PasswordLastSet','LastLogon','Name','SID','PrincipalSource','ObjectClass'
$groupProps = 'Description','Name','SID','PrincipalSource','ObjectClass'
$princProps = 'Name','SID','PrincipalSource','ObjectClass'
$helpUri = @{
    'Add-LocalGroupMember'    = 'https://go.microsoft.com/fwlink/?LinkId=717987'
    'Disable-LocalUser'       = 'https://go.microsoft.com/fwlink/?LinkId=717986'
    'Enable-LocalUser'        = 'https://go.microsoft.com/fwlink/?LinkId=717985'
    'Get-LocalGroup'          = 'https://go.microsoft.com/fwlink/?LinkId=717974'
    'Get-LocalGroupMember'    = 'https://go.microsoft.com/fwlink/?LinkId=717988'
    'Get-LocalUser'           = 'https://go.microsoft.com/fwlink/?LinkId=717980'
    'New-LocalGroup'          = 'https://go.microsoft.com/fwlink/?LinkId=717990'
    'New-LocalUser'           = 'https://go.microsoft.com/fwlink/?LinkId=717981'
    'Remove-LocalGroup'       = 'https://go.microsoft.com/fwlink/?LinkId=717975'
    'Remove-LocalGroupMember' = 'https://go.microsoft.com/fwlink/?LinkId=717989'
    'Remove-LocalUser'        = 'https://go.microsoft.com/fwlink/?LinkId=717982'
    'Rename-LocalGroup'       = 'https://go.microsoft.com/fwlink/?LinkId=717978'
    'Rename-LocalUser'        = 'https://go.microsoft.com/fwlink/?LinkID=717983'
    'Set-LocalGroup'          = 'https://go.microsoft.com/fwlink/?LinkId=717979'
    'Set-LocalUser'           = 'https://go.microsoft.com/fwlink/?LinkId=717984'
}
$aliases = @{ algm='Add-LocalGroupMember'; dlu='Disable-LocalUser'; elu='Enable-LocalUser'; glg='Get-LocalGroup'; glgm='Get-LocalGroupMember'; glu='Get-LocalUser'; nlg='New-LocalGroup'; nlu='New-LocalUser'; rlg='Remove-LocalGroup'; rlgm='Remove-LocalGroupMember'; rlu='Remove-LocalUser'; rnlg='Rename-LocalGroup'; rnlu='Rename-LocalUser'; slg='Set-LocalGroup'; slu='Set-LocalUser' }

Describe 'Microsoft.PowerShell.LocalAccounts module surface' {
    It 'exports the 15 cmdlet names with the Windows HelpUri' {
        $cmds = Get-Command -Module Microsoft.PowerShell.LocalAccounts
        @($cmds | Where-Object CommandType -ne 'Alias').Count | Should -Be 15
        foreach ($k in $helpUri.Keys) { (Get-Command $k).HelpUri | Should -Be $helpUri[$k] }
    }
    It 'exports the aliases' {
        foreach ($k in $aliases.Keys) { (Get-Command $k).ResolvedCommandName | Should -Be $aliases[$k] }
    }
    It 'has the parameter sets of the Windows cmdlets' {
        (Get-Command Get-LocalUser).Parameters.Keys | Should -Contain 'SID'
        (Get-Command Add-LocalGroupMember).ParameterSets.Name | Should -Contain 'Group'
        (Get-Command New-LocalUser).ParameterSets.Name | Should -Contain 'NoPassword'
        (Get-Command Set-LocalUser).Parameters['PasswordNeverExpires'].ParameterType.Name | Should -Be 'Boolean'
    }
    It 'Get-Help -Online resolves the HelpUri (Pester OnlineHelp row shape)' {
        [System.Management.Automation.Internal.InternalTestHooks]::SetTestHook('BypassOnlineHelpRetrieval', $true)
        try { foreach ($k in $helpUri.Keys) { (Get-Help $k -Online).Replace('Help URI: ', '') | Should -Be $helpUri[$k] } }
        finally { [System.Management.Automation.Internal.InternalTestHooks]::SetTestHook('BypassOnlineHelpRetrieval', $false) }
    }
}

Describe 'Get-LocalUser' {
    It 'lists Administrator and Guest' {
        $n = (Get-LocalUser).Name
        $n | Should -Contain 'Administrator'
        $n | Should -Contain 'Guest'
    }
    It 'returns LocalUser objects with the Windows type names' {
        $u = Get-LocalUser -Name Administrator
        $u.psobject.TypeNames[0] | Should -Be 'Microsoft.PowerShell.Commands.LocalUser'
        $u.psobject.TypeNames[1] | Should -Be 'Microsoft.PowerShell.Commands.LocalPrincipal'
        $u.psobject.TypeNames[2] | Should -Be 'System.Object'
    }
    It 'has the Windows property set in the Windows order' {
        $u = Get-LocalUser -Name Administrator
        ($u.psobject.Properties.Name -join ',') | Should -Be ($userProps -join ',')
    }
    It 'has the Windows property types' {
        $u = Get-LocalUser -Name Administrator
        $u.SID | Should -BeOfType ([System.Security.Principal.SecurityIdentifier])
        $u.Enabled | Should -BeOfType ([bool])
        $u.PrincipalSource | Should -Be 'Local'
        $u.ObjectClass | Should -Be 'User'
        $u.SID.Value | Should -Match '-500$'
        (Get-LocalUser -Name Guest).SID.Value | Should -Match '-501$'
    }
    It 'has the Windows default table columns' {
        $t = (Get-LocalUser | Format-Table | Out-String -Width 200) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1
        ($t.Trim() -split '\s+') -join ',' | Should -Be 'Name,Enabled,Description'
    }
    It 'matches wildcards without error and case-insensitively' {
        @(Get-LocalUser -Name 'adm*').Name | Should -Be 'Administrator'
        @(Get-LocalUser -Name '?uest').Name | Should -Be 'Guest'
        @(Get-LocalUser -Name '[ag]*').Count | Should -Be 2
        @(Get-LocalUser -Name 'administrator').Name | Should -Be 'Administrator'
        @(Get-LocalUser -Name 'nosuch*' -ErrorVariable ev).Count | Should -Be 0
        $ev.Count | Should -Be 0
        @(Get-LocalUser -Name '*').Count | Should -Be @(Get-LocalUser).Count
    }
    It 'finds users by SID and through the pipeline' {
        $a = Get-LocalUser -Name Administrator
        (Get-LocalUser -SID $a.SID).Name | Should -Be 'Administrator'
        ('Guest' | Get-LocalUser).Name | Should -Be 'Guest'
        (Get-LocalUser -Name Guest | Get-LocalUser).Name | Should -Be 'Guest'
    }
    It 'writes a UserNotFound error for an unknown name' {
        $r = Get-LocalUser -Name nosuchuser -ErrorAction SilentlyContinue -ErrorVariable ev
        $r | Should -BeNullOrEmpty
        $ev.Count | Should -Be 1
        $ev[0].FullyQualifiedErrorId | Should -Be 'UserNotFound,Microsoft.PowerShell.Commands.GetLocalUserCommand'
        $ev[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $ev[0].CategoryInfo.Reason | Should -Be 'UserNotFoundException'
        $ev[0].CategoryInfo.Activity | Should -Be 'Get-LocalUser'
        $ev[0].Exception.Message | Should -Be 'User nosuchuser was not found.'
        $ev[0].TargetObject | Should -Be 'nosuchuser'
    }
    It 'keeps going after one unknown name' {
        $r = Get-LocalUser -Name Guest, nosuch -ErrorAction SilentlyContinue -ErrorVariable ev
        @($r).Name | Should -Be 'Guest'
        $ev.Count | Should -Be 1
    }
    It 'treats a domain-qualified name as unknown (as Windows does)' {
        $null = Get-LocalUser -Name "$env:COMPUTERNAME\Administrator" -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'UserNotFound,Microsoft.PowerShell.Commands.GetLocalUserCommand'
    }
    It 'writes UserNotFound with a SecurityIdentifier target for an unknown SID' {
        $a = Get-LocalUser -Name Administrator
        $sid = [System.Security.Principal.SecurityIdentifier]($a.SID.Value -replace '-500$', '-9999')
        $null = Get-LocalUser -SID $sid -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'UserNotFound,Microsoft.PowerShell.Commands.GetLocalUserCommand'
        $ev[0].CategoryInfo.TargetType | Should -Be 'SecurityIdentifier'
        $ev[0].Exception.Message | Should -Be "User $($sid.Value) was not found."
    }
    It 'rejects a null name' {
        # the binding error is raised by the engine: its id ends in the function name here (the Windows cmdlet type name there)
        $err = $null
        try { Get-LocalUser -Name $null -ErrorAction Stop } catch { $err = $_ }
        $err.FullyQualifiedErrorId | Should -BeLike 'ParameterArgumentValidationError,*'
    }
}

Describe 'Get-LocalGroup' {
    It 'lists Administrators and Users with their well-known SIDs' {
        (Get-LocalGroup -Name Administrators).SID.Value | Should -Be 'S-1-5-32-544'
        (Get-LocalGroup -Name Users).SID.Value | Should -Be 'S-1-5-32-545'
    }
    It 'returns LocalGroup objects with the Windows type names and properties' {
        $g = Get-LocalGroup -Name Administrators
        $g.psobject.TypeNames[0] | Should -Be 'Microsoft.PowerShell.Commands.LocalGroup'
        $g.psobject.TypeNames[1] | Should -Be 'Microsoft.PowerShell.Commands.LocalPrincipal'
        ($g.psobject.Properties.Name -join ',') | Should -Be ($groupProps -join ',')
        $g.ObjectClass | Should -Be 'Group'
        $g.PrincipalSource | Should -Be 'Local'
    }
    It 'has the Windows default table columns' {
        $t = (Get-LocalGroup | Format-Table | Out-String -Width 200) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1
        ($t.Trim() -split '\s+') -join ',' | Should -Be 'Name,Description'
    }
    It 'supports wildcards and -SID' {
        @(Get-LocalGroup -Name 'Admin*').Name | Should -Be 'Administrators'
        @(Get-LocalGroup -Name 'nosuch*').Count | Should -Be 0
        (Get-LocalGroup -SID 'S-1-5-32-544').Name | Should -Be 'Administrators'
    }
    It 'writes GroupNotFound for an unknown name and SID' {
        $null = Get-LocalGroup -Name nosuchgroup -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'GroupNotFound,Microsoft.PowerShell.Commands.GetLocalGroupCommand'
        $ev[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $ev[0].Exception.Message | Should -Be 'Group nosuchgroup was not found.'
        $null = Get-LocalGroup -SID 'S-1-5-32-9999' -ErrorAction SilentlyContinue -ErrorVariable ev2
        $ev2[0].FullyQualifiedErrorId | Should -Be 'GroupNotFound,Microsoft.PowerShell.Commands.GetLocalGroupCommand'
        $ev2[0].CategoryInfo.TargetType | Should -Be 'SecurityIdentifier'
    }
}

Describe 'Get-LocalGroupMember' {
    It 'lists the Administrators members as LocalPrincipal objects' {
        $m = @(Get-LocalGroupMember -Group Administrators)
        $m.Count | Should -BeGreaterThan 0
        $m[0].psobject.TypeNames[0] | Should -Be 'Microsoft.PowerShell.Commands.LocalPrincipal'
        ($m[0].psobject.Properties.Name -join ',') | Should -Be ($princProps -join ',')
        ($m.Name | Where-Object { $_ -like '*\Administrator' }) | Should -Not -BeNullOrEmpty
        ($m | Where-Object { $_.Name -like '*\Administrator' }).ObjectClass | Should -Be 'User'
        ($m | Where-Object { $_.Name -like '*\Administrator' }).PrincipalSource | Should -Be 'Local'
    }
    It 'accepts the group by name, object, SID and pipeline' {
        $a = @((Get-LocalGroupMember -Name Administrators).SID.Value)
        @((Get-LocalGroupMember -Group (Get-LocalGroup -Name Administrators)).SID.Value) | Should -Be $a
        @((Get-LocalGroupMember -SID 'S-1-5-32-544').SID.Value) | Should -Be $a
        @((Get-LocalGroup -Name Administrators | Get-LocalGroupMember).SID.Value) | Should -Be $a
    }
    It 'has the Windows default table columns' {
        $t = (Get-LocalGroupMember -Name Administrators | Format-Table | Out-String -Width 200) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1
        ($t.Trim() -split '\s+') -join ',' | Should -Be 'ObjectClass,Name,PrincipalSource'
    }
    It 'filters with -Member (short name, wildcards)' {
        @(Get-LocalGroupMember -Name Administrators -Member 'Admin*').Count | Should -Be 1
        @(Get-LocalGroupMember -Name Administrators -Member 'nosuch*' -ErrorVariable ev).Count | Should -Be 0
        $ev.Count | Should -Be 0
        $null = Get-LocalGroupMember -Name Administrators -Member nosuch -ErrorAction SilentlyContinue -ErrorVariable ev2
        $ev2[0].FullyQualifiedErrorId | Should -Be 'PrincipalNotFound,Microsoft.PowerShell.Commands.GetLocalGroupMemberCommand'
        $ev2[0].Exception.Message | Should -Be 'Principal nosuch was not found.'
    }
    It 'writes GroupNotFound for an unknown group and does not expand wildcards in -Name' {
        $null = Get-LocalGroupMember -Name nosuchgroup -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'GroupNotFound,Microsoft.PowerShell.Commands.GetLocalGroupMemberCommand'
        $null = Get-LocalGroupMember -Name 'Admin*' -ErrorAction SilentlyContinue -ErrorVariable ev2
        $ev2[0].FullyQualifiedErrorId | Should -Be 'GroupNotFound,Microsoft.PowerShell.Commands.GetLocalGroupMemberCommand'
        $null = Get-LocalGroupMember -SID 'S-1-5-32-9999' -ErrorAction SilentlyContinue -ErrorVariable ev3
        $ev3[0].CategoryInfo.TargetType | Should -Be 'SecurityIdentifier'
    }
}

Describe 'write cmdlets with -WhatIf change nothing and keep the Windows error ordering' {
    It 'does not create, rename or remove with -WhatIf' {
        $before = (Get-LocalUser).Name -join ','
        New-LocalUser -Name laccwhatif1 -NoPassword -WhatIf
        Remove-LocalUser -Name Guest -WhatIf
        Rename-LocalUser -Name Guest -NewName GuestX -WhatIf
        Disable-LocalUser -Name Guest -WhatIf
        Set-LocalUser -Name Guest -Description zz -WhatIf
        New-LocalGroup -Name laccwhatifg -WhatIf
        ((Get-LocalUser).Name -join ',') | Should -Be $before
        @(Get-LocalGroup -Name laccwhatifg -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'Set-LocalUser checks that the user exists before ShouldProcess' {
        $null = Set-LocalUser -Name nosuchuser -Description zz -WhatIf -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'UserNotFound,Microsoft.PowerShell.Commands.SetLocalUserCommand'
    }
    It 'Add-LocalGroupMember reports an unknown member before ShouldProcess' {
        $null = Add-LocalGroupMember -Group Replicator -Member nosuchuser -WhatIf -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'PrincipalNotFound,Microsoft.PowerShell.Commands.AddLocalGroupMemberCommand'
    }
    It 'rejects -NoPassword together with -Password' {
        $err = $null
        try { New-LocalUser -Name x1 -NoPassword -Password (ConvertTo-SecureString 'a' -AsPlainText -Force) -WhatIf -ErrorAction Stop } catch { $err = $_ }
        $err.FullyQualifiedErrorId | Should -BeLike 'AmbiguousParameterSet,*'
    }
}

Describe 'account round trip (nitro only: creates, changes and removes accounts)' {
    BeforeAll {
        if ($skipRoundTrip) { return }
        $script:u = 'laccu1'; $script:u2 = 'laccu2'; $script:g = 'laccg1'; $script:g2 = 'laccg2'
        $script:pw = ConvertTo-SecureString 'Nitr0-Lacc-Pw!42' -AsPlainText -Force
        foreach ($n in $script:u, $script:u2) { Remove-LocalUser -Name $n -ErrorAction SilentlyContinue }
        foreach ($n in $script:g, $script:g2) { Remove-LocalGroup -Name $n -ErrorAction SilentlyContinue }
    }
    AfterAll {
        if ($skipRoundTrip) { return }
        foreach ($n in $script:u, $script:u2) { Remove-LocalUser -Name $n -ErrorAction SilentlyContinue }
        foreach ($n in $script:g, $script:g2) { Remove-LocalGroup -Name $n -ErrorAction SilentlyContinue }
    }
    It 'creates a user with a password and returns it' -Skip:$skipRoundTrip {
        $r = New-LocalUser -Name $script:u -Password $script:pw -FullName 'Lacc One' -Description 'lane test' -PasswordNeverExpires
        $r.psobject.TypeNames[0] | Should -Be 'Microsoft.PowerShell.Commands.LocalUser'
        $r.Name | Should -Be $script:u
        $r.Enabled | Should -BeTrue
        $r.FullName | Should -Be 'Lacc One'
        $r.Description | Should -Be 'lane test'
        $r.SID.Value | Should -Match '^S-1-5-21-'
        $r.PasswordExpires | Should -BeNullOrEmpty
        (Get-LocalUser -Name $script:u).SID | Should -Be $r.SID
    }
    It 'reports UserNotFound/UserExists style errors with Windows error ids' -Skip:$skipRoundTrip {
        $null = New-LocalUser -Name $script:u -NoPassword -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'UserExists,Microsoft.PowerShell.Commands.NewLocalUserCommand'
        $ev[0].CategoryInfo.Category | Should -Be 'ResourceExists'
        $null = Remove-LocalUser -Name nosuchuser -ErrorAction SilentlyContinue -ErrorVariable ev2
        $ev2[0].FullyQualifiedErrorId | Should -Be 'UserNotFound,Microsoft.PowerShell.Commands.RemoveLocalUserCommand'
    }
    It 'sets properties' -Skip:$skipRoundTrip {
        Set-LocalUser -Name $script:u -Description 'changed' -FullName 'Lacc Uno' -PasswordNeverExpires $false -UserMayChangePassword $false
        $r = Get-LocalUser -Name $script:u
        $r.Description | Should -Be 'changed'
        $r.FullName | Should -Be 'Lacc Uno'
        $r.UserMayChangePassword | Should -BeFalse
        Set-LocalUser -Name $script:u -UserMayChangePassword $true -AccountExpires ([datetime]'2036-01-02 03:04:05')
        $r = Get-LocalUser -Name $script:u
        $r.UserMayChangePassword | Should -BeTrue
        $r.AccountExpires.Year | Should -Be 2036
        Set-LocalUser -Name $script:u -AccountNeverExpires
        (Get-LocalUser -Name $script:u).AccountExpires | Should -BeNullOrEmpty
    }
    It 'disables and enables' -Skip:$skipRoundTrip {
        Disable-LocalUser -Name $script:u
        (Get-LocalUser -Name $script:u).Enabled | Should -BeFalse
        Enable-LocalUser -Name $script:u
        (Get-LocalUser -Name $script:u).Enabled | Should -BeTrue
        Disable-LocalUser -SID (Get-LocalUser -Name $script:u).SID
        (Get-LocalUser -Name $script:u).Enabled | Should -BeFalse
    }
    It 'rejects invalid names with InvalidName and creates nothing' -Skip:$skipRoundTrip {
        foreach ($bad in 'bad/name', 'bad:name', 'bad*name', 'bad.') {
            $null = New-LocalUser -Name $bad -NoPassword -ErrorAction SilentlyContinue -ErrorVariable ev
            $ev[0].FullyQualifiedErrorId | Should -Be 'InvalidName,Microsoft.PowerShell.Commands.NewLocalUserCommand'
            $null = New-LocalGroup -Name $bad -ErrorAction SilentlyContinue -ErrorVariable evg
            $evg[0].FullyQualifiedErrorId | Should -Be 'InvalidName,Microsoft.PowerShell.Commands.NewLocalGroupCommand'
        }
        $null = Rename-LocalUser -Name $script:u -NewName 'bad/name' -ErrorAction SilentlyContinue -ErrorVariable evr
        $evr[0].FullyQualifiedErrorId | Should -Be 'InvalidName,Microsoft.PowerShell.Commands.RenameLocalUserCommand'
        @(Get-LocalUser -Name 'bad*' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'creates a user without a password, disabled' -Skip:$skipRoundTrip {
        $r = New-LocalUser -Name $script:u2 -NoPassword -Disabled
        $r.Enabled | Should -BeFalse
        $r.PasswordRequired | Should -BeFalse
    }
    It 'renames a user and keeps the SID' -Skip:$skipRoundTrip {
        $sid = (Get-LocalUser -Name $script:u2).SID
        Rename-LocalUser -Name $script:u2 -NewName 'laccu3'
        try {
            (Get-LocalUser -Name 'laccu3').SID | Should -Be $sid
            @(Get-LocalUser -Name $script:u2 -ErrorAction SilentlyContinue).Count | Should -Be 0
            $null = Rename-LocalUser -Name laccu3 -NewName $script:u -ErrorAction SilentlyContinue -ErrorVariable ev
            $ev[0].FullyQualifiedErrorId | Should -Be 'NameInUse,Microsoft.PowerShell.Commands.RenameLocalUserCommand'
        }
        finally { Remove-LocalUser -Name laccu3 -ErrorAction SilentlyContinue }
        @(Get-LocalUser -Name laccu3 -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'creates, describes, renames and removes a group' -Skip:$skipRoundTrip {
        $r = New-LocalGroup -Name $script:g -Description 'lane group'
        $r.psobject.TypeNames[0] | Should -Be 'Microsoft.PowerShell.Commands.LocalGroup'
        $r.Description | Should -Be 'lane group'
        $r.SID.Value | Should -Match '^S-1-5-21-'
        $null = New-LocalGroup -Name $script:g -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'GroupExists,Microsoft.PowerShell.Commands.NewLocalGroupCommand'
        Set-LocalGroup -Name $script:g -Description 'new text'
        (Get-LocalGroup -Name $script:g).Description | Should -Be 'new text'
        $sid = (Get-LocalGroup -Name $script:g).SID
        Rename-LocalGroup -Name $script:g -NewName $script:g2
        (Get-LocalGroup -Name $script:g2).SID | Should -Be $sid
        Rename-LocalGroup -Name $script:g2 -NewName $script:g
    }
    It 'adds and removes group members (name, object, SID) with the Windows error ids' -Skip:$skipRoundTrip {
        Add-LocalGroupMember -Group $script:g -Member $script:u
        $m = @(Get-LocalGroupMember -Name $script:g)
        $m.Count | Should -Be 1
        $m[0].Name | Should -BeLike "*\$($script:u)"
        $m[0].ObjectClass | Should -Be 'User'
        $m[0].PrincipalSource | Should -Be 'Local'
        $null = Add-LocalGroupMember -Group $script:g -Member $script:u -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'MemberExists,Microsoft.PowerShell.Commands.AddLocalGroupMemberCommand'
        @(Get-LocalGroupMember -Name $script:g -Member $script:u).Count | Should -Be 1
        Remove-LocalGroupMember -Name $script:g -Member (Get-LocalUser -Name $script:u)
        @(Get-LocalGroupMember -Name $script:g).Count | Should -Be 0
        $null = Remove-LocalGroupMember -Name $script:g -Member $script:u -ErrorAction SilentlyContinue -ErrorVariable ev2
        $ev2[0].FullyQualifiedErrorId | Should -Be 'MemberNotFound,Microsoft.PowerShell.Commands.RemoveLocalGroupMemberCommand'
        Add-LocalGroupMember -SID (Get-LocalGroup -Name $script:g).SID -Member (Get-LocalUser -Name $script:u)
        @(Get-LocalGroupMember -Name $script:g).Count | Should -Be 1
        Remove-LocalGroupMember -Group (Get-LocalGroup -Name $script:g) -Member $script:u
        @(Get-LocalGroupMember -Name $script:g).Count | Should -Be 0
    }
    It 'removes users and groups (name, pipeline, SID) and they are gone' -Skip:$skipRoundTrip {
        Get-LocalUser -Name $script:u | Remove-LocalUser
        @(Get-LocalUser -Name $script:u -ErrorAction SilentlyContinue).Count | Should -Be 0
        Remove-LocalGroup -SID (Get-LocalGroup -Name $script:g).SID
        @(Get-LocalGroup -Name $script:g -ErrorAction SilentlyContinue).Count | Should -Be 0
        $null = Remove-LocalGroup -Name $script:g -ErrorAction SilentlyContinue -ErrorVariable ev
        $ev[0].FullyQualifiedErrorId | Should -Be 'GroupNotFound,Microsoft.PowerShell.Commands.RemoveLocalGroupCommand'
    }
}
