#requires -Modules Pester
# Pester v5 tests. Graph is mocked at the Invoke-IaRequest seam, so these run
# fully offline. Run from the module folder:  Invoke-Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'IntuneTide.psd1') -Force
}

Describe 'Resource registry' {
    It 'has unique keys and covers new areas' {
        InModuleScope IntuneTide {
            $reg = Get-IaResourceRegistry
            ($reg.Key | Select-Object -Unique).Count | Should -Be $reg.Count
            $reg.Key | Should -Contain 'cloudPcProvisioningPolicies'
            $reg.Key | Should -Contain 'roleScopeTags'
            $reg.Area | Should -Contain 'Cloud PC'
        }
    }
    It 'resolves types by area and key' {
        InModuleScope IntuneTide {
            (Resolve-IaResourceType -Area 'Apps').Key | Should -Contain 'mobileApps'
            (Resolve-IaResourceType -Type 'intents').Count | Should -Be 1
        }
    }
}

Describe 'Assignment model' {
    It 'parses a group target with a filter' {
        InModuleScope IntuneTide {
            $t = ConvertFrom-IaTarget -Target ([pscustomobject]@{
                '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1'
                deviceAndAppManagementAssignmentFilterId = 'f1'
                deviceAndAppManagementAssignmentFilterType = 'include' })
            $t.Kind | Should -Be 'group'
            $t.IsExclude | Should -BeFalse
            $t.FilterType | Should -Be 'include'
        }
    }
    It 'preserves a Cloud PC target @odata.type on write' {
        InModuleScope IntuneTide {
            $t = ConvertFrom-IaTarget -Target ([pscustomobject]@{
                '@odata.type' = '#microsoft.graph.cloudPcManagementGroupAssignmentTarget'; groupId = 'g1' })
            $t.Kind | Should -Be 'group'
            (ConvertTo-IaTargetBody -Target $t)['@odata.type'] |
                Should -Be '#microsoft.graph.cloudPcManagementGroupAssignmentTarget'
        }
    }
    It 'keeps type-specific assignment fields (remediation runSchedule)' {
        InModuleScope IntuneTide {
            $a = ConvertFrom-IaAssignment -Item ([pscustomobject]@{
                id = 'x'; source = 'direct'
                target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' }
                runRemediationScript = $true
                runSchedule = [pscustomobject]@{ interval = 1 } })
            $body = ConvertTo-IaAssignmentBody -Assignment $a
            $body.runRemediationScript | Should -BeTrue
            $body.runSchedule.interval | Should -Be 1
            $body.ContainsKey('id') | Should -BeFalse
        }
    }
}

Describe 'Inventory, compare and copy (mocked Graph)' {
    BeforeEach {
        InModuleScope IntuneTide {
            Reset-IaDirectoryCache
            $script:Posts = [System.Collections.Generic.List[object]]::new()
            $script:Groups = @{
                'aaaa' = 'All Workstations'; 'bbbb' = 'Pilot Ring'; 'cccc' = 'New Devices'
            }
            function script:tgt($id, $excl) {
                [pscustomobject]@{ '@odata.type' = $(if ($excl) { '#microsoft.graph.exclusionGroupAssignmentTarget' } else { '#microsoft.graph.groupAssignmentTarget' }); groupId = $id }
            }
            Mock Invoke-IaRequest {
                if ($Method -eq 'POST') { $script:Posts.Add([pscustomobject]@{ Uri = $Uri; Body = $Body }); return $null }
                if ($Uri -match '/members/\$count') { return 0 }
                if ($Uri -match 'assignmentFilters') { return [pscustomobject]@{ value = @() } }
                if ($Uri -match '/groups/([^?]+)') {
                    $gid = $Matches[1]
                    if ($script:Groups.ContainsKey($gid)) { return [pscustomobject]@{ id = $gid; displayName = $script:Groups[$gid] } }
                    throw 'not found'
                }
                if ($Uri -match 'configurationPolicies') {
                    return [pscustomobject]@{ value = @(
                        [pscustomobject]@{ id = 'cp1'; name = 'Win Baseline'; '@odata.type' = '#x'
                            assignments = @([pscustomobject]@{ target = (tgt 'aaaa' $false) }, [pscustomobject]@{ target = (tgt 'bbbb' $true) }) }
                        [pscustomobject]@{ id = 'cp2'; name = 'Only-A'; '@odata.type' = '#x'
                            assignments = @([pscustomobject]@{ target = (tgt 'aaaa' $false) }) }
                    ) }
                }
                return [pscustomobject]@{ value = @() }
            }
        }
    }

    It 'enumerates and resolves group names + exclude intent' {
        InModuleScope IntuneTide {
            $items = Get-IaInventory -Type 'configurationPolicies' -AssignedOnly
            $cp = $items | Where-Object Name -eq 'Win Baseline'
            ($cp.Assignments | Where-Object { -not $_.Target.IsExclude }).Target.GroupName | Should -Be 'All Workstations'
            ($cp.Assignments | Where-Object { $_.Target.IsExclude }).Target.GroupName | Should -Be 'Pilot Ring'
        }
    }

    It 'compares two groups into buckets' {
        InModuleScope IntuneTide {
            $items = Get-IaInventory -Type 'configurationPolicies' -AssignedOnly
            (Get-IaItemGroupMode -Item ($items | Where-Object Name -eq 'Win Baseline') -GroupId 'bbbb') | Should -Be 'exclude'
            (Get-IaItemGroupMode -Item ($items | Where-Object Name -eq 'Only-A') -GroupId 'bbbb') | Should -Be 'none'
        }
    }

    It 'copies selected resources and posts merged assignments' {
        InModuleScope IntuneTide {
            $items = Get-IaInventory -Type 'configurationPolicies' -AssignedOnly
            $plans = Invoke-IaCopy -Items $items -SrcId 'aaaa' -DstId 'cccc' -DstName 'New Devices' -IncludeIds @('cp2') -Commit
            @($plans | Where-Object Added).Count | Should -Be 1
            $script:Posts.Count | Should -Be 1
            $script:Posts[0].Uri | Should -Match 'configurationPolicies/cp2/assign'
        }
    }

    It 'preview (no -Commit) writes nothing' {
        InModuleScope IntuneTide {
            $items = Get-IaInventory -Type 'configurationPolicies' -AssignedOnly
            $null = Invoke-IaCopy -Items $items -SrcId 'aaaa' -DstId 'cccc'
            $script:Posts.Count | Should -Be 0
        }
    }
}
