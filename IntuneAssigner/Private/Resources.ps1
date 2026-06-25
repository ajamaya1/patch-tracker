# Registry of assignable Intune resource types across every area.
# Each entry declaratively describes one assignable surface: where to list it
# on Microsoft Graph (beta), how to read its name/assignments, and how to write
# assignments back via the /assign action. Adding an area is a one-line change.

function Get-IaResourceRegistry {
    [CmdletBinding()]
    param()

    # Per-assignment @odata types required by some /assign actions.
    $dcAssign  = '#microsoft.graph.deviceConfigurationAssignment'
    $appAssign = '#microsoft.graph.mobileAppAssignment'

    @(
        # ----- Configuration -----
        [pscustomobject]@{ Key='configurationPolicies'; Area='Configuration'; Label='Settings catalog profile';
            ListPath='deviceManagement/configurationPolicies'; NameField='name'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='deviceConfigurations'; Area='Configuration'; Label='Device configuration profile';
            ListPath='deviceManagement/deviceConfigurations'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$dcAssign; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='groupPolicyConfigurations'; Area='Configuration'; Label='Administrative template (ADMX)';
            ListPath='deviceManagement/groupPolicyConfigurations'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Compliance -----
        [pscustomobject]@{ Key='deviceCompliancePolicies'; Area='Compliance'; Label='Compliance policy';
            ListPath='deviceManagement/deviceCompliancePolicies'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Scripts -----
        [pscustomobject]@{ Key='deviceManagementScripts'; Area='Scripts'; Label='Platform / PowerShell script';
            ListPath='deviceManagement/deviceManagementScripts'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='deviceManagementScriptAssignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='deviceShellScripts'; Area='Scripts'; Label='macOS shell script';
            ListPath='deviceManagement/deviceShellScripts'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='deviceManagementScriptAssignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Remediations -----
        [pscustomobject]@{ Key='deviceHealthScripts'; Area='Remediations'; Label='Remediation (health script)';
            ListPath='deviceManagement/deviceHealthScripts'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='deviceHealthScriptAssignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Windows Update -----
        [pscustomobject]@{ Key='windowsUpdateRings'; Area='Windows Update'; Label='Update ring';
            ListPath='deviceManagement/deviceConfigurations'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$dcAssign; ODataTypeContains='windowsUpdateForBusinessConfiguration'; HasIntent=$false }
        [pscustomobject]@{ Key='windowsFeatureUpdateProfiles'; Area='Windows Update'; Label='Feature update profile';
            ListPath='deviceManagement/windowsFeatureUpdateProfiles'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='windowsQualityUpdateProfiles'; Area='Windows Update'; Label='Quality update profile';
            ListPath='deviceManagement/windowsQualityUpdateProfiles'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='windowsDriverUpdateProfiles'; Area='Windows Update'; Label='Driver update profile';
            ListPath='deviceManagement/windowsDriverUpdateProfiles'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Endpoint security -----
        [pscustomobject]@{ Key='intents'; Area='Endpoint security'; Label='Security baseline / intent';
            ListPath='deviceManagement/intents'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Enrollment -----
        [pscustomobject]@{ Key='deviceEnrollmentConfigurations'; Area='Enrollment'; Label='Enrollment configuration';
            ListPath='deviceManagement/deviceEnrollmentConfigurations'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='enrollmentConfigurationAssignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Apps -----
        [pscustomobject]@{ Key='mobileApps'; Area='Apps'; Label='Application';
            ListPath='deviceAppManagement/mobileApps'; NameField='displayName'; ExpandAssignments=$true;
            AssignBodyKey='mobileAppAssignments'; AssignmentODataType=$appAssign; ODataTypeContains=$null; HasIntent=$true }
        [pscustomobject]@{ Key='mobileAppConfigurations'; Area='Apps'; Label='App configuration policy';
            ListPath='deviceAppManagement/mobileAppConfigurations'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='targetedManagedAppConfigurations'; Area='Apps'; Label='Managed app config (MAM)';
            ListPath='deviceAppManagement/targetedManagedAppConfigurations'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- App protection -----
        [pscustomobject]@{ Key='iosManagedAppProtections'; Area='App protection'; Label='iOS app protection policy';
            ListPath='deviceAppManagement/iosManagedAppProtections'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='androidManagedAppProtections'; Area='App protection'; Label='Android app protection policy';
            ListPath='deviceAppManagement/androidManagedAppProtections'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        [pscustomobject]@{ Key='windowsManagedAppProtections'; Area='App protection'; Label='Windows app protection policy';
            ListPath='deviceAppManagement/windowsManagedAppProtections'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Cloud PC (Windows 365) -----
        [pscustomobject]@{ Key='cloudPcProvisioningPolicies'; Area='Cloud PC'; Label='Provisioning policy';
            ListPath='deviceManagement/virtualEndpoint/provisioningPolicies'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
        # ----- Scope tags -----
        [pscustomobject]@{ Key='roleScopeTags'; Area='Scope tags'; Label='Scope tag';
            ListPath='deviceManagement/roleScopeTags'; NameField='displayName'; ExpandAssignments=$false;
            AssignBodyKey='assignments'; AssignmentODataType=$null; ODataTypeContains=$null; HasIntent=$false }
    )
}

function Resolve-IaResourceType {
    # Select registry entries by Key and/or Area (case-insensitive).
    [CmdletBinding()]
    param([string[]]$Area, [string[]]$Type)

    $all = Get-IaResourceRegistry
    if (-not $Area -and -not $Type) { return $all }
    $areaSet = @(); if ($Area) { $areaSet = @($Area | ForEach-Object { $_.ToLower() }) }
    $keySet  = @(); if ($Type) { $keySet  = @($Type | ForEach-Object { $_.ToLower() }) }
    $all | Where-Object { $keySet -contains $_.Key.ToLower() -or $areaSet -contains $_.Area.ToLower() }
}
