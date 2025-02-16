# src/powershell/policy_management/Set-SentinelPolicy.ps1

<#
.SYNOPSIS
    Advanced policy management for Microsoft Sentinel
.DESCRIPTION
    Manages and enforces policies for data retention, ingestion, and access
.PARAMETER WorkspaceId
    The Log Analytics workspace ID
.PARAMETER PolicyPath
    Path to policy configuration file
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,
    
    [Parameter(Mandatory = $true)]
    [string]$PolicyPath
)

class SentinelPolicyManager {
    [string]$WorkspaceId
    [hashtable]$Policies
    [System.Collections.ArrayList]$ValidationResults
    hidden [hashtable]$CurrentState

    SentinelPolicyManager([string]$WorkspaceId, [string]$PolicyPath) {
        $this.WorkspaceId = $WorkspaceId
        $this.ValidationResults = [System.Collections.ArrayList]::new()
        $this.LoadPolicies($PolicyPath)
        $this.LoadCurrentState()
    }

    [void] LoadPolicies([string]$PolicyPath) {
        if (-not (Test-Path $PolicyPath)) {
            throw "Policy file not found: $PolicyPath"
        }

        $this.Policies = Get-Content $PolicyPath | ConvertFrom-Json -AsHashtable
        $this.ValidatePolicies()
    }

    [void] LoadCurrentState() {
        $this.CurrentState = @{
            RetentionPolicies = $this.GetCurrentRetentionPolicies()
            DataSources = $this.GetCurrentDataSources()
            AccessPolicies = $this.GetCurrentAccessPolicies()
        }
    }

    [void] ValidatePolicies() {
        # Validate retention policies
        foreach ($policy in $this.Policies.RetentionPolicies) {
            if (-not $policy.TablePattern) {
                $this.AddValidationResult(
                    "RetentionPolicy",
                    "Error",
                    "Missing TablePattern in retention policy"
                )
            }
            if ($policy.RetentionDays -lt 0) {
                $this.AddValidationResult(
                    "RetentionPolicy",
                    "Error",
                    "Invalid retention period: $($policy.RetentionDays)"
                )
            }
        }

        # Validate data source policies
        foreach ($policy in $this.Policies.DataSources) {
            if (-not $policy.SourceType) {
                $this.AddValidationResult(
                    "DataSourcePolicy",
                    "Error",
                    "Missing SourceType in data source policy"
                )
            }
        }

        # Validate access policies
        foreach ($policy in $this.Policies.AccessPolicies) {
            if (-not $policy.RoleDefinition) {
                $this.AddValidationResult(
                    "AccessPolicy",
                    "Error",
                    "Missing RoleDefinition in access policy"
                )
            }
        }
    }

    [void] ApplyPolicies() {
        Write-Verbose "Applying Sentinel policies..."

        # Apply retention policies
        foreach ($policy in $this.Policies.RetentionPolicies) {
            $this.ApplyRetentionPolicy($policy)
        }

        # Apply data source policies
        foreach ($policy in $this.Policies.DataSources) {
            $this.ApplyDataSourcePolicy($policy)
        }

        # Apply access policies
        foreach ($policy in $this.Policies.AccessPolicies) {
            $this.ApplyAccessPolicy($policy)
        }
    }

    [void] ApplyRetentionPolicy([hashtable]$Policy) {
        Write-Verbose "Applying retention policy for pattern: $($Policy.TablePattern)"
        
        try {
            $tables = Get-AzOperationalInsightsTable -WorkspaceId $this.WorkspaceId |
                Where-Object Name -Match $Policy.TablePattern

            foreach ($table in $tables) {
                Set-AzOperationalInsightsTable `
                    -WorkspaceId $this.WorkspaceId `
                    -TableName $table.Name `
                    -RetentionInDays $Policy.RetentionDays

                Write-Verbose "Updated retention for table $($table.Name) to $($Policy.RetentionDays) days"
            }
        }
        catch {
            $this.AddValidationResult(
                "RetentionPolicy",
                "Error",
                "Failed to apply retention policy: $_"
            )
        }
    }

    [void] ApplyDataSourcePolicy([hashtable]$Policy) {
        Write-Verbose "Applying data source policy for: $($Policy.SourceType)"
        
        try {
            switch ($Policy.SourceType) {
                "WindowsEvent" {
                    Set-AzOperationalInsightsWindowsEventDataSource `
                        -WorkspaceId $this.WorkspaceId `
                        -Name $Policy.Name `
                        -EventLogNames $Policy.EventLogs `
                        -CollectErrors $Policy.CollectErrors `
                        -CollectWarnings $Policy.CollectWarnings `
                        -CollectInformation $Policy.CollectInformation
                }
                "WindowsPerformanceCounter" {
                    Set-AzOperationalInsightsWindowsPerformanceCounterDataSource `
                        -WorkspaceId $this.WorkspaceId `
                        -Name $Policy.Name `
                        -ObjectName $Policy.ObjectName `
                        -CounterName $Policy.CounterName `
                        -InstanceName $Policy.InstanceName `
                        -IntervalSeconds $Policy.IntervalSeconds
                }
                default {
                    throw "Unsupported data source type: $($Policy.SourceType)"
                }
            }
        }
        catch {
            $this.AddValidationResult(
                "DataSourcePolicy",
                "Error",
                "Failed to apply data source policy: $_"
            )
        }
    }

    [void] ApplyAccessPolicy([hashtable]$Policy) {
        Write-Verbose "Applying access policy for role: $($Policy.RoleDefinition)"
        
        try {
            New-AzRoleAssignment `
                -WorkspaceId $this.WorkspaceId `
                -RoleDefinitionName $Policy.RoleDefinition `
                -ObjectId $Policy.ObjectId
        }
        catch {
            $this.AddValidationResult(
                "AccessPolicy",
                "Error",
                "Failed to apply access policy: $_"
            )
        }
    }

    [hashtable] GetCurrentRetentionPolicies() {
        $policies = @{}
        
        try {
            $tables = Get-AzOperationalInsightsTable -WorkspaceId $this.WorkspaceId
            foreach ($table in $tables) {
                $policies[$table.Name] = @{
                    RetentionDays = $table.RetentionInDays
                    LastModified = $table.LastModified
                }
            }
        }
        catch {
            Write-Warning "Failed to get current retention policies: $_"
        }
        
        return $policies
    }

    [hashtable] GetCurrentDataSources() {
        $sources = @{}
        
        try {
            # Get Windows Event data sources
            $eventSources = Get-AzOperationalInsightsWindowsEventDataSource `
                -WorkspaceId $this.WorkspaceId
            
            foreach ($source in $eventSources) {
                $sources[$source.Name] = @{
                    Type = "WindowsEvent"
                    Configuration = $source
                }
            }

            # Get Performance Counter data sources
            $counterSources = Get-AzOperationalInsightsWindowsPerformanceCounterDataSource `
                -WorkspaceId $this.WorkspaceId
            
            foreach ($source in $counterSources) {
                $sources[$source.Name] = @{
                    Type = "WindowsPerformanceCounter"
                    Configuration = $source
                }
            }
        }
        catch {
            Write-Warning "Failed to get current data sources: $_"
        }
        
        return $sources
    }

    [hashtable] GetCurrentAccessPolicies() {
        $policies = @{}
        
        try {
            $assignments = Get-AzRoleAssignment -Scope $this.WorkspaceId
            foreach ($assignment in $assignments) {
                $policies[$assignment.ObjectId] = @{
                    RoleDefinition = $assignment.RoleDefinitionName
                    PrincipalType = $assignment.PrincipalType
                    Scope = $assignment.Scope
                }
            }
        }
        catch {
            Write-Warning "Failed to get current access policies: $_"
        }
        
        return $policies
    }

    [void] AddValidationResult([string]$PolicyType, [string]$Severity, [string]$Message) {
        $result = @{
            Timestamp = Get-Date
            PolicyType = $PolicyType
            Severity = $Severity
            Message = $Message
        }
        
        $this.ValidationResults.Add($result)
        
        if ($Severity -eq "Error") {
            Write-Error "[$PolicyType] $Message"
        }
        else {
            Write-Warning "[$PolicyType] $Message"
        }
    }

    [void] GenerateReport([string]$OutputPath) {
        $report = @{
            Timestamp = Get-Date
            WorkspaceId = $this.WorkspaceId
            AppliedPolicies = $this.Policies
            CurrentState = $this.CurrentState
            ValidationResults = $this.ValidationResults
            Summary = @{
                TotalPolicies = @{
                    Retention = $this.Policies.RetentionPolicies.Count
                    DataSource = $this.Policies.DataSources.Count
                    Access = $this.Policies.AccessPolicies.Count
                }
                ValidationIssues = @{
                    Errors = ($this.ValidationResults | Where-Object Severity -eq "Error").Count
                    Warnings = ($this.ValidationResults | Where-Object Severity -eq "Warning").Count
                }
            }
        }

        $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
        Write-Verbose "Policy management report generated: $OutputPath"
    }
}

# Main execution
try {
    $policyManager = [SentinelPolicyManager]::new($WorkspaceId, $PolicyPath)
    $policyManager.ApplyPolicies()
    $policyManager.GenerateReport(
        "policy_management_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    )
}
catch {
    Write-Error "Policy management failed: $_"
    exit 1
}