# src/powershell/Set-SentinelOptimization.ps1

<#
.SYNOPSIS
    Comprehensive Sentinel optimization and management script.
.DESCRIPTION
    Implements cost optimization, log routing, and performance tuning for Microsoft Sentinel.
.PARAMETER WorkspaceId
    The Log Analytics workspace ID.
.PARAMETER SubscriptionId
    The Azure subscription ID.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,
    
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "config/sentinel_optimization.yaml"
)

# Import required modules
Import-Module Az.SecurityInsights
Import-Module Az.OperationalInsights
Import-Module Az.Monitor

class SentinelOptimizer {
    [string]$WorkspaceId
    [string]$SubscriptionId
    [hashtable]$Config
    [System.Collections.ArrayList]$LogMetrics

    SentinelOptimizer([string]$WorkspaceId, [string]$SubscriptionId, [string]$ConfigPath) {
        $this.WorkspaceId = $WorkspaceId
        $this.SubscriptionId = $SubscriptionId
        $this.Config = $this.LoadConfiguration($ConfigPath)
        $this.LogMetrics = @()
    }

    [hashtable] LoadConfiguration([string]$ConfigPath) {
        try {
            $config = Get-Content -Path $ConfigPath | ConvertFrom-Yaml
            $this.ValidateConfiguration($config)
            return $config
        }
        catch {
            Write-Error "Failed to load configuration: $_"
            throw
        }
    }

    [void] ValidateConfiguration([hashtable]$Config) {
        $requiredParams = @(
            'retention_policies',
            'ingestion_thresholds',
            'table_configurations'
        )

        foreach ($param in $requiredParams) {
            if (-not $Config.ContainsKey($param)) {
                throw "Missing required configuration parameter: $param"
            }
        }
    }

    [void] OptimizeWorkspace() {
        Write-Verbose "Starting Sentinel workspace optimization..."
        
        # Analyze current state
        $this.AnalyzeIngestionPatterns()
        
        # Apply optimizations
        $this.OptimizeRetentionPolicies()
        $this.OptimizeTableConfigurations()
        $this.OptimizeQueryPerformance()
        
        # Generate report
        $this.GenerateOptimizationReport()
    }

    [void] AnalyzeIngestionPatterns() {
        Write-Verbose "Analyzing ingestion patterns..."
        
        $query = @"
        union withsource=TableName *
        | where TimeGenerated > ago(7d)
        | summarize 
            IngestionVolume=sum(_BilledSize),
            RecordCount=count() 
            by bin(TimeGenerated, 1h), TableName
"@

        $results = Invoke-AzOperationalInsightsQuery -WorkspaceId $this.WorkspaceId -Query $query
        
        foreach ($row in $results.Results) {
            $this.LogMetrics.Add(@{
                TimeGenerated = $row.TimeGenerated
                TableName = $row.TableName
                IngestionVolume = $row.IngestionVolume
                RecordCount = $row.RecordCount
            })
        }
    }

    [void] OptimizeRetentionPolicies() {
        Write-Verbose "Optimizing retention policies..."
        
        foreach ($table in $this.Config.table_configurations.Keys) {
            $retention = $this.Config.table_configurations[$table].retention
            
            try {
                Set-AzOperationalInsightsTable `
                    -WorkspaceId $this.WorkspaceId `
                    -TableName $table `
                    -RetentionInDays $retention
                
                Write-Verbose "Updated retention policy for $table to $retention days"
            }
            catch {
                Write-Error "Failed to update retention policy for $table: $_"
            }
        }
    }

    [void] OptimizeTableConfigurations() {
        Write-Verbose "Optimizing table configurations..."
        
        foreach ($table in $this.Config.table_configurations.Keys) {
            $config = $this.Config.table_configurations[$table]
            
            # Apply table-specific optimizations
            if ($config.Contains('filters')) {
                $this.ApplyTableFilters($table, $config.filters)
            }
            
            if ($config.Contains('transformations')) {
                $this.ApplyTableTransformations($table, $config.transformations)
            }
        }
    }

    [void] ApplyTableFilters($TableName, $Filters) {
        Write-Verbose "Applying filters to $TableName..."
        
        $filterQuery = $this.BuildFilterQuery($Filters)
        
        try {
            Set-AzOperationalInsightsStorageInsight `
                -WorkspaceId $this.WorkspaceId `
                -TableName $TableName `
                -Query $filterQuery
                
            Write-Verbose "Successfully applied filters to $TableName"
        }
        catch {
            Write-Error "Failed to apply filters to $TableName: $_"
        }
    }

    [string] BuildFilterQuery($Filters) {
        $filterClauses = @()
        
        foreach ($filter in $Filters) {
            switch ($filter.type) {
                "exclude" {
                    $filterClauses += "not($($filter.field) $($filter.operator) $($filter.value))"
                }
                "include" {
                    $filterClauses += "$($filter.field) $($filter.operator) $($filter.value)"
                }
            }
        }
        
        return $filterClauses -join " and "
    }

    [void] GenerateOptimizationReport() {
        Write-Verbose "Generating optimization report..."
        
        $report = @{
            Timestamp = Get-Date
            WorkspaceId = $this.WorkspaceId
            Metrics = @{
                TotalIngestionVolume = ($this.LogMetrics | Measure-Object -Property IngestionVolume -Sum).Sum
                TableMetrics = $this.GetTableMetrics()
                OptimizationActions = $this.GetOptimizationActions()
            }
        }

        $reportPath = "reports/optimization_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $report | ConvertTo-Json -Depth 10 | Out-File $reportPath
        
        Write-Verbose "Report generated: $reportPath"
    }

    [hashtable] GetTableMetrics() {
        $metrics = @{}
        
        foreach ($table in $this.LogMetrics.TableName | Select-Object -Unique) {
            $tableData = $this.LogMetrics | Where-Object { $_.TableName -eq $table }
            
            $metrics[$table] = @{
                TotalVolume = ($tableData | Measure-Object -Property IngestionVolume -Sum).Sum
                RecordCount = ($tableData | Measure-Object -Property RecordCount -Sum).Sum
                AverageHourlyVolume = ($tableData | Measure-Object -Property IngestionVolume -Average).Average
            }
        }
        
        return $metrics
    }
}

# Main execution
try {
    # Initialize optimizer
    $optimizer = [SentinelOptimizer]::new($WorkspaceId, $SubscriptionId, $ConfigPath)
    
    # Run optimization
    $optimizer.OptimizeWorkspace()
}
catch {
    Write-Error "Optimization failed: $_"
    exit 1
}