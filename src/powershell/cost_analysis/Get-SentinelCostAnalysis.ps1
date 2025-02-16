# src/powershell/cost_analysis/Get-SentinelCostAnalysis.ps1

<#
.SYNOPSIS
    Advanced cost analysis for Microsoft Sentinel
.DESCRIPTION
    Performs detailed cost analysis of Sentinel workspace including ingestion, storage, and query costs
.PARAMETER WorkspaceId
    The Log Analytics workspace ID
.PARAMETER Days
    Number of days to analyze
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30
)

class SentinelCostAnalyzer {
    [string]$WorkspaceId
    [int]$Days
    [hashtable]$CostMetrics
    [PSCustomObject]$Thresholds

    SentinelCostAnalyzer([string]$WorkspaceId, [int]$Days) {
        $this.WorkspaceId = $WorkspaceId
        $this.Days = $Days
        $this.CostMetrics = @{}
        $this.Thresholds = $this.LoadThresholds()
    }

    [PSCustomObject] LoadThresholds() {
        return @{
            DailyIngestionGB = 100
            QueryCostPerDay = 50
            StorageCostPerGB = @{
                Hot = 2.5
                Warm = 0.5
                Cold = 0.1
            }
        }
    }

    [void] AnalyzeCosts() {
        Write-Verbose "Starting cost analysis for workspace $($this.WorkspaceId)"
        
        # Analyze different cost components
        $this.AnalyzeIngestionCosts()
        $this.AnalyzeStorageCosts()
        $this.AnalyzeQueryCosts()
        
        # Generate recommendations
        $this.GenerateOptimizationRecommendations()
    }

    [void] AnalyzeIngestionCosts() {
        Write-Verbose "Analyzing ingestion costs..."
        
        $query = @"
        union withsource=TableName *
        | where TimeGenerated > ago($($this.Days)d)
        | summarize 
            IngestedGB = sum(_BilledSize)/(1024*1024*1024),
            RowCount = count()
            by bin(TimeGenerated, 1d), TableName
"@
        
        $results = Invoke-AzOperationalInsightsQuery -WorkspaceId $this.WorkspaceId -Query $query
        
        $this.CostMetrics.Ingestion = @{
            DailyStats = @{}
            TableStats = @{}
            TotalGB = 0
            EstimatedCost = 0
        }

        foreach ($row in $results.Results) {
            $date = $row.TimeGenerated.ToString('yyyy-MM-dd')
            $tableName = $row.TableName
            
            # Update daily stats
            if (-not $this.CostMetrics.Ingestion.DailyStats[$date]) {
                $this.CostMetrics.Ingestion.DailyStats[$date] = @{
                    TotalGB = 0
                    Tables = @{}
                }
            }
            
            $this.CostMetrics.Ingestion.DailyStats[$date].TotalGB += $row.IngestedGB
            $this.CostMetrics.Ingestion.DailyStats[$date].Tables[$tableName] = $row.IngestedGB
            
            # Update table stats
            if (-not $this.CostMetrics.Ingestion.TableStats[$tableName]) {
                $this.CostMetrics.Ingestion.TableStats[$tableName] = @{
                    TotalGB = 0
                    DailyAverage = 0
                    RowCount = 0
                }
            }
            
            $this.CostMetrics.Ingestion.TableStats[$tableName].TotalGB += $row.IngestedGB
            $this.CostMetrics.Ingestion.TableStats[$tableName].RowCount += $row.RowCount
        }

        # Calculate averages and totals
        foreach ($table in $this.CostMetrics.Ingestion.TableStats.Keys) {
            $this.CostMetrics.Ingestion.TableStats[$table].DailyAverage = 
                $this.CostMetrics.Ingestion.TableStats[$table].TotalGB / $this.Days
            
            $this.CostMetrics.Ingestion.TotalGB += $this.CostMetrics.Ingestion.TableStats[$table].TotalGB
        }

        # Calculate estimated cost
        $this.CostMetrics.Ingestion.EstimatedCost = 
            $this.CostMetrics.Ingestion.TotalGB * $this.Thresholds.StorageCostPerGB.Hot
    }

    [void] AnalyzeStorageCosts() {
        Write-Verbose "Analyzing storage costs..."
        
        $this.CostMetrics.Storage = @{
            TierStats = @{
                Hot = @{
                    TotalGB = 0
                    Cost = 0
                }
                Warm = @{
                    TotalGB = 0
                    Cost = 0
                }
                Cold = @{
                    TotalGB = 0
                    Cost = 0
                }
            }
            TotalCost = 0
        }

        # Get storage details
        $storageConfig = Get-AzOperationalInsightsWorkspace -ResourceGroupName $this.WorkspaceId
        
        # Calculate tier-specific costs
        foreach ($table in $this.CostMetrics.Ingestion.TableStats.Keys) {
            $tier = $this.DetermineStorageTier($table)
            $totalGB = $this.CostMetrics.Ingestion.TableStats[$table].TotalGB
            
            $this.CostMetrics.Storage.TierStats[$tier].TotalGB += $totalGB
            $this.CostMetrics.Storage.TierStats[$tier].Cost += 
                $totalGB * $this.Thresholds.StorageCostPerGB[$tier]
        }

        # Calculate total storage cost
        $this.CostMetrics.Storage.TotalCost = 
            $this.CostMetrics.Storage.TierStats.Values | 
            Measure-Object -Property Cost -Sum | 
            Select-Object -ExpandProperty Sum
    }

    [void] AnalyzeQueryCosts() {
        Write-Verbose "Analyzing query costs..."
        
        $query = @"
        _LogOperation
        | where TimeGenerated > ago($($this.Days)d)
        | where Operation == "Query"
        | extend QueryCost = _BilledSize/(1024*1024)
        | summarize 
            TotalQueries = count(),
            TotalCost = sum(QueryCost)
            by bin(TimeGenerated, 1d)
"@
        
        $results = Invoke-AzOperationalInsightsQuery -WorkspaceId $this.WorkspaceId -Query $query
        
        $this.CostMetrics.Queries = @{
            DailyStats = @{}
            TotalQueries = 0
            TotalCost = 0
            AverageCostPerQuery = 0
        }

        foreach ($row in $results.Results) {
            $date = $row.TimeGenerated.ToString('yyyy-MM-dd')
            
            $this.CostMetrics.Queries.DailyStats[$date] = @{
                QueryCount = $row.TotalQueries
                Cost = $row.TotalCost
            }
            
            $this.CostMetrics.Queries.TotalQueries += $row.TotalQueries
            $this.CostMetrics.Queries.TotalCost += $row.TotalCost
        }

        if ($this.CostMetrics.Queries.TotalQueries -gt 0) {
            $this.CostMetrics.Queries.AverageCostPerQuery = 
                $this.CostMetrics.Queries.TotalCost / $this.CostMetrics.Queries.TotalQueries
        }
    }

    [string] DetermineStorageTier([string]$TableName) {
        $hotTables = @('SecurityAlert', 'SecurityEvent', 'SigninLogs')
        $warmTables = @('AuditLogs', 'AzureActivity')
        
        if ($TableName -in $hotTables) { return 'Hot' }
        if ($TableName -in $warmTables) { return 'Warm' }
        return 'Cold'
    }

    [void] GenerateOptimizationRecommendations() {
        Write-Verbose "Generating optimization recommendations..."
        
        $this.CostMetrics.Recommendations = @()

        # Check high ingestion tables
        foreach ($table in $this.CostMetrics.Ingestion.TableStats.Keys) {
            $dailyAvg = $this.CostMetrics.Ingestion.TableStats[$table].DailyAverage
            
            if ($dailyAvg -gt $this.Thresholds.DailyIngestionGB) {
                $this.CostMetrics.Recommendations += @{
                    Type = 'HighIngestion'
                    Target = $table
                    CurrentValue = $dailyAvg
                    Threshold = $this.Thresholds.DailyIngestionGB
                    Impact = 'High'
                    Suggestion = "Consider implementing filters or reducing retention for table: $table"
                }
            }
        }

        # Check storage tier optimization
        foreach ($table in $this.CostMetrics.Ingestion.TableStats.Keys) {
            $currentTier = $this.DetermineStorageTier($table)
            $potentialTier = $this.CalculateOptimalTier($table)
            
            if ($currentTier -ne $potentialTier) {
                $this.CostMetrics.Recommendations += @{
                    Type = 'StorageTier'
                    Target = $table
                    CurrentTier = $currentTier
                    RecommendedTier = $potentialTier
                    Impact = 'Medium'
                    Suggestion = "Consider moving table $table from $currentTier to $potentialTier tier"
                }
            }
        }

        # Check query cost optimization
        if ($this.CostMetrics.Queries.AverageCostPerQuery -gt $this.Thresholds.QueryCostPerDay) {
            $this.CostMetrics.Recommendations += @{
                Type = 'QueryOptimization'
                Target = 'Queries'
                CurrentValue = $this.CostMetrics.Queries.AverageCostPerQuery
                Threshold = $this.Thresholds.QueryCostPerDay
                Impact = 'Medium'
                Suggestion = "Consider optimizing queries to reduce data scan costs"
            }
        }
    }

    [string] CalculateOptimalTier([string]$TableName) {
        $stats = $this.CostMetrics.Ingestion.TableStats[$TableName]
        $dailyAvg = $stats.DailyAverage
        
        if ($dailyAvg -lt 1) { return 'Cold' }
        if ($dailyAvg -lt 10) { return 'Warm' }
        return 'Hot'
    }

    [void] GenerateReport([string]$OutputPath) {
        $report = @{
            Timestamp = Get-Date
            WorkspaceId = $this.WorkspaceId
            AnalysisPeriod = "$($this.Days) days"
            Summary = @{
                TotalCost = $this.CostMetrics.Ingestion.EstimatedCost + 
                           $this.CostMetrics.Storage.TotalCost + 
                           $this.CostMetrics.Queries.TotalCost
                IngestionCost = $this.CostMetrics.Ingestion.EstimatedCost
                StorageCost = $this.CostMetrics.Storage.TotalCost
                QueryCost = $this.CostMetrics.Queries.TotalCost
            }
            DetailedMetrics = $this.CostMetrics
            Recommendations = $this.CostMetrics.Recommendations
        }

        $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
        Write-Verbose "Cost analysis report generated: $OutputPath"
    }
}

# Main execution
try {
    $analyzer = [SentinelCostAnalyzer]::new($WorkspaceId, $Days)
    $analyzer.AnalyzeCosts()
    $analyzer.GenerateReport("cost_analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').json")
}
catch {
    Write-Error "Cost analysis failed: $_"
    exit 1
}