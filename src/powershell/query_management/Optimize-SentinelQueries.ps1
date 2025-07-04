# src/powershell/query_management/Optimize-SentinelQueries.ps1

<#
.SYNOPSIS
    Advanced query optimization and management for Microsoft Sentinel
.DESCRIPTION
    Analyzes, optimizes, and manages KQL queries with performance tracking and cost optimization
.PARAMETER WorkspaceId
    The Log Analytics workspace ID
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $false)]
    [string]$QueryLibraryPath = "config/queries"
)

class QueryOptimizationManager {
    [string]$WorkspaceId
    [string]$QueryLibraryPath
    [string]$RuleConfigPath # Add new property
    [hashtable]$OptimizationRules
    [System.Collections.ArrayList]$OptimizationHistory

    QueryOptimizationManager([string]$WorkspaceId, [string]$QueryLibraryPath, [string]$RuleConfigPath = "config/powershell_optimizer_rules.json") {
        $this.WorkspaceId = $WorkspaceId
        $this.QueryLibraryPath = $QueryLibraryPath
        $this.RuleConfigPath = $RuleConfigPath
        $this.OptimizationHistory = [System.Collections.ArrayList]::new()
        $this.InitializeOptimizationRules()
    }

    [void] InitializeOptimizationRules() {
        Write-Verbose "Loading optimization rules from $($this.RuleConfigPath)..."
        try {
            $jsonContent = Get-Content -Raw -Path $this.RuleConfigPath -ErrorAction Stop
            $loadedRules = ConvertFrom-Json -InputObject $jsonContent -ErrorAction Stop
            $this.OptimizationRules = @{} # Initialize as Hashtable
            foreach ($rule in $loadedRules) {
                $this.OptimizationRules[$rule.RuleName] = $rule # Store the whole rule object
            }
            Write-Verbose "Successfully loaded $($this.OptimizationRules.Count) rules."
        }
        catch {
            Write-Error "Failed to load or parse optimization rules from $($this.RuleConfigPath): $_"
            # Fallback to empty rules or handle error as appropriate
            $this.OptimizationRules = @{}
        }
    }

    [void] OptimizeQueries() {
        Write-Verbose "Starting query optimization process..."

        # Get all query files
        $queryFiles = Get-ChildItem -Path $this.QueryLibraryPath -Filter "*.kql" -Recurse

        foreach ($file in $queryFiles) {
            try {
                $originalQuery = Get-Content $file.FullName -Raw
                $optimizedQuery = $this.OptimizeQuery($originalQuery)

                # Benchmark the optimization
                $benchmarkResults = $this.BenchmarkQueries($originalQuery, $optimizedQuery)

                # Save optimization if beneficial
                if ($benchmarkResults.Improvement -gt 10) {
                    $this.SaveOptimizedQuery($file, $optimizedQuery, $benchmarkResults)
                }

                # Record optimization history
                $this.RecordOptimization($file.Name, $benchmarkResults)
            }
            catch {
                Write-Error "Error optimizing query $($file.Name): $_"
                continue
            }
        }

        # Generate optimization report
        $this.GenerateOptimizationReport()
    }

    [string] OptimizeQuery([string]$query) {
        $optimizedQuery = $query

        foreach ($ruleName in $this.OptimizationRules.Keys) {
            $rule = $this.OptimizationRules[$ruleName]
            $pattern = $rule.Pattern
            $replacement = $rule.Replacement # Using the replacement string directly

            try {
                if ($optimizedQuery -match $pattern) {
                    # For simple replacement from JSON. Capture groups like $1, $2 work here.
                    $optimizedQuery = $optimizedQuery -replace $pattern, $replacement
                    Write-Verbose "Applied rule `"$($rule.RuleName)`" using simple replacement."
                }
            }
            catch {
                Write-Warning "Failed to apply rule `"$($rule.RuleName)`" with pattern `"$pattern`": $_"
            }
        }

        return $optimizedQuery
    }

    [hashtable] BenchmarkQueries([string]$original, [string]$optimized) {
        $results = @{
            OriginalMetrics = $this.MeasureQueryPerformance($original)
            OptimizedMetrics = $this.MeasureQueryPerformance($optimized)
            Improvement = 0.0
            Recommendations = @()
        }

        # Calculate improvement percentage
        if ($results.OriginalMetrics.ExecutionTime -gt 0) {
            $results.Improvement = (
                ($results.OriginalMetrics.ExecutionTime - $results.OptimizedMetrics.ExecutionTime) /
                $results.OriginalMetrics.ExecutionTime
            ) * 100
        }

        # Generate recommendations
        if ($results.OptimizedMetrics.DataScanned -gt 1GB) {
            $results.Recommendations += "Consider adding more specific time filters"
        }
        if ($results.OptimizedMetrics.ExecutionTime -gt 30) {
            $results.Recommendations += "Consider implementing query partitioning"
        }

        return $results
    }

    [hashtable] MeasureQueryPerformance([string]$query) {
        $metrics = @{
            ExecutionTime = 0.0
            DataScanned = 0
            ResultCount = 0
            ResourceUtilization = 0.0
        }

        try {
            $start = Get-Date
            $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $this.WorkspaceId -Query $query
            $end = Get-Date

            $metrics.ExecutionTime = ($end - $start).TotalSeconds
            $metrics.DataScanned = $result.Statistics.DataProcessedMB * 1MB
            $metrics.ResultCount = $result.Results.Count
            $metrics.ResourceUtilization = $result.Statistics.ResourceUtilization

            return $metrics
        }
        catch {
            Write-Error "Error measuring query performance: $_"
            return $metrics
        }
    }

    [void] SaveOptimizedQuery([System.IO.FileInfo]$file, [string]$optimizedQuery, [hashtable]$benchmarkResults) {
        $optimizedPath = $file.FullName -replace '\.kql$', '_optimized.kql'
        
        # Add optimization metadata as comments
        $metadata = @"
// Optimized Query
// Original File: $($file.Name)
// Optimization Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
// Performance Improvement: $($benchmarkResults.Improvement)%
// Execution Time: $($benchmarkResults.OptimizedMetrics.ExecutionTime) seconds
// Data Scanned: $($benchmarkResults.OptimizedMetrics.DataScanned / 1MB) MB
// Recommendations:
$($benchmarkResults.Recommendations | ForEach-Object { "// - $_" })

$optimizedQuery
"@

        $metadata | Out-File -FilePath $optimizedPath -Encoding UTF8
    }

    [void] RecordOptimization([string]$queryName, [hashtable]$benchmarkResults) {
        $optimization = @{
            Timestamp = Get-Date
            QueryName = $queryName
            Improvement = $benchmarkResults.Improvement
            OriginalMetrics = $benchmarkResults.OriginalMetrics
            OptimizedMetrics = $benchmarkResults.OptimizedMetrics
            Recommendations = $benchmarkResults.Recommendations
        }

        $this.OptimizationHistory.Add($optimization)
    }

    [void] GenerateOptimizationReport() {
        $report = @{
            Timestamp = Get-Date
            Summary = @{
                TotalQueries = $this.OptimizationHistory.Count
                AverageImprovement = ($this.OptimizationHistory | 
                    Measure-Object -Property Improvement -Average).Average
                TopImprovements = $this.OptimizationHistory |
                    Sort-Object Improvement -Descending |
                    Select-Object -First 5
            }
            DetailedResults = $this.OptimizationHistory |
                Group-Object QueryName |
                ForEach-Object {
                    @{
                        QueryName = $_.Name
                        Improvements = $_.Group |
                            Select-Object Improvement, Recommendations
                    }
                }
            Recommendations = $this.OptimizationHistory.Recommendations |
                Group-Object |
                Select-Object Name, Count |
                Sort-Object Count -Descending
        }

        # Save report
        $reportPath = Join-Path $this.QueryLibraryPath "optimization_report.json"
        $report | ConvertTo-Json -Depth 10 | Out-File $reportPath

        # Generate HTML report
        $this.GenerateHTMLReport($report)
    }

    [void] GenerateHTMLReport([hashtable]$report) {
        $htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <title>Query Optimization Report</title>
    <style>
        /* Add CSS styles here */
    </style>
</head>
<body>
    <h1>Query Optimization Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Queries: $($report.Summary.TotalQueries)</p>
        <p>Average Improvement: $($report.Summary.AverageImprovement)%</p>
    </div>
    <div class="top-improvements">
        <h2>Top Improvements</h2>
        <table>
            <tr>
                <th>Query</th>
                <th>Improvement</th>
            </tr>
            $(
                $report.Summary.TopImprovements | ForEach-Object {
                    "<tr><td>$($_.QueryName)</td><td>$($_.Improvement)%</td></tr>"
                }
            )
        </table>
    </div>
    <div class="recommendations">
        <h2>Common Recommendations</h2>
        <ul>
            $(
                $report.Recommendations | ForEach-Object {
                    "<li>$($_.Name) (Count: $($_.Count))</li>"
                }
            )
        </ul>
    </div>
</body>
</html>
"@

        $htmlPath = Join-Path $this.QueryLibraryPath "optimization_report.html"
        $htmlTemplate | Out-File $htmlPath
    }
}

# Main execution
try {
    $optimizer = [QueryOptimizationManager]::new($WorkspaceId, $QueryLibraryPath)
    $optimizer.OptimizeQueries()
}
catch {
    Write-Error "Query optimization failed: $_"
    exit 1
}