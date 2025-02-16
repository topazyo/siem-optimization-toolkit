# src/powershell/ingestion_monitoring/Watch-SentinelIngestion.ps1

<#
.SYNOPSIS
    Advanced ingestion monitoring for Microsoft Sentinel
.DESCRIPTION
    Monitors and analyzes log ingestion patterns, alerts on anomalies
.PARAMETER WorkspaceId
    The Log Analytics workspace ID
.PARAMETER AlertThreshold
    Percentage increase that triggers an alert
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,
    
    [Parameter(Mandatory = $false)]
    [int]$AlertThreshold = 50
)

# src/powershell/ingestion_monitoring/Watch-SentinelIngestion.ps1 (continued)

class SentinelIngestionMonitor {
    [string]$WorkspaceId
    [int]$AlertThreshold
    [hashtable]$BaselineMetrics
    [hashtable]$CurrentMetrics
    [System.Collections.ArrayList]$Alerts
    hidden [string]$MetricsPath

    SentinelIngestionMonitor([string]$WorkspaceId, [int]$AlertThreshold) {
        $this.WorkspaceId = $WorkspaceId
        $this.AlertThreshold = $AlertThreshold
        $this.Alerts = [System.Collections.ArrayList]::new()
        $this.MetricsPath = "metrics/ingestion"
        $this.LoadBaseline()
    }

    [void] LoadBaseline() {
        $baselinePath = Join-Path $this.MetricsPath "baseline.json"
        if (Test-Path $baselinePath) {
            $this.BaselineMetrics = Get-Content $baselinePath | ConvertFrom-Json -AsHashtable
        }
        else {
            $this.BaselineMetrics = @{
                Tables = @{}
                DailyAverages = @{}
                HourlyPatterns = @{}
            }
        }
    }

    [void] MonitorIngestion() {
        Write-Verbose "Starting ingestion monitoring..."
        
        # Get current metrics
        $this.CollectCurrentMetrics()
        
        # Analyze patterns
        $this.AnalyzePatterns()
        
        # Check for anomalies
        $this.DetectAnomalies()
        
        # Update baseline if needed
        $this.UpdateBaseline()
    }

    [void] CollectCurrentMetrics() {
        $query = @"
        union withsource=TableName *
        | where TimeGenerated > ago(1h)
        | summarize 
            IngestionLatency=max(ingestion_time()-TimeGenerated),
            IngestionVolume=sum(_BilledSize),
            RecordCount=count()
            by bin(TimeGenerated, 5m), TableName
"@

        $results = Invoke-AzOperationalInsightsQuery -WorkspaceId $this.WorkspaceId -Query $query
        
        $this.CurrentMetrics = @{
            Tables = @{}
            Volumes = @{}
            Latencies = @{}
            Timestamp = Get-Date
        }

        foreach ($row in $results.Results) {
            $tableName = $row.TableName
            $timeSlot = $row.TimeGenerated.ToString('yyyy-MM-dd HH:mm')
            
            if (-not $this.CurrentMetrics.Tables[$tableName]) {
                $this.CurrentMetrics.Tables[$tableName] = @{
                    TimeSlots = @{}
                    TotalVolume = 0
                    MaxLatency = 0
                    RecordCount = 0
                }
            }

            $this.CurrentMetrics.Tables[$tableName].TimeSlots[$timeSlot] = @{
                Volume = $row.IngestionVolume
                Latency = $row.IngestionLatency
                Records = $row.RecordCount
            }

            $this.CurrentMetrics.Tables[$tableName].TotalVolume += $row.IngestionVolume
            $this.CurrentMetrics.Tables[$tableName].RecordCount += $row.RecordCount
            
            if ($row.IngestionLatency -gt $this.CurrentMetrics.Tables[$tableName].MaxLatency) {
                $this.CurrentMetrics.Tables[$tableName].MaxLatency = $row.IngestionLatency
            }
        }
    }

    [void] AnalyzePatterns() {
        foreach ($tableName in $this.CurrentMetrics.Tables.Keys) {
            $currentStats = $this.CurrentMetrics.Tables[$tableName]
            $baselineStats = $this.BaselineMetrics.Tables[$tableName]

            if ($baselineStats) {
                # Calculate volume deviation
                $volumeDeviation = $this.CalculateDeviation(
                    $currentStats.TotalVolume,
                    $baselineStats.AverageVolume
                )

                # Calculate latency deviation
                $latencyDeviation = $this.CalculateDeviation(
                    $currentStats.MaxLatency,
                    $baselineStats.AverageLatency
                )

                # Check for significant deviations
                if ($volumeDeviation -gt $this.AlertThreshold) {
                    $this.AddAlert(
                        "VolumeAnomaly",
                        $tableName,
                        "Volume deviation of ${volumeDeviation}% detected",
                        "High"
                    )
                }

                if ($latencyDeviation -gt $this.AlertThreshold) {
                    $this.AddAlert(
                        "LatencyAnomaly",
                        $tableName,
                        "Latency deviation of ${latencyDeviation}% detected",
                        "High"
                    )
                }
            }
        }
    }

    [void] DetectAnomalies() {
        # Detect pattern anomalies
        foreach ($tableName in $this.CurrentMetrics.Tables.Keys) {
            $currentStats = $this.CurrentMetrics.Tables[$tableName]
            
            # Check for sudden spikes
            $timeSlots = $currentStats.TimeSlots.Keys | Sort-Object
            $volumes = $timeSlots | ForEach-Object { $currentStats.TimeSlots[$_].Volume }
            
            $spikeDetected = $this.DetectSpikes($volumes)
            if ($spikeDetected) {
                $this.AddAlert(
                    "VolumeSpikeDetected",
                    $tableName,
                    "Sudden volume spike detected",
                    "Medium"
                )
            }

            # Check for data gaps
            $gaps = $this.DetectDataGaps($timeSlots)
            if ($gaps.Count -gt 0) {
                $this.AddAlert(
                    "DataGapDetected",
                    $tableName,
                    "Data gaps detected: $($gaps -join ', ')",
                    "High"
                )
            }
        }
    }

    [void] UpdateBaseline() {
        foreach ($tableName in $this.CurrentMetrics.Tables.Keys) {
            if (-not $this.BaselineMetrics.Tables[$tableName]) {
                $this.BaselineMetrics.Tables[$tableName] = @{
                    AverageVolume = 0
                    AverageLatency = 0
                    SampleCount = 0
                }
            }

            $baseline = $this.BaselineMetrics.Tables[$tableName]
            $current = $this.CurrentMetrics.Tables[$tableName]

            # Update moving averages
            $baseline.AverageVolume = (
                ($baseline.AverageVolume * $baseline.SampleCount) + $current.TotalVolume
            ) / ($baseline.SampleCount + 1)

            $baseline.AverageLatency = (
                ($baseline.AverageLatency * $baseline.SampleCount) + $current.MaxLatency
            ) / ($baseline.SampleCount + 1)

            $baseline.SampleCount++
        }

        # Save updated baseline
        $this.SaveBaseline()
    }

    [void] SaveBaseline() {
        if (-not (Test-Path $this.MetricsPath)) {
            New-Item -ItemType Directory -Path $this.MetricsPath -Force
        }

        $baselinePath = Join-Path $this.MetricsPath "baseline.json"
        $this.BaselineMetrics | ConvertTo-Json -Depth 10 | Out-File $baselinePath
    }

    [float] CalculateDeviation([float]$current, [float]$baseline) {
        if ($baseline -eq 0) { return 0 }
        return [Math]::Abs(($current - $baseline) / $baseline * 100)
    }

    [bool] DetectSpikes([array]$values) {
        if ($values.Count -lt 3) { return $false }
        
        $mean = ($values | Measure-Object -Average).Average
        $stdDev = [Math]::Sqrt(
            ($values | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
        )
        
        $threshold = $mean + (3 * $stdDev)
        return ($values[-1] -gt $threshold)
    }

    [array] DetectDataGaps([array]$timeSlots) {
        $gaps = @()
        for ($i = 1; $i -lt $timeSlots.Count; $i++) {
            $previous = [datetime]$timeSlots[$i-1]
            $current = [datetime]$timeSlots[$i]
            
            if (($current - $previous).TotalMinutes -gt 10) {
                $gaps += "$previous -> $current"
            }
        }
        return $gaps
    }

    [void] AddAlert([string]$Type, [string]$Target, [string]$Message, [string]$Severity) {
        $alert = @{
            Timestamp = Get-Date
            Type = $Type
            Target = $Target
            Message = $Message
            Severity = $Severity
        }
        
        $this.Alerts.Add($alert)
        
        # Log alert
        Write-Warning "[$Severity] $Type - $Target : $Message"
    }

    [void] GenerateReport([string]$OutputPath) {
        $report = @{
            Timestamp = Get-Date
            WorkspaceId = $this.WorkspaceId
            Metrics = $this.CurrentMetrics
            Baseline = $this.BaselineMetrics
            Alerts = $this.Alerts
            Summary = @{
                TotalTables = $this.CurrentMetrics.Tables.Count
                TotalAlerts = $this.Alerts.Count
                AlertsByType = ($this.Alerts | Group-Object Type | ForEach-Object {
                    @{
                        $_.Name = $_.Count
                    }
                })
            }
        }

        $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
        Write-Verbose "Ingestion monitoring report generated: $OutputPath"
    }
}

# Main execution
try {
    $monitor = [SentinelIngestionMonitor]::new($WorkspaceId, $AlertThreshold)
    $monitor.MonitorIngestion()
    $monitor.GenerateReport(
        "ingestion_monitoring_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    )
}
catch {
    Write-Error "Ingestion monitoring failed: $_"
    exit 1
}