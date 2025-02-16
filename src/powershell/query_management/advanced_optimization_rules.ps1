# src/powershell/query_management/advanced_optimization_rules.ps1

class AdvancedQueryOptimizationRules {
    static [hashtable] GetOptimizationRules() {
        return @{
            # Time-based Optimizations
            TimeSeries = @{
                Pattern = '(\w+)\s*\|\s*where\s+TimeGenerated\s*>[=]?\s*ago\((\d+)([dhm])\)'
                Action = {
                    param($match)
                    $table = $match[1]
                    $value = $match[2]
                    $unit = $match[3]
                    
                    # Convert large time ranges to materialized views
                    if (($unit -eq 'd' -and $value -gt 7) -or 
                        ($unit -eq 'h' -and $value -gt 168)) {
                        return @"
let timeRange = ago($value$unit);
let baseData = materialize(
    $table
    | where TimeGenerated > timeRange
    | summarize by bin(TimeGenerated, 1h)
);
baseData
"@
                    }
                    return $match[0]
                }
                Impact = "High"
                Description = "Optimizes time-series queries by implementing materialization for large time ranges"
            }

            # Complex Join Optimizations
            AdvancedJoin = @{
                Pattern = 'join\s*\(([^)]+)\)\s*on\s*(\$?\w+)\s*==\s*(\$?\w+)'
                Action = {
                    param($match)
                    $subquery = $match[1]
                    $leftKey = $match[2]
                    $rightKey = $match[3]

                    return @"
join hint.strategy=broadcast hint.shufflekey=$leftKey (
    let rightSide = materialize(
        $subquery
        | summarize arg_max(TimeGenerated, *) by $rightKey
    );
    rightSide
) on $leftKey == $rightKey
"@
                }
                Impact = "High"
                Description = "Implements advanced join optimizations with materialization and broadcast hints"
            }

            # Data Volume Reduction
            DataReduction = @{
                Pattern = '(\w+)\s*\|\s*where\s+([^|]+)(?:\|\s*project\s+([^|]+))?'
                Action = {
                    param($match)
                    $table = $match[1]
                    $whereClause = $match[2]
                    $projection = $match[3]

                    # Add data volume reduction techniques
                    return @"
$table
| where $whereClause
| project-smart   // Smart projection based on usage
| reduce by bin(TimeGenerated, 1h)  // Data reduction
| project $($projection ?? '*')
"@
                }
                Impact = "Medium"
                Description = "Reduces data volume through smart projection and binning"
            }

            # String Operations Optimization
            StringOps = @{
                Pattern = '(contains|startswith|endswith)\s*\(([\w\._]+),\s*["\']([^"\']+)["\']\)'
                Action = {
                    param($match)
                    $operator = $match[1]
                    $field = $match[2]
                    $value = $match[3]

                    switch ($operator) {
                        'contains' { return "$field has '$value'" }
                        'startswith' { return "$field hasprefix '$value'" }
                        'endswith' { return "$field hassuffix '$value'" }
                    }
                }
                Impact = "Medium"
                Description = "Optimizes string operations using more efficient operators"
            }

            # Dynamic Field Handling
            DynamicFields = @{
                Pattern = 'parse_json\((\w+)\)\.(\w+)'
                Action = {
                    param($match)
                    $field = $match[1]
                    $subfield = $match[2]

                    return @"
extend ['$subfield'] = parse_json($field)['$subfield']
| project-away $field
"@
                }
                Impact = "Medium"
                Description = "Optimizes handling of dynamic fields and JSON parsing"
            }

            # Aggregation Optimization
            AdvancedAggregation = @{
                Pattern = 'summarize\s+(?!by\s+bin\(TimeGenerated,)'
                Action = {
                    param($match)
                    return @"
summarize hint.strategy=shuffle
    by bin(TimeGenerated, 1h)
"@
                }
                Impact = "High"
                Description = "Implements advanced aggregation strategies with proper binning"
            }

            # Regex Optimization
            RegexOps = @{
                Pattern = 'matches\s+regex\s+["\'](.*?)["\']'
                Action = {
                    param($match)
                    $regex = $match[1]
                    
                    # Convert common regex patterns to more efficient operators
                    if ($regex -match '^\^.*\$$') {
                        return "== '$($regex -replace '^\^|\$$', '')'"
                    }
                    if ($regex -match '^\^') {
                        return "startswith '$($regex -replace '^\^', '')'"
                    }
                    if ($regex -match '\$$') {
                        return "endswith '$($regex -replace '\$$', '')'"
                    }
                    return $match[0]
                }
                Impact = "Medium"
                Description = "Converts regex operations to more efficient string operations where possible"
            }

            # Lookup Optimization
            AdvancedLookup = @{
                Pattern = 'lookup\s+(\w+)\s+on\s+(\w+)'
                Action = {
                    param($match)
                    $lookupTable = $match[1]
                    $lookupField = $match[2]

                    return @"
lookup hint.remote=true (
    $lookupTable
    | summarize arg_max(TimeGenerated, *) by $lookupField
) on $lookupField
"@
                }
                Impact = "High"
                Description = "Optimizes lookup operations with proper hints and summarization"
            }

            # Nested Subquery Optimization
            NestedQueries = @{
                Pattern = 'let\s+(\w+)\s*=\s*([^;]+);\s*\1'
                Action = {
                    param($match)
                    $varName = $match[1]
                    $subquery = $match[2]

                    # Add materialization for frequently used subqueries
                    return @"
let $varName = materialize(
    $subquery
);
$varName
"@
                }
                Impact = "High"
                Description = "Optimizes nested subqueries through materialization"
            }

            # Union Optimization
            AdvancedUnion = @{
                Pattern = 'union\s+(?!withsource=\w+\s+)([\w\s,]+)'
                Action = {
                    param($match)
                    $tables = $match[1]

                    return @"
union withsource=TableName hint.strategy=shuffle (
    $tables
)
"@
                }
                Impact = "Medium"
                Description = "Optimizes union operations with proper hints and source tracking"
            }

            # Numeric Operations
            NumericOps = @{
                Pattern = '(sum|avg|min|max)\s*\((\w+)\)\s+by\s+(\w+)'
                Action = {
                    param($match)
                    $aggregation = $match[1]
                    $field = $match[2]
                    $groupBy = $match[3]

                    return @"
summarize hint.shufflekey=$groupBy
    $aggregation($field)
    by $groupBy
"@
                }
                Impact = "Medium"
                Description = "Optimizes numeric aggregations with proper hints"
            }

            # Window Functions
            WindowFunctions = @{
                Pattern = 'row_number\(\)\s+by\s+(\w+)'
                Action = {
                    param($match)
                    $partitionBy = $match[1]

                    return @"
partition by $partitionBy hint.strategy=shuffle (
    row_number()
)
"@
                }
                Impact = "Medium"
                Description = "Optimizes window functions with proper partitioning strategies"
            }
        }
    }

    static [string] ApplyOptimizations([string]$query, [hashtable]$rules) {
        $optimizedQuery = $query

        foreach ($rule in $rules.GetEnumerator()) {
            try {
                if ($optimizedQuery -match $rule.Value.Pattern) {
                    $optimizedQuery = $optimizedQuery -replace $rule.Value.Pattern, ($rule.Value.Action.Invoke($matches))
                    Write-Verbose "Applied $($rule.Key) optimization"
                }
            }
            catch {
                Write-Warning "Failed to apply $($rule.Key) optimization: $_"
            }
        }

        return $optimizedQuery
    }

    static [hashtable] ValidateOptimizations([string]$originalQuery, [string]$optimizedQuery) {
        return @{
            Original = @{
                Length = $originalQuery.Length
                Complexity = [AdvancedQueryOptimizationRules]::CalculateComplexity($originalQuery)
                EstimatedCost = [AdvancedQueryOptimizationRules]::EstimateQueryCost($originalQuery)
            }
            Optimized = @{
                Length = $optimizedQuery.Length
                Complexity = [AdvancedQueryOptimizationRules]::CalculateComplexity($optimizedQuery)
                EstimatedCost = [AdvancedQueryOptimizationRules]::EstimateQueryCost($optimizedQuery)
            }
            ImprovementMetrics = @{
                ComplexityReduction = 0.0
                EstimatedCostReduction = 0.0
            }
        }
    }

    static [int] CalculateComplexity([string]$query) {
        $complexityFactors = @{
            'join' = 5
            'union' = 3
            'summarize' = 4
            'project' = 1
            'where' = 1
            'extend' = 2
            'parse_json' = 3
            'materialize' = 2
        }

        $complexity = 0
        foreach ($factor in $complexityFactors.Keys) {
            $complexity += ([regex]::Matches($query, $factor).Count * $complexityFactors[$factor])
        }

        return $complexity
    }

    static [float] EstimateQueryCost([string]$query) {
        $costFactors = @{
            'TimeGenerated > ago(' = 1.0
            'join' = 2.5
            'union' = 1.5
            'summarize' = 2.0
            'parse_json' = 1.5
            'materialize' = 1.0
        }

        $estimatedCost = 1.0
        foreach ($factor in $costFactors.Keys) {
            $matches = [regex]::Matches($query, $factor).Count
            if ($matches -gt 0) {
                $estimatedCost *= ($costFactors[$factor] * $matches)
            }
        }

        return $estimatedCost
    }
}