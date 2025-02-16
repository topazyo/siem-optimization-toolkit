# src/kql/benchmarking/optimization_patterns.py

from typing import Dict, List, Callable, Pattern
import re
from dataclasses import dataclass

@dataclass
class OptimizationPattern:
    name: str
    pattern: Pattern
    fix: Callable
    impact: str
    description: str
    examples: List[str]

class KQLOptimizationPatterns:
    """
    Comprehensive KQL query optimization patterns.
    """

    def __init__(self):
        self.patterns = self._initialize_patterns()

    def _initialize_patterns(self) -> Dict[str, OptimizationPattern]:
        """Initialize all optimization patterns."""
        return {
            'large_time_range': OptimizationPattern(
                name="large_time_range",
                pattern=re.compile(r'ago\(\d+d\)'),
                fix=self._optimize_time_range,
                impact="high",
                description="Optimize queries spanning large time ranges",
                examples=[
                    "| where TimeGenerated > ago(90d)",
                    "| where TimeGenerated between(ago(180d)..now())"
                ]
            ),
            
            'project_optimization': OptimizationPattern(
                name="project_optimization",
                pattern=re.compile(r'project\s+\*'),
                fix=self._optimize_project,
                impact="high",
                description="Optimize project statements to include only necessary columns",
                examples=[
                    "| project *",
                    "| project-away *"
                ]
            ),
            
            'union_optimization': OptimizationPattern(
                name="union_optimization",
                pattern=re.compile(r'union\s+(?!withsource)'),
                fix=self._optimize_union,
                impact="medium",
                description="Add source tracking to union operations",
                examples=[
                    "union Alert, SecurityEvent",
                    "union kind=outer *"
                ]
            ),
            
            'inefficient_join': OptimizationPattern(
                name="inefficient_join",
                pattern=re.compile(r'join\s+\(.*?\)'),
                fix=self._optimize_join,
                impact="high",
                description="Optimize join operations with proper hints and keys",
                examples=[
                    "| join (SecurityEvent)",
                    "| join kind=inner (SecurityAlert)"
                ]
            ),
            
            'string_operations': OptimizationPattern(
                name="string_operations",
                pattern=re.compile(r'contains|startswith|endswith'),
                fix=self._optimize_string_operations,
                impact="medium",
                description="Optimize string comparison operations",
                examples=[
                    "| where Computer contains 'srv'",
                    "| where CommandLine startswith 'powershell'"
                ]
            ),
            
            'excessive_parsing': OptimizationPattern(
                name="excessive_parsing",
                pattern=re.compile(r'parse-(?:where|where-)?json|\{.*?\}'),
                fix=self._optimize_parsing,
                impact="high",
                description="Optimize JSON parsing operations",
                examples=[
                    "| parse-json CustomFields",
                    "| extend props = parse_json(Properties)"
                ]
            ),
            
            'unoptimized_aggregation': OptimizationPattern(
                name="unoptimized_aggregation",
                pattern=re.compile(r'summarize\s+(?!by\s+bin)'),
                fix=self._optimize_aggregation,
                impact="high",
                description="Optimize aggregation operations with proper binning",
                examples=[
                    "| summarize count() by Computer",
                    "| summarize avg(CPU) by _ResourceId"
                ]
            ),
            
            'mv_expand_optimization': OptimizationPattern(
                name="mv_expand_optimization",
                pattern=re.compile(r'mv-expand\s+(?!bagexpansion)'),
                fix=self._optimize_mv_expand,
                impact="medium",
                description="Optimize array expansion operations",
                examples=[
                    "| mv-expand Tags",
                    "| mv-expand Properties"
                ]
            ),
            
            'case_sensitivity': OptimizationPattern(
                name="case_sensitivity",
                pattern=re.compile(r'=~|contains|startswith|endswith'),
                fix=self._optimize_case_sensitivity,
                impact="low",
                description="Optimize case-sensitive operations",
                examples=[
                    "| where Computer =~ 'SERVER'",
                    "| where ProcessName contains 'chrome'"
                ]
            ),
            
            'lookup_optimization': OptimizationPattern(
                name="lookup_optimization",
                pattern=re.compile(r'lookup\s+kind=(?!leftouter)'),
                fix=self._optimize_lookup,
                impact="medium",
                description="Optimize lookup operations",
                examples=[
                    "| lookup kind=inner",
                    "| lookup SecurityAlert on AlertId"
                ]
            )
        }

    def _optimize_time_range(self, match: re.Match) -> str:
        """Optimize large time range queries."""
        days = int(re.search(r'\d+', match.group()).group())
        if days > 30:
            return f"""
            let timerange = ago({days}d);
            let daily_stats = materialize(
                {original_table}
                | where TimeGenerated > timerange
                | summarize DailyStats=count() by bin(TimeGenerated, 1d)
            );
            """
        return match.group()

    def _optimize_project(self, match: re.Match) -> str:
        """Optimize project statements."""
        return """project
            TimeGenerated,
            SourceSystem,
            EventID,
            Computer,
            Activity,
            CommandLine,
            ParentProcessName,
            ProcessName,
            Account"""

    def _optimize_union(self, match: re.Match) -> str:
        """Optimize union operations."""
        return f"union withsource=TableName"

    def _optimize_join(self, match: re.Match) -> str:
        """Optimize join operations."""
        join_content = match.group(1)
        return f"""join hint.strategy=broadcast (
            {join_content}
            | summarize arg_max(TimeGenerated, *) by AlertId
        )"""

    def _optimize_string_operations(self, match: re.Match) -> str:
        """Optimize string comparison operations."""
        op = match.group()
        if op == 'contains':
            return 'has'
        elif op in ['startswith', 'endswith']:
            return 'matches regex'

    def _optimize_parsing(self, match: re.Match) -> str:
        """Optimize JSON parsing operations."""
        return """
        | extend parsed = iff(notempty(CustomFields), parse_json(CustomFields), dynamic(null))
        | project-away CustomFields
        """

    def _optimize_aggregation(self, match: re.Match) -> str:
        """Optimize aggregation operations."""
        return """summarize hint.strategy=shuffle
            count(),
            make_list(Computer),
            max(TimeGenerated)
            by bin(TimeGenerated, 1h)"""

    def _optimize_mv_expand(self, match: re.Match) -> str:
        """Optimize array expansion operations."""
        return "mv-expand bagexpansion=array"

    def _optimize_case_sensitivity(self, match: re.Match) -> str:
        """Optimize case-sensitive operations."""
        op = match.group()
        if op == '=~':
            return '=='
        elif op == 'contains':
            return 'has_cs'
        return op

    def _optimize_lookup(self, match: re.Match) -> str:
        """Optimize lookup operations."""
        return "lookup hint.remote=true kind=leftouter"