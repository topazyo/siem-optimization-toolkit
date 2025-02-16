# src/python/query_optimization/kql_optimizer.py

from typing import Dict, List, Optional, Tuple
import re
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass
import asyncio
import aiohttp

@dataclass
class QueryPerformanceMetrics:
    execution_time: float
    data_scanned: float
    result_count: int
    resource_utilization: float

class KQLOptimizer:
    """
    Advanced KQL query optimization and performance monitoring system.
    """

    def __init__(self, workspace_id: str, subscription_id: str):
        self.workspace_id = workspace_id
        self.subscription_id = subscription_id
        self.logger = logging.getLogger(__name__)
        self.performance_baseline = {}
        self.query_patterns = self._load_query_patterns()

    def _load_query_patterns(self) -> Dict:
        """Load predefined query optimization patterns."""
        return {
            'table_scan': {
                'pattern': r'^\s*(\w+)\s*$',
                'suggestion': 'Add time and scope filters to reduce data scan',
            },
            'multiple_joins': {
                'pattern': r'join.*join',
                'suggestion': 'Consider materializing intermediate results',
            },
            'inefficient_where': {
                'pattern': r'where.*contains',
                'suggestion': 'Use "has" or "in" operators for better performance',
            }
        }

    async def optimize_query(self, query: str) -> Tuple[str, Dict]:
        """
        Optimize a KQL query for better performance.

        Args:
            query (str): Original KQL query

        Returns:
            Tuple[str, Dict]: Optimized query and optimization details
        """
        optimization_details = {
            'original_query': query,
            'optimizations_applied': [],
            'estimated_improvement': 0.0
        }

        optimized_query = query

        # Apply time window optimization
        optimized_query, time_opt = self._optimize_time_window(optimized_query)
        if time_opt:
            optimization_details['optimizations_applied'].append(time_opt)

        # Optimize join operations
        optimized_query, join_opt = self._optimize_joins(optimized_query)
        if join_opt:
            optimization_details['optimizations_applied'].append(join_opt)

        # Optimize where clauses
        optimized_query, where_opt = self._optimize_where_clauses(optimized_query)
        if where_opt:
            optimization_details['optimizations_applied'].append(where_opt)

        # Estimate performance improvement
        optimization_details['estimated_improvement'] = \
            await self._estimate_performance_improvement(query, optimized_query)

        return optimized_query, optimization_details

    def _optimize_time_window(self, query: str) -> Tuple[str, Optional[Dict]]:
        """Optimize time window filters in the query."""
        time_pattern = r'ago\(\d+d\)'
        optimization = None

        if not re.search(time_pattern, query):
            # Add time filter if missing
            query = f"""
            let timeframe = 1d;
            {query}
            | where TimeGenerated > ago(timeframe)
            """
            optimization = {
                'type': 'time_window',
                'description': 'Added time window filter',
                'impact': 'Reduces data scan range'
            }

        return query, optimization

    def _optimize_joins(self, query: str) -> Tuple[str, Optional[Dict]]:
        """Optimize join operations in the query."""
        if 'join' not in query.lower():
            return query, None

        optimization = {
            'type': 'join_optimization',
            'description': 'Optimized join operations',
            'changes': []
        }

        # Optimize join order (smaller table first)
        if re.search(r'join.*\(', query):
            query = self._reorder_joins(query)
            optimization['changes'].append('Reordered joins for optimal performance')

        # Add join hints where beneficial
        if 'kind=' not in query:
            query = query.replace('join', 'join kind=innerunique')
            optimization['changes'].append('Added join hint for better performance')

        return query, optimization

    async def _estimate_performance_improvement(
        self, 
        original_query: str, 
        optimized_query: str
    ) -> float:
        """Estimate performance improvement percentage."""
        original_metrics = await self._run_query_benchmark(original_query)
        optimized_metrics = await self._run_query_benchmark(optimized_query)

        if original_metrics and optimized_metrics:
            improvement = (
                (original_metrics.execution_time - optimized_metrics.execution_time)
                / original_metrics.execution_time
            ) * 100
            return round(improvement, 2)
        return 0.0

    async def _run_query_benchmark(self, query: str) -> Optional[QueryPerformanceMetrics]:
        """Run performance benchmark for a query."""
        try:
            start_time = datetime.now()
            # Execute query with statistics
            stats_query = f"""
            set notruncation;
            set querystats;
            {query}
            """
            # Query execution logic here
            end_time = datetime.now()
            
            return QueryPerformanceMetrics(
                execution_time=(end_time - start_time).total_seconds(),
                data_scanned=0.0,  # Calculate from actual execution
                result_count=0,    # Calculate from actual execution
                resource_utilization=0.0  # Calculate from actual execution
            )
        except Exception as e:
            self.logger.error(f"Benchmark error: {str(e)}")
            return None