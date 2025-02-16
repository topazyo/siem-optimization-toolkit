# src/kql/benchmarking/query_optimizer.py

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json
import asyncio
import re
from datetime import datetime, timedelta
import logging
import pandas as pd

@dataclass
class QueryPerformanceMetrics:
    original_query: str
    optimized_query: str
    execution_time: float
    data_scanned: float
    result_count: int
    cpu_time: float
    memory_usage: float
    optimization_impact: float

class KQLQueryOptimizer:
    """
    Advanced KQL query optimization and benchmarking system.
    """

    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self.logger = logging.getLogger(__name__)
        self.optimization_patterns = self._load_optimization_patterns()
        self.performance_baseline = {}

    def _load_optimization_patterns(self) -> Dict:
        """Load query optimization patterns."""
        return {
            'table_scan': {
                'pattern': r'^\s*(\w+)\s*$',
                'fix': lambda m: f"{m.group(1)} | where TimeGenerated > ago(1d)",
                'impact': 'high'
            },
            'inefficient_where': {
                'pattern': r'where\s+\w+\s+contains\s+',
                'fix': lambda m: m.group().replace('contains', 'has'),
                'impact': 'medium'
            },
            'unoptimized_join': {
                'pattern': r'join\s+\(.*?\)',
                'fix': lambda m: f"join kind=innerunique ({m.group(1)})",
                'impact': 'high'
            },
            'missing_materialization': {
                'pattern': r'(\w+\s*\|\s*where.*?){2,}',
                'fix': lambda m: f"let results = materialize({m.group(1)})",
                'impact': 'medium'
            },
            'inefficient_summarize': {
                'pattern': r'summarize\s+(?!by)',
                'fix': lambda m: f"summarize by bin(TimeGenerated, 1h)",
                'impact': 'high'
            }
        }

    async def optimize_query(self, query: str) -> Tuple[str, Dict]:
        """
        Optimize KQL query for better performance.
        
        Args:
            query (str): Original KQL query
            
        Returns:
            Tuple[str, Dict]: Optimized query and optimization details
        """
        optimized = query
        optimizations = []

        # Apply optimization patterns
        for name, pattern in self.optimization_patterns.items():
            matches = re.finditer(pattern['pattern'], optimized)
            for match in matches:
                try:
                    original_part = match.group(0)
                    optimized_part = pattern['fix'](match)
                    optimized = optimized.replace(original_part, optimized_part)
                    
                    optimizations.append({
                        'type': name,
                        'original': original_part,
                        'optimized': optimized_part,
                        'impact': pattern['impact']
                    })
                except Exception as e:
                    self.logger.error(f"Optimization error for {name}: {str(e)}")

        # Add performance hints
        optimized = self._add_performance_hints(optimized)

        return optimized, {
            'optimizations': optimizations,
            'estimated_improvement': self._estimate_improvement(optimizations)
        }

    def _add_performance_hints(self, query: str) -> str:
        """Add performance hints to query."""
        hints = []
        
        # Add query hints based on patterns
        if 'join' in query.lower():
            hints.append('hint.strategy=shuffle')
        if 'summarize' in query.lower():
            hints.append('hint.materialized=true')
        
        if hints:
            return f"// Set query options\nset {', '.join(hints)}\n{query}"
        return query

    async def benchmark_query(
        self,
        query: str,
        iterations: int = 3
    ) -> QueryPerformanceMetrics:
        """Benchmark query performance."""
        try:
            # Run original query
            original_metrics = await self._run_benchmark(query, iterations)
            
            # Run optimized query
            optimized_query, _ = await self.optimize_query(query)
            optimized_metrics = await self._run_benchmark(
                optimized_query,
                iterations
            )
            
            # Calculate improvement
            improvement = (
                (original_metrics['execution_time'] - optimized_metrics['execution_time'])
                / original_metrics['execution_time']
            ) * 100
            
            return QueryPerformanceMetrics(
                original_query=query,
                optimized_query=optimized_query,
                execution_time=optimized_metrics['execution_time'],
                data_scanned=optimized_metrics['data_scanned'],
                result_count=optimized_metrics['result_count'],
                cpu_time=optimized_metrics['cpu_time'],
                memory_usage=optimized_metrics['memory_usage'],
                optimization_impact=improvement
            )

        except Exception as e:
            self.logger.error(f"Benchmark error: {str(e)}")
            raise

    async def _run_benchmark(
        self,
        query: str,
        iterations: int
    ) -> Dict[str, float]:
        """Run performance benchmark."""
        metrics = []
        
        for _ in range(iterations):
            start_time = datetime.utcnow()
            
            # Execute query with statistics
            stats_query = f"""
            set notruncation;
            set querystats;
            {query}
            """
            
            try:
                result = await self._execute_query(stats_query)
                end_time = datetime.utcnow()
                
                metrics.append({
                    'execution_time': (end_time - start_time).total_seconds(),
                    'data_scanned': result.get('statistics', {}).get('data_scanned', 0),
                    'result_count': len(result.get('results', [])),
                    'cpu_time': result.get('statistics', {}).get('cpu_time', 0),
                    'memory_usage': result.get('statistics', {}).get('memory_peak', 0)
                })
                
            except Exception as e:
                self.logger.error(f"Query execution error: {str(e)}")
                continue

        # Calculate averages
        return {
            metric: sum(d[metric] for d in metrics) / len(metrics)
            for metric in metrics[0].keys()
        } if metrics else {}

    async def generate_optimization_report(
        self,
        queries: List[str]
    ) -> Dict:
        """Generate comprehensive optimization report."""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_queries': len(queries),
                'optimized_queries': 0,
                'average_improvement': 0.0
            },
            'query_details': []
        }

        total_improvement = 0
        
        for query in queries:
            try:
                # Benchmark query
                metrics = await self.benchmark_query(query)
                
                # Add to report
                if metrics.optimization_impact > 0:
                    report['summary']['optimized_queries'] += 1
                    total_improvement += metrics.optimization_impact
                
                report['query_details'].append({
                    'original_query': metrics.original_query,
                    'optimized_query': metrics.optimized_query,
                    'performance_metrics': {
                        'execution_time': metrics.execution_time,
                        'data_scanned': metrics.data_scanned,
                        'result_count': metrics.result_count,
                        'cpu_time': metrics.cpu_time,
                        'memory_usage': metrics.memory_usage
                    },
                    'improvement': metrics.optimization_impact
                })
                
            except Exception as e:
                self.logger.error(f"Report generation error: {str(e)}")
                continue

        # Calculate average improvement
        if report['summary']['optimized_queries'] > 0:
            report['summary']['average_improvement'] = (
                total_improvement / report['summary']['optimized_queries']
            )

        return report