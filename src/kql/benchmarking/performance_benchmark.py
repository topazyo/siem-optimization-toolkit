# src/kql/benchmarking/performance_benchmark.py

from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import asyncio
import time
import statistics
from datetime import datetime, timedelta
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

@dataclass
class BenchmarkResult:
    query_id: str
    execution_time: float
    data_scanned: float
    result_count: int
    cpu_time: float
    memory_usage: float
    timestamp: datetime
    metrics: Dict

class QueryBenchmark:
    """
    Advanced query performance benchmarking system.
    """

    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self.logger = logging.getLogger(__name__)
        self.results_cache = {}
        self.baseline_metrics = {}

    async def benchmark_query(
        self,
        query: str,
        iterations: int = 5,
        warmup_runs: int = 2
    ) -> BenchmarkResult:
        """
        Benchmark query performance with multiple iterations.
        
        Args:
            query (str): Query to benchmark
            iterations (int): Number of benchmark iterations
            warmup_runs (int): Number of warmup runs
            
        Returns:
            BenchmarkResult: Benchmark results
        """
        # Perform warmup runs
        for _ in range(warmup_runs):
            await self._execute_query(query)

        results = []
        
        # Run benchmark iterations
        for i in range(iterations):
            try:
                start_time = time.time()
                stats = await self._execute_query_with_stats(query)
                execution_time = time.time() - start_time
                
                results.append({
                    'execution_time': execution_time,
                    'data_scanned': stats['data_scanned'],
                    'result_count': stats['result_count'],
                    'cpu_time': stats['cpu_time'],
                    'memory_usage': stats['memory_usage']
                })
                
            except Exception as e:
                self.logger.error(f"Benchmark iteration {i} failed: {str(e)}")
                continue

        # Calculate aggregate metrics
        metrics = self._calculate_metrics(results)
        
        return BenchmarkResult(
            query_id=self._generate_query_id(query),
            execution_time=metrics['avg_execution_time'],
            data_scanned=metrics['avg_data_scanned'],
            result_count=metrics['avg_result_count'],
            cpu_time=metrics['avg_cpu_time'],
            memory_usage=metrics['avg_memory_usage'],
            timestamp=datetime.utcnow(),
            metrics=metrics
        )

    async def compare_queries(
        self,
        queries: Dict[str, str]
    ) -> Dict[str, BenchmarkResult]:
        """Compare performance of multiple queries."""
        results = {}
        
        for name, query in queries.items():
            try:
                results[name] = await self.benchmark_query(query)
            except Exception as e:
                self.logger.error(f"Benchmark failed for {name}: {str(e)}")
                continue

        return results

    async def generate_performance_report(
        self,
        results: Dict[str, BenchmarkResult]
    ) -> Dict:
        """Generate comprehensive performance report."""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_queries': len(results),
                'avg_execution_time': statistics.mean(
                    [r.execution_time for r in results.values()]
                ),
                'total_data_scanned': sum(
                    [r.data_scanned for r in results.values()]
                )
            },
            'query_details': {},
            'performance_distribution': self._analyze_performance_distribution(
                results
            ),
            'optimization_recommendations': self._generate_recommendations(
                results
            )
        }

        # Add query-specific details
        for name, result in results.items():
            report['query_details'][name] = {
                'execution_time': result.execution_time,
                'data_scanned': result.data_scanned,
                'result_count': result.result_count,
                'performance_rating': self._calculate_performance_rating(result),
                'optimization_potential': self._assess_optimization_potential(
                    result
                )
            }

        return report

    def _calculate_metrics(self, results: List[Dict]) -> Dict:
        """Calculate aggregate metrics from benchmark results."""
        return {
            'avg_execution_time': statistics.mean(
                [r['execution_time'] for r in results]
            ),
            'avg_data_scanned': statistics.mean(
                [r['data_scanned'] for r in results]
            ),
            'avg_result_count': statistics.mean(
                [r['result_count'] for r in results]
            ),
            'avg_cpu_time': statistics.mean(
                [r['cpu_time'] for r in results]
            ),
            'avg_memory_usage': statistics.mean(
                [r['memory_usage'] for r in results]
            ),
            'std_execution_time': statistics.stdev(
                [r['execution_time'] for r in results]
            ),
            'min_execution_time': min(
                [r['execution_time'] for r in results]
            ),
            'max_execution_time': max(
                [r['execution_time'] for r in results]
            ),
            'execution_time_p95': self._calculate_percentile(
                [r['execution_time'] for r in results],
                95
            )
        }

    async def visualize_results(
        self,
        results: Dict[str, BenchmarkResult],
        output_path: str
    ):
        """Generate performance visualization."""
        # Create performance comparison plot
        plt.figure(figsize=(12, 6))
        
        # Execution time comparison
        plt.subplot(2, 2, 1)
        execution_times = [r.execution_time for r in results.values()]
        query_names = list(results.keys())
        sns.barplot(x=query_names, y=execution_times)
        plt.title('Query Execution Time Comparison')
        plt.xticks(rotation=45)
        
        # Data scanned comparison
        plt.subplot(2, 2, 2)
        data_scanned = [r.data_scanned for r in results.values()]
        sns.barplot(x=query_names, y=data_scanned)
        plt.title('Data Scanned Comparison')
        plt.xticks(rotation=45)
        
        # Memory usage comparison
        plt.subplot(2, 2, 3)
        memory_usage = [r.memory_usage for r in results.values()]
        sns.barplot(x=query_names, y=memory_usage)
        plt.title('Memory Usage Comparison')
        plt.xticks(rotation=45)
        
        # Performance distribution
        plt.subplot(2, 2, 4)
        execution_times = [r.execution_time for r in results.values()]
        sns.histplot(execution_times, kde=True)
        plt.title('Execution Time Distribution')
        
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    def _calculate_performance_rating(self, result: BenchmarkResult) -> str:
        """Calculate performance rating based on metrics."""
        score = 0
        
        # Execution time rating
        if result.execution_time < 1:
            score += 5
        elif result.execution_time < 5:
            score += 3
        elif result.execution_time < 10:
            score += 1
            
        # Data scanned rating
        if result.data_scanned < 100:
            score += 5
        elif result.data_scanned < 500:
            score += 3
        elif result.data_scanned < 1000:
            score += 1
            
        # Memory usage rating
        if result.memory_usage < 100:
            score += 5
        elif result.memory_usage < 500:
            score += 3
        elif result.memory_usage < 1000:
            score += 1

        if score >= 12:
            return "excellent"
        elif score >= 8:
            return "good"
        elif score >= 4:
            return "fair"
        return "poor"

    def _assess_optimization_potential(self, result: BenchmarkResult) -> Dict:
        """Assess potential optimizations based on performance metrics."""
        potential = {
            'optimizations': [],
            'estimated_improvement': 0.0
        }

        # Check execution time
        if result.execution_time > 5:
            potential['optimizations'].append({
                'type': 'time_range_optimization',
                'description': 'Consider reducing time range or adding time filters',
                'estimated_improvement': 30
            })

        # Check data scanning
        if result.data_scanned > 500:
            potential['optimizations'].append({
                'type': 'data_volume_optimization',
                'description': 'Consider adding more specific filters',
                'estimated_improvement': 25
            })

        # Check memory usage
        if result.memory_usage > 500:
            potential['optimizations'].append({
                'type': 'memory_optimization',
                'description': 'Consider using summarize or project to reduce data',
                'estimated_improvement': 20
            })

        # Calculate total estimated improvement
        if potential['optimizations']:
            potential['estimated_improvement'] = sum(
                opt['estimated_improvement']
                for opt in potential['optimizations']
            ) / len(potential['optimizations'])

        return potential