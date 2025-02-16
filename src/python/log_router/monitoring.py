# src/python/log_router/monitoring.py

from typing import Dict, List, Optional
import asyncio
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from prometheus_client import Counter, Histogram, Gauge
import logging

class RouterMonitoring:
    """Advanced monitoring system for log router."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._initialize_metrics()
        self.performance_data = []

    def _initialize_metrics(self):
        """Initialize Prometheus metrics."""
        self.processed_logs = Counter(
            'router_processed_logs_total',
            'Total number of processed logs',
            ['rule_name', 'destination']
        )
        
        self.processing_time = Histogram(
            'router_processing_time_seconds',
            'Time spent processing logs',
            ['rule_name']
        )
        
        self.destination_latency = Histogram(
            'router_destination_latency_seconds',
            'Destination sending latency',
            ['destination']
        )
        
        self.error_counter = Counter(
            'router_errors_total',
            'Total number of errors',
            ['type', 'rule_name']
        )
        
        self.queue_size = Gauge(
            'router_queue_size',
            'Current routing queue size'
        )

    async def record_metrics(
        self,
        rule_name: str,
        destination: str,
        processing_time: float,
        success: bool
    ):
        """Record routing metrics."""
        self.processed_logs.labels(rule_name, destination).inc()
        self.processing_time.labels(rule_name).observe(processing_time)
        
        if not success:
            self.error_counter.labels('processing', rule_name).inc()

        # Store for analysis
        self.performance_data.append({
            'timestamp': datetime.utcnow(),
            'rule_name': rule_name,
            'destination': destination,
            'processing_time': processing_time,
            'success': success
        })

    async def generate_performance_report(
        self,
        time_window: timedelta = timedelta(hours=1)
    ) -> Dict:
        """Generate detailed performance report."""
        try:
            # Convert to DataFrame for analysis
            df = pd.DataFrame(self.performance_data)
            df = df[df['timestamp'] > datetime.utcnow() - time_window]
            
            report = {
                'timestamp': datetime.utcnow().isoformat(),
                'time_window': str(time_window),
                'overall_metrics': {
                    'total_logs': len(df),
                    'success_rate': (df['success'].mean() * 100),
                    'avg_processing_time': df['processing_time'].mean(),
                    'p95_processing_time': df['processing_time'].quantile(0.95)
                },
                'rule_metrics': {},
                'destination_metrics': {},
                'anomalies': await self._detect_anomalies(df)
            }

            # Rule-specific metrics
            for rule in df['rule_name'].unique():
                rule_df = df[df['rule_name'] == rule]
                report['rule_metrics'][rule] = {
                    'total_logs': len(rule_df),
                    'success_rate': (rule_df['success'].mean() * 100),
                    'avg_processing_time': rule_df['processing_time'].mean()
                }

            # Destination metrics
            for dest in df['destination'].unique():
                dest_df = df[df['destination'] == dest]
                report['destination_metrics'][dest] = {
                    'total_logs': len(dest_df),
                    'success_rate': (dest_df['success'].mean() * 100),
                    'avg_processing_time': dest_df['processing_time'].mean()
                }

            return report

        except Exception as e:
            self.logger.error(f"Error generating performance report: {str(e)}")
            return {}

    async def _detect_anomalies(self, df: pd.DataFrame) -> List[Dict]:
        """Detect anomalies in performance data."""
        anomalies = []

        # Processing time anomalies
        mean_time = df['processing_time'].mean()
        std_time = df['processing_time'].std()
        threshold = mean_time + (3 * std_time)

        anomaly_df = df[df['processing_time'] > threshold]
        for _, row in anomaly_df.iterrows():
            anomalies.append({
                'type': 'high_processing_time',
                'timestamp': row['timestamp'].isoformat(),
                'rule_name': row['rule_name'],
                'value': row['processing_time'],
                'threshold': threshold
            })

        # Success rate anomalies
        for rule in df['rule_name'].unique():
            rule_df = df[df['rule_name'] == rule]
            success_rate = rule_df['success'].mean() * 100
            if success_rate < 95:  # Threshold for success rate
                anomalies.append({
                    'type': 'low_success_rate',
                    'rule_name': rule,
                    'value': success_rate,
                    'threshold': 95
                })

        return anomalies