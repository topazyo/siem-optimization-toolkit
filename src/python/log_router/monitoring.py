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
        """
        Initializes the RouterMonitoring instance.

        This constructor sets up logging and initializes various data structures
        for metrics collection. This includes a list to store raw performance data
        points for later analysis and several Prometheus client metrics (Counter,
        Histogram, Gauge) to track real-time performance indicators.

        Key attributes initialized:
        - `logger` (logging.Logger): A configured logger instance.
        - `performance_data` (List[Dict]): A list to store dictionaries, where
          each dictionary represents a recorded metrics event (e.g., a single
          log processing attempt).
        - `processed_logs` (prometheus_client.Counter): Tracks the total number
          of processed logs, labeled by `rule_name` and `destination`.
        - `processing_time` (prometheus_client.Histogram): Records the
          distribution of time spent processing logs, labeled by `rule_name`.
        - `destination_latency` (prometheus_client.Histogram): Records the
          distribution of latency when sending logs to destinations, labeled by
          `destination`.
        - `error_counter` (prometheus_client.Counter): Tracks the total number
          of errors encountered, labeled by `type` (e.g., 'processing') and
          `rule_name`.
        - `queue_size` (prometheus_client.Gauge): (If applicable to the router design)
          Tracks the current size of any internal processing queues.
        """
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
        """
        Asynchronously records metrics for a single log processing event.

        This method updates various Prometheus metrics (counters and histograms)
        based on the outcome and performance of processing a log. It also appends
        a record of this event to an internal list (`self.performance_data`)
        for later detailed analysis and report generation.

        Args:
            rule_name (str): The name of the routing rule that processed the log.
            destination (str): The destination to which the log was routed.
            processing_time (float): The time taken to process the log, in seconds.
            success (bool): True if the log was processed and sent successfully,
                            False otherwise.
        """
        self.processed_logs.labels(rule_name=rule_name, destination=destination).inc()
        self.processing_time.labels(rule_name=rule_name).observe(processing_time)
        
        if not success:
            self.error_counter.labels(type='processing', rule_name=rule_name).inc()

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
        """
        Asynchronously generates a detailed performance report based on collected metrics.

        The report is generated from the `performance_data` collected within the
        specified `time_window`. It includes overall performance summaries,
        metrics broken down by rule and destination, and a list of detected anomalies.

        Args:
            time_window (timedelta, optional): The duration of past data to include
                                               in the report. Defaults to 1 hour.

        Returns:
            Dict: A dictionary containing the performance report. The structure includes:
                  - 'timestamp' (str): ISO format timestamp of report generation.
                  - 'time_window' (str): The time window used for the report.
                  - 'overall_metrics' (Dict): Aggregated metrics like 'total_logs',
                    'success_rate', 'avg_processing_time', 'p95_processing_time'.
                  - 'rule_metrics' (Dict): Metrics per rule, including 'total_logs',
                    'success_rate', 'avg_processing_time' for each rule.
                  - 'destination_metrics' (Dict): Metrics per destination, similar to
                    rule metrics.
                  - 'anomalies' (List[Dict]): A list of detected anomalies, such as
                    high processing times or low success rates for specific rules.
                    Each anomaly entry details its type, timestamp (if applicable),
                    rule name, value, and the threshold breached.
        """
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