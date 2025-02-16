# tests/unit/test_ingestion_monitor.py

import unittest
from src.python.ingestion_monitoring.sentinel_monitor import SentinelMonitor

class TestSentinelMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = SentinelMonitor(
            workspace_id="test-workspace",
            subscription_id="test-subscription"
        )

    def test_analyze_ingestion_patterns(self):
        results = self.monitor.analyze_ingestion_patterns(days_lookback=1)
        self.assertIsInstance(results, dict)
        self.assertIn('total_volume', results)
        self.assertIn('recommendations', results)

    def test_optimize_retention_policies(self):
        current_policies = {
            'SecurityEvent': 90,
            'SigninLogs': 30
        }
        optimized = self.monitor.optimize_retention_policies(current_policies)
        self.assertIsInstance(optimized, dict)