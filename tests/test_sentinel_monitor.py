# tests/test_sentinel_monitor.py

import unittest
from unittest.mock import Mock, patch
import asyncio
from datetime import datetime, timedelta
from src.python.ingestion_monitoring.sentinel_monitor import SentinelMonitor

class TestSentinelMonitor(unittest.TestCase):
    """Test suite for Sentinel monitoring functionality."""

    def setUp(self):
        self.monitor = SentinelMonitor(
            workspace_id="test-workspace",
            subscription_id="test-subscription"
        )

    @patch('src.python.ingestion_monitoring.sentinel_monitor.LogAnalyticsManagementClient')
    async def test_analyze_ingestion_patterns(self, mock_client):
        """Test ingestion pattern analysis."""
        # Mock data
        mock_data = {
            'tables': [{
                'rows': [
                    ['2023-01-01', 100, 'SecurityEvent'],
                    ['2023-01-01', 200, 'SigninLogs']
                ],
                'columns': ['TimeGenerated', 'IngestionVolume', 'TableName']
            }]
        }
        mock_client.return_value.query.return_value = mock_data

        # Run analysis
        results = await self.monitor.analyze_ingestion_patterns(days_lookback=1)

        # Verify results
        self.assertIn('total_volume', results)
        self.assertIn('daily_patterns', results)
        self.assertIn('recommendations', results)

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        test_data = {
            'total_volume': 1000,
            'daily_patterns': {'2023-01-01': 500},
            'peak_hours': [9, 10, 11]
        }

        recommendations = self.monitor._generate_recommendations(test_data)
        self.assertIsInstance(recommendations, list)
        self.assertTrue(len(recommendations) > 0)

# tests/test_kql_optimizer.py

class TestKQLOptimizer(unittest.TestCase):
    """Test suite for KQL query optimization."""

    def setUp(self):
        self.optimizer = KQLOptimizer(
            workspace_id="test-workspace",
            subscription_id="test-subscription"
        )

    async def test_optimize_query(self):
        """Test query optimization."""
        test_query = "SecurityEvent | where EventID == 4624"
        optimized_query, details = await self.optimizer.optimize_query(test_query)

        self.assertIsInstance(optimized_query, str)
        self.assertIn('optimizations_applied', details)
        self.assertIn('estimated_improvement', details)

    def test_optimize_time_window(self):
        """Test time window optimization."""
        test_query = "SecurityEvent"
        optimized_query, optimization = self.optimizer._optimize_time_window(
            test_query
        )

        self.assertIn('TimeGenerated', optimized_query)
        self.assertIsNotNone(optimization)

# tests/test_threat_hunter.py

class TestThreatHunter(unittest.TestCase):
    """Test suite for threat hunting functionality."""

    def setUp(self):
        self.hunter = ThreatHunter(
            workspace_id="test-workspace",
            kql_optimizer=Mock()
        )

    async def test_run_hunt(self):
        """Test threat hunting execution."""
        hunt_id = "golden_ticket_detection"
        result = await self.hunter.run_hunt(hunt_id)

        self.assertIsInstance(result, ThreatHuntingResult)
        self.assertEqual(result.query_id, hunt_id)
        self.assertIsInstance(result.findings, list)