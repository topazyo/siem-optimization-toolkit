import asyncio
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.python.query_optimization.kql_optimizer import KQLOptimizer
from src.python.threat_hunting.hunter import ThreatHunter, ThreatHuntingResult

class TestThreatHunterIntegration(unittest.TestCase):

    def setUp(self):
        self.mock_workspace_id = "test-workspace"
        self.mock_subscription_id = "test-subscription"
        self.kql_optimizer = KQLOptimizer(
            workspace_id=self.mock_workspace_id,
            subscription_id=self.mock_subscription_id
        )
        self.mock_hunt_id = "TEST_HUNT_001"
        self.mock_hunting_queries_config = {
            self.mock_hunt_id: {
                'name': 'Test Hunt',
                'query': 'SecurityEvent | take 1',
                'analysis_params': {},
                'severity_config': {'default': 'Low'},
                'confidence_config': {'default': 0.1}
            }
        }
        self.mock_detection_patterns_config = []

    @patch.object(ThreatHunter, '_load_detection_patterns')
    @patch.object(ThreatHunter, '_load_hunting_queries')
    def test_run_hunt_integration(self, mock_load_hunting_queries, mock_load_detection_patterns):
        mock_load_hunting_queries.return_value = self.mock_hunting_queries_config
        mock_load_detection_patterns.return_value = self.mock_detection_patterns_config

        threat_hunter = ThreatHunter(
            workspace_id=self.mock_workspace_id,
            kql_optimizer=self.kql_optimizer
        )

        # Manage asyncio loop for unittest
        # Note: Python 3.8+ has asyncio.run() which is simpler, but this is more compatible.
        # For older versions or specific test setups:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = None # Ensure result is defined in this scope
        try:
            result = loop.run_until_complete(threat_hunter.run_hunt(hunt_id=self.mock_hunt_id))
        finally:
            # Important: Close the loop if you created it.
            # Also, if this is not the main thread and other tests use asyncio,
            # you might need to be careful about setting/resetting the event loop policy.
            # For standard unittest, this explicit loop management is often needed for async code.
            asyncio.set_event_loop(None)
            loop.close()

        self.assertIsInstance(result, ThreatHuntingResult)
        self.assertEqual(result.query_id, self.mock_hunt_id)
        self.assertIsInstance(result.timestamp, datetime)
        self.assertEqual(result.findings, []) # From _execute_query stub
        self.assertEqual(result.severity, "Medium") # From _determine_severity stub
        self.assertEqual(result.confidence, 0.5) # From _calculate_confidence stub
        self.assertEqual(result.related_entities, []) # From _identify_related_entities stub
        self.assertEqual(result.recommended_actions, ["No immediate action required. Continue monitoring."])

# This allows running the test file directly like `python tests/integration/test_threat_hunter_integration.py`
if __name__ == '__main__':
    unittest.main()
