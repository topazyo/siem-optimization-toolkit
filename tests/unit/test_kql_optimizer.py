import asyncio
import unittest
import logging
from unittest.mock import patch, MagicMock
from src.python.query_optimization.kql_optimizer import KQLOptimizer, QueryPerformanceMetrics
from datetime import datetime

class TestKQLOptimizer(unittest.TestCase):

    def setUp(self):
        self.mock_workspace_id = "test-workspace"
        self.mock_subscription_id = "test-subscription"
        logging.disable(logging.CRITICAL)
        self.optimizer = KQLOptimizer(
            workspace_id=self.mock_workspace_id,
            subscription_id=self.mock_subscription_id
        )

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init_optimizer(self):
        self.assertEqual(self.optimizer.workspace_id, self.mock_workspace_id)
        self.assertEqual(self.optimizer.subscription_id, self.mock_subscription_id)
        self.assertIsNotNone(self.optimizer.logger)
        self.assertEqual(self.optimizer.performance_baseline, {})
        self.assertIn('table_scan', self.optimizer.query_patterns)

    def test_optimize_time_window_no_existing_filter(self):
        query = "SecurityEvent | take 10"
        optimized_query, optimization_details = self.optimizer._optimize_time_window(query)
        self.assertIn("| where TimeGenerated > ago(timeframe)", optimized_query)
        self.assertIn("let timeframe = 1d;", optimized_query)
        self.assertIsNotNone(optimization_details)
        if optimization_details:
            self.assertEqual(optimization_details['type'], 'time_window')

    def test_optimize_time_window_with_existing_filter(self):
        query = "SecurityEvent | where TimeGenerated > ago(7d) | take 10"
        optimized_query, optimization_details = self.optimizer._optimize_time_window(query)
        self.assertEqual(optimized_query, query)
        self.assertIsNone(optimization_details)

    def test_optimize_joins_no_joins(self):
        query = "SecurityEvent | where EventID == 4624"
        optimized_query, optimization_details = self.optimizer._optimize_joins(query)
        self.assertEqual(optimized_query, query)
        self.assertIsNone(optimization_details)

    @patch.object(KQLOptimizer, '_reorder_joins', side_effect=lambda q: q)
    def test_optimize_joins_simple_join_adds_kind(self, mock_reorder_joins_method):
        query = "T1 | join (T2) on CommonColumn"
        expected_query_part = "join kind=innerunique (T2) on CommonColumn"
        optimized_query, optimization_details = self.optimizer._optimize_joins(query)
        mock_reorder_joins_method.assert_called_once_with(query)
        self.assertIn(expected_query_part, optimized_query)
        self.assertIsNotNone(optimization_details)
        if optimization_details:
            self.assertIn('Added join hint for better performance', optimization_details.get('changes', []))

    @patch.object(KQLOptimizer, '_reorder_joins', side_effect=lambda q: q)
    def test_optimize_joins_with_existing_kind(self, mock_reorder_joins_method):
        query = "T1 | join kind=leftouter (T2) on CommonColumn"
        optimized_query, optimization_details = self.optimizer._optimize_joins(query)
        mock_reorder_joins_method.assert_called_once_with(query)
        self.assertNotIn("kind=innerunique", optimized_query.replace("kind=leftouter", "kind=SOMETHING_ELSE"))
        if optimization_details and optimization_details.get('changes'):
             self.assertTrue(all("Added join hint" not in change for change in optimization_details['changes']))

    def test_optimize_where_clauses_stub(self):
        query = "SecurityEvent | where field contains 'value'"
        optimized_query, details = self.optimizer._optimize_where_clauses(query)
        self.assertEqual(optimized_query, query)
        self.assertIsNone(details)

    @patch('src.python.query_optimization.kql_optimizer.datetime')
    def test_run_query_benchmark_stub(self, mock_dt):
        mock_now_val = datetime(2023, 1, 1, 12, 0, 0)
        mock_later_val = datetime(2023, 1, 1, 12, 0, 5)
        mock_dt.now.side_effect = [mock_now_val, mock_later_val]
        query = "SecurityEvent | count"
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        metrics = None
        try:
            metrics = loop.run_until_complete(self.optimizer._run_query_benchmark(query))
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        self.assertIsInstance(metrics, QueryPerformanceMetrics)
        if metrics:
            self.assertEqual(metrics.execution_time, 5.0)
            self.assertEqual(metrics.data_scanned, 0.0)
            self.assertEqual(metrics.result_count, 0)
            self.assertEqual(metrics.resource_utilization, 0.0)

    @patch.object(KQLOptimizer, '_optimize_time_window')
    @patch.object(KQLOptimizer, '_optimize_joins')
    @patch.object(KQLOptimizer, '_optimize_where_clauses')
    @patch.object(KQLOptimizer, '_estimate_performance_improvement')
    def test_optimize_query_orchestration(
        self,
        mock_estimate_perf,
        mock_optimize_where,
        mock_optimize_joins,
        mock_optimize_time
    ):
        query = "Initial Query"
        mock_optimize_time.return_value = ("query_after_time_opt", {"type": "time"})
        mock_optimize_joins.return_value = ("query_after_join_opt", {"type": "join"})
        mock_optimize_where.return_value = ("query_after_where_opt", {"type": "where"})
        future = asyncio.Future()
        future.set_result(10.5)
        mock_estimate_perf.return_value = future
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        optimized_query, details = None, None
        try:
            optimized_query, details = loop.run_until_complete(self.optimizer.optimize_query(query))
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        mock_optimize_time.assert_called_once_with(query)
        mock_optimize_joins.assert_called_once_with("query_after_time_opt")
        mock_optimize_where.assert_called_once_with("query_after_join_opt")
        mock_estimate_perf.assert_called_once_with(query, "query_after_where_opt")
        self.assertEqual(optimized_query, "query_after_where_opt")
        if details:
            self.assertIn({"type": "time"}, details.get('optimizations_applied', []))
            self.assertIn({"type": "join"}, details.get('optimizations_applied', []))
            self.assertIn({"type": "where"}, details.get('optimizations_applied', []))
            self.assertEqual(details.get('estimated_improvement'), 10.5)

# End of the Python code block for the file.
# The if __name__ == '__main__' block for direct execution:
# if __name__ == '__main__':
#     unittest.main()
# This part will be handled by the test runner normally.
# Adding it here makes the tool call string more complex and prone to syntax errors.
# We'll assume the test runner (e.g., `python -m unittest discover`) will pick it up.
