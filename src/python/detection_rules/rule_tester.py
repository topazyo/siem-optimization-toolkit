# src/python/detection_rules/rule_tester.py

from typing import Dict, List, Optional
import asyncio
import json
from datetime import datetime, timedelta
import pandas as pd

class RuleTester:
    """Testing framework for detection rules."""

    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine
        self.logger = logging.getLogger(__name__)
        self.test_cases = self._load_test_cases()

    def _load_test_cases(self) -> Dict:
        """Load test cases for rules."""
        test_cases_path = Path('tests/detection_rules/test_cases')
        test_cases = {}

        for case_file in test_cases_path.glob('*.json'):
            with open(case_file, 'r') as f:
                test_cases[case_file.stem] = json.load(f)

        return test_cases

    async def test_rule(
        self,
        rule_id: str,
        test_case_id: Optional[str] = None
    ) -> Dict:
        """
        Test a specific rule against test cases.
        
        Args:
            rule_id (str): Rule to test
            test_case_id (Optional[str]): Specific test case to run
            
        Returns:
            Dict: Test results
        """
        results = {
            'rule_id': rule_id,
            'timestamp': datetime.utcnow().isoformat(),
            'test_cases': [],
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0
            }
        }

        test_cases = (
            {test_case_id: self.test_cases[test_case_id]}
            if test_case_id
            else self.test_cases
        )

        for case_id, case in test_cases.items():
            if rule_id in case.get('applicable_rules', []):
                test_result = await self._run_test_case(rule_id, case)
                results['test_cases'].append(test_result)
                results['summary']['total_tests'] += 1
                if test_result['passed']:
                    results['summary']['passed'] += 1
                else:
                    results['summary']['failed'] += 1

        return results

    async def _run_test_case(self, rule_id: str, test_case: Dict) -> Dict:
        """Run a single test case."""
        try:
            # Prepare test context
            context = self._prepare_test_context(test_case)
            
            # Evaluate rule
            rule_result = await self.rule_engine.evaluate_rules(
                context,
                [rule_id]
            )
            
            # Validate results
            validation_result = self._validate_results(
                rule_result[rule_id],
                test_case['expected_results']
            )

            return {
                'test_case_id': test_case['id'],
                'description': test_case['description'],
                'passed': validation_result['passed'],
                'details': validation_result['details']
            }

        except Exception as e:
            self.logger.error(f"Test case execution error: {str(e)}")
            return {
                'test_case_id': test_case['id'],
                'description': test_case['description'],
                'passed': False,
                'details': {'error': str(e)}
            }

    def _prepare_test_context(self, test_case: Dict) -> Dict:
        """Prepare context for test execution."""
        return {
            'timeframe': test_case.get('timeframe', '24h'),
            'data_volume': test_case.get('data_volume', 1000),
            'test_data': test_case.get('input_data', {}),
            'parameters': test_case.get('parameters', {})
        }

    def _validate_results(
        self,
        actual_result: RuleResult,
        expected_result: Dict
    ) -> Dict:
        """Validate rule results against expected outcomes."""
        validation = {
            'passed': True,
            'details': {
                'matches': True,
                'severity': True,
                'confidence': True
            }
        }

        # Validate matches
        if len(actual_result.matches) != len(expected_result['matches']):
            validation['passed'] = False
            validation['details']['matches'] = False

        # Validate severity
        if actual_result.severity != expected_result['severity']:
            validation['passed'] = False
            validation['details']['severity'] = False

        # Validate confidence
        if abs(actual_result.confidence - expected_result['confidence']) > 0.1:
            validation['passed'] = False
            validation['details']['confidence'] = False

        return validation

    async def generate_test_report(self, test_results: Dict) -> str:
        """Generate detailed test report."""
        report_template = """
        # Detection Rule Test Report
        Generated: {timestamp}

        ## Summary
        - Total Tests: {total_tests}
        - Passed: {passed_tests}
        - Failed: {failed_tests}
        - Success Rate: {success_rate:.2f}%

        ## Detailed Results
        {detailed_results}

        ## Performance Metrics
        {performance_metrics}
        """

        detailed_results = self._format_test_results(test_results['test_cases'])
        performance_metrics = self._calculate_performance_metrics(
            test_results['test_cases']
        )

        return report_template.format(
            timestamp=test_results['timestamp'],
            total_tests=test_results['summary']['total_tests'],
            passed_tests=test_results['summary']['passed'],
            failed_tests=test_results['summary']['failed'],
            success_rate=(
                test_results['summary']['passed'] /
                test_results['summary']['total_tests'] * 100
            ),
            detailed_results=detailed_results,
            performance_metrics=performance_metrics
        )