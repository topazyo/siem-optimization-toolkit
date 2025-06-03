# src/python/detection_rules/rule_tester.py

from typing import Dict, List, Optional
import asyncio
import json
from datetime import datetime, timedelta
import pandas as pd
import logging # Added import
from pathlib import Path # Added import
from .rule_engine import RuleEngine, RuleResult # Added import

class RuleTester:
    """Testing framework for detection rules."""

    def __init__(self, rule_engine: RuleEngine, test_cases_dir: Optional[str] = None):
        """
        Initializes the RuleTester instance.

        This constructor takes a RuleEngine instance, sets up logging, and loads
        all available test cases from JSON files located in a predefined path
        (e.g., 'tests/detection_rules/test_cases').

        Args:
            rule_engine (RuleEngine): An instance of the `RuleEngine` that will be
                                      used to evaluate rules against test cases.
            test_cases_dir (Optional[str], optional): Path to the directory containing
                                                      test case JSON files. If None,
                                                      defaults to 'tests/detection_rules/test_cases'.

        Initializes key attributes:
        - `rule_engine` (RuleEngine): The provided rule engine instance.
        - `test_cases_dir` (Optional[str]): The directory path for test cases.
        - `logger` (logging.Logger): A configured logger instance.
        - `test_cases` (Dict[str, Dict]): Loaded test cases.
        """
        self.rule_engine = rule_engine
        self.test_cases_dir = test_cases_dir
        self.logger = logging.getLogger(__name__)
        self.test_cases = self._load_test_cases()

    def _load_test_cases(self) -> Dict:
        """
        Load test cases from the specified directory or a default path.
        Uses `self.test_cases_dir` if set, otherwise defaults to 'tests/detection_rules/test_cases'.
        """
        if self.test_cases_dir:
            test_cases_path = Path(self.test_cases_dir)
        else:
            # Default path, consider making it relative to this file or a well-known base
            # For now, keeping existing default relative to CWD or a discoverable 'tests' dir
            test_cases_path = Path('tests/detection_rules/test_cases')

        self.logger.info(f"Loading test cases from directory: {test_cases_path.resolve()}")
        test_cases = {}

        if not test_cases_path.is_dir():
            self.logger.warning(f"Test cases directory not found: {test_cases_path.resolve()}. Returning empty dict.")
            return test_cases

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
        Asynchronously tests a specific detection rule against one or all applicable test cases.

        It loads test case data (input logs, parameters) and expected outcomes.
        For each relevant test case, it uses the `rule_engine` to evaluate the rule
        and then compares the actual results against the expected results.

        Args:
            rule_id (str): The unique identifier of the detection rule to be tested.
            test_case_id (Optional[str], optional): If provided, only this specific
                                                    test case will be run for the rule.
                                                    Otherwise, all test cases applicable
                                                    to the rule (based on 'applicable_rules'
                                                    in test case files) are executed.
                                                    Defaults to None.

        Returns:
            Dict: A dictionary containing the test results, structured as follows:
                  - 'rule_id' (str): The ID of the rule that was tested.
                  - 'timestamp' (str): ISO format timestamp of when the tests were run.
                  - 'test_cases' (List[Dict]): A list of results for each executed test case.
                    Each entry includes:
                      - 'test_case_id' (str): Identifier of the test case.
                      - 'description' (str): Description of the test case.
                      - 'passed' (bool): True if the test case passed, False otherwise.
                      - 'details' (Dict): Further details on validation, like comparison
                                          of matches, severity, confidence, or error info.
                  - 'summary' (Dict): A summary of the test run for this rule, including:
                      - 'total_tests' (int): Total number of test cases run.
                      - 'passed' (int): Number of test cases that passed.
                      - 'failed' (int): Number of test cases that failed.
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

        # Determine which test cases to run
        applicable_test_cases = {}
        if test_case_id:
            if test_case_id in self.test_cases:
                applicable_test_cases = {test_case_id: self.test_cases[test_case_id]}
            else:
                self.logger.warning(f"Test case ID '{test_case_id}' not found.")
        else:
            # Filter all loaded test cases for those applicable to the rule_id
            for tc_id, case_data in self.test_cases.items():
                if rule_id in case_data.get('applicable_rules', []):
                    applicable_test_cases[tc_id] = case_data

        test_cases_to_run = applicable_test_cases

        for case_id, case in test_cases_to_run.items():
            # Ensure 'applicable_rules' check is done if not filtering by specific test_case_id initially
            # This check is now implicitly handled by how `test_cases_to_run` is populated.
            # if rule_id in case.get('applicable_rules', []): # This might be redundant now
            test_result = await self._run_test_case(rule_id, case)
            results['test_cases'].append(test_result)
            results['summary']['total_tests'] += 1
            if test_result['passed']:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1

        # If a specific test_case_id was provided but wasn't applicable or found,
        # the summary might show 0 tests. This behavior might need adjustment
        # based on desired outcome (e.g., raise error if specific test case not found/applicable).

        return results

    async def _run_test_case(self, rule_id: str, test_case: Dict) -> Dict:
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

    # --- Stubs for report generation helpers ---

    def _format_test_results(self, test_cases: List[Dict]) -> str:
        """Stub for formatting detailed test results into a string."""
        self.logger.warning("RuleTester._format_test_results is a stub and not yet implemented.")
        return "Detailed test results not available."

    def _calculate_performance_metrics(self, test_cases: List[Dict]) -> str:
        """Stub for calculating and formatting performance metrics from test cases."""
        self.logger.warning("RuleTester._calculate_performance_metrics is a stub and not yet implemented.")
        return "Performance metrics not available."

    async def generate_test_report(self, test_results: Dict) -> str:
        """
        Asynchronously generates a formatted string report from rule test results.

        The report is typically structured in Markdown or HTML, providing a summary
        of the test run, detailed results for each test case, and any relevant
        performance metrics observed during testing.

        Args:
            test_results (Dict): The dictionary returned by the `test_rule` method,
                                 containing the results of a test run for a specific rule.

        Returns:
            str: A formatted string (e.g., Markdown) representing the test report.
                 Key sections include:
                 - Summary: Total tests, passed, failed, success rate.
                 - Detailed Results: A breakdown for each test case, including its ID,
                   description, pass/fail status, and any specific validation details
                   or errors.
                 - Performance Metrics: (If available and calculated) Metrics about
                   the rule's performance during the tests, such as average
                   execution time.
        """
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