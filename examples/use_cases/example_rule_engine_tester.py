import asyncio
import json
import yaml
from pathlib import Path
from datetime import datetime, timedelta

# Assuming these are the correct import paths based on the project structure
from src.python.detection_rules.rule_engine import RuleEngine, DetectionRule, RuleResult, CustomDetectionRule
# CustomDetectionRule might be implicitly used by RuleEngine but good to have if we directly interact
from src.python.detection_rules.rule_tester import RuleTester

# --- Temporary Configuration Setup ---
# Create temporary directories for config and test cases for this example
EXAMPLE_TEMP_BASE_PATH = Path(__file__).parent / "example_temp_files"
TEMP_RULES_PATH = EXAMPLE_TEMP_BASE_PATH / "config/detection_rules"
TEMP_TEST_CASES_PATH = EXAMPLE_TEMP_BASE_PATH / "tests/detection_rules/test_cases"

def setup_temporary_config():
    print("Setting up temporary configuration for RuleEngine and RuleTester example...")
    TEMP_RULES_PATH.mkdir(parents=True, exist_ok=True)
    TEMP_TEST_CASES_PATH.mkdir(parents=True, exist_ok=True)

    # 1. Create a dummy detection rule YAML file
    dummy_rule_id = "EXMPL-001"
    dummy_rule_config = {
        'id': dummy_rule_id,
        'name': 'Example Suspicious Activity Rule',
        'description': 'Detects if a specific example event occurs.',
        'risk_level': 'Medium',
        'tactics': ['TA0002'], # Example MITRE Tactic
        'techniques': ['T1078'], # Example MITRE Technique
        'query': 'ExampleTable | where EventType == "Suspicious" and User == "{user_placeholder}"',
        'parameters': {'user_placeholder': 'test_user'}, # Parameters for the query
        'enabled': True,
        'last_modified': datetime.utcnow().isoformat(),
        'author': 'Example Script',
        'validation_rules': {} # Placeholder
    }
    with open(TEMP_RULES_PATH / f"{dummy_rule_id}.yaml", 'w') as f:
        yaml.dump(dummy_rule_config, f)
    print(f"Created dummy rule: {TEMP_RULES_PATH / f'{dummy_rule_id}.yaml'}")

    # 2. Create a dummy test case JSON file for the rule
    dummy_test_case_id = f"test_{dummy_rule_id}"
    dummy_test_case = {
        'id': dummy_test_case_id,
        'description': 'Tests the Example Suspicious Activity Rule for a specific user.',
        'applicable_rules': [dummy_rule_id],
        'timeframe': '24h',
        'data_volume': 100, # Example data volume
        'input_data': { # Mock data that _execute_query would hypothetically query
            'ExampleTable': [
                {'EventType': 'Normal', 'User': 'another_user', 'TimeGenerated': datetime.utcnow().isoformat()},
                {'EventType': 'Suspicious', 'User': 'test_user', 'TimeGenerated': (datetime.utcnow() - timedelta(hours=1)).isoformat()}
            ]
        },
        'parameters': {'user_placeholder': 'test_user'}, # Parameters for this specific test run
        'expected_results': {
            # Because _execute_query is stubbed to return [], we expect 0 matches.
            # If _execute_query had mock logic based on input_data, this would change.
            'matches_count': 0, # Expected number of matches
            'severity': 'Medium', # Expected severity if matches were found (or default from stub)
            'confidence': 0.5    # Expected confidence (or default from stub)
        }
    }
    with open(TEMP_TEST_CASES_PATH / f"{dummy_test_case_id}.json", 'w') as f:
        json.dump(dummy_test_case, f, indent=2)
    print(f"Created dummy test case: {TEMP_TEST_CASES_PATH / f'{dummy_test_case_id}.json'}")

    return dummy_rule_id, dummy_test_case_id

def cleanup_temporary_config():
    print("\nCleaning up temporary configuration...")
    import shutil
    if EXAMPLE_TEMP_BASE_PATH.exists():
        shutil.rmtree(EXAMPLE_TEMP_BASE_PATH)
        print(f"Removed temporary directory: {EXAMPLE_TEMP_BASE_PATH}")

async def main():
    print("Starting RuleEngine and RuleTester example...")

    dummy_rule_id, dummy_test_case_id = setup_temporary_config()

    # --- RuleEngine Example ---
    print("\n--- RuleEngine Demonstration ---")
    try:
        # Initialize RuleEngine with the path to our temporary rule configs
        # Note: RuleEngine._load_rules uses Path(self.rules_path)
        rule_engine = RuleEngine(rules_path=str(TEMP_RULES_PATH)) # Pass string path
        print(f"RuleEngine initialized. Loaded rules: {list(rule_engine.rules.keys())}")

        # Mock context for rule evaluation
        mock_eval_context = {
            'data_volume': 500, # Example context
            'user_placeholder': 'test_user'
            # This context parameter would be used by a real _prepare_query
        }

        print(f"\nEvaluating rule '{dummy_rule_id}' with mock context...")
        # RuleEngine.evaluate_rules calls CustomDetectionRule.evaluate
        # CustomDetectionRule.evaluate calls stubs: _prepare_query, _execute_query, _determine_severity, _calculate_confidence
        rule_results = await rule_engine.evaluate_rules(context=mock_eval_context, rule_ids=[dummy_rule_id])

        if dummy_rule_id in rule_results:
            result = rule_results[dummy_rule_id]
            print("\nRule Evaluation Result:")
            print(f"  Rule ID: {result.rule_id}")
            print(f"  Timestamp: {result.timestamp}")
            print(f"  Severity: {result.severity}") # From stub
            print(f"  Confidence: {result.confidence}") # From stub
            print(f"  Matches Found: {len(result.matches)}") # From stub (_execute_query returns [])
            # print(f"  Matches: {result.matches}") # Would be empty list
            print(f"  Performance Metrics: {result.performance_metrics}")
        else:
            print(f"  Rule '{dummy_rule_id}' did not produce results.")

    except Exception as e:
        print(f"An error occurred during RuleEngine demonstration: {e}")

    # --- RuleTester Example ---
    print("\n--- RuleTester Demonstration ---")
    # We need a RuleEngine instance for RuleTester, created above.
    if 'rule_engine' not in locals():
        print("RuleEngine not initialized, skipping RuleTester demonstration.")
    else:
        try:
            # Initialize RuleTester
            # RuleTester._load_test_cases uses Path('tests/detection_rules/test_cases')
            # We need to ensure it looks at our temporary path.
            # For this example, we'll temporarily modify the path it looks at,
            # or more robustly, RuleTester could accept a test_cases_path.
            # Let's assume RuleTester needs its CWD to be EXAMPLE_TEMP_BASE_PATH for _load_test_cases to work as written.
            # This is a simplification for the example. A better RuleTester might take a path.

            # Simplification: We will rely on the fact that _load_test_cases in the
            # original RuleTester might use a hardcoded relative path.
            # A more robust example would involve either:
            # 1. Modifying RuleTester to accept a base path for test cases.
            # 2. Changing CWD (less ideal for library code).
            # For this example, we'll assume we need to make the default path work.
            # The path 'tests/detection_rules/test_cases' is relative to CWD.
            # So, if we can ensure CWD is EXAMPLE_TEMP_BASE_PATH when RuleTester is init, it works.
            # Alternatively, if RuleTester's _load_test_cases was Path(__file__).parent.parent / "tests" ...
            # it would be relative to rule_tester.py, which is also not what we want for this example.

            # Given the current RuleTester._load_test_cases stub uses a fixed relative path,
            # this part of the example might not load the dummy test case correctly without
            # either changing RuleTester or carefully managing CWD.
            # For now, we will proceed and note this limitation.
            # A real fix involves making RuleTester's test case path configurable.

            print(f"Initializing RuleTester (Note: Test case loading depends on RuleTester's internal path logic).")
            print(f"For this example, dummy test cases are in: {TEMP_TEST_CASES_PATH}")
            print(f"RuleTester by default might look in: {Path.cwd() / 'tests/detection_rules/test_cases'}")

            # To make it work with the current RuleTester stub for _load_test_cases,
            # we might need to ensure the RuleTester's default path somehow aligns.
            # This is tricky without changing RuleTester.
            # Let's assume for the example, that RuleTester *could* find it,
            # acknowledging the stub's fixed path is a limitation.
            rule_tester = RuleTester(rule_engine) # RuleTester's __init__ calls _load_test_cases
                                                # _load_test_cases is stubbed to look at a fixed path
                                                # so it won't find our temp test case.
                                                # To make this example work, _load_test_cases stub would need
                                                # to be more flexible or RuleTester would need path injection.

            # To truly test, we'd need to patch RuleTester._load_test_cases or make it configurable
            # For now, we will manually load the test case for the example's logic
            # and then call the internal methods of rule_tester to simulate a run.
            # This is because the stubbed RuleTester._load_test_cases won't find our temp file.

            print(f"\nTesting rule '{dummy_rule_id}' with test case '{dummy_test_case_id}'...")
            # The public test_rule method itself orchestrates loading, so we call that.
            # It will use the (currently empty due to fixed path in stub) self.test_cases.
            # So this will likely report 0 tests run for dummy_rule_id.
            test_run_results = await rule_tester.test_rule(rule_id=dummy_rule_id) # test_case_id=dummy_test_case_id)

            print("\nRule Test Run Results:")
            print(f"  Rule ID: {test_run_results.get('rule_id')}")
            print(f"  Timestamp: {test_run_results.get('timestamp')}")
            print(f"  Summary: Total Tests: {test_run_results.get('summary', {}).get('total_tests')}, "
                  f"Passed: {test_run_results.get('summary', {}).get('passed')}, "
                  f"Failed: {test_run_results.get('summary', {}).get('failed')}")

            if test_run_results.get('test_cases'):
                for tc_result in test_run_results.get('test_cases', []):
                    print(f"    Test Case ID: {tc_result.get('test_case_id')}")
                    print(f"      Description: {tc_result.get('description')}")
                    print(f"      Passed: {tc_result.get('passed')}")
                    print(f"      Details: {json.dumps(tc_result.get('details'), indent=2)}")
            else:
                print("    No test cases were executed for this rule by RuleTester.test_rule.")
                print("    This is likely because RuleTester._load_test_cases stub has a fixed path "
                      "and did not find the temporary test case file.")
                print("    A real RuleTester would need a configurable test case path.")

            # Generating the report (will use stubbed _format_test_results etc.)
            report_str = await rule_tester.generate_test_report(test_run_results)
            print("\nGenerated Test Report (stubbed content):")
            print(report_str)

        except Exception as e:
            print(f"An error occurred during RuleTester demonstration: {e}")
            import traceback
            traceback.print_exc()


    finally:
        cleanup_temporary_config()

    print("\nRuleEngine and RuleTester example finished.")

if __name__ == "__main__":
    asyncio.run(main())
