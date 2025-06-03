import asyncio
import yaml
import json
from pathlib import Path
from datetime import datetime

# Assuming these are the correct import paths
from src.python.query_optimization.kql_optimizer import KQLOptimizer
from src.python.threat_hunting.hunter import ThreatHunter, ThreatHuntingResult

# --- Temporary Configuration Setup for ThreatHunter Example ---
EXAMPLE_CONFIG_PATH = Path(__file__).parent.parent / "config" # Assuming 'config' is one level up from 'examples/use_cases'
TEMP_HUNTING_QUERIES_FILE = EXAMPLE_CONFIG_PATH / "hunting_queries.yaml"
TEMP_DETECTION_PATTERNS_FILE = EXAMPLE_CONFIG_PATH / "detection_patterns.yaml"
# Store original content if files exist, to restore them later
original_hunting_queries = None
original_detection_patterns = None

def setup_temporary_hunter_config(mock_hunt_id="HUNT-EXMPL-001"):
    global original_hunting_queries, original_detection_patterns
    print("Setting up temporary configuration for ThreatHunter example...")
    EXAMPLE_CONFIG_PATH.mkdir(parents=True, exist_ok=True)

    # Backup original files if they exist
    if TEMP_HUNTING_QUERIES_FILE.exists():
        original_hunting_queries = TEMP_HUNTING_QUERIES_FILE.read_text()
    if TEMP_DETECTION_PATTERNS_FILE.exists():
        original_detection_patterns = TEMP_DETECTION_PATTERNS_FILE.read_text()

    # 1. Create a dummy hunting_queries.yaml
    dummy_hunting_queries = {
        mock_hunt_id: {
            'name': 'Example Suspicious Command Execution Hunt',
            'description': 'Hunts for specific command line patterns indicative of suspicious activity.',
            'query': 'SecurityEvent | where CommandLine contains "powershell -enc" and EventID == 4688',
            'analysis_params': { # Parameters for _analyze_findings stub
                'some_threshold': 1,
                'look_for_pattern': 'example_stub_pattern'
            },
            'severity_config': {'default': 'Low'}, # For _determine_severity stub
            'confidence_config': {'default': 0.3}, # For _calculate_confidence stub
            'scheduled': False
        }
    }
    with open(TEMP_HUNTING_QUERIES_FILE, 'w') as f:
        yaml.dump(dummy_hunting_queries, f)
    print(f"Created/Overwrote dummy: {TEMP_HUNTING_QUERIES_FILE}")

    # 2. Create a dummy detection_patterns.yaml
    dummy_detection_patterns = [ # Assuming it's a list of patterns
        {
            'name': 'Example Stub Pattern Matcher',
            'indicators': {'pattern_type': 'example_stub_pattern'}, # For _matches_threat_pattern stub
            'recommendations': ['Isolate host if pattern matches.', 'Review user activity.']
        }
    ]
    with open(TEMP_DETECTION_PATTERNS_FILE, 'w') as f:
        yaml.dump(dummy_detection_patterns, f)
    print(f"Created/Overwrote dummy: {TEMP_DETECTION_PATTERNS_FILE}")

    return mock_hunt_id

def cleanup_temporary_hunter_config():
    global original_hunting_queries, original_detection_patterns
    print("\nCleaning up temporary ThreatHunter configuration...")

    if original_hunting_queries is not None:
        TEMP_HUNTING_QUERIES_FILE.write_text(original_hunting_queries)
        print(f"Restored original: {TEMP_HUNTING_QUERIES_FILE}")
    elif TEMP_HUNTING_QUERIES_FILE.exists():
        TEMP_HUNTING_QUERIES_FILE.unlink()
        print(f"Removed temporary: {TEMP_HUNTING_QUERIES_FILE}")

    if original_detection_patterns is not None:
        TEMP_DETECTION_PATTERNS_FILE.write_text(original_detection_patterns)
        print(f"Restored original: {TEMP_DETECTION_PATTERNS_FILE}")
    elif TEMP_DETECTION_PATTERNS_FILE.exists():
        TEMP_DETECTION_PATTERNS_FILE.unlink()
        print(f"Removed temporary: {TEMP_DETECTION_PATTERNS_FILE}")

    # If the config directory itself was created by this script and is now empty, remove it.
    # This is a basic check; a more robust check would see if it was empty *before* this script.
    try:
        if EXAMPLE_CONFIG_PATH.is_dir() and not any(EXAMPLE_CONFIG_PATH.iterdir()):
            EXAMPLE_CONFIG_PATH.rmdir()
            print(f"Removed empty directory: {EXAMPLE_CONFIG_PATH}")
    except OSError as e:
        print(f"Error removing directory {EXAMPLE_CONFIG_PATH}: {e}")


async def main():
    print("Starting Threat Hunter example...")

    mock_workspace_id = "your-log-analytics-workspace-id"
    mock_subscription_id = "your-azure-subscription-id"

    mock_hunt_id = setup_temporary_hunter_config()

    try:
        # Initialize KQLOptimizer (dependency for ThreatHunter)
        kql_optimizer = KQLOptimizer(
            workspace_id=mock_workspace_id,
            subscription_id=mock_subscription_id
        )
        print("KQLOptimizer initialized for ThreatHunter.")

        # Initialize ThreatHunter
        # This will use the temporary config/hunting_queries.yaml and config/detection_patterns.yaml
        # because ThreatHunter's _load_hunting_queries and _load_detection_patterns stubs
        # use fixed paths to these files.
        threat_hunter = ThreatHunter(
            workspace_id=mock_workspace_id,
            kql_optimizer=kql_optimizer
        )
        print("ThreatHunter initialized.")

        print(f"\nRunning hunt for ID: '{mock_hunt_id}' (using stubbed methods)...")
        # This call will use several stubbed methods:
        # - KQLOptimizer.optimize_query (stubbed)
        # - ThreatHunter._execute_query (stubbed)
        # - ThreatHunter._analyze_findings (which calls other stubs like _matches_threat_pattern)
        # - ThreatHunter._determine_severity, _calculate_confidence, etc. (all stubbed)
        hunt_result = await threat_hunter.run_hunt(hunt_id=mock_hunt_id)

        print("\n--- Threat Hunting Result ---")
        if hunt_result:
            print(f"  Query ID: {hunt_result.query_id}")
            print(f"  Timestamp: {hunt_result.timestamp}")
            print(f"  Severity: {hunt_result.severity}") # From stub
            print(f"  Confidence: {hunt_result.confidence}") # From stub

            print(f"  Findings ({len(hunt_result.findings)}):") # From stub (_analyze_findings -> _execute_query returns [])
            if not hunt_result.findings:
                print("    No findings returned by stubbed analysis.")
            for finding in hunt_result.findings: # This loop won't run if findings is empty
                print(f"    - {finding}")

            print(f"  Related Entities ({len(hunt_result.related_entities)}):") # From stub
            if not hunt_result.related_entities:
                print("    No related entities identified by stub.")
            for entity in hunt_result.related_entities: # Won't run
                 print(f"    - {entity}")

            print(f"  Recommended Actions:")
            if hunt_result.recommended_actions:
                 for action in hunt_result.recommended_actions:
                     print(f"    - {action}") # From _generate_recommendations (which might use stubbed detection_patterns)
            else:
                print("    No specific recommendations provided.")
        else:
            print("  No hunt result returned.")

    except Exception as e:
        print(f"\nAn error occurred during Threat Hunter example: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup_temporary_hunter_config()

    print("\nThreat Hunter example finished.")

if __name__ == "__main__":
    asyncio.run(main())
