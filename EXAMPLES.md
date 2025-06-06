# SIEM Optimization Toolkit - Usage Examples

This document provides an overview of the example scripts available in the `examples/use_cases/` directory. These scripts demonstrate how to use various components of the SIEM Optimization Toolkit.

**Note on Azure API Calls and Stubbed Methods:**

This toolkit contains a mix of components. Some, like the `AdvancedKQLOptimizer` and `QueryBenchmark` (for their query execution and benchmarking features), have been updated to attempt **live Azure API calls** to your Log Analytics workspace. For these components to function correctly, you must meet the Azure connectivity prerequisites (see `README.md`). If these prerequisites are not met, the Azure calls will fail.

Other components, or parts of components not directly related to live query execution, may still use placeholder (stubbed) methods for some Azure API interactions or complex internal logic. Therefore, while examples will run and show the intended flow, the output data for these stubbed parts will be based on mock data and may not reflect real-world processing outcomes until those specific stubs are replaced with full implementations.

Always check the individual example script's comments and the component's own documentation for specific details on its behavior regarding Azure interaction and stubbed functionalities.

## Running the Examples

Ensure you have installed the necessary dependencies from `requirements.txt`:
```bash
pip install -r requirements.txt
```
All examples are designed to be run from the root directory of the repository.

---

### 1. Sentinel Ingestion Monitoring Analysis

**File:** `python examples/use_cases/example_sentinel_monitor_analysis.py`

**Description:**
This script demonstrates how to use the `SentinelMonitor` component to analyze log ingestion patterns. It initializes the monitor, calls the `analyze_ingestion_patterns` method, and prints a summary of the analysis results (based on simulated Azure data interaction), including total volume, daily patterns, peak hours, recommendations, and cost impact.

**Note on Azure Credentials:**
For real-world use against an Azure environment, ensure your Azure credentials are properly configured for `DefaultAzureCredential` (e.g., by logging in with `az login`). The example uses placeholder Workspace and Subscription IDs which you would replace. The underlying Azure data retrieval in `SentinelMonitor` is structured for live calls but currently uses simulated data.

**To Run:**
```bash
python examples/use_cases/example_sentinel_monitor_analysis.py
```

---

### 2. KQL Query Optimization

**File:** `python examples/use_cases/example_kql_optimizer.py`

**Description:**
This script shows how to use the `AdvancedKQLOptimizer` to attempt to optimize a Kusto Query Language (KQL) query. It initializes the optimizer, provides a sample KQL query, calls the `optimize_query` method, and then prints the original query, the potentially modified query (as the optimizer can now apply some safe changes directly or add detailed suggestions as comments), and a list of identified optimization opportunities.

**Note on Azure Credentials:**
`AdvancedKQLOptimizer` initialization itself does not require Azure calls. However, its methods for query optimization and benchmarking (e.g., `benchmark_query`, and `optimize_query` when it invokes benchmarking) now make **live Azure calls** to execute KQL queries and retrieve performance statistics from your Log Analytics workspace.

Ensure your Azure environment is correctly authenticated (e.g., via `az login` or environment variables for `DefaultAzureCredential`) and the `workspace_id` provided to the optimizer is valid and accessible. If these prerequisites are not met, the Azure-dependent operations will fail. Refer to the main `README.md` for more details on Azure connectivity prerequisites.

**To Run:**
```bash
python examples/use_cases/example_kql_optimizer.py
```

---

### 3. Detection Rule Engine and Tester

**File:** `python examples/use_cases/example_rule_engine_tester.py`

**Description:**
This script demonstrates the workflow of using the `RuleEngine` to evaluate detection rules and the `RuleTester` to test them.
It programmatically:
1. Sets up temporary directories for a dummy rule configuration (`.yaml`) and a dummy test case (`.json`).
2. Initializes `RuleEngine` using the temporary rule.
3. Evaluates the dummy rule with a mock context and prints the (stubbed) results.
4. Initializes `RuleTester` with the `RuleEngine`.
5. Calls `test_rule` to test the dummy rule (noting that `RuleTester`'s default test case loading is stubbed and might not find the temporary test case correctly without modification to `RuleTester` itself).
6. Prints the (stubbed) test results and a (stubbed) test report.
7. Cleans up the temporary files and directories.

This example is particularly useful for understanding the interaction between rule definitions, the engine, and the testing framework, even with stubbed underlying logic.

**To Run:**
```bash
python examples/use_cases/example_rule_engine_tester.py
```

---

### 4. Threat Hunting

**File:** `python examples/use_cases/example_threat_hunter.py`

**Description:**
This script illustrates how to use the `ThreatHunter` component to execute a threat hunting query.
It programmatically:
1. Sets up temporary `hunting_queries.yaml` and `detection_patterns.yaml` files in the `config/` directory (backing up and restoring any originals). This is done because `ThreatHunter`'s stubs for loading these configurations expect them in fixed locations.
2. Initializes `AdvancedKQLOptimizer` (a dependency for `ThreatHunter`).
3. Initializes `ThreatHunter`.
4. Calls `run_hunt` for a mock hunt ID defined in the temporary configuration.
5. Prints a `ThreatHuntingResult` (based on simulated Azure data interaction for query execution), showing structure for findings, severity, confidence, etc.
6. Cleans up the temporary configuration files.

**To Run:**
```bash
python examples/use_cases/example_threat_hunter.py
```

---

### 5. Enhanced Log Routing

**File:** `python examples/use_cases/example_enhanced_log_router.py`

**Description:**
This script demonstrates the capabilities of the `EnhancedLogRouter`.
It:
1. Initializes `EnhancedLogRouter` (noting its `config_path` argument is for a stubbed `_load_config`).
2. Manually adds a sample `RoutingRule` to the router instance, defining conditions and (stubbed) transformations.
3. Defines a list of sample log messages.
4. Calls `route_logs` to process these messages.
5. Prints the (stubbed) routed logs, which will show how logs are grouped by destination type and include metadata from the `_enrich_log` method.
6. Generates and prints a (stubbed) metrics report from the router.

This example shows the basic flow of log processing, even though while some basic condition matching and simple transformations are implemented, many advanced transformations and actual destination sending logic are currently placeholders.

**To Run:**
```bash
python examples/use_cases/example_enhanced_log_router.py
```
