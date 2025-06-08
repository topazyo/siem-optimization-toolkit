import asyncio
from src.python.query_optimization.advanced_kql_optimizer import AdvancedKQLOptimizer
# Assuming KQLOptimizer is in src.python.query_optimization.kql_optimizer
# Adjust if the path is different.

async def main():
    print("Starting KQL Optimizer example...")

    # Replace with your actual workspace ID and subscription ID for real use.
    mock_workspace_id = "your-log-analytics-workspace-id"
    mock_subscription_id = "your-azure-subscription-id"

    # Initialize KQLOptimizer
    # For this example, KQLOptimizer's __init__ doesn't make Azure calls,
    # but its methods that might benchmark queries would.
    # Our stubs currently prevent actual Azure calls.
    try:
        optimizer = AdvancedKQLOptimizer(
            workspace_id=mock_workspace_id
        )
        print("KQLOptimizer initialized.")
    except Exception as e:
        print(f"Error initializing KQLOptimizer: {e}")
        # If KQLOptimizer's __init__ were to fail, the script would stop here.
        return

    # Example KQL query to optimize
    # This is a simple query; a more complex one might show more optimization steps.
    original_query = """
    SecurityEvent
    | where EventID == 4624 # Successful logon
    | where AccountType == 'User'
    | summarize count() by Account, TargetLogonId
    | where count_ > 5
    | join kind=inner (
        AuditLogs
        | where OperationName has "successful login"
    ) on $left.Account == $right.UserId
    | project Account, TargetLogonId, OperationName, count_
    """
    # A simpler query that might trigger the "time_window" optimization
    # original_query = "SecurityEvent | take 100"


    print("\nOriginal KQL Query:")
    print(original_query)

    print("\nOptimizing query (using stubs for actual optimization logic and benchmarking)...")
    try:
        # Call optimize_query
        # The underlying optimization methods (_optimize_time_window, _optimize_joins, _optimize_where_clauses)
        # are currently stubbed. _estimate_performance_improvement is also stubbed.
        optimized_query, optimization_details = await optimizer.optimize_query(original_query)

        print("\n--- Query Optimization Results ---")

        print("\nOptimized KQL Query:")
        print(optimized_query) # Will likely be same as original due to stubs, or with minor additions like time filter

        print("\nOptimization Details:")
        if optimization_details:
            print(f"  Original Query Hash (example): {hash(optimization_details.get('original_query'))}") # Example detail
            print("  Optimizations Applied:")
            for opt in optimization_details.get('optimizations_applied', []):
                print(f"    - Type: {opt.get('type')}")
                print(f"      Description: {opt.get('description')}")
                if opt.get('impact'):
                    print(f"      Impact: {opt.get('impact')}")
                if opt.get('changes'):
                    print(f"      Changes: {', '.join(opt.get('changes',[]))}")
            print(f"  Estimated Improvement: {optimization_details.get('estimated_improvement', 0.0)}%")
        else:
            print("  No optimization details returned.")

    except Exception as e:
        print(f"\nAn error occurred during query optimization: {e}")

    print("\nKQL Optimizer example finished.")

if __name__ == "__main__":
    asyncio.run(main())
