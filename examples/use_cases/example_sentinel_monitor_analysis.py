import asyncio
from src.python.ingestion_monitoring.sentinel_monitor import SentinelMonitor
import json # For pretty printing

async def main():
    print("Starting Sentinel Monitor example...")

    # Replace with your actual workspace ID and subscription ID for real use
    # For this example, we'll use placeholder IDs.
    # Ensure these are valid if you intend to run this against a live Azure environment.
    mock_workspace_id = "your-log-analytics-workspace-id"
    mock_subscription_id = "your-azure-subscription-id"

    print(f"Initializing SentinelMonitor with Workspace ID: {mock_workspace_id}, Subscription ID: {mock_subscription_id}")

    # Initialize the monitor
    # In a real scenario, ensure Azure credentials are set up for DefaultAzureCredential to work.
    # This might involve logging in via Azure CLI (`az login`) or setting environment variables.
    try:
        monitor = SentinelMonitor(
            workspace_id=mock_workspace_id,
            subscription_id=mock_subscription_id
        )
        print("SentinelMonitor initialized.")
    except Exception as e:
        print(f"Error initializing SentinelMonitor: {e}")
        print("Please ensure you are authenticated with Azure (e.g., `az login`) and "
              "the Azure SDKs can find your credentials.")
        print("This example will proceed with mocked calls for demonstration purposes "
              "if Azure connectivity/authentication fails for the actual SDK calls within SentinelMonitor's stubs.")
        # To allow the example to run without live Azure access, we can mock the monitor's methods
        # if actual initialization fails due to auth or other issues.
        # For now, we assume stubs in SentinelMonitor handle Azure calls gracefully.
        # If SentinelMonitor's __init__ itself tries to connect and fails hard, this example would stop.
        # The current stubs mostly affect data fetching methods, not __init__.
        pass


    print("\nRunning ingestion pattern analysis (using stubs for Azure calls)...")
    try:
        # Call analyze_ingestion_patterns (uses stubbed _get_ingestion_data -> _execute_query)
        # The number of days for lookback can be adjusted.
        analysis_results = await monitor.analyze_ingestion_patterns(days_lookback=7)
        print("Analysis complete.")

        print("\n--- Ingestion Analysis Results ---")

        # Pretty print parts of the results
        if analysis_results:
            print(f"Analysis Period Start: {analysis_results.get('analysis_period', {}).get('start')}")
            print(f"Analysis Period End: {analysis_results.get('analysis_period', {}).get('end')}")
            print(f"Total Volume (GB): {analysis_results.get('total_volume_gb', 'N/A')}")

            print("\nDaily Patterns (Volume in GB):")
            daily_patterns = analysis_results.get('daily_patterns', {})
            if daily_patterns:
                for day, volume in daily_patterns.items():
                    print(f"  {day}: {volume:.2f} GB")
            else:
                print("  No daily pattern data.")

            print("\nPeak Hours (based on average hourly volume):")
            peak_hours = analysis_results.get('peak_hours', [])
            if peak_hours:
                print(f"  {', '.join(map(str, peak_hours))}")
            else:
                print("  No peak hour data.")

            print("\nRecommendations:")
            recommendations = analysis_results.get('recommendations', [])
            if recommendations:
                for rec in recommendations:
                    print(f"  - Type: {rec.get('type')}")
                    print(f"    Severity: {rec.get('severity')}")
                    print(f"    Description: {rec.get('description')}")
                    if rec.get('table_name'):
                        print(f"    Table: {rec.get('table_name')}")
                    print(f"    Suggested Actions: {', '.join(rec.get('suggested_actions', []))}")
            else:
                print("  No recommendations provided by the stubbed methods.")

            print("\nCost Impact Analysis:")
            cost_impact = analysis_results.get('cost_impact', {})
            if cost_impact:
                print(f"  Current Monthly Cost Estimate: ${cost_impact.get('current_monthly_cost', 0):.2f}")
                print(f"  Projected Monthly Savings Estimate: ${cost_impact.get('projected_savings', 0):.2f}")
            else:
                print("  No cost impact data.")

        else:
            print("  No analysis results returned (as expected from stubs).")

    except Exception as e:
        print(f"\nAn error occurred during analysis: {e}")
        print("This might be due to issues connecting to Azure if stubs are not fully covering API calls,")
        print("or if there's an issue in the example script logic itself.")

    print("\nSentinel Monitor example finished.")

if __name__ == "__main__":
    # For Python 3.7+
    asyncio.run(main())
