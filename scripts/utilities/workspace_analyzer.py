# scripts/utilities/workspace_analyzer.py

import argparse
import asyncio
from src.python.ingestion_monitoring.sentinel_monitor import SentinelMonitor

async def analyze_workspace(workspace_id: str, subscription_id: str):
    """Analyze a Sentinel workspace and generate optimization report."""
    monitor = SentinelMonitor(workspace_id, subscription_id)
    
    # Run analysis
    results = await monitor.analyze_ingestion_patterns()
    
    # Generate report
    report = await monitor.generate_report(results)
    
    # Export results
    await monitor.export_results(results, format='json')
    
    print("Analysis complete! Check the generated report for details.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze Sentinel workspace for optimization opportunities"
    )
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--subscription-id", required=True)
    
    args = parser.parse_args()
    
    asyncio.run(analyze_workspace(args.workspace_id, args.subscription_id))