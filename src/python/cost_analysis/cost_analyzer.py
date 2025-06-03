# src/python/cost_analysis/cost_analyzer.py

from typing import Dict, List, Optional, Union, Any # Added Any
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from dataclasses import dataclass
import asyncio
import json
import logging

@dataclass
class CostBreakdown:
    """
    Stores the detailed results of a Microsoft Sentinel cost analysis.

    This dataclass encapsulates various aspects of cost, including breakdowns
    by table, storage tier, and query usage. It also includes total cost,
    cost trends over time, and identified optimization opportunities.
    """
    table_costs: Dict[str, float]  # Cost associated with each table, keys are table names, values are costs.
                                   # Example: {'SecurityEvent': 120.50, 'Syslog': 80.25}
    storage_costs: Dict[str, float]  # Cost associated with different storage tiers (e.g., hot, warm, cold).
                                     # Example: {'hot_tier_gb': 200.0, 'archive_tier_gb': 50.0}
    query_costs: Dict[str, float]  # Costs related to query execution, potentially broken down by query pack or type.
                                   # Example: {'adhoc_queries_usd': 75.0, 'scheduled_analytics_usd': 150.0}
    total_cost: float  # The overall total cost calculated from all components.
    cost_trends: Dict[str, List[float]]  # Time-series data showing cost trends.
                                         # Keys might be 'daily', 'weekly', 'monthly', with lists of cost values.
                                         # Example: {'daily': [10.0, 12.5, 11.0, ...]}
    optimization_opportunities: List[Dict]  # A list of identified potential cost optimizations.
                                            # Each dictionary might contain 'type', 'target', 'potential_savings', 'recommendations'.
                                            # Example: [{'type': 'table_tiering', 'target': 'OldLogs',
                                            #            'potential_savings': 50.0, 'recommendations': ['Move to archive']}]

class SentinelCostAnalyzer:
    """
    Advanced cost analysis and optimization tool for Microsoft Sentinel.
    """

    def __init__(self, workspace_id: str, subscription_id: str):
        """
        Initializes the SentinelCostAnalyzer instance.

        Sets up necessary identifiers for Azure, initializes a logger, loads
        predefined cost thresholds (e.g., for daily ingestion, query execution),
        and prepares a DataFrame to store historical cost data if needed for trend analysis.

        Args:
            workspace_id (str): The Azure Log Analytics workspace ID for Sentinel.
            subscription_id (str): The Azure subscription ID containing the workspace.

        Initializes key attributes:
        - `workspace_id` (str): Stores the Log Analytics workspace ID.
        - `subscription_id` (str): Stores the Azure subscription ID.
        - `logger` (logging.Logger): A configured logger instance.
        - `cost_thresholds` (Dict): A dictionary loaded by `_load_cost_thresholds`,
                                    containing thresholds for various cost parameters
                                    (e.g., daily ingestion limits, storage tier costs).
        - `historical_data` (pd.DataFrame): An empty DataFrame, potentially used
                                           to accumulate historical cost data for
                                           more advanced trend analysis over time.
        """
        self.workspace_id = workspace_id
        self.subscription_id = subscription_id
        self.logger = logging.getLogger(__name__)
        self.cost_thresholds = self._load_cost_thresholds() # Assumes this method is defined
        self.historical_data = pd.DataFrame()

    def _load_cost_thresholds(self) -> Dict: # Existing method, ensure it's above stubs that might use its output
        """Load cost threshold configurations."""
        return {
            'daily_ingestion': 100,  # GB
            'query_execution': 50,    # USD
            'storage_tier': {
                'hot': 2.5,          # USD per GB
                'warm': 0.5,
                'cold': 0.1
            }
        }

    async def analyze_costs(self, days_lookback: int = 30) -> CostBreakdown:
        """
        Asynchronously performs a comprehensive cost analysis for Microsoft Sentinel.

        This method fetches cost data for the specified lookback period, then
        analyzes costs broken down by tables, storage, and queries. It also
        calculates cost trends and identifies potential optimization opportunities.

        Args:
            days_lookback (int, optional): The number of past days to include
                                           in the cost analysis. Defaults to 30.

        Returns:
            CostBreakdown: A dataclass instance containing the detailed results.
                           - `table_costs` (Dict[str, float]): Costs per table, e.g.,
                             `{'SecurityEvent': 150.75, 'Syslog': 90.50}`.
                           - `storage_costs` (Dict[str, float]): Costs per storage tier/type,
                             e.g., `{'hot_tier_usd': 200.0, 'archive_tier_usd': 30.0}`.
                           - `query_costs` (Dict[str, float]): Costs related to query usage,
                             e.g., `{'analytics_rules_usd': 50.0, 'hunting_queries_usd': 25.0}`.
                           - `total_cost` (float): Sum of all identified costs.
                           - `cost_trends` (Dict[str, List[float]]): Time series data for costs,
                             e.g., `{'daily_total_usd': [20.0, 22.5, ...],
                                     'weekly_ingestion_gb': [100, 110, ...]}`.
                           - `optimization_opportunities` (List[Dict]): A list where each
                             dict describes an opportunity, e.g., `{'type': 'data_tiering',
                             'table': 'OldCustomTable', 'potential_savings_usd': 40.0,
                             'recommendation': 'Move to archive storage after 90 days.'}`.

        Raises:
            Exception: Propagates exceptions from underlying data fetching or analysis errors.
        """
        try:
            # Fetch cost data
            cost_data = await self._fetch_cost_data(days_lookback)
            
            # Analyze different cost components
            table_costs = await self._analyze_table_costs(cost_data)
            storage_costs = await self._analyze_storage_costs(cost_data)
            query_costs = await self._analyze_query_costs(cost_data)
            
            # Identify optimization opportunities
            opportunities = self._identify_optimization_opportunities(
                table_costs,
                storage_costs,
                query_costs
            )
            
            # Calculate trends
            trends = self._calculate_cost_trends(cost_data)
            
            return CostBreakdown(
                table_costs=table_costs,
                storage_costs=storage_costs,
                query_costs=query_costs,
                total_cost=sum(table_costs.values()) + 
                          sum(storage_costs.values()) + 
                          sum(query_costs.values()),
                cost_trends=trends,
                optimization_opportunities=opportunities
            )

        except Exception as e:
            self.logger.error(f"Cost analysis error: {str(e)}")
            raise

    async def _fetch_cost_data(self, days_lookback: int) -> pd.DataFrame:
        """Fetch detailed cost data from Azure."""
        query = """
        let timeframe = {days}d;
        union withsource=TableName *
        | where TimeGenerated > ago(timeframe)
        | summarize 
            DataVolume=sum(_BilledSize),
            QueryCost=sum(QueryCost),
            StorageCost=sum(StorageCost)
        by bin(TimeGenerated, 1d), TableName
        """.format(days=days_lookback)
        
        # Execute query and process results
        results = await self._execute_query(query) # Calls new stub
        return pd.DataFrame(results)

    # --- Stubs for primary analysis methods called by analyze_costs ---

    async def _execute_query(self, query: str) -> List[Dict]:
        """Stub for executing a KQL query against Azure Log Analytics."""
        self.logger.warning("SentinelCostAnalyzer._execute_query is a stub and not yet implemented.")
        return []

    async def _analyze_table_costs(self, cost_data: pd.DataFrame) -> Dict[str, float]:
        """Stub for analyzing table costs from cost data."""
        # This method originally called _calculate_trend and _estimate_optimization_potential
        self.logger.warning("SentinelCostAnalyzer._analyze_table_costs is a stub and not yet implemented. Its sub-calls are also stubbed.")
        # Example of how it might call other stubs if it had logic:
        # if not cost_data.empty:
        #    self._calculate_trend(cost_data.get('some_column', pd.Series(dtype='float64')))
        #    self._estimate_optimization_potential(cost_data)
        return {}

    async def _analyze_storage_costs(self, cost_data: pd.DataFrame) -> Dict[str, float]:
        """Stub for analyzing storage costs from cost data."""
        self.logger.warning("SentinelCostAnalyzer._analyze_storage_costs is a stub and not yet implemented.")
        return {}

    async def _analyze_query_costs(self, cost_data: pd.DataFrame) -> Dict[str, float]:
        """Stub for analyzing query costs from cost data."""
        self.logger.warning("SentinelCostAnalyzer._analyze_query_costs is a stub and not yet implemented.")
        return {}

    def _calculate_cost_trends(self, cost_data: pd.DataFrame) -> Dict[str, List[float]]:
        """Stub for calculating cost trends from cost data."""
        self.logger.warning("SentinelCostAnalyzer._calculate_cost_trends is a stub and not yet implemented.")
        return {'overall': [], 'daily': []}

    # --- Stubs for helper methods used in analysis ---

    def _estimate_optimization_potential(self, table_data: pd.DataFrame) -> float:
        """Stub for estimating optimization potential for a table."""
        self.logger.warning("SentinelCostAnalyzer._estimate_optimization_potential is a stub and not yet implemented.")
        return 0.0

    def _identify_optimization_opportunities(
        self,
        table_costs: Dict, # This now receives output from a stub
        storage_costs: Dict,
        query_costs: Dict
    ) -> List[Dict]:
        """Identify cost optimization opportunities."""
        opportunities = []

        # Analyze table-level optimizations
        for table, costs in table_costs.items():
            if costs['daily_cost'] > self.cost_thresholds['daily_ingestion']:
                opportunities.append({
                    'type': 'table_optimization',
                    'target': table,
                    'current_cost': costs['daily_cost'],
                    'potential_savings': costs['optimization_potential'],
                    'recommendations': [
                        'Implement table-specific filters',
                        'Review retention period',
                        'Consider moving to cold storage'
                    ]
                })

        # Analyze storage optimizations
        for tier, cost in storage_costs.items():
            if cost > self.cost_thresholds['storage_tier'][tier]:
                opportunities.append({
                    'type': 'storage_optimization',
                    'target': f'{tier}_tier',
                    'current_cost': cost,
                    'potential_savings': self._calculate_storage_savings(
                        tier,
                        cost
                    ),
                    'recommendations': [
                        'Implement data lifecycle management',
                        'Review retention policies',
                        'Consider compression options'
                    ]
                })

        return opportunities

    def _calculate_trend(self, data: pd.Series) -> Dict: # Existing method, ensure it's above stubs that might use its output
        """Calculate trend metrics for a data series."""
        if data.empty: # Added safety for empty series from stubbed callers
            return {'direction': 'unknown', 'magnitude': 0, 'percent_change': 0}
        trend = np.polyfit(range(len(data)), data, 1)[0] if len(data) > 1 else 0
        return {
            'direction': 'increasing' if trend > 0 else ('decreasing' if trend < 0 else 'flat'),
            'magnitude': abs(trend),
            'percent_change': (
                (data.iloc[-1] - data.iloc[0]) / data.iloc[0] * 100
            ) if len(data) > 1 and data.iloc[0] != 0 else 0
        }

    # --- Stubs for report generation helpers ---

    def _format_trend(self, trend_data: Dict) -> str:
        """Stub for formatting trend data into a string."""
        self.logger.warning("SentinelCostAnalyzer._format_trend is a stub and not yet implemented.")
        return "Trend data not available"

    def _calculate_potential_savings(self, opportunities: List[Dict]) -> float:
        """Stub for calculating potential savings from opportunities."""
        self.logger.warning("SentinelCostAnalyzer._calculate_potential_savings is a stub and not yet implemented.")
        return 0.0

    def _format_table_costs(self, table_costs: Dict) -> str:
        """Stub for formatting table costs into a string."""
        self.logger.warning("SentinelCostAnalyzer._format_table_costs is a stub and not yet implemented.")
        return "Table cost data not available"

    def _format_storage_costs(self, storage_costs: Dict) -> str:
        """Stub for formatting storage costs into a string."""
        self.logger.warning("SentinelCostAnalyzer._format_storage_costs is a stub and not yet implemented.")
        return "Storage cost data not available"

    def _format_query_costs(self, query_costs: Dict) -> str:
        """Stub for formatting query costs into a string."""
        self.logger.warning("SentinelCostAnalyzer._format_query_costs is a stub and not yet implemented.")
        return "Query cost data not available"

    def _format_opportunities(self, opportunities: List[Dict]) -> str:
        """Stub for formatting optimization opportunities into a string."""
        self.logger.warning("SentinelCostAnalyzer._format_opportunities is a stub and not yet implemented.")
        return "Optimization opportunities data not available"

    def _generate_recommendations(self, analysis: 'CostBreakdown') -> str:
        """Stub for generating recommendations based on cost analysis."""
        self.logger.warning("SentinelCostAnalyzer._generate_recommendations is a stub and not yet implemented.")
        return "Recommendations not available"

    async def generate_cost_report(self, analysis: CostBreakdown) -> str:
        """
        Asynchronously generates a formatted string report from a CostBreakdown object.

        The report is typically structured in Markdown or HTML, providing a human-readable
        summary of the cost analysis, including total costs, breakdowns, trends,
        and optimization opportunities.

        Args:
            analysis (CostBreakdown): A `CostBreakdown` object containing the
                                      results of a prior cost analysis.

        Returns:
            str: A formatted string (e.g., Markdown) representing the cost report.
        """
        report_template = """
        # Sentinel Cost Analysis Report
        Generated: {timestamp}

        ## Executive Summary
        - Total Cost: ${total_cost:,.2f}
        - Trend: {trend}
        - Potential Savings: ${potential_savings:,.2f}

        ## Cost Breakdown
        ### Table Costs
        {table_cost_breakdown}

        ### Storage Costs
        {storage_cost_breakdown}

        ### Query Costs
        {query_cost_breakdown}

        ## Optimization Opportunities
        {optimization_opportunities}

        ## Recommendations
        {recommendations}
        """

        return report_template.format(
            timestamp=datetime.utcnow().isoformat(),
            total_cost=analysis.total_cost,
            trend=self._format_trend(analysis.cost_trends['overall']),
            potential_savings=self._calculate_potential_savings(
                analysis.optimization_opportunities
            ),
            table_cost_breakdown=self._format_table_costs(
                analysis.table_costs
            ),
            storage_cost_breakdown=self._format_storage_costs(
                analysis.storage_costs
            ),
            query_cost_breakdown=self._format_query_costs(
                analysis.query_costs
            ),
            optimization_opportunities=self._format_opportunities(
                analysis.optimization_opportunities
            ),
            recommendations=self._generate_recommendations(analysis)
        )

    def _calculate_storage_savings(self, tier: str, current_cost: float) -> float:
        """Calculate potential storage cost savings."""
        if tier == 'hot':
            # Estimate savings from moving to warm storage
            potential_warm_cost = (
                current_cost / self.cost_thresholds['storage_tier']['hot']
            ) * self.cost_thresholds['storage_tier']['warm']
            return current_cost - potential_warm_cost
        elif tier == 'warm':
            # Estimate savings from moving to cold storage
            potential_cold_cost = (
                current_cost / self.cost_thresholds['storage_tier']['warm']
            ) * self.cost_thresholds['storage_tier']['cold']
            return current_cost - potential_cold_cost
        return 0.0

    async def export_analysis(
        self,
        analysis: CostBreakdown,
        format: str = 'json'
    ) -> None:
        """
        Asynchronously exports the cost analysis results to a file.

        The analysis data, contained in a `CostBreakdown` object, can be
        exported in various formats like JSON, CSV, or HTML. The output
        filename includes a timestamp.

        Args:
            analysis (CostBreakdown): The `CostBreakdown` object containing the
                                      analysis data to be exported.
            format (str, optional): The desired output format. Supported formats
                                    are 'json', 'csv', and 'html'. Defaults to 'json'.

        Raises:
            ValueError: If an unsupported format is specified.
            Exception: Propagates errors encountered during file writing.
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f'cost_analysis_{timestamp}.{format}'

        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(analysis.__dict__, f, indent=2)
            elif format == 'csv':
                pd.DataFrame({
                    'table_costs': analysis.table_costs,
                    'storage_costs': analysis.storage_costs,
                    'query_costs': analysis.query_costs
                }).to_csv(filename)
            elif format == 'html':
                report = await self.generate_cost_report(analysis)
                with open(filename, 'w') as f:
                    f.write(report)
            else:
                raise ValueError(f"Unsupported export format: {format}")

            self.logger.info(f"Analysis exported to {filename}")

        except Exception as e:
            self.logger.error(f"Export error: {str(e)}")
            raise

    async def visualize_costs(self, analysis: CostBreakdown) -> Dict:
        """
        Asynchronously generates data for cost visualizations using Plotly.

        Creates graph objects for key aspects of the cost analysis, such as
        a pie chart for cost breakdown by component (tables, storage, queries)
        and a line chart for cost trends over time.

        Args:
            analysis (CostBreakdown): A `CostBreakdown` object containing the
                                      results of a prior cost analysis.

        Returns:
            Dict[str, go.Figure]: A dictionary where keys are descriptive names
                                  (e.g., 'cost_breakdown_pie', 'daily_cost_trend_line')
                                  and values are Plotly `Figure` objects. These objects
                                  can then be rendered to HTML, JSON, or displayed in
                                  compatible environments. For example:
                                  `visualizations['cost_breakdown_pie'].to_html()`
        """
        import plotly.graph_objects as go # type: ignore
        
        visualizations = {}

        # Cost breakdown pie chart
        # Ensure values are summable and handle potential empty dicts for costs
        table_total = sum(analysis.table_costs.values()) if analysis.table_costs else 0
        storage_total = sum(analysis.storage_costs.values()) if analysis.storage_costs else 0
        query_total = sum(analysis.query_costs.values()) if analysis.query_costs else 0

        cost_breakdown_fig = go.Figure(data=[go.Pie(
            labels=['Table Costs', 'Storage Costs', 'Query Costs'],
            values=[table_total, storage_total, query_total],
            title='Overall Cost Distribution'
        )])
        visualizations['cost_breakdown_pie'] = cost_breakdown_fig

        # Cost trend line chart (assuming 'daily' trend exists and has a 'total_cost' like list)
        # This part needs careful handling of the 'cost_trends' structure.
        # Assuming analysis.cost_trends is like {'daily_total_usd': [10,12,11,...]}
        # Or if it's a DataFrame already: trend_data = analysis.cost_trends.get('daily_total_usd_df')

        # Example: if cost_trends['daily_total_usd'] is a list of daily costs
        daily_costs = analysis.cost_trends.get('daily_total_usd', []) # Default to empty list
        if daily_costs:
            trend_chart_fig = go.Figure(data=[go.Scatter(
                x=list(range(len(daily_costs))), # Simple index for x-axis
                y=daily_costs,
                mode='lines+markers',
                name='Daily Total Cost (USD)'
            )])
            trend_chart_fig.update_layout(title='Daily Cost Trend',
                                          xaxis_title='Day',
                                          yaxis_title='Cost (USD)')
            visualizations['daily_cost_trend_line'] = trend_chart_fig
        else:
            # Handle case where trend data might be missing or in a different format
            self.logger.warning("Daily cost trend data not found or in unexpected format for visualization.")


        return visualizations