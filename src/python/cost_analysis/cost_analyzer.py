# src/python/cost_analysis/cost_analyzer.py

from typing import Dict, List, Optional, Union
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from dataclasses import dataclass
import asyncio
import json
import logging

@dataclass
class CostBreakdown:
    table_costs: Dict[str, float]
    storage_costs: Dict[str, float]
    query_costs: Dict[str, float]
    total_cost: float
    cost_trends: Dict[str, List[float]]
    optimization_opportunities: List[Dict]

class SentinelCostAnalyzer:
    """
    Advanced cost analysis and optimization tool for Microsoft Sentinel.
    """

    def __init__(self, workspace_id: str, subscription_id: str):
        self.workspace_id = workspace_id
        self.subscription_id = subscription_id
        self.logger = logging.getLogger(__name__)
        self.cost_thresholds = self._load_cost_thresholds()
        self.historical_data = pd.DataFrame()

    def _load_cost_thresholds(self) -> Dict:
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
        Perform comprehensive cost analysis.
        
        Args:
            days_lookback (int): Number of days to analyze
            
        Returns:
            CostBreakdown: Detailed cost analysis results
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
        results = await self._execute_query(query)
        return pd.DataFrame(results)

    async def _analyze_table_costs(self, data: pd.DataFrame) -> Dict[str, float]:
        """Analyze costs by table."""
        table_analysis = {}
        
        for table in data['TableName'].unique():
            table_data = data[data['TableName'] == table]
            
            table_analysis[table] = {
                'daily_cost': table_data['DataVolume'].mean() * 
                             self.cost_thresholds['storage_tier']['hot'],
                'trend': self._calculate_trend(table_data['DataVolume']),
                'optimization_potential': self._estimate_optimization_potential(
                    table_data
                )
            }
        
        return table_analysis

    def _identify_optimization_opportunities(
        self,
        table_costs: Dict,
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

    def _calculate_trend(self, data: pd.Series) -> Dict:
        """Calculate trend metrics for a data series."""
        trend = np.polyfit(range(len(data)), data, 1)[0]
        return {
            'direction': 'increasing' if trend > 0 else 'decreasing',
            'magnitude': abs(trend),
            'percent_change': (
                (data.iloc[-1] - data.iloc[0]) / data.iloc[0]
            ) * 100 if len(data) > 1 else 0
        }

    async def generate_cost_report(self, analysis: CostBreakdown) -> str:
        """Generate detailed cost analysis report."""
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
        """Export cost analysis results."""
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
        """Generate cost visualization data."""
        import plotly.graph_objects as go
        
        visualizations = {}

        # Cost breakdown pie chart
        cost_breakdown = go.Figure(data=[go.Pie(
            labels=['Table Costs', 'Storage Costs', 'Query Costs'],
            values=[
                sum(analysis.table_costs.values()),
                sum(analysis.storage_costs.values()),
                sum(analysis.query_costs.values())
            ]
        )])
        visualizations['cost_breakdown'] = cost_breakdown

        # Cost trend line chart
        trend_data = pd.DataFrame(analysis.cost_trends['daily'])
        trend_chart = go.Figure(data=[go.Scatter(
            x=trend_data.index,
            y=trend_data['total_cost'],
            mode='lines+markers'
        )])
        visualizations['cost_trend'] = trend_chart

        return visualizations