# src/python/dashboards/sentinel_dashboard.py

from typing import Dict, List, Optional
import json
import yaml
from datetime import datetime, timedelta
from dataclasses import dataclass
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

@dataclass
class DashboardMetrics:
    ingestion_volume: float
    cost_metrics: Dict
    query_performance: Dict
    threat_findings: List[Dict]
    system_health: Dict

class SentinelDashboard:
    """
    Dynamic dashboard generator for Sentinel monitoring and optimization.
    """

    def __init__(self, template_path: str = 'config/dashboard_templates.yaml'):
        self.templates = self._load_templates(template_path)
        self.current_metrics = None

    def _load_templates(self, path: str) -> Dict:
        """Load dashboard templates from YAML configuration."""
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    async def generate_dashboard(self, metrics: DashboardMetrics) -> Dict:
        """Generate a complete dashboard with all visualizations."""
        self.current_metrics = metrics
        
        dashboard = {
            'timestamp': datetime.utcnow().isoformat(),
            'sections': {
                'cost_optimization': self._create_cost_section(),
                'performance_metrics': self._create_performance_section(),
                'threat_hunting': self._create_threat_section(),
                'system_health': self._create_health_section()
            }
        }

        return dashboard

    def _create_cost_section(self) -> Dict:
        """Create cost optimization visualizations."""
        cost_data = self.current_metrics.cost_metrics
        
        # Create cost trend chart
        cost_trend = go.Figure(data=[
            go.Scatter(
                x=list(cost_data['daily_costs'].keys()),
                y=list(cost_data['daily_costs'].values()),
                mode='lines+markers',
                name='Daily Cost'
            )
        ])

        # Create cost breakdown pie chart
        cost_breakdown = go.Figure(data=[
            go.Pie(
                labels=list(cost_data['cost_by_category'].keys()),
                values=list(cost_data['cost_by_category'].values())
            )
        ])

        return {
            'title': 'Cost Optimization Metrics',
            'charts': {
                'cost_trend': cost_trend.to_json(),
                'cost_breakdown': cost_breakdown.to_json()
            },
            'summary_metrics': {
                'total_cost': cost_data['total_cost'],
                'cost_trend': cost_data['cost_trend_percentage'],
                'savings_opportunities': cost_data['potential_savings']
            }
        }

    def _create_performance_section(self) -> Dict:
        """Create performance monitoring visualizations."""
        perf_data = self.current_metrics.query_performance
        
        # Create query performance heatmap
        performance_heatmap = go.Figure(data=go.Heatmap(
            z=perf_data['execution_times'],
            x=perf_data['query_names'],
            y=perf_data['time_periods']
        ))

        return {
            'title': 'Query Performance Metrics',
            'charts': {
                'performance_heatmap': performance_heatmap.to_json()
            },
            'summary_metrics': {
                'avg_execution_time': perf_data['avg_execution_time'],
                'optimization_impact': perf_data['optimization_impact']
            }
        }

    def _create_threat_section(self) -> Dict:
        """Create threat hunting visualizations."""
        threat_data = pd.DataFrame(self.current_metrics.threat_findings)
        
        # Create threat severity distribution
        severity_dist = px.bar(
            threat_data.groupby('severity').size().reset_index(),
            x='severity',
            y=0
        )

        return {
            'title': 'Threat Hunting Results',
            'charts': {
                'severity_distribution': severity_dist.to_json()
            },
            'summary_metrics': {
                'total_findings': len(threat_data),
                'high_severity_count': len(
                    threat_data[threat_data['severity'] == 'high']
                )
            }
        }

    async def export_dashboard(self, format: str = 'html') -> str:
        """Export dashboard in specified format."""
        if format == 'html':
            return self._generate_html_dashboard()
        elif format == 'pdf':
            return await self._generate_pdf_dashboard()
        else:
            raise ValueError(f"Unsupported format: {format}")