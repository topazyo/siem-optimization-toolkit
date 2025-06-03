# src/python/dashboards/sentinel_dashboard.py

from typing import Dict, List, Optional
import json
import yaml
from datetime import datetime, timedelta
from dataclasses import dataclass
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import logging # Added import

@dataclass
class DashboardMetrics:
    """
    Holds all data required to generate the Sentinel monitoring dashboard.

    This dataclass aggregates various metrics from different aspects of Sentinel
    operations, including data ingestion, cost, query performance, threat
    detections, and overall system health.
    """
    ingestion_volume: float  # Total data ingestion volume, typically in GB.
    cost_metrics: Dict  # Metrics related to Sentinel costs.
                        # Example: {'total_cost': 500.75, 'daily_costs': {'2023-01-01': 20.5, ...},
                        #           'cost_by_category': {'Data Ingestion': 300.0, 'Analytics Rules': 100.25},
                        #           'cost_trend_percentage': 5.2, 'potential_savings': 75.0}
    query_performance: Dict  # Performance metrics for KQL queries.
                             # Example: {'avg_execution_time': 0.5, 'slow_queries': [{'name': 'xyz', 'time': 2.3}],
                             #           'execution_times': [[0.2, 0.5], [0.8, 0.3]], # Heatmap data
                             #           'query_names': ['QueryA', 'QueryB'], # Heatmap labels
                             #           'time_periods': ['Last 24h', 'Last 7d'], # Heatmap labels
                             #           'optimization_impact': 15.0} # Percentage improvement
    threat_findings: List[Dict]  # List of detected threats or notable events.
                                 # Example: [{'id': 'THREAT001', 'severity': 'high', 'description': 'Malware detected', 'timestamp': '...'},
                                 #           {'id': 'THREAT002', 'severity': 'medium', 'description': 'Suspicious login'}]
    system_health: Dict  # Metrics indicating the health of the Sentinel system and its components.
                         # Example: {'data_connector_status': {'AzureActivity': 'healthy', 'Office365': 'error'},
                         #           'rule_latency_avg_ms': 120, 'ingestion_delay_avg_s': 30}

class SentinelDashboard:
    """
    Dynamic dashboard generator for Sentinel monitoring and optimization.
    """

    def __init__(self, template_path: str = 'config/dashboard_templates.yaml'):
        """
        Initializes the SentinelDashboard instance.

        This constructor loads dashboard layout templates from a specified YAML file.
        These templates define the structure and content sections of the dashboard.
        It also initializes an attribute to hold the current metrics data.

        Args:
            template_path (str, optional): The file system path to the YAML file
                                           containing dashboard layout templates.
                                           Defaults to 'config/dashboard_templates.yaml'.

        Initializes key attributes:
        - `templates` (Dict): A dictionary loaded from the `template_path` file,
                              containing definitions for dashboard sections and elements.
        - `current_metrics` (Optional[DashboardMetrics]): Stores the `DashboardMetrics`
                                                        object last used to generate a
                                                        dashboard. Initialized to None.
        """
        self.templates = self._load_templates(template_path)
        self.current_metrics = None # Will be set when generate_dashboard is called

    def _load_templates(self, path: str) -> Dict:
        """Load dashboard templates from YAML configuration."""
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    async def generate_dashboard(self, metrics: DashboardMetrics) -> Dict:
        """
        Asynchronously generates a structured dashboard dictionary from provided metrics.

        The dashboard is composed of several sections (e.g., cost, performance,
        threats, health), each containing titles, Plotly charts serialized to JSON,
        and summary metrics. This structured dictionary can then be used by other
        methods to render the dashboard into a specific format like HTML or PDF.

        Args:
            metrics (DashboardMetrics): A `DashboardMetrics` object containing all the
                                        data needed to populate the dashboard sections.

        Returns:
            Dict: A dictionary representing the complete dashboard.
                  The structure is typically:
                  {
                      'timestamp': 'ISO_timestamp_of_generation',
                      'sections': {
                          'cost_optimization': {
                              'title': 'Cost Optimization Metrics',
                              'charts': {'cost_trend_json': '{plotly_json}', ...},
                              'summary_metrics': {'total_cost': ..., ...}
                          },
                          'performance_metrics': { ... },
                          'threat_hunting': { ... },
                          'system_health': { ... }
                      }
                  }
        """
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
        """
        Asynchronously exports the currently generated dashboard into the specified format.

        Currently supports HTML. PDF generation is intended for future implementation.
        The dashboard must be generated using `generate_dashboard` before exporting.

        Args:
            format (str, optional): The desired output format for the dashboard.
                                    Currently supported: 'html'. 'pdf' is a placeholder.
                                    Defaults to 'html'.

        Returns:
            str: A string containing the dashboard content in the specified format
                 (e.g., HTML content). For 'pdf', it would eventually return PDF data
                 or a path to the PDF file.

        Raises:
            ValueError: If an unsupported `format` is specified.
            RuntimeError: If `generate_dashboard` has not been called first to populate
                          `self.current_metrics`.
        """
        if self.current_metrics is None:
            raise RuntimeError("Dashboard has not been generated yet. Call generate_dashboard() first.")

        if format == 'html':
            # _generate_html_dashboard would use self.current_metrics or the full dashboard dict
            return self._generate_html_dashboard() # Calls new stub
        elif format == 'pdf':
            # _generate_pdf_dashboard would use self.current_metrics or the full dashboard dict
            # This is a placeholder for future PDF generation logic
            self.logger.warning("PDF export is not fully implemented yet.")
            return await self._generate_pdf_dashboard() # Calls new stub
        else:
            raise ValueError(f"Unsupported format: {format}")

    # --- Stubs for private methods ---

    def _create_health_section(self) -> Dict:
        """Stub for creating the system health section of the dashboard."""
        self.logger.warning("SentinelDashboard._create_health_section is a stub and not yet implemented.")
        return {'title': 'System Health', 'charts': {}, 'summary_metrics': {'status': 'Not Implemented'}}

    def _generate_html_dashboard(self) -> str:
        """Stub for generating an HTML representation of the dashboard."""
        self.logger.warning("SentinelDashboard._generate_html_dashboard is a stub and not yet implemented.")
        return "<html><body><h1>Dashboard Not Implemented</h1></body></html>"

    async def _generate_pdf_dashboard(self) -> str:
        """Stub for generating a PDF representation of the dashboard."""
        self.logger.warning("SentinelDashboard._generate_pdf_dashboard is a stub and not yet implemented.")
        return "" # Returning empty string for PDF stub