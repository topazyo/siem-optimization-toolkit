# src/python/ingestion_monitoring/sentinel_monitor.py

import azure.mgmt.loganalytics
from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from datetime import datetime, timedelta
import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
import yaml
import json

class SentinelMonitor:
    """
    Comprehensive monitoring and optimization tool for Microsoft Sentinel SIEM.
    
    Attributes:
        workspace_id (str): Log Analytics workspace ID
        subscription_id (str): Azure subscription ID
        credential (DefaultAzureCredential): Azure authentication credentials
        logger (Logger): Logging instance
    """

    def __init__(self, workspace_id: str, subscription_id: str, config_path: str = None):
        """
        Initializes the SentinelMonitor instance.

        Args:
            workspace_id (str): The Azure Log Analytics workspace ID where Sentinel is enabled.
            subscription_id (str): The Azure subscription ID containing the workspace.
            config_path (str, optional): Path to a YAML configuration file.
                                         If not provided, default settings are used.

        Initializes key attributes:
        - `workspace_id`: Stores the Log Analytics workspace ID.
        - `subscription_id`: Stores the Azure subscription ID.
        - `credential`: An instance of `DefaultAzureCredential` for authentication.
        - `logger`: A configured logger instance for logging messages.
        - `config`: A dictionary containing configuration settings, loaded from
                    `config_path` or defaults.
        - `la_client`: An instance of `LogAnalyticsManagementClient` for interacting
                       with Log Analytics.
        - `monitor_client`: An instance of `MonitorManagementClient` for interacting
                            with Azure Monitor.
        """
        self.workspace_id = workspace_id
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.logger = self._setup_logger()
        self.config = self._load_config(config_path)
        
        # Initialize Azure clients
        self.la_client = LogAnalyticsManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )
        self.monitor_client = MonitorManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )

    def _setup_logger(self) -> logging.Logger:
        """Configure logging with appropriate formatting and handlers."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from YAML file or use defaults."""
        default_config = {
            'ingestion_thresholds': {
                'daily_gb': 100,
                'hourly_gb': 5,
                'alert_threshold': 0.8
            },
            'retention_policies': {
                'hot_tier': 30,
                'warm_tier': 90,
                'cold_tier': 365
            },
            'cost_thresholds': {
                'hot_tier': 2.5,
                'warm_tier': 0.5,
                'cold_tier': 0.1
            }
        }

        if config_path:
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load config file: {str(e)}")
                return default_config
        return default_config

    async def analyze_ingestion_patterns(self, days_lookback: int = 7) -> Dict:
        """
        Asynchronously analyzes log ingestion patterns over a specified period
        and provides optimization recommendations.

        Args:
            days_lookback (int): The number of past days to include in the analysis,
                                 starting from the current UTC time. Defaults to 7 days.

        Returns:
            Dict: A dictionary containing the analysis results and recommendations.
                  The structure includes:
                  - 'analysis_period' (dict): Start and end ISO format timestamps for the analysis.
                  - 'total_volume_gb' (float): Total ingested data volume in GB.
                  - 'daily_patterns' (dict): Dictionary with dates as keys and daily
                                            ingestion volume (GB) as values.
                  - 'peak_hours' (list): List of the top 3 peak ingestion hours (0-23).
                  - 'recommendations' (list): A list of dictionaries, where each dictionary
                                              represents a specific recommendation.
                                              Recommendations can include types like
                                              'volume_reduction' or 'table_optimization',
                                              severity, description, and suggested actions.
                  - 'cost_impact' (dict): An analysis of the current estimated monthly cost
                                          and potential savings from optimizations.
                                          Includes 'current_monthly_cost' and
                                          'projected_savings'.
        """
        try:
            start_time = datetime.utcnow() - timedelta(days=days_lookback)
            end_time = datetime.utcnow()

            # Fetch ingestion data
            ingestion_data = await self._get_ingestion_data(start_time, end_time)
            
            # Analyze patterns
            analysis_results = self._analyze_patterns(ingestion_data)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(analysis_results)

            return {
                'analysis_period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                },
                'total_volume_gb': analysis_results['total_volume'],
                'daily_patterns': analysis_results['daily_patterns'],
                'peak_hours': analysis_results['peak_hours'],
                'recommendations': recommendations,
                'cost_impact': self._calculate_cost_impact(analysis_results)
            }

        except Exception as e:
            self.logger.error(f"Error in ingestion pattern analysis: {str(e)}")
            raise

    async def _get_ingestion_data(self, start_time: datetime, end_time: datetime) -> pd.DataFrame:
        """Fetch ingestion data from Log Analytics workspace."""
        query = """
        union withsource=TableName *
        | where TimeGenerated between(datetime({start}) .. datetime({end}))
        | summarize 
            IngestionVolume=sum(_BilledSize),
            RecordCount=count() 
            by bin(TimeGenerated, 1h), TableName
        """.format(
            start=start_time.isoformat(),
            end=end_time.isoformat()
        )

        response = await self.la_client.query(
            self.workspace_id,
            query
        )

        return pd.DataFrame(response.tables[0].rows, columns=response.tables[0].columns)

    def _analyze_patterns(self, ingestion_data: pd.DataFrame) -> Dict:
        """Analyze ingestion patterns from collected data."""
        analysis = {
            'total_volume': ingestion_data['IngestionVolume'].sum() / 1024**3,  # Convert to GB
            'daily_patterns': {},
            'peak_hours': [],
            'table_distribution': {},
            'anomalies': []
        }

        # Analyze daily patterns
        daily_groups = ingestion_data.groupby(
            pd.Grouper(key='TimeGenerated', freq='D')
        )
        analysis['daily_patterns'] = daily_groups['IngestionVolume'].sum().to_dict()

        # Identify peak hours
        hourly_volumes = ingestion_data.groupby(
            [ingestion_data['TimeGenerated'].dt.hour]
        )['IngestionVolume'].mean()
        analysis['peak_hours'] = hourly_volumes.nlargest(3).index.tolist()

        # Analyze table distribution
        table_volumes = ingestion_data.groupby('TableName')['IngestionVolume'].sum()
        analysis['table_distribution'] = table_volumes.to_dict()

        # Detect anomalies using Z-score
        z_scores = np.abs(stats.zscore(ingestion_data['IngestionVolume']))
        anomaly_mask = z_scores > 3
        analysis['anomalies'] = ingestion_data[anomaly_mask].to_dict('records')

        return analysis

    def _generate_recommendations(self, analysis: Dict) -> List[Dict]:
        """Generate optimization recommendations based on analysis results."""
        recommendations = []

        # Check overall volume against thresholds
        daily_avg = analysis['total_volume'] / len(analysis['daily_patterns'])
        if daily_avg > self.config['ingestion_thresholds']['daily_gb']:
            recommendations.append({
                'type': 'volume_reduction',
                'severity': 'high',
                'description': f'Daily ingestion volume ({daily_avg:.2f} GB) exceeds threshold',
                'suggested_actions': [
                    'Review table distribution for optimization opportunities',
                    'Consider implementing table-specific filters',
                    'Evaluate retention periods for high-volume tables'
                ]
            })

        # Analyze table distribution for optimization opportunities
        table_volumes = pd.Series(analysis['table_distribution'])
        high_volume_tables = table_volumes[
            table_volumes > (table_volumes.mean() + 2 * table_volumes.std())
        ]
        
        for table, volume in high_volume_tables.items():
            recommendations.append({
                'type': 'table_optimization',
                'severity': 'medium',
                'table_name': table,
                'current_volume_gb': volume / 1024**3,
                'suggested_actions': [
                    'Review collection filters',
                    'Implement table-specific retention policy',
                    'Consider moving to cold storage'
                ]
            })

        return recommendations

    def _calculate_cost_impact(self, analysis: Dict) -> Dict:
        """Calculate cost impact of current ingestion patterns."""
        cost_impact = {
            'current_monthly_cost': 0,
            'projected_savings': 0,
            'optimization_opportunities': []
        }

        # Calculate current costs
        total_gb = analysis['total_volume']
        monthly_gb = total_gb * (30 / 7)  # Extrapolate to monthly
        current_cost = monthly_gb * self.config['cost_thresholds']['hot_tier']
        
        # Calculate potential savings
        optimized_cost = self._calculate_optimized_cost(analysis)
        
        cost_impact['current_monthly_cost'] = current_cost
        cost_impact['projected_savings'] = current_cost - optimized_cost
        
        return cost_impact

    def optimize_retention_policies(self, current_policies: Dict) -> Dict:
        """
        Generates optimized retention policies for different data tables based on analysis.

        Args:
            current_policies (Dict): A dictionary where keys are table names (str)
                                     and values are their current retention periods in days (int).
                                     Example: {'SecurityEvent': 90, 'Syslog': 30}

        Returns:
            Dict: A dictionary where keys are table names (str). Each value is a
                  dictionary containing:
                  - 'current_retention' (int): The original retention period in days.
                  - 'recommended_retention' (int): The newly recommended retention period
                                                   in days, based on analysis.
                  - 'storage_tier' (str): The recommended storage tier (e.g., 'Hot',
                                          'Cold') for the table.
                  - 'estimated_savings' (float): Estimated cost savings (currency/month)
                                                 if the recommended retention is applied.
        """
        optimized_policies = {}
        
        for table, current_retention in current_policies.items():
            # Get table statistics
            table_stats = self._get_table_statistics(table)
            
            # Calculate optimal retention period
            optimal_retention = self._calculate_optimal_retention(
                table_stats,
                current_retention
            )
            
            optimized_policies[table] = {
                'current_retention': current_retention,
                'recommended_retention': optimal_retention,
                'storage_tier': self._determine_storage_tier(table_stats),
                'estimated_savings': self._calculate_retention_savings(
                    table_stats,
                    current_retention,
                    optimal_retention
                )
            }
        
        return optimized_policies

    async def generate_report(self, analysis_results: Dict) -> str:
        """
        Asynchronously generates a comprehensive HTML report from analysis results.

        Args:
            analysis_results (Dict): The results dictionary obtained from the
                                     `analyze_ingestion_patterns` method. This dictionary
                                     contains all the data needed to populate the report.

        Returns:
            str: An HTML string representing the generated report. This can be saved
                 to an .html file or displayed in a web browser.
        """
        template = """
        <html>
            <head>
                <title>Sentinel Optimization Report</title>
                <style>
                    /* Add CSS styling here */
                </style>
            </head>
            <body>
                <h1>Sentinel Optimization Report</h1>
                <h2>Analysis Period: {start_date} to {end_date}</h2>
                
                <!-- Add report sections here -->
            </body>
        </html>
        """
        
        # Implementation details for report generation
        return template.format(
            start_date=analysis_results['analysis_period']['start'],
            end_date=analysis_results['analysis_period']['end']
        )

    async def export_results(self, results: Dict, format: str = 'json') -> None:
        """
        Asynchronously exports the provided analysis results to a file.

        The output filename will be automatically generated with a timestamp
        (e.g., sentinel_analysis_YYYYMMDD_HHMMSS.format).

        Args:
            results (Dict): The dictionary containing the data to be exported.
                            Typically, this is the output from methods like
                            `analyze_ingestion_patterns` or `optimize_retention_policies`.
            format (str, optional): The desired output format. Supported formats are
                                    'json' and 'csv'. Defaults to 'json'.

        Raises:
            ValueError: If an unsupported format is specified.
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f'sentinel_analysis_{timestamp}.{format}'
        
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
            elif format == 'csv':
                pd.DataFrame(results).to_csv(filename, index=False)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
            self.logger.info(f"Results exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"Error exporting results: {str(e)}")
            raise