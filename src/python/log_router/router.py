# src/python/log_router/router.py

from typing import Dict, List, Optional, Union
import asyncio
import aiokafka
from azure.storage.blob.aio import BlobServiceClient
from datetime import datetime
import json
import logging
from dataclasses import dataclass
import yaml # Added import

@dataclass
class LogRoute:
    """
    Defines a specific rule for routing logs from a source to a destination.

    This dataclass encapsulates all the criteria and actions for a single
    log routing path, including where the logs come from, where they go,
    conditions they must meet (filters), modifications to apply
    (transformations), how long they should be kept, and the rule's priority.
    """
    source: str  # Identifier for the source of the logs (e.g., "FirewallEvents", "SyslogStream").
    destination: str  # Identifier for the target system or storage (e.g., "AzureBlobStorage", "Splunk").
    filters: List[Dict]  # A list of filter conditions. Each dictionary defines a filter,
                         # e.g., {"field": "EventID", "operator": "equals", "value": 4625}.
                         # Logs must pass all filters to be routed by this rule.
    transformations: List[Dict]  # A list of transformations to apply to the log before sending to the destination.
                                 # e.g., {"type": "rename_field", "old_name": "src_ip", "new_name": "SourceIpAddress"}.
    retention: int  # Retention period in days for logs sent via this route to the destination.
    priority: int  # A numerical priority for the rule. Lower numbers typically indicate higher priority.
                   # Used to resolve conflicts if a log matches multiple routes.

class LogRouter:
    """
    Advanced log routing and optimization system for Sentinel.
    """

    def __init__(self, config_path: str = 'config/log_router.yaml'):
        """
        Initializes the LogRouter instance.

        This involves setting up logging, loading the router configuration from a YAML file,
        initializing routes based on the configuration, and preparing a dictionary to store
        routing metrics.

        Args:
            config_path (str, optional): The file system path to the router's
                                        configuration YAML file.
                                        Defaults to 'config/log_router.yaml'.

        Initializes key attributes:
        - `logger` (logging.Logger): A configured logger instance.
        - `config` (Dict): The raw configuration loaded from the YAML file.
        - `routes` (Dict[str, LogRoute]): A dictionary storing `LogRoute` objects,
                                          typically keyed by source or a unique route ID,
                                          parsed from the `config`.
        - `metrics` (Dict): A dictionary to store runtime metrics about log routing,
                            such as counts and volumes per destination.
        """
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.routes: Dict[str, LogRoute] = {}
        self.metrics = {}
        self._initialize_routes()

    def _load_config(self, config_path: str) -> Dict:
        """Load router configuration."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            raise

    def _initialize_routes(self) -> None:
        """Initialize log routing rules."""
        for route_config in self.config['routes']:
            route = LogRoute(**route_config)
            self.routes[route.source] = route

    async def route_logs(self, logs: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Asynchronously routes a list of log entries based on configured rules.

        For each log entry, the method attempts to find a matching route by
        evaluating filters. If a route is found, specified transformations are
        applied to the log. The log is then added to a list associated with its
        determined destination. Routing metrics (e.g., log count, volume) are
        updated for each successfully routed log.

        Args:
            logs (List[Dict]): A list of dictionaries, where each dictionary
                               represents a single log entry. Each log entry should
                               contain fields that can be used by the routing rules'
                               filters and transformations (e.g., a 'source' field
                               to match against `LogRoute.source`).

        Returns:
            Dict[str, List[Dict]]: A dictionary where keys are destination names (str)
                                   and values are lists of log dictionaries (List[Dict])
                                   that have been routed to that destination. Logs that
                                   do not match any route or fail during processing may be
                                   omitted or logged as errors.
        """
        routed_logs = {}
        
        for log in logs:
            try:
                destination = await self._determine_route(log)
                if destination:
                    if destination not in routed_logs:
                        routed_logs[destination] = []
                    
                    # Apply transformations
                    transformed_log = await self._apply_transformations(
                        log,
                        self.routes[log['source']].transformations
                    )
                    
                    routed_logs[destination].append(transformed_log)
                    
                    # Update metrics
                    await self._update_metrics(log, destination)
                    
            except Exception as e:
                self.logger.error(f"Error routing log: {str(e)}")
                continue

        return routed_logs

    async def _determine_route(self, log: Dict) -> Optional[str]:
        """Determine appropriate route for a log."""
        source = log.get('source')
        if source not in self.routes:
            return None

        route = self.routes[source]
        
        # Check filters
        if await self._apply_filters(log, route.filters):
            return route.destination

        return None

    async def _apply_filters(self, log: Dict, filters: List[Dict]) -> bool:
        """Apply filters to determine if log should be routed."""
        for filter_rule in filters:
            try:
                field = filter_rule['field']
                operator = filter_rule['operator']
                value = filter_rule['value']

                if not await self._evaluate_filter(log, field, operator, value):
                    return False
                    
            except Exception as e:
                self.logger.error(f"Filter evaluation error: {str(e)}")
                return False

        return True

    async def _apply_transformations(
        self,
        log: Dict,
        transformations: List[Dict]
    ) -> Dict:
        """Apply transformations to log data."""
        transformed_log = log.copy()
        
        for transform in transformations:
            try:
                if transform['type'] == 'rename_field':
                    transformed_log = await self._rename_field(
                        transformed_log,
                        transform['old_name'],
                        transform['new_name']
                    )
                elif transform['type'] == 'add_field':
                    transformed_log = await self._add_field(
                        transformed_log,
                        transform['field'],
                        transform['value']
                    )
                elif transform['type'] == 'remove_field':
                    transformed_log = await self._remove_field(
                        transformed_log,
                        transform['field']
                    )
                    
            except Exception as e:
                self.logger.error(f"Transformation error: {str(e)}")
                continue

        return transformed_log

    # --- Stubs for private methods ---

    async def _evaluate_filter(self, log: Dict, field: str, operator: str, value: Any) -> bool:
        """Stub for evaluating a single filter condition against a log entry."""
        self.logger.warning("LogRouter._evaluate_filter is a stub and not yet implemented.")
        return True # Assume filter passes for now

    async def _rename_field(self, log: Dict, old_name: str, new_name: str) -> Dict:
        """Stub for renaming a field in a log entry."""
        self.logger.warning("LogRouter._rename_field is a stub and not yet implemented.")
        return log # Return original log

    async def _add_field(self, log: Dict, field: str, value: Any) -> Dict:
        """Stub for adding a new field to a log entry."""
        self.logger.warning("LogRouter._add_field is a stub and not yet implemented.")
        return log # Return original log

    async def _remove_field(self, log: Dict, field: str) -> Dict:
        """Stub for removing a field from a log entry."""
        self.logger.warning("LogRouter._remove_field is a stub and not yet implemented.")
        return log # Return original log

    async def _update_metrics(self, log: Dict, destination: str) -> None:
        """Update routing metrics."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d-%H')
        
        if timestamp not in self.metrics:
            self.metrics[timestamp] = {}
            
        if destination not in self.metrics[timestamp]:
            self.metrics[timestamp][destination] = {
                'count': 0,
                'volume': 0,
                'sources': set()
            }
            
        self.metrics[timestamp][destination]['count'] += 1
        self.metrics[timestamp][destination]['volume'] += len(str(log))
        self.metrics[timestamp][destination]['sources'].add(log.get('source'))

    async def export_metrics(self) -> None:
        """
        Asynchronously exports collected routing metrics to a JSON file.

        The metrics, stored in the `self.metrics` attribute, are serialized to JSON.
        This typically includes counts of logs, data volumes, and unique sources
        per destination, aggregated over time windows. The output file is named
        with a timestamp to ensure uniqueness and is placed in the 'metrics/' directory.
        Sets within the metrics (like 'sources') are converted to lists for JSON compatibility.

        The file will be named `metrics/routing_metrics_YYYYMMDD_HHMMSS.json`.
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        metrics_file = f'metrics/routing_metrics_{timestamp}.json'
        
        try:
            # Convert sets to lists for JSON serialization
            serializable_metrics = {}
            for ts, destinations in self.metrics.items():
                serializable_metrics[ts] = {}
                for dest, metrics in destinations.items():
                    serializable_metrics[ts][dest] = {
                        **metrics,
                        'sources': list(metrics['sources'])
                    }
            
            with open(metrics_file, 'w') as f:
                json.dump(serializable_metrics, f, indent=2)
                
            self.logger.info(f"Metrics exported to {metrics_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {str(e)}")