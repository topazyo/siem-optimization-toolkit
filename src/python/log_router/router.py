# src/python/log_router/router.py

from typing import Dict, List, Optional, Union
import asyncio
import aiokafka
from azure.storage.blob.aio import BlobServiceClient
from datetime import datetime
import json
import logging
from dataclasses import dataclass

@dataclass
class LogRoute:
    source: str
    destination: str
    filters: List[Dict]
    transformations: List[Dict]
    retention: int
    priority: int

class LogRouter:
    """
    Advanced log routing and optimization system for Sentinel.
    """

    def __init__(self, config_path: str = 'config/log_router.yaml'):
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
        Route logs based on configured rules.
        
        Args:
            logs (List[Dict]): Logs to route
            
        Returns:
            Dict[str, List[Dict]]: Routed logs by destination
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
        """Export routing metrics."""
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