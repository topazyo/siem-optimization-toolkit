# src/python/log_router/enhanced_router.py

from typing import Dict, List, Optional, Union, Callable
from dataclasses import dataclass, field
import asyncio
import aiokafka
from azure.storage.blob.aio import BlobServiceClient
from azure.eventhub.aio import EventHubProducerClient
from datetime import datetime, timedelta
import json
import yaml
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

@dataclass
class RoutingRule:
    name: str
    conditions: List[Dict]
    transformations: List[Dict]
    destination: Dict
    priority: int
    enabled: bool = True
    metadata: Dict = field(default_factory=dict)
    performance_metrics: Dict = field(default_factory=dict)

@dataclass
class TransformationContext:
    original_log: Dict
    transformed_log: Dict
    route: RoutingRule
    metadata: Dict = field(default_factory=dict)

class EnhancedLogRouter:
    """
    Advanced log routing system with dynamic routing, transformation, and monitoring.
    """

    def __init__(self, config_path: str):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.rules: List[RoutingRule] = []
        self.transformers: Dict[str, Callable] = {}
        self.destinations: Dict[str, Callable] = {}
        self.metrics = defaultdict(lambda: defaultdict(int))
        self.cache = {}
        
        self._initialize_system()

    def _initialize_system(self):
        """Initialize router components."""
        self._load_rules()
        self._register_transformers()
        self._setup_destinations()
        self._initialize_monitoring()

    def _load_rules(self):
        """Load and validate routing rules."""
        for rule_config in self.config['rules']:
            try:
                rule = RoutingRule(**rule_config)
                self._validate_rule(rule)
                self.rules.append(rule)
            except Exception as e:
                self.logger.error(f"Failed to load rule {rule_config.get('name')}: {str(e)}")

        # Sort rules by priority
        self.rules.sort(key=lambda x: x.priority)

    async def route_logs(self, logs: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Route logs based on rules with advanced processing.
        
        Args:
            logs (List[Dict]): Logs to route
            
        Returns:
            Dict[str, List[Dict]]: Routed logs by destination
        """
        routed_logs = defaultdict(list)
        processing_tasks = []

        async with asyncio.TaskGroup() as tg:
            for log in logs:
                task = tg.create_task(self._process_log(log))
                processing_tasks.append(task)

        # Process results
        for task in processing_tasks:
            try:
                result = await task
                if result:
                    destination, processed_log = result
                    routed_logs[destination].append(processed_log)
            except Exception as e:
                self.logger.error(f"Log processing error: {str(e)}")

        # Batch send to destinations
        await self._send_to_destinations(routed_logs)
        
        return dict(routed_logs)

    async def _process_log(self, log: Dict) -> Optional[Tuple[str, Dict]]:
        """Process a single log entry."""
        try:
            # Find matching rule
            rule = await self._find_matching_rule(log)
            if not rule:
                return None

            # Create transformation context
            context = TransformationContext(
                original_log=log,
                transformed_log=log.copy(),
                route=rule
            )

            # Apply transformations
            transformed_log = await self._apply_transformations(context)
            
            # Enrich with metadata
            transformed_log = await self._enrich_log(transformed_log, rule)
            
            # Update metrics
            await self._update_metrics(rule, transformed_log)
            
            return (rule.destination['type'], transformed_log)

        except Exception as e:
            self.logger.error(f"Log processing error: {str(e)}")
            return None

    async def _find_matching_rule(self, log: Dict) -> Optional[RoutingRule]:
        """Find the first matching rule for a log entry."""
        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                if await self._evaluate_conditions(log, rule.conditions):
                    return rule
            except Exception as e:
                self.logger.error(f"Rule evaluation error {rule.name}: {str(e)}")
                continue

        return None

    async def _evaluate_conditions(self, log: Dict, conditions: List[Dict]) -> bool:
        """Evaluate rule conditions against a log entry."""
        for condition in conditions:
            try:
                # Get field value using dot notation
                field_value = self._get_nested_value(log, condition['field'])
                
                # Apply condition
                if not await self._apply_condition(
                    field_value,
                    condition['operator'],
                    condition['value']
                ):
                    return False
                    
            except Exception as e:
                self.logger.error(f"Condition evaluation error: {str(e)}")
                return False

        return True

    async def _apply_transformations(self, context: TransformationContext) -> Dict:
        """Apply transformations to log data with context."""
        for transform in context.route.transformations:
            try:
                transformer = self.transformers.get(transform['type'])
                if transformer:
                    context.transformed_log = await transformer(
                        context.transformed_log,
                        transform,
                        context
                    )
            except Exception as e:
                self.logger.error(f"Transformation error: {str(e)}")
                continue

        return context.transformed_log

    async def _send_to_destinations(self, routed_logs: Dict[str, List[Dict]]):
        """Send logs to their destinations with batching and retry logic."""
        async with asyncio.TaskGroup() as tg:
            for destination, logs in routed_logs.items():
                sender = self.destinations.get(destination)
                if sender:
                    tg.create_task(self._send_with_retry(sender, logs))

    async def _send_with_retry(
        self,
        sender: Callable,
        logs: List[Dict],
        max_retries: int = 3,
        backoff_factor: float = 1.5
    ):
        """Send logs with exponential backoff retry."""
        retry_count = 0
        while retry_count < max_retries:
            try:
                await sender(logs)
                break
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    self.logger.error(f"Failed to send logs after {max_retries} retries: {str(e)}")
                    break
                    
                wait_time = backoff_factor ** retry_count
                await asyncio.sleep(wait_time)

    async def _enrich_log(self, log: Dict, rule: RoutingRule) -> Dict:
        """Enrich log with additional context and metadata."""
        enriched_log = log.copy()
        
        # Add routing metadata
        enriched_log['_metadata'] = {
            'route_name': rule.name,
            'routing_time': datetime.utcnow().isoformat(),
            'transformations_applied': [t['type'] for t in rule.transformations]
        }

        # Add compliance metadata if configured
        if 'compliance' in rule.metadata:
            enriched_log['_metadata']['compliance'] = rule.metadata['compliance']

        # Add data classification
        if 'classification' in rule.metadata:
            enriched_log['_metadata']['classification'] = rule.metadata['classification']

        return enriched_log

    def _register_transformers(self):
        """Register available transformation functions."""
        self.transformers = {
            'field_rename': self._transform_field_rename,
            'field_mask': self._transform_field_mask,
            'field_extract': self._transform_field_extract,
            'field_combine': self._transform_field_combine,
            'value_map': self._transform_value_map,
            'timestamp_convert': self._transform_timestamp,
            'geoip_enrich': self._transform_geoip_enrich,
            'regex_extract': self._transform_regex_extract
        }

    async def _transform_field_rename(
        self,
        log: Dict,
        transform: Dict,
        context: TransformationContext
    ) -> Dict:
        """Rename fields in the log entry."""
        result = log.copy()
        old_field = transform['old_field']
        new_field = transform['new_field']
        
        if '.' in old_field:
            # Handle nested fields
            value = self._get_nested_value(result, old_field)
            if value is not None:
                self._set_nested_value(result, new_field, value)
                self._remove_nested_field(result, old_field)
        else:
            # Handle top-level fields
            if old_field in result:
                result[new_field] = result.pop(old_field)
                
        return result

    async def _transform_field_mask(
        self,
        log: Dict,
        transform: Dict,
        context: TransformationContext
    ) -> Dict:
        """Mask sensitive fields."""
        result = log.copy()
        field = transform['field']
        mask_char = transform.get('mask_char', '*')
        pattern = transform.get('pattern', None)
        
        value = self._get_nested_value(result, field)
        if value is not None:
            if pattern:
                # Apply pattern-based masking
                masked_value = re.sub(pattern, mask_char * len(value), str(value))
            else:
                # Apply full masking
                masked_value = mask_char * len(str(value))
                
            self._set_nested_value(result, field, masked_value)
            
        return result

    async def _transform_geoip_enrich(
        self,
        log: Dict,
        transform: Dict,
        context: TransformationContext
    ) -> Dict:
        """Enrich log with GeoIP information."""
        result = log.copy()
        ip_field = transform['ip_field']
        
        ip_address = self._get_nested_value(result, ip_field)
        if ip_address:
            try:
                # Use cache if available
                if ip_address in self.cache:
                    geo_data = self.cache[ip_address]
                else:
                    geo_data = await self._lookup_geoip(ip_address)
                    self.cache[ip_address] = geo_data

                result['_geo'] = geo_data
                
            except Exception as e:
                self.logger.error(f"GeoIP enrichment error: {str(e)}")
                
        return result

    async def _lookup_geoip(self, ip_address: str) -> Dict:
        """Perform GeoIP lookup."""
        # Implementation would depend on your GeoIP database/service
        pass

    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        parts = path.split('.')
        current = obj
        
        for part in parts:
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return None
            else:
                return None
                
        return current

    def _set_nested_value(self, obj: Dict, path: str, value: Any):
        """Set value in nested dictionary using dot notation."""
        parts = path.split('.')
        current = obj
        
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
            
        current[parts[-1]] = value

    async def _update_metrics(self, rule: RoutingRule, log: Dict):
        """Update routing metrics."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d-%H')
        
        self.metrics[timestamp]['total_logs'] += 1
        self.metrics[timestamp]['total_bytes'] += len(json.dumps(log))
        self.metrics[timestamp][f'rule_{rule.name}_matches'] += 1
        
        # Update rule performance metrics
        rule.performance_metrics['processed_logs'] = \
            rule.performance_metrics.get('processed_logs', 0) + 1
        rule.performance_metrics['last_processed'] = datetime.utcnow().isoformat()

    async def generate_metrics_report(self) -> Dict:
        """Generate detailed metrics report."""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_metrics': dict(self.metrics),
            'rule_metrics': {},
            'performance_metrics': {
                'average_processing_time': await self._calculate_avg_processing_time(),
                'error_rate': await self._calculate_error_rate(),
                'destination_latency': await self._get_destination_latency()
            }
        }

        # Add rule-specific metrics
        for rule in self.rules:
            report['rule_metrics'][rule.name] = {
                'processed_logs': rule.performance_metrics.get('processed_logs', 0),
                'last_processed': rule.performance_metrics.get('last_processed'),
                'error_count': rule.performance_metrics.get('error_count', 0)
            }

        return report