# src/python/log_router/enhanced_router.py

from typing import Dict, List, Optional, Union, Callable, Any # Added Any
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
    """
    Defines an advanced rule for routing and transforming logs.

    This dataclass encapsulates the logic for a single routing path, including
    its unique name, conditions for matching logs, a series of transformations
    to apply, the target destination, priority for execution order,
    operational status (enabled/disabled), and associated metadata and
    performance metrics.
    """
    name: str  # Unique name for the routing rule (e.g., "PII_Scrubbing_and_Archive").
    conditions: List[Dict]  # A list of conditions that a log must meet to be processed by this rule.
                             # Each dictionary defines a condition, e.g.,
                             # {"field": "UserData.Email", "operator": "exists"}.
    transformations: List[Dict]  # A list of transformation steps to apply to the log.
                                 # Each dictionary defines a transformation, e.g.,
                                 # {"type": "field_mask", "field": "UserData.SSN"}.
    destination: Dict  # Configuration for the destination where the transformed log should be sent.
                       # e.g., {"type": "AzureBlob", "container": "archived-logs"}.
    priority: int  # Numerical priority of the rule. Lower numbers indicate higher priority.
                   # Rules are typically evaluated in ascending order of priority.
    enabled: bool = True  # Flag indicating whether the rule is currently active.
    metadata: Dict = field(default_factory=dict)  # Arbitrary metadata associated with the rule,
                                               # e.g., {"owner": "compliance_team", "version": "1.2"}.
    performance_metrics: Dict = field(default_factory=dict)  # Dictionary to store runtime performance metrics
                                                          # for this specific rule, e.g.,
                                                          # {"processed_logs": 1000, "error_count": 5}.

@dataclass
class TransformationContext:
    """
    Holds data and state during the log transformation process for a single log entry.

    This dataclass is passed through the transformation pipeline for a log,
    allowing different transformation steps to access the original log, the
    log as it's being modified, details of the routing rule being applied,
    and any other relevant metadata accumulated during processing.
    """
    original_log: Dict  # The log entry as it was received, before any transformations.
    transformed_log: Dict  # The log entry as it is being modified by transformation steps.
                           # This field is updated in place by transformers.
    route: RoutingRule  # The `RoutingRule` instance that matched the log and triggered this transformation.
    metadata: Dict = field(default_factory=dict)  # Arbitrary metadata that can be passed between transformation
                                               # steps or used to influence transformation logic.

class EnhancedLogRouter:
    """
    Advanced log routing system with dynamic routing, transformation, and monitoring.
    """

    def __init__(self, config_path: str):
        """
        Initializes the EnhancedLogRouter instance.

        This constructor sets up logging, loads the main configuration from the
        specified YAML file, and then initializes various components of the router
        including rules, transformers, destinations, metrics collection, and caching.

        Args:
            config_path (str): The file system path to the main configuration
                               YAML file for the router. This file defines rules,
                               transformer settings, and destination details.

        Initializes key attributes:
        - `logger` (logging.Logger): A configured logger instance.
        - `config` (Dict): The raw configuration loaded from `config_path`.
        - `rules` (List[RoutingRule]): A list to store `RoutingRule` instances,
                                       parsed and validated from the config.
        - `transformers` (Dict[str, Callable]): A dictionary mapping transformation
                                                types (str) to their implementing
                                                callable functions.
        - `destinations` (Dict[str, Callable]): A dictionary mapping destination
                                                types (str) to functions responsible
                                                for sending logs to those destinations.
        - `metrics` (defaultdict): A nested dictionary for collecting various
                                   runtime metrics about log processing.
        - `cache` (Dict): A generic cache that can be used by various components,
                          for example, by GeoIP enrichment to store recent lookups.
        """
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

    # --- Stubs for initialization helpers ---
    def _load_config(self, config_path: str) -> Dict:
        """Stub for loading router configuration from a YAML file."""
        self.logger.warning("EnhancedLogRouter._load_config is a stub and not yet implemented.")
        return {'rules': []}

    def _load_rules(self):
        """Load and validate routing rules."""
        # Note: This method calls _validate_rule, which is now a stub.
        # The original logic might need adjustment if it relied on _validate_rule's behavior.
        for rule_config in self.config.get('rules', []): # Use .get for safety if config is from stub
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
        Asynchronously routes a list of log entries based on defined rules,
        applying advanced processing like transformations and enrichments.

        This method processes each log concurrently using `asyncio.TaskGroup`.
        For each log, it finds a matching `RoutingRule`, applies the specified
        transformations (e.g., field masking, GeoIP enrichment), enriches the log
        with metadata (like rule name and processing time), and updates
        internal metrics. Finally, it batches the processed logs and sends them
        to their respective destinations.

        Args:
            logs (List[Dict]): A list of dictionaries, where each dictionary
                               represents a single log entry. These logs will be
                               evaluated against the configured routing rules.

        Returns:
            Dict[str, List[Dict]]: A dictionary where keys are destination types
                                   (e.g., "AzureBlob", "KafkaTopic") and values are
                                   lists of processed log dictionaries that have been
                                   routed to that destination type. Logs that fail
                                   processing or do not match any rule may be logged
                                   as errors and not included in the output.
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
                if not await self._apply_condition( # Calls the new stub
                    field_value,
                    condition['operator'],
                    condition['value']
                ):
                    return False
                    
            except Exception as e:
                self.logger.error(f"Condition evaluation error: {str(e)}") # This might not be reached if _apply_condition stub always returns True
                return False

        return True

    def _validate_rule(self, rule: RoutingRule) -> None:
        """Stub for validating a routing rule."""
        self.logger.warning("EnhancedLogRouter._validate_rule is a stub and not yet implemented.")
        pass

    def _setup_destinations(self) -> None:
        """Stub for setting up destination senders."""
        self.logger.warning("EnhancedLogRouter._setup_destinations is a stub and not yet implemented.")
        pass

    def _initialize_monitoring(self) -> None:
        """Stub for initializing monitoring components."""
        self.logger.warning("EnhancedLogRouter._initialize_monitoring is a stub and not yet implemented.")
        pass

    async def _apply_condition(self, field_value: Any, operator: str, condition_value: Any) -> bool:
        """Stub for applying a single condition operator."""
        self.logger.warning("EnhancedLogRouter._apply_condition is a stub and not yet implemented.")
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
            'geoip_enrich': self._transform_geoip_enrich, # Existing, assumed to have a real implementation
            'regex_extract': self._transform_regex_extract # New stub
        }

    # --- Stubs for transformation helpers ---

    async def _transform_field_extract(self, log: Dict, transform: Dict, context: TransformationContext) -> Dict:
        """Stub for extracting a field."""
        self.logger.warning("EnhancedLogRouter._transform_field_extract is a stub and not yet implemented.")
        return log

    async def _transform_field_combine(self, log: Dict, transform: Dict, context: TransformationContext) -> Dict:
        """Stub for combining fields."""
        self.logger.warning("EnhancedLogRouter._transform_field_combine is a stub and not yet implemented.")
        return log

    async def _transform_value_map(self, log: Dict, transform: Dict, context: TransformationContext) -> Dict:
        """Stub for mapping field values."""
        self.logger.warning("EnhancedLogRouter._transform_value_map is a stub and not yet implemented.")
        return log

    async def _transform_timestamp(self, log: Dict, transform: Dict, context: TransformationContext) -> Dict:
        """Stub for converting timestamp formats."""
        self.logger.warning("EnhancedLogRouter._transform_timestamp is a stub and not yet implemented.")
        return log

    async def _transform_regex_extract(self, log: Dict, transform: Dict, context: TransformationContext) -> Dict:
        """Stub for regex extraction."""
        self.logger.warning("EnhancedLogRouter._transform_regex_extract is a stub and not yet implemented.")
        return log

    # --- Existing transformation methods (assuming _transform_field_rename, _transform_field_mask, _transform_geoip_enrich are kept) ---

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
            if part not in current or not isinstance(current[part], dict): # Ensure path exists and is a dict
                current[part] = {}
            current = current[part]
            
        current[parts[-1]] = value

    def _remove_nested_field(self, obj: Dict, path: str) -> None:
        """Stub for removing a nested field from a dictionary."""
        self.logger.warning("EnhancedLogRouter._remove_nested_field is a stub and not yet implemented.")
        # Example tentative logic:
        # parts = path.split('.')
        # current = obj
        # for part in parts[:-1]:
        #     if part not in current or not isinstance(current.get(part), dict):
        #         return # Field does not exist or path is invalid
        #     current = current[part]
        # current.pop(parts[-1], None) # Remove last part if it exists
        pass

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
        """
        Asynchronously generates a detailed report of routing and performance metrics.

        This report provides insights into the router's operation, including
        overall log processing statistics, metrics for each individual rule,
        and system performance indicators.

        Returns:
            Dict: A dictionary containing the metrics report, structured as follows:
                - 'timestamp' (str): ISO format timestamp of when the report was generated.
                - 'overall_metrics' (Dict): Aggregated metrics across all rules and logs,
                  typically including 'total_logs' processed and 'total_bytes' handled,
                  often broken down by time windows (e.g., hourly).
                - 'rule_metrics' (Dict): Metrics specific to each `RoutingRule`, keyed by
                  rule name. Each rule's metrics may include:
                    - 'processed_logs' (int): Number of logs processed by this rule.
                    - 'last_processed' (str): Timestamp of the last log processed.
                    - 'error_count' (int): Number of errors encountered for this rule.
                - 'performance_metrics' (Dict): System-level performance indicators, such as:
                    - 'average_processing_time' (float): Average time taken to process a log.
                    - 'error_rate' (float): Percentage of logs that resulted in an error.
                    - 'destination_latency' (Dict): Metrics related to the latency of
                                                    sending data to different destinations.
        """
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

    # --- Stubs for metric calculation helpers ---

    async def _calculate_avg_processing_time(self) -> float:
        """Stub for calculating average processing time."""
        self.logger.warning("EnhancedLogRouter._calculate_avg_processing_time is a stub and not yet implemented.")
        return 0.0

    async def _calculate_error_rate(self) -> float:
        """Stub for calculating error rate."""
        self.logger.warning("EnhancedLogRouter._calculate_error_rate is a stub and not yet implemented.")
        return 0.0

    async def _get_destination_latency(self) -> Dict:
        """Stub for getting destination latencies."""
        self.logger.warning("EnhancedLogRouter._get_destination_latency is a stub and not yet implemented.")
        return {}