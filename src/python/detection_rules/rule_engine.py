# src/python/detection_rules/rule_engine.py

from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import yaml
import json
from datetime import datetime, timedelta
import logging
import asyncio
from abc import ABC, abstractmethod
from pathlib import Path # Added import

@dataclass
class DetectionRule:
    """
    Defines the structure and metadata for a security detection rule.

    This dataclass encapsulates all necessary information to define, manage,
    and execute a detection rule within the system. It includes identifiers,
    descriptive information, MITRE ATT&CK mappings, the actual detection logic (query),
    and operational metadata.
    """
    id: str  # Unique identifier for the rule (e.g., "RULE-001").
    name: str  # Human-readable name of the rule (e.g., "Suspicious Logon Activity").
    description: str  # Detailed explanation of what the rule detects and why it's important.
    risk_level: str  # Severity of the detected event (e.g., "Low", "Medium", "High", "Critical").
    tactics: List[str]  # MITRE ATT&CK tactic(s) associated with the rule (e.g., ["TA0002"]).
    techniques: List[str]  # MITRE ATT&CK technique(s) associated with the rule (e.g., ["T1078"]).
    query: str  # The actual query (e.g., KQL) used to detect the threat or event.
    parameters: Dict  # Key-value pairs for parameters that can be substituted into the query (e.g., {"threshold": 5}).
    enabled: bool  # Flag indicating whether the rule is currently active and should be evaluated.
    last_modified: datetime  # Timestamp of when the rule was last modified.
    author: str  # Name or identifier of the person who created or last modified the rule.
    validation_rules: Dict  # Specific criteria or conditions to validate the rule's logic or parameters.

@dataclass
class RuleResult:
    """
    Represents the outcome of a single detection rule's evaluation.

    This dataclass stores all relevant information generated when a detection rule
    is executed, including whether it found matches, the severity and confidence
    of the detection, contextual information, and performance metrics of the evaluation.
    """
    rule_id: str  # The unique identifier of the rule that was evaluated.
    timestamp: datetime  # Timestamp of when the rule evaluation occurred.
    matches: List[Dict]  # A list of dictionaries, where each dictionary represents a match found by the rule.
                         # The structure of these dictionaries depends on the rule's query.
    severity: str  # The determined severity of the detection (e.g., "High"), potentially derived from the rule's risk_level or match data.
    confidence: float  # A score (e.g., 0.0 to 1.0) indicating the confidence in the detection's accuracy.
    context: Dict  # Additional contextual information relevant to the evaluation (e.g., data sources queried, time range).
    performance_metrics: Dict  # Metrics related to the rule's execution, such as 'execution_time' (seconds),
                               # 'matches_found' (count), and 'data_scanned' (e.g., GB).

class BaseDetectionRule(ABC):
    """Abstract base class for detection rules."""
    
    @abstractmethod
    async def evaluate(self, context: Dict) -> RuleResult:
        """Evaluate the rule against provided context."""
        pass

    @abstractmethod
    def validate(self) -> bool:
        """Validate rule configuration."""
        pass

class CustomDetectionRule(BaseDetectionRule):
    """Custom detection rule implementation."""

    def __init__(self, rule_config: Dict):
        """
        Initializes a CustomDetectionRule instance.

        Args:
            rule_config (Dict): A dictionary containing the configuration for this rule.
                                This dictionary is expected to have keys and value types
                                that match the fields of the `DetectionRule` dataclass.
                                For example:
                                {
                                    "id": "RULE-001",
                                    "name": "Suspicious Logon",
                                    "description": "Detects multiple failed logons.",
                                    "risk_level": "Medium",
                                    "tactics": ["TA0002"],
                                    "techniques": ["T1078"],
                                    "query": "SecurityEvent | where EventID == 4625",
                                    "parameters": {"threshold": 3},
                                    "enabled": True,
                                    "last_modified": "2023-01-01T12:00:00Z", # Will be parsed to datetime
                                    "author": "AnalystX",
                                    "validation_rules": {}
                                }

        Initializes key attributes:
        - `config` (DetectionRule): An instance of the `DetectionRule` dataclass,
                                    populated from the `rule_config` dictionary.
        - `logger` (logging.Logger): A configured logger instance for logging messages
                                     specific to this rule instance.
        """
        self.config = DetectionRule(**rule_config)
        self.logger = logging.getLogger(__name__)

    async def evaluate(self, context: Dict) -> RuleResult:
        """
        Asynchronously evaluates the detection rule against the provided context.

        This method prepares the rule's query using parameters from the context,
        executes the query against the relevant data source (implicitly handled
        by `_execute_query`), analyzes the results to determine severity and
        confidence, and calculates performance metrics for the evaluation.

        Args:
            context (Dict): A dictionary providing the data and environmental
                            parameters necessary for the rule's evaluation.
                            This may include things like time ranges, specific
                            entity IDs, or data volume information for metrics.
                            Example: {"time_range": "24h", "data_volume": 1024}

        Returns:
            RuleResult: An instance of the `RuleResult` dataclass containing the
                        outcome of the evaluation, including any matches found,
                        determined severity, confidence score, and performance data.

        Raises:
            Exception: Propagates exceptions that occur during query preparation,
                       execution, or result analysis.
        """
        try:
            start_time = datetime.utcnow()
            
            # Prepare query with parameters
            query = self._prepare_query(context)
            
            # Execute query
            matches = await self._execute_query(query)
            
            # Analyze results
            severity = self._determine_severity(matches)
            confidence = self._calculate_confidence(matches)
            
            # Calculate performance metrics
            performance_metrics = {
                'execution_time': (datetime.utcnow() - start_time).total_seconds(),
                'matches_found': len(matches),
                'data_scanned': context.get('data_volume', 0)
            }

            return RuleResult(
                rule_id=self.config.id,
                timestamp=datetime.utcnow(),
                matches=matches,
                severity=severity,
                confidence=confidence,
                context=context,
                performance_metrics=performance_metrics
            )

        except Exception as e:
            self.logger.error(f"Rule evaluation error: {str(e)}")
            raise

    def validate(self) -> bool:
        """
        Validates the configuration of this detection rule.

        This method checks various aspects of the rule's configuration as defined
        in its `self.config` (a `DetectionRule` instance). This typically includes:
        - Syntax validation of the rule's query.
        - Validation of parameter definitions and their usage.
        - Ensuring that MITRE ATT&CK tactics and techniques mappings are valid.

        Returns:
            bool: True if the rule configuration is valid, False otherwise.
                  Errors encountered during validation are logged.
        """
        try:
            # Validate query syntax
            if not self._validate_query_syntax(self.config.query):
                return False

            # Validate parameters
            if not self._validate_parameters(self.config.parameters):
                return False

            # Validate tactics and techniques
            if not self._validate_attack_mappings(
                self.config.tactics,
                self.config.techniques
            ):
                return False

            return True

        except Exception as e:
            self.logger.error(f"Rule validation error: {str(e)}")
            return False

    # --- Stubs for private methods ---

    def _prepare_query(self, context: Dict) -> str:
        """
        Prepares the KQL query by substituting placeholders with values from
        the rule's parameters or the provided context.

        Placeholders in the query string should be in the format `{key}`.
        It first tries to fill placeholders from `self.config.parameters`.
        Then, it attempts to fill any remaining placeholders from the `context` dict.
        """
        prepared_query = self.config.query

        # Substitute from rule's own parameters first
        if self.config.parameters:
            for key, value in self.config.parameters.items():
                placeholder = f"{{{key}}}"
                prepared_query = prepared_query.replace(placeholder, str(value))

        # Substitute from context parameters (context can override rule params if names clash, or fill others)
        # For more specific control, could differentiate context params (e.g. context_param.X)
        if context:
            for key, value in context.items():
                placeholder = f"{{{key}}}"
                # This simple replace might not be ideal if context has many keys not in query
                # A more targeted approach would be to only replace known placeholders.
                if placeholder in prepared_query: # Only replace if placeholder exists
                    prepared_query = prepared_query.replace(placeholder, str(value))

        self.logger.info(f"CustomDetectionRule._prepare_query: Prepared query: {prepared_query}")
        return prepared_query

    async def _execute_query(self, query: str) -> List[Dict]:
        """
        Simulates KQL query execution. Returns mock data if the query
        contains a specific pattern, otherwise returns an empty list.
        """
        self.logger.info(f"CustomDetectionRule._execute_query: Simulating execution for query: {query}")

        # Define a magic string that, if present in the query, triggers mock results
        magic_trigger_string = 'User == "test_user_suspicious_activity_trigger"'

        if magic_trigger_string in query:
            self.logger.info(f"CustomDetectionRule._execute_query: Magic trigger '{magic_trigger_string}' found. Returning mock matches.")
            return [
                {
                    "TimeGenerated": datetime.utcnow().isoformat(),
                    "Activity": "Suspicious login attempt",
                    "Details": "Triggered by mock pattern in _execute_query",
                    "User": "test_user_suspicious_activity_trigger" # Ensure the field is present
                },
                {
                    "TimeGenerated": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                    "Activity": "Anomalous file access",
                    "Details": "Further details for mock pattern.",
                    "User": "test_user_suspicious_activity_trigger"
                }
            ]
        else:
            self.logger.info("CustomDetectionRule._execute_query: No magic trigger found. Returning empty list for matches.")
            return []

    def _determine_severity(self, matches: List[Dict]) -> str:
        """Stub for determining the severity of rule matches."""
        self.logger.warning("CustomDetectionRule._determine_severity is a stub and not yet implemented.")
        return "Medium"

    def _calculate_confidence(self, matches: List[Dict]) -> float:
        """Stub for calculating the confidence of rule matches."""
        self.logger.warning("CustomDetectionRule._calculate_confidence is a stub and not yet implemented.")
        return 0.5

    def _validate_query_syntax(self, query: str) -> bool:
        """Stub for validating KQL query syntax."""
        self.logger.warning("CustomDetectionRule._validate_query_syntax is a stub and not yet implemented.")
        return True

    def _validate_parameters(self, parameters: Dict) -> bool:
        """Stub for validating rule parameters."""
        self.logger.warning("CustomDetectionRule._validate_parameters is a stub and not yet implemented.")
        return True

    def _validate_attack_mappings(self, tactics: List[str], techniques: List[str]) -> bool:
        """Stub for validating ATT&CK tactics and techniques."""
        self.logger.warning("CustomDetectionRule._validate_attack_mappings is a stub and not yet implemented.")
        return True

class RuleEngine:
    """Detection rule engine for Sentinel."""

    def __init__(self, rules_path: str = 'config/detection_rules'):
        """
        Initializes the RuleEngine instance.

        This involves setting up the path to rule definition files, preparing
        a dictionary to store loaded rules, and initializing a logger.
        It also triggers the initial loading of rules from the specified path.

        Args:
            rules_path (str, optional): The file system path to the directory
                                        containing detection rule YAML files.
                                        Defaults to 'config/detection_rules'.

        Initializes key attributes:
        - `rules_path` (str): Stores the path to the rule configuration files.
        - `rules` (Dict[str, CustomDetectionRule]): A dictionary that will store
          loaded and validated `CustomDetectionRule` instances, keyed by their rule ID.
        - `logger` (logging.Logger): A configured logger instance for logging messages
                                     related to the rule engine's operations.
        """
        self.rules_path = rules_path
        self.rules: Dict[str, CustomDetectionRule] = {}
        self.logger = logging.getLogger(__name__)
        self._load_rules()

    def _load_rules(self) -> None:
        """Load detection rules from configuration."""
        try:
            rules_dir = Path(self.rules_path)
            for rule_file in rules_dir.glob('*.yaml'):
                with open(rule_file, 'r') as f:
                    rule_config = yaml.safe_load(f)
                    rule = CustomDetectionRule(rule_config)
                    if rule.validate():
                        self.rules[rule.config.id] = rule
                    else:
                        self.logger.warning(
                            f"Rule validation failed: {rule_file.name}"
                        )

        except Exception as e:
            self.logger.error(f"Error loading rules: {str(e)}")
            raise

    async def evaluate_rules(
        self,
        context: Dict,
        rule_ids: Optional[List[str]] = None
    ) -> Dict[str, RuleResult]:
        """
        Asynchronously evaluates a specified set of rules or all loaded rules.

        For each rule to be evaluated, this method calls its `evaluate` method
        with the provided context. Results are collected into a dictionary.

        Args:
            context (Dict): A dictionary providing the data and environmental
                            parameters for rule evaluation. This is passed to each
                            rule's `evaluate` method.
            rule_ids (Optional[List[str]], optional): A list of rule IDs to evaluate.
                                                      If None or empty, all enabled rules
                                                      loaded by the engine are evaluated.
                                                      Defaults to None.

        Returns:
            Dict[str, RuleResult]: A dictionary where keys are rule IDs (str) and
                                   values are the corresponding `RuleResult` objects
                                   from their evaluation. If a rule fails evaluation,
                                   it might be omitted from the results or include an error indicator,
                                   depending on error handling within `rule.evaluate`.
        """
        results = {}
        rules_to_evaluate = (
            {rid: self.rules[rid] for rid in rule_ids}
            if rule_ids
            else self.rules
        )

        for rule_id, rule in rules_to_evaluate.items():
            try:
                results[rule_id] = await rule.evaluate(context)
            except Exception as e:
                self.logger.error(f"Rule evaluation error {rule_id}: {str(e)}")
                continue

        return results

    async def add_rule(self, rule_config: Dict) -> bool:
        """
        Asynchronously adds a new detection rule to the engine.

        The provided `rule_config` dictionary is used to instantiate a
        `CustomDetectionRule`. The new rule is then validated. If valid,
        it's added to the engine's active rules and its configuration is
        saved to a YAML file in the `rules_path` directory.

        Args:
            rule_config (Dict): A dictionary containing the configuration for the new rule.
                                This dictionary should conform to the structure expected by
                                `CustomDetectionRule.__init__` (and `DetectionRule` dataclass).

        Returns:
            bool: True if the rule was successfully added (i.e., it's valid and saved),
                  False otherwise (e.g., validation failed, error during saving).
        """
        try:
            rule = CustomDetectionRule(rule_config)
            if rule.validate():
                self.rules[rule.config.id] = rule
                await self._save_rule(rule_config)
                return True
            return False

        except Exception as e:
            self.logger.error(f"Error adding rule: {str(e)}")
            return False

    async def update_rule(self, rule_id: str, updates: Dict) -> bool:
        """
        Asynchronously updates an existing detection rule.

        The rule specified by `rule_id` has its configuration updated with the
        key-value pairs from the `updates` dictionary. The modified rule is then
        validated. If valid, the engine's instance of the rule is replaced,
        and the updated configuration is saved to its YAML file.

        Args:
            rule_id (str): The unique identifier of the rule to be updated.
            updates (Dict): A dictionary containing the configuration fields to update
                            and their new values. For example, `{"enabled": False, "risk_level": "High"}`.

        Returns:
            bool: True if the rule was successfully updated (i.e., it's valid and saved),
                  False otherwise (e.g., rule not found, validation failed, error during saving).

        Raises:
            ValueError: If a rule with the given `rule_id` is not found.
        """
        try:
            if rule_id not in self.rules:
                raise ValueError(f"Rule not found: {rule_id}")

            current_config = self.rules[rule_id].config
            updated_config = {**current_config.__dict__, **updates}
            
            rule = CustomDetectionRule(updated_config)
            if rule.validate():
                self.rules[rule_id] = rule
                await self._save_rule(updated_config)
                return True
            return False

        except Exception as e:
            self.logger.error(f"Error updating rule: {str(e)}")
            return False

    async def _save_rule(self, rule_config: Dict) -> None:
        """Save rule configuration to file."""
        rule_path = Path(self.rules_path) / f"{rule_config['id']}.yaml"
        try:
            with open(rule_path, 'w') as f:
                yaml.dump(rule_config, f)
        except Exception as e:
            self.logger.error(f"Error saving rule: {str(e)}")
            raise