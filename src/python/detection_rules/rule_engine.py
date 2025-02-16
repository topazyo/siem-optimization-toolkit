# src/python/detection_rules/rule_engine.py

from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import yaml
import json
from datetime import datetime, timedelta
import logging
import asyncio
from abc import ABC, abstractmethod

@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    risk_level: str
    tactics: List[str]
    techniques: List[str]
    query: str
    parameters: Dict
    enabled: bool
    last_modified: datetime
    author: str
    validation_rules: Dict

@dataclass
class RuleResult:
    rule_id: str
    timestamp: datetime
    matches: List[Dict]
    severity: str
    confidence: float
    context: Dict
    performance_metrics: Dict

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
        self.config = DetectionRule(**rule_config)
        self.logger = logging.getLogger(__name__)

    async def evaluate(self, context: Dict) -> RuleResult:
        """Evaluate the detection rule."""
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
        """Validate rule configuration."""
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

class RuleEngine:
    """Detection rule engine for Sentinel."""

    def __init__(self, rules_path: str = 'config/detection_rules'):
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
        Evaluate specified or all rules.
        
        Args:
            context (Dict): Evaluation context
            rule_ids (Optional[List[str]]): Specific rules to evaluate
            
        Returns:
            Dict[str, RuleResult]: Evaluation results by rule ID
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
        """Add a new detection rule."""
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
        """Update an existing detection rule."""
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