# src/kql/testing/query_validator.py

from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import re
import json
import logging
from datetime import datetime, timedelta

@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    performance_impact: str
    suggestions: List[str]

class KQLQueryValidator:
    """
    Advanced KQL query validation and testing system.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.validation_rules = self._load_validation_rules()

    def _load_validation_rules(self) -> Dict:
        """Load query validation rules."""
        return {
            'syntax': {
                'required_elements': [
                    'TimeGenerated',
                    'where'
                ],
                'prohibited_patterns': [
                    r'project\s+\*',
                    r'where\s+1\s*==\s*1',
                    r'where\s+true'
                ],
                'recommended_patterns': [
                    r'where TimeGenerated > ago\(\d+[dhm]\)',
                    r'summarize.+by bin\(TimeGenerated,',
                    r'project-away\b'
                ]
            },
            'performance': {
                'join_conditions': [
                    r'join.+kind=',
                    r'lookup.+kind='
                ],
                'materialization': [
                    r'let\s+\w+\s*=\s*materialize',
                    r'summarize.+by bin'
                ],
                'filtering': [
                    r'where.+contains',
                    r'where.+startswith'
                ]
            },
            'security': {
                'required_fields': [
                    'Account',
                    'Computer',
                    'IpAddress'
                ],
                'sensitive_patterns': [
                    r'password',
                    r'secret',
                    r'token'
                ]
            }
        }

    async def validate_query(self, query: str) -> ValidationResult:
        """
        Validate KQL query against all rules.
        
        Args:
            query (str): KQL query to validate
            
        Returns:
            ValidationResult: Validation results and suggestions
        """
        errors = []
        warnings = []
        suggestions = []

        # Syntax validation
        syntax_result = self._validate_syntax(query)
        errors.extend(syntax_result['errors'])
        warnings.extend(syntax_result['warnings'])
        suggestions.extend(syntax_result['suggestions'])

        # Performance validation
        perf_result = self._validate_performance(query)
        errors.extend(perf_result['errors'])
        warnings.extend(perf_result['warnings'])
        suggestions.extend(perf_result['suggestions'])

        # Security validation
        security_result = self._validate_security(query)
        errors.extend(security_result['errors'])
        warnings.extend(security_result['warnings'])
        suggestions.extend(security_result['suggestions'])

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            performance_impact=self._assess_performance_impact(query),
            suggestions=suggestions
        )

    def _validate_syntax(self, query: str) -> Dict:
        """Validate query syntax."""
        result = {
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # Check required elements
        for element in self.validation_rules['syntax']['required_elements']:
            if element not in query:
                result['errors'].append(
                    f"Missing required element: {element}"
                )

        # Check prohibited patterns
        for pattern in self.validation_rules['syntax']['prohibited_patterns']:
            if re.search(pattern, query, re.IGNORECASE):
                result['errors'].append(
                    f"Found prohibited pattern: {pattern}"
                )

        # Check recommended patterns
        for pattern in self.validation_rules['syntax']['recommended_patterns']:
            if not re.search(pattern, query, re.IGNORECASE):
                result['suggestions'].append(
                    f"Consider adding recommended pattern: {pattern}"
                )

        return result

    def _validate_performance(self, query: str) -> Dict:
        """Validate query performance aspects."""
        result = {
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # Check join conditions
        for pattern in self.validation_rules['performance']['join_conditions']:
            if re.search(r'join', query, re.IGNORECASE):
                if not re.search(pattern, query, re.IGNORECASE):
                    result['warnings'].append(
                        f"Join operation missing optimization hint: {pattern}"
                    )

        # Check materialization
        for pattern in self.validation_rules['performance']['materialization']:
            if re.search(r'summarize', query, re.IGNORECASE):
                if not re.search(pattern, query, re.IGNORECASE):
                    result['suggestions'].append(
                        f"Consider adding materialization: {pattern}"
                    )

        # Check filtering optimization
        for pattern in self.validation_rules['performance']['filtering']:
            if re.search(pattern, query, re.IGNORECASE):
                result['suggestions'].append(
                    "Consider using 'has' instead of 'contains' for better performance"
                )

        return result

    def _validate_security(self, query: str) -> Dict:
        """Validate query security aspects."""
        result = {
            'errors': [],
            'warnings': [],
            'suggestions': []
        }

        # Check required security fields
        for field in self.validation_rules['security']['required_fields']:
            if not re.search(rf'\b{field}\b', query):
                result['warnings'].append(
                    f"Security-relevant field missing: {field}"
                )

        # Check sensitive patterns
        for pattern in self.validation_rules['security']['sensitive_patterns']:
            if re.search(pattern, query, re.IGNORECASE):
                result['warnings'].append(
                    f"Query contains sensitive pattern: {pattern}"
                )

        return result

    def _assess_performance_impact(self, query: str) -> str:
        """Assess query performance impact."""
        impact_score = 0
        
        # Check for performance-intensive operations
        if re.search(r'join', query, re.IGNORECASE):
            impact_score += 3
        if re.search(r'union', query, re.IGNORECASE):
            impact_score += 2
        if re.search(r'parse\w*json', query, re.IGNORECASE):
            impact_score += 2
        if re.search(r'summarize', query, re.IGNORECASE):
            impact_score += 2
        if re.search(r'contains', query, re.IGNORECASE):
            impact_score += 1

        # Assess time range impact
        time_match = re.search(r'ago\((\d+)([dhm])\)', query)
        if time_match:
            value = int(time_match.group(1))
            unit = time_match.group(2)
            if unit == 'd' and value > 7:
                impact_score += 3
            elif unit == 'h' and value > 24:
                impact_score += 2

        if impact_score >= 8:
            return "high"
        elif impact_score >= 4:
            return "medium"
        return "low"