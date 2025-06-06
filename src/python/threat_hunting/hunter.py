
# src/kql/threat_hunting/hunter.py

from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import asyncio
from datetime import datetime, timedelta
import json
import yaml
import logging
from concurrent.futures import ThreadPoolExecutor

@dataclass
class HuntingQuery:
    name: str
    description: str
    query: str
    tactics: List[str]
    techniques: List[str]
    risk_level: str
    data_sources: List[str]
    parameters: Dict
    validation: Dict

@dataclass
class HuntingResult:
    query_name: str
    timestamp: datetime
    findings: List[Dict]
    severity: str
    confidence: float
    affected_entities: List[Dict]
    evidence: Dict
    recommendations: List[str]

class ThreatHunter:
    """
    Advanced threat hunting system using KQL queries.
    """

    def __init__(self, workspace_id: str, config_path: str = 'config/hunting.yaml'):
        self.workspace_id = workspace_id
        self.logger = logging.getLogger(__name__)
        self.queries = self._load_queries(config_path)
        self.results_cache = {}
        self.executor = ThreadPoolExecutor(max_workers=10)

    def _load_queries(self, config_path: str) -> Dict[str, HuntingQuery]:
        """Load hunting queries from configuration."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            queries = {}
            for query_config in config['queries']:
                query = HuntingQuery(**query_config)
                queries[query.name] = query

            return queries

        except Exception as e:
            self.logger.error(f"Error loading queries: {str(e)}")
            raise

    async def hunt(
        self,
        query_names: Optional[List[str]] = None,
        timeframe: str = "24h"
    ) -> Dict[str, HuntingResult]:
        """
        Execute threat hunting queries.

        Args:
            query_names (Optional[List[str]]): Specific queries to run
            timeframe (str): Time range for hunting

        Returns:
            Dict[str, HuntingResult]: Hunting results by query name
        """
        results = {}
        queries_to_run = (
            {name: self.queries[name] for name in query_names}
            if query_names
            else self.queries
        )

        async with asyncio.TaskGroup() as tg:
            for name, query in queries_to_run.items():
                task = tg.create_task(
                    self._execute_hunt(query, timeframe)
                )
                results[name] = await task

        return results

    async def _execute_hunt(
        self,
        query: HuntingQuery,
        timeframe: str
    ) -> HuntingResult:
        """Execute a single hunting query."""
        try:
            # Prepare query
            prepared_query = self._prepare_query(query, timeframe)

            # Execute query
            results = await self._execute_query(prepared_query)

            # Analyze findings
            findings = await self._analyze_findings(results, query)

            # Generate recommendations
            recommendations = await self._generate_recommendations(findings, query)

            return HuntingResult(
                query_name=query.name,
                timestamp=datetime.utcnow(),
                findings=findings,
                severity=self._determine_severity(findings),
                confidence=self._calculate_confidence(findings),
                affected_entities=self._extract_entities(findings),
                evidence=self._collect_evidence(findings),
                recommendations=recommendations
            )

        except Exception as e:
            self.logger.error(f"Hunt execution error: {str(e)}")
            raise

    def _prepare_query(self, query: HuntingQuery, timeframe: str) -> str:
        """Prepare query with parameters."""
        prepared = query.query

        # Replace timeframe
        prepared = prepared.replace('${timeframe}', timeframe)

        # Replace other parameters
        for key, value in query.parameters.items():
            prepared = prepared.replace(f'${key}', str(value))

        return prepared

    async def _analyze_findings(
        self,
        results: List[Dict],
        query: HuntingQuery
    ) -> List[Dict]:
        """Analyze query results for threat indicators."""
        findings = []
        
        for result in results:
            # Apply detection logic
            if self._matches_threat_pattern(result, query):
                finding = {
                    'timestamp': result.get('TimeGenerated'),
                    'indicators': self._extract_indicators(result),
                    'risk_score': self._calculate_risk_score(result, query),
                    'context': self._gather_context(result),
                    'evidence': self._collect_evidence({result})
                }
                findings.append(finding)

        return findings

    async def _generate_recommendations(
        self,
        findings: List[Dict],
        query: HuntingQuery
    ) -> List[str]:
        """Generate response recommendations."""
        recommendations = set()
        
        for finding in findings:
            # Add tactic-specific recommendations
            for tactic in query.tactics:
                recommendations.update(
                    self._get_tactic_recommendations(tactic)
                )

            # Add severity-specific recommendations
            severity = self._determine_severity([finding])
            recommendations.update(
                self._get_severity_recommendations(severity)
            )

            # Add technique-specific recommendations
            for technique in query.techniques:
                recommendations.update(
                    self._get_technique_recommendations(technique)
                )

        return list(recommendations)

    def _calculate_risk_score(self, finding: Dict, query: HuntingQuery) -> float:
        """Calculate risk score for a finding."""
        base_score = {
            'high': 8.0,
            'medium': 5.0,
            'low': 2.0
        }.get(query.risk_level, 5.0)
        
        modifiers = 0.0

        # Add technique-based modifier
        modifiers += len(query.techniques) * 0.5

        # Add data source reliability modifier
        modifiers += len(query.data_sources) * 0.3

        # Add indicator confidence modifier
        indicators = self._extract_indicators(finding)
        modifiers += len(indicators) * 0.4

        return min(10.0, base_score + modifiers)

    async def generate_hunt_report(
        self,
        results: Dict[str, HuntingResult]
    ) -> Dict:
        """Generate comprehensive hunting report."""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_queries': len(results),
                'total_findings': sum(len(r.findings) for r in results.values()),
                'high_severity_findings': sum(
                    1 for r in results.values()
                    if r.severity == 'high'
                )
            },
            'findings_by_tactic': self._group_by_tactic(results),
            'affected_entities': self._summarize_affected_entities(results),
            'recommendations': self._consolidate_recommendations(results)
        }

        # Add MITRE ATT&CK mapping
        report['mitre_mapping'] = self._generate_mitre_mapping(results)

        # Add timeline analysis
        report['timeline'] = await self._generate_timeline(results)

        return report

    def _generate_mitre_mapping(
        self,
        results: Dict[str, HuntingResult]
    ) -> Dict:
        """Generate MITRE ATT&CK technique mapping."""
        mapping = {}

        for result in results.values():
            query = self.queries[result.query_name]

            for technique in query.techniques:
                if technique not in mapping:
                    mapping[technique] = {
                        'findings_count': 0,
                        'queries': set(),
                        'severity': set()
                    }

                mapping[technique]['findings_count'] += len(result.findings)
                mapping[technique]['queries'].add(result.query_name)
                mapping[technique]['severity'].add(result.severity)

        # Convert sets to lists for JSON serialization
        for technique in mapping:
            mapping[technique]['queries'] = list(mapping[technique]['queries'])
            mapping[technique]['severity'] = list(mapping[technique]['severity'])

        return mapping

    async def _generate_timeline(
        self,
        results: Dict[str, HuntingResult]
    ) -> List[Dict]:
        """Generate timeline of findings."""
        timeline = []

        for result in results.values():
            for finding in result.findings:
                timeline.append({
                    'timestamp': finding['timestamp'],
                    'query_name': result.query_name,
                    'severity': result.severity,
                    'indicators': finding['indicators'],
                    'affected_entities': self._extract_entities({finding})
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])

        return timeline