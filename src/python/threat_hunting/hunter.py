# src/python/threat_hunting/hunter.py

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import asyncio
from dataclasses import dataclass
import json
import yaml

@dataclass
class ThreatHuntingResult:
    query_id: str
    timestamp: datetime
    findings: List[Dict]
    severity: str
    confidence: float
    related_entities: List[Dict]
    recommended_actions: List[str]

class ThreatHunter:
    """
    Advanced threat hunting system implementing custom detection logic.
    """

    def __init__(self, workspace_id: str, kql_optimizer: KQLOptimizer):
        self.workspace_id = workspace_id
        self.kql_optimizer = kql_optimizer
        self.hunting_queries = self._load_hunting_queries()
        self.detection_patterns = self._load_detection_patterns()

    def _load_hunting_queries(self) -> Dict:
        """Load custom hunting queries from configuration."""
        with open('config/hunting_queries.yaml', 'r') as f:
            return yaml.safe_load(f)

    def _load_detection_patterns(self) -> Dict:
        """Load threat detection patterns and indicators."""
        with open('config/detection_patterns.yaml', 'r') as f:
            return yaml.safe_load(f)

    async def run_hunt(self, hunt_id: str) -> ThreatHuntingResult:
        """
        Execute a specific threat hunting query.
        
        Args:
            hunt_id (str): Identifier for the hunting query
            
        Returns:
            ThreatHuntingResult: Results of the threat hunt
        """
        try:
            # Get query configuration
            hunt_config = self.hunting_queries.get(hunt_id)
            if not hunt_config:
                raise ValueError(f"Invalid hunt ID: {hunt_id}")

            # Optimize the query
            optimized_query, _ = await self.kql_optimizer.optimize_query(
                hunt_config['query']
            )

            # Execute the optimized query
            results = await self._execute_query(optimized_query)

            # Analyze results
            findings = self._analyze_findings(results, hunt_config['analysis_params'])

            return ThreatHuntingResult(
                query_id=hunt_id,
                timestamp=datetime.utcnow(),
                findings=findings,
                severity=self._determine_severity(findings),
                confidence=self._calculate_confidence(findings),
                related_entities=self._identify_related_entities(findings),
                recommended_actions=self._generate_recommendations(findings)
            )

        except Exception as e:
            self.logger.error(f"Error in threat hunt {hunt_id}: {str(e)}")
            raise

    def _analyze_findings(self, results: List[Dict], analysis_params: Dict) -> List[Dict]:
        """Analyze query results for threat indicators."""
        findings = []
        
        for result in results:
            # Apply detection logic
            if self._matches_threat_pattern(result, analysis_params):
                finding = {
                    'timestamp': result.get('TimeGenerated'),
                    'pattern_matched': result.get('pattern_type'),
                    'entities': self._extract_entities(result),
                    'risk_score': self._calculate_risk_score(result),
                    'evidence': self._collect_evidence(result)
                }
                findings.append(finding)

        return findings

    def _matches_threat_pattern(self, event: Dict, params: Dict) -> bool:
        """Check if an event matches known threat patterns."""
        for pattern in self.detection_patterns:
            if all(
                event.get(field) == value 
                for field, value in pattern['indicators'].items()
            ):
                return True
        return False

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate response recommendations based on findings."""
        recommendations = []
        
        if not findings:
            return ["No immediate action required. Continue monitoring."]

        # Analyze findings and generate specific recommendations
        threat_types = set(finding['pattern_matched'] for finding in findings)
        
        for threat_type in threat_types:
            if threat_type in self.detection_patterns:
                recommendations.extend(
                    self.detection_patterns[threat_type]['recommendations']
                )

        return recommendations

    async def run_scheduled_hunts(self) -> Dict[str, ThreatHuntingResult]:
        """Execute all scheduled hunting queries."""
        results = {}
        
        for hunt_id in self.hunting_queries:
            if self.hunting_queries[hunt_id].get('scheduled', False):
                results[hunt_id] = await self.run_hunt(hunt_id)

        return results

    async def generate_hunting_report(
        self,
        results: Dict[str, ThreatHuntingResult]
    ) -> str:
        """Generate a comprehensive hunting report."""
        report_template = """
        # Threat Hunting Report
        Generated: {timestamp}

        ## Summary
        - Total Hunts Executed: {total_hunts}
        - Findings Identified: {total_findings}
        - High Severity Issues: {high_severity_count}

        ## Detailed Findings
        {detailed_findings}

        ## Recommendations
        {recommendations}
        """

        # Process results and generate report
        detailed_findings = self._format_detailed_findings(results)
        recommendations = self._compile_recommendations(results)

        return report_template.format(
            timestamp=datetime.utcnow().isoformat(),
            total_hunts=len(results),
            total_findings=sum(len(r.findings) for r in results.values()),
            high_severity_count=sum(
                1 for r in results.values() if r.severity == 'high'
            ),
            detailed_findings=detailed_findings,
            recommendations=recommendations
        )