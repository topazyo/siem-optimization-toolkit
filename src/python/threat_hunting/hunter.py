# src/python/threat_hunting/hunter.py

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import asyncio
from dataclasses import dataclass
import json
import yaml

@dataclass
class ThreatHuntingResult:
    """
    Stores the results of a single threat hunting query execution.

    This dataclass encapsulates all relevant information derived from running
    a hunting query, including the query identifier, when it was run, any
    findings, assessed severity and confidence, identified related entities,
    and suggested actions.
    """
    query_id: str  # The unique identifier of the hunting query that was executed.
    timestamp: datetime  # Timestamp of when the hunt was completed and results generated.
    findings: List[Dict]  # A list of dictionaries, where each dictionary represents a specific
                           # finding or piece of evidence uncovered by the hunt.
                           # Example: [{'timestamp': '...', 'pattern_matched': 'suspicious_process',
                           #            'entities': [{'type': 'host', 'id': 'HOST01'}],
                           #            'risk_score': 75, 'evidence': {'process_name': 'evil.exe'}}]
    severity: str  # Overall assessed severity of the findings (e.g., "Low", "Medium", "High").
    confidence: float  # Confidence score (e.g., 0.0 to 1.0) in the accuracy/relevance of the findings.
    related_entities: List[Dict]  # List of entities (hosts, users, IPs, etc.) associated with the findings.
                                 # Example: [{'type': 'ip_address', 'value': '192.168.1.100'},
                                 #           {'type': 'user', 'name': 'jdoe'}]
    recommended_actions: List[str]  # A list of suggested actions to take based on the findings
                                     # (e.g., "Isolate host HOST01", "Block IP 192.168.1.100").

class ThreatHunter:
    """
    Advanced threat hunting system implementing custom detection logic.
    """

    def __init__(self, workspace_id: str, kql_optimizer: 'KQLOptimizer'): # Type hint KQLOptimizer in quotes
        """
        Initializes the ThreatHunter instance.

        Sets up the Azure Log Analytics workspace ID, an instance of KQLOptimizer
        for query optimization, and loads predefined hunting queries and detection
        patterns from configuration files.

        Args:
            workspace_id (str): The Azure Log Analytics workspace ID where hunts
                                will be performed.
            kql_optimizer (KQLOptimizer): An instance of the `KQLOptimizer` class,
                                          used to optimize hunting queries before execution.

        Initializes key attributes:
        - `workspace_id` (str): Stores the Log Analytics workspace ID.
        - `kql_optimizer` (KQLOptimizer): Stores the provided KQL optimizer instance.
        - `hunting_queries` (Dict): A dictionary loaded from 'config/hunting_queries.yaml',
                                    containing definitions for various hunting queries. Each
                                    entry typically includes the KQL query, parameters,
                                    scheduling info, and analysis parameters.
        - `detection_patterns` (Dict): A dictionary loaded from 'config/detection_patterns.yaml',
                                       containing patterns and indicators used in analyzing
                                       query results for threats.
        """
        self.workspace_id = workspace_id
        self.kql_optimizer = kql_optimizer
        self.hunting_queries = self._load_hunting_queries()
        self.detection_patterns = self._load_detection_patterns()
        # It's good practice to also initialize a logger here, e.g.:
        # import logging
        # self.logger = logging.getLogger(__name__)

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
        Asynchronously executes a specific threat hunting query identified by `hunt_id`.

        The method retrieves the query configuration (which includes the KQL query
        and analysis parameters like thresholds or patterns to look for) from
        `self.hunting_queries`. The KQL query is then optimized using `self.kql_optimizer`.
        After execution, the results are analyzed to identify findings, determine severity
        and confidence, extract related entities, and generate recommendations.

        Args:
            hunt_id (str): The unique identifier for the hunting query to be executed.
                           This ID should correspond to an entry in `hunting_queries.yaml`.
                           The `hunt_config` loaded from YAML is expected to have keys like:
                           - 'query' (str): The KQL query string.
                           - 'analysis_params' (Dict): Parameters for `_analyze_findings`,
                             which might include thresholds, whitelists, or specific patterns.
                             Example: {'threshold': 5, 'ignore_ips': ['127.0.0.1']}
                           - Other metadata like 'name', 'description', 'severity_level'.

        Returns:
            ThreatHuntingResult: A dataclass instance containing the detailed results
                                 of the executed threat hunt.

        Raises:
            ValueError: If the provided `hunt_id` is not found in the loaded
                        hunting queries.
            Exception: Propagates exceptions from query execution or analysis errors.
        """
        try:
            # Get query configuration
            hunt_config = self.hunting_queries.get(hunt_id)
            if not hunt_config:
                raise ValueError(f"Invalid hunt ID or hunt configuration not found: {hunt_id}")

            kql_query = hunt_config.get('query')
            if not kql_query:
                raise ValueError(f"Query string not found in hunt configuration for hunt ID: {hunt_id}")

            analysis_params = hunt_config.get('analysis_params', {}) # Default to empty dict if not present

            # Optimize the query
            optimized_query, _ = await self.kql_optimizer.optimize_query(kql_query)

            # Execute the optimized query
            # Assuming _execute_query is defined and handles actual KQL execution
            results = await self._execute_query(optimized_query)

            # Analyze results
            findings = self._analyze_findings(results, analysis_params)

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
        """
        Asynchronously executes all threat hunting queries that are marked as 'scheduled'.

        It iterates through all loaded hunting queries, checks a 'scheduled' flag
        (expected in the query's configuration in `hunting_queries.yaml`), and
        runs each scheduled hunt using the `run_hunt` method.

        Returns:
            Dict[str, ThreatHuntingResult]: A dictionary where keys are the hunt IDs
                                            of the executed scheduled hunts, and values
                                            are the corresponding `ThreatHuntingResult` objects.
                                            Hunts that fail during execution might be omitted
                                            or could include an error status within their result,
                                            depending on `run_hunt`'s error handling.
        """
        results = {}
        
        for hunt_id, hunt_config in self.hunting_queries.items():
            if hunt_config.get('scheduled', False): # Check for 'scheduled' flag
                try:
                    results[hunt_id] = await self.run_hunt(hunt_id)
                except Exception as e:
                    # self.logger.error(f"Scheduled hunt {hunt_id} failed: {str(e)}") # Assuming logger
                    # Optionally, store error information in results
                    results[hunt_id] = ThreatHuntingResult(
                        query_id=hunt_id,
                        timestamp=datetime.utcnow(),
                        findings=[],
                        severity="Error",
                        confidence=0.0,
                        related_entities=[],
                        recommended_actions=[f"Hunt failed: {str(e)}"]
                    )
        return results

    async def generate_hunting_report(
        self,
        results: Dict[str, ThreatHuntingResult]
    ) -> str:
        """
        Asynchronously generates a formatted string report from the results of
        one or more threat hunts.

        The report is typically structured in Markdown or HTML and summarizes the
        outcomes of the hunting activities, including total hunts, findings,
        high-severity issues, detailed breakdowns per hunt, and compiled recommendations.

        Args:
            results (Dict[str, ThreatHuntingResult]): A dictionary where keys are
                                                      hunt IDs and values are the
                                                      `ThreatHuntingResult` objects,
                                                      as returned by `run_scheduled_hunts`
                                                      or from multiple `run_hunt` calls.

        Returns:
            str: A formatted string (e.g., Markdown) representing the hunting report.
                 Key sections typically include:
                 - Summary: Total hunts executed, total findings, number of high-severity issues.
                 - Detailed Findings: A breakdown for each hunt, showing its findings.
                 - Recommendations: A compiled list of recommended actions from all hunts.
        """
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