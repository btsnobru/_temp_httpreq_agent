
import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from agents.reconnaissance import ReconnaissanceAgent
from agents.detection import DetectionAgent
from agents.validation import ValidationAgent
from agents.exploitation import ExploitationAgent
from agents.learning import LearningAgent
from core.decision_engine import DecisionEngine
from core.cost_analyzer import CostAnalyzer
from utils.claude_interface import ClaudeInterface
from knowledge.patterns_db import PatternsDatabase

@dataclass
class Target:
    url: str
    priority: int = 1
    budget_allocated: float = 10.0
    status: str = "pending"
    findings: List[Dict] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []

class DesyncHunterOrchestrator:
    """
    Main orchestrator that coordinates all agents and manages the hunting process.
    Implements the multi-agent architecture described in the project specification.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize core components
        self.claude_interface = ClaudeInterface(config['api'])
        self.patterns_db = PatternsDatabase(config['database']['path'])
        self.decision_engine = DecisionEngine(config['thresholds'])
        self.cost_analyzer = CostAnalyzer(config['api']['cost_per_token'])
        
        # Initialize specialized agents
        self.recon_agent = ReconnaissanceAgent(self.claude_interface, self.patterns_db)
        self.detection_agent = DetectionAgent(self.claude_interface, self.patterns_db)
        self.validation_agent = ValidationAgent(self.claude_interface)
        self.exploitation_agent = ExploitationAgent(self.claude_interface, self.patterns_db)
        self.learning_agent = LearningAgent(self.claude_interface, self.patterns_db)
        
        self.active_targets: List[Target] = []
        self.total_cost = 0.0
        self.session_findings = []
        
    async def hunt(self, targets: List[str]) -> Dict[str, Any]:
        """
        Main hunting method that orchestrates the entire desync hunting process.
        
        Args:
            targets: List of URLs to analyze
            
        Returns:
            Dict containing results, costs, and findings
        """
        self.logger.info(f"Starting DesyncHunter session with {len(targets)} targets")
        
        # Phase 1: Input Processing and Prioritization
        processed_targets = await self._process_and_prioritize_targets(targets)
        
        # Phase 2: Concurrent Reconnaissance
        recon_results = await self._execute_reconnaissance(processed_targets)
        
        # Phase 3: Intelligent Detection
        detection_results = await self._execute_detection(recon_results)
        
        # Phase 4: Rigorous Validation
        validated_findings = await self._execute_validation(detection_results)
        
        # Phase 5: Focused Exploitation
        exploits = await self._execute_exploitation(validated_findings)
        
        # Phase 6: Learning and Optimization
        await self._execute_learning(exploits)
        
        # Generate final report
        return self._generate_final_report()
    
    async def _process_and_prioritize_targets(self, targets: List[str]) -> List[Target]:
        """Process input URLs and prioritize based on historical intelligence."""
        processed = []
        
        for url in targets:
            # Basic URL validation and sanitization
            sanitized_url = self._sanitize_url(url)
            
            # Get historical intelligence for prioritization
            priority = await self.patterns_db.get_target_priority(sanitized_url)
            
            target = Target(
                url=sanitized_url,
                priority=priority,
                budget_allocated=self.config['thresholds']['max_cost_per_target']
            )
            processed.append(target)
            
        # Sort by priority (higher priority first)
        processed.sort(key=lambda x: x.priority, reverse=True)
        self.active_targets = processed
        
        self.logger.info(f"Prioritized {len(processed)} targets")
        return processed
    
    async def _execute_reconnaissance(self, targets: List[Target]) -> List[Dict]:
        """Execute reconnaissance phase for all targets concurrently."""
        self.logger.info("Starting reconnaissance phase")
        
        semaphore = asyncio.Semaphore(self.config['targets']['concurrent_analysis'])
        tasks = []
        
        for target in targets:
            task = self._recon_single_target(semaphore, target)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and update costs
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Recon failed for {targets[i].url}: {result}")
                continue
                
            valid_results.append(result)
            self.total_cost += result.get('cost', 0)
            
        self.logger.info(f"Reconnaissance completed for {len(valid_results)} targets")
        return valid_results
    
    async def _recon_single_target(self, semaphore: asyncio.Semaphore, target: Target) -> Dict:
        """Execute reconnaissance for a single target."""
        async with semaphore:
            try:
                result = await self.recon_agent.analyze_target(target.url)
                target.status = "recon_complete"
                
                # Cost tracking
                cost = self.cost_analyzer.calculate_recon_cost(result)
                result['cost'] = cost
                result['target_url'] = target.url
                
                return result
                
            except Exception as e:
                self.logger.error(f"Reconnaissance failed for {target.url}: {e}")
                target.status = "recon_failed"
                raise
    
    async def _execute_detection(self, recon_results: List[Dict]) -> List[Dict]:
        """Execute detection phase using adaptive testing strategies."""
        self.logger.info("Starting detection phase")
        
        detection_results = []
        
        for recon_result in recon_results:
            # Skip if budget exceeded
            if self.total_cost >= self.config['thresholds']['max_cost_per_target'] * len(self.active_targets):
                self.logger.warning("Budget limit reached, stopping detection phase")
                break
                
            try:
                # Generate adaptive tests based on fingerprint
                result = await self.detection_agent.detect_vulnerabilities(recon_result)
                
                # Cost tracking
                cost = self.cost_analyzer.calculate_detection_cost(result)
                result['cost'] = cost
                self.total_cost += cost
                
                if result.get('findings'):
                    detection_results.append(result)
                    self.logger.info(f"Found {len(result['findings'])} potential vulnerabilities in {result['target_url']}")
                
            except Exception as e:
                self.logger.error(f"Detection failed for {recon_result['target_url']}: {e}")
                continue
        
        self.logger.info(f"Detection phase completed with {len(detection_results)} targets having findings")
        return detection_results
    
    async def _execute_validation(self, detection_results: List[Dict]) -> List[Dict]:
        """Execute validation phase to eliminate false positives."""
        self.logger.info("Starting validation phase")
        
        validated_findings = []
        
        for detection_result in detection_results:
            for finding in detection_result.get('findings', []):
                try:
                    # Multi-layer validation
                    validation_result = await self.validation_agent.validate_finding(finding)
                    
                    # Cost tracking
                    cost = self.cost_analyzer.calculate_validation_cost(validation_result)
                    validation_result['cost'] = cost
                    self.total_cost += cost
                    
                    # Check confidence threshold
                    confidence = validation_result.get('confidence_score', 0)
                    if confidence >= self.config['thresholds']['confidence_minimum']:
                        validated_findings.append(validation_result)
                        self.logger.info(f"Validated finding with confidence {confidence:.2f}")
                    else:
                        self.logger.info(f"Rejected finding with low confidence {confidence:.2f}")
                        
                except Exception as e:
                    self.logger.error(f"Validation failed for finding: {e}")
                    continue
        
        self.logger.info(f"Validation phase completed with {len(validated_findings)} validated findings")
        return validated_findings
    
    async def _execute_exploitation(self, validated_findings: List[Dict]) -> List[Dict]:
        """Execute exploitation phase to develop functional exploits."""
        self.logger.info("Starting exploitation phase")
        
        exploits = []
        
        for finding in validated_findings:
            try:
                # Develop functional exploit
                exploit_result = await self.exploitation_agent.develop_exploit(finding)
                
                # Cost tracking
                cost = self.cost_analyzer.calculate_exploitation_cost(exploit_result)
                exploit_result['cost'] = cost
                self.total_cost += cost
                
                if exploit_result.get('exploit_successful'):
                    exploits.append(exploit_result)
                    self.logger.info(f"Successfully developed exploit for {finding['vulnerability_type']}")
                
            except Exception as e:
                self.logger.error(f"Exploitation failed for finding: {e}")
                continue
        
        self.logger.info(f"Exploitation phase completed with {len(exploits)} successful exploits")
        return exploits
    
    async def _execute_learning(self, exploits: List[Dict]) -> None:
        """Execute learning phase for continuous optimization."""
        self.logger.info("Starting learning phase")
        
        try:
            # Update patterns database with new findings
            await self.learning_agent.update_knowledge_base(exploits)
            
            # Optimize detection thresholds
            await self.learning_agent.optimize_thresholds(self.session_findings)
            
            # Generate new test patterns
            await self.learning_agent.generate_new_patterns(exploits)
            
            self.logger.info("Learning phase completed successfully")
            
        except Exception as e:
            self.logger.error(f"Learning phase failed: {e}")
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive final report."""
        report = {
            'session_summary': {
                'targets_analyzed': len(self.active_targets),
                'total_cost': self.total_cost,
                'findings_count': len(self.session_findings),
                'execution_time': datetime.now().isoformat(),
            },
            'cost_breakdown': self.cost_analyzer.get_cost_breakdown(),
            'findings': self.session_findings,
            'recommendations': self._generate_recommendations(),
            'metrics': self._calculate_session_metrics()
        }
        
        self.logger.info(f"Generated final report with {len(self.session_findings)} findings")
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on session results."""
        recommendations = []
        
        if self.total_cost > 50:
            recommendations.append("Consider optimizing detection algorithms to reduce API costs")
        
        if len(self.session_findings) == 0:
            recommendations.append("Try expanding target scope or adjusting detection thresholds")
        
        return recommendations
    
    def _calculate_session_metrics(self) -> Dict[str, float]:
        """Calculate key performance metrics for the session."""
        targets_count = len(self.active_targets)
        findings_count = len(self.session_findings)
        
        return {
            'cost_per_target': self.total_cost / max(targets_count, 1),
            'findings_per_target': findings_count / max(targets_count, 1),
            'cost_per_finding': self.total_cost / max(findings_count, 1) if findings_count > 0 else 0,
            'success_rate': findings_count / max(targets_count, 1)
        }
    
    def _sanitize_url(self, url: str) -> str:
        """Sanitize and validate input URL."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
