
import asyncio
import logging
from typing import Dict, List, Any, Optional
import statistics
import time
from datetime import datetime, timedelta

from utils.claude_interface import ClaudeInterface
from knowledge.patterns_db import PatternsDatabase

class LearningAgent:
    """
    Learning Agent responsible for continuous learning and system optimization.
    
    Capabilities:
    - Pattern recognition of successful attack vectors
    - Threshold optimization based on results
    - New test generation from failure analysis
    - Success rate tracking and improvement
    - Knowledge base updates and maintenance
    """
    
    def __init__(self, claude_interface: ClaudeInterface, patterns_db: PatternsDatabase):
        self.claude = claude_interface
        self.patterns_db = patterns_db
        self.logger = logging.getLogger(__name__)
        
        # Learning parameters
        self.learning_rate = 0.1
        self.pattern_confidence_threshold = 0.7
        self.minimum_samples_for_learning = 5
        
    async def update_knowledge_base(self, exploits: List[Dict[str, Any]]) -> None:
        """
        Update knowledge base with new successful exploits and patterns.
        
        Args:
            exploits: List of successful exploitation results
        """
        self.logger.info(f"Updating knowledge base with {len(exploits)} exploits")
        
        for exploit in exploits:
            if exploit.get('exploit_successful'):
                await self._process_successful_exploit(exploit)
            else:
                await self._process_failed_exploit(exploit)
        
        # Update global success patterns
        await self._update_global_patterns(exploits)
        
        # Cleanup old data
        await self.patterns_db.cleanup_old_data(days=365)
    
    async def optimize_thresholds(self, session_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Optimize detection and validation thresholds based on session results.
        
        Args:
            session_findings: All findings from the current session
            
        Returns:
            Optimized threshold recommendations
        """
        self.logger.info("Optimizing detection and validation thresholds")
        
        # Analyze current performance
        performance_data = await self._analyze_session_performance(session_findings)
        
        # Get historical performance
        historical_data = await self.patterns_db.get_performance_metrics(days=30)
        
        # Calculate threshold adjustments
        threshold_adjustments = await self._calculate_threshold_adjustments(
            performance_data, historical_data
        )
        
        # Use AI to validate and enhance adjustments
        ai_recommendations = await self._get_ai_threshold_recommendations(
            performance_data, threshold_adjustments
        )
        
        return {
            'current_performance': performance_data,
            'historical_baseline': historical_data,
            'threshold_adjustments': threshold_adjustments,
            'ai_recommendations': ai_recommendations,
            'optimization_timestamp': time.time()
        }
    
    async def generate_new_patterns(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate new test patterns based on successful exploits and failures.
        
        Args:
            exploits: Recent exploitation attempts
            
        Returns:
            New test patterns to try
        """
        self.logger.info("Generating new test patterns from exploit analysis")
        
        # Analyze successful patterns
        successful_patterns = [e for e in exploits if e.get('exploit_successful')]
        
        # Identify common success factors
        success_factors = await self._identify_success_factors(successful_patterns)
        
        # Generate pattern variations
        new_patterns = await self._generate_pattern_variations(success_factors)
        
        # Use AI to suggest additional patterns
        ai_patterns = await self._get_ai_generated_patterns(successful_patterns)
        
        # Combine and prioritize patterns
        all_patterns = new_patterns + ai_patterns
        prioritized_patterns = await self._prioritize_new_patterns(all_patterns)
        
        return prioritized_patterns
    
    async def analyze_failure_modes(self, failed_attempts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze failure modes to improve detection accuracy.
        
        Args:
            failed_attempts: List of failed exploitation attempts
            
        Returns:
            Failure analysis and improvement recommendations
        """
        self.logger.info(f"Analyzing {len(failed_attempts)} failure modes")
        
        # Categorize failures
        failure_categories = await self._categorize_failures(failed_attempts)
        
        # Identify common failure patterns
        failure_patterns = await self._identify_failure_patterns(failure_categories)
        
        # Generate improvement recommendations
        improvements = await self._generate_improvement_recommendations(failure_patterns)
        
        return {
            'failure_categories': failure_categories,
            'common_patterns': failure_patterns,
            'improvement_recommendations': improvements,
            'analysis_timestamp': time.time()
        }
    
    async def update_target_intelligence(self, session_results: Dict[str, Any]) -> None:
        """
        Update target-specific intelligence based on session results.
        
        Args:
            session_results: Complete session results
        """
        findings = session_results.get('findings', [])
        
        for finding in findings:
            target_url = finding.get('target_url')
            if not target_url:
                continue
            
            # Update target success rate
            await self._update_target_success_rate(target_url, finding)
            
            # Store infrastructure intelligence
            if finding.get('infrastructure_fingerprint'):
                await self.patterns_db.store_target_intelligence(
                    target_url,
                    'infrastructure',
                    finding['infrastructure_fingerprint'],
                    confidence=0.9,
                    expires_hours=24*7  # 1 week
                )
            
            # Store vulnerability patterns
            if finding.get('exploit_successful'):
                await self.patterns_db.store_target_intelligence(
                    target_url,
                    'vulnerability_confirmed',
                    {
                        'technique': finding.get('technique'),
                        'confidence': finding.get('confidence_score', 0),
                        'exploit_type': finding.get('exploit_type')
                    },
                    confidence=finding.get('confidence_score', 0.5),
                    expires_hours=24*30  # 30 days
                )
    
    async def _process_successful_exploit(self, exploit: Dict[str, Any]) -> None:
        """Process a successful exploit for learning."""
        
        # Extract pattern information
        technique = exploit.get('technique')
        payload = exploit.get('payload_used', '')
        impact_level = exploit.get('impact_level', 'low')
        
        # Store successful pattern
        pattern_data = {
            'technique': technique,
            'infrastructure_type': exploit.get('infrastructure_type', 'unknown'),
            'payload_template': payload,
            'conditions': {
                'impact_level': impact_level,
                'exploit_type': exploit.get('exploit_type'),
                'success_indicators': exploit.get('evidence', {})
            },
            'success_rate': 1.0
        }
        
        await self.patterns_db.store_successful_pattern(pattern_data)
        
        # Update technique effectiveness
        await self._update_technique_effectiveness(technique, success=True)
    
    async def _process_failed_exploit(self, exploit: Dict[str, Any]) -> None:
        """Process a failed exploit attempt for learning."""
        
        technique = exploit.get('technique')
        error = exploit.get('error', 'unknown_failure')
        
        # Store failure pattern for analysis
        failure_data = {
            'technique': technique,
            'failure_reason': error,
            'timestamp': time.time()
        }
        
        # This would be stored in a failures table if we had one
        # For now, just update technique effectiveness
        await self._update_technique_effectiveness(technique, success=False)
    
    async def _update_global_patterns(self, exploits: List[Dict[str, Any]]) -> None:
        """Update global success patterns and statistics."""
        
        # Calculate technique success rates
        technique_stats = {}
        
        for exploit in exploits:
            technique = exploit.get('technique', 'unknown')
            success = exploit.get('exploit_successful', False)
            
            if technique not in technique_stats:
                technique_stats[technique] = {'attempts': 0, 'successes': 0}
            
            technique_stats[technique]['attempts'] += 1
            if success:
                technique_stats[technique]['successes'] += 1
        
        # Update database with new statistics
        for technique, stats in technique_stats.items():
            success_rate = stats['successes'] / stats['attempts']
            
            # This would update a technique_statistics table
            self.logger.info(f"Technique {technique}: {success_rate:.2f} success rate")
    
    async def _analyze_session_performance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze performance of current session."""
        
        total_findings = len(findings)
        successful_exploits = sum(1 for f in findings if f.get('exploit_successful'))
        validated_findings = sum(1 for f in findings if f.get('validation_passed'))
        false_positives = sum(1 for f in findings if f.get('validation_passed') is False)
        
        # Calculate rates
        success_rate = successful_exploits / max(total_findings, 1)
        validation_rate = validated_findings / max(total_findings, 1)
        false_positive_rate = false_positives / max(total_findings, 1)
        
        # Confidence distribution
        confidences = [f.get('confidence_score', 0) for f in findings if 'confidence_score' in f]
        avg_confidence = statistics.mean(confidences) if confidences else 0.0
        
        return {
            'total_findings': total_findings,
            'successful_exploits': successful_exploits,
            'validated_findings': validated_findings,
            'false_positives': false_positives,
            'success_rate': success_rate,
            'validation_rate': validation_rate,
            'false_positive_rate': false_positive_rate,
            'average_confidence': avg_confidence
        }
    
    async def _calculate_threshold_adjustments(
        self, 
        current_performance: Dict[str, Any], 
        historical_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate threshold adjustments based on performance."""
        
        adjustments = {}
        
        # Confidence threshold adjustment
        current_fp_rate = current_performance.get('false_positive_rate', 0.0)
        target_fp_rate = 0.05  # 5% target
        
        if current_fp_rate > target_fp_rate:
            # Too many false positives, increase confidence threshold
            adjustments['confidence_threshold'] = 0.05
        elif current_fp_rate < target_fp_rate * 0.5:
            # Very few false positives, can lower threshold
            adjustments['confidence_threshold'] = -0.02
        else:
            adjustments['confidence_threshold'] = 0.0
        
        # Validation threshold adjustment
        current_validation_rate = current_performance.get('validation_rate', 0.0)
        if current_validation_rate < 0.3:  # Less than 30% validation rate
            adjustments['detection_sensitivity'] = -0.1
        elif current_validation_rate > 0.8:  # More than 80% validation rate
            adjustments['detection_sensitivity'] = 0.05
        else:
            adjustments['detection_sensitivity'] = 0.0
        
        return adjustments
    
    async def _get_ai_threshold_recommendations(
        self, 
        performance_data: Dict[str, Any],
        threshold_adjustments: Dict[str, float]
    ) -> Dict[str, Any]:
        """Get AI-powered threshold optimization recommendations."""
        
        prompt = f"""
        Analyze this HTTP Request Smuggling detection performance and recommend optimizations:

        Current Performance:
        - Total Findings: {performance_data.get('total_findings')}
        - Success Rate: {performance_data.get('success_rate', 0):.2%}
        - Validation Rate: {performance_data.get('validation_rate', 0):.2%}
        - False Positive Rate: {performance_data.get('false_positive_rate', 0):.2%}
        - Average Confidence: {performance_data.get('average_confidence', 0):.2f}

        Calculated Adjustments:
        {threshold_adjustments}

        Provide recommendations for:
        1. Optimal confidence thresholds
        2. Detection sensitivity adjustments
        3. Validation criteria improvements
        4. Expected performance impact
        5. Risk assessment of changes

        Focus on maximizing true positives while minimizing false positives.
        """
        
        try:
            response = await self.claude.analyze(prompt)
            return {
                'recommendations': response.get('analysis', ''),
                'optimal_thresholds': response.get('structured_data', {}),
                'expected_impact': response.get('next_steps', [])
            }
        except Exception as e:
            self.logger.error(f"AI threshold recommendations failed: {e}")
            return {'recommendations': 'AI analysis unavailable'}
    
    async def _identify_success_factors(self, successful_patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify common factors in successful exploits."""
        
        success_factors = {
            'techniques': {},
            'payload_patterns': [],
            'infrastructure_types': {},
            'timing_patterns': [],
            'response_patterns': {}
        }
        
        for pattern in successful_patterns:
            # Technique distribution
            technique = pattern.get('technique', 'unknown')
            success_factors['techniques'][technique] = success_factors['techniques'].get(technique, 0) + 1
            
            # Infrastructure correlation
            infra = pattern.get('infrastructure_type', 'unknown')
            success_factors['infrastructure_types'][infra] = success_factors['infrastructure_types'].get(infra, 0) + 1
            
            # Timing patterns
            if 'response_time' in pattern.get('evidence', {}):
                success_factors['timing_patterns'].append(pattern['evidence']['response_time'])
        
        return success_factors
    
    async def _generate_pattern_variations(self, success_factors: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate variations of successful patterns."""
        
        new_patterns = []
        
        # Generate technique variations
        for technique, count in success_factors['techniques'].items():
            if count >= self.minimum_samples_for_learning:
                # Create variations based on successful technique
                variations = await self._create_technique_variations(technique)
                new_patterns.extend(variations)
        
        return new_patterns
    
    async def _create_technique_variations(self, base_technique: str) -> List[Dict[str, Any]]:
        """Create variations of a successful technique."""
        
        variations = []
        
        if base_technique == 'expect_obfuscated':
            # Generate new Expect header variations
            expect_variations = [
                'x 100-continue',
                'z 100-continue', 
                '\t100-continue',
                '100-continue\r',
                '100-continueZ'
            ]
            
            for variant in expect_variations:
                variations.append({
                    'technique': 'expect_obfuscated_variant',
                    'base_technique': base_technique,
                    'payload_variant': f'Expect: {variant}',
                    'confidence': 0.6,
                    'priority': 'medium'
                })
        
        elif base_technique == 'vh_hv':
            # Generate header masquerading variations
            header_variations = [
                '\tContent-Length',
                'Content-Length\r',
                'content-length',  # Case variation
                ' Transfer-Encoding',
                'Host\n'
            ]
            
            for variant in header_variations:
                variations.append({
                    'technique': 'vh_hv_variant',
                    'base_technique': base_technique,
                    'payload_variant': f'{variant}: value',
                    'confidence': 0.5,
                    'priority': 'low'
                })
        
        return variations
    
    async def _get_ai_generated_patterns(self, successful_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use AI to generate new test patterns from successful ones."""
        
        if not successful_patterns:
            return []
        
        prompt = f"""
        Based on these successful HTTP Request Smuggling patterns, generate new test variations:

        Successful Patterns:
        {successful_patterns[:5]}  # Limit to first 5 for prompt size

        Generate:
        1. New payload variations for each technique
        2. Header manipulation alternatives
        3. Encoding/obfuscation methods
        4. Combined attack techniques
        5. Infrastructure-specific adaptations

        Focus on novel approaches that maintain the core vulnerability principles.
        """
        
        try:
            response = await self.claude.analyze(prompt)
            
            # Parse AI response into structured patterns
            ai_patterns = self._parse_ai_patterns(response.get('analysis', ''))
            return ai_patterns
            
        except Exception as e:
            self.logger.error(f"AI pattern generation failed: {e}")
            return []
    
    async def _prioritize_new_patterns(self, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize new patterns based on success probability and novelty."""
        
        # Score patterns based on various factors
        for pattern in patterns:
            score = 0.0
            
            # Base technique success rate
            if pattern.get('confidence', 0) > 0.7:
                score += 0.4
            
            # Novelty factor
            if 'variant' in pattern.get('technique', ''):
                score += 0.2
            
            # Priority indicator
            priority = pattern.get('priority', 'medium')
            if priority == 'high':
                score += 0.3
            elif priority == 'medium':
                score += 0.2
            
            pattern['priority_score'] = score
        
        # Sort by priority score
        return sorted(patterns, key=lambda x: x.get('priority_score', 0), reverse=True)
    
    async def _categorize_failures(self, failed_attempts: List[Dict[str, Any]]) -> Dict[str, List]:
        """Categorize failure modes."""
        
        categories = {
            'network_errors': [],
            'validation_failures': [],
            'exploitation_failures': [],
            'false_positives': [],
            'timeout_errors': []
        }
        
        for attempt in failed_attempts:
            error = attempt.get('error', '').lower()
            
            if 'timeout' in error or 'connection' in error:
                categories['network_errors'].append(attempt)
            elif 'validation' in error:
                categories['validation_failures'].append(attempt)
            elif 'exploit' in error:
                categories['exploitation_failures'].append(attempt)
            elif attempt.get('validation_passed') is False:
                categories['false_positives'].append(attempt)
            else:
                categories['timeout_errors'].append(attempt)
        
        return categories
    
    async def _identify_failure_patterns(self, failure_categories: Dict[str, List]) -> Dict[str, Any]:
        """Identify common patterns in failures."""
        
        patterns = {}
        
        for category, failures in failure_categories.items():
            if not failures:
                continue
                
            # Common techniques that fail
            failed_techniques = {}
            for failure in failures:
                technique = failure.get('technique', 'unknown')
                failed_techniques[technique] = failed_techniques.get(technique, 0) + 1
            
            patterns[category] = {
                'count': len(failures),
                'common_techniques': failed_techniques,
                'failure_rate': len(failures) / sum(len(f) for f in failure_categories.values())
            }
        
        return patterns
    
    async def _generate_improvement_recommendations(self, failure_patterns: Dict[str, Any]) -> List[str]:
        """Generate recommendations to address failure patterns."""
        
        recommendations = []
        
        # Network error recommendations
        if failure_patterns.get('network_errors', {}).get('count', 0) > 5:
            recommendations.append("Implement better connection pooling and retry logic")
            recommendations.append("Add exponential backoff for failed connections")
        
        # Validation failure recommendations
        if failure_patterns.get('validation_failures', {}).get('failure_rate', 0) > 0.3:
            recommendations.append("Review validation criteria - may be too strict")
            recommendations.append("Implement multi-layer validation with confidence scoring")
        
        # False positive recommendations
        if failure_patterns.get('false_positives', {}).get('count', 0) > 3:
            recommendations.append("Increase confidence threshold for validation")
            recommendations.append("Add additional verification steps for edge cases")
        
        return recommendations
    
    async def _update_target_success_rate(self, target_url: str, finding: Dict[str, Any]) -> None:
        """Update success rate for a specific target."""
        
        # This would update target statistics in the database
        success = finding.get('exploit_successful', False)
        
        # Store the result for target intelligence
        await self.patterns_db.store_target_intelligence(
            target_url,
            'success_rate',
            {'success': success, 'timestamp': time.time()},
            confidence=1.0,
            expires_hours=24*7  # 1 week
        )
    
    async def _update_technique_effectiveness(self, technique: str, success: bool) -> None:
        """Update effectiveness statistics for a technique."""
        
        # This would be more sophisticated in a real implementation
        # For now, just log the information
        self.logger.info(f"Technique {technique} {'succeeded' if success else 'failed'}")
    
    def _parse_ai_patterns(self, ai_response: str) -> List[Dict[str, Any]]:
        """Parse AI-generated patterns from response text."""
        
        # This is a simplified parser - would be more sophisticated in practice
        patterns = []
        
        lines = ai_response.split('\n')
        current_pattern = {}
        
        for line in lines:
            line = line.strip()
            
            if 'technique:' in line.lower():
                if current_pattern:
                    patterns.append(current_pattern)
                current_pattern = {'technique': line.split(':', 1)[1].strip()}
            
            elif 'payload:' in line.lower():
                current_pattern['payload_variant'] = line.split(':', 1)[1].strip()
                
            elif 'confidence:' in line.lower():
                try:
                    confidence = float(line.split(':', 1)[1].strip())
                    current_pattern['confidence'] = confidence
                except:
                    current_pattern['confidence'] = 0.5
        
        if current_pattern:
            patterns.append(current_pattern)
        
        return patterns[:10]  # Limit to 10 patterns
