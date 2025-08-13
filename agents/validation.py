
import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import time
import statistics

from utils.http_client import HTTPClient
from utils.claude_interface import ClaudeInterface

@dataclass
class ValidationMetrics:
    """Container for validation metrics."""
    reproducibility_score: float
    technical_consistency: float
    exploitation_feasibility: float
    impact_potential: float
    overall_confidence: float

class ValidationAgent:
    """
    Validation Agent responsible for rigorous elimination of false positives.
    
    Implements multi-layer validation approach:
    1. Technical Confirmation: Consistent reproduction of discrepancy
    2. Behavior Analysis: Analysis of unique response patterns
    3. Timing Validation: Verification of timeouts and race conditions
    4. Semantic Consistency: Logical validation of observed behavior
    5. Infrastructure Compatibility: Stack compatibility verification
    """
    
    def __init__(self, claude_interface: ClaudeInterface):
        self.claude = claude_interface
        self.http_client = HTTPClient()
        self.logger = logging.getLogger(__name__)
        
        # Validation configuration
        self.confidence_threshold = 0.85
        self.min_reproductions = 3
        self.max_validation_time = 300  # 5 minutes per finding
    
    async def validate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive validation of a potential vulnerability finding.
        
        Args:
            finding: Detection result to validate
            
        Returns:
            Validated result with confidence metrics
        """
        self.logger.info(f"Starting validation for {finding.get('technique', 'unknown')} finding")
        
        start_time = time.time()
        
        try:
            # Layer 1: Technical Confirmation
            technical_result = await self._technical_confirmation(finding)
            
            # Layer 2: Behavior Analysis
            behavior_result = await self._behavior_analysis(finding, technical_result)
            
            # Layer 3: Timing Validation
            timing_result = await self._timing_validation(finding)
            
            # Layer 4: Semantic Consistency
            semantic_result = await self._semantic_consistency_check(finding, technical_result)
            
            # Layer 5: Infrastructure Compatibility
            infrastructure_result = await self._infrastructure_compatibility(finding)
            
            # Calculate overall validation metrics
            metrics = self._calculate_validation_metrics(
                technical_result, behavior_result, timing_result,
                semantic_result, infrastructure_result
            )
            
            # AI-powered validation analysis
            ai_validation = await self._ai_validation_analysis(finding, {
                'technical': technical_result,
                'behavior': behavior_result,
                'timing': timing_result,
                'semantic': semantic_result,
                'infrastructure': infrastructure_result,
                'metrics': metrics
            })
            
            validation_time = time.time() - start_time
            
            return {
                'finding_id': finding.get('id', 'unknown'),
                'original_finding': finding,
                'validation_layers': {
                    'technical_confirmation': technical_result,
                    'behavior_analysis': behavior_result,
                    'timing_validation': timing_result,
                    'semantic_consistency': semantic_result,
                    'infrastructure_compatibility': infrastructure_result
                },
                'metrics': metrics.__dict__,
                'confidence_score': metrics.overall_confidence,
                'validation_passed': metrics.overall_confidence >= self.confidence_threshold,
                'ai_validation': ai_validation,
                'validation_time': validation_time,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Validation failed for finding: {e}")
            return {
                'finding_id': finding.get('id', 'unknown'),
                'validation_passed': False,
                'confidence_score': 0.0,
                'error': str(e),
                'timestamp': time.time()
            }
    
    async def _technical_confirmation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Layer 1: Technical confirmation through reproduction."""
        self.logger.debug("Performing technical confirmation")
        
        technique = finding.get('technique')
        payload = finding.get('payload_used', '')
        target_url = finding.get('target_url', '')
        evidence = finding.get('evidence', {})
        
        reproduction_results = []
        
        # Attempt to reproduce the finding multiple times
        for attempt in range(self.min_reproductions):
            try:
                result = await self._reproduce_finding(target_url, technique, payload, evidence)
                reproduction_results.append(result)
                
                # Add small delay between attempts
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.logger.warning(f"Reproduction attempt {attempt + 1} failed: {e}")
                reproduction_results.append({
                    'success': False,
                    'error': str(e),
                    'attempt': attempt + 1
                })
        
        # Calculate reproduction statistics
        successful_reproductions = sum(1 for r in reproduction_results if r.get('success', False))
        reproduction_rate = successful_reproductions / len(reproduction_results)
        
        # Analyze consistency of successful reproductions
        consistency_score = 0.0
        if successful_reproductions > 0:
            consistency_score = await self._analyze_reproduction_consistency(
                [r for r in reproduction_results if r.get('success', False)]
            )
        
        return {
            'reproduction_attempts': len(reproduction_results),
            'successful_reproductions': successful_reproductions,
            'reproduction_rate': reproduction_rate,
            'consistency_score': consistency_score,
            'reproduction_results': reproduction_results,
            'technical_confidence': min(reproduction_rate + consistency_score * 0.5, 1.0)
        }
    
    async def _reproduce_finding(self, url: str, technique: str, payload: str, evidence: Dict) -> Dict[str, Any]:
        """Attempt to reproduce a specific finding."""
        
        try:
            # Parse the original payload to reconstruct the request
            if 'headers' in evidence or payload.startswith('{'):
                # Header-based technique
                import json
                try:
                    headers = json.loads(payload) if payload.startswith('{') else evidence.get('headers_sent', {})
                except:
                    headers = {}
                
                response = await self.http_client.request(
                    method="POST",
                    url=url,
                    headers=headers,
                    data=""
                )
                
            else:
                # Path-based or other technique
                response = await self.http_client.get(url)
            
            # Analyze response for vulnerability indicators
            vulnerability_confirmed = await self._check_vulnerability_indicators(
                response, technique, evidence
            )
            
            return {
                'success': vulnerability_confirmed,
                'response_status': response.status,
                'response_headers': dict(response.headers),
                'response_time': getattr(response, 'response_time', 0),
                'vulnerability_confirmed': vulnerability_confirmed,
                'timestamp': time.time()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    async def _check_vulnerability_indicators(self, response, technique: str, original_evidence: Dict) -> bool:
        """Check if response indicates vulnerability presence."""
        
        # Compare with original evidence
        original_status = original_evidence.get('response_status', 0)
        status_match = abs(response.status - original_status) <= 1  # Allow small variation
        
        # Check response time patterns
        original_time = original_evidence.get('response_time', 0)
        current_time = getattr(response, 'response_time', 0)
        
        # For timing-based vulnerabilities
        if technique in ['expect_vanilla', 'expect_obfuscated']:
            timing_consistent = abs(current_time - original_time) < 2.0
        else:
            timing_consistent = True
        
        # Check for specific vulnerability indicators based on technique
        if technique == 'vh_hv':
            # V-H/H-V discrepancy should show consistent abnormal behavior
            return status_match and timing_consistent
        
        elif technique in ['expect_vanilla', 'expect_obfuscated']:
            # Expect-based should show 100-continue or specific errors
            expect_indicators = (
                response.status == 100 or
                response.status in [400, 417] or
                timing_consistent
            )
            return expect_indicators
        
        elif technique == '0_cl':
            # 0.CL should show fast responses or specific status codes
            early_response = (
                current_time < 1.0 and 
                response.status in [200, 301, 302, 400, 404]
            )
            return early_response
        
        else:
            # Default: status code and timing consistency
            return status_match and timing_consistent
    
    async def _analyze_reproduction_consistency(self, successful_results: List[Dict]) -> float:
        """Analyze consistency across successful reproductions."""
        
        if len(successful_results) < 2:
            return 0.5  # Can't analyze consistency with less than 2 results
        
        # Extract response characteristics
        status_codes = [r.get('response_status', 0) for r in successful_results]
        response_times = [r.get('response_time', 0) for r in successful_results]
        
        # Calculate consistency scores
        status_consistency = 1.0 if len(set(status_codes)) == 1 else 0.5
        
        # Response time consistency (coefficient of variation)
        if len(response_times) > 1 and statistics.mean(response_times) > 0:
            cv = statistics.stdev(response_times) / statistics.mean(response_times)
            time_consistency = max(0, 1.0 - cv)  # Lower CV = higher consistency
        else:
            time_consistency = 0.5
        
        # Overall consistency
        overall_consistency = (status_consistency + time_consistency) / 2
        
        return min(overall_consistency, 1.0)
    
    async def _behavior_analysis(self, finding: Dict, technical_result: Dict) -> Dict[str, Any]:
        """Layer 2: Analyze unique response patterns and behaviors."""
        self.logger.debug("Performing behavior analysis")
        
        target_url = finding.get('target_url', '')
        technique = finding.get('technique', '')
        
        # Analyze response patterns from technical confirmation
        successful_reproductions = [
            r for r in technical_result.get('reproduction_results', [])
            if r.get('success', False)
        ]
        
        if not successful_reproductions:
            return {
                'pattern_analysis': {},
                'unique_behaviors': [],
                'behavior_confidence': 0.0
            }
        
        # Pattern analysis
        pattern_analysis = await self._analyze_response_patterns(successful_reproductions)
        
        # Test for unique behaviors specific to the technique
        unique_behaviors = await self._test_unique_behaviors(target_url, technique)
        
        # Calculate behavior confidence
        behavior_confidence = self._calculate_behavior_confidence(
            pattern_analysis, unique_behaviors
        )
        
        return {
            'pattern_analysis': pattern_analysis,
            'unique_behaviors': unique_behaviors,
            'behavior_confidence': behavior_confidence,
            'analysis_timestamp': time.time()
        }
    
    async def _analyze_response_patterns(self, reproductions: List[Dict]) -> Dict[str, Any]:
        """Analyze patterns in response characteristics."""
        
        # Extract patterns
        status_patterns = {}
        timing_patterns = []
        header_patterns = {}
        
        for repro in reproductions:
            status = repro.get('response_status', 0)
            status_patterns[status] = status_patterns.get(status, 0) + 1
            
            timing = repro.get('response_time', 0)
            timing_patterns.append(timing)
            
            headers = repro.get('response_headers', {})
            for header, value in headers.items():
                if header not in header_patterns:
                    header_patterns[header] = []
                header_patterns[header].append(value)
        
        # Calculate pattern consistency
        dominant_status = max(status_patterns, key=status_patterns.get) if status_patterns else 0
        status_consistency = status_patterns.get(dominant_status, 0) / len(reproductions)
        
        timing_consistency = 1.0 - (statistics.stdev(timing_patterns) / max(statistics.mean(timing_patterns), 0.1))
        timing_consistency = max(0, min(timing_consistency, 1.0))
        
        return {
            'status_patterns': status_patterns,
            'dominant_status': dominant_status,
            'status_consistency': status_consistency,
            'timing_mean': statistics.mean(timing_patterns),
            'timing_stdev': statistics.stdev(timing_patterns) if len(timing_patterns) > 1 else 0,
            'timing_consistency': timing_consistency,
            'header_patterns': header_patterns
        }
    
    async def _test_unique_behaviors(self, url: str, technique: str) -> List[Dict[str, Any]]:
        """Test for behaviors unique to the specific vulnerability technique."""
        
        unique_behaviors = []
        
        if technique in ['expect_vanilla', 'expect_obfuscated']:
            # Test for 100-continue handling
            behavior = await self._test_expect_behavior(url)
            if behavior['unique']:
                unique_behaviors.append(behavior)
        
        elif technique == 'vh_hv':
            # Test for header parsing discrepancies
            behavior = await self._test_header_discrepancy_behavior(url)
            if behavior['unique']:
                unique_behaviors.append(behavior)
        
        elif technique == '0_cl':
            # Test for early response patterns
            behavior = await self._test_early_response_behavior(url)
            if behavior['unique']:
                unique_behaviors.append(behavior)
        
        return unique_behaviors
    
    async def _test_expect_behavior(self, url: str) -> Dict[str, Any]:
        """Test for unique Expect header handling behavior."""
        
        try:
            # Test with valid Expect header
            valid_response = await self.http_client.request(
                method="POST",
                url=url,
                headers={"Expect": "100-continue", "Content-Length": "0"},
                data=""
            )
            
            # Test with invalid Expect header
            invalid_response = await self.http_client.request(
                method="POST", 
                url=url,
                headers={"Expect": "invalid-value", "Content-Length": "0"},
                data=""
            )
            
            # Analyze behavior difference
            status_difference = abs(valid_response.status - invalid_response.status)
            unique_behavior = (
                status_difference > 0 or
                valid_response.status == 100 or
                invalid_response.status in [400, 417]
            )
            
            return {
                'test_type': 'expect_behavior',
                'unique': unique_behavior,
                'valid_response_status': valid_response.status,
                'invalid_response_status': invalid_response.status,
                'status_difference': status_difference,
                'confidence': 0.8 if unique_behavior else 0.2
            }
            
        except Exception as e:
            return {
                'test_type': 'expect_behavior',
                'unique': False,
                'error': str(e),
                'confidence': 0.0
            }
    
    async def _test_header_discrepancy_behavior(self, url: str) -> Dict[str, Any]:
        """Test for header parsing discrepancy behavior."""
        
        try:
            # Test with normal headers
            normal_response = await self.http_client.get(url)
            
            # Test with malformed Content-Length
            malformed_response = await self.http_client.request(
                method="GET",
                url=url,
                headers={" Content-Length": "0"}  # Leading space
            )
            
            # Analyze discrepancy
            status_difference = abs(normal_response.status - malformed_response.status)
            content_difference = len(await normal_response.text()) != len(await malformed_response.text())
            
            unique_behavior = status_difference > 0 or content_difference
            
            return {
                'test_type': 'header_discrepancy',
                'unique': unique_behavior,
                'normal_status': normal_response.status,
                'malformed_status': malformed_response.status,
                'status_difference': status_difference,
                'content_difference': content_difference,
                'confidence': 0.7 if unique_behavior else 0.3
            }
            
        except Exception as e:
            return {
                'test_type': 'header_discrepancy',
                'unique': False,
                'error': str(e),
                'confidence': 0.0
            }
    
    async def _test_early_response_behavior(self, url: str) -> Dict[str, Any]:
        """Test for early response behavior patterns."""
        
        try:
            # Test normal endpoint
            normal_response = await self.http_client.get(url)
            normal_time = getattr(normal_response, 'response_time', 1.0)
            
            # Test potential early response endpoint
            early_url = url.rstrip('/') + '/nonexistent'
            early_response = await self.http_client.get(early_url)
            early_time = getattr(early_response, 'response_time', 1.0)
            
            # Check for early response pattern
            significantly_faster = early_time < (normal_time * 0.5)
            expected_error_status = early_response.status in [400, 404, 405]
            
            unique_behavior = significantly_faster and expected_error_status
            
            return {
                'test_type': 'early_response',
                'unique': unique_behavior,
                'normal_time': normal_time,
                'early_time': early_time,
                'time_ratio': early_time / max(normal_time, 0.1),
                'early_status': early_response.status,
                'confidence': 0.6 if unique_behavior else 0.4
            }
            
        except Exception as e:
            return {
                'test_type': 'early_response',
                'unique': False,
                'error': str(e),
                'confidence': 0.0
            }
    
    def _calculate_behavior_confidence(self, pattern_analysis: Dict, unique_behaviors: List[Dict]) -> float:
        """Calculate overall behavior confidence score."""
        
        # Pattern consistency contributes to confidence
        pattern_score = (
            pattern_analysis.get('status_consistency', 0) * 0.4 +
            pattern_analysis.get('timing_consistency', 0) * 0.3
        )
        
        # Unique behaviors contribute to confidence
        unique_score = 0.0
        if unique_behaviors:
            behavior_scores = [b.get('confidence', 0) for b in unique_behaviors]
            unique_score = max(behavior_scores) * 0.3  # Take best unique behavior
        
        return min(pattern_score + unique_score, 1.0)
    
    async def _timing_validation(self, finding: Dict) -> Dict[str, Any]:
        """Layer 3: Validate timing characteristics and race conditions."""
        self.logger.debug("Performing timing validation")
        
        target_url = finding.get('target_url', '')
        technique = finding.get('technique', '')
        
        # Collect baseline timing measurements
        baseline_times = await self._collect_baseline_timings(target_url)
        
        # Test timing under different conditions
        timing_tests = await self._perform_timing_tests(target_url, technique, finding)
        
        # Analyze timing patterns
        timing_analysis = self._analyze_timing_patterns(baseline_times, timing_tests)
        
        return {
            'baseline_timings': baseline_times,
            'timing_tests': timing_tests,
            'timing_analysis': timing_analysis,
            'timing_confidence': timing_analysis.get('confidence', 0.0)
        }
    
    async def _collect_baseline_timings(self, url: str, samples: int = 5) -> Dict[str, Any]:
        """Collect baseline timing measurements."""
        
        timing_samples = []
        
        for _ in range(samples):
            try:
                start_time = time.time()
                response = await self.http_client.get(url)
                end_time = time.time()
                
                timing_samples.append({
                    'response_time': end_time - start_time,
                    'status_code': response.status,
                    'timestamp': start_time
                })
                
                await asyncio.sleep(0.1)  # Small delay between samples
                
            except Exception as e:
                timing_samples.append({
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        # Calculate statistics
        valid_times = [s['response_time'] for s in timing_samples if 'response_time' in s]
        
        if valid_times:
            return {
                'samples': timing_samples,
                'mean': statistics.mean(valid_times),
                'stdev': statistics.stdev(valid_times) if len(valid_times) > 1 else 0,
                'min': min(valid_times),
                'max': max(valid_times),
                'count': len(valid_times)
            }
        else:
            return {
                'samples': timing_samples,
                'mean': 0,
                'stdev': 0,
                'min': 0,
                'max': 0,
                'count': 0
            }
    
    async def _perform_timing_tests(self, url: str, technique: str, finding: Dict) -> List[Dict]:
        """Perform technique-specific timing tests."""
        
        tests = []
        
        # Test concurrent requests
        concurrent_test = await self._test_concurrent_timing(url, technique)
        tests.append(concurrent_test)
        
        # Test under load
        load_test = await self._test_load_timing(url, technique)
        tests.append(load_test)
        
        # Test with delays
        delay_test = await self._test_delay_timing(url, technique)
        tests.append(delay_test)
        
        return tests
    
    async def _test_concurrent_timing(self, url: str, technique: str) -> Dict[str, Any]:
        """Test timing behavior under concurrent requests."""
        
        try:
            # Send multiple concurrent requests
            tasks = []
            for _ in range(5):
                task = self.http_client.get(url)
                tasks.append(task)
            
            start_time = time.time()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            total_time = time.time() - start_time
            
            # Analyze concurrent behavior
            successful_responses = [r for r in responses if not isinstance(r, Exception)]
            response_times = [getattr(r, 'response_time', 0) for r in successful_responses]
            
            return {
                'test_type': 'concurrent',
                'total_time': total_time,
                'successful_requests': len(successful_responses),
                'response_times': response_times,
                'mean_response_time': statistics.mean(response_times) if response_times else 0,
                'timing_variance': statistics.variance(response_times) if len(response_times) > 1 else 0
            }
            
        except Exception as e:
            return {
                'test_type': 'concurrent',
                'error': str(e)
            }
    
    async def _test_load_timing(self, url: str, technique: str) -> Dict[str, Any]:
        """Test timing behavior under increased load."""
        
        try:
            # Send rapid sequential requests
            response_times = []
            
            for i in range(10):
                start_time = time.time()
                response = await self.http_client.get(url)
                end_time = time.time()
                
                response_times.append({
                    'sequence': i,
                    'response_time': end_time - start_time,
                    'status': response.status
                })
                
                # No delay for load testing
            
            return {
                'test_type': 'load',
                'request_count': len(response_times),
                'response_times': response_times,
                'timing_trend': self._analyze_timing_trend(response_times)
            }
            
        except Exception as e:
            return {
                'test_type': 'load',
                'error': str(e)
            }
    
    async def _test_delay_timing(self, url: str, technique: str) -> Dict[str, Any]:
        """Test timing behavior with intentional delays."""
        
        try:
            # Test with different delay intervals
            delay_results = []
            
            for delay in [0.1, 0.5, 1.0, 2.0]:
                start_time = time.time()
                response = await self.http_client.get(url)
                end_time = time.time()
                
                delay_results.append({
                    'delay': delay,
                    'response_time': end_time - start_time,
                    'status': response.status
                })
                
                await asyncio.sleep(delay)
            
            return {
                'test_type': 'delay',
                'delay_results': delay_results,
                'delay_impact': self._analyze_delay_impact(delay_results)
            }
            
        except Exception as e:
            return {
                'test_type': 'delay',
                'error': str(e)
            }
    
    def _analyze_timing_trend(self, response_times: List[Dict]) -> Dict[str, Any]:
        """Analyze timing trends in sequential requests."""
        
        times = [rt['response_time'] for rt in response_times]
        
        if len(times) < 3:
            return {'trend': 'insufficient_data'}
        
        # Simple linear trend analysis
        x = list(range(len(times)))
        n = len(times)
        
        sum_x = sum(x)
        sum_y = sum(times)
        sum_xy = sum(x[i] * times[i] for i in range(n))
        sum_x2 = sum(xi * xi for xi in x)
        
        if n * sum_x2 - sum_x * sum_x == 0:
            slope = 0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        
        if slope > 0.01:
            trend = 'increasing'
        elif slope < -0.01:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'slope': slope,
            'correlation': abs(slope) > 0.01
        }
    
    def _analyze_delay_impact(self, delay_results: List[Dict]) -> Dict[str, Any]:
        """Analyze impact of delays on response behavior."""
        
        response_times = [dr['response_time'] for dr in delay_results]
        delays = [dr['delay'] for dr in delay_results]
        
        # Check if response times increase with delays (expected behavior)
        time_increases_with_delay = all(
            response_times[i] >= response_times[i-1] * 0.9  # Allow some variance
            for i in range(1, len(response_times))
        )
        
        return {
            'normal_delay_behavior': time_increases_with_delay,
            'response_time_range': max(response_times) - min(response_times),
            'delay_sensitivity': max(response_times) / min(response_times) if min(response_times) > 0 else 1.0
        }
    
    def _analyze_timing_patterns(self, baseline: Dict, tests: List[Dict]) -> Dict[str, Any]:
        """Analyze overall timing patterns for validation."""
        
        baseline_mean = baseline.get('mean', 1.0)
        baseline_stdev = baseline.get('stdev', 0.1)
        
        # Analyze each test type
        analysis = {}
        
        for test in tests:
            test_type = test.get('test_type', 'unknown')
            
            if test_type == 'concurrent':
                test_mean = test.get('mean_response_time', baseline_mean)
                timing_anomaly = abs(test_mean - baseline_mean) > (2 * baseline_stdev)
                analysis[test_type] = {
                    'anomaly_detected': timing_anomaly,
                    'deviation_factor': abs(test_mean - baseline_mean) / max(baseline_stdev, 0.1)
                }
            
            elif test_type == 'load':
                trend = test.get('timing_trend', {})
                analysis[test_type] = {
                    'performance_degradation': trend.get('trend') == 'increasing',
                    'stable_performance': trend.get('trend') == 'stable'
                }
            
            elif test_type == 'delay':
                delay_impact = test.get('delay_impact', {})
                analysis[test_type] = {
                    'normal_behavior': delay_impact.get('normal_delay_behavior', True),
                    'delay_sensitivity': delay_impact.get('delay_sensitivity', 1.0)
                }
        
        # Calculate overall timing confidence
        anomaly_count = sum(1 for a in analysis.values() if a.get('anomaly_detected', False))
        normal_behavior_count = sum(1 for a in analysis.values() if a.get('normal_behavior', True))
        
        timing_confidence = (normal_behavior_count - anomaly_count) / max(len(analysis), 1)
        timing_confidence = max(0, min(timing_confidence, 1.0))
        
        return {
            'test_analysis': analysis,
            'confidence': timing_confidence,
            'anomalies_detected': anomaly_count,
            'normal_behaviors': normal_behavior_count
        }
    
    async def _semantic_consistency_check(self, finding: Dict, technical_result: Dict) -> Dict[str, Any]:
        """Layer 4: Validate logical consistency of observed behavior."""
        self.logger.debug("Performing semantic consistency check")
        
        technique = finding.get('technique', '')
        evidence = finding.get('evidence', {})
        
        # Check technique-specific semantic consistency
        if technique in ['expect_vanilla', 'expect_obfuscated']:
            consistency = await self._check_expect_semantic_consistency(finding, technical_result)
        elif technique == 'vh_hv':
            consistency = await self._check_header_semantic_consistency(finding, technical_result)
        elif technique == '0_cl':
            consistency = await self._check_zero_cl_semantic_consistency(finding, technical_result)
        else:
            consistency = await self._check_generic_semantic_consistency(finding, technical_result)
        
        return consistency
    
    async def _check_expect_semantic_consistency(self, finding: Dict, technical_result: Dict) -> Dict[str, Any]:
        """Check semantic consistency for Expect-based vulnerabilities."""
        
        evidence = finding.get('evidence', {})
        reproductions = technical_result.get('reproduction_results', [])
        
        # Expect-based vulnerabilities should show specific patterns
        expected_behaviors = [
            'status_100_continue',  # Server sends 100-continue
            'status_417_expectation_failed',  # Server rejects expectation
            'status_400_bad_request',  # Server confused by malformed Expect
            'timing_anomaly'  # Unusual timing due to server confusion
        ]
        
        observed_behaviors = []
        
        for repro in reproductions:
            if not repro.get('success'):
                continue
                
            status = repro.get('response_status', 0)
            timing = repro.get('response_time', 0)
            
            if status == 100:
                observed_behaviors.append('status_100_continue')
            elif status == 417:
                observed_behaviors.append('status_417_expectation_failed')
            elif status == 400:
                observed_behaviors.append('status_400_bad_request')
            
            if timing > 5.0 or timing < 0.1:
                observed_behaviors.append('timing_anomaly')
        
        # Calculate semantic consistency
        matching_behaviors = set(expected_behaviors) & set(observed_behaviors)
        consistency_score = len(matching_behaviors) / len(expected_behaviors)
        
        return {
            'check_type': 'expect_semantic',
            'expected_behaviors': expected_behaviors,
            'observed_behaviors': list(set(observed_behaviors)),
            'matching_behaviors': list(matching_behaviors),
            'consistency_score': consistency_score,
            'semantically_consistent': consistency_score >= 0.5
        }
    
    async def _check_header_semantic_consistency(self, finding: Dict, technical_result: Dict) -> Dict[str, Any]:
        """Check semantic consistency for header-based vulnerabilities."""
        
        # Header vulnerabilities should show parser discrepancies
        expected_behaviors = [
            'status_code_difference',  # Different status codes
            'content_length_difference',  # Different content lengths
            'header_parsing_difference',  # Different header interpretation
            'response_consistency'  # Consistent discrepant behavior
        ]
        
        observed_behaviors = []
        reproductions = technical_result.get('reproduction_results', [])
        
        # Analyze reproduction consistency
        if len(reproductions) > 1:
            statuses = [r.get('response_status', 0) for r in reproductions if r.get('success')]
            if len(set(statuses)) > 1:
                observed_behaviors.append('status_code_difference')
            elif len(set(statuses)) == 1 and statuses:
                observed_behaviors.append('response_consistency')
        
        # Check against normal behavior (this would be more sophisticated in practice)
        observed_behaviors.append('header_parsing_difference')
        
        matching_behaviors = set(expected_behaviors) & set(observed_behaviors)
        consistency_score = len(matching_behaviors) / len(expected_behaviors)
        
        return {
            'check_type': 'header_semantic',
            'expected_behaviors': expected_behaviors,
            'observed_behaviors': observed_behaviors,
            'matching_behaviors': list(matching_behaviors),
            'consistency_score': consistency_score,
            'semantically_consistent': consistency_score >= 0.4
        }
    
    async def _check_zero_cl_semantic_consistency(self, finding: Dict, technical_result: Dict) -> Dict[str, Any]:
        """Check semantic consistency for 0.CL desync vulnerabilities."""
        
        expected_behaviors = [
            'fast_response_time',  # Early response gadgets respond quickly
            'appropriate_status_code',  # Expected status codes for gadgets
            'minimal_content',  # Early responses have minimal content
            'consistent_behavior'  # Consistent across reproductions
        ]
        
        observed_behaviors = []
        reproductions = technical_result.get('reproduction_results', [])
        
        for repro in reproductions:
            if not repro.get('success'):
                continue
                
            timing = repro.get('response_time', 1.0)
            status = repro.get('response_status', 0)
            
            if timing < 1.0:
                observed_behaviors.append('fast_response_time')
            
            if status in [200, 301, 302, 400, 404, 405]:
                observed_behaviors.append('appropriate_status_code')
            
            # Assume minimal content for early responses (would check actual content)
            observed_behaviors.append('minimal_content')
        
        if len(reproductions) > 1:
            observed_behaviors.append('consistent_behavior')
        
        matching_behaviors = set(expected_behaviors) & set(observed_behaviors)
        consistency_score = len(matching_behaviors) / len(expected_behaviors)
        
        return {
            'check_type': 'zero_cl_semantic',
            'expected_behaviors': expected_behaviors,
            'observed_behaviors': list(set(observed_behaviors)),
            'matching_behaviors': list(matching_behaviors),
            'consistency_score': consistency_score,
            'semantically_consistent': consistency_score >= 0.6
        }
    
    async def _check_generic_semantic_consistency(self, finding: Dict, technical_result: Dict) -> Dict[str, Any]:
        """Generic semantic consistency check for unknown techniques."""
        
        reproductions = technical_result.get('reproduction_results', [])
        successful_reproductions = [r for r in reproductions if r.get('success')]
        
        # Basic consistency checks
        consistent_behavior = len(successful_reproductions) >= 2
        reproduction_rate = len(successful_reproductions) / max(len(reproductions), 1)
        
        consistency_score = reproduction_rate * 0.8 + (0.2 if consistent_behavior else 0)
        
        return {
            'check_type': 'generic_semantic',
            'successful_reproductions': len(successful_reproductions),
            'total_attempts': len(reproductions),
            'reproduction_rate': reproduction_rate,
            'consistency_score': consistency_score,
            'semantically_consistent': consistency_score >= 0.5
        }
    
    async def _infrastructure_compatibility(self, finding: Dict) -> Dict[str, Any]:
        """Layer 5: Verify compatibility with detected infrastructure."""
        self.logger.debug("Performing infrastructure compatibility check")
        
        technique = finding.get('technique', '')
        target_url = finding.get('target_url', '')
        
        # Get infrastructure information (would come from reconnaissance)
        # For now, we'll perform basic compatibility checks
        
        compatibility_checks = []
        
        # Check web server compatibility
        server_compat = await self._check_server_compatibility(target_url, technique)
        compatibility_checks.append(server_compat)
        
        # Check proxy/CDN compatibility
        proxy_compat = await self._check_proxy_compatibility(target_url, technique)
        compatibility_checks.append(proxy_compat)
        
        # Check protocol compatibility
        protocol_compat = await self._check_protocol_compatibility(target_url, technique)
        compatibility_checks.append(protocol_compat)
        
        # Calculate overall compatibility
        compatibility_scores = [c.get('compatibility_score', 0) for c in compatibility_checks]
        overall_compatibility = statistics.mean(compatibility_scores) if compatibility_scores else 0.0
        
        return {
            'compatibility_checks': compatibility_checks,
            'overall_compatibility': overall_compatibility,
            'infrastructure_compatible': overall_compatibility >= 0.6
        }
    
    async def _check_server_compatibility(self, url: str, technique: str) -> Dict[str, Any]:
        """Check web server compatibility with the technique."""
        
        try:
            response = await self.http_client.get(url)
            server_header = response.headers.get('Server', '').lower()
            
            # Technique-specific server compatibility
            if technique in ['expect_vanilla', 'expect_obfuscated']:
                # Most servers support Expect header
                compatibility_score = 0.8
                compatible_servers = ['nginx', 'apache', 'iis']
                
            elif technique == 'vh_hv':
                # Header parsing varies by server
                if 'nginx' in server_header:
                    compatibility_score = 0.9  # Nginx known for parsing issues
                elif 'apache' in server_header:
                    compatibility_score = 0.7  # Apache has some parsing quirks
                else:
                    compatibility_score = 0.5  # Unknown server
                compatible_servers = ['nginx', 'apache']
                
            elif technique == '0_cl':
                # Early response gadgets work on most servers
                compatibility_score = 0.7
                compatible_servers = ['nginx', 'apache', 'iis', 'lighttpd']
                
            else:
                # Generic compatibility
                compatibility_score = 0.5
                compatible_servers = []
            
            # Check if detected server is in compatible list
            server_detected = any(server in server_header for server in compatible_servers)
            if server_detected:
                compatibility_score += 0.2
            
            return {
                'check_type': 'server_compatibility',
                'server_header': server_header,
                'compatible_servers': compatible_servers,
                'server_detected': server_detected,
                'compatibility_score': min(compatibility_score, 1.0)
            }
            
        except Exception as e:
            return {
                'check_type': 'server_compatibility',
                'error': str(e),
                'compatibility_score': 0.3  # Assume partial compatibility
            }
    
    async def _check_proxy_compatibility(self, url: str, technique: str) -> Dict[str, Any]:
        """Check proxy/CDN compatibility with the technique."""
        
        try:
            response = await self.http_client.get(url)
            
            # Look for proxy/CDN indicators
            proxy_headers = [
                'Via', 'X-Forwarded-For', 'X-Real-IP', 'CF-Ray', 
                'X-Cache', 'X-Served-By', 'X-Amz-Cf-Id'
            ]
            
            detected_proxies = []
            for header in proxy_headers:
                if header in response.headers:
                    detected_proxies.append(header)
            
            has_proxy = len(detected_proxies) > 0
            
            # Technique compatibility with proxies
            if technique in ['expect_vanilla', 'expect_obfuscated']:
                # Proxies may interfere with Expect handling
                compatibility_score = 0.6 if has_proxy else 0.8
                
            elif technique == 'vh_hv':
                # Header discrepancies work well with proxies
                compatibility_score = 0.8 if has_proxy else 0.7
                
            elif technique == '0_cl':
                # Early responses may be affected by proxies
                compatibility_score = 0.5 if has_proxy else 0.8
                
            else:
                compatibility_score = 0.6
            
            return {
                'check_type': 'proxy_compatibility',
                'detected_proxy_headers': detected_proxies,
                'has_proxy': has_proxy,
                'compatibility_score': compatibility_score
            }
            
        except Exception as e:
            return {
                'check_type': 'proxy_compatibility',
                'error': str(e),
                'compatibility_score': 0.5
            }
    
    async def _check_protocol_compatibility(self, url: str, technique: str) -> Dict[str, Any]:
        """Check HTTP protocol compatibility with the technique."""
        
        # Determine protocol version (simplified)
        uses_https = url.startswith('https://')
        
        # Most techniques work with both HTTP and HTTPS
        if technique in ['expect_vanilla', 'expect_obfuscated', 'vh_hv', '0_cl']:
            compatibility_score = 0.9  # High compatibility
        else:
            compatibility_score = 0.7  # Good compatibility
        
        return {
            'check_type': 'protocol_compatibility',
            'uses_https': uses_https,
            'protocol_version': 'HTTP/1.1',  # Assumed
            'compatibility_score': compatibility_score
        }
    
    def _calculate_validation_metrics(
        self, 
        technical: Dict, 
        behavior: Dict, 
        timing: Dict, 
        semantic: Dict, 
        infrastructure: Dict
    ) -> ValidationMetrics:
        """Calculate comprehensive validation metrics."""
        
        # Extract scores from each validation layer
        reproducibility_score = technical.get('technical_confidence', 0.0)
        technical_consistency = (
            technical.get('consistency_score', 0.0) * 0.6 +
            timing.get('timing_confidence', 0.0) * 0.4
        )
        exploitation_feasibility = (
            behavior.get('behavior_confidence', 0.0) * 0.5 +
            infrastructure.get('overall_compatibility', 0.0) * 0.5
        )
        impact_potential = semantic.get('consistency_score', 0.0)
        
        # Calculate overall confidence with weighted scoring
        overall_confidence = (
            reproducibility_score * 0.3 +
            technical_consistency * 0.25 +
            exploitation_feasibility * 0.25 +
            impact_potential * 0.2
        )
        
        return ValidationMetrics(
            reproducibility_score=reproducibility_score,
            technical_consistency=technical_consistency,
            exploitation_feasibility=exploitation_feasibility,
            impact_potential=impact_potential,
            overall_confidence=min(overall_confidence, 1.0)
        )
    
    async def _ai_validation_analysis(self, finding: Dict, validation_data: Dict) -> Dict[str, Any]:
        """Use Claude AI for intelligent validation analysis."""
        
        prompt = f"""
        As a cybersecurity expert specializing in HTTP Request Smuggling, analyze this validation data:
        
        Original Finding:
        - Technique: {finding.get('technique', 'unknown')}
        - Target: {finding.get('target_url', 'unknown')}
        - Evidence: {finding.get('evidence', {})}
        
        Validation Results:
        - Technical Confirmation: {validation_data['technical']}
        - Behavior Analysis: {validation_data['behavior']}
        - Timing Validation: {validation_data['timing']}
        - Semantic Consistency: {validation_data['semantic']}
        - Infrastructure Compatibility: {validation_data['infrastructure']}
        - Overall Metrics: {validation_data['metrics']}
        
        Based on this validation data:
        1. Assess the likelihood this is a genuine vulnerability
        2. Identify any red flags suggesting false positive
        3. Recommend confidence adjustments
        4. Suggest additional validation tests if needed
        5. Estimate exploitability for bug bounty purposes
        
        Provide actionable analysis for bug bounty hunters.
        """
        
        try:
            response = await self.claude.analyze(prompt)
            return {
                'ai_assessment': response.get('analysis', ''),
                'genuine_vulnerability_likelihood': response.get('likelihood', 'unknown'),
                'false_positive_indicators': response.get('false_positive_indicators', []),
                'confidence_adjustment': response.get('confidence_adjustment', 0),
                'additional_tests': response.get('additional_tests', []),
                'exploitability_assessment': response.get('exploitability', 'unknown')
            }
        except Exception as e:
            self.logger.error(f"AI validation analysis failed: {e}")
            return {
                'ai_assessment': 'AI analysis unavailable',
                'genuine_vulnerability_likelihood': 'unknown',
                'false_positive_indicators': [],
                'confidence_adjustment': 0,
                'additional_tests': [],
                'exploitability_assessment': 'unknown'
            }
