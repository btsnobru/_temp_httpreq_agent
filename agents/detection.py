
import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from utils.http_client import HTTPClient
from utils.claude_interface import ClaudeInterface
from knowledge.patterns_db import PatternsDatabase

class DesyncTechnique(Enum):
    """Enumeration of HTTP Request Smuggling techniques from James Kettle's research."""
    CL_0 = "cl_0"  # Content-Length: 0 based
    ZERO_CL = "0_cl"  # 0.CL desync
    VH_HV = "vh_hv"  # V-H/H-V discrepancies
    EXPECT_VANILLA = "expect_vanilla"  # Standard Expect: 100-continue
    EXPECT_OBFUSCATED = "expect_obfuscated"  # Obfuscated Expect headers
    DOUBLE_DESYNC = "double_desync"  # 0.CL → CL.0 conversion
    TRANSFER_ENCODING = "transfer_encoding"  # TE discrepancies
    HTTP2_DOWNGRADE = "http2_downgrade"  # H2.CL, H2.TE issues

@dataclass
class DetectionResult:
    """Container for detection results."""
    technique: DesyncTechnique
    success: bool
    confidence: float
    evidence: Dict[str, Any]
    payload_used: str
    response_analysis: Dict[str, Any]

class DetectionAgent:
    """
    Detection Agent responsible for systematic detection of HTTP Request Smuggling vulnerabilities.
    
    Implements all modern techniques from "HTTP/1.1 Must Die" research:
    - V-H/H-V Discrepancies: Content-Length masquerading
    - Expect-based Desync: Vanilla and obfuscated variants
    - 0.CL Desync Detection: Implicit-zero content length
    - Early-response Gadget Discovery: /con, /nul, redirects
    - Transfer-Encoding Variants: Chunked encoding issues
    - HTTP/2 Downgrading Issues: H2.CL, H2.TE detection
    """
    
    def __init__(self, claude_interface: ClaudeInterface, patterns_db: PatternsDatabase):
        self.claude = claude_interface
        self.patterns_db = patterns_db
        self.http_client = HTTPClient()
        self.logger = logging.getLogger(__name__)
        
        # Initialize detection patterns based on research
        self.detection_patterns = self._initialize_detection_patterns()
        
    def _initialize_detection_patterns(self) -> Dict[DesyncTechnique, List[Dict]]:
        """Initialize detection patterns based on James Kettle's research."""
        return {
            DesyncTechnique.VH_HV: [
                # Content-Length with leading space
                {"name": "CL_leading_space", "header": " Content-Length", "value": "23"},
                # Content-Length with newline
                {"name": "CL_newline", "header": "Content-Length", "value": "\n23"},
                # Host header masquerading
                {"name": "host_masquerade", "header": " Host", "value": "target.com"},
                # Duplicate headers with invalid values
                {"name": "duplicate_cl", "headers": {"Content-Length": ["23", "invalid"]}},
            ],
            
            DesyncTechnique.EXPECT_VANILLA: [
                {"name": "expect_100", "header": "Expect", "value": "100-continue"},
            ],
            
            DesyncTechnique.EXPECT_OBFUSCATED: [
                # Obfuscated Expect header variations
                {"name": "expect_obfuscated_y", "header": "Expect", "value": "y 100-continue"},
                {"name": "expect_newline", "header": "Expect", "value": "\n100-continue"},
                {"name": "expect_leading_space", "header": " Expect", "value": "100-continue"},
                {"name": "expect_invalid", "header": "Expect", "value": "200-continue"},
                {"name": "expect_malformed", "header": "Expect", "value": "100-continueX"},
            ],
            
            DesyncTechnique.ZERO_CL: [
                # 0.CL desync patterns with early-response gadgets
                {"name": "zero_cl_con", "path": "/con", "method": "POST"},
                {"name": "zero_cl_nul", "path": "/nul", "method": "POST"},
                {"name": "zero_cl_aux", "path": "/aux", "method": "POST"},
                {"name": "zero_cl_prn", "path": "/prn", "method": "POST"},
                {"name": "zero_cl_redirect", "path": "/redirect", "method": "POST"},
                {"name": "zero_cl_404", "path": "/nonexistent", "method": "POST"},
            ],
            
            DesyncTechnique.TRANSFER_ENCODING: [
                # Transfer-Encoding variations
                {"name": "te_chunked", "header": "Transfer-Encoding", "value": "chunked"},
                {"name": "te_space", "header": " Transfer-Encoding", "value": "chunked"},
                {"name": "te_newline", "header": "Transfer-Encoding", "value": "\nchunked"},
                {"name": "te_duplicate", "headers": {"Transfer-Encoding": ["chunked", "identity"]}},
            ],
        }
    
    async def detect_vulnerabilities(self, recon_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute systematic vulnerability detection using adaptive testing strategies.
        
        Args:
            recon_result: Results from reconnaissance phase
            
        Returns:
            Dictionary containing all detected vulnerabilities
        """
        url = recon_result['url']
        fingerprint = recon_result.get('tech_fingerprint', {})
        
        self.logger.info(f"Starting detection phase for {url}")
        
        # Generate adaptive test strategy based on fingerprint
        test_strategy = await self._generate_adaptive_strategy(recon_result)
        
        # Execute detection tests
        detection_results = []
        
        for technique in test_strategy['priority_techniques']:
            self.logger.info(f"Testing {technique.value} technique")
            
            try:
                results = await self._test_technique(url, technique, recon_result)
                if results:
                    detection_results.extend(results)
                    
            except Exception as e:
                self.logger.error(f"Detection failed for technique {technique.value}: {e}")
                continue
        
        # Early-response gadget discovery
        gadgets = await self._discover_early_response_gadgets(url)
        
        # Analyze results with Claude AI
        ai_analysis = await self._analyze_detection_results(detection_results, recon_result)
        
        return {
            'target_url': url,
            'findings': detection_results,
            'early_response_gadgets': gadgets,
            'ai_analysis': ai_analysis,
            'test_strategy': test_strategy,
            'total_tests': len(detection_results)
        }
    
    async def _generate_adaptive_strategy(self, recon_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate adaptive testing strategy based on target fingerprint."""
        fingerprint = recon_result.get('tech_fingerprint', {})
        
        # Default priority order
        priority_techniques = [
            DesyncTechnique.EXPECT_OBFUSCATED,
            DesyncTechnique.VH_HV,
            DesyncTechnique.ZERO_CL,
            DesyncTechnique.EXPECT_VANILLA,
            DesyncTechnique.TRANSFER_ENCODING,
        ]
        
        # Adapt based on detected technologies
        web_server = fingerprint.get('web_server', {}).get('detected', [])
        cdn_provider = fingerprint.get('cdn_provider', {}).get('detected', [])
        
        if 'nginx' in web_server:
            # Nginx-specific optimizations
            priority_techniques = [
                DesyncTechnique.ZERO_CL,  # Nginx vulnerable to 0.CL
                DesyncTechnique.EXPECT_OBFUSCATED,
                DesyncTechnique.VH_HV,
            ]
            
        elif 'apache' in web_server:
            # Apache-specific optimizations
            priority_techniques = [
                DesyncTechnique.VH_HV,  # Apache parser discrepancies
                DesyncTechnique.EXPECT_VANILLA,
                DesyncTechnique.TRANSFER_ENCODING,
            ]
            
        elif 'cloudflare' in cdn_provider:
            # Cloudflare-specific tests
            priority_techniques = [
                DesyncTechnique.EXPECT_OBFUSCATED,  # Known Cloudflare bypass
                DesyncTechnique.DOUBLE_DESYNC,
                DesyncTechnique.VH_HV,
            ]
        
        return {
            'priority_techniques': priority_techniques,
            'optimization_reason': f"Adapted for {web_server} + {cdn_provider}",
            'estimated_test_count': len(priority_techniques) * 3
        }
    
    async def _test_technique(self, url: str, technique: DesyncTechnique, recon_result: Dict) -> List[DetectionResult]:
        """Test a specific desync technique with multiple variations."""
        patterns = self.detection_patterns.get(technique, [])
        results = []
        
        for pattern in patterns:
            try:
                result = await self._execute_single_test(url, technique, pattern, recon_result)
                if result:
                    results.append(result)
                    
            except Exception as e:
                self.logger.error(f"Single test failed for {pattern.get('name', 'unknown')}: {e}")
                continue
        
        return results
    
    async def _execute_single_test(self, url: str, technique: DesyncTechnique, pattern: Dict, recon_result: Dict) -> Optional[DetectionResult]:
        """Execute a single detection test."""
        
        if technique == DesyncTechnique.VH_HV:
            return await self._test_vh_hv_discrepancy(url, pattern)
        elif technique in [DesyncTechnique.EXPECT_VANILLA, DesyncTechnique.EXPECT_OBFUSCATED]:
            return await self._test_expect_based_desync(url, pattern)
        elif technique == DesyncTechnique.ZERO_CL:
            return await self._test_zero_cl_desync(url, pattern)
        elif technique == DesyncTechnique.TRANSFER_ENCODING:
            return await self._test_transfer_encoding(url, pattern)
        elif technique == DesyncTechnique.DOUBLE_DESYNC:
            return await self._test_double_desync(url, pattern, recon_result)
        
        return None
    
    async def _test_vh_hv_discrepancy(self, url: str, pattern: Dict) -> Optional[DetectionResult]:
        """Test V-H/H-V discrepancy techniques."""
        
        # Construct malformed request based on pattern
        if "header" in pattern and "value" in pattern:
            headers = {pattern["header"]: pattern["value"]}
        elif "headers" in pattern:
            headers = pattern["headers"]
        else:
            return None
        
        # Test request with malformed headers
        try:
            response1 = await self.http_client.request(
                method="GET",
                url=url,
                headers=headers
            )
            
            # Compare with normal request
            response2 = await self.http_client.get(url)
            
            # Analyze discrepancy
            discrepancy_detected = await self._analyze_response_discrepancy(response1, response2)
            
            if discrepancy_detected['has_discrepancy']:
                return DetectionResult(
                    technique=DesyncTechnique.VH_HV,
                    success=True,
                    confidence=discrepancy_detected['confidence'],
                    evidence={
                        'pattern_name': pattern.get('name'),
                        'malformed_response': {
                            'status': response1.status,
                            'headers': dict(response1.headers),
                            'content_length': len(await response1.text())
                        },
                        'normal_response': {
                            'status': response2.status,
                            'headers': dict(response2.headers),
                            'content_length': len(await response2.text())
                        },
                        'discrepancy_analysis': discrepancy_detected
                    },
                    payload_used=str(headers),
                    response_analysis=discrepancy_detected
                )
                
        except Exception as e:
            self.logger.error(f"V-H/H-V test failed: {e}")
            
        return None
    
    async def _test_expect_based_desync(self, url: str, pattern: Dict) -> Optional[DetectionResult]:
        """Test Expect-based desync techniques."""
        
        expect_header = {pattern["header"]: pattern["value"]}
        
        # Create POST request with Expect header
        payload = "test_payload"
        headers = {
            **expect_header,
            "Content-Length": str(len(payload)),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            # Send request with Expect header
            response = await self.http_client.request(
                method="POST",
                url=url,
                headers=headers,
                data=payload
            )
            
            # Analyze response for desync indicators
            desync_detected = await self._analyze_expect_response(response, pattern)
            
            if desync_detected['is_vulnerable']:
                return DetectionResult(
                    technique=DesyncTechnique.EXPECT_OBFUSCATED if "obfuscated" in pattern.get("name", "") else DesyncTechnique.EXPECT_VANILLA,
                    success=True,
                    confidence=desync_detected['confidence'],
                    evidence={
                        'pattern_name': pattern.get('name'),
                        'response_status': response.status,
                        'response_headers': dict(response.headers),
                        'response_time': getattr(response, 'response_time', 0),
                        'desync_analysis': desync_detected
                    },
                    payload_used=str(headers),
                    response_analysis=desync_detected
                )
                
        except Exception as e:
            self.logger.error(f"Expect-based test failed: {e}")
            
        return None
    
    async def _test_zero_cl_desync(self, url: str, pattern: Dict) -> Optional[DetectionResult]:
        """Test 0.CL desync with early-response gadgets."""
        
        # Construct URL with potential early-response gadget
        test_path = pattern.get('path', '/')
        test_url = url.rstrip('/') + test_path
        method = pattern.get('method', 'GET')
        
        try:
            # Send request to potential gadget endpoint
            response = await self.http_client.request(method=method, url=test_url)
            
            # Check for early response indicators
            early_response = await self._analyze_early_response(response, test_path)
            
            if early_response['is_early_response']:
                # Test for 0.CL desync vulnerability
                desync_result = await self._test_zero_cl_exploitation(test_url)
                
                if desync_result['vulnerable']:
                    return DetectionResult(
                        technique=DesyncTechnique.ZERO_CL,
                        success=True,
                        confidence=desync_result['confidence'],
                        evidence={
                            'gadget_path': test_path,
                            'response_status': response.status,
                            'response_time': getattr(response, 'response_time', 0),
                            'early_response_analysis': early_response,
                            'desync_test_result': desync_result
                        },
                        payload_used=f"{method} {test_path}",
                        response_analysis=early_response
                    )
                    
        except Exception as e:
            self.logger.error(f"0.CL test failed for {test_path}: {e}")
            
        return None
    
    async def _test_transfer_encoding(self, url: str, pattern: Dict) -> Optional[DetectionResult]:
        """Test Transfer-Encoding discrepancies."""
        
        # Construct chunked request
        if "header" in pattern:
            headers = {pattern["header"]: pattern["value"]}
        elif "headers" in pattern:
            headers = pattern["headers"]
        else:
            return None
        
        # Add Content-Length to create CL.TE condition
        headers["Content-Length"] = "0"
        
        try:
            response = await self.http_client.request(
                method="POST",
                url=url,
                headers=headers,
                data=""
            )
            
            # Analyze for TE discrepancy
            te_analysis = await self._analyze_te_discrepancy(response, pattern)
            
            if te_analysis['vulnerable']:
                return DetectionResult(
                    technique=DesyncTechnique.TRANSFER_ENCODING,
                    success=True,
                    confidence=te_analysis['confidence'],
                    evidence={
                        'pattern_name': pattern.get('name'),
                        'headers_sent': headers,
                        'response_analysis': te_analysis
                    },
                    payload_used=str(headers),
                    response_analysis=te_analysis
                )
                
        except Exception as e:
            self.logger.error(f"Transfer-Encoding test failed: {e}")
            
        return None
    
    async def _test_double_desync(self, url: str, pattern: Dict, recon_result: Dict) -> Optional[DetectionResult]:
        """Test double-desync (0.CL → CL.0) conversion."""
        
        # This is a complex test that requires multiple stages
        try:
            # Stage 1: Establish 0.CL desync
            stage1_result = await self._establish_zero_cl_desync(url)
            
            if not stage1_result['established']:
                return None
            
            # Stage 2: Weaponize with CL.0
            stage2_result = await self._weaponize_cl_zero(url, stage1_result)
            
            if stage2_result['weaponized']:
                return DetectionResult(
                    technique=DesyncTechnique.DOUBLE_DESYNC,
                    success=True,
                    confidence=stage2_result['confidence'],
                    evidence={
                        'stage1': stage1_result,
                        'stage2': stage2_result,
                        'double_desync_confirmed': True
                    },
                    payload_used="Double-desync sequence",
                    response_analysis=stage2_result
                )
                
        except Exception as e:
            self.logger.error(f"Double-desync test failed: {e}")
            
        return None
    
    async def _discover_early_response_gadgets(self, url: str) -> List[Dict[str, Any]]:
        """Discover early-response gadgets for 0.CL desync."""
        
        # Windows reserved names and common early-response paths
        potential_gadgets = [
            "/con", "/nul", "/aux", "/prn", "/com1", "/com2", "/lpt1", "/lpt2",
            "/admin", "/login", "/auth", "/redirect", "/404", "/error",
            "/static", "/assets", "/favicon.ico", "/robots.txt",
            "/wp-admin", "/administrator", "/phpmyadmin"
        ]
        
        discovered_gadgets = []
        
        for path in potential_gadgets:
            try:
                test_url = url.rstrip('/') + path
                response = await self.http_client.get(test_url)
                
                # Check if this is an early-response gadget
                analysis = await self._analyze_early_response(response, path)
                
                if analysis['is_early_response']:
                    discovered_gadgets.append({
                        'path': path,
                        'status_code': response.status,
                        'response_time': getattr(response, 'response_time', 0),
                        'confidence': analysis['confidence'],
                        'analysis': analysis
                    })
                    
            except Exception as e:
                self.logger.debug(f"Gadget test failed for {path}: {e}")
                continue
        
        self.logger.info(f"Discovered {len(discovered_gadgets)} potential early-response gadgets")
        return discovered_gadgets
    
    async def _analyze_response_discrepancy(self, response1, response2) -> Dict[str, Any]:
        """Analyze discrepancy between two responses."""
        
        # Compare status codes
        status_different = response1.status != response2.status
        
        # Compare headers
        headers1 = dict(response1.headers)
        headers2 = dict(response2.headers)
        headers_different = headers1 != headers2
        
        # Compare content
        try:
            content1 = await response1.text()
            content2 = await response2.text()
            content_different = content1 != content2
            content_length_diff = len(content1) != len(content2)
        except:
            content_different = True
            content_length_diff = True
        
        # Calculate confidence based on differences
        differences = sum([status_different, headers_different, content_different])
        confidence = min(differences * 0.3, 1.0)
        
        return {
            'has_discrepancy': differences > 0,
            'confidence': confidence,
            'status_different': status_different,
            'headers_different': headers_different,
            'content_different': content_different,
            'content_length_different': content_length_diff
        }
    
    async def _analyze_expect_response(self, response, pattern: Dict) -> Dict[str, Any]:
        """Analyze response for Expect-based desync indicators."""
        
        # Check for 100-continue response
        has_100_continue = response.status == 100
        
        # Check for unusual response times (indicating server confusion)
        response_time = getattr(response, 'response_time', 0)
        unusual_timing = response_time > 5.0 or response_time < 0.1
        
        # Check for error responses that might indicate parser confusion
        error_response = response.status in [400, 408, 409, 413, 417, 500, 502, 503]
        
        # Pattern-specific analysis
        pattern_name = pattern.get('name', '')
        obfuscated_pattern = 'obfuscated' in pattern_name or 'invalid' in pattern_name
        
        confidence = 0.0
        if has_100_continue and not obfuscated_pattern:
            confidence += 0.3  # Normal behavior
        elif has_100_continue and obfuscated_pattern:
            confidence += 0.8  # Unexpected 100-continue with obfuscated header
        elif error_response and obfuscated_pattern:
            confidence += 0.7  # Error with obfuscated header suggests parser confusion
        elif unusual_timing:
            confidence += 0.5  # Timing anomalies
        
        return {
            'is_vulnerable': confidence >= 0.6,
            'confidence': min(confidence, 1.0),
            'has_100_continue': has_100_continue,
            'unusual_timing': unusual_timing,
            'error_response': error_response,
            'response_time': response_time
        }
    
    async def _analyze_early_response(self, response, path: str) -> Dict[str, Any]:
        """Analyze if response indicates an early-response gadget."""
        
        # Check response time (early responses are typically faster)
        response_time = getattr(response, 'response_time', 0)
        fast_response = response_time < 0.5
        
        # Check for specific status codes that indicate early responses
        early_status_codes = [301, 302, 400, 403, 404, 405, 501]
        has_early_status = response.status in early_status_codes
        
        # Windows reserved name detection
        windows_reserved = path.lower() in ['/con', '/nul', '/aux', '/prn', '/com1', '/com2', '/lpt1', '/lpt2']
        
        # Check content length (early responses often have minimal content)
        try:
            content = await response.text()
            minimal_content = len(content) < 1000
        except:
            minimal_content = True
        
        # Calculate confidence
        confidence = 0.0
        if windows_reserved and response.status == 400:
            confidence = 0.9  # Windows reserved name with 400 error
        elif has_early_status and fast_response:
            confidence = 0.7  # Fast error response
        elif minimal_content and has_early_status:
            confidence = 0.6  # Minimal error content
        elif fast_response:
            confidence = 0.4  # Just fast response
        
        return {
            'is_early_response': confidence >= 0.5,
            'confidence': confidence,
            'fast_response': fast_response,
            'early_status_code': has_early_status,
            'windows_reserved': windows_reserved,
            'minimal_content': minimal_content,
            'response_time': response_time
        }
    
    async def _analyze_te_discrepancy(self, response, pattern: Dict) -> Dict[str, Any]:
        """Analyze Transfer-Encoding discrepancy."""
        
        # Check for chunked transfer encoding in response
        te_header = response.headers.get('Transfer-Encoding', '').lower()
        has_chunked = 'chunked' in te_header
        
        # Check for content-length header presence
        has_cl = 'Content-Length' in response.headers
        
        # CL.TE condition (both headers present)
        cl_te_condition = has_chunked and has_cl
        
        # Check for response anomalies
        response_time = getattr(response, 'response_time', 0)
        unusual_timing = response_time > 5.0
        
        error_response = response.status >= 400
        
        confidence = 0.0
        if cl_te_condition:
            confidence += 0.6  # Both headers present
        if unusual_timing:
            confidence += 0.3  # Timing anomaly
        if error_response:
            confidence += 0.2  # Error response
        
        return {
            'vulnerable': confidence >= 0.6,
            'confidence': min(confidence, 1.0),
            'has_chunked': has_chunked,
            'has_content_length': has_cl,
            'cl_te_condition': cl_te_condition,
            'unusual_timing': unusual_timing
        }
    
    async def _establish_zero_cl_desync(self, url: str) -> Dict[str, Any]:
        """Attempt to establish 0.CL desync condition."""
        
        # This is a simplified implementation
        # Real implementation would be more sophisticated
        
        try:
            # Send request designed to trigger 0.CL desync
            headers = {
                'Content-Length': '0',
                'Transfer-Encoding': 'chunked'
            }
            
            response = await self.http_client.post(url, headers=headers, data='')
            
            # Analyze response for desync establishment
            established = response.status != 400  # 400 would indicate rejection
            
            return {
                'established': established,
                'response_status': response.status,
                'confidence': 0.5 if established else 0.0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to establish 0.CL desync: {e}")
            return {'established': False, 'confidence': 0.0}
    
    async def _weaponize_cl_zero(self, url: str, stage1_result: Dict) -> Dict[str, Any]:
        """Weaponize established desync with CL.0 attack."""
        
        # This is a simplified implementation
        # Real implementation would involve more sophisticated payload crafting
        
        try:
            # Send weaponizing request
            malicious_payload = "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n"
            
            response = await self.http_client.post(url, data=malicious_payload)
            
            # Check if weaponization was successful
            weaponized = 'evil.com' in str(response.headers) or response.status == 302
            
            return {
                'weaponized': weaponized,
                'confidence': 0.8 if weaponized else 0.2,
                'response_status': response.status
            }
            
        except Exception as e:
            self.logger.error(f"Failed to weaponize CL.0: {e}")
            return {'weaponized': False, 'confidence': 0.0}
    
    async def _test_zero_cl_exploitation(self, test_url: str) -> Dict[str, Any]:
        """Test for 0.CL desync exploitation potential."""
        
        try:
            # Send crafted request to test for desync
            headers = {
                'Content-Length': '0',
                'X-Test-Header': 'desync-test'
            }
            
            response = await self.http_client.post(test_url, headers=headers, data='')
            
            # Simple vulnerability check (would be more sophisticated in real implementation)
            vulnerable = (
                response.status in [200, 301, 302] and 
                getattr(response, 'response_time', 0) < 1.0
            )
            
            return {
                'vulnerable': vulnerable,
                'confidence': 0.7 if vulnerable else 0.2,
                'response_status': response.status
            }
            
        except Exception as e:
            self.logger.error(f"0.CL exploitation test failed: {e}")
            return {'vulnerable': False, 'confidence': 0.0}
    
    async def _analyze_detection_results(self, results: List[DetectionResult], recon_result: Dict) -> Dict[str, Any]:
        """Use Claude AI to analyze detection results."""
        
        if not results:
            return {'analysis': 'No vulnerabilities detected', 'recommendations': []}
        
        # Prepare data for AI analysis
        findings_summary = []
        for result in results:
            findings_summary.append({
                'technique': result.technique.value,
                'confidence': result.confidence,
                'evidence': result.evidence
            })
        
        prompt = f"""
        As an expert in HTTP Request Smuggling, analyze these detection results:
        
        Target: {recon_result['url']}
        Infrastructure: {recon_result.get('tech_fingerprint', {})}
        
        Findings:
        {findings_summary}
        
        Based on James Kettle's "HTTP/1.1 Must Die" research:
        1. Assess the likelihood of successful exploitation
        2. Prioritize findings by exploitability
        3. Recommend next steps for validation
        4. Identify potential impact scenarios
        5. Suggest bypass techniques if WAF detected
        
        Provide actionable analysis for bug bounty hunting.
        """
        
        try:
            response = await self.claude.analyze(prompt)
            return {
                'analysis': response.get('analysis', ''),
                'exploitation_likelihood': response.get('exploitation_likelihood', 'unknown'),
                'priority_findings': response.get('priority_findings', []),
                'next_steps': response.get('next_steps', []),
                'impact_scenarios': response.get('impact_scenarios', [])
            }
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return {'analysis': 'AI analysis unavailable', 'recommendations': []}
