
import asyncio
import logging
from typing import Dict, List, Any, Optional
import re

from utils.http_client import HTTPClient
from utils.claude_interface import ClaudeInterface
from knowledge.patterns_db import PatternsDatabase
from knowledge.fingerprints import FingerprintAnalyzer

class ReconnaissanceAgent:
    """
    Reconnaissance Agent responsible for complete HTTP infrastructure mapping.
    
    Implements comprehensive target analysis including:
    - Front-end/back-end server identification
    - CDN detection (Cloudflare, Akamai, Fastly, etc.)
    - Technology fingerprinting (nginx, Apache, IIS)
    - Header analysis for revealing information
    - Proxy/load balancer architecture mapping
    - WAF detection and configuration analysis
    """
    
    def __init__(self, claude_interface: ClaudeInterface, patterns_db: PatternsDatabase):
        self.claude = claude_interface
        self.patterns_db = patterns_db
        self.http_client = HTTPClient()
        self.fingerprint_analyzer = FingerprintAnalyzer()
        self.logger = logging.getLogger(__name__)
        
    async def analyze_target(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance analysis of the target.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            Complete fingerprint and risk assessment
        """
        self.logger.info(f"Starting reconnaissance for {url}")
        
        try:
            # Gather initial HTTP information
            basic_info = await self._gather_basic_info(url)
            
            # Perform technology fingerprinting
            tech_fingerprint = await self._fingerprint_technologies(url, basic_info)
            
            # Analyze proxy/CDN architecture
            architecture = await self._analyze_architecture(url, basic_info)
            
            # Detect WAF and security measures
            security_analysis = await self._analyze_security_measures(url, basic_info)
            
            # Use Claude AI for intelligent analysis
            ai_analysis = await self._perform_ai_analysis({
                'url': url,
                'basic_info': basic_info,
                'tech_fingerprint': tech_fingerprint,
                'architecture': architecture,
                'security_analysis': security_analysis
            })
            
            # Generate risk assessment and recommendations
            risk_assessment = await self._generate_risk_assessment(ai_analysis)
            
            return {
                'url': url,
                'basic_info': basic_info,
                'tech_fingerprint': tech_fingerprint,
                'architecture': architecture,
                'security_analysis': security_analysis,
                'ai_analysis': ai_analysis,
                'risk_assessment': risk_assessment,
                'timestamp': asyncio.get_event_loop().time()
            }
            
        except Exception as e:
            self.logger.error(f"Reconnaissance failed for {url}: {e}")
            raise
    
    async def _gather_basic_info(self, url: str) -> Dict[str, Any]:
        """Gather basic HTTP information from the target."""
        try:
            # Standard GET request
            response = await self.http_client.get(url)
            
            # OPTIONS request for additional info
            options_response = await self.http_client.options(url)
            
            # HEAD request for header analysis
            head_response = await self.http_client.head(url)
            
            return {
                'status_code': response.status,
                'headers': dict(response.headers),
                'options_headers': dict(options_response.headers) if options_response else {},
                'head_headers': dict(head_response.headers) if head_response else {},
                'response_time': response.response_time,
                'content_length': len(await response.text()) if response.status == 200 else 0,
                'server_header': response.headers.get('Server', ''),
                'x_powered_by': response.headers.get('X-Powered-By', ''),
                'via_header': response.headers.get('Via', ''),
                'x_forwarded_for': response.headers.get('X-Forwarded-For', ''),
            }
            
        except Exception as e:
            self.logger.error(f"Failed to gather basic info for {url}: {e}")
            return {}
    
    async def _fingerprint_technologies(self, url: str, basic_info: Dict) -> Dict[str, Any]:
        """Perform comprehensive technology fingerprinting."""
        fingerprint = {
            'web_server': self._identify_web_server(basic_info.get('headers', {})),
            'backend_technology': self._identify_backend_tech(basic_info.get('headers', {})),
            'cdn_provider': await self._identify_cdn(url, basic_info.get('headers', {})),
            'load_balancer': self._identify_load_balancer(basic_info.get('headers', {})),
            'waf_detected': await self._detect_waf(url, basic_info.get('headers', {})),
            'cms_detection': await self._detect_cms(url),
        }
        
        return fingerprint
    
    def _identify_web_server(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Identify web server technology from headers."""
        server_header = headers.get('Server', '').lower()
        
        signatures = {
            'nginx': ['nginx'],
            'apache': ['apache'],
            'iis': ['microsoft-iis', 'iis'],
            'cloudflare': ['cloudflare'],
            'lighttpd': ['lighttpd'],
            'caddy': ['caddy'],
        }
        
        detected = []
        for tech, patterns in signatures.items():
            for pattern in patterns:
                if pattern in server_header:
                    detected.append(tech)
                    break
        
        return {
            'detected': detected,
            'server_header': server_header,
            'confidence': 0.9 if detected else 0.1
        }
    
    def _identify_backend_tech(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Identify backend technology from headers."""
        tech_indicators = {
            'x-powered-by': headers.get('X-Powered-By', '').lower(),
            'x-aspnet-version': headers.get('X-AspNet-Version', ''),
            'x-drupal-cache': headers.get('X-Drupal-Cache', ''),
            'x-generator': headers.get('X-Generator', '').lower(),
        }
        
        detected_tech = []
        
        if 'php' in tech_indicators['x-powered-by']:
            detected_tech.append('php')
        if 'asp.net' in tech_indicators['x-powered-by']:
            detected_tech.append('asp.net')
        if tech_indicators['x-aspnet-version']:
            detected_tech.append('asp.net')
        if 'node.js' in tech_indicators['x-powered-by']:
            detected_tech.append('node.js')
        if tech_indicators['x-drupal-cache']:
            detected_tech.append('drupal')
        
        return {
            'detected': detected_tech,
            'indicators': tech_indicators,
            'confidence': 0.8 if detected_tech else 0.2
        }
    
    async def _identify_cdn(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Identify CDN provider through multiple detection methods."""
        cdn_indicators = {
            'cloudflare': [
                'cf-ray', 'cf-cache-status', 'cloudflare',
                'cf-request-id', 'server: cloudflare'
            ],
            'akamai': [
                'akamai', 'x-akamai', 'edge-cache-tag',
                'x-cache: hit from akamai', 'x-cache-remote: hit from akamai'
            ],
            'fastly': [
                'fastly', 'x-served-by: cache-', 'x-cache: hit, miss',
                'x-timer', 'x-fastly-request-id'
            ],
            'maxcdn': ['x-maxcdn-request-id', 'maxcdn'],
            'keycdn': ['keycdn', 'x-keycdn-zone'],
            'aws_cloudfront': [
                'x-amz-cf-id', 'x-amz-cf-pop', 'cloudfront',
                'x-cache: hit from cloudfront'
            ],
        }
        
        detected_cdns = []
        
        # Check headers for CDN indicators
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        all_header_text = ' '.join(headers_lower.keys()) + ' ' + ' '.join(headers_lower.values())
        
        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator.lower() in all_header_text:
                    detected_cdns.append(cdn)
                    break
        
        # DNS-based detection (simplified)
        dns_indicators = await self._check_dns_cdn_indicators(url)
        detected_cdns.extend(dns_indicators)
        
        return {
            'detected': list(set(detected_cdns)),
            'confidence': 0.9 if detected_cdns else 0.3,
            'dns_indicators': dns_indicators
        }
    
    async def _check_dns_cdn_indicators(self, url: str) -> List[str]:
        """Check DNS records for CDN indicators (simplified implementation)."""
        # This would normally involve DNS resolution
        # For now, return empty list as DNS queries require additional setup
        return []
    
    def _identify_load_balancer(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Identify load balancer technology."""
        lb_indicators = {
            'f5': ['f5-', 'bigip', 'f5'],
            'nginx': ['nginx'],
            'haproxy': ['haproxy'],
            'aws_elb': ['awselb', 'aws-elb'],
            'google_lb': ['gfe', 'google frontend'],
        }
        
        detected = []
        headers_text = ' '.join(headers.keys()).lower() + ' ' + ' '.join(headers.values()).lower()
        
        for lb, patterns in lb_indicators.items():
            for pattern in patterns:
                if pattern in headers_text:
                    detected.append(lb)
                    break
        
        return {
            'detected': detected,
            'confidence': 0.7 if detected else 0.3
        }
    
    async def _detect_waf(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect Web Application Firewall."""
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'akamai': ['akamaighost'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'wordfence': ['wordfence'],
            'modsecurity': ['mod_security', 'modsecurity'],
            'barracuda': ['barracuda'],
            'f5_asm': ['f5-asm', 'f5 asm'],
        }
        
        detected_wafs = []
        headers_text = ' '.join(headers.keys()).lower() + ' ' + ' '.join(headers.values()).lower()
        
        for waf, signatures in waf_signatures.items():
            for signature in signatures:
                if signature in headers_text:
                    detected_wafs.append(waf)
                    break
        
        # Test with malicious payload to trigger WAF
        try:
            test_payload = "' OR '1'='1"
            test_response = await self.http_client.get(f"{url}?test={test_payload}")
            if test_response.status in [403, 406, 501, 503]:
                detected_wafs.append('unknown_waf')
        except:
            pass
        
        return {
            'detected': list(set(detected_wafs)),
            'confidence': 0.8 if detected_wafs else 0.4
        }
    
    async def _detect_cms(self, url: str) -> Dict[str, Any]:
        """Detect Content Management System."""
        cms_indicators = {
            'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'drupal': ['/sites/default/', '/modules/', 'drupal'],
            'joomla': ['/administrator/', '/components/', 'joomla'],
            'magento': ['/skin/frontend/', '/js/mage/', 'magento'],
        }
        
        detected_cms = []
        
        try:
            response = await self.http_client.get(url)
            content = await response.text()
            content_lower = content.lower()
            
            for cms, indicators in cms_indicators.items():
                for indicator in indicators:
                    if indicator in content_lower:
                        detected_cms.append(cms)
                        break
        except:
            pass
        
        return {
            'detected': detected_cms,
            'confidence': 0.8 if detected_cms else 0.2
        }
    
    async def _analyze_architecture(self, url: str, basic_info: Dict) -> Dict[str, Any]:
        """Analyze proxy/load balancer architecture."""
        architecture = {
            'proxy_chain': self._analyze_proxy_chain(basic_info.get('headers', {})),
            'caching_layers': self._identify_caching_layers(basic_info.get('headers', {})),
            'backend_servers': await self._estimate_backend_servers(url),
            'connection_handling': self._analyze_connection_handling(basic_info.get('headers', {})),
        }
        
        return architecture
    
    def _analyze_proxy_chain(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze proxy chain from headers."""
        via_header = headers.get('Via', '')
        x_forwarded_for = headers.get('X-Forwarded-For', '')
        x_real_ip = headers.get('X-Real-IP', '')
        
        proxy_count = 0
        if via_header:
            proxy_count = len(via_header.split(','))
        
        return {
            'via_header': via_header,
            'x_forwarded_for': x_forwarded_for,
            'x_real_ip': x_real_ip,
            'estimated_proxy_count': proxy_count,
            'has_proxy_chain': bool(via_header or x_forwarded_for)
        }
    
    def _identify_caching_layers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Identify caching layers from headers."""
        cache_indicators = {
            'x-cache': headers.get('X-Cache', ''),
            'cache-control': headers.get('Cache-Control', ''),
            'expires': headers.get('Expires', ''),
            'etag': headers.get('ETag', ''),
            'last-modified': headers.get('Last-Modified', ''),
        }
        
        has_caching = any(cache_indicators.values())
        
        return {
            'indicators': cache_indicators,
            'has_caching': has_caching,
            'cache_type': self._determine_cache_type(cache_indicators)
        }
    
    def _determine_cache_type(self, cache_indicators: Dict[str, str]) -> str:
        """Determine type of caching based on indicators."""
        x_cache = cache_indicators.get('x-cache', '').lower()
        
        if 'cloudflare' in x_cache:
            return 'cloudflare'
        elif 'varnish' in x_cache:
            return 'varnish'
        elif 'hit' in x_cache or 'miss' in x_cache:
            return 'reverse_proxy_cache'
        elif cache_indicators.get('cache-control'):
            return 'browser_cache'
        
        return 'unknown'
    
    async def _estimate_backend_servers(self, url: str) -> Dict[str, Any]:
        """Estimate number of backend servers through multiple requests."""
        server_identifiers = set()
        
        try:
            for _ in range(5):  # Make 5 requests to sample different backend servers
                response = await self.http_client.get(url)
                
                # Look for server-specific identifiers
                server_id = response.headers.get('Server-ID', '')
                x_served_by = response.headers.get('X-Served-By', '')
                
                if server_id:
                    server_identifiers.add(server_id)
                if x_served_by:
                    server_identifiers.add(x_served_by)
                    
                await asyncio.sleep(0.1)  # Small delay between requests
        except:
            pass
        
        return {
            'estimated_server_count': len(server_identifiers) if server_identifiers else 1,
            'server_identifiers': list(server_identifiers),
            'load_balanced': len(server_identifiers) > 1
        }
    
    def _analyze_connection_handling(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze connection handling characteristics."""
        connection = headers.get('Connection', '').lower()
        keep_alive = headers.get('Keep-Alive', '')
        
        return {
            'connection_header': connection,
            'keep_alive': keep_alive,
            'supports_keep_alive': 'keep-alive' in connection,
            'connection_close': 'close' in connection
        }
    
    async def _analyze_security_measures(self, url: str, basic_info: Dict) -> Dict[str, Any]:
        """Analyze security measures and protections."""
        headers = basic_info.get('headers', {})
        
        security_headers = {
            'hsts': headers.get('Strict-Transport-Security', ''),
            'csp': headers.get('Content-Security-Policy', ''),
            'x_frame_options': headers.get('X-Frame-Options', ''),
            'x_content_type_options': headers.get('X-Content-Type-Options', ''),
            'x_xss_protection': headers.get('X-XSS-Protection', ''),
            'referrer_policy': headers.get('Referrer-Policy', ''),
        }
        
        return {
            'security_headers': security_headers,
            'security_score': self._calculate_security_score(security_headers),
            'missing_headers': self._identify_missing_security_headers(security_headers)
        }
    
    def _calculate_security_score(self, security_headers: Dict[str, str]) -> float:
        """Calculate security score based on present security headers."""
        total_headers = len(security_headers)
        present_headers = sum(1 for header in security_headers.values() if header)
        
        return present_headers / total_headers if total_headers > 0 else 0.0
    
    def _identify_missing_security_headers(self, security_headers: Dict[str, str]) -> List[str]:
        """Identify missing security headers."""
        return [header for header, value in security_headers.items() if not value]
    
    async def _perform_ai_analysis(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Use Claude AI to perform intelligent analysis of reconnaissance data."""
        prompt = f"""
        As a cybersecurity expert specializing in HTTP Request Smuggling vulnerabilities, 
        analyze the following reconnaissance data for potential desync attack vectors:

        Target: {recon_data['url']}
        
        Technical Fingerprint:
        - Web Server: {recon_data['tech_fingerprint']['web_server']}
        - Backend Technology: {recon_data['tech_fingerprint']['backend_technology']}
        - CDN: {recon_data['tech_fingerprint']['cdn_provider']}
        - WAF: {recon_data['tech_fingerprint']['waf_detected']}
        
        Architecture Analysis:
        - Proxy Chain: {recon_data['architecture']['proxy_chain']}
        - Caching: {recon_data['architecture']['caching_layers']}
        - Load Balancing: {recon_data['architecture']['backend_servers']}
        
        Based on James Kettle's "HTTP/1.1 Must Die" research, identify:
        1. Most promising desync attack vectors for this infrastructure
        2. Specific techniques to test (CL.0, V-H/H-V, Expect-based, etc.)
        3. WAF bypass strategies if applicable
        4. Risk assessment for successful exploitation
        5. Recommended test priorities
        
        Provide specific, actionable analysis focused on HTTP Request Smuggling potential.
        """
        
        try:
            response = await self.claude.analyze(prompt)
            return {
                'ai_recommendations': response.get('analysis', ''),
                'attack_vectors': response.get('attack_vectors', []),
                'test_priorities': response.get('test_priorities', []),
                'bypass_strategies': response.get('bypass_strategies', [])
            }
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return {
                'ai_recommendations': '',
                'attack_vectors': [],
                'test_priorities': [],
                'bypass_strategies': []
            }
    
    async def _generate_risk_assessment(self, ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment."""
        # This would normally use more sophisticated scoring
        base_score = 0.5
        
        # Adjust score based on AI analysis
        if ai_analysis.get('attack_vectors'):
            base_score += 0.2
        
        if ai_analysis.get('bypass_strategies'):
            base_score += 0.1
            
        # Cap at 1.0
        risk_score = min(base_score, 1.0)
        
        return {
            'risk_score': risk_score,
            'risk_level': self._categorize_risk(risk_score),
            'recommended_tests': ai_analysis.get('test_priorities', []),
            'entry_points': ai_analysis.get('attack_vectors', [])
        }
    
    def _categorize_risk(self, score: float) -> str:
        """Categorize risk level based on score."""
        if score >= 0.8:
            return 'high'
        elif score >= 0.6:
            return 'medium'
        elif score >= 0.4:
            return 'low'
        else:
            return 'minimal'
